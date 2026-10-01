import { createHash, createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';
import { derivedCases, sizeVectorCases, type Derivations } from '../scripts/audit-vectors/derive.mjs';
import { assertSameValue } from '../scripts/audit-vectors/respell.mjs';
import { assertTypeScriptVerdicts } from '../scripts/audit-vectors/selfcheck.mjs';
import { checkMust } from '../scripts/vector-guard.mjs';
import { canonicalize } from '../src/canonicalize.js';

// The generators refuse to emit a vector whose hand-written intent the implementation contradicts.
describe('vector generator self-check', () => {
  it('passes when the implementation agrees with the stated intent', () => {
    expect(() => checkMust('text vector', 'ok-accept', 'accept', '{}')).not.toThrow();
    expect(() => checkMust('text vector', 'ok-reject', 'reject', null)).not.toThrow();
  });

  it('refuses when a must-accept vector is rejected, or a must-reject vector accepted', () => {
    expect(() => checkMust('text vector', 'regressed', 'accept', null)).toThrow(/refusing to emit/);
    expect(() => checkMust('size vector', 'loosened', 'reject', '"x"')).toThrow(/refusing to emit/);
  });
});

describe('audit-vector generator guards', () => {
  const KEYRING = { k1: '11'.repeat(32) };
  const key = Buffer.from(KEYRING.k1, 'hex');
  const core = { seq: 0, prev_hash: '0'.repeat(64), writer_key_id: 'k1' };
  const bytes = canonicalize(core);
  const entry = {
    ...core,
    entry_hash: createHash('sha256').update(bytes, 'utf8').digest('hex'),
    entry_hmac: createHmac('sha256', key).update(bytes, 'utf8').digest('hex'),
  };
  const LF = String.fromCharCode(10);
  const line = canonicalize(entry);
  const good = { name: 'good', chain: [entry], expect: { ok: true, last_seq: 0 } };
  const file = { name: 'file', data: Buffer.from(line + LF, 'utf8'), expect: { ok: true, last_seq: 0 } };
  const size = { name: 'size', prefix: line.slice(0, 5), unit: line[5]!, count: 1, suffix: line.slice(6) + LF, expect: { ok: true, last_seq: 0 }, value_expect: { ok: true, last_seq: 0 } };

  it('assertTypeScriptVerdicts passes when TypeScript reaches every stated verdict', () => {
    expect(() => assertTypeScriptVerdicts([good, file, ...sizeVectorCases(size)], KEYRING)).not.toThrow();
  });

  it.each([
    ['a wrong ok', { ...good, expect: { ok: false, last_seq: 0 } }],
    ['a wrong last_seq', { ...good, expect: { ok: true, last_seq: 1 } }],
    ['a verdict that depends on the anchor', { ...good, anchor: { count: 1 } }],
    ['a verdict that depends on the keyring', { ...good, keyring: {} }],
    ['a wrong file verdict', { ...file, expect: { ok: false, last_seq: -1 } }],
    ['a wrong size verdict', sizeVectorCases({ ...size, expect: { ok: false, last_seq: -1 } })[0]!],
    ['a wrong size value_expect', sizeVectorCases({ ...size, value_expect: { ok: false, last_seq: -1 } })[1]!],
  ])('assertTypeScriptVerdicts refuses %s', (_label, c) => {
    expect(() => assertTypeScriptVerdicts([c], KEYRING)).toThrow(/refusing to emit/);
  });

  it('assertSameValue refuses a respelling that changes the value, or is no respelling at all', () => {
    expect(() => assertSameValue('ok', '{"a":1}', '{"a": 1}')).not.toThrow();
    expect(() => assertSameValue('changed', '{"a":1}', '{"a":2}')).toThrow(/changes the value/);
    expect(() => assertSameValue('identical', '{"a":1}', '{"a":1}')).toThrow(/changes the value/);
  });

  const hex = (text: string): string => Buffer.from(text, 'utf8').toString('hex');
  const later = { later: true };
  const D: Derivations = {
    later_entry: later,
    later_lines_hex: [hex(`${canonicalize(later)}${LF}`), hex(`j${LF}`), hex('{')],
    inserted_lines_hex: [hex(`#${LF}`)],
    ignored_anchors: [{ count: 9, last_hash: 'f'.repeat(64) }],
    genesis_hash: '0'.repeat(64),
    max_depth: 1,
  };
  const text = (c: { data?: Uint8Array }): string => Buffer.from(c.data!).toString('utf8');

  it('derives forged_first, later_failure and ignored_anchor from a failing case exactly as the spec says', () => {
    const broken = { name: 'g', chain: [entry, null], expect: { ok: false, last_seq: 0 } };
    expect(derivedCases(broken, D)).toEqual([
      { name: 'g/forged-first', chain: [later, null], expect: { ok: false, last_seq: -1 } },
      { name: 'g/later-entry', chain: [entry, null, later], expect: { ok: false, last_seq: 0 } },
      { name: 'g/ignored-anchor-0', chain: [entry, null], anchor: D.ignored_anchors[0], expect: { ok: false, last_seq: 0 } },
    ]);
    const brokenFile = { name: 'f', data: Buffer.from(`${line}${LF}x${LF}`, 'utf8'), expect: { ok: false, last_seq: 0 } };
    const [forged, ...rest] = derivedCases(brokenFile, D);
    // Line 0 is replaced by the forged line; every later line is kept byte for byte.
    expect(text(forged!)).toBe(`${canonicalize(later)}${LF}x${LF}`);
    expect(forged!.expect).toEqual({ ok: false, last_seq: -1 });
    const original = `${line}${LF}x${LF}`;
    expect(rest.map(text)).toEqual([`${original}${canonicalize(later)}${LF}`, `${original}j${LF}`, `${original}{`, original]);
    expect(rest.map((c) => c.expect)).toEqual(rest.map(() => ({ ok: false, last_seq: 0 })));
    // An anchored failing case keeps its anchor and gets no later or anchor cases (its failure may BE the anchor).
    const anchored = { ...broken, anchor: { count: 2, last_hash: 'a'.repeat(64) } };
    expect(derivedCases(anchored, D).map((c) => c.name)).toEqual(['g/forged-first']);
  });

  it('derives tail_failure (as given and under the TRUE anchor) and head_replay from a passing case', () => {
    const cases = derivedCases(good, D);
    expect(cases.map((c) => c.name)).toEqual([
      'good/tail-later-entry', 'good/tail-later-entry-true-anchor',
      'good/tail-last-entry-again', 'good/tail-last-entry-again-true-anchor',
      'good/tail-entry-0-again', 'good/tail-entry-0-again-true-anchor',
      'good/tail-whole-chain-again', 'good/tail-whole-chain-again-true-anchor',
      'good/head-replay',
    ]);
    expect(cases.map((c) => c.expect)).toEqual(cases.map(() => ({ ok: false, last_seq: 0 })));
    expect(cases[1]).toMatchObject({ chain: [entry, later], anchor: { count: 1, last_hash: entry.entry_hash } });
    expect(cases[8]).toMatchObject({ chain: [entry, entry] });
    // The file form appends the later and inserted lines, the last line, line 0 and the whole file; then
    // inserts line 0 again, and each inserted line, at index 1.
    const fileCases = derivedCases(file, D).filter((c) => !c.name.endsWith('-true-anchor'));
    expect(fileCases.map(text)).toEqual([
      `${line}${LF}${canonicalize(later)}${LF}`, `${line}${LF}j${LF}`, `${line}${LF}{`, `${line}${LF}#${LF}`,
      `${line}${LF}${line}${LF}`, `${line}${LF}${line}${LF}`, `${line}${LF}${line}${LF}`,
      `${line}${LF}${line}${LF}`, `${line}${LF}#${LF}`,
    ]);
    expect(fileCases.slice(-2).map((c) => c.name)).toEqual(['file/head-replay', 'file/head-inserted-line-0']);
    // Inserted at index 1 of a longer file: every line after it is kept.
    const two = { name: 'two', data: Buffer.from(`${line}${LF}${line}${LF}`, 'utf8'), expect: { ok: true, last_seq: 1 } };
    const inserted = derivedCases(two, D).find((c) => c.name === 'two/head-inserted-line-0')!;
    expect(text(inserted)).toBe(`${line}${LF}#${LF}${line}${LF}`);
    expect(inserted.expect).toEqual({ ok: false, last_seq: 0 });
    // An EMPTY passing chain: only the later entry, as given and under the genesis anchor.
    expect(derivedCases({ name: 'e', chain: [], expect: { ok: true, last_seq: -1 } }, D)).toEqual([
      { name: 'e/tail-later-entry', chain: [later], expect: { ok: false, last_seq: -1 } },
      { name: 'e/tail-later-entry-true-anchor', chain: [later], anchor: { count: 0, last_hash: D.genesis_hash }, expect: { ok: false, last_seq: -1 } },
    ]);
  });

  it('composes the rules up to max_depth, each at most once on a derivation path', () => {
    const broken = { name: 'g', chain: [entry, null], expect: { ok: false, last_seq: 0 } };
    const names = derivedCases(broken, { ...D, max_depth: 2 }).map((c) => c.name);
    expect(names).toEqual(expect.arrayContaining(['g/later-entry/ignored-anchor-0', 'g/forged-first/later-entry', 'g/forged-first/ignored-anchor-0']));
    expect(names.filter((n) => n.split('/').length > 3)).toEqual([]);
    for (const rule of ['forged-first', 'later-entry', 'ignored-anchor']) {
      expect(names.filter((n) => n.split(rule).length > 2)).toEqual([]);
    }
    expect(derivedCases(broken, { ...D, max_depth: 0 })).toEqual([]);
  });

  it('the emitters are wired to their guards (source-level)', () => {
    const emit = readFileSync(join(__dirname, '..', 'scripts', 'emit-audit-vectors.mts'), 'utf8');
    expect(emit).toMatch(/const allCases = baseCases\.flatMap\(\(c\) => \[c, \.\.\.derivedCases\(c, DERIVATIONS\)\]\);/);
    expect(emit).toMatch(/assertTypeScriptVerdicts\(allCases, KEYRING\);/);
    expect(emit).toMatch(/case_count: allCases\.length,/);
    expect(emit).toMatch(/\.\.\.sizeVectors\.flatMap\(sizeVectorCases\),/);
    expect(emit).toMatch(/derivations: DERIVATIONS,/);
    expect(emit).toMatch(/jsonl_size_vectors: sizeVectors,/);
    const respell = readFileSync(join(__dirname, '..', 'scripts', 'audit-vectors', 'respell.mts'), 'utf8');
    expect(respell).toMatch(/assertSameValue\(label, line1, text\);/);
  });
});
