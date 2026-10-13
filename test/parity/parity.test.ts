import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { CanonicalizationError, canonicalize } from '../../src/canonicalize.js';
import type { KeyProvider } from '../../src/keys.js';
import { GENESIS_HASH, sealEntry, type SealedEntry } from '../../src/seal.js';
import { verifyChain } from '../../src/verify.js';
import { verifyJsonl } from '../../src/jsonl.js';
import { parseJson } from '../../src/json.js';
import {
  buildChain,
  chainTextVariants,
  EDGE_TEXTS,
  jsonlVariants,
  maxSizeJsonl,
  sealRaw,
  KEY_HEX,
  KEY_ID,
  MUTATIONS,
  prng,
  randomTexts,
} from './corpus.js';
import { runPython, type CanonicalOutcome, type JsonlCase, type SealOutcome, type VerifyCase, type VerifyOutcome } from './python.js';

// THE HEADLINE TEST. The same raw JSON texts go through TypeScript (parseJson -> canonicalize) and
// Python (json.loads -> canonicalize). Both must reject, or both must accept with IDENTICAL UTF-8
// bytes; both verifiers must reach the same verdict on the same chains, and neither may throw.

const vectorsDir = join(__dirname, '..', '..', 'vectors');
const jcs = parseJson(readFileSync(join(vectorsDir, 'jcs-vectors.json'), 'utf8')) as {
  vectors: { name: string; value: unknown }[];
  text_vectors: { name: string; json_text: string }[];
  size_vectors: { name: string; prefix: string; unit: string; count: number; suffix: string }[];
};
const seal = parseJson(readFileSync(join(vectorsDir, 'audit-seal-vectors.json'), 'utf8')) as {
  key_hex: string;
  key_id: string;
  vectors: { name: string; core: unknown }[];
  verify_vectors: {
    name: string;
    chain: unknown;
    anchor?: { count: number; last_hash: string };
    keyring?: Record<string, string>;
  }[];
  jsonl_vectors: { name: string; data_hex: string; keyring?: Record<string, string>; anchor?: { count: number; last_hash: string } }[];
  jsonl_size_vectors: { name: string; prefix: string; unit: string; count: number; suffix: string }[];
};

function tsCanonical(text: string): CanonicalOutcome {
  let value: unknown;
  try {
    value = parseJson(text);
  } catch {
    return { ok: false, phase: 'parse' };
  }
  try {
    return { ok: true, hex: Buffer.from(canonicalize(value), 'utf8').toString('hex') };
  } catch (err) {
    // canonicalize wraps an unreadable value (proxy, throwing getter) as CanonicalizationError WITH a
    // cause. Nothing parseJson produces is unreadable, so here a cause means a crash, not a refusal.
    if (err instanceof CanonicalizationError && err.cause === undefined) return { ok: false, phase: 'domain' };
    return { ok: false, phase: 'crash', error: String(err) };
  }
}

// The sealing primitive, on the same texts: the parsed value is the payload of a genesis entry. (Not
// appendEntry: Python's append_entry deliberately drops None members, reading None as undefined.)
function tsSeal(text: string): SealOutcome {
  let value: unknown;
  try {
    value = parseJson(text);
  } catch {
    return { ok: false, phase: 'parse' };
  }
  try {
    const core = { payload: value, prev_hash: GENESIS_HASH, seq: 0, writer_key_id: KEY_ID };
    const sealed = sealEntry(core, Buffer.from(KEY_HEX, 'hex'));
    return { ok: true, entry_hash: sealed.entry_hash, entry_hmac: sealed.entry_hmac };
  } catch (err) {
    if (err instanceof CanonicalizationError && err.cause === undefined) return { ok: false, phase: 'domain' };
    return { ok: false, phase: 'crash', error: String(err) };
  }
}

function sealAgree(ts: SealOutcome, py: SealOutcome | undefined): boolean {
  if (py === undefined) return false;
  if (ts.ok || py.ok) return ts.ok && py.ok && ts.entry_hash === py.entry_hash && ts.entry_hmac === py.entry_hmac;
  return ts.phase !== 'crash' && py.phase !== 'crash';
}

// Agreement: identical bytes, or both refuse. WHY each refuses may differ (Python's parser rejects a
// 5000-digit integer that JS parses to Infinity and then refuses as a number), but a crash never agrees.
function agree(ts: CanonicalOutcome, py: CanonicalOutcome | undefined): boolean {
  if (py === undefined) return false;
  if (ts.ok || py.ok) return ts.ok && py.ok && ts.hex === py.hex;
  return ts.phase !== 'crash' && py.phase !== 'crash';
}

function tsVerify(c: VerifyCase): VerifyOutcome {
  const keyring = Object.fromEntries(Object.entries(c.keyring).map(([k, v]) => [k, Buffer.from(v, 'hex')]));
  const keys: KeyProvider = {
    getKey: (id) => (Object.hasOwn(keyring, id) ? keyring[id]! : null),
    activeKeyId: () => Object.keys(keyring)[0]!,
  };
  try {
    const anchor = c.anchor && { count: c.anchor.count, lastHash: c.anchor.last_hash };
    const r = verifyChain(parseJson(c.chain) as SealedEntry[], keys, anchor);
    return { threw: false, ok: r.ok, last_seq: r.lastSeq };
  } catch (err) {
    return { threw: true, error: String(err) };
  }
}

function tsVerifyJsonl(c: JsonlCase): VerifyOutcome {
  const keyring = Object.fromEntries(Object.entries(c.keyring).map(([k, v]) => [k, Buffer.from(v, 'hex')]));
  const keys: KeyProvider = {
    getKey: (id) => (Object.hasOwn(keyring, id) ? keyring[id]! : null),
    activeKeyId: () => Object.keys(keyring)[0]!,
  };
  try {
    const anchor = c.anchor && { count: c.anchor.count, lastHash: c.anchor.last_hash };
    const r = verifyJsonl(Buffer.from(c.data_hex, 'hex'), keys, anchor);
    return { threw: false, ok: r.ok, last_seq: r.lastSeq };
  } catch (err) {
    return { threw: true, error: String(err) };
  }
}

interface Labeled<T> {
  label: string;
  input: T;
}

const canonicalCases: Labeled<string>[] = [
  ...jcs.vectors.map((v) => ({ label: `jcs:${v.name}`, input: JSON.stringify(v.value) })),
  ...jcs.text_vectors.map((v) => ({ label: `jcs-text:${v.name}`, input: v.json_text })),
  ...jcs.size_vectors.map((v) => ({ label: `jcs-size:${v.name}`, input: v.prefix + v.unit.repeat(v.count) + v.suffix })),
  ...seal.vectors.map((v) => ({ label: `seal:${v.name}`, input: JSON.stringify(v.core) })),
  ...EDGE_TEXTS.map((t, i) => ({ label: `edge#${i}`, input: t })),
  ...randomTexts(0x5eed, 1500).map((t, i) => ({ label: `random#${i}`, input: t })),
];

const sealKeyring = { [seal.key_id]: seal.key_hex };
const jsonlCases: Labeled<JsonlCase>[] = seal.jsonl_size_vectors.map((v) => ({
  label: `vector:${v.name}`,
  input: { data_hex: Buffer.from(v.prefix + v.unit.repeat(v.count) + v.suffix, 'utf8').toString('hex'), keyring: sealKeyring },
}));
jsonlCases.push(...seal.jsonl_vectors.map((v) => ({
  label: `vector:${v.name}`,
  input: { data_hex: v.data_hex, keyring: v.keyring ?? sealKeyring, ...(v.anchor && { anchor: v.anchor }) },
})));
jsonlCases.push({
  label: 'jsonl-max-size-line:canonical',
  input: { data_hex: maxSizeJsonl().toString('hex'), keyring: { [KEY_ID]: KEY_HEX } },
});
{
  // Sealed with a key of EXACTLY the 16-byte minimum: both languages must accept it.
  const k16 = Buffer.alloc(16, 0x5a);
  const entry = sealRaw({ seq: 0, prev_hash: '0'.repeat(64), writer_key_id: 'k16', note: 'minimum-length key' }, k16);
  jsonlCases.push({
    label: 'jsonl-16-byte-key:canonical',
    input: { data_hex: Buffer.from(`${canonicalize(entry)}${String.fromCharCode(10)}`, 'utf8').toString('hex'), keyring: { k16: k16.toString('hex') } },
  });
}
{
  // Large junk after (or instead of) a valid chain: both languages must reach the SAME verdict, and
  // streaming makes it cost no more than the first bad line.
  const keyring = { [KEY_ID]: KEY_HEX };
  const valid = Buffer.from(buildChain(prng(0x10f), 3).map((e) => `${canonicalize(e)}${String.fromCharCode(10)}`).join(''), 'utf8');
  const junk: [string, Buffer][] = [
    ['chain-then-4MiB-of-line-feeds', Buffer.concat([valid, Buffer.alloc(4 * 2 ** 20, 10)])],
    ['4MiB-of-zero-lines', Buffer.alloc(4 * 2 ** 20, `0${String.fromCharCode(10)}`)],
    ['chain-then-4MiB-of-empty-objects', Buffer.concat([valid, Buffer.alloc(3 * 2 ** 20, `{}${String.fromCharCode(10)}`)])],
  ];
  for (const [name, data] of junk) jsonlCases.push({ label: `jsonl-junk:${name}`, input: { data_hex: data.toString('hex'), keyring } });
  // A VALID file over 1 MiB made of several large lines: the size bound applies per line, at every offset.
  const big: Record<string, unknown>[] = [];
  let prevHash = '0'.repeat(64);
  for (let seq = 0; seq < 4; seq += 1) { // 4 x 400 KB: the last line starts past 1 MiB
    const entry = sealRaw({ seq, prev_hash: prevHash, writer_key_id: KEY_ID, pad: 'y'.repeat(400_000) });
    big.push(entry);
    prevHash = entry.entry_hash as string;
  }
  const bigFile = Buffer.from(big.map((e) => `${canonicalize(e)}${String.fromCharCode(10)}`).join(''), 'utf8');
  jsonlCases.push({ label: 'jsonl-large-lines:canonical', input: { data_hex: bigFile.toString('hex'), keyring } });
}
const verifyCases: Labeled<VerifyCase>[] = [
  ...seal.verify_vectors.map((v) => ({
    label: `vector:${v.name}`,
    input: { chain: JSON.stringify(v.chain), keyring: v.keyring ?? sealKeyring, ...(v.anchor && { anchor: v.anchor }) },
  })),
];
{
  const rand = prng(0xc4a1);
  for (let round = 0; round < 25; round += 1) {
    const base = buildChain(rand, 3 + Math.floor(rand() * 4)); // >= 3 so delete-middle is never a tail cut
    const keyring = { [KEY_ID]: KEY_HEX };
    const trueAnchor = { count: base.length, last_hash: base[base.length - 1]!.entry_hash as string };
    for (const [name, mutate] of Object.entries(MUTATIONS)) {
      const chain = JSON.stringify(mutate(base, rand));
      verifyCases.push(
        { label: `chain#${round}:${name}`, input: { chain, keyring } },
        { label: `chain#${round}:${name}+anchor`, input: { chain, keyring, anchor: trueAnchor } },
      );
    }
    for (const [name, text] of chainTextVariants(base)) {
      verifyCases.push({ label: `text#${round}:${name}`, input: { chain: text, keyring } });
    }
    for (const [name, data] of jsonlVariants(base)) {
      const data_hex = data.toString('hex');
      jsonlCases.push(
        { label: `jsonl#${round}:${name}`, input: { data_hex, keyring } },
        { label: `jsonl#${round}:${name}+anchor`, input: { data_hex, keyring, anchor: trueAnchor } },
      );
    }
    const anchor = { count: base.length, last_hash: base[base.length - 1]!.entry_hash as string };
    const [, canonical] = jsonlVariants(base)[0]!;
    const cut = canonical.subarray(0, canonical.lastIndexOf(0x0a, canonical.length - 2) + 1);
    jsonlCases.push(
      { label: `jsonl-anchor#${round}:full`, input: { data_hex: canonical.toString('hex'), keyring, anchor } },
      { label: `jsonl-anchor#${round}:truncated`, input: { data_hex: cut.toString('hex'), keyring, anchor } },
    );
    verifyCases.push(
      { label: `anchor#${round}:full`, input: { chain: JSON.stringify(base), keyring, anchor } },
      { label: `anchor#${round}:truncated`, input: { chain: JSON.stringify(base.slice(0, -1)), keyring, anchor } },
    );
  }
}

describe('cross-language parity (TypeScript vs Python)', () => {
  let py: ReturnType<typeof runPython>;
  beforeAll(() => {
    py = runPython({
      canonicalize: canonicalCases.map((c) => c.input),
      seal: { key_hex: KEY_HEX, writer_key_id: KEY_ID },
      verify: verifyCases.map((c) => c.input),
      verify_jsonl: jsonlCases.map((c) => c.input),
    });
  });

  it(`canonicalizes ${canonicalCases.length} JSON texts to identical bytes (or both reject)`, () => {
    const diverged = canonicalCases.flatMap((c, i) => {
      const ts = tsCanonical(c.input);
      const p = py.canonicalize[i];
      return agree(ts, p) ? [] : [{ case: c.label, input: c.input, ts, py: p }];
    });
    expect(diverged).toEqual([]);
  });

  it(`seals the same ${canonicalCases.length} JSON texts to identical entries (or both refuse)`, () => {
    let sealed = 0;
    const diverged = canonicalCases.flatMap((c, i) => {
      const ts = tsSeal(c.input);
      const p = py.seal[i];
      if (ts.ok) sealed += 1;
      return sealAgree(ts, p) ? [] : [{ case: c.label, input: c.input.slice(0, 200), ts, py: p }];
    });
    expect(diverged).toEqual([]);
    expect(sealed).toBeGreaterThan(500); // the comparison is not vacuous: most texts seal
  });

  it(`reaches the same verdict on ${verifyCases.length} chains, and neither side throws`, () => {
    const diverged = verifyCases.flatMap((c, i) => {
      const ts = tsVerify(c.input);
      const p = py.verify[i];
      const same = JSON.stringify(ts) === JSON.stringify(p) && !ts.threw;
      return same ? [] : [{ case: c.label, ts, py: p }];
    });
    expect(diverged).toEqual([]);
  });

  it(`verifies ${jsonlCases.length} canonical-JSONL files byte for byte to the same verdict`, () => {
    const diverged = jsonlCases.flatMap((c, i) => {
      const ts = tsVerifyJsonl(c.input);
      const p = py.verify_jsonl[i];
      const same = JSON.stringify(ts) === JSON.stringify(p) && !ts.threw;
      return same ? [] : [{ case: c.label, ts, py: p }];
    });
    expect(diverged).toEqual([]);
  });

  it('accepts only the canonical and fully anchored JSONL; rejects every other variant', () => {
    const mayVerify = /:(canonical|empty-file|full|canonical\+anchor)$/;
    for (const c of jsonlCases.filter((j) => !j.label.startsWith('vector:'))) {
      const ts = tsVerifyJsonl(c.input);
      expect(!ts.threw && ts.ok, c.label).toBe(mayVerify.test(c.label));
    }
  });

  it('actually exercises rejection: every attack mutation fails verification in both', () => {
    const attacks = verifyCases.filter((c) => /^chain#\d+:(?!identity$|identity\+anchor$|truncate-tail$)/.test(c.label));
    expect(attacks.length).toBeGreaterThan(200);
    for (const c of attacks) {
      const ts = tsVerify(c.input);
      expect(ts.threw ? true : !ts.ok, c.label).toBe(true);
    }
  });
});
