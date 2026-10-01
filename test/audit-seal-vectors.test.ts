import { createHash, createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';
import { canonicalize } from '../src/canonicalize.js';
import type { KeyProvider } from '../src/keys.js';
import { verifyChain } from '../src/verify.js';
import { verifyJsonl } from '../src/jsonl.js';
import { parseJson } from '../src/json.js';
import { derivedCases, sizeVectorCases, type Case, type Derivations } from '../scripts/audit-vectors/derive.mjs';

// Keeps the committed audit-seal vectors honest vs the authoritative TS seal primitive;
// python/tests/test_seal.py asserts the Python port reproduces the same entry_hash + entry_hmac.
const vectorsPath = join(__dirname, '..', 'vectors', 'audit-seal-vectors.json');

interface Vector {
  name: string;
  core: unknown;
  entry_hash: string;
  entry_hmac: string;
}
/** A plain map-backed provider: unlike InMemoryKeyProvider it accepts short keys, so the VERIFIER's own
 *  16-byte minimum is what the keyring vectors exercise. */
function keyring(map: Record<string, string>): KeyProvider {
  const keys = new Map(Object.entries(map).map(([id, hex]) => [id, Buffer.from(hex, 'hex')]));
  return { getKey: (id) => keys.get(id) ?? null, activeKeyId: () => Object.keys(map)[0]! };
}

type Verdict = { ok: boolean; last_seq: number };
const data = parseJson(readFileSync(vectorsPath, 'utf8')) as {
  key_hex: string;
  key_id: string;
  derivations: Derivations;
  vectors: Vector[];
  verify_vectors: (Case & { chain: unknown })[];
  jsonl_vectors: (Omit<Case, 'data'> & { data_hex: string })[];
  jsonl_size_vectors: { name: string; prefix: string; unit: string; count: number; suffix: string; expect: Verdict; value_expect: Verdict }[];
  case_count: number;
};
const key = Buffer.from(data.key_hex, 'hex');
const defaultKeys = keyring({ [data.key_id]: data.key_hex });

/** The verdict of one case (a chain or a file) against its expectation, as a mismatch line or null. */
function mismatch(c: Case): string | null {
  const a = c.anchor as { count?: unknown; last_hash?: unknown } | undefined;
  const anchor = a && ({ count: a.count, lastHash: a.last_hash } as never);
  const keys = c.keyring ? keyring(c.keyring) : defaultKeys;
  const result = c.data !== undefined ? verifyJsonl(c.data, keys, anchor) : verifyChain(c.chain, keys, anchor);
  const ok = result.ok === c.expect.ok && result.lastSeq === c.expect.last_seq;
  return ok ? null : `${c.name}: got (${result.ok}, ${result.lastSeq}), want (${c.expect.ok}, ${c.expect.last_seq})`;
}

/** One test per base vector: the vector itself and every case the spec derives from it. */
function checkWithDerivations(base: Case): void {
  const cases = [base, ...derivedCases(base, data.derivations)];
  expect(cases.map(mismatch).filter((m) => m !== null)).toEqual([]);
}

describe('audit-seal cross-language vectors', () => {
  it('the committed vector file is non-empty', () => {
    expect(data.vectors.length).toBeGreaterThan(0);
  });

  for (const v of data.vectors) {
    it(`seals "${v.name}" to the committed entry_hash + entry_hmac`, () => {
      const canonical = canonicalize(v.core);
      expect(createHash('sha256').update(canonical, 'utf8').digest('hex')).toBe(v.entry_hash);
      expect(createHmac('sha256', key).update(canonical, 'utf8').digest('hex')).toBe(v.entry_hmac);
    });
  }
});

// Shared with python/tests/test_seal.py and test_jsonl.py: both verifiers must reach the same verdict on
// every vector AND every derived case (vectors/audit-seal-vectors.json: derivations), and never throw.
describe('audit-chain cross-language VERIFY vectors (with derivations)', () => {
  it('the committed verify-vector set is non-empty', () => {
    expect(data.verify_vectors.length).toBeGreaterThan(0);
  });

  it('derives exactly case_count cases, base and derived (a harness that skips a rule reaches fewer)', () => {
    const bases: Case[] = [
      ...data.verify_vectors,
      ...data.jsonl_vectors.map(({ data_hex, ...v }) => ({ ...v, data: Buffer.from(data_hex, 'hex') })),
      ...data.jsonl_size_vectors.flatMap(sizeVectorCases),
    ];
    expect(bases.reduce((n, c) => n + 1 + derivedCases(c, data.derivations).length, 0)).toBe(data.case_count);
  });

  for (const v of data.verify_vectors) {
    it(`verifies "${v.name}" to ok=${v.expect.ok} last_seq=${v.expect.last_seq}`, () => checkWithDerivations(v));
  }
});

describe('audit-chain cross-language JSONL vectors (with derivations)', () => {
  for (const { data_hex, ...v } of data.jsonl_vectors) {
    it(`verifies file "${v.name}" to ok=${v.expect.ok} last_seq=${v.expect.last_seq}`, () =>
      checkWithDerivations({ ...v, data: Buffer.from(data_hex, 'hex') }));
  }

  for (const v of data.jsonl_size_vectors) {
    // A size vector is two cases: the generated file (expect), and its parsed lines (value_expect). With its
    // derived cases a valid 1 MiB vector verifies ~230 MiB of files, well past vitest's 5 s default on CI.
    it(`verifies generated file "${v.name}", as a file and as a chain`, () => {
      for (const c of sizeVectorCases(v)) checkWithDerivations(c);
    }, 120_000);
  }
});
