// The generator's self-check: it refuses to write a vector file in which the TypeScript verifier does not
// reach every stated verdict, for every base vector AND every derived case (derive.mts). A generator bug
// (a derivation, a respelling that is not what it claims) then fails loudly here instead of becoming
// "the spec".

import { verifyJsonl } from '../../src/jsonl.js';
import type { KeyProvider } from '../../src/keys.js';
import { verifyChain, type ChainAnchor, type VerifyResult } from '../../src/verify.js';
import type { Case } from './derive.mjs';

export interface SizeVector {
  name: string;
  prefix: string;
  unit: string;
  count: number;
  suffix: string;
  expect: { ok: boolean; last_seq: number };
  value_expect: { ok: boolean; last_seq: number };
}

function keyringOf(map: Record<string, string>): KeyProvider {
  // A plain map, like the test harnesses: the verifier's own 16-byte key minimum is what applies.
  const keys = new Map(Object.entries(map).map(([id, hex]) => [id, Buffer.from(hex, 'hex')]));
  return { getKey: (id) => keys.get(id) ?? null, activeKeyId: () => '' };
}

/** TypeScript's verdict on one case (a chain or a file), with its keyring (or the default) and anchor. */
export function verdictOf(c: Case, defaultKeyring: Record<string, string>): VerifyResult {
  // An absent anchor field stays absent (undefined), never null: that difference is part of the spec.
  const a = c.anchor as { count?: unknown; last_hash?: unknown } | undefined;
  const anchor = a && ({ count: a.count, lastHash: a.last_hash } as ChainAnchor);
  const keys = keyringOf(c.keyring ?? defaultKeyring);
  return c.data !== undefined ? verifyJsonl(c.data, keys, anchor) : verifyChain(c.chain, keys, anchor);
}

/** Every vector name is unique across the file: a name is how a failure is reported and looked up. */
export function assertUniqueNames(vectors: { name: string }[]): void {
  const seen = new Set<string>();
  for (const { name } of vectors) {
    if (seen.has(name)) throw new Error(`vector name "${name}" is used twice; refusing to emit`);
    seen.add(name);
  }
}

export function assertTypeScriptVerdicts(cases: Case[], defaultKeyring: Record<string, string>): void {
  for (const c of cases) {
    const result = verdictOf(c, defaultKeyring);
    if (result.ok !== c.expect.ok || result.lastSeq !== c.expect.last_seq) {
      throw new Error(`case "${c.name}": TypeScript verifies it to (${result.ok}, ${result.lastSeq}); refusing to emit`);
    }
  }
}
