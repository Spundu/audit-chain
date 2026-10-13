import { beforeEach, describe, expect, it, vi } from 'vitest';
import { InMemoryKeyProvider } from '../src/keys.js';
import { appendEntry, type SealedEntry } from '../src/seal.js';
import { verifyChain } from '../src/verify.js';
import { draft } from './draft.js';

// Behavioural, not source-level: the HMAC verdict IS crypto.timingSafeEqual's answer, asked once per entry
// that reaches the HMAC step. A verifier that compares with === (calling timingSafeEqual only for show, or
// not at all) fails here.
const spy = vi.hoisted(() => ({ calls: 0, answer: null as boolean | null }));
vi.mock('node:crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:crypto')>();
  return {
    ...actual,
    timingSafeEqual: (a: NodeJS.ArrayBufferView, b: NodeJS.ArrayBufferView): boolean => {
      spy.calls += 1;
      return spy.answer ?? actual.timingSafeEqual(a, b);
    },
  };
});

const keys = new InMemoryKeyProvider({ k1: Buffer.alloc(32, 7) }, 'k1');
function chainOf(n: number): SealedEntry[] {
  const chain: SealedEntry[] = [];
  for (let i = 0; i < n; i += 1) chain.push(appendEntry(chain.at(-1) ?? null, draft(i), keys));
  return chain;
}
const verdict = (entries: unknown[]): [boolean, number] => {
  const result = verifyChain(entries, keys);
  return [result.ok, result.lastSeq];
};
/** The chain with entry 1's HMAC replaced by other valid lowercase hex: its entry_hash still matches. */
function forgedHmacAt1(): SealedEntry[] {
  const chain = chainOf(3);
  const hmac = chain[1]!.entry_hmac;
  chain[1] = { ...chain[1]!, entry_hmac: (hmac[0] === 'a' ? 'b' : 'a') + hmac.slice(1) };
  return chain;
}

describe('the HMAC compare is crypto.timingSafeEqual (behavioural)', () => {
  beforeEach(() => {
    spy.calls = 0;
    spy.answer = null;
  });

  it('asks it once per entry of a valid chain', () => {
    expect(verdict(chainOf(3))).toEqual([true, 2]);
    expect(spy.calls).toBe(3);
  });

  it('asks it for a forged HMAC, and stops there', () => {
    expect(verdict(forgedHmacAt1())).toEqual([false, 0]);
    expect(spy.calls).toBe(2);
  });

  it('never asks it for an entry that breaks before the HMAC step', () => {
    const chain = chainOf(3);
    chain[1] = { ...chain[1]!, request_id: 'tampered' };
    expect(verdict(chain)).toEqual([false, 0]);
    expect(spy.calls).toBe(1);
  });

  it('its answer is the whole HMAC verdict (there is no second compare)', () => {
    spy.answer = false;
    expect(verdict(chainOf(3))).toEqual([false, -1]);
    spy.answer = true;
    expect(verdict(forgedHmacAt1())).toEqual([true, 2]);
  });
});
