import { describe, it, expect } from 'vitest';
import { CanonicalizationError, MAX_DEPTH } from '../src/canonicalize.js';
import { InMemoryKeyProvider } from '../src/keys.js';
import { GENESIS_HASH, appendEntry, sealEntry } from '../src/seal.js';
import { verifyChain } from '../src/verify.js';
import { draft } from './draft.js';

// The chain has no record schema: it seals any JSON object, and refuses only what could never verify.

const KEY = Buffer.alloc(32, 1);
const keys = new InMemoryKeyProvider({ k1: KEY }, 'k1');
const core = { ...draft(0), seq: 0, prev_hash: GENESIS_HASH, writer_key_id: 'k1' };

function nested(depth: number): unknown {
  let value: unknown = 0;
  for (let i = 0; i < depth; i += 1) value = [value];
  return value;
}

describe('appendEntry seals records of any shape', () => {
  it.each([
    ['a flat record', { event: 'login' }],
    ['nested objects and arrays', { actor: { name: 'alice', roles: ['admin', 'ops'] }, items: [{ sku: 'a', qty: 2 }] }],
    ['null members', { reason: null, list: [null] }],
    ['non-ASCII keys and values', { ['caf' + String.fromCharCode(0xe9)]: String.fromCodePoint(0x1f600) }],
    ['an empty record', {}],
  ])('%s: appends and verifies', (_label, record) => {
    const entry = appendEntry(null, record, keys);
    expect(entry).toMatchObject({ ...record, seq: 0, prev_hash: GENESIS_HASH, writer_key_id: 'k1' });
    expect(verifyChain([entry], keys).ok).toBe(true);
  });

  it.each([['an array', []], ['null', null], ['a string', 'login'], ['a number', 7]])(
    'refuses a draft that is %s (TypeError)',
    (_label, bad) => {
      expect(() => appendEntry(null, bad as never, keys)).toThrow(TypeError);
    },
  );

  it('refuses a draft carrying a derived field: it would be sealed but never verify', () => {
    expect(() => appendEntry(null, { ...draft(0), entry_hmac: 'x' }, keys)).toThrow(/must not contain entry_hash or entry_hmac/);
  });
});

describe('sealEntry refuses what could never verify', () => {
  it.each([
    ['entry_hash', 'a'.repeat(64)],
    ['entry_hmac', 'b'.repeat(64)],
    ['entry_hash', null],
  ])('a core already carrying %s (%j)', (field, value) => {
    expect(() => sealEntry({ ...core, [field]: value }, KEY)).toThrow(/must not contain entry_hash or entry_hmac/);
  });

  it.each([['an array', []], ['null', null], ['a string', 'x']])('a core that is %s (TypeError)', (_label, bad) => {
    expect(() => sealEntry(bad as never, KEY)).toThrow(TypeError);
  });

  it.each([
    ['a fractional number', { amount: 0.5 }],
    ['an unsafe integer', { amount: 2 ** 53 }],
    ['a lone surrogate', { note: String.fromCharCode(0xd800) }],
    ['a value nested deeper than MAX_DEPTH', { deep: nested(MAX_DEPTH) }],
  ])('a core holding %s (outside the canonical domain)', (_label, over) => {
    expect(() => sealEntry({ ...core, ...over }, KEY)).toThrow(CanonicalizationError);
  });

  it('accepts the deepest value the canonical domain allows', () => {
    expect(() => sealEntry({ ...core, deep: nested(MAX_DEPTH - 1) }, KEY)).not.toThrow();
  });
});

describe('InMemoryKeyProvider', () => {
  it('refuses an activeId that is not in the keyring', () => {
    expect(() => new InMemoryKeyProvider({ k1: Buffer.alloc(32) }, 'k2')).toThrow(/not present/);
  });

  it('keeps its own copy: wiping the buffer it was given changes nothing afterwards', () => {
    const secret = Buffer.alloc(32, 7);
    const provider = new InMemoryKeyProvider({ k1: secret }, 'k1');
    secret.fill(0); // the caller wipes its copy, as it should
    const entry = appendEntry(null, draft(0), provider);
    expect(verifyChain([entry], new InMemoryKeyProvider({ k1: Buffer.alloc(32, 7) }, 'k1')).ok).toBe(true);
    expect(verifyChain([entry], new InMemoryKeyProvider({ k1: Buffer.alloc(32, 0) }, 'k1')).ok).toBe(false);
  });

  it('hands out copies: writing into a returned key does not change the stored one', () => {
    const provider = new InMemoryKeyProvider({ k1: Buffer.alloc(32, 7) }, 'k1');
    provider.getKey('k1')!.fill(0);
    expect(provider.getKey('k1')).toEqual(Buffer.alloc(32, 7));
  });

  it('stores exactly the bytes of a view, not the rest of its underlying buffer', () => {
    const backing = new Uint8Array(40).fill(5);
    backing.fill(9, 8, 24);
    const provider = new InMemoryKeyProvider({ k1: backing.subarray(8, 24) }, 'k1');
    expect(provider.getKey('k1')).toEqual(Buffer.alloc(16, 9));
  });

  it('measures a string key in UTF-8 bytes, not UTF-16 units', () => {
    const e = String.fromCharCode(0xe9); // 2 UTF-8 bytes, 1 UTF-16 unit
    expect(() => new InMemoryKeyProvider({ k: e.repeat(8) }, 'k')).not.toThrow(); // 16 bytes
    expect(() => new InMemoryKeyProvider({ k: e.repeat(7) }, 'k')).toThrow(/at least 16/); // 14 bytes
  });
});
