import { describe, it, expect, expectTypeOf } from 'vitest';
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

  it.each([
    ['a Map', new Map([['event', 'login']])],
    ['an Error', new Error('disk full')],
    ['a Date', new Date(0)],
    ['a class instance', new (class LoginRecord { event = 'login'; })()],
  ])('refuses %s instead of sealing it as an empty record (TypeError)', (_label, bad) => {
    expect(() => appendEntry(null, bad, keys)).toThrow(TypeError);
    expect(() => sealEntry(bad, KEY)).toThrow(TypeError);
  });

  it('accepts a null-prototype record, as some JSON parsers produce', () => {
    const record = Object.assign(Object.create(null) as Record<string, unknown>, { event: 'login' });
    expect(verifyChain([appendEntry(null, record, keys)], keys).ok).toBe(true);
  });

  it('refuses a draft carrying a derived field: it would be sealed but never verify', () => {
    expect(() => appendEntry(null, { ...draft(0), entry_hmac: 'x' }, keys)).toThrow(/must not contain entry_hash or entry_hmac/);
  });
});

describe('appendEntry refuses a prev it could only extend into a chain that never verifies', () => {
  const head = appendEntry(null, draft(0), keys);

  it.each([
    ['seq as a string (a BIGINT read back as text)', { ...head, seq: '0' }],
    ['seq null', { ...head, seq: null }],
    ['a fractional seq', { ...head, seq: 0.5 }],
    ['a negative seq', { ...head, seq: -1 }],
    ['seq true', { ...head, seq: true }],
    ['an unsafe seq', { ...head, seq: 2 ** 53 }],
    ['no entry_hash', { seq: 0 }],
    ['an uppercase entry_hash', { ...head, entry_hash: head.entry_hash.toUpperCase() }],
    ['a short entry_hash', { ...head, entry_hash: head.entry_hash.slice(1) }],
    ['a string', 'head'],
    ['a number', 7],
  ])('%s (TypeError, as in Python)', (_label, prev) => {
    expect(() => appendEntry(prev as never, draft(1), keys)).toThrow(TypeError);
  });

  it('treats undefined as null: the chain is empty', () => {
    expect(appendEntry(undefined, draft(0), keys)).toMatchObject({ seq: 0, prev_hash: GENESIS_HASH });
  });

  it('refuses a provider whose active key id is not a string (TypeError)', () => {
    const numeric = { getKey: () => KEY, activeKeyId: () => 1 };
    expect(() => appendEntry(null, draft(0), numeric as never)).toThrow(TypeError);
  });
});

describe('record types', () => {
  it('accepts an interface, and keeps each member of a union (checked by tsc)', () => {
    interface Login { event: 'login'; user: string }
    interface Refund { event: 'refund'; amount_pence: number }
    const entry = appendEntry<Login | Refund>(null, { event: 'refund', amount_pence: 1900 }, keys);
    expectTypeOf(entry.seq).toEqualTypeOf<number>();
    expectTypeOf(entry.entry_hash).toEqualTypeOf<string>();
    if (entry.event === 'refund') expectTypeOf(entry.amount_pence).toEqualTypeOf<number>();
    expect(entry).toMatchObject({ event: 'refund', amount_pence: 1900, seq: 0 });
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

  it('keeps keys in memory of their own, never in the shared Buffer pool', () => {
    // The caller's key is a small Buffer.from(), so it sits in Node's shared pool next to other buffers.
    const provider = new InMemoryKeyProvider({ k1: Buffer.from('07'.repeat(32), 'hex') }, 'k1');
    const out = provider.getKey('k1')!;
    expect(out.buffer.byteLength).toBe(32); // exactly the key: no neighbours to wipe, or be wiped by
    new Uint8Array(out.buffer).fill(0);
    expect(provider.getKey('k1')).toEqual(Buffer.alloc(32, 7));
  });

  it('copies a key by its real length, whatever its length getters claim', () => {
    const key = new Uint8Array(32).fill(9);
    Object.defineProperty(key, 'length', { get: () => 48 });
    Object.defineProperty(key, 'byteLength', { get: () => 48 });
    expect(new InMemoryKeyProvider({ k1: key }, 'k1').getKey('k1')).toEqual(Buffer.alloc(32, 9));
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
