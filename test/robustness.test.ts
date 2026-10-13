import { createHash, createHmac, createSecretKey } from 'node:crypto';
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';
import * as api from '../src/index.js';
import { CanonicalizationError, canonicalize } from '../src/canonicalize.js';
import { parseJson } from '../src/json.js';
import { jsonlEntryAt, jsonlLineCount, parseJsonl, toJsonlLine, verifyJsonl } from '../src/jsonl.js';
import { InMemoryKeyProvider } from '../src/keys.js';
import { appendEntry, sealEntry, type SealedEntry } from '../src/seal.js';
import { verifyChain, verifyEntries } from '../src/verify.js';
import { JsonlChainWriter, readChain } from '../src/writer.js';
import { draft } from './draft.js';

const KEY = Buffer.alloc(32, 7);
const keys = new InMemoryKeyProvider({ k1: KEY }, 'k1');
const LF = String.fromCharCode(10);


function chainBytes(n: number): Buffer {
  let prev: SealedEntry | null = null;
  let out = '';
  for (let i = 0; i < n; i += 1) {
    prev = appendEntry(prev, draft(i), keys);
    out += toJsonlLine(prev);
  }
  return Buffer.from(out, 'utf8');
}

function withTmp(fn: (path: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), 'audit-chain-robust-'));
  try {
    fn(join(dir, 'chain.jsonl'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('JSONL verification is streaming: junk costs no more than its first bad line', () => {
  it('rejects 64 MiB of line feeds at line 0, fast and without holding the lines', () => {
    const start = Date.now();
    const heapBefore = process.memoryUsage().heapUsed;
    expect(verifyJsonl(Buffer.alloc(64 * 2 ** 20, 10), keys)).toMatchObject({ ok: false, brokenAt: 0 });
    expect(Date.now() - start).toBeLessThan(5000);
    expect(process.memoryUsage().heapUsed - heapBefore).toBeLessThan(64 * 2 ** 20);
  });

  it('rejects 16 MiB of valid-but-meaningless lines at line 0', () => {
    expect(verifyJsonl(Buffer.alloc(16 * 2 ** 20, `0${LF}`), keys)).toMatchObject({ ok: false, brokenAt: 0 });
    expect(verifyJsonl(Buffer.alloc(16 * 2 ** 20, `{}${LF}`), keys)).toMatchObject({ ok: false, brokenAt: 0 });
  });

  it('breaks a legitimate chain followed by 32 MiB of line feeds at the first junk line', () => {
    const data = Buffer.concat([chainBytes(3), Buffer.alloc(32 * 2 ** 20, 10)]);
    expect(verifyJsonl(data, keys)).toMatchObject({ ok: false, lastSeq: 2, brokenAt: 3 });
  });

  it('makes the writer refuse (not crash) at start-up on a chain followed by 32 MiB of line feeds', () => {
    withTmp((path) => {
      writeFileSync(path, chainBytes(3));
      appendFileSync(path, Buffer.alloc(32 * 2 ** 20, 10));
      expect(() => new JsonlChainWriter(path, keys)).toThrow(/refusing to append.*entry 3/);
    });
  });
});

describe('writer-stamped fields', () => {
  it('seq, prev_hash and writer_key_id come from the writer, never from the draft', () => {
    const e0 = appendEntry(null, draft(0), keys);
    const forged = { ...draft(1), seq: 5, prev_hash: 'f'.repeat(64), writer_key_id: 'other' };
    const e1 = appendEntry(e0, forged, keys);
    expect(e1).toMatchObject({ seq: 1, prev_hash: e0.entry_hash, writer_key_id: 'k1' });
    expect(verifyChain([e0, e1], keys).ok).toBe(true);
  });
});

describe('non-ASCII content through seal and writer', () => {
  it('round-trips accented, CJK and astral characters through the writer and verifies', () => {
    withTmp((path) => {
      const w = new JsonlChainWriter(path, keys);
      const text = `caf${String.fromCharCode(0xe9)} ${String.fromCharCode(0x65e5)} ${String.fromCodePoint(0x1f600)}`;
      w.append({ ...draft(0), [text]: text, nested: { note: text } });
      expect(verifyJsonl(readFileSync(path), keys).ok).toBe(true);
      expect(() => new JsonlChainWriter(path, keys)).not.toThrow();
      expect(readChain(path, keys)[0]).toMatchObject({ [text]: text, nested: { note: text } });
    });
  });
});

describe('readChain returns only what verifies', () => {
  it('returns a verified entry of any record shape, sealed by any writer', () => {
    withTmp((path) => {
      const foreign = { seq: 0, prev_hash: '0'.repeat(64), writer_key_id: 'k1', note: 'other shape' };
      const bytes = canonicalize(foreign);
      const sealed = {
        ...foreign,
        entry_hash: createHash('sha256').update(bytes, 'utf8').digest('hex'),
        entry_hmac: createHmac('sha256', KEY).update(bytes, 'utf8').digest('hex'),
      };
      writeFileSync(path, toJsonlLine(sealed));
      expect(readChain(path, keys)).toEqual([sealed]);
    });
  });

  it('refuses a file holding an entry that was never sealed', () => {
    withTmp((path) => {
      const { entry_hmac: _m, ...unsealed } = appendEntry(null, draft(0), keys);
      writeFileSync(path, toJsonlLine(unsealed));
      expect(() => readChain(path, keys)).toThrow(/does not verify: it breaks at entry 0/);
    });
  });
});

describe('the size budget bounds the WORK, not just the result', () => {
  it('rejects many references to one ~1 MB string fast, and to one long key', () => {
    const big = 'x'.repeat(1_000_000);
    const start = Date.now();
    expect(() => canonicalize(Array.from({ length: 5000 }, () => big))).toThrow(CanonicalizationError);
    const withKey = { [big]: 1 };
    expect(() => canonicalize(Array.from({ length: 5000 }, () => withKey))).toThrow(CanonicalizationError);
    expect(Date.now() - start).toBeLessThan(5000);
  });
});

describe('package entry point', () => {
  it.each([
    'canonicalize', 'CanonicalizationError', 'MAX_CANONICAL_BYTES', 'MAX_DEPTH', 'parseJson', 'JsonSyntaxError',
    'parseJsonl', 'verifyJsonl', 'toJsonlLine', 'InMemoryKeyProvider', 'MIN_KEY_BYTES', 'GENESIS_HASH',
    'nextState', 'appendEntry', 'sealEntry', 'verifyChain', 'verifyEntries', 'JsonlChainWriter', 'readChain',
  ])('exports %s', (name) => {
    expect((api as Record<string, unknown>)[name]).toBeDefined();
  });
});

describe('API contracts', () => {
  it.each([
    ['a string', 'x'], ['a number', 3], ['null', null], ['an array', [10]],
    // EMPTY non-bytes too: they have no line to trip over, so only the explicit type check refuses them.
    ['an empty string', ''], ['an empty array', []], ['an empty ArrayBuffer', new ArrayBuffer(0)], ['a length-0 object', { length: 0 }],
    // Other typed arrays and views are not bytes, even when they hold a line feed.
    ['a Uint16Array', new Uint16Array([10])], ['an Int8Array', new Int8Array([10])], ['a Float64Array', new Float64Array([10])],
    ['a DataView', new DataView(new ArrayBuffer(1))],
  ])('every JSONL function throws TypeError for %s', (_label, data) => {
    expect(() => parseJsonl(data as never)).toThrow(TypeError);
    expect(() => verifyJsonl(data as never, keys)).toThrow(TypeError);
    expect(() => jsonlEntryAt(data as never, 0)).toThrow(TypeError);
    expect(() => jsonlLineCount(data as never)).toThrow(TypeError);
  });

  it.each([
    ['null', null], ['undefined', undefined], ['a plain object', { k1: KEY }], ['a Map', new Map([['k1', KEY]])],
    ['a string', 'k1'], ['a number', 42],
  ])('rejects %s as the keys UP FRONT, whatever the input (as Python rejects a non-mapping keyring)', (_label, bad) => {
    expect(() => verifyChain([], bad as never)).toThrow(TypeError);
    expect(() => verifyChain({}, bad as never)).toThrow(TypeError); // before the entries are even looked at
    expect(() => verifyJsonl(new Uint8Array(0), bad as never)).toThrow(TypeError);
    expect(() => verifyEntries(() => null, bad as never)).toThrow(TypeError);
    withTmp((path) => expect(() => new JsonlChainWriter(path, bad as never)).toThrow(TypeError));
  });

  it.each([['a string getKey', { getKey: 'k1' }], ['a numeric getKey', { getKey: 1 }]])('rejects %s up front', (_label, bad) => {
    expect(() => verifyChain([], bad as never)).toThrow(TypeError);
  });

  it('accepts a FUNCTION carrying getKey and activeKeyId as a provider (verify and writer)', () => {
    const provider = Object.assign(() => undefined, { getKey: (id: string) => (id === 'k1' ? KEY : null), activeKeyId: () => 'k1' });
    expect(verifyChain([], provider as never).ok).toBe(true);
    withTmp((path) => {
      const writer = new JsonlChainWriter(path, provider as never);
      writer.append(draft(0));
      expect(verifyJsonl(readFileSync(path), keys).ok).toBe(true);
    });
  });

  // Keys are BYTES (a Uint8Array such as a Buffer), measured in bytes: anything else is no key at all.
  it.each([
    ['an ArrayBuffer', new ArrayBuffer(32)],
    ['a DataView', new DataView(new ArrayBuffer(32))],
    ['a Uint16Array (16 elements, 32 bytes, but not bytes)', new Uint16Array(16)],
    ['a secret KeyObject', createSecretKey(Buffer.alloc(32, 7))],
    ['a string', 'x'.repeat(32)],
    ['a length-only object', { length: 64 }],
  ])('treats %s as no key: verify breaks, sealing and the in-memory keyring refuse', (_label, notBytes) => {
    const entry = appendEntry(null, draft(0), keys);
    const provider = { getKey: () => notBytes, activeKeyId: () => 'k1' };
    expect(verifyChain([entry], provider as never)).toMatchObject({ ok: false, brokenAt: 0, reason: 'unknown writer_key_id' });
    const { entry_hash: _h, entry_hmac: _m, ...core } = entry;
    expect(() => sealEntry(core as never, notBytes as never)).toThrow(/at least 16 bytes/);
    // (InMemoryKeyProvider alone also takes a string, which it documents as UTF-8 key bytes.)
    if (typeof notBytes !== 'string') expect(() => new InMemoryKeyProvider({ k: notBytes as never }, 'k')).toThrow(/at least 16 bytes/);
  });

  it('accepts a plain Uint8Array key of 16 bytes, and a Buffer view into a larger buffer', () => {
    const plain = new Uint8Array(16).fill(3);
    const view = Buffer.from(new Uint8Array(40).fill(5).buffer, 8, 16);
    for (const k of [plain, view]) {
      const provider = new InMemoryKeyProvider({ k1: k as never }, 'k1');
      const entry = appendEntry(null, draft(0), provider);
      expect(verifyChain([entry], provider).ok).toBe(true);
    }
  });

  it('breaks at an array that carries a sealed entry\'s properties (only a plain object is an entry)', () => {
    const entry = appendEntry(null, draft(0), keys);
    expect(verifyChain([Object.assign([], entry)], keys)).toMatchObject({ ok: false, brokenAt: 0 });
  });

  it('a provider without activeKeyId can verify but cannot start a writer', () => {
    const verifyOnly = { getKey: (id: string) => (id === 'k1' ? KEY : null) };
    expect(verifyChain([], verifyOnly as never).ok).toBe(true);
    withTmp((path) => expect(() => new JsonlChainWriter(path, verifyOnly as never)).toThrow(TypeError));
  });

  it('InMemoryKeyProvider looks keys up exactly: no case folding, no prototype members', () => {
    const k = new InMemoryKeyProvider({ Key1: KEY }, 'Key1');
    for (const id of ['key1', 'KEY1', 'Key1 ', '__proto__', 'constructor', 'toString', '']) {
      expect(k.getKey(id)).toBeNull();
    }
    expect(k.getKey('Key1')).toEqual(KEY);
    const lower = new InMemoryKeyProvider({ k1: KEY }, 'k1');
    expect(lower.getKey('K1')).toBeNull();
    expect(lower.getKey('k1 ')).toBeNull();
  });

  it('parseJson members are ordinary writable, enumerable, configurable data properties', () => {
    const value = parseJson('{"a":1,"__proto__":2}') as Record<string, unknown>;
    for (const key of ['a', '__proto__']) {
      expect(Object.getOwnPropertyDescriptor(value, key)).toEqual({ value: key === 'a' ? 1 : 2, writable: true, enumerable: true, configurable: true });
    }
  });

  it('compares HMACs in constant time (source-level guard)', () => {
    const source = readFileSync(join(__dirname, '..', 'src', 'verify.ts'), 'utf8');
    expect(source).toMatch(/timingSafeEqual\(/);
    expect(source).toMatch(/if \(!hexEqual\(recomputedHmac, entry_hmac\)\)/);
  });
});

describe('keys are typed as Uint8Array, not only Buffer', () => {
  it('a plain Uint8Array key seals, verifies and fills an InMemoryKeyProvider (type-checked by tsc)', () => {
    const raw = new Uint8Array(32).fill(9);
    const provider: api.KeyProvider = { getKey: (id: string) => (id === 'k1' ? raw : null), activeKeyId: () => 'k1' };
    const entry = appendEntry(null, draft(0), provider);
    const { entry_hash: _h, entry_hmac: _m, ...core } = entry;
    expect(sealEntry(core, raw)).toEqual(entry);
    expect(verifyChain([entry], provider).ok).toBe(true);
    expect(verifyChain([entry], new InMemoryKeyProvider({ k1: raw }, 'k1')).ok).toBe(true);
  });
});
