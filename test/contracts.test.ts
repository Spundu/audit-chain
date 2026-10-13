import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, vi } from 'vitest';
import { CanonicalizationError, canonicalize } from '../src/canonicalize.js';
import { jsonlEntryAt, toJsonlLine } from '../src/jsonl.js';
import { InMemoryKeyProvider } from '../src/keys.js';
import { appendEntry, type SealedEntry } from '../src/seal.js';
import { verifyChain, verifyEntries, type ChainStep } from '../src/verify.js';
import { JsonlChainWriter } from '../src/writer.js';
import { draft } from './draft.js';

const keys = new InMemoryKeyProvider({ k1: Buffer.alloc(32, 4) }, 'k1');
const LF = String.fromCharCode(10);


function chain(n: number): SealedEntry[] {
  const out: SealedEntry[] = [];
  let prev: SealedEntry | null = null;
  for (let i = 0; i < n; i += 1) {
    prev = appendEntry(prev, draft(i), keys);
    out.push(prev);
  }
  return out;
}

describe('verifyEntries: an unreadable step breaks the chain, whatever the reason type', () => {
  it.each([
    ['a string', 'disk read error'],
    ['an array', ['E_IO', 'disk read error']],
    ['a Buffer', Buffer.from('x')],
    ['null', null],
    ['a number', 5],
    ['an Error', new Error('boom')],
    ['an object with a throwing toString', { toString: () => { throw new Error('no'); } }],
  ])('%s', (_label, reason) => {
    const entries = chain(2);
    const next = (i: number): ChainStep => (i < 2 ? { entry: entries[i] } : i === 2 ? ({ unreadable: reason } as never) : null);
    const result = verifyEntries(next, keys);
    expect(result).toMatchObject({ ok: false, lastSeq: 1, brokenAt: 2 });
    expect(typeof result.reason).toBe('string'); // VerifyResult.reason is text, whatever the caller passed
    const middle = (i: number): ChainStep => (i === 0 ? { entry: entries[0] } : i === 1 ? ({ unreadable: reason } as never) : i === 2 ? { entry: entries[1] } : null);
    expect(verifyEntries(middle, keys, { count: 3, lastHash: entries[1]!.entry_hash })).toMatchObject({ ok: false, lastSeq: 0 });
  });
});

describe('anchors and checkpoints of the wrong shape fail closed', () => {
  it.each([
    ['count missing', { lastHash: 'x' }],
    ['lastHash missing', { count: 2 }],
    ['snake_case last_hash', { count: 2, last_hash: 'x' }],
    ['empty object', {}],
  ])('verifyChain refuses an anchor with %s', (_label, anchor) => {
    const entries = chain(2);
    expect(verifyChain(entries, keys, anchor as never).ok).toBe(false);
  });

  it.each([['null', null], ['a number', 2], ['a string', 'head']])('the writer refuses a checkpoint that is %s', (_label, checkpoint) => {
    const dir = mkdtempSync(join(tmpdir(), 'audit-chain-contracts-'));
    try {
      const path = join(dir, 'c.jsonl');
      new JsonlChainWriter(path, keys).append(draft(0));
      expect(() => new JsonlChainWriter(path, keys, checkpoint as never)).toThrow(TypeError);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('API-only totality and helpers', () => {
  it('a collection whose length cannot be read vouches for nothing', () => {
    const entries = chain(2);
    const proxy = new Proxy(entries, { get: (t, p) => (p === 'length' ? (() => { throw new Error('no'); })() : Reflect.get(t, p)) });
    expect(verifyChain(proxy, keys)).toMatchObject({ ok: false, lastSeq: -1 });
  });

  it('jsonlEntryAt returns undefined past the end, on an empty file and on a torn tail', () => {
    const data = Buffer.from(chain(2).map((e) => toJsonlLine(e)).join(''), 'utf8');
    expect(jsonlEntryAt(data, 1)).toBeDefined();
    expect(jsonlEntryAt(data, 2)).toBeUndefined();
    expect(jsonlEntryAt(Buffer.alloc(0), 0)).toBeUndefined();
    expect(jsonlEntryAt(Buffer.concat([data, Buffer.from('{"torn')]), 2)).toBeUndefined();
  });
});

describe('the size budget bounds work for every construct it charges', () => {
  it.each([
    ['single-element arrays', (x: unknown) => [x, x]],
    ['single-member objects', (x: unknown) => ({ k: x, j: x })],
    ['arrays of nulls and booleans', (x: unknown) => [x, null, true, false, x]],
    ['objects of short numbers and empty strings', (x: unknown) => ({ a: x, b: 0, c: '', d: x })],
    ['empty containers', (x: unknown) => [x, [], {}, x]],
    ['empty strings', (x: unknown) => [x, '', '', x]],
  ])('a doubling DAG of %s is rejected fast', (_label, wrap) => {
    let tree: unknown = 0;
    for (let i = 0; i < 40; i += 1) tree = wrap(tree);
    const start = Date.now();
    expect(() => canonicalize(tree)).toThrow(CanonicalizationError);
    expect(Date.now() - start).toBeLessThan(5000);
  });
});

describe('the size budget charges array brackets (a deterministic work count, not wall time)', () => {
  it('a million references to a 98-deep single-element array are refused after a bounded number of containers', () => {
    // Each reference is ~196 bracket bytes and 2 other bytes. Charged, the budget trips after ~5,300
    // references; uncharged, only after ~500,000, i.e. about MAX_DEPTH times more containers visited.
    let deep: unknown = 0;
    for (let i = 0; i < 98; i += 1) deep = [deep];
    const value = Array.from({ length: 1_000_000 }, () => deep);
    let containers = 0;
    const isArray = Array.isArray;
    const spy = vi.spyOn(Array, 'isArray').mockImplementation((v: unknown): v is unknown[] => {
      containers += 1;
      if (containers > 5_000_000) throw new Error('unbounded work');
      return isArray(v);
    });
    try {
      expect(() => canonicalize(value)).toThrow(CanonicalizationError);
    } finally {
      spy.mockRestore();
    }
    expect(containers).toBeLessThan(1_500_000);
  });
});

describe('vector generator self-check is wired in (source-level)', () => {
  it('both text and size vectors go through checkMust', () => {
    const src = readFileSync(join(__dirname, '..', 'scripts', 'emit-jcs-vectors.mts'), 'utf8');
    expect(src).toMatch(/checkMust\('text vector'/);
    expect(src).toMatch(/checkMust\('size vector'/);
    expect(src.split(LF).some((l) => l.includes("from './vector-guard.mjs'"))).toBe(true);
  });
});

describe('more API contracts', () => {
  it('an element whose read throws breaks the chain AT that index (with or without an anchor)', () => {
    const entries = chain(3);
    const proxy = new Proxy(entries, {
      get: (t, p) => (p === '1' ? (() => { throw new Error('no'); })() : Reflect.get(t, p)),
    });
    expect(verifyChain(proxy, keys)).toMatchObject({ ok: false, lastSeq: 0, brokenAt: 1 });
    expect(verifyChain(proxy, keys, { count: 3, lastHash: entries[2]!.entry_hash })).toMatchObject({ ok: false, brokenAt: 1 });
  });

  it('a step carrying both entry and unreadable is unreadable', () => {
    const entries = chain(2);
    const next = (i: number): ChainStep => (i === 0 ? ({ entry: entries[0], unreadable: 'x' } as never) : i === 1 ? { entry: entries[1] } : null);
    expect(verifyEntries(next, keys)).toMatchObject({ ok: false, lastSeq: -1, brokenAt: 0 });
  });

  it.each([['false', false], ['zero', 0], ['empty string', ''], ['a number', 3], ['a string', 'head']])(
    'an anchor that is %s is a TypeError, not "no anchor"',
    (_label, anchor) => {
      expect(() => verifyChain(chain(2), keys, anchor as never)).toThrow(TypeError);
    },
  );

  it('undefined and null mean "no anchor"', () => {
    expect(verifyChain(chain(2), keys, undefined).ok).toBe(true);
    expect(verifyChain(chain(2), keys, null as never).ok).toBe(true);
  });

  it('accepts plain Uint8Array input, including a subarray with a non-zero byteOffset', async () => {
    const { verifyJsonl, parseJsonl, jsonlLineCount } = await import('../src/jsonl.js');
    const bytes = Buffer.from(chain(2).map((e) => toJsonlLine(e)).join(''), 'utf8');
    const plain = new Uint8Array(bytes);
    expect(verifyJsonl(plain, keys)).toMatchObject({ ok: true, lastSeq: 1 });
    const padded = new Uint8Array(bytes.length + 7);
    padded.set(bytes, 7);
    const view = padded.subarray(7);
    expect(view.byteOffset).toBe(7);
    expect(verifyJsonl(view, keys)).toMatchObject({ ok: true, lastSeq: 1 });
    expect(parseJsonl(view).entries).toHaveLength(2);
    expect(jsonlLineCount(view)).toBe(2);
    expect(jsonlEntryAt(view, 1)).toBeDefined();
  });

  it('parseJson refuses a String wrapper object', async () => {
    const { parseJson } = await import('../src/json.js');
    expect(() => parseJson(new String('1') as never)).toThrow(TypeError);
  });
});
