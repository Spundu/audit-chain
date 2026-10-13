import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';
import { CanonicalizationError, MAX_CANONICAL_BYTES, canonicalize } from '../src/canonicalize.js';
import { JsonSyntaxError, parseJson } from '../src/json.js';
import { jsonlEntryAt, jsonlLineCount, parseJsonl, toJsonlLine, verifyJsonl } from '../src/jsonl.js';
import { InMemoryKeyProvider } from '../src/keys.js';
import { appendEntry, type SealedEntry } from '../src/seal.js';
import { verifyEntries, type ChainStep } from '../src/verify.js';
import { JsonlChainWriter } from '../src/writer.js';
import { draft } from './draft.js';

const keys = new InMemoryKeyProvider({ k1: Buffer.alloc(32, 3) }, 'k1');
const LF = String.fromCharCode(10);
const CR = String.fromCharCode(13);


function chain(n: number, over: Record<string, unknown> = {}): SealedEntry[] {
  const out: SealedEntry[] = [];
  let prev: SealedEntry | null = null;
  for (let i = 0; i < n; i += 1) {
    prev = appendEntry(prev, draft(i, over), keys);
    out.push(prev);
  }
  return out;
}

const fileOf = (entries: SealedEntry[]): Buffer => Buffer.from(entries.map((e) => toJsonlLine(e)).join(''), 'utf8');

describe('verifyEntries: a failing SOURCE is an infrastructure error, not tampering', () => {
  it('propagates an exception thrown by next() mid-stream, with or without an anchor', () => {
    const entries = chain(4);
    const next = (i: number): ChainStep => {
      if (i === 2) throw new Error('ETIMEDOUT: db cursor');
      return i < entries.length ? { entry: entries[i] } : null;
    };
    expect(() => verifyEntries(next, keys)).toThrow('ETIMEDOUT');
    expect(() => verifyEntries(next, keys, { count: 4, lastHash: entries[3]!.entry_hash })).toThrow('ETIMEDOUT');
  });

  it('reports an explicitly unreadable entry as a broken chain at that index', () => {
    const entries = chain(3);
    const next = (i: number): ChainStep => (i === 1 ? { unreadable: 'corrupt row' } : i < 3 ? { entry: entries[i] } : null);
    expect(verifyEntries(next, keys)).toMatchObject({ ok: false, lastSeq: 0, brokenAt: 1, reason: 'corrupt row' });
  });

  it('throws TypeError for a malformed step (a programming error)', () => {
    expect(() => verifyEntries(() => undefined as never, keys)).toThrow(TypeError);
    expect(() => verifyEntries(() => ({ nothing: 1 }) as never, keys)).toThrow(TypeError);
  });
});

describe('torn tail and multi-line files', () => {
  it('a complete final entry whose line feed became a carriage return is torn at that line', () => {
    const data = Buffer.from(fileOf(chain(3)).toString('utf8').slice(0, -1) + CR, 'utf8');
    expect(verifyJsonl(data, keys)).toMatchObject({ ok: false, lastSeq: 1, brokenAt: 2 });
    const parsed = parseJsonl(data);
    expect(parsed.badLine).toBe(2);
    expect(parsed.entries).toHaveLength(2);
  });

  it('verifies a file of several large lines totalling over 1 MiB (the size bound is per line)', () => {
    const entries = chain(4, { note: 'x'.repeat(400_000) });
    const data = fileOf(entries);
    // The last line STARTS past 1 MiB: the limit applies to each line's length, not to where it starts.
    expect(data.lastIndexOf(10, data.length - 2) + 1).toBeGreaterThan(MAX_CANONICAL_BYTES);
    expect(verifyJsonl(data, keys)).toMatchObject({ ok: true, lastSeq: 3 });
  });
});

describe('writer checkpoint at the current head', () => {
  it('starts when the checkpoint IS the head, and continues the chain', () => {
    const dir = mkdtempSync(join(tmpdir(), 'audit-chain-engine-'));
    try {
      const path = join(dir, 'c.jsonl');
      const w = new JsonlChainWriter(path, keys);
      w.append(draft(0));
      const head = w.append(draft(1));
      const restarted = new JsonlChainWriter(path, keys, { count: 2, lastHash: head.entry_hash });
      expect(restarted.append(draft(2)).seq).toBe(2);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('input-type contracts of the exported helpers', () => {
  it.each([['null', null], ['a number', 1], ['bytes', Buffer.from('{}')]])('parseJson throws TypeError for %s', (_l, v) => {
    expect(() => parseJson(v as never)).toThrow(TypeError);
  });

  it('jsonlEntryAt and jsonlLineCount require bytes and count only terminated lines', () => {
    expect(() => jsonlEntryAt('x' as never, 0)).toThrow(TypeError);
    expect(() => jsonlLineCount('x' as never)).toThrow(TypeError);
    expect(jsonlLineCount(Buffer.from(LF + LF))).toBe(2);
    expect(jsonlLineCount(Buffer.from(`a${LF}b`))).toBe(1);
    expect(jsonlLineCount(Buffer.alloc(0))).toBe(0);
  });

  it('error classes carry their own names', () => {
    expect(new CanonicalizationError('x').name).toBe('CanonicalizationError');
    expect(new JsonSyntaxError('x').name).toBe('JsonSyntaxError');
  });
});

describe('the size budget bounds work on shared-reference trees with EMPTY leaves', () => {
  it('rejects a doubling tree of empty strings and short keys fast', () => {
    let tree: unknown = '';
    for (let i = 0; i < 40; i += 1) tree = { a: tree, b: [tree, tree] };
    const start = Date.now();
    expect(() => canonicalize(tree)).toThrow(CanonicalizationError);
    expect(Date.now() - start).toBeLessThan(5000);
  });
});
