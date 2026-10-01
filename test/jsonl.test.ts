import { createHash, createHmac } from 'node:crypto';
import { describe, it, expect, vi } from 'vitest';
import { MAX_CANONICAL_BYTES, MAX_DEPTH, canonicalize } from '../src/canonicalize.js';
import { jsonlEntryAt, jsonlLineCount, parseJsonl, verifyJsonl } from '../src/jsonl.js';
import { InMemoryKeyProvider } from '../src/keys.js';

const KEY = Buffer.alloc(32, 9);
const keys = new InMemoryKeyProvider({ k1: KEY }, 'k1');
const LF = String.fromCharCode(10);

function seal(core: Record<string, unknown>): Record<string, unknown> {
  const bytes = canonicalize(core);
  return {
    ...core,
    entry_hash: createHash('sha256').update(bytes, 'utf8').digest('hex'),
    entry_hmac: createHmac('sha256', KEY).update(bytes, 'utf8').digest('hex'),
  };
}

describe('verifyJsonl / parseJsonl', () => {
  it('verifies a sealed line of EXACTLY max_canonical_bytes (the pre-decode length check is not off by one)', () => {
    const base = { seq: 0, prev_hash: '0'.repeat(64), writer_key_id: 'k1', pad: '' };
    const overhead = Buffer.byteLength(canonicalize(seal(base)), 'utf8');
    const line = canonicalize(seal({ ...base, pad: 'x'.repeat(MAX_CANONICAL_BYTES - overhead) }));
    expect(Buffer.byteLength(line, 'utf8')).toBe(MAX_CANONICAL_BYTES);
    expect(verifyJsonl(Buffer.from(line + LF, 'utf8'), keys)).toMatchObject({ ok: true, lastSeq: 0 });
  });

  it('reports a line whose value is outside the canonical domain as bad, with no entry for it', () => {
    const good = canonicalize(seal({ seq: 0, prev_hash: '0'.repeat(64), writer_key_id: 'k1' }));
    const parsed = parseJsonl(Buffer.from(`${good}${LF}[1.5]${LF}`, 'utf8'));
    expect(parsed.badLine).toBe(1);
    expect(parsed.entries).toHaveLength(1);
  });

  it(`refuses a line nested deeper than MAX_DEPTH (${MAX_DEPTH}) in the PARSER, before recursing further`, () => {
    const nest = (n: number): string => '['.repeat(n) + ']'.repeat(n);
    expect(parseJsonl(Buffer.from(nest(MAX_DEPTH) + LF, 'utf8'))).toMatchObject({ badLine: null });
    // Not "outside the canonical domain": the parser itself stops, so a short hostile line costs the
    // caller's stack little more than a legitimate one.
    expect(parseJsonl(Buffer.from(nest(MAX_DEPTH + 1) + LF, 'utf8'))).toMatchObject({ badLine: 0, reason: 'line is not valid JSON' });
    expect(parseJsonl(Buffer.from(nest(1000) + LF, 'utf8'))).toMatchObject({ badLine: 0, reason: 'line is not valid JSON' });
  });

  it('refuses an over-limit line BEFORE decoding or parsing it (a huge line costs no decoding work)', () => {
    const decode = vi.spyOn(TextDecoder.prototype, 'decode');
    try {
      const line = Buffer.alloc(MAX_CANONICAL_BYTES + 1, 0x61);
      expect(verifyJsonl(Buffer.concat([line, Buffer.from(LF)]), keys)).toMatchObject({ ok: false, brokenAt: 0, reason: 'line exceeds the canonical size limit' });
      expect(parseJsonl(Buffer.concat([line, Buffer.from(LF)]))).toMatchObject({ badLine: 0 });
      expect(decode).not.toHaveBeenCalled();
    } finally {
      decode.mockRestore();
    }
  });

  it('never searches with Buffer.prototype.indexOf, which is wrong past 2 GiB (clamped offset, int32 result)', () => {
    const line = canonicalize(seal({ seq: 0, prev_hash: '0'.repeat(64), writer_key_id: 'k1' }));
    const file = Buffer.from(line + LF + line + LF, 'utf8');
    const spy = vi.spyOn(Buffer.prototype, 'indexOf');
    try {
      verifyJsonl(file, keys);
      parseJsonl(file);
      jsonlEntryAt(file, 1);
      expect(jsonlLineCount(file)).toBe(2);
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  // Opt-in (allocates over 2 GiB): AUDIT_CHAIN_BIG_TESTS=1 npx vitest run test/jsonl.test.ts
  it.skipIf(!process.env.AUDIT_CHAIN_BIG_TESTS)('finds every line feed in a Buffer over 2 GiB', () => {
    const size = 2 ** 31 + 64;
    const data = Buffer.alloc(size, 32);
    for (const at of [100, 2 ** 31 + 4, size - 1]) data[at] = 10;
    expect(jsonlLineCount(data)).toBe(3);
    expect(parseJsonl(data)).toMatchObject({ badLine: 0 });
  }, 600_000);
});
