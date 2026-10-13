import { describe, it, expect } from 'vitest';
import { createHash, createHmac } from 'node:crypto';
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { CanonicalizationError, canonicalize } from '../src/canonicalize.js';
import { toJsonlLine, verifyJsonl } from '../src/jsonl.js';
import { InMemoryKeyProvider } from '../src/keys.js';
import { JsonlChainWriter, readChain } from '../src/writer.js';
import { verifyChain } from '../src/verify.js';
import { draft, draftTooBigToStore } from './draft.js';

const keys = new InMemoryKeyProvider({ k1: Buffer.alloc(32, 3) }, 'k1');


function withTmp(fn: (path: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), 'audit-chain-writer-'));
  try {
    fn(join(dir, 'audit.jsonl'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('JsonlChainWriter', () => {
  it('appends a verifiable chain of canonical lines', () => {
    withTmp((path) => {
      const writer = new JsonlChainWriter(path, keys);
      for (let i = 0; i < 3; i += 1) writer.append(draft(i));
      const bytes = readFileSync(path);
      for (const line of bytes.toString('utf8').split('\n').slice(0, -1)) {
        expect(canonicalize(JSON.parse(line))).toBe(line);
      }
      expect(verifyJsonl(bytes, keys).ok).toBe(true);
      expect(verifyChain(readChain(path, keys), keys).ok).toBe(true);
    });
  });

  it('recovers the chain tail across a restart and keeps it verifiable', () => {
    withTmp((path) => {
      const before = new JsonlChainWriter(path, keys);
      before.append(draft(0));
      before.append(draft(1));

      // "restart": a fresh writer on the same file must continue, not reset to seq 0.
      const after = new JsonlChainWriter(path, keys);
      expect(after.append(draft(2)).seq).toBe(2);
      expect(verifyJsonl(readFileSync(path), keys).ok).toBe(true);
    });
  });

  it('refuses to start on a forged tail instead of sealing onto a head that can never verify', () => {
    withTmp((path) => {
      const writer = new JsonlChainWriter(path, keys);
      const e1 = writer.append(draft(0));
      appendFileSync(path, `${canonicalize({ ...e1, seq: 1, prev_hash: e1.entry_hash, entry_hash: 'f'.repeat(64) })}\n`);
      expect(() => new JsonlChainWriter(path, keys)).toThrow(/refusing to append/);
    });
  });

  it('refuses to start on a torn final line (crash mid-append) instead of throwing a parse error', () => {
    withTmp((path) => {
      const writer = new JsonlChainWriter(path, keys);
      writer.append(draft(0));
      appendFileSync(path, '{"v":1,"seq":1,');
      expect(() => new JsonlChainWriter(path, keys)).toThrow(/refusing to append.*entry 1/);
    });
  });

  it('refuses a file whose final line feed was removed, instead of fusing the next entry onto it', () => {
    withTmp((path) => {
      const writer = new JsonlChainWriter(path, keys);
      writer.append(draft(0));
      writer.append(draft(1));
      const bytes = readFileSync(path);
      writeFileSync(path, bytes.subarray(0, bytes.length - 1));
      expect(verifyJsonl(readFileSync(path), keys)).toMatchObject({ ok: false, brokenAt: 1 });
      expect(() => new JsonlChainWriter(path, keys)).toThrow(/refusing to append.*entry 1/);
    });
  });

  it('refuses further appends after a failed write, until restarted', () => {
    withTmp((path) => {
      const writer = new JsonlChainWriter(path, keys);
      writer.append(draft(0));
      rmSync(dirname(path), { recursive: true, force: true }); // the next write fails (ENOENT)
      expect(() => writer.append(draft(1))).toThrow();
      mkdirSync(dirname(path), { recursive: true });
      expect(() => writer.append(draft(2))).toThrow(/after a failed write/);
    });
  });

  it('an entry too large to store fails cleanly at seal time and does not latch the writer', () => {
    withTmp((path) => {
      const writer = new JsonlChainWriter(path, keys);
      writer.append(draft(0));
      // A core just under the limit: sealable on its own, but its stored line (core + hashes) is not.
      expect(() => writer.append(draftTooBigToStore(1))).toThrow(CanonicalizationError);
      expect(writer.append(draft(1)).seq).toBe(1);
      expect(verifyJsonl(readFileSync(path), keys).ok).toBe(true);
    });
  });

  it('keeps going after a record holding a Proxy: the head is read back from the line it wrote', () => {
    withTmp((path) => {
      const writer = new JsonlChainWriter(path, keys);
      writer.append({ ...draft(0), state: new Proxy({ count: 1 }, {}) }); // structuredClone refuses a Proxy
      expect(writer.head).toMatchObject({ seq: 0, state: { count: 1 } });
      expect(writer.append(draft(1)).seq).toBe(1);
      expect(verifyJsonl(readFileSync(path), keys)).toMatchObject({ ok: true, lastSeq: 1 });
    });
  });

  it('keeps its head private: mutating a returned entry or the head getter changes nothing', () => {
    withTmp((path) => {
      const writer = new JsonlChainWriter(path, keys);
      const e0 = writer.append(draft(0));
      e0.entry_hash = 'f'.repeat(64);
      writer.head!.seq = 41;
      writer.append(draft(1));
      expect(verifyJsonl(readFileSync(path), keys).ok).toBe(true);
    });
  });

  it('reads each checkpoint field once, so a getter cannot pass validation and then change', () => {
    withTmp((path) => {
      const writer = new JsonlChainWriter(path, keys);
      for (let i = 0; i < 3; i += 1) writer.append(draft(i));
      const LF = String.fromCharCode(10);
      const firstLine = readFileSync(path, 'utf8').split(LF)[0]!;
      writeFileSync(path, firstLine + LF); // truncated to 1 entry
      let reads = 0;
      const shifty = {
        get count() { return reads++ === 0 ? 3 : Number.NaN; },
        get lastHash() { return reads++ < 2 ? 'a'.repeat(64) : undefined; },
      };
      expect(() => new JsonlChainWriter(path, keys, shifty as never)).toThrow(/refusing to append/);
    });
  });

  it('accepts a count-0 checkpoint at the genesis hash, on an empty or a grown file', () => {
    withTmp((path) => {
      const genesis = { count: 0, lastHash: '0'.repeat(64) };
      expect(() => new JsonlChainWriter(path, keys, genesis)).not.toThrow();
      new JsonlChainWriter(path, keys).append(draft(0));
      expect(new JsonlChainWriter(path, keys, genesis).head?.seq).toBe(0);
      expect(() => new JsonlChainWriter(path, keys, { count: 0, lastHash: 'a'.repeat(64) })).toThrow(/checkpoint/);
    });
  });

  it('accepts a checkpoint taken before later appends (the file may have grown since)', () => {
    withTmp((path) => {
      const writer = new JsonlChainWriter(path, keys);
      const e0 = writer.append(draft(0));
      writer.append(draft(1));
      const checkpoint = { count: 1, lastHash: e0.entry_hash };
      expect(new JsonlChainWriter(path, keys, checkpoint).append(draft(2)).seq).toBe(2);
    });
  });

  it('refuses a malformed checkpoint instead of silently skipping the truncation check', () => {
    withTmp((path) => {
      const writer = new JsonlChainWriter(path, keys);
      const e0 = writer.append(draft(0));
      for (const bad of [
        JSON.parse(`{"count":5,"last_hash":"${e0.entry_hash}"}`), // snake_case, as the vectors spell it
        {},
        { count: 5 },
        { count: true, lastHash: e0.entry_hash },
        { count: '1', lastHash: e0.entry_hash },
        { count: -1, lastHash: e0.entry_hash },
        { count: 1.5, lastHash: e0.entry_hash },
        { count: 1, lastHash: e0.entry_hash.toUpperCase() },
        { count: 1, lastHash: 'g'.repeat(64) },
        { count: 1, lastHash: e0.entry_hash.slice(0, 63) },
      ]) {
        expect(() => new JsonlChainWriter(path, keys, bad as never), JSON.stringify(bad)).toThrow(TypeError);
      }
    });
  });

  it('detects a truncated file at restart only when given the anchor', () => {
    withTmp((path) => {
      const writer = new JsonlChainWriter(path, keys);
      writer.append(draft(0));
      const head = writer.append(draft(1));
      const anchor = { count: 2, lastHash: head.entry_hash };
      const firstLine = readFileSync(path, 'utf8').split('\n')[0]!;
      writeFileSync(path, `${firstLine}\n`);
      expect(() => new JsonlChainWriter(path, keys)).not.toThrow(); // invisible without anchor
      expect(() => new JsonlChainWriter(path, keys, anchor)).toThrow(/refusing to append/);
    });
  });

  it('checks the raw BYTES of the file at start-up (a U+FFFD swapped for an invalid byte is refused)', () => {
    withTmp((path) => {
      const writer = new JsonlChainWriter(path, keys);
      writer.append({ ...draft(0), note: `x${String.fromCharCode(0xfffd)}y` });
      const bytes = readFileSync(path);
      const at = bytes.indexOf(Buffer.from([0xef, 0xbf, 0xbd]));
      writeFileSync(path, Buffer.concat([bytes.subarray(0, at), Buffer.from([0xff]), bytes.subarray(at + 3)]));
      expect(() => new JsonlChainWriter(path, keys)).toThrow(/refusing to append.*entry 0/);
    });
  });

  it('refuses a function-valued checkpoint (a checkpoint is a plain object)', () => {
    withTmp((path) => {
      const fn = Object.assign(() => undefined, { count: 0, lastHash: '0'.repeat(64) });
      expect(() => new JsonlChainWriter(path, keys, fn as never)).toThrow(TypeError);
    });
  });

  it('has a null head (never undefined) on a missing or empty file', () => {
    withTmp((path) => {
      expect(new JsonlChainWriter(path, keys).head).toBeNull();
      writeFileSync(path, '');
      expect(new JsonlChainWriter(path, keys).head).toBeNull();
    });
  });

  it('refuses to start on a missing file that has a non-empty checkpoint', () => {
    withTmp((path) => {
      expect(() => new JsonlChainWriter(path, keys, { count: 1, lastHash: 'a'.repeat(64) })).toThrow(
        /no longer contains checkpoint entry 0/,
      );
    });
  });
});

describe('JsonlChainWriter continues any verified chain', () => {
  it('continues a chain whose records have another shape, sealed by another writer', () => {
    withTmp((path) => {
      const k = keys.getKey('k1')!;
      const core = { seq: 0, prev_hash: '0'.repeat(64), writer_key_id: 'k1', note: 'written by another writer' };
      const bytes = canonicalize(core);
      const entry = {
        ...core,
        entry_hash: createHash('sha256').update(bytes, 'utf8').digest('hex'),
        entry_hmac: createHmac('sha256', k).update(bytes, 'utf8').digest('hex'),
      };
      writeFileSync(path, toJsonlLine(entry));
      const writer = new JsonlChainWriter(path, keys);
      expect(writer.head).toEqual(entry);
      expect(writer.append(draft(1)).prev_hash).toBe(entry.entry_hash);
      expect(verifyJsonl(readFileSync(path), keys)).toMatchObject({ ok: true, lastSeq: 1 });
    });
  });
});

describe('readChain', () => {
  it('returns [] for a file that does not exist', () => {
    withTmp((path) => expect(readChain(path, keys)).toEqual([]));
  });

  it('returns the entries it verified, typed as the caller says', () => {
    withTmp((path) => {
      const writer = new JsonlChainWriter<{ event: string; request_id: string }>(path, keys);
      writer.append({ event: 'user.login', request_id: 'req-0' });
      writer.append({ event: 'user.logout', request_id: 'req-1' });
      const entries = readChain<{ event: string }>(path, keys);
      expect(entries.map((e) => [e.seq, e.event])).toEqual([[0, 'user.login'], [1, 'user.logout']]);
    });
  });

  it('throws when the file does not verify (verifyJsonl gives a verdict instead)', () => {
    withTmp((path) => {
      const writer = new JsonlChainWriter(path, keys);
      writer.append(draft(0));
      appendFileSync(path, '{"not":"canonical" }\n');
      expect(() => readChain(path, keys)).toThrow(/does not verify: it breaks at entry 1/);
      expect(verifyJsonl(readFileSync(path), keys)).toMatchObject({ ok: false, brokenAt: 1 });
    });
  });

  it('with an anchor, refuses a file truncated at a line boundary (invisible without one)', () => {
    withTmp((path) => {
      const writer = new JsonlChainWriter(path, keys);
      writer.append(draft(0));
      const head = writer.append(draft(1));
      const anchor = { count: 2, lastHash: head.entry_hash };
      expect(readChain(path, keys, anchor)).toHaveLength(2);
      writeFileSync(path, `${readFileSync(path, 'utf8').split('\n')[0]!}\n`);
      expect(readChain(path, keys)).toHaveLength(1);
      expect(() => readChain(path, keys, anchor)).toThrow(/does not verify/);
    });
  });
});
