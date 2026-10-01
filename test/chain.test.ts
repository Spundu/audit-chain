import { describe, it, expect } from 'vitest';
import { createHash, createHmac } from 'node:crypto';
import type { SealedAuditEntry } from '../src/record.js';
import { CanonicalizationError, MAX_CANONICAL_BYTES, canonicalize } from '../src/canonicalize.js';
import { InMemoryKeyProvider } from '../src/keys.js';
import { appendEntry, sealEntry, type AuditDraft } from '../src/seal.js';
import { verifyChain } from '../src/verify.js';

function draft(i: number, over: Partial<AuditDraft> = {}): AuditDraft {
  return {
    v: 1,
    chain: 'brain',
    call_id: `call-${i}`,
    session_id: 'sess-1',
    agent: { name: 'brain', kind: 'main' },
    ts_unix_ms: 1000 + i,
    boot_id: 'boot-1',
    host_id: 'host-1',
    phase: 'pre',
    ...over,
  };
}

function buildChain(keys: InMemoryKeyProvider, n: number): SealedAuditEntry[] {
  const chain: SealedAuditEntry[] = [];
  let prev: SealedAuditEntry | null = null;
  for (let i = 0; i < n; i += 1) {
    prev = appendEntry(prev, draft(i), keys, 'agent-pipe');
    chain.push(prev);
  }
  return chain;
}

const keys = new InMemoryKeyProvider({ k1: Buffer.alloc(32, 7) }, 'k1');

describe('audit chain seal + verify', () => {
  it('verifies a well-formed chain', () => {
    const chain = buildChain(keys, 3);
    const result = verifyChain(chain, keys);
    expect(result.ok).toBe(true);
    expect(result.lastSeq).toBe(2);
  });

  it('detects content tampering (entry_hash)', () => {
    const chain = buildChain(keys, 3);
    const tampered = [chain[0]!, { ...chain[1]!, call_id: 'evil' }, chain[2]!];
    const result = verifyChain(tampered, keys);
    expect(result.ok).toBe(false);
    expect(result.brokenAt).toBe(1);
  });

  it('detects reordering (seq / prev_hash)', () => {
    const chain = buildChain(keys, 3);
    const result = verifyChain([chain[1]!, chain[0]!, chain[2]!], keys);
    expect(result.ok).toBe(false);
    expect(result.brokenAt).toBe(0);
  });

  it('detects a deleted middle entry', () => {
    const chain = buildChain(keys, 3);
    const result = verifyChain([chain[0]!, chain[2]!], keys);
    expect(result.ok).toBe(false);
    expect(result.brokenAt).toBe(1);
  });

  it('detects tail truncation only with an anchor', () => {
    const chain = buildChain(keys, 3);
    const truncated = [chain[0]!, chain[1]!];
    expect(verifyChain(truncated, keys).ok).toBe(true); // chain alone cannot tell
    const anchor = { count: 3, lastHash: chain[2]!.entry_hash };
    expect(verifyChain(truncated, keys, anchor).ok).toBe(false);
  });

  it('detects forgery: content re-hashed but HMAC cannot be reforged without the key', () => {
    const chain = buildChain(keys, 3);
    const { entry_hash: _h, entry_hmac, ...core } = chain[1]!;
    const forgedCore = { ...core, call_id: 'evil' };
    const forgedHash = createHash('sha256').update(canonicalize(forgedCore), 'utf8').digest('hex');
    const forged = { ...forgedCore, entry_hash: forgedHash, entry_hmac } as SealedAuditEntry;
    const result = verifyChain([chain[0]!, forged, chain[2]!], keys);
    expect(result.ok).toBe(false);
    expect(result.brokenAt).toBe(1);
    expect(result.reason).toMatch(/HMAC/);
  });

  it('fails verification under the wrong key', () => {
    const chain = buildChain(keys, 3);
    const wrong = new InMemoryKeyProvider({ k1: Buffer.alloc(32, 9) }, 'k1');
    expect(verifyChain(chain, wrong).ok).toBe(false);
  });

  it('returns ok:false (never throws) on a non-hex entry_hmac of the right length', () => {
    const chain = buildChain(keys, 3);
    // content unchanged → entry_hash stays valid and prev_hash linkage holds, so verification reaches the HMAC
    // comparison. A 64-char NON-hex hmac used to decode to a zero-length Buffer and make timingSafeEqual throw.
    const forged = { ...chain[1]!, entry_hmac: 'z'.repeat(64) } as SealedAuditEntry;
    let result: ReturnType<typeof verifyChain> | undefined;
    expect(() => {
      result = verifyChain([chain[0]!, forged, chain[2]!], keys);
    }).not.toThrow();
    expect(result?.ok).toBe(false);
    expect(result?.brokenAt).toBe(1);
    expect(result?.reason).toMatch(/HMAC/);
  });

  it('rejects an uppercase spelling of the correct entry_hmac (parity with the Python verifier)', () => {
    // The seal only emits lowercase hex. A case-insensitive compare let TS accept what Python rejects.
    const chain = buildChain(keys, 3);
    const upper = { ...chain[1]!, entry_hmac: chain[1]!.entry_hmac.toUpperCase() } as SealedAuditEntry;
    const result = verifyChain([chain[0]!, upper, chain[2]!], keys);
    expect(result.ok).toBe(false);
    expect(result.brokenAt).toBe(1);
  });

  it('returns ok:false (never throws) on a non-ASCII entry_hmac', () => {
    const chain = buildChain(keys, 3);
    const forged = { ...chain[1]!, entry_hmac: 'é'.repeat(64) } as SealedAuditEntry;
    expect(verifyChain([chain[0]!, forged, chain[2]!], keys).ok).toBe(false);
  });

  it('never throws on API-only inputs: throwing getters and revoked proxies are broken chains', () => {
    const getterEntry = Object.defineProperty({}, 'seq', { get: () => { throw new Error('boom'); }, enumerable: true });
    expect(verifyChain([getterEntry] as unknown as SealedAuditEntry[], keys)).toMatchObject({ ok: false, brokenAt: 0 });
    const revoked = Proxy.revocable([], {});
    revoked.revoke();
    expect(verifyChain(revoked.proxy as SealedAuditEntry[], keys)).toMatchObject({ ok: false, brokenAt: 0 });
  });

  it('refuses keys shorter than 16 bytes (an empty key lets anyone forge)', () => {
    expect(() => new InMemoryKeyProvider({ k: '' }, 'k')).toThrow(/at least 16/);
    expect(() => new InMemoryKeyProvider({ k: Buffer.alloc(15) }, 'k')).toThrow(/at least 16/);
    const shortKeys = { getKey: () => Buffer.alloc(0), activeKeyId: () => 'k1' };
    expect(verifyChain(buildChain(keys, 1), shortKeys).ok).toBe(false);
  });

  it('a retired key still verifies AND can still forge at any position (rotation does not revoke)', () => {
    const old = Buffer.alloc(32, 1);
    const both = new InMemoryKeyProvider({ old, new: Buffer.alloc(32, 2) }, 'new');
    const e0 = appendEntry(null, draft(0), new InMemoryKeyProvider({ old }, 'old'), 'agent-pipe');
    const e1 = appendEntry(e0, draft(1), both, 'agent-pipe');
    const e2 = appendEntry(e1, draft(2), new InMemoryKeyProvider({ old }, 'old'), 'agent-pipe');
    expect(verifyChain([e0, e1, e2], both).ok).toBe(true); // documented limitation, pinned here
  });

  it('lets a failing key provider throw: an infrastructure error is not tampering', () => {
    const failing = { getKey: () => { throw new Error('KMS timeout'); }, activeKeyId: () => 'k1' };
    expect(() => verifyChain(buildChain(keys, 2), failing)).toThrow('KMS timeout');
  });

  it('treats a short key as unknown when VERIFYING, even for a chain sealed with that same short key', () => {
    const short = Buffer.alloc(15, 7);
    const core = { seq: 0, prev_hash: '0'.repeat(64), writer_key_id: 'k1' };
    const bytes = canonicalize(core);
    const entry = {
      ...core,
      entry_hash: createHash('sha256').update(bytes, 'utf8').digest('hex'),
      entry_hmac: createHmac('sha256', short).update(bytes, 'utf8').digest('hex'),
    } as unknown as SealedAuditEntry;
    const shortKeys = { getKey: () => short, activeKeyId: () => 'k1' };
    const result = verifyChain([entry], shortKeys);
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/writer_key_id/);
  });

  it('refuses to seal an entry whose stored line (core + hashes) would exceed the size limit', () => {
    const big = { ...draft(0), args_canonical: 'x'.repeat(MAX_CANONICAL_BYTES - 400) };
    expect(() => canonicalize({ ...big, seq: 0, prev_hash: '0'.repeat(64), writer_key_id: 'k1', producer: 'agent-pipe' })).not.toThrow();
    expect(() => appendEntry(null, big, keys, 'agent-pipe')).toThrow(CanonicalizationError);
  });

  it('seals every field when a draft carries an explicit undefined optional field', () => {
    const sealed = appendEntry(null, { ...draft(0), args_canonical: undefined, tool: 'zz-last' }, keys, 'agent-pipe');
    const { entry_hash: _h, entry_hmac: _m, ...core } = sealed;
    const text = canonicalize(core);
    for (const field of ['seq', 'prev_hash', 'writer_key_id', 'tool', 'producer']) expect(text).toContain(`"${field}":`);
    expect(verifyChain([sealed], keys).ok).toBe(true);
  });

  it('accepts a key of exactly 16 bytes for sealing and verifying, and refuses 15', () => {
    const k16 = new InMemoryKeyProvider({ k16: Buffer.alloc(16, 5) }, 'k16');
    const sealed = appendEntry(null, draft(0), k16, 'agent-pipe');
    expect(verifyChain([sealed], k16).ok).toBe(true);
    expect(() => new InMemoryKeyProvider({ k15: Buffer.alloc(15, 5) }, 'k15')).toThrow(/at least 16/);
    expect(() => sealEntry({ ...sealed, entry_hash: undefined, entry_hmac: undefined } as never, Buffer.alloc(15))).toThrow(/at least 16/);
  });
});
