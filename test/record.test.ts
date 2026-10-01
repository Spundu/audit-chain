import { describe, it, expect } from 'vitest';
import { ZodError } from 'zod';
import { InMemoryKeyProvider } from '../src/keys.js';
import { AuditCoreSchema, SealedAuditEntrySchema } from '../src/record.js';
import { appendEntry, sealEntry, type AuditDraft } from '../src/seal.js';

// The example record schema's invariants. The chain construction doesn't depend on them, but the TS
// writer enforces them, and silently losing one (e.g. .strict() stripping unknown fields instead of
// refusing them) would drop audit data without an error.

const keys = new InMemoryKeyProvider({ k1: Buffer.alloc(32, 1) }, 'k1');

function draft(over: Record<string, unknown> = {}): AuditDraft {
  return {
    v: 1,
    chain: 'brain',
    call_id: 'c',
    session_id: 's',
    agent: { name: 'n', kind: 'main' },
    ts_unix_ms: 1,
    boot_id: 'b',
    host_id: 'h',
    phase: 'pre',
    ...over,
  } as AuditDraft;
}

describe('record schema', () => {
  it.each(['nonce', 'recap_hash', 'vault_receipt_digest'])('refuses the vault-only field %s on the brain chain', (field) => {
    expect(() => appendEntry(null, draft({ [field]: 'x' }), keys, 'agent-pipe')).toThrow(/vault chain/);
  });

  it('allows the vault-only fields on the vault chain', () => {
    const entry = appendEntry(null, draft({ chain: 'vault', nonce: 'n', recap_hash: 'r', vault_receipt_digest: 'd' }), keys, 'vault');
    expect(entry.nonce).toBe('n');
    expect(SealedAuditEntrySchema.safeParse(entry).success).toBe(true);
    expect(SealedAuditEntrySchema.safeParse({ ...entry, chain: 'brain' }).success).toBe(false);
  });

  it.each(['entry_hash', 'prev_hash', 'action_hash'])('refuses a 64-char %s that is not hex (a lowercase letter past f)', (field) => {
    const entry = appendEntry(null, draft({ chain: 'vault' }), keys, 'vault');
    expect(SealedAuditEntrySchema.safeParse(entry).success).toBe(true);
    expect(SealedAuditEntrySchema.safeParse({ ...entry, [field]: 'g'.repeat(64) }).success).toBe(false);
    const { entry_hash: _h, entry_hmac: _m, ...core } = entry;
    expect(() => sealEntry({ ...core, [field]: 'g'.repeat(64) } as never, Buffer.alloc(32, 1))).toThrow();
  });

  it.each([
    ['the core', draft({ surprise: 1 })],
    ['decision', draft({ decision: { tier: 'green', action: 'allow', source: 's', reason: 'r', surprise: 1 } })],
    ['result', draft({ result: { status: 'ok', duration_ms: 1, surprise: 1 } })],
    ['agent', draft({ agent: { name: 'n', kind: 'main', surprise: 1 } })],
  ])('refuses an unknown field in %s instead of silently dropping it', (_where, d) => {
    expect(() => appendEntry(null, d, keys, 'agent-pipe')).toThrow();
  });

  it('refuses a prev_hash that is not 64 lowercase hex chars', () => {
    const core = { ...draft(), seq: 0, producer: 'agent-pipe', writer_key_id: 'k1', prev_hash: 'A'.repeat(64) };
    expect(AuditCoreSchema.safeParse(core).success).toBe(false);
  });

  it.each([['uppercase', 'A'.repeat(64)], ['past f', 'g'.repeat(64)], ['63 chars', 'a'.repeat(63)], ['65 chars', 'a'.repeat(65)], ['empty', '']])(
    'refuses an entry_hmac that is not 64 lowercase hex chars (%s)',
    (_label, hmac) => {
      const entry = appendEntry(null, draft({ chain: 'vault' }), keys, 'vault');
      expect(SealedAuditEntrySchema.safeParse(entry).success).toBe(true);
      expect(SealedAuditEntrySchema.safeParse({ ...entry, entry_hmac: hmac }).success).toBe(false);
    },
  );

  it.each([[0.5], [-1], [Number.NaN], [Number.POSITIVE_INFINITY], ['0']])('refuses a seq of %s (a ZodError)', (seq) => {
    const core = { ...draft(), seq, producer: 'agent-pipe', writer_key_id: 'k1', prev_hash: '0'.repeat(64) };
    expect(AuditCoreSchema.safeParse({ ...core, seq: 0 }).success).toBe(true);
    expect(() => AuditCoreSchema.parse(core)).toThrow(ZodError);
  });
});

describe('InMemoryKeyProvider', () => {
  it('refuses an activeId that is not in the keyring', () => {
    expect(() => new InMemoryKeyProvider({ k1: Buffer.alloc(32) }, 'k2')).toThrow(/not present/);
  });

  it('measures a string key in UTF-8 bytes, not UTF-16 units', () => {
    const e = String.fromCharCode(0xe9); // 2 UTF-8 bytes, 1 UTF-16 unit
    expect(() => new InMemoryKeyProvider({ k: e.repeat(8) }, 'k')).not.toThrow(); // 16 bytes
    expect(() => new InMemoryKeyProvider({ k: e.repeat(7) }, 'k')).toThrow(/at least 16/); // 14 bytes
  });
});
