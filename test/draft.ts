import { MAX_CANONICAL_BYTES, canonicalize } from '../src/canonicalize.js';
import { GENESIS_HASH, type AuditDraft } from '../src/seal.js';

/** An example audit record for the tests. The chain seals any JSON object: these fields mean nothing to it. */
export function draft(i: number, over: AuditDraft = {}): AuditDraft {
  return {
    v: 1,
    event: 'user.login',
    request_id: `req-${i}`,
    session_id: 'sess-1',
    actor: { name: 'alice', role: 'admin' },
    ts_unix_ms: 1_000 + i,
    host_id: 'host-1',
    ...over,
  };
}

/**
 * Draft `i` of a chain sealed under key id 'k1', padded so that its core fits the size limit with 100
 * bytes to spare, while its stored line (the core plus 160 bytes of hashes) does not fit.
 */
export function draftTooBigToStore(i: number): AuditDraft {
  const base = draft(i, { note: '' });
  const core = canonicalize({ ...base, seq: i, prev_hash: GENESIS_HASH, writer_key_id: 'k1' });
  return { ...base, note: 'x'.repeat(MAX_CANONICAL_BYTES - Buffer.byteLength(core, 'utf8') - 100) };
}
