import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { CanonicalizationError, MAX_CANONICAL_BYTES, canonicalize } from './canonicalize.js';
import { isLowerHex } from './hex.js';
import { isUsableKey, requireKeyProvider, type KeyProvider } from './keys.js';
import { GENESIS_HASH } from './record.js';
import { isOutOfResources } from './stack.js';

/** External corroboration that pins the chain's length + head, detecting tail truncation. */
export interface ChainAnchor {
  count: number;
  lastHash: string;
}

export interface VerifyResult {
  ok: boolean;
  lastSeq: number;
  brokenAt: number | null;
  reason: string | null;
}

function sha256Hex(bytes: string): string {
  return createHash('sha256').update(bytes, 'utf8').digest('hex');
}

/** ',"entry_hash":"<64 hex>"' + ',"entry_hmac":"<64 hex>"': 2 x (1 + 14 + 64 + 1). */
const DERIVED_MEMBERS_BYTES = 160;

// Total by construction: any non-string, non-hex or odd/mismatched-length input returns false rather
// than throwing. Without the hex guard a 64-char NON-hex entry_hmac (same string length as the real
// one) decodes via Buffer.from(_, 'hex') to a ZERO-length buffer, and timingSafeEqual then throws.
// LOWERCASE only: the seal emits lowercase hex and the Python verifier compares the exact string.
function hexEqual(a: string, b: unknown): boolean {
  if (typeof b !== 'string') return false;
  if (a.length !== b.length || a.length % 2 !== 0) return false;
  if (!isLowerHex(a) || !isLowerHex(b)) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

/**
 * Verify a hash-chained, HMAC-sealed audit stream. Detects content tampering (entry_hash),
 * reorder / middle-delete (seq + prev_hash linkage), and forgery / unseal (HMAC). Tail
 * truncation is only detectable WITH an anchor: the chain alone cannot prove how many
 * entries existed.
 */
export function verifyChain(entries: unknown, keys: KeyProvider, anchor?: ChainAnchor | null): VerifyResult {
  requireKeyProvider(keys);
  // Total on any input, typed or not (a chain is usually parsed from untrusted JSON, so `entries` is
  // `unknown`): every malformed shape is a broken chain at the first bad index, never an exception.
  let list: readonly unknown[];
  let count: number;
  try {
    if (!Array.isArray(entries)) return broken(0, 'entries is not an array');
    list = entries;
    count = list.length;
  } catch (err) {
    if (isOutOfResources(err)) throw err;
    return broken(0, 'entries cannot be read'); // a proxy or a getter: never reachable from JSON
  }
  return verifyEntries(
    (i) => {
      if (i >= count) return null;
      try {
        return { entry: list[i] };
      } catch (err) {
        if (isOutOfResources(err)) throw err;
        return { unreadable: 'entry cannot be read' }; // a getter or proxy: never reachable from JSON
      }
    },
    keys,
    anchor,
  );
}

/** One step of a chain being verified: the next entry, why it could not be read, or the end (null). */
export type ChainStep = { entry: unknown } | { unreadable: string } | null;

/** A caller-supplied "unreadable" reason of any type, as text (the chain breaks there regardless). */
function describe(reason: unknown): string {
  try {
    return String(reason);
  } catch (err) {
    if (isOutOfResources(err)) throw err;
    return 'entry cannot be read';
  }
}

function broken(at: number, reason: string): VerifyResult {
  return { ok: false, lastSeq: at - 1, brokenAt: at, reason };
}

/**
 * The verification engine, INCREMENTAL: `next(i)` supplies entry i on demand and nothing is retained
 * but the previous entry_hash, so a caller can stream a chain of any length in constant memory, and
 * verification stops at the first entry that fails. The ordering rules fall out of the structure: an
 * earlier entry is always verified before a later one can fail, and the anchor is checked only after
 * the last entry (never on a chain that already broke).
 *
 * `next` reports an entry it could not read as `{ unreadable: reason }` (a broken chain at that index).
 * If `next` THROWS, the exception propagates: a source that fails (a database cursor or network stream
 * timing out) is an infrastructure error, not evidence of tampering, exactly like a failing KeyProvider.
 */
export function verifyEntries(
  next: (i: number) => ChainStep,
  keys: KeyProvider,
  anchor?: ChainAnchor | null,
): VerifyResult {
  requireKeyProvider(keys);
  // Only undefined / null mean "no anchor". Anything else that is not an object is a programming error,
  // never a silent "not anchored" (which would switch the truncation check off).
  if (anchor !== undefined && anchor !== null && typeof anchor !== 'object') {
    throw new TypeError('anchor must be an object { count, lastHash }, or undefined');
  }
  let prevHash = GENESIS_HASH;
  let count = 0;
  for (;;) {
    const step = next(count); // outside the try: the source's own failures propagate
    if (step === null) break;
    if (typeof step !== 'object' || !('entry' in step || 'unreadable' in step)) {
      throw new TypeError('next() must return { entry }, { unreadable } or null');
    }
    let outcome: EntryOutcome;
    try {
      outcome = 'unreadable' in step ? { error: describe(step.unreadable) } : verifyEntry(step.entry, count, prevHash, keys);
    } catch (err) {
      // A failing key provider (KMS timeout, ...) is an infrastructure error, not tampering: it
      // propagates. Anything else here came from reading the entry itself (getters, proxies).
      if (err instanceof KeyProviderError) throw err.cause;
      if (isOutOfResources(err)) throw err;
      outcome = { error: 'entry cannot be read' };
    }
    if ('error' in outcome) return broken(count, outcome.error);
    prevHash = outcome.entryHash;
    count += 1;
  }

  if (anchor) {
    // A wrong count breaks at n (the chain length): every entry present verified, and is vouched for.
    if (count !== anchor.count) {
      return broken(count, `count ${count} != anchor count (truncation)`);
    }
    if (prevHash !== anchor.lastHash) {
      return broken(Math.max(count - 1, 0), 'head hash does not match anchor');
    }
  }

  return { ok: true, lastSeq: count - 1, brokenAt: null, reason: null };
}

type EntryOutcome = { entryHash: string } | { error: string };

/** Marks an exception thrown BY the KeyProvider, so it is re-thrown rather than read as tampering. */
class KeyProviderError extends Error {}

function lookUpKey(keys: KeyProvider, writerKeyId: string): Uint8Array | null {
  try {
    return keys.getKey(writerKeyId);
  } catch (err) {
    throw new KeyProviderError('key provider failed', { cause: err });
  }
}

function verifyEntry(entry: unknown, i: number, prevHash: string, keys: KeyProvider): EntryOutcome {
  if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
    return { error: 'entry is not an object' };
  }
  const { entry_hash, entry_hmac, ...core } = entry as Record<string, unknown>;
  if (core.seq !== i) return { error: `seq mismatch: expected ${i}` };
  if (core.prev_hash !== prevHash) return { error: 'prev_hash linkage broken (reorder/delete)' };

  let bytes: string;
  try {
    bytes = canonicalize(core);
  } catch (err) {
    if (err instanceof CanonicalizationError) return { error: `not canonicalizable: ${err.message}` };
    throw err;
  }
  if (entry_hash !== sha256Hex(bytes)) return { error: 'entry_hash mismatch (content tampered)' };

  const key = typeof core.writer_key_id === 'string' ? lookUpKey(keys, core.writer_key_id) : null;
  if (!isUsableKey(key)) return { error: 'unknown writer_key_id' };
  const recomputedHmac = createHmac('sha256', key).update(bytes, 'utf8').digest('hex');
  if (!hexEqual(recomputedHmac, entry_hmac)) return { error: 'HMAC mismatch (forged or unsealed)' };
  // The whole ENTRY, not just its core, must fit the size limit: the sealer refuses to create a larger
  // one and canonical JSONL can never store it. With both hash fields verified as 64 lowercase hex
  // chars, canonical(entry) is exactly canonical(core) plus two 79-byte members and their two commas.
  if (Buffer.byteLength(bytes, 'utf8') + DERIVED_MEMBERS_BYTES > MAX_CANONICAL_BYTES) {
    return { error: 'entry exceeds the canonical size limit' };
  }
  return { entryHash: entry_hash };
}
