import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { isSha256Hex } from './hex.js';
import { jsonlEntryAt, jsonlLineCount, parseJsonl, toJsonlLine, verifyJsonl } from './jsonl.js';
import { requireKeyProvider, type KeyProvider } from './keys.js';
import { GENESIS_HASH, SealedAuditEntrySchema, type AuditCore, type SealedAuditEntry } from './record.js';
import { appendEntry, type AuditDraft } from './seal.js';
import type { ChainAnchor } from './verify.js';

// The WRITER side of a chain: a single-writer, append-only canonical-JSONL file. On construction it
// VERIFIES the existing file with its own keys and continues from the verified head, so a restart
// continues the same chain. It refuses to append to a chain that does not verify (a forged or torn
// tail, a tampered entry): appending would seal new entries onto a head that can never verify.
// Truncation or rollback is NOT detectable here unless a checkpoint (count, head) is supplied.
// Single-writer is an assumption, not an enforcement: two writers on one file will fork it.

/**
 * Parse and schema-validate every entry of a canonical-JSONL chain file (or [] if absent). For
 * TRUSTED reads after verification: it throws on the first non-canonical or schema-invalid line.
 * To check an untrusted file, use verifyJsonl, which returns a verdict instead. It READS THE FILE AGAIN:
 * to act on exactly the bytes you verified, keep them and use parseJsonl(bytes).entries instead.
 */
export function readChain(path: string): SealedAuditEntry[] {
  if (!existsSync(path)) return [];
  const parsed = parseJsonl(readFileSync(path));
  if (parsed.badLine !== null) throw new Error(`line ${parsed.badLine}: ${parsed.reason}`);
  return parsed.entries.map((entry) => SealedAuditEntrySchema.parse(entry));
}

function entryHashOf(entry: unknown): unknown {
  return entry !== null && typeof entry === 'object' ? (entry as Record<string, unknown>).entry_hash : undefined;
}

export class JsonlChainWriter {
  readonly #path: string;
  readonly #keys: KeyProvider;
  readonly #producer: AuditCore['producer'];
  #prev: SealedAuditEntry | null;
  #writeFailed = false;

  /**
   * @param checkpoint an earlier (count, head) of this file, e.g. recorded elsewhere at the last
   *   append. The file must still contain that entry at position count - 1 (it may have grown since);
   *   a shorter file, or a different entry there, means it was truncated or rolled back.
   */
  constructor(path: string, keys: KeyProvider, producer: AuditCore['producer'], checkpoint?: ChainAnchor) {
    requireKeyProvider(keys);
    if (typeof (keys as { activeKeyId?: unknown }).activeKeyId !== 'function') {
      throw new TypeError('keys must be a KeyProvider { getKey(writerKeyId), activeKeyId() }');
    }
    this.#path = path;
    this.#keys = keys;
    this.#producer = producer;
    const data = existsSync(path) ? readFileSync(path) : Buffer.alloc(0);
    const result = verifyJsonl(data, keys);
    if (!result.ok) {
      throw new Error(`refusing to append: existing chain breaks at entry ${result.brokenAt}: ${result.reason}`);
    }
    // Verified: every line is canonical. Read back only the entries needed, never the whole chain.
    const count = jsonlLineCount(data);
    if (checkpoint !== undefined) {
      if (checkpoint === null || typeof checkpoint !== 'object') throw new TypeError('checkpoint must be an object');
      // Validate first: a checkpoint loaded in the wrong shape (e.g. snake_case last_hash) must not
      // silently compare undefined === undefined and switch the truncation check off.
      // Read each field ONCE and compare only the validated copies (a getter could change its answer).
      const { count: at, lastHash } = checkpoint as { count: unknown; lastHash: unknown };
      if (typeof at !== 'number' || !Number.isSafeInteger(at) || at < 0) {
        throw new TypeError('checkpoint.count must be a non-negative integer');
      }
      if (typeof lastHash !== 'string' || !isSha256Hex(lastHash)) {
        throw new TypeError('checkpoint.lastHash must be 64 lowercase hex chars');
      }
      const atCheckpoint = at === 0 ? GENESIS_HASH : entryHashOf(at <= count ? jsonlEntryAt(data, at - 1) : undefined);
      if (atCheckpoint !== lastHash) {
        throw new Error(`refusing to append: ${path} no longer contains checkpoint entry ${at - 1}`);
      }
    }
    if (count === 0) {
      this.#prev = null;
      return;
    }
    const last = jsonlEntryAt(data, count - 1);
    // The chain verifies, but this writer only continues chains of ITS record shape (a chain written
    // by the schema-less Python append_entry, for example, may not match it).
    const head = SealedAuditEntrySchema.safeParse(last);
    if (!head.success) throw new Error("refusing to append: the chain's last entry does not match this writer's schema");
    this.#prev = head.data;
  }

  /** Seal a submitted draft, append it as one canonical line, and advance the chain head. */
  append(draft: AuditDraft): SealedAuditEntry {
    if (this.#writeFailed) throw new Error('refusing to append after a failed write: restart the writer');
    const entry = appendEntry(this.#prev, draft, this.#keys, this.#producer);
    const line = toJsonlLine(entry); // outside the latch: an error here wrote nothing
    try {
      appendFileSync(this.#path, line, 'utf8');
    } catch (err) {
      // A failed write (disk full, ...) may have left a partial line; appending after it would fuse
      // the next entry onto the torn bytes. A restarted writer re-verifies the file first.
      this.#writeFailed = true;
      throw err;
    }
    // The head is private state: callers get copies, so mutating a returned entry cannot make the
    // writer seal the next entry onto a head that no longer matches the file.
    this.#prev = structuredClone(entry);
    return entry;
  }

  get head(): SealedAuditEntry | null {
    return this.#prev === null ? null : structuredClone(this.#prev);
  }
}
