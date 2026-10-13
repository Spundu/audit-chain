import { createHash } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, writeSync } from 'node:fs';
import { dirname } from 'node:path';
import process from 'node:process';
import { canonicalize } from './canonicalize.js';
import { isSha256Hex } from './hex.js';
import { parseJson } from './json.js';
import { jsonlEntryAt, jsonlLineCount, parseJsonl, toJsonlLine, verifyJsonl } from './jsonl.js';
import { requireKeyProvider, type KeyProvider } from './keys.js';
import { GENESIS_HASH, appendEntry, type AuditDraft, type SealedEntry } from './seal.js';
import type { ChainAnchor } from './verify.js';

// The WRITER side of a chain: a single-writer, append-only canonical-JSONL file. On construction it
// VERIFIES the existing file with its own keys and continues from the verified head, so a restart
// continues the same chain. It refuses to append to a chain that does not verify (a forged or torn
// tail, a tampered entry): appending would seal new entries onto a head that can never verify.
// Truncation or rollback is NOT detectable here unless a checkpoint (count, head) is supplied.
// Single-writer is an assumption, not an enforcement: two writers on one file will fork it.
// append() returns only after its line is flushed to disk (fsync), and after the directory entry of a
// file it created, so a head recorded elsewhere as a checkpoint never points past what a power cut can
// leave in the file.

// "This file system cannot fsync a directory": skipped, since the file's own fsync has succeeded.
// Windows cannot fsync a directory at all (EPERM). Elsewhere EPERM and EACCES are permission errors,
// thrown like any other: the line is on disk, but its directory entry may not be.
const NO_DIRECTORY_FSYNC = new Set(['EISDIR', 'EINVAL', 'ENOTSUP']);

function cannotFsyncDirectory(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException | null)?.code ?? '';
  return NO_DIRECTORY_FSYNC.has(code) || (process.platform === 'win32' && code === 'EPERM');
}

function fsyncDirectoryOf(path: string): void {
  let fd: number | undefined;
  try {
    fd = openSync(dirname(path), 'r');
    fsyncSync(fd);
  } catch (err) {
    if (!cannotFsyncDirectory(err)) throw err;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/** Append bytes and fsync them. (fs.appendFileSync's flush option is skipped for UTF-8 strings in Node 24.) */
function appendDurably(path: string, bytes: Uint8Array): void {
  const created = !existsSync(path);
  const fd = openSync(path, 'a');
  try {
    for (let written = 0; written < bytes.length; ) written += writeSync(fd, bytes, written, bytes.length - written);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  if (created) fsyncDirectoryOf(path);
}

/**
 * Read a chain file and return its entries, but only if the whole file verifies (and, with an anchor,
 * ends exactly at that head); otherwise throw. The bytes are read once, so the entries returned are
 * exactly the ones verified. A missing file is an empty chain. For a verdict instead of an exception,
 * use verifyJsonl. `T` only types the result: records are not checked against it.
 */
export function readChain<T extends object = AuditDraft>(
  path: string,
  keys: KeyProvider,
  anchor?: ChainAnchor | null,
): SealedEntry<T>[] {
  const data = existsSync(path) ? readFileSync(path) : Buffer.alloc(0);
  const result = verifyJsonl(data, keys, anchor);
  if (!result.ok) throw new Error(`chain does not verify: it breaks at entry ${result.brokenAt}: ${result.reason}`);
  return parseJsonl(data).entries as SealedEntry<T>[];
}

function entryHashOf(entry: unknown): unknown {
  return entry !== null && typeof entry === 'object' ? (entry as Record<string, unknown>).entry_hash : undefined;
}

/** Appends records of any JSON shape. `T` only types `append` and `head`: records are not checked against it. */
export class JsonlChainWriter<T extends object = AuditDraft> {
  readonly #path: string;
  readonly #keys: KeyProvider;
  #prev: SealedEntry<T> | null;
  #writeFailed = false;

  /**
   * @param checkpoint an earlier (count, head) of this file, e.g. recorded elsewhere at the last
   *   append. The file must still contain that entry at position count - 1 (it may have grown since);
   *   a shorter file, or a different entry there, means it was truncated or rolled back.
   */
  constructor(path: string, keys: KeyProvider, checkpoint?: ChainAnchor) {
    requireKeyProvider(keys);
    if (typeof (keys as { activeKeyId?: unknown }).activeKeyId !== 'function') {
      throw new TypeError('keys must be a KeyProvider { getKey(writerKeyId), activeKeyId() }');
    }
    this.#path = path;
    this.#keys = keys;
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
    // The chain verified, so its last line is a sealed entry with a valid seq and entry_hash: the
    // writer continues any verified chain, whatever its record shape (a Python-written one included).
    this.#prev = count === 0 ? null : (jsonlEntryAt(data, count - 1) as SealedEntry<T>);
  }

  /** Seal a submitted draft, append it as one canonical line flushed to disk, and advance the chain head. */
  append(draft: T): SealedEntry<T> {
    if (this.#writeFailed) throw new Error('refusing to append after a failed write: restart the writer');
    const entry = appendEntry(this.#prev, draft, this.#keys);
    const line = toJsonlLine(entry);
    // The next head is the entry AS WRITTEN, read back from its own line: plain data that later changes
    // to the caller's objects cannot touch, and that any value canonicalize accepted (a Proxy, say)
    // cannot make uncopyable. Everything that can fail runs before the write, so an error wrote nothing.
    const head = parseJson(line.slice(0, -1)) as SealedEntry<T>;
    // The line must hold exactly what was hashed. A value that reads differently each time (a Proxy, a
    // getter) could be canonicalized one way for the seal and another for the line: refuse it here,
    // on the plain data read back, before anything is written.
    const { entry_hash: sealedHash, entry_hmac: _hmac, ...core } = head as Record<string, unknown>;
    if (createHash('sha256').update(canonicalize(core), 'utf8').digest('hex') !== sealedHash) {
      throw new Error('refusing to append: the record changed while it was being sealed');
    }
    try {
      appendDurably(this.#path, Buffer.from(line, 'utf8'));
    } catch (err) {
      // A failed write (disk full, ...) may have left a partial line; appending after it would fuse
      // the next entry onto the torn bytes. A restarted writer re-verifies the file first.
      this.#writeFailed = true;
      throw err;
    }
    this.#prev = head;
    return entry;
  }

  get head(): SealedEntry<T> | null {
    return this.#prev === null ? null : structuredClone(this.#prev);
  }
}
