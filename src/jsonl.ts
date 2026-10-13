import { MAX_CANONICAL_BYTES, MAX_DEPTH, canonicalize } from './canonicalize.js';
import { parseJson } from './json.js';
import type { KeyProvider } from './keys.js';
import { isOutOfResources } from './stack.js';
import { verifyEntries, type ChainAnchor, type VerifyResult } from './verify.js';

// The on-disk format: CANONICAL JSONL. Each entry is one line holding exactly canonical(entry)
// (derived fields included), UTF-8 encoded, terminated by "\n". python/audit_chain/jsonl.py
// implements the same rules and returns the same verdicts.
//
// Requiring every line to BE its own canonical form is what makes the FILE BYTES authenticated, and
// not merely the value a JSON parser happens to produce from them. JSON.parse and Python's json.loads
// disagree on texts that never reach the parsed value (an overwritten duplicate key holding NaN or a
// 5000-digit integer, extreme nesting), and `1.0`, an escaped letter or extra whitespace are other
// spellings of the same value. None of those texts is canonical, so both languages reject them at the
// same line.
//
// Lines are found lazily and verified as they are read (verifyEntries), so a file of any size (past
// 2 GiB too) is checked in constant memory and the work stops at the first bad line: a file of millions of junk lines
// costs no more than its first one.

export interface ParsedJsonl {
  /** Entries parsed from the canonical lines BEFORE the first bad line. */
  entries: unknown[];
  /** Index of the first line that is not valid canonical JSON, or null if every line is. */
  badLine: number | null;
  reason: string | null;
}

const NEWLINE = 0x0a;

// Uint8Array.prototype.indexOf, NEVER data.indexOf: on a Buffer that resolves to Buffer.prototype.indexOf,
// which clamps the start offset to 2^31 - 1 and wraps its result to a 32-bit integer. On a Buffer over
// 2 GiB it would find the wrong line feed (misreading lines, and jsonlLineCount would never end).
function indexOfNewline(data: Uint8Array, from: number): number {
  return Uint8Array.prototype.indexOf.call(data, NEWLINE, from);
}
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

type Line = { line: Uint8Array; next: number } | { torn: true } | null;

/**
 * The line starting at byte `start`, or null at the end of the file. EVERY line, including the last,
 * must end with a line feed: an unterminated tail is torn. Accepting it would let anyone drop the final
 * byte unnoticed, and the next append would then fuse two entries into one unparseable line.
 */
function lineAt(data: Uint8Array, start: number): Line {
  if (start >= data.length) return null;
  const end = indexOfNewline(data, start);
  if (end === -1) return { torn: true };
  return { line: data.subarray(start, end), next: end + 1 };
}

function parseLine(line: Uint8Array): { value: unknown } | { error: string } {
  // Can't be canonical, and decoding it could exceed V8's maximum string length.
  if (line.length > MAX_CANONICAL_BYTES) return { error: 'line exceeds the canonical size limit' };
  let text: string;
  try {
    text = utf8.decode(line);
  } catch (err) {
    if (isOutOfResources(err)) throw err;
    return { error: 'line is not valid UTF-8' };
  }
  let value: unknown;
  try {
    // Never JSON.parse: see json.ts (V8 misparses escaped keys). No canonical line nests deeper than
    // MAX_DEPTH, so the parser refuses deeper text before recursing further: a short hostile line then
    // costs the caller's stack little more than a legitimate one.
    value = parseJson(text, MAX_DEPTH);
  } catch (err) {
    if (isOutOfResources(err)) throw err;
    return { error: 'line is not valid JSON' };
  }
  try {
    if (canonicalize(value) !== text) return { error: 'line is not in canonical form' };
  } catch (err) {
    if (isOutOfResources(err)) throw err;
    return { error: 'line is outside the canonical domain' };
  }
  return { value };
}

function requireBytes(data: unknown, fn: string): asserts data is Uint8Array {
  if (!(data instanceof Uint8Array)) throw new TypeError(`${fn} expects bytes (Uint8Array/Buffer)`);
}

/** Parse canonical JSONL, stopping at the first line that is not canonical. Never throws on content. */
export function parseJsonl(data: Uint8Array): ParsedJsonl {
  requireBytes(data, 'parseJsonl');
  const entries: unknown[] = [];
  for (let pos = 0; ; ) {
    const l = lineAt(data, pos);
    if (l === null) return { entries, badLine: null, reason: null };
    if ('torn' in l) return { entries, badLine: entries.length, reason: 'last line is not terminated (torn)' };
    const parsed = parseLine(l.line);
    if ('error' in parsed) return { entries, badLine: entries.length, reason: parsed.error };
    entries.push(parsed.value);
    pos = l.next;
  }
}

/**
 * Verify a canonical-JSONL chain file byte for byte, streaming: each line is parsed and verified as it
 * is reached, and the first failure (a bad line or a bad entry) ends verification at that index. The
 * verdict is the one verifyChain gives on the parsed entries, except that a non-canonical line breaks
 * the chain at that line. Never throws on content: only if `data` is not bytes, or the KeyProvider
 * itself throws (an infrastructure error, not tampering).
 */
export function verifyJsonl(data: Uint8Array, keys: KeyProvider, anchor?: ChainAnchor | null): VerifyResult {
  requireBytes(data, 'verifyJsonl');
  let pos = 0;
  return verifyEntries(
    () => {
      const l = lineAt(data, pos);
      if (l === null) return null;
      if ('torn' in l) return { unreadable: 'last line is not terminated (torn)' };
      pos = l.next;
      const parsed = parseLine(l.line);
      return 'error' in parsed ? { unreadable: parsed.error } : { entry: parsed.value };
    },
    keys,
    anchor,
  );
}

/**
 * The entry on line `index` of a file that has ALREADY been verified, or undefined past the end. It
 * scans line feeds without parsing the lines before it, so it stays cheap on large files.
 */
export function jsonlEntryAt(data: Uint8Array, index: number): unknown {
  requireBytes(data, 'jsonlEntryAt');
  let pos = 0;
  for (let i = 0; ; i += 1) {
    const l = lineAt(data, pos);
    if (l === null || 'torn' in l) return undefined;
    if (i === index) {
      const parsed = parseLine(l.line);
      return 'error' in parsed ? undefined : parsed.value;
    }
    pos = l.next;
  }
}

/** Number of complete (line-feed-terminated) lines in the file. */
export function jsonlLineCount(data: Uint8Array): number {
  requireBytes(data, 'jsonlLineCount');
  let count = 0;
  for (let pos = indexOfNewline(data, 0); pos !== -1; pos = indexOfNewline(data, pos + 1)) count += 1;
  return count;
}

/** One canonical-JSONL line (UTF-8 text including the trailing newline) for a sealed entry. */
export function toJsonlLine(entry: Record<string, unknown>): string {
  return `${canonicalize(entry)}\n`;
}
