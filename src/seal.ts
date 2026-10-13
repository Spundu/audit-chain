import { createHash, createHmac } from 'node:crypto';
import { canonicalize } from './canonicalize.js';
import { isSha256Hex } from './hex.js';
import { MIN_KEY_BYTES, isUsableKey, type KeyProvider } from './keys.js';
import { isPlainObject } from './plain.js';

// The chain seals ANY JSON object: there is no record schema. If your records have a shape, check it
// before you append (with zod, a JSON Schema validator or plain code). The chain only guarantees that
// what was sealed cannot change, move or disappear from the middle without verification failing.

/** `prev_hash` of entry 0. */
export const GENESIS_HASH = '0'.repeat(64);

/** A record to append: any plain JSON object. */
export type AuditDraft = Record<string, unknown>;

/** The fields the chain relies on. appendEntry assigns them; a draft never chooses them. */
export type ChainFields = {
  seq: number;
  prev_hash: string;
  writer_key_id: string;
};

/** What sealing adds: SHA-256 and HMAC-SHA-256 of the canonical core, 64 lowercase hex chars each. */
export type SealFields = {
  entry_hash: string;
  entry_hmac: string;
};

/**
 * A sealed chain entry: your record, the chain fields and the seal. `T` may be an interface or a union
 * of record types; each member of a union keeps its own fields.
 */
export type SealedEntry<T extends object = AuditDraft> = (T extends unknown
  ? Omit<T, keyof ChainFields | keyof SealFields>
  : never) &
  ChainFields &
  SealFields;

/** The part of the previous entry that the next one links to. */
export type ChainHead = Pick<SealedEntry, 'seq' | 'entry_hash'>;

export interface ChainState {
  seq: number;
  prevHash: string;
}

/**
 * The seq and prev_hash of the entry that follows `prev` (null or undefined: the chain is empty). `prev`
 * must look like a sealed entry, or the next entry could be sealed but never verify: a TypeError, as
 * Python's next_state raises.
 */
export function nextState(prev: ChainHead | null | undefined): ChainState {
  if (prev === null || prev === undefined) return { seq: 0, prevHash: GENESIS_HASH };
  if (typeof prev !== 'object') throw new TypeError('prev must be the previous sealed entry, or null');
  const { seq, entry_hash: hash } = prev as { seq: unknown; entry_hash: unknown }; // read each field once
  if (typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 0) {
    throw new TypeError('prev.seq must be a non-negative safe integer');
  }
  if (typeof hash !== 'string' || !isSha256Hex(hash)) {
    throw new TypeError('prev.entry_hash must be 64 lowercase hex chars');
  }
  return { seq: seq + 1, prevHash: hash };
}

function digestHex(bytes: string): string {
  return createHash('sha256').update(bytes, 'utf8').digest('hex');
}

function requirePlainObject(value: unknown, name: string): asserts value is AuditDraft {
  // A Map, an Error or a class instance would otherwise be spread into {} and sealed as an empty record.
  if (!isPlainObject(value)) throw new TypeError(`${name} must be a plain JSON object`);
}

/**
 * Seal a fully-formed core: entry_hash = SHA-256(canonical(core)), entry_hmac = HMAC-SHA-256(key, the
 * same bytes). The core is any plain JSON object that does not already carry entry_hash or entry_hmac;
 * the chain fields are not checked here (appendEntry sets them). Throws, and seals nothing, on a short
 * key, a core that is not a plain object, a core outside the canonical domain, or an entry too large
 * to store.
 */
export function sealEntry<T extends object>(core: T, key: Uint8Array): T & SealFields {
  if (!isUsableKey(key)) throw new Error(`HMAC key must be at least ${MIN_KEY_BYTES} bytes (a Buffer or Uint8Array)`);
  requirePlainObject(core, 'core');
  if (core.entry_hash !== undefined || core.entry_hmac !== undefined) {
    // They would be hashed here, overwritten below and stripped at verification: never verifiable.
    throw new Error('core must not contain entry_hash or entry_hmac');
  }
  const bytes = canonicalize(core);
  const sealed = {
    ...core,
    entry_hash: digestHex(bytes),
    entry_hmac: createHmac('sha256', key).update(bytes, 'utf8').digest('hex'),
  };
  // The stored line is canonical(sealed): the core plus ~160 bytes of hashes. Refuse here an entry
  // that could be sealed but never written (or verified) as a line.
  canonicalize(sealed);
  return sealed as T & SealFields;
}

/**
 * Append a draft to the chain: assigns seq, prev_hash and writer_key_id (replacing any the draft
 * carries), then seals with the provider's active key.
 */
export function appendEntry<T extends object>(prev: ChainHead | null | undefined, draft: T, keys: KeyProvider): SealedEntry<T> {
  requirePlainObject(draft, 'draft');
  const { seq, prevHash } = nextState(prev);
  const writerKeyId: unknown = keys.activeKeyId();
  if (typeof writerKeyId !== 'string') throw new TypeError('activeKeyId() must return a string');
  const key = keys.getKey(writerKeyId);
  if (!key) throw new Error(`No HMAC key for writer_key_id='${writerKeyId}'`);
  return sealEntry({ ...draft, seq, prev_hash: prevHash, writer_key_id: writerKeyId }, key) as unknown as SealedEntry<T>;
}
