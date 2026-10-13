import { createHash, createHmac } from 'node:crypto';
import { canonicalize } from './canonicalize.js';
import { MIN_KEY_BYTES, isUsableKey, type KeyProvider } from './keys.js';

// The chain seals ANY JSON object: there is no record schema. If your records have a shape, check it
// before you append (with zod, a JSON Schema validator or plain code). The chain only guarantees that
// what was sealed cannot change, move or disappear from the middle without verification failing.

/** `prev_hash` of entry 0. */
export const GENESIS_HASH = '0'.repeat(64);

/** A record to append: any JSON object. */
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

/** A sealed chain entry: your record, the chain fields and the seal. */
export type SealedEntry<T extends AuditDraft = AuditDraft> = Omit<T, keyof ChainFields | keyof SealFields> &
  ChainFields &
  SealFields;

export interface ChainState {
  seq: number;
  prevHash: string;
}

export function nextState(prev: Pick<SealedEntry, 'seq' | 'entry_hash'> | null): ChainState {
  return prev ? { seq: prev.seq + 1, prevHash: prev.entry_hash } : { seq: 0, prevHash: GENESIS_HASH };
}

function digestHex(bytes: string): string {
  return createHash('sha256').update(bytes, 'utf8').digest('hex');
}

function requireObject(value: unknown, name: string): asserts value is AuditDraft {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${name} must be a JSON object`);
  }
}

/**
 * Seal a fully-formed core: entry_hash = SHA-256(canonical(core)), entry_hmac = HMAC-SHA-256(key, the
 * same bytes). The core is any JSON object that does not already carry entry_hash or entry_hmac; the
 * chain fields are not checked here (appendEntry sets them). Throws, and seals nothing, on a short key,
 * a core that is not an object, a core outside the canonical domain, or an entry too large to store.
 */
export function sealEntry<T extends AuditDraft>(core: T, key: Uint8Array): T & SealFields {
  if (!isUsableKey(key)) throw new Error(`HMAC key must be at least ${MIN_KEY_BYTES} bytes (a Buffer or Uint8Array)`);
  requireObject(core, 'core');
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
  return sealed;
}

/**
 * Append a draft to the chain: assigns seq, prev_hash and writer_key_id (replacing any the draft
 * carries), then seals with the provider's active key.
 */
export function appendEntry<T extends AuditDraft>(
  prev: Pick<SealedEntry, 'seq' | 'entry_hash'> | null,
  draft: T,
  keys: KeyProvider,
): SealedEntry<T> {
  requireObject(draft, 'draft');
  const { seq, prevHash } = nextState(prev);
  const writerKeyId = keys.activeKeyId();
  const key = keys.getKey(writerKeyId);
  if (!key) throw new Error(`No HMAC key for writer_key_id='${writerKeyId}'`);
  return sealEntry({ ...draft, seq, prev_hash: prevHash, writer_key_id: writerKeyId }, key) as SealedEntry<T>;
}
