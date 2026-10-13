// The HMAC sealing keyring. `verifyChain` resolves a key by `writer_key_id`, so historical
// entries stay verifiable across key rotation. Where the real key lives, and who can read it,
// is the deployer's decision; see THREAT-MODEL.md.

/** Shortest HMAC key accepted for sealing or verifying. A short (or empty) key lets anyone forge. */
export const MIN_KEY_BYTES = 16;

export interface KeyProvider {
  /**
   * Raw HMAC key bytes for a writer_key_id, or null if unknown. MUST return null (never throw) for an
   * unknown id: the id comes from chain content, which anyone who can write the file controls, and a
   * throw propagates out of verification as an infrastructure error instead of a broken chain.
   */
  getKey(writerKeyId: string): Uint8Array | null;
  /** The id of the key new entries are sealed with. */
  activeKeyId(): string;
}

/**
 * `keys` must be a KeyProvider, checked up front like the anchor: a wrong-typed keyring (a plain object,
 * a Map, null) is an API error whatever the input, never an empty chain that "verifies" and a sealed one
 * that throws later. Python's verifiers raise TypeError the same way.
 */
export function requireKeyProvider(keys: unknown): asserts keys is KeyProvider {
  const provider = keys as { getKey?: unknown } | null;
  if (provider === null || (typeof provider !== 'object' && typeof provider !== 'function') || typeof provider.getKey !== 'function') {
    throw new TypeError('keys must be a KeyProvider { getKey(writerKeyId) }');
  }
}

/**
 * A key the library will use: raw bytes (a Uint8Array, such as a Buffer) of at least MIN_KEY_BYTES,
 * measured in BYTES. Anything else (a KeyObject, an ArrayBuffer, a DataView, a Uint16Array, a string)
 * is no key at all, whatever its `length` says: verification treats it as an unknown key id and sealing
 * refuses it (fail closed). Python accepts `bytes` / `bytearray` the same way.
 */
export function isUsableKey(key: unknown): key is Uint8Array {
  return key instanceof Uint8Array && key.byteLength >= MIN_KEY_BYTES;
}

/**
 * A copy of the key's bytes in memory of its own: exactly its length, never a view of the caller's
 * buffer, and never in Node's shared Buffer pool (a small Buffer.from() copy lands there, next to
 * other buffers, so wiping one of THOSE through its .buffer would zero this key too). Copying from the
 * typed array itself reads its real length, whatever a subclass's length getter claims.
 */
function ownCopy(bytes: Uint8Array): Buffer {
  const copy = new Uint8Array(bytes);
  return Buffer.from(copy.buffer, copy.byteOffset, copy.byteLength);
}

/**
 * Holds keys that are already in memory: test keys, or keys your code loaded from a secret manager at
 * startup. (To fetch keys from a KMS on demand, implement KeyProvider.) It keeps its own copy of every
 * key and hands out copies, so wiping or reusing the caller's buffer later, or writing into a returned
 * one, never changes the key it seals and verifies with. Keys must be random bytes: a 16-character
 * password passes the length check with far less than 128 bits of secret.
 */
export class InMemoryKeyProvider implements KeyProvider {
  readonly #keys = new Map<string, Buffer>();
  readonly #activeId: string;

  constructor(keys: Record<string, Uint8Array | string>, activeId: string) {
    for (const [id, key] of Object.entries(keys)) {
      const bytes: unknown = typeof key === 'string' ? Buffer.from(key, 'utf8') : key;
      const copy = bytes instanceof Uint8Array ? ownCopy(bytes) : null;
      if (copy === null || !isUsableKey(copy)) {
        throw new Error(`key '${id}' must be at least ${MIN_KEY_BYTES} bytes (a Buffer, a Uint8Array or a UTF-8 string)`);
      }
      this.#keys.set(id, copy);
    }
    if (!this.#keys.has(activeId)) {
      throw new Error(`activeId '${activeId}' is not present in the keyring`);
    }
    this.#activeId = activeId;
  }

  getKey(writerKeyId: string): Buffer | null {
    const key = this.#keys.get(writerKeyId);
    return key === undefined ? null : ownCopy(key);
  }

  activeKeyId(): string {
    return this.#activeId;
  }
}
