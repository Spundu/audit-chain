// Seal vectors, and the value-level verify vectors for malformed-hmac, structural and anchor cases.

import {
  BROKEN_AT_1, K2, KEY_HEX, TWO_KEYS, baseChain, coreOf, full, head, key, oneEntry, oneEntrySealedWith,
  omit, realHmac1, rehashedAt1, resealAt1, rotated, seal, withField1, withFieldAt, withHmacAt1,
} from './fixtures.mjs';

interface Vector {
  name: string;
  core: unknown;
}

// Representative cores: an example audit record (any JSON object can be sealed) with nested actor,
// decision and result objects, hash-like fields, unicode in a nested field, and the genesis-linked
// first entry.
export const VECTORS: Vector[] = [
  {
    name: 'genesis-approval-minimal',
    core: {
      v: 1, seq: 0, event: 'payment.approval', request_id: 'r1', service: 'payments',
      prev_hash: '0'.repeat(64), writer_key_id: 'k1',
    },
  },
  {
    name: 'payment-settled-nested',
    core: {
      v: 1, seq: 1, event: 'payment.settled', request_id: 'r2', session_id: 's1',
      actor: { name: 'alice', role: 'admin' }, service: 'payments',
      ts_unix_ms: 1_700_000_000_000, instance_id: 'i-xyz', host_id: 'host-1',
      operation: 'payments.capture', category: 'money',
      request_hash: 'a'.repeat(64), document_hash: 'r'.repeat(64), nonce: 'example-nonce',
      decision: { level: 'review', outcome: 'executed', by: 'bob', reason: 'approved' },
      result: { status: 'ok', duration_ms: 120, amount_pence: 1900 },
      prev_hash: 'e'.repeat(64), writer_key_id: 'k1',
    },
  },
  {
    // null is sealed content (not pruned by the seal primitive), and derived-looking names nested
    // below the top level are ordinary members.
    name: 'null-members-and-nested-derived-names',
    core: {
      v: 1, seq: 0, event: 'note', request_id: 'r0', service: 'payments', prev_hash: '0'.repeat(64), writer_key_id: 'k1',
      x: null, meta: { entry_hash: 'e'.repeat(64), entry_hmac: 'm' }, list: [null, { entry_hmac: 'n' }],
    },
  },
  {
    name: 'unicode-in-nested-reason',
    core: {
      v: 1, seq: 2, event: 'payment.approval', request_id: 'r3', service: 'payments',
      decision: { level: 'blocked', outcome: 'denied', by: 'policy', reason: 'café — 日本語 🎉' },
      prev_hash: 'f'.repeat(64), writer_key_id: 'k1',
    },
  },
];

// VERIFY vectors: materialised chains + the outcome BOTH verifiers must report (error wording is
// language-local; ok/last_seq are not). This first group pins fail-closed behaviour on a malformed
// entry_hmac: every case must return ok:false at index 1 (last_seq 0) and must never throw.
export const VERIFY_VECTORS = [
  { name: 'valid-chain', chain: baseChain(), expect: { ok: true, last_seq: 2 } },
  { name: 'hmac-non-hex-right-length', chain: withHmacAt1('z'.repeat(64)), expect: BROKEN_AT_1 },
  { name: 'hmac-non-ascii', chain: withHmacAt1('é'.repeat(64)), expect: BROKEN_AT_1 },
  { name: 'hmac-lone-surrogate', chain: withHmacAt1('\ud800'.repeat(64)), expect: BROKEN_AT_1 },
  { name: 'hmac-uppercase-of-real', chain: withHmacAt1(realHmac1.toUpperCase()), expect: BROKEN_AT_1 },
  { name: 'hmac-truncated', chain: withHmacAt1(realHmac1.slice(0, 63)), expect: BROKEN_AT_1 },
  { name: 'hmac-empty', chain: withHmacAt1(''), expect: BROKEN_AT_1 },
  { name: 'hmac-null', chain: withHmacAt1(null), expect: BROKEN_AT_1 },
];

// STRUCTURAL vectors: malformed shapes a verifier parsing untrusted JSON will meet. Entries marked
// "resealed" carry a VALID entry_hash + entry_hmac under the real key, so the only thing wrong is the
// shape; both verifiers must still refuse it at index 1, never accept it and never throw.
const withProto = (value: unknown) => (core: Record<string, unknown>) => {
  const out: Record<string, unknown> = { ...core };
  Object.defineProperty(out, '__proto__', { value, enumerable: true, writable: true, configurable: true });
  return out;
};
const protoChain = resealAt1(withProto({ amount: '19.00' })) as Record<string, unknown>[];
const protoTampered = protoChain.map((e, i) => {
  if (i !== 1) return e;
  const out: Record<string, unknown> = { ...e };
  Object.defineProperty(out, '__proto__', { value: { amount: '1900.00' }, enumerable: true, writable: true });
  return out;
});
// The resealed __proto__ entry is VALID at index 1, so the break moves to index 2 (whose prev_hash still
// points at the original entry 1): what matters is that index 1 verifies in both and its tamper does not.
export const STRUCTURAL_VECTORS = [
  { name: 'entries-not-an-array', chain: { 0: baseChain()[0] }, expect: { ok: false, last_seq: -1 } },
  { name: 'entries-is-an-empty-object', chain: {}, expect: { ok: false, last_seq: -1 } },
  { name: 'entries-is-a-string', chain: '', expect: { ok: false, last_seq: -1 } },
  { name: 'entries-is-null', chain: null, expect: { ok: false, last_seq: -1 } },
  { name: 'entry-null', chain: [baseChain()[0], null], expect: BROKEN_AT_1 },
  { name: 'entry-is-an-array', chain: [baseChain()[0], []], expect: BROKEN_AT_1 },
  { name: 'entry-is-a-string', chain: [baseChain()[0], 'x'], expect: BROKEN_AT_1 },
  { name: 'resealed-seq-as-string', chain: resealAt1((c) => ({ ...c, seq: '1' })), expect: BROKEN_AT_1 },
  { name: 'resealed-seq-as-bool', chain: resealAt1((c) => ({ ...c, seq: true })), expect: BROKEN_AT_1 },
  // Resealed (valid hash + HMAC) with prev_hash spelled in UPPERCASE: the linkage compare is exact.
  { name: 'resealed-prev-hash-uppercased', chain: resealAt1((c) => ({ ...c, prev_hash: String(c.prev_hash).toUpperCase() })), expect: BROKEN_AT_1 },
  // A NUMERIC writer_key_id is not the string "1", even when the keyring has a key named "1".
  {
    name: 'resealed-numeric-writer-key-id',
    chain: resealAt1((c) => ({ ...c, writer_key_id: 1 })),
    keyring: { 'k1': KEY_HEX, '1': KEY_HEX },
    expect: BROKEN_AT_1,
  },
  { name: 'resealed-unknown-writer-key-id', chain: resealAt1((c) => ({ ...c, writer_key_id: 'unknown-key' })), expect: BROKEN_AT_1 },
  { name: 'key-of-15-bytes-is-unknown', chain: oneEntrySealedWith('short', Buffer.alloc(15, 7)), keyring: { short: Buffer.alloc(15, 7).toString('hex') }, expect: { ok: false, last_seq: -1 } },
  { name: 'key-of-exactly-16-bytes-verifies', chain: oneEntrySealedWith('min', Buffer.alloc(16, 7)), keyring: { min: Buffer.alloc(16, 7).toString('hex') }, expect: { ok: true, last_seq: 0 } },
  { name: 'resealed-writer-key-id-list', chain: resealAt1((c) => ({ ...c, writer_key_id: ['k1'] })), expect: BROKEN_AT_1 },
  {
    name: 'resealed-writer-key-id-missing',
    chain: resealAt1(({ writer_key_id: _w, ...c }) => c),
    expect: BROKEN_AT_1,
  },
  { name: 'non-canonical-float-payload', chain: withField1('amount', 1.5), expect: BROKEN_AT_1 },
  { name: 'non-canonical-unsafe-integer', chain: withField1('amount', 2 ** 53), expect: BROKEN_AT_1 },
  { name: 'non-canonical-lone-surrogate', chain: withField1('note', '\ud800'), expect: BROKEN_AT_1 },
  // ONLY entry_hash changed (the HMAC covers the core bytes, not entry_hash, so it still matches): the
  // entry_hash check alone must catch these, at the entry itself.
  { name: 'entry-hash-only-changed-on-last-entry', chain: withFieldAt(2, 'entry_hash', 'f'.repeat(64)), expect: { ok: false, last_seq: 1 } },
  { name: 'entry-hash-only-changed-on-middle-entry', chain: withFieldAt(1, 'entry_hash', 'f'.repeat(64)), expect: BROKEN_AT_1 },
  { name: 'entry-hash-uppercased', chain: withFieldAt(1, 'entry_hash', (baseChain()[1]!.entry_hash as string).toUpperCase()), expect: BROKEN_AT_1 },
  { name: 'prev-hash-uppercased', chain: withFieldAt(1, 'prev_hash', (baseChain()[0]!.entry_hash as string).toUpperCase()), expect: BROKEN_AT_1 },
  { name: 'proto-member-is-sealed', chain: protoChain, expect: { ok: false, last_seq: 1 } },
  { name: 'proto-member-tamper-detected', chain: protoTampered, expect: BROKEN_AT_1 },
];

// ANCHOR vectors: tail truncation is invisible to the chain alone and caught only against an anchor.
const NESTED = { x: null, meta: { entry_hash: 'e'.repeat(64), entry_hmac: 'm' }, list: [{ entry_hmac: 'n' }] };

export const ANCHOR_VECTORS = [
  { name: 'truncated-no-anchor-verifies', chain: full.slice(0, 2), expect: { ok: true, last_seq: 1 } },
  {
    name: 'truncated-with-anchor',
    chain: full.slice(0, 2),
    anchor: { count: 3, last_hash: head },
    expect: { ok: false, last_seq: 1 },
  },
  { name: 'full-with-anchor', chain: full, anchor: { count: 3, last_hash: head }, expect: { ok: true, last_seq: 2 } },
  {
    name: 'anchor-head-mismatch',
    chain: full,
    anchor: { count: 3, last_hash: 'f'.repeat(64) },
    expect: { ok: false, last_seq: 1 },
  },
  { name: 'anchor-count-is-a-bool', chain: full.slice(0, 1), anchor: { count: true, last_hash: full[0]!.entry_hash }, expect: { ok: false, last_seq: 0 } },
  { name: 'anchor-count-is-a-string', chain: full, anchor: { count: '3', last_hash: head }, expect: { ok: false, last_seq: 2 } },
  // THE CORE is the entry minus exactly the two TOP-LEVEL fields entry_hash and entry_hmac. Nothing
  // else is excluded: a null member, an entry_* member, or derived-looking keys nested deeper are all
  // sealed content, so adding or editing one without the key breaks the chain at that entry.
  { name: 'unsealed-null-member-added', chain: withFieldAt(1, 'x', null), expect: BROKEN_AT_1 },
  { name: 'unsealed-entry-prefixed-member-added', chain: withFieldAt(1, 'entry_note', 'hi'), expect: BROKEN_AT_1 },
  { name: 'sealed-null-and-nested-derived-names-verify', chain: oneEntry(NESTED), expect: { ok: true, last_seq: 0 } },
  {
    name: 'nested-derived-name-edited-without-key',
    chain: [{ ...oneEntry(NESTED)[0], meta: { entry_hash: 'f'.repeat(64), entry_hmac: 'm' } }],
    expect: { ok: false, last_seq: -1 },
  },
  // KEY SELECTION is by writer_key_id, with distinct key bytes: a rotation k1 -> k2 verifies; an entry
  // LABELLED k2 but sealed with k1's key does not ("any known key" and "first key" verifiers fail here).
  { name: 'rotation-to-a-second-key-verifies', chain: rotated(K2), keyring: TWO_KEYS, expect: { ok: true, last_seq: 1 } },
  { name: 'labelled-second-key-sealed-with-first', chain: rotated(key), keyring: TWO_KEYS, expect: BROKEN_AT_1 },
  // Hash fields are exact STRINGS: the right hex wrapped in an array is not a match.
  { name: 'entry-hmac-wrapped-in-array', chain: withFieldAt(1, 'entry_hmac', [realHmac1]), expect: BROKEN_AT_1 },
  { name: 'entry-hmac-wrapped-in-nested-array', chain: withFieldAt(1, 'entry_hmac', [[realHmac1]]), expect: BROKEN_AT_1 },
  { name: 'entry-hash-wrapped-in-array', chain: withFieldAt(1, 'entry_hash', [full[1]!.entry_hash]), expect: BROKEN_AT_1 },
  // seq and prev_hash are REQUIRED, not defaulted: validly sealed entries missing either break at 0.
  { name: 'first-entry-missing-prev-hash', chain: [seal(omit(coreOf(full[0]!), 'prev_hash'))], expect: { ok: false, last_seq: -1 } },
  { name: 'first-entry-missing-seq', chain: [seal(omit(coreOf(full[0]!), 'seq'))], expect: { ok: false, last_seq: -1 } },
  // A writer_key_id naming an Object.prototype member is just an unknown id (never a lookup crash).
  { name: 'writer-key-id-proto', chain: rehashedAt1({ writer_key_id: '__proto__' }), expect: BROKEN_AT_1 },
  { name: 'writer-key-id-constructor', chain: rehashedAt1({ writer_key_id: 'constructor' }), expect: BROKEN_AT_1 },
  // Null / empty anchor fields are a WRONG anchor, not "no anchor".
  { name: 'anchor-count-null', chain: full, anchor: { count: null, last_hash: head }, expect: { ok: false, last_seq: 2 } },
  { name: 'anchor-last-hash-empty', chain: full, anchor: { count: 3, last_hash: '' }, expect: { ok: false, last_seq: 1 } },
  { name: 'anchor-last-hash-null', chain: full, anchor: { count: 3, last_hash: null }, expect: { ok: false, last_seq: 1 } },
  // HEAD truncation: seq is ABSOLUTE (entry i has seq i) and entry 0 must link to the genesis hash, so
  // deleting the first entries is detected without any anchor. Validly sealed, wrong only in position.
  { name: 'head-dropped', chain: full.slice(1), expect: { ok: false, last_seq: -1 } },
  { name: 'first-entry-seq-1-at-genesis', chain: [seal({ ...coreOf(full[1]!), prev_hash: '0'.repeat(64) })], expect: { ok: false, last_seq: -1 } },
  { name: 'first-entry-seq-0-not-at-genesis', chain: [seal({ ...coreOf(full[0]!), prev_hash: 'e'.repeat(64) })], expect: { ok: false, last_seq: -1 } },
  // ORDER: the anchor is checked only AFTER every entry verifies, so a forged early entry is reported
  // at its own index even when the anchor is also wrong. An anchor-first verifier would vouch for it.
  { name: 'forged-first-entry-and-wrong-count-anchor', chain: withFieldAt(0, 'entry_hmac', '0'.repeat(64)), anchor: { count: 5, last_hash: head }, expect: { ok: false, last_seq: -1 } },
  { name: 'forged-first-entry-and-wrong-head-anchor', chain: withFieldAt(0, 'entry_hmac', '0'.repeat(64)), anchor: { count: 3, last_hash: 'f'.repeat(64) }, expect: { ok: false, last_seq: -1 } },
  // count must EQUAL the chain length: a longer chain than anchored is not "fine" (that is checkpoint
  // semantics, which only the writer uses).
  { name: 'anchor-count-less-than-chain-length', chain: full, anchor: { count: 2, last_hash: full[1]!.entry_hash }, expect: { ok: false, last_seq: 2 } },
  { name: 'anchor-head-uppercased', chain: full, anchor: { count: 3, last_hash: head.toUpperCase() }, expect: { ok: false, last_seq: 1 } },
  { name: 'anchor-count-is-an-object', chain: full, anchor: { count: { toString: 1 }, last_hash: head }, expect: { ok: false, last_seq: 2 } },
  { name: 'empty-chain-anchored-at-genesis', chain: [], anchor: { count: 0, last_hash: '0'.repeat(64) }, expect: { ok: true, last_seq: -1 } },
  { name: 'empty-chain-anchored-at-count-1', chain: [], anchor: { count: 1, last_hash: head }, expect: { ok: false, last_seq: -1 } },
  // CROSS-ENTRY ORDER: every check runs per entry, in index order. A verifier that pre-scans all entry
  // types, or checks every seal before any link, would vouch for a forged or misplaced entry 0.
  { name: 'forged-first-entry-then-null-entry', chain: [{ ...full[0], entry_hmac: '0'.repeat(64) }, null], expect: { ok: false, last_seq: -1 } },
  { name: 'head-dropped-then-forged', chain: [full[1], { ...full[2], entry_hmac: '0'.repeat(64) }], expect: { ok: false, last_seq: -1 } },
  { name: 'swapped-head-then-forged', chain: [full[1], full[0], { ...full[2], entry_hmac: '0'.repeat(64) }], expect: { ok: false, last_seq: -1 } },
  // LOOSE TYPE MATCHING: links, positions, key ids and anchor fields compare exactly (all resealed).
  { name: 'resealed-prev-hash-wrapped-in-array', chain: resealAt1((c) => ({ ...c, prev_hash: [c.prev_hash] })), expect: BROKEN_AT_1 },
  { name: 'resealed-seq-wrapped-in-array', chain: resealAt1((c) => ({ ...c, seq: [1] })), expect: BROKEN_AT_1 },
  { name: 'resealed-writer-key-id-case-variant', chain: resealAt1((c) => ({ ...c, writer_key_id: 'K1' })), expect: BROKEN_AT_1 },
  { name: 'first-entry-genesis-spelled-0', chain: [seal({ ...coreOf(full[0]!), prev_hash: '0' })], expect: { ok: false, last_seq: -1 } },
  { name: 'anchor-count-wrapped-in-array', chain: full, anchor: { count: [3], last_hash: head }, expect: { ok: false, last_seq: 2 } },
  { name: 'anchor-last-hash-wrapped-in-array', chain: full, anchor: { count: 3, last_hash: [head] }, expect: { ok: false, last_seq: 1 } },
  // An HMAC with one or two extra hex digits: Node's Buffer.from(hex) silently drops a trailing odd
  // nibble, so only an exact length check stops the 65-char form from matching.
  { name: 'hmac-real-plus-one-hex-digit', chain: withHmacAt1(`${realHmac1}0`), expect: BROKEN_AT_1 },
  { name: 'hmac-real-plus-two-hex-digits', chain: withHmacAt1(`${realHmac1}00`), expect: BROKEN_AT_1 },
  { name: 'empty-chain-anchor-head-mismatch', chain: [], anchor: { count: 0, last_hash: 'x' }, expect: { ok: false,last_seq: -1 } },
];
