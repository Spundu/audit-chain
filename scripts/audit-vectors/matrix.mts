// Value-level verify vectors in matrix form: every derived-field mutation, appended entries, link and
// key-id types, forgery beyond an anchored prefix, empty-ish core members and keyring edges.

import { createHash } from 'node:crypto';
import { canonicalize } from '../../src/canonicalize.js';
import {
  BROKEN_AT_1, HASH_NEAR_MISSES, KEY_HEX, full, head, key, oneEntry, oneEntrySealedWith, rehashedAt1, resealAt1, withField1,
  withFieldAt,
} from './fixtures.mjs';

// DERIVED-FIELD MATRIX: each field must be PRESENT and EXACTLY the 64-char lowercase-hex string. Every
// mutation below, on a middle entry (index 1) and on the last entry (index 2), must break the chain at
// that entry: a verifier that skips an absent/null/empty field, trims whitespace, or compares decoded
// bytes would accept these keyless edits.
const TAB = String.fromCharCode(9);
const LF_CHAR = String.fromCharCode(10);
const REMOVE = Symbol('remove');
const FIELD_MUTATIONS: [string, (v: string) => unknown][] = [
  ['absent', () => REMOVE],
  ['null', () => null],
  ['empty', () => ''],
  ['trailing-space', (v) => `${v} `],
  ['leading-space', (v) => ` ${v}`],
  ['spaced-bytes', (v) => (v.match(/../g) ?? []).join(' ')],
  ['trailing-tab', (v) => v + TAB],
  ['trailing-lf', (v) => v + LF_CHAR],
  ['suffix-zz', (v) => `${v}zz`],
  ['suffix-g0', (v) => `${v}g0`],
  ['truncated-to-1', (v) => v.slice(0, 1)],
  ...HASH_NEAR_MISSES,
  // Right length, not ASCII / not well-formed: a verifier that compares these as native strings with a
  // byte-length or ASCII-only primitive THROWS instead of breaking the chain.
  ['non-ascii-64', () => String.fromCharCode(0xe9).repeat(64)],
  ['lone-surrogates-64', () => String.fromCharCode(0xd800).repeat(64)],
];
function mutatedEntry(index: number, field: 'entry_hash' | 'entry_hmac', mutate: (v: string) => unknown): Record<string, unknown> {
  const entry: Record<string, unknown> = { ...full[index]! };
  const next = mutate(entry[field] as string);
  if (next === REMOVE) delete entry[field];
  else entry[field] = next;
  return entry;
}
export const DERIVED_FIELD_VECTORS = (['entry_hmac', 'entry_hash'] as const).flatMap((field) =>
  FIELD_MUTATIONS.flatMap(([label, mutate]) =>
    [0, 1, 2].map((index) => ({
      name: `${field.replace('_', '-')}-${label}-at-${['first', 'middle', 'last'][index]}`,
      chain: full.map((e, i) => (i === index ? mutatedEntry(index, field, mutate) : e)),
      expect: { ok: false, last_seq: index - 1 },
    })),
  ),
);
// A keyless attacker APPENDS an entry: correctly linked and hashed, but with no HMAC, or with neither
// derived member. The chain verifies up to the real head and breaks at the appended entry.
const appendedCore = { seq: 3, prev_hash: head, writer_key_id: 'vault-k1', note: 'appended without the key' };
const appendedHash = createHash('sha256').update(canonicalize(appendedCore), 'utf8').digest('hex');
export const APPENDED_VECTORS = [
  { name: 'appended-entry-without-hmac', chain: [...full, { ...appendedCore, entry_hash: appendedHash }], expect: { ok: false, last_seq: 2 } },
  { name: 'appended-entry-without-derived-fields', chain: [...full, appendedCore], expect: { ok: false, last_seq: 2 } },
  // Members whose names only RESEMBLE the derived fields are sealed content, not derived fields.
  { name: 'unsealed-uppercase-entry-hash-member', chain: withFieldAt(1, 'ENTRY_HASH', 'x'), expect: BROKEN_AT_1 },
  { name: 'unsealed-mixed-case-entry-hmac-member', chain: withFieldAt(1, 'Entry_Hmac', 'x'), expect: BROKEN_AT_1 },
  { name: 'unsealed-entry-hash-with-trailing-space-member', chain: withFieldAt(1, 'entry_hash ', 'x'), expect: BROKEN_AT_1 },
  { name: 'resealed-writer-key-id-with-leading-space', chain: resealAt1((c) => ({ ...c, writer_key_id: ' vault-k1' })), expect: BROKEN_AT_1 },
];

// LINK and KEY-ID fields that are the right length but not ASCII / not well-formed: never a throw.
const E_ACUTE_64 = String.fromCharCode(0xe9).repeat(64);
const LONE_64 = String.fromCharCode(0xd800).repeat(64);
export const LINK_TYPE_VECTORS = [
  ...([['non-ascii', E_ACUTE_64], ['lone-surrogates', LONE_64]] as const).flatMap(([label, value]) =>
    [0, 1, 2].map((index) => ({
      name: `prev-hash-${label}-64-at-${['first', 'middle', 'last'][index]}`,
      chain: withFieldAt(index, 'prev_hash', value),
      expect: { ok: false, last_seq: index - 1 },
    })),
  ),
  { name: 'rehashed-non-ascii-writer-key-id', chain: rehashedAt1({ writer_key_id: String.fromCharCode(0xe9).repeat(8) }), expect: BROKEN_AT_1 },
  { name: 'two-adjacent-lone-high-surrogates-in-payload', chain: withField1('note', String.fromCharCode(0xd800, 0xd800)), expect: BROKEN_AT_1 },
];

// FORGERY BEYOND AN ANCHORED PREFIX: the anchor never excuses a later entry. Entry 2 is forged without
// the key; an anchor pinning only entries 0..1 (right or wrong head), or fewer, must not change that the
// chain breaks AT the forged entry.
const forgedAt2 = full.map((e, i) => (i === 2 ? { ...e, entry_hmac: '0'.repeat(64) } : e));
export const ANCHORED_FORGERY_VECTORS = [
  { name: 'forged-entry-beyond-anchor-count', chain: forgedAt2, anchor: { count: 2, last_hash: full[1]!.entry_hash }, expect: { ok: false, last_seq: 1 } },
  { name: 'forged-entry-beyond-anchor-with-wrong-head', chain: forgedAt2, anchor: { count: 2, last_hash: 'f'.repeat(64) }, expect: { ok: false, last_seq: 1 } },
  { name: 'forged-entry-beyond-short-anchor', chain: forgedAt2, anchor: { count: 1, last_hash: full[0]!.entry_hash }, expect: { ok: false, last_seq: 1 } },
];

// THE CORE keeps EVERY member, whatever its value: false, 0, "", " ", [], {} and null (also under a
// record-schema name) are sealed content. Added without the key, each breaks the chain at that entry;
// sealed with the key, an entry holding all of them verifies.
const EMPTYISH: [string, string, unknown][] = [
  ['false', 'extra', false], ['zero', 'extra', 0], ['empty-string', 'extra', ''], ['space', 'extra', ' '],
  ['empty-array', 'extra', []], ['empty-object', 'extra', {}], ['null-decision', 'decision', null], ['null-session-id', 'session_id', null],
];
export const CORE_MEMBER_VECTORS = [
  ...EMPTYISH.flatMap(([label, field, value]) =>
    [1, 2].map((index) => ({
      name: `unsealed-${label}-member-added-at-${index === 1 ? 'middle' : 'last'}`,
      chain: withFieldAt(index, field, value),
      expect: { ok: false, last_seq: index - 1 },
    })),
  ),
  {
    name: 'sealed-emptyish-members-verify',
    chain: oneEntry({ a: false, b: 0, c: '', d: ' ', e: [], f: {}, g: null, nested: { h: [null, false, 0, '', [], {}] } }),
    expect: { ok: true, last_seq: 0 },
  },
];

// KEYRING edges: an empty-string key id and a key longer than the HMAC block size are ordinary keys.
export const KEYRING_EDGE_VECTORS = [
  { name: 'empty-string-key-id-verifies', chain: oneEntrySealedWith('', key), keyring: { '': KEY_HEX }, expect: { ok: true, last_seq: 0 } },
  { name: 'key-longer-than-hmac-block-verifies', chain: oneEntrySealedWith('long', Buffer.alloc(100, 0x42)), keyring: { long: Buffer.alloc(100, 0x42).toString('hex') }, expect: { ok: true, last_seq: 0 } },
];
