// Value-level verify vectors for the ORDER and EXACTNESS rules. Every check runs per entry, in index
// order, so a verifier that runs one check over ALL entries first would vouch for a forged earlier
// entry. An empty keyring knows no key. The value domain (depth, lone surrogates in KEYS) holds at the
// value level too, not just in a parser. Keys sort by UTF-16 code unit, astral keys included. seq and
// prev_hash compare exactly.

import { createHash, createHmac } from 'node:crypto';
import { MAX_DEPTH, canonicalize } from '../../src/canonicalize.js';
import {
  BROKEN_AT_1, GENESIS, HASH_NEAR_MISSES, K2, KEY_HEX, TWO_KEYS, coreOf, full, head, key, resealAt, resealAt1, seal,
  sealWith,
} from './fixtures.mjs';

const NEVER = { ok: false, last_seq: -1 };
const cp = (...points: number[]): string => String.fromCodePoint(...points);
const sha256 = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');

/** Entry 0 edited WITHOUT the key: call_id changed, so its entry_hash and entry_hmac are stale. */
export const forged0: Record<string, unknown> = { ...full[0]!, call_id: 'cX' };
/** The same forgery with entry_hash recomputed: only the HMAC catches it. */
const rehashedForged0 = { ...forged0, entry_hash: sha256(canonicalize(coreOf(forged0))) };

// CROSS-ENTRY ORDER: a forged entry 0, then a later entry that fails exactly ONE check. Checking that
// one step for all entries before walking them (a domain, seq, link, hash or key-id pre-pass) would
// report the later entry and vouch for entry 0. The oversized-entry case is a generated size vector.
const LATER_FAILURES: [string, Record<string, unknown>][] = [
  ['float', { amount: 1.5 }],
  ['unsafe-integer', { amount: 2 ** 53 }],
  ['lone-surrogate', { note: String.fromCharCode(0xd800) }],
  ['seq-7', { seq: 7 }],
  ['broken-link', { prev_hash: 'e'.repeat(64) }],
  ['unknown-key-id', { writer_key_id: 'nope' }],
];
const CROSS_ENTRY_ORDER_VECTORS = [
  ...LATER_FAILURES.map(([label, change]) => ({
    name: `forged-first-entry-then-${label}-entry`,
    chain: [forged0, full[1], { ...full[2], ...change }],
    expect: NEVER,
  })),
  { name: 'rehashed-forged-first-entry-then-stale-hash-entry', chain: [rehashedForged0, full[1], { ...full[2], call_id: 'cY' }], expect: NEVER },
];

// AN EMPTY KEYRING knows no key: a valid chain, and a keyless forgery whose hashes and links were all
// recomputed (only the stale HMACs are wrong), both break at entry 0. A verifier that falls back to
// "hash chain only" when no keys are configured would accept the forgery.
function relinkedAndRehashed(cores: Record<string, unknown>[]): Record<string, unknown>[] {
  let prev = GENESIS;
  return cores.map((c, i) => {
    const core = { ...c, prev_hash: prev };
    prev = sha256(canonicalize(core));
    return { ...core, entry_hash: prev, entry_hmac: full[i]!.entry_hmac };
  });
}
const EMPTY_KEYRING_VECTORS = [
  { name: 'valid-chain-with-empty-keyring', chain: full, keyring: {}, expect: NEVER },
  {
    name: 'rehashed-forgery-with-empty-keyring',
    chain: relinkedAndRehashed([coreOf(forged0), coreOf(full[1]!), coreOf(full[2]!)]),
    keyring: {},
    expect: NEVER,
  },
];

// No anchor is applied to a chain with a bad entry, wherever it is: the verdict is the bad entry's.
// And an anchor MISSING a field is a wrong anchor, never a partial one: a missing last_hash is not "skip
// the head check", a missing count is not "skip the count check" (absent, not null).
const ANCHOR_AFTER_BAD_ENTRY_VECTORS = [
  { name: 'null-fourth-entry-with-wrong-head-anchor', chain: [...full, null], anchor: { count: 3, last_hash: 'f'.repeat(64) }, expect: { ok: false, last_seq: 2 } },
  { name: 'null-fourth-entry-with-right-anchor', chain: [...full, null], anchor: { count: 3, last_hash: head }, expect: { ok: false, last_seq: 2 } },
  { name: 'anchor-without-last-hash', chain: full, anchor: { count: 3 }, expect: { ok: false, last_seq: 1 } },
  { name: 'anchor-without-count', chain: full, anchor: { last_hash: head }, expect: { ok: false, last_seq: 2 } },
  { name: 'anchor-with-neither-field', chain: full, anchor: {}, expect: { ok: false, last_seq: 2 } },
];

// THE VALUE DOMAIN at the value level. The 101-deep entry carries a hash and HMAC over the JCS text an
// implementation WITHOUT the depth limit would produce; the lone-surrogate entries carry the seal of the
// same entry holding U+FFFD, which is what a lossy UTF-8 encoder turns a lone surrogate into.
const nest = (levels: number, inner: unknown): unknown => (levels === 0 ? inner : [nest(levels - 1, inner)]);
function sealedOverUnlimitedJcs(core: Record<string, unknown>): Record<string, unknown> {
  // Top-level keys sorted; everything below is arrays of one integer, so JSON.stringify is exact JCS.
  const text = JSON.stringify(Object.fromEntries(Object.keys(core).sort().map((k) => [k, core[k]])));
  return { ...core, entry_hash: sha256(text), entry_hmac: createHmac('sha256', key).update(text, 'utf8').digest('hex') };
}
const atDepthLimit = { seq: 0, prev_hash: GENESIS, writer_key_id: 'vault-k1', deep: nest(MAX_DEPTH - 1, 0) };
const overDepthLimit = { seq: 0, prev_hash: GENESIS, writer_key_id: 'vault-k1', deep: nest(MAX_DEPTH, 0) };
if (sealedOverUnlimitedJcs(atDepthLimit).entry_hash !== seal(atDepthLimit).entry_hash) {
  throw new Error('depth vectors: the hand-built JCS text is not canonical');
}
const SEALED_1900 = seal({ seq: 0, prev_hash: GENESIS, writer_key_id: 'vault-k1', amount_cents: 1900 });
const ULP_NEIGHBOURS: [string, number][] = [['above', 1900.0000000000002], ['below', 1899.9999999999998]];
for (const [, value] of ULP_NEIGHBOURS) if (Number.isInteger(value)) throw new Error(`${value} is an integer`);
const FFFD = cp(0xfffd);
function sealedWithFffdThenLone(place: 'key' | 'value', lone: string, after = ''): Record<string, unknown> {
  const sealed = seal({ seq: 0, prev_hash: GENESIS, writer_key_id: 'vault-k1', m: place === 'key' ? { [FFFD + after]: 1 } : FFFD + after });
  return { ...sealed, m: place === 'key' ? { [lone + after]: 1 } : lone + after };
}
const VALUE_DOMAIN_VECTORS = [
  { name: 'entry-nested-exactly-100-deep-verifies', chain: [seal(atDepthLimit)], expect: { ok: true, last_seq: 0 } },
  { name: 'entry-nested-101-deep-sealed-without-the-depth-limit', chain: [sealedOverUnlimitedJcs(overDepthLimit)], expect: NEVER },
  { name: 'lone-high-surrogate-key-sealed-as-fffd', chain: [sealedWithFffdThenLone('key', String.fromCharCode(0xd800))], expect: NEVER },
  { name: 'lone-low-surrogate-key-sealed-as-fffd', chain: [sealedWithFffdThenLone('key', String.fromCharCode(0xdc00))], expect: NEVER },
  { name: 'lone-surrogate-value-sealed-as-fffd', chain: [sealedWithFffdThenLone('value', String.fromCharCode(0xd800))], expect: NEVER },
  // A high surrogate followed by a unit in U+E000..U+FFFF is still lone: a pairing check that forgets
  // the upper bound of the low-surrogate range (<= 0xDFFF) would accept it.
  ...([['value', 0xe000], ['value', 0xffff], ['key', 0xf900]] as const).map(([place, next]) => ({
    name: `high-surrogate-before-u${next.toString(16)}-in-${place}-sealed-as-fffd`,
    chain: [sealedWithFffdThenLone(place, String.fromCharCode(0xd800), String.fromCharCode(next))],
    expect: NEVER,
  })),
  {
    name: 'entry-nested-101-deep-at-index-1',
    chain: [full[0], sealedOverUnlimitedJcs({ seq: 1, prev_hash: full[0]!.entry_hash, writer_key_id: 'vault-k1', deep: nest(MAX_DEPTH, 0) })],
    expect: BROKEN_AT_1,
  },
  // A NON-integer right next to an integer is outside the domain too. Each carries the seal of the
  // integer, which is what an integrality test with a tolerance (or a round trip through 15 significant
  // digits) would compute, so such a verifier accepts the keyless change.
  ...ULP_NEIGHBOURS.map(([side, value]) => ({
    name: `integer-replaced-by-its-1-ulp-neighbour-${side}`,
    chain: [{ ...SEALED_1900, amount_cents: value }],
    expect: NEVER,
  })),
  // Keys inserted OUT of order: two sharing the high surrogate 0xD83D, then U+10000 (0xD800), U+E000
  // and U+FFFF. Canonical order is by UTF-16 unit: U+10000, U+1F600, U+1F601, U+E000, U+FFFF.
  {
    name: 'astral-keys-inserted-out-of-order-verify',
    chain: [seal({ seq: 0, prev_hash: GENESIS, writer_key_id: 'vault-k1', m: { [cp(0x1f601)]: 1, [cp(0x1f600)]: 2, [cp(0x10000)]: 3, [cp(0xe000)]: 4, [cp(0xffff)]: 5 } })],
    expect: { ok: true, last_seq: 0 },
  },
];

// seq is EXACTLY the index and prev_hash EXACTLY the previous entry_hash (or the genesis hash): no
// ">= i", no whitespace stripping, no prefix match. Every entry below is validly resealed, so only the
// seq or link check can catch it.
const PREV_HASH_MUTATIONS: [string, (v: string) => string][] = [
  ['trailing-space', (v) => `${v} `],
  ['leading-space', (v) => ` ${v}`],
  ['trailing-lf', (v) => v + String.fromCharCode(10)],
  // (Not the lone surrogate: prev_hash is sealed content here, and a lone surrogate has no canonical form.)
  ...HASH_NEAR_MISSES.filter(([label]) => label !== 'lone-surrogate-appended'),
];
const SEQ_AND_LINK_VECTORS = [
  { name: 'resealed-seq-2-at-index-1', chain: resealAt1((c) => ({ ...c, seq: 2 })), expect: BROKEN_AT_1 },
  { name: 'resealed-seq-0-at-index-1', chain: resealAt1((c) => ({ ...c, seq: 0 })), expect: BROKEN_AT_1 },
  // ...and on the LAST entry, where no later link would notice.
  ...([['string', '2'], ['bool', true], ['array', [2]], ['null', null], ['3', 3], ['1', 1]] as const).map(([label, seq]) => ({
    name: `resealed-seq-${label}-at-last`, chain: resealAt(2, (c) => ({ ...c, seq })), expect: { ok: false, last_seq: 1 },
  })),
  ...PREV_HASH_MUTATIONS.flatMap(([label, mutate]) => [
    { name: `resealed-prev-hash-${label}-at-first`, chain: [seal({ ...coreOf(full[0]!), prev_hash: mutate(GENESIS) }), full[1], full[2]], expect: NEVER },
    { name: `resealed-prev-hash-${label}-at-middle`, chain: resealAt1((c) => ({ ...c, prev_hash: mutate(String(c.prev_hash)) })), expect: BROKEN_AT_1 },
  ]),
  // The genesis hash is the link of entry 0 ONLY; and a null or empty link, or a null seq, is no link.
  { name: 'resealed-prev-hash-genesis-at-middle', chain: resealAt1((c) => ({ ...c, prev_hash: GENESIS })), expect: BROKEN_AT_1 },
  { name: 'resealed-prev-hash-null-at-first', chain: [seal({ ...coreOf(full[0]!), prev_hash: null })], expect: NEVER },
  { name: 'resealed-prev-hash-empty-at-first', chain: [seal({ ...coreOf(full[0]!), prev_hash: '' })], expect: NEVER },
  { name: 'resealed-seq-null-at-first', chain: [seal({ ...coreOf(full[0]!), seq: null })], expect: NEVER },
];

// Hash NEAR MISSES (fixtures.mts) on the anchor's last_hash, and on the last entry's hash fields under the
// TRUE anchor: a verifier that links or anchors on the hash it recomputed, instead of the stored one,
// passes those unless the stored field is compared exactly. Plus anchor count and one-entry edges.
const ANCHOR_EXACTNESS_VECTORS = [
  ...HASH_NEAR_MISSES.map(([label, mutate]) => ({
    name: `anchor-last-hash-${label}`, chain: full, anchor: { count: 3, last_hash: mutate(head) }, expect: { ok: false, last_seq: 1 },
  })),
  ...(['entry_hash', 'entry_hmac'] as const).flatMap((field) =>
    HASH_NEAR_MISSES.map(([label, mutate]) => ({
      name: `${field.replace('_', '-')}-${label}-at-last-under-the-true-anchor`,
      chain: full.map((e, i) => (i === 2 ? { ...e, [field]: mutate(e[field] as string) } : e)),
      anchor: { count: 3, last_hash: head },
      expect: { ok: false, last_seq: 1 },
    })),
  ),
  { name: 'anchor-count-not-an-integer', chain: full, anchor: { count: 2.5, last_hash: head }, expect: { ok: false, last_seq: 2 } },
  // count compares as the exact number: not truncated (3.5 -> 3), not the next double rounded, not ToInt32.
  { name: 'anchor-count-3.5', chain: full, anchor: { count: 3.5, last_hash: head }, expect: { ok: false, last_seq: 2 } },
  { name: 'anchor-count-one-ulp-above-3', chain: full, anchor: { count: 3.0000000000000004, last_hash: head }, expect: { ok: false, last_seq: 2 } },
  { name: 'anchor-count-2-pow-32-plus-3', chain: full, anchor: { count: 4294967299, last_hash: head }, expect: { ok: false, last_seq: 2 } },
  { name: 'one-entry-chain-with-wrong-head-anchor', chain: full.slice(0, 1), anchor: { count: 1, last_hash: 'f'.repeat(64) }, expect: NEVER },
];

// KEYRING SEMANTICS: rotating back to an earlier key verifies; an unused short key beside the real one is
// harmless; a key id that differs from the keyring's only by Unicode normalization is unknown (ids are
// compared exactly); an empty chain verifies under an empty keyring (no entry needs a key).
function sealedWithKeys(steps: [string, Buffer][]): Record<string, unknown>[] {
  let prev = GENESIS;
  return steps.map(([id, k], seq) => {
    const entry = sealWith({ seq, prev_hash: prev, writer_key_id: id, note: id }, k);
    prev = entry.entry_hash as string;
    return entry;
  });
}
const NFC_ID = `k${cp(0xe9)}`;
const NFD_ID = `ke${cp(0x301)}`;
const KEYRING_SEMANTICS_VECTORS = [
  { name: 'rotation-back-to-an-earlier-key-verifies', chain: sealedWithKeys([['vault-k1', key], ['k2', K2], ['vault-k1', key]]), keyring: TWO_KEYS, expect: { ok: true, last_seq: 2 } },
  { name: 'unused-short-key-in-the-keyring-is-harmless', chain: full, keyring: { 'vault-k1': KEY_HEX, short: Buffer.alloc(15, 1).toString('hex') }, expect: { ok: true, last_seq: 2 } },
  { name: 'key-id-differing-only-by-normalization-is-unknown', chain: sealedWithKeys([[NFD_ID, key]]), keyring: { [NFC_ID]: KEY_HEX }, expect: NEVER },
  { name: 'empty-chain-with-empty-keyring-verifies', chain: [], keyring: {}, expect: { ok: true, last_seq: -1 } },
];

// KEYLESS REORDERS of genuine entries in the middle of the chain: each breaks at the first misplaced
// entry (and each gets later-failure twins, see derive.mts).
const REORDER_VECTORS = [
  { name: 'middle-entries-swapped', chain: [full[0], full[2], full[1]], expect: { ok: false, last_seq: 0 } },
  { name: 'middle-entry-replayed', chain: [full[0], full[1], full[1], full[2]], expect: { ok: false, last_seq: 1 } },
  { name: 'middle-entry-deleted', chain: [full[0], full[2]], expect: { ok: false, last_seq: 0 } },
];

export const ORDER_AND_EXACTNESS_VECTORS = [
  ...CROSS_ENTRY_ORDER_VECTORS, ...EMPTY_KEYRING_VECTORS, ...ANCHOR_AFTER_BAD_ENTRY_VECTORS, ...VALUE_DOMAIN_VECTORS,
  ...SEQ_AND_LINK_VECTORS, ...ANCHOR_EXACTNESS_VECTORS, ...KEYRING_SEMANTICS_VECTORS, ...REORDER_VECTORS,
];
