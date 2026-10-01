// THE CORE DEFINITION: the core of an entry is the entry minus EXACTLY its two top-level members named
// "entry_hash" and "entry_hmac", compared as exact strings. Everything else is sealed content: a derived
// NAME anywhere but the root, and any key that merely resembles a derived name (after NUL truncation,
// NFKC or Unicode look-alikes, a case or separator change). A verifier that strips derived members from
// the line TEXT, or recognizes derived names loosely, drops attacker-added members from what it hashes.
//
// Also here: value-level domain rules against a plain RFC 8785 / JSON.stringify serializer, brackets
// inside strings (a naive bracket-counting depth check rejects valid chains), and writer_key_id null
// against a keyring that has an empty-string id (a null-to-zero-value conversion must not find a key).

import { createHash, createHmac } from 'node:crypto';
import { canonicalize } from '../../src/canonicalize.js';
import { BROKEN_AT_1, GENESIS, KEY_HEX, full, key, resealAt, resealAt1, seal, withFieldAt } from './fixtures.mjs';

const NEVER = { ok: false, last_seq: -1 };
const LF = String.fromCharCode(10);
const NUL = String.fromCharCode(0);
const sha256 = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');
const hmac = (text: string): string => createHmac('sha256', key).update(text, 'utf8').digest('hex');

// ---- keys that RESEMBLE a derived name: each added, unsealed, to entry 1 must break it ----------------
const DERIVED_NAMES = ['entry_hash', 'entry_hmac'] as const;
const fullwidth = (s: string): string =>
  [...s].map((c) => (c === '_' ? String.fromCharCode(0xff3f) : String.fromCharCode(0xff41 + c.charCodeAt(0) - 97))).join('');
const LOOK_ALIKES: [string, (name: string) => string][] = [
  ['nul-suffixed', (n) => n + NUL],
  ['nul-then-text', (n) => `${n}${NUL}x`],
  ['fullwidth', fullwidth],
  ['fullwidth-underscore', (n) => n.replace('_', String.fromCharCode(0xff3f))],
  ['small-low-line', (n) => n.replace('_', String.fromCharCode(0xfe4d))],
  ['cyrillic-e', (n) => String.fromCharCode(0x435) + n.slice(1)],
  ['zero-width-space-inside', (n) => n.replace('_', `${String.fromCharCode(0x200b)}_`)],
  ['bom-prefixed', (n) => String.fromCharCode(0xfeff) + n],
  ['camel-case', (n) => n.replace(/_(.)/, (_m, c: string) => c.toUpperCase())],
  ['kebab-case', (n) => n.replace('_', '-')],
  ['dotted', (n) => n.replace('_', '.')],
  ['no-separator', (n) => n.replace('_', '')],
  ['space-separated', (n) => n.replace('_', ' ')],
  ['leading-underscore', (n) => `_${n}`],
];
const LOOK_ALIKE_VECTORS = DERIVED_NAMES.flatMap((name) =>
  LOOK_ALIKES.map(([label, spell]) => ({
    name: `unsealed-member-named-${name.replace('_', '-')}-${label}`,
    chain: withFieldAt(1, spell(name), 'attacker-controlled'),
    expect: BROKEN_AT_1,
  })),
);

// ---- derived names NESTED in the core: sealed content (verifies), and added without the key (breaks) --
const nestedCore = (meta: Record<string, unknown>): Record<string, unknown> => ({
  seq: 0, prev_hash: GENESIS, writer_key_id: 'vault-k1', meta,
});
const withMeta = seal(nestedCore({ a: 1, b: 2 })); // "entry_hash"/"entry_hmac" sort between a and b
const NESTED_DERIVED_VECTORS = [
  // Sealed nested derived names holding 64 hex digits: a text stripper removes them and breaks a valid chain.
  { name: 'sealed-nested-derived-names-with-hex-values-verify', chain: [seal(nestedCore({ a: 1, entry_hash: 'a'.repeat(64), entry_hmac: 'b'.repeat(64), z: 2 }))], expect: { ok: true, last_seq: 0 } },
  // Added without the key: the entry's OWN hash (so a stripper finds exactly the root text again), and 64-hex junk.
  { name: 'unsealed-nested-entry-hash-own-value', chain: [{ ...withMeta, meta: { a: 1, entry_hash: withMeta.entry_hash, b: 2 } }], expect: NEVER },
  { name: 'unsealed-nested-entry-hmac-own-value', chain: [{ ...withMeta, meta: { a: 1, entry_hmac: withMeta.entry_hmac, b: 2 } }], expect: NEVER },
  { name: 'unsealed-nested-derived-names-hex-junk', chain: [{ ...withMeta, meta: { a: 1, entry_hash: 'c'.repeat(64), entry_hmac: 'd'.repeat(64), b: 2 } }], expect: NEVER },
];

// ---- FILE-only: the root derived members DUPLICATED, and non-canonical core text sealed over itself ----
const line1 = canonicalize(full[1]!);
const baseFile = (middle: string): Buffer => Buffer.from([canonicalize(full[0]!), middle, canonicalize(full[2]!)].map((l) => l + LF).join(''), 'utf8');
/** A line whose CORE text is spelled non-canonically and sealed over exactly that text (by the key holder). */
function sealedOverOwnText(coreText: string): string {
  const members = `"entry_hash":"${sha256(coreText)}","entry_hmac":"${hmac(coreText)}"`;
  return `${coreText.slice(0, -1)},${members}}`;
}
const e1Core = Object.fromEntries(Object.entries(full[1]!).filter(([k]) => !k.startsWith('entry_h')));
const e1CoreText = canonicalize(e1Core);
const CORE_TEXT_FILES = [
  ...DERIVED_NAMES.map((name) => {
    const member = `"${name}":"${full[1]![name] as string}"`;
    if (line1.split(member).length !== 2) throw new Error(`${name} member not found once`);
    return { name: `root-${name.replace('_', '-')}-duplicated-same-value`, data: baseFile(line1.replace(member, `${member},${member}`)), expect: { ok: false, last_seq: 0 } };
  }),
  // Key-holder-sealed, but over non-canonical core text: the line is still not canonical and must break.
  ...([
    ['whitespace', e1CoreText.replace('":', '": ')],
    ['integral-float', e1CoreText.replace('"seq":1,', '"seq":1.0,')],
    ['unsorted-members', JSON.stringify(Object.fromEntries(Object.entries(e1Core).reverse()))],
    ['duplicate-member', e1CoreText.replace('"seq":1,', '"seq":1,"seq":1,')],
  ] as const).map(([label, text]) => {
    if (text === e1CoreText) throw new Error(`core text ${label} unchanged`);
    return { name: `sealed-over-non-canonical-core-text-${label}`, data: baseFile(sealedOverOwnText(text)), expect: { ok: false, last_seq: 0 } };
  }),
];

// ---- the value domain against a PLAIN serializer (floats, unsafe integers, lone surrogates allowed) ---
function sealedOverPlainJson(core: Record<string, unknown>): Record<string, unknown> {
  // What JSON.stringify / an unrestricted RFC 8785 would sign (keys sorted; these values need no escaping
  // beyond what JSON.stringify does).
  const text = JSON.stringify(Object.fromEntries(Object.keys(core).sort().map((k) => [k, core[k]])));
  return { ...core, entry_hash: sha256(text), entry_hmac: hmac(text) };
}
const PLAIN_DOMAIN_VECTORS = ([
  ['float', 1.5],
  ['unsafe-integer', 2 ** 53],
  ['lone-surrogate', String.fromCharCode(0xd800)],
] as const).map(([label, value]) => ({
  name: `${label}-sealed-over-a-plain-serializer`,
  chain: [sealedOverPlainJson({ seq: 0, prev_hash: GENESIS, writer_key_id: 'vault-k1', amount: value })],
  expect: NEVER,
}));

// ---- brackets inside strings, and a null key id against an empty-string key id ----------------------
const MISC_VECTORS = [
  { name: 'unbalanced-brackets-inside-strings-verify', chain: [seal({ seq: 0, prev_hash: GENESIS, writer_key_id: 'vault-k1', note: '['.repeat(150), other: '{'.repeat(150) })], expect: { ok: true, last_seq: 0 } },
  { name: 'resealed-null-writer-key-id-with-empty-id-in-keyring', chain: resealAt1((c) => ({ ...c, writer_key_id: null })), keyring: { 'vault-k1': KEY_HEX, '': KEY_HEX }, expect: BROKEN_AT_1 },
];

// ---- the chain fields are TOP-LEVEL members only ----------------------------------------------------
// seq, prev_hash and writer_key_id nested deeper (under a member that sorts first, and inside an array),
// with CONFLICTING values, are ordinary sealed content: the chain verifies. A verifier that reads the
// first member with that name in document order (a token scan, a regex, a depth-first search) reads the
// decoys instead, and then accepts a keyless deletion of entry 1 (entry 2's decoys "link" to entry 0).
function chainWithDecoys(): Record<string, unknown>[] {
  const e0 = seal({ seq: 0, prev_hash: GENESIS, writer_key_id: 'vault-k1', action: 'login' });
  const e1 = seal({ seq: 1, prev_hash: e0.entry_hash, writer_key_id: 'vault-k1', action: 'transfer', amount: '5000.00' });
  const e2 = seal({
    seq: 2, prev_hash: e1.entry_hash, writer_key_id: 'vault-k1', action: 'search',
    args: { prev_hash: e0.entry_hash, seq: 1, writer_key_id: 'other' }, list: [{ seq: 1, prev_hash: e0.entry_hash }],
  });
  return [e0, e1, e2];
}
const decoys = chainWithDecoys();
// Derived names nested under a member that sorts BEFORE the root ones ("args" < "entry_hash"): a
// first-match text read or strip finds the nested copy first.
const withArgs = seal({ seq: 0, prev_hash: GENESIS, writer_key_id: 'vault-k1', args: { a: 1, b: 2 } });
// Members named after Object.prototype properties are ordinary members (a JS verifier must not trip on them).
const PROTO_NAMES = ['hasOwnProperty', 'toString', 'valueOf', 'constructor', 'toJSON', 'isPrototypeOf'];
const TOP_LEVEL_VECTORS = [
  { name: 'nested-chain-field-decoys-verify', chain: decoys, expect: { ok: true, last_seq: 2 } },
  { name: 'nested-chain-field-decoys-middle-entry-deleted', chain: [decoys[0], decoys[2]], expect: { ok: false, last_seq: 0 } },
  {
    name: 'sealed-derived-names-nested-before-the-root-ones-verify',
    chain: [seal({ seq: 0, prev_hash: GENESIS, writer_key_id: 'vault-k1', args: { a: 1, entry_hash: 'a'.repeat(64), entry_hmac: 'b'.repeat(64) } })],
    expect: { ok: true, last_seq: 0 },
  },
  { name: 'unsealed-own-hash-nested-before-the-root-one', chain: [{ ...withArgs, args: { a: 1, b: 2, entry_hash: withArgs.entry_hash } }], expect: NEVER },
  { name: 'unsealed-own-hmac-nested-before-the-root-one', chain: [{ ...withArgs, args: { a: 1, b: 2, entry_hmac: withArgs.entry_hmac } }], expect: NEVER },
  {
    name: 'members-named-after-prototype-properties-verify',
    chain: [seal({ seq: 0, prev_hash: GENESIS, writer_key_id: 'vault-k1', ...Object.fromEntries(PROTO_NAMES.map((n) => [n, n])), nested: Object.fromEntries(PROTO_NAMES.map((n) => [n, 1])) })],
    expect: { ok: true, last_seq: 0 },
  },
  ...PROTO_NAMES.map((n) => ({ name: `unsealed-member-named-${n}`, chain: withFieldAt(1, n, 'attacker-controlled'), expect: BROKEN_AT_1 })),
  // writer_key_id compares EXACTLY: a trailing space, tab, line feed or NUL is another (unknown) id.
  ...([['trailing-space', ' '], ['trailing-tab', String.fromCharCode(9)], ['trailing-lf', LF], ['nul-suffix', NUL]] as const).map(([label, suffix]) => ({
    name: `resealed-writer-key-id-${label}`,
    chain: resealAt1((c) => ({ ...c, writer_key_id: `vault-k1${suffix}` })),
    expect: BROKEN_AT_1,
  })),
];
// A chain field present ONLY nested (its top-level member moved under a member that sorts first, or into
// an array), with its correct value, is ABSENT: the entry breaks. A verifier that falls back to the
// shallowest (or first) member of that name anywhere in the entry accepts it.
const NESTINGS: [string, (field: string, value: unknown) => Record<string, unknown>][] = [
  ['under-args', (field, value) => ({ args: { [field]: value } })],
  ['in-a-list', (field, value) => ({ list: [{ [field]: value }] })],
];
const NESTED_ONLY_VECTORS = ['seq', 'prev_hash', 'writer_key_id'].flatMap((field) =>
  NESTINGS.flatMap(([where, nest]) =>
    [0, 1, 2].map((index) => ({
      name: `resealed-${field}-only-nested-${where}-at-${index}`,
      chain: resealAt(index, (core) => {
        const { [field]: value, ...rest } = core;
        return { ...rest, ...nest(field, value) };
      }),
      expect: { ok: false, last_seq: index - 1 },
    })),
  ),
);

export const CORE_DEFINITION_VECTORS = [
  ...LOOK_ALIKE_VECTORS, ...NESTED_DERIVED_VECTORS, ...PLAIN_DOMAIN_VECTORS, ...MISC_VECTORS, ...TOP_LEVEL_VECTORS,
  ...NESTED_ONLY_VECTORS,
];
export const CORE_DEFINITION_FILES = CORE_TEXT_FILES;
