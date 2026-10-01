// Generates vectors/jcs-vectors.json, consumed by BOTH test/jcs-vectors.test.ts (TS) and
// python/tests/test_canonical_vectors.py (Python). Expected canonical bytes + sha256 are computed by the
// TS canonicalize, and both languages must reproduce them exactly. Run: npm run vectors

import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MAX_CANONICAL_BYTES, MAX_DEPTH, canonicalize } from '../src/canonicalize.js';
import { parseJson } from '../src/json.js';
import { checkMust } from './vector-guard.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const outPath = join(here, '..', 'vectors', 'jcs-vectors.json');

interface Vector {
  name: string;
  value: unknown;
}

// Tricky code points are built programmatically so the SOURCE stays pure-ASCII (literal control
// chars / private-use chars do not survive editing). U+E000 is BMP private-use; U+1F600 is astral.
const ALL_C0 = String.fromCharCode(...Array.from({ length: 32 }, (_, i) => i));
const PRINTABLE = String.fromCharCode(...Array.from({ length: 95 }, (_, i) => i + 32), 0xfffd, 0xad, 0x200b, 0x202e);
const CONTROL_CHARS = [0x00, 0x07, 0x08, 0x0b, 0x0c, 0x0d, 0x1f].map((n) => String.fromCharCode(n)).join('');
const DEL_BOM_C1 = String.fromCharCode(0x7f, 0xfeff, ...Array.from({ length: 32 }, (_, i) => 0x80 + i));
const KEY_E000 = String.fromCharCode(0xe000); // BMP private-use, code point 0xE000
const KEY_EMOJI = String.fromCodePoint(0x1f600); // astral, UTF-16 first unit 0xD83D

// Vectors chosen to exercise every divergence risk between JS JSON.stringify and Python json.dumps:
// key sorting (incl. UTF-16-vs-codepoint), array order, string escaping (quotes/backslash/slash),
// control chars (short forms vs \uXXXX), raw non-ASCII + astral, integers, bool/null, real pay action.
const VECTORS: Vector[] = [
  { name: 'empty-object', value: {} },
  { name: 'empty-array', value: [] },
  { name: 'key-order', value: { b: 1, a: 2 } },
  { name: 'nested-sort-array-order', value: { z: [3, 1, 2], a: { y: 1, x: 2 } } },
  { name: 'string-escapes', value: { s: 'he said "hi"\nline\tend\\done/slash' } },
  { name: 'control-chars', value: { c: CONTROL_CHARS } },
  { name: 'unicode-values', value: { u: 'café — 日本語 🎉' } },
  { name: 'integers', value: { zero: 0, neg: -42, max: 9007199254740991 } },
  { name: 'bool-null', value: { t: true, f: false, z: null } },
  { name: 'array-of-objects', value: { items: [{ id: 2, v: 'b' }, { id: 1, v: 'a' }] } },
  // U+E000 (code point 0xE000) vs U+1F600 (astral): code-POINT order puts U+E000 first; UTF-16
  // CODE-UNIT order puts the emoji first (its first unit 0xD83D < 0xE000). This vector FAILS for a
  // naive Python sorted() and PASSES only with the UTF-16-BE key sort -- proving exact correctness.
  { name: 'utf16-vs-codepoint-key-sort', value: { [KEY_E000]: 1, [KEY_EMOJI]: 2 } },
  // Astral keys compared among THEMSELVES, inserted in reverse: two that share the high surrogate 0xD83D
  // (only the low unit decides), then U+10000 (0xD800) against U+FFFF and U+E000. A comparator that
  // buckets astral characters, or looks only at the first unit, keeps insertion order and changes bytes.
  // U+D7FF, the last code point before the surrogate block, is an ordinary character (raw, in both).
  { name: 'u-d7ff-key-and-value', value: { [String.fromCharCode(0xd7ff)]: String.fromCharCode(0xd7ff) } },
  // DEL, U+FEFF and every C1 control are written RAW in keys exactly as in values (only C0 is escaped).
  { name: 'del-bom-and-c1-controls-in-key-and-value', value: { [DEL_BOM_C1]: DEL_BOM_C1 } },
  // Keys that differ only AFTER an embedded U+0000, inserted out of order: a comparator that stops at a
  // NUL (C-string style) sees them as equal and keeps insertion order.
  { name: 'keys-differing-after-a-nul', value: { [`a${String.fromCharCode(0)}b`]: 1, [`a${String.fromCharCode(0)}a`]: 2, a: 3 } },
  { name: 'nul-key-and-empty-key', value: { [String.fromCharCode(0)]: 1, '': 2 } },
  { name: 'astral-keys-sharing-a-high-surrogate-reversed', value: { [String.fromCodePoint(0x1f601)]: 1, [KEY_EMOJI]: 2 } },
  {
    name: 'astral-and-bmp-keys-out-of-order',
    value: { [KEY_EMOJI]: 1, [String.fromCodePoint(0x10000)]: 2, [String.fromCharCode(0xffff)]: 3, [KEY_E000]: 4 },
  },
  // Every C0 control character (U+0000..U+001F), in a key and a value: each has exactly one escape.
  { name: 'all-c0-controls-in-key-and-value', value: { [ALL_C0]: ALL_C0 } },
  // Every printable ASCII character is written RAW (only " and backslash are escaped), and so are
  // U+FFFD, soft hyphen, zero-width space and right-to-left override.
  { name: 'printable-ascii-and-lookalikes', value: { [PRINTABLE]: PRINTABLE } },
  {
    name: 'realistic-payment-record',
    value: {
      merchant: 'example-merchant',
      amount: '19.00',
      currency: 'EUR',
      card_handle: 'card_a',
      checkout_url: 'https://shop.example/cart?item=42&qty=1',
      reason: 'subscription',
      request_id: 'req_0001',
    },
  },
];

// TEXT vectors: raw JSON texts, parsed by each language's own JSON parser, then canonicalized. They
// cover what a `value` vector cannot express (a JS round-trip loses -0, 1.0, 2^53+1, lone surrogates...).
// `must` is the hand-written intent; the emitter refuses to write a file the TS implementation disagrees
// with, so a regression cannot quietly become the new "expected" output.
interface TextVector {
  name: string;
  json_text: string;
  must: 'accept' | 'reject';
}
const BS = String.fromCharCode(92);
const nest = (n: number): string => '['.repeat(n) + ']'.repeat(n);
const nestObjects = (n: number): string => '{"a":'.repeat(n) + '0' + '}'.repeat(n);
/** n containers alternating array / object, outermost an array: [{"a":[{"a":...0...}]}] */
const nestMixed = (n: number): string => {
  let open = '';
  let close = '';
  for (let i = 0; i < n; i += 1) {
    open += i % 2 === 0 ? '[' : '{"a":';
    close = (i % 2 === 0 ? ']' : '}') + close;
  }
  return open + '0' + close;
};

const TEXT_VECTORS: TextVector[] = [
  { name: 'integer-like-keys-sort-as-strings', json_text: '{"10":1,"9":2,"b":3,"1":4,"":5}', must: 'accept' },
  { name: 'proto-key-is-an-ordinary-member', json_text: '{"__proto__":{"x":1},"b":2}', must: 'accept' },
  { name: 'proto-key-with-scalar-value', json_text: '{"__proto__":"s"}', must: 'accept' },
  { name: 'duplicate-keys-last-wins', json_text: '{"a":1,"a":2}', must: 'accept' },
  { name: 'negative-zero-is-zero', json_text: '[-0,-0.0,0e5]', must: 'accept' },
  { name: 'integral-float-and-exponent-forms', json_text: '[1.0,1e2,1E2,0.1e1,100e-2]', must: 'accept' },
  { name: 'max-safe-integers', json_text: '[9007199254740991,-9007199254740991]', must: 'accept' },
  { name: 'escaped-surrogate-pair-is-one-char', json_text: '{"\\ud83d\\ude00":"\\ud83d\\ude00"}', must: 'accept' },
  { name: 'unicode-not-normalized-nfc', json_text: '"\\u00e9"', must: 'accept' },
  { name: 'unicode-not-normalized-nfd', json_text: '"e\\u0301"', must: 'accept' },
  // Characters some serializers escape by default (Go's encoding/json escapes & < > U+2028 U+2029; some
  // escape DEL). The canonical form writes all of them RAW, whether the input spelled them raw or escaped.
  {
    name: 'html-sensitive-and-line-separators-are-raw',
    json_text: `{"u":"a&b<c>d${String.fromCharCode(0x2028, 0x2029, 0x7f)}","e":"${BS}u0026${BS}u003c${BS}u003e${BS}u2028${BS}u2029${BS}u007f"}`,
    must: 'accept',
  },
  // C1 controls (U+0080..U+009F) and U+FEFF inside a string are ordinary characters: written RAW, never
  // escaped, never stripped (some serializers escape C1; some readers strip a BOM wherever it appears).
  {
    name: 'c1-controls-and-bom-inside-strings-are-raw',
    json_text: `["a${String.fromCharCode(0x80, 0x85, 0x9f, 0xfeff)}b","${BS}u0080${BS}u0085${BS}u009f${BS}ufeff"]`,
    must: 'accept',
  },
  // Keys sort by UTF-16 code unit: uppercase before "_" before lowercase. Not case-folded, not locale order.
  { name: 'mixed-case-keys-sort-by-code-unit', json_text: '{"b":1,"B":2,"a":3,"A":4,"_":5,"Z":6,"z":7}', must: 'accept' },
  // Keys sort by their UNESCAPED UTF-16 code units, not by their escaped spelling and not by the whole
  // serialized member ("a" < "a b" < "a!" as strings, although '"' sorts after ' ' and '!').
  { name: 'prefix-keys-sort-before-longer-keys', json_text: '{"a!":3,"a b":2,"a":1}', must: 'accept' },
  { name: 'keys-needing-escapes-sort-unescaped', json_text: `{"]":4,"${BS}${BS}":3,"#":2,"${BS}"":1}`, must: 'accept' },
  { name: 'control-char-keys-sort-unescaped', json_text: `{" ":3,"${BS}n":2,"${BS}u0001":1}`, must: 'accept' },
  // Unicode is not normalized for KEYS either: NFC and NFD spellings are two different members.
  { name: 'nfc-and-nfd-keys-are-distinct', json_text: `{"${BS}u00e9":1,"e${BS}u0301":2}`, must: 'accept' },
  { name: 'nested-empties', json_text: '{"a":{},"b":[],"c":[{}],"d":{"e":[[]]}}', must: 'accept' },
  { name: 'depth-at-limit', json_text: nest(100), must: 'accept' },
  { name: 'depth-over-limit', json_text: nest(101), must: 'reject' },
  { name: 'object-depth-at-limit', json_text: nestObjects(100), must: 'accept' },
  { name: 'object-depth-over-limit', json_text: nestObjects(101), must: 'reject' },
  { name: 'mixed-depth-at-limit', json_text: nestMixed(100), must: 'accept' },
  { name: 'mixed-depth-over-limit', json_text: nestMixed(101), must: 'reject' },
  { name: 'non-integer', json_text: '1.5', must: 'reject' },
  { name: 'smallest-subnormal', json_text: '5e-324', must: 'reject' },
  { name: 'underflow-below-smallest-double-is-zero', json_text: '[1e-400,-1e-400]', must: 'accept' },
  { name: 'two-pow-53', json_text: '9007199254740992', must: 'reject' },
  { name: 'two-pow-53-plus-one', json_text: '9007199254740993', must: 'reject' },
  { name: 'negative-two-pow-53', json_text: '-9007199254740992', must: 'reject' },
  { name: 'one-e-21', json_text: '1e21', must: 'reject' },
  { name: 'overflow-to-infinity', json_text: '1e400', must: 'reject' },
  { name: 'lone-high-surrogate-value', json_text: '"\\ud800"', must: 'reject' },
  { name: 'lone-low-surrogate-key', json_text: '{"\\udc00":1}', must: 'reject' },
  { name: 'reversed-surrogate-pair', json_text: '"\\ude00\\ud83d"', must: 'reject' },
  // The surrogate ranges' UPPER bounds, as values and keys, and a high surrogate before a non-surrogate.
  { name: 'lone-dbff-value', json_text: `"${BS}udbff"`, must: 'reject' },
  { name: 'lone-dfff-value', json_text: `"${BS}udfff"`, must: 'reject' },
  { name: 'lone-dbff-key', json_text: `{"${BS}udbff":1}`, must: 'reject' },
  { name: 'lone-dfff-key', json_text: `{"${BS}udfff":1}`, must: 'reject' },
  { name: 'high-surrogate-before-ascii', json_text: `"${BS}udbffa"`, must: 'reject' },
  { name: 'highest-valid-pair', json_text: `"${BS}udbff${BS}udfff"`, must: 'accept' },
  // A high surrogate must be followed by a LOW one: not another high, not a non-surrogate escape.
  { name: 'two-high-surrogates', json_text: `"${BS}ud800${BS}ud800"`, must: 'reject' },
  { name: 'highest-high-then-lowest-high', json_text: `"${BS}udbff${BS}ud800"`, must: 'reject' },
  { name: 'repeated-emoji-high-half', json_text: `"${BS}ud83d${BS}ud83d"`, must: 'reject' },
  { name: 'high-surrogate-then-escaped-letter', json_text: `"${BS}ud800${BS}u0041"`, must: 'reject' },
  { name: 'lone-high-then-valid-pair', json_text: `"${BS}ud800${BS}ud800${BS}udc00"`, must: 'reject' },
  { name: 'two-high-surrogates-as-key', json_text: `{"${BS}ud800${BS}ud800":1}`, must: 'reject' },
  // A high surrogate followed by a unit ABOVE the low-surrogate range is still lone.
  ...(['e000', 'f900', 'ffff'] as const).flatMap((next) => (['d800', 'dbff'] as const).flatMap((high) => [
    { name: `high-${high}-before-${next}`, json_text: `"${BS}u${high}${BS}u${next}"`, must: 'reject' as const },
    { name: `high-${high}-before-${next}-as-key`, json_text: `{"${BS}u${high}${BS}u${next}":1}`, must: 'reject' as const },
  ])),
  // A raw NUL after a complete value is trailing garbage, not a terminator.
  { name: 'value-followed-by-raw-nul', json_text: `{}${String.fromCharCode(0)}`, must: 'reject' },
  // RAW (unescaped) NFD text keeps its bytes: no normalization in either direction.
  { name: 'raw-nfd-text-is-kept', json_text: `{"e${String.fromCharCode(0x301)}":"Cafe${String.fromCharCode(0x301)}"}`, must: 'accept' },
  // Noncharacters are valid Unicode scalar values: accepted and written raw, in values and keys.
  {
    name: 'noncharacters-are-ordinary',
    json_text: `{"${BS}ufffe${BS}uffff":"${BS}ufdd0${BS}ufdef${BS}ufffe${BS}uffff"}`,
    must: 'accept',
  },
  // Numbers are the IEEE-754 double the text rounds to, even when the decimal is not an integer.
  { name: 'decimals-that-round-to-integers', json_text: '[1.0000000000000001,0.99999999999999999,-9007199254740991.4]', must: 'accept' },
  { name: 'decimal-that-rounds-to-two-pow-53', json_text: '9007199254740991.5', must: 'reject' },
  // Doubles right NEXT to an integer are not integers: an integrality test with a tolerance, or a round
  // trip through 15 significant digits, would turn each of these into the integer beside it.
  { name: 'one-ulp-above-one', json_text: '1.0000000000000002', must: 'reject' },
  { name: 'one-ulp-below-one', json_text: '0.9999999999999999', must: 'reject' },
  { name: 'one-ulp-past-minus-one', json_text: '-1.0000000000000002', must: 'reject' },
  { name: 'one-ulp-above-1900', json_text: '1900.0000000000002', must: 'reject' },
  { name: 'half-past-an-integer-near-2-pow-50', json_text: '1000000000000000.5', must: 'reject' },
  { name: 'half-below-2-pow-52', json_text: '4503599627370495.5', must: 'reject' },
  // The negative side of the safe range: decimals that round to -2^53 are unsafe too.
  { name: 'decimal-that-rounds-to-minus-two-pow-53', json_text: '-9007199254740991.5', must: 'reject' },
  { name: 'minus-two-pow-53-as-a-fraction', json_text: '-9007199254740992.0', must: 'reject' },
  { name: 'minus-two-pow-53-as-an-exponent', json_text: '-9.007199254740992e15', must: 'reject' },
  // U+D7FF, the last code point before the surrogate block, escaped: an ordinary character.
  { name: 'escaped-u-d7ff', json_text: `"${BS}ud7ff"`, must: 'accept' },
  // ORDER MATTERS: JSON.parse on V8 12.9+ (Node 23 and later), once it has parsed an object whose key is a single
  // backslash, returns a backslash for any later one-escape key after the same preceding keys. Run in
  // sequence in one process, these catch an implementation that parses with such a host parser.
  ...[`${BS}${BS}`, `${BS}n`, `${BS}t`, `${BS}"`, `${BS}/`, `${BS}u0041`].map((key, i) => ({
    name: `escaped-single-char-key-${i === 0 ? 'backslash-first' : 'after-backslash-' + i}`,
    json_text: `{"":1,"${key}":2}`,
    must: 'accept' as const,
  })),
];

function canonicalOrNull(text: string): string | null {
  try {
    return canonicalize(parseJson(text));
  } catch {
    return null;
  }
}

// SIZE vectors pin max_canonical_bytes without shipping megabytes: the JSON text is
// prefix + unit repeated count times + suffix. Accepted ones give the SHA-256 (and byte length) of
// the canonical form; rejected ones give null. They include a structure-heavy input (the limit counts
// every byte, not just strings) and one whose UTF-16 length fits while its UTF-8 length does not.
interface SizeVector {
  name: string;
  prefix: string;
  unit: string;
  count: number;
  suffix: string;
  must: 'accept' | 'reject';
}
const M = MAX_CANONICAL_BYTES;
const SIZE_VECTORS: SizeVector[] = [
  { name: 'ascii-string-exactly-at-limit', prefix: '"', unit: 'a', count: M - 2, suffix: '"', must: 'accept' },
  { name: 'ascii-string-one-byte-over', prefix: '"', unit: 'a', count: M - 1, suffix: '"', must: 'reject' },
  { name: 'many-members-exactly-at-limit', prefix: '[', unit: '1,', count: (M - 4) / 2, suffix: '11]', must: 'accept' },
  { name: 'many-members-one-byte-over', prefix: '[', unit: '1,', count: (M - 4) / 2, suffix: '111]', must: 'reject' },
  { name: 'empty-objects-exactly-at-limit', prefix: '[', unit: '{},', count: (M - 4) / 3, suffix: '{}]', must: 'accept' },
  { name: 'utf16-fits-utf8-does-not', prefix: '"', unit: String.fromCharCode(0xe9), count: M / 2, suffix: '"', must: 'reject' },
  // Every construct the size budget charges by hand, at the limit (must fit) and just over. An
  // implementation whose running budget over-charges any of them rejects the at-limit case.
  ...atAndOver('nulls', '[', 'null,', 5, 'null]'),
  ...atAndOver('trues', '[', 'true,', 5, 'true]'),
  ...atAndOver('falses', '[', 'false,', 6, 'false,10]'),
  ...atAndOver('negative-ints', '[', '-1,', 3, '-1111]'),
  ...atAndOver('single-member-objects-null', '[', '{"a":null},', 11, '{"a":null}]'),
  ...atAndOver('single-element-arrays', '[', '[0],', 4, '[1000]]'),
  ...atAndOver('two-member-objects', '[', '{"a":0,"b":0},', 14, '{"a":0,"b":10},0]'),
  ...atAndOver('single-member-objects-false', '[', '{"":false},', 11, '{"":false}]'),
  ...atAndOver('astral-keys', '[', `{"${String.fromCodePoint(0x1f600)}":0},`, 11, `{"${String.fromCodePoint(0x1f600)}":0}]`),
  ...atAndOver('astral-string', '"', String.fromCodePoint(0x1f600), 4, 'aa"'),
  // The limit is on the CANONICAL OUTPUT, not the input text: exponent spellings are SHORTER than their
  // canonical form (so the text is under 1 MiB but the output is not), whitespace-padded text is LONGER
  // (so the text is ~2 MiB but the output fits exactly).
  ...atAndOver('exponent-spellings-expand', '[', '1e15,', 17, '10000000000000]'),
  ...atAndOver('whitespace-padded-text', '[', '1 , ', 2, '11]'),
  // ESCAPE EXPANSION: the limit is on the canonical (escaped) bytes, not the raw string length.
  ...atAndOver('escaped-quotes', '"', `${BS}"`, 2, '"'),
  ...atAndOver('escaped-backslashes', '"', `${BS}${BS}`, 2, '"'),
  ...atAndOver('escaped-control-chars', '"', `${BS}u0001`, 6, 'aa"'),
];

/** Two size vectors: `unit` (unitBytes UTF-8 bytes) repeated to land EXACTLY on the limit, and the same
 *  text with one more unit, which must be rejected. */
function atAndOver(name: string, prefix: string, unit: string, unitBytes: number, suffix: string): SizeVector[] {
  const fixed = Buffer.byteLength(prefix + suffix, 'utf8');
  const count = (M - fixed) / unitBytes;
  if (!Number.isInteger(count)) throw new Error(`size vector "${name}" cannot land exactly on the limit`);
  return [
    { name: `${name}-exactly-at-limit`, prefix, unit, count, suffix, must: 'accept' },
    { name: `${name}-one-unit-over`, prefix, unit, count: count + 1, suffix, must: 'reject' },
  ];
}

const sizeVectors = SIZE_VECTORS.map((v) => {
  const expected = canonicalOrNull(v.prefix + v.unit.repeat(v.count) + v.suffix);
  checkMust('size vector', v.name, v.must, expected);
  const { must: _must, ...spec } = v;
  return {
    ...spec,
    expected_bytes: expected === null ? null : Buffer.byteLength(expected, 'utf8'),
    expected_sha256: expected === null ? null : createHash('sha256').update(expected, 'utf8').digest('hex'),
  };
});

const textVectors = TEXT_VECTORS.map((v) => {
  const expected = canonicalOrNull(v.json_text);
  checkMust('text vector', v.name, v.must, expected);
  return {
    name: v.name,
    json_text: v.json_text,
    expected_canonical: expected,
    expected_sha256: expected === null ? null : createHash('sha256').update(expected, 'utf8').digest('hex'),
  };
});

const out = {
  _comment:
    'GENERATED by scripts/emit-jcs-vectors.mts -- do not hand-edit. Normative canonicalization vectors: ' +
    'expected_canonical is the exact byte string (UTF-8) both implementations must produce for value, ' +
    'and expected_sha256 its SHA-256. text_vectors: json_text is parsed by each language\'s own JSON ' +
    'parser; expected_canonical null means the input is outside the canonical domain and must be rejected. ' +
    'max_canonical_bytes and max_depth are the domain limits (UTF-8 bytes of the canonical form; nesting). ' +
    'size_vectors: json_text = prefix + unit repeated count times + suffix; expected_sha256 null = reject.',
  max_canonical_bytes: MAX_CANONICAL_BYTES,
  max_depth: MAX_DEPTH,
  text_vectors: textVectors,
  size_vectors: sizeVectors,
  vectors: VECTORS.map((v) => {
    const expected_canonical = canonicalize(v.value);
    return {
      name: v.name,
      value: v.value,
      expected_canonical,
      expected_sha256: createHash('sha256').update(expected_canonical, 'utf8').digest('hex'),
    };
  }),
};

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, `${JSON.stringify(out, null, 2)}\n`, 'utf8');
console.log(`wrote ${out.vectors.length} JCS vectors -> ${outPath}`);
