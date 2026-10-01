import { createHash, createHmac } from 'node:crypto';
import { MAX_CANONICAL_BYTES, canonicalize } from '../../src/canonicalize.js';
import { parseJson } from '../../src/json.js';

// Inputs for the parity suite. Everything here is a raw JSON TEXT: each language parses it with its
// own parser, so parser disagreements are in scope, not just canonicalizer disagreements.

/** Deterministic PRNG (mulberry32) so a failing random case is reproducible from its index. */
export function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Code points chosen for escaping, sorting and encoding edge cases: every C0 control, quote and
// backslash, DEL, C1, U+2028/2029, BMP private-use (sorts AFTER surrogates in UTF-16 but BEFORE them by
// code point), U+FFFF, and astral characters (encoded as surrogate pairs in UTF-16).
const CODE_POINTS: number[] = [
  ...Array.from({ length: 0x20 }, (_, i) => i),
  0x22, 0x5c, 0x2f, 0x30, 0x31, 0x39, 0x2d, 0x2e, 0x41, 0x61, 0x7a, 0x7f, 0x80, 0x9f, 0xa0, 0xe9, 0xff, 0x100, 0x3b1, 0x5d0, 0x65e5,
  0x2028, 0x2029, 0xd7ff, 0xe000, 0xf8ff, 0xfeff, 0xfffd, 0xfffe, 0xffff,
  0x10000, 0x1f600, 0x1f389, 0x10ffff,
];

function randomString(rand: () => number, maxLen: number): string {
  const len = Math.floor(rand() * (maxLen + 1));
  let s = '';
  for (let i = 0; i < len; i += 1) {
    s += rand() < 0.5
      ? String.fromCodePoint(CODE_POINTS[Math.floor(rand() * CODE_POINTS.length)]!)
      : String.fromCharCode(0x61 + Math.floor(rand() * 4));
  }
  return s;
}

const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const INTS = [0, 1, -1, 42, -42, 255, 2 ** 31, -(2 ** 31), 2 ** 32, MAX_SAFE, -MAX_SAFE, MAX_SAFE - 1];

function randomValue(rand: () => number, depth: number): unknown {
  const r = rand();
  if (depth <= 0 || r < 0.45) {
    const p = rand();
    if (p < 0.4) return randomString(rand, 8);
    if (p < 0.7) return rand() < 0.5 ? INTS[Math.floor(rand() * INTS.length)] : Math.floor((rand() - 0.5) * 2e6);
    if (p < 0.8) return rand() < 0.5;
    return null;
  }
  const n = Math.floor(rand() * 5);
  if (r < 0.7) return Array.from({ length: n }, () => randomValue(rand, depth - 1));
  const obj: Record<string, unknown> = {};
  for (let i = 0; i < n; i += 1) {
    // A third of keys are digit strings: JS objects enumerate integer-like keys numerically first.
    const key = rand() < 0.33 ? String(Math.floor(rand() * 20)) : randomString(rand, 4);
    obj[key] = randomValue(rand, depth - 1);
  }
  return obj;
}

/** Random well-formed documents, serialized compactly (and every third one also indented). */
export function randomTexts(seed: number, count: number): string[] {
  const rand = prng(seed);
  const out: string[] = [];
  for (let i = 0; i < count; i += 1) {
    const value = randomValue(rand, 4);
    out.push(JSON.stringify(value));
    if (i % 3 === 0) out.push(JSON.stringify(value, null, 2));
  }
  return out;
}

// ── chains ────────────────────────────────────────────────────────────────────────────────────

export const KEY_ID = 'k1';
export const KEY_HEX = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
const KEY = Buffer.from(KEY_HEX, 'hex');

type Entry = Record<string, unknown>;

export function sealRaw(core: Entry, key: Buffer = KEY): Entry {
  const bytes = canonicalize(core);
  return {
    ...core,
    entry_hash: createHash('sha256').update(bytes, 'utf8').digest('hex'),
    entry_hmac: createHmac('sha256', key).update(bytes, 'utf8').digest('hex'),
  };
}

/** A valid chain whose cores carry random (well-formed) payloads. */
export function buildChain(rand: () => number, n: number): Entry[] {
  const chain: Entry[] = [];
  let prev = '0'.repeat(64);
  for (let seq = 0; seq < n; seq += 1) {
    const entry = sealRaw({ seq, prev_hash: prev, writer_key_id: KEY_ID, payload: randomValue(rand, 3) });
    chain.push(entry);
    prev = entry.entry_hash as string;
  }
  return chain;
}

/** The attacks a verifier must catch, applied to a valid chain. Each returns a NEW chain. */
export const MUTATIONS: Record<string, (c: Entry[], rand: () => number) => unknown[]> = {
  identity: (c) => c,
  'swap-adjacent': (c) => (c.length < 2 ? c : [c[1], c[0], ...c.slice(2)]),
  'delete-middle': (c) => c.filter((_, i) => i !== Math.floor(c.length / 2)),
  'duplicate-entry': (c) => [...c.slice(0, 2), c[1], ...c.slice(2)].filter(Boolean),
  'truncate-tail': (c) => c.slice(0, -1),
  'drop-genesis': (c) => c.slice(1),
  'tamper-payload': (c) => c.map((e, i) => (i === 1 ? { ...e, payload: 'tampered' } : e)),
  'rehash-without-key': (c) =>
    c.map((e, i) => {
      if (i !== 1) return e;
      const { entry_hash: _h, entry_hmac, ...core } = e;
      const forged = { ...core, payload: 'forged' };
      return { ...sealRaw(forged), entry_hmac };
    }),
  'reseal-wrong-key': (c) =>
    c.map((e, i) => {
      if (i !== 1) return e;
      const { entry_hash: _h, entry_hmac: _m, ...core } = e;
      return sealRaw(core, Buffer.alloc(32, 7));
    }),
  'splice-other-chain': (c, rand) => [c[0], ...buildChain(rand, c.length).slice(1)],
  'unknown-key-id': (c) => c.map((e, i) => (i === 1 ? { ...e, writer_key_id: 'nope' } : e)),
};

// ── hand-picked texts ─────────────────────────────────────────────────────────────────────────

const nest = (n: number): string => '['.repeat(n) + ']'.repeat(n);
export const nestObjects = (n: number): string => '{"a":'.repeat(n) + '0' + '}'.repeat(n);
/** n containers alternating array / object, outermost an array: [{"a":[{"a":...0...}]}] */
export const nestMixed = (n: number): string => {
  let open = '';
  let close = '';
  for (let i = 0; i < n; i += 1) {
    open += i % 2 === 0 ? '[' : '{"a":';
    close = (i % 2 === 0 ? ']' : '}') + close;
  }
  return open + '0' + close;
};


/** Parser- and number-level edge cases: every one must agree (same bytes, or both refuse). */
export const EDGE_TEXTS: string[] = [
  '1.5', '1.0', '1e2', '1E+2', '-1e-0', '0.5e1', '100e-2', '1e-7', '-0', '-0.0', '0e5',
  '9007199254740991', '9007199254740992', '9007199254740993', '-9007199254740991', '-9007199254740992',
  '9007199254740991.0', '9007199254740991.4', '9007199254740991.5', '9007199254740990.5',
  '1e21', '1e400', '-1e400', '5e-324', '1'.repeat(400), '1'.repeat(5000), `0.${'0'.repeat(400)}1`,
  '"\ud800"', '"\udc00"', '"\ude00\ud83d"', '"\ud83d\ude00"', '"\ud83d"', '{"\ud800":1}',
  '"\u0000"', '"\u00E9"', '"\u2028\u2029"', '"\u007f\u0080\u009f"', '"\ufeff"',
  // The same code points written as JSON escapes (String.raw keeps the backslashes in the JSON text).
  String.raw`"\ud800"`, String.raw`"\udc00"`, String.raw`"\ude00\ud83d"`, String.raw`"\ud83d\ude00"`,
  String.raw`{"\ud800":1}`, String.raw`"\u0000\u001f"`, String.raw`"\/"`, String.raw`"\u00E9\u00e9"`,
  String.raw`"\u2028\u2029"`, String.raw`"\u007f\u0080\u009f"`, String.raw`"\ufeff"`,
  String.raw`{"\ue000":1,"\ud83d\ude00":2}`, String.raw`{"a\u0000":1,"a":2}`, String.raw`{"\u0061":1,"a":2}`,
  '{"__proto__":{"x":1},"b":2}', '{"__proto__":"s"}', '{"__proto__":null}', '{"constructor":1,"toJSON":2}',
  '{"a":1,"a":2}', '{"a":1,"a":1.5}', '{"a":1.5,"a":1}', '{"10":1,"9":2,"1":3,"":4,"01":5,"-1":6}',
  '{"4294967295":1,"4294967294":2}', '{"\ue000":1,"\ud83d\ude00":2}',
  '{}', '[]', '[{}]', '{"a":{}}', '[[],[[]]]', ' \t\n\r[1 , 2]\r\n', 'null', 'true', '""',
  nest(99), nest(100), nest(101), nest(1500),
  nestObjects(100), nestObjects(101), nestObjects(1500), nestMixed(100), nestMixed(101), nestMixed(1001),
  // Parser grammar edges (each one a parser mutant that a unit test alone might not catch).
  `"a${String.fromCharCode(13)}b"`, `"a${String.fromCharCode(8)}b"`, `"a${String.fromCharCode(10)}b"`,
  `"${String.fromCharCode(92)}u004G"`, `"${String.fromCharCode(92)}u004"x"`,
  '{"a" :1}', '[ ]', '{ }', '{"a":1,}', '1e', '1e+', '[1E-]', '1.e5', '[1x2]', '{"a":1x"b":2}', '{"a" 1}', 'tru1', 'nulx', '[1.9e9,0.9]', '1.00000000000000000001e1', '[1e+2,1E-2,-0e-0]',
  `${String.fromCharCode(12)}1`, `${String.fromCharCode(11)}1`, `"a${String.fromCharCode(0x1f)}"`,
  `"${String.fromCharCode(92)}'"`, `"${String.fromCharCode(92)}u00C9"`,
  // Size limit, built from many small members (structure-heavy): exactly at the limit, one byte over.
  `[${'1,'.repeat((MAX_CANONICAL_BYTES - 4) / 2)}11]`, `[${'1,'.repeat((MAX_CANONICAL_BYTES - 4) / 2)}111]`,
  `[${'{},'.repeat((MAX_CANONICAL_BYTES - 4) / 3)}{}]`, `[${'{},'.repeat((MAX_CANONICAL_BYTES - 4) / 3)}{},0]`,
  // Size limit: exactly MAX_CANONICAL_BYTES, one byte over, and UTF-16-fits-but-UTF-8-does-not.
  `"${'a'.repeat(MAX_CANONICAL_BYTES - 2)}"`, `"${'a'.repeat(MAX_CANONICAL_BYTES - 1)}"`,
  `"${String.fromCharCode(0xe9).repeat(MAX_CANONICAL_BYTES / 2)}"`, `["${'a'.repeat(MAX_CANONICAL_BYTES - 5)}",1]`, 'NaN', 'Infinity', '[1,]', "{'a':1}", '﻿{}', '',
];

/**
 * Byte-level variants of one valid chain in canonical JSONL. Only 'canonical' (and the anchored and
 * empty-file variants, and the anchored variants the test adds) may verify; every other must break at the same line in both
 * languages. Several are parser differentials: texts that JSON.parse and json.loads read differently.
 */
export function jsonlVariants(chain: Entry[]): [string, Buffer][] {
  const lines = chain.map((e) => canonicalize(e));
  const join = (ls: string[]): Buffer => Buffer.from(ls.map((l) => `${l}\n`).join(''), 'utf8');
  const at1 = (f: (line: string) => string): Buffer => join(lines.map((l, i) => (i === 1 ? f(l) : l)));
  const at0 = (f: (line: string) => string): Buffer => join(lines.map((l, i) => (i === 0 ? f(l) : l)));
  const inject = (member: string): Buffer => at1((l) => `{${member},${l.slice(1)}`);
  const bytes1 = (f: (b: Buffer) => Buffer): Buffer => {
    const parts: Buffer[] = lines.map((l) => Buffer.from(`${l}\n`, 'utf8'));
    parts[1] = f(parts[1]!);
    return Buffer.concat(parts);
  };
  const deep = '['.repeat(3000) + ']'.repeat(3000);
  return [
    ['canonical', join(lines)],
    ['no-final-newline', Buffer.from(lines.join('\n'), 'utf8')],
    ['empty-file', Buffer.alloc(0)],
    ['lone-newline', Buffer.from('\n')],
    ['crlf', Buffer.from(lines.map((l) => `${l}\r\n`).join(''), 'utf8')],
    ['blank-line-between', Buffer.from(`${lines[0]}\n\n${lines.slice(1).join('\n')}\n`, 'utf8')],
    ['extra-final-newline', Buffer.concat([join(lines), Buffer.from('\n')])],
    ['bom-prefix', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), join(lines)])],
    ['space-after-colon', at1((l) => l.replace('":', '": '))],
    ['trailing-space', at1((l) => `${l} `)],
    ['raw-cr-between-tokens', at1((l) => l.replace(',"', ',\r"'))],
    ['seq-as-1.0', at1((l) => l.replace('"seq":1,', '"seq":1.0,'))],
    ['seq-as-1e0', at1((l) => l.replace('"seq":1,', '"seq":1e0,'))],
    ['seq-as-1E0', at1((l) => l.replace('"seq":1,', '"seq":1E0,'))],
    ['seq-0-as-minus-zero', at0((l) => l.replace('"seq":0,', '"seq":-0,'))],
    ['escaped-ascii', at1((l) => l.replace('"prev_hash"', '"prev_\\u0068ash"'))],
    ['keys-reordered', at1((l) => JSON.stringify(Object.fromEntries(Object.entries(parseJson(l) as Entry).reverse())))],
    ['dup-before-same-value', inject('"seq":1')],
    ['dup-before-nan', inject('"seq":NaN')],
    ['dup-before-infinity', inject('"payload":-Infinity')],
    ['dup-before-5000-digits', inject(`"payload":${'1'.repeat(5000)}`)],
    ['dup-before-3000-deep', inject(`"payload":${deep}`)],
    ['dup-hmac-before-nan', at1((l) => l.replace('"entry_hmac":', '"entry_hmac":NaN,"entry_hmac":'))],
    ['invalid-utf8-ff', bytes1((b) => Buffer.concat([b.subarray(0, 5), Buffer.from([0xff]), b.subarray(5)]))],
    ['overlong-slash', bytes1((b) => Buffer.concat([b.subarray(0, 1), Buffer.from([0xc0, 0xaf]), b.subarray(1)]))],
    ['cesu8-surrogate', bytes1((b) => Buffer.concat([b.subarray(0, 1), Buffer.from([0xed, 0xa0, 0x80]), b.subarray(1)]))],
    ['nul-byte', bytes1((b) => Buffer.concat([b.subarray(0, 1), Buffer.from([0x00]), b.subarray(1)]))],
    ['torn-tail', join(lines).subarray(0, join(lines).length - 7)],
    ['final-lf-to-cr', Buffer.concat([join(lines).subarray(0, -1), Buffer.from([13])])],
    ['entry-is-null', at1(() => 'null')],
    ['oversized-line', at1(() => `"${'a'.repeat(MAX_CANONICAL_BYTES)}"`)],
    ['entry-is-number', at1(() => '5')],
    ['duplicate-line', join([lines[0]!, lines[1]!, ...lines.slice(1)])],
    ['swapped-lines', join([lines[0]!, lines[2]!, lines[1]!, ...lines.slice(3)])],
  ];
}

/** Textual variants of one valid chain: same values written differently, and parser-differential
 * duplicate-key injections. Each is a (label, text) pair; the verdict must agree across languages. */
export function chainTextVariants(chain: Entry[]): [string, string][] {
  const text = JSON.stringify(chain);
  const call1 = JSON.stringify(chain[1]!.payload);
  return [
    ['as-written', text],
    ['pretty-printed', JSON.stringify(chain, null, 2)],
    ['seq-as-1.0', text.replace('"seq":1,', '"seq":1.0,')],
    ['seq-as-1e0', text.replace('"seq":1,', '"seq":1e0,')],
    ['seq-as-string', text.replace('"seq":1,', '"seq":"1",')],
    ['keys-reversed', JSON.stringify(chain.map((e) => Object.fromEntries(Object.entries(e).reverse())))],
    ['dup-key-before (last wins: valid)', text.replace('{"seq":1,', '{"seq":1,"payload":"evil",')],
    ['dup-key-after (last wins: tampered)', text.replace(`"payload":${call1},`, `"payload":${call1},"payload":"evil",`)],
    // Entry 1's hashes, uppercased (entry 0's prev_hash is the all-zero genesis, which has no case).
    ['uppercase-prev-hash', JSON.stringify(chain.map((e, i) => (i === 1 ? { ...e, prev_hash: String(e.prev_hash).toUpperCase() } : e)))],
    ['uppercase-entry-hash', JSON.stringify(chain.map((e, i) => (i === 1 ? { ...e, entry_hash: String(e.entry_hash).toUpperCase() } : e)))],
  ];
}

/** A valid, sealed, one-entry canonical-JSONL file whose line is EXACTLY MAX_CANONICAL_BYTES long. */
export function maxSizeJsonl(): Buffer {
  const base = { seq: 0, prev_hash: '0'.repeat(64), writer_key_id: KEY_ID, pad: '' };
  const overhead = Buffer.byteLength(canonicalize(sealRaw(base)), 'utf8');
  const line = canonicalize(sealRaw({ ...base, pad: 'x'.repeat(MAX_CANONICAL_BYTES - overhead) }));
  if (Buffer.byteLength(line, 'utf8') !== MAX_CANONICAL_BYTES) throw new Error('max-size line is not exact');
  return Buffer.from(`${line}\n`, 'utf8');
}
