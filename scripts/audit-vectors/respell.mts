// JSONL RESPELLING vectors: the lexical freedoms JSON allows for the SAME value, each applied at ONE site
// of a canonical line. A generic engine visits every node of a nested entry: every object and array at
// every depth (whitespace at each structural position, member order, duplicate members with the same or
// an overwritten value, whitespace inside an empty container), every key and string value (a character
// written as a \u escape, lower- and uppercase hex) and every number (exponent, fraction, -0). Hand-written
// cases add the character classes a canonical string can hold (\/, ", long-form controls, escaped
// non-ASCII and surrogate pairs) and more number spellings. Every respelled line parses to exactly the
// sealed value, so the hash and HMAC still match and only the byte-exact "line == canonical(value)" check
// catches it. A verifier that validates lines lexically, at any depth, instead of comparing them with a
// full re-serialization would accept these keyless edits.

import { canonicalize } from '../../src/canonicalize.js';
import { parseJson } from '../../src/json.js';
import { GENESIS, seal } from './fixtures.mjs';

const BS = String.fromCharCode(92);
const LF = String.fromCharCode(10);
const WHITESPACE = [' ', String.fromCharCode(9), String.fromCharCode(13)]; // a raw line feed would split the line
const E_ACUTE = String.fromCharCode(0xe9);
const EMOJI = String.fromCodePoint(0x1f600);
// Every character class a canonical string can hold: an ASCII letter, a slash, a quote and a backslash
// (short escapes), a line feed (short escape), U+001F (long escape), raw non-ASCII BMP and astral.
const NOTE = `j/k"q${BS}z${LF}${String.fromCharCode(0x1f)}${E_ACUTE}${EMOJI}`;

function canonicalLines(): [string, string] {
  const e0 = seal({ seq: 0, prev_hash: GENESIS, writer_key_id: 'vault-k1', note: 'first' });
  const e1 = seal({
    seq: 1, prev_hash: e0.entry_hash, writer_key_id: 'vault-k1', amount: 1900, zero: 0, note: NOTE,
    list: [1, 'x', { y: 1, x: 2 }], meta: { b: { d: 2, c: 1 }, a: [3], e: {}, f: [] },
  });
  return [canonicalize(e0), canonicalize(e1)];
}

// ---- the generic engine: canonical serialization, except for one (site, spelling) -------------------

interface Site {
  path: string;
  op: string;
  ws: string;
}

const hex4 = (code: number, upper: boolean): string => {
  const h = code.toString(16).padStart(4, '0');
  return upper ? h.toUpperCase() : h;
};

/** A string with its first character (both halves of a surrogate pair) written as \u escapes. */
function escapedFirst(s: string, upper: boolean): string {
  const units = (s.codePointAt(0) ?? 0) > 0xffff ? 2 : 1;
  const head = Array.from({ length: units }, (_, i) => `${BS}u${hex4(s.charCodeAt(i), upper)}`).join('');
  return `"${head}${JSON.stringify(s.slice(units)).slice(1, -1)}"`;
}

const NUMBER_SPELLINGS: Record<string, (n: number) => string> = {
  exponent: (n) => `${n}e0`,
  fraction: (n) => `${n}.0`,
  'minus-zero': () => '-0',
};

function write(v: unknown, path: string, t: Site): string {
  const here = t.path === path ? t.op : '';
  const ws = (op: string): string => (here === op ? t.ws : '');
  if (v === null || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'number') return here in NUMBER_SPELLINGS ? NUMBER_SPELLINGS[here]!(v) : JSON.stringify(v);
  if (typeof v === 'string') return here.startsWith('escape') ? escapedFirst(v, here === 'escape-upper') : JSON.stringify(v);
  const sep = `${ws('ws-before-comma')},${ws('ws-after-comma')}`;
  if (Array.isArray(v)) {
    if (v.length === 0) return `[${ws('ws-inside-empty')}]`;
    return `[${ws('ws-after-open')}${v.map((x, i) => write(x, `${path}[${i}]`, t)).join(sep)}${ws('ws-before-close')}]`;
  }
  const obj = v as Record<string, unknown>;
  const keys = Object.keys(obj).sort(); // UTF-16 code-unit order, as canonicalize sorts
  if (keys.length === 0) return `{${ws('ws-inside-empty')}}`;
  let members = keys.map((k) => `${write(k, `${path}#${k}`, t)}${ws('ws-before-colon')}:${ws('ws-after-colon')}${write(obj[k], `${path}.${k}`, t)}`);
  if (here === 'members-swapped') members = [members[1]!, members[0]!, ...members.slice(2)];
  if (here === 'duplicate-first-member-same-value') members = [members[0]!, ...members];
  if (here === 'duplicate-first-member-overwritten') {
    members = [`${JSON.stringify(keys[0])}:${obj[keys[0]!] === null ? '0' : 'null'}`, ...members];
  }
  return `{${ws('ws-after-open')}${members.join(sep)}${ws('ws-before-close')}}`;
}

function sitesOf(v: unknown, path: string, out: { path: string; op: string }[]): void {
  const add = (op: string, at = path): void => void out.push({ path: at, op });
  if (typeof v === 'number') {
    add('exponent');
    add('fraction');
    if (v === 0) add('minus-zero');
  } else if (typeof v === 'string') {
    add(out.length % 2 === 0 ? 'escape-lower' : 'escape-upper');
  } else if (Array.isArray(v)) {
    if (v.length === 0) return add('ws-inside-empty');
    for (const op of ['ws-after-open', 'ws-before-close']) add(op);
    if (v.length > 1) for (const op of ['ws-before-comma', 'ws-after-comma']) add(op);
    v.forEach((x, i) => sitesOf(x, `${path}[${i}]`, out));
  } else if (v !== null && typeof v === 'object') {
    const keys = Object.keys(v).sort();
    if (keys.length === 0) return add('ws-inside-empty');
    for (const op of ['ws-after-open', 'ws-before-close', 'ws-before-colon', 'ws-after-colon', 'duplicate-first-member-same-value', 'duplicate-first-member-overwritten']) add(op);
    if (keys.length > 1) for (const op of ['ws-before-comma', 'ws-after-comma', 'members-swapped']) add(op);
    for (const k of keys) {
      sitesOf(k, `${path}#${k}`, out);
      sitesOf((v as Record<string, unknown>)[k], `${path}.${k}`, out);
    }
  }
}

function genericRespellings(line: string): [string, string][] {
  const value = parseJson(line);
  const sites: { path: string; op: string }[] = [];
  sitesOf(value, '$', sites);
  return sites.map(({ path, op }, i) => {
    const label = `${path.replace(/^\$/, 'root').replace(/#/g, '.key-')}-${op}`;
    return [label, write(value, '$', { path, op, ws: WHITESPACE[i % WHITESPACE.length]! })];
  });
}

// ---- hand-written: character classes and further number spellings ----------------------------------

type Respelling = [label: string, from: string, to: string];

const SPECIAL: Respelling[] = [
  ['slash-escaped', 'j/k', `j${BS}/k`],
  ['slash-as-unicode-escape', 'j/k', `j${BS}u002fk`],
  ['quote-as-unicode-escape', `${BS}"q`, `${BS}u0022q`],
  ['backslash-as-unicode-escape', `${BS}${BS}z`, `${BS}u005cz`],
  ['backslash-as-uppercase-hex-escape', `${BS}${BS}z`, `${BS}u005Cz`],
  ['line-feed-in-long-form', `${BS}n`, `${BS}u000a`],
  ['line-feed-in-long-form-uppercase-hex', `${BS}n`, `${BS}u000A`],
  ['control-escape-with-uppercase-hex', `${BS}u001f`, `${BS}u001F`],
  ['non-ascii-as-unicode-escape', E_ACUTE, `${BS}u00e9`],
  ['non-ascii-as-uppercase-hex-escape', E_ACUTE, `${BS}u00E9`],
  ['astral-as-escaped-surrogate-pair', EMOJI, `${BS}ud83d${BS}ude00`],
  ['astral-as-uppercase-hex-surrogate-pair', EMOJI, `${BS}uD83D${BS}uDE00`],
  ...['19e2', '19E2', '1.9e3', '1.9E+3', '190000e-2', '1900.00'].map((alt): Respelling => [`integer-as-${alt}`, '"amount":1900', `"amount":${alt}`]),
  ...['-0.0', '0e0', '0E-5'].map((alt): Respelling => [`zero-as-${alt}`, '"zero":0', `"zero":${alt}`]),
  ...['1E0', '10e-1', '0.1e1'].map((alt): Respelling => [`seq-as-${alt}`, '"seq":1,', `"seq":${alt},`]),
];

/** Two-line files whose SECOND line is respelled: each must break at line 1 (last_seq 0). */
export function respellingVectors(): { name: string; data: Buffer; expect: { ok: boolean; last_seq: number } }[] {
  const [line0, line1] = canonicalLines();
  const special = SPECIAL.map(([label, from, to]): [string, string] => {
    if (line1.split(from).length !== 2) throw new Error(`respelling ${label}: "${from}" is not in the line exactly once`);
    return [label, line1.replace(from, to)];
  });
  return [...genericRespellings(line1), ...special].map(([label, text]) => {
    assertSameValue(label, line1, text);
    return { name: `respelled-${label}`, data: Buffer.from(`${line0}${LF}${text}${LF}`, 'utf8'), expect: { ok: false, last_seq: 0 } };
  });
}

/** A respelling must be ANOTHER spelling of EXACTLY the canonical line's value, or the vector proves nothing. */
export function assertSameValue(label: string, canonicalLine: string, text: string): void {
  if (text === canonicalLine || canonicalize(parseJson(text)) !== canonicalLine) throw new Error(`respelling ${label} changes the value`);
}
