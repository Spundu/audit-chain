import { canonicalize } from '../../src/canonicalize.js';
import { parseJson } from '../../src/json.js';
import { GENESIS, full, head, oneEntry, realHmac1, seal } from './fixtures.mjs';
import { forged0 } from './order.mjs';
import type { SizeVector } from './selfcheck.mjs';

// JSONL vectors: raw canonical-JSONL FILE bytes (hex) and the verdict of verifyJsonl / verify_jsonl.
// Only canonical lines verify; every other spelling of the same entry breaks the chain at that line.
// Several are parser differentials that JSON.parse and json.loads read differently.
const lines = full.map((e) => canonicalize(e));
const file = (ls: string[]): Buffer => Buffer.from(ls.map((l) => `${l}\n`).join(''), 'utf8');
const line1 = (f: (l: string) => string): Buffer => file(lines.map((l, i) => (i === 1 ? f(l) : l)));
const injectAt1 = (member: string): Buffer => line1((l) => `{${member},${l.slice(1)}`);
const withBytesAt1 = (bytes: number[]): Buffer => {
  const parts = lines.map((l) => Buffer.from(`${l}\n`, 'utf8'));
  parts[1] = Buffer.concat([parts[1]!.subarray(0, 1), Buffer.from(bytes), parts[1]!.subarray(1)]);
  return Buffer.concat(parts);
};
const LINE_1_BROKEN = { ok: false, last_seq: 0 };

// A legitimately sealed chain that JSON.parse on V8 12.9+ (Node 23 and later) misreads: entry 0 has a key that is a
// single backslash, entry 1 a key that is a line feed after the same preceding key. JSON.parse then
// returns a backslash for entry 1's key, so a verifier built on it rejects a valid chain.
function escapedKeyChain(): Buffer {
  const e0 = seal({ seq: 0, prev_hash: '0'.repeat(64), writer_key_id: 'k1', p: { '': 1, [String.fromCharCode(92)]: 2 } });
  const e1 = seal({ seq: 1, prev_hash: e0.entry_hash, writer_key_id: 'k1', p: { '': 1, [String.fromCharCode(10)]: 2 } });
  return file([canonicalize(e0), canonicalize(e1)]);
}

// A sealed entry holding U+FFFD, whose UTF-8 bytes (EF BF BD) are then replaced by the single invalid
// byte FF. A LOSSY decoder turns FF back into U+FFFD, so the text, hash and HMAC all still match: only
// strict UTF-8 decoding notices that the file bytes changed.
function fffdSwappedForFf(): Buffer {
  const e0 = seal({ seq: 0, prev_hash: '0'.repeat(64), writer_key_id: 'k1', note: `x${String.fromCharCode(0xfffd)}y` });
  const bytes = file([canonicalize(e0)]);
  const at = bytes.indexOf(Buffer.from([0xef, 0xbf, 0xbd]));
  return Buffer.concat([bytes.subarray(0, at), Buffer.from([0xff]), bytes.subarray(at + 3)]);
}
/** A one-entry canonical-JSONL file sealing `extra` into entry 0. */
function oneLineFile(extra: Record<string, unknown>): Buffer {
  return file([canonicalize(oneEntry(extra)[0]!)]);
}
/** `data` with the FIRST occurrence of the byte sequence `from` replaced by `to`. */
function swapBytes(data: Buffer, from: number[], to: number[]): Buffer {
  const at = data.indexOf(Buffer.from(from));
  if (at < 0) throw new Error('swapBytes: sequence not found');
  return Buffer.concat([data.subarray(0, at), Buffer.from(to), data.subarray(at + from.length)]);
}
const cp = (...points: number[]): string => String.fromCodePoint(...points);
const LF_CHAR = String.fromCharCode(10);
// Every UTF-8 length class, and the code points non-UTF-8 readers mangle: U+0085 (NEL, a line break to
// str.splitlines), U+00A0, U+00FF, U+20AC, U+2028/U+2029 (line breaks to some readers), an astral char.
// Plus raw noncharacters (U+FFFE, U+FDD0, U+1FFFF): valid UTF-8 that a strict-XML-style decoder rejects.
const NON_ASCII = cp(0x85, 0xa0, 0xff, 0x20ac, 0x2028, 0x2029, 0x1f600, 0xfffe, 0xfdd0, 0x1ffff);
// Every C0 control character, sealed in a key and a value (each has an exact escape in canonical form).
const ALL_C0 = String.fromCharCode(...Array.from({ length: 32 }, (_, i) => i));
const NUL = String.fromCharCode(0);
const DEL_BOM_C1 = String.fromCharCode(0x7f, 0xfeff, ...Array.from({ length: 32 }, (_, i) => 0x80 + i));
// All printable ASCII (0x20..0x7E) and U+FFFD, U+00AD, U+200B, U+202E.
const PRINTABLE = String.fromCharCode(...Array.from({ length: 95 }, (_, i) => i + 32), 0xfffd, 0xad, 0x200b, 0x202e);

// NFC and NFD "twin" keys holding the same value. Swapping their spellings in the line leaves the parsed
// value (and so the hash and HMAC) unchanged: only the byte-exact compare, NOT a Unicode-normalizing
// one, sees that the line is no longer canonical.
const TWIN_NFD = `"e${cp(0x301)}":1`;
const TWIN_NFC = `"${cp(0xe9)}":1`;
const twinLine = canonicalize(oneEntry({ [`e${cp(0x301)}`]: 1, [cp(0xe9)]: 1 })[0]!);
if (twinLine.split(TWIN_NFD).length !== 2 || twinLine.split(TWIN_NFC).length !== 2) throw new Error('twin keys not found once each');
const twinSwapped = twinLine.split(TWIN_NFD).map((part) => part.split(TWIN_NFC).join(TWIN_NFD)).join(TWIN_NFC);

// LAX UTF-8 DECODERS. The second line seals a note holding é, '/' and U+FFFD; each file then replaces the
// bytes of one of them with an ill-formed sequence that some lax decoder turns back into exactly that
// character: no continuation-bit check, 3- and 4-byte overlongs, code points above U+10FFFF or F5 leads
// read as U+FFFD, a truncated sequence, a lone continuation byte or an encoded surrogate read as U+FFFD.
// Compared as decoded text the line would still match; the file bytes do not, and must break there.
const UTF8_SEALED = seal({ seq: 1, prev_hash: full[0]!.entry_hash, writer_key_id: 'k1', note: `caf${cp(0xe9)} a/b ${cp(0xfffd)} x` });
const E_ACUTE_BYTES = [0xc3, 0xa9];
const SLASH_BYTES = [0x61, 0x2f, 0x62]; // 'a/b': the only slash in the line
const FFFD_BYTES = [0xef, 0xbf, 0xbd];
const LAX_UTF8: [string, number[], number[]][] = [
  ['e-acute-second-byte-not-a-continuation-69', E_ACUTE_BYTES, [0xc3, 0x69]],
  ['e-acute-second-byte-not-a-continuation-e9', E_ACUTE_BYTES, [0xc3, 0xe9]],
  ['e-acute-as-3-byte-overlong', E_ACUTE_BYTES, [0xe0, 0x83, 0xa9]],
  ['slash-as-3-byte-overlong', SLASH_BYTES, [0x61, 0xe0, 0x80, 0xaf, 0x62]],
  ['slash-as-4-byte-overlong', SLASH_BYTES, [0x61, 0xf0, 0x80, 0x80, 0xaf, 0x62]],
  ['fffd-as-code-point-above-10ffff', FFFD_BYTES, [0xf4, 0x90, 0x80, 0x80]],
  ['fffd-as-f5-lead-sequence', FFFD_BYTES, [0xf5, 0x80, 0x80, 0x80]],
  ['fffd-as-truncated-sequence', FFFD_BYTES, [0xe2, 0x82]],
  ['fffd-as-lone-continuation-byte', FFFD_BYTES, [0x80]],
  ['fffd-as-lone-c0-lead', FFFD_BYTES, [0xc0]],
  ['fffd-as-encoded-surrogate', FFFD_BYTES, [0xed, 0xa0, 0x80]],
];

// A keylessly forged first line (see order.mts), then a later COMPLETE line that is bad in one way.
const forgedLine0 = canonicalize(forged0);
const CR = String.fromCharCode(13);
const forgedThen = (...later: string[]): Buffer => file([forgedLine0, lines[1]!, ...later]);
const forgedThenInvalidUtf8 = Buffer.concat([file([forgedLine0, lines[1]!]), Buffer.from('{"c', 'utf8'), Buffer.from([0xff]), Buffer.from('"}', 'utf8'), Buffer.from([10])]);

/**
 * The FILE twin of a verify vector: its chain as canonical JSONL, with the same anchor, keyring and
 * verdict. The emitter applies this to EVERY verify vector, so none can be left without one. A chain that
 * is not an array, or holds an entry outside the canonical domain (a lone surrogate, say), has no
 * canonical file and stays a value vector only.
 */
interface TwinSource {
  name: string;
  chain: unknown;
  anchor?: { count?: unknown; last_hash?: unknown };
  keyring?: Record<string, string>;
  expect: { ok: boolean; last_seq: number };
}
export function fileTwinOf(v: TwinSource): (Omit<TwinSource, 'chain'> & { data: Buffer })[] {
  if (!Array.isArray(v.chain)) return [];
  let twinLines: string[];
  try {
    twinLines = v.chain.map((e: unknown) => canonicalize(e));
  } catch {
    return [];
  }
  return [{
    name: `${v.name}-file`,
    data: file(twinLines),
    ...(v.anchor !== undefined ? { anchor: v.anchor } : {}),
    ...(v.keyring !== undefined ? { keyring: v.keyring } : {}),
    expect: v.expect,
  }];
}

export const JSONL_VECTORS = [
  // NO TRANSFORMATION of the line text before the byte-exact compare: not C-string NUL termination, not
  // whitespace trimming, not Unicode normalization. Each of these edits a terminated line and must break.
  { name: 'nul-then-hidden-bytes-in-middle-line', data: line1((l) => `${l}${NUL}{"amount":"1900.00"}`), expect: LINE_1_BROKEN },
  { name: 'nul-then-hidden-bytes-in-last-line', data: file(lines.map((l, i) => (i === 2 ? `${l}${NUL}x` : l))), expect: { ok: false, last_seq: 1 } },
  { name: 'nul-at-end-of-line', data: line1((l) => `${l}${NUL}`), expect: LINE_1_BROKEN },
  { name: 'leading-space-on-line', data: line1((l) => ` ${l}`), expect: LINE_1_BROKEN },
  { name: 'trailing-space-on-line', data: line1((l) => `${l} `), expect: LINE_1_BROKEN },
  { name: 'trailing-tab-on-last-line', data: file(lines.map((l, i) => (i === 2 ? `${l}${String.fromCharCode(9)}` : l))), expect: { ok: false, last_seq: 1 } },
  { name: 'leading-tab-on-first-line', data: file(lines.map((l, i) => (i === 0 ? `${String.fromCharCode(9)}${l}` : l))), expect: { ok: false, last_seq: -1 } },
  { name: 'sealed-nfc-rewritten-as-nfd-bytes', data: swapBytes(oneLineFile({ payee: `Caf${cp(0xe9)}` }), [0xc3, 0xa9], [0x65, 0xcc, 0x81]), expect: { ok: false, last_seq: -1 } },
  { name: 'sealed-nfd-rewritten-as-nfc-bytes', data: swapBytes(oneLineFile({ payee: `Cafe${cp(0x301)}` }), [0x65, 0xcc, 0x81], [0xc3, 0xa9]), expect: { ok: false, last_seq: -1 } },
  { name: 'sealed-raw-nfd-verifies', data: oneLineFile({ payee: `Cafe${cp(0x301)}`, [`e${cp(0x301)}`]: 1 }), expect: { ok: true, last_seq: 0 } },
  { name: 'nfc-nfd-twin-keys-verify', data: file([twinLine]), expect: { ok: true, last_seq: 0 } },
  { name: 'nfc-nfd-twin-keys-swapped', data: file([twinSwapped]), expect: { ok: false, last_seq: -1 } },
  // Every printable ASCII character, raw, plus characters some encoders escape or strip: U+FFFD, soft
  // hyphen, zero-width space, right-to-left override.
  { name: 'printable-ascii-and-lookalikes-verify', data: oneLineFile({ note: PRINTABLE, [PRINTABLE]: 1 }), expect: { ok: true, last_seq: 0 } },
  { name: 'all-c0-controls-in-key-and-value-verifies', data: oneLineFile({ note: ALL_C0, [ALL_C0]: 1 }), expect: { ok: true, last_seq: 0 } },
  // Bytes AFTER the final line feed are an unterminated (torn) line, even if they are only whitespace or NULs.
  ...([['space', [32]], ['cr', [13]], ['tab', [9]], ['nuls', [0, 0, 0]]] as const).map(([label, tail]) => ({
    name: `tail-after-final-lf-${label}`,
    data: Buffer.concat([file(lines), Buffer.from(tail)]),
    expect: { ok: false, last_seq: 2 },
  })),
  // CROSS-LINE ORDER: the lines before a bad line are verified first, whatever makes the later line bad.
  // A pre-scan of every line (UTF-8, syntax, whitespace, size) would report the later line and vouch for
  // the forged first one. The over-limit case is a generated size vector.
  { name: 'forged-first-line-then-trailing-space-line', data: forgedThen(`${lines[2]} `), expect: { ok: false, last_seq: -1 } },
  { name: 'forged-first-line-then-unclosed-line', data: forgedThen(lines[2]!.slice(0, -1)), expect: { ok: false, last_seq: -1 } },
  { name: 'forged-first-line-then-cr-terminated-line', data: forgedThen(`${lines[2]}${CR}`), expect: { ok: false, last_seq: -1 } },
  { name: 'forged-first-line-then-invalid-utf8-line', data: forgedThenInvalidUtf8, expect: { ok: false, last_seq: -1 } },
  { name: 'forged-middle-line-then-junk-line', data: file([lines[0]!, canonicalize({ ...full[1], request_id: 'rX' }), lines[2]!, 'x']), expect: { ok: false, last_seq: 0 } },
  { name: 'lax-utf8-control-sealed-line-verifies', data: file([lines[0]!, canonicalize(UTF8_SEALED)]), expect: { ok: true, last_seq: 1 } },
  ...LAX_UTF8.map(([label, from, to]) => ({
    name: `lax-utf8-${label}`,
    data: swapBytes(file([lines[0]!, canonicalize(UTF8_SEALED)]), from, to),
    expect: LINE_1_BROKEN,
  })),
  // U+D7FF, the last code point before the surrogate block, is an ordinary character.
  { name: 'u-d7ff-in-key-and-value-verifies', data: oneLineFile({ note: cp(0xd7ff), [cp(0xd7ff)]: 1 }), expect: { ok: true, last_seq: 0 } },
  // DEL, U+FEFF and the C1 controls, raw in a key and a value.
  { name: 'del-bom-and-c1-in-key-and-value-verifies', data: oneLineFile({ note: DEL_BOM_C1, [DEL_BOM_C1]: 1 }), expect: { ok: true, last_seq: 0 } },
  // Whitespace BEFORE the first line, and files of only whitespace: nothing is skipped or trimmed.
  { name: 'line-feed-before-a-valid-file', data: Buffer.concat([Buffer.from([10]), file(lines)]), expect: { ok: false, last_seq: -1 } },
  ...([['lf', [10]], ['two-lfs', [10, 10]], ['space-then-lf', [32, 10]], ['space', [32]]] as const).map(([label, bytes]) => ({
    name: `whitespace-only-file-${label}`,
    data: Buffer.from(bytes),
    expect: { ok: false, last_seq: -1 },
  })),
  // Only 0x0A separates lines: VT, FF, FS, GS and RS are never line separators. In place of the line
  // feed after line 0 they join two lines into one invalid line; in place of the final one, a torn tail.
  ...([['vt', 0x0b], ['ff', 0x0c], ['fs', 0x1c], ['gs', 0x1d], ['rs', 0x1e]] as const).flatMap(([label, code]) => [
    { name: `${label}-in-place-of-the-first-line-feed`, data: Buffer.from(`${lines[0]}${String.fromCharCode(code)}${lines[1]}${LF_CHAR}${lines[2]}${LF_CHAR}`, 'utf8'), expect: { ok: false, last_seq: -1 } },
    { name: `${label}-in-place-of-the-final-line-feed`, data: Buffer.from(`${lines[0]}${LF_CHAR}${lines[1]}${LF_CHAR}${lines[2]}${String.fromCharCode(code)}`, 'utf8'), expect: { ok: false, last_seq: 1 } },
  ]),
  // Later lines that are bad in yet other ways (each also gets a forged-first twin, see derive.mts).
  { name: 'bom-prefixed-middle-line', data: Buffer.concat([file([lines[0]!]), Buffer.from([0xef, 0xbb, 0xbf]), file([lines[1]!, lines[2]!])]), expect: LINE_1_BROKEN },
  { name: 'line-nested-101-deep-in-middle', data: file([lines[0]!, '['.repeat(101) + ']'.repeat(101), lines[2]!]), expect: LINE_1_BROKEN },
  { name: 'line-nested-3000-deep-in-middle', data: file([lines[0]!, '['.repeat(3000) + ']'.repeat(3000), lines[2]!]), expect: LINE_1_BROKEN },
  // No anchor on a file with a COMPLETE bad line either (not only a torn one): the bad line's verdict.
  { name: 'junk-fourth-line-with-wrong-head-anchor', data: file([...lines, 'x']), anchor: { count: 3, last_hash: 'f'.repeat(64) }, expect: { ok: false, last_seq: 2 } },
  // ACCEPTING files with non-ASCII bytes, in a key and a value: ASCII-only, Latin-1, cp1252 or
  // splitlines-based readers fail these.
  { name: 'non-ascii-in-keys-and-values-verifies', data: oneLineFile({ note: NON_ASCII, [NON_ASCII]: 1 }), expect: { ok: true, last_seq: 0 } },
  // UTF-8 tamper INSIDE a string, where a lenient decoder yields exactly the sealed character.
  { name: 'overlong-slash-inside-string', data: swapBytes(oneLineFile({ note: 'a/b' }), [0x61, 0x2f], [0x61, 0xc0, 0xaf]), expect: { ok: false, last_seq: -1 } },
  { name: 'cesu8-pair-inside-string', data: swapBytes(oneLineFile({ note: cp(0x1f600) }), [0xf0, 0x9f, 0x98, 0x80], [0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]), expect: { ok: false, last_seq: -1 } },
  { name: 'latin1-byte-for-sealed-u00ff', data: swapBytes(oneLineFile({ note: cp(0xff) }), [0xc3, 0xbf], [0xff]), expect: { ok: false, last_seq: -1 } },
  { name: 'latin1-transcoded-e-acute', data: swapBytes(oneLineFile({ note: cp(0xe9) }), [0xc3, 0xa9], [0xe9]), expect: { ok: false, last_seq: -1 } },
  { name: 'cp1252-transcoded-euro', data: swapBytes(oneLineFile({ note: cp(0x20ac) }), [0xe2, 0x82, 0xac], [0x80]), expect: { ok: false, last_seq: -1 } },
  // Canonical lines that are not objects are entries that fail, never lines to skip.
  { name: 'null-line-inserted', data: file([lines[0]!, 'null', lines[1]!, lines[2]!]), expect: LINE_1_BROKEN },
  { name: 'array-line-inserted', data: file([lines[0]!, '[]', lines[1]!, lines[2]!]), expect: LINE_1_BROKEN },
  { name: 'number-line-inserted', data: file([lines[0]!, '0', lines[1]!, lines[2]!]), expect: LINE_1_BROKEN },
  { name: 'string-line-inserted', data: file([lines[0]!, '"x"', lines[1]!, lines[2]!]), expect: LINE_1_BROKEN },
  // Cross-entry order on a file: a forged first line is reported at 0 even when a later line is junk.
  { name: 'forged-first-line-then-null-line', data: file([canonicalize({ ...full[0], entry_hmac: '0'.repeat(64) }), 'null']), expect: { ok: false, last_seq: -1 } },
  { name: 'hmac-real-plus-one-hex-digit-line', data: line1((l) => l.replace(realHmac1, `${realHmac1}0`)), expect: LINE_1_BROKEN },
  // Anchors on files: an empty file is still checked against the anchor; the head hash is checked too.
  { name: 'empty-file-with-anchor', data: Buffer.alloc(0), anchor: { count: 3, last_hash: head }, expect: { ok: false, last_seq: -1 } },
  { name: 'empty-file-anchored-at-genesis', data: Buffer.alloc(0), anchor: { count: 0, last_hash: GENESIS }, expect: { ok: true, last_seq: -1 } },
  { name: 'canonical-file-wrong-head-anchor', data: file(lines), anchor: { count: 3, last_hash: 'f'.repeat(64) }, expect: { ok: false, last_seq: 1 } },
  // The final line is a COMPLETE sealed entry whose terminating line feed became a carriage return: only
  // the torn-tail rule rejects it (the entry itself would verify).
  { name: 'final-line-feed-replaced-by-cr', data: Buffer.concat([file(lines).subarray(0, -1), Buffer.from([13])]), expect: { ok: false, last_seq: 1 } },
  { name: 'canonical-file', data: file(lines), expect: { ok: true, last_seq: 2 } },
  { name: 'escaped-key-after-backslash-key', data: escapedKeyChain(), expect: { ok: true, last_seq: 1 } },
  { name: 'trailing-blank-line', data: Buffer.concat([file(lines), Buffer.from([10])]), expect: { ok: false, last_seq: 2 } },
  // No anchor is applied to a file with a bad line: the verdict is the bad line's, not the anchor's.
  {
    name: 'torn-tail-with-wrong-head-anchor',
    data: Buffer.concat([file(lines), Buffer.from('{"torn')]),
    anchor: { count: 3, last_hash: 'f'.repeat(64) },
    expect: { ok: false, last_seq: 2 },
  },
  // ORDER: the lines before a bad or torn line are still verified first; a forged first line is
  // reported there, not hidden behind the later torn line.
  {
    name: 'forged-first-line-then-torn-line',
    data: Buffer.concat([file(lines.map((l, i) => (i === 0 ? canonicalize({ ...full[0], entry_hmac: '0'.repeat(64) }) : l))), Buffer.from('{"torn')]),
    expect: { ok: false, last_seq: -1 },
  },
  { name: 'entry-hash-only-changed-on-last-line', data: file(lines.map((l, i) => (i === 2 ? canonicalize({ ...full[2], entry_hash: 'f'.repeat(64) }) : l))), expect: { ok: false, last_seq: 1 } },
  { name: 'entry-hash-only-changed-on-middle-line', data: file(lines.map((l, i) => (i === 1 ? canonicalize({ ...full[1], entry_hash: 'f'.repeat(64) }) : l))), expect: LINE_1_BROKEN },
  { name: 'replacement-char-bytes-swapped-for-invalid-ff', data: fffdSwappedForFf(), expect: { ok: false, last_seq: -1 } },
  { name: 'no-final-newline-is-torn', data: Buffer.from(lines.join('\n'), 'utf8'), expect: { ok: false, last_seq: 1 } },
  { name: 'empty-file', data: Buffer.alloc(0), expect: { ok: true, last_seq: -1 } },
  { name: 'canonical-file-with-anchor', data: file(lines), anchor: { count: 3, last_hash: head }, expect: { ok: true, last_seq: 2 } },
  { name: 'truncated-file-with-anchor', data: file(lines.slice(0, 2)), anchor: { count: 3, last_hash: head }, expect: { ok: false, last_seq: 1 } },
  { name: 'crlf-line-endings', data: Buffer.from(lines.map((l) => `${l}\r\n`).join(''), 'utf8'), expect: { ok: false, last_seq: -1 } },
  { name: 'bom-prefix', data: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), file(lines)]), expect: { ok: false, last_seq: -1 } },
  { name: 'blank-line', data: Buffer.from(`${lines[0]}\n\n${lines[1]}\n${lines[2]}\n`, 'utf8'), expect: LINE_1_BROKEN },
  { name: 'whitespace-in-line', data: line1((l) => l.replace('":', '": ')), expect: LINE_1_BROKEN },
  { name: 'seq-written-as-1.0', data: line1((l) => l.replace('"seq":1,', '"seq":1.0,')), expect: LINE_1_BROKEN },
  { name: 'duplicate-key-same-value', data: injectAt1('"seq":1'), expect: LINE_1_BROKEN },
  { name: 'overwritten-duplicate-nan', data: injectAt1('"seq":NaN'), expect: LINE_1_BROKEN },
  { name: 'overwritten-duplicate-5000-digits', data: injectAt1(`"seq":${'9'.repeat(5000)}`), expect: LINE_1_BROKEN },
  { name: 'overwritten-duplicate-3000-deep', data: injectAt1(`"seq":${'['.repeat(3000)}${']'.repeat(3000)}`), expect: LINE_1_BROKEN },
  { name: 'invalid-utf8-byte', data: withBytesAt1([0xff]), expect: LINE_1_BROKEN },
  { name: 'overlong-utf8', data: withBytesAt1([0xc0, 0xaf]), expect: LINE_1_BROKEN },
  { name: 'utf8-encoded-surrogate', data: withBytesAt1([0xed, 0xa0, 0x80]), expect: LINE_1_BROKEN },
  { name: 'torn-final-line', data: file(lines).subarray(0, file(lines).length - 7), expect: { ok: false, last_seq: 1 } },
];

// JSONL SIZE vectors, in generated form (file = prefix + unit x count + suffix, UTF-8) so the spec stays
// small: a validly sealed line of EXACTLY max_canonical_bytes (must verify: a verifier whose line-length
// pre-check is off by one rejects it) and the same line one byte longer (must be refused).
// value_expect: the verdict of verifyChain / verify_chain on the entries parsed from the file's lines: the
// whole ENTRY must fit the limit at the value level too (seal refuses to create a larger one). Each pair is
// padded with a given unit: ASCII, and a 2-byte character (so a limit measured in UTF-16 units or code
// points instead of UTF-8 bytes fails the pair).

function sizePair(tag: string, unit: string): SizeVector[] {
  const MAX = 1_048_576;
  const unitBytes = Buffer.byteLength(unit, 'utf8');
  const base = { seq: 0, prev_hash: '0'.repeat(64), writer_key_id: 'k1', pad: '' };
  const room = MAX - Buffer.byteLength(canonicalize(seal(base)), 'utf8');
  const count = Math.floor(room / unitBytes);
  const filler = 'x'.repeat(room - count * unitBytes); // tops the pad up to exactly the limit
  // A validly sealed entry whose pad is unit x count + tail, spelled as its canonical line. Members are in
  // canonical key order and every value needs no escaping, so JSON.stringify is exact even when the line
  // is too long for canonicalize() to produce.
  const lineFor = (tail: string): string => {
    const entry = seal({ ...base, pad: unit.repeat(count) + tail });
    return JSON.stringify(Object.fromEntries(Object.keys(entry).sort().map((k) => [k, entry[k]])));
  };
  const split = (line: string, tail: string, bytes: number): Pick<SizeVector, 'prefix' | 'suffix'> => {
    if (Buffer.byteLength(line, 'utf8') !== bytes) throw new Error(`size vector ${tag}: line is not ${bytes} bytes`);
    const at = line.indexOf('"pad":"') + '"pad":"'.length;
    const prefix = line.slice(0, at);
    const suffix = `${tail}${line.slice(at + unit.length * count + tail.length)}\n`;
    if (prefix + unit.repeat(count) + suffix !== `${line}\n`) throw new Error(`size vector ${tag} does not split cleanly`);
    return { prefix, suffix };
  };
  const at = lineFor(filler);
  if (canonicalize(parseJson(at)) !== at) throw new Error(`size vector ${tag}: at-limit line is not canonical`);
  const over = lineFor(`${filler}x`);
  return [
    { name: `sealed-line-exactly-at-limit${tag}`, ...split(at, filler, MAX), unit, count, expect: { ok: true, last_seq: 0 }, value_expect: { ok: true, last_seq: 0 } },
    { name: `sealed-line-one-byte-over-limit${tag}`, ...split(over, `${filler}x`, MAX + 1), unit, count, expect: { ok: false, last_seq: -1 }, value_expect: { ok: false, last_seq: -1 } },
  ];
}

// CROSS-LINE ORDER with an oversized later line: a forged first line, a valid second line, then a line
// (a well-formed entry) longer than the limit. A size pre-scan would report line 2 and vouch for line 0.
function forgedThenOverLimit(): SizeVector {
  const big: Record<string, unknown> = { ...full[2]!, pad: '' };
  const text = JSON.stringify(Object.fromEntries(Object.keys(big).sort().map((k) => [k, big[k]])));
  const at = text.indexOf('"pad":"') + '"pad":"'.length;
  const LF = String.fromCharCode(10);
  return {
    name: 'forged-first-line-then-over-limit-line',
    prefix: forgedLine0 + LF + lines[1]! + LF + text.slice(0, at),
    unit: 'x',
    count: 1_048_576,
    suffix: text.slice(at) + LF,
    expect: { ok: false, last_seq: -1 },
    value_expect: { ok: false, last_seq: -1 },
  };
}

// The size limit is PER LINE, not a limit on where a line starts: after an at-limit first line, the
// second (small, valid) line starts past byte 1 MiB and must verify.
function lineStartingPastOneMiB(): SizeVector {
  const atLimit = sizePair('', 'x')[0]!;
  const line0 = atLimit.prefix + atLimit.unit.repeat(atLimit.count) + atLimit.suffix;
  const e0 = parseJson(line0.slice(0, -1)) as Record<string, unknown>;
  const e1 = seal({ seq: 1, prev_hash: e0.entry_hash, writer_key_id: 'k1', note: 'starts past 1 MiB' });
  const LF = String.fromCharCode(10);
  return {
    name: 'line-starting-past-1-mib-verifies',
    prefix: atLimit.prefix,
    unit: atLimit.unit,
    count: atLimit.count,
    suffix: atLimit.suffix + canonicalize(e1) + LF,
    expect: { ok: true, last_seq: 1 },
    value_expect: { ok: true, last_seq: 1 },
  };
}

// An over-limit but validly sealed entry at a LATER position, in the middle or last: the size rule (step
// 8, and the per-line limit) applies at every position, and nothing after it is vouched for.
function overLimitLineAt(position: 'middle' | 'last'): SizeVector {
  const MAX = 1_048_576;
  const LF = String.fromCharCode(10);
  const base = { seq: 1, prev_hash: full[0]!.entry_hash, writer_key_id: 'k1', pad: '' };
  const room = MAX + 1 - Buffer.byteLength(canonicalize(seal(base)), 'utf8');
  const e1 = seal({ ...base, pad: 'x'.repeat(room) }); // its core fits; the whole entry is 1 byte over
  const line1 = JSON.stringify(Object.fromEntries(Object.keys(e1).sort().map((k) => [k, e1[k]])));
  if (Buffer.byteLength(line1, 'utf8') !== MAX + 1) throw new Error('over-limit line is not MAX + 1 bytes');
  const at = line1.indexOf('"pad":"') + '"pad":"'.length;
  const e2 = seal({ seq: 2, prev_hash: e1.entry_hash, writer_key_id: 'k1', note: 'after' });
  return {
    name: `over-limit-line-at-${position}`,
    prefix: lines[0]! + LF + line1.slice(0, at),
    unit: 'x',
    count: room,
    suffix: line1.slice(at + room) + LF + (position === 'middle' ? canonicalize(e2) + LF : ''),
    expect: { ok: false, last_seq: 0 },
    value_expect: { ok: false, last_seq: 0 },
  };
}

// The later-failure rule (derive.mts) for the size vectors, written out: each vector whose first failure is
// the size limit, with a keylessly forged line appended. The verdict must not change, at file or value
// level: a verifier that checks sizes in a second pass would report the forged line first.
function thenForgedLine(v: SizeVector): SizeVector {
  const forgedLine = canonicalize({ ...full[0]!, forged_without_the_key: true });
  return { ...v, name: `${v.name}-then-forged-line`, suffix: v.suffix + forgedLine + String.fromCharCode(10) };
}

export function jsonlSizeVectors(): SizeVector[] {
  const [atLimit, overLimit, atLimit2, overLimit2] = [...sizePair('', 'x'), ...sizePair('-two-byte-pad', String.fromCharCode(0xe9))];
  const middle = overLimitLineAt('middle');
  const last = overLimitLineAt('last');
  return [
    atLimit!, overLimit!, atLimit2!, overLimit2!, forgedThenOverLimit(), lineStartingPastOneMiB(), middle, last,
    ...[overLimit!, overLimit2!, middle, last].map(thenForgedLine),
  ];
}
