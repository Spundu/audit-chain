// Shared fixtures of the audit-seal vector groups: the public test key, the sealing helpers, and the
// valid 3-entry base chain that every group mutates.

import { createHash, createHmac } from 'node:crypto';
import { canonicalize } from '../../src/canonicalize.js';

// Fixed, PUBLIC 32-byte test key. Never use it for anything but these vectors.
export const KEY_HEX = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
export const key = Buffer.from(KEY_HEX, 'hex');
export function seal(core: Record<string, unknown>): Record<string, unknown> {
  const canonical = canonicalize(core);
  return {
    ...core,
    entry_hash: createHash('sha256').update(canonical, 'utf8').digest('hex'),
    entry_hmac: createHmac('sha256', key).update(canonical, 'utf8').digest('hex'),
  };
}

export function sealWith(core: Record<string, unknown>, k: Buffer): Record<string, unknown> {
  const canonical = canonicalize(core);
  return {
    ...core,
    entry_hash: createHash('sha256').update(canonical, 'utf8').digest('hex'),
    entry_hmac: createHmac('sha256', k).update(canonical, 'utf8').digest('hex'),
  };
}

// KEYRING vectors carry their own `keyring` ({id: key_hex}), overriding the default {key_id: key_hex}.
export function oneEntrySealedWith(id: string, k: Buffer): unknown[] {
  return [sealWith({ seq: 0, prev_hash: '0'.repeat(64), writer_key_id: id, note: 'keyring rule' }, k)];
}

// The valid 3-entry base chain. Each entry carries a `nonce`, searched for (deterministically, from 0) so
// that its entry_hash AND entry_hmac both start with "00": then every hash field of the chain, the
// genesis link and the head included, has leading zeros for the respellings in HASH_NEAR_MISSES.
let groundChain: Record<string, unknown>[] | null = null;
function grindBaseChain(): Record<string, unknown>[] {
  const chain: Record<string, unknown>[] = [];
  let prev = '0'.repeat(64);
  for (let seq = 0; seq < 3; seq += 1) {
    for (let nonce = 0; ; nonce += 1) {
      const entry = seal({
        v: 1, seq, event: 'payment.approval', request_id: `r${seq}`, service: 'payments',
        prev_hash: prev, writer_key_id: 'k1', nonce,
      });
      if ((entry.entry_hash as string).startsWith('00') && (entry.entry_hmac as string).startsWith('00')) {
        chain.push(entry);
        prev = entry.entry_hash as string;
        break;
      }
    }
  }
  return chain;
}
/** A fresh copy (the array and each flat entry) of the base chain, safe for a caller to mutate. */
export function baseChain(): Record<string, unknown>[] {
  groundChain ??= grindBaseChain();
  return groundChain.map((entry) => ({ ...entry }));
}

export function withHmacAt1(hmac: unknown): Record<string, unknown>[] {
  const chain = baseChain();
  chain[1] = { ...chain[1], entry_hmac: hmac };
  return chain;
}

export const realHmac1 = baseChain()[1]!.entry_hmac as string;
export const BROKEN_AT_1 = { ok: false, last_seq: 0 };
/** The base chain with entry `index` changed by `mutate` and validly RESEALED (hash and HMAC recomputed). */
export function resealAt(index: number, mutate: (core: Record<string, unknown>) => Record<string, unknown>): unknown[] {
  const chain = baseChain();
  const { entry_hash: _h, entry_hmac: _m, ...core } = chain[index]!;
  chain[index] = seal(mutate(core));
  return chain;
}
export const resealAt1 = (mutate: (core: Record<string, unknown>) => Record<string, unknown>): unknown[] => resealAt(1, mutate);
export function coreOf(entry: Record<string, unknown>): Record<string, unknown> {
  const { entry_hash: _h, entry_hmac: _m, ...core } = entry;
  return core;
}

export function withFieldAt(index: number, field: string, value: unknown): unknown[] {
  const chain = baseChain();
  chain[index] = { ...chain[index], [field]: value };
  return chain;
}

export function withField1(field: string, value: unknown): unknown[] {
  const chain = baseChain();
  chain[1] = { ...chain[1], [field]: value };
  return chain;
}
export const full = baseChain();
export const head = full[2]!.entry_hash as string;

export const GENESIS = '0'.repeat(64);
export function oneEntry(extra: Record<string, unknown>): Record<string, unknown>[] {
  return [seal({ seq: 0, prev_hash: GENESIS, writer_key_id: 'k1', ...extra })];
}
export function omit(core: Record<string, unknown>, field: string): Record<string, unknown> {
  const { [field]: _dropped, ...rest } = core;
  return rest;
}
/** Entry 1 with some core fields changed and entry_hash recomputed, but the ORIGINAL (stale) HMAC. */
export function rehashedAt1(changes: Record<string, unknown>): unknown[] {
  const chain = baseChain();
  const core = { ...coreOf(chain[1]!), ...changes };
  chain[1] = { ...core, entry_hash: createHash('sha256').update(canonicalize(core), 'utf8').digest('hex'), entry_hmac: chain[1]!.entry_hmac };
  return chain;
}
export const K2 = Buffer.alloc(32, 0x5a);
export const TWO_KEYS = { 'k1': KEY_HEX, k2: K2.toString('hex') };
/** Entry 0 sealed with k1; entry 1 labelled k2 and sealed with `k1or2`. */
export function rotated(k1or2: Buffer): unknown[] {
  const e0 = seal({ seq: 0, prev_hash: GENESIS, writer_key_id: 'k1', note: 'k1' });
  return [e0, sealWith({ seq: 1, prev_hash: e0.entry_hash, writer_key_id: 'k2', note: 'k2' }, k1or2)];
}

/** The hex digit after `c` (f wraps to 0): a DIFFERENT lowercase hex digit, so only an exact compare notices. */
const nextHexDigit = (c: string): string => ((Number.parseInt(c, 16) + 1) % 16).toString(16);
const withDigitChanged = (v: string, at: number): string => v.slice(0, at) + nextHexDigit(v[at]!) + v.slice(at + 1);

const DIGIT_TWIN_ZEROS = [0x0660, 0xff10, 0x1d7ce]; // Arabic-Indic, fullwidth, mathematical bold (astral)
const fullwidth = (c: string): string =>
  c >= '0' && c <= '9' ? String.fromCharCode(0xff10 + Number(c)) : String.fromCharCode(0xff41 + c.charCodeAt(0) - 97);
function leadingZeros(fn: (v: string) => string): (v: string) => string {
  return (v) => {
    if (!v.startsWith('00')) throw new Error(`hash respelling needs a field starting with 00: ${v}`);
    return fn(v);
  };
}

/**
 * NEAR MISSES of a 64-char lowercase-hex hash, applied to entry_hash, entry_hmac, prev_hash and the
 * anchor's last_hash: each must be a mismatch. First, ones that stay lowercase hex: extra digits (a
 * decoded-bytes compare drops an odd trailing nibble; a prefix compare ignores the rest), one digit changed
 * at the first, a middle, a second-half and the last position (an off-by-one, skip-first or half-length
 * compare misses it), a digit dropped from either end. Then RESPELLINGS of the true value that a
 * non-exact compare reads as equal: a digit as its non-ASCII decimal twin or in fullwidth (numeric
 * parsing, a Unicode \d, NFKC), non-ASCII junk that a lossy ASCII conversion drops, and the forms a
 * number parser accepts for the leading zeros ('+', whitespace, '_', '0x'), plus a lone surrogate (value
 * level only: no canonical line can hold it). Every hash field of the base chain starts with "00".
 */
export const HASH_NEAR_MISSES: [string, (v: string) => string][] = [
  ['plus-hex-digit-0', (v) => `${v}0`],
  ['plus-hex-digit-f', (v) => `${v}f`],
  ['plus-hex-digits-00', (v) => `${v}00`],
  ['hex-digit-0-prepended', (v) => `0${v}`],
  ['first-digit-changed', (v) => withDigitChanged(v, 0)],
  ['digit-31-changed', (v) => withDigitChanged(v, 31)],
  ['digit-40-changed', (v) => withDigitChanged(v, 40)],
  ['last-digit-changed', (v) => withDigitChanged(v, 63)],
  ['first-digit-dropped', (v) => v.slice(1)],
  ['last-digit-dropped', (v) => v.slice(0, 63)],
  ...DIGIT_TWIN_ZEROS.map((zero): [string, (v: string) => string] => [
    `first-digit-as-u${zero.toString(16)}-twin`,
    leadingZeros((v) => String.fromCodePoint(zero) + v.slice(1)),
  ]),
  ['first-char-fullwidth', (v) => fullwidth(v[0]!) + v.slice(1)],
  ['all-fullwidth', (v) => [...v].map(fullwidth).join('')],
  ['e-acute-appended', (v) => v + String.fromCharCode(0xe9)],
  ['e-acute-inserted', (v) => v.slice(0, 32) + String.fromCharCode(0xe9) + v.slice(32)],
  ['nbsp-appended', (v) => v + String.fromCharCode(0xa0)],
  ['leading-zero-as-plus', leadingZeros((v) => `+${v.slice(1)}`)],
  ['leading-zero-as-space', leadingZeros((v) => ` ${v.slice(1)}`)],
  ['leading-zero-as-nbsp', leadingZeros((v) => String.fromCharCode(0xa0) + v.slice(1))],
  ['leading-zero-as-ideographic-space', leadingZeros((v) => String.fromCharCode(0x3000) + v.slice(1))],
  ['leading-zero-dropped-trailing-space', leadingZeros((v) => `${v.slice(1)} `)],
  ['leading-zero-dropped-inner-underscore', leadingZeros((v) => `${v.slice(1, 32)}_${v.slice(32)}`)],
  ['leading-zeros-as-0x', leadingZeros((v) => `0x${v.slice(2)}`)],
  ['lone-surrogate-appended', (v) => v + String.fromCharCode(0xd800)],
  // A C-string compare stops at a NUL; a compare that drops invisible format characters (soft hyphen,
  // zero-width space, word joiner, BOM) sees only the true value.
  ['nul-appended', (v) => v + String.fromCharCode(0)],
  ['nul-then-junk-appended', (v) => `${v}${String.fromCharCode(0)}forged`],
  ['nul-inserted', (v) => v.slice(0, 32) + String.fromCharCode(0) + v.slice(32)],
  ...([['soft-hyphen', 0xad], ['zero-width-space', 0x200b], ['word-joiner', 0x2060], ['bom', 0xfeff]] as const).flatMap(
    ([label, code]): [string, (v: string) => string][] => [
      [`${label}-appended`, (v) => v + String.fromCharCode(code)],
      [`${label}-inserted`, (v) => v.slice(0, 32) + String.fromCharCode(code) + v.slice(32)],
    ],
  ),
];
