// DERIVATIONS: rules that turn every vector into more cases a conformant verifier must also pass. The
// vector file carries the constants (`derivations`); every harness applies the rules (TS: this module, in
// test/audit-seal-vectors.test.ts and the generator's self-check; Python: python/tests/_derivations.py;
// the installed build: scripts/consumer-smoke.mjs). They pin the ORDER of the checks in both directions,
// under every kind of anchor, and what may follow a valid chain.
//
// A case is a verify vector (`chain`), a JSONL vector (`data`, its bytes), or a size vector read as both.
// `entry_failure` is harness bookkeeping: true when the verdict comes from a failing entry or line, not
// the anchor (a base vector without an anchor that fails; every case a rule below produces).
//
// The rules apply to each base case AND to the cases they derive, each rule at most once on a derivation
// path, to a depth of `max_depth` rules:
//  forged_first    expect ok false with last_seq >= 0: entry 0 replaced by `later_entry`, a keyless forgery
//                  (seq 0, the genesis link, a stale seal); for a file, line 0 replaced by later_lines_hex[0],
//                  its canonical line. Expect ok false, last_seq -1.
//  later_failure   entry_failure: append `later_entry` (a chain) or each of `later_lines_hex` (a file).
//                  Expect unchanged.
//  ignored_anchor  entry_failure and no anchor: verify with each of `ignored_anchors`. Expect unchanged.
//  tail_failure    expect ok true (n = last_seq + 1 entries): append, one at a time, `later_entry`, a copy
//                  of the last entry, a copy of entry 0 and the whole chain again (for a file: each of
//                  `later_lines_hex` and `inserted_lines_hex`, the last line, line 0, the whole file). Expect
//                  ok false, last_seq n - 1, both as given and, when there is no anchor, under the TRUE
//                  anchor {count: n, last_hash: head} (head: the last entry's entry_hash, or genesis_hash).
//  head_replay     expect ok true with n >= 1: a copy of entry 0 (line 0) inserted at index 1; for a file,
//                  also each of `inserted_lines_hex` inserted at index 1. Expect ok false, last_seq 0.

import { canonicalize } from '../../src/canonicalize.js';
import { parseJson } from '../../src/json.js';

export interface Verdict {
  ok: boolean;
  last_seq: number;
}
export interface Derivations {
  later_entry: Record<string, unknown>;
  later_lines_hex: string[];
  inserted_lines_hex: string[];
  ignored_anchors: { count: number; last_hash: string }[];
  genesis_hash: string;
  max_depth: number;
}
export interface Case {
  name: string;
  chain?: unknown;
  data?: Uint8Array;
  keyring?: Record<string, string>;
  anchor?: unknown;
  expect: Verdict;
}
interface Node {
  c: Case;
  applied: ReadonlySet<string>;
  entryFailure: boolean;
}

const LF = 10;
const BROKEN_AT_0: Verdict = { ok: false, last_seq: -1 };

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** The complete lines of a file (without their line feeds), and whatever follows the last line feed. */
function splitLines(data: Uint8Array): { lines: Uint8Array[]; rest: Uint8Array } {
  const lines: Uint8Array[] = [];
  let start = 0;
  for (let end = data.indexOf(LF, start); end !== -1; end = data.indexOf(LF, start)) {
    lines.push(data.subarray(start, end));
    start = end + 1;
  }
  return { lines, rest: data.subarray(start) };
}
const withLf = (line: Uint8Array): Buffer => Buffer.concat([line, Buffer.from([LF])]);
const entryOfLine = (line: Uint8Array): Record<string, unknown> => {
  const text = Buffer.from(line).toString('utf8');
  const value = parseJson(text);
  // Only reached for a line the chain got past (or a passing file): a canonical entry.
  if (!isObject(value) || canonicalize(value) !== text) throw new Error('derivation: not a canonical entry line');
  return value;
};

type Rule = (n: Node, d: Derivations) => { suffix: string; c: Case; entryFailure: boolean }[] | null;

const forgedFirst: Rule = ({ c }, d) => {
  if (c.expect.ok || c.expect.last_seq < 0) return null;
  if (c.data !== undefined) {
    const { lines, rest } = splitLines(c.data);
    const data = Buffer.concat([Buffer.from(d.later_lines_hex[0]!, 'hex'), ...lines.slice(1).map(withLf), rest]);
    return [{ suffix: 'forged-first', c: { ...c, data, expect: BROKEN_AT_0 }, entryFailure: true }];
  }
  const [, ...rest] = c.chain as unknown[];
  return [{ suffix: 'forged-first', c: { ...c, chain: [d.later_entry, ...rest], expect: BROKEN_AT_0 }, entryFailure: true }];
};

const laterFailure: Rule = ({ c, entryFailure }, d) => {
  if (!entryFailure) return null;
  if (c.data !== undefined) {
    return d.later_lines_hex.map((hex, i) => ({ suffix: `later-line-${i}`, c: { ...c, data: Buffer.concat([c.data!, Buffer.from(hex, 'hex')]) }, entryFailure: true }));
  }
  if (!Array.isArray(c.chain)) return [];
  return [{ suffix: 'later-entry', c: { ...c, chain: [...c.chain, d.later_entry] }, entryFailure: true }];
};

const ignoredAnchor: Rule = ({ c, entryFailure }, d) => {
  if (!entryFailure || c.anchor !== undefined) return null;
  return d.ignored_anchors.map((anchor, i) => ({ suffix: `ignored-anchor-${i}`, c: { ...c, anchor }, entryFailure: true }));
};

const tailFailure: Rule = ({ c }, d) => {
  if (!c.expect.ok) return null;
  const n = c.expect.last_seq + 1;
  const expect: Verdict = { ok: false, last_seq: n - 1 };
  let tails: [string, Case, string][]; // [label, case, head]
  if (c.data !== undefined) {
    const { lines } = splitLines(c.data);
    const head = n === 0 ? d.genesis_hash : (entryOfLine(lines[n - 1]!).entry_hash as string);
    const appended = [
      ...d.later_lines_hex.map((hex, i): [string, Uint8Array] => [`later-line-${i}`, Buffer.from(hex, 'hex')]),
      ...d.inserted_lines_hex.map((hex, i): [string, Uint8Array] => [`inserted-line-${i}`, Buffer.from(hex, 'hex')]),
      ...(n >= 1 ? ([['last-line-again', withLf(lines[n - 1]!)], ['line-0-again', withLf(lines[0]!)], ['whole-file-again', c.data]] as [string, Uint8Array][]) : []),
    ];
    tails = appended.map(([label, bytes]) => [label, { ...c, data: Buffer.concat([c.data!, bytes]), expect }, head]);
  } else {
    const chain = c.chain as unknown[];
    const head = n === 0 ? d.genesis_hash : ((chain[n - 1] as Record<string, unknown>).entry_hash as string);
    const appended: [string, unknown[]][] = [
      ['later-entry', [d.later_entry]],
      ...(n >= 1 ? ([['last-entry-again', [chain[n - 1]]], ['entry-0-again', [chain[0]]], ['whole-chain-again', chain]] as [string, unknown[]][]) : []),
    ];
    tails = appended.map(([label, more]) => [label, { ...c, chain: [...chain, ...more], expect }, head]);
  }
  return tails.flatMap(([label, t, head]) => [
    { suffix: `tail-${label}`, c: t, entryFailure: true },
    ...(c.anchor === undefined ? [{ suffix: `tail-${label}-true-anchor`, c: { ...t, anchor: { count: n, last_hash: head } }, entryFailure: true }] : []),
  ]);
};

const headReplay: Rule = ({ c }, d) => {
  if (!c.expect.ok || c.expect.last_seq < 0) return null;
  const expect: Verdict = { ok: false, last_seq: 0 };
  if (c.data !== undefined) {
    const { lines, rest } = splitLines(c.data);
    const afterLine0 = (inserted: Uint8Array): Buffer => Buffer.concat([withLf(lines[0]!), inserted, ...lines.slice(1).map(withLf), rest]);
    return [
      { suffix: 'head-replay', c: { ...c, data: afterLine0(withLf(lines[0]!)), expect }, entryFailure: true },
      ...d.inserted_lines_hex.map((hex, i) => ({
        suffix: `head-inserted-line-${i}`,
        c: { ...c, data: afterLine0(Buffer.from(hex, 'hex')), expect },
        entryFailure: true,
      })),
    ];
  }
  const chain = c.chain as unknown[];
  return [{ suffix: 'head-replay', c: { ...c, chain: [chain[0], ...chain], expect }, entryFailure: true }];
};

const RULES: [string, Rule][] = [
  ['forged_first', forgedFirst],
  ['later_failure', laterFailure],
  ['ignored_anchor', ignoredAnchor],
  ['tail_failure', tailFailure],
  ['head_replay', headReplay],
];

/** Every case derived from `base` (not including `base` itself). */
export function derivedCases(base: Case, d: Derivations): Case[] {
  const out: Case[] = [];
  let frontier: Node[] = [{ c: base, applied: new Set(), entryFailure: !base.expect.ok && base.anchor === undefined }];
  for (let depth = 0; depth < d.max_depth; depth += 1) {
    const next: Node[] = [];
    for (const node of frontier) {
      for (const [ruleName, rule] of RULES) {
        if (node.applied.has(ruleName)) continue;
        for (const child of rule(node, d) ?? []) {
          const derived: Node = {
            c: { ...child.c, name: `${node.c.name}/${child.suffix}` },
            applied: new Set([...node.applied, ruleName]),
            entryFailure: child.entryFailure,
          };
          out.push(derived.c);
          next.push(derived);
        }
      }
    }
    frontier = next;
  }
  return out;
}

/** A size vector read as the two cases it is: the generated file, and the chain of its parsed lines. */
export function sizeVectorCases(v: { name: string; prefix: string; unit: string; count: number; suffix: string; expect: Verdict; value_expect: Verdict }): Case[] {
  const text = v.prefix + v.unit.repeat(v.count) + v.suffix;
  const data = Buffer.from(text, 'utf8');
  const chain = text.split(String.fromCharCode(LF)).slice(0, -1).map((line) => parseJson(line));
  return [
    { name: v.name, data, expect: v.expect },
    { name: `${v.name} (value level)`, chain, expect: v.value_expect },
  ];
}
