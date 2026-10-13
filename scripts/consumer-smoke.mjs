// Consumer smoke test for the PUBLISHED package. Run it from a directory where the packed tarball has
// been installed (CI does: npm pack, npm install <tgz>, node <repo>/scripts/consumer-smoke.mjs). It
// proves what `npm test` cannot, because the tests import ../src: that main/types/exports resolve,
// that the package loads through require() and ESM import, and that the installed build reproduces
// every normative canonicalization vector (value, text and size) shipped inside it, every seal vector,
// every audit verdict (with the spec's derived cases) and a writer round trip.

import { Buffer } from 'node:buffer';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import process from 'node:process';

const NAME = 'sealed-audit-chain';
const requireHere = createRequire(`${process.cwd()}/`);
const fail = (message) => {
  process.stderr.write(`consumer smoke test FAILED: ${message}\n`);
  process.exit(1);
};

const pkg = requireHere(NAME);
const EXPORTS = ['canonicalize', 'parseJson', 'verifyJsonl', 'verifyChain', 'verifyEntries', 'JsonlChainWriter', 'readChain', 'InMemoryKeyProvider'];
for (const name of EXPORTS) if (typeof pkg[name] !== 'function') fail(`require('${NAME}').${name} is not a function`);

// The vector files are resolved through the "exports" map, then parsed with the package's own strict
// parser: never JSON.parse (or a JSON import) on spec text, see src/json.ts.
const readVectors = (file) => pkg.parseJson(readFileSync(requireHere.resolve(`${NAME}/vectors/${file}`), 'utf8'));
const jcs = readVectors('jcs-vectors.json');
for (const v of jcs.vectors) {
  if (pkg.canonicalize(v.value) !== v.expected_canonical) fail(`vector ${v.name} does not reproduce`);
}
for (const v of jcs.text_vectors) {
  let got;
  try {
    got = pkg.canonicalize(pkg.parseJson(v.json_text));
  } catch {
    got = null;
  }
  if (got !== v.expected_canonical) fail(`text vector ${v.name} does not reproduce`);
}
const { createHash, createHmac, randomBytes } = requireHere('node:crypto');
for (const v of jcs.size_vectors) {
  let digest;
  try {
    const canonical = pkg.canonicalize(pkg.parseJson(v.prefix + v.unit.repeat(v.count) + v.suffix));
    digest = createHash('sha256').update(canonical, 'utf8').digest('hex');
  } catch {
    digest = null;
  }
  if (digest !== v.expected_sha256) fail(`size vector ${v.name} does not reproduce`);
}
if (requireHere(`${NAME}/package.json`).name !== NAME) fail('package.json is not resolvable');

// Every seal vector: the installed canonicalize, hashed and keyed, gives the committed derived fields.
const audit = readVectors('audit-seal-vectors.json');
const sealKey = Buffer.from(audit.key_hex, 'hex');
for (const v of audit.vectors) {
  const canonical = pkg.canonicalize(v.core);
  if (createHash('sha256').update(canonical, 'utf8').digest('hex') !== v.entry_hash) fail(`seal vector ${v.name}: entry_hash`);
  if (createHmac('sha256', sealKey).update(canonical, 'utf8').digest('hex') !== v.entry_hmac) fail(`seal vector ${v.name}: entry_hmac`);
}

// Every verify, JSONL and size vector, plus every case the spec derives from them (the `derivations` in
// audit-seal-vectors.json, implemented a third time here), through the INSTALLED build: a shipped
// verifier that accepted a keyless forgery fails here, not only the source tests.
const d = audit.derivations;
const LF = 10;
const keyringOf = (map) => {
  const keys = new Map(Object.entries(map).map(([id, hex]) => [id, Buffer.from(hex, 'hex')]));
  return { getKey: (id) => keys.get(id) ?? null, activeKeyId: () => '' };
};
const anchorOf = (a) => a && { count: a.count, lastHash: a.last_hash };
const bytesOf = (hex) => Buffer.from(hex, 'hex');
const withLf = (line) => Buffer.concat([line, Buffer.from([LF])]);
function linesOf(data) {
  const lines = [];
  let start = 0;
  for (let end = data.indexOf(LF, start); end !== -1; end = data.indexOf(LF, start)) {
    lines.push(data.subarray(start, end));
    start = end + 1;
  }
  return { lines, rest: data.subarray(start) };
}
// Each rule maps a case (and whether its verdict comes from a failing entry) to [suffix, derived case] pairs.
const RULES = [
  ['forged_first', (c) => {
    if (c.expect.ok || c.expect.last_seq < 0) return [];
    const expect = { ok: false, last_seq: -1 };
    if (c.data === undefined) return [['forged-first', { ...c, chain: [d.later_entry, ...c.chain.slice(1)], expect }]];
    const { lines, rest } = linesOf(c.data);
    return [['forged-first', { ...c, data: Buffer.concat([bytesOf(d.later_lines_hex[0]), ...lines.slice(1).map(withLf), rest]), expect }]];
  }],
  ['later_failure', (c, entryFailure) => {
    if (!entryFailure) return [];
    if (c.data !== undefined) return d.later_lines_hex.map((hex, i) => [`later-line-${i}`, { ...c, data: Buffer.concat([c.data, bytesOf(hex)]) }]);
    return Array.isArray(c.chain) ? [['later-entry', { ...c, chain: [...c.chain, d.later_entry] }]] : [];
  }],
  ['ignored_anchor', (c, entryFailure) =>
    entryFailure && c.anchor === undefined ? d.ignored_anchors.map((anchor, i) => [`ignored-anchor-${i}`, { ...c, anchor }]) : []],
  ['tail_failure', (c) => {
    if (!c.expect.ok) return [];
    const n = c.expect.last_seq + 1;
    const expect = { ok: false, last_seq: n - 1 };
    let head;
    let tails;
    if (c.data !== undefined) {
      const { lines } = linesOf(c.data);
      head = n === 0 ? d.genesis_hash : pkg.parseJson(lines[n - 1].toString('utf8')).entry_hash;
      const more = [
        ...d.later_lines_hex.map((hex, i) => [`later-line-${i}`, bytesOf(hex)]),
        ...d.inserted_lines_hex.map((hex, i) => [`inserted-line-${i}`, bytesOf(hex)]),
      ];
      if (n >= 1) more.push(['last-line-again', withLf(lines[n - 1])], ['line-0-again', withLf(lines[0])], ['whole-file-again', c.data]);
      tails = more.map(([label, extra]) => [label, { ...c, data: Buffer.concat([c.data, extra]), expect }]);
    } else {
      head = n === 0 ? d.genesis_hash : c.chain[n - 1].entry_hash;
      const more = [['later-entry', [d.later_entry]]];
      if (n >= 1) more.push(['last-entry-again', [c.chain[n - 1]]], ['entry-0-again', [c.chain[0]]], ['whole-chain-again', c.chain]);
      tails = more.map(([label, extra]) => [label, { ...c, chain: [...c.chain, ...extra], expect }]);
    }
    return tails.flatMap(([label, t]) => [
      [`tail-${label}`, t],
      ...(c.anchor === undefined ? [[`tail-${label}-true-anchor`, { ...t, anchor: { count: n, last_hash: head } }]] : []),
    ]);
  }],
  ['head_replay', (c) => {
    if (!c.expect.ok || c.expect.last_seq < 0) return [];
    const expect = { ok: false, last_seq: 0 };
    if (c.data === undefined) return [['head-replay', { ...c, chain: [c.chain[0], ...c.chain], expect }]];
    const line0 = c.data.subarray(0, c.data.indexOf(LF) + 1);
    const inserted = [['head-replay', line0], ...d.inserted_lines_hex.map((hex, i) => [`head-inserted-line-${i}`, bytesOf(hex)])];
    return inserted.map(([suffix, extra]) => [suffix, { ...c, data: Buffer.concat([line0, extra, c.data.subarray(line0.length)]), expect }]);
  }],
];
/** The base case, then every case derived from it: each rule at most once on a path, to max_depth rules. */
function* casesOf(base) {
  yield base;
  let frontier = [{ c: base, applied: [], entryFailure: !base.expect.ok && base.anchor === undefined }];
  for (let depth = 0; depth < d.max_depth; depth += 1) {
    const next = [];
    for (const node of frontier) {
      for (const [ruleName, rule] of RULES) {
        if (node.applied.includes(ruleName)) continue;
        for (const [suffix, c] of rule(node.c, node.entryFailure)) {
          const derived = { ...c, name: `${node.c.name}/${suffix}` };
          yield derived;
          next.push({ c: derived, applied: [...node.applied, ruleName], entryFailure: true });
        }
      }
    }
    frontier = next;
  }
}
const baseCases = [
  ...audit.verify_vectors,
  ...audit.jsonl_vectors.map(({ data_hex, ...v }) => ({ ...v, data: bytesOf(data_hex) })),
  // A size vector is two cases: the generated file (expect), and its parsed lines as a chain (value_expect).
  ...audit.jsonl_size_vectors.flatMap((v) => {
    const text = v.prefix + v.unit.repeat(v.count) + v.suffix;
    const chain = text.split(String.fromCharCode(LF)).slice(0, -1).map((line) => pkg.parseJson(line));
    return [
      { name: v.name, data: Buffer.from(text, 'utf8'), expect: v.expect },
      { name: `${v.name} (value level)`, chain, expect: v.value_expect },
    ];
  }),
];
const defaultRing = { [audit.key_id]: audit.key_hex };
let auditCases = 0;
for (const base of baseCases) {
  for (const c of casesOf(base)) {
    const keys = keyringOf(c.keyring ?? defaultRing);
    const anchor = anchorOf(c.anchor);
    const result = c.data !== undefined ? pkg.verifyJsonl(c.data, keys, anchor) : pkg.verifyChain(c.chain, keys, anchor);
    if (result.ok !== c.expect.ok || result.lastSeq !== c.expect.last_seq) fail(`audit case ${c.name}: got (${result.ok}, ${result.lastSeq})`);
    auditCases += 1;
  }
}
if (auditCases !== audit.case_count) fail(`derived ${auditCases} audit cases, the vector file says ${audit.case_count}`);

// The installed writer: write, restart from a checkpoint, verify under the anchor; a tampered file breaks
// and the writer refuses to continue it.
const dir = mkdtempSync(join(tmpdir(), 'audit-chain-smoke-'));
try {
  const path = join(dir, 'audit.jsonl');
  const keys = new pkg.InMemoryKeyProvider({ k1: randomBytes(32) }, 'k1');
  const draft = (i) => ({ event: 'user.login', user: `u${i}`, ts_unix_ms: i });
  const first = new pkg.JsonlChainWriter(path, keys);
  first.append(draft(0));
  first.append(draft(1));
  const restarted = new pkg.JsonlChainWriter(path, keys, { count: 2, lastHash: first.head.entry_hash });
  restarted.append(draft(2));
  const written = readFileSync(path);
  const verdict = pkg.verifyJsonl(written, keys, { count: 3, lastHash: restarted.head.entry_hash });
  if (!verdict.ok || verdict.lastSeq !== 2) fail(`writer round trip: got (${verdict.ok}, ${verdict.lastSeq})`);
  const read = pkg.readChain(path, keys);
  if (read.length !== 3 || read[1].user !== 'u1') fail('readChain did not return the verified entries');
  const tampered = Buffer.from(written);
  tampered[tampered.indexOf('"u1"') + 2] = 'x'.charCodeAt(0);
  writeFileSync(path, tampered);
  const broken = pkg.verifyJsonl(tampered, keys);
  if (broken.ok || broken.lastSeq !== 0) fail(`tampered writer file: got (${broken.ok}, ${broken.lastSeq})`);
  let refusal = '';
  try {
    void new pkg.JsonlChainWriter(path, keys);
  } catch (err) {
    refusal = String(err?.message);
  }
  if (!refusal.startsWith('refusing to append')) fail(`the writer did not refuse a tampered chain (${refusal})`);
  let unread = '';
  try {
    pkg.readChain(path, keys);
  } catch (err) {
    unread = String(err?.message);
  }
  if (!unread.startsWith('chain does not verify')) fail(`readChain returned a tampered chain (${unread})`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}

// ESM: a bare-specifier import resolved from the consumer directory, through the "exports" map.
const esm = spawnSync(
  process.execPath,
  [
    '--input-type=module',
    '-e',
    `import { readFileSync } from 'node:fs';
     import { fileURLToPath } from 'node:url';
     import { verifyJsonl, canonicalize, parseJson } from '${NAME}';
     const url = import.meta.resolve('${NAME}/vectors/audit-seal-vectors.json');
     const v = parseJson(readFileSync(fileURLToPath(url), 'utf8'));
     if (typeof verifyJsonl !== 'function' || typeof canonicalize !== 'function' || !v.verify_vectors.length) process.exit(1);`,
  ],
  { cwd: process.cwd(), encoding: 'utf8' },
);
if (esm.status !== 0) fail(`ESM import failed:\n${esm.stderr}`);

process.stdout.write(
  `consumer smoke test passed: ${EXPORTS.length} exports, ${jcs.vectors.length + jcs.text_vectors.length + jcs.size_vectors.length} canonicalization vectors, ${audit.vectors.length} seal vectors, ${auditCases} audit cases, writer round trip, CJS + ESM\n`,
);
