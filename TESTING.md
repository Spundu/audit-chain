# audit-chain: testing

How two implementations are held to one spec, how to run each suite, and how the code was reviewed.

## Running the tests

```sh
npm ci                                          # install, and build dist/ (the prepare script)
npm run typecheck && npm run lint && npm test   # TypeScript: unit and vector tests
pip install -e ".[test,lint]"                   # this repository's Python package, editable
pytest && ruff check python examples            # Python: unit and vector tests, lint
npm run test:parity                             # both languages together, and the README examples
npm run vectors                                 # regenerate vectors/ from scripts/
```

The package needs Node 22.12 or later, and developing it needs 22.13 or later (for ESLint 10).
Python needs 3.12 or later. TypeScript consumers need `@types/node`: the public signatures use Node's
`Buffer`. CI runs the TypeScript suite on Node 22, 24 and 26, the Python suite on Python 3.12, 3.13 and
3.14, and the parity suite on every pairing of the two.

`AUDIT_CHAIN_PYTHON` picks the interpreter for the parity suite (default `python`). It must import
this repository's `audit_chain`, as the editable install above does: the worker reports where it
imported the package from, and the suite refuses to compare against any other copy. `dist/` is the
TypeScript build; build Python distributions with `python -m build --outdir dist-python` so the two
never mix. `AUDIT_CHAIN_BIG_TESTS=1 npm test` also runs a test that allocates a buffer over 2 GiB; an
always-on test checks the same property (no `Buffer.prototype.indexOf`) cheaply.

## What each suite proves

- **The vectors.** [`vectors/`](vectors/) is the normative spec ([SPEC.md](SPEC.md#the-vector-files)):
  canonical forms, seals, and the exact verdict for 723 chains and 907 canonical-JSONL files, which
  five ordering rules expand into 35,473 verification cases. Both suites assert every vector and every
  derived case. The generators refuse to write a vector the TypeScript implementation disagrees with,
  and CI regenerates both files and fails on any diff.
- **The parity suite** (`npm run test:parity`) feeds **raw inputs** to both languages. Each side
  parses them with its own parser, canonicalizes, seals and verifies, so parse-level disagreements are
  in scope, not just canonicalizer bugs. It covers:
  - every vector, plus a curated list of number, string, key and nesting edge cases;
  - ~1,500 seeded random documents drawn from escape-, sort- and encoding-sensitive code points and
    integer-like keys;
  - each of those texts sealed again, as the payload of a genesis entry, by each language's sealing
    primitive: the `entry_hash` and `entry_hmac` must match;
  - each text that is a JSON object appended as a record, after a real previous entry, by each
    language's writer (`appendEntry` / `append_entry`): the entries must be identical, `null`
    members included;
  - ~25 random chains × {reorder, delete, duplicate, truncate, drop genesis, tamper, re-hash without the
    key, re-seal with the wrong key, splice another chain, unknown key id}, with and without an anchor;
  - textual rewrites of valid chains: `1` → `1.0` / `1e0` / `"1"`, pretty-printing, key reordering,
    duplicate-key injection before and after the real key, and uppercased hashes;
  - ~30 byte-level variants per chain as canonical JSONL files: CRLF, BOM, blank lines, whitespace,
    a raw carriage return, overwritten duplicates holding `NaN`, `-Infinity`, 5,000-digit integers or
    3,000-deep arrays, invalid, overlong and CESU-8 UTF-8, NUL bytes, torn tails, duplicated and
    swapped lines, with and without an anchor.

  A case passes when both sides produce identical bytes and seals, or both refuse, and when both
  verifiers return the same `(ok, lastSeq)` without throwing. A crash never counts as a refusal.
- **The README examples.** The parity suite also runs [`examples/quickstart.mjs`](examples/quickstart.mjs)
  and [`examples/quickstart.py`](examples/quickstart.py) and requires the README to show exactly what
  they print; the unit suite requires it to show exactly their source.
- **The published artifacts.** CI packs the npm tarball, installs it into an empty project, and runs
  every vector, every derived case and a writer round trip through the installed build with
  `require()`, plus an ES-module import check. It also builds the Python wheel, checks that it ships
  the typed library and nothing else (no tests, no parity worker), installs it into a clean virtual
  environment and runs the Python quick start there.

Most of the 4,000-odd test cases are generated from the shared vectors; the hand-written tests are the
unit tests in `test/` and `python/tests/`.

## How this was verified

The code was written with Claude Code, and reviewed by AI agents, not by a human. In the source
project it went through repeated rounds of adversarial review before it was extracted. After
extraction, in October 2026, four independent review agents (Claude) each reviewed it cold, given
only the repository and one lens:

- **Correctness and cryptography:** 48,000 random JSON texts through both canonicalizers and 20,000
  mutated chain files through both verifiers, plus value-level probes. No tampered or forged chain
  verified, and the languages never disagreed outside the two value-level parser differences that
  [THREAT-MODEL.md](THREAT-MODEL.md) documents.
- **An attacker without the key:** 30,000 random byte-level mutations of a real chain file, nesting
  up to a million levels deep, hostile 1 MiB lines, and every non-surrogate BMP code point as keys and
  values. Nothing verified except a cut at a line boundary, which is the documented truncation that an
  anchor catches; there was no crash, hang or disagreement.
- **Test quality:** 85 realistic bugs planted one at a time in both languages. The suites caught 82.
  Two of the other three cannot change any output. The third, a Python sealer that serialized with
  `json.dumps(sort_keys=True)`, is now caught by six tests and by the parity suite.
- **A first-time reader:** found that the TypeScript writer accepted only the source project's record
  shape, that the README examples did not run, and that the in-memory key provider shared the caller's
  key buffer. All three are fixed, with tests; the commit history shows each fix.

**A second round** reviewed the fixes the same way: one agent for correctness, and one checking every
claim in the docs as a hiring manager would. It found that Node's `appendFileSync` silently skips its
`flush` option for UTF-8 strings (the writer now writes and fsyncs explicitly, and a test counts the
real fsync calls), that a malformed previous entry could be extended into a chain that never
verifies, that a record holding a Proxy could make the writer repeat a `seq`, that a `Map` or an
`Error` passed as a record was sealed as an empty one, that copied keys sat in Node's shared Buffer
pool, and that Python's writer dropped `null` members while TypeScript's kept them. Each is fixed, with
tests that fail on the code before the fix, and the parity suite now compares the two writers
directly.

The verification and canonicalization logic those reviews attacked has not changed since (one helper
moved into its own module).
