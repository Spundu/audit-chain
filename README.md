# audit-chain

A tamper-evident, HMAC-sealed, hash-chained audit log, implemented twice, in **TypeScript** and in
**Python**, and proven **byte-identical** by shared test vectors plus a cross-language parity suite.

Either implementation can write a chain and the other can verify it. That only works if both turn the
same JSON into exactly the same bytes, and JSON gives you plenty of ways to get that wrong: key order,
`-0`, `1.0` vs `1`, integers above 2^53, lone surrogates, `__proto__`, integer-like keys, and nesting
depth. This repository treats each of those as a spec question with a committed answer.

Extracted from a larger private project, in which two independent writers (a Node service and a Python
service) each keep their own chain, and each side must be able to check the other's.

Package names: **`sealed-audit-chain`** on npm and PyPI (the registries treat `audit-chain` as too
close to an existing `auditchain`); the Python import package is `audit_chain`.

## The chain construction

An **entry** is a JSON object. Its **core** is the entry without the two derived fields `entry_hash` and
`entry_hmac`: EXACTLY those two top-level members, compared as exact strings. Everything else is sealed
content, including a derived name nested deeper and any key that merely resembles one (`ENTRY_HASH`,
`entryHash`, `entry-hash`, `entry_hash` followed by a NUL, fullwidth or Cyrillic look-alikes). The core is
a VALUE: take it from the parsed entry, never by cutting the derived members out of the line text.
Among the core's fields, the chain itself relies on three, read ONLY as top-level members of the
entry (a member with the same name nested deeper is ordinary sealed content, never the chain field,
and a chain field present only nested is absent: the entry breaks):

| field | meaning |
|---|---|
| `seq` | 0-based position in the chain; entry *i* has `seq = i` |
| `prev_hash` | the previous entry's `entry_hash`; for entry 0, the **genesis hash**: 64 × `"0"` |
| `writer_key_id` | which HMAC key sealed the entry (keys can rotate; old entries stay verifiable, see the threat model) |

Sealing an entry:

```
bytes      = UTF-8( canonical(core) )                        # see "Canonical form" below
entry_hash = lowercase_hex( SHA-256(bytes) )
entry_hmac = lowercase_hex( HMAC-SHA-256(key[writer_key_id], bytes) )
```

Because `prev_hash`, `seq` and `writer_key_id` are inside the core, the hash and the HMAC both cover
the link to the previous entry, the entry's position, and the key choice.

Verifying a chain `entries[0..n)`: `entries` must be an array; then the checks below run **entry by
entry, in index order**. Entry `i` gets all of steps 1 to 8 before entry `i + 1` is looked at, and the
first failure ends verification (both implementations; the order decides which prefix is vouched for):

1. entry `i` is an object;
2. `seq == i` (a JSON number: `1.0` is `1`; a string or boolean is not);
3. `prev_hash ==` the previous entry's `entry_hash` (genesis for `i = 0`);
4. `canonical(core)` exists (the core is inside the canonical domain);
5. `entry_hash` is **present** and is **exactly** `SHA-256(bytes)` as a 64-character lowercase-hex
   string: not absent, null, empty, padded, spaced or suffixed;
6. `writer_key_id` is a string naming a known key of at least 16 bytes;
7. `entry_hmac` is **present** and is **exactly** the recomputed HMAC in the same form, compared in
   constant time;
8. the whole entry's canonical form fits the 1 MiB limit. With both hash fields valid that is
   `canonical(core)` plus 160 bytes: two members `"entry_hash":"<64 hex>"` and `"entry_hmac":"<64 hex>"`
   of 79 bytes each, and their two commas.

Then, optionally, and **only once every entry has verified**, against an external **anchor**
`(count, last_hash)`: `n == count` (a number) and the last entry's `entry_hash == last_hash` (for an
empty chain, the genesis hash). Only `undefined`/`null` (TypeScript) or `None` (Python) mean "no anchor",
never a silently skipped check. In TypeScript any other non-object is a `TypeError`, and an object of
the wrong shape (a missing, `null` or non-numeric `count`, a missing `lastHash`) is a **wrong** anchor:
verification fails. In Python the anchor must be a `ChainAnchor`; anything else is a `TypeError`.

The result is `{ ok, lastSeq }`. On success `lastSeq` is the last entry (`-1` for an empty chain). On
failure it is the entry **before** the one the chain breaks at (`brokenAt - 1` in TypeScript). An
anchor whose count is wrong breaks at `n` (the chain length): every entry present verified, and is vouched for. An anchor whose head hash
is wrong breaks at the last entry, because that is the entry the anchor disputes (for an empty chain,
whose head is the genesis hash, a wrong head breaks at 0: `lastSeq` -1).
Both implementations return the **same** `(ok, lastSeq)` for every input, and neither ever throws on
chain content. That includes non-arrays, `null` entries, non-hex or non-ASCII HMACs, and cores that
can't be canonicalized.

What does throw is never about the content, so it is never turned into a verdict: a failing key
provider, a failing entry source, running out of memory, and **running out of stack**. Verification
started too deep in the caller's own stack propagates the host's error (`RangeError` in JavaScript,
`RecursionError` in Python) instead of reporting a valid chain as broken; every depth the data itself
can reach is bounded far below the stack. V8 has a second shape for this error: a regular expression
compiled with the stack nearly exhausted throws a `SyntaxError`. So the TypeScript verification path
uses no regular expressions at all, and recognises that shape too. Tests sweep verification across
the whole band of stack depths where it runs out, in both languages, and inject a genuine
stack-overflow error at every place the TypeScript verifier catches an exception. Running out of
memory is the same: `MemoryError` in Python, and in JavaScript V8's catchable allocation failures
(`Array buffer allocation failed`, `Invalid string length`, `Invalid array length`, `Invalid typed
array length`; running out of heap proper aborts the process). The library's own limits keep
everything it builds far below those maxima, so none of them can be caused by the data.

### On disk: canonical JSONL

A chain file holds one entry per line, and **each line is exactly `canonical(entry)`** (the derived
fields included), UTF-8, terminated by a line feed (`0x0A`). **Every** line needs its line feed,
including the last one. An unterminated last line counts as torn and breaks the chain at that entry.
Otherwise anyone could drop the final byte unnoticed, and the next append would fuse two entries
into one line, destroying an entry that had been sealed legitimately. `verifyJsonl(bytes)` / `verify_jsonl(bytes)` decode each line as strict UTF-8, parse it, and
**require the line to equal the canonical form of what it parsed to**, byte for byte: the line is
never trimmed, never cut at a NUL, never Unicode-normalized first. Only then do they run the checks
above. The first line that fails breaks the chain at that entry, but the lines **before** it
are still verified first. A forged early entry is reported at its own index, never hidden behind a
later bad line of any kind: torn, invalid UTF-8, invalid JSON, not canonical, or over the size limit.
And no anchor is applied to a file with a bad line, wherever it is. Both ordering rules are pinned by
vectors: they decide which prefix `lastSeq` vouches for. The order is pinned in BOTH directions. An
earlier failure is never hidden behind a later one: a verifier must not pre-scan the file (for size,
encoding, syntax, depth or anything else) and report a later line first; the `forged_first`
derivation catches exactly that. And a later failure never
pre-empts an earlier one: a verifier must not check every seal (or every line) before walking the
links, apply the anchor early, or defer a canonicity, domain or size check; the `later_failure` and
`ignored_anchor` derivations catch those, for EVERY failing vector (see the vector files below). And
nothing may follow a valid chain: an entry replayed (the last one, the first one, or the whole chain
again), a keyless one, or a line a lenient reader would skip (a `#` or `//` comment, a NUL line, `true`,
`false`, `null`, `{}`) breaks the chain right there, also under the anchor that matches the valid
prefix; the `tail_failure` and `head_replay` derivations catch a verifier that stops reading at the
anchor's count, skips such a line, or accepts a restart at a validly sealed genesis entry.

That rule is what authenticates the **file bytes**, and not just whatever value a JSON parser makes
of them. `JSON.parse` and Python's `json.loads` disagree about texts that never survive into the
parsed value: an overwritten duplicate key holding `NaN` (Python accepts it) or a 5,000-digit
integer (Python refuses it), or nesting deep enough to exceed one parser's recursion limit. And `1.0`,
`\u0041` for `A`, a BOM, a raw carriage return, extra whitespace or reordered keys are all other spellings of the same value. None of those lines is
canonical, so both languages reject them at the same line. Invalid UTF-8 (a stray `0xFF`, overlong
forms, CESU-8 surrogates) is rejected, never replaced with U+FFFD: the line is checked as BYTES. A lax
decoder (no continuation-bit check, overlongs, code points above U+10FFFF or truncated sequences read
as U+FFFD) followed by a text compare would accept changed bytes, and the `lax-utf8-*` vectors catch it.

Use `verifyChain` / `verify_chain` only for entries you already hold as values. They authenticate
the canonical *value*, so it's then your parser's reading of the text that you are trusting.

**The TypeScript side doesn't use `JSON.parse` on untrusted text.** V8 12.9 and later, as shipped in
Node 23, 24, 25 and 26 at least, has a `JSON.parse` bug. Once it has parsed an object whose key is a single backslash, it returns a
backslash for any later one-escape key (`\n`, `\t`, `\"`, `\u0041`, ...) that follows the same
preceding keys. The parser then hands you a *different value* from the one the text encodes, and the
result depends on what the process parsed earlier. Node 20 and 22 are not affected, but the rule is the
same on every version. `verifyJsonl`,
the writer, the vector generators and the vector-driven and parity tests parse untrusted and spec text
with the library's own strict RFC 8259 parser, `parseJson`. If
you call `verifyChain` on text you parsed yourself, parse it with `parseJson` too. The text and
JSONL vectors include poison-then-target cases, processed in order, that fail on an implementation
built on the affected parser. `parseJson(text, maxDepth?)` refuses nesting deeper than `maxDepth`
(default and maximum 1000). `verifyJsonl` passes 100, the canonical limit: no canonical line nests
deeper, so a short, deeply nested hostile line stops the parser early instead of using up the caller's
stack.

## Canonical form

`canonical(value)` is the RFC 8785 (JCS) serialization, **restricted to a strict value domain**:

- `null`, `true`, `false`;
- **numbers** whose value is an integer with |n| ≤ 2^53 − 1, written as plain decimal integers. `-0`
  is `0`. JSON number texts are read as IEEE-754 doubles, so `1.0`, `1e2` and `100e-2` are the
  integers 1, 100 and 1. Non-integers, `NaN`, `±Infinity`, and anything outside the safe range
  (`2^53`, `1e21`, `5e-324`) are **rejected**. A text too small to be a double at all (`1e-400`)
  parses to 0 in both languages and is accepted as `0`. Canonical JSONL rejects that spelling anyway. Store fractional or large amounts as decimal
  **strings**;
- **strings and keys** that are well-formed Unicode. A lone surrogate, raw or `\uD800`-escaped, is
  **rejected**; an escaped surrogate pair is the one astral character it encodes. Strings are
  escaped as `JSON.stringify` does (short forms `\b \t \n \f \r \" \\`, other controls as lowercase
  `\u00xx`, everything else, including non-ASCII, raw);
- **arrays** in order; **objects** with members sorted by the **UTF-16 code units** of their keys (so
  `"10" < "9"`, and U+1F600 sorts before U+E000), with no whitespace anywhere. `__proto__` is an
  ordinary key. Duplicate keys in a JSON text resolve **last-wins**, as `JSON.parse` and Python's
  `json.loads` both do;
- at most **100** levels of nested arrays/objects;
- a canonical form of at most **1 MiB** (1,048,576 UTF-8 bytes). Without a bound, a big enough value
  exceeds V8's maximum string length: TypeScript would fail where Python succeeds, and a chain that
  one language wrote could never be verified by the other. The limits are normative and repeated in
  `vectors/jcs-vectors.json` (`max_canonical_bytes`, `max_depth`).

Anything outside the domain throws `CanonicalizationError` in both languages. (In TypeScript an
`undefined` member counts as absent, as in `JSON.stringify`, and symbol-keyed and non-enumerable
properties are not members; no JSON text can produce any of them.) There is no best-effort
serialization.

**This is a subset of RFC 8785, not all of it.** RFC 8785 serializes arbitrary IEEE-754 doubles, and
this spec refuses them. Floats are exactly where JavaScript, Python and most other languages drift
apart, and an audit record has no need for them. Keys are **not** Unicode-normalized: `"\u00e9"` (NFC,
one code point) and `"e\u0301"` (NFD, `e` plus a combining accent) are different keys and produce
different hashes, identically in both languages.

## Normative spec: the vector files

The files in [`vectors/`](vectors/) are the specification. Both test suites assert them, and an
implementation in a third language is conformant when it passes them:

- [`vectors/jcs-vectors.json`](vectors/jcs-vectors.json)
  - `vectors`: a JSON `value` and the exact `expected_canonical` string, with its SHA-256;
  - `text_vectors`: a raw `json_text` to parse with your own JSON parser, then canonicalize.
    `expected_canonical: null` means the input must be **rejected**. These cover the cases a
    value vector can't express: `-0`, `1.0`, `2^53 + 1`, lone surrogates, `__proto__`, and the
    nesting limit;
  - `size_vectors`: the 1 MiB limit, exactly at it and one byte over. The text is generated as
    `prefix + unit × count + suffix`, so the spec stays small. They include a structure-heavy input and
    one whose UTF-16 length fits while its UTF-8 length does not.
- [`vectors/audit-seal-vectors.json`](vectors/audit-seal-vectors.json)
  - `vectors`: a `core` and the `entry_hash` / `entry_hmac` it seals to under the public test key
    `key_hex`. The default keyring for every verify and JSONL vector is `{key_id: key_hex}`. A
    vector with its own `keyring` uses that instead: unknown key ids, the 15- versus 16-byte key
    minimum, and the **empty** keyring `{}` (no keys at all, so no entry verifies, while an empty chain
    still does: a verifier must not fall back to checking hashes only). Key ids compare exactly (one that
    differs only by Unicode normalization is unknown), rotating back to an earlier key verifies, and an
    unused short key in the keyring changes nothing;
  - `verify_vectors`: whole chains (some with an `anchor`) and the exact `(ok, last_seq)` a verifier
    must return. They include malformed HMACs, entries where *only* `entry_hash` changed (the HMAC
    still matches, so only the hash check catches them), uppercased hashes, non-object entries, wrong
    `seq` types, non-canonical content, a `__proto__` tamper, and truncation with and without an anchor.
    Resealed entries pin that `seq` and `prev_hash` compare exactly. The value domain is pinned at the
    value level too: an entry 101 levels deep, lone-surrogate keys, and an integer replaced by the double
    one ulp away, each carrying the seal an implementation without that rule would compute. Anchors
    missing a field are wrong anchors (an absent field is not `null` and not "skip that check"). Every
    hash field (`entry_hash`, `entry_hmac`, `prev_hash` and the anchor's `last_hash`) is pinned against
    NEAR MISSES that are still lowercase hex: extra digits, one digit changed at the first, a middle or
    the last position, a digit dropped. A decoded-bytes, prefix or partial compare fails these, and the
    last entry's are also checked under the true anchor (a verifier that links or anchors on the hash
    it recomputed, instead of the stored field, fails those). The near misses also RESPELL the true
    value: a digit as its Arabic-Indic, fullwidth or mathematical twin, the field in fullwidth,
    non-ASCII junk added, the leading zeros as `+`, whitespace, `_` or `0x`, and a NUL or an invisible
    format character (soft hyphen, zero-width space, word joiner, BOM) appended or inserted. Parsing
    the hex to a number or bytes, normalizing it (NFKC), converting it lossily to ASCII, comparing it as
    a NUL-terminated C string, or dropping invisible characters before comparing is not conformant:
    the only conformant compare is exact string (byte) equality;
  - `jsonl_vectors`: whole canonical-JSONL **files** (`data_hex`) and the verdict of
    `verifyJsonl` / `verify_jsonl`, including the parser differentials (overwritten duplicates
    holding `NaN` or 5,000-digit numbers, 3,000-deep nesting), CRLF, BOM, bad UTF-8, torn tails,
    trailing blank lines, a dropped head, the ordering rules, non-ASCII content (which must verify),
    UTF-8 tampering inside strings, NFC/NFD twin keys swapped in place, non-object lines, and anchors
    on files. The `respelled-*` files apply every lexical freedom JSON has for the same value, at every
    node of a nested entry: whitespace (space, tab, carriage return) at each structural position of every
    object and array, member order and duplicate members (same or overwritten value) in every object, a
    `\u` escape in every key and string, and other spellings of every number (exponent, fraction,
    `-0`); plus the escapes of each character class (`\/`, long-form and uppercase-hex control
    escapes, escaped non-ASCII and surrogate pairs) and more numbers (`19e2`, `1.9E+3`, `0E-5`). Each line
    parses to exactly the sealed value, so only the byte-exact check catches it: a verifier that
    validates lines lexically (at any depth) instead of comparing them with a full re-serialization
    fails these. Every value-level vector whose entries all have a canonical form also appears as a
    file, named `<vector>-file`. And the CORE DEFINITION is pinned: derived names nested in the core
    (sealed: must verify; added without the key: must break), the root derived members duplicated,
    lines sealed over their own non-canonical core text, and keys that resemble a derived name after
    NUL truncation, NFKC folding, a Unicode look-alike or a case or separator change. A verifier that
    strips derived members from the line text, or recognizes derived names loosely, fails these;
  - **`derivations`**: the ORDERING rules and what may follow a valid chain, as five rules that every
    harness applies to EVERY base case (each verify vector, each JSONL file, and each size vector read
    both as its file and as its parsed lines) and again to the cases they derive: each rule at most
    once on a derivation path, up to `max_depth` (2) rules deep, so each rule is also checked under an
    anchor, after a forged first entry, and so on. The file carries the constants and `case_count`, the
    number of cases (base and derived) a harness must reach. `scripts/audit-vectors/derive.mts`,
    `python/tests/_derivations.py` and `scripts/consumer-smoke.mjs` implement them independently. A
    case "fails at an entry" when it is a failing base case without an anchor, or any derived case:
    - `forged_first`: a case that breaks after entry 0 (at a later entry, a later line or the anchor),
      with entry 0 replaced by `later_entry`, a keyless forgery (for a file, line 0 by its canonical
      line), must break AT entry 0. A verifier that runs any check over all entries or lines before
      walking them in order (a depth, encoding, size, shape or key pre-scan, or the anchor first) fails it;
    - `later_failure`: a case that fails at an entry keeps its verdict with a later failure appended
      (`later_entry` to a chain; each of `later_lines_hex`, a forged line, a junk line and a torn tail,
      to a file). A verifier that checks every seal, line, domain or size rule before walking the links
      reports the later failure and over-reports the vouched-for prefix;
    - `ignored_anchor`: a case that fails at an entry, without an anchor, keeps its verdict under each
      of `ignored_anchors`: the anchor is checked only after every entry verified;
    - `tail_failure`: a valid case of n entries breaks at entry n (`last_seq` n - 1) with any of these
      appended: `later_entry`, the last entry again, entry 0 again, or the whole chain again (for a
      file: each of `later_lines_hex` and of `inserted_lines_hex`, the lines a lenient reader skips, or
      the last line, line 0 or the whole file again). It does so both as given and under the TRUE anchor
      of the valid prefix: a matching anchor never excuses what follows it;
    - `head_replay`: a valid case with entry 0 (line 0) inserted again at index 1, and for a file each
      of `inserted_lines_hex` inserted there, breaks at entry 1 (`last_seq` 0);
  - `jsonl_size_vectors`: a validly sealed line of exactly 1 MiB (it must verify) and one byte more
    (it must not), a forged first line followed by an over-limit line, a valid line that starts past
    byte 1 MiB (the limit is per line), and a validly sealed over-limit entry in the middle and at the
    end of a file, in the generated `prefix + unit × count + suffix` form.
    `value_expect` is the verdict of `verify_chain` on the entries parsed from the file's lines.

The files are generated by `npm run vectors` from `scripts/`. The generators refuse to write a vector
that the TypeScript implementation disagrees with (every canonical form, every verify, JSONL and size
verdict, and every derived case), and CI regenerates both files and fails on any diff.

## The parity suite

`npm run test:parity` feeds **raw inputs** to both languages. Each side parses them with its own
parser, canonicalizes, and verifies. Parse-level disagreements are therefore in scope, not just
canonicalizer bugs. It covers:

- every vector, plus a curated list of number, string, key and nesting edge cases;
- ~1,500 seeded random documents drawn from escape-, sort- and encoding-sensitive code points and
  integer-like keys;
- ~25 random chains × {reorder, delete, duplicate, truncate, drop genesis, tamper, re-hash without the
  key, re-seal with the wrong key, splice another chain, unknown key id}, with and without an anchor;
- textual rewrites of valid chains: `1` → `1.0` / `1e0` / `"1"`, pretty-printing, key reordering,
  duplicate-key injection before and after the real key, and uppercased hashes;
- ~30 byte-level variants per chain as canonical JSONL files: CRLF, BOM, blank lines, whitespace,
  a raw carriage return, overwritten duplicates holding `NaN`, `-Infinity`, 5,000-digit integers or
  3,000-deep arrays, invalid, overlong and CESU-8 UTF-8, NUL bytes, torn tails, duplicated and
  swapped lines, with and without an anchor.

A case passes when both sides produce identical bytes or both refuse, and when both verifiers return
the same `(ok, lastSeq)` without throwing. A crash inside canonicalize never counts as a refusal.

## Install & run

Node ≥ 22.12 to use the package (≥ 22.13 to develop it: ESLint 10 needs it), Python ≥ 3.12.
TypeScript consumers need `@types/node`: the public signatures use Node's `Buffer`.

```sh
npm ci && npm test                        # TypeScript: unit + vector tests
pip install -e ".[test]" && pytest        # Python: unit + vector tests
npm run test:parity                       # both at once (needs the pip install above)
```

The parity suite runs `python/tests/parity_worker.py`; set `AUDIT_CHAIN_PYTHON` to choose the
interpreter (default `python`). `dist/` is the TypeScript build: build Python distributions with
`python -m build --outdir dist-python`, so the two never mix. `AUDIT_CHAIN_BIG_TESTS=1 npm test`
also runs a test that allocates a buffer over 2 GiB.

## Writing and verifying a chain

TypeScript:

```ts
import { readFileSync } from 'node:fs';
import { InMemoryKeyProvider, JsonlChainWriter, verifyJsonl } from 'sealed-audit-chain';

const keys = new InMemoryKeyProvider({ k1: keyBytes }, 'k1'); // >= 16 bytes; tests only
// `published` is the { count, lastHash } you stored OUTSIDE the file at the last append. The writer
// verifies the file first, then refuses it if it no longer holds that entry (truncated or rolled back).
const writer = new JsonlChainWriter('audit.jsonl', keys, published);
const entry = writer.append(draft);
published = { count: entry.seq + 1, lastHash: entry.entry_hash }; // store it outside the file again

// An auditor, later: every entry verifies AND the file ends exactly at the published head.
const result = verifyJsonl(readFileSync('audit.jsonl'), keys, published);
if (!result.ok) console.error(`broken at entry ${result.brokenAt}: ${result.reason}`);
```

Python:

```py
from audit_chain import ChainAnchor, append_entry, parse_jsonl, to_jsonl_line, verify_jsonl

keyring = {"k1": key_bytes}  # >= 16 bytes
with open("audit.jsonl", "rb") as f:  # bytes: never let a text reader rewrite line endings
    data = f.read()

# Verify before appending: never seal a new entry onto a chain that does not verify.
result = verify_jsonl(data, keyring, ChainAnchor(1042, published_head))
if not result.ok:  # not `assert`: python -O strips asserts, and this check must never disappear
    raise RuntimeError(f"refusing to append: {result.error}")

entries = parse_jsonl(data).entries
entry = append_entry(entries[-1] if entries else None, draft, key_bytes, writer_key_id="k1")
with open("audit.jsonl", "ab") as f:
    f.write(to_jsonl_line(entry))
```

The chain seals **any JSON object**: there is no record schema in either language. If your records
have a shape, check it before you append. When it **starts**, `JsonlChainWriter` verifies the
existing file with its own keys (it doesn't re-read the file between appends; see "Single writer"),
and it **refuses to start** on a chain that doesn't verify (a forged or torn last line, a tampered
entry). Otherwise it would seal new entries onto a head that can never verify. `readChain(path,
keys, anchor?)` reads the file once, verifies it, and returns the entries only if it verifies, so
what you act on is exactly what was verified. The Python side is the seal and verify core only:
`append_entry` treats a `None` member as absent, as TypeScript treats an `undefined` one.

`verifyChain` and `verifyJsonl` (`verify_chain` / `verify_jsonl`) are both thin wrappers over one
incremental engine, `verifyEntries` / `verify_entries`, which takes entries one at a time and keeps
only the previous hash. Use it directly to verify a chain from any other source (a database cursor, a
network stream) with the same verdicts:

- TypeScript: `verifyEntries(next, keys, anchor?)`, where `next(i)` returns `{ entry }`, or
  `{ unreadable: reason }` for a record it could not read (the chain breaks there), or `null` at the end;
- Python: `verify_entries(steps, keyring, anchor=None)`, where `steps` yields `("entry", value)` or
  `("unreadable", reason)`.

An unreadable step breaks the chain at that index whatever the reason is (a string, a tuple, bytes,
an exception), and a malformed step is a `TypeError`.

If the source itself fails (`next` throws, the iterator raises), the exception propagates: a timed-out
cursor is an infrastructure error, not evidence of tampering.

Either language verifies a chain the other wrote, and `JsonlChainWriter` continues any chain that
verifies, whichever writer sealed it.
Keys are bytes in both languages, and their minimum length is measured in bytes: in TypeScript a
`Uint8Array` (such as a `Buffer`), in Python `bytes` or `bytearray`. Anything else a provider returns
(a `KeyObject`, an `ArrayBuffer`, a `DataView`, a string) is no key at all: verification reports an
unknown key id and sealing refuses it. The TypeScript `InMemoryKeyProvider` also takes a string, which
it treats as UTF-8, while Python only accepts `bytes`. A failing key provider (a KMS timeout, say)
makes verification **throw**, because an infrastructure error is not evidence of tampering. For the
same reason, a key provider **must return `null`/`None` for an unknown key id, and never throw**.
Passing something that is not a key provider at all (in TypeScript anything without a `getKey` method,
such as a plain object or a `Map`; in Python anything that is not a mapping) is a `TypeError` up front,
whatever the chain holds. The
id comes from chain content, and anyone who can write the file chooses it. A provider that throws
on unknown ids turns a tampered entry into a "KMS error" and exposes the key service to
attacker-chosen lookups.

## Threat model & limitations

What the chain **does** give you, against anyone who does **not** hold the HMAC key: any change to
the bytes of a canonical-JSONL file, any reordering, any deletion in the middle, any duplicated or
spliced-in entry, and any forged entry all make `verifyJsonl` fail at that entry. `verifyChain`, on
values you've already parsed, gives the same guarantee for the **values**. Other spellings of the
same value (whitespace, `1.0`, a duplicate key that gets overwritten) are invisible at that level,
which is why the file format is canonical and verified byte for byte.

What it does **not** give you:

- **No non-repudiation.** HMAC is a symmetric key: whoever can verify can also forge. Anyone holding
  the key can rewrite any entry, or the whole chain, and re-seal it, and the result verifies
  perfectly. This is tamper-*evidence* against parties **without** the key, not proof of who wrote
  what. If you need that, sign the head with an asymmetric key (e.g. Ed25519) or anchor it with a
  third party.
- **Key rotation does not revoke.** To keep old entries verifiable you keep the old keys, and the
  verifier accepts any known key at any position. So a key that leaked before it was retired can
  still forge entries anywhere, including new ones at the end. Rotation limits how many *future*
  entries a key seals, not what someone holding a leaked key can do. To contain a leak, anchor or
  sign the head at the time of rotation, and treat later entries sealed with the retired key as
  forged.
- **Tail truncation is invisible without an anchor.** (Deleting from the *head* is detected: `seq` is
  absolute, and entry 0 must link to the genesis hash.) Deleting the last *k* entries leaves a shorter,
  perfectly valid chain. It is detected only if the head `(count, last_hash)` is anchored somewhere
  the attacker can't also rewrite (another system, a transparency log, a signed checkpoint), and
  the verifier is given that anchor. The same goes for rolling the whole file back to an older copy.
  The writer can't tell either unless you give it a checkpoint `(count, head)` recorded elsewhere. It
  then refuses a file that no longer holds that entry at `count - 1`. A file that has grown since the
  checkpoint is fine. Without a checkpoint, the writer will happily continue a truncated file from
  its new, shorter head.
- **The chain is not bound to an identity.** The verifier doesn't know *which* chain it's looking at.
  Two chains sealed with the same key from genesis are interchangeable prefixes of each other. Use a
  distinct key (`writer_key_id`) per chain **and verify each chain with a keyring that holds only that
  chain's key ids** (its rotation keys included). A shared keyring that knows both chains' keys accepts
  either chain's file in place of the other, and the writer would continue it. Alternatively, check an
  identifying field (a log name you put in every record, say) yourself.
- **Key management is out of scope.** Where the key lives, who can read it, and how it rotates are the
  deployer's problem. `InMemoryKeyProvider` is for tests. Keys shorter than 16 bytes are refused (for
  sealing) or treated as unknown (for verifying). The key must never be readable by the producers
  whose actions are being logged.
- **Garbage in, sealed garbage out.** The writer seals whatever it's given. A compromised writer
  produces a valid chain of lies. The chain proves the log wasn't changed afterwards, not that it
  was true.
- **Single writer.** `JsonlChainWriter` assumes one writer per file. Two concurrent writers fork the
  chain, which verification then (correctly) reports as broken. After a failed write (disk full, for
  instance), which may leave a partial line, the writer refuses further appends. Restart it: a new
  writer re-verifies the file and refuses a torn tail rather than fusing the next entry onto it.
- **Value-level verification of text depends on the parser.** The byte-exact guarantee belongs to
  canonical JSONL. If you parse text yourself and call `verifyChain` / `verify_chain`, the verdict is
  about the *value* your parser produced. Parsers differ at the edges, in both directions. `parseJson`
  refuses nesting deeper than 1000 and a 5,000-digit integer parses to `Infinity`, while `json.loads`
  nests to a platform- and version-dependent C-stack limit (on CPython 3.12 about 3,000 levels on Windows
  and about 10,000 on Linux/macOS; far more on 3.14; not tied to `sys.getrecursionlimit`), refuses integer literals of more than 4,300 digits, and accepts `NaN`. (A long number with a fraction
  or an exponent is a correctly rounded float in both, and becomes infinite only if its magnitude
  overflows: only those integer literals differ.) So a text
  with such a value hidden in an overwritten duplicate key can get different verdicts in the two
  languages. No such text is canonical, so `verifyJsonl` rejects it identically in both.
- **Other parsers, and text that isn't valid Unicode.** Duplicate keys resolve last-wins in
  `JSON.parse` and `json.loads`. A verifier in another language whose parser keeps the first
  duplicate, or rejects duplicates, would disagree on such a text at the value level. Canonical JSONL
  rejects duplicates at the byte level, so `verifyJsonl` is unaffected. Likewise, a JSON *text* that
  is itself ill-formed UTF-16 isn't in scope for the value-level functions. One example is a raw lone
  high surrogate followed by an escaped low surrogate; such text can't come from decoding UTF-8.
  `JSON.parse` merges that key with the astral character it spells, while `json.loads` keeps the two
  apart, and the Python canonicalizer then refuses the collision.
- **The file is one buffer.** Verification streams through it: one line is parsed at a time, nothing
  is kept but the previous hash, and it stops at the first bad line, so junk costs no more than its
  first line, and it works on a buffer of any size in both languages (the TypeScript side never uses
  `Buffer.prototype.indexOf`, which misreports offsets past 2 GiB). But `verifyJsonl` / `verify_jsonl`
  take the whole file as bytes, and the writer reads it with Node's `readFileSync`, which stops at
  2 GiB: the TypeScript writer refuses to start on a larger file (it fails closed). Rotate chain files well before that size, for example by starting a
  new chain and anchoring the old one's head.
- **Denial of service is not in scope.** Anyone who can write to the file can break the chain, by
  appending a bad line for instance. The writer then refuses to continue, and that is by design: it
  won't paper over a broken log. Detection is the guarantee. Keeping the log available is up to
  file permissions.

## Layout

```
src/            TypeScript: canonicalize, json (strict parser), jsonl, seal, verify, keys, writer,
                hex and stack (internal helpers), index (the package entry)
test/           vitest: unit + vector tests; test/parity/ is the cross-language suite
python/         Python: audit_chain (canonical, jsonl, seal, verify) + pytest tests and the parity worker
vectors/        the normative spec (generated; do not hand-edit)
scripts/        vector generators (npm run vectors; emit-*-vectors.mts, the groups in audit-vectors/,
                vector-guard.mts) and consumer-smoke.mjs (CI installs the packed tarball and runs every
                canonicalization, seal, verify, JSONL and size vector, every derived case, and a writer
                round trip, through the installed build)
```

## License

[MIT](LICENSE)
