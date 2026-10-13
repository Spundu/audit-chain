# audit-chain: specification

The full rules for the chain, its canonical form and its file format. The [README](README.md) has the
short version and [THREAT-MODEL.md](THREAT-MODEL.md) what it protects against. The normative source of
truth is [`vectors/`](vectors/): both test suites assert every vector, and an implementation in another
language is conformant when it passes them.

- [The chain construction](#the-chain-construction)
- [On disk: canonical JSONL](#on-disk-canonical-jsonl)
- [Canonical form](#canonical-form)
- [Verifying from any source](#verifying-from-any-source)
- [The vector files](#the-vector-files)

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
| `writer_key_id` | which HMAC key sealed the entry (keys can rotate; old entries stay verifiable, see [THREAT-MODEL.md](THREAT-MODEL.md)) |

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
anchor whose count is wrong breaks at `n` (the chain length): every entry present verified, and is
vouched for. An anchor whose head hash
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

## On disk: canonical JSONL

A chain file holds one entry per line, and **each line is exactly `canonical(entry)`** (the derived
fields included), UTF-8, terminated by a line feed (`0x0A`). **Every** line needs its line feed,
including the last one. An unterminated last line counts as torn and breaks the chain at that entry.
Otherwise anyone could drop the final byte unnoticed, and the next append would fuse two entries
into one line, destroying an entry that had been sealed legitimately. `verifyJsonl(bytes)` /
`verify_jsonl(bytes)` decode each line as strict UTF-8, parse it, and
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
`\u0041` for `A`, a BOM, a raw carriage return, extra whitespace or reordered keys are all other
spellings of the same value. None of those lines is
canonical, so both languages reject them at the same line. Invalid UTF-8 (a stray `0xFF`, overlong
forms, CESU-8 surrogates) is rejected, never replaced with U+FFFD: the line is checked as BYTES. A lax
decoder (no continuation-bit check, overlongs, code points above U+10FFFF or truncated sequences read
as U+FFFD) followed by a text compare would accept changed bytes, and the `lax-utf8-*` vectors catch it.

Use `verifyChain` / `verify_chain` only for entries you already hold as values. They authenticate
the canonical *value*, so it's then your parser's reading of the text that you are trusting.

**The TypeScript side doesn't use `JSON.parse` on untrusted text.** V8 12.9 and later, as shipped in
Node 23, 24, 25 and 26 at least, has a `JSON.parse` bug. Once it has parsed an object whose key is a
single backslash, it returns a
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
  parses to 0 in both languages and is accepted as `0`. Canonical JSONL rejects that spelling anyway.
  Store fractional or large amounts as decimal
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

## Verifying from any source

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

## The vector files

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
