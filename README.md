# audit-chain

A tamper-evident audit log, implemented in **TypeScript** and in **Python**. Each entry is sealed
with SHA-256 and an HMAC and linked to the entry before it, so changing, reordering, deleting or
forging an entry makes verification fail at that entry. The two implementations are
**byte-identical**: either one can write a chain and the other can verify it, which shared test
vectors and a cross-language parity suite prove.

**Status:** 0.1.0. Not yet published to npm or PyPI: install it from GitHub (below). No runtime
dependencies in either language. It was extracted from a private project in which a Node service and
a Python service each keep a chain, and each must be able to check the other's.

## Why the hard part is the bytes

A hash is computed over bytes, and JSON gives two languages many ways to turn the same value into
different bytes: key order, `-0`, `1.0` versus `1`, integers above 2^53, lone surrogates,
`__proto__`, integer-like keys, nesting depth. Here each of those is a spec question with a committed
answer in [`vectors/`](vectors/), which both implementations must reproduce byte for byte.

## Install

```sh
npm install github:Spundu/audit-chain                    # Node >= 22.12; import from 'sealed-audit-chain'
pip install "git+https://github.com/Spundu/audit-chain"  # Python >= 3.12; import audit_chain
```

## Quick start

TypeScript or JavaScript ([`examples/quickstart.mjs`](examples/quickstart.mjs)):

```js
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { InMemoryKeyProvider, JsonlChainWriter, readChain, verifyJsonl } from 'sealed-audit-chain';

// A random 32-byte HMAC key. In production, load it from your secret manager.
const keys = new InMemoryKeyProvider({ k1: randomBytes(32) }, 'k1');
const file = join(mkdtempSync(join(tmpdir(), 'audit-')), 'audit.jsonl');

// Append records of any JSON shape. Keep the head somewhere the log's writers cannot rewrite.
const writer = new JsonlChainWriter(file, keys);
writer.append({ event: 'user.login', user: 'alice' });
const last = writer.append({ event: 'payment.refund', user: 'alice', amount_pence: 1900 });
const head = { count: last.seq + 1, lastHash: last.entry_hash };

// Later, an auditor: every entry verifies, and the file ends exactly at the stored head.
console.log(verifyJsonl(readFileSync(file), keys, head));
console.log(readChain(file, keys, head).map((entry) => entry.event));

// Change one name in the history: verification now fails at that entry.
writeFileSync(file, readFileSync(file, 'utf8').replace('alice', 'mallory'));
console.log(verifyJsonl(readFileSync(file), keys, head));
```

It prints:

```
{ ok: true, lastSeq: 1, brokenAt: null, reason: null }
[ 'user.login', 'payment.refund' ]
{
  ok: false,
  lastSeq: -1,
  brokenAt: 0,
  reason: 'entry_hash mismatch (content tampered)'
}
```

Python ([`examples/quickstart.py`](examples/quickstart.py)):

```py
import os
import secrets
import tempfile
from pathlib import Path

from audit_chain import ChainAnchor, append_entry, parse_jsonl, to_jsonl_line, verify_jsonl

key = secrets.token_bytes(32)  # a random HMAC key; in production, load it from your secret manager
keyring = {"k1": key}
path = Path(tempfile.mkdtemp()) / "audit.jsonl"


def append(record: dict) -> dict:
    data = path.read_bytes() if path.exists() else b""
    result = verify_jsonl(data, keyring)  # never seal onto a chain that does not verify
    if not result.ok:
        raise RuntimeError(f"refusing to append: {result.error}")
    entries = parse_jsonl(data).entries
    entry = append_entry(entries[-1] if entries else None, record, key, writer_key_id="k1")
    with path.open("ab") as f:  # bytes: a text-mode writer could change the line endings
        f.write(to_jsonl_line(entry))
        f.flush()
        os.fsync(f.fileno())  # on disk before the head is stored anywhere
    return entry


append({"event": "user.login", "user": "alice"})
last = append({"event": "payment.refund", "user": "alice", "amount_pence": 1900})
head = ChainAnchor(last["seq"] + 1, last["entry_hash"])

# Later, an auditor: every entry verifies, and the file ends exactly at the stored head.
print(verify_jsonl(path.read_bytes(), keyring, head))

# Change one name in the history: verification now fails at that entry.
path.write_bytes(path.read_bytes().replace(b"alice", b"mallory", 1))
print(verify_jsonl(path.read_bytes(), keyring, head))
```

It prints:

```
VerifyResult(ok=True, last_seq=1, error=None)
VerifyResult(ok=False, last_seq=-1, error='entry_hash mismatch at index 0')
```

CI runs both examples and fails if they stop printing exactly this.

## How it works

An entry is any JSON object: there is no record schema, so check your records' shape before you
append if they have one. The chain relies on three fields, which the writer sets:

| field | meaning |
|---|---|
| `seq` | the entry's position in the chain, from 0 |
| `prev_hash` | the previous entry's `entry_hash` (64 zeros for entry 0) |
| `writer_key_id` | which HMAC key sealed the entry (keys can rotate; old entries stay verifiable) |

Sealing adds two more:

```
bytes      = UTF-8( canonical(the entry without entry_hash and entry_hmac) )
entry_hash = lowercase_hex( SHA-256(bytes) )
entry_hmac = lowercase_hex( HMAC-SHA-256(key[writer_key_id], bytes) )
```

`canonical` is RFC 8785 (JCS), restricted to a strict domain: integers only (no floats), well-formed
Unicode, at most 100 levels of nesting and 1 MiB. On disk a chain is **canonical JSONL**: one entry
per line, each line exactly `canonical(entry)`, and verification compares the bytes, so another
spelling of the same value (extra whitespace, `1.0`, a duplicate key) is refused too. Verification
walks the entries in order and stops at the first one that fails. It never throws on file content: a
malformed chain is a failed result, not an exception. The full rules are in [SPEC.md](SPEC.md).

## What it protects against, and what it doesn't

Against anyone **without** the HMAC key, `verifyJsonl` fails at the first changed, reordered,
inserted, duplicated or forged entry, and at a deletion from the head or the middle. On its own it
does **not** catch:

- **entries cut off the end, or a file rolled back to an older copy.** Store the head
  (`count`, `lastHash`) somewhere the log's writers cannot rewrite, and pass it as the `anchor`: then
  those fail too;
- **anyone who holds the key.** HMAC is symmetric, so a key holder can rewrite and re-seal everything.
  For proof of who wrote what, sign the head with an asymmetric key;
- **lies written at the time.** The chain proves the log was not changed afterwards, not that it was
  true.

Key rotation, keeping two chains apart, and the limits of value-level verification are in
[THREAT-MODEL.md](THREAT-MODEL.md).

## One spec, two implementations

- **[`vectors/`](vectors/) is the spec.** It pins canonical forms, seals, and the exact verdict for
  723 chains and 907 canonical-JSONL files, which five ordering rules expand into 35,473 verification
  cases. Both test suites assert every one, the generators refuse to write a vector the TypeScript
  implementation disagrees with, and CI regenerates the files and fails on any difference.
- **The parity suite** gives the same raw JSON texts and files to both languages, each parsing them
  with its own parser, and requires identical canonical bytes, identical seals and identical
  verdicts, over more than 2,000 texts and hundreds of attacked chains and files.
- **CI** runs it all on Node 22, 24 and 26 and Python 3.12, 3.13 and 3.14, and checks the packed npm
  tarball and the Python wheel as a user would install them. Details in [TESTING.md](TESTING.md).

## API

| | TypeScript (`sealed-audit-chain`) | Python (`audit_chain`) |
|---|---|---|
| append to a file | `new JsonlChainWriter(path, keys, checkpoint?)`, then `.append(record)` | verify, then `append_entry(prev, record, key, writer_key_id=...)` and `to_jsonl_line(entry)` (see the quick start) |
| read a verified file | `readChain(path, keys, anchor?)` | `verify_jsonl(data, keyring, anchor)`, then `parse_jsonl(data).entries` |
| verify a file's bytes | `verifyJsonl(bytes, keys, anchor?)` → `{ ok, lastSeq, brokenAt, reason }` | `verify_jsonl(data, keyring, anchor=None)` → `VerifyResult(ok, last_seq, error)` |
| verify parsed entries | `verifyChain(entries, keys, anchor?)` | `verify_chain(entries, keyring, anchor=None)` |
| verify any other source | `verifyEntries(next, keys, anchor?)` | `verify_entries(steps, keyring, anchor=None)` |
| seal one entry | `appendEntry(prev, record, keys)`, `sealEntry(core, key)` | `append_entry(...)`, `seal_core(core, key)` |
| keys | a `KeyProvider`: `getKey(id)` and `activeKeyId()` | a mapping `{key_id: bytes}` |
| anchor | `{ count, lastHash }` | `ChainAnchor(count, last_hash)` |
| canonical JSON | `canonicalize(value)`, and `parseJson(text)` to parse | `canonicalize(value)` |

On failure `lastSeq` / `last_seq` is the last entry the verifier vouches for (`-1` for none). Keys are
random bytes, at least 16 of them and preferably 32. A key provider must return `null` (`None`) for an
unknown key id and never throw: the id comes from the file, so anyone who can write the file chooses
it. `InMemoryKeyProvider` is for tests.

## Notes

- **The TypeScript side never uses `JSON.parse` on untrusted text.** V8 12.9 and later (Node 23 to 26
  at least; reproduced here on Node 24.14) sometimes returns a wrong key for an escaped one-character key,
  depending on what the process parsed before: after `{"a":1,"\\":2}`, the text `{"a":1,"\n":2}` can
  come back with a backslash as its second key.
  [`scripts/v8-json-parse-repro.mjs`](scripts/v8-json-parse-repro.mjs) reproduces it; we found no
  upstream report of it as of October 2026. The library parses with its own strict parser,
  `parseJson`, and the parity suite checks it against Python's.
- **One writer per file.** `JsonlChainWriter` takes no lock, so run one writer per chain. Each
  `append` is flushed to disk (fsync) before it returns. A restarted writer verifies the file before
  it appends anything.

## Development

```sh
npm ci && npm run typecheck && npm run lint && npm test        # TypeScript
pip install -e ".[test,lint]" && pytest && ruff check python examples   # Python
npm run test:parity    # both languages together, and the README examples (after the pip install)
npm run vectors        # regenerate vectors/ from scripts/
```

[CLAUDE.md](CLAUDE.md) has the rules for changing the code, and [TESTING.md](TESTING.md) explains the
suites.

## How this was built

Written with Claude Code (every commit says so), and reviewed by AI agents, not by a human. After
extraction, four independent review agents attacked it cold: about 100,000 mutated JSON texts, chains
and files produced no accepted forgery and no disagreement between the two languages, and of 85
realistic bugs planted in the code, the tests caught 82, two of the others cannot change any output,
and the third is caught now. What they did find is fixed, with tests. The details are in
[TESTING.md](TESTING.md#how-this-was-verified).

## Layout

```
src/            TypeScript: canonicalize, json (strict parser), jsonl, seal, verify, keys, writer,
                hex and stack (internal helpers), index (the package entry)
test/           vitest: unit and vector tests; test/parity/ is the cross-language suite
python/         Python: audit_chain (canonical, jsonl, seal, verify), the pytest tests and the parity worker
examples/       the two quick starts above, run in CI
vectors/        the normative spec (generated; do not hand-edit)
scripts/        the vector generators (npm run vectors), consumer-smoke.mjs (CI installs the packed
                tarball and runs every vector through it) and v8-json-parse-repro.mjs
```

## License

[MIT](LICENSE)
