# audit-chain: threat model and limitations

What the chain protects against, what it does not, and the rules for keys that follow from that.
The [README](README.md) has the summary and [SPEC.md](SPEC.md) the exact verification rules.

## What it gives you

Against anyone who does **not** hold the HMAC key: any change to the bytes of an entry, any
reordering, any deletion from the head or the middle, any duplicated or spliced-in entry, anything
appended after the last entry, and any forged entry make `verifyJsonl` fail at that entry. Cutting
entries off the **end** of the file (down to an empty file), or rolling it back to an older copy, is
different: what is left is still a valid chain, so it is detected only against an anchor (see *Tail
truncation* below). `verifyChain`, on values you've already parsed, gives the same guarantee for the
**values**. Other spellings of the
same value (whitespace, `1.0`, a duplicate key that gets overwritten) are invisible at that level,
which is why the file format is canonical and verified byte for byte.

## What it does not give you

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
  deployer's problem. `InMemoryKeyProvider` holds keys that are already in memory (test keys, or keys
  loaded at startup) and keeps its own copies; to fetch keys from a KMS, implement `KeyProvider`. Keys
  shorter than 16 bytes are refused (for sealing) or treated as unknown (for
  verifying). Use random bytes, 32 of them: the minimum is counted in bytes, so a 16-character
  password passes it with far less than 128 bits of secret. The key must never be readable by the
  producers whose actions are being logged.
- **Garbage in, sealed garbage out.** The writer seals whatever it's given. A compromised writer
  produces a valid chain of lies. The chain proves the log wasn't changed afterwards, not that it
  was true.
- **Single writer.** `JsonlChainWriter` assumes one writer per file and takes no lock: keeping to
  one (one process, or an OS-level lock) is up to you. Two concurrent writers fork the chain, which
  verification then (correctly) reports as broken. After a failed write (disk full, for instance),
  which may leave a partial line, the writer refuses further appends. Restart it: a new writer
  re-verifies the file and refuses a torn tail rather than fusing the next entry onto it. Each
  `append` is flushed to disk (fsync) before it returns, together with the directory of a file it
  creates (where the platform allows it), so a head recorded after it survives a power cut. The Python
  side has no writer class; the README's Python example verifies before it
  appends, and fsyncs each line.
- **Value-level verification of text depends on the parser.** The byte-exact guarantee belongs to
  canonical JSONL. If you parse text yourself and call `verifyChain` / `verify_chain`, the verdict is
  about the *value* your parser produced. Parsers differ at the edges, in both directions. `parseJson`
  refuses nesting deeper than 1000 and a 5,000-digit integer parses to `Infinity`, while `json.loads`
  nests to a platform- and version-dependent C-stack limit (on CPython 3.12 about 3,000 levels on Windows
  and about 10,000 on Linux/macOS; far more on 3.14; not tied to `sys.getrecursionlimit`), refuses
  integer literals of more than 4,300 digits, and accepts `NaN`. (A long number with a fraction
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
  2 GiB: the TypeScript writer refuses to start on a larger file (it fails closed). Rotate chain files
  well before that size, for example by starting a
  new chain and anchoring the old one's head.
- **Denial of service is not in scope.** Anyone who can write to the file can break the chain, by
  appending a bad line for instance. The writer then refuses to continue, and that is by design: it
  won't paper over a broken log. Detection is the guarantee. Keeping the log available is up to
  file permissions.

## Keys and key providers

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
