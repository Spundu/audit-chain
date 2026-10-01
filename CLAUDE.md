# audit-chain

Tamper-evident, HMAC-sealed hash chain, implemented twice: TypeScript (`src/`, CommonJS via
`module: NodeNext`, relative imports keep the `.js` suffix) and Python (`python/audit_chain/`).
The two MUST stay byte-identical. `vectors/` is the normative spec; `test/parity/` runs raw JSON
texts through both languages and fails on any byte or verdict difference.

Rules:
- Never hand-edit `vectors/*.json`. Change the generators (`scripts/emit-*.mts` and the vector groups
  in `scripts/audit-vectors/`), then `npm run vectors`. A change to an
  existing `expected_*` value is a breaking change to the chain format: every previously sealed chain
  stops verifying.
- Any change to canonicalize or verify lands in BOTH languages in the same commit, with a vector that
  would have caught the divergence, and a parity case if the vector can't express it.
- `verifyChain` / `verify_chain` never throw on chain CONTENT: a malformed chain is a failed result.
  API misuse (a wrong-typed anchor or keyring) is a TypeError, and infrastructure errors (key
  provider, entry source, memory, stack) propagate. Both return the same `(ok, lastSeq)` for every
  chain.
- The on-disk format is canonical JSONL (each line == canonical(entry)), verified byte for byte by
  `verifyJsonl` / `verify_jsonl`. Never relax that to "parses to the same value": the two JSON
  parsers disagree on texts that never reach the parsed value.
- Never parse untrusted JSON with `JSON.parse` in TypeScript; use `parseJson` (src/json.ts). V8 12.9+
  (Node 23 through at least 26) misparses escaped one-character keys depending on earlier parses in
  the process; the rule holds on every Node version.
- The canonical domain (safe integers, well-formed Unicode, depth <= 100) is deliberate. Don't widen it
  to floats.
- Verify before done: `npm run typecheck && npm run lint && npm test && npm run build`, then
  `pip install -e ".[test,lint]" && pytest && ruff check python`, then `npm run test:parity`.
