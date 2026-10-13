"""audit-chain: tamper-evident, HMAC-sealed audit chain. A byte-identical port of the TypeScript
implementation, checked by the shared vectors in vectors/ and the cross-language parity suite."""
from .canonical import MAX_CANONICAL_BYTES, MAX_DEPTH, CanonicalizationError, canonicalize
from .jsonl import ParsedJsonl, parse_jsonl, to_jsonl_line, verify_jsonl
from .seal import GENESIS_HASH, MIN_KEY_BYTES, append_entry, next_state, seal_core
from .verify import ChainAnchor, VerifyResult, verify_chain, verify_entries

__all__ = [
    "GENESIS_HASH",
    "MAX_CANONICAL_BYTES",
    "MAX_DEPTH",
    "MIN_KEY_BYTES",
    "CanonicalizationError",
    "ChainAnchor",
    "ParsedJsonl",
    "VerifyResult",
    "append_entry",
    "canonicalize",
    "next_state",
    "parse_jsonl",
    "seal_core",
    "to_jsonl_line",
    "verify_chain",
    "verify_entries",
    "verify_jsonl",
]
