"""Seal primitive (port of src/seal.ts).

entry_hash = sha256(JCS(core)); entry_hmac = HMAC-SHA256(key, sameBytes). Byte-identical to the TS
impl (proven by vectors/audit-seal-vectors.json). append_entry assigns seq/prev_hash/writer_key_id/producer
and deep-drops None (matching JSON.stringify dropping `undefined`)."""
from __future__ import annotations

import hashlib
import hmac
from typing import Any

from .canonical import canonicalize

GENESIS_HASH = "0" * 64
MIN_KEY_BYTES = 16  # a short (or empty) key lets anyone forge
_DERIVED_FIELDS = ("entry_hash", "entry_hmac")


def prune_none(value: Any) -> Any:
    """Deep-drop None MEMBERS of dicts: a None field means an absent field, as `undefined` does in
    JSON.stringify. None inside a list is kept and serializes as null (TypeScript's canonicalize
    rejects `undefined` array elements instead; there is no list equivalent of an absent field)."""
    if isinstance(value, dict):
        return {k: prune_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [prune_none(v) for v in value]
    return value


def _seal_bytes(core: dict[str, Any]) -> bytes:
    return canonicalize(core).encode("utf-8")


def seal_core(core: dict[str, Any], key: bytes) -> dict[str, Any]:
    """Seal a fully-formed core (already clean: no None, no derived fields)."""
    if not isinstance(key, bytes | bytearray) or len(key) < MIN_KEY_BYTES:
        raise ValueError(f"HMAC key must be at least {MIN_KEY_BYTES} bytes")
    if any(field in core for field in _DERIVED_FIELDS):
        # They would be hashed here, overwritten below and stripped at verification: never verifiable.
        raise ValueError("core must not contain entry_hash or entry_hmac")
    data = _seal_bytes(core)
    sealed = {
        **core,
        "entry_hash": hashlib.sha256(data).hexdigest(),
        "entry_hmac": hmac.new(key, data, hashlib.sha256).hexdigest(),
    }
    # The stored line is canonical(sealed): the core plus ~160 bytes of hashes. Refuse here an entry
    # that could be sealed but never written (or verified) as a line.
    canonicalize(sealed)
    return sealed


def next_state(prev: dict[str, Any] | None) -> tuple[int, str]:
    if prev is None:
        return (0, GENESIS_HASH)
    return (int(prev["seq"]) + 1, prev["entry_hash"])


def append_entry(
    prev: dict[str, Any] | None, draft: dict[str, Any], key: bytes,
    *, writer_key_id: str, producer: str,
) -> dict[str, Any]:
    """Assign seq/prev_hash/writer_key_id/producer, deep-prune None, and seal.

    The writer stamps `producer` from the channel the draft arrived on; there is no default. Unlike
    the TypeScript writer this one has no schema: a None member means "absent" and is dropped."""
    seq, prev_hash = next_state(prev)
    core = prune_none({
        **draft, "producer": producer, "seq": seq, "prev_hash": prev_hash, "writer_key_id": writer_key_id,
    })
    return seal_core(core, key)
