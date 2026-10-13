"""Seal primitive (port of src/seal.ts).

entry_hash = sha256(JCS(core)); entry_hmac = HMAC-SHA256(key, sameBytes). Byte-identical to the TS
impl (checked by vectors/audit-seal-vectors.json and the parity suite). The chain seals any JSON object:
there is no record schema. append_entry assigns seq/prev_hash/writer_key_id; a None member is JSON null,
as in TypeScript, so the same record seals to the same entry in both languages."""
from __future__ import annotations

import hashlib
import hmac
import math
from collections.abc import Mapping
from typing import Any

from .canonical import canonicalize

GENESIS_HASH = "0" * 64
MIN_KEY_BYTES = 16  # a short (or empty) key lets anyone forge
_DERIVED_FIELDS = ("entry_hash", "entry_hmac")
_MAX_SAFE_INTEGER = 2**53 - 1
_LOWER_HEX = frozenset("0123456789abcdef")


def _is_seq(value: object) -> bool:
    """A non-negative safe integer, read as JSON reads numbers (TypeScript's Number.isSafeInteger):
    1.0 counts, a bool never does."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    if isinstance(value, float) and not (math.isfinite(value) and value.is_integer()):
        return False
    return 0 <= value <= _MAX_SAFE_INTEGER


def _is_sha256_hex(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in _LOWER_HEX for c in value)


def _seal_bytes(core: dict[str, Any]) -> bytes:
    return canonicalize(core).encode("utf-8")


def seal_core(core: dict[str, Any], key: bytes) -> dict[str, Any]:
    """Seal a fully-formed core: a dict without the derived fields. The chain fields are not checked
    here (append_entry sets them)."""
    if not isinstance(key, bytes | bytearray) or len(key) < MIN_KEY_BYTES:
        raise ValueError(f"HMAC key must be at least {MIN_KEY_BYTES} bytes")
    if not isinstance(core, dict):
        raise TypeError("core must be a dict (a JSON object)")
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


def next_state(prev: Mapping[str, Any] | None) -> tuple[int, str]:
    """The seq and prev_hash of the entry after `prev` (None: the chain is empty). `prev` must look like
    a sealed entry, or the next entry could be sealed but never verify: a TypeError, as in TypeScript."""
    if prev is None:
        return (0, GENESIS_HASH)
    try:  # any mapping, or a row object such as sqlite3.Row
        seq, entry_hash = prev["seq"], prev["entry_hash"]
    except (KeyError, IndexError, TypeError) as exc:
        raise TypeError("prev must be the previous sealed entry, or None") from exc
    if not _is_seq(seq):
        raise TypeError("prev['seq'] must be a non-negative safe integer")
    if not _is_sha256_hex(entry_hash):
        raise TypeError("prev['entry_hash'] must be 64 lowercase hex chars")
    return (int(seq) + 1, entry_hash)


def append_entry(
    prev: Mapping[str, Any] | None, draft: Mapping[str, Any], key: bytes, *, writer_key_id: str,
) -> dict[str, Any]:
    """Assign seq/prev_hash/writer_key_id (replacing any the draft carries), and seal.

    A None member is sealed as JSON null, exactly as TypeScript seals null: the same record gives the
    same entry in both languages."""
    if not isinstance(writer_key_id, str):
        raise TypeError("writer_key_id must be a str")
    seq, prev_hash = next_state(prev)
    core = {**draft, "seq": seq, "prev_hash": prev_hash, "writer_key_id": writer_key_id}
    return seal_core(core, key)
