"""Chain verification (port of src/verify.ts). Re-derives every entry to detect content tamper
(entry_hash), forgery/unseal (entry_hmac, timing-safe), and reorder / middle-delete (seq + prev_hash
continuity). Keys resolved by writer_key_id (rotation-ready). Tail truncation is only detectable WITH
an anchor: the chain alone cannot prove how many entries existed.

Total on any chain content (a chain is usually parsed from untrusted JSON): every malformed shape is a
broken chain at the first bad index, never an exception -- and the SAME verdict (ok, last_seq) as
TypeScript. What does raise is not chain content: TypeError for a keyring that is not a mapping, any
exception the keyring itself raises, MemoryError, and RecursionError (the caller ran out of stack)."""
from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .canonical import MAX_CANONICAL_BYTES, CanonicalizationError, canonicalize
from .seal import _DERIVED_FIELDS, GENESIS_HASH, MIN_KEY_BYTES

# ',"entry_hash":"<64 hex>"' + ',"entry_hmac":"<64 hex>"': 2 x (1 + 14 + 64 + 1).
_DERIVED_MEMBERS_BYTES = 160


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    last_seq: int
    error: str | None = None


@dataclass(frozen=True)
class ChainAnchor:
    """External corroboration that pins the chain's length + head, detecting tail truncation."""

    count: int
    last_hash: str


def _hmac_equal(expected: str, got: object) -> bool:
    """Total, timing-safe compare against the exact lowercase-hex string the seal emits. Compares BYTES:
    compare_digest raises TypeError on a non-ASCII str, so comparing strings would make a forged
    non-ASCII entry_hmac throw instead of failing closed. surrogatepass keeps a lone surrogate (legal in
    parsed JSON) from raising on encode; differing lengths simply compare False."""
    if not isinstance(got, str):
        return False
    return hmac.compare_digest(expected.encode("ascii"), got.encode("utf-8", "surrogatepass"))


def _same_number(value: object, expected: int) -> bool:
    # JSON numbers are doubles in JS, where `1.0 === 1`; a bool is never a number there.
    return isinstance(value, int | float) and not isinstance(value, bool) and value == expected


class _KeyringError(Exception):
    """Wraps an exception raised BY the keyring, so it propagates instead of reading as tampering."""


def _look_up_key(keyring: Mapping[str, Any], writer_key_id: str) -> Any:
    try:
        return keyring.get(writer_key_id)
    except Exception as exc:
        raise _KeyringError from exc


@dataclass(frozen=True)
class _Verified:
    """The ONLY success outcome of _verify_entry: anything else is a failure reason. A dedicated type,
    so no caller-supplied value (an "unreadable" reason of any type) can ever be mistaken for success."""

    entry_hash: str


def _verify_entry(entry: object, i: int, prev_hash: str, keyring: Mapping[str, Any]) -> str | _Verified:
    """_Verified(entry_hash) if the entry verifies, else the reason it does not."""
    if not isinstance(entry, dict):
        return "entry is not an object"
    core = {k: v for k, v in entry.items() if k not in _DERIVED_FIELDS}
    if not _same_number(core.get("seq"), i):
        return "seq discontinuity"
    if core.get("prev_hash") != prev_hash:
        return "prev_hash break"
    try:
        data = canonicalize(core).encode("utf-8")
    except CanonicalizationError as exc:
        return f"not canonicalizable: {exc}"
    entry_hash = hashlib.sha256(data).hexdigest()
    if entry.get("entry_hash") != entry_hash:
        return "entry_hash mismatch"
    writer_key_id = core.get("writer_key_id")
    key = _look_up_key(keyring, writer_key_id) if isinstance(writer_key_id, str) else None
    if not isinstance(key, bytes | bytearray) or len(key) < MIN_KEY_BYTES:
        return "unknown writer_key_id"
    if not _hmac_equal(hmac.new(key, data, hashlib.sha256).hexdigest(), entry.get("entry_hmac")):
        return "entry_hmac mismatch"
    # The whole ENTRY, not just its core, must fit the size limit: seal_core refuses to create a larger
    # one and canonical JSONL can never store it. With both hash fields verified as 64 lowercase hex
    # chars, canonical(entry) is exactly canonical(core) plus two 79-byte members and their commas.
    if len(data) + _DERIVED_MEMBERS_BYTES > MAX_CANONICAL_BYTES:
        return "entry exceeds the canonical size limit"
    return _Verified(entry_hash)


def _describe(reason: object) -> str:
    try:
        return str(reason)
    except (MemoryError, RecursionError):
        raise  # the caller ran out of memory or stack: not evidence about the entry
    except Exception:  # noqa: BLE001 -- a reason whose __str__ raises is still a broken chain
        return "entry cannot be read"


def verify_chain(
    entries: Any, keyring: Mapping[str, Any], anchor: ChainAnchor | None = None
) -> VerifyResult:
    """keyring.get(writer_key_id) MUST return None (never raise) for an unknown id: the id comes from
    chain content, and an exception from the keyring propagates as an infrastructure error."""
    if not isinstance(keyring, Mapping):
        raise TypeError("keyring must be a mapping of writer_key_id -> key bytes")
    if not isinstance(entries, list):
        return VerifyResult(False, -1, "entries is not a list")
    try:
        entries = list(entries)  # a list subclass may override iteration; read it exactly once
    except (MemoryError, RecursionError):
        raise  # the caller ran out of memory or stack: not evidence about the chain
    except Exception:  # noqa: BLE001 -- API-only (json.loads never builds one); TS: a revoked Proxy
        return VerifyResult(False, -1, "entries cannot be read")
    return verify_entries((("entry", e) for e in entries), keyring, anchor)


def verify_entries(
    steps: Iterable[tuple[str, Any]], keyring: Mapping[str, Any], anchor: ChainAnchor | None = None
) -> VerifyResult:
    """The verification engine, INCREMENTAL (port of verifyEntries in src/verify.ts). `steps` yields
    ("entry", value) for each entry in order, or ("unreadable", reason) for one that could not be read;
    nothing is retained but the previous entry_hash, and verification stops at the first failure. So an
    earlier entry is always verified before a later one can fail, and the anchor is checked only after
    the last entry, never on a chain that already broke."""
    if not isinstance(keyring, Mapping):
        raise TypeError("keyring must be a mapping of writer_key_id -> key bytes")
    if anchor is not None and not isinstance(anchor, ChainAnchor):
        # Only None means "no anchor"; anything else would silently switch the truncation check off.
        raise TypeError("anchor must be a ChainAnchor, or None")
    prev_hash = GENESIS_HASH
    count = 0
    for step in steps:  # an exception from the source itself propagates (infrastructure)
        if not (isinstance(step, tuple) and len(step) == 2 and step[0] in ("entry", "unreadable")):
            raise TypeError('steps must yield ("entry", value) or ("unreadable", reason)')
        kind, payload = step
        if kind == "unreadable":
            # The chain breaks here, WHATEVER the reason's type (a tuple, bytes, an exception...).
            return VerifyResult(False, count - 1, f"{_describe(payload)} at index {count}")
        try:
            outcome: str | _Verified = _verify_entry(payload, count, prev_hash, keyring)
        except _KeyringError as exc:
            # A failing keyring (KMS timeout, ...) is an infrastructure error, not tampering.
            raise exc.__cause__ from None  # type: ignore[misc]
        except (MemoryError, RecursionError):
            raise  # the caller ran out of memory or stack: not evidence about the entry
        except Exception:  # noqa: BLE001 -- e.g. a dict subclass whose accessors raise: API-only
            outcome = "entry cannot be read"
        if not isinstance(outcome, _Verified):
            return VerifyResult(False, count - 1, f"{outcome} at index {count}")
        prev_hash = outcome.entry_hash
        count += 1

    if anchor is not None:
        # A wrong count breaks at n (the chain length): every entry present verified, and is vouched for.
        if not _same_number(anchor.count, count):
            return VerifyResult(False, count - 1, f"count {count} != anchor count")
        if prev_hash != anchor.last_hash:
            return VerifyResult(False, max(count - 1, 0) - 1, "head hash does not match anchor")
    return VerifyResult(True, count - 1)
