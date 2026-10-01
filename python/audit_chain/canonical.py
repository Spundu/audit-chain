"""Deterministic JSON canonicalization: RFC 8785 (JCS) serialization over a strict value domain.

This MUST stay byte-identical to ``src/canonicalize.ts``. It is verified by the shared vectors in
``vectors/jcs-vectors.json`` and by the cross-language parity suite (``test/parity``).

Domain (anything outside it raises CanonicalizationError; never a best-effort serialization):
  * ``None``, ``bool``
  * numbers whose value is an integer with |n| <= 2**53 - 1. An integral ``float`` (``1.0``, ``1e2``,
    ``-0.0``) is accepted as that integer, because JSON numbers are IEEE-754 doubles in JavaScript and
    ``JSON.parse`` cannot tell ``1.0`` from ``1``. Non-integral, non-finite and unsafe values are rejected.
  * ``str`` (and object keys) that are valid Unicode: a lone surrogate is rejected. A valid surrogate
    PAIR in a Python str is combined into its code point, exactly as JavaScript sees it.
  * ``list``; ``dict`` with ``str`` keys, sorted by UTF-16 code unit -- NOT Python's default code-point
    order (they differ for astral chars vs BMP chars >= U+E000); reproduced via UTF-16-BE bytes.
  * at most MAX_DEPTH nested lists/dicts.
  * a canonical form of at most MAX_CANONICAL_BYTES UTF-8 bytes (the TypeScript side cannot build
    arbitrarily long strings, so an unbounded form would verify in Python and fail in TypeScript).

Output: no whitespace; ``,`` and ``:`` separators; non-ASCII emitted raw (``ensure_ascii=False``) and
control characters escaped exactly as ``JSON.stringify`` does. ``None`` -> ``null``.
"""
from __future__ import annotations

import json
import math
from typing import Any

MAX_DEPTH = 100
MAX_CANONICAL_BYTES = 1_048_576  # 1 MiB; normative, repeated in vectors/jcs-vectors.json
_MAX_SAFE_INTEGER = 2**53 - 1


class CanonicalizationError(ValueError):
    """The value is outside the canonical domain; it has no canonical form."""


def _string(s: str) -> str:
    try:
        # Round-tripping through UTF-16 combines a valid surrogate pair into one code point (what JS
        # sees) and raises on a lone surrogate (which has no UTF-8 encoding and no canonical form).
        return s.encode("utf-16-be", "surrogatepass").decode("utf-16-be")
    except UnicodeDecodeError:
        raise CanonicalizationError("string contains a lone surrogate") from None


class _Budget:
    """Running LOWER BOUND on the canonical form's UTF-8 size: code points and ASCII structure, which
    escaping and multi-byte encoding only enlarge. Aborting once it passes the limit never rejects a
    value that fits, and it bounds the work on shared-reference trees whose output would be huge.
    Mirrors the TypeScript budget; the exact size check happens once, after serialization."""

    __slots__ = ("used",)

    def __init__(self) -> None:
        self.used = 0

    def charge(self, amount: int) -> None:
        self.used += amount
        if self.used > MAX_CANONICAL_BYTES:
            raise CanonicalizationError(f"canonical form exceeds {MAX_CANONICAL_BYTES} bytes")


def _utf16_key(s: str) -> bytes:
    # JS ``Array.prototype.sort`` compares strings by UTF-16 code units; UTF-16-BE byte order
    # reproduces that ordering exactly, including astral chars via their surrogate pairs.
    return s.encode("utf-16-be")


def _integer(n: int | float) -> int:
    if isinstance(n, float) and not (math.isfinite(n) and n.is_integer()):
        raise CanonicalizationError("number is not an integer")
    value = int(n)
    if abs(value) > _MAX_SAFE_INTEGER:
        # No value in the message: formatting a >4300-digit int raises ValueError itself.
        raise CanonicalizationError("number is outside [-(2^53-1), 2^53-1]")
    return value


def _normalize(value: Any, depth: int, budget: _Budget) -> Any:
    if value is None or isinstance(value, bool):  # bool is a subclass of int -- keep it a bool
        budget.charge(4 if value is None or value else 5)
        return value
    if isinstance(value, int | float):
        n = _integer(value)
        budget.charge(len(str(n)))
        return n
    if isinstance(value, str):
        budget.charge(len(value) + 2)  # >= its escaped UTF-8 form; checked BEFORE the UTF-16 round trip
        return _string(value)
    if not isinstance(value, list | dict):
        raise CanonicalizationError(f"{type(value).__name__} is not a JSON value")
    if depth >= MAX_DEPTH:
        raise CanonicalizationError(f"nesting deeper than {MAX_DEPTH}")
    budget.charge(2)  # [ ] or { }
    if isinstance(value, list):
        items = []
        for i, v in enumerate(value):
            if i:
                budget.charge(1)  # ,
            items.append(_normalize(v, depth + 1, budget))
        return items
    members: dict[str, Any] = {}
    for key, member in value.items():
        if not isinstance(key, str):
            raise CanonicalizationError("object keys must be strings")
        budget.charge(len(key) + (4 if members else 3))  # "key": and ,
        normalized = _string(key)
        if normalized in members:
            # Two distinct Python strs that are ONE JavaScript string (a surrogate pair written as two
            # code points vs the astral char): silently keeping one would leave the other unhashed.
            raise CanonicalizationError("two keys are the same string once surrogate pairs are combined")
        members[normalized] = _normalize(member, depth + 1, budget)
    return {k: members[k] for k in sorted(members, key=_utf16_key)}


def canonicalize(value: Any) -> str:
    """Deterministic, stable string form of a JSON value (matches canonicalize.ts).

    Raises CanonicalizationError, and nothing else, for any value outside the canonical domain."""
    try:
        normalized = _normalize(value, 0, _Budget())
    except (CanonicalizationError, MemoryError, RecursionError):
        raise  # out of memory / stack is the caller's infrastructure problem, not a domain error
    except Exception as exc:  # e.g. a mapping whose iteration raises: unreadable means no canonical form
        raise CanonicalizationError("value cannot be read as JSON") from exc
    text = json.dumps(normalized, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    if len(text.encode("utf-8")) > MAX_CANONICAL_BYTES:
        raise CanonicalizationError(f"canonical form exceeds {MAX_CANONICAL_BYTES} bytes")
    return text
