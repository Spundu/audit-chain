"""Canonical JSONL (port of src/jsonl.ts): the on-disk format, verified byte for byte.

Each entry is one line holding exactly canonical(entry) (derived fields included), UTF-8 encoded,
terminated by a line feed. Requiring every line to BE its own canonical form is what authenticates the
FILE BYTES, not merely the value a JSON parser happens to produce: json.loads and JSON.parse disagree on
texts that never reach the parsed value (an overwritten duplicate key holding NaN or a 5000-digit
integer, extreme nesting), and none of those texts is canonical, so both languages reject them at the
same line with the same verdict.

Lines are found lazily and verified as they are read (verify_entries), so a file of any size is checked
with one line in memory at a time, and the work stops at the first bad line.
"""
from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from .canonical import MAX_CANONICAL_BYTES, MAX_DEPTH, canonicalize
from .verify import ChainAnchor, VerifyResult, verify_entries

_LF = b"\n"
_TORN = "last line is not terminated (torn)"
_TOO_LONG = "line exceeds the canonical size limit"


@dataclass(frozen=True)
class ParsedJsonl:
    entries: list[Any]  # entries parsed from the canonical lines BEFORE the first bad line
    bad_line: int | None  # index of the first line that is not valid canonical JSON
    reason: str | None


def _lines(data: bytes) -> Iterator[bytes | str]:
    """Each line's bytes in order, found lazily; a reason string instead for a line too long to be
    canonical (never sliced, so never copied) or for an unterminated tail. EVERY line, including the
    last, must end with a line feed: accepting a torn tail would let anyone drop the final byte unnoticed,
    and the next append would fuse two entries into one unparseable line."""
    start, size = 0, len(data)
    while start < size:
        end = data.find(_LF, start)
        if end == -1:
            yield _TORN
            return
        yield _TOO_LONG if end - start > MAX_CANONICAL_BYTES else data[start:end]
        start = end + 1


def _max_nesting(text: str) -> int:
    """Deepest [ / { nesting of a JSON text, ignoring brackets inside strings. Used only to tell a line
    that is hostile (nested deeper than any canonical value may be) from a caller that is merely running
    low on stack when json.loads raises RecursionError."""
    depth = deepest = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == chr(92):
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth -= 1
    return deepest


def _parse_line(line: bytes) -> tuple[Any] | str:
    if len(line) > MAX_CANONICAL_BYTES:  # can't be canonical; don't even decode it
        return _TOO_LONG
    try:
        text = line.decode("utf-8")  # strict: invalid UTF-8, overlongs, encoded surrogates all fail
    except UnicodeDecodeError:
        return "line is not valid UTF-8"
    try:
        value = json.loads(text)
    except MemoryError:
        raise
    except RecursionError:
        # A line nested deeper than any canonical value is hostile: "not valid JSON", like TS. A shallow
        # line means the CALLER is low on stack: an infrastructure error, never a verdict.
        if _max_nesting(text) > MAX_DEPTH:
            return "line is not valid JSON"
        raise
    except Exception:  # noqa: BLE001 -- JSONDecodeError, int-digit limit: not JSON
        return "line is not valid JSON"
    try:
        if canonicalize(value) != text:
            return "line is not in canonical form"
    except (MemoryError, RecursionError):
        raise
    except Exception:  # noqa: BLE001 -- CanonicalizationError (e.g. NaN, which json.loads accepts)
        return "line is outside the canonical domain"
    return (value,)


def _require_bytes(data: object, fn: str) -> bytes:
    if not isinstance(data, bytes | bytearray):
        raise TypeError(f"{fn} expects bytes")
    return bytes(data)


def parse_jsonl(data: bytes | bytearray) -> ParsedJsonl:
    """Parse canonical JSONL, stopping at the first line that is not canonical. Never raises on content."""
    entries: list[Any] = []
    for line in _lines(_require_bytes(data, "parse_jsonl")):
        parsed = line if isinstance(line, str) else _parse_line(line)
        if isinstance(parsed, str):
            return ParsedJsonl(entries, len(entries), parsed)
        entries.append(parsed[0])
    return ParsedJsonl(entries, None, None)


def verify_jsonl(
    data: bytes | bytearray, keyring: Mapping[str, Any], anchor: ChainAnchor | None = None
) -> VerifyResult:
    """Verify a canonical-JSONL chain file byte for byte, streaming (same verdict as verifyJsonl in
    TypeScript): each line is parsed and verified as it is reached, and the first failure ends it."""
    raw = _require_bytes(data, "verify_jsonl")

    def steps() -> Iterator[tuple[str, Any]]:
        for line in _lines(raw):
            parsed = line if isinstance(line, str) else _parse_line(line)
            yield ("unreadable", parsed) if isinstance(parsed, str) else ("entry", parsed[0])

    return verify_entries(steps(), keyring, anchor)


def to_jsonl_line(entry: dict[str, Any]) -> bytes:
    """One canonical-JSONL line (UTF-8, including the trailing newline) for a sealed entry."""
    return canonicalize(entry).encode("utf-8") + _LF
