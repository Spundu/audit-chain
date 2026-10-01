"""Running out of stack is an infrastructure error of the CALLER, never evidence about the data: it
propagates from every entry point and is never reported as a broken chain (same contract as TS,
test/stack.test.ts). Each sweep calls verification from every depth in the band just below the recursion
limit, where it runs out of stack at every possible point, and must see only "ok" and "raised"."""
from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import Any

import pytest

import audit_chain.jsonl as jsonl_mod
from audit_chain import MAX_DEPTH, append_entry, to_jsonl_line, verify_chain, verify_entries, verify_jsonl
from audit_chain.jsonl import _max_nesting, _parse_line

KEY = bytes(range(32))
RING = {"k1": KEY}
LF = b"\n"
BS = chr(92)
QUOTE = chr(34)


def _chain(n: int, extra: dict[str, Any] | None = None) -> list[dict]:
    out: list[dict] = []
    prev = None
    for i in range(n):
        draft = {"v": 1, "call_id": f"c{i}", **(extra or {})}
        prev = append_entry(prev, draft, KEY, writer_key_id="k1", producer="p")
        out.append(prev)
    return out


def _file(entries: list[dict]) -> bytes:
    return b"".join(to_jsonl_line(e) for e in entries)


def _nested(levels: int) -> object:
    value: object = 0
    for _ in range(levels):
        value = [value]
    return value


def _outcomes(run: Callable[[], Any], band: int = 400) -> set[str]:
    def at_depth(n: int) -> Any:
        return run() if n == 0 else at_depth(n - 1)

    limit = sys.getrecursionlimit()
    outcomes: set[str] = set()
    for depth in range(limit - band, limit):
        try:
            outcomes.add("ok" if at_depth(depth).ok else "BROKEN")
        except RecursionError:
            outcomes.add("raised")
    return outcomes


# Valid chains whose content stresses the hostile-depth check (_max_nesting): brackets inside strings, an
# escaped quote before brackets, an escaped backslash before a closing quote, and an entry exactly
# MAX_DEPTH deep. Misjudging any of them turns a low-stack RecursionError into a "BROKEN" verdict.
VALID_CHAINS = {
    "plain": _chain(2),
    "brackets-in-a-string": _chain(2, {"note": "[" * 150}),
    "escaped-quote-then-brackets": _chain(2, {"note": QUOTE + "[" * 150}),
    "escaped-backslash-before-a-closing-quote": _chain(2, {"a": BS, "b": "[" * 150}),
    "exactly-max-depth": _chain(1, {"deep": _nested(MAX_DEPTH - 1)}),
}


@pytest.mark.parametrize("name", VALID_CHAINS)
def test_verify_jsonl_raises_or_verifies_never_broken(name: str) -> None:
    data = _file(VALID_CHAINS[name])
    assert _outcomes(lambda: verify_jsonl(data, RING)) == {"ok", "raised"}


@pytest.mark.parametrize("name", VALID_CHAINS)
def test_verify_chain_raises_or_verifies_never_broken(name: str) -> None:
    entries = VALID_CHAINS[name]
    assert _outcomes(lambda: verify_chain(entries, RING)) == {"ok", "raised"}


@pytest.mark.parametrize("name", VALID_CHAINS)
def test_verify_entries_raises_or_verifies_never_broken(name: str) -> None:
    entries = VALID_CHAINS[name]
    assert _outcomes(lambda: verify_entries((("entry", e) for e in entries), RING)) == {"ok", "raised"}


def test_hostile_depth_is_a_verdict() -> None:
    assert verify_jsonl(b"[" * 3000 + b"]" * 3000 + LF, RING).ok is False
    # Thousands of sibling containers before a deep run: still judged hostile by its real depth.
    siblings = b"[" + b"[],{}," * 2500 + b"[" * 5000 + b"]" * 5000 + b"]" + LF
    result = verify_jsonl(siblings, RING)
    assert (result.ok, result.last_seq) == (False, -1)


@pytest.mark.parametrize("exc", [RecursionError, MemoryError])
def test_an_unreadable_reason_whose_str_runs_out_propagates(exc: type[BaseException]) -> None:
    class Reason:
        def __str__(self) -> str:
            raise exc

    with pytest.raises(exc):
        verify_entries(iter([("unreadable", Reason())]), RING)


@pytest.mark.parametrize("exc", [RecursionError, MemoryError])
def test_a_list_whose_iteration_runs_out_propagates_at_once(exc: type[BaseException]) -> None:
    calls = []

    class Failing(list):
        def __iter__(self):  # noqa: ANN204
            calls.append(1)
            if len(calls) == 1:
                raise exc  # only the first read fails: a second read would hide the error
            return super().__iter__()

    with pytest.raises(exc):
        verify_chain(Failing(_chain(1)), RING)
    assert calls == [1]


@pytest.mark.parametrize(
    ("text", "deepest"),
    [
        ("0", 0),
        ("[]", 1),
        ("{}", 1),
        ("[[]]", 2),
        ('{"a":[{}]}', 3),
        ("[][][]", 1),  # closing brackets count down
        ("[[]][[", 2),
        ("[[],[[]]]", 3),  # a sibling closes before the deeper run: depth goes back down by ONE each
        ('[{},[{"a":[]}]]', 4),
        ("[" + "[]," * 50 + "[[[0]]]]", 4),
        ('"[[["', 0),  # brackets inside a string
        ('["' + BS + '"[["]', 1),  # an escaped quote does not end the string
        ('["' + BS + BS + '",[[]]]', 3),  # an escaped backslash does not escape the closing quote
        ('{"k' + BS + '"[":"]"}', 1),  # an escaped quote inside a KEY
        ("[" * MAX_DEPTH + "]" * MAX_DEPTH, MAX_DEPTH),
        ("[" * (MAX_DEPTH + 1) + "]" * (MAX_DEPTH + 1), MAX_DEPTH + 1),
    ],
)
def test_max_nesting(text: str, deepest: int) -> None:
    assert _max_nesting(text) == deepest


def test_parse_line_tells_a_hostile_line_from_a_caller_low_on_stack(monkeypatch: pytest.MonkeyPatch) -> None:
    # json.loads running out of stack, deterministically: the line's own depth decides.
    def out_of_stack(_text: str) -> Any:
        raise RecursionError

    monkeypatch.setattr(jsonl_mod.json, "loads", out_of_stack)
    at_limit = json.dumps(_nested(MAX_DEPTH)).encode()  # exactly MAX_DEPTH levels: may be canonical
    assert _max_nesting(at_limit.decode()) == MAX_DEPTH
    with pytest.raises(RecursionError):
        _parse_line(at_limit)
    assert _parse_line(("[" * (MAX_DEPTH + 1) + "]" * (MAX_DEPTH + 1)).encode()) == "line is not valid JSON"
