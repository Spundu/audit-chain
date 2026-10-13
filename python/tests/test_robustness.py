"""Robustness and API-edge contracts: streaming JSONL, writer-stamped fields, work bounds, keyring
failures, and the Python-only API edges that mirror the TypeScript ones."""
from __future__ import annotations

import hmac
import pathlib
import time
from collections import UserDict
from collections.abc import Mapping
from types import MappingProxyType

import pytest

from audit_chain import (
    CanonicalizationError,
    append_entry,
    canonicalize,
    seal_core,
    to_jsonl_line,
    verify_chain,
    verify_jsonl,
)

KEY = bytes(range(32))
RING = {"k1": KEY}
LF = b"\n"


def _chain(n: int) -> list[dict]:
    out: list[dict] = []
    prev = None
    for i in range(n):
        prev = append_entry(prev, {"v": 1, "request_id": f"r{i}"}, KEY, writer_key_id="k1")
        out.append(prev)
    return out


def _file(entries: list[dict]) -> bytes:
    return b"".join(to_jsonl_line(e) for e in entries)


# -- streaming: junk costs no more than its first bad line -------------------------------------------


def test_64_mib_of_line_feeds_is_rejected_at_line_0_fast(work) -> None:  # noqa: ANN001
    start = time.monotonic()
    result = verify_jsonl(LF * (64 * 2**20), RING)
    assert (result.ok, result.last_seq) == (False, -1)
    assert work["lines_parsed"] == 1
    assert time.monotonic() - start < 30  # hang guard only; the bound above is the real check


@pytest.mark.parametrize("line", [b"0", b"{}"])
def test_millions_of_meaningless_lines_are_rejected_at_line_0_fast(line: bytes, work) -> None:  # noqa: ANN001
    start = time.monotonic()
    result = verify_jsonl((line + LF) * (4 * 2**20), RING)
    assert (result.ok, result.last_seq) == (False, -1)
    assert work["lines_parsed"] == 1
    assert time.monotonic() - start < 30  # hang guard only; the bound above is the real check


def test_a_chain_followed_by_line_feeds_breaks_at_the_first_junk_line() -> None:
    result = verify_jsonl(_file(_chain(3)) + LF * (32 * 2**20), RING)
    assert (result.ok, result.last_seq) == (False, 2)


# -- writer-stamped fields ---------------------------------------------------------------------------


def test_seq_prev_hash_and_key_id_come_from_the_writer_not_the_draft() -> None:
    e0 = _chain(1)[0]
    forged = {"v": 1, "seq": 7, "prev_hash": "f" * 64, "writer_key_id": "other"}
    e1 = append_entry(e0, forged, KEY, writer_key_id="k1")
    stamped = (e1["seq"], e1["prev_hash"], e1["writer_key_id"])
    assert stamped == (1, e0["entry_hash"], "k1")
    assert verify_chain([e0, e1], RING).ok



# -- keyring failures are infrastructure errors, whatever their type ---------------------------------


@pytest.mark.parametrize("exc", [TimeoutError, ConnectionError, RuntimeError, OSError, KeyError, ValueError])
def test_any_keyring_exception_propagates(exc: type[Exception]) -> None:
    class Failing(dict):
        def get(self, key, default=None):  # noqa: ANN001, ANN201
            raise exc("kms down")

    with pytest.raises(exc):
        verify_chain(_chain(1), Failing())


# -- API edges ---------------------------------------------------------------------------------------


def test_canonicalize_raises_only_canonicalization_error_for_unreadable_or_foreign_mappings() -> None:
    class Unreadable(dict):
        def items(self):  # noqa: ANN201
            raise RuntimeError("boom")

    with pytest.raises(CanonicalizationError):
        canonicalize(Unreadable(a=1))
    with pytest.raises(CanonicalizationError):
        canonicalize(UserDict({"a": 1}))  # a Mapping, but not a JSON object type


def test_an_entry_whose_accessors_raise_is_a_broken_chain() -> None:
    class Unreadable(dict):
        def get(self, key, default=None):  # noqa: ANN001, ANN201
            raise RuntimeError("boom")

    entry = Unreadable(_chain(1)[0])
    assert (verify_chain([entry], RING).ok, verify_chain([entry], RING).last_seq) == (False, -1)


def test_bytearray_keys_and_data_are_accepted() -> None:
    entries = _chain(2)
    assert verify_chain(entries, {"k1": bytearray(KEY)}).ok
    assert verify_jsonl(bytearray(_file(entries)), RING).ok
    assert seal_core({"seq": 0, "prev_hash": "0" * 64, "writer_key_id": "k1"}, bytearray(KEY))["entry_hmac"]


def test_an_entry_that_is_a_non_dict_mapping_breaks_the_chain() -> None:
    from collections import UserDict

    entry = _chain(1)[0]
    result = verify_chain([UserDict(entry)], RING)
    assert (result.ok, result.last_seq) == (False, -1)


def test_only_a_list_is_a_chain() -> None:
    entries = _chain(1)
    assert (verify_chain(tuple(entries), RING).ok, verify_chain(tuple(entries), RING).last_seq) == (False, -1)


def test_hmac_is_compared_in_constant_time() -> None:
    source = (pathlib.Path(__file__).resolve().parents[1] / "audit_chain" / "verify.py").read_text("utf-8")
    assert "hmac.compare_digest(" in source
    assert "_hmac_equal(hmac.new(key, data, hashlib.sha256).hexdigest()" in source


def _forged_hmac_at_1() -> list[dict]:
    """A 3-entry chain whose entry 1 HMAC is other valid lowercase hex: its entry_hash still matches."""
    chain = _chain(3)
    real = chain[1]["entry_hmac"]
    chain[1] = {**chain[1], "entry_hmac": ("b" if real[0] == "a" else "a") + real[1:]}
    return chain


@pytest.fixture
def compare_digest(monkeypatch: pytest.MonkeyPatch) -> dict:
    """Counts hmac.compare_digest calls; `answer`, when set, replaces its result."""
    real = hmac.compare_digest
    spy: dict = {"calls": 0, "answer": None}

    def counting(a: bytes, b: bytes) -> bool:
        spy["calls"] += 1
        return real(a, b) if spy["answer"] is None else spy["answer"]

    monkeypatch.setattr(hmac, "compare_digest", counting)
    return spy


def _verdict(entries: list[dict]) -> tuple[bool, int]:
    result = verify_chain(entries, RING)
    return result.ok, result.last_seq


def test_compare_digest_is_asked_once_per_entry_that_reaches_the_hmac_step(compare_digest: dict) -> None:
    # Behavioural, not source-level: a verifier comparing with == fails these.
    assert _verdict(_chain(3)) == (True, 2) and compare_digest["calls"] == 3
    compare_digest["calls"] = 0
    assert _verdict(_forged_hmac_at_1()) == (False, 0) and compare_digest["calls"] == 2
    compare_digest["calls"] = 0
    tampered = _chain(3)
    tampered[1] = {**tampered[1], "request_id": "tampered"}
    assert _verdict(tampered) == (False, 0) and compare_digest["calls"] == 1


def test_compare_digest_answer_is_the_whole_hmac_verdict(compare_digest: dict) -> None:
    compare_digest["answer"] = False
    assert _verdict(_chain(3)) == (False, -1)
    compare_digest["answer"] = True
    assert _verdict(_forged_hmac_at_1()) == (True, 2)


# -- the streaming engine, MemoryError, exports, harness self-checks -----------------------------------


def test_a_failing_source_propagates_from_verify_entries() -> None:
    from audit_chain import verify_entries

    entries = _chain(4)

    def source():  # noqa: ANN202
        for i, e in enumerate(entries):
            if i == 2:
                raise TimeoutError("ETIMEDOUT: db cursor")
            yield ("entry", e)

    with pytest.raises(TimeoutError):
        verify_entries(source(), RING)


def test_verify_entries_reports_unreadable_and_rejects_malformed_steps() -> None:
    from audit_chain import verify_entries

    e = _chain(1)[0]
    result = verify_entries(iter([("entry", e), ("unreadable", "corrupt row")]), RING)
    assert (result.ok, result.last_seq) == (False, 0)
    with pytest.raises(TypeError):
        verify_entries(iter([("bogus", e)]), RING)
    with pytest.raises(TypeError):
        verify_entries(iter([None]), RING)  # type: ignore[list-item]


def test_a_final_line_feed_replaced_by_cr_is_torn() -> None:
    from audit_chain import parse_jsonl

    data = _file(_chain(3))[:-1] + b"\r"
    result = verify_jsonl(data, RING)
    assert (result.ok, result.last_seq) == (False, 1)
    parsed = parse_jsonl(data)
    assert parsed.bad_line == 2 and len(parsed.entries) == 2


def test_several_large_lines_over_1_mib_verify() -> None:
    # 4 x 400 KB: the last line STARTS past 1 MiB (the size bound is per line, not per offset).
    entries: list[dict] = []
    prev = None
    for i in range(4):
        draft = {"v": 1, "pad": "y" * 400_000, "i": i}
        prev = append_entry(prev, draft, KEY, writer_key_id="k1")
        entries.append(prev)
    data = _file(entries)
    assert data.rindex(b"\n", 0, len(data) - 1) + 1 > 2**20
    assert (verify_jsonl(data, RING).ok, verify_jsonl(data, RING).last_seq) == (True, 3)


def test_memory_error_is_never_turned_into_a_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    import audit_chain.canonical as canonical_mod
    import audit_chain.jsonl as jsonl_mod

    data = _file(_chain(1))

    def oom(*_a, **_k):  # noqa: ANN002, ANN003, ANN202
        raise MemoryError

    with monkeypatch.context() as m:
        m.setattr(jsonl_mod.json, "loads", oom)
        with pytest.raises(MemoryError):
            verify_jsonl(data, RING)
    with monkeypatch.context() as m:
        m.setattr(jsonl_mod, "canonicalize", oom)
        with pytest.raises(MemoryError):
            verify_jsonl(data, RING)
    with monkeypatch.context() as m:
        m.setattr(canonical_mod, "_normalize", oom)
        with pytest.raises(MemoryError):
            canonicalize({"a": 1})

    class OomEntry(dict):
        def get(self, key, default=None):  # noqa: ANN001, ANN201
            raise MemoryError

    class OomList(list):
        def __iter__(self):  # noqa: ANN204
            raise MemoryError

    with pytest.raises(MemoryError):
        verify_chain([OomEntry(_chain(1)[0])], RING)
    with pytest.raises(MemoryError):
        verify_chain(OomList(_chain(1)), RING)


@pytest.mark.parametrize("keyring", [None, object(), "k1"])
def test_verify_jsonl_requires_a_mapping_keyring(keyring: object) -> None:
    with pytest.raises(TypeError):
        verify_jsonl(b"", keyring)  # type: ignore[arg-type]


@pytest.mark.parametrize("exc", [TypeError, KeyError, ValueError, RuntimeError])
def test_unreadable_mappings_entries_and_lists_never_escape(exc: type[Exception]) -> None:
    class BadItems(dict):
        def items(self):  # noqa: ANN201
            raise exc("boom")

    class BadGet(dict):
        def get(self, key, default=None):  # noqa: ANN001, ANN201
            raise exc("boom")

    class BadIter(list):
        def __iter__(self):  # noqa: ANN204
            raise exc("boom")

    with pytest.raises(CanonicalizationError):
        canonicalize(BadItems(a=1))
    assert not verify_chain([BadGet(_chain(1)[0])], RING).ok
    assert not verify_chain(BadIter(_chain(1)), RING).ok


def test_a_split_surrogate_pair_key_is_the_astral_key() -> None:
    halves = chr(0xD83D) + chr(0xDE00)
    assert canonicalize({halves: 1}) == canonicalize({chr(0x1F600): 1})


def test_result_types_are_frozen_and_hashable() -> None:
    import dataclasses

    from audit_chain import ChainAnchor, VerifyResult, parse_jsonl

    for value in (VerifyResult(True, 0), ChainAnchor(1, "0" * 64), parse_jsonl(b"")):
        with pytest.raises(dataclasses.FrozenInstanceError):
            value.ok = False  # type: ignore[misc, union-attr]
    hash(VerifyResult(True, 0))
    hash(ChainAnchor(1, "0" * 64))


def test_every_documented_name_is_exported() -> None:
    import audit_chain

    for name in audit_chain.__all__:
        assert hasattr(audit_chain, name), name
    documented = ("verify_entries", "verify_jsonl", "verify_chain", "parse_jsonl", "canonicalize")
    for name in documented:
        assert name in audit_chain.__all__, name


def test_the_parity_worker_counts_a_wrapped_crash_as_a_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    import audit_chain.parity_worker as worker

    def wrapped_crash(_value):  # noqa: ANN001, ANN202
        raise CanonicalizationError("value cannot be read as JSON") from RuntimeError("bug")

    monkeypatch.setattr(worker, "canonicalize", wrapped_crash)
    assert worker._outcome("1", worker._canonical_hex)["phase"] == "crash"

    def domain(_value):  # noqa: ANN001, ANN202
        raise CanonicalizationError("number is not an integer")

    monkeypatch.setattr(worker, "canonicalize", domain)
    assert worker._outcome("1", worker._canonical_hex)["phase"] == "domain"

    # The seal path classifies the same way.
    import audit_chain.seal as seal

    seal_one = worker._sealer(KEY, "k1")
    monkeypatch.setattr(seal, "canonicalize", wrapped_crash)
    assert worker._outcome("1", seal_one)["phase"] == "crash"
    monkeypatch.setattr(seal, "canonicalize", domain)
    assert worker._outcome("1", seal_one)["phase"] == "domain"


@pytest.mark.parametrize(
    "reason",
    ["disk read error", ("E_IO", "x"), ["x"], b"b", bytearray(b"b"), None, 5, ValueError("v"), "VALID-ENTRY",
     "UNPRINTABLE"],
)
def test_an_unreadable_step_breaks_the_chain_whatever_the_reason_type(reason: object) -> None:
    from audit_chain import ChainAnchor, verify_entries

    e0, e1 = _chain(2)
    if reason == "VALID-ENTRY":
        reason = _chain(3)[2]  # a reason that is itself a perfectly valid next entry: still unreadable
    if reason == "UNPRINTABLE":

        class Unprintable:
            def __str__(self) -> str:
                raise ValueError("no str")

        reason = Unprintable()  # even a reason that cannot be turned into text breaks the chain
    last = verify_entries(iter([("entry", e0), ("entry", e1), ("unreadable", reason)]), RING)
    assert (last.ok, last.last_seq) == (False, 1)
    middle = verify_entries(
        iter([("entry", e0), ("unreadable", reason), ("entry", e1)]), RING, ChainAnchor(3, e1["entry_hash"])
    )
    assert (middle.ok, middle.last_seq) == (False, 0)
    first = verify_entries(iter([("unreadable", (e0["entry_hash"],)), ("entry", e1)]), RING)
    assert (first.ok, first.last_seq) == (False, -1)


@pytest.mark.parametrize("step", [("entry",), ("entry", {}, "extra"), "entry", ["unreadable", "x"], None])
def test_a_malformed_step_is_a_type_error(step: object) -> None:
    from audit_chain import verify_entries

    with pytest.raises(TypeError):
        verify_entries(iter([step]), RING)


@pytest.mark.parametrize("anchor", [False, 0, "", (3, "x"), {"count": 3, "last_hash": "x"}])
def test_an_anchor_that_is_not_a_chain_anchor_is_a_type_error(anchor: object) -> None:
    with pytest.raises(TypeError):
        verify_chain(_chain(2), RING, anchor)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        verify_jsonl(_file(_chain(2)), RING, anchor)  # type: ignore[arg-type]


def test_none_means_no_anchor() -> None:
    assert verify_chain(_chain(2), RING, None).ok


@pytest.mark.parametrize("entries", [_chain(1), {}, "", None])
def test_verify_chain_requires_a_mapping_keyring_whatever_the_entries(entries: object) -> None:
    with pytest.raises(TypeError):
        verify_chain(entries, None)  # type: ignore[arg-type]



def test_the_parity_worker_reports_a_python_crash_as_threw(monkeypatch: pytest.MonkeyPatch) -> None:
    import audit_chain.parity_worker as worker

    def crash(*_a, **_k):  # noqa: ANN002, ANN003, ANN202
        raise KeyError("simulated crash")

    monkeypatch.setattr(worker, "verify_chain", crash)
    monkeypatch.setattr(worker, "verify_jsonl", crash)
    chain_case = {"chain": "[]", "keyring": {"k1": KEY.hex()}}
    assert worker._verdict(chain_case, worker._chain_runner(chain_case))["threw"] is True
    jsonl_case = {"data_hex": "", "keyring": {"k1": KEY.hex()}}
    assert worker._verdict(jsonl_case, worker._jsonl_runner(jsonl_case))["threw"] is True


class _MinimalMapping(Mapping):
    def __init__(self, data: dict) -> None:
        self._data = data

    def __getitem__(self, key: str) -> bytes:
        return self._data[key]

    def __iter__(self):  # noqa: ANN204
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)


@pytest.mark.parametrize(
    "make", [dict, MappingProxyType, _MinimalMapping], ids=["dict", "MappingProxyType", "Mapping"]
)
def test_any_mapping_is_a_keyring(make) -> None:  # noqa: ANN001
    # README: only a value that is NOT a mapping is a TypeError; any Mapping works, not just dict.
    entries = _chain(2)
    ring = make(dict(RING))
    assert _verdict(entries) == (True, 1)
    assert (verify_chain(entries, ring).ok, verify_chain(entries, ring).last_seq) == (True, 1)
    jsonl = verify_jsonl(_file(entries), ring)
    assert (jsonl.ok, jsonl.last_seq) == (True, 1)
    from audit_chain import verify_entries

    streamed = verify_entries((("entry", e) for e in entries), ring)
    assert (streamed.ok, streamed.last_seq) == (True, 1)
