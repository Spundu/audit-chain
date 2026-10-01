"""Canonical-JSONL verification: the shared file vectors plus the Python-only API edges."""
from __future__ import annotations

import json
import pathlib

import pytest
from _derivations import mismatches, size_vector_cases

from audit_chain import (
    append_entry,
    canonicalize,
    parse_jsonl,
    seal_core,
    to_jsonl_line,
    verify_chain,
    verify_jsonl,
)
from audit_chain.canonical import CanonicalizationError

_VEC = json.loads(
    (pathlib.Path(__file__).resolve().parents[2] / "vectors" / "audit-seal-vectors.json").read_text("utf-8")
)
KEYRING = {"vault-k1": bytes.fromhex(_VEC["key_hex"])}
KEY = bytes(range(32))


# Every vector, plus the cases the spec derives from it (vectors/audit-seal-vectors.json: derivations).
@pytest.mark.parametrize("v", _VEC["jsonl_vectors"], ids=[v["name"] for v in _VEC["jsonl_vectors"]])
def test_jsonl_vectors(v: dict) -> None:
    base = {k: val for k, val in v.items() if k != "data_hex"} | {"data": bytes.fromhex(v["data_hex"])}
    assert mismatches(base, _VEC["derivations"], KEYRING) == []


def _chain(n: int = 3) -> list[dict]:
    entries: list[dict] = []
    prev = None
    for i in range(n):
        prev = append_entry(prev, {"v": 1, "call_id": f"c{i}"}, KEY, writer_key_id="k1", producer="vault")
        entries.append(prev)
    return entries


def test_to_jsonl_line_round_trips() -> None:
    data = b"".join(to_jsonl_line(e) for e in _chain())
    assert verify_jsonl(data, {"k1": KEY}).ok
    assert parse_jsonl(data).entries == _chain()


def test_verify_jsonl_requires_bytes() -> None:
    with pytest.raises(TypeError):
        verify_jsonl("not bytes", {"k1": KEY})  # type: ignore[arg-type]


def test_colliding_keys_after_pair_combination_are_rejected() -> None:
    # Two different Python strs that are ONE JavaScript string: neither may escape the hash.
    with pytest.raises(CanonicalizationError):
        canonicalize({chr(0x1F600): "real", chr(0xD83D) + chr(0xDE00): "hidden"})


def test_huge_integer_is_a_domain_error_not_a_crash() -> None:
    e = _chain(1)[0]
    with pytest.raises(CanonicalizationError):
        canonicalize(10**5000)
    assert not verify_chain([{**e, "x": 10**5000}], {"k1": KEY}).ok


def test_keyring_misuse() -> None:
    entries = _chain(1)
    with pytest.raises(TypeError):
        verify_chain(entries, None)  # type: ignore[arg-type]
    assert not verify_chain(entries, {"k1": "not bytes"}).ok
    assert not verify_chain(entries, {"k1": b""}).ok  # a short key is an unknown key


def test_short_key_cannot_seal() -> None:
    with pytest.raises(ValueError):
        seal_core({"seq": 0}, b"")


def test_producer_must_be_stamped_by_the_writer() -> None:
    with pytest.raises(TypeError):
        append_entry(None, {"v": 1}, KEY, writer_key_id="k1")  # type: ignore[call-arg]


def test_derived_fields_in_a_draft_are_refused() -> None:
    # They would be hashed, overwritten and then stripped at verification: sealed but never verifiable.
    with pytest.raises(ValueError):
        append_entry(None, {"entry_hash": "x"}, KEY, writer_key_id="k1", producer="p")


def test_unterminated_last_line_is_torn() -> None:
    data = b"".join(to_jsonl_line(e) for e in _chain(2))
    result = verify_jsonl(data[:-1], {"k1": KEY})
    assert (result.ok, result.last_seq) == (False, 0)


def test_a_failing_keyring_raises_instead_of_reporting_tampering() -> None:
    class FailingKeyring(dict):
        def get(self, key, default=None):  # noqa: ANN001, ANN201
            raise TimeoutError("KMS timeout")

    with pytest.raises(TimeoutError):
        verify_chain(_chain(2), FailingKeyring())


def test_an_unreadable_entries_list_is_a_broken_chain_not_a_crash() -> None:
    class Unreadable(list):
        def __iter__(self):  # noqa: ANN204
            raise RuntimeError("boom")

    result = verify_chain(Unreadable(_chain(1)), {"k1": KEY})
    assert (result.ok, result.last_seq) == (False, -1)


def test_a_short_key_is_unknown_when_verifying_even_if_it_sealed_the_entry() -> None:
    import hashlib
    import hmac

    short = b"k" * 15
    core = {"seq": 0, "prev_hash": "0" * 64, "writer_key_id": "k1"}
    data = canonicalize(core).encode("utf-8")
    entry = {
        **core,
        "entry_hash": hashlib.sha256(data).hexdigest(),
        "entry_hmac": hmac.new(short, data, hashlib.sha256).hexdigest(),
    }
    result = verify_chain([entry], {"k1": short})
    assert not result.ok and "writer_key_id" in (result.error or "")


def test_a_sealed_line_of_exactly_the_size_limit_verifies() -> None:
    from audit_chain import MAX_CANONICAL_BYTES

    base = {"seq": 0, "prev_hash": "0" * 64, "writer_key_id": "k1", "pad": ""}
    overhead = len(to_jsonl_line(seal_core(base, KEY))) - 1
    line = to_jsonl_line(seal_core({**base, "pad": "x" * (MAX_CANONICAL_BYTES - overhead)}, KEY))
    assert len(line) == MAX_CANONICAL_BYTES + 1  # + the line feed
    assert verify_jsonl(line, {"k1": KEY}).ok


def test_a_16_byte_key_seals_and_verifies_and_15_is_refused() -> None:
    from audit_chain import MIN_KEY_BYTES

    assert MIN_KEY_BYTES == 16
    k16 = b"k" * 16
    entry = append_entry(None, {"v": 1}, k16, writer_key_id="k16", producer="p")
    assert verify_chain([entry], {"k16": k16}).ok
    with pytest.raises(ValueError):
        seal_core({"seq": 0}, b"k" * 15)


def test_prune_none_drops_none_members_deeply_but_keeps_none_in_lists() -> None:
    from audit_chain import prune_none

    assert prune_none({"a": None, "b": {"c": None, "d": 1}, "e": [None, {"f": None}]}) == {
        "b": {"d": 1},
        "e": [None, {}],
    }
    entry = append_entry(None, {"v": 1, "gone": None, "kept": [None]}, KEY, writer_key_id="k1", producer="p")
    assert "gone" not in entry and entry["kept"] == [None]


def test_to_jsonl_line_is_exactly_utf8_canonical_plus_lf() -> None:
    note = "a+b " + chr(0xE9) + chr(0x1F600)
    entry = append_entry(None, {"v": 1, "note": note}, KEY, writer_key_id="k1", producer="p")
    assert to_jsonl_line(entry) == canonicalize(entry).encode("utf-8") + b"\n"
    assert b"a+b" in to_jsonl_line(entry) and chr(0x1F600).encode("utf-8") in to_jsonl_line(entry)


@pytest.mark.parametrize("entries", [{}, "", None, 0, ("x",)])
def test_non_list_entries_are_a_broken_chain(entries: object) -> None:
    result = verify_chain(entries, {"k1": KEY})
    assert (result.ok, result.last_seq) == (False, -1)


def test_parse_jsonl_reports_the_bad_line_and_only_the_entries_before_it() -> None:
    good = b"".join(to_jsonl_line(e) for e in _chain(2))
    parsed = parse_jsonl(good + b'{"not":"canonical" }\n' + good)
    assert parsed.bad_line == 2 and parsed.entries == _chain(2) and parsed.reason


@pytest.mark.parametrize("data", [3, "text", memoryview(b"{}\n"), None])
def test_parse_jsonl_requires_bytes(data: object) -> None:
    with pytest.raises(TypeError):
        parse_jsonl(data)  # type: ignore[arg-type]


def test_a_line_outside_the_canonical_domain_is_bad_with_no_entry() -> None:
    good = to_jsonl_line(_chain(1)[0])
    parsed = parse_jsonl(good + b"[1.5]\n")
    assert parsed.bad_line == 1 and len(parsed.entries) == 1


@pytest.mark.parametrize("v", _VEC["jsonl_size_vectors"], ids=[v["name"] for v in _VEC["jsonl_size_vectors"]])
def test_jsonl_size_vectors(v: dict) -> None:
    # Two cases: the generated file (expect), and its parsed lines as a chain (value_expect).
    for c in size_vector_cases(v):
        assert mismatches(c, _VEC["derivations"], KEYRING) == []
