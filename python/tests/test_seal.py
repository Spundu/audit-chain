"""Audit chain: seal byte-identical to TS (cross-language vectors) + tamper detection."""
from __future__ import annotations

import hashlib
import hmac
import json
import pathlib
from typing import Any

import pytest
from _derivations import derived_cases, mismatches, size_vector_cases

from audit_chain.canonical import MAX_DEPTH, CanonicalizationError
from audit_chain.seal import GENESIS_HASH, append_entry, seal_core
from audit_chain.verify import verify_chain

_REPO = pathlib.Path(__file__).resolve().parents[2]
_VEC = json.loads(
    (_REPO / "vectors" / "audit-seal-vectors.json").read_text(encoding="utf-8")
)
KEY = bytes.fromhex(_VEC["key_hex"])
KEYRING = {_VEC["key_id"]: KEY}


def test_seal_matches_cross_language_vectors() -> None:
    assert _VEC["vectors"], "run: npm run vectors"
    for v in _VEC["vectors"]:
        sealed = seal_core(v["core"], KEY)
        assert sealed["entry_hash"] == v["entry_hash"], v["name"]
        assert sealed["entry_hmac"] == v["entry_hmac"], v["name"]


# Every value the JCS vectors accept, with the canonical text they pin for it: seal_core must hash exactly
# those bytes. The expected bytes are built from the pinned text, never from canonicalize(), so a sealer
# that serializes any other way (json.dumps with sort_keys, say: code-point key order, "1.0") fails here.
_JCS = json.loads((_REPO / "vectors" / "jcs-vectors.json").read_text(encoding="utf-8"))
_SEALABLE = [
    *[(f"value:{v['name']}", v["value"], v["expected_canonical"]) for v in _JCS["vectors"]],
    *[
        (f"text:{v['name']}", json.loads(v["json_text"]), v["expected_canonical"])
        for v in _JCS["text_vectors"]
        if v["expected_canonical"] is not None
    ],
]


def _container_depth(value: Any) -> int:
    """How many lists/dicts are nested inside each other: 0 for a scalar, 1 for [] or {}."""
    depth, level = 0, [value]
    while containers := [v for v in level if isinstance(v, dict | list)]:
        depth += 1
        level = [c for v in containers for c in (v.values() if isinstance(v, dict) else v)]
    return depth


@pytest.mark.parametrize(("name", "value", "canonical"), _SEALABLE, ids=[n for n, _, _ in _SEALABLE])
def test_seal_core_seals_exactly_the_canonical_bytes(name: str, value: Any, canonical: str) -> None:
    core = {"payload": value, "prev_hash": GENESIS_HASH, "seq": 0, "writer_key_id": "k1"}
    if 1 + _container_depth(value) > MAX_DEPTH:  # the core object adds one level of nesting
        with pytest.raises(CanonicalizationError):
            seal_core(core, KEY)
        return
    expected = f'{{"payload":{canonical},"prev_hash":"{GENESIS_HASH}","seq":0,"writer_key_id":"k1"}}'.encode()
    sealed = seal_core(core, KEY)
    assert sealed["entry_hash"] == hashlib.sha256(expected).hexdigest(), name
    assert sealed["entry_hmac"] == hmac.new(KEY, expected, hashlib.sha256).hexdigest(), name


def test_the_sealable_set_reaches_the_cases_a_naive_sealer_gets_wrong() -> None:
    texts = [c for _, _, c in _SEALABLE]
    assert any(c.startswith("[1,100,") for c in texts)  # integral floats (1.0, 1e2) seal as integers
    assert any(chr(0xD83D) in c or chr(0x1F600) in c for c in texts)  # astral keys: UTF-16 order
    assert sum(1 + _container_depth(v) > MAX_DEPTH for _, v, _ in _SEALABLE) >= 1  # the depth edge


def test_the_verify_vector_set_is_non_empty() -> None:
    assert _VEC["verify_vectors"], "run: npm run vectors"


def test_derives_exactly_case_count_cases() -> None:
    # Base and derived: a harness that skips a rule reaches fewer cases than the vector file says.
    files = [{**v, "data": bytes.fromhex(v["data_hex"])} for v in _VEC["jsonl_vectors"]]
    sizes = [c for v in _VEC["jsonl_size_vectors"] for c in size_vector_cases(v)]
    bases = [*_VEC["verify_vectors"], *files, *sizes]
    assert sum(1 + len(derived_cases(c, _VEC["derivations"])) for c in bases) == _VEC["case_count"]


# Shared with test/audit-seal-vectors.test.ts: same verdict as TS, never an exception, on every vector AND
# every case the spec derives from it (vectors/audit-seal-vectors.json: derivations).
@pytest.mark.parametrize("v", _VEC["verify_vectors"], ids=[v["name"] for v in _VEC["verify_vectors"]])
def test_verify_matches_cross_language_verify_vectors(v: dict) -> None:
    assert mismatches(v, _VEC["derivations"], KEYRING) == []


def _build_chain(n: int = 3) -> list[dict]:
    entries: list[dict] = []
    prev: dict | None = None
    for i in range(n):
        draft = {"v": 1, "event": "payment.approval", "request_id": f"r{i}", "request_hash": "a" * 64}
        entry = append_entry(prev, draft, KEY, writer_key_id=_VEC["key_id"])
        entries.append(entry)
        prev = entry
    return entries


def test_append_entry_builds_a_verifiable_chain() -> None:
    entries = _build_chain()
    assert entries[0]["seq"] == 0 and entries[0]["prev_hash"] == GENESIS_HASH
    assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
    result = verify_chain(entries, KEYRING)
    assert result.ok and result.last_seq == 2


def test_verify_detects_content_tamper() -> None:
    entries = _build_chain()
    entries[1] = {**entries[1], "request_id": "TAMPERED"}  # changed content, stale entry_hash
    result = verify_chain(entries, KEYRING)
    assert not result.ok and "entry_hash" in (result.error or "")


def test_verify_detects_forgery_without_the_key() -> None:
    entries = _build_chain()
    core = {k: v for k, v in entries[1].items() if k not in ("entry_hash", "entry_hmac")}
    entries[1] = seal_core(core, bytes.fromhex("ff" * 32))  # valid hash, hmac under a wrong key
    result = verify_chain(entries, KEYRING)
    assert not result.ok and "entry_hmac" in (result.error or "")


def test_verify_detects_middle_delete() -> None:
    entries = _build_chain()
    del entries[1]  # seq jumps 0 -> 2
    assert not verify_chain(entries, KEYRING).ok


def test_verify_detects_reorder() -> None:
    entries = _build_chain()
    entries[1], entries[2] = entries[2], entries[1]
    assert not verify_chain(entries, KEYRING).ok


def test_unknown_writer_key_is_rejected() -> None:
    entries = _build_chain()
    result = verify_chain(entries, {})
    assert not result.ok and "writer_key_id" in (result.error or "")


def test_verify_fails_closed_on_non_ascii_entry_hmac() -> None:
    # hmac.compare_digest raises TypeError on a non-ASCII str; a forged entry must yield a normal
    # failed VerifyResult, never an exception (same contract as the TS verifier).
    entries = _build_chain()
    entries[1] = {**entries[1], "entry_hmac": "é" * 64}
    result = verify_chain(entries, KEYRING)
    assert not result.ok and "entry_hmac" in (result.error or "")


def test_verify_rejects_uppercase_entry_hmac() -> None:
    # The seal only emits lowercase hex; TS and Python must agree that any other spelling is a mismatch.
    entries = _build_chain()
    entries[1] = {**entries[1], "entry_hmac": entries[1]["entry_hmac"].upper()}
    assert not verify_chain(entries, KEYRING).ok


# -- what append_entry refuses, exactly as TypeScript's appendEntry does ------------------------------

_HEAD = {"seq": 0, "entry_hash": "a" * 64}
KEYRING_K1 = {"k1": KEY}


@pytest.mark.parametrize(
    "prev",
    [
        {**_HEAD, "seq": "0"},  # a BIGINT read back as a string
        {**_HEAD, "seq": None},
        {**_HEAD, "seq": 0.5},
        {**_HEAD, "seq": -1},
        {**_HEAD, "seq": True},
        {**_HEAD, "seq": 2**53},
        {"seq": 0},
        {**_HEAD, "entry_hash": "A" * 64},
        {**_HEAD, "entry_hash": "a" * 63},
        "head",
        7,
    ],
)
def test_a_prev_that_could_only_lead_to_a_broken_chain_is_a_type_error(prev: object) -> None:
    with pytest.raises(TypeError):
        append_entry(prev, {"v": 1}, KEY, writer_key_id="k1")  # type: ignore[arg-type]


def test_a_row_read_back_from_a_database_works_as_prev() -> None:
    import sqlite3

    first = append_entry(None, {"v": 1}, KEY, writer_key_id="k1")
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("CREATE TABLE audit (seq INTEGER, entry_hash TEXT)")
    db.execute("INSERT INTO audit VALUES (?, ?)", (first["seq"], first["entry_hash"]))
    row = db.execute("SELECT seq, entry_hash FROM audit").fetchone()
    second = append_entry(row, {"v": 2}, KEY, writer_key_id="k1")
    assert verify_chain([first, second], KEYRING_K1).ok


def test_a_whole_float_seq_counts_as_that_integer_as_in_typescript() -> None:
    entry = append_entry({"seq": 1.0, "entry_hash": "a" * 64}, {"v": 1}, KEY, writer_key_id="k1")
    assert entry["seq"] == 2 and type(entry["seq"]) is int


def test_the_writer_key_id_must_be_a_str() -> None:
    with pytest.raises(TypeError):
        append_entry(None, {"v": 1}, KEY, writer_key_id=1)  # type: ignore[arg-type]


@pytest.mark.parametrize("draft", [[("v", 1)], "v", 7, None])
def test_a_draft_that_is_not_a_mapping_is_a_type_error(draft: object) -> None:
    with pytest.raises(TypeError):
        append_entry(None, draft, KEY, writer_key_id="k1")  # type: ignore[arg-type]


def test_seal_core_wants_a_dict() -> None:
    with pytest.raises(TypeError):
        seal_core([("seq", 0)], KEY)  # type: ignore[arg-type]
