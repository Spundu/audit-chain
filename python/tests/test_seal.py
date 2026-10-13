"""Audit chain: seal byte-identical to TS (cross-language vectors) + tamper detection."""
from __future__ import annotations

import json
import pathlib

import pytest
from _derivations import derived_cases, mismatches, size_vector_cases

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
