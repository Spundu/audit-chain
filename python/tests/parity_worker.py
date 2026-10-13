"""Cross-language parity worker (test harness: it lives with the tests and never ships in the package).

Reads one JSON request from stdin and writes one JSON response to stdout. Every input is a raw JSON
TEXT (or raw JSONL BYTES), parsed here by Python's own ``json`` module, because that is the real
cross-language situation: a chain written by one implementation and read by the other. The TypeScript
side of the parity suite (``test/parity``) runs the same inputs and compares results byte for byte.

Request (every member optional):
  canonicalize: [json_text, ...]
  seal:         {"key_hex": hex, "writer_key_id": id}: also seal each canonicalize text, as the payload
                of a genesis entry, with seal_core
  append:       {"key_hex": hex, "writer_key_id": id}: also append each canonicalize text that is a JSON
                object, as the record itself, after a genesis entry, with append_entry
  verify:       [{"chain": json_text, "keyring": {id: key_hex}, "anchor"?: {"count", "last_hash"}}, ...]
  verify_jsonl: [{"data_hex": hex_bytes, "keyring": {...}, "anchor"?: {...}}, ...]
Response:
  audit_chain:  the directory audit_chain was imported from, so the parity suite can refuse to compare
                against any copy but this repository's
  canonicalize: [{"ok": true, "hex": utf8_hex} | {"ok": false, "phase": "parse" | "domain" | "crash"}]
  seal, append: [{"ok": true, "entry_hash": hex, "entry_hmac": hex} | {"ok": false, "phase": ...}]
                (append: phase "not-an-object" or "derived-fields" when the text is not a record)
  verify, verify_jsonl: [{"threw": false, "ok": bool, "last_seq": int} | {"threw": true, "error": str}]

Run: python python/tests/parity_worker.py < request.json  (audit_chain installed with pip install -e .)
"""
from __future__ import annotations

import json
import pathlib
import sys
from collections.abc import Callable
from typing import Any

import audit_chain
from audit_chain.canonical import CanonicalizationError, canonicalize
from audit_chain.jsonl import verify_jsonl
from audit_chain.seal import GENESIS_HASH, append_entry, seal_core
from audit_chain.verify import ChainAnchor, VerifyResult, verify_chain

Runner = Callable[[dict[str, bytes], ChainAnchor | None], VerifyResult]


def _outcome(text: str, produce: Callable[[Any], dict[str, Any]]) -> dict[str, Any]:
    # A parse failure and a domain rejection are both legitimate refusals. Anything else escaping
    # canonicalize is a crash, which the parity suite always reports.
    try:
        value = json.loads(text)
    except Exception:  # noqa: BLE001 -- JSONDecodeError, int-digit limit, RecursionError: all "not JSON"
        return {"ok": False, "phase": "parse"}
    try:
        return {"ok": True, **produce(value)}
    except _NotARecord as exc:
        return {"ok": False, "phase": exc.phase}
    except CanonicalizationError as exc:
        # canonicalize wraps an unreadable value as CanonicalizationError FROM another exception.
        # Nothing json.loads produces is unreadable, so here a cause means a crash, not a refusal.
        if exc.__cause__ is None:
            return {"ok": False, "phase": "domain"}
        return {"ok": False, "phase": "crash", "error": f"wrapped {type(exc.__cause__).__name__}"}
    except Exception as exc:  # noqa: BLE001 -- report, never crash the worker
        return {"ok": False, "phase": "crash", "error": f"{type(exc).__name__}: {exc}"}


def _canonical_hex(value: Any) -> dict[str, Any]:
    return {"hex": canonicalize(value).encode("utf-8").hex()}


def _sealer(key: bytes, writer_key_id: str) -> Callable[[Any], dict[str, Any]]:
    # The sealing primitive alone, on any JSON value (nested as a payload); _appender compares the writers.
    def seal(value: Any) -> dict[str, Any]:
        core = {"payload": value, "prev_hash": GENESIS_HASH, "seq": 0, "writer_key_id": writer_key_id}
        sealed = seal_core(core, key)
        return {"entry_hash": sealed["entry_hash"], "entry_hmac": sealed["entry_hmac"]}

    return seal


class _NotARecord(Exception):
    def __init__(self, phase: str) -> None:
        super().__init__(phase)
        self.phase = phase


def _appender(key: bytes, writer_key_id: str) -> Callable[[Any], dict[str, Any]]:
    # The writers themselves: the record is the parsed text, appended after a real previous entry.
    def append(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise _NotARecord("not-an-object")
        if "entry_hash" in value or "entry_hmac" in value:
            raise _NotARecord("derived-fields")  # both writers refuse those; the unit tests cover it
        first = append_entry(None, {"n": 0}, key, writer_key_id=writer_key_id)
        sealed = append_entry(first, value, key, writer_key_id=writer_key_id)
        return {"entry_hash": sealed["entry_hash"], "entry_hmac": sealed["entry_hmac"]}

    return append


def _verdict(case: dict[str, Any], run: Runner) -> dict[str, Any]:
    keyring = {k: bytes.fromhex(v) for k, v in case["keyring"].items()}
    a = case.get("anchor")
    anchor = ChainAnchor(a.get("count"), a.get("last_hash")) if a is not None else None  # absent -> None
    try:
        result = run(keyring, anchor)
    except Exception as exc:  # noqa: BLE001 -- a throw IS the finding; report it, never crash the worker
        return {"threw": True, "error": f"{type(exc).__name__}: {exc}"}
    return {"threw": False, "ok": result.ok, "last_seq": result.last_seq}


def _chain_runner(case: dict[str, Any]) -> Runner:
    return lambda keyring, anchor: verify_chain(json.loads(case["chain"]), keyring, anchor)


def _jsonl_runner(case: dict[str, Any]) -> Runner:
    return lambda keyring, anchor: verify_jsonl(bytes.fromhex(case["data_hex"]), keyring, anchor)


def main() -> None:
    request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    texts = request.get("canonicalize", [])
    seal, append = request.get("seal"), request.get("append")
    sealer = _sealer(bytes.fromhex(seal["key_hex"]), seal["writer_key_id"]) if seal else None
    appender = _appender(bytes.fromhex(append["key_hex"]), append["writer_key_id"]) if append else None
    response = {
        "audit_chain": str(pathlib.Path(audit_chain.__file__).resolve().parent),
        "canonicalize": [_outcome(t, _canonical_hex) for t in texts],
        "seal": [_outcome(t, sealer) for t in texts] if sealer else [],
        "append": [_outcome(t, appender) for t in texts] if appender else [],
        "verify": [_verdict(c, _chain_runner(c)) for c in request.get("verify", [])],
        "verify_jsonl": [_verdict(c, _jsonl_runner(c)) for c in request.get("verify_jsonl", [])],
    }
    # ensure_ascii: the envelope must survive any content (incl. lone surrogates) as plain ASCII.
    sys.stdout.write(json.dumps(response, ensure_ascii=True))


if __name__ == "__main__":
    main()
