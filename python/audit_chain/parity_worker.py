"""Cross-language parity worker (test harness, not part of the library API).

Reads one JSON request from stdin and writes one JSON response to stdout. Every input is a raw JSON
TEXT (or raw JSONL BYTES), parsed here by Python's own ``json`` module, because that is the real
cross-language situation: a chain written by one implementation and read by the other. The TypeScript
side of the parity suite (``test/parity``) runs the same inputs and compares results byte for byte.

Request (every list optional):
  canonicalize: [json_text, ...]
  verify:       [{"chain": json_text, "keyring": {id: key_hex}, "anchor"?: {"count", "last_hash"}}, ...]
  verify_jsonl: [{"data_hex": hex_bytes, "keyring": {...}, "anchor"?: {...}}, ...]
Response:
  canonicalize: [{"ok": true, "hex": utf8_hex} | {"ok": false, "phase": "parse" | "domain" | "crash"}]
  verify, verify_jsonl: [{"threw": false, "ok": bool, "last_seq": int} | {"threw": true, "error": str}]

Run: python -m audit_chain.parity_worker < request.json
"""
from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import Any

from .canonical import CanonicalizationError, canonicalize
from .jsonl import verify_jsonl
from .verify import ChainAnchor, VerifyResult, verify_chain

Runner = Callable[[dict[str, bytes], ChainAnchor | None], VerifyResult]


def _canonical_hex(text: str) -> dict[str, Any]:
    # A parse failure and a domain rejection are both legitimate refusals. Anything else escaping
    # canonicalize is a crash, which the parity suite always reports.
    try:
        value = json.loads(text)
    except Exception:  # noqa: BLE001 -- JSONDecodeError, int-digit limit, RecursionError: all "not JSON"
        return {"ok": False, "phase": "parse"}
    try:
        return {"ok": True, "hex": canonicalize(value).encode("utf-8").hex()}
    except CanonicalizationError as exc:
        # canonicalize wraps an unreadable value as CanonicalizationError FROM another exception.
        # Nothing json.loads produces is unreadable, so here a cause means a crash, not a refusal.
        if exc.__cause__ is None:
            return {"ok": False, "phase": "domain"}
        return {"ok": False, "phase": "crash", "error": f"wrapped {type(exc.__cause__).__name__}"}
    except Exception as exc:  # noqa: BLE001 -- report, never crash the worker
        return {"ok": False, "phase": "crash", "error": f"{type(exc).__name__}: {exc}"}


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
    response = {
        "canonicalize": [_canonical_hex(t) for t in request.get("canonicalize", [])],
        "verify": [_verdict(c, _chain_runner(c)) for c in request.get("verify", [])],
        "verify_jsonl": [_verdict(c, _jsonl_runner(c)) for c in request.get("verify_jsonl", [])],
    }
    # ensure_ascii: the envelope must survive any content (incl. lone surrogates) as plain ASCII.
    sys.stdout.write(json.dumps(response, ensure_ascii=True))


if __name__ == "__main__":
    main()
