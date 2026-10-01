"""The spec's derivation rules (vectors/audit-seal-vectors.json, `derivations`), implemented here
independently of the TypeScript generator (scripts/audit-vectors/derive.mts). Every harness derives these
cases from each base case; a conformant verifier must pass them too.

A case is a verify vector (`chain`), a JSONL vector (`data`, its bytes), or a size vector read as both (its
file with `expect`, its parsed lines as a chain with `value_expect`). A case has `entry_failure` when it is
a base case with ok false and no anchor, or any derived case. The rules apply to every base case and to the
cases they derive, each rule at most once on a derivation path, up to `max_depth` rules deep:

forged_first    ok false, last_seq >= 0: entry 0 replaced by `later_entry` (line 0 by later_lines_hex[0]).
                Expect ok false, last_seq -1.
later_failure   entry_failure: append `later_entry` (a chain that is a list) or each of `later_lines_hex`.
                Expect unchanged.
ignored_anchor  entry_failure and no anchor: verify with each of `ignored_anchors`. Expect unchanged.
tail_failure    ok true, n = last_seq + 1: append `later_entry`, the last entry, entry 0, the whole chain
                (a file: each later and inserted line, the last line, line 0, the whole file; copies only
                when n >= 1). Expect ok false, last_seq n - 1, as given and, without an anchor, under the
                TRUE anchor {count: n, last_hash: the last entry_hash, or genesis_hash}.
head_replay     ok true, n >= 1: a copy of entry 0 (line 0) inserted at index 1; for a file, also each of
                `inserted_lines_hex` inserted at index 1. Expect ok false, last_seq 0.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from audit_chain import ChainAnchor, verify_chain, verify_jsonl

Case = dict[str, Any]
Rule = Callable[[Case, bool, dict[str, Any]], list[tuple[str, Case]]]

_LF = bytes([10])
_BROKEN_AT_0 = {"ok": False, "last_seq": -1}


def _lines(data: bytes) -> tuple[list[bytes], bytes]:
    """The complete lines of a file (without their line feeds), and whatever follows the last line feed."""
    *lines, rest = data.split(_LF)
    return lines, rest


def _forged_first(c: Case, _entry_failure: bool, d: dict[str, Any]) -> list[tuple[str, Case]]:
    if c["expect"]["ok"] or c["expect"]["last_seq"] < 0:
        return []
    if "data" in c:
        lines, rest = _lines(c["data"])
        data = bytes.fromhex(d["later_lines_hex"][0]) + b"".join(line + _LF for line in lines[1:]) + rest
        return [("forged-first", {**c, "data": data, "expect": _BROKEN_AT_0})]
    return [("forged-first", {**c, "chain": [d["later_entry"], *c["chain"][1:]], "expect": _BROKEN_AT_0})]


def _later_failure(c: Case, entry_failure: bool, d: dict[str, Any]) -> list[tuple[str, Case]]:
    if not entry_failure:
        return []
    if "data" in c:
        return [
            (f"later-line-{i}", {**c, "data": c["data"] + bytes.fromhex(h)})
            for i, h in enumerate(d["later_lines_hex"])
        ]
    if not isinstance(c["chain"], list):
        return []
    return [("later-entry", {**c, "chain": [*c["chain"], d["later_entry"]]})]


def _ignored_anchor(c: Case, entry_failure: bool, d: dict[str, Any]) -> list[tuple[str, Case]]:
    if not entry_failure or "anchor" in c:
        return []
    return [(f"ignored-anchor-{i}", {**c, "anchor": a}) for i, a in enumerate(d["ignored_anchors"])]


def _tail_failure(c: Case, _entry_failure: bool, d: dict[str, Any]) -> list[tuple[str, Case]]:
    if not c["expect"]["ok"]:
        return []
    n = c["expect"]["last_seq"] + 1
    expect = {"ok": False, "last_seq": n - 1}
    tails: list[tuple[str, Case]]
    if "data" in c:
        data: bytes = c["data"]
        lines, _ = _lines(data)
        head = d["genesis_hash"] if n == 0 else json.loads(lines[n - 1])["entry_hash"]
        more = [(f"later-line-{i}", bytes.fromhex(h)) for i, h in enumerate(d["later_lines_hex"])]
        more += [(f"inserted-line-{i}", bytes.fromhex(h)) for i, h in enumerate(d["inserted_lines_hex"])]
        if n >= 1:
            last, first = lines[n - 1] + _LF, lines[0] + _LF
            more += [("last-line-again", last), ("line-0-again", first), ("whole-file-again", data)]
        tails = [(label, {**c, "data": data + extra, "expect": expect}) for label, extra in more]
    else:
        chain: list[Any] = c["chain"]
        head = d["genesis_hash"] if n == 0 else chain[n - 1]["entry_hash"]
        entries = [("later-entry", [d["later_entry"]])]
        if n >= 1:
            entries += [
                ("last-entry-again", [chain[n - 1]]),
                ("entry-0-again", [chain[0]]),
                ("whole-chain-again", chain),
            ]
        tails = [(label, {**c, "chain": [*chain, *extra], "expect": expect}) for label, extra in entries]
    out: list[tuple[str, Case]] = []
    for label, t in tails:
        out.append((f"tail-{label}", t))
        if "anchor" not in c:
            out.append((f"tail-{label}-true-anchor", {**t, "anchor": {"count": n, "last_hash": head}}))
    return out


def _head_replay(c: Case, _entry_failure: bool, d: dict[str, Any]) -> list[tuple[str, Case]]:
    if not c["expect"]["ok"] or c["expect"]["last_seq"] < 0:
        return []
    expect = {"ok": False, "last_seq": 0}
    if "data" in c:
        data: bytes = c["data"]
        line0 = data[: data.index(_LF) + 1]
        after = data[len(line0) :]
        inserted = [("head-replay", line0)]
        for i, h in enumerate(d["inserted_lines_hex"]):
            inserted.append((f"head-inserted-line-{i}", bytes.fromhex(h)))
        return [(name, {**c, "data": line0 + extra + after, "expect": expect}) for name, extra in inserted]
    return [("head-replay", {**c, "chain": [c["chain"][0], *c["chain"]], "expect": expect})]


_RULES: list[tuple[str, Rule]] = [
    ("forged_first", _forged_first),
    ("later_failure", _later_failure),
    ("ignored_anchor", _ignored_anchor),
    ("tail_failure", _tail_failure),
    ("head_replay", _head_replay),
]


def derived_cases(base: Case, d: dict[str, Any]) -> list[Case]:
    """Every case derived from `base` (not including `base` itself)."""
    out: list[Case] = []
    frontier = [(base, frozenset[str](), not base["expect"]["ok"] and "anchor" not in base)]
    for _ in range(d["max_depth"]):
        following = []
        for c, applied, entry_failure in frontier:
            for rule_name, rule in _RULES:
                if rule_name in applied:
                    continue
                for suffix, child in rule(c, entry_failure, d):
                    derived = {**child, "name": f"{c['name']}/{suffix}"}
                    out.append(derived)
                    following.append((derived, applied | {rule_name}, True))
        frontier = following
    return out


def size_vector_cases(v: dict[str, Any]) -> list[Case]:
    """A size vector read as the two cases it is: the generated file, and the chain of its parsed lines."""
    data = (v["prefix"] + v["unit"] * v["count"] + v["suffix"]).encode("utf-8")
    chain = [json.loads(line) for line in data.split(_LF)[:-1]]
    return [
        {"name": v["name"], "data": data, "expect": v["expect"]},
        {"name": f"{v['name']} (value level)", "chain": chain, "expect": v["value_expect"]},
    ]


def mismatches(base: Case, d: dict[str, Any], default_keyring: dict[str, bytes]) -> list[str]:
    """Every case (the base and each derived case) whose verdict differs from its expectation."""
    out: list[str] = []
    for c in [base, *derived_cases(base, d)]:
        a = c.get("anchor")
        anchor = ChainAnchor(a.get("count"), a.get("last_hash")) if a is not None else None  # absent -> None
        ring = {k: bytes.fromhex(h) for k, h in c["keyring"].items()} if "keyring" in c else default_keyring
        if "data" in c:
            result = verify_jsonl(c["data"], ring, anchor)
        else:
            result = verify_chain(c["chain"], ring, anchor)
        if {"ok": result.ok, "last_seq": result.last_seq} != c["expect"]:
            out.append(f"{c['name']}: got ({result.ok}, {result.last_seq}), want {c['expect']}")
    return out
