"""Shared fixtures. `work` counts the operations that bound the library's work, so the work-bound tests
assert a DETERMINISTIC bound (independent of machine speed and Python version) instead of wall time."""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterator

import pytest

import audit_chain.canonical as canonical_mod
import audit_chain.jsonl as jsonl_mod


@pytest.fixture
def work(monkeypatch: pytest.MonkeyPatch) -> Iterator[Counter]:
    counts: Counter = Counter()
    charge = canonical_mod._Budget.charge
    parse_line = jsonl_mod._parse_line

    def counting_charge(self, amount: int) -> None:  # noqa: ANN001
        counts["budget_charges"] += 1
        if amount < 1:
            counts["non_positive_charges"] += 1
        charge(self, amount)

    def counting_parse_line(line: bytes):  # noqa: ANN202
        counts["lines_parsed"] += 1
        return parse_line(line)

    monkeypatch.setattr(canonical_mod._Budget, "charge", counting_charge)
    monkeypatch.setattr(jsonl_mod, "_parse_line", counting_parse_line)
    yield counts
    # Every charge must be at least one canonical byte: that is what makes the charge count a bound on
    # the work. Checked here, after the test, because an assertion raised INSIDE canonicalize would be
    # wrapped into the CanonicalizationError the test expects anyway.
    assert counts["non_positive_charges"] == 0, "the budget was charged zero or a negative amount"
