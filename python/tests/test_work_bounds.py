"""The size budget bounds the WORK, not just the result: shared-reference trees whose canonical form
would be astronomically large are refused after a bounded number of operations. The `work` fixture
(conftest.py) counts those operations, so each bound is deterministic, not a wall-clock guess."""
from __future__ import annotations

import time

import pytest

from audit_chain import CanonicalizationError, canonicalize


def test_many_references_to_one_big_string_or_key_are_rejected_fast(work) -> None:  # noqa: ANN001
    big = "x" * 1_000_000
    start = time.monotonic()
    with pytest.raises(CanonicalizationError):
        canonicalize([big] * 5000)
    with pytest.raises(CanonicalizationError):
        canonicalize([{big: 1}] * 5000)
    assert work["budget_charges"] <= 20  # a few structure charges, then two ~1 MB string charges
    assert time.monotonic() - start < 30  # hang guard only; the bound above is the real check


def test_a_doubling_tree_of_empty_strings_is_rejected_fast(work) -> None:  # noqa: ANN001
    tree: object = ""
    for _ in range(40):
        tree = {"a": tree, "b": [tree, tree]}
    start = time.monotonic()
    with pytest.raises(CanonicalizationError):
        canonicalize(tree)
    assert work["budget_charges"] <= 2**20  # every charge is >= 1 byte: at most one per canonical byte
    assert time.monotonic() - start < 30  # hang guard only; the bound above is the real check


@pytest.mark.parametrize(
    "wrap",
    [
        lambda x: [x, x],
        lambda x: {"k": x, "j": x},
        lambda x: [x, None, True, False, x],
        lambda x: {"a": x, "b": 0, "c": "", "d": x},
        lambda x: [x, [], {}, x],
        lambda x: [x, "", "", x],
    ],
)
def test_the_budget_bounds_work_for_every_construct(wrap, work) -> None:  # noqa: ANN001
    tree: object = 0
    for _ in range(40):
        tree = wrap(tree)
    start = time.monotonic()
    with pytest.raises(CanonicalizationError):
        canonicalize(tree)
    assert work["budget_charges"] <= 2**20  # every charge is >= 1 byte: at most one per canonical byte
    assert time.monotonic() - start < 30  # hang guard only; the bound above is the real check


def test_a_string_dominated_dag_is_bounded(work) -> None:  # noqa: ANN001
    tree: object = ""
    for _ in range(40):
        tree = {"": tree, "a": "", "b": "", "c": [tree, "", ""]}
    with pytest.raises(CanonicalizationError):
        canonicalize(tree)
    assert work["budget_charges"] <= 2**20
