"""Canonical-domain unit tests for inputs no JSON vector can carry (Python-only types)."""
from __future__ import annotations

from collections import OrderedDict
from decimal import Decimal

import pytest

from audit_chain.canonical import MAX_DEPTH, CanonicalizationError, canonicalize


def test_integer_like_keys_sort_as_strings() -> None:
    assert canonicalize({"9": "a", "10": "b", "x": "c"}) == '{"10":"b","9":"a","x":"c"}'


def test_integral_float_is_the_integer() -> None:
    # JSON.parse cannot tell 1.0 from 1, so neither may we.
    assert canonicalize([1.0, -0.0, 1e2]) == "[1,0,100]"


def test_surrogate_pair_code_points_combine_like_js() -> None:
    # A Python str holding the two UTF-16 halves of U+1F600 is the same string JavaScript sees.
    halves = chr(0xD83D) + chr(0xDE00)
    assert len(halves) == 2
    assert canonicalize(halves) == canonicalize(chr(0x1F600)) == '"' + chr(0x1F600) + '"'


def test_dict_subclasses_are_objects() -> None:
    assert canonicalize(OrderedDict([("b", 1), ("a", 2)])) == '{"a":2,"b":1}'


@pytest.mark.parametrize(
    "value",
    [
        1.5,
        float("nan"),
        float("inf"),
        2**53,
        -(2**53),
        "\ud800",
        {"\udc00": 1},
        {1: "non-str key"},
        (1, 2),
        {1, 2},
        b"bytes",
        Decimal("1"),
        object(),
    ],
    ids=repr,
)
def test_rejects_outside_the_domain(value: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize(value)


def test_nesting_limit() -> None:
    def nest(n: int) -> object:
        return 0 if n == 0 else [nest(n - 1)]

    canonicalize(nest(MAX_DEPTH))
    with pytest.raises(CanonicalizationError):
        canonicalize(nest(MAX_DEPTH + 1))


def test_budget_bounds_shared_reference_trees(work) -> None:  # noqa: ANN001
    empty: list = []
    with pytest.raises(CanonicalizationError):
        canonicalize([empty] * 2_000_000)
    tree: object = []
    for _ in range(60):
        tree = [tree, tree]
    with pytest.raises(CanonicalizationError):
        canonicalize(tree)
    assert work["budget_charges"] <= 2 * 2**20  # each run: at most one charge per canonical byte


def test_seal_refuses_an_entry_whose_stored_line_would_be_too_large() -> None:
    from audit_chain import MAX_CANONICAL_BYTES, seal_core

    core = {"seq": 0, "prev_hash": "0" * 64, "writer_key_id": "k1", "x": "a" * (MAX_CANONICAL_BYTES - 200)}
    canonicalize(core)  # the core alone fits
    with pytest.raises(CanonicalizationError):
        seal_core(core, bytes(32))
