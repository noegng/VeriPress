"""Aggregated anchoring, XRPL side (interfaces.md § Ancrage groupé) — OWNER: Dev B.
Offline: the batch memo shape {"b": root, "n": count} next to the three per-photo shapes."""

import pytest

from veripress.ledger import XrplLedger, _anchor_from_memo

TX = "AB" * 32
ROOT = "5f" * 32


def test_batch_memo_gives_root_and_size():
    a = _anchor_from_memo({"b": ROOT, "n": 3}, TX, 1_795_000_000)
    assert (a.digest, a.batch_size, a.signature, a.pubkey) == (ROOT, 3, "", "")
    assert not a.anonymous and a.timestamp == 1_795_000_000


@pytest.mark.parametrize("n", [0, -2, "x", None, [3]])
def test_batch_memo_with_a_bad_count_is_ignored(n):
    assert _anchor_from_memo({"b": ROOT, "n": n}, TX, 0) is None


def test_per_photo_memos_are_not_batches():
    named = _anchor_from_memo({"d": "aa" * 32, "s": "ff" * 64, "k": "ED" + "11" * 32}, TX, 0)
    anon = _anchor_from_memo({"d": "aa" * 32, "a": 1, "r": "1", "h": "22" * 32}, TX, 0)
    passkey = _anchor_from_memo({"d": "aa" * 32, "k": "ED" + "11" * 32, "w": "33" * 32}, TX, 0)
    assert [x.batch_size for x in (named, anon, passkey)] == [0, 0, 0]


def test_anchor_batch_refuses_an_empty_batch():
    lg = XrplLedger.__new__(XrplLedger)  # fails before any network access
    with pytest.raises(ValueError):
        lg.anchor_batch(ROOT, 0)
