"""Prefix filter and fast Japanese name windows.

Every candidate is first checked against a confidential prefix filter that
the registry gives participating providers. Japanese text yields about four
name windows (3-10 characters inside kana/kanji runs) per character, so this
check is the hot loop.

  * Name tokens (n:) use an unkeyed polynomial hash finished with the
    splitmix64 mixer. It is computed for every window of a text at once with
    numpy (about 60 vector operations per text, not 4 Python calls per
    character). A pure-Python fallback gives identical values.
  * Other tokens (e:, p:, t:, a:, r:) are few; they keep a SHA-256 prefix.
  * PREFIX_BITS is 32 (24 in v0.4). With 1,000 canaries registered, a
    24-bit filter sent about 1,600 false-positive lookups per million
    Japanese characters to the registry; 32 bits cuts that by 256x. A leaked
    filter is an oracle either way (see README), so the wider prefix costs
    nothing that was not already lost.
"""
from __future__ import annotations

import hashlib

from .tokens import NAME_MAX, NAME_MIN

try:
    import numpy as np
except ImportError:          # pragma: no cover - exercised by forcing HAVE_NUMPY = False
    np = None

HAVE_NUMPY = np is not None
PREFIX_BITS = 32
_M = (1 << 64) - 1
_BASE = 0x100000001B3                       # FNV-64 prime: odd, large
_SEED = 0x6A09E667F3BCC909                  # SHA-512 IV word, any constant works
_SEED_L = [((_SEED + L) * pow(_BASE, L, 1 << 64)) & _M for L in range(NAME_MAX + 1)]
_CJK_RANGES = ((0x3040, 0x30FF), (0x3400, 0x9FFF), (0x3005, 0x3005))


def _mix(z: int) -> int:
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _M
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _M
    return z ^ (z >> 31)


def name_prefix(s: str) -> int:
    h = (_SEED + len(s)) & _M
    for ch in s:
        h = (h * _BASE + ord(ch)) & _M
    return _mix(h) >> (64 - PREFIX_BITS)


def prefix(token: str) -> int:
    if token.startswith("n:"):
        return name_prefix(token[2:])
    d = hashlib.sha256(b"shinafure-v1|P|" + token.encode()).digest()
    return int.from_bytes(d[:8], "big") >> (64 - PREFIX_BITS)


def other_hits(tokens, filt: frozenset[int]) -> set[str]:
    """Non-name tokens whose prefix is in the filter (same value as prefix())."""
    sha, pfx, fb, shift = hashlib.sha256, b"shinafure-v1|P|", int.from_bytes, 64 - PREFIX_BITS
    return {t for t in set(tokens) if (fb(sha(pfx + t.encode()).digest()[:8], "big") >> shift) in filt}


def _is_cjk(ch: str) -> bool:
    o = ord(ch)
    return any(a <= o <= b for a, b in _CJK_RANGES)


# ------------------------------------------------------------ name windows
def name_window_hits_py(joined: str, filt: frozenset[int]) -> tuple[int, list[str]]:
    """Reference implementation: every window of 3..10 kana/kanji, as
    tokens.candidates() yields them. Returns (number of windows, windows
    whose prefix is in the filter)."""
    count, hits, n = 0, [], len(joined)
    shift = 64 - PREFIX_BITS
    for i in range(n):
        if not _is_cjk(joined[i]):
            continue
        poly = 0
        for L in range(1, NAME_MAX + 1):
            j = i + L - 1
            if j >= n or not _is_cjk(joined[j]):
                break
            poly = (poly * _BASE + ord(joined[j])) & _M
            if L >= NAME_MIN:
                count += 1
                if (_mix((poly + _SEED_L[L]) & _M) >> shift) in filt:
                    hits.append(joined[i:i + L])
    return count, hits


if HAVE_NUMPY:
    _U = np.uint64

    def _mix_np(z):
        z = (z ^ (z >> _U(30))) * _U(0xBF58476D1CE4E5B9)
        z = (z ^ (z >> _U(27))) * _U(0x94D049BB133111EB)
        return z ^ (z >> _U(31))

    def name_window_hits_np(joined: str, filt_sorted) -> tuple[int, list[str]]:
        n = len(joined)
        if n < NAME_MIN:
            return 0, []
        c32 = np.frombuffer(joined.encode("utf-32-le"), dtype=np.uint32)
        cjk = np.zeros(n, dtype=bool)
        for a, b in _CJK_RANGES:
            cjk |= (c32 >= a) & (c32 <= b)
        if not cjk.any():
            return 0, []
        bad = np.concatenate(([0], np.cumsum(~cjk, dtype=np.int64)))   # non-CJK count in c[:i]
        c = c32.astype(np.uint64)
        h = np.zeros(n, dtype=np.uint64)
        base, shift = _U(_BASE), _U(64 - PREFIX_BITS)
        count, hits = 0, []
        with np.errstate(over="ignore"):
            for L in range(1, NAME_MAX + 1):
                m = n - L + 1
                if m <= 0:
                    break
                h = h[:m] * base + c[L - 1:L - 1 + m]
                if L < NAME_MIN:
                    continue
                idx = np.flatnonzero(bad[L:L + m] == bad[:m])           # window entirely kana/kanji
                if idx.size == 0:
                    continue
                count += int(idx.size)
                pf = _mix_np(h[idx] + _U(_SEED_L[L])) >> shift
                pos = np.searchsorted(filt_sorted, pf)
                pos[pos == filt_sorted.size] = 0
                for i in idx[filt_sorted[pos] == pf].tolist() if filt_sorted.size else ():
                    hits.append(joined[i:i + L])
        return count, hits


class PrefixFilter:
    """The provider's copy of the registry's prefix filter."""

    def __init__(self, prefixes) -> None:
        self.set = frozenset(prefixes)
        self.sorted = np.array(sorted(self.set), dtype=np.uint64) if HAVE_NUMPY else None

    def __contains__(self, p: int) -> bool:
        return p in self.set

    def name_hits(self, joined: str, use_numpy: bool = True) -> tuple[int, list[str]]:
        if use_numpy and HAVE_NUMPY:
            return name_window_hits_np(joined, self.sorted)
        return name_window_hits_py(joined, self.set)
