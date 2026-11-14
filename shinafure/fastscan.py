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
  * PREFIX_BITS is 48 (24 in v0.4, 32 in v0.5-v1.0). Japanese text yields
    about 3.3 million distinct name windows per million characters, so the
    false-positive lookups per million characters are about
    3.3e6 x tokens / 2^bits. With 8 million registered tokens (a million
    canaries) that was 6,000 at 32 bits, and is under 0.1 at 48. A leaked
    filter is an oracle either way (see README), so the wider prefix costs
    nothing that was not already lost.
  * The provider keeps the filter and the F list as sorted numpy arrays
    (8 bytes per entry), not Python sets.
"""
from __future__ import annotations

import hashlib

from .tokens import NAME_MAX, NAME_MIN

try:
    import numpy as np
except ImportError:          # pragma: no cover - exercised by forcing HAVE_NUMPY = False
    np = None

HAVE_NUMPY = np is not None
PREFIX_BITS = 48
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


def other_hits(tokens, filt) -> set[str]:
    """Non-name tokens whose prefix is in the filter (same value as prefix())."""
    sha, pfx, fb, shift = hashlib.sha256, b"shinafure-v1|P|", int.from_bytes, 64 - PREFIX_BITS
    uniq = list(set(tokens))
    pfs = [fb(sha(pfx + t.encode()).digest()[:8], "big") >> shift for t in uniq]
    if isinstance(filt, PrefixFilter):
        return {t for t, ok in zip(uniq, filt.contains_many(pfs)) if ok}
    return {t for t, p in zip(uniq, pfs) if p in filt}


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


def _sorted_u64(values):
    a = np.fromiter(values, dtype=np.uint64)
    a.sort()
    return np.unique(a)


def _in_sorted(a, xs) -> "np.ndarray":
    if a.size == 0:
        return np.zeros(len(xs), dtype=bool)
    x = np.asarray(xs, dtype=np.uint64)
    pos = np.searchsorted(a, x)
    pos[pos == a.size] = 0
    return a[pos] == x


class PrefixFilter:
    """The provider's copy of the registry's prefix filter."""

    def __init__(self, prefixes) -> None:
        if HAVE_NUMPY:
            self.sorted, self._set = _sorted_u64(prefixes), None
        else:
            self.sorted, self._set = None, frozenset(prefixes)

    @property
    def set(self) -> frozenset[int]:          # pure-Python paths and tests
        if self._set is None:
            self._set = frozenset(int(x) for x in self.sorted)
        return self._set

    def __contains__(self, p: int) -> bool:
        if self.sorted is not None:
            return bool(_in_sorted(self.sorted, [p])[0])
        return p in self._set

    def contains_many(self, ps) -> list[bool]:
        if self.sorted is not None:
            return _in_sorted(self.sorted, ps).tolist() if ps else []
        return [p in self._set for p in ps]

    def name_hits(self, joined: str, use_numpy: bool = True) -> tuple[int, list[str]]:
        if use_numpy and HAVE_NUMPY:
            return name_window_hits_np(joined, self.sorted)
        return name_window_hits_py(joined, self.set)


class FValueSet:
    """The provider's copy of the registered F values: the first 8 bytes of
    each, sorted. A false match (about tokens / 2^64) only costs one lookup,
    which then returns nothing."""

    def __init__(self, fs) -> None:
        self._np = HAVE_NUMPY
        keys = (int.from_bytes(f[:8], "big") for f in fs)
        self._a = _sorted_u64(keys) if self._np else frozenset(keys)

    def __contains__(self, f: bytes) -> bool:
        k = int.from_bytes(f[:8], "big")
        return bool(_in_sorted(self._a, [k])[0]) if self._np else k in self._a

    def __len__(self) -> int:
        return len(self._a)
