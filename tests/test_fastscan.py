"""v0.5: the fast path must give exactly what the reference path gives."""
import random

import pytest

from shinafure import group
from shinafure.canary import make_canaries
from shinafure.fastscan import HAVE_NUMPY, PrefixFilter, name_prefix, name_window_hits_py, prefix
from shinafure.registry import DOMAIN, Detector, Registry, register_canaries
from shinafure.tokens import candidates, name_windows, split_candidates

HIRA = "あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもやゆよらりるれろわをん"
KATA = "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲンー"
KANJI = "佐藤鈴木高橋田中伊藤渡辺山本中村鷲見東海林朔眞瑛璃々東京都港区赤坂市町村丁目番号様"
OTHER = " 　、。,.\n\t-0123456789abcXYZ()（）「」・"


def random_text(rng, n):
    pools = (HIRA, KATA, KANJI, OTHER)
    return "".join(rng.choice(rng.choice(pools)) for _ in range(n))


@pytest.fixture(scope="module")
def texts():
    rng = random.Random(3)
    out = [random_text(rng, rng.randint(0, 400)) for _ in range(60)]
    out += ["", "あ", "ab", "鷲見朔眞", "鷲見 朔眞さん", "ーー々々", "a" * 50, "東京都港区赤坂９丁目１７番３号　鷲見ハイツ５０２"]
    return out


def reference(text):
    return [t[2:] for t in candidates(text) if t.startswith("n:")]


@pytest.mark.skipif(not HAVE_NUMPY, reason="numpy not installed")
def test_numpy_windows_equal_reference(texts):
    rng = random.Random(8)
    for text in texts:
        ref = reference(text)
        _, joined = split_candidates(text)
        picked = set(rng.sample(ref, min(len(ref), 5)))
        filt = PrefixFilter({name_prefix(w) for w in picked} | {rng.getrandbits(32) for _ in range(50)})
        n_np, hits_np = filt.name_hits(joined, use_numpy=True)
        n_py, hits_py = filt.name_hits(joined, use_numpy=False)
        assert n_np == n_py == len(ref)
        assert sorted(hits_np) == sorted(hits_py)
        assert picked <= set(hits_np)                                 # no false negatives
        assert {w for w in ref if name_prefix(w) in filt.set} == set(hits_np)


def test_python_windows_equal_reference(texts):
    for text in texts:
        _, joined = split_candidates(text)
        n, _ = name_window_hits_py(joined, frozenset())
        assert n == len(reference(text)) == sum(1 for _ in name_windows(joined))


def test_prefix_is_32_bits_and_spread():
    vals = [prefix(f"n:{i}鷲見") for i in range(2000)] + [prefix(f"e:{i}@x.example") for i in range(2000)]
    assert all(0 <= v < 2**32 for v in vals)
    assert len(set(vals)) == len(vals)
    assert sum(v >> 31 for v in vals) in range(1800, 2200)        # top bit roughly balanced


@pytest.mark.skipif(group.backend.name != "openssl", reason="cryptography not installed")
def test_openssl_and_pure_backends_agree():
    pure, fast = group.PURE, group.backend
    rng = random.Random(1)
    k = rng.randrange(1, 2**255)
    for i in range(25):
        tok = f"n:{random_text(rng, 6)}{i}"
        hp, hf = pure.hash_x(DOMAIN, tok.encode()), fast.hash_x(DOMAIN, tok.encode())
        assert hp == hf
        want = pure.mul_x(k, hp)
        assert fast.mul_x(k, hf) == want
        # blind on one backend, evaluate on the other, unblind on the first
        for a, b in ((pure, fast), (fast, pure)):
            r, blinded = group.blind(DOMAIN, tok, be=a)
            assert group.unblind_x(r, b.mul_x(k, blinded), be=a) == want


def test_registry_rejects_points_off_the_curve():
    reg = Registry(require_tickets=False)
    from shinafure import ec
    x = next(x for x in range(1, 100) if pow((x**3 + ec.A * x + ec.B) % ec.P, (ec.P - 1) // 2, ec.P) != 1)
    with pytest.raises(ValueError):
        reg.evaluate(x.to_bytes(32, "big"), "x")                     # x with no curve point
    with pytest.raises(ValueError):
        reg.evaluate(b"\x01" * 33, "x")


@pytest.fixture(scope="module")
def world():
    reg = Registry(oprf_per_hour=10**9, require_tickets=False)
    cs = make_canaries(200, "fs", "kanari.example", random.Random(4))
    register_canaries(reg, "acme", cs)
    return reg, cs


def test_numpy_and_python_scans_detect_the_same(world, texts):
    reg, cs = world
    det = Detector(reg, reg.add_provider("p"), "p")
    body = "\n".join(texts[:20])
    planted = body + "\n" + "\n".join(
        f"{c.person['last']}{c.person['first']} {c.person['address']}" for c in cs[:6]) + "\n" + cs[7].person["email"]
    a = det.scan(planted, report=False, use_numpy=True)
    b = det.scan(planted, report=False, use_numpy=False)
    assert (a.confirmed, a.suspect, a.candidates) == (b.confirmed, b.suspect, b.candidates)
    assert a.candidates == sum(1 for _ in candidates(planted))
    assert cs[7].canary_id in a.confirmed and len(a.confirmed) >= 7


def test_registry_never_sees_non_matching_lookups(world):
    reg, cs = world
    det = Detector(reg, reg.add_provider("q"), "q")
    seen = []
    orig = reg.lookup
    reg.lookup = lambda key, f: seen.append(f) or orig(key, f)
    try:
        # force prefix false positives: a filter that passes every name window
        det._filter = PrefixFilter(set(range(0)))
        det._filter.name_hits = lambda joined, use_numpy=True: (0, [w[2:] for w in name_windows(joined)])
        d = det.scan("山田花子さんと田中太郎さんの住所は不明です。" + cs[0].person["email"], report=False)
    finally:
        reg.lookup = orig
    assert d.oprf_calls > 50                       # many windows went through the OPRF...
    assert len(seen) == 0 or all(reg._entries.get(f) for f in seen)   # ...but only real hits reached lookup
