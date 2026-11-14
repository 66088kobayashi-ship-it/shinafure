"""Provider-side cost as the registry grows (registered tokens simulated as random
prefixes and F values; 5 real canaries are planted to check detection).

    python -m demo.scale
"""
import random, secrets, sys, time, tracemalloc  # noqa: E401
sys.path.insert(0, ".")
from demo.bench import build, texts
from shinafure.fastscan import PrefixFilter, FValueSet, PREFIX_BITS
docs = texts("corpus", 1_000_000)
ja = docs["JEITA（日本語の文学作品など）"]; en = docs["Gutenberg（英語の書籍）"]
det, cs = build(5)
base_pf, base_f = set(det.registry._prefixes), list(det.registry._entries)
rng = random.Random(1)
plant = "\n" + "\n".join(f"{c.person['last']}{c.person['first']} {c.person['phone']}" for c in cs)
print(f"prefix bits {PREFIX_BITS}")
print("| canaries | tokens | provider lists MB | JEITA chars/s | JEITA lookups | Gutenberg chars/s | Gutenberg lookups | planted confirmed |")
for n in (1_000, 10_000, 100_000, 1_000_000):
    toks = n * 8
    pfs = [rng.getrandbits(PREFIX_BITS) for _ in range(toks)] + list(base_pf)
    fs = [secrets.token_bytes(32) for _ in range(toks)] + base_f
    tracemalloc.start()
    det._filter = PrefixFilter(pfs); det._fvals = FValueSet(fs)
    cur, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    del pfs, fs
    mb = (det._filter.sorted.nbytes + det._fvals._a.nbytes) / 1e6
    row = [f"{n:,}", f"{toks:,}", f"{mb:.0f}"]
    for text in (ja, en):
        t = time.perf_counter(); d = det.scan(text, report=False); dt = time.perf_counter() - t
        row += [f"{len(text)/dt:,.0f}", f"{d.oprf_calls:,}"]
    row.append(str(len(det.scan(plant, report=False).confirmed)))
    print("| " + " | ".join(row) + " |", flush=True)
