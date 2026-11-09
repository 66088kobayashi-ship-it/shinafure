"""Pool several llm_eval output files and compare canary styles.

  python -m demo.pool family_ordinary.jsonl family_rare.jsonl family_ordinary_s12.jsonl family_rare_s12.jsonl

For each canary chunk it decides two things independently:
  survived : the canary's full name or the last 8 digits of its phone are still in the AI's output
  detected : Shinafure confirmed the canary in that output
and prints both per style, plus a two-sided Fisher exact test on survival.
"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from math import comb

from demo.llm_eval import build_chunks
from shinafure.registry import Detector, Registry, register_canaries


def fisher(a: int, b: int, c: int, d: int) -> float:
    n, r1, c1 = a + b + c + d, a + b, a + c
    pmf = lambda x: comb(r1, x) * comb(n - r1, c1 - x) / comb(n, c1)
    p0 = pmf(a)
    return min(1.0, sum(pmf(x) for x in range(max(0, c1 - (n - r1)), min(r1, c1) + 1) if pmf(x) <= p0 + 1e-12))


def survived(person: dict, out: str) -> bool:
    name = re.escape(person["last"]) + r"[\s　]*" + re.escape(person["first"])
    tail = re.sub(r"\D", "", person["phone"])[-8:]
    return bool(re.search(name, out)) or tail in re.sub(r"\D", "", out)


def main(paths: list[str], task: str = "family", out_path: str = "results_pooled.md") -> None:
    lines: list[str] = []

    def out(*a):  # print and also collect into the results file
        lines.append(" ".join(str(x) for x in a))
        print(*a)

    worlds, stats = {}, defaultdict(lambda: {"n": 0, "kept": 0, "det": 0, "ctrl": 0, "fp": 0})
    for path in paths:
        for line in open(path, encoding="utf-8"):
            d = json.loads(line)
            if d["task"] != task:
                continue
            style, seed, rows = d.get("canary_style", "rare"), d.get("seed", 11), d.get("rows", 20)
            key = (style, seed, rows)
            if key not in worlds:
                canaries, chunks = build_chunks(rows, seed=seed, style=style)
                reg = Registry(oprf_per_hour=10**9, require_tickets=False)
                register_canaries(reg, "pool", canaries)
                worlds[key] = ({c.canary_id: c for c in canaries}, Detector(reg, reg.add_provider("p"), "p"))
            by_id, det = worlds[key]
            st = stats[style]
            r = det.scan(d["output"], report=False)
            if d["canary"]:
                st["n"] += 1
                st["kept"] += survived(by_id[d["canary"]].person, d["output"])
                st["det"] += d["canary"] in r.confirmed
            else:
                st["ctrl"] += 1
                st["fp"] += bool(r.confirmed)
    out(f"| カナリア | 出力に残った | 検出 | 残ったうち検出 | 誤検知 |\n|---|---:|---:|---:|---:|")
    for style in ("ordinary", "mixed", "rare"):
        s = stats.get(style)
        if not s:
            continue
        kd = f"{s['det']}/{s['kept']}" if s["kept"] else "—"
        out(f"| {style} | {s['kept']}/{s['n']} | {s['det']}/{s['n']} | {kd} | {s['fp']}/{s['ctrl']} |")
    o, r = stats.get("ordinary"), stats.get("rare")
    if o and r and o["n"] and r["n"]:
        p = fisher(o["kept"], o["n"] - o["kept"], r["kept"], r["n"] - r["kept"])
        out(f"\n残った割合: ordinary {o['kept'] / o['n']:.0%} / rare {r['kept'] / r['n']:.0%}  "
              f"Fisher の正確確率検定（両側）p = {p:.3f}" + ("  → 有意（p<0.05）" if p < 0.05 else "  → まだ有意ではない"))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"対象: {', '.join(paths)}（指示: {task}）\n\n" + "\n".join(lines) + "\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: python -m demo.pool FILE.jsonl [FILE.jsonl ...]")
    main(sys.argv[1:])
