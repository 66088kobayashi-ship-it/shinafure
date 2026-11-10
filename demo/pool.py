"""Pool llm_eval output files and compare canary styles, per model.

  python -m demo.pool --rows 40 "out_*.jsonl" "../old/*.jsonl"

Patterns are expanded here (PowerShell does not expand them for programs).
--rows keeps only calls made with that many rows per chunk.

For each canary chunk it decides independently:
  survived : the canary's full name or the last 8 digits of its phone are still in the AI's output
  detected : Shinafure confirmed the canary in that output
and, as the baseline, how many of the real customers in the same chunks
survived (same rule). Rows whose full name appears twice in a chunk, or
equals the canary's, are left out of the baseline: the output cannot tell
which of them survived.

Prints, per model:
  * canary survival and detection per style, false positives on control chunks
  * canary vs. real-customer survival per style (two-sided Fisher exact test)
  * ordinary vs. rare canary survival (two-sided Fisher exact test)
"""
from __future__ import annotations

import argparse
import glob
import json
import re
from collections import Counter, defaultdict
from math import comb

from demo.llm_eval import build_chunks
from shinafure.registry import Detector, Registry, register_canaries

DEFAULT_MODEL = {"ollama": "qwen2.5:7b"}


def fisher(a: int, b: int, c: int, d: int) -> float:
    n, r1, c1 = a + b + c + d, a + b, a + c
    pmf = lambda x: comb(r1, x) * comb(n - r1, c1 - x) / comb(n, c1)
    p0 = pmf(a)
    lo, hi = max(0, c1 - (n - r1)), min(r1, c1)
    return min(1.0, sum(pmf(x) for x in range(lo, hi + 1) if pmf(x) <= p0 * (1 + 1e-9)))


def survived(person: dict, out: str) -> bool:
    name = re.escape(person["last"]) + r"[\s　]*" + re.escape(person["first"])
    tail = re.sub(r"\D", "", person["phone"])[-8:]
    return bool(re.search(name, out)) or tail in re.sub(r"\D", "", out)


def model_of(d: dict) -> str:
    m = d.get("model") or "default"
    return DEFAULT_MODEL.get(d.get("backend", ""), m) if m == "default" else m


def pct(k: int, n: int) -> str:
    return f"{k}/{n}（{k / n:.0%}）" if n else "—"


def main(paths: list[str], task: str = "family", out_path: str = "results_pooled.md", rows_only: int | None = None) -> None:
    lines: list[str] = []

    def out(*a):  # print and also collect into the results file
        lines.append(" ".join(str(x) for x in a))
        print(*a)

    worlds, runs = {}, Counter()
    stats = defaultdict(lambda: {"n": 0, "kept": 0, "det": 0, "ctrl": 0, "fp": 0, "base_n": 0, "base_kept": 0})
    for path in paths:
        for line in open(path, encoding="utf-8"):
            d = json.loads(line)
            if d["task"] != task or d.get("error"):
                continue
            style, seed, rows, model = d.get("canary_style", "rare"), d.get("seed", 11), d.get("rows", 20), model_of(d)
            if rows_only is not None and rows != rows_only:
                continue
            runs[(model, style, seed, rows)] += 1
            key = (style, seed, rows)
            if key not in worlds:
                canaries, chunks = build_chunks(rows, seed=seed, style=style)
                reg = Registry(oprf_per_hour=10**9, require_tickets=False)
                register_canaries(reg, "pool", canaries)
                worlds[key] = ({c.canary_id: c for c in canaries}, chunks,
                               Detector(reg, reg.add_provider("p"), "p"))
            by_id, chunks, det = worlds[key]
            st = stats[(model, style)]
            r = det.scan(d["output"], report=False)
            if d["canary"]:
                canary = by_id[d["canary"]].person
                st["n"] += 1
                st["kept"] += survived(canary, d["output"])
                st["det"] += d["canary"] in r.confirmed
                rows_ = [x for x in chunks[d["chunk"]]["rows"] if not x.get("canary")]
                names = Counter(x["last"] + x["first"] for x in rows_)
                for x in rows_:
                    full = x["last"] + x["first"]
                    if names[full] > 1 or full == canary["last"] + canary["first"]:
                        continue
                    st["base_n"] += 1
                    st["base_kept"] += survived(x, d["output"])
            else:
                st["ctrl"] += 1
                st["fp"] += bool(r.confirmed)

    out("実行（モデル / カナリア / 乱数の種 / 1回の行数：呼び出し回数）")
    for (model, style, seed, rows), n in sorted(runs.items()):
        out(f"- {model} / {style} / seed {seed} / {rows}行：{n}回")
    for model in sorted({m for m, _ in stats}):
        out(f"\n## {model}（指示: {task}）\n")
        out("| カナリア | カナリアが残った | 検出 | 残ったうち検出 | 同じ出力の本物の顧客が残った | 差（Fisher、両側） | 誤検知 |")
        out("|---|---:|---:|---:|---:|---:|---:|")
        for style in ("ordinary", "mixed", "rare"):
            s = stats.get((model, style))
            if not s:
                continue
            kd = f"{s['det']}/{s['kept']}" if s["kept"] else "—"
            p = fisher(s["kept"], s["n"] - s["kept"], s["base_kept"], s["base_n"] - s["base_kept"]) if s["n"] and s["base_n"] else float("nan")
            out(f"| {style} | {pct(s['kept'], s['n'])} | {s['det']}/{s['n']} | {kd} | "
                f"{pct(s['base_kept'], s['base_n'])} | p={p:.3f} | {s['fp']}/{s['ctrl']} |")
        o, ra = stats.get((model, "ordinary")), stats.get((model, "rare"))
        if o and ra and o["n"] and ra["n"]:
            p = fisher(o["kept"], o["n"] - o["kept"], ra["kept"], ra["n"] - ra["kept"])
            out(f"\nordinary と rare のカナリアの直接比較：{o['kept'] / o['n']:.0%} 対 {ra['kept'] / ra['n']:.0%}、p = {p:.3f}")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"対象: {', '.join(paths)}\n\n" + "\n".join(lines) + "\n")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+", help="jsonl files or patterns such as out_*.jsonl")
    ap.add_argument("--task", default="family")
    ap.add_argument("--rows", type=int, default=None, help="only calls with this many rows per chunk")
    ap.add_argument("--results", default="results_pooled.md")
    a = ap.parse_args()
    paths = []
    for f in a.files:
        for p in sorted(glob.glob(f)) if any(ch in f for ch in "*?[") else [f]:
            if p not in paths:
                paths.append(p)
    if not paths:
        raise SystemExit("no files matched: " + " ".join(a.files))
    main(paths, a.task, a.results, a.rows)
