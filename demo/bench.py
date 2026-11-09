"""How fast is provider-side matching?

    python -m demo.bench corpus [--canaries 1000] [--mb 1]

Registers N canaries (mixed style), then scans Japanese and English corpora
and a synthetic customer CSV. Reports characters per second, candidates,
OPRF lookups, and the detection result, so an optimized matcher can be
checked for identical output.
"""
from __future__ import annotations

import argparse
import random
import sys
import time

from shinafure.canary import make_canaries
from shinafure.issuance import new_opening
from shinafure.registry import Detector, Registry, register_canaries, register_ticketed

from .measure import faker_people, load_corpora, t_csv


def build(n_canaries: int, seed: int = 7, ticketed: bool = False) -> tuple[Detector, list]:
    if not ticketed:
        reg = Registry(oprf_per_hour=10**12, require_tickets=False)
        cs = make_canaries(n_canaries, "bench", "kanari.example", random.Random(seed))
        register_canaries(reg, "acme", cs)
        return Detector(reg, reg.add_provider("bench"), "bench"), cs
    # v0.6 production path: real towns, frequency-weighted surnames, regions spread over the country
    reg = Registry(oprf_per_hour=10**12, tickets_per_day=10**9)
    txt, sms = {}, []
    name, value = reg.domain_challenge("acme", "kanari.example")
    txt[name] = [value]
    reg.verify_domain("acme", "kanari.example", lambda n: txt.get(n, []))
    reg.confirm_phone_block("acme", reg.start_phone_block("acme", "0701", lambda num, code: sms.append(code)), sms[-1])
    regions = ["", "北海道", "東北", "関東", "中部", "近畿", "中国", "四国", "九州・沖縄"]
    items = []
    for i in range(n_canaries):
        op = new_opening("kanari.example", "0701", 0.2, regions[i % len(regions)])
        items.append((reg.issue_ticket("acme", "bench", op.commitment()), op))
    cs = register_ticketed(reg, "acme", items)
    return Detector(reg, reg.add_provider("bench"), "bench"), cs


def texts(corpus_dir: str, limit: int) -> dict[str, str]:
    out = load_corpora(corpus_dir, limit)
    people = faker_people(4000, seed=3)
    out["顧客CSV（Faker、日本語）"] = t_csv(people)[:limit]
    return out


def run(det: Detector, docs: dict[str, str], plant: list | None = None) -> list[tuple]:
    rows = []
    for name, text in docs.items():
        if plant:
            # plant a few canaries so detection output is non-trivial and comparable
            text = text + "\n" + "\n".join(f"{c.person['last']}{c.person['first']} {c.person['phone']}" for c in plant)
        t = time.perf_counter()
        d = det.scan(text, report=False)
        dt = time.perf_counter() - t
        rows.append((name, len(text), dt, d.candidates, d.oprf_calls,
                     tuple(sorted(d.confirmed)), tuple(sorted(d.suspect))))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("--canaries", type=int, default=1000)
    ap.add_argument("--mb", type=float, default=1.0, help="characters per text, in millions")
    ap.add_argument("--ticketed", action="store_true", help="v0.6 canaries from tickets (real towns)")
    ap.add_argument("--no-plant", action="store_true", help="measure false positives: plant nothing")
    a = ap.parse_args()
    det, cs = build(a.canaries, ticketed=a.ticketed)
    docs = texts(a.corpus, int(a.mb * 1_000_000))
    total_c = total_t = 0
    print("| テキスト | 文字数 | 秒 | 文字/秒 | 候補 | 台帳への照会 | 確定 | 疑い |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for name, n, dt, cand, oprf, conf, sus in run(det, docs, plant=None if a.no_plant else cs[:5]):
        total_c += n
        total_t += dt
        print(f"| {name} | {n:,} | {dt:.2f} | {n / dt:,.0f} | {cand:,} | {oprf:,} | {len(conf)} | {len(sus)} |")
    print(f"\n合計 {total_c:,} 文字 / {total_t:.2f} 秒 = {total_c / total_t:,.0f} 文字/秒（カナリア {a.canaries} 人登録）",
          file=sys.stderr)


if __name__ == "__main__":
    main()
