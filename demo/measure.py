"""Measurements for 品触れ (Shinafure).

  1. Robustness: a stolen customer table (10,000 realistic people + 10
     canaries) goes through the reshaping an attacker's pipeline would do
     before or while feeding it to an AI. How many canaries are still
     detected?
  2. False positives: the same transformations on a table *without*
     canaries, plus Japanese and English text corpora (JEITA, KNBC blogs,
     Project Gutenberg, Reuters) and 50,000 extra synthetic people.
  3. Cost: candidates per MB, registry round trips per MB, throughput.

The transformations are deterministic stand-ins for what an LLM pipeline
would produce; no real model is called.

Run:  python -m demo.measure  [corpus_dir]
"""
from __future__ import annotations

import glob
import json
import os
import random
import sys
import time
from collections import defaultdict

from faker import Faker

from shinafure.canary import make_canaries
from shinafure.registry import Detector, Registry, register_canaries

FW = str.maketrans("0123456789-", "０１２３４５６７８９－")


def faker_people(n: int, seed: int) -> list[dict]:
    f = Faker("ja_JP")
    Faker.seed(seed)
    rows = []
    for i in range(n):
        ln, fn = f.last_name_pair(), f.first_name_pair()
        rows.append({"id": f"U{seed}{i:06d}", "last": ln[0], "first": fn[0], "last_kana": ln[1],
                     "first_kana": fn[1], "last_roma": ln[2], "first_roma": fn[2],
                     "email": f.email(), "phone": f.phone_number(), "address": f.address().replace("\n", " "),
                     "canary": None})
    return rows


# ------------------------------------------------------------ transformations
def t_csv(rows):
    lines = ["id,氏名,フリガナ,メール,電話,住所"]
    lines += [f"{r['id']},{r['last']} {r['first']},{r['last_kana']} {r['first_kana']},{r['email']},{r['phone']},{r['address']}" for r in rows]
    return "\n".join(lines)


def t_json(rows):
    return json.dumps([{"name": f"{r['last']} {r['first']}", "kana": f"{r['last_kana']} {r['first_kana']}",
                        "email": r["email"], "tel": r["phone"], "addr": r["address"]} for r in rows],
                      ensure_ascii=False, indent=1)


def t_markdown(rows):
    out = ["| 氏名 | メール | 電話 | 住所 |", "|---|---|---|---|"]
    out += [f"| {r['last']}{r['first']} | {r['email']} | {r['phone']} | {r['address']} |" for r in rows]
    return "\n".join(out)


def t_name_phone(rows):
    return "\n".join(f"{r['last']} {r['first']}\t{r['phone']}" for r in rows)


def t_name_address(rows):
    return "\n".join(f"{r['last']}{r['first']}様 {r['address']}" for r in rows)


def t_name_only(rows):
    return "、".join(f"{r['last']}{r['first']}" for r in rows)


def t_email_only(rows):
    return "\n".join(r["email"] for r in rows)


def t_english(rows):
    def intl(p):
        d = p.replace("-", "")
        return "+81 " + d[1:3] + "-" + d[3:7] + "-" + d[7:]
    return "\n".join(f"{r['first_roma']} {r['last_roma']} <{r['email']}> tel {intl(r['phone'])}" for r in rows)


def t_katakana_fullwidth(rows):
    return "\n".join(f"{r['last_kana']}　{r['first_kana']}：{r['phone'].translate(FW)}" for r in rows)


def t_phone_styles(rows):
    styles = [lambda d: f"({d[:3]}) {d[3:7]}-{d[7:]}", lambda d: f"{d[:3]}.{d[3:7]}.{d[7:]}",
              lambda d: f"{d[:3]} {d[3:7]} {d[7:]}", lambda d: f"+81-{d[1:3]}-{d[3:7]}-{d[7:]}",
              lambda d: f"+81 (0){d[1:3]}-{d[3:7]}-{d[7:]}", lambda d: d]
    out = []
    for i, r in enumerate(rows):
        d = "".join(ch for ch in r["phone"] if ch.isdigit())
        out.append(f"No.{i} 連絡先 " + styles[i % len(styles)](d))
    return "\n".join(out)


def t_messy_address(rows):
    return "\n".join(f"{r['last']}　{r['first']}　{r['address'].translate(FW)}" for r in rows)


def _family(rows, with_phone):
    fam = defaultdict(list)
    for r in rows:
        fam[r["last"]].append(r)
    out = []
    for last, rs in fam.items():
        members = ", ".join(f"{r['first']}" + (f"（{r['phone']}）" if with_phone else "") for r in rs)
        out.append(f"■{last}家: {members}")
    return "\n".join(out)


def t_family_phone(rows):
    return _family(rows, True)


def t_family_names(rows):
    return _family(rows, False)


def t_strip_canary_domain(rows):
    # an attacker who has noticed that some emails share an unusual domain drops those rows
    return t_csv([r for r in rows if not r["email"].endswith("@kanari.example")])


def t_summary(rows):
    pref = defaultdict(int)
    for r in rows:
        pref[r["address"][:3]] += 1
    return "顧客の都道府県別件数: " + "、".join(f"{k}{v}件" for k, v in sorted(pref.items()))


TRANSFORMS = [
    ("CSV（全列）", t_csv),
    ("JSONに変換", t_json),
    ("Markdown表に変換", t_markdown),
    ("列抽出：氏名＋電話", t_name_phone),
    ("列抽出：氏名＋住所", t_name_address),
    ("列抽出：氏名のみ", t_name_only),
    ("列抽出：メールのみ", t_email_only),
    ("英語化（ローマ字氏名・+81電話・メール）", t_english),
    ("カタカナ氏名＋全角数字の電話", t_katakana_fullwidth),
    ("全角数字・空白ゆれの住所", t_messy_address),
    ("電話番号のみ（括弧・ドット・空白・+81など6種の書式）", t_phone_styles),
    ("名寄せ（家族ごと、電話あり）", t_family_phone),
    ("名寄せ（家族ごと、名前のみ）", t_family_names),
    ("要約（都道府県別件数のみ）", t_summary),
    ("攻撃者がカナリア用ドメインに気づき、その行を削除", t_strip_canary_domain),
]


# ------------------------------------------------------------------ corpora
def load_corpora(root: str, limit: int = 3_000_000) -> dict[str, str]:
    out = {}
    paths = sorted(glob.glob(os.path.join(root, "jeita/jeita/*.chasen")))
    buf, n = [], 0
    for p in paths:
        for line in open(p, encoding="utf-8", errors="ignore"):
            w = line.split("\t", 1)[0]
            if w == "EOS\n" or w == "EOS":
                buf.append("\n")
            else:
                buf.append(w)
                n += len(w)
        if n > limit:
            break
    out["JEITA（日本語の文学作品など）"] = "".join(buf)[:limit]
    buf = []
    for p in sorted(glob.glob(os.path.join(root, "knbc/knbc/corpus2/*.tsv"))):
        for line in open(p, encoding="euc-jp", errors="ignore"):
            cols = line.split("\t")
            if len(cols) > 1:
                buf.append(cols[1])
    out["KNBC（日本語ブログ）"] = "\n".join(buf)[:limit]
    for name, pat in (("Gutenberg（英語の書籍）", "gutenberg/gutenberg/*.txt"), ("Reuters（英語ニュース）", "reuters/reuters/*/*")):
        buf, n = [], 0
        for p in sorted(glob.glob(os.path.join(root, pat))):
            if os.path.isdir(p):
                continue
            t = open(p, encoding="latin-1", errors="ignore").read()
            buf.append(t)
            n += len(t)
            if n > limit:
                break
        out[name] = "\n".join(buf)[:limit]
    return out


def main(corpus_dir: str) -> None:
    rng = random.Random(42)
    people = faker_people(10_000, seed=1)
    canaries = make_canaries(10, "app-db", "kanari.example", rng, style="rare")
    for c in canaries:
        people.insert(rng.randrange(len(people) + 1), {**c.person, "id": f"U{rng.randint(10**6, 10**7)}", "canary": c.canary_id})
    clean = [r for r in people if r["canary"] is None]
    present = {c.canary_id for c in canaries}

    reg = Registry(oprf_per_hour=10**9, require_tickets=False)
    notified = []
    register_canaries(reg, "example-co", canaries, webhook=notified.append)
    key = reg.add_provider("provider-x")
    det = Detector(reg, key, "provider-x")

    lines = ["## 1. 変換後も見つかるか（顧客10,000人＋カナリア10人）", "",
             "| 攻撃者側の変換 | 確定で検出 | 疑い（氏名のみ） | 同じ変換・カナリアなしでの誤検知 | 照会回数 |",
             "|---|---:|---:|---:|---:|"]
    for name, fn in TRANSFORMS:
        text = fn(people)
        d = det.scan(text, report=False)
        conf = set(d.confirmed) & present
        sus = (set(d.suspect) - set(d.confirmed)) & present
        dc = det.scan(fn(clean), report=False)
        fp = len(dc.confirmed) + len(dc.suspect)
        lines.append(f"| {name} | {len(conf)}/10 | {len(sus)} | {fp} | {d.oprf_calls} |")
        print(f"  {name}: confirmed={len(conf)} suspect={len(sus)} fp={fp}", file=sys.stderr)

    # chunked sending: 50 rows per request
    chunks = [people[i:i + 50] for i in range(0, len(people), 50)]
    with_canary = [ch for ch in chunks if any(r["canary"] for r in ch)]
    hit_chunks = sum(1 for ch in with_canary if det.scan(t_csv(ch), report=False).confirmed)
    clean_hits = sum(1 for ch in chunks if not any(r["canary"] for r in ch) and det.scan(t_csv(ch), report=False).confirmed)
    lines += ["", f"分割送信（50行ずつ{len(chunks)}回）：カナリアを含む{len(with_canary)}回のうち **{hit_chunks}回** で確定検出。"
                  f"カナリアを含まない{len(chunks) - len(with_canary)}回での誤検知は **{clean_hits}回**。"]

    # end-to-end notification path
    det.scan(t_csv(people[:200] + [r for r in people if r["canary"]][:1]))
    lines += ["", f"登録者への通知（1回の送信で発生）: {len(notified)}件。通知に含まれるのはカナリアID・データセット名・提供者名・時刻のみ。"]

    # ------------------------------------------------------ false positives
    lines += ["", "## 2. 誤検知（カナリアを含まない文書）", "",
              "| 文書 | 文字数 | 候補の数 | 照会回数 | 確定 | 疑い | 処理速度 |", "|---|---:|---:|---:|---:|---:|---:|"]
    corp = load_corpora(corpus_dir)
    corp["合成の顧客5万人（別の乱数、CSV）"] = t_csv(faker_people(50_000, seed=7))
    total_chars = total_time = 0
    for name, text in corp.items():
        t = time.perf_counter()
        d = det.scan(text, report=False)
        dt = time.perf_counter() - t
        total_chars += len(text)
        total_time += dt
        lines.append(f"| {name} | {len(text):,} | {d.candidates:,} | {d.oprf_calls} | {len(d.confirmed)} | {len(d.suspect)} | "
                     f"{len(text) / dt / 1e6:.2f} M文字/秒 |")
        print(f"  corpus {name}: chars={len(text)} cand={d.candidates} oprf={d.oprf_calls} conf={len(d.confirmed)} sus={len(d.suspect)} {dt:.1f}s", file=sys.stderr)
    lines += ["", f"合計 {total_chars:,} 文字を {total_time:.0f} 秒で処理（純Python、1スレッド）。"]

    # --------------------------------------------------------------- scaling
    lines += ["", "## 3. 規模を大きくしたとき（計算）", "",
              "登録トークン数 R、接頭辞のビット数 b のとき、無関係な候補が照会に回る割合は約 R / 2^b。"
              "同じ値は、接頭辞の一覧が漏れた場合に攻撃者が『カナリアかもしれない』として捨てる実データの割合でもある。", "",
              "| 登録トークン数 R | b=24 | b=32 | b=40 |", "|---:|---:|---:|---:|"]
    jeita_per_char = 12_930_944 / 3_000_000
    for R in (70, 10_000, 1_000_000, 70_000_000):
        cells = []
        for b in (24, 32, 40):
            rate = R / 2 ** b
            per_10k = 10_000 * jeita_per_char * rate
            cells.append(f"{per_10k:,.2f}回 / {min(rate, 1):.4%}")
        lines.append(f"| {R:,} | " + " | ".join(cells) + " |")
    lines += ["", "各セル：日本語1万文字あたりの照会回数 / 漏えい時に攻撃者が捨てる実データの割合。"]

    md = "\n".join(lines)
    print(md)
    open("results.md", "w").write(md + "\n")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "corpus")
