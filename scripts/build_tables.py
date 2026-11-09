"""Build the address table for ticketed canaries.

    python scripts/build_tables.py path/to/latest.csv

Input: Geolonia 住所データ latest.csv
  https://github.com/geolonia/japanese-addresses  (data/latest.csv, CC BY 4.0)
Output: shinafure/data/addresses_jp.tsv.gz
  one line per town that has numbered 丁目 (the 住居表示 style used in most
  urban and suburban areas):  prefecture <TAB> municipality <TAB> town <TAB> chome numbers

Only towns whose names are kana/kanji (no digits, brackets or spaces) are
kept, so that generated addresses normalize and match like real ones.

Also writes shinafure/data/names_jp.tsv from Faker's ja_JP person provider
(MIT): surnames with their frequency weights, and given names, each with
katakana and romaji. These are the ordinary names; the rare names stay the
hand-picked lists in shinafure/canary.py.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import re
import sys
from collections import defaultdict
from pathlib import Path

KNUM = {c: i for i, c in enumerate("〇一二三四五六七八九")}
NAME_OK = re.compile(r"[぀-ヿ㐀-鿿々]+")
MAX_CITY_TOWN = 26      # candidate extraction looks at most 30 characters between prefecture and number


def kanji_num(s: str) -> int | None:
    if s == "十":
        return 10
    m = re.fullmatch(r"([二三四五六七八九]?)十([一二三四五六七八九]?)", s)
    if m:
        return (KNUM[m.group(1)] if m.group(1) else 1) * 10 + (KNUM[m.group(2)] if m.group(2) else 0)
    return KNUM.get(s) if len(s) == 1 else None


def main(src: str) -> None:
    towns: dict[tuple[str, str, str], set[int]] = defaultdict(set)
    with open(src, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            pref, city, town = row["都道府県名"], row["市区町村名"], row["大字町丁目名"]
            m = re.fullmatch(r"(.+?)([一二三四五六七八九十]+)丁目", town)
            if not m:
                continue
            n = kanji_num(m.group(2))
            base = m.group(1)
            if not n or not (NAME_OK.fullmatch(base) and NAME_OK.fullmatch(city)):
                continue
            if len(city) + len(base) > MAX_CITY_TOWN:
                continue
            towns[(pref, city, base)].add(n)
    lines = [f"{p}\t{c}\t{t}\t{','.join(map(str, sorted(ns)))}" for (p, c, t), ns in sorted(towns.items())]
    body = ("\n".join(lines) + "\n").encode()
    out = Path(__file__).resolve().parent.parent / "shinafure" / "data" / "addresses_jp.tsv.gz"
    out.parent.mkdir(exist_ok=True)
    with open(out, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as gz:
        gz.write(body)
    units = sum(len(ns) for ns in towns.values())
    print(f"{len(towns)} towns, {units} town-chome units, {out.stat().st_size:,} bytes, "
          f"sha256 {hashlib.sha256(body).hexdigest()[:16]}")


def names() -> None:
    from faker.providers.person.ja_JP import Provider as P
    from shinafure.canary import ORD_GIVEN
    rows = [f"S\t{k}\t{kana}\t{roma}\t{int(w)}" for (k, kana, roma), w in P.last_name_pairs.items()]
    seen, given = set(), []
    for k, kana, roma in list(P.first_name_pairs) + list(ORD_GIVEN):
        if k not in seen:
            seen.add(k)
            given.append(f"G\t{k}\t{kana}\t{roma}\t1")
    out = Path(__file__).resolve().parent.parent / "shinafure" / "data" / "names_jp.tsv"
    out.write_text("\n".join(rows + given) + "\n", encoding="utf-8")
    print(f"{len(rows)} surnames, {len(given)} given names -> {out.name}")


if __name__ == "__main__":
    main(sys.argv[1])
    names()
