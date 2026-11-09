"""Name and address tables for ticketed canaries.

Addresses: every town with numbered 丁目 in Geolonia 住所データ (CC BY 4.0,
based on 国土交通省 位置参照情報 and 日本郵便 郵便番号データ), built by
scripts/build_tables.py: 22,059 towns, 90,786 town-chome units.
Ordinary names: Faker ja_JP (MIT) surnames with frequency weights and given
names. Rare names: the hand-picked lists in canary.py.

A canary's address is drawn uniformly from the units of one region (or the
whole country). Regions are the eight 地方, never single prefectures: the
smallest prefecture has only 133 units, which would let a registrant aim a
canary at one person's address far more easily (see coincidence_bound).

The table version is recorded in every ticket. The registry must keep every
version it has issued tickets for, or it cannot regenerate those canaries.
"""
from __future__ import annotations

import gzip
import hashlib
from functools import lru_cache
from pathlib import Path

from .canary import BUILDINGS, GIVEN, SURNAMES

_DIR = Path(__file__).resolve().parent / "data"

REGIONS = {
    "北海道": ("北海道",),
    "東北": ("青森県", "岩手県", "宮城県", "秋田県", "山形県", "福島県"),
    "関東": ("茨城県", "栃木県", "群馬県", "埼玉県", "千葉県", "東京都", "神奈川県"),
    "中部": ("新潟県", "富山県", "石川県", "福井県", "山梨県", "長野県", "岐阜県", "静岡県", "愛知県"),
    "近畿": ("三重県", "滋賀県", "京都府", "大阪府", "兵庫県", "奈良県", "和歌山県"),
    "中国": ("鳥取県", "島根県", "岡山県", "広島県", "山口県"),
    "四国": ("徳島県", "香川県", "愛媛県", "高知県"),
    "九州・沖縄": ("福岡県", "佐賀県", "長崎県", "熊本県", "大分県", "宮崎県", "鹿児島県", "沖縄県"),
}
NATIONWIDE = ""
BAN_MAX, GO_MAX = 30, 20       # 番 1-30, 号 1-20


@lru_cache(maxsize=1)
def _raw() -> tuple[bytes, bytes]:
    return gzip.decompress((_DIR / "addresses_jp.tsv.gz").read_bytes()), (_DIR / "names_jp.tsv").read_bytes()


@lru_cache(maxsize=1)
def version() -> str:
    a, n = _raw()
    rare = repr((SURNAMES, GIVEN, BUILDINGS)).encode()
    return "jp-" + hashlib.sha256(a + b"\0" + n + b"\0" + rare).hexdigest()[:12]


@lru_cache(maxsize=None)
def units(region: str = NATIONWIDE) -> tuple[tuple[str, str, str, int], ...]:
    """(prefecture, municipality, town, chome) in file order."""
    if region and region not in REGIONS:
        raise ValueError(f"unknown region: {region}")
    prefs = set(REGIONS[region]) if region else None
    out = []
    for line in _raw()[0].decode().splitlines():
        p, c, t, ns = line.split("\t")
        if prefs is None or p in prefs:
            out += [(p, c, t, int(n)) for n in ns.split(",")]
    return tuple(out)


@lru_cache(maxsize=1)
def names() -> tuple[tuple, tuple[int, ...], tuple]:
    """(ordinary surnames, their cumulative weights, ordinary given names)."""
    sur, cum, given, total = [], [], [], 0
    for line in _raw()[1].decode().splitlines():
        kind, k, kana, roma, w = line.split("\t")
        if kind == "S":
            total += int(w)
            sur.append((k, kana, roma))
            cum.append(total)
        else:
            given.append((k, kana, roma))
    return tuple(sur), tuple(cum), tuple(given)


def coincidence_bound(tickets: int = 1, regions=None) -> float:
    """Upper bound on the chance that `tickets` honest tickets yield a canary
    with one given real person's full name and address (番・号 included),
    when the registrant picks the name style and, among `regions` (default:
    every choice it is allowed, "" meaning the whole country), the region
    that suits that target best. Ignores the building name and assumes the
    target's address is in the table; a target outside it cannot be hit."""
    sur, cum, given = names()
    p_rare = 1 / (len(SURNAMES) * len(GIVEN))
    p_ordinary = (max(b - a for a, b in zip((0,) + cum, cum)) / cum[-1]) / len(given)
    regions = [NATIONWIDE, *REGIONS] if regions is None else list(regions)
    smallest = min(len(units(r)) for r in regions)
    p_addr = 1 / (smallest * BAN_MAX * GO_MAX)
    return min(1.0, tickets * max(p_rare, p_ordinary) * p_addr)
