"""v1.4: a canary's surname and given name in separate fields still count as its name."""
import json
import random

import pytest

from shinafure.canary import make_canaries
from shinafure.fastscan import name_prefix, name_prefix_many
from shinafure.registry import Detector, Registry, register_canaries
from shinafure.tokens import field_pairs, nfkc, split_candidates


@pytest.fixture(scope="module")
def world():
    reg = Registry(oprf_per_hour=10**9, require_tickets=False)
    cs = make_canaries(40, "sp", "kanari.example", random.Random(5))
    register_canaries(reg, "acme", cs)
    det = Detector(reg, reg.add_provider("p"), "p")
    rare = next(c for c in cs if c.person["style"] == "rare")
    ordinary = next(c for c in cs if c.person["style"] == "ordinary")
    return det, rare, ordinary


def layouts(p):
    """Records with the name split into two fields and no email or phone:
    only name + address can confirm them."""
    j = lambda d: json.dumps(d, ensure_ascii=False)
    return {
        "csv": f"姓,名,住所\n山田,花子,東京都千代田区1-1-1\n{p['last']},{p['first']},{p['address']}\n",
        "quoted csv": f'"{p["last"]}","{p["first"]}","{p["address"]}"',
        "tsv kana": f"セイ\tメイ\t住所\n{p['last_kana']}\t{p['first_kana']}\t{p['address']}",
        "json": j({"last_name": p["last"], "first_name": p["first"], "address": p["address"]}),
        "form": f"姓：{p['last']}\n名：{p['first']}\n住所：{p['address']}",
        "form, slash and honorific": f"お名前 {p['last']} / {p['first']} 様\nご住所 {p['address']}",
        "one field per line": f"{p['last']}\n{p['first']}\n{p['address']}",
        "romaji json": j({"last_roma": p["last_roma"], "first_roma": p["first_roma"], "addr": p["address"]}),
        "romaji yaml": f"last: {p['last_roma']}\nfirst: {p['first_roma']}\naddress: {p['address']}",
    }


@pytest.mark.parametrize("style", ["rare", "ordinary"])
def test_split_names_with_an_address_are_confirmed(world, style):
    det, rare, ordinary = world
    c = rare if style == "rare" else ordinary
    for name, text in layouts(c.person).items():
        d = det.scan(text, report=False)
        assert c.canary_id in d.confirmed, (style, name)


def test_fields_are_not_joined_across_sentences():
    assert field_pairs(nfkc("佐藤は、花子と話した。")) == []           # 、。 separate sentences, not fields
    assert field_pairs(nfkc("佐藤 花子")) == []                         # spaces: already joined for name windows
    assert "佐藤花子" in field_pairs(nfkc("佐藤,花子"))
    assert "佐藤花子" in field_pairs(nfkc("姓: 佐藤 | 名: 花子"))       # across one short label
    assert "佐藤花子" in field_pairs(nfkc("佐藤／花子さん"))


def test_romaji_pairs_only_for_keyed_records():
    names = lambda t: [x for x in split_candidates(t)[0] if x.startswith("r:") and "hakuto" in x]
    assert "r:hakuto|takanashi" in names('{"last":"Takanashi","first":"Hakuto"}')
    assert "r:hakuto|takanashi" not in names("Takanashi met the team and Hakuto")   # prose


def test_bulk_name_prefixes_equal_single():
    r = random.Random(1)
    xs = ["".join(chr(r.randrange(0x3040, 0x9FFF)) for _ in range(r.randint(1, 10))) for _ in range(3000)]
    assert name_prefix_many(xs) == [name_prefix(x) for x in xs]
