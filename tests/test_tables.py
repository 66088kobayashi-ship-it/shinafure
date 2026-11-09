"""v0.6: ticketed canaries use real towns and frequency-weighted surnames."""
import random
import re
from collections import Counter

import pytest

from shinafure import tables
from shinafure.issuance import Opening, Ticket, canary_from_ticket, new_opening
from shinafure.registry import Detector, Registry, register_ticketed
from shinafure.tokens import candidates, norm_address, person_tokens


def tickets(n, region="", seed=0, rare_ratio=0.2):
    rng = random.Random(seed)
    out = []
    for i in range(n):
        op = new_opening("kanari.example", "0701234", rare_ratio, region)
        t = Ticket(f"t{seed}-{i}", "acme", "ds", op.commitment(), rng.randbytes(32), tables.version())
        out.append(canary_from_ticket(t, op))
    return out


def test_tables_load_and_cover_the_country():
    assert len(tables.units()) > 90_000
    assert len({u[0] for u in tables.units()}) == 47
    assert sum(len(tables.units(r)) for r in tables.REGIONS) == len(tables.units())
    sur, cum, given = tables.names()
    assert len(sur) == 50 and len(given) >= 60 and list(cum) == sorted(cum)


def test_every_generated_address_is_found_in_text():
    for c in tickets(400, seed=1):
        p = c.person
        want = "a:" + norm_address(p["address"])
        for text in (f"{p['last']} {p['first']} / {p['address']}",
                     "住所," + re.sub(r"(\d+)号", r"\1", re.sub(r"(\d+)(丁目|番)", r"\1-", p["address"]))):
            assert want in set(candidates(text)), (p["address"], text)


def test_region_keeps_addresses_inside_it():
    kanto = set(tables.REGIONS["関東"])
    assert all(c.person["address"].startswith(tuple(kanto)) for c in tickets(150, "関東", seed=2))
    with pytest.raises(ValueError):
        new_opening("kanari.example", "0701234", region="東京都")      # single prefectures are not allowed
    bad = Opening(b"\0" * 32, "kanari.example", "0701234", 200, "東京都")
    assert Opening.parse(bad.to_bytes("x"), "x") is None


def test_ordinary_surnames_follow_real_frequency():
    counts = Counter(c.person["last"] for c in tickets(1500, seed=3, rare_ratio=0.0))
    top = [k for k, _ in counts.most_common(2)]
    assert top[0] == "佐藤" and "鈴木" in top + [counts.most_common(3)[2][0]]


def test_tickets_from_another_table_version_are_refused():
    op = new_opening("kanari.example", "0701234")
    t = Ticket("old", "acme", "ds", op.commitment(), b"\1" * 32, "jp-000000000000")
    with pytest.raises(ValueError):
        canary_from_ticket(t, op)


def test_coincidence_bound_is_small():
    year = 100 * 365
    assert tables.coincidence_bound(year) < 1e-4                    # worst region (四国)
    assert tables.coincidence_bound(year, regions=[""]) < 3e-6      # whole country
    assert tables.coincidence_bound(year) > tables.coincidence_bound(year, regions=[""])


def test_ticketed_canaries_with_real_addresses_confirm_end_to_end():
    reg = Registry(oprf_per_hour=10**9)
    txt, sms = {}, []
    name, value = reg.domain_challenge("acme", "kanari.example")
    txt[name] = [value]
    assert reg.verify_domain("acme", "kanari.example", lambda n: txt.get(n, []))
    cid = reg.start_phone_block("acme", "0701234", lambda num, code: sms.append(code))
    assert reg.confirm_phone_block("acme", cid, sms[-1])
    items = []
    for region in ("", "関東", "四国"):
        op = new_opening("kanari.example", "0701234", 0.2, region)
        items.append((reg.issue_ticket("acme", "crm", op.commitment()), op))
    inbox = []
    cs = register_ticketed(reg, "acme", items, webhook=inbox.append)
    det = Detector(reg, reg.add_provider("p"), "p")
    for c in cs:
        p = c.person
        det.scan(f"{p['last']}{p['first']}様 {p['address']}")
    assert sorted(n.canary_id for n in inbox) == sorted(c.canary_id for c in cs)
    assert not reg.abuse_log
