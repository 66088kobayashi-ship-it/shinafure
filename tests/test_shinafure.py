import asyncio
import random

import httpx
import pytest

from shinafure.canary import make_canaries
from shinafure.proxy import create_proxy
from shinafure.registry import Detector, RateLimited, Registry, register_canaries
from shinafure.tokens import candidates, norm_address, norm_phone, person_tokens


@pytest.fixture
def world():
    rng = random.Random(5)
    cs = make_canaries(6, "crm-export", "kanari.example", rng, style="rare")
    reg = Registry(require_tickets=False)
    inbox = []
    register_canaries(reg, "acme", cs, webhook=inbox.append)
    key = reg.add_provider("p1")
    return cs, reg, Detector(reg, key, "p1"), inbox


@pytest.mark.parametrize("raw", ["070-1234-5678", "(070) 1234-5678", "070.1234.5678", "+81 70 1234 5678",
                                 "+81 (0)70-1234-5678", "０７０－１２３４－５６７８"])
def test_phone_formats_normalize_to_one_value(raw):
    assert norm_phone(raw) == "07012345678"


def test_address_variants_normalize():
    a = norm_address("東京都港区赤坂9丁目17番3号 鷲見ハイツ502")
    assert a == norm_address("東京都港区赤坂９－１７－３") == "東京都港区赤坂9-17-3"


def test_registry_holds_no_plaintext(world):
    cs, reg, _, _ = world
    dump = repr(reg._entries) + repr(reg._prefixes)
    for c in cs:
        for tok in person_tokens(c.person):
            assert tok[2:] not in dump


def test_strong_token_confirms(world):
    cs, _, det, inbox = world
    d = det.scan(f"連絡先一覧: {cs[0].person['email']}")
    assert set(d.confirmed) == {cs[0].canary_id}
    assert inbox and inbox[-1].canary_id == cs[0].canary_id and inbox[-1].status == "confirmed"


def test_single_name_is_only_suspect_but_two_names_confirm(world):
    cs, _, det, inbox = world
    p, q = cs[0].person, cs[1].person
    d = det.scan(f"{p['last']} {p['first']}さんから連絡")
    assert d.suspect and not d.confirmed and not inbox   # a single rare name is not enough to notify
    d = det.scan(f"{p['last']}{p['first']}、{q['last']}{q['first']}")
    assert set(d.confirmed) == {cs[0].canary_id, cs[1].canary_id}


def test_name_plus_address_confirms(world):
    cs, _, det, _ = world
    p = cs[2].person
    d = det.scan(f"{p['last_kana']} {p['first_kana']} 様 / {p['address']}")
    assert set(d.confirmed) == {cs[2].canary_id}


def test_romanized_and_international_formats(world):
    cs, _, det, _ = world
    p = cs[3].person
    d = det.scan(f"{p['last_roma'].upper()}, {p['first_roma']} +81 {p['phone'][1:]}")
    assert cs[3].canary_id in d.confirmed


def test_unrelated_text_does_not_trigger(world):
    _, _, det, inbox = world
    text = "田中太郎 090-1111-2222 taro@example.com 東京都港区赤坂1-2-3 Tanaka Taro\n" * 200
    d = det.scan(text)
    assert not d.confirmed and not d.suspect and not inbox


def test_only_providers_get_the_filter_and_lookups(world):
    _, reg, _, _ = world
    with pytest.raises(PermissionError):
        reg.prefix_filter("not-a-key")
    with pytest.raises(PermissionError):
        reg.lookup("not-a-key", b"x" * 32)


def test_oprf_is_rate_limited():
    reg = Registry(oprf_per_hour=3, require_tickets=False)
    cs = make_canaries(1, "d", "kanari.example", random.Random(1), style="rare")
    with pytest.raises(RateLimited):
        register_canaries(reg, "acme", cs, caller="greedy")


def test_proxy_flag_and_block(world):
    cs, reg, det, inbox = world

    async def upstream(body):
        return {"choices": [{"message": {"role": "assistant", "content": "ok"}}]}

    async def go(policy):
        app = create_proxy(det, upstream, policy=policy)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://p") as c:
            body = {"model": "m", "messages": [{"role": "user", "content": f"整形して: {cs[4].person['phone']}"}]}
            return await c.post("/v1/chat/completions", json=body), app

    r, app = asyncio.run(go("flag"))
    assert r.status_code == 200 and "confirmed=1" in r.headers["x-shinafure"]
    r, _ = asyncio.run(go("block"))
    assert r.status_code == 403
    note = inbox[-1]
    assert note.provider == "p1" and note.dataset == "crm-export"
    assert "整形" not in repr(note)  # the prompt never reaches the registrant


# ----------------------------------------------------------- v0.2: ordinary canaries
@pytest.fixture
def ordinary():
    cs = make_canaries(6, "crm", "kanari.example", random.Random(9), style="ordinary")
    reg = Registry(require_tickets=False)
    register_canaries(reg, "acme", cs)
    return cs, Detector(reg, reg.add_provider("p1"), "p1")


def test_ordinary_names_never_confirm_alone_even_several(ordinary):
    cs, det = ordinary
    text = "、".join(c.person["last"] + c.person["first"] for c in cs)
    d = det.scan(text, report=False)
    assert not d.confirmed           # common names collide with real people
    assert set(d.suspect) == {c.canary_id for c in cs}


def test_ordinary_name_plus_mangled_phone_confirms(ordinary):
    cs, det = ordinary
    p = cs[0].person
    digits = "".join(ch for ch in p["phone"] if ch.isdigit())
    mangled = digits[1:3] + "-" + digits[3:7] + "-" + digits[7:]   # leading 0 dropped, as the 7b model did
    d = det.scan(f"{p['last']} {p['first']}: {mangled}", report=False)
    assert set(d.confirmed) == {cs[0].canary_id}
    d = det.scan(f"連絡先: {mangled}", report=False)                 # tail alone is only a suspect
    assert not d.confirmed and cs[0].canary_id in d.suspect


def test_mixed_style_is_the_default():
    a = make_canaries(30, "d", "kanari.example", random.Random(1))
    assert {c.person["style"] for c in a} == {"rare", "ordinary"}
    m = make_canaries(50, "d", "kanari.example", random.Random(2), style="mixed", rare_ratio=0.2)
    rare = sum(c.person["style"] == "rare" for c in m)
    assert 3 <= rare <= 20
