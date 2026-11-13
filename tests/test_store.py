"""v0.9: the registry survives a restart."""
import os
import stat

import pytest
from fastapi.testclient import TestClient

from shinafure.issuance import canary_from_ticket, new_opening, seal
from shinafure.registry import Detector, blind, escrow_key, finalize, prefix, register_ticketed, token_kind, unblind_point
from shinafure.remote import RemoteRegistry
from shinafure.service import create_app
from shinafure.store import PersistentRegistry
from shinafure.tokens import person_tokens

ADMIN = "admin-token-0123456789"


def onboard(reg, who, domain, block):
    txt, sms = {}, []
    n, v = reg.domain_challenge(who, domain)
    txt[n] = [v]
    assert reg.verify_domain(who, domain, lambda q: txt.get(q, []))
    assert reg.confirm_phone_block(who, reg.start_phone_block(who, block, lambda num, c: sms.append(c)), sms[-1])


def test_everything_survives_a_restart(tmp_path):
    path = str(tmp_path / "reg.db")
    reg = PersistentRegistry(path, oprf_per_hour=10**9)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    onboard(reg, "acme", "kanari.example", "0701")
    items = [(reg.issue_ticket("acme", "crm", op.commitment()), op)
             for op in (new_opening("kanari.example", "0701") for _ in range(3))]
    cs = register_ticketed(reg, "acme", items)
    key = reg.add_provider("gw")
    Detector(reg, key, "gw").scan(cs[0].person["email"])
    reg.close()

    inbox = []
    again = PersistentRegistry(path, oprf_per_hour=10**9)
    again.webhooks["acme"] = inbox.append
    assert again._k == reg._k and len(again.reports) == 1
    d = Detector(again, key, "gw").scan(f"{cs[1].person['email']} / {cs[2].person['last']}{cs[2].person['first']} {cs[2].person['address']}")
    assert set(d.confirmed) == {cs[1].canary_id, cs[2].canary_id}          # old tickets still verify
    assert sorted(r.canary_id for r in inbox) == sorted(d.confirmed)
    t = again.issue_ticket("acme", "crm", new_opening("kanari.example", "0701").commitment())   # ownership kept
    assert t.ticket_id in again._tickets


def test_abuse_log_survives_and_wrong_key_is_refused(tmp_path):
    path = str(tmp_path / "reg.db")
    reg = PersistentRegistry(path, oprf_per_hour=10**9)
    onboard(reg, "stalker", "stalk.example", "0809")
    op = new_opening("stalk.example", "0809")
    t = reg.issue_ticket("stalker", "crm", op.commitment())
    c = canary_from_ticket(t, op)
    toks = [(x, token_kind(x, c.person)) for x in person_tokens(c.person) if not x.startswith("e:")] + [("e:victim@gmail.com", "e")]
    rows, esc = [], {}
    for x, k in toks:
        r, b = blind(x)
        pt = unblind_point(r, reg.evaluate(b, "x"))
        rows.append((finalize(pt), prefix(x), t.ticket_id, "crm", k))
        esc[(finalize(pt), t.ticket_id)] = seal(escrow_key(pt), op.to_bytes(t.ticket_id))
    reg.register("stalker", rows, None, esc)
    Detector(reg, reg.add_provider("gw"), "gw").scan("victim@gmail.com")
    reg.close()
    again = PersistentRegistry(path)
    assert again.abuse_log and again.abuse_log[-1][0] == "stalker"
    again.close()
    with pytest.raises(ValueError):
        PersistentRegistry(path, key_hex="1234")


def test_service_tokens_survive_and_are_stored_hashed(tmp_path):
    path = str(tmp_path / "svc.db")
    app = create_app(PersistentRegistry(path), ADMIN, resolve_txt=lambda n: [], send_sms=lambda n, c: None)
    c = TestClient(app)
    adm = {"Authorization": f"Bearer {ADMIN}"}
    ptok = c.post("/admin/providers", json={"name": "gw"}, headers=adm).json()["token"]
    rtok = c.post("/admin/registrants", json={"name": "acme"}, headers=adm).json()["token"]
    app2 = create_app(PersistentRegistry(path), ADMIN)
    c2 = TestClient(app2)
    assert RemoteRegistry("http://r", ptok, c2).prefix_filter() == frozenset()
    RemoteRegistry("http://r", rtok, c2).domain_challenge("acme", "kanari.example")
    raw = open(path, "rb").read()
    assert ptok.encode() not in raw and rtok.encode() not in raw
