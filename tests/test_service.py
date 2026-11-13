"""v0.8: the registry as an HTTP service, with the same Detector on top."""
import pytest
from fastapi.testclient import TestClient

from shinafure.issuance import canary_from_ticket, new_opening, seal
from shinafure.registry import Detector, Registry, blind, escrow_key, finalize, prefix, register_ticketed, token_kind, unblind_point
from shinafure.remote import RemoteRegistry
from shinafure.service import create_app
from shinafure.tokens import person_tokens

ADMIN = "admin-token-0123456789"


@pytest.fixture
def world():
    txt, sms, inbox, wire = {}, [], [], []
    app = create_app(Registry(oprf_per_hour=10**9), ADMIN, resolve_txt=lambda n: txt.get(n, []),
                     send_sms=lambda num, code: sms.append(code), notify=lambda who, r: inbox.append((who, r)))
    client = TestClient(app)
    client.event_hooks["request"] = [lambda req: wire.append(req.content)]
    adm = {"Authorization": f"Bearer {ADMIN}"}
    tok = lambda path, name: client.post(path, json={"name": name}, headers=adm).json()["token"]

    def remote(t):
        return RemoteRegistry("http://registry", t, client)

    def onboard(name, domain, block):
        r = remote(tok("/admin/registrants", name))
        n, v = r.domain_challenge(name, domain)
        txt[n] = [v]
        assert r.verify_domain(name, domain)
        assert r.confirm_phone_block(name, r.start_phone_block(name, block), sms[-1])
        return r

    return client, tok, remote, onboard, inbox, wire


def test_end_to_end_over_http(world):
    client, tok, remote, onboard, inbox, wire = world
    acme = onboard("acme", "kanari.example", "0701")
    items = []
    for _ in range(3):
        op = new_opening("kanari.example", "0701", 0.2, "関東")
        items.append((acme.issue_ticket("acme", "crm", op.commitment()), op))
    cs = register_ticketed(acme, "acme", items)
    det = Detector(remote(tok("/admin/providers", "gw")), "", "gw")
    d = det.scan(f"顧客一覧\n{cs[0].person['email']}\n{cs[1].person['last']}{cs[1].person['first']} {cs[1].person['address']}")
    assert set(d.confirmed) == {cs[0].canary_id, cs[1].canary_id}
    assert sorted(r.canary_id for _, r in inbox) == sorted(d.confirmed)
    sent = b"".join(wire).decode()
    for c in cs:                                   # no canary value ever crosses the wire in plaintext
        for t in person_tokens(c.person):
            assert t[2:] not in sent
    assert "顧客一覧" not in sent                  # nor any of the prompt


def test_stalking_is_still_withheld_over_http(world):
    client, tok, remote, onboard, inbox, wire = world
    st = onboard("stalker", "stalk.example", "0809")
    op = new_opening("stalk.example", "0809")
    t = st.issue_ticket("stalker", "crm", op.commitment())
    c = canary_from_ticket(t, op)
    toks = [(x, token_kind(x, c.person)) for x in person_tokens(c.person) if not x.startswith("e:")]
    toks.append(("e:hanako.yamada.1987@gmail.com", "e"))
    rows, esc = [], {}
    for x, k in toks:
        r, b = blind(x)
        pt = unblind_point(r, st.evaluate(b))
        f = finalize(pt)
        rows.append((f, prefix(x), t.ticket_id, "crm", k))
        esc[(f, t.ticket_id)] = seal(escrow_key(pt), op.to_bytes(t.ticket_id))
    st.register("stalker", rows, None, esc)
    det = Detector(remote(tok("/admin/providers", "gw")), "", "gw")
    d = det.scan("問い合わせ: hanako.yamada.1987@gmail.com")
    assert t.ticket_id in d.confirmed and inbox == []


def test_roles_are_enforced(world):
    client, tok, remote, onboard, inbox, wire = world
    reg_tok, prov_tok = tok("/admin/registrants", "acme"), tok("/admin/providers", "gw")
    with pytest.raises(PermissionError):
        remote(reg_tok).prefix_filter()
    with pytest.raises(PermissionError):
        remote(prov_tok).issue_ticket("x", "crm", b"\0" * 32)
    with pytest.raises(PermissionError):
        remote("not-a-token").evaluate(b"\0" * 32)
    assert client.post("/admin/providers", json={"name": "x"}, headers={"Authorization": f"Bearer {prov_tok}"}).status_code == 403
    assert client.get("/provider/filter").status_code == 401


def test_admin_token_must_be_long():
    with pytest.raises(RuntimeError):
        create_app(Registry(), "short")
