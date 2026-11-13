"""v1.0: revoking and rotating tokens, signed webhooks, retried notifications."""
import json

import pytest
from fastapi.testclient import TestClient

from shinafure.issuance import new_opening
from shinafure.registry import Detector, Registry, register_ticketed
from shinafure.remote import RemoteRegistry
from shinafure.service import create_app, verify_signature
from shinafure.store import PersistentRegistry

ADMIN = "admin-token-0123456789"
ADM = {"Authorization": f"Bearer {ADMIN}"}


class Hook:
    """A registrant's webhook endpoint that can be switched off."""
    def __init__(self):
        self.up, self.got = True, []

    def __call__(self, url, body, headers):
        if not self.up:
            return False
        self.got.append((url, body, headers))
        return True


def build(reg, hook, now):
    txt, sms = {}, []
    app = create_app(reg, ADMIN, resolve_txt=lambda n: txt.get(n, []), send_sms=lambda n, c: sms.append(c),
                     post=hook, clock=lambda: now[0])
    return app, TestClient(app), txt, sms


def setup_world(reg, hook, now):
    app, c, txt, sms = build(reg, hook, now)
    r = c.post("/admin/registrants", json={"name": "acme", "webhook_url": "https://acme.example/hook"}, headers=ADM).json()
    p = c.post("/admin/providers", json={"name": "gw"}, headers=ADM).json()
    acme = RemoteRegistry("http://r", r["token"], c)
    n, v = acme.domain_challenge("acme", "kanari.example")
    txt[n] = [v]
    acme.verify_domain("acme", "kanari.example")
    acme.confirm_phone_block("acme", acme.start_phone_block("acme", "0701"), sms[-1])
    ops = [new_opening("kanari.example", "0701") for _ in range(3)]
    cs = register_ticketed(acme, "acme", [(acme.issue_ticket("acme", "crm", o.commitment()), o) for o in ops])
    return app, c, r, p, cs


def test_revoked_and_rotated_tokens_stop_working():
    hook, now = Hook(), [1000.0]
    app, c, r, p, cs = setup_world(Registry(oprf_per_hour=10**9), hook, now)
    ids = {t["name"]: t["id"] for t in c.get("/admin/tokens", headers=ADM).json()["tokens"]}
    assert set(ids) == {"acme", "gw"}
    assert c.delete(f"/admin/tokens/{ids['gw']}", headers=ADM).status_code == 200
    with pytest.raises(PermissionError):
        RemoteRegistry("http://r", p["token"], c).prefix_filter()
    new = c.post("/me/rotate", headers={"Authorization": f"Bearer {r['token']}"}).json()["token"]
    with pytest.raises(PermissionError):
        RemoteRegistry("http://r", r["token"], c).domain_challenge("acme", "x.example")
    RemoteRegistry("http://r", new, c).domain_challenge("acme", "x.example")
    assert c.delete("/admin/tokens/abc", headers=ADM).status_code == 404       # ids shorter than 8 never match


def test_webhooks_are_signed_and_retried_until_delivered():
    hook, now = Hook(), [1000.0]
    app, c, r, p, cs = setup_world(Registry(oprf_per_hour=10**9), hook, now)
    det = Detector(RemoteRegistry("http://r", p["token"], c), "", "gw")
    det.scan(cs[0].person["email"])
    url, body, headers = hook.got[-1]
    assert verify_signature(r["webhook_secret"], body, headers["X-Shinafure-Signature"])
    assert not verify_signature("wrong", body, headers["X-Shinafure-Signature"])
    assert json.loads(body)["canary_id"] == cs[0].canary_id

    hook.up = False                                     # the registrant's endpoint goes down
    det.scan(cs[1].person["email"])
    assert len(app.state.outbox) == 1
    assert c.post("/admin/outbox/retry", headers=ADM).json()["delivered"] == 0     # not due yet
    now[0] += 31
    assert app.state.retry_outbox()["waiting"] == 1                                # due, still down, backs off
    hook.up = True
    now[0] += 3600
    assert app.state.retry_outbox() == {"delivered": 1, "waiting": 0, "given_up": 0}
    assert json.loads(hook.got[-1][1])["canary_id"] == cs[1].canary_id


def test_outbox_and_revocations_survive_restart(tmp_path):
    path = str(tmp_path / "r.db")
    hook, now = Hook(), [1000.0]
    app, c, r, p, cs = setup_world(PersistentRegistry(path, oprf_per_hour=10**9), hook, now)
    hook.up = False
    Detector(RemoteRegistry("http://r", p["token"], c), "", "gw").scan(cs[2].person["email"])
    gw = next(t["id"] for t in c.get("/admin/tokens", headers=ADM).json()["tokens"] if t["name"] == "gw")
    c.delete(f"/admin/tokens/{gw}", headers=ADM)

    hook2, now2 = Hook(), [99999.0]
    app2, c2, *_ = build(PersistentRegistry(path, oprf_per_hour=10**9), hook2, now2)
    assert len(app2.state.outbox) == 1
    assert app2.state.retry_outbox()["delivered"] == 1
    url, body, headers = hook2.got[-1]
    assert verify_signature(r["webhook_secret"], body, headers["X-Shinafure-Signature"])   # same secret after restart
    with pytest.raises(PermissionError):
        RemoteRegistry("http://r", p["token"], c2).prefix_filter()
