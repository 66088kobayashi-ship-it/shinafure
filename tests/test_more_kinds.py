"""v1.2: secret (API key) and sentence canaries, issued from tickets like people."""
import json

import pytest

from shinafure.issuance import Opening, canary_from_ticket, new_opening, seal
from shinafure.registry import Detector, Registry, blind, escrow_key, finalize, prefix, register_ticketed, unblind_point
from shinafure.tokens import candidates, norm_sentence, person_tokens


@pytest.fixture
def world():
    reg = Registry(oprf_per_hour=10**9)
    txt, sms, inbox = {}, [], []
    n, v = reg.domain_challenge("acme", "kanari.example")
    txt[n] = [v]
    reg.verify_domain("acme", "kanari.example", lambda q: txt.get(q, []))
    reg.confirm_phone_block("acme", reg.start_phone_block("acme", "0701", lambda num, c: sms.append(c)), sms[-1])
    items = []
    for kind in ("secret", "secret", "sentence", "sentence"):
        op = new_opening("kanari.example", "0701", kind=kind)
        items.append((reg.issue_ticket("acme", "repo", op.commitment()), op))
    cs = register_ticketed(reg, "acme", items, webhook=inbox.append)
    return reg, cs, Detector(reg, reg.add_provider("gw"), "gw"), inbox


def test_secret_found_in_config_code_and_json(world):
    reg, cs, det, inbox = world
    key = cs[0].person["secret"]
    for text in (f"DATABASE_URL=postgres://db\nPAYMENT_API_KEY={key}\nDEBUG=false",
                 f'client = Client(api_key="{key}", timeout=30)',
                 json.dumps({"service": {"token": key}})):
        assert cs[0].canary_id in det.scan(text, report=False).confirmed, text


def test_sentence_survives_reflowing_and_punctuation(world):
    reg, cs, det, inbox = world
    s = cs[2].person["sentence"]
    variants = [f"社外秘\n\n{s}\n以上。",
                "議事録： " + s.replace("、", "，").replace("は", "は ", 1),
                "- " + s, "  3. " + s, "> " + s,
                "「" + s[:12] + "\n" + s[12:] .replace("予定。", "予定") + "」"]
    for text in variants[:5]:
        assert cs[2].canary_id in det.scan(text, report=False).confirmed, text
    # a line break inside the sentence splits it: not found (stated limit)
    assert cs[2].canary_id not in det.scan(variants[5], report=False).confirmed


def test_rewording_is_not_detected(world):
    reg, cs, det, inbox = world
    s = cs[3].person["sentence"].replace("予定", "見込み")
    assert not det.scan(s, report=False).confirmed


def test_notifications_and_verification_work_for_new_kinds(world):
    reg, cs, det, inbox = world
    det.scan(cs[1].person["secret"] + "\n" + cs[3].person["sentence"])
    assert sorted(r.canary_id for r in inbox) == sorted([cs[1].canary_id, cs[3].canary_id])
    assert not reg.abuse_log


def test_a_real_key_cannot_be_registered_to_watch_it(world):
    reg, cs, det, inbox = world
    op = new_opening("kanari.example", "0701", kind="secret")
    t = reg.issue_ticket("acme", "repo", op.commitment())
    real = "app_live_" + "Q" * 36                         # someone else's key
    r, b = blind("k:" + real)
    pt = unblind_point(r, reg.evaluate(b, "x"))
    reg.register("acme", [(finalize(pt), prefix("k:" + real), t.ticket_id, "repo", "k")], None,
                 {(finalize(pt), t.ticket_id): seal(escrow_key(pt), op.to_bytes(t.ticket_id))})
    n = len(inbox)
    det.refresh()
    assert t.ticket_id in det.scan(f"KEY={real}").confirmed and len(inbox) == n
    assert reg.abuse_log[-1][2] == "registered token is not part of the ticket's canary"


def test_kind_is_committed():
    op = new_opening("kanari.example", "0701", kind="secret")
    other = Opening(op.secret, op.domain, op.phone_block, op.rare_permille, op.region, "sentence")
    assert op.commitment() != other.commitment()
    with pytest.raises(ValueError):
        new_opening("kanari.example", "0701", kind="password")


def test_ordinary_text_yields_no_false_secrets_or_sentences():
    text = ("This is a normal paragraph. It has a URL https://example.com/path?x=1 and a hash "
            "sha256:9f86d081884c7d659a2feaa0c55ad015 and an id user_42.\n普通の文章です。会議は明日の10時から始まります。")
    toks = [t for t in candidates(text) if t[0] in "ks"]
    assert all(t.startswith("s:") for t in toks)             # no key-shaped strings here
    assert norm_sentence("A, B「C」。") == "ABC"
