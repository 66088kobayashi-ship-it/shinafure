"""v0.4: verified issuance. A registrant can only be notified about canaries
it could not aim at a real person."""
import pytest

from shinafure.issuance import Opening, canary_from_ticket, new_opening, seal, unseal
from shinafure.registry import (Detector, RateLimited, Registry, blind, escrow_key, finalize, prefix,
                                register_ticketed, token_kind, unblind_point)
from shinafure.tokens import person_tokens

VICTIM = {"email": "hanako.yamada.1987@gmail.com", "name": "山田花子",
          "address": "東京都世田谷区松原3-12-8"}


class World:
    """DNS zone, phone network and inboxes, shared by everyone."""

    def __init__(self, **kw):
        self.reg = Registry(oprf_per_hour=10**9, **kw)
        self.txt: dict[str, list[str]] = {}
        self.blocks: dict[str, str] = {}          # block prefix -> owner
        self.sms: dict[str, list[str]] = {}       # owner -> codes received
        self.notes: dict[str, list] = {}
        self.det = Detector(self.reg, self.reg.add_provider("p1"), "p1")

    def send_sms(self, number, code):
        for blk, owner in self.blocks.items():
            if number.startswith(blk):
                self.sms.setdefault(owner, []).append(code)

    def onboard(self, who, domain, block):
        """Honest ownership checks for a domain and block `who` really controls."""
        name, value = self.reg.domain_challenge(who, domain)
        self.txt.setdefault(name, []).append(value)
        assert self.reg.verify_domain(who, domain, lambda n: self.txt.get(n, []))
        self.blocks[block] = who
        cid = self.reg.start_phone_block(who, block, self.send_sms)
        assert self.reg.confirm_phone_block(who, cid, self.sms[who][-1])
        self.notes[who] = []

    def tickets(self, who, n, domain, block, dataset="crm"):
        out = []
        for _ in range(n):
            op = new_opening(domain, block)
            out.append((self.reg.issue_ticket(who, dataset, op.commitment()), op))
        return out

    def scan(self, text):
        self.det.refresh()
        return self.det.scan(text)


@pytest.fixture
def w():
    w = World()
    w.onboard("acme", "kanari.example", "0701234")
    w.onboard("stalker", "stalk.example", "0809876")
    return w


def rows_for(reg, ticket, op, swap=None, extra=()):
    """What a registrant sends. `swap` replaces tokens of the genuine canary
    (kind -> list of fake tokens); `extra` adds tokens. Openings are sealed
    honestly, so only the registry's regeneration check can catch it."""
    c = canary_from_ticket(ticket, op)
    toks = [(t, token_kind(t, c.person)) for t in sorted(person_tokens(c.person))]
    for kind, fakes in (swap or {}).items():
        toks = [x for x in toks if x[0][0] != kind] + [(f, kind) for f in fakes]
    toks += list(extra)
    rows, escrows = [], {}
    for tok, kind in toks:
        r, b = blind(tok)
        pt = unblind_point(r, reg.evaluate(b, "x"))
        f = finalize(pt)
        rows.append((f, prefix(tok), ticket.ticket_id, ticket.dataset, kind))
        escrows[(f, ticket.ticket_id)] = seal(escrow_key(pt), op.to_bytes(ticket.ticket_id))
    return c, rows, escrows


# ------------------------------------------------------------ honest use
def test_honest_canaries_notify_on_every_path(w):
    cs = register_ticketed(w.reg, "acme", w.tickets("acme", 6, "kanari.example", "0701234"),
                           webhook=w.notes["acme"].append)
    for c in cs:
        assert c.person["email"].endswith("@kanari.example") and c.person["phone"].startswith("070-1234-")
    p = cs[0].person
    w.scan(f"顧客: {p['email']}")                                     # strong token
    w.scan(f"{p['last']} {p['first']} / {p['address']}")               # name + address
    digits = "".join(ch for ch in cs[1].person["phone"] if ch.isdigit())
    w.scan(f"{cs[1].person['last']}{cs[1].person['first']} {digits[1:]}")  # name + mangled phone
    got = [n.canary_id for n in w.notes["acme"]]
    assert got.count(cs[0].canary_id) == 2 and cs[1].canary_id in got
    assert not w.reg.abuse_log


def test_canary_is_fixed_by_the_ticket_not_by_the_registrant(w):
    (t, op), = w.tickets("acme", 1, "kanari.example", "0701234")
    assert canary_from_ticket(t, op).person == canary_from_ticket(t, op).person
    other = Opening(op.secret, op.domain, op.phone_block, op.rare_permille)
    assert other.commitment() == t.commitment   # the opening is all it can vary, and it is committed


# ------------------------------------------------------------- stalking
def test_real_email_swapped_into_a_ticket_never_notifies(w):
    (t, op), = w.tickets("stalker", 1, "stalk.example", "0809876")
    _, rows, esc = rows_for(w.reg, t, op, swap={"e": ["e:" + VICTIM["email"]]})
    w.reg.register("stalker", rows, w.notes["stalker"].append, esc)
    d = w.scan(f"問い合わせ: {VICTIM['email']}")
    assert t.ticket_id in d.confirmed                 # the provider did match it...
    assert w.notes["stalker"] == []                   # ...but nobody is told
    assert w.reg.abuse_log[-1][2] == "registered token is not part of the ticket's canary"


def test_real_name_and_address_swapped_in_never_notify(w):
    (t, op), = w.tickets("stalker", 1, "stalk.example", "0809876")
    fake_names = ["n:" + VICTIM["name"]]
    _, rows, esc = rows_for(w.reg, t, op, swap={"n": fake_names, "a": ["a:" + VICTIM["address"]]})
    w.reg.register("stalker", rows, w.notes["stalker"].append, esc)
    d = w.scan(f"{VICTIM['name']} 様 {VICTIM['address']}")
    assert t.ticket_id in d.confirmed and w.notes["stalker"] == []
    assert w.reg.abuse_log


def test_adding_tokens_beyond_one_canary_is_refused(w):
    (t, op), = w.tickets("stalker", 1, "stalk.example", "0809876")
    _, rows, esc = rows_for(w.reg, t, op, extra=[("e:" + VICTIM["email"], "e")])
    with pytest.raises(PermissionError):
        w.reg.register("stalker", rows, None, esc)


def test_unverified_domain_or_block_never_notifies(w):
    for domain, block, why in (("gmail.com", "0809876", "email domain not verified for registrant"),
                               ("stalk.example", "0901111", "phone block not verified for registrant")):
        op = new_opening(domain, block)
        t = w.reg.issue_ticket("stalker", "crm", op.commitment())
        c, rows, esc = rows_for(w.reg, t, op)
        w.reg.register("stalker", rows, w.notes["stalker"].append, esc)
        w.scan(c.person["email"])
        assert w.notes["stalker"] == [] and w.reg.abuse_log[-1][2] == why


def test_tickets_cannot_be_forged_or_borrowed(w):
    (t, op), = w.tickets("acme", 1, "kanari.example", "0701234")
    _, rows, esc = rows_for(w.reg, t, op)
    with pytest.raises(PermissionError):
        w.reg.register("stalker", rows, None, esc)                # someone else's ticket
    bad = [(f, p, "crm-made-up", ds, k) for f, p, _, ds, k in rows]
    with pytest.raises(PermissionError):
        w.reg.register("acme", bad, None, esc)                    # never issued
    with pytest.raises(PermissionError):
        w.reg.register("acme", rows, None, {})                    # no sealed openings


def test_failure_is_invisible_to_the_registrant(w):
    (t, op), = w.tickets("stalker", 1, "stalk.example", "0809876")
    _, rows, esc = rows_for(w.reg, t, op, swap={"e": ["e:" + VICTIM["email"]]})
    w.reg.register("stalker", rows, w.notes["stalker"].append, esc)
    w.scan(VICTIM["email"])
    # Not suspended, not asked anything: it can keep drawing tickets and its
    # genuine canaries still notify, so nothing tells it the victim appeared.
    honest = register_ticketed(w.reg, "stalker", w.tickets("stalker", 1, "stalk.example", "0809876"),
                               webhook=w.notes["stalker"].append)
    w.scan(honest[0].person["email"])
    assert [n.canary_id for n in w.notes["stalker"]] == [honest[0].canary_id]


# --------------------------------------------------------- ownership
def test_domain_needs_the_txt_record():
    reg = Registry()
    reg.domain_challenge("stalker", "gmail.com")
    assert not reg.verify_domain("stalker", "gmail.com", lambda n: ["v=spf1 include:_spf.google.com"])
    with pytest.raises(PermissionError):
        reg.issue_ticket("stalker", "crm", b"\0" * 32)


def test_phone_block_needs_the_code_sent_inside_it(w):
    cid = w.reg.start_phone_block("stalker", "0901111", w.send_sms)   # a block it does not own
    assert "0901111" not in w.blocks
    assert not w.reg.confirm_phone_block("stalker", cid, "000000")
    assert not w.reg.confirm_phone_block("stalker", cid, w.sms["stalker"][-1])   # one attempt only


def test_ticket_cap_bounds_grinding():
    w = World(tickets_per_day=5)
    w.onboard("acme", "kanari.example", "0701234")
    w.tickets("acme", 5, "kanari.example", "0701234")
    with pytest.raises(RateLimited):
        w.tickets("acme", 1, "kanari.example", "0701234")


# ------------------------------------------------- registry stays blind
def test_registry_state_does_not_open_the_deposits(w):
    cs = register_ticketed(w.reg, "acme", w.tickets("acme", 3, "kanari.example", "0701234"))
    state = repr(dict(w.reg._entries)) + repr(w.reg._escrows) + repr(w.reg._tickets)
    for c in cs:
        for tok in person_tokens(c.person):
            assert tok[2:] not in state
    for (f, _), sealed in w.reg._escrows.items():
        assert unseal(f, sealed) is None    # F, which the registry holds, is not the key


def test_shared_ordinary_name_keeps_every_canary():
    from shinafure.canary import make_canaries
    import random
    reg = Registry(require_tickets=False)
    from shinafure.registry import register_canaries
    a = make_canaries(1, "ds-a", "kanari.example", random.Random(4), style="ordinary")
    b = make_canaries(1, "ds-b", "kanari.example", random.Random(4), style="ordinary")
    assert a[0].person["last"] + a[0].person["first"] == b[0].person["last"] + b[0].person["first"]
    register_canaries(reg, "acme", a)
    register_canaries(reg, "acme", b)
    d = Detector(reg, reg.add_provider("p"), "p").scan(a[0].person["last"] + a[0].person["first"], report=False)
    assert set(d.suspect) == {a[0].canary_id, b[0].canary_id}
