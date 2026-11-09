"""Can a registrant use 品触れ to track a real person? (v0.4)

    python -m demo.abuse

An honest company and a stalker both pass the ownership checks for their own
domain and phone block. The stalker then tries to get notified when a real
person's data appears in an AI input. Each row: did the provider match it,
and was the registrant notified.
"""
from __future__ import annotations

from shinafure.issuance import canary_from_ticket, new_opening, seal
from shinafure.registry import (Detector, Registry, blind, escrow_key, finalize, prefix,
                                register_ticketed, token_kind, unblind_point)
from shinafure.tokens import person_tokens

VICTIM_EMAIL = "hanako.yamada.1987@gmail.com"
VICTIM_NAME, VICTIM_ADDR = "山田花子", "東京都世田谷区松原3-12-8"


def main() -> None:
    reg = Registry(oprf_per_hour=10**9)
    txt, owners, sms = {}, {}, {}
    inbox = {"acme": [], "stalker": []}

    def send(number, code):
        for blk, who in owners.items():
            if number.startswith(blk):
                sms.setdefault(who, []).append(code)

    def onboard(who, domain, block):
        name, value = reg.domain_challenge(who, domain)
        txt[name] = [value]
        assert reg.verify_domain(who, domain, lambda n: txt.get(n, []))
        owners[block] = who
        assert reg.confirm_phone_block(who, reg.start_phone_block(who, block, send), sms[who][-1])

    onboard("acme", "kanari.example", "0701234")
    onboard("stalker", "stalk.example", "0809876")
    det = Detector(reg, reg.add_provider("p1"), "p1")

    def ticket(who, domain, block):
        op = new_opening(domain, block)
        return reg.issue_ticket(who, "crm", op.commitment()), op

    def rows_for(t, op, swap=None, extra=()):
        """Openings sealed honestly; only the tokens are tampered with."""
        c = canary_from_ticket(t, op)
        toks = [(x, token_kind(x, c.person)) for x in sorted(person_tokens(c.person))]
        for kind, fakes in (swap or {}).items():
            toks = [x for x in toks if x[0][0] != kind] + [(f, kind) for f in fakes]
        toks += list(extra)
        rows, esc = [], {}
        for tok, kind in toks:
            r, b = blind(tok)
            pt = unblind_point(r, reg.evaluate(b, "x"))
            f = finalize(pt)
            rows.append((f, prefix(tok), t.ticket_id, "crm", kind))
            esc[(f, t.ticket_id)] = seal(escrow_key(pt), op.to_bytes(t.ticket_id))
        return c, rows, esc

    def honest():
        c = register_ticketed(reg, "acme", [ticket("acme", "kanari.example", "0701234")],
                              webhook=inbox["acme"].append)[0]
        return "acme", c.canary_id, f"顧客: {c.person['email']}"

    def stalker(domain, block, swap, text):
        def setup():
            t, op = ticket("stalker", domain, block)
            c, rows, esc = rows_for(t, op, swap)
            reg.register("stalker", rows, inbox["stalker"].append, esc)
            return "stalker", t.ticket_id, text or c.person["email"]
        return setup

    scenarios = [
        ("正規：自社カナリアのメールが入力に出る", honest),
        ("悪用：実在の人のメールをチケットに紛れ込ませる",
         stalker("stalk.example", "0809876", {"e": ["e:" + VICTIM_EMAIL]}, f"問い合わせ: {VICTIM_EMAIL}")),
        ("悪用：実在の人の氏名と住所を紛れ込ませる",
         stalker("stalk.example", "0809876", {"n": ["n:" + VICTIM_NAME], "a": ["a:" + VICTIM_ADDR]},
                 f"{VICTIM_NAME} 様 {VICTIM_ADDR}")),
        ("悪用：所有を確認していないドメインでカナリアを作る", stalker("gmail.com", "0809876", None, None)),
        ("悪用：所有を確認していない番号ブロックでカナリアを作る", stalker("stalk.example", "0901111", None, None)),
    ]
    out = []
    for label, setup in scenarios:
        who, cid, text = setup()
        before, logged = len(inbox[who]), len(reg.abuse_log)
        det.refresh()
        d = det.scan(text)
        told = len(inbox[who]) > before
        why = reg.abuse_log[-1][2] if len(reg.abuse_log) > logged else ""
        out.append((label, "一致" if cid in d.confirmed else "なし", "届いた" if told else "届かない", why))

    t, op = ticket("stalker", "stalk.example", "0809876")
    _, rows, esc = rows_for(t, op, extra=[("e:" + VICTIM_EMAIL, "e")])
    try:
        reg.register("stalker", rows, None, esc)
        out.append(("悪用：1枚のチケットに手がかりを足す", "-", "登録できた", ""))
    except PermissionError as exc:
        out.append(("悪用：1枚のチケットに手がかりを足す", "-", "登録を拒否", str(exc).split(":")[0]))

    print("| 試み | 提供者の照合 | 登録者への通知 | 台帳の判断（登録者には見えない） |")
    print("| --- | --- | --- | --- |")
    for r in out:
        print("| " + " | ".join(r) + " |")


if __name__ == "__main__":
    main()
