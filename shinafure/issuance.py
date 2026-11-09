"""Verified issuance: canaries a registrant cannot aim at a real person.

The abuse this closes
  品触れ notifies whoever registered a value when that value appears in an AI
  input anywhere. A stalker who registered a real person's email, or name and
  address, would turn the network into a tracker. The registry cannot just
  inspect what is registered: registration is blind, it never sees plaintext.

Four pieces
  1. Ownership. A registrant proves control of email domains (a DNS TXT
     record) and of phone-number blocks (a one-time code sent to a random
     number inside the block). Done in Registry.
  2. Tickets. Every canary starts as a ticket. The registrant first commits to
     an Opening (secret s, domain, phone block, rare ratio); only then does
     the registry hand out a random nonce r. The canary is a deterministic
     function of H(r || s), so the registrant cannot choose its name, address
     or numbers. Grinding is capped by how many tickets it may draw.
  3. Sealed openings. For every token t of the canary, the registrant deposits
     the Opening encrypted under a key derived from k·H(t), the OPRF point
     whose hash is F(t). The registry stores F(t) but not k·H(t), so it cannot
     open a deposit until a provider actually sees t in an input and passes
     the key along with its report. (Deriving an encryption key from the
     message through a server's OPRF is the DupLESS construction.)
  4. Check before notify. On a confirmed match the registry opens the deposit,
     regenerates the canary, and checks that every token registered under the
     ticket belongs to it and that its domain and block are verified for this
     registrant. Only then is the registrant notified. A failed check changes
     nothing the registrant can observe (being asked, or being suspended,
     would itself tell a stalker that the target's data appeared); it goes to
     an abuse log for people to act on.

This module holds the pieces both sides compute. It imports nothing from
the registry, so the registry can import it.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass

from .canary import BUILDINGS, GIVEN, ORD_GIVEN, ORD_SURNAMES, PLACES, SURNAMES, Canary

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
SUFFIX_LEN = 8                 # 36^8 ≈ 2.8e12: a canary email is not guessable
PHONE_DIGITS = 11              # Japanese mobile numbers: 0X0-XXXX-XXXX
_BLOCK = re.compile(r"0\d{2,10}")


def valid_block(block: str) -> bool:
    return bool(_BLOCK.fullmatch(block))


@dataclass(frozen=True)
class Opening:
    """What the registrant commits to before it sees the ticket's nonce."""
    secret: bytes
    domain: str
    phone_block: str
    rare_permille: int = 200   # share of rare-name canaries, in 1/1000

    def commitment(self) -> bytes:
        h = hashlib.sha256(b"shinafure-commit-v1")
        for part in (self.secret, self.domain.encode(), self.phone_block.encode(), str(self.rare_permille).encode()):
            h.update(len(part).to_bytes(2, "big") + part)
        return h.digest()

    def to_bytes(self, ticket_id: str) -> bytes:
        return json.dumps({"t": ticket_id, "s": self.secret.hex(), "d": self.domain,
                           "b": self.phone_block, "q": self.rare_permille}, sort_keys=True).encode()

    @staticmethod
    def parse(blob: bytes, ticket_id: str) -> "Opening | None":
        try:
            o = json.loads(blob)
            if o["t"] != ticket_id:
                return None
            op = Opening(bytes.fromhex(o["s"]), str(o["d"]), str(o["b"]), int(o["q"]))
        except (ValueError, KeyError, TypeError):
            return None
        ok = len(op.secret) == 32 and valid_block(op.phone_block) and 0 <= op.rare_permille <= 1000
        return op if ok else None


def new_opening(domain: str, phone_block: str, rare_ratio: float = 0.2) -> Opening:
    if not valid_block(phone_block):
        raise ValueError("phone_block must be 3-11 digits starting with 0")
    return Opening(secrets.token_bytes(32), domain.strip().lower(), phone_block, round(rare_ratio * 1000))


@dataclass(frozen=True)
class Ticket:
    ticket_id: str
    registrant: str
    dataset: str
    commitment: bytes
    nonce: bytes               # drawn by the registry after the commitment


class Drbg:
    """SHA-256 counter-mode generator. A protocol-level PRG, so a canary
    regenerates identically on any machine and any Python version."""

    def __init__(self, seed: bytes) -> None:
        self._seed, self._ctr, self._buf = seed, 0, b""

    def _bytes(self, n: int) -> bytes:
        while len(self._buf) < n:
            self._buf += hashlib.sha256(self._seed + self._ctr.to_bytes(8, "big")).digest()
            self._ctr += 1
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def below(self, n: int) -> int:
        bits = (n - 1).bit_length()
        while True:
            x = int.from_bytes(self._bytes((bits + 7) // 8), "big") & ((1 << bits) - 1)
            if x < n:
                return x

    def choice(self, seq):
        return seq[self.below(len(seq))]

    def randint(self, a: int, b: int) -> int:
        return a + self.below(b - a + 1)


def canary_from_ticket(ticket: Ticket, op: Opening) -> Canary:
    """Deterministic: the registrant chooses nothing but the committed Opening."""
    g = Drbg(hashlib.sha256(b"shinafure-canary-v1|" + ticket.nonce + op.secret).digest())
    rare = g.below(1000) < op.rare_permille
    S, G = (SURNAMES, GIVEN) if rare else (ORD_SURNAMES, ORD_GIVEN)
    s, gv = g.choice(S), g.choice(G)
    pref, town = g.choice(PLACES)
    suffix = "".join(g.choice(ALPHABET) for _ in range(SUFFIX_LEN))
    digits = op.phone_block + "".join(str(g.below(10)) for _ in range(PHONE_DIGITS - len(op.phone_block)))
    person = {
        "last": s[0], "first": gv[0], "last_kana": s[1], "first_kana": gv[1],
        "last_roma": s[2], "first_roma": gv[2],
        "email": f"{gv[2].lower()}.{s[2].lower()}.{suffix}@{op.domain}",
        "phone": f"{digits[:3]}-{digits[3:7]}-{digits[7:]}",
        "address": f"{pref}{town}{g.randint(1, 9)}丁目{g.randint(1, 30)}番{g.randint(1, 20)}号 "
                   f"{s[0]}{g.choice(BUILDINGS)}{g.randint(1, 9)}0{g.randint(1, 9)}",
        "style": "rare" if rare else "ordinary",
    }
    return Canary(ticket.ticket_id, ticket.dataset, person)


# ------------------------------------------------------- sealed openings
# Encrypt-then-MAC from the standard library only (HMAC-SHA256 keystream).
# A deployment would use AES-GCM; the construction is not the point here.
def _sub(key: bytes, label: bytes) -> bytes:
    return hmac.new(key, label, hashlib.sha256).digest()


def _stream(key: bytes, nonce: bytes, n: int) -> bytes:
    out = b"".join(hmac.new(key, nonce + i.to_bytes(4, "big"), hashlib.sha256).digest()
                   for i in range((n + 31) // 32))
    return out[:n]


def seal(key: bytes, plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(16)
    ct = bytes(a ^ b for a, b in zip(plaintext, _stream(_sub(key, b"enc"), nonce, len(plaintext))))
    tag = hmac.new(_sub(key, b"mac"), nonce + ct, hashlib.sha256).digest()[:16]
    return nonce + ct + tag


def unseal(key: bytes, blob: bytes) -> bytes | None:
    if len(blob) < 32:
        return None
    nonce, ct, tag = blob[:16], blob[16:-16], blob[-16:]
    want = hmac.new(_sub(key, b"mac"), nonce + ct, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, want):
        return None
    return bytes(a ^ b for a, b in zip(ct, _stream(_sub(key, b"enc"), nonce, len(ct))))
