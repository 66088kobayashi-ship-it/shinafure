"""The registry ("品触れ" ledger) and the provider-side detector.

Threats this design takes seriously
  1. The registry must never hold plaintext canary values; a breach of the
     registry must not hand attackers a list of canaries to strip out.
  2. Providers must not send prompt contents to the registry.
  3. Nobody without the registry's cooperation may test "is this value a
     canary?" offline (otherwise attackers would filter stolen data first).
  4. Registrants must not be able to use the network to track real people
     (registering someone's real email, or name and address). See issuance.py.

Mechanism (close to Google's Password Checkup, applied to canary people)
  * F(t) = SHA256(k · H(t)) is an oblivious PRF keyed by the registry's secret
    k. Registrants learn F of their own tokens without revealing them
    (blinding), and register only F values. The registry stores F values.
  * Providers keep a confidential 24-bit prefix filter P(t) of registered
    tokens and check every candidate locally. Only candidates whose prefix
    matches go to the registry, blinded, so the registry learns nothing about
    the prompt. The OPRF endpoint is rate-limited per caller.
  * A canary is *confirmed* when a strong token (email, phone) matches, or
    when a name and a partner (address, phone tail) of the same canary match,
    or when two different rare-name canaries appear in one input. Anything
    else is *suspect* and never notified.
  * With require_tickets (the default), every canary comes from a ticket and
    carries sealed openings; the registry checks a confirmed match before it
    notifies anyone (issuance.py).

The honest weak point: the prefix filter is an oracle if it leaks (an
attacker could drop records whose tokens hit it). It is only given to
participating providers, never published.
"""
from __future__ import annotations

import hashlib
import secrets
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from . import ec
from .canary import Canary
from .issuance import Opening, Ticket, canary_from_ticket, seal, unseal, valid_block
from .tokens import NAME_KINDS, PARTNER_KINDS, STRONG, candidates, person_tokens

DOMAIN = b"shinafure-v0"
MAX_TOKENS_PER_CANARY = 8      # e, p, t, n×3 (kanji, katakana, hiragana), r, a


def H(token: str) -> ec.Point:
    return ec.hash_to_curve(DOMAIN, token.encode())


def prefix(token: str) -> int:
    return int.from_bytes(hashlib.sha256(DOMAIN + b"|P|" + token.encode()).digest()[:3], "big")


def finalize(kh: ec.Point) -> bytes:
    return hashlib.sha256(DOMAIN + b"|F|" + ec.encode(kh)).digest()


def escrow_key(kh: ec.Point) -> bytes:
    """Opens a sealed opening. Same OPRF point as F, different hash, so
    holding F (as the registry does) does not give the key."""
    return hashlib.sha256(DOMAIN + b"|K|" + ec.encode(kh)).digest()


def _rand() -> int:
    return secrets.randbelow(ec.N - 1) + 1


def blind(token: str) -> tuple[int, bytes]:
    r = _rand()
    return r, ec.encode(ec.mul(r, H(token)))


def unblind_point(r: int, evaluated: bytes) -> ec.Point:
    return ec.mul(pow(r, -1, ec.N), ec.decode(evaluated))


def unblind(r: int, evaluated: bytes) -> bytes:
    return finalize(unblind_point(r, evaluated))


def token_kind(tok: str, person: dict) -> str:
    kind = tok[0]
    if kind in ("n", "r") and person.get("style") == "ordinary":
        return "m"  # ordinary-looking names never confirm on their own
    return kind


class RateLimited(Exception):
    pass


@dataclass
class Report:
    registrant: str
    canary_id: str
    dataset: str
    provider: str
    kinds: tuple[str, ...]
    status: str            # confirmed | suspect
    at: float
    delivered: bool = False


Entry = tuple[str, str, str, str]   # (registrant, canary_id, dataset, kind)


class Registry:
    def __init__(self, oprf_per_hour: int = 50_000, clock: Callable[[], float] = time.time,
                 require_tickets: bool = True, tickets_per_day: int = 100) -> None:
        self._k = _rand()
        self._entries: dict[bytes, list[Entry]] = defaultdict(list)  # F -> entries (names can be shared)
        self._prefixes: set[int] = set()
        self._providers: dict[str, str] = {}   # api key -> provider name
        self._usage: dict[str, list] = defaultdict(list)
        self.oprf_per_hour = oprf_per_hour
        self.clock = clock
        self.reports: list[Report] = []
        self.webhooks: dict[str, Callable[[Report], None]] = {}
        # verified issuance
        self.require_tickets = require_tickets
        self.tickets_per_day = tickets_per_day
        self._domains: dict[str, set[str]] = defaultdict(set)
        self._blocks: dict[str, set[str]] = defaultdict(set)
        self._challenges: dict[tuple, object] = {}
        self._tickets: dict[str, Ticket] = {}
        self._ticket_times: dict[str, list[float]] = defaultdict(list)
        self._by_canary: dict[str, list[bytes]] = defaultdict(list)
        self._escrows: dict[tuple[bytes, str], bytes] = {}           # (F, canary_id) -> sealed opening
        self.abuse_log: list[tuple[str, str, str, float]] = []        # for people, never for the registrant

    # ---------------------------------------------------------- OPRF
    def evaluate(self, blinded: bytes, caller: str) -> bytes:
        now = self.clock()
        u = self._usage[caller]
        u[:] = [t for t in u if t > now - 3600]
        if len(u) >= self.oprf_per_hour:
            raise RateLimited(caller)
        u.append(now)
        return ec.encode(ec.mul(self._k, ec.decode(blinded)))

    # ------------------------------------------------------- ownership
    def domain_challenge(self, registrant: str, domain: str) -> tuple[str, str]:
        """Returns (TXT record name, value) the registrant must publish."""
        domain = domain.strip().lower()
        token = secrets.token_urlsafe(18)
        self._challenges[("d", registrant, domain)] = token
        return f"_shinafure.{domain}", f"shinafure-verify={token}"

    def verify_domain(self, registrant: str, domain: str, resolve_txt: Callable[[str], list[str]]) -> bool:
        domain = domain.strip().lower()
        token = self._challenges.get(("d", registrant, domain))
        if token is None:
            return False
        if f"shinafure-verify={token}" not in resolve_txt(f"_shinafure.{domain}"):
            return False
        del self._challenges[("d", registrant, domain)]
        self._domains[registrant].add(domain)
        return True

    def start_phone_block(self, registrant: str, block: str, send_sms: Callable[[str, str], None]) -> str:
        """Sends a code to a random number inside the claimed block. Only
        someone who receives calls for the whole block can answer reliably."""
        if not valid_block(block):
            raise ValueError("block must be 3-11 digits starting with 0")
        number = block + "".join(str(secrets.randbelow(10)) for _ in range(11 - len(block)))
        code = f"{secrets.randbelow(10**6):06d}"
        cid = secrets.token_hex(8)
        self._challenges[("p", registrant, cid)] = (block, code)
        send_sms(number, code)
        return cid

    def confirm_phone_block(self, registrant: str, challenge_id: str, code: str) -> bool:
        ch = self._challenges.pop(("p", registrant, challenge_id), None)   # one attempt only
        if ch is None or not secrets.compare_digest(ch[1], code):
            return False
        self._blocks[registrant].add(ch[0])
        return True

    # --------------------------------------------------------- tickets
    def issue_ticket(self, registrant: str, dataset: str, commitment: bytes) -> Ticket:
        if not (self._domains[registrant] and self._blocks[registrant]):
            raise PermissionError("verify a domain and a phone block first")
        if len(commitment) != 32:
            raise ValueError("commitment must be 32 bytes")
        now = self.clock()
        log = self._ticket_times[registrant]
        log[:] = [t for t in log if t > now - 86400]
        if len(log) >= self.tickets_per_day:
            raise RateLimited(registrant)
        log.append(now)
        t = Ticket(f"{dataset}-{secrets.token_hex(6)}", registrant, dataset, commitment, secrets.token_bytes(32))
        self._tickets[t.ticket_id] = t
        return t

    # ----------------------------------------------------- registrants
    def register(self, registrant: str, f_values: Iterable[tuple[bytes, int, str, str, str]],
                 webhook: Optional[Callable[[Report], None]] = None,
                 escrows: Optional[dict[tuple[bytes, str], bytes]] = None) -> int:
        """f_values: (F, prefix, canary_id, dataset, kind). No plaintext.
        With require_tickets, canary_id must be a ticket issued to this
        registrant and every row needs its sealed opening in `escrows`."""
        rows = list(f_values)
        if self.require_tickets:
            escrows = escrows or {}
            count = defaultdict(int)
            for f, _, cid, ds, _ in rows:
                t = self._tickets.get(cid)
                if t is None or t.registrant != registrant or t.dataset != ds:
                    raise PermissionError(f"no such ticket for {registrant}: {cid}")
                count[cid] += 1
                if len(self._by_canary[cid]) + count[cid] > MAX_TOKENS_PER_CANARY:
                    raise PermissionError(f"too many tokens for one canary: {cid}")
                if (f, cid) not in escrows:
                    raise PermissionError("every token needs its sealed opening")
        for f, p, cid, ds, kind in rows:
            self._entries[f].append((registrant, cid, ds, kind))
            self._by_canary[cid].append(f)
            self._prefixes.add(p)
            if self.require_tickets:
                self._escrows[(f, cid)] = escrows[(f, cid)]
        if webhook:
            self.webhooks[registrant] = webhook
        return len(rows)

    # ------------------------------------------------------- providers
    def add_provider(self, name: str) -> str:
        key = secrets.token_hex(16)
        self._providers[key] = name
        return key

    def prefix_filter(self, api_key: str) -> frozenset[int]:
        if api_key not in self._providers:
            raise PermissionError("providers only")
        return frozenset(self._prefixes)

    def lookup(self, api_key: str, f: bytes) -> list[Entry]:
        if api_key not in self._providers:
            raise PermissionError("providers only")
        return list(self._entries.get(f, ()))

    def report(self, api_key: str, registrant: str, canary_id: str, dataset: str,
               kinds: tuple[str, ...], status: str, keys: Optional[dict[bytes, bytes]] = None) -> Report:
        """keys: F -> escrow key, for the tokens the provider actually saw."""
        r = Report(registrant, canary_id, dataset, self._providers[api_key], kinds, status, self.clock())
        self.reports.append(r)
        if status != "confirmed":
            return r
        if self.require_tickets:
            ok, why = self._verify(registrant, canary_id, keys or {})
            if not ok:
                self.abuse_log.append((registrant, canary_id, why, r.at))
                return r          # nothing the registrant can observe changes
        hook = self.webhooks.get(registrant)
        if hook:
            hook(r)
            r.delivered = True
        return r

    # ------------------------------------------------ check before notify
    def _verify(self, registrant: str, cid: str, keys: dict[bytes, bytes]) -> tuple[bool, str]:
        ticket = self._tickets.get(cid)
        if ticket is None or ticket.registrant != registrant:
            return False, "unknown ticket"
        if not keys:
            return False, "no keys"
        blobs = set()
        for f, key in keys.items():
            sealed = self._escrows.get((f, cid))
            if sealed is None:
                return False, "token not registered under this ticket"
            blob = unseal(key, sealed)
            if blob is None:
                return False, "sealed opening does not open"
            blobs.add(blob)
        if len(blobs) != 1:
            return False, "inconsistent openings"
        op = Opening.parse(blobs.pop(), cid)
        if op is None:
            return False, "malformed opening"
        if op.commitment() != ticket.commitment:
            return False, "opening does not match commitment"
        if op.domain not in self._domains[registrant]:
            return False, "email domain not verified for registrant"
        if op.phone_block not in self._blocks[registrant]:
            return False, "phone block not verified for registrant"
        canary = canary_from_ticket(ticket, op)
        expected = {finalize(ec.mul(self._k, H(tok))): token_kind(tok, canary.person)
                    for tok in person_tokens(canary.person)}
        for f in self._by_canary[cid]:
            kinds = {e[3] for e in self._entries[f] if e[1] == cid}
            if expected.get(f) not in kinds:
                return False, "registered token is not part of the ticket's canary"
        return True, "ok"


def register_canaries(registry: Registry, registrant: str, canaries: list[Canary],
                      caller: str = "registrant", webhook=None) -> int:
    """Experiments only (Registry(require_tickets=False)): hand-made canaries."""
    rows = []
    for c in canaries:
        for tok in person_tokens(c.person):
            r, b = blind(tok)
            f = unblind(r, registry.evaluate(b, caller))
            rows.append((f, prefix(tok), c.canary_id, c.dataset, token_kind(tok, c.person)))
    return registry.register(registrant, rows, webhook)


def register_ticketed(registry: Registry, registrant: str, items: list[tuple[Ticket, Opening]],
                      caller: str = "registrant", webhook=None) -> list[Canary]:
    """Registrant side, production path: regenerate each ticket's canary,
    learn F and the escrow key of every token obliviously, seal the opening
    under each key, register. Returns the canaries to plant."""
    rows, escrows, out = [], {}, []
    for ticket, op in items:
        c = canary_from_ticket(ticket, op)
        blob = op.to_bytes(ticket.ticket_id)
        for tok in person_tokens(c.person):
            r, b = blind(tok)
            pt = unblind_point(r, registry.evaluate(b, caller))
            f = finalize(pt)
            rows.append((f, prefix(tok), c.canary_id, c.dataset, token_kind(tok, c.person)))
            escrows[(f, c.canary_id)] = seal(escrow_key(pt), blob)
        out.append(c)
    registry.register(registrant, rows, webhook, escrows)
    return out


@dataclass
class Detection:
    confirmed: dict[str, set] = field(default_factory=dict)   # canary_id -> kinds
    suspect: dict[str, set] = field(default_factory=dict)
    candidates: int = 0
    oprf_calls: int = 0


class Detector:
    """Runs at the AI provider / AI gateway, on every inference input."""

    def __init__(self, registry: Registry, api_key: str, name: str) -> None:
        self.registry = registry
        self.api_key = api_key
        self.name = name
        self.refresh()

    def refresh(self) -> None:
        self._filter = self.registry.prefix_filter(self.api_key)

    def scan(self, text: str, report: bool = True) -> Detection:
        det = Detection()
        hits: dict[str, dict] = {}
        seen: set[str] = set()
        for tok in candidates(text):
            det.candidates += 1
            if tok in seen or prefix(tok) not in self._filter:
                continue
            seen.add(tok)
            r, b = blind(tok)
            det.oprf_calls += 1
            pt = unblind_point(r, self.registry.evaluate(b, self.name))
            f = finalize(pt)
            for registrant, cid, ds, kind in self.registry.lookup(self.api_key, f):
                h = hits.setdefault(cid, {"registrant": registrant, "dataset": ds, "kinds": set(), "keys": {}})
                h["kinds"].add(kind)
                h["keys"][f] = escrow_key(pt)

        def solid(k: set) -> bool:
            # a strong token, or two different weak kinds where one is a partner
            return bool(k & STRONG) or bool(k & NAME_KINDS and k & PARTNER_KINDS) or PARTNER_KINDS <= k

        # Two or more *different* rare-name canaries in one input is not a
        # coincidence: one rare name can be, several cannot. Ordinary names
        # ("m") are excluded, they collide with real people.
        rare_name_only = [cid for cid, h in hits.items() if not solid(h["kinds"]) and h["kinds"] & {"n", "r"}]
        multi = set(rare_name_only) if len(rare_name_only) >= 2 else set()
        for cid, h in hits.items():
            kinds = h["kinds"]
            confirmed = solid(kinds) or cid in multi
            target = det.confirmed if confirmed else det.suspect
            target[cid] = kinds
            if report:
                self.registry.report(self.api_key, h["registrant"], cid, h["dataset"],
                                     tuple(sorted(kinds)), "confirmed" if confirmed else "suspect",
                                     keys=h["keys"] if confirmed else None)
        return det
