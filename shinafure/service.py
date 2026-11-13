"""The registry as an HTTP service.

    SHINAFURE_ADMIN_TOKEN=... uvicorn shinafure.service:app --port 8800

Three kinds of caller, each with a bearer token:
  admin       creates providers and registrants (POST /admin/...)
  registrant  proves ownership, draws tickets, registers F values
  provider    gets the prefix filter and F list, evaluates the OPRF, looks up and reports

Binary values travel as hex. Only blinded points, F values, prefixes and
sealed openings cross the wire; never a canary in plaintext, never a prompt.
Run it behind TLS. shinafure.remote.RemoteRegistry is the matching client:
Detector and register_ticketed work with it unchanged.

Notifications go to the registrant's webhook URL (JSON POST), or to a
`notify` callable when the app is built in code.
"""
from __future__ import annotations

import hmac
import os
import secrets
from typing import Callable, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from .registry import RateLimited, Registry, Report


def _dns_txt(name: str) -> list[str]:
    try:
        import dns.resolver
    except ImportError:
        raise HTTPException(501, "install dnspython to verify domains")
    try:
        return [b"".join(r.strings).decode() for r in dns.resolver.resolve(name, "TXT")]
    except Exception:
        return []


def _webhook_post(url: str, report: Report) -> None:
    import httpx
    try:
        httpx.post(url, json=report_json(report), timeout=5)
    except httpx.HTTPError:
        pass                            # delivery is best effort; the report stays in the registry


def report_json(r: Report) -> dict:
    return {"registrant": r.registrant, "canary_id": r.canary_id, "dataset": r.dataset, "provider": r.provider,
            "kinds": list(r.kinds), "status": r.status, "at": r.at}


# ------------------------------------------------------------------ bodies
class Name(BaseModel):
    name: str
    webhook_url: Optional[str] = None


class Blinded(BaseModel):
    blinded: str


class Domain(BaseModel):
    domain: str


class Block(BaseModel):
    block: str


class Confirm(BaseModel):
    challenge_id: str
    code: str


class TicketReq(BaseModel):
    dataset: str
    commitment: str


class Row(BaseModel):
    f: str
    prefix: int
    canary_id: str
    dataset: str
    kind: str


class Escrow(BaseModel):
    f: str
    canary_id: str
    sealed: str


class RegisterReq(BaseModel):
    rows: list[Row]
    escrows: list[Escrow] = []


class Lookup(BaseModel):
    f: str


class ReportReq(BaseModel):
    registrant: str
    canary_id: str
    dataset: str
    kinds: list[str]
    status: str
    keys: dict[str, str] = {}


def _hex(s: str) -> bytes:
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise HTTPException(400, "bad hex")


def create_app(registry: Optional[Registry] = None, admin_token: Optional[str] = None,
               resolve_txt: Callable[[str], list[str]] = _dns_txt,
               send_sms: Optional[Callable[[str, str], None]] = None,
               notify: Optional[Callable[[str, Report], None]] = None) -> FastAPI:
    reg = registry or Registry()
    admin = admin_token or os.environ.get("SHINAFURE_ADMIN_TOKEN") or ""
    if len(admin) < 16:
        raise RuntimeError("set an admin token of 16+ characters (SHINAFURE_ADMIN_TOKEN)")
    registrants: dict[str, str] = {}          # token -> registrant name
    providers: dict[str, tuple[str, str]] = {}  # token -> (provider name, registry api key)
    app = FastAPI(title="品触れ registry", version="0.8")

    def bearer(authorization: str = Header(default="")) -> str:
        if not authorization.startswith("Bearer "):
            raise HTTPException(401, "missing bearer token")
        return authorization[7:]

    def is_admin(tok: str = Depends(bearer)) -> None:
        if not hmac.compare_digest(tok, admin):
            raise HTTPException(403, "admin only")

    def registrant(tok: str = Depends(bearer)) -> str:
        if tok not in registrants:
            raise HTTPException(403, "registrants only")
        return registrants[tok]

    def provider(tok: str = Depends(bearer)) -> tuple[str, str]:
        if tok not in providers:
            raise HTTPException(403, "providers only")
        return providers[tok]

    def caller(tok: str = Depends(bearer)) -> str:
        if tok in registrants:
            return "r:" + registrants[tok]
        if tok in providers:
            return "p:" + providers[tok][0]
        raise HTTPException(403, "unknown caller")

    # ---------------------------------------------------------- admin
    @app.post("/admin/providers", dependencies=[Depends(is_admin)])
    def add_provider(b: Name):
        tok = secrets.token_urlsafe(24)
        providers[tok] = (b.name, reg.add_provider(b.name))
        return {"token": tok}

    @app.post("/admin/registrants", dependencies=[Depends(is_admin)])
    def add_registrant(b: Name):
        tok = secrets.token_urlsafe(24)
        registrants[tok] = b.name
        if notify:
            reg.webhooks[b.name] = lambda r, n=b.name: notify(n, r)
        elif b.webhook_url:
            reg.webhooks[b.name] = lambda r, u=b.webhook_url: _webhook_post(u, r)
        return {"token": tok}

    # ----------------------------------------------------------- OPRF
    @app.post("/oprf/evaluate")
    def evaluate(b: Blinded, who: str = Depends(caller)):
        try:
            return {"evaluated": reg.evaluate(_hex(b.blinded), who).hex()}
        except RateLimited:
            raise HTTPException(429, "rate limited")
        except ValueError:
            raise HTTPException(400, "not a curve point")

    # ------------------------------------------------------ registrant
    @app.post("/domains/challenge")
    def domain_challenge(b: Domain, who: str = Depends(registrant)):
        name, value = reg.domain_challenge(who, b.domain)
        return {"name": name, "value": value}

    @app.post("/domains/verify")
    def domain_verify(b: Domain, who: str = Depends(registrant)):
        return {"ok": reg.verify_domain(who, b.domain, resolve_txt)}

    @app.post("/phone-blocks/start")
    def block_start(b: Block, who: str = Depends(registrant)):
        if send_sms is None:
            raise HTTPException(501, "no SMS sender configured")
        try:
            return {"challenge_id": reg.start_phone_block(who, b.block, send_sms)}
        except ValueError as e:
            raise HTTPException(400, str(e))

    @app.post("/phone-blocks/confirm")
    def block_confirm(b: Confirm, who: str = Depends(registrant)):
        return {"ok": reg.confirm_phone_block(who, b.challenge_id, b.code)}

    @app.post("/tickets")
    def ticket(b: TicketReq, who: str = Depends(registrant)):
        try:
            t = reg.issue_ticket(who, b.dataset, _hex(b.commitment))
        except PermissionError as e:
            raise HTTPException(403, str(e))
        except RateLimited:
            raise HTTPException(429, "ticket limit reached")
        except ValueError as e:
            raise HTTPException(400, str(e))
        return {"ticket_id": t.ticket_id, "registrant": t.registrant, "dataset": t.dataset,
                "commitment": t.commitment.hex(), "nonce": t.nonce.hex(), "table": t.table}

    @app.post("/register")
    def register(b: RegisterReq, who: str = Depends(registrant)):
        rows = [(_hex(r.f), r.prefix, r.canary_id, r.dataset, r.kind) for r in b.rows]
        esc = {(_hex(e.f), e.canary_id): _hex(e.sealed) for e in b.escrows}
        try:
            n = reg.register(who, rows, None, esc if b.escrows or reg.require_tickets else None)
        except PermissionError as e:
            raise HTTPException(403, str(e))
        return {"registered": n}

    # -------------------------------------------------------- provider
    @app.get("/provider/filter")
    def prefix_filter(p: tuple = Depends(provider)):
        return {"prefixes": sorted(reg.prefix_filter(p[1]))}

    @app.get("/provider/f-values")
    def f_values(p: tuple = Depends(provider)):
        return {"f": sorted(f.hex() for f in reg.f_values(p[1]))}

    @app.post("/provider/lookup")
    def lookup(b: Lookup, p: tuple = Depends(provider)):
        return {"entries": [list(e) for e in reg.lookup(p[1], _hex(b.f))]}

    @app.post("/provider/report")
    def report(b: ReportReq, p: tuple = Depends(provider)):
        r = reg.report(p[1], b.registrant, b.canary_id, b.dataset, tuple(b.kinds), b.status,
                       {_hex(k): _hex(v) for k, v in b.keys.items()})
        return {"delivered": r.delivered}

    return app


def _lazy_app():
    try:
        return create_app()
    except RuntimeError:
        return None


app = _lazy_app()     # for `uvicorn shinafure.service:app` (needs SHINAFURE_ADMIN_TOKEN)
