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

Notifications go to the registrant's webhook URL as a JSON POST signed with
HMAC-SHA256 (header X-Shinafure-Signature: sha256=<hex>, key = the webhook
secret given when the registrant was created), or to a `notify` callable
when the app is built in code. Failed deliveries wait in an outbox and are
retried with backoff (30 s doubling, at most 1 h apart, 12 attempts).

Tokens can be listed and revoked by the admin (GET/DELETE /admin/tokens),
and replaced by their holder (POST /me/rotate, the old one stops working).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from typing import Callable, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from .registry import RateLimited, Registry, Report

MAX_ATTEMPTS = 12


def _dns_txt(name: str) -> list[str]:
    try:
        import dns.resolver
    except ImportError:
        raise HTTPException(501, "install dnspython to verify domains")
    try:
        return [b"".join(r.strings).decode() for r in dns.resolver.resolve(name, "TXT")]
    except Exception:
        return []


def _http_post(url: str, body: bytes, headers: dict) -> bool:
    import httpx
    try:
        return httpx.post(url, content=body, headers=headers, timeout=5).is_success
    except httpx.HTTPError:
        return False


def verify_signature(secret: str, body: bytes, header: str) -> bool:
    """For registrants: check that a notification really came from the registry."""
    want = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header or "")


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
               notify: Optional[Callable[[str, Report], None]] = None,
               post: Callable[[str, bytes, dict], bool] = _http_post,
               retry_seconds: float = 0, clock: Callable[[], float] = time.time) -> FastAPI:
    reg = registry or Registry()
    admin = admin_token or os.environ.get("SHINAFURE_ADMIN_TOKEN") or ""
    if len(admin) < 16:
        raise RuntimeError("set an admin token of 16+ characters (SHINAFURE_ADMIN_TOKEN)")
    # tokens are kept as SHA-256 hashes; with a PersistentRegistry they survive restarts
    registrants: dict[str, str] = {}            # token hash -> registrant name
    providers: dict[str, tuple[str, str]] = {}  # token hash -> (provider name, registry api key)
    db = getattr(reg, "db", None)
    app = FastAPI(title="品触れ registry", version="0.9")

    def h(tok: str) -> str:
        return hashlib.sha256(tok.encode()).hexdigest()

    lock = getattr(reg, "lock", None) or threading.RLock()
    urls: dict[str, Optional[str]] = {}         # registrant -> webhook URL
    hook_secrets: dict[str, str] = {}           # registrant -> webhook signing secret
    outbox: list[dict] = []                     # undelivered notifications

    # ------------------------------------------------------- delivery
    def try_deliver(name: str, payload: dict) -> bool:
        if notify:
            try:
                notify(name, Report(payload["registrant"], payload["canary_id"], payload["dataset"],
                                    payload["provider"], tuple(payload["kinds"]), payload["status"], payload["at"]))
                return True
            except Exception:
                return False
        url = urls.get(name)
        if not url:
            return True
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode()
        sig = "sha256=" + hmac.new(hook_secrets.get(name, "").encode(), body, hashlib.sha256).hexdigest()
        return post(url, body, {"content-type": "application/json", "X-Shinafure-Signature": sig})

    def enqueue(name: str, payload: dict) -> None:
        item = {"registrant": name, "payload": payload, "attempts": 1, "next_at": clock() + 30}
        with lock:
            if db is not None:
                with db:
                    item["id"] = db.execute("INSERT INTO outbox(registrant, payload, attempts, next_at) VALUES(?, ?, ?, ?)",
                                            (name, json.dumps(payload, ensure_ascii=False), 1, item["next_at"])).lastrowid
            outbox.append(item)

    def deliver(name: str, report: Report) -> None:
        payload = report_json(report)
        if not try_deliver(name, payload):
            enqueue(name, payload)

    def retry_outbox() -> dict:
        now, sent = clock(), 0
        with lock:
            due = [x for x in outbox if x["next_at"] <= now and x["attempts"] < MAX_ATTEMPTS]
        for x in due:
            ok = try_deliver(x["registrant"], x["payload"])
            with lock:
                if ok:
                    sent += 1
                    outbox.remove(x)
                    if db is not None:
                        with db:
                            db.execute("DELETE FROM outbox WHERE id=?", (x["id"],))
                else:
                    x["attempts"] += 1
                    x["next_at"] = now + min(3600, 30 * 2 ** x["attempts"])
                    if db is not None:
                        with db:
                            db.execute("UPDATE outbox SET attempts=?, next_at=? WHERE id=?", (x["attempts"], x["next_at"], x["id"]))
        return {"delivered": sent, "waiting": len(outbox),
                "given_up": sum(1 for x in outbox if x["attempts"] >= MAX_ATTEMPTS)}

    app.state.retry_outbox = retry_outbox
    app.state.outbox = outbox

    def hook_for(name: str, webhook_url: Optional[str]):
        urls[name] = webhook_url
        reg.webhooks[name] = lambda r, n=name: deliver(n, r)

    # --------------------------------------------------------- tokens
    def remember(tok_hash: str, role: str, name: str, ref: str = "", webhook: Optional[str] = None) -> None:
        if db is not None:
            with lock, db:
                db.execute("INSERT INTO tokens VALUES(?, ?, ?, ?, ?)", (tok_hash, role, name, ref, webhook))

    def forget(tok_hash: str) -> None:
        registrants.pop(tok_hash, None)
        providers.pop(tok_hash, None)
        if db is not None:
            with lock, db:
                db.execute("DELETE FROM tokens WHERE hash=?", (tok_hash,))

    if db is not None:
        for th, role, name, ref, webhook in db.execute("SELECT * FROM tokens"):
            if role == "registrant":
                registrants[th] = name
                hook_for(name, webhook)
            else:
                providers[th] = (name, ref)
        hook_secrets.update(dict(db.execute("SELECT registrant, secret FROM webhook_secrets")))
        for i, name, payload, attempts, next_at in db.execute("SELECT * FROM outbox ORDER BY id"):
            outbox.append({"id": i, "registrant": name, "payload": json.loads(payload), "attempts": attempts, "next_at": next_at})

    if retry_seconds > 0:
        def loop():
            while True:
                time.sleep(retry_seconds)
                retry_outbox()
        threading.Thread(target=loop, daemon=True, name="shinafure-outbox").start()

    def bearer(authorization: str = Header(default="")) -> str:
        if not authorization.startswith("Bearer "):
            raise HTTPException(401, "missing bearer token")
        return h(authorization[7:])

    def is_admin(tok: str = Depends(bearer)) -> None:
        if not hmac.compare_digest(tok, h(admin)):
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
        providers[h(tok)] = (b.name, reg.add_provider(b.name))
        remember(h(tok), "provider", b.name, providers[h(tok)][1])
        return {"token": tok, "id": h(tok)[:12]}

    @app.post("/admin/registrants", dependencies=[Depends(is_admin)])
    def add_registrant(b: Name):
        tok = secrets.token_urlsafe(24)
        registrants[h(tok)] = b.name
        hook_for(b.name, b.webhook_url)
        remember(h(tok), "registrant", b.name, "", b.webhook_url)
        if b.name not in hook_secrets:
            hook_secrets[b.name] = secrets.token_urlsafe(32)
            if db is not None:
                with lock, db:
                    db.execute("INSERT OR REPLACE INTO webhook_secrets VALUES(?, ?)", (b.name, hook_secrets[b.name]))
        return {"token": tok, "id": h(tok)[:12], "webhook_secret": hook_secrets[b.name]}

    @app.get("/admin/tokens", dependencies=[Depends(is_admin)])
    def list_tokens():
        out = [{"id": t[:12], "role": "registrant", "name": n} for t, n in registrants.items()]
        out += [{"id": t[:12], "role": "provider", "name": n} for t, (n, _) in providers.items()]
        return {"tokens": out}

    @app.delete("/admin/tokens/{token_id}", dependencies=[Depends(is_admin)])
    def revoke(token_id: str):
        hits = [t for t in list(registrants) + list(providers) if t.startswith(token_id)]
        if len(token_id) < 8 or len(hits) != 1:
            raise HTTPException(404, "no single token with that id")
        forget(hits[0])
        return {"revoked": token_id}

    @app.get("/admin/outbox", dependencies=[Depends(is_admin)])
    def outbox_status():
        return {"waiting": len(outbox), "given_up": sum(1 for x in outbox if x["attempts"] >= MAX_ATTEMPTS)}

    @app.post("/admin/outbox/retry", dependencies=[Depends(is_admin)])
    def outbox_retry():
        return retry_outbox()

    @app.post("/me/rotate")
    def rotate(tok_hash: str = Depends(bearer)):
        if tok_hash in registrants:
            role, name, ref = "registrant", registrants[tok_hash], ""
        elif tok_hash in providers:
            role, (name, ref) = "provider", providers[tok_hash]
        else:
            raise HTTPException(403, "unknown caller")
        new = secrets.token_urlsafe(24)
        webhook = urls.get(name) if role == "registrant" else None
        forget(tok_hash)
        if role == "registrant":
            registrants[h(new)] = name
        else:
            providers[h(new)] = (name, ref)
        remember(h(new), role, name, ref, webhook)
        return {"token": new, "id": h(new)[:12]}

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
        path = os.environ.get("SHINAFURE_DB")
        if path:
            from .store import PersistentRegistry
            return create_app(PersistentRegistry(path), retry_seconds=60)
        return create_app(retry_seconds=60)
    except RuntimeError:
        return None


app = _lazy_app()     # for `uvicorn shinafure.service:app` (needs SHINAFURE_ADMIN_TOKEN; SHINAFURE_DB=path keeps state)
