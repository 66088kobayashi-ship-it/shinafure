"""Client for the registry service (shinafure.service).

RemoteRegistry has the methods Detector and register_ticketed call on a
Registry, so a provider or registrant swaps in the remote one:

    reg = RemoteRegistry("https://registry.example", token)
    det = Detector(reg, api_key="", name="my-gateway")      # api_key is unused remotely
"""
from __future__ import annotations

from typing import Callable, Optional

import httpx

from .issuance import Ticket
from .registry import RateLimited


class RemoteRegistry:
    def __init__(self, base_url: str, token: str, client: Optional[httpx.Client] = None) -> None:
        self.c = client or httpx.Client(base_url=base_url, timeout=30)
        self.h = {"Authorization": f"Bearer {token}"}

    def _post(self, path: str, body: dict) -> dict:
        r = self.c.post(path, json=body, headers=self.h)
        if r.status_code == 429:
            raise RateLimited(path)
        if r.status_code == 403:
            raise PermissionError(r.json().get("detail", "forbidden"))
        if r.status_code == 400:
            raise ValueError(r.json().get("detail", "bad request"))
        r.raise_for_status()
        return r.json()

    def _get(self, path: str) -> dict:
        r = self.c.get(path, headers=self.h)
        if r.status_code == 403:
            raise PermissionError(r.json().get("detail", "forbidden"))
        r.raise_for_status()
        return r.json()

    # used by everyone
    def evaluate(self, blinded: bytes, caller: str = "") -> bytes:
        return bytes.fromhex(self._post("/oprf/evaluate", {"blinded": blinded.hex()})["evaluated"])

    # registrants
    def domain_challenge(self, registrant: str, domain: str) -> tuple[str, str]:
        d = self._post("/domains/challenge", {"domain": domain})
        return d["name"], d["value"]

    def verify_domain(self, registrant: str, domain: str, resolve_txt: Callable = None) -> bool:
        return self._post("/domains/verify", {"domain": domain})["ok"]

    def confirm_phone_block(self, registrant: str, challenge_id: str, code: str) -> bool:
        return self._post("/phone-blocks/confirm", {"challenge_id": challenge_id, "code": code})["ok"]

    def start_phone_block(self, registrant: str, block: str, send_sms: Callable = None) -> str:
        return self._post("/phone-blocks/start", {"block": block})["challenge_id"]

    def issue_ticket(self, registrant: str, dataset: str, commitment: bytes) -> Ticket:
        d = self._post("/tickets", {"dataset": dataset, "commitment": commitment.hex()})
        return Ticket(d["ticket_id"], d["registrant"], d["dataset"], bytes.fromhex(d["commitment"]),
                      bytes.fromhex(d["nonce"]), d["table"])

    def register(self, registrant: str, f_values, webhook=None, escrows=None) -> int:
        rows = [{"f": f.hex(), "prefix": p, "canary_id": c, "dataset": ds, "kind": k} for f, p, c, ds, k in f_values]
        esc = [{"f": f.hex(), "canary_id": c, "sealed": s.hex()} for (f, c), s in (escrows or {}).items()]
        return self._post("/register", {"rows": rows, "escrows": esc})["registered"]

    # providers
    def prefix_filter(self, api_key: str = "") -> frozenset[int]:
        return frozenset(self._get("/provider/filter")["prefixes"])

    def f_values(self, api_key: str = "") -> frozenset[bytes]:
        return frozenset(bytes.fromhex(f) for f in self._get("/provider/f-values")["f"])

    def lookup(self, api_key: str, f: bytes) -> list[tuple]:
        return [tuple(e) for e in self._post("/provider/lookup", {"f": f.hex()})["entries"]]

    def report(self, api_key: str, registrant: str, canary_id: str, dataset: str, kinds, status: str, keys=None):
        body = {"registrant": registrant, "canary_id": canary_id, "dataset": dataset, "kinds": list(kinds),
                "status": status, "keys": {k.hex(): v.hex() for k, v in (keys or {}).items()}}
        return self._post("/provider/report", body)
