"""OpenAI-compatible proxy that an AI provider or AI gateway puts in front of
its models. It scans every inference input for registered canaries.

    POST /v1/chat/completions   (same request/response shape as OpenAI)

Policy on a confirmed hit is the provider's choice: here "flag" forwards the
request and records the hit (the provider's abuse team investigates under its
own terms of service), "block" refuses the request. The registrant is
notified either way, but learns only which canary was seen, when, and by which
provider; never the prompt.
"""
from __future__ import annotations

from typing import Awaitable, Callable, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .registry import Detector


def _texts(body: dict) -> list[str]:
    out = []
    for m in body.get("messages", []):
        c = m.get("content")
        if isinstance(c, str):
            out.append(c)
        elif isinstance(c, list):
            out += [p.get("text", "") for p in c if isinstance(p, dict) and p.get("type") == "text"]
    if isinstance(body.get("input"), str):
        out.append(body["input"])
    return out


def create_proxy(detector: Detector, upstream: Callable[[dict], Awaitable[dict]],
                 policy: str = "flag") -> FastAPI:
    app = FastAPI(title="shinafure proxy")
    app.state.events = []

    @app.post("/v1/chat/completions")
    async def chat(request: Request):
        body = await request.json()
        det = detector.scan("\n".join(_texts(body)))
        if det.confirmed:
            app.state.events.append({"canaries": sorted(det.confirmed), "policy": policy})
            if policy == "block":
                raise HTTPException(403, "request refused under the provider's usage policy")
        resp = await upstream(body)
        return JSONResponse(resp, headers={"x-shinafure": f"confirmed={len(det.confirmed)};suspect={len(det.suspect)}"})

    return app
