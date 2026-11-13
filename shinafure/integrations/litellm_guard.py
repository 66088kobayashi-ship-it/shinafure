"""品触れ as a LiteLLM guardrail: check every request before it reaches the model.

LiteLLM proxy (config.yaml):

    guardrails:
      - guardrail_name: shinafure
        litellm_params:
          guardrail: shinafure.integrations.litellm_guard.ShinafureGuardrail
          mode: pre_call
          default_on: true

The guardrail needs a Detector (a provider's view of a registry):
  * SHINAFURE_REGISTRY_URL + SHINAFURE_PROVIDER_TOKEN : the registry service
    (shinafure.service), the normal setup
  * configure(detector, policy) in code
  * SHINAFURE_DEMO=1 : an in-process registry with 5 experiment canaries, to try it

policy "flag"  : let the request through, record the result in
                 data["metadata"]["shinafure"] and report confirmed canaries
policy "block" : also refuse requests that contain a confirmed canary (HTTP 403)

The prompt never leaves the gateway: only blinded candidates go to the
registry, and only canary IDs go to the registrant.
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Any

from litellm.integrations.custom_guardrail import CustomGuardrail

from ..registry import Detector

_state: dict[str, Any] = {"detector": None, "policy": "flag", "refreshed": 0.0,
                         "refresh_every": float(os.environ.get("SHINAFURE_REFRESH_SECONDS", "300"))}


def configure(detector: Detector, policy: str = "flag") -> None:
    if policy not in ("flag", "block"):
        raise ValueError("policy must be flag or block")
    _state.update(detector=detector, policy=policy, refreshed=time.monotonic())


def demo_detector() -> tuple[Detector, list]:
    """A registry with 5 experiment canaries, and the provider's detector."""
    import random

    from ..canary import make_canaries
    from ..registry import Registry, register_canaries
    reg = Registry(require_tickets=False)
    cs = make_canaries(5, "demo", "kanari.example", random.Random(1))
    register_canaries(reg, "demo", cs, webhook=lambda r: print(f"[shinafure] notify demo: {r.canary_id} via {r.provider}"))
    return Detector(reg, reg.add_provider("litellm-gateway"), "litellm-gateway"), cs


def request_text(data: dict) -> str:
    """Every piece of user-controlled text in a chat, completion, responses
    or embedding request."""
    parts: list[str] = []

    def take(v):
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, list):
            for x in v:
                take(x)
        elif isinstance(v, dict):
            if isinstance(v.get("text"), str):
                parts.append(v["text"])
            for k in ("content", "input", "arguments"):
                if k in v:
                    take(v[k])

    for key in ("messages", "prompt", "input", "system"):
        if key in data:
            take(data[key])
    return "\n".join(parts)


class ShinafureGuardrail(CustomGuardrail):
    def __init__(self, detector: Detector | None = None, policy: str | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        if detector is not None:
            configure(detector, policy or "flag")
        elif _state["detector"] is None and os.environ.get("SHINAFURE_REGISTRY_URL"):
            from ..remote import RemoteRegistry
            remote = RemoteRegistry(os.environ["SHINAFURE_REGISTRY_URL"], os.environ["SHINAFURE_PROVIDER_TOKEN"])
            name = os.environ.get("SHINAFURE_PROVIDER_NAME", "litellm-gateway")
            configure(Detector(remote, "", name), policy or os.environ.get("SHINAFURE_POLICY", "flag"))
        elif _state["detector"] is None and os.environ.get("SHINAFURE_DEMO"):
            configure(demo_detector()[0], policy or os.environ.get("SHINAFURE_POLICY", "flag"))

    async def async_pre_call_hook(self, user_api_key_dict: Any, cache: Any, data: dict, call_type: str):
        det = _state["detector"]
        if det is None:
            return data
        text = request_text(data)
        if not text:
            return data
        if time.monotonic() - _state["refreshed"] > _state["refresh_every"]:
            _state["refreshed"] = time.monotonic()        # pick up canaries registered since the last fetch
            await asyncio.to_thread(det.refresh)
        d = await asyncio.to_thread(det.scan, text)      # CPU work off the event loop
        data.setdefault("metadata", {})["shinafure"] = {"confirmed": len(d.confirmed), "suspect": len(d.suspect)}
        if d.confirmed and _state["policy"] == "block":
            try:
                from fastapi import HTTPException
            except ImportError:                        # SDK use without the proxy
                raise PermissionError("request contains stolen data (品触れ)")
            raise HTTPException(status_code=403, detail="request contains stolen data (品触れ)")
        return data
