"""Demo registry server (port 8800). DNS TXT and SMS are answered locally through
/demo/publish-txt and /demo/last-sms so a registrant can onboard without a real
domain or phone block. Not for production: use shinafure.service.create_app with
real resolve_txt and send_sms.

    SHINAFURE_ADMIN_TOKEN=... python -m demo.registry_server
"""
import os, uvicorn
from fastapi import Body
from shinafure.registry import Registry
from shinafure.service import create_app
TXT, SMS = {}, []
from shinafure.store import PersistentRegistry
app = create_app(PersistentRegistry(os.environ["SHINAFURE_DB"]) if os.environ.get("SHINAFURE_DB") else Registry(), os.environ["SHINAFURE_ADMIN_TOKEN"], resolve_txt=lambda n: TXT.get(n, []),
                 send_sms=lambda num, code: SMS.append(code), notify=lambda who, r: print(f"NOTIFY {who} {r.canary_id} via {r.provider}", flush=True))

@app.post("/demo/publish-txt")
def publish(b: dict = Body(...)):
    TXT.setdefault(b["name"], []).append(b["value"]); return {"ok": True}

@app.get("/demo/last-sms")
def last_sms():
    return {"code": SMS[-1]}

uvicorn.run(app, port=8800, log_level="warning")
