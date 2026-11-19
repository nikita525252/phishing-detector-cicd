import uuid, httpx
from datetime import datetime, timezone
from fastapi import APIRouter, Header
from pydantic import BaseModel
from cachetools import TTLCache
from .bus import bus
from .problem import Problem

router = APIRouter(prefix="/api/v1/scans", tags=["scan"])
idem = TTLCache(maxsize=10_000, ttl=86400)
scans: dict = {}

class Req(BaseModel):
    url: str
    screenshotId: str | None = None
    htmlContent: str | None = None

def aggregate(v, t, d, degraded):
    vs = float(v.get("similarityScore", 0)) if v else 0.0
    ts = float(t.get("confidence", 0)) if (t and t.get("isPhishing")) else 0.0
    risk = 0.5*vs + 0.4*ts + (0.1 if (d and d.get("isSuspicious")) else 0)
    cat = "PHISHING" if risk >= .75 else ("SUSPICIOUS" if risk >= .4 else "BENIGN")
    return {"category": cat, "riskScore": round(risk, 2),
            "confidence": 0.6 if degraded else 0.9, "degraded": degraded}

@router.post("", status_code=202)
async def create(req: Req, idempotency_key: str = Header(..., alias="Idempotency-Key")):
    if idempotency_key in idem: return idem[idempotency_key]
    sid = str(uuid.uuid4()); scans[sid] = {"id": sid, "url": req.url, "status": "PENDING"}
    degraded, v, t, d = False, None, None, None
    async with httpx.AsyncClient(timeout=2.0) as c:
        try:
            r = await c.post("http://localhost:8080/internal/v1/visual/analyze",
                             json={"screenshotId": req.screenshotId}); r.raise_for_status(); v = r.json()
        except Exception:
            degraded = True
            await bus.publish("visual.retry", {"scanId": sid})
        try:
            r = await c.post("http://localhost:8080/internal/v1/text/analyze",
                             json={"htmlContent": req.htmlContent}); r.raise_for_status(); t = r.json()
        except Exception: degraded = True
        try:
            dom = req.url.split("//")[-1].split("/")[0]
            r = await c.post("http://localhost:8080/internal/v1/domains/check",
                             json={"domain": dom}); r.raise_for_status(); d = r.json()
        except Exception: degraded = True
    verdict = aggregate(v, t, d, degraded)
    scans[sid].update(status="COMPLETED", verdict=verdict)
    await bus.publish("verdicts", {
        "eventId": str(uuid.uuid4()), "eventType": "verdict.issued", "schemaVersion": 1,
        "occurredAt": datetime.now(timezone.utc).isoformat(),
        "payload": {"scanId": sid, "url": req.url, **verdict}})
    idem[idempotency_key] = {"scanId": sid, "status": "PENDING", "degraded": degraded}
    return idem[idempotency_key]

@router.get("/{sid}")
async def get(sid: str):
    if sid not in scans: raise Problem(404, "Scan not found", f"id={sid}")
    return scans[sid]
