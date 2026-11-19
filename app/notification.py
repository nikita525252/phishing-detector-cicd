import os, httpx
from fastapi import APIRouter
from .bus import bus

router = APIRouter(prefix="/api/v1/notifications")
_seen: set = set()
_log: list = []
_SMTP = os.getenv("SMTP_URL", "http://localhost:8090")

async def on_verdict(e: dict):
    if e["eventId"] in _seen: return
    _seen.add(e["eventId"])
    p = e["payload"]
    msg = ("Частичная проверка: " if p.get("degraded") else "Проверка завершена: ") + f"{p['url']} — {p['category']}"
    status = "SENT"
    try:
        async with httpx.AsyncClient(timeout=2.0) as c:
            await c.post(f"{_SMTP}/send", json={"recipientId":"user-123","message":msg})
    except Exception: status = "FAILED"
    _log.append({"id": e["eventId"], "status": status, "message": msg})

bus.subscribe("verdicts", on_verdict)

@router.get("")
async def history(page: int = 1, size: int = 20):
    return {"items": _log[(page-1)*size: page*size], "total": len(_log)}
