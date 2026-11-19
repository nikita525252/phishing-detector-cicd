import os, httpx, uuid
from fastapi import APIRouter
from pydantic import BaseModel
from cachetools import TTLCache
from .bus import bus

visual = APIRouter(prefix="/internal/v1/visual")
text   = APIRouter(prefix="/internal/v1/text")
domain = APIRouter(prefix="/internal/v1/domains")
_cache = TTLCache(maxsize=10_000, ttl=86400)
_WHOIS = os.getenv("WHOIS_URL", "http://localhost:8089")

class VReq(BaseModel): screenshotId: str | None = None
@visual.post("/analyze")
async def v_analyze(r: VReq):
    await bus.publish("visual", {"eventId": str(uuid.uuid4()), "similarityScore": 0.95})
    return {"similarityScore": 0.95, "matchedBrand": "Sberbank"}

class TReq(BaseModel): htmlContent: str | None = None
@text.post("/analyze")
async def t_analyze(r: TReq):
    await bus.publish("text", {"eventId": str(uuid.uuid4()), "isPhishing": True})
    return {"isPhishing": True, "confidence": 0.87}

class DReq(BaseModel): domain: str
@domain.post("/check")
async def d_check(r: DReq):
    if r.domain in _cache: return _cache[r.domain]
    try:
        async with httpx.AsyncClient(timeout=2.0) as c:
            resp = await c.post(f"{_WHOIS}/whois", json={"domain": r.domain}); resp.raise_for_status()
            data = resp.json()
    except Exception:
        data = {"domain": r.domain, "ageDays": None, "isSuspicious": False, "status": "UNKNOWN"}
    _cache[r.domain] = data
    await bus.publish("domains", {"eventId": str(uuid.uuid4()), **data})
    return data

# --- ПУБЛИЧНЫЙ ЭНДПОИНТ (ИСПРАВЛЕН) ---
def format_age(days: int) -> str:
    if days is None: return "Неизвестно"
    if days % 10 == 1 and days % 100 != 11: return f"{days} день назад"
    elif days % 10 in (2, 3, 4) and days % 100 not in (12, 13, 14): return f"{days} дня назад"
    else: return f"{days} дней назад"

@domain.get("/{domain_name}")
async def public_domain_info(domain_name: str):
    data = await d_check(DReq(domain=domain_name))
    risk = 0.9 if data.get("isSuspicious") else 0.1
    age = data.get("ageDays", 0)
    
    return {
        "domain": domain_name, 
        "riskScore": risk, 
        "status": data.get("status", "OK"),
        "ageDays": age,
        "registered": format_age(age)
    }
