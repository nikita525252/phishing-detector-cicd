import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app, SECRET_KEY, ALGORITHM
from app.scan import aggregate
import jwt
import time

# Генерируем настоящий валидный токен для тестов
payload = {"sub": "user-123", "role": "analyst", "exp": int(time.time()) + 3600}
VALID_TOKEN = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

H = {"Authorization": f"Bearer {VALID_TOKEN}", "Idempotency-Key": "k1"}
BODY = {"url": "https://sberbank-login.ru", "htmlContent": "<form/>", "screenshotId": "s1"}

# --- 3 ТЕСТА ДЛЯ SCAN-SERVICE ---
@pytest.mark.scan
def test_verdict_happy():
    assert aggregate({"similarityScore": .95}, {"isPhishing": True, "confidence": .9},
                     {"isSuspicious": True}, False)["category"] == "PHISHING"

@pytest.mark.scan
def test_verdict_degraded():
    v = aggregate(None, {"isPhishing": True, "confidence": .8}, {"isSuspicious": True}, True)
    assert v["confidence"] == 0.6 and v["degraded"] is True

@pytest.mark.scan
@pytest.mark.asyncio
async def test_scan_idempotent(monkeypatch):
    import app.scan as s
    class R:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {"similarityScore": .9, "isPhishing": True,
                                "confidence": .9, "isSuspicious": True}
    class C:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def post(self, *a, **k): return R()
    monkeypatch.setattr(s.httpx, "AsyncClient", lambda *a, **k: C())
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r1 = await c.post("/api/v1/scans", json=BODY, headers=H)
        r2 = await c.post("/api/v1/scans", json=BODY, headers=H)
        assert r1.status_code == 202 
        assert r1.json()["scanId"] == r2.json()["scanId"]

# --- 1 ТЕСТ ДЛЯ API GATEWAY ---
@pytest.mark.gateway
@pytest.mark.asyncio
async def test_missing_jwt_401():
    # raise_app_exceptions=False позволяет прочитать ответ 401, а не упасть с ошибкой
    async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://t") as c:
        r = await c.post("/api/v1/scans", json=BODY)
        assert r.status_code == 401
