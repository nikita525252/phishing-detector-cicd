import jwt, time
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from .problem import register
from .scan import router as scan_r
from .analyzers import visual, text, domain
from .notification import router as notif_r
from .monitoring import router as mon_r
from .ui import router as ui_r

app = FastAPI(title="phishing-detector (lab4)")
register(app)

# Увеличили ключ до 32+ символов, чтобы убрать предупреждение
SECRET_KEY = "super-secret-lab-key-1234567890-abcdef"
ALGORITHM = "HS256"

@app.middleware("http")
async def jwt_auth(request: Request, call_next):
    if request.url.path == "/" or request.url.path in ("/api/v1/health", "/api/v1/token"):
        return await call_next(request)
        
    if request.url.path.startswith("/api/"):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            # Возвращаем JSONResponse напрямую, чтобы не было 500 ошибки
            return JSONResponse(status_code=401, content={"detail": "Missing or invalid Authorization header"})
            
        token = auth_header.split(" ")[1]
        try:
            jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except jwt.ExpiredSignatureError:
            return JSONResponse(status_code=401, content={"detail": "Token has expired"})
        except jwt.InvalidTokenError:
            return JSONResponse(status_code=401, content={"detail": "Invalid token signature"})
            
    return await call_next(request)

@app.get("/api/v1/token")
async def get_token():
    payload = {"sub": "user-123", "role": "analyst", "exp": int(time.time()) + 3600}
    return {"access_token": jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)}

for r in (ui_r, scan_r, visual, text, domain, notif_r, mon_r): app.include_router(r)

@app.get("/api/v1/health")
async def health(): return {"status": "ok"}
