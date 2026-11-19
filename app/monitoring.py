from fastapi import APIRouter
from pydantic import BaseModel
import uuid
router = APIRouter(prefix="/api/v1/monitoring")
_rules, _incidents = [], []

class Rule(BaseModel): domain: str; periodHours: int
@router.post("/rules", status_code=201)
async def create(r: Rule):
    rid = str(uuid.uuid4()); _rules.append({"ruleId": rid, **r.model_dump()}); return {"ruleId": rid}

@router.get("/incidents")
async def incidents(page: int = 1, size: int = 20):
    return {"items": _incidents[(page-1)*size: page*size], "total": len(_incidents)}
