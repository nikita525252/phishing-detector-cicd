from fastapi import Request
from fastapi.responses import JSONResponse

class Problem(Exception):
    def __init__(self, status, title, detail=None):
        self.status, self.title, self.detail = status, title, detail

def register(app):
    @app.exception_handler(Problem)
    async def _(r: Request, e: Problem):
        return JSONResponse(status_code=e.status, media_type="application/problem+json",
            content={"type":"about:blank","title":e.title,"status":e.status,"detail":e.detail})
