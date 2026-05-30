from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.routes.analyze import router as analyze_router

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Sentinel AI Engine", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(analyze_router, prefix="/api")

@app.get("/health")
def health():
    return {"status": "ok", "service": "sentinel-ai-engine"}
