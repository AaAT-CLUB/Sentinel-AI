import os
import requests
from datetime import datetime
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv

# Existing app routes
from app.routes.analyze import router as analyze_router
# New compliance scanning engine
from app.services.compliance_service import check_compliance_all

load_dotenv()

# Setup rate limiting
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Sentinel AI Engine", version="1.0.0")
app.state.limiter = limiter

# Exception handlers & Middleware
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(analyze_router, prefix="/api")

@app.get("/health")
def health():
    return {"status": "ok", "service": "sentinel-ai-engine"}
