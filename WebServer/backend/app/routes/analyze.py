from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.services.analyzer import analyze_url
import requests as req

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


class AnalyzeRequest(BaseModel):
    url: str


class AnalyzeResponse(BaseModel):
    safe: bool
    riskLevel: str
    confidence: int
    summary: str
    cveCount: int


@router.get("/status")
async def status():
    # Threat DB — ping NVD API
    threat_db = False
    try:
        r = req.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
            timeout=5
        )
        threat_db = r.status_code == 200
    except Exception:
        pass

    # AI Engine — check Anthropic status page
    ai_engine = False
    try:
        r = req.get("https://status.anthropic.com/api/v2/status.json", timeout=5)
        data = r.json()
        ai_engine = data.get("status", {}).get("indicator") == "none"
    except Exception:
        pass

    return {
        "api": True,        # if this endpoint responds, API is up
        "threat_db": threat_db,
        "ai_engine": ai_engine,
    }


@router.post("/analyze", response_model=AnalyzeResponse)
@limiter.limit("10/minute")
async def analyze(request: Request, body: AnalyzeRequest):
    url = body.url.strip()
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")
    try:
        return analyze_url(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
