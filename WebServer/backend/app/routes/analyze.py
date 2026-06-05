from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.services.analyzer import analyze_url
# IMPORT YOUR PROFESSIONAL SCANNER SHELL
from app.services.scanner_shell import scan_target
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
    # Added this field to match your frontend expectation
    vulnerability_table: str 


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

    # AI Engine — check Claude status
    ai_engine = False
    try:
        r = req.get("https://status.claude.com/api/v2/status.json", timeout=5)
        data = r.json()
        indicator = data.get("status", {}).get("indicator", "major")
        ai_engine = indicator in ("none", "minor")
    except Exception:
        pass

    return {
        "api":       True,
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
        # 1. Run the AI analysis
        result = analyze_url(url)
        
        # 2. Run your professional scanner shell
        # This returns the dict structure: open_ports, services, flags, etc.
        scan_data = scan_target(url)
        
        # 3. Merge your findings into the vulnerability_table field
        # We use the 'summary' from your scanner_shell as the table
        result["vulnerability_table"] = scan_data.get("summary", "No vulnerabilities found.")
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")