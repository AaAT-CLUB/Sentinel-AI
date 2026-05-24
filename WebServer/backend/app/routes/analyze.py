from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services.analyzer import analyze_url

router = APIRouter()

class AnalyzeRequest(BaseModel):
    url: str

class AnalyzeResponse(BaseModel):
    safe: bool
    riskLevel: str
    confidence: int
    summary: str
    cveCount: int

@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest):
    url = request.url.strip()
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")
    try:
        return analyze_url(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
