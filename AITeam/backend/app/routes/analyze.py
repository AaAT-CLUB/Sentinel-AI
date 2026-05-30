from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
# Import the AI analyzer
from app.services.analyzer import analyze_url
# Import your own scanner logic
from CyberSecurityTeam.main import run_scan 
import re

router = APIRouter()

class AnalyzeRequest(BaseModel):
    url: str

class AnalyzeResponse(BaseModel):
    safe: bool
    riskLevel: str
    confidence: int
    summary: str
    cveCount: int
    vulnerability_table: str

@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest):
    url = request.url.strip()
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")
        
    try:
        # 1. Run the AI summary engine
        result = analyze_url(url)
        
        # 2. Run YOUR specialized scanner
        # Assuming run_scan returns the formatted table string
        your_data = run_scan(url) 
        
        # 3. Force merge: AI provides the summary, YOU provide the technical table
        result["vulnerability_table"] = your_data if your_data else ""
            
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")