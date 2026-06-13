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
# New compliance scanning engine (Handles both OWASP 5 and Week 4 Top 9)
from app.services.compliance_service import check_compliance_all

load_dotenv()

# Setup rate limiting
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Sentinel AI Engine", version="1.0.0")
app.state.limiter = limiter

# Exception handlers & Middleware
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"], 
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"]
)

# Route registrations
app.include_router(analyze_router, prefix="/api")

# =========================================================================
# CONFIGURATION FOR TEAM 2 INTEGRATION
# Matches your working Tailscale configuration and .env keys
# =========================================================================
TEAM2_API_KEY = os.getenv("DATA_API_KEY", "sk_sentinel_Bead_O4xRDfdpSsXuc758mQahfB980HuTTBEe5gTUPo9P6T4")
TEAM2_BASE_URL = os.getenv("DATA_API_URL", "https://sentinel-ai-data.tail55e29b.ts.net/data-api")

@app.get("/health")
def health():
    return {"status": "ok", "service": "sentinel-ai-engine"}

@app.get("/api/compliance")
def get_compliance_report(url: str = Query(..., description="The target URL to check for compliance")):
    """
    Compliance Endpoint: Checks a URL against the scanning engine controls, 
    calculates an aggregate score, and logs the report payload directly to Team 2's DB.
    """
    # 1. Run automated compliance scan parameters (Now dynamically returns all 9 checks)
    report = check_compliance_all(url)
    
    # Formats the detailed pass/fail breakdown into a clean string statement automatically
    details_summary = ", ".join([
        f"{k}: {'PASS' if v['pass'] else 'FAIL'}" 
        for k, v in report["results"].items()
    ])
    description_text = f"Automated Compliance Scan. Score: {report['score']}/100. Breakdown: {details_summary}"
    
    # Extract clean domain name to create a valid unique identifier format
    clean_domain = url.replace("https://", "").replace("http://", "").rstrip("/").upper()
    
    # 2. Match Team 2's exact database parameters from app.service.ts
    # Use strftime to guarantee a standard ISO timestamp without trailing microsecond decimals
    clean_timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    
    payload = {
        "cve_id": f"COMPLIANCE-{clean_domain}",
        "description": description_text,
        "severity": "HIGH" if report["score"] < 100 else "LOW",
        "published_date": clean_timestamp
    }
    
    # Exact header expected by Team 2's ApiKeyGuard
    headers = {
        "x-api-key": TEAM2_API_KEY,
        "Content-Type": "application/json"
    }
    
    # 3. Synchronize data to Team 2's backend via POST JSON body
    try:
        sync_endpoint = f"{TEAM2_BASE_URL.rstrip('/')}/vulnerabilities"
        response = requests.post(sync_endpoint, json=payload, headers=headers, timeout=5)
        
        report["team2_database_sync"] = {
            "status": "success" if response.status_code in [200, 201] else "failed",
            "code": response.status_code
        }
    except Exception as e:
        report["team2_database_sync"] = {
            "status": "failed",
            "error": str(e)
        }
        
    return report