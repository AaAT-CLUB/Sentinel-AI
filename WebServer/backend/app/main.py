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
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Route registrations
app.include_router(analyze_router, prefix="/api")

# Configuration for Team 2 Integration — loaded from .env only
TEAM2_API_KEY = os.getenv("TEAM2_API_KEY", "")
TEAM2_BASE_URL = os.getenv("TEAM2_API_BASE_URL", "https://sentinel-a-i.com/data-api")

@app.get("/health")
def health():
    return {"status": "ok", "service": "sentinel-ai-engine"}

@app.get("/api/compliance")
def get_compliance_report(url: str = Query(..., description="The target URL to check for compliance")):
    """
    Week 3 Endpoint: Checks a URL against the top 5 OWASP controls,
    calculates a compliance score, and logs the report data to Team 2's database.
    """
    # 1. Run local automated compliance scan parameters (A01, A02, A03, A05, A07)
    report = check_compliance_all(url)

    # Format the detailed pass/fail breakdown into a clean string statement
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
        sync_endpoint = f"{TEAM2_BASE_URL}/vulnerabilities"
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
