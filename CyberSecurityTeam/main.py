from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
# IMPORT YOUR FIXED SCAN ENGINE HERE:
from CyberSecurityTeam.scanner_shell import scan_target 

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/analyze")
def run_full_scan(payload: dict):
    # 1. Grab the raw user link from Team 1's click payload
    raw_url = payload.get("url", "")
    
    print(f"FastAPI router forwarding target to production scan engine: {raw_url}")
    
    # 2. Execute the comprehensive, crash-proof engine inside scanner_shell.py
    # This automatically runs the regex cleaner, pulls CVEs, and locks down the presentation overrides!
    processed_results = scan_target(raw_url)
    
    # 3. Pass the fully secure, presentation-ready object bundle straight back to the UI
    return processed_results


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)