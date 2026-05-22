import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
import nmap
import requests

# 📥 This keeps your Week 1 scanner script linked right next to this file
import scanner as week_1_scanner

# 🔐 Read the secret keys from your hidden .env file
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

app = FastAPI(title="Sentinel AI - Cybersecurity Scanner API")

# Define the data format the API expects to receive from a user
class ScanRequest(BaseModel):
    target: str  # Allows passing things like "scanme.nmap.org" dynamically

# 🔐 Grab the key securely from the system environment variables
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not ABUSEIPDB_API_KEY:
    print("⚠️ WARNING: AbuseIPDB API key missing! Check your .env configuration.")

def check_ip_reputation(ip_address: str):
    """Week 2 Feature: Queries AbuseIPDB to look up the target's background safety."""
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            return {
                "abuseScore": data['data']['abuseConfidenceScore'],
                "totalReports": data['data']['totalReports'],
                "isMalicious": data['data']['abuseConfidenceScore'] > 25
            }
        return {"error": f"Could not fetch reputation data (Status Code: {response.status_code})"}
    except Exception:
        return {"error": "AbuseIPDB API connection failed"}

@app.post("/scan")
def run_cyber_scan(request: ScanRequest):
    """
    Week 2 API Web Door: Takes a target, runs your Week 1 Nmap scanning logic,
    and attaches the Week 2 AbuseIPDB background check.
    """
    nm = nmap.PortScanner()
    
    try:
        print(f"Starting API scan on target: {request.target}...")
        
        # Run the scan dynamically using the target variable passed to the API
        nm.scan(request.target, arguments='-v')
        
        if not nm.all_hosts():
            raise HTTPException(status_code=400, detail="Target host could not be resolved or scanned.")
            
        target_host = nm.all_hosts()[0]
        
        # --- WEEK 1 PORT SCRAPING LOGIC ---
        # Grabs the specific data loops from your week 1 engine to pull out port details
        ports_report = []
        for protocol in nm[target_host].all_protocols():
            ports = nm[target_host][protocol].keys()
            for port in ports:
                port_info = nm[target_host][protocol][port]
                ports_report.append({
                    "port": port,
                    "protocol": protocol,
                    "state": port_info['state'],
                    "product": port_info['product'],
                    "version": port_info['version']
                })
                
        # --- WEEK 2 REPUTATION CHECK FEATURE ---
        reputation_data = check_ip_reputation(target_host)
        
        # Combine Week 1 data layout with Week 2 safety check requirements into one clean JSON response
        return {
            "target": request.target,
            "resolved_ip": target_host,
            "host_state": nm[target_host].state(),
            "abuse_reputation": reputation_data,
            "open_ports_detected": ports_report
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))