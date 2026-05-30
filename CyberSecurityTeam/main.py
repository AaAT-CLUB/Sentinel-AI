from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import nmap
import requests

# Initialize FastAPI and Nmap Port Scanner
app = FastAPI()
scanner = nmap.PortScanner()

# Enable CORS so Team 1's frontend can talk to your backend safely across ports
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def fetch_team2_local_feed():
    """
    Port of Team 2's Node.js script logic.
    Fetches the 50 most recent global CVEs from the NVD API data stream.
    Extracts descriptions and maps severity metrics following their structural parsing.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50"
    feed_results = []
    
    try:
        print("Team 2 Integration: Pulling recent CVE feed from NVD...")
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            for item in vulnerabilities:
                cve = item.get('cve', {})
                cve_id = cve.get('id', 'Unknown CVE')
                published_date = cve.get('published', '')[:10]
                
                # Extract English description (Matches getEnglishDescription)
                descriptions = cve.get('descriptions', [])
                description = "No description available."
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break
                
                # Determine Severity ranking (Matches getSeverity logic)
                metrics = cve.get('metrics', {})
                severity = "UNKNOWN"
                base_score = 0.0
                
                if metrics.get('cvssMetricV40'):
                    cvss_data = metrics['cvssMetricV40'][0].get('cvssData', {})
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    base_score = cvss_data.get('baseScore', 0.0)
                elif metrics.get('cvssMetricV31'):
                    cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    base_score = cvss_data.get('baseScore', 0.0)
                elif metrics.get('cvssMetricV30'):
                    cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    base_score = cvss_data.get('baseScore', 0.0)
                elif metrics.get('cvssMetricV2'):
                    cvss_data = metrics['cvssMetricV2'][0]
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    base_score = cvss_data.get('baseScore', 0.0)
                
                feed_results.append({
                    "cve_id": cve_id,
                    "description": description,
                    "severity": severity.upper(),
                    "base_score": base_score,
                    "published_date": published_date
                })
            print(f"Successfully processed {len(feed_results)} items from recent feed stream.")
    except Exception as e:
        print(f"⚠️ Failed to parse Team 2 live feed stream: {e}")
        
    return feed_results


def fetch_team2_cve_data(product: str, version: str):
    """
    Targeted search matching software versions and extracting severity scores.
    """
    if not product or product == "Unknown (No Banner)":
        return [], 0.0

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={product} {version}"
    cve_results = []
    max_severity = 0.0

    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])[:3]
            
            for item in vulnerabilities:
                cve = item.get('cve', {})
                cve_id = cve.get('id', 'Unknown CVE')
                desc = cve.get('descriptions', [{}])[0].get('value', '')
                short_desc = desc[:100] + "..." if len(desc) > 100 else desc
                
                metrics = cve.get('metrics', {})
                cvss_data = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}) or metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {})
                base_score = cvss_data.get('baseScore', 0.0)
                
                if base_score > max_severity:
                    max_severity = base_score
                    
                cve_results.append(f"{cve_id} (Severity Score: {base_score}): {short_desc}")
                
    except Exception:
        pass
    return cve_results, max_severity


# ── INTERCEPT TEAM 1'S PATH ──────────────────────────────────────────
@app.post("/api/analyze")
def run_full_scan(payload: dict):
    # Team 1's frontend passes {"url": "https://example.com"} in the request body
    raw_url = payload.get("url", "")
    
    # Strip URL prefixes and trailing paths so Nmap gets a clean domain name or IP
    target_ip_or_domain = raw_url.replace("https://", "").replace("http://", "").split("/")[0]
    
    print(f"Starting network threat scan on: {target_ip_or_domain}...")
    
    # 1. RUN LIVE NMAP SCAN
    scanner.scan(target_ip_or_domain, arguments='-v -sV')
    
    scan_results = []
    local_vulnerabilities_fallback = []
    max_track_severity = 0.0
    
    for host in scanner.all_hosts():
        for protocol in scanner[host].all_protocols():
            ports = scanner[host][protocol].keys()
            for port in ports:
                port_info = scanner[host][protocol][port]
                
                product = port_info.get('product') or "Unknown (No Banner)"
                version = port_info.get('version') or "Hidden"
                state = port_info.get('state', 'closed')
                
                scan_results.append({
                    "port": port,
                    "state": state,
                    "product": product,
                    "version": version
                })

                if state == 'open' and product != "Unknown (No Banner)":
                    cves, severity_score = fetch_team2_cve_data(product, version)
                    if severity_score > max_track_severity:
                        max_track_severity = severity_score
                    for cve in cves:
                        local_vulnerabilities_fallback.append(f"[Port {port}] {cve}")

    # 2. INTERSECT WITH TEAM 2's RECENT FEED STREAM 
    recent_feed = fetch_team2_local_feed()
    team_2_findings = []
    
    for entry in recent_feed:
        for item in scan_results:
            prod_name = item["product"].lower()
            if prod_name != "unknown (no banner)" and prod_name in entry["description"].lower():
                finding_str = f"[Team 2 Data Match] Port {item['port']} ({item['product']}) -> {entry['cve_id']} (Severity: {entry['severity']})"
                team_2_findings.append(finding_str)
                if entry["base_score"] > max_track_severity:
                    max_track_severity = entry["base_score"]

    final_vulnerabilities = list(set(team_2_findings + local_vulnerabilities_fallback))

    # 3. TRANSPILE DATA TO SPOOF TEAM 1'S EXPECTED FORMAT 
    # Determine the strict "HIGH" | "MEDIUM" | "LOW" flags they look for
    if max_track_severity >= 7.0:
        ui_risk_level = "HIGH"
        is_safe = False
    elif max_track_severity >= 4.0:
        ui_risk_level = "MEDIUM"
        is_safe = False
    else:
        ui_risk_level = "LOW"
        is_safe = True

    # Convert the 10-point CVSS maximum score into a 0-100 integer for their confidence bar
    ui_confidence = int(min(max_track_severity * 10, 100))
    if ui_confidence == 0 and not is_safe:
        ui_confidence = 45  # Visual safety floor indicator if bugs exist without defined score metrics

    # Format all complex open port arrays and vulnerability strings into a single text block
    open_ports_list = [f"Port {item['port']}/{item['product']}" for item in scan_results if item['state'] == 'open']
    ports_string = ", ".join(open_ports_list) if open_ports_list else "None Detected"
    
    ui_summary = f"SYSTEM EXPOSURE REPORT FOR TARGET: {target_ip_or_domain}\n"
    ui_summary += "=" * 50 + "\n"
    ui_summary += f"• Active Service Ports Uncovered: {ports_string}\n"
    ui_summary += f"• Highest System Threat Metric: {max_track_severity} / 10 CVSS\n\n"
    ui_summary += "VERIFIED CVE VULNERABILITY FINDINGS:\n"
    
    if final_vulnerabilities:
        for vuln in final_vulnerabilities:
            ui_summary += f" -> {vuln}\n"
    else:
        ui_summary += " -> No active system vulnerabilities matched in current definitions stream.\n"

    # 4. HAND BACK THE DISGUISED OBJECT BUNDLE
    return {
        "safe": is_safe,
        "riskLevel": ui_risk_level,
        "confidence": ui_confidence,
        "summary": ui_summary
    }


if __name__ == "__main__":
    import uvicorn
    # Automatically bind server to localhost on Port 8000
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)