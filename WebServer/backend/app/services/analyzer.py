import os, re, json, requests, anthropic
from urllib.parse import urlparse
from dotenv import load_dotenv
from app.services.scanner_shell import scan_target

load_dotenv()
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
NVD_API_KEY = os.getenv("NVD_API_KEY")

def fetch_cves_for_domain(domain):
    try:
        keyword = domain.replace("www.", "").split(".")[0]
        resp = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": 5},
            headers={"apiKey": NVD_API_KEY} if NVD_API_KEY else {}, timeout=8)
        resp.raise_for_status()
        cves = []
        for item in resp.json().get("vulnerabilities", []):
            cve = item.get("cve", {})
            desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "N/A")
            metrics = cve.get("metrics", {})
            sev = "UNKNOWN"
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    sev = metrics[key][0].get("cvssData", {}).get("baseSeverity") or "UNKNOWN"
                    break
            cves.append({"id": cve.get("id", "UNKNOWN"), "description": desc, "severity": sev})
        return cves
    except Exception as e:
        print(f"[NVD] {e}"); return []

def analyze_url(url):
    domain = urlparse(url).netloc or urlparse(url).path
    cves = fetch_cves_for_domain(domain)
    scan = scan_target(domain)
    cve_block = ("\n\nRelated CVEs:\n" + "\n".join(f"- {c['id']} ({c['severity']}): {c['description'][:200]}" for c in cves)) if cves else "\n\nNo CVEs found."
    scan_block = ""
    if scan and scan.get("open_ports"):
        scan_block = f"\n\nPort Scan: ports={scan['open_ports']}, flags={scan.get('flags', [])}"
    prompt = f"""You are a cybersecurity AI. Analyze this URL for threats.\nURL: {url}\nDomain: {domain}{cve_block}{scan_block}\nRespond ONLY with JSON: {{\"safe\": bool, \"riskLevel\": \"LOW|MEDIUM|HIGH\", \"confidence\": 0-100, \"summary\": \"2-3 sentences\"}}"""
    msg = client.messages.create(model="claude-haiku-4-5", max_tokens=400, messages=[{"role": "user", "content": prompt}])
    raw = re.sub(r"^```[a-z]*\n?|\n?```$", "", msg.content[0].text.strip())
    result = json.loads(raw)
    return {"safe": bool(result.get("safe")), "riskLevel": str(result.get("riskLevel", "LOW")).upper(), "confidence": int(result.get("confidence", 50)), "summary": str(result.get("summary", "")), "cveCount": len(cves)}
