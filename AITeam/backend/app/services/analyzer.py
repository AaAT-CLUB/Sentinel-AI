"""
Core analysis logic for Sentinel AI.

Flow:
  1. Extract domain from submitted URL
  2. Query NVD for any CVEs mentioning that domain/product
  3. Send domain + CVE context to Claude for threat assessment
  4. Return structured result to the route handler
"""

import os
import re
import json
import requests
import anthropic
from urllib.parse import urlparse
from dotenv import load_dotenv
from app.services.scanner_shell import scan_target

load_dotenv()

NVD_API_KEY   = os.getenv("NVD_API_KEY")
ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY")

client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)


def fetch_cves_for_domain(domain: str) -> list[dict]:
    try:
        keyword = domain.replace("www.", "").split(".")[0]
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"keywordSearch": keyword, "resultsPerPage": 5}
        headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
        resp = requests.get(url, params=params, headers=headers, timeout=8)
        resp.raise_for_status()
        data = resp.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")
            descriptions = cve.get("descriptions", [])
            description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description available.")
            metrics = cve.get("metrics", {})
            severity = "UNKNOWN"
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    severity = (metrics[key][0].get("cvssData", {}).get("baseSeverity") or metrics[key][0].get("baseSeverity") or "UNKNOWN")
                    break
            cves.append({"id": cve_id, "description": description, "severity": severity})
        return cves
    except Exception as e:
        print(f"[NVD] Warning: could not fetch CVEs for '{domain}': {e}")
        return []


def analyze_with_claude(url: str, domain: str, cves: list[dict], scan: dict = None) -> dict:
    cve_block = ""
    if cves:
        lines = [f"- {c['id']} ({c['severity']}): {c['description'][:200]}" for c in cves]
        cve_block = "\n\nRelated CVEs found in NVD:\n" + "\n".join(lines)
    else:
        cve_block = "\n\nNo CVEs found in NVD for this domain."

    scan_block = ""
    if scan and scan.get("open_ports"):
        scan_block = f"\n\nPort Scan Results:"
        scan_block += f"\n- Open ports: {scan['open_ports']}"
        for port, svc in scan.get("services", {}).items():
            scan_block += f"\n- Port {port}: {svc}"
        if scan.get("flags"):
            scan_block += f"\n- Flags: {', '.join(scan['flags'])}"

    prompt = f"""You are a cybersecurity threat analysis AI. Analyze this URL for phishing, malware, and general threat indicators.

URL submitted: {url}
Domain: {domain}
{cve_block}{scan_block}

Evaluate the URL based on:
- Domain reputation (known malicious patterns, typosquatting, suspicious TLDs)
- URL structure (excessive subdomains, obfuscation, random strings, misleading paths)
- Known vulnerability context from the CVE data above
- Port scan findings if provided
- Any phishing or social engineering indicators

Respond ONLY with a JSON object in this exact format (no markdown, no explanation):
{{
  "safe": true or false,
  "riskLevel": "LOW" or "MEDIUM" or "HIGH",
  "confidence": integer from 0 to 100,
  "summary": "2-3 sentence plain English explanation of your assessment"
}}"""

    message = client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=400,
        messages=[{"role": "user", "content": prompt}]
    )
    raw = message.content[0].text.strip()
    raw = re.sub(r"^```[a-z]*\n?", "", raw)
    raw = re.sub(r"\n?```$", "", raw)
    return json.loads(raw)


def analyze_url(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    cves   = fetch_cves_for_domain(domain)
    scan   = scan_target(domain)
    result = analyze_with_claude(url, domain, cves, scan)
    return {
        "safe":       bool(result.get("safe", True)),
        "riskLevel":  str(result.get("riskLevel", "LOW")).upper(),
        "confidence": int(result.get("confidence", 50)),
        "summary":    str(result.get("summary", "")),
        "cveCount":   len(cves),
    }
