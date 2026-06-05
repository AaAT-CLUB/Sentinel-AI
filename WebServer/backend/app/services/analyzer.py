import os, re, json, requests, anthropic
from urllib.parse import urlparse
from dotenv import load_dotenv
from app.services.scanner_shell import scan_target

load_dotenv()
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
NVD_API_KEY = os.getenv("NVD_API_KEY")

DATA_API = "https://sentinel-a-i.com/data-api"


# ── SEVERITY PARSER (Team 2) ──────────────────────────────────────────────────
def get_severity(metrics: dict) -> str:
    if metrics.get("cvssMetricV40") and metrics["cvssMetricV40"][0].get("cvssData", {}).get("baseSeverity"):
        return metrics["cvssMetricV40"][0]["cvssData"]["baseSeverity"]
    if metrics.get("cvssMetricV31") and metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseSeverity"):
        return metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
    if metrics.get("cvssMetricV30") and metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseSeverity"):
        return metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
    if metrics.get("cvssMetricV2") and metrics["cvssMetricV2"][0].get("baseSeverity"):
        return metrics["cvssMetricV2"][0]["baseSeverity"]
    return "UNKNOWN"


# ── DATA TEAM CVE API (primary) ───────────────────────────────────────────────
def fetch_cves_from_data_api(keyword: str) -> list:
    try:
        resp = requests.get(
            f"{DATA_API}/vulnerabilities",
            params={"keyword": keyword, "limit": 5},
            timeout=5
        )
        resp.raise_for_status()
        cves = []
        for item in resp.json():
            cves.append({
                "id":          item.get("cve_id", "UNKNOWN"),
                "description": item.get("description", "N/A"),
                "severity":    item.get("severity", "UNKNOWN"),
            })
        return cves
    except Exception as e:
        print(f"[DataAPI] {e}")
        return None   # None = failed, not just empty


# ── NVD LOOKUP (fallback) ─────────────────────────────────────────────────────
def fetch_cves_from_nvd(keyword: str) -> list:
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": 5},
            headers={"apiKey": NVD_API_KEY} if NVD_API_KEY else {},
            timeout=8
        )
        resp.raise_for_status()
        cves = []
        for item in resp.json().get("vulnerabilities", []):
            cve = item.get("cve", {})
            desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "N/A")
            sev  = get_severity(cve.get("metrics", {}))
            cves.append({"id": cve.get("id", "UNKNOWN"), "description": desc, "severity": sev})
        return cves
    except Exception as e:
        print(f"[NVD] {e}")
        return []


# ── CVE LOOKUP — tries Data API first, falls back to NVD ─────────────────────
def fetch_cves_for_domain(domain: str) -> list:
    keyword = domain.replace("www.", "").split(".")[0]

    result = fetch_cves_from_data_api(keyword)
    if result is not None:
        print(f"[CVE] Using Data team API — {len(result)} results for '{keyword}'")
        return result

    print(f"[CVE] Data API unavailable — falling back to NVD for '{keyword}'")
    return fetch_cves_from_nvd(keyword)


# ── MAIN ENTRY POINT ──────────────────────────────────────────────────────────
def analyze_url(url: str) -> dict:
    domain = urlparse(url).netloc or urlparse(url).path
    cves   = fetch_cves_for_domain(domain)
    scan   = scan_target(domain)

    cve_block = (
        "\n\nRelated CVEs:\n" + "\n".join(f"- {c['id']} ({c['severity']}): {c['description'][:200]}" for c in cves)
        if cves else "\n\nNo CVEs found."
    )
    scan_block = ""
    if scan and scan.get("open_ports"):
        scan_block = f"\n\nPort Scan: ports={scan['open_ports']}, flags={scan.get('flags', [])}"

    prompt = f"""You are a cybersecurity AI. Analyze this URL for threats.
URL: {url}
Domain: {domain}{cve_block}{scan_block}
Respond ONLY with JSON: {{"safe": bool, "riskLevel": "LOW|MEDIUM|HIGH", "confidence": 0-100, "summary": "2-3 sentences"}}"""

    msg = client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=400,
        messages=[{"role": "user", "content": prompt}]
    )
    raw    = re.sub(r"^```[a-z]*\n?|\n?```$", "", msg.content[0].text.strip())
    result = json.loads(raw)

    return {
        "safe":       bool(result.get("safe")),
        "riskLevel":  str(result.get("riskLevel", "LOW")).upper(),
        "confidence": int(result.get("confidence", 50)),
        "summary":    str(result.get("summary", "")),
        "cveCount":   len(cves),
    }
