import os, re, json, time, sqlite3, requests, anthropic
from urllib.parse import urlparse
from dotenv import load_dotenv
from app.services.scanner_shell import scan_target

load_dotenv()
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
NVD_API_KEY = os.getenv("NVD_API_KEY")
DATA_API    = "https://sentinel-a-i.com/data-api"

CACHE_DB  = "/tmp/sentinel_cache.db"
CACHE_TTL = 3600  # 1 hour


# ── CACHE ─────────────────────────────────────────────────────────────────────
def _db():
    conn = sqlite3.connect(CACHE_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_cache (
            domain    TEXT PRIMARY KEY,
            result    TEXT,
            cached_at INTEGER
        )
    """)
    return conn

def get_cached(domain: str):
    try:
        conn = _db()
        row  = conn.execute(
            "SELECT result, cached_at FROM scan_cache WHERE domain = ?", (domain,)
        ).fetchone()
        conn.close()
        if row and (int(time.time()) - row[1]) < CACHE_TTL:
            print(f"[Cache] HIT for {domain}")
            return json.loads(row[0])
    except Exception as e:
        print(f"[Cache] read error: {e}")
    return None

def set_cache(domain: str, result: dict):
    try:
        conn = _db()
        conn.execute(
            "INSERT OR REPLACE INTO scan_cache (domain, result, cached_at) VALUES (?, ?, ?)",
            (domain, json.dumps(result), int(time.time()))
        )
        conn.commit()
        conn.close()
        print(f"[Cache] SET for {domain}")
    except Exception as e:
        print(f"[Cache] write error: {e}")


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
        return [{"id": i.get("cve_id","UNKNOWN"), "description": i.get("description","N/A"), "severity": i.get("severity","UNKNOWN")} for i in resp.json()]
    except Exception as e:
        print(f"[DataAPI] {e}")
        return None


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
            cve  = item.get("cve", {})
            desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "N/A")
            sev  = get_severity(cve.get("metrics", {}))
            cves.append({"id": cve.get("id","UNKNOWN"), "description": desc, "severity": sev})
        return cves
    except Exception as e:
        print(f"[NVD] {e}")
        return []


# ── CVE LOOKUP ────────────────────────────────────────────────────────────────
def fetch_cves_for_domain(domain: str) -> list:
    keyword = domain.replace("www.", "").split(".")[0]
    result  = fetch_cves_from_data_api(keyword)
    if result:
        print(f"[CVE] Data API — {len(result)} results for '{keyword}'")
        return result
    print(f"[CVE] Falling back to NVD for '{keyword}'")
    return fetch_cves_from_nvd(keyword)


# ── MAIN ENTRY POINT ──────────────────────────────────────────────────────────
def analyze_url(url: str) -> dict:
    domain = urlparse(url).netloc or urlparse(url).path

    # Return cached result if still fresh
    cached = get_cached(domain)
    if cached:
        return cached

    cves = fetch_cves_for_domain(domain)
    scan = scan_target(domain)

    cve_block = (
        "\n\nCVE findings:\n" + "\n".join(
            f"- {c['id']} ({c['severity']}): {c['description'][:200]}" for c in cves
        ) if cves else "\n\nNo CVEs found for this domain."
    )
    scan_block = ""
    if scan and scan.get("open_ports"):
        scan_block = (
            f"\n\nPort scan results:"
            f"\n- Open ports: {scan['open_ports']}"
            f"\n- Services: {scan.get('services', {})}"
            f"\n- Flags: {scan.get('flags', [])}"
        )

    prompt = f"""You are a cybersecurity threat analyst. Assess this URL for threats.

URL: {url}
Domain: {domain}
{cve_block}
{scan_block}

Instructions:
- Judge whether CVEs actually relate to this specific domain or just share a keyword
- Use open ports and services as evidence of real exposure
- Be specific about what makes it safe or dangerous
- Confidence should reflect how much real evidence you have

Respond ONLY with valid JSON, no markdown:
{{"safe": bool, "riskLevel": "LOW|MEDIUM|HIGH", "confidence": 0-100, "summary": "2-3 sentences with specific findings"}}"""

    msg = client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=400,
        messages=[{"role": "user", "content": prompt}]
    )
    raw    = re.sub(r"^```[a-z]*\n?|\n?```$", "", msg.content[0].text.strip())
    result = json.loads(raw)

    output = {
        "safe":       bool(result.get("safe")),
        "riskLevel":  str(result.get("riskLevel", "LOW")).upper(),
        "confidence": int(result.get("confidence", 50)),
        "summary":    str(result.get("summary", "")),
        "cveCount":   len(cves),
    }

    set_cache(domain, output)
    return output
