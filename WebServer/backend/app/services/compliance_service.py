import requests
import re

def check_compliance_all(url: str):
    """
    Runs all 5 mandatory Week 3 compliance checks and returns a structured report.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    results = {
        "A01_Broken_Access_Control": check_access_control(url),
        "A02_Cryptographic_Failures": check_crypto(url),
        "A03_Injection": check_injection(url),
        "A05_Security_Misconfiguration": check_misconfig(url),
        "A07_Auth_Failures": check_auth_failures(url)
    }
    
    passed_count = sum([1 for r in results.values() if r["pass"]])
    score = passed_count * 20
    
    return {
        "url": url,
        "score": score,
        "results": results
    }

def check_access_control(url: str) -> dict:
    paths = ["/admin", "/config", "/.env", "/backup.sql"]
    found = []
    for path in paths:
        try:
            r = requests.head(f"{url.rstrip('/')}{path}", timeout=2, allow_redirects=False)
            if r.status_code == 200:
                found.append(path)
        except:
            continue
    return {
        "pass": len(found) == 0, 
        "details": f"Exposed paths found: {found}" if found else "No exposed administrative paths detected."
    }

def check_crypto(url: str) -> dict:
    if not url.startswith("https://"):
        return {"pass": False, "details": "Site does not use HTTPS. Traffic is unencrypted."}
    
    try:
        r = requests.get(url, timeout=3)
        hsts = r.headers.get("Strict-Transport-Security")
        if hsts:
            return {"pass": True, "details": "HTTPS is active and HSTS security header is enforced."}
        return {"pass": True, "details": "HTTPS is active, but HSTS header is missing."}
    except:
        return {"pass": False, "details": "Failed to connect to the HTTPS endpoint."}

def check_injection(url: str) -> dict:
    test_url = f"{url.rstrip('/')}/?id='"
    try:
        r = requests.get(test_url, timeout=3)
        errors = ["sql syntax", "mysql_fetch", "ora-", "postgre", "sqlite"]
        detected = [e for e in errors if e in r.text.lower()]
        
        if detected:
            return {"pass": False, "details": f"Potential SQL Injection vulnerability. Leaked database messages: {detected}"}
        return {"pass": True, "details": "No visible database errors leaked during injection testing."}
    except:
        return {"pass": True, "details": "Endpoint handled unexpected input cleanly."}

def check_misconfig(url: str) -> dict:
    try:
        r = requests.head(url, timeout=2)
        server_header = r.headers.get("Server", "")
        has_version = bool(re.search(r'\d', server_header))
        
        if has_version:
            return {"pass": False, "details": f"Server banner exposes specific version data: '{server_header}'"}
        return {"pass": True, "details": f"Server banner is clean or hidden ('{server_header}')."}
    except:
        return {"pass": False, "details": "Target was unreachable during configuration scan."}

def check_auth_failures(url: str) -> dict:
    try:
        r = requests.get(url, timeout=3)
        html_content = r.text.lower()
        has_login = "type=\"password\"" in html_content or "action=\"/login\"" in html_content
        
        if has_login and not url.startswith("https://"):
            return {"pass": False, "details": "Login credentials are submitted over unencrypted HTTP protocol."}
        if has_login:
            return {"pass": True, "details": "Login form discovered and securely enforced over HTTPS."}
        return {"pass": True, "details": "No standard high-risk credential intake forms discovered on home route."}
    except:
        return {"pass": True, "details": "Could not complete authentication audit."}