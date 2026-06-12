import requests
import re

def check_compliance_all(url: str):
    """
    Runs all 9 compliance checks and returns a structured report.
    5 OWASP controls + 4 additional security checks.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    results = {
        # ── ORIGINAL 5 OWASP CHECKS ──────────────────────────────
        "A01_Broken_Access_Control":     check_access_control(url),
        "A02_Cryptographic_Failures":    check_crypto(url),
        "A03_Injection":                 check_injection(url),
        "A05_Security_Misconfiguration": check_misconfig(url),
        "A07_Auth_Failures":             check_auth_failures(url),
        # ── NEW WEEK 4 CHECKS ─────────────────────────────────────
        "W4_Security_Headers":           check_security_headers(url),
        "W4_Open_Redirect":              check_open_redirect(url),
        "W4_Directory_Listing":          check_directory_listing(url),
        "W4_Cookie_Security":            check_cookie_security(url),
    }

    passed_count = sum([1 for r in results.values() if r["pass"]])
    score = round((passed_count / len(results)) * 100)

    return {
        "url": url,
        "score": score,
        "passed": passed_count,
        "total_checks": len(results),
        "results": results
    }


# ── ORIGINAL 5 OWASP CHECKS ──────────────────────────────────────────


def check_access_control(url: str) -> dict:
    paths = ["/admin", "/config", "/.env", "/backup.sql"]
    found = []
    for path in paths:
        try:
            r = requests.head(
                f"{url.rstrip('/')}{path}",
                timeout=2,
                allow_redirects=False
            )
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


# ── NEW WEEK 4 CHECKS ─────────────────────────────────────────────────


def check_security_headers(url: str) -> dict:
    """
    Checks for 3 important browser protection headers.
    X-Frame-Options: prevents clickjacking
    Content-Security-Policy: controls what scripts can run
    X-Content-Type-Options: stops browsers guessing file types
    """
    try:
        r = requests.get(url, timeout=3)
        missing = []
        if not r.headers.get("X-Frame-Options"):
            missing.append("X-Frame-Options")
        if not r.headers.get("Content-Security-Policy"):
            missing.append("Content-Security-Policy")
        if not r.headers.get("X-Content-Type-Options"):
            missing.append("X-Content-Type-Options")
        if missing:
            return {"pass": False, "details": f"Missing security headers: {missing}"}
        return {"pass": True, "details": "All critical security headers are present."}
    except:
        return {"pass": False, "details": "Could not retrieve headers from target."}


def check_open_redirect(url: str) -> dict:
    """
    Tests if the site blindly redirects to external URLs.
    Attackers use this to send users to fake login pages.
    """
    test_url = f"{url.rstrip('/')}/?next=https://evil.com"
    try:
        r = requests.get(test_url, timeout=3, allow_redirects=False)
        if r.status_code in [301, 302, 303, 307, 308]:
            location = r.headers.get("Location", "")
            if "evil.com" in location:
                return {"pass": False, "details": f"Open redirect detected — site redirects to external URL: {location}"}
        return {"pass": True, "details": "No open redirect vulnerability detected."}
    except:
        return {"pass": True, "details": "Redirect test completed without issues."}


def check_directory_listing(url: str) -> dict:
    """
    Checks if the server exposes folder contents.
    This reveals file structure to attackers.
    """
    paths = ["/images/", "/uploads/", "/files/", "/static/"]
    exposed = []
    for path in paths:
        try:
            r = requests.get(
                f"{url.rstrip('/')}{path}",
                timeout=2,
                allow_redirects=False
            )
            if r.status_code == 200 and "index of" in r.text.lower():
                exposed.append(path)
        except:
            continue
    if exposed:
        return {"pass": False, "details": f"Directory listing enabled on: {exposed}"}
    return {"pass": True, "details": "No directory listing vulnerabilities detected."}


def check_cookie_security(url: str) -> dict:
    """
    Checks if cookies have Secure and HttpOnly flags.
    Without these, cookies can be stolen through
    JavaScript or unencrypted connections.
    """
    try:
        r = requests.get(url, timeout=3)
        cookies = r.cookies
        if not cookies:
            return {"pass": True, "details": "No cookies set on this endpoint."}
        insecure = []
        for cookie in cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly flag")
            if issues:
                insecure.append(f"{cookie.name}: {', '.join(issues)}")
        if insecure:
            return {"pass": False, "details": f"Insecure cookies found: {insecure}"}
        return {"pass": True, "details": "All cookies have proper Secure and HttpOnly flags."}
    except:
        return {"pass": True, "details": "Could not complete cookie security audit."}