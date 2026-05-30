"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SCANNER SHELL — FOR CYBERSECURITY TEAM (TEAM 3)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This file is the integration point between Team 3's
scanner and the AI analysis engine.

HOW IT WORKS:
  1. The AI backend calls scan_target(domain) below
  2. You fill in the function with your Nmap/scanner logic
  3. Return your findings in the ScanResult format
  4. The AI reads your output and generates the threat summary

WHAT TO EDIT:
  → Only edit the section marked "TEAM 3 — EDIT HERE"
  → Do not change the function name or return format
  → The rest of the pipeline handles everything else

RETURN FORMAT:
  Your function must return a dict with these keys:
  {
    "open_ports":  [22, 80, 443],           ← list of ints
    "services":    {"22": "OpenSSH 8.9"},   ← port → service string
    "flags":       ["SSH exposed on 22"],   ← plain English findings
    "raw":         "optional raw scan text" ← anything extra you want AI to see
  }
"""

import nmap


# ── RETURN FORMAT ────────────────────────────────────────────────────
def empty_result() -> dict:
    return {
        "open_ports": [],
        "services":   {},
        "flags":      [],
        "raw":        ""
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#   TEAM 3 — EDIT HERE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def scan_target(domain: str) -> dict:
    nm = nmap.PortScanner()
    result = empty_result()

    try:
        print(f"Scanner shell: starting scan on {domain}...")

        # -T4 = aggressive timing (faster), --top-ports 100 = only scan common ports
        # --host-timeout 30s = give up after 30 seconds so we never block the API
        nm.scan(domain, arguments='-T4 --top-ports 100 --host-timeout 30s')

        if not nm.all_hosts():
            result["flags"].append("No hosts found — target may be offline or blocking scans")
            return result

        host = nm.all_hosts()[0]
        result["raw"] = f"Host: {host} | State: {nm[host].state()} | Hostname: {nm[host].hostname()}"

        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                data = nm[host][proto][port]
                if data['state'] == 'open':
                    name = data.get('name', '')
                    product = data.get('product', '')
                    version = data.get('version', '')
                    service_label = f"{name} {product} {version}".strip()
                    result["open_ports"].append(port)
                    result["services"][str(port)] = service_label if service_label else "unknown"

        # ── PLAIN ENGLISH FLAGS FOR THE AI ──────────────────────────
        if 21 in result["open_ports"]:
            result["flags"].append("FTP open on port 21 — unencrypted file transfer, high risk")
        if 22 in result["open_ports"]:
            result["flags"].append("SSH exposed on port 22 — remote login possible, check auth strength")
        if 23 in result["open_ports"]:
            result["flags"].append("Telnet open on port 23 — extremely insecure, unencrypted remote access")
        if 80 in result["open_ports"]:
            result["flags"].append("HTTP running on port 80 — unencrypted web traffic, consider HTTPS")
        if 443 in result["open_ports"]:
            result["flags"].append("HTTPS running on port 443 — encrypted web traffic, good")
        if 3306 in result["open_ports"]:
            result["flags"].append("MySQL database exposed on port 3306 — critical, should not be public")
        if 5432 in result["open_ports"]:
            result["flags"].append("PostgreSQL database exposed on port 5432 — critical, should not be public")
        if 6379 in result["open_ports"]:
            result["flags"].append("Redis exposed on port 6379 — critical, often has no auth by default")
        if 8080 in result["open_ports"]:
            result["flags"].append("Alternative HTTP on port 8080 — often used for admin panels, check access")
        if not result["open_ports"]:
            result["flags"].append("No open ports detected — target may be heavily firewalled")

        return result

    except Exception as e:
        result["flags"].append(f"Scanner error: {str(e)}")
        return result
