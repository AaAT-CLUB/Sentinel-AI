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

import subprocess


# ── RETURN FORMAT ────────────────────────────────────────────────────
# This is what we pass to Claude. Keep these keys consistent.
def empty_result() -> dict:
    return {
        "open_ports": [],
        "services":   {},
        "flags":      [],
        "raw":        ""
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#   TEAM 3 — EDIT HERE
#   Replace the placeholder below with your scanner logic.
#   The `domain` parameter is the target (e.g. "google.com")
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def scan_target(domain: str) -> dict:
    """
    Run a security scan against the given domain.
    Returns structured findings for the AI to interpret.

    Args:
        domain: The target domain, e.g. "example.com"

    Returns:
        dict with keys: open_ports, services, flags, raw
    """

    # ── PLACEHOLDER (remove this block and add your code below) ──
    # Right now this returns empty results so the AI still works
    # without a real scanner. Team 3: replace this with your logic.
    result = empty_result()
    result["flags"].append("Scanner not connected — no port data available")
    return result

    # ── EXAMPLE: how to call your existing scanner.py ─────────────
    # If you have scanner.py on the server, you can call it like this:
    #
    # try:
    #     output = subprocess.check_output(
    #         ["python3", "/path/to/scanner.py", domain],
    #         timeout=20,
    #         stderr=subprocess.STDOUT,
    #         text=True
    #     )
    #     result = empty_result()
    #     result["raw"] = output
    #     # Parse your output and fill in open_ports, services, flags
    #     return result
    # except Exception as e:
    #     result = empty_result()
    #     result["flags"].append(f"Scanner error: {str(e)}")
    #     return result

    # ── EXAMPLE: direct python-nmap usage ─────────────────────
    # import nmap
    # nm = nmap.PortScanner()
    # nm.scan(domain, '1-1024', '-sV')
    #
    # result = empty_result()
    # for host in nm.all_hosts():
    #     for proto in nm[host].all_protocols():
    #         for port, data in nm[host][proto].items():
    #             if data['state'] == 'open':
    #                 result["open_ports"].append(port)
    #                 result["services"][str(port)] = f"{data.get('name','')} {data.get('version','')}".strip()
    #
    # if 22 in result["open_ports"]:
    #     result["flags"].append("SSH exposed on port 22")
    # if 21 in result["open_ports"]:
    #     result["flags"].append("FTP open — unencrypted file transfer risk")
    #
    # return result
