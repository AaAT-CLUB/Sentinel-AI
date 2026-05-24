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
  {
    "open_ports":  [22, 80, 443],
    "services":    {"22": "OpenSSH 8.9"},
    "flags":       ["SSH exposed on 22"],
    "raw":         "optional raw scan text"
  }
"""

import subprocess


def empty_result() -> dict:
    return {"open_ports": [], "services": {}, "flags": [], "raw": ""}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#   TEAM 3 — EDIT HERE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def scan_target(domain: str) -> dict:
    """
    Run a security scan against the given domain.
    Replace the placeholder below with your Nmap/scanner logic.
    """
    # PLACEHOLDER — remove this and add your code
    result = empty_result()
    result["flags"].append("Scanner not connected — no port data available")
    return result
