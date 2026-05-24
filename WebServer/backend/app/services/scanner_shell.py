"""
SCANNER SHELL — FOR CYBERSECURITY TEAM (TEAM 3)

Edit the scan_target() function below with your scanner logic.
Do not change the function name or return format.

Return format:
  {
    "open_ports": [22, 80, 443],
    "services":   {"22": "OpenSSH 8.9"},
    "flags":      ["SSH exposed on port 22"],
    "raw":        "optional raw output"
  }
"""

def empty_result():
    return {"open_ports": [], "services": {}, "flags": [], "raw": ""}

# ── TEAM 3: REPLACE THE PLACEHOLDER BELOW WITH YOUR SCANNER CODE ──
def scan_target(domain: str) -> dict:
    result = empty_result()
    result["flags"].append("Scanner not connected — no port data available")
    return result
