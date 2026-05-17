import os
import requests
import anthropic
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
NVD_API_KEY = os.environ.get("NVD_API_KEY")

def fetch_cve(cve_id: str) -> dict:
    headers = {"apiKey": NVD_API_KEY}
    response = requests.get(NVD_URL, params={"cveId": cve_id}, headers=headers)
    response.raise_for_status()
    data = response.json()
    vuln = data["vulnerabilities"][0]["cve"]
    description = next(
        (d["value"] for d in vuln["descriptions"] if d["lang"] == "en"),
        "No description available"
    )
    try:
        score = vuln["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
        severity = vuln["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
    except (KeyError, IndexError):
        score, severity = "N/A", "N/A"

    return {
        "id": vuln["id"],
        "description": description,
        "score": score,
        "severity": severity,
        "published": vuln["published"][:10],
    }

def explain_cve(cve: dict) -> str:
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    prompt = f"""You are a cybersecurity assistant. Explain this vulnerability in plain English for someone with no security background.

CVE ID: {cve['id']}
Severity: {cve['severity']} (score {cve['score']} out of 10)
Published: {cve['published']}
Technical description: {cve['description']}

Explain:
1. What is affected
2. What an attacker could do
3. How serious it is
4. What should be done to fix it

Keep it simple — no jargon."""

    message = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text

def OpenAI_call(message: str) -> str:
    client = OpenAI()

    response = client.chat.completions.create(
        model="gpt-4o",  # or "gpt-3.5-turbo"
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": message}
        ]
    )
    
    return response.choices[0].message.content


if __name__ == "__main__":
    cve_id = "CVE-2021-44228"  # Log4Shell
    print(f"Fetching {cve_id} from NVD...\n")

    cve = fetch_cve(cve_id)
    print(f"ID:        {cve['id']}")
    print(f"Severity:  {cve['severity']} ({cve['score']}/10)")
    print(f"Published: {cve['published']}")
    print(f"Raw desc:  {cve['description'][:120]}...")
    print("\n--- AI Explanation ---\n")

    #explanation = explain_cve(cve)
    #print(explanation)
    print(OpenAI_call("Explain what ChatGPT is in one sentence."))
