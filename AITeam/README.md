# Sentinel AI - AI Team

## Week 1 Setup

This folder contains the AI engine for Sentinel AI — responsible for fetching CVE vulnerability data and generating plain-English threat briefings using Claude and GPT-4o.

---

## What This Does

- Fetches real CVE data from the NVD (National Vulnerability Database) API
- Sends the CVE to Claude (Anthropic) or GPT-4o (OpenAI) for AI summarization
- Returns a plain-English threat briefing explaining the vulnerability, its severity, and how to fix it

---

## Stack

- **Language:** Python 3
- **AI Models:** Anthropic Claude Haiku, OpenAI GPT-4o
- **Data Source:** NVD API (nvd.nist.gov)

---

## Files

| File | Description |
|------|-------------|
| `week1.py` | CVE fetch + AI summarization script |

---

## API Keys Required

| Key | Where to Get It |
|-----|----------------|
| `ANTHROPIC_API_KEY` | console.anthropic.com |
| `OPENAI_API_KEY` | platform.openai.com |
| `NVD_API_KEY` | nvd.nist.gov/developers |

---

## Setup

Install dependencies:

```bash
pip install anthropic openai python-dotenv requests
```

Create a `.env` file:

```
ANTHROPIC_API_KEY=sk-ant-api03-...
OPENAI_API_KEY=sk-proj-...
NVD_API_KEY=your-nvd-key-here
```

Run the script:

```bash
python week1.py
```

---

## Example Output

```
Fetching CVE-2021-44228 from NVD...

ID:        CVE-2021-44228
Severity:  CRITICAL (10.0/10)
Published: 2021-12-10

--- AI Explanation ---

A critical remote code execution vulnerability in Apache Log4j 2...
```

---

## Coming Next (Week 2)

- Wrap into a FastAPI backend
- Expose `POST /api/analyze` endpoint
- Connect to the frontend UI at `sentinel-frontend/`
- Integrate with Team 2's database
