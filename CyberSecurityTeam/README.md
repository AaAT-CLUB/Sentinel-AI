# Sentinel AI - Cybersecurity Team

## Project Overview

This folder contains the cybersecurity scanner for Sentinel AI. Our code is responsible for checking websites and IP addresses to see what "doors" (ports) are left open, and checking if those addresses have a history of malicious behavior.

---

## Week 1 Setup: The Basic Scanner

In Week 1, we built a simple scanner that runs in the terminal. It uses Nmap to see if a computer is online and finds out what services are running on it.

### What It Does (Week 1)
* Takes a target website or IP address (like `scanme.nmap.org`).
* Scans it to find open ports (like Port 80 for web traffic).
* Lists out the open ports, the state they are in, and what software they are running.

### Running the Week 1 Script Directly
Before we built the web API, we just ran the scanner directly in the terminal like this:
```bash
python scanner.py
```

---

## Week 2 Setup: The Live API

In Week 2, we upgraded our terminal script into a real web API. Now, the frontend and database teams can send a request to our code, and our code will automatically scan the target and reply with the results.

### What It Does (Week 2)
* **Web Service:** Uses FastAPI to create a `/scan` endpoint that other teams can talk to.
* **Background Checks:** Connects to AbuseIPDB to look up the target's reputation and see if it has been reported by other security researchers.
* **Security Guardrails:** Uses a `.env` file to keep our private API keys hidden so they don't get stolen on GitHub.

## Stack

* **Language:** Python 3.14.5
* **Framework:** FastAPI, Uvicorn
* **Core Tools:** Nmap (`python-nmap`), Requests
* **Data Source:** AbuseIPDB API

## Files

| File | Description |
| :--- | :--- |
| `main.py` | The main web server and the AbuseIPDB background check code |
| `scanner.py` | The Week 1 Nmap scanning logic |
| `.env.example` | A safe template showing what API keys you need to run the app |

## API Keys Required

| Key | Where to Get It |
| :--- | :--- |
| `ABUSEIPDB_API_KEY` | [abuseipdb.com/api](https://www.abuseipdb.com/) |

## Setup & Installation

1. **Install Nmap:**
   Make sure you have the Nmap software installed on your computer first.

2. **Install Python packages:**
   ```bash
   pip install fastapi uvicorn python-nmap requests python-dotenv
   ```

3. **Set up your API Key:**
   Make a copy of the `.env.example` file, rename the copy to `.env`, and paste your key inside:
   ```bash
   ABUSEIPDB_API_KEY=your_actual_abuseipdb_key_here
   ```

4. **Start up the Server:**
   ```bash
   python -m uvicorn main:app --reload
   ```

---

## Example API Usage

### `POST /scan`
Send a target to this endpoint to run a full scan.

**Request Body:**
```json
{
  "target": "scanme.nmap.org"
}
```

**Response Body (`200 OK`):**
```json
{
  "target": "scanme.nmap.org",
  "resolved_ip": "45.33.32.156",
  "host_state": "up",
  "abuse_reputation": {
    "abuseScore": 13,
    "totalReports": 4,
    "isMalicious": false
  },
  "open_ports_detected": [
    {
      "port": 22,
      "protocol": "tcp",
      "state": "open",
      "product": "",
      "version": ""
    },
    {
      "port": 80,
      "protocol": "tcp",
      "state": "open",
      "product": "",
      "version": ""
    }
  ]
}
```

---

## Coming Next (Week 3)

* Save our scan results to the database.
* Connect our scanner to the frontend user interface.