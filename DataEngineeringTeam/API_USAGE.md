# Sentinel AI Data API Usage Guide

This guide is for Sentinel AI teams that need to read vulnerability data or trigger a CVE import from the Data Engineering API.

## Base URL

Production API base URL:

```text
https://sentinel-a-i.com/data-api
```

The Data Engineering API is exposed through Nginx under `/data-api/*`. The existing FastAPI service remains under `/api/*`, so do not use `/api` for the endpoints in this document.

## Authentication

Read-only endpoints do not require authentication.

The import endpoint requires an API key in the `x-api-key` header:

```bash
curl -X POST https://sentinel-a-i.com/data-api/import-cves \
  -H "x-api-key: YOUR_API_KEY"
```

The API key is stored on the droplet in:

```text
/root/Sentinel-AI/DataEngineeringTeam/.env
```

From the droplet console, root can print it with:

```bash
grep '^API_KEY=' /root/Sentinel-AI/DataEngineeringTeam/.env | cut -d= -f2-
```

Do not commit the API key, paste it into public channels, or hardcode it in browser code.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/` | No | Confirms the Data Engineering API is reachable. |
| `GET` | `/health` | No | Confirms the API can connect to PostgreSQL. |
| `GET` | `/vulnerabilities` | No | Returns imported vulnerabilities, newest first, with optional filters. |
| `GET` | `/vulnerabilities/:cve_id` | No | Returns one vulnerability by exact CVE ID. |
| `POST` | `/vulnerabilities` | Yes | Inserts one or more CVEs manually with deduplication by `cve_id`. |
| `POST` | `/import-cves` | Yes | Fetches CVEs from NVD and inserts new rows into PostgreSQL. |

## Endpoint Details

### `GET /`

Checks that the service is online.

```bash
curl https://sentinel-a-i.com/data-api/
```

Example response:

```json
{
  "message": "Sentinel AI Data Engineering API"
}
```

### `GET /health`

Checks that the API is online and can reach the database.

```bash
curl https://sentinel-a-i.com/data-api/health
```

Example success response:

```json
{
  "status": "ok"
}
```

If PostgreSQL is unreachable, this endpoint returns a service unavailable error.

### `GET /vulnerabilities`

Returns imported vulnerabilities. By default, this endpoint returns the latest 100 records.

```bash
curl https://sentinel-a-i.com/data-api/vulnerabilities
```

Optional query parameters:

| Parameter | Example | Description |
|---|---|---|
| `limit` | `250` | Maximum rows to return. Defaults to `100`; must be an integer from `1` to `1000`. |
| `cve_id` | `CVE-2026-0001` | Exact CVE ID match. |
| `keyword` | `buffer overflow` | Case-insensitive search inside the description. |
| `description` | `buffer overflow` | Alias for `keyword`. |
| `severity` | `HIGH` | Case-insensitive severity match. |
| `published_from` | `2026-01-01` | Return rows with `published_date` on or after this date. |
| `published_to` | `2026-06-30` | Return rows with `published_date` on or before this date. |

Examples:

```bash
curl "https://sentinel-a-i.com/data-api/vulnerabilities?limit=500"
curl "https://sentinel-a-i.com/data-api/vulnerabilities?severity=HIGH&limit=250"
curl "https://sentinel-a-i.com/data-api/vulnerabilities?keyword=buffer%20overflow"
curl "https://sentinel-a-i.com/data-api/vulnerabilities?cve_id=CVE-1999-0095"
```

Response shape:

```json
[
  {
    "id": 50,
    "cve_id": "CVE-1999-1216",
    "description": "Cisco routers 9.17 and earlier allow remote attackers...",
    "severity": "HIGH",
    "published_date": "1993-04-22T04:00:00.000Z"
  }
]
```

Notes:

- Results are ordered by `published_date` descending.
- `severity` can be values such as `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, or `UNKNOWN`.
- `published_date` is returned as an ISO timestamp string.

### `GET /vulnerabilities/:cve_id`

Returns one vulnerability by exact CVE ID.

```bash
curl https://sentinel-a-i.com/data-api/vulnerabilities/CVE-1999-0095
```

Example response:

```json
{
  "id": 1,
  "cve_id": "CVE-1999-0095",
  "description": "The debug command in Sendmail is enabled...",
  "severity": "HIGH",
  "published_date": "1988-10-01T04:00:00.000Z"
}
```

If the CVE ID does not exist, the API returns `404 Not Found`.

### `POST /vulnerabilities`

Inserts a vulnerability manually. The endpoint uses `cve_id` as the deduplication key, so repeated requests for the same CVE ID do not create duplicate rows.

```bash
curl -X POST https://sentinel-a-i.com/data-api/vulnerabilities \
  -H "Content-Type: application/json" \
  -H "x-api-key: YOUR_API_KEY" \
  -d '{
    "cve_id": "CVE-2026-0001",
    "description": "Example vulnerability description",
    "severity": "HIGH",
    "published_date": "2026-06-05T00:00:00Z"
  }'
```

Example response for a new row:

```json
{
  "inserted": true,
  "vulnerability": {
    "id": 51,
    "cve_id": "CVE-2026-0001",
    "description": "Example vulnerability description",
    "severity": "HIGH",
    "published_date": "2026-06-05T00:00:00.000Z"
  }
}
```

Example response for a duplicate:

```json
{
  "inserted": false,
  "duplicate": true,
  "cve_id": "CVE-2026-0001"
}
```

You can also submit an array of vulnerability objects to insert multiple records in one request:

```bash
curl -X POST https://sentinel-a-i.com/data-api/vulnerabilities \
  -H "Content-Type: application/json" \
  -H "x-api-key: YOUR_API_KEY" \
  -d '[
    {
      "cve_id": "CVE-2026-0001",
      "description": "First vulnerability",
      "severity": "HIGH",
      "published_date": "2026-06-05T00:00:00Z"
    },
    {
      "cve_id": "CVE-2026-0002",
      "description": "Second vulnerability",
      "severity": "MEDIUM",
      "published_date": "2026-06-05T00:00:00Z"
    }
  ]'
```

Required fields:

- `cve_id`
- `published_date`

Optional fields:

- `description`
- `severity`; defaults to `UNKNOWN`

### `POST /import-cves`

Fetches 50 CVEs from the NVD API and inserts them into the `vulnerabilities` table. Duplicate `cve_id` values are skipped.

```bash
curl -X POST https://sentinel-a-i.com/data-api/import-cves \
  -H "x-api-key: YOUR_API_KEY"
```

Example response when rows already exist:

```json
{
  "imported": 0,
  "skipped": 50,
  "total": 50
}
```

Example response after a fresh import:

```json
{
  "imported": 50,
  "skipped": 0,
  "total": 50
}
```

Use this endpoint intentionally. It calls the external NVD API and writes to the production PostgreSQL database.

## JavaScript Examples

### Read Vulnerabilities

```js
async function getVulnerabilities() {
  const params = new URLSearchParams({
    severity: 'HIGH',
    limit: '250',
  });
  const response = await fetch(`https://sentinel-a-i.com/data-api/vulnerabilities?${params}`);

  if (!response.ok) {
    throw new Error(`Data API request failed: ${response.status}`);
  }

  return response.json();
}
```

### Trigger an Import From a Backend Service

Do not put the API key in frontend/browser code. Call this from a backend service or server-side job.

```js
async function importCves(apiKey) {
  const response = await fetch('https://sentinel-a-i.com/data-api/import-cves', {
    method: 'POST',
    headers: {
      'x-api-key': apiKey,
    },
  });

  if (!response.ok) {
    throw new Error(`Import failed: ${response.status}`);
  }

  return response.json();
}
```

## Database Reference

The API reads and writes to the PostgreSQL database:

```text
Database: sentinel_dev
Table: public.vulnerabilities
```

Schema:

```sql
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id SERIAL PRIMARY KEY,
  cve_id VARCHAR(50) UNIQUE NOT NULL,
  description TEXT,
  severity VARCHAR(20),
  published_date TIMESTAMP
);
```

## Operational Notes

- The NestJS API runs on the droplet as `sentinel-data-api.service`.
- The service binds to `127.0.0.1:3000`; public access goes through Nginx at `/data-api/*`.
- PostgreSQL listens locally on `127.0.0.1:5432`.
- The existing FastAPI backend runs as `sentinel-api.service` and remains available at `/api/*`.
- The API key and database password are stored in the droplet `.env`, not in GitHub.

Useful droplet checks:

```bash
systemctl status sentinel-data-api --no-pager
systemctl status postgresql --no-pager
systemctl status nginx --no-pager
curl -i http://127.0.0.1:3000/health
curl -i https://sentinel-a-i.com/data-api/health
```

## Troubleshooting

### `GET /health` is not `200 OK`

Check that PostgreSQL and the Nest API are running:

```bash
systemctl is-active postgresql
systemctl is-active sentinel-data-api
```

### `POST /import-cves` returns `401 Unauthorized`

The `x-api-key` header is missing or does not match `API_KEY` in:

```text
/root/Sentinel-AI/DataEngineeringTeam/.env
```

### `/data-api/*` returns an Nginx error

Check Nginx and the Nest service:

```bash
nginx -t
systemctl status nginx --no-pager
systemctl status sentinel-data-api --no-pager
```

### Import succeeds but no new rows appear

The import endpoint skips duplicate `cve_id` values. A response like this is expected when the latest fetched CVEs already exist:

```json
{
  "imported": 0,
  "skipped": 50,
  "total": 50
}
```
