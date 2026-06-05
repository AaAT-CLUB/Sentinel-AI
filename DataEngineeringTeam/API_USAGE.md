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
| `GET` | `/vulnerabilities` | No | Returns up to 100 imported vulnerabilities, newest first. |
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

Returns the latest imported vulnerabilities.

```bash
curl https://sentinel-a-i.com/data-api/vulnerabilities
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

- The endpoint returns at most 100 records.
- Results are ordered by `published_date` descending.
- `severity` can be values such as `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, or `UNKNOWN`.
- `published_date` is returned as an ISO timestamp string.

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
  const response = await fetch('https://sentinel-a-i.com/data-api/vulnerabilities');

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
