# Sentinel AI Data API Usage Guide

This guide is for teams and services that need Sentinel AI vulnerability data from the Data Engineering API.

## Base URLs

The Data API is private infrastructure. Public internet access to `/data-api/*` is intentionally disabled.

Use the right URL for your caller:

| Caller | Base URL |
|---|---|
| DataEngineering service running on the Droplet | `http://127.0.0.1:3000` |
| Team laptop connected to Tailscale | `https://sentinel-ai-data.<tailnet>.ts.net/data-api` |
| Other backend service on the same Droplet | `http://127.0.0.1:3000` |

Replace `<tailnet>` with the team's Tailscale MagicDNS tailnet name.

Do not call `https://sentinel-a-i.com/data-api` from new code. That public path is being removed.

## Tailscale Access For Team Devices

1. Install Tailscale from `https://tailscale.com/download`.
2. Sign in with the account invited to the Sentinel AI tailnet.
3. If device approval is enabled, wait for a Tailscale admin to approve your device.
4. Confirm you can see the Droplet in Tailscale as `sentinel-ai-data`.
5. Call the private API URL over Tailscale:

```bash
curl https://sentinel-ai-data.<tailnet>.ts.net/data-api/health
```

If the Droplet is disconnected by a Tailscale admin, or if `tailscaled` is stopped on the Droplet, team laptop access will stop until it is reconnected.

## Authentication

`GET /health` is public inside the private network so monitors can verify the service.

Every other endpoint requires an `x-api-key` header. API keys are scoped, revocable, and stored as hashes in PostgreSQL. Raw keys are shown only once when created.

Example:

```bash
curl "https://sentinel-ai-data.<tailnet>.ts.net/data-api/vulnerabilities?limit=25" \
  -H "x-api-key: sk_sentinel_<prefix>_<secret>"
```

Never put an API key in browser code. Call the Data API from backend code or a trusted local tool.

## API Key Scopes

| Scope | Allows |
|---|---|
| `read:vulnerabilities` | `GET /`, `GET /vulnerabilities`, `GET /vulnerabilities/:cve_id` |
| `write:vulnerabilities` | `POST /vulnerabilities` |
| `import:cves` | `POST /import-cves` |
| `admin:logs` | `GET /logs` |

Request the smallest scope set needed for the caller.

## API Key Administration

Run these commands from `DataEngineeringTeam/` on a trusted operator machine or on the Droplet with production database environment variables loaded.

Create or verify the key table:

```bash
npm run db:migrate
```

Create a key:

```bash
npm run api-key:create -- --owner webserver --scopes read:vulnerabilities
```

Create a key with multiple scopes:

```bash
npm run api-key:create -- --owner data-importer --scopes read:vulnerabilities,import:cves
```

List keys:

```bash
npm run api-key:list
```

Revoke a key:

```bash
npm run api-key:revoke -- --prefix <prefix>
```

Store raw keys in the team password manager immediately. They cannot be recovered from the database.

## Endpoints

| Method | Path | Auth | Required Scope | Purpose |
|---|---|---|---|---|
| `GET` | `/health` | No | none | Confirms the API can connect to PostgreSQL. |
| `GET` | `/` | Yes | `read:vulnerabilities` | Confirms the Data Engineering API is reachable. |
| `GET` | `/vulnerabilities` | Yes | `read:vulnerabilities` | Returns imported vulnerabilities, newest first, with optional filters. |
| `GET` | `/vulnerabilities/:cve_id` | Yes | `read:vulnerabilities` | Returns one vulnerability by exact CVE ID. |
| `POST` | `/vulnerabilities` | Yes | `write:vulnerabilities` | Inserts one or more CVEs manually with deduplication by `cve_id`. |
| `POST` | `/import-cves` | Yes | `import:cves` | Fetches CVEs from NVD and inserts new rows into PostgreSQL. |
| `GET` | `/logs` | Yes | `admin:logs` | Returns recent in-memory request logs. |

## Endpoint Details

### `GET /health`

Checks that the API is online and can reach the database.

```bash
curl https://sentinel-ai-data.<tailnet>.ts.net/data-api/health
```

Example response:

```json
{
  "status": "ok"
}
```

### `GET /vulnerabilities`

Returns imported vulnerabilities. By default, this endpoint returns the latest 100 records.

```bash
curl "https://sentinel-ai-data.<tailnet>.ts.net/data-api/vulnerabilities?severity=HIGH&limit=250" \
  -H "x-api-key: sk_sentinel_<prefix>_<secret>"
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

### `GET /vulnerabilities/:cve_id`

Returns one vulnerability by exact CVE ID.

```bash
curl https://sentinel-ai-data.<tailnet>.ts.net/data-api/vulnerabilities/CVE-1999-0095 \
  -H "x-api-key: sk_sentinel_<prefix>_<secret>"
```

If the CVE ID does not exist, the API returns `404 Not Found`.

### `POST /vulnerabilities`

Inserts a vulnerability manually. The endpoint uses `cve_id` as the deduplication key, so repeated requests for the same CVE ID do not create duplicate rows.

```bash
curl -X POST https://sentinel-ai-data.<tailnet>.ts.net/data-api/vulnerabilities \
  -H "Content-Type: application/json" \
  -H "x-api-key: sk_sentinel_<prefix>_<secret>" \
  -d '{
    "cve_id": "CVE-2026-0001",
    "description": "Example vulnerability description",
    "severity": "HIGH",
    "published_date": "2026-06-05T00:00:00Z"
  }'
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
curl -X POST https://sentinel-ai-data.<tailnet>.ts.net/data-api/import-cves \
  -H "x-api-key: sk_sentinel_<prefix>_<secret>"
```

Use this endpoint intentionally. It calls the external NVD API and writes to the production PostgreSQL database.

## Database Reference

The API reads and writes to:

```text
Database: sentinel_dev
Table: public.vulnerabilities
```

Expected vulnerability schema:

```sql
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id SERIAL PRIMARY KEY,
  cve_id VARCHAR(50) UNIQUE NOT NULL,
  description TEXT,
  severity VARCHAR(20),
  published_date TIMESTAMP
);
```

API keys are stored in:

```text
Table: public.api_keys
```

Raw API keys are not stored.

## Operational Notes

- The NestJS Data API runs as `sentinel-data-api.service`.
- The service binds to `127.0.0.1:3000`.
- PostgreSQL listens locally on `127.0.0.1:5432`.
- Production secrets should live in `/etc/sentinel/data-api.env` with `root:root` ownership and `600` permissions.
- The existing public FastAPI backend remains separate under `/api/*`.

Useful Droplet checks:

```bash
systemctl status sentinel-data-api.service --no-pager
systemctl status postgresql --no-pager
systemctl status tailscaled --no-pager
ss -tulpn | grep -E '(:3000|:5432|:80|:443)'
curl -i http://127.0.0.1:3000/health
```

## Migration Note For Other Teams

Other teams should not edit DataEngineering credentials directly.

Backend services on the same Droplet should call:

```text
http://127.0.0.1:3000
```

Team laptops should call:

```text
https://sentinel-ai-data.<tailnet>.ts.net/data-api
```

All non-health calls must include `x-api-key`. Ask DataEngineering for the minimum required scope.

## Troubleshooting

### `GET /health` is not `200 OK`

Check that PostgreSQL and the Nest API are running:

```bash
systemctl is-active postgresql
systemctl is-active sentinel-data-api.service
```

### Requests return `401 Unauthorized`

The `x-api-key` header is missing, malformed, expired, revoked, or does not match a hashed key in PostgreSQL.

### Requests return `403 Forbidden`

The key is valid but does not have the scope required for that endpoint.

### The Tailscale URL does not resolve

Confirm Tailscale is connected on both the laptop and Droplet:

```bash
tailscale status
```

If the Droplet shows disconnected in the Tailscale admin console, a Tailscale admin must reconnect or approve it.
