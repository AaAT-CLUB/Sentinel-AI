# Sentinel AI - Data Engineering Team

This folder contains the PostgreSQL setup notes, NVD CVE import tooling, and the NestJS/Fastify Data API managed by the Data Engineering team.

## Ownership

Data Engineering owns:

- the PostgreSQL vulnerability data model;
- the Data API in this folder;
- Data API authentication and key management;
- Droplet-side Data API service configuration.

Other teams should integrate through the documented API and request scoped API keys from Data Engineering.

## Database

Database name: `sentinel_dev`

Primary table: `vulnerabilities`

Expected schema:

```sql
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id SERIAL PRIMARY KEY,
  cve_id VARCHAR(50) UNIQUE NOT NULL,
  description TEXT,
  severity VARCHAR(20),
  published_date TIMESTAMP
);
```

API keys are stored in `api_keys` after running:

```bash
npm run db:migrate
```

Raw API keys are never stored in PostgreSQL.

## Local Setup

Install dependencies:

```bash
npm install
```

Create a local `.env` file:

```text
DB_HOST=localhost
DB_PORT=5432
DB_NAME=sentinel_dev
DB_USER=admin
DB_PASSWORD=your_password_here
API_KEY_PEPPER=local-development-pepper
NVD_API_KEY=
HOST=127.0.0.1
PORT=3000
```

Build and test:

```bash
npm test
```

Start the API in development:

```bash
npm start
```

Build for production:

```bash
npm run build
```

## Key Management

Create or verify the API key table:

```bash
npm run db:migrate
```

Create a scoped key:

```bash
npm run api-key:create -- --owner data-team-user --scopes read:vulnerabilities
```

List keys:

```bash
npm run api-key:list
```

Revoke a key:

```bash
npm run api-key:revoke -- --prefix <prefix>
```

Store the raw key in the team password manager when it is created. It is shown once and cannot be recovered from the database.

## API Endpoints

Only `GET /health` is unauthenticated. All other endpoints require `x-api-key`.

| Method | Path | Scope |
|---|---|---|
| `GET` | `/health` | none |
| `GET` | `/` | `read:vulnerabilities` |
| `GET` | `/vulnerabilities` | `read:vulnerabilities` |
| `GET` | `/vulnerabilities/:cve_id` | `read:vulnerabilities` |
| `POST` | `/vulnerabilities` | `write:vulnerabilities` |
| `POST` | `/import-cves` | `import:cves` |
| `GET` | `/logs` | `admin:logs` |

For full usage details, see [API_USAGE.md](API_USAGE.md).

## Production Access Model

The production Data API runs on the DigitalOcean Droplet as `sentinel-data-api.service`.

Runtime expectations:

- NestJS binds to `127.0.0.1:3000`.
- PostgreSQL binds to `127.0.0.1:5432`.
- Public internet access to `/data-api/*` is intentionally removed.
- Team laptops access the API through Tailscale.
- Same-Droplet backend services can call `http://127.0.0.1:3000`.

Team laptop URL shape:

```text
https://sentinel-ai-data.<tailnet>.ts.net/data-api
```

Replace `<tailnet>` with the team Tailscale MagicDNS tailnet name.

## Production Secrets

Production secrets should be stored outside the repo checkout:

```text
/etc/sentinel/data-api.env
```

Recommended permissions:

```bash
chown root:root /etc/sentinel/data-api.env
chmod 600 /etc/sentinel/data-api.env
```

The systemd unit should reference that file:

```ini
EnvironmentFile=/etc/sentinel/data-api.env
```

Do not store production secrets in committed files.

## NVD Import

Run the existing CVE import script:

```bash
npm run import:cves
```

Or trigger the API import endpoint with a key scoped for `import:cves`.
