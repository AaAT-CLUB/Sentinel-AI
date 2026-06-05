# Sentinel AI - Data Engineering Team

## Week 1 Setup

This folder contains the PostgreSQL database setup, Node.js NVD CVE import script, and a NestJS API using Fastify.

## Database

Database name: sentinel_dev

Table: vulnerabilities

Columns:

- id
- cve_id
- description
- severity
- published_date

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

## Setup

Install dependencies:

`npm install`

Create a `.env` file:

```
DB_HOST=localhost
DB_PORT=5432
DB_NAME=sentinel_dev
DB_USER=admin
DB_PASSWORD=your_password_here
API_KEY=your_api_key_here
NVD_API_KEY=
HOST=127.0.0.1
PORT=3000
```

### Run the existing CVE import script

`npm run import:cves`

### Start the API in development

`npm start`

### Build the API for production

`npm run build`

## API Endpoints

- `GET /` — API health and welcome message
- `GET /health` — health status
- `GET /vulnerabilities` — list imported vulnerabilities
- `POST /import-cves` — fetch CVEs from NVD and insert into the database. Requires an `x-api-key` header matching `API_KEY`.

On the production DigitalOcean droplet, Nginx exposes this API under `/data-api/*` so it does not conflict with the existing FastAPI service under `/api/*`.

Examples:

```bash
curl https://sentinel-a-i.com/data-api/health
curl https://sentinel-a-i.com/data-api/vulnerabilities
curl -X POST https://sentinel-a-i.com/data-api/import-cves -H "x-api-key: $API_KEY"
```

## Notes

- The NestJS app uses Fastify as the HTTP adapter.
- The API listens on `PORT` from the environment, or port `3000` by default.
- On the production droplet, set `HOST=127.0.0.1` so the API is reachable through Nginx but not exposed directly on the public network.
