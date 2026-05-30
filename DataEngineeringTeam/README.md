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

## Setup

Install dependencies:

`npm install`

Create a `.env` file:

```
DB_HOST=localhost
DB_PORT=5432
DB_NAME=sentinel_dev
DB_USER=postgres
DB_PASSWORD=your_password_here
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
- `POST /import-cves` — fetch CVEs from NVD and insert into the database

## Notes

- The NestJS app uses Fastify as the HTTP adapter.
- The API listens on port `3000` by default.
