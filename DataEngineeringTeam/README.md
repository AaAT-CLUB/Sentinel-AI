# Sentinel AI - Data Engineering Team

## Week 1 Setup

This folder contains the PostgreSQL database setup and Node.js NVD CVE import script.

## Database

Database name:

sentinel_dev

Table:

vulnerabilities

Columns:

- id
- cve_id
- description
- severity
- published_date

## Setup

Install dependencies:

npm install

Create a .env file:

DB_HOST=localhost
DB_PORT=5432
DB_NAME=sentinel_dev
DB_USER=postgres
DB_PASSWORD=your_password_here

Run the CVE import:

npm run import:cves