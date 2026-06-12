# Durable Production Auditing Design

## Goal

Store Data Engineering API audit records durably in the PostgreSQL database on
the DigitalOcean Droplet while preserving read availability and preventing
security-sensitive writes from completing without an audit trail.

## Scope

This design replaces the process-memory request log store used by the
Data Engineering API. It covers API audit persistence, retrieval, redaction,
retention, and failure behavior. It does not add an external log aggregation
service or change the existing private Tailscale access model.

Nest console logs and the systemd journal remain operational diagnostics. The
PostgreSQL audit table becomes the durable audit record.

## Architecture

The API will use an `AuditService` backed by the existing `PG_POOL` provider.
The global request interceptor and HTTP exception filter will construct
sanitized audit events and pass them to this service.

Read-only requests use best-effort audit writes. If persistence fails, the
response continues and Nest emits an error containing the request ID and error
category, without sensitive request data.

Security-sensitive write operations use a PostgreSQL transaction containing
both the business change and its audit insert. If either statement fails, the
transaction rolls back and the API returns an error. This applies to:

- `POST /vulnerabilities`
- `POST /import-cves`
- future endpoints that create, update, delete, import, authenticate, or change
  security configuration

The `GET /logs` endpoint will query PostgreSQL rather than process memory. It
remains protected by the `admin:logs` scope.

## Database Schema

Add an append-only `audit_logs` table:

```sql
CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  request_id UUID NOT NULL,
  method VARCHAR(10) NOT NULL,
  route TEXT NOT NULL,
  status_code INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL CHECK (duration_ms >= 0),
  source_ip INET NULL,
  actor_owner TEXT NULL,
  actor_key_prefix VARCHAR(32) NULL,
  action TEXT NOT NULL,
  resource_type TEXT NULL,
  resource_id TEXT NULL,
  result VARCHAR(16) NOT NULL CHECK (result IN ('success', 'failure')),
  error_category TEXT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS audit_logs_occurred_at_idx
  ON audit_logs (occurred_at DESC);

CREATE INDEX IF NOT EXISTS audit_logs_actor_key_prefix_idx
  ON audit_logs (actor_key_prefix, occurred_at DESC);

CREATE INDEX IF NOT EXISTS audit_logs_action_idx
  ON audit_logs (action, occurred_at DESC);
```

Application code will expose only insert and select operations for this table.
There will be no API endpoint for updating or deleting individual audit rows.
Production database permissions should deny `UPDATE` on `audit_logs` to the
runtime role. Retention cleanup requires narrowly scoped `DELETE` permission or
a separate maintenance database role.

## Audit Event Model

Every record contains:

- UTC timestamp
- generated or forwarded request ID
- method and normalized route
- status code and measured duration
- source IP
- authenticated API-key owner and prefix, when available
- action name
- resource type and sanitized identifier, when applicable
- success or failure result
- sanitized error category
- bounded JSON metadata

Action names use stable lowercase identifiers such as:

- `health_check`
- `list_vulnerabilities`
- `get_vulnerability`
- `create_vulnerability`
- `import_cves`
- `read_audit_logs`
- `authorization_failed`

The normalized route records the route pattern, such as
`/vulnerabilities/:cveId`, rather than an unbounded raw URL. Query strings are
not stored.

## Redaction

Audit records must never contain:

- raw API keys
- `Authorization` or `x-api-key` header values
- passwords, password hashes, salts, or peppers
- database credentials
- complete request or response bodies
- arbitrary query strings
- exception stack traces

Allowed sanitized details include:

- CVE ID
- API-key owner and prefix
- requested result limit
- severity filter
- number of records inserted, skipped, or returned
- stable error categories such as `unauthorized`, `forbidden`,
  `validation_error`, `not_found`, `database_error`, or `internal_error`

Metadata must be built from an allowlist for each action. The audit service
must reject unsupported metadata keys rather than attempting broad recursive
redaction.

## Request Identity

The interceptor will accept a valid incoming `x-request-id` or generate a UUID.
The selected value will be returned in the response header and included in
console errors and the database audit record. Incoming request IDs must have a
bounded length and restricted character set; invalid values are replaced.

## Write Transactions

Business services that perform security-sensitive writes will accept or create
a PostgreSQL client transaction:

1. Acquire a client from the existing pool.
2. Run `BEGIN`.
3. Perform the business insert or import.
4. Insert the corresponding audit event using the same client.
5. Run `COMMIT`.
6. On any error, run `ROLLBACK` and rethrow a sanitized server error.
7. Release the client in `finally`.

The global interceptor must not create a second success audit entry for a write
already audited transactionally. It may record rejected writes that never
entered a business transaction using best-effort failure auditing.

## Read Failure Behavior

For read-only endpoints, audit insertion happens after the result is known. An
audit database failure does not alter the HTTP response. The application emits
a Nest error with:

- request ID
- method and normalized route
- the fixed message `audit persistence failed`
- a sanitized error category

The console error must not include the event metadata or raw database error
message. Existing service monitoring should alert on this message through the
systemd journal.

## Audit Retrieval

`GET /logs` returns newest records first and requires `admin:logs`.

Supported parameters:

- `limit`: integer from 1 to 200, default 100
- `before_id`: optional positive audit ID for cursor pagination
- `action`: optional exact action name
- `result`: optional `success` or `failure`

The response shape is:

```json
{
  "items": [],
  "next_before_id": null
}
```

The request that reads audit logs is itself audited as `read_audit_logs`.
Its audit event is not included in the response currently being assembled.

## Retention

Audit records are retained for 90 days.

The migration adds a maintenance command that executes:

```sql
DELETE FROM audit_logs
WHERE occurred_at < NOW() - INTERVAL '90 days';
```

Production will run this command once per day with a systemd timer or cron job.
The command reports only the number of deleted rows. It must not print audit
record contents.

## Migration and Deployment

The existing database migration command will create the `audit_logs` table and
indexes idempotently. Deployment order:

1. Back up PostgreSQL.
2. Deploy the migration code.
3. Run the migration against the Droplet-local database.
4. Deploy and restart the Data API.
5. Make authenticated read and write requests.
6. Verify records through `GET /logs` and direct database inspection.
7. Install and enable the daily retention job.
8. Verify a forced read-audit failure preserves the read response.
9. Verify a forced write-audit failure rolls back the business write.

No public database port or new public API route is required. Tailscale and
loopback clients continue using the existing Data API URLs.

## Testing

Automated tests will cover:

- audit schema migration and indexes
- successful persistent insert
- owner and API-key prefix attribution
- request ID generation and propagation
- route normalization and query-string exclusion
- metadata allowlisting and secret rejection
- read requests continuing after audit persistence failure
- write transaction rollback after audit persistence failure
- prevention of duplicate success records for transactional writes
- exception category mapping
- `/logs` authentication, filtering, ordering, and cursor pagination
- deletion of records older than 90 days without deleting newer records

The full TypeScript build and existing test suite must continue to pass.

## Operational Acceptance Criteria

The feature is complete when:

- audit records survive API restarts
- no secret values appear in stored test records
- authorized operators can page through records using `GET /logs`
- read requests remain available during simulated audit insert failure
- sensitive writes leave neither business data nor an audit row when the audit
  insert fails
- records older than 90 days are removed by the maintenance command
- PostgreSQL remains reachable only through the existing private server setup
