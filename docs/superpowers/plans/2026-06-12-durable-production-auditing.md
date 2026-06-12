# Durable Production Auditing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist sanitized Data API audit records in the Droplet-local PostgreSQL database, retain them for 90 days, keep reads available when audit persistence fails, and roll back sensitive writes when their audit insert fails.

**Architecture:** Add a focused `AuditService` and request audit context shared by the interceptor, exception filter, controller, and transactional write methods. Read requests are audited best-effort after their result is known; write methods use one PostgreSQL client and transaction for both business data and the audit row. Replace the in-memory `/logs` implementation with cursor-paginated PostgreSQL queries and add idempotent migration/pruning scripts plus a systemd timer.

**Tech Stack:** NestJS 11, Fastify 5, TypeScript, PostgreSQL through `pg`, RxJS, Node test scripts, systemd.

---

## File Map

- Create `DataEngineeringTeam/src/audit.types.ts`: audit event, query, request-context, and database-client types.
- Create `DataEngineeringTeam/src/audit-policy.ts`: stable action names, route normalization, error categorization, request-ID validation, and metadata allowlists.
- Create `DataEngineeringTeam/src/audit.service.ts`: PostgreSQL insert/query operations and best-effort failure logging.
- Modify `DataEngineeringTeam/src/main.ts`: establish and return a validated request ID before guards execute.
- Modify `DataEngineeringTeam/src/auth.guard.ts`: attach authenticated owner and API-key prefix to the request context already used by auditing.
- Modify `DataEngineeringTeam/src/logging.interceptor.ts`: persist successful read events and skip successful writes already audited transactionally.
- Modify `DataEngineeringTeam/src/all-exceptions.filter.ts`: persist sanitized failure events without changing the original HTTP response.
- Modify `DataEngineeringTeam/src/app.controller.ts`: pass request audit context into write methods and expose paginated database audit queries.
- Modify `DataEngineeringTeam/src/app.service.ts`: run vulnerability writes and imports in transactions with the audit insert.
- Modify `DataEngineeringTeam/src/app.module.ts`: register `AuditService` and remove `LogsService`.
- Delete `DataEngineeringTeam/src/logs.service.ts`: remove the process-memory log store after all consumers migrate.
- Create `DataEngineeringTeam/scripts/audit-logs.js`: idempotent table/index migration and 90-day pruning command.
- Modify `DataEngineeringTeam/package.json`: run audit migration and expose the pruning command.
- Create `DataEngineeringTeam/systemd/sentinel-audit-prune.service`: one-shot retention cleanup unit.
- Create `DataEngineeringTeam/systemd/sentinel-audit-prune.timer`: daily retention schedule.
- Create `DataEngineeringTeam/test/audit-policy.test.js`: redaction, request ID, route, and error-category tests.
- Create `DataEngineeringTeam/test/audit.service.test.js`: insert, listing, filtering, pagination, and best-effort failure tests.
- Create `DataEngineeringTeam/test/audit-transaction.test.js`: commit and rollback behavior for sensitive writes.
- Create `DataEngineeringTeam/test/audit-scripts.test.js`: migration and 90-day pruning tests.
- Modify `DataEngineeringTeam/test/app.service.test.js`: adapt existing service tests to transaction-capable pool doubles.
- Modify `DataEngineeringTeam/test/auth-global-config.test.js`: verify audit providers remain globally wired.
- Modify `DataEngineeringTeam/API_USAGE.md`: document durable `/logs`, pagination, retention, and operational commands.
- Modify `DataEngineeringTeam/README.md`: document migration and systemd timer installation.

### Task 1: Define Audit Types and Sanitization Policy

**Files:**
- Create: `DataEngineeringTeam/src/audit.types.ts`
- Create: `DataEngineeringTeam/src/audit-policy.ts`
- Create: `DataEngineeringTeam/test/audit-policy.test.js`
- Modify: `DataEngineeringTeam/package.json`

- [ ] **Step 1: Add the failing audit-policy test**

Create `test/audit-policy.test.js` with assertions for:

```js
const assert = require('node:assert/strict');
const {
  categorizeAuditError,
  createRequestId,
  normalizeAuditRoute,
  sanitizeAuditMetadata,
} = require('../dist/audit-policy');

assert.equal(normalizeAuditRoute('/vulnerabilities/CVE-2026-0001?token=secret'), '/vulnerabilities/:cveId');
assert.equal(normalizeAuditRoute('/logs?limit=25'), '/logs');
assert.match(createRequestId('valid-request_123'), /^valid-request_123$/);
assert.match(createRequestId('bad request id'), /^[0-9a-f-]{36}$/);
assert.deepEqual(
  sanitizeAuditMetadata('create_vulnerability', {
    cve_id: 'CVE-2026-0001',
    inserted: true,
  }),
  { cve_id: 'CVE-2026-0001', inserted: true },
);
assert.throws(
  () => sanitizeAuditMetadata('create_vulnerability', { 'x-api-key': 'secret' }),
  /Unsupported audit metadata key/,
);
assert.equal(categorizeAuditError({ status: 401 }), 'unauthorized');
assert.equal(categorizeAuditError({ status: 403 }), 'forbidden');
assert.equal(categorizeAuditError(new Error('database exploded')), 'internal_error');

console.log('Audit policy normalizes routes, validates request IDs, and rejects secret metadata.');
```

- [ ] **Step 2: Add the new test to `npm test` and verify RED**

Append `node test/audit-policy.test.js` to the test script.

Run:

```powershell
cd DataEngineeringTeam
npm test
```

Expected: build or test failure because `audit-policy` does not exist.

- [ ] **Step 3: Create the audit type contracts**

Create `src/audit.types.ts` defining:

```ts
import { QueryResult } from 'pg';
import { ApiKeyPrincipal } from './api-key.service';

export type AuditResult = 'success' | 'failure';
export type AuditAction =
  | 'health_check'
  | 'root_read'
  | 'list_vulnerabilities'
  | 'get_vulnerability'
  | 'create_vulnerability'
  | 'import_cves'
  | 'read_audit_logs'
  | 'authorization_failed';

export type AuditMetadata = Record<string, string | number | boolean | null>;

export interface AuditEvent {
  requestId: string;
  method: string;
  route: string;
  statusCode: number;
  durationMs: number;
  sourceIp: string | null;
  actorOwner: string | null;
  actorKeyPrefix: string | null;
  action: AuditAction;
  resourceType: string | null;
  resourceId: string | null;
  result: AuditResult;
  errorCategory: string | null;
  metadata: AuditMetadata;
}

export interface AuditRequestContext {
  requestId: string;
  method: string;
  route: string;
  sourceIp: string | null;
  startedAt: number;
  principal?: ApiKeyPrincipal;
  transactionallyAudited?: boolean;
}

export interface AuditQuery {
  limit?: string | number;
  before_id?: string | number;
  action?: string;
  result?: string;
}

export interface Queryable {
  query(sql: string, params?: unknown[]): Promise<QueryResult<any>>;
}
```

- [ ] **Step 4: Implement the allowlist policy**

Create `src/audit-policy.ts` with:

- `createRequestId(value)` accepting only 1-128 characters from `[A-Za-z0-9._:-]`, otherwise returning `randomUUID()`.
- `normalizeAuditRoute(url)` stripping query strings and mapping vulnerability identifiers to `/vulnerabilities/:cveId`.
- `actionForRequest(method, route)` returning one of the stable `AuditAction` values.
- `categorizeAuditError(error)` mapping statuses 400, 401, 403, 404, and 429 to stable categories and all unknown errors to `internal_error`.
- `sanitizeAuditMetadata(action, metadata)` copying only keys from this explicit map:

```ts
const ALLOWED_METADATA_KEYS: Record<AuditAction, readonly string[]> = {
  health_check: [],
  root_read: [],
  list_vulnerabilities: ['limit', 'severity', 'count'],
  get_vulnerability: ['cve_id', 'found'],
  create_vulnerability: ['cve_id', 'inserted', 'duplicate', 'count'],
  import_cves: ['imported', 'skipped', 'total'],
  read_audit_logs: ['limit', 'count'],
  authorization_failed: [],
};
```

Reject any unsupported key with `Error('Unsupported audit metadata key: <key>')`. Limit string values to 256 characters.

- [ ] **Step 5: Run the focused test and verify GREEN**

Run:

```powershell
npm run build
node test/audit-policy.test.js
```

Expected: `Audit policy normalizes routes, validates request IDs, and rejects secret metadata.`

- [ ] **Step 6: Commit**

```powershell
git add DataEngineeringTeam/src/audit.types.ts DataEngineeringTeam/src/audit-policy.ts DataEngineeringTeam/test/audit-policy.test.js DataEngineeringTeam/package.json
git commit -m "feat: define audit event policy"
```

### Task 2: Add PostgreSQL Audit Migration and Retention Command

**Files:**
- Create: `DataEngineeringTeam/scripts/audit-logs.js`
- Create: `DataEngineeringTeam/test/audit-scripts.test.js`
- Modify: `DataEngineeringTeam/package.json`

- [ ] **Step 1: Write the failing script test**

Create a pool double that records SQL and test:

```js
const assert = require('node:assert/strict');
const { migrateAuditLogs, pruneAuditLogs } = require('../scripts/audit-logs');

const calls = [];
const pool = {
  async query(sql, params = []) {
    calls.push({ sql, params });
    return { rowCount: /DELETE FROM audit_logs/.test(sql) ? 7 : 0, rows: [] };
  },
};

(async () => {
  await migrateAuditLogs(pool);
  assert.match(calls[0].sql, /CREATE TABLE IF NOT EXISTS audit_logs/);
  assert.match(calls[0].sql, /metadata JSONB NOT NULL/);
  assert(calls.some(({ sql }) => /audit_logs_occurred_at_idx/.test(sql)));

  const deleted = await pruneAuditLogs(pool);
  assert.equal(deleted, 7);
  assert.match(calls.at(-1).sql, /INTERVAL '90 days'/);
  console.log('Audit migration creates durable storage and pruning removes records older than 90 days.');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
```

- [ ] **Step 2: Verify RED**

Run:

```powershell
node test/audit-scripts.test.js
```

Expected: module-not-found failure for `scripts/audit-logs`.

- [ ] **Step 3: Implement the script**

Create `scripts/audit-logs.js` following the connection pattern in `scripts/api-keys.js`. Export:

```js
async function migrateAuditLogs(pool) { /* execute the approved table and three index statements */ }
async function pruneAuditLogs(pool) {
  const result = await pool.query(`
    DELETE FROM audit_logs
    WHERE occurred_at < NOW() - INTERVAL '90 days'
  `);
  return result.rowCount ?? 0;
}
```

The CLI accepts `migrate` and `prune`. `prune` prints only `Deleted <count> expired audit log rows`.

- [ ] **Step 4: Wire package commands**

Change scripts to:

```json
"db:migrate": "node scripts/api-keys.js migrate && node scripts/audit-logs.js migrate",
"audit:prune": "node scripts/audit-logs.js prune"
```

Add `node test/audit-scripts.test.js` to `npm test`.

- [ ] **Step 5: Verify GREEN**

Run:

```powershell
node test/audit-scripts.test.js
npm run build
```

Expected: test message followed by exit code 0.

- [ ] **Step 6: Commit**

```powershell
git add DataEngineeringTeam/scripts/audit-logs.js DataEngineeringTeam/test/audit-scripts.test.js DataEngineeringTeam/package.json
git commit -m "feat: add audit database migration and retention"
```

### Task 3: Implement the Audit Service and Database Retrieval

**Files:**
- Create: `DataEngineeringTeam/src/audit.service.ts`
- Create: `DataEngineeringTeam/test/audit.service.test.js`
- Modify: `DataEngineeringTeam/src/app.module.ts`
- Modify: `DataEngineeringTeam/package.json`

- [ ] **Step 1: Write failing service tests**

Cover:

- `insert()` issues a parameterized `INSERT INTO audit_logs`.
- metadata passes through `sanitizeAuditMetadata`.
- `list({limit: 25, before_id: 100, action: 'create_vulnerability', result: 'failure'})` uses `id < $n`, newest-first ordering, and returns `{items, next_before_id}`.
- invalid limit, cursor, action, or result throws `BadRequestException`.
- `persistBestEffort()` catches a database error and invokes an injected logger error without throwing.

Use pool doubles; do not connect to a real database.

- [ ] **Step 2: Verify RED**

Run:

```powershell
npm run build
node test/audit.service.test.js
```

Expected: build failure because `AuditService` does not exist.

- [ ] **Step 3: Implement `AuditService`**

Create an injectable service with:

```ts
constructor(@Inject('PG_POOL') private readonly pool: Pool) {}

async insert(event: AuditEvent, client: Queryable = this.pool): Promise<void>
async persistBestEffort(event: AuditEvent): Promise<void>
async list(query: AuditQuery): Promise<{ items: unknown[]; next_before_id: string | null }>
```

`insert()` must use positional parameters for every value and serialize only sanitized metadata. `persistBestEffort()` logs exactly:

```ts
this.logger.error(
  `audit persistence failed request_id=${event.requestId} method=${event.method} route=${event.route} category=database_error`,
);
```

`list()` defaults to 100, caps at 200, requests `limit + 1`, and uses the extra row only to determine `next_before_id`.

- [ ] **Step 4: Register the service**

Add `AuditService` to `AppModule.providers`. Keep `LogsService` temporarily until Task 7.

- [ ] **Step 5: Verify GREEN**

Run:

```powershell
npm run build
node test/audit.service.test.js
```

Expected: all audit service assertions pass.

- [ ] **Step 6: Commit**

```powershell
git add DataEngineeringTeam/src/audit.service.ts DataEngineeringTeam/src/app.module.ts DataEngineeringTeam/test/audit.service.test.js DataEngineeringTeam/package.json
git commit -m "feat: persist and query audit records"
```

### Task 4: Establish Request IDs and Authenticated Actor Context

**Files:**
- Modify: `DataEngineeringTeam/src/main.ts`
- Modify: `DataEngineeringTeam/src/auth.guard.ts`
- Create: `DataEngineeringTeam/test/audit-request-context.test.js`
- Modify: `DataEngineeringTeam/package.json`

- [ ] **Step 1: Write failing request-context tests**

Test the exported request-ID hook factory with:

- valid `x-request-id` preserved;
- invalid header replaced by UUID;
- generated ID stored on `request.auditContext.requestId`;
- `x-request-id` response header set before guards run.

Extend the guard test to assert a valid key sets:

```js
request.apiKey = principal;
request.auditContext.principal = principal;
```

- [ ] **Step 2: Verify RED**

Run the focused tests and expect missing hook/context behavior.

- [ ] **Step 3: Add a Fastify `onRequest` hook in `main.ts`**

Export a small `attachAuditRequestContext(request, reply, done)` function. It must:

- call `createRequestId(request.headers['x-request-id'])`;
- set `request.auditContext` with request ID, method, normalized route, source IP, and `startedAt`;
- set the response `x-request-id` header;
- call `done()`.

Register it before `app.listen()`:

```ts
app.getHttpAdapter().getInstance().addHook('onRequest', attachAuditRequestContext);
```

- [ ] **Step 4: Update `ApiKeyGuard`**

Expand its request type to include `auditContext`. After validation:

```ts
request.apiKey = principal;
if (request.auditContext) {
  request.auditContext.principal = principal;
}
```

Never store the raw header value.

- [ ] **Step 5: Verify GREEN**

Run:

```powershell
npm run build
node test/audit-request-context.test.js
node test/api-key-hardening.test.js
```

Expected: all focused tests pass.

- [ ] **Step 6: Commit**

```powershell
git add DataEngineeringTeam/src/main.ts DataEngineeringTeam/src/auth.guard.ts DataEngineeringTeam/test/audit-request-context.test.js DataEngineeringTeam/test/api-key-hardening.test.js DataEngineeringTeam/package.json
git commit -m "feat: attach audit request and actor context"
```

### Task 5: Persist Successful Reads and Failed Requests

**Files:**
- Modify: `DataEngineeringTeam/src/logging.interceptor.ts`
- Modify: `DataEngineeringTeam/src/all-exceptions.filter.ts`
- Create: `DataEngineeringTeam/test/audit-http-pipeline.test.js`
- Modify: `DataEngineeringTeam/package.json`

- [ ] **Step 1: Write failing interceptor/filter tests**

Test that:

- a successful `GET /health` calls `persistBestEffort()` once with `health_check`, status 200, duration, and no secrets;
- query strings do not appear in the stored route;
- a context marked `transactionallyAudited` is not persisted again;
- a 401 failure is categorized as `unauthorized`;
- exception responses are unchanged even if `persistBestEffort()` fails.

- [ ] **Step 2: Verify RED**

Run the focused test and expect constructor/signature failures.

- [ ] **Step 3: Replace interceptor memory writes**

Inject `AuditService` instead of `LogsService`. Use an RxJS operator that awaits `persistBestEffort()` before returning the successful value:

```ts
mergeMap(async (value) => {
  if (!request.auditContext.transactionallyAudited) {
    await this.auditService.persistBestEffort(buildSuccessEvent(request, response, value));
  }
  return value;
})
```

Build metadata only from endpoint-specific allowlisted values. Do not pass request headers or bodies.

- [ ] **Step 4: Replace exception filter memory writes**

Inject `AuditService`. Build a failure event from `request.auditContext`, status, normalized route, actor principal, and `categorizeAuditError(exception)`. Start `persistBestEffort()` without allowing its failure to replace the original HTTP exception response:

```ts
void this.auditService.persistBestEffort(event);
response.status(statusCode).send(exception.getResponse());
```

Keep the console request summary, but do not print exception messages or event metadata.

- [ ] **Step 5: Verify GREEN**

Run:

```powershell
npm run build
node test/audit-http-pipeline.test.js
```

Expected: success, failure, no-duplicate, and response-preservation assertions pass.

- [ ] **Step 6: Commit**

```powershell
git add DataEngineeringTeam/src/logging.interceptor.ts DataEngineeringTeam/src/all-exceptions.filter.ts DataEngineeringTeam/test/audit-http-pipeline.test.js DataEngineeringTeam/package.json
git commit -m "feat: audit HTTP reads and failures"
```

### Task 6: Make Sensitive Writes Transactional With Their Audit Rows

**Files:**
- Modify: `DataEngineeringTeam/src/app.service.ts`
- Modify: `DataEngineeringTeam/src/app.controller.ts`
- Modify: `DataEngineeringTeam/test/app.service.test.js`
- Create: `DataEngineeringTeam/test/audit-transaction.test.js`
- Modify: `DataEngineeringTeam/package.json`

- [ ] **Step 1: Write failing transaction tests**

Create a pool double exposing `connect()` and a client that records:

```text
BEGIN
INSERT INTO vulnerabilities ...
INSERT INTO audit_logs ...
COMMIT
release
```

Test:

- successful single create commits and sets `context.transactionallyAudited = true`;
- duplicate CVE still commits an audit event with `inserted=false` and `duplicate=true`;
- audit insert failure executes `ROLLBACK`, never `COMMIT`, and rejects with a sanitized 500;
- bulk create uses one transaction and one request-level audit row;
- import fetch happens before `BEGIN`, then business insert and audit insert share the client;
- import audit failure rolls back inserted CVEs.

- [ ] **Step 2: Verify RED**

Run the focused transaction test and expect missing audit dependency/signatures.

- [ ] **Step 3: Inject `AuditService` into `AppService`**

Change the constructor to:

```ts
constructor(
  @Inject('PG_POOL') private readonly pool: Pool,
  private readonly auditService: AuditService,
) {}
```

Add a private transaction helper:

```ts
private async withAuditedWrite<T>(
  context: AuditRequestContext,
  operation: (client: PoolClient) => Promise<{ value: T; event: AuditEvent }>,
): Promise<T>
```

The helper performs `BEGIN`, calls the operation, inserts the audit event through the same client, commits, marks the context as transactionally audited, and returns the value. Any failure rolls back and throws `InternalServerErrorException('Write failed and was rolled back')`. Always release the client.

- [ ] **Step 4: Convert write methods**

Use signatures:

```ts
createVulnerability(input: unknown, context: AuditRequestContext)
createVulnerabilities(inputs: unknown[], context: AuditRequestContext)
importCVEs(context: AuditRequestContext)
```

Normalize all bulk inputs before beginning the transaction. Produce one event per HTTP request, not one per CVE. Use only these metadata fields:

- create: `cve_id`, `inserted`, `duplicate`, or `count`;
- import: `imported`, `skipped`, `total`.

- [ ] **Step 5: Pass request context from the controller**

Add `@Req() request` to write handlers and call:

```ts
this.appService.createVulnerability(body, request.auditContext)
this.appService.createVulnerabilities(body, request.auditContext)
this.appService.importCVEs(request.auditContext)
```

If `auditContext` is unexpectedly absent, throw `InternalServerErrorException('Audit context unavailable')` before changing data.

- [ ] **Step 6: Adapt existing service tests**

Update pool doubles to provide `connect()` and pass a minimal audit context into write methods. Keep all existing result assertions.

- [ ] **Step 7: Verify GREEN**

Run:

```powershell
npm run build
node test/app.service.test.js
node test/audit-transaction.test.js
```

Expected: existing behavior passes, transaction ordering is exact, and audit failure rolls back.

- [ ] **Step 8: Commit**

```powershell
git add DataEngineeringTeam/src/app.service.ts DataEngineeringTeam/src/app.controller.ts DataEngineeringTeam/test/app.service.test.js DataEngineeringTeam/test/audit-transaction.test.js DataEngineeringTeam/package.json
git commit -m "feat: require durable audits for sensitive writes"
```

### Task 7: Replace `/logs` Memory Retrieval With PostgreSQL

**Files:**
- Modify: `DataEngineeringTeam/src/app.controller.ts`
- Modify: `DataEngineeringTeam/src/app.module.ts`
- Delete: `DataEngineeringTeam/src/logs.service.ts`
- Create: `DataEngineeringTeam/test/audit-controller.test.js`
- Modify: `DataEngineeringTeam/test/auth-global-config.test.js`
- Modify: `DataEngineeringTeam/package.json`

- [ ] **Step 1: Write failing controller tests**

Test that `GET /logs`:

- still has `admin:logs`;
- forwards `limit`, `before_id`, `action`, and `result` to `AuditService.list`;
- returns `{items, next_before_id}`;
- does not expose or depend on `LogsService`.

- [ ] **Step 2: Verify RED**

Run the focused test and expect the controller still to use `LogsService`.

- [ ] **Step 3: Replace the controller dependency**

Inject `AuditService`, remove `LogsService`, and implement:

```ts
@Get('logs')
@RequireScopes('admin:logs')
async getLogs(@Query() query: AuditQuery) {
  return this.auditService.list(query);
}
```

The interceptor will add the `read_audit_logs` event only after the query result is assembled, so the current audit read does not appear in its own response.

- [ ] **Step 4: Remove memory logging**

Delete `src/logs.service.ts`. Remove its provider and imports from `AppModule`. Verify `rg -n "LogsService|logs.service" DataEngineeringTeam/src DataEngineeringTeam/test` returns no results.

- [ ] **Step 5: Verify GREEN**

Run:

```powershell
npm run build
node test/audit-controller.test.js
node test/auth-global-config.test.js
```

Expected: database-backed controller tests pass and no memory store remains.

- [ ] **Step 6: Commit**

```powershell
git add DataEngineeringTeam/src/app.controller.ts DataEngineeringTeam/src/app.module.ts DataEngineeringTeam/src/logs.service.ts DataEngineeringTeam/test/audit-controller.test.js DataEngineeringTeam/test/auth-global-config.test.js DataEngineeringTeam/package.json
git commit -m "feat: serve durable audit logs from PostgreSQL"
```

### Task 8: Add Daily 90-Day Retention Units

**Files:**
- Create: `DataEngineeringTeam/systemd/sentinel-audit-prune.service`
- Create: `DataEngineeringTeam/systemd/sentinel-audit-prune.timer`
- Create: `DataEngineeringTeam/test/audit-systemd.test.js`
- Modify: `DataEngineeringTeam/package.json`

- [ ] **Step 1: Write a failing static unit test**

Assert the service includes:

```ini
Type=oneshot
EnvironmentFile=/etc/sentinel/audit-maintenance.env
WorkingDirectory=/root/Sentinel-AI/DataEngineeringTeam
ExecStart=/usr/bin/npm run audit:prune
```

Assert the timer includes:

```ini
OnCalendar=daily
Persistent=true
Unit=sentinel-audit-prune.service
```

- [ ] **Step 2: Verify RED**

Run the test and expect missing files.

- [ ] **Step 3: Create the systemd units**

Use the exact directives above, add `NoNewPrivileges=true` and
`PrivateTmp=true`, and omit `User=` so the unit matches the repository's
current root-managed Droplet services. Use
`WorkingDirectory=/root/Sentinel-AI/DataEngineeringTeam`.

- [ ] **Step 4: Verify GREEN**

Run:

```powershell
node test/audit-systemd.test.js
```

Expected: service and timer assertions pass.

- [ ] **Step 5: Commit**

```powershell
git add DataEngineeringTeam/systemd DataEngineeringTeam/test/audit-systemd.test.js DataEngineeringTeam/package.json
git commit -m "ops: schedule audit retention cleanup"
```

### Task 9: Update Operator Documentation

**Files:**
- Modify: `DataEngineeringTeam/README.md`
- Modify: `DataEngineeringTeam/API_USAGE.md`

- [ ] **Step 1: Update setup and migration docs**

Document:

```bash
npm run db:migrate
npm run audit:prune
```

State that audit records live in PostgreSQL, survive API restarts, and are retained for 90 days.

Document the production privilege split, replacing the example role names with
the actual Droplet roles during deployment:

```sql
GRANT INSERT, SELECT ON audit_logs TO sentinel_data_api;
GRANT USAGE, SELECT ON SEQUENCE audit_logs_id_seq TO sentinel_data_api;
REVOKE UPDATE, DELETE ON audit_logs FROM sentinel_data_api;
GRANT DELETE ON audit_logs TO sentinel_audit_maintenance;
```

The retention unit must load `/etc/sentinel/audit-maintenance.env`, containing
maintenance-role database credentials, instead of the runtime API environment
file. The runtime API role must not receive `DELETE`.

- [ ] **Step 2: Update `/logs` usage**

Document:

```bash
curl "http://127.0.0.1:3000/logs?limit=100&action=create_vulnerability&result=failure" \
  -H "x-api-key: sk_sentinel_<prefix>_<secret>"
```

Describe `before_id`, `action`, `result`, newest-first ordering, and the response envelope.

- [ ] **Step 3: Document timer installation**

Add:

```bash
sudo cp systemd/sentinel-audit-prune.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-audit-prune.timer
sudo systemctl list-timers sentinel-audit-prune.timer
```

Also document:

```bash
sudo journalctl -u sentinel-data-api.service -f
sudo journalctl -u sentinel-audit-prune.service
```

Explain that `audit persistence failed` alerts require investigation.

- [ ] **Step 4: Verify documentation consistency**

Run:

```powershell
rg -n "in-memory|last 1000|audit:prune|before_id|90 days" DataEngineeringTeam/README.md DataEngineeringTeam/API_USAGE.md
```

Expected: no stale claim that `/logs` is in-memory; new commands and retention are present.

- [ ] **Step 5: Commit**

```powershell
git add DataEngineeringTeam/README.md DataEngineeringTeam/API_USAGE.md
git commit -m "docs: document durable audit operations"
```

### Task 10: Full Verification and Deployment Smoke Test

**Files:**
- No new files expected.

- [ ] **Step 1: Run static checks and full tests**

Run:

```powershell
cd DataEngineeringTeam
npm test
```

Expected: TypeScript build succeeds and every old and new test exits 0.

- [ ] **Step 2: Check repository hygiene**

Run:

```powershell
cd ..
git diff --check
git status --short
rg -n "LogsService|private readonly entries|x-api-key.*metadata|Authorization.*metadata" DataEngineeringTeam/src DataEngineeringTeam/test
```

Expected: no whitespace errors, no memory log store, and no code path copying secret headers into metadata.

- [ ] **Step 3: Run the migration on the target server**

On the DigitalOcean Droplet, after backing up PostgreSQL:

```bash
cd /root/Sentinel-AI/DataEngineeringTeam
npm ci
npm run build
npm run db:migrate
sudo systemctl restart sentinel-data-api.service
```

Expected: migration reports both `api_keys` and `audit_logs` ready; service becomes active.

- [ ] **Step 4: Verify a durable read event**

```bash
export ADMIN_LOGS_KEY='load-from-team-password-manager'
curl -i http://127.0.0.1:3000/health
sudo systemctl restart sentinel-data-api.service
curl "http://127.0.0.1:3000/logs?limit=20&action=health_check" \
  -H "x-api-key: ${ADMIN_LOGS_KEY}"
```

Expected: the pre-restart health event remains in the response.

- [ ] **Step 5: Verify an audited sensitive write**

Use a non-production test CVE ID and a key with `write:vulnerabilities`:

```bash
export WRITE_KEY='load-from-team-password-manager'
curl -X POST http://127.0.0.1:3000/vulnerabilities \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${WRITE_KEY}" \
  -d '{"cve_id":"CVE-2099-TEST","description":"Audit deployment test","severity":"LOW","published_date":"2099-01-01T00:00:00Z"}'
```

Then query `/logs?action=create_vulnerability` with the admin key. Expected: one row with owner/prefix and CVE ID, but no raw key or request body.

- [ ] **Step 6: Verify retention scheduling**

```bash
sudo systemctl enable --now sentinel-audit-prune.timer
sudo systemctl start sentinel-audit-prune.service
sudo systemctl status sentinel-audit-prune.service --no-pager
sudo systemctl list-timers sentinel-audit-prune.timer
```

Expected: prune service exits successfully and the timer shows its next daily run.

- [ ] **Step 7: Record verification evidence**

Capture:

- `npm test` summary;
- migration output;
- one persisted read record after restart;
- one sanitized write record;
- timer status.

Do not capture raw API keys in screenshots, terminal transcripts, or issue comments.
