const assert = require('node:assert/strict');
const { AppService } = require('../dist/app.service');

const tests = [];

function test(name, fn) {
  tests.push({ name, fn });
}

function createService(queryHandler) {
  const queries = [];
  const pool = {
    async query(sql, params) {
      queries.push({ sql, params });
      return queryHandler?.(sql, params) ?? { rows: [], rowCount: 0 };
    },
  };

  return { service: new AppService(pool), queries };
}

test('getVulnerabilities defaults to limit 100', async () => {
  const { service, queries } = createService();

  await service.getVulnerabilities({});

  assert.equal(queries[0].params[queries[0].params.length - 1], 100);
  assert.match(queries[0].sql, /LIMIT \$\d+/);
});

test('getVulnerabilities accepts a custom integer limit', async () => {
  const { service, queries } = createService();

  await service.getVulnerabilities({ limit: '250' });

  assert.equal(queries[0].params[queries[0].params.length - 1], 250);
});

test('getVulnerabilities filters by cve id, description keyword, and severity', async () => {
  const { service, queries } = createService();

  await service.getVulnerabilities({
    cve_id: 'CVE-2026-0001',
    keyword: 'buffer overflow',
    severity: 'HIGH',
    limit: '25',
  });

  assert.match(queries[0].sql, /cve_id = \$1/);
  assert.match(queries[0].sql, /description ILIKE \$2/);
  assert.match(queries[0].sql, /UPPER\(severity\) = \$3/);
  assert.deepEqual(queries[0].params, ['CVE-2026-0001', '%buffer overflow%', 'HIGH', 25]);
});

test('getVulnerabilityByCveId returns one vulnerability by exact cve id', async () => {
  const expected = { cve_id: 'CVE-2026-0001' };
  const { service, queries } = createService(() => ({ rows: [expected], rowCount: 1 }));

  const result = await service.getVulnerabilityByCveId('CVE-2026-0001');

  assert.equal(result, expected);
  assert.match(queries[0].sql, /WHERE cve_id = \$1/);
  assert.deepEqual(queries[0].params, ['CVE-2026-0001']);
});

test('createVulnerability inserts a new cve and reports inserted true', async () => {
  const inserted = {
    id: 1,
    cve_id: 'CVE-2026-0001',
    description: 'Example',
    severity: 'HIGH',
    published_date: '2026-06-05T00:00:00.000Z',
  };
  const { service, queries } = createService(() => ({ rows: [inserted], rowCount: 1 }));

  const result = await service.createVulnerability({
    cve_id: 'CVE-2026-0001',
    description: 'Example',
    severity: 'high',
    published_date: '2026-06-05T00:00:00.000Z',
  });

  assert.deepEqual(result, { inserted: true, vulnerability: inserted });
  assert.match(queries[0].sql, /ON CONFLICT \(cve_id\) DO NOTHING/);
  assert.deepEqual(queries[0].params, [
    'CVE-2026-0001',
    'Example',
    'HIGH',
    '2026-06-05T00:00:00.000Z',
  ]);
});

test('createVulnerability deduplicates existing cve ids', async () => {
  const { service } = createService(() => ({ rows: [], rowCount: 0 }));

  const result = await service.createVulnerability({
    cve_id: 'CVE-2026-0001',
    description: 'Example',
    severity: 'HIGH',
    published_date: '2026-06-05T00:00:00.000Z',
  });

  assert.deepEqual(result, {
    inserted: false,
    duplicate: true,
    cve_id: 'CVE-2026-0001',
  });
});

async function run() {
  for (const { name, fn } of tests) {
    await fn();
    console.log(`ok - ${name}`);
  }
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
