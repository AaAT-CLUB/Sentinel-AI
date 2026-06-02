import { Inject, Injectable, InternalServerErrorException, ServiceUnavailableException } from '@nestjs/common';
import { Pool } from 'pg';

@Injectable()
export class AppService {
  constructor(@Inject('PG_POOL') private readonly pool: Pool) {}

  async getHealth() {
    try {
      await this.pool.query('SELECT 1');
      return { status: 'ok' };
    } catch {
      throw new ServiceUnavailableException('Database unreachable');
    }
  }

  async getVulnerabilities() {
    try {
      const result = await this.pool.query(
        `SELECT id, cve_id, description, severity, published_date
         FROM vulnerabilities
         ORDER BY published_date DESC
         LIMIT 100`,
      );
      return result.rows;
    } catch {
      throw new InternalServerErrorException('Failed to query vulnerabilities');
    }
  }

  async importCVEs() {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (process.env.NVD_API_KEY) {
      headers['apiKey'] = process.env.NVD_API_KEY;
    }

    let response: Response;
    try {
      response = await fetch(
        'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50',
        { headers },
      );
    } catch {
      throw new InternalServerErrorException('Failed to reach NVD API');
    }

    if (!response.ok) {
      throw new InternalServerErrorException(`NVD API returned ${response.status}`);
    }

    const data = await response.json();
    const vulnerabilities: any[] = data.vulnerabilities || [];

    if (vulnerabilities.length === 0) {
      return { imported: 0, skipped: 0, total: 0 };
    }

    // Build a single bulk INSERT instead of 50 serial round-trips
    const params: unknown[] = [];
    const placeholders = vulnerabilities.map((item, i) => {
      const cve = item.cve;
      const base = i * 4;
      params.push(cve.id, this.getEnglishDescription(cve), this.getSeverity(cve), cve.published);
      return `($${base + 1}, $${base + 2}, $${base + 3}, $${base + 4})`;
    });

    try {
      const result = await this.pool.query(
        `INSERT INTO vulnerabilities (cve_id, description, severity, published_date)
         VALUES ${placeholders.join(', ')}
         ON CONFLICT (cve_id) DO NOTHING
         RETURNING id`,
        params,
      );

      const imported = result.rowCount ?? 0;
      return { imported, skipped: vulnerabilities.length - imported, total: vulnerabilities.length };
    } catch {
      throw new InternalServerErrorException('Failed to insert vulnerabilities into database');
    }
  }

  private getSeverity(cve: any): string {
    const metrics = cve.metrics;

    if (metrics?.cvssMetricV40?.[0]?.cvssData?.baseSeverity) {
      return metrics.cvssMetricV40[0].cvssData.baseSeverity;
    }
    if (metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity) {
      return metrics.cvssMetricV31[0].cvssData.baseSeverity;
    }
    if (metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity) {
      return metrics.cvssMetricV30[0].cvssData.baseSeverity;
    }
    if (metrics?.cvssMetricV2?.[0]?.baseSeverity) {
      return metrics.cvssMetricV2[0].baseSeverity;
    }

    return 'UNKNOWN';
  }

  private getEnglishDescription(cve: any): string {
    const descriptions: any[] = cve.descriptions || [];
    return descriptions.find((d) => d.lang === 'en')?.value ?? 'No description available.';
  }
}
