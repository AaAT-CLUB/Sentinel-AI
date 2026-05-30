import { Inject, Injectable } from '@nestjs/common';
import { Pool } from 'pg';

@Injectable()
export class AppService {
  constructor(@Inject('PG_POOL') private readonly pool: Pool) {}

  // Simple health check response used by the /health endpoint.
  getHealth() {
    return { status: 'ok' };
  }

  // Reads vulnerability records from the database and returns the most recent 100.
  async getVulnerabilities() {
    const result = await this.pool.query(
      `SELECT id, cve_id, description, severity, published_date FROM vulnerabilities ORDER BY published_date DESC LIMIT 100`,
    );

    return result.rows;
  }

  // Fetches CVE data from the NVD API and inserts each vulnerability into PostgreSQL.
  async importCVEs() {
    const url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50';
    const response = await fetch(url);

    if (!response.ok) {
      throw new Error(`NVD API request failed: ${response.status}`);
    }

    const data = await response.json();
    const vulnerabilities = data.vulnerabilities || [];
    let imported = 0;
    let skipped = 0;

    for (const item of vulnerabilities) {
      const cve = item.cve;
      const cveId = cve.id;
      const description = this.getEnglishDescription(cve);
      const severity = this.getSeverity(cve);
      const publishedDate = cve.published;

      const result = await this.pool.query(
        `INSERT INTO vulnerabilities (cve_id, description, severity, published_date)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (cve_id) DO NOTHING RETURNING id`,
        [cveId, description, severity, publishedDate],
      );

      if (result.rowCount === 1) {
        imported += 1;
      } else {
        skipped += 1;
      }
    }

    return {
      imported,
      skipped,
      total: vulnerabilities.length,
    };
  }

  private getSeverity(cve: any): string {
    const metrics = cve.metrics;

    // The NVD API may return different CVSS metric versions.
    // Check each supported version in order of preference.
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
    const descriptions = cve.descriptions || [];
    const englishDescription = descriptions.find((desc: any) => desc.lang === 'en');
    return englishDescription?.value || 'No description available.';
  }
}
