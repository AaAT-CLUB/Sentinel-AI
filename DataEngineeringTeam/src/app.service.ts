import {
  BadRequestException,
  Inject,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { Pool } from 'pg';

type VulnerabilityQuery = {
  cve_id?: string;
  cveId?: string;
  keyword?: string;
  description?: string;
  severity?: string;
  published_from?: string;
  published_to?: string;
  limit?: string | number;
};

type CreateVulnerabilityInput = {
  cve_id?: unknown;
  description?: unknown;
  severity?: unknown;
  published_date?: unknown;
};

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

  async getVulnerabilities(query: VulnerabilityQuery = {}) {
    const params: unknown[] = [];
    const filters: string[] = [];

    const cveId = this.cleanOptionalString(query.cve_id ?? query.cveId);
    if (cveId) {
      params.push(cveId);
      filters.push(`cve_id = $${params.length}`);
    }

    const keyword = this.cleanOptionalString(query.keyword ?? query.description);
    if (keyword) {
      params.push(`%${keyword}%`);
      filters.push(`description ILIKE $${params.length}`);
    }

    const severity = this.cleanOptionalString(query.severity);
    if (severity) {
      params.push(severity.toUpperCase());
      filters.push(`UPPER(severity) = $${params.length}`);
    }

    const publishedFrom = this.cleanOptionalString(query.published_from);
    if (publishedFrom) {
      this.assertValidDate(publishedFrom, 'published_from');
      params.push(publishedFrom);
      filters.push(`published_date >= $${params.length}`);
    }

    const publishedTo = this.cleanOptionalString(query.published_to);
    if (publishedTo) {
      this.assertValidDate(publishedTo, 'published_to');
      params.push(publishedTo);
      filters.push(`published_date <= $${params.length}`);
    }

    const limit = this.parseLimit(query.limit);
    params.push(limit);

    const whereClause = filters.length > 0 ? `WHERE ${filters.join(' AND ')}` : '';

    try {
      const result = await this.pool.query(
        `SELECT id, cve_id, description, severity, published_date
         FROM vulnerabilities
         ${whereClause}
         ORDER BY published_date DESC
         LIMIT $${params.length}`,
        params,
      );
      return result.rows;
    } catch {
      throw new InternalServerErrorException('Failed to query vulnerabilities');
    }
  }

  async getVulnerabilityByCveId(cveId: string) {
    const normalizedCveId = this.cleanRequiredString(cveId, 'cve_id');

    try {
      const result = await this.pool.query(
        `SELECT id, cve_id, description, severity, published_date
         FROM vulnerabilities
         WHERE cve_id = $1
         LIMIT 1`,
        [normalizedCveId],
      );

      const vulnerability = result.rows[0];
      if (!vulnerability) {
        throw new NotFoundException(`Vulnerability ${normalizedCveId} was not found`);
      }
      return vulnerability;
    } catch (error) {
      if (error instanceof NotFoundException || error instanceof BadRequestException) {
        throw error;
      }
      throw new InternalServerErrorException('Failed to query vulnerability');
    }
  }

  async createVulnerabilities(inputs: unknown[]) {
    const results = [];
    for (const input of inputs) {
      results.push(await this.createVulnerability(input));
    }
    return { total: inputs.length, results };
  }

  async createVulnerability(input: unknown) {
    const vulnerability = this.normalizeCreateInput(input);

    try {
      const result = await this.pool.query(
        `INSERT INTO vulnerabilities (cve_id, description, severity, published_date)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (cve_id) DO NOTHING
         RETURNING id, cve_id, description, severity, published_date`,
        [
          vulnerability.cve_id,
          vulnerability.description,
          vulnerability.severity,
          vulnerability.published_date,
        ],
      );

      if (result.rowCount === 0) {
        return { inserted: false, duplicate: true, cve_id: vulnerability.cve_id };
      }

      return { inserted: true, vulnerability: result.rows[0] };
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      throw new InternalServerErrorException('Failed to insert vulnerability into database');
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

  private parseLimit(value: string | number | undefined): number {
    if (value === undefined || value === '') {
      return 100;
    }

    const limit = Number(value);
    if (!Number.isInteger(limit) || limit < 1 || limit > 1000) {
      throw new BadRequestException('limit must be an integer between 1 and 1000');
    }
    return limit;
  }

  private normalizeCreateInput(input: unknown) {
    if (!this.isRecord(input)) {
      throw new BadRequestException('Request body must be a vulnerability object');
    }

    const body = input as CreateVulnerabilityInput;
    const cveId = this.cleanRequiredString(body.cve_id, 'cve_id');
    const publishedDate = this.cleanRequiredString(body.published_date, 'published_date');
    this.assertValidDate(publishedDate, 'published_date');

    return {
      cve_id: cveId,
      description: this.cleanOptionalString(body.description) ?? null,
      severity: (this.cleanOptionalString(body.severity) ?? 'UNKNOWN').toUpperCase(),
      published_date: publishedDate,
    };
  }

  private cleanRequiredString(value: unknown, fieldName: string): string {
    const text = this.cleanOptionalString(value);
    if (!text) {
      throw new BadRequestException(`${fieldName} is required`);
    }
    return text;
  }

  private cleanOptionalString(value: unknown): string | undefined {
    if (typeof value !== 'string' && typeof value !== 'number') {
      return undefined;
    }

    const text = String(value).trim();
    return text.length > 0 ? text : undefined;
  }

  private assertValidDate(value: string, fieldName: string) {
    if (Number.isNaN(Date.parse(value))) {
      throw new BadRequestException(`${fieldName} must be a valid date`);
    }
  }

  private isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }
}
