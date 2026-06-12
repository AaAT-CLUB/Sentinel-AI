import { Body, Controller, Get, Param, Post, Query } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { AppService } from './app.service';
import { LogsService } from './logs.service';
import { Public } from './public.decorator';
import { RequireScopes } from './scopes.decorator';

@Controller()
export class AppController {
  constructor(
    private readonly appService: AppService,
    private readonly logsService: LogsService,
  ) {}

  @Get()
  @Throttle({ 'db-default': { ttl: 60_000, limit: 10 } })
  @RequireScopes('read:vulnerabilities')
  getRoot() {
    return { message: 'Sentinel AI Data Engineering API' };
  }

  // 30 health checks per IP per minute
  @Public()
  @Get('health')
  @Throttle({ 'db-default': { ttl: 60_000, limit: 10 } })
  getHealth() {
    return this.appService.getHealth();
  }

  // 20 reads per IP per minute to prevent DB read overload
  @Get('vulnerabilities')
  @Throttle({ 'db-default': { ttl: 60_000, limit: 30 } })
  @RequireScopes('read:vulnerabilities')
  async getVulnerabilities(@Query() query: Record<string, string>) {
    return this.appService.getVulnerabilities(query);
  }

  @Get('vulnerabilities/:cveId')
  @Throttle({ 'db-default': { ttl: 60_000, limit: 30 } })
  @RequireScopes('read:vulnerabilities')
  async getVulnerabilityByCveId(@Param('cveId') cveId: string) {
    return this.appService.getVulnerabilityByCveId(cveId);
  }

  @Post('vulnerabilities')
  @Throttle({ 'db-default': { ttl: 60_000, limit: 30 } })
  @RequireScopes('write:vulnerabilities')
  async createVulnerability(@Body() body: unknown) {
    if (Array.isArray(body)) {
      return this.appService.createVulnerabilities(body);
    }
    return this.appService.createVulnerability(body);
  }

  // 5 imports per IP per minute - expensive: hits NVD API + bulk DB write
  @Post('import-cves')
  @Throttle({ 'db-default': { ttl: 60_000, limit: 5 } })
  @RequireScopes('import:cves')
  async importCves() {
    return this.appService.importCVEs();
  }

  // Admin-only: returns persisted request log entries
  @Get('logs')
  @RequireScopes('admin:logs')
  getLogs(@Query() query: Record<string, string>) {
    return this.logsService.getAll(query);
  }
}
