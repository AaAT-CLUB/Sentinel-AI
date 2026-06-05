import { Body, Controller, Get, Param, Post, Query, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { ApiKeyGuard } from './auth.guard';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getRoot() {
    return { message: 'Sentinel AI Data Engineering API' };
  }

  @Get('health')
  getHealth() {
    return this.appService.getHealth();
  }

  @Get('vulnerabilities')
  @UseGuards(ApiKeyGuard)
  async getVulnerabilities(@Query() query: Record<string, string>) {
    return this.appService.getVulnerabilities(query);
  }

  @Get('vulnerabilities/:cveId')
  @UseGuards(ApiKeyGuard)
  async getVulnerabilityByCveId(@Param('cveId') cveId: string) {
    return this.appService.getVulnerabilityByCveId(cveId);
  }

  @Post('vulnerabilities')
  @UseGuards(ApiKeyGuard)
  async createVulnerability(@Body() body: unknown) {
    if (Array.isArray(body)) {
      return this.appService.createVulnerabilities(body);
    }
    return this.appService.createVulnerability(body);
  }

  @Post('import-cves')
  @UseGuards(ApiKeyGuard)
  async importCves() {
    return this.appService.importCVEs();
  }
}
