import { ExceptionFilter, Catch, ArgumentsHost, HttpException, Logger } from '@nestjs/common';
import { LogsService } from './logs.service';

@Catch(HttpException)
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger('API');

  constructor(private readonly logsService: LogsService) {}

  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const request = ctx.getRequest();
    const response = ctx.getResponse();
    const statusCode = exception.getStatus();

    const entry = {
      timestamp: new Date().toISOString(),
      method: request.method,
      url: request.url,
      statusCode,
      durationMs: 0,
      ip: request.ip ?? request.headers['x-forwarded-for'] ?? 'unknown',
      apiKeyPrefix: request.apiKey?.prefix ?? 'NONE',
      user_agent: request.headers['user-agent'] ?? null,
    };

    this.logger.log(`${entry.method} ${entry.url} ${statusCode}`);
    this.logsService.push(entry);

    response.status(statusCode).send(exception.getResponse());
  }
}
