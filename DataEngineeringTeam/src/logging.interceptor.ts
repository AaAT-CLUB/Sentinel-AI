import { Injectable, NestInterceptor, ExecutionContext, CallHandler, Logger } from '@nestjs/common';
import { Observable, tap } from 'rxjs';
import { LogsService } from './logs.service';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger('API');

  constructor(private readonly logsService: LogsService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const start = Date.now();

    return next.handle().pipe(
      tap(() => {
        const response = context.switchToHttp().getResponse();
        const durationMs = Date.now() - start;
        const entry = {
          timestamp: new Date().toISOString(),
          method: request.method,
          url: request.url,
          statusCode: response.statusCode,
          durationMs,
          ip: request.ip ?? request.headers['x-forwarded-for'] ?? 'unknown',
          apiKeyPrefix: request.apiKey?.prefix ?? 'NONE',
          user_agent: request.headers['user-agent'] ?? null,
        };
        this.logger.log(`${entry.method} ${entry.url} ${entry.statusCode} ${durationMs}ms`);
        this.logsService.push(entry);
      }),
    );
  }
}
