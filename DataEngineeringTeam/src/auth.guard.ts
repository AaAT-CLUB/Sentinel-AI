import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<{ headers: Record<string, string> }>();
    const provided = request.headers['x-api-key'];
    const expected = process.env.API_KEY;

    if (!expected) {
      throw new UnauthorizedException('API_KEY is not configured on this server');
    }
    if (!provided || provided !== expected) {
      throw new UnauthorizedException('Invalid or missing x-api-key header');
    }
    return true;
  }
}
