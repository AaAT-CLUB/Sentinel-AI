import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from './public.decorator';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }

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
