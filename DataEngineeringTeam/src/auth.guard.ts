import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ApiKeyPrincipal, ApiKeyService } from './api-key.service';
import { IS_PUBLIC_KEY } from './public.decorator';
import { REQUIRED_SCOPES_KEY } from './scopes.decorator';

type ApiKeyRequest = {
  headers: Record<string, string | string[] | undefined>;
  apiKey?: ApiKeyPrincipal;
};

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly apiKeyService: ApiKeyService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest<ApiKeyRequest>();
    const provided = this.readApiKeyHeader(request.headers['x-api-key']);
    if (!provided) {
      throw new UnauthorizedException('Invalid or missing x-api-key header');
    }

    let principal: ApiKeyPrincipal | null;
    try {
      principal = await this.apiKeyService.validate(provided);
    } catch (error) {
      if (error instanceof Error && error.message.includes('API_KEY_PEPPER')) {
        throw new UnauthorizedException(error.message);
      }
      throw error;
    }

    if (!principal) {
      throw new UnauthorizedException('Invalid or missing x-api-key header');
    }

    request.apiKey = principal;

    const requiredScopes =
      this.reflector.getAllAndOverride<string[]>(REQUIRED_SCOPES_KEY, [
        context.getHandler(),
        context.getClass(),
      ]) ?? [];
    const missingScopes = requiredScopes.filter((scope) => !principal.scopes.includes(scope));
    if (missingScopes.length > 0) {
      throw new ForbiddenException('API key does not have the required scope');
    }

    return true;
  }

  private readApiKeyHeader(value: string | string[] | undefined): string | undefined {
    if (Array.isArray(value)) {
      return value[0];
    }
    return value;
  }
}
