import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { Request } from 'express';

const COOKIE_AUTH_PATHS = new Set([
  '/api/auth/refresh',
  '/api/auth/logout',
]);

@Injectable()
export class TrustedOriginGuard implements CanActivate {
  private configuredOrigin(): string {
    const configuredUrl = process.env.WEB_URL ?? 'http://localhost:3000';

    try {
      const parsed = new URL(configuredUrl);

      if (
        !['http:', 'https:'].includes(parsed.protocol) ||
        parsed.username ||
        parsed.password
      ) {
        throw new Error('Invalid WEB_URL');
      }

      return parsed.origin;
    } catch {
      throw new InternalServerErrorException(
        'A configuração de origem confiável é inválida.',
      );
    }
  }

  private headerValue(value: string | string[] | undefined): string | undefined {
    if (Array.isArray(value)) {
      return value[0]?.trim() || undefined;
    }

    return value?.trim() || undefined;
  }

  private matchesConfiguredOrigin(value: string, isOrigin: boolean): boolean {
    if (isOrigin && value === 'null') {
      return false;
    }

    try {
      const parsed = new URL(value);

      if (
        !['http:', 'https:'].includes(parsed.protocol) ||
        parsed.username ||
        parsed.password
      ) {
        return false;
      }

      return parsed.origin === this.configuredOrigin();
    } catch {
      return false;
    }
  }

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();
    const method = request.method.toUpperCase();

    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      return true;
    }

    const origin = this.headerValue(request.headers.origin);
    const referer = this.headerValue(request.headers.referer);

    if (origin !== undefined) {
      if (!this.matchesConfiguredOrigin(origin, true)) {
        throw new ForbiddenException('Origem da requisição não autorizada.');
      }

      return true;
    }

    if (referer !== undefined) {
      if (!this.matchesConfiguredOrigin(referer, false)) {
        throw new ForbiddenException('Origem da requisição não autorizada.');
      }

      return true;
    }

    const requestPath = request.path.split('?')[0];

    if (COOKIE_AUTH_PATHS.has(requestPath)) {
      throw new ForbiddenException(
        'A origem é obrigatória para esta operação de sessão.',
      );
    }

    return true;
  }
}