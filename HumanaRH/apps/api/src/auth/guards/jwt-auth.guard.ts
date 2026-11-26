import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { PrismaService } from '../../prisma/prisma.service';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

export interface AuthenticatedUser {
  id: string;
  tenantId: string;
  email: string;
  name: string;
  sessionId: string;
}

type AuthenticatedRequest = Request & {
  user?: AuthenticatedUser;
};

interface AccessTokenPayload {
  sub: string;
  tid: string;
  sid: string;
}

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly jwt: JwtService,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(
      IS_PUBLIC_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (isPublic) return true;

    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const authorization = request.headers.authorization;

    if (!authorization?.startsWith('Bearer ')) {
      throw new UnauthorizedException('Autenticação necessária.');
    }

    try {
      const token = authorization.slice(7);

      const payload = await this.jwt.verifyAsync<AccessTokenPayload>(token);

      if (
        typeof payload.sub !== 'string' ||
        typeof payload.tid !== 'string' ||
        typeof payload.sid !== 'string'
      ) {
        throw new UnauthorizedException();
      }

      const user = await this.prisma.user.findFirst({
        where: {
          id: payload.sub,
          tenantId: payload.tid,
          status: 'ACTIVE',
          tenant: {
            status: 'ACTIVE',
          },
        },
        select: {
          id: true,
          tenantId: true,
          email: true,
          name: true,
        },
      });

      if (!user) {
        throw new UnauthorizedException();
      }

      const session = await this.prisma.refreshSession.findFirst({
        where: {
          id: payload.sid,
          userId: user.id,
          tenantId: user.tenantId,
          revokedAt: null,
          expiresAt: {
            gt: new Date(),
          },
        },
        select: {
          id: true,
        },
      });

      if (!session) {
        throw new UnauthorizedException();
      }

      request.user = {
        ...user,
        sessionId: session.id,
      };

      return true;
    } catch {
      throw new UnauthorizedException(
        'Sessão inválida, revogada ou expirada.',
      );
    }
  }
}