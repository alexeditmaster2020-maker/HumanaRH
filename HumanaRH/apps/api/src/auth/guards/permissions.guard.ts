import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { PrismaService } from '../../prisma/prisma.service';
import { ALLOW_AUTHENTICATED_KEY } from '../decorators/allow-authenticated.decorator';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { REQUIRED_PERMISSIONS_KEY } from '../decorators/permissions.decorator';
import { AuthenticatedUser } from './jwt-auth.guard';

type AuthenticatedRequest = Request & {
  user?: AuthenticatedUser;
};

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly prisma: PrismaService,
  ) {}

  private async auditDenied(
    request: AuthenticatedRequest,
    reason: string,
    requiredPermissions: string[] = [],
  ): Promise<void> {
    const user = request.user;

    if (!user) return;

    try {
      await this.prisma.securityEvent.create({
        data: {
          tenantId: user.tenantId,
          userId: user.id,
          type: 'PERMISSION_DENIED',
          ipAddress: request.ip,
          userAgent: request.get('user-agent')?.slice(0, 500),
          details: {
            reason,
            path: request.path,
            method: request.method,
            requiredPermissions,
          },
        },
      });
    } catch {
      // Uma falha na auditoria não deve liberar uma operação proibida.
    }
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const handler = context.getHandler();
    const controller = context.getClass();

    const isPublic = this.reflector.getAllAndOverride<boolean>(
      IS_PUBLIC_KEY,
      [handler, controller],
    );

    if (isPublic) return true;

    const request = context
      .switchToHttp()
      .getRequest<AuthenticatedRequest>();

    const user = request.user;

    if (!user) {
      throw new ForbiddenException('Usuário autenticado não encontrado.');
    }

    const allowAuthenticated = this.reflector.getAllAndOverride<boolean>(
      ALLOW_AUTHENTICATED_KEY,
      [handler, controller],
    );

    if (allowAuthenticated) return true;

    const requiredPermissions = this.reflector.getAllAndOverride<string[]>(
      REQUIRED_PERMISSIONS_KEY,
      [handler, controller],
    );

    if (!requiredPermissions || requiredPermissions.length === 0) {
      await this.auditDenied(
        request,
        'MISSING_PERMISSION_METADATA',
      );

      throw new ForbiddenException(
        'A rota não possui uma política de autorização configurada.',
      );
    }

    const assignments = await this.prisma.userRole.findMany({
      where: {
        userId: user.id,
        role: {
          tenantId: user.tenantId,
        },
      },
      select: {
        role: {
          select: {
            permissions: {
              select: {
                permission: {
                  select: {
                    key: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    const grantedPermissions = new Set(
      assignments.flatMap((assignment) =>
        assignment.role.permissions.map(
          (item) => item.permission.key,
        ),
      ),
    );

    const missingPermissions = requiredPermissions.filter(
      (permission) => !grantedPermissions.has(permission),
    );

    if (missingPermissions.length > 0) {
      await this.auditDenied(
        request,
        'INSUFFICIENT_PERMISSIONS',
        requiredPermissions,
      );

      throw new ForbiddenException(
        'Você não possui permissão para esta operação.',
      );
    }

    return true;
  }
}