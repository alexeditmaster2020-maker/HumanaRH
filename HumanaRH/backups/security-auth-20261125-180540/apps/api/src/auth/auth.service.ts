import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as argon2 from 'argon2';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { Request, Response } from 'express';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

const ACCESS_TOKEN_SECONDS = 900;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_MINUTES = 15;

const OWNER_PERMISSIONS = [
  { key: 'users.read', module: 'users', action: 'read', description: 'Consultar usuários' },
  { key: 'users.create', module: 'users', action: 'create', description: 'Cadastrar usuários' },
  { key: 'users.update', module: 'users', action: 'update', description: 'Atualizar usuários' },
  { key: 'users.block', module: 'users', action: 'block', description: 'Bloquear usuários' },
  { key: 'roles.read', module: 'roles', action: 'read', description: 'Consultar perfis' },
  { key: 'roles.manage', module: 'roles', action: 'manage', description: 'Gerenciar perfis e permissões' },
  { key: 'organization.manage', module: 'organization', action: 'manage', description: 'Gerenciar organização' },
];

@Injectable()
export class AuthService {
  private readonly refreshDays = Number(process.env.REFRESH_TOKEN_TTL_DAYS ?? 7);

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
  ) {}

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  private cookieOptions() {
    return {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax' as const,
      path: '/api/auth',
      maxAge: this.refreshDays * 24 * 60 * 60 * 1000,
    };
  }

  private setRefreshCookie(response: Response, token: string) {
    response.cookie('refreshToken', token, this.cookieOptions());
  }

  private clearRefreshCookie(response: Response) {
    response.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/api/auth',
    });
  }

  private async issueTokens(
    user: { id: string; tenantId: string; name: string; email: string },
    request: Request,
    response: Response,
    familyId = randomUUID(),
  ) {
    const refreshToken = randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + this.refreshDays * 86400000);

    const session = await this.prisma.refreshSession.create({
      data: {
        userId: user.id,
        tenantId: user.tenantId,
        tokenHash: this.hashToken(refreshToken),
        familyId,
        expiresAt,
        ipAddress: request.ip,
        userAgent: request.get('user-agent')?.slice(0, 500),
      },
    });

    const accessToken = await this.jwt.signAsync({
      sub: user.id,
      tid: user.tenantId,
      sid: session.id,
    });

    this.setRefreshCookie(response, refreshToken);

    return {
      accessToken,
      tokenType: 'Bearer',
      expiresIn: ACCESS_TOKEN_SECONDS,
      user: {
        id: user.id,
        tenantId: user.tenantId,
        name: user.name,
        email: user.email,
      },
    };
  }

  async register(dto: RegisterDto, request: Request, response: Response) {
    const email = dto.email.trim().toLowerCase();
    const slug = dto.tenantSlug.trim().toLowerCase();

    const existingTenant = await this.prisma.tenant.findUnique({
      where: { slug },
      select: { id: true },
    });

    if (existingTenant) {
      throw new ConflictException('Este identificador de organização já está em uso.');
    }

    const passwordHash = await argon2.hash(dto.password, {
      type: argon2.argon2id,
      memoryCost: 19456,
      timeCost: 2,
      parallelism: 1,
    });

    try {
      const user = await this.prisma.$transaction(async (tx) => {
        const tenant = await tx.tenant.create({
          data: {
            name: dto.organizationName.trim(),
            slug,
          },
        });

        const createdUser = await tx.user.create({
          data: {
            tenantId: tenant.id,
            name: dto.name.trim(),
            email,
            passwordHash,
          },
        });

        const ownerRole = await tx.role.create({
          data: {
            tenantId: tenant.id,
            name: 'Proprietário',
            slug: 'owner',
            description: 'Administrador principal da organização',
            isSystem: true,
          },
        });

        const permissions = await Promise.all(
          OWNER_PERMISSIONS.map((permission) =>
            tx.permission.upsert({
              where: { key: permission.key },
              update: {},
              create: permission,
            }),
          ),
        );

        await tx.rolePermission.createMany({
          data: permissions.map((permission) => ({
            roleId: ownerRole.id,
            permissionId: permission.id,
          })),
        });

        await tx.userRole.create({
          data: {
            tenantId: tenant.id,
            userId: createdUser.id,
            roleId: ownerRole.id,
          },
        });

        await tx.securityEvent.create({
          data: {
            tenantId: tenant.id,
            userId: createdUser.id,
            type: 'TENANT_CREATED',
            ipAddress: request.ip,
            userAgent: request.get('user-agent')?.slice(0, 500),
          },
        });

        return createdUser;
      });

      return this.issueTokens(user, request, response);
    } catch (error) {
      if (
        error instanceof ConflictException ||
        (error instanceof Error && error.message.includes('Unique constraint'))
      ) {
        throw new ConflictException('Organização ou usuário já cadastrado.');
      }
      throw error;
    }
  }

  async login(dto: LoginDto, request: Request, response: Response) {
    const tenant = await this.prisma.tenant.findUnique({
      where: { slug: dto.tenantSlug },
      select: { id: true, status: true },
    });

    const user = tenant
      ? await this.prisma.user.findUnique({
          where: {
            tenantId_email: {
              tenantId: tenant.id,
              email: dto.email,
            },
          },
        })
      : null;

    const invalidCredentials = () =>
      new UnauthorizedException('Organização, e-mail ou senha inválidos.');

    if (!tenant || tenant.status !== 'ACTIVE' || !user) {
      throw invalidCredentials();
    }

    if (user.status !== 'ACTIVE') {
      throw invalidCredentials();
    }

    const now = new Date();

    if (user.lockedUntil && user.lockedUntil > now) {
      throw new UnauthorizedException('Conta temporariamente bloqueada. Tente novamente mais tarde.');
    }

    const validPassword = await argon2.verify(user.passwordHash, dto.password)
      .catch(() => false);

    if (!validPassword) {
      const attempts = user.failedLoginAttempts + 1;
      const lockedUntil = attempts >= MAX_LOGIN_ATTEMPTS
        ? new Date(Date.now() + LOCK_MINUTES * 60000)
        : null;

      await this.prisma.user.update({
        where: { id: user.id },
        data: {
          failedLoginAttempts: attempts >= MAX_LOGIN_ATTEMPTS ? 0 : attempts,
          lockedUntil,
        },
      });

      await this.prisma.securityEvent.create({
        data: {
          tenantId: user.tenantId,
          userId: user.id,
          type: 'LOGIN_FAILED',
          ipAddress: request.ip,
          userAgent: request.get('user-agent')?.slice(0, 500),
        },
      });

      throw invalidCredentials();
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: 0,
        lockedUntil: null,
        lastLoginAt: now,
      },
    });

    await this.prisma.securityEvent.create({
      data: {
        tenantId: user.tenantId,
        userId: user.id,
        type: 'LOGIN_SUCCESS',
        ipAddress: request.ip,
        userAgent: request.get('user-agent')?.slice(0, 500),
      },
    });

    return this.issueTokens(user, request, response);
  }

  async refresh(request: Request, response: Response) {
    const cookies = (request as Request & {
      cookies?: Record<string, string>;
    }).cookies;

    const rawToken = cookies?.refreshToken;

    if (!rawToken) {
      throw new UnauthorizedException('Sessão de renovação não encontrada.');
    }

    const tokenHash = this.hashToken(rawToken);
    const session = await this.prisma.refreshSession.findUnique({
      where: { tokenHash },
      include: {
        user: true,
        tenant: true,
      },
    });

    if (!session) {
      throw new UnauthorizedException('Sessão inválida.');
    }

    if (session.revokedAt) {
      await this.prisma.refreshSession.updateMany({
        where: { familyId: session.familyId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      this.clearRefreshCookie(response);
      throw new UnauthorizedException('Sessão reutilizada. Entre novamente.');
    }

    if (
      session.expiresAt <= new Date() ||
      session.user.status !== 'ACTIVE' ||
      session.tenant.status !== 'ACTIVE'
    ) {
      await this.prisma.refreshSession.updateMany({
        where: { familyId: session.familyId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      this.clearRefreshCookie(response);
      throw new UnauthorizedException('Sessão expirada ou usuário inativo.');
    }

    const newRawToken = randomBytes(32).toString('base64url');
    const newExpiresAt = new Date(Date.now() + this.refreshDays * 86400000);

    const newSession = await this.prisma.$transaction(async (tx) => {
      const claimed = await tx.refreshSession.updateMany({
        where: {
          id: session.id,
          revokedAt: null,
          expiresAt: { gt: new Date() },
        },
        data: {
          revokedAt: new Date(),
          lastUsedAt: new Date(),
        },
      });

      if (claimed.count !== 1) return null;

      const created = await tx.refreshSession.create({
        data: {
          userId: session.userId,
          tenantId: session.tenantId,
          tokenHash: this.hashToken(newRawToken),
          familyId: session.familyId,
          expiresAt: newExpiresAt,
          ipAddress: request.ip,
          userAgent: request.get('user-agent')?.slice(0, 500),
        },
      });

      await tx.refreshSession.update({
        where: { id: session.id },
        data: { replacedById: created.id },
      });

      await tx.securityEvent.create({
        data: {
          tenantId: session.tenantId,
          userId: session.userId,
          type: 'TOKEN_REFRESH',
          ipAddress: request.ip,
        },
      });

      return created;
    });

    if (!newSession) {
      await this.prisma.refreshSession.updateMany({
        where: { familyId: session.familyId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      this.clearRefreshCookie(response);
      throw new UnauthorizedException('Não foi possível renovar a sessão.');
    }

    const accessToken = await this.jwt.signAsync({
      sub: session.userId,
      tid: session.tenantId,
      sid: newSession.id,
    });

    this.setRefreshCookie(response, newRawToken);

    return {
      accessToken,
      tokenType: 'Bearer',
      expiresIn: ACCESS_TOKEN_SECONDS,
    };
  }

  async logout(request: Request, response: Response) {
    const cookies = (request as Request & {
      cookies?: Record<string, string>;
    }).cookies;

    const rawToken = cookies?.refreshToken;

    if (rawToken) {
      const tokenHash = this.hashToken(rawToken);
      const session = await this.prisma.refreshSession.findUnique({
        where: { tokenHash },
      });

      if (session && !session.revokedAt) {
        await this.prisma.refreshSession.updateMany({
          where: { familyId: session.familyId, revokedAt: null },
          data: { revokedAt: new Date() },
        });

        await this.prisma.securityEvent.create({
          data: {
            tenantId: session.tenantId,
            userId: session.userId,
            type: 'LOGOUT',
            ipAddress: request.ip,
          },
        });
      }
    }

    this.clearRefreshCookie(response);
    return { message: 'Logout realizado com sucesso.' };
  }
}