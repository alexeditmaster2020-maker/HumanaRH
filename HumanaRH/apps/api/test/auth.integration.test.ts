import 'reflect-metadata';

import assert = require('node:assert/strict');
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { test } from 'node:test';

import * as dotenv from 'dotenv';
import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import cookieParser = require('cookie-parser');

const envPath = resolve(process.cwd(), '../../.env');

const parsedEnv = dotenv.parse(readFileSync(envPath, 'utf8'));

if (!parsedEnv.DATABASE_URL) {
  throw new Error('DATABASE_URL não encontrada. Teste interrompido.');
}

const databaseUrl = new URL(parsedEnv.DATABASE_URL);

if (
  databaseUrl.hostname !== 'localhost' ||
  databaseUrl.port !== '5434' ||
  databaseUrl.username !== 'humanarh' ||
  databaseUrl.pathname !== '/humanarh'
) {
  throw new Error(
    'A conexão original não corresponde ao ambiente esperado. Teste interrompido.',
  );
}

databaseUrl.pathname = '/humanarh_test';

process.env.DATABASE_URL = databaseUrl.toString();

dotenv.config({ path: envPath });

const uniqueSuffix = randomUUID().replace(/-/g, '').slice(0, 12);
const slugPrefix = `it-${uniqueSuffix}`;
const emailPrefix = `it-${uniqueSuffix}`;

const tenantSlugs = [
  `${slugPrefix}-a`,
  `${slugPrefix}-b`,
];

const userEmails = [
  `${emailPrefix}-a@example.test`,
  `${emailPrefix}-b@example.test`,
];

function extractRefreshCookie(response: Response): string {
  const cookies = response.headers.getSetCookie();

  const cookie = cookies
    .map((part) => part.trim())
    .find((part) => part.startsWith('refreshToken='));

  assert.ok(cookie, 'Cookie refreshToken não encontrado.');

  return cookie.split(';', 1)[0];
}

async function readJson(response: Response): Promise<any> {
  return response.json();
}

test(
  'integração HTTP: isolamento de tenants e ciclo de autenticação',
  { timeout: 60000 },
  async () => {
    let app: any;
    let prisma: any;
    let baseUrl = '';

    const results: string[] = [];

    try {
      const { AppModule } = await import('../src/app.module');
      const { PrismaService } = await import('../src/prisma/prisma.service');
      const { AuthService } = await import('../src/auth/auth.service');

      app = await NestFactory.create(AppModule, {
        logger: ['error', 'warn'],
      });

      app.setGlobalPrefix('api');
      app.use(cookieParser());

      app.enableCors({
        origin: process.env.WEB_URL ?? 'http://localhost:3000',
        credentials: true,
      });

      app.useGlobalPipes(
        new ValidationPipe({
          whitelist: true,
          transform: true,
          forbidNonWhitelisted: true,
        }),
      );

      prisma = app.get(PrismaService);
      const authService = app.get(AuthService);

      const databaseCheck = await prisma.$queryRawUnsafe(
        'SELECT current_database() AS database_name',
      );

      assert.equal(
        databaseCheck[0]?.database_name,
        'humanarh_test',
        'Proteção: a API não está conectada ao banco humanarh_test.',
      );

      results.push('Banco de dados de teste confirmado.');

      const jwt = app.get(JwtService);

      await app.listen(0, '127.0.0.1');

      const address = app.getHttpServer().address();

      assert.ok(
        address && typeof address === 'object',
        'Não foi possível identificar a porta temporária da API.',
      );

      baseUrl = `http://127.0.0.1:${address.port}/api`;

      async function request(
        path: string,
        options: {
          method?: string;
          body?: unknown;
          token?: string;
          cookie?: string;
          origin?: string | null;
          referer?: string | null;
        } = {},
      ): Promise<Response> {
        const headers: Record<string, string> = {};

        if (options.body !== undefined) {
          headers['content-type'] = 'application/json';
        }

        if (options.token) {
          headers.authorization = `Bearer ${options.token}`;
        }

        if (options.cookie) {
          headers.cookie = options.cookie;
        }

        if (options.origin !== null) {
          headers.origin = options.origin ?? 'http://localhost:3000';
        }

        if (options.referer) {
          headers.referer = options.referer;
        }

        return fetch(`${baseUrl}${path}`, {
          method: options.method ?? 'GET',
          headers,
          body:
            options.body !== undefined
              ? JSON.stringify(options.body)
              : undefined,
        });
      }

      const rejectedOrigin = await request('/auth/logout', {
        method: 'POST',
        origin: 'https://attacker.example',
      });

      assert.equal(
        rejectedOrigin.status,
        403,
        'External origin should be rejected.',
      );
      results.push('External origin rejected (HTTP 403).');

      const allowedOrigin = await request('/auth/logout', {
        method: 'POST',
        origin: 'http://localhost:3000',
      });

      assert.ok(
        [200, 201].includes(allowedOrigin.status),
        `Trusted origin should be accepted: HTTP ${allowedOrigin.status}`,
      );
      results.push('Trusted origin accepted.');

      const allowedReferer = await request('/auth/logout', {
        method: 'POST',
        origin: null,
        referer: 'http://localhost:3000/account',
      });

      assert.ok(
        [200, 201].includes(allowedReferer.status),
        `Trusted Referer should be accepted: HTTP ${allowedReferer.status}`,
      );
      results.push('Trusted Referer fallback accepted.');

      const missingOrigin = await request('/auth/logout', {
        method: 'POST',
        origin: null,
        referer: null,
      });

      assert.equal(
        missingOrigin.status,
        403,
        'Logout without Origin and Referer should be rejected.',
      );
      results.push('Logout without origin reference rejected (HTTP 403).');

      const password = 'TesteSeguro2026!';

      const registrationA = await request('/auth/register', {
        method: 'POST',
        body: {
          organizationName: 'Organização de Teste A',
          tenantSlug: tenantSlugs[0],
          name: 'Usuário Teste A',
          email: userEmails[0],
          password,
        },
      });

      assert.ok(
        [200, 201].includes(registrationA.status),
        `Cadastro do Tenant A falhou: HTTP ${registrationA.status}`,
      );

      const registeredA = await readJson(registrationA);

      assert.ok(registeredA.user?.id);
      assert.ok(registeredA.user?.tenantId);
      assert.ok(registeredA.accessToken);

      results.push('Cadastro do Tenant A aprovado.');

      const registrationB = await request('/auth/register', {
        method: 'POST',
        body: {
          organizationName: 'Organização de Teste B',
          tenantSlug: tenantSlugs[1],
          name: 'Usuário Teste B',
          email: userEmails[1],
          password,
        },
      });

      assert.ok(
        [200, 201].includes(registrationB.status),
        `Cadastro do Tenant B falhou: HTTP ${registrationB.status}`,
      );

      const registeredB = await readJson(registrationB);

      assert.ok(registeredB.user?.id);
      assert.ok(registeredB.user?.tenantId);
      assert.ok(registeredB.accessToken);

      assert.notEqual(
        registeredA.user.tenantId,
        registeredB.user.tenantId,
        'Os dois cadastros não criaram tenants independentes.',
      );

      results.push('Cadastro do Tenant B e independência dos tenants aprovados.');

      const loginA = await request('/auth/login', {
        method: 'POST',
        body: {
          tenantSlug: tenantSlugs[0],
          email: userEmails[0],
          password,
        },
      });

      assert.ok(
        [200, 201].includes(loginA.status),
        `Login do Tenant A falhou: HTTP ${loginA.status}`,
      );

      const loggedA = await readJson(loginA);
      const cookieA = extractRefreshCookie(loginA);

      assert.ok(loggedA.accessToken);

      results.push('Login do Tenant A aprovado.');

      const loginB = await request('/auth/login', {
        method: 'POST',
        body: {
          tenantSlug: tenantSlugs[1],
          email: userEmails[1],
          password,
        },
      });

      assert.ok(
        [200, 201].includes(loginB.status),
        `Login do Tenant B falhou: HTTP ${loginB.status}`,
      );

      const loggedB = await readJson(loginB);
      const cookieB = extractRefreshCookie(loginB);

      assert.ok(loggedB.accessToken);

      results.push('Login do Tenant B aprovado.');

      const meA = await request('/auth/me', {
        token: loggedA.accessToken,
      });

      assert.equal(meA.status, 200);

      const identityA = await readJson(meA);

      assert.equal(identityA.user.id, loggedA.user.id);
      assert.equal(identityA.user.tenantId, registeredA.user.tenantId);

      results.push('Identidade autenticada do Tenant A aprovada.');

      const meB = await request('/auth/me', {
        token: loggedB.accessToken,
      });

      assert.equal(meB.status, 200);

      const identityB = await readJson(meB);

      assert.equal(identityB.user.id, loggedB.user.id);
      assert.equal(identityB.user.tenantId, registeredB.user.tenantId);

      results.push('Identidade autenticada do Tenant B aprovada.');

      const sessionA = await prisma.refreshSession.findFirst({
        where: {
          userId: loggedA.user.id,
          tenantId: loggedA.user.tenantId,
        },
        orderBy: {
          createdAt: 'desc',
        },
        select: {
          id: true,
        },
      });

      const sessionB = await prisma.refreshSession.findFirst({
        where: {
          userId: loggedB.user.id,
          tenantId: loggedB.user.tenantId,
        },
        orderBy: {
          createdAt: 'desc',
        },
        select: {
          id: true,
        },
      });

      assert.ok(sessionA?.id, 'Sessão do Tenant A não encontrada.');
      assert.ok(sessionB?.id, 'Sessão do Tenant B não encontrada.');

      const forgedTenantToken = await jwt.signAsync({
        sub: loggedA.user.id,
        tid: loggedB.user.tenantId,
        sid: sessionA.id,
      });

      const forgedTenantResponse = await request('/auth/me', {
        token: forgedTenantToken,
      });

      assert.equal(
        forgedTenantResponse.status,
        401,
        'Token com tenantId de outra organização deveria ser rejeitado.',
      );

      results.push('Token com tenantId cruzado rejeitado (HTTP 401).');

      const forgedSessionToken = await jwt.signAsync({
        sub: loggedA.user.id,
        tid: loggedA.user.tenantId,
        sid: sessionB.id,
      });

      const forgedSessionResponse = await request('/auth/me', {
        token: forgedSessionToken,
      });

      assert.equal(
        forgedSessionResponse.status,
        401,
        'Sessão de outra organização deveria ser rejeitada.',
      );

      results.push('Token com sessão cruzada rejeitado (HTTP 401).');

      const refreshA = await request('/auth/refresh', {
        method: 'POST',
        cookie: cookieA,
      });

      assert.ok(
        [200, 201].includes(refreshA.status),
        `Refresh do Tenant A falhou: HTTP ${refreshA.status}`,
      );

      const refreshedA = await readJson(refreshA);
      const refreshedCookieA = extractRefreshCookie(refreshA);

      assert.ok(refreshedA.accessToken);
      assert.notEqual(
        refreshedCookieA,
        cookieA,
        'O refresh token não foi rotacionado.',
      );

      const refreshedMeA = await request('/auth/me', {
        token: refreshedA.accessToken,
      });

      assert.equal(refreshedMeA.status, 200);

      results.push('Renovação e rotação de sessão do Tenant A aprovadas.');

      const logoutB = await request('/auth/logout', {
        method: 'POST',
        cookie: cookieB,
      });

      assert.ok(
        [200, 201].includes(logoutB.status),
        `Logout do Tenant B falhou: HTTP ${logoutB.status}`,
      );

      const refreshAfterLogoutB = await request('/auth/refresh', {
        method: 'POST',
        cookie: cookieB,
      });

      assert.equal(
        refreshAfterLogoutB.status,
        401,
        'A sessão do Tenant B deveria ser rejeitada após logout.',
      );

      const meAfterLogoutB = await request('/auth/me', {
        token: loggedB.accessToken,
      });

      assert.equal(
        meAfterLogoutB.status,
        401,
        'O access token do Tenant B deveria ser rejeitado após logout.',
      );

      results.push('Logout e revogação da sessão do Tenant B aprovados.');

      const directRequest = {
        ip: '127.0.0.1',
        get: (header: string) =>
          header.toLowerCase() === 'user-agent'
            ? 'humanarh-concurrency-integration-test'
            : undefined,
      } as any;

      const directResponse = {} as any;

      const wrongLogin = () =>
        authService.login(
          {
            tenantSlug: tenantSlugs[1],
            email: userEmails[1],
            password: 'SenhaIncorreta2026!',
          },
          directRequest,
          directResponse,
        );

      const parallelFailures = await Promise.allSettled(
        Array.from({ length: 5 }, () => wrongLogin()),
      );

      assert.equal(
        parallelFailures.filter((result) => result.status === 'rejected').length,
        5,
        'As cinco tentativas simultâneas deveriam ser rejeitadas.',
      );

      const lockedUser = await prisma.user.findFirst({
        where: {
          id: registeredB.user.id,
          tenantId: registeredB.user.tenantId,
        },
        select: {
          failedLoginAttempts: true,
          lockedUntil: true,
        },
      });

      assert.ok(lockedUser, 'Usuário de teste não encontrado após as tentativas.');
      assert.equal(
        lockedUser.failedLoginAttempts,
        0,
        'O contador deveria ser reiniciado ao atingir o limite.',
      );
      assert.ok(
        lockedUser.lockedUntil instanceof Date &&
          lockedUser.lockedUntil.getTime() > Date.now(),
        'A conta deveria estar bloqueada após cinco tentativas.',
      );

      const failedEventsBeforeSixthAttempt = await prisma.securityEvent.count({
        where: {
          tenantId: registeredB.user.tenantId,
          userId: registeredB.user.id,
          type: 'LOGIN_FAILED',
        },
      });

      assert.equal(
        failedEventsBeforeSixthAttempt,
        5,
        'Deveriam existir exatamente cinco eventos de falha.',
      );

      await assert.rejects(
        () => wrongLogin(),
        /Conta temporariamente bloqueada/,
        'A sexta tentativa deveria encontrar a conta bloqueada.',
      );

      const failedEventsAfterSixthAttempt = await prisma.securityEvent.count({
        where: {
          tenantId: registeredB.user.tenantId,
          userId: registeredB.user.id,
          type: 'LOGIN_FAILED',
        },
      });

      assert.equal(
        failedEventsAfterSixthAttempt,
        5,
        'A tentativa durante o bloqueio não deveria gerar outro evento.',
      );

      results.push(
        'Cinco tentativas simultâneas, bloqueio de 15 minutos e auditoria transacional aprovados.',
      );
      console.log('\n========== RESULTADOS DOS TESTES ==========');

      for (const result of results) {
        console.log(`PASSOU: ${result}`);
      }

      console.log(`\nTotal de verificações aprovadas: ${results.length}`);
    } finally {
      if (app && prisma) {
        try {
          const tenants = await prisma.tenant.findMany({
            where: {
              slug: {
                in: tenantSlugs,
              },
            },
            select: {
              id: true,
            },
          });

          const tenantIds = tenants.map((tenant: { id: string }) => tenant.id);

          if (tenantIds.length > 0) {
            const users = await prisma.user.findMany({
              where: {
                tenantId: {
                  in: tenantIds,
                },
              },
              select: {
                id: true,
              },
            });

            const userIds = users.map((user: { id: string }) => user.id);

            await prisma.securityEvent.deleteMany({
              where: {
                tenantId: {
                  in: tenantIds,
                },
              },
            });

            await prisma.refreshSession.deleteMany({
              where: {
                tenantId: {
                  in: tenantIds,
                },
              },
            });

            if (userIds.length > 0) {
              await prisma.passwordResetToken.deleteMany({
                where: {
                  userId: {
                    in: userIds,
                  },
                },
              });

              await prisma.user.deleteMany({
                where: {
                  id: {
                    in: userIds,
                  },
                },
              });
            }

            await prisma.tenant.deleteMany({
              where: {
                id: {
                  in: tenantIds,
                },
              },
            });
          }

          const remainingTenants = await prisma.tenant.count({
            where: {
              slug: {
                in: tenantSlugs,
              },
            },
          });

          const remainingUsers = await prisma.user.count({
            where: {
              email: {
                in: userEmails,
              },
            },
          });

          const remainingSessions = await prisma.refreshSession.count({
            where: {
              tenant: {
                slug: {
                  in: tenantSlugs,
                },
              },
            },
          });

          const remainingEvents = await prisma.securityEvent.count({
            where: {
              tenant: {
                slug: {
                  in: tenantSlugs,
                },
              },
            },
          });

          assert.equal(remainingTenants, 0, 'Restaram tenants de teste.');
          assert.equal(remainingUsers, 0, 'Restaram usuários de teste.');
          assert.equal(remainingSessions, 0, 'Restaram sessões de teste.');
          assert.equal(remainingEvents, 0, 'Restaram eventos de auditoria de teste.');

          console.log('\nLIMPEZA APROVADA: nenhum registro de teste residual.');
        } finally {
          await app.close();
        }
      }
    }
  },
);