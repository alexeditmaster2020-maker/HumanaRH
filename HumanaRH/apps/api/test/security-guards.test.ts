import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import {
  ForbiddenException,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../src/prisma/prisma.service';
import { JwtAuthGuard } from '../src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from '../src/auth/guards/permissions.guard';
import { TrustedOriginGuard } from '../src/auth/guards/trusted-origin.guard';

const HANDLER = function testHandler() {};
class TestController {}

function createContext(request: any) {
  return {
    getHandler: () => HANDLER,
    getClass: () => TestController,
    switchToHttp: () => ({
      getRequest: () => request,
    }),
  } as any;
}

function createReflector(metadata: Record<string, unknown> = {}) {
  return {
    getAllAndOverride: (key: string) => metadata[key],
  } as unknown as Reflector;
}

function createRequest(overrides: Record<string, unknown> = {}): any {
  return {
    headers: {},
    path: '/api/test',
    method: 'GET',
    ip: '127.0.0.1',
    get: (name: string) =>
      name.toLowerCase() === 'user-agent' ? 'HumanaRH security tests' : undefined,
    ...overrides,
  };
}

const user = {
  id: 'user-test-001',
  tenantId: 'tenant-test-001',
  email: 'teste@humanarh.local',
  name: 'Usuário de Teste',
  sessionId: 'session-test-001',
};

test('JWT: rota pública não exige token', async () => {
  const prisma = {} as PrismaService;
  const jwt = {} as JwtService;

  const guard = new JwtAuthGuard(
    createReflector({ isPublic: true }),
    jwt,
    prisma,
  );

  assert.equal(await guard.canActivate(createContext(createRequest())), true);
});

test('JWT: rejeita requisição sem token', async () => {
  const guard = new JwtAuthGuard(
    createReflector(),
    {} as JwtService,
    {} as PrismaService,
  );

  await assert.rejects(
    () => guard.canActivate(createContext(createRequest())),
    UnauthorizedException,
  );
});

test('JWT: aceita token válido e valida usuário e sessão no tenant', async () => {
  let userQuery: any;
  let sessionQuery: any;

  const prisma = {
    user: {
      findFirst: async (args: any) => {
        userQuery = args;
        return {
          id: user.id,
          tenantId: user.tenantId,
          email: user.email,
          name: user.name,
        };
      },
    },
    refreshSession: {
      findFirst: async (args: any) => {
        sessionQuery = args;
        return { id: user.sessionId };
      },
    },
  } as unknown as PrismaService;

  const jwt = {
    verifyAsync: async () => ({
      sub: user.id,
      tid: user.tenantId,
      sid: user.sessionId,
    }),
  } as unknown as JwtService;

  const guard = new JwtAuthGuard(createReflector(), jwt, prisma);
  const request = createRequest({
    headers: { authorization: 'Bearer token-valido-de-teste' },
  });

  assert.equal(await guard.canActivate(createContext(request)), true);
  assert.deepEqual(request.user, user);

  assert.equal(userQuery.where.id, user.id);
  assert.equal(userQuery.where.tenantId, user.tenantId);
  assert.equal(userQuery.where.status, 'ACTIVE');
  assert.equal(userQuery.where.tenant.status, 'ACTIVE');

  assert.equal(sessionQuery.where.id, user.sessionId);
  assert.equal(sessionQuery.where.userId, user.id);
  assert.equal(sessionQuery.where.tenantId, user.tenantId);
  assert.equal(sessionQuery.where.revokedAt, null);
});

test('JWT: rejeita sessão revogada ou inexistente', async () => {
  const prisma = {
    user: {
      findFirst: async () => ({
        id: user.id,
        tenantId: user.tenantId,
        email: user.email,
        name: user.name,
      }),
    },
    refreshSession: {
      findFirst: async () => null,
    },
  } as unknown as PrismaService;

  const jwt = {
    verifyAsync: async () => ({
      sub: user.id,
      tid: user.tenantId,
      sid: user.sessionId,
    }),
  } as unknown as JwtService;

  const guard = new JwtAuthGuard(createReflector(), jwt, prisma);

  await assert.rejects(
    () => guard.canActivate(createContext(createRequest({
      headers: { authorization: 'Bearer token-de-teste' },
    }))),
    UnauthorizedException,
  );
});

test('RBAC: rota pública não exige permissão', async () => {
  const guard = new PermissionsGuard(
    createReflector({ isPublic: true }),
    {} as PrismaService,
  );

  assert.equal(await guard.canActivate(createContext(createRequest())), true);
});

test('RBAC: usuário com permissão autorizada acessa o recurso', async () => {
  let roleQuery: any;

  const prisma = {
    userRole: {
      findMany: async (args: any) => {
        roleQuery = args;
        return [{
          role: {
            permissions: [{
              permission: { key: 'users.read' },
            }],
          },
        }];
      },
    },
  } as unknown as PrismaService;

  const guard = new PermissionsGuard(
    createReflector({ required_permissions: ['users.read'] }),
    prisma,
  );

  const request = createRequest({ user });

  assert.equal(await guard.canActivate(createContext(request)), true);
  assert.equal(roleQuery.where.userId, user.id);
  assert.equal(roleQuery.where.role.tenantId, user.tenantId);
});

test('RBAC: usuário sem permissão recebe 403 e gera auditoria', async () => {
  let auditData: any;

  const prisma = {
    userRole: {
      findMany: async () => [],
    },
    securityEvent: {
      create: async (args: any) => {
        auditData = args.data;
        return {};
      },
    },
  } as unknown as PrismaService;

  const guard = new PermissionsGuard(
    createReflector({ required_permissions: ['users.delete'] }),
    prisma,
  );

  await assert.rejects(
    () => guard.canActivate(createContext(createRequest({ user }))),
    ForbiddenException,
  );

  assert.equal(auditData.tenantId, user.tenantId);
  assert.equal(auditData.userId, user.id);
  assert.equal(auditData.type, 'PERMISSION_DENIED');
  assert.equal(auditData.details.reason, 'INSUFFICIENT_PERMISSIONS');
  assert.deepEqual(auditData.details.requiredPermissions, ['users.delete']);
});

test('RBAC: rota privada sem política explícita é negada e auditada', async () => {
  let auditData: any;

  const prisma = {
    securityEvent: {
      create: async (args: any) => {
        auditData = args.data;
        return {};
      },
    },
  } as unknown as PrismaService;

  const guard = new PermissionsGuard(createReflector(), prisma);

  await assert.rejects(
    () => guard.canActivate(createContext(createRequest({ user }))),
    ForbiddenException,
  );

  assert.equal(auditData.tenantId, user.tenantId);
  assert.equal(auditData.details.reason, 'MISSING_PERMISSION_METADATA');
});

test('RBAC: usuário autenticado sem identidade recebe 403', async () => {
  const guard = new PermissionsGuard(
    createReflector(),
    {} as PrismaService,
  );

  await assert.rejects(
    () => guard.canActivate(createContext(createRequest())),
    ForbiddenException,
  );
});

test('RBAC: decorator de autenticação permite usuário autenticado', async () => {
  const guard = new PermissionsGuard(
    createReflector({ allow_authenticated_only: true }),
    {} as PrismaService,
  );

  assert.equal(
    await guard.canActivate(createContext(createRequest({ user }))),
    true,
  );
});


// TrustedOriginGuard: testes unitários de proteção contra CSRF.
test('Origin: aceita origem confiável em operação de escrita', () => {
  const previous = process.env.WEB_URL;
  process.env.WEB_URL = 'http://localhost:3000';

  try {
    const guard = new TrustedOriginGuard();
    const request = createRequest({
      method: 'POST',
      headers: { origin: 'http://localhost:3000' },
    });

    assert.equal(guard.canActivate(createContext(request)), true);
  } finally {
    if (previous === undefined) delete process.env.WEB_URL;
    else process.env.WEB_URL = previous;
  }
});

test('Origin: rejeita origem externa', () => {
  const previous = process.env.WEB_URL;
  process.env.WEB_URL = 'http://localhost:3000';

  try {
    const guard = new TrustedOriginGuard();
    const request = createRequest({
      method: 'POST',
      headers: { origin: 'https://attacker.example' },
    });

    assert.throws(
      () => guard.canActivate(createContext(request)),
      ForbiddenException,
    );
  } finally {
    if (previous === undefined) delete process.env.WEB_URL;
    else process.env.WEB_URL = previous;
  }
});

test('Origin: rejeita valor null', () => {
  const previous = process.env.WEB_URL;
  process.env.WEB_URL = 'http://localhost:3000';

  try {
    const guard = new TrustedOriginGuard();
    const request = createRequest({
      method: 'POST',
      headers: { origin: 'null' },
    });

    assert.throws(
      () => guard.canActivate(createContext(request)),
      ForbiddenException,
    );
  } finally {
    if (previous === undefined) delete process.env.WEB_URL;
    else process.env.WEB_URL = previous;
  }
});

test('Origin: rejeita cabeçalho com caminho adicional', () => {
  const previous = process.env.WEB_URL;
  process.env.WEB_URL = 'http://localhost:3000';

  try {
    const guard = new TrustedOriginGuard();
    const request = createRequest({
      method: 'POST',
      headers: { origin: 'http://localhost:3000/attacker' },
    });

    assert.throws(
      () => guard.canActivate(createContext(request)),
      ForbiddenException,
    );
  } finally {
    if (previous === undefined) delete process.env.WEB_URL;
    else process.env.WEB_URL = previous;
  }
});

test('Referer: aceita URL da origem confiável', () => {
  const previous = process.env.WEB_URL;
  process.env.WEB_URL = 'http://localhost:3000';

  try {
    const guard = new TrustedOriginGuard();
    const request = createRequest({
      method: 'PATCH',
      headers: { referer: 'http://localhost:3000/account/profile' },
    });

    assert.equal(guard.canActivate(createContext(request)), true);
  } finally {
    if (previous === undefined) delete process.env.WEB_URL;
    else process.env.WEB_URL = previous;
  }
});

test('Referer: rejeita URL de origem externa', () => {
  const previous = process.env.WEB_URL;
  process.env.WEB_URL = 'http://localhost:3000';

  try {
    const guard = new TrustedOriginGuard();
    const request = createRequest({
      method: 'DELETE',
      headers: { referer: 'https://attacker.example/account' },
    });

    assert.throws(
      () => guard.canActivate(createContext(request)),
      ForbiddenException,
    );
  } finally {
    if (previous === undefined) delete process.env.WEB_URL;
    else process.env.WEB_URL = previous;
  }
});

test('Origin e Referer ausentes: rejeita operação de escrita', () => {
  const previous = process.env.WEB_URL;
  process.env.WEB_URL = 'http://localhost:3000';

  try {
    const guard = new TrustedOriginGuard();
    const request = createRequest({
      method: 'POST',
      headers: {},
    });

    assert.throws(
      () => guard.canActivate(createContext(request)),
      ForbiddenException,
    );
  } finally {
    if (previous === undefined) delete process.env.WEB_URL;
    else process.env.WEB_URL = previous;
  }
});

test('Origin: GET não exige validação de origem', () => {
  const previous = process.env.WEB_URL;
  process.env.WEB_URL = 'http://localhost:3000';

  try {
    const guard = new TrustedOriginGuard();
    const request = createRequest({
      method: 'GET',
      headers: { origin: 'https://attacker.example' },
    });

    assert.equal(guard.canActivate(createContext(request)), true);
  } finally {
    if (previous === undefined) delete process.env.WEB_URL;
    else process.env.WEB_URL = previous;
  }
});

test('Configuração: WEB_URL inválida gera erro interno', () => {
  const previous = process.env.WEB_URL;
  process.env.WEB_URL = 'javascript:alert(1)';

  try {
    const guard = new TrustedOriginGuard();
    const request = createRequest({
      method: 'POST',
      headers: { origin: 'http://localhost:3000' },
    });

    assert.throws(
      () => guard.canActivate(createContext(request)),
      InternalServerErrorException,
    );
  } finally {
    if (previous === undefined) delete process.env.WEB_URL;
    else process.env.WEB_URL = previous;
  }
});