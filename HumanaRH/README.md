# HumanaRH

Monorepo inicial do HumanaRH — SaaS de gestão de pessoas e Departamento Pessoal.

## Stack inicial
- Backend: NestJS + Prisma
- Frontend: Next.js (App Router)
- Banco: PostgreSQL
- Infraestrutura local: Docker Compose
- Linguagem: TypeScript

> Esta é a fundação técnica da Etapa 1. Os módulos funcionais serão implementados e validados progressivamente.

## Pré-requisitos
- Node.js 22+
- npm 10+
- Docker Desktop

## Subir infraestrutura
```bash
docker compose up -d postgres
```

## Instalar dependências
```bash
npm install
```

## Configurar ambiente
```bash
cp .env.example .env
```

## Prisma
```bash
npm run db:generate
npm run db:migrate
```

## Desenvolvimento
```bash
npm run dev:api
npm run dev:web
```

- API: http://localhost:3001/api
- Health: http://localhost:3001/api/health
- Web: http://localhost:3000

## Próximas etapas
1. Validar ambiente e persistência.
2. Implementar autenticação JWT, RBAC e isolamento multi-tenant.
3. Implementar empresas, filiais e colaboradores.
4. Avançar pelos módulos definidos na arquitetura aprovada.
