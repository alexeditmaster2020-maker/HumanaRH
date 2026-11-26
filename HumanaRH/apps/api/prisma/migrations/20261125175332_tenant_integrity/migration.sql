BEGIN;

-- ============================================================
-- HUMANA RH - INTEGRIDADE MULTI-TENANT
-- Migration: tenant_integrity
-- ============================================================

-- 1. Verificar inconsistencias antes de alterar a estrutura.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM "UserCompany" uc
        JOIN "User" u ON u."id" = uc."userId"
        JOIN "Company" c ON c."id" = uc."companyId"
        WHERE u."tenantId" <> c."tenantId"
    ) THEN
        RAISE EXCEPTION 'Migration interrompida: UserCompany possui associacoes entre tenants diferentes.';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM "UserBranch" ub
        JOIN "User" u ON u."id" = ub."userId"
        JOIN "Branch" b ON b."id" = ub."branchId"
        JOIN "Company" c ON c."id" = b."companyId"
        WHERE u."tenantId" <> c."tenantId"
    ) THEN
        RAISE EXCEPTION 'Migration interrompida: UserBranch possui associacoes entre tenants diferentes.';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM "UserRole" ur
        JOIN "User" u ON u."id" = ur."userId"
        JOIN "Role" r ON r."id" = ur."roleId"
        WHERE u."tenantId" <> r."tenantId"
    ) THEN
        RAISE EXCEPTION 'Migration interrompida: UserRole possui associacoes entre tenants diferentes.';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM "RefreshSession" rs
        JOIN "User" u ON u."id" = rs."userId"
        WHERE u."tenantId" <> rs."tenantId"
    ) THEN
        RAISE EXCEPTION 'Migration interrompida: RefreshSession possui tenant diferente do usuario.';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM "SecurityEvent" se
        JOIN "User" u ON u."id" = se."userId"
        WHERE se."userId" IS NOT NULL
          AND (se."tenantId" IS NULL OR se."tenantId" <> u."tenantId")
    ) THEN
        RAISE EXCEPTION 'Migration interrompida: SecurityEvent possui tenant diferente do usuario.';
    END IF;
END $$;

-- 2. Remover as chaves estrangeiras antigas.

ALTER TABLE "Branch"
    DROP CONSTRAINT "Branch_companyId_fkey";

ALTER TABLE "RefreshSession"
    DROP CONSTRAINT "RefreshSession_userId_fkey";

ALTER TABLE "SecurityEvent"
    DROP CONSTRAINT "SecurityEvent_userId_fkey";

ALTER TABLE "SecurityEvent"
    DROP CONSTRAINT "SecurityEvent_tenantId_fkey";

ALTER TABLE "UserBranch"
    DROP CONSTRAINT "UserBranch_branchId_fkey";

ALTER TABLE "UserBranch"
    DROP CONSTRAINT "UserBranch_userId_fkey";

ALTER TABLE "UserCompany"
    DROP CONSTRAINT "UserCompany_companyId_fkey";

ALTER TABLE "UserCompany"
    DROP CONSTRAINT "UserCompany_userId_fkey";

ALTER TABLE "UserRole"
    DROP CONSTRAINT "UserRole_roleId_fkey";

ALTER TABLE "UserRole"
    DROP CONSTRAINT "UserRole_userId_fkey";

-- 3. Adicionar tenantId inicialmente como opcional.

ALTER TABLE "Branch"
    ADD COLUMN "tenantId" UUID;

ALTER TABLE "UserBranch"
    ADD COLUMN "tenantId" UUID;

ALTER TABLE "UserCompany"
    ADD COLUMN "tenantId" UUID;

ALTER TABLE "UserRole"
    ADD COLUMN "tenantId" UUID;

-- 4. Preencher tenantId a partir dos relacionamentos existentes.

UPDATE "Branch" b
SET "tenantId" = c."tenantId"
FROM "Company" c
WHERE c."id" = b."companyId";

UPDATE "UserCompany" uc
SET "tenantId" = u."tenantId"
FROM "User" u
WHERE u."id" = uc."userId";

UPDATE "UserBranch" ub
SET "tenantId" = u."tenantId"
FROM "User" u
WHERE u."id" = ub."userId";

UPDATE "UserRole" ur
SET "tenantId" = u."tenantId"
FROM "User" u
WHERE u."id" = ur."userId";

-- 5. Impedir que registros sem tenant sejam aceitos.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM "Branch" WHERE "tenantId" IS NULL) THEN
        RAISE EXCEPTION 'Migration interrompida: Branch possui tenantId nulo.';
    END IF;

    IF EXISTS (SELECT 1 FROM "UserCompany" WHERE "tenantId" IS NULL) THEN
        RAISE EXCEPTION 'Migration interrompida: UserCompany possui tenantId nulo.';
    END IF;

    IF EXISTS (SELECT 1 FROM "UserBranch" WHERE "tenantId" IS NULL) THEN
        RAISE EXCEPTION 'Migration interrompida: UserBranch possui tenantId nulo.';
    END IF;

    IF EXISTS (SELECT 1 FROM "UserRole" WHERE "tenantId" IS NULL) THEN
        RAISE EXCEPTION 'Migration interrompida: UserRole possui tenantId nulo.';
    END IF;
END $$;

ALTER TABLE "Branch"
    ALTER COLUMN "tenantId" SET NOT NULL;

ALTER TABLE "UserCompany"
    ALTER COLUMN "tenantId" SET NOT NULL;

ALTER TABLE "UserBranch"
    ALTER COLUMN "tenantId" SET NOT NULL;

ALTER TABLE "UserRole"
    ALTER COLUMN "tenantId" SET NOT NULL;

-- 6. Criar índices únicos compostos.

CREATE UNIQUE INDEX "Branch_id_tenantId_key"
    ON "Branch"("id", "tenantId");

CREATE UNIQUE INDEX "Company_id_tenantId_key"
    ON "Company"("id", "tenantId");

CREATE UNIQUE INDEX "Role_id_tenantId_key"
    ON "Role"("id", "tenantId");

CREATE UNIQUE INDEX "User_id_tenantId_key"
    ON "User"("id", "tenantId");

-- 7. Criar índices de tenant.

CREATE INDEX "UserBranch_tenantId_idx"
    ON "UserBranch"("tenantId");

CREATE INDEX "UserCompany_tenantId_idx"
    ON "UserCompany"("tenantId");

CREATE INDEX "UserRole_tenantId_idx"
    ON "UserRole"("tenantId");

-- 8. Criar chaves estrangeiras compostas.

ALTER TABLE "Branch"
    ADD CONSTRAINT "Branch_companyId_tenantId_fkey"
    FOREIGN KEY ("companyId", "tenantId")
    REFERENCES "Company"("id", "tenantId")
    ON DELETE RESTRICT
    ON UPDATE CASCADE;

ALTER TABLE "UserCompany"
    ADD CONSTRAINT "UserCompany_userId_tenantId_fkey"
    FOREIGN KEY ("userId", "tenantId")
    REFERENCES "User"("id", "tenantId")
    ON DELETE CASCADE
    ON UPDATE CASCADE;

ALTER TABLE "UserCompany"
    ADD CONSTRAINT "UserCompany_companyId_tenantId_fkey"
    FOREIGN KEY ("companyId", "tenantId")
    REFERENCES "Company"("id", "tenantId")
    ON DELETE CASCADE
    ON UPDATE CASCADE;

ALTER TABLE "UserBranch"
    ADD CONSTRAINT "UserBranch_userId_tenantId_fkey"
    FOREIGN KEY ("userId", "tenantId")
    REFERENCES "User"("id", "tenantId")
    ON DELETE CASCADE
    ON UPDATE CASCADE;

ALTER TABLE "UserBranch"
    ADD CONSTRAINT "UserBranch_branchId_tenantId_fkey"
    FOREIGN KEY ("branchId", "tenantId")
    REFERENCES "Branch"("id", "tenantId")
    ON DELETE CASCADE
    ON UPDATE CASCADE;

ALTER TABLE "UserRole"
    ADD CONSTRAINT "UserRole_userId_tenantId_fkey"
    FOREIGN KEY ("userId", "tenantId")
    REFERENCES "User"("id", "tenantId")
    ON DELETE CASCADE
    ON UPDATE CASCADE;

ALTER TABLE "UserRole"
    ADD CONSTRAINT "UserRole_roleId_tenantId_fkey"
    FOREIGN KEY ("roleId", "tenantId")
    REFERENCES "Role"("id", "tenantId")
    ON DELETE CASCADE
    ON UPDATE CASCADE;

ALTER TABLE "RefreshSession"
    ADD CONSTRAINT "RefreshSession_userId_tenantId_fkey"
    FOREIGN KEY ("userId", "tenantId")
    REFERENCES "User"("id", "tenantId")
    ON DELETE CASCADE
    ON UPDATE CASCADE;

ALTER TABLE "SecurityEvent"
    ADD CONSTRAINT "SecurityEvent_userId_tenantId_fkey"
    FOREIGN KEY ("userId", "tenantId")
    REFERENCES "User"("id", "tenantId")
    ON DELETE RESTRICT
    ON UPDATE CASCADE;
ALTER TABLE "SecurityEvent"
    ADD CONSTRAINT "SecurityEvent_tenantId_fkey"
    FOREIGN KEY ("tenantId")
    REFERENCES "Tenant"("id")
    ON DELETE RESTRICT
    ON UPDATE CASCADE;

COMMIT;
