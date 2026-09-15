CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(50) NOT NULL UNIQUE,
    name VARCHAR(150) NOT NULL,
    is_master BOOLEAN NOT NULL DEFAULT FALSE,
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Coarse, backend-enforced matrix. module in {identity,config,stock,sales,purchasing,
-- assets,cashflow,invoicing,bi,reports} -- the same names gateway-service routes by.
-- level: 1=view,2=edit. Rows with level=0 are simply not stored (absence = none).
CREATE TABLE role_module_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    module  VARCHAR(30) NOT NULL,
    level   SMALLINT NOT NULL CHECK (level IN (1, 2)),
    PRIMARY KEY (role_id, module)
);

-- Fine, frontend-only matrix. menu_key is the exact shell route path (e.g.
-- "/config/cadastros/usuarios") -- the source of truth for this list lives in
-- apps/web/packages/shared/src/menu.ts, not enumerated/validated here.
CREATE TABLE role_menu_permissions (
    role_id  UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    menu_key VARCHAR(100) NOT NULL,
    level    SMALLINT NOT NULL CHECK (level IN (1, 2)),
    PRIMARY KEY (role_id, menu_key)
);

-- Secure, revocable sessions. One row per successful login (audit/history table).
-- Redis holds a fast-lookup existence key ("session:<id>") with a TTL matching
-- expires_at -- this Postgres row is the durable record and survives Redis eviction.
CREATE TABLE sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    user_agent  TEXT NOT NULL DEFAULT '',
    ip          VARCHAR(64) NOT NULL DEFAULT ''
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_active ON sessions(user_id) WHERE revoked_at IS NULL;

ALTER TABLE users ADD COLUMN role_id UUID REFERENCES roles(id);

INSERT INTO roles (code, name, is_master, is_system) VALUES
    ('MASTER', 'Master', TRUE, TRUE),
    ('SEM_ACESSO', 'Sem acesso', FALSE, TRUE);

-- Backfill: rows created before this migration predate RBAC entirely (e.g. the
-- bootstrap admin from SeedAdmin on a pre-existing dev DB). Grandfather them into
-- MASTER rather than leaving role_id NULL or silently locking them out.
UPDATE users SET role_id = (SELECT id FROM roles WHERE code = 'MASTER') WHERE role_id IS NULL;

ALTER TABLE users ALTER COLUMN role_id SET NOT NULL;
CREATE INDEX idx_users_role_id ON users(role_id);
