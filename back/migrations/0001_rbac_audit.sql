-- Migration 0001: role-based access and audit controls.
--
-- Apply this ONCE to an EXISTING Cloudflare D1 database that predates RBAC.
-- Fresh databases do not need it — back/schema.sql already creates every table
-- and column below. Local SQLite runners migrate themselves automatically on
-- `db_sqlite.py init` and should NOT run this file.
--
--   wrangler d1 execute <DB_NAME> --remote --file=back/migrations/0001_rbac_audit.sql
--
-- NOTE: SQLite/D1 has no "ADD COLUMN IF NOT EXISTS", so run this exactly once.
-- If a column already exists the statement errors; that is expected and means
-- the migration (or a newer schema.sql) was already applied.

-- 1. Global role on users (NULL/'pending' = registered but not yet granted).
ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'pending';

-- 2. Attribution and scope on queued scans.
ALTER TABLE scan_jobs ADD COLUMN requested_by TEXT;
ALTER TABLE scan_jobs ADD COLUMN requested_by_number_id INTEGER;
ALTER TABLE scan_jobs ADD COLUMN company_id TEXT;
ALTER TABLE scan_jobs ADD COLUMN source TEXT DEFAULT 'telegram';

CREATE INDEX IF NOT EXISTS idx_scan_jobs_requested_by ON scan_jobs(requested_by);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_company_id ON scan_jobs(company_id);

-- 3. Team membership (per-user/team target scope).
CREATE TABLE IF NOT EXISTS team_members (
  id TEXT PRIMARY KEY,
  company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'operator',
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS team_members_company_user_uq ON team_members(company_id, user_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user_id ON team_members(user_id);
CREATE INDEX IF NOT EXISTS idx_team_members_company_id ON team_members(company_id);

-- 4. Append-only audit log.
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  actor_number_id INTEGER,
  actor_label TEXT,
  source TEXT NOT NULL DEFAULT 'telegram',
  action TEXT NOT NULL,
  decision TEXT NOT NULL DEFAULT 'allow',
  target_type TEXT,
  target TEXT,
  company_id TEXT REFERENCES companies(id) ON DELETE SET NULL,
  detail TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor_number_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_company_id ON audit_log(company_id);
