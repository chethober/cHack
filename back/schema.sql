-- SQLite schema for Cloudflare D1 and local SQLite (local.db)

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, -- store uuid as text
  username TEXT NOT NULL UNIQUE,
  number_id INTEGER UNIQUE, -- bigint is INTEGER in SQLite
  first_name TEXT,
  last_name TEXT,
  -- Global role for RBAC. NULL/'pending' = registered but not yet granted access.
  -- Hierarchy (ascending): pending < viewer < operator < admin. Superadmins are
  -- defined out-of-band via the ADMIN_IDS worker secret and always outrank this.
  role TEXT DEFAULT 'pending',
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Companies table
CREATE TABLE IF NOT EXISTS companies (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  slug TEXT UNIQUE,
  description TEXT,
  data TEXT DEFAULT '{}', -- json as text
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Domains table
CREATE TABLE IF NOT EXISTS domains (
  id TEXT PRIMARY KEY,
  company_id TEXT REFERENCES companies(id) ON DELETE CASCADE,
  host TEXT NOT NULL,
  canonical_url TEXT,
  data TEXT DEFAULT '{}',
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS domains_company_host_uq ON domains(company_id, lower(host));
CREATE INDEX IF NOT EXISTS idx_domains_company_id ON domains(company_id);

-- People table
CREATE TABLE IF NOT EXISTS people (
  id TEXT PRIMARY KEY,
  company_id TEXT REFERENCES companies(id) ON DELETE CASCADE,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  given_name TEXT,
  family_name TEXT,
  emails TEXT DEFAULT '[]', -- JSON array of emails (SQLite doesn't support TEXT[])
  phones TEXT DEFAULT '[]', -- JSON array of phones (SQLite doesn't support TEXT[])
  notes TEXT,
  data TEXT DEFAULT '{}',
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_people_company_id ON people(company_id);

-- Scan jobs table (asynchronous queue for runner)
CREATE TABLE IF NOT EXISTS scan_jobs (
  id TEXT PRIMARY KEY,
  command TEXT NOT NULL,
  domain TEXT NOT NULL,
  runner TEXT DEFAULT 'default', -- target runner (e.g. VPS-US)
  status TEXT NOT NULL DEFAULT 'pending', -- pending, running, completed, failed
  stdout TEXT DEFAULT '',
  requested_by TEXT REFERENCES users(id) ON DELETE SET NULL, -- who queued the scan
  requested_by_number_id INTEGER, -- Telegram id of requester (denormalized for audit)
  company_id TEXT REFERENCES companies(id) ON DELETE SET NULL, -- team scope the target belongs to
  source TEXT DEFAULT 'telegram', -- telegram | cli | tui | daemon
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_requested_by ON scan_jobs(requested_by);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_company_id ON scan_jobs(company_id);

-- Sessions table (persists Telegram bot state)
CREATE TABLE IF NOT EXISTS sessions (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Registered runners heartbeat tracking table
CREATE TABLE IF NOT EXISTS runners (
  name TEXT PRIMARY KEY,
  ip TEXT,
  country TEXT,
  last_seen INTEGER NOT NULL -- Unix timestamp in seconds
);

-- Findings table (Vulnerabilities, misconfigurations, takeover, CVEs)
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  domain_id TEXT REFERENCES domains(id) ON DELETE CASCADE,
  company_id TEXT REFERENCES companies(id) ON DELETE CASCADE,
  tool TEXT NOT NULL,
  severity TEXT NOT NULL, -- critical, high, medium, low, info
  vuln_type TEXT NOT NULL, -- xss, sqli, takeover, secret, cve, cors, exposure, idor, ssrf, etc.
  title TEXT NOT NULL,
  url TEXT,
  description TEXT,
  evidence TEXT,
  poc TEXT,
  cve TEXT,
  status TEXT NOT NULL DEFAULT 'open', -- open, verified, false_positive, resolved
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_domain_id ON findings(domain_id);
CREATE INDEX IF NOT EXISTS idx_findings_company_id ON findings(company_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_vuln_type ON findings(vuln_type);

-- Discovered Endpoints / URLs table
CREATE TABLE IF NOT EXISTS endpoints (
  id TEXT PRIMARY KEY,
  domain_id TEXT REFERENCES domains(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  method TEXT DEFAULT 'GET',
  params TEXT DEFAULT '[]', -- JSON array of parameter names
  status_code INTEGER,
  content_type TEXT,
  source TEXT, -- katana, gau, waymore, hakrawler, etc.
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_endpoints_domain_id ON endpoints(domain_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_url ON endpoints(url);

-- Discovered Secrets & Leaks table (JS analysis, git/env exposure)
CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  domain_id TEXT REFERENCES domains(id) ON DELETE CASCADE,
  rule_name TEXT NOT NULL,
  secret_type TEXT NOT NULL,
  match_snippet TEXT NOT NULL,
  file_url TEXT,
  severity TEXT NOT NULL DEFAULT 'high', -- critical, high, medium, low
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_secrets_domain_id ON secrets(domain_id);
CREATE INDEX IF NOT EXISTS idx_secrets_rule_name ON secrets(rule_name);

-- Network Services & Port Scan table
CREATE TABLE IF NOT EXISTS network_services (
  id TEXT PRIMARY KEY,
  domain_id TEXT REFERENCES domains(id) ON DELETE CASCADE,
  ip TEXT NOT NULL,
  port INTEGER NOT NULL,
  protocol TEXT DEFAULT 'tcp',
  service TEXT,
  product TEXT,
  version TEXT,
  banner TEXT,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_net_services_domain_id ON network_services(domain_id);
CREATE INDEX IF NOT EXISTS idx_net_services_ip_port ON network_services(ip, port);


-- ===========================================================================
-- RBAC & Audit (role-based access and audit controls)
-- ===========================================================================

-- Team membership: binds a user to a company (= team) with a per-team role.
-- This is the unit of "per-user/team target scope": an operator may only act
-- on domains belonging to companies they are a member of. A user may belong to
-- many teams with different roles. Global users.role still applies on top (an
-- admin/superadmin bypasses team-scope checks entirely).
CREATE TABLE IF NOT EXISTS team_members (
  id TEXT PRIMARY KEY,
  company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'operator', -- viewer | operator | admin (scoped to this team)
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS team_members_company_user_uq ON team_members(company_id, user_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user_id ON team_members(user_id);
CREATE INDEX IF NOT EXISTS idx_team_members_company_id ON team_members(company_id);

-- Audit log: append-only record of scans and sensitive actions across every
-- surface (Telegram, CLI, TUI, runner daemon). Never updated or deleted by the
-- app itself; retention/rotation is an operator concern.
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  actor_number_id INTEGER,       -- Telegram id (or 0/NULL for local shell actors)
  actor_label TEXT,              -- human-readable actor (username / OS user)
  source TEXT NOT NULL DEFAULT 'telegram', -- telegram | cli | tui | daemon
  action TEXT NOT NULL,          -- e.g. scan.recon, scan.web, role.grant, db.reset, access.denied
  decision TEXT NOT NULL DEFAULT 'allow', -- allow | deny
  target_type TEXT,              -- domain | person | company | user | db | job
  target TEXT,                   -- the value acted on (domain/host/name/id)
  company_id TEXT REFERENCES companies(id) ON DELETE SET NULL, -- scope, when known
  detail TEXT DEFAULT '{}'       -- JSON blob: reason, job_id, old/new role, etc.
);

CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor_number_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_company_id ON audit_log(company_id);
