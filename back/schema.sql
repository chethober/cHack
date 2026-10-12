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
  runner TEXT DEFAULT 'default', -- target runner name, or 'default' for any runner
  region TEXT,                   -- preferred runner region (ISO country, e.g. 'US'); NULL = any region
  priority INTEGER NOT NULL DEFAULT 0, -- higher runs first (e.g. 10 for high-value targets)
  status TEXT NOT NULL DEFAULT 'pending', -- pending, running, completed, failed, blocked, skipped
  stdout TEXT DEFAULT '',
  -- Runner orchestration columns
  attempts INTEGER NOT NULL DEFAULT 0,     -- how many times this job has been dispatched
  max_attempts INTEGER NOT NULL DEFAULT 3, -- give up (mark failed) after this many attempts
  next_eligible_at INTEGER NOT NULL DEFAULT 0, -- Unix ts; job is not dispatchable before this (retry backoff)
  assigned_runner TEXT,          -- runner currently holding the job (for stale-lease reclaim)
  started_at INTEGER,            -- Unix ts the current run was dispatched (lease start)
  -- Task dependency graph (DAG) columns
  job_type TEXT,                 -- phase name: subdomain_enum, httpx, naabu, katana, nuclei, ...
  pipeline_id TEXT,              -- groups every job spawned from one recon run
  parent_id TEXT,                -- the job whose completion spawned this one
  result TEXT DEFAULT '{}',      -- JSON summary the phase emits (e.g. {"open_ports":[443]})
  depends_on TEXT DEFAULT '[]',  -- JSON array of job ids that must complete before this runs (fan-in)
  -- RBAC / audit columns
  requested_by TEXT REFERENCES users(id) ON DELETE SET NULL, -- who queued the scan
  requested_by_number_id INTEGER, -- Telegram id of requester (denormalized for audit)
  company_id TEXT REFERENCES companies(id) ON DELETE SET NULL, -- team scope the target belongs to
  source TEXT DEFAULT 'telegram', -- telegram | cli | tui | daemon
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Dispatch ordering: pending jobs, highest priority then oldest first.
CREATE INDEX IF NOT EXISTS idx_scan_jobs_dispatch
  ON scan_jobs(status, priority DESC, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_pipeline ON scan_jobs(pipeline_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);

-- Trigger rules table (the dependency graph, stored as editable data)
-- When a job of `on_job_type` completes, its result JSON is tested against the
-- condition; if it passes, a child job of `spawn_job_type` is enqueued.
CREATE TABLE IF NOT EXISTS trigger_rules (
  id TEXT PRIMARY KEY,
  on_job_type TEXT NOT NULL,              -- parent phase that fires this rule
  cond_key TEXT NOT NULL DEFAULT '',      -- key looked up in the parent's result JSON
  cond_op TEXT NOT NULL DEFAULT 'always', -- always | exists | eq | gt | gte | contains
  cond_value TEXT DEFAULT '',             -- compared value (numeric for gt/gte)
  spawn_job_type TEXT NOT NULL,           -- child phase to enqueue when the condition holds
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_trigger_rules_on ON trigger_rules(on_job_type);

-- Default dependency graph:
--   subdomain_enum --(subdomains>0)--> httpx
--   httpx --(live_hosts>0)--> naabu, katana
--   naabu --(open_ports contains 443)--> httpx_fingerprint
--   katana --(endpoints>0)--> nuclei
INSERT OR IGNORE INTO trigger_rules (id, on_job_type, cond_key, cond_op, cond_value, spawn_job_type) VALUES
  ('rule_sub_httpx',    'subdomain_enum', 'subdomains', 'gt',       '0',   'httpx'),
  ('rule_httpx_naabu',  'httpx',          'live_hosts', 'gt',       '0',   'naabu'),
  ('rule_httpx_katana', 'httpx',          'live_hosts', 'gt',       '0',   'katana'),
  ('rule_naabu_fp',     'naabu',          'open_ports', 'contains', '443', 'httpx_fingerprint'),
  ('rule_katana_nuclei','katana',         'endpoints',  'gt',       '0',   'nuclei');

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


-- ====================================================================
-- Continuous Attack-Surface Monitoring
-- ====================================================================

-- Recurring scan schedules (consumed by the Cloudflare Worker cron trigger).
CREATE TABLE IF NOT EXISTS monitors (
  id TEXT PRIMARY KEY,
  owner_chat_id INTEGER NOT NULL,              -- Telegram chat/user id to alert
  target_type TEXT NOT NULL DEFAULT 'domain',  -- domain | company | network
  target TEXT NOT NULL,                         -- domain, company slug/name, or IP/CIDR
  scan_type TEXT NOT NULL DEFAULT 'infogather', -- recon | infogather | web | network
  runner TEXT NOT NULL DEFAULT 'default',
  interval_minutes INTEGER NOT NULL DEFAULT 1440, -- cadence between runs
  enabled INTEGER NOT NULL DEFAULT 1,
  last_run_at TEXT,
  next_run_at TEXT,
  last_job_id TEXT,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_monitors_due ON monitors(enabled, next_run_at);
CREATE INDEX IF NOT EXISTS idx_monitors_owner ON monitors(owner_chat_id);

-- Rolling attack-surface inventory (runner-local drift baseline).
-- One row per distinct asset ever seen for a target; drift = assets whose
-- asset_key is not yet present when a fresh scan completes.
CREATE TABLE IF NOT EXISTS surface_assets (
  id TEXT PRIMARY KEY,
  target TEXT NOT NULL,               -- normalized monitor/scan target key
  asset_kind TEXT NOT NULL,          -- subdomain | port | tls_cert | cloud_asset
  asset_key TEXT NOT NULL,           -- canonical identity of the asset
  asset_meta TEXT DEFAULT '{}',      -- JSON details (ip, provider, SANs, expiry, ...)
  first_seen TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  last_seen TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS surface_assets_uq ON surface_assets(target, asset_kind, asset_key);
CREATE INDEX IF NOT EXISTS idx_surface_assets_target ON surface_assets(target, asset_kind);

-- Detected drift between runs (alert history / audit feed).
CREATE TABLE IF NOT EXISTS drift_events (
  id TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  scan_type TEXT,
  asset_kind TEXT NOT NULL,          -- subdomain | port | tls_cert | cloud_asset
  change_type TEXT NOT NULL DEFAULT 'new',
  asset_key TEXT NOT NULL,
  asset_meta TEXT DEFAULT '{}',
  alerted INTEGER NOT NULL DEFAULT 0,
  detected_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_drift_events_target ON drift_events(target, detected_at);

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
