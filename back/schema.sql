-- SQLite schema for Cloudflare D1 and local SQLite (local.db)

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, -- store uuid as text
  username TEXT NOT NULL UNIQUE,
  number_id INTEGER UNIQUE, -- bigint is INTEGER in SQLite
  first_name TEXT,
  last_name TEXT,
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
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

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
