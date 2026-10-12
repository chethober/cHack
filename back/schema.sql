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
  status TEXT NOT NULL DEFAULT 'pending', -- pending, running, completed, failed, blocked, skipped
  stdout TEXT DEFAULT '',
  -- Task dependency graph (DAG) columns
  job_type TEXT,                 -- phase name: subdomain_enum, httpx, naabu, katana, nuclei, ...
  pipeline_id TEXT,              -- groups every job spawned from one recon run
  parent_id TEXT,                -- the job whose completion spawned this one
  result TEXT DEFAULT '{}',      -- JSON summary the phase emits (e.g. {"open_ports":[443]})
  depends_on TEXT DEFAULT '[]',  -- JSON array of job ids that must complete before this runs (fan-in)
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

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

