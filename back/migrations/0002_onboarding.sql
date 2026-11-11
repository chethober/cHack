-- Phase 1 autonomous onboarding: candidate programs + human-decision gate.
-- Idempotent; mirrors the bb_programs / pending_approvals block in schema.sql.
CREATE TABLE IF NOT EXISTS bb_programs (
  id TEXT PRIMARY KEY,
  platform TEXT NOT NULL DEFAULT 'manual',
  handle TEXT,
  name TEXT,
  url TEXT,
  scope_raw TEXT,
  roe_raw TEXT,
  scope_parsed TEXT DEFAULT '{}',
  roe_flags TEXT DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'new',
  last_seen_hash TEXT,
  company_id TEXT REFERENCES companies(id) ON DELETE SET NULL,
  created_by INTEGER,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS bb_programs_platform_handle_uq ON bb_programs(platform, lower(handle));
CREATE INDEX IF NOT EXISTS idx_bb_programs_status ON bb_programs(status);

CREATE TABLE IF NOT EXISTS pending_approvals (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL DEFAULT 'onboard',
  program_id TEXT REFERENCES bb_programs(id) ON DELETE CASCADE,
  payload TEXT DEFAULT '{}',
  chat_id INTEGER,
  message_id INTEGER,
  status TEXT NOT NULL DEFAULT 'pending',
  decision TEXT,
  decided_by INTEGER,
  decided_at TEXT,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_pending_approvals_status ON pending_approvals(status);
CREATE INDEX IF NOT EXISTS idx_pending_approvals_program ON pending_approvals(program_id);
