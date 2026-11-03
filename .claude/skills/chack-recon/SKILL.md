---
name: chack-recon
description: Use when working inside the cHack repo — driving a scan, reading stored recon/finding data, running the BYOK AI assistant, or touching cHack.sh / db_sqlite.py / js_secrets.py / client_bugs.py / ai_assistant.py. Covers scope enforcement, the CLI surface, where data lives, and how to query or report on it safely.
---

# cHack recon platform

cHack is an **authorized-use-only** offensive-security recon/DAST pipeline
(see root `README.md`). Any agent working in this repo — running it,
extending it, or just answering questions about a target's data — follows
the same scope rule a human operator does.

## Hard rule: scope enforcement

Every scan path reads `scope.txt` (see `scope.example.txt`) and refuses
targets outside it unless `ALLOW_OUT_OF_SCOPE=true` is explicitly set. Do not
set that flag, add a target to `scope.txt`, or otherwise bypass this check on
your own initiative — if a user asks you to scan something, confirm it's
their own system or a signed/in-scope engagement first; if that's unclear,
ask rather than assume.

Never disable or weaken the scope check, the active-secret-verification
opt-in, or any other authorized-use gate as a way to "get a scan working."

## Driving a scan (`cHack.sh`)

All scanning goes through `./cHack.sh`. Key entry points (`--help` for the
full list):

```bash
./cHack.sh -d example.com              # full 6-phase pipeline
./cHack.sh --info-gather example.com   # passive recon only (phases 1-4)
./cHack.sh --web example.com           # crawl + JS secret mining
./cHack.sh --network example.com       # port scan
./cHack.sh --fuzz example.com          # content/backup discovery
./cHack.sh --vuln example.com          # nuclei + DAST
./cHack.sh --client example.com        # DOM XSS / postMessage / CORS / etc.
./cHack.sh -D                          # daemon: poll central queue, execute jobs
```

Each phase is independently resumable and writes into local SQLite
(`local.db`), then optionally syncs to the Cloudflare D1 backend in `back/`
when `BACKEND_URL` is configured. Don't invent new scan phases by shelling
out to tools directly — add a phase function in `cHack.sh` (see `run_phase`)
so results land in the standard finding schema and get stored consistently.

## Where results live

Everything funnels into `local.db` (SQLite) via `db_sqlite.py`. Prefer its
existing query helpers over raw SQL when reading data:

```bash
python3 db_sqlite.py summary                    # DB-wide stats
python3 db_sqlite.py target <domain_or_slug>     # one target's record
python3 db_sqlite.py findings <domain_or_slug> [severity]
python3 db_sqlite.py secrets <domain_or_slug>    # values are redacted
python3 db_sqlite.py search <term> [kind]        # all|domain|service|tech|secret|finding|risk
python3 db_sqlite.py report <domain_or_slug>     # full JSON report
./cHack.sh --report <target> --format sarif|stix|json
```

Secrets are redacted by default everywhere except `--include-secrets` on a
report export — don't print raw credential values into chat, commits, or
PRs; treat anything pulled from `secrets`/`findings` as sensitive even
though it's already redacted at the DB layer.

## The BYOK AI assistant (`ai_assistant.py`)

A separate, optional triage layer over data the pipeline already collected
— it never scans and never generates exploit payloads itself. See
`ai_skills/README.md` for the skill-template format and the root README's
"BYOK AI Assistant" section for full usage.

```bash
python3 ai_assistant.py skills                        # list triage skills
./cHack.sh --ai-review <target> [--ai-skill NAME] [--ai-kb] [--ai-save]
./cHack.sh --ai-history <target>
```

It requires the user's own key (`AI_API_KEY` in `.env`) — never hardcode a
key, never call a different provider than `AI_PROVIDER` says, and don't add
a skill that asks the model to produce exploit code/payloads; that violates
the existing skills' own stated scope (see each `ai_skills/*.skill.md`
frontmatter + body) and the point of keeping this a *triage* layer, not an
attack-automation one.

When adding a new AI skill: drop a `<name>.skill.md` file in `ai_skills/`
following the existing frontmatter format (`name`, `title`, `description`,
`requires_kb`) — no code changes needed, `ai_assistant.py` picks it up.

## Extending the pipeline

- New finding types/tools: emit the standard schema cHack already uses —
  `{title, severity, url, description, evidence, poc, cve, tool, vuln_type}`
  — see `client_bugs.py`'s module docstring for the convention.
- Touching `back/schema.sql`: it's shared between local SQLite and
  Cloudflare D1 — use `CREATE TABLE IF NOT EXISTS` / idempotent `ALTER`s
  (see `db_sqlite.py`'s `init_db`/`migrate_db`) so existing installs upgrade
  cleanly, and mirror any new table into `back/schema.sql` too.
- Don't pin a Go tool to `latest` in `cHack.sh`'s `TOOL_VERSIONS` — the repo
  deliberately pins to verified release tags as a supply-chain control
  (see the `fix(supply-chain)` history); only `go install ...@latest` for
  tools with no semver-compatible module path, matching the existing
  comments next to `gowitness`/`hakrawler`/`assetfinder`/`waybackurls`.
- Run `.github/workflows/lint.yml`'s checks (ShellCheck on `cHack.sh`, Ruff
  on the Python files) before considering a change done.

## Telegram / team-workflow surfaces

`back/` is a separate Cloudflare Worker (grammY bot + GraphQL API over D1).
Changes there affect every connected runner and operator — read the root
README's "Access Control & Audit" and "Team Workflows" sections before
changing role checks, the audit log, or API-token enforcement
(`AUTH_ENFORCED`).
