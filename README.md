# cHack

**An automated, multi-phase reconnaissance and attack-surface mapping platform** — driven from an interactive terminal UI, scripted on the CLI, or orchestrated remotely through a Telegram bot backed by a Cloudflare Worker.

cHack chains the best-in-class ProjectDiscovery / recon tooling into a single, resumable pipeline: subdomain discovery → live-host probing → port scanning → deep web crawling & JS secret mining → content/backup fuzzing → vulnerability & DAST scanning. Results stream into SQLite on each runner and sync up to a central Cloudflare D1 database you can query from Telegram.

> ⚠️ **Authorized use only.** cHack is an offensive security tool. Only run it against
> systems you own or are explicitly authorized to test (e.g. an in-scope bug-bounty
> program or a signed engagement). Unauthorized scanning may be illegal. You are solely
> responsible for how you use it.

---

## ✨ Features

- **Six-phase recon pipeline** — fully automated from a single domain to a vulnerability report.
- **Three ways to drive it** — interactive TUI, direct CLI flags, or a Telegram bot.
- **Distributed runners** — point many VPS runners at one central queue; the scheduler auto-balances by capacity, routes by region, honors per-job priority, retries failures with jittered backoff, and reclaims jobs stranded on offline nodes.
- **Parallel execution** — port scanning and web crawling run concurrently; tunable worker threads (`-t`).
- **JS secret mining** — dedicated scanner (`js_secrets.py`) with entropy checks, vendor filtering, false-positive suppression, tiered classification (confirmed-live / candidate / informational), and optional **active verification** that pings each provider's read-only API to confirm which credentials are actually live.
- **Central datastore** — per-runner SQLite synced to Cloudflare D1 for a single source of truth.
- **Self-provisioning** — missing Go tools are auto-installed and periodically updated.
- **Live job tracking** — stream logs, status, and executive summaries straight to Telegram.
- **Team workflows** — campaigns, shared target groups, job templates, and per-target playbooks, with API-token auth and roles for multi-user operation.

---

## 🏗️ Architecture

cHack is a distributed system with three cooperating parts:

```
   Telegram  ──►  Cloudflare Worker  ──►  D1 (central cloud DB)
   (operator)       (back/, job queue)            ▲
                           │                       │ sync
                           ▼                       │
                     VPS runners   ◄───────────────┘
                     (cHack.sh --daemon)
                      └─ local SQLite (local.db) via db_sqlite.py
```

- **`back/`** — a Cloudflare Worker (grammY Telegram bot + GraphQL API) that receives
  operator commands and holds the central job queue in Cloudflare D1.
- **`cHack.sh`** — the recon engine (~2.5k lines of Bash). Runs standalone (TUI/CLI) or as a
  `--daemon` that polls the central queue, executes jobs, and streams results back.
- **`db_sqlite.py`** — each runner's local SQLite store and the sync layer to D1.
- **`js_secrets.py`** — JavaScript secret/credential scanner used by the web-recon phase.

### Runner orchestration

The central queue (`back/`, Cloudflare D1) schedules work across every connected runner:

- **Auto-balance** — each runner pulls only while it has a free slot (`?slots=N`, default 1), so new work flows to idle nodes instead of piling onto busy ones.
- **Region-aware** — a job may pin a region (ISO country, e.g. `US`); it only runs on a runner in that region, and region-local jobs are preferred over unpinned ones.
- **Priority** — higher-`priority` jobs (e.g. high-value targets) are dispatched ahead of the rest; ties break by age.
- **Retries with jitter** — a failed job is requeued up to `max_attempts` (default 3) with exponential backoff plus jitter (`30s · 2^attempt`, capped at 30 min).
- **Health checks & reclaim** — runners heartbeat continuously (even mid-job); a runner silent past ~3 min is treated as offline and its in-flight jobs are requeued (or failed once attempts run out). Claims are atomic, so two runners never execute the same job.

> **Upgrading an existing deployment:** these add columns to `scan_jobs`. After deploying the Worker, hit `GET /api/db/migrate` once to apply the (idempotent) schema changes.

---

## 🔁 The Recon Pipeline

A full scan (`-d <domain>`) runs six phases; individual phases are also exposed as standalone commands.

| Phase | Stage | What it does | Key tools |
| :---: | :--- | :--- | :--- |
| **1** | Subdomain discovery | Enumerate subdomains, resolve DNS, check for takeovers | `subfinder`, `assetfinder`, `alterx`, `dnsx`, `subzy` |
| **2** | Live HTTP probing | Fingerprint live hosts, tech stack, status, titles | `httpx` |
| **3** | Port & service scan | Discover open ports and network services | `naabu` |
| **4** | Web crawl & JS secrets | Crawl, mine URLs & parameters, extract secrets from JS | `katana`, `hakrawler`, `gau`, `waybackurls`, `js_secrets.py` |
| **5** | Content discovery | Find directories, sensitive files, and backup exposures | content & backup fuzzing |
| **6** | Vulnerability & DAST | Template-based scanning and XSS assessment | `nuclei`, `dalfox` |

Phases 3 and 4 run **in parallel** to cut wall-clock time.

---

## ⚡ Install

Run on any Ubuntu/Debian/Linux VPS — the installer provisions Go, the recon toolchain, and Python deps:

```bash
git clone https://github.com/chethober/cHack.git && cd cHack && chmod +x install.sh cHack.sh && ./install.sh
```

> With GitHub CLI (SSH/auth configured):
> ```bash
> gh repo clone chethober/cHack && cd cHack && chmod +x install.sh cHack.sh && ./install.sh
> ```

### Requirements

- Linux (Ubuntu/Debian recommended), `bash`, `curl`, `jq`, `whois`
- **Go ≥ 1.23** (for the ProjectDiscovery toolchain — cHack auto-installs the Go tools)
- **Python 3**
- Optional: a Cloudflare account + `wrangler` (only for the Telegram bot / central queue)

Missing Go tools are installed automatically on first run and refreshed weekly.

---

## 🚀 Usage

### Interactive TUI
```bash
./cHack.sh            # launches the TUI when run in a terminal
./cHack.sh -i         # force the interactive menu
```

### Direct scan workflows
```bash
./cHack.sh -d example.com            # full end-to-end recon + DAST (Phases 1–6)
./cHack.sh --info-gather example.com # non-intrusive info gathering (Phases 1–4)
./cHack.sh --web example.com         # web crawling & JS secret analysis
./cHack.sh --network 192.168.1.1/24  # port & network service scan (IP / CIDR / domain)
./cHack.sh --fuzz example.com        # content & backup file discovery
./cHack.sh --vuln example.com        # vulnerability & DAST scanning
./cHack.sh -t 100 -d example.com     # tune concurrency (default: 50)
VERIFY_SECRETS=1 ./cHack.sh --web example.com  # confirm which leaked secrets are live (opt-in)
```

> ⚠️ **Active verification (`VERIFY_SECRETS=1`)** sends each matched credential to
> its provider's read-only API (e.g. `GET api.github.com/user`) to check whether it
> is live. This separates real bugs from look-alikes but transmits captured tokens
> to third parties — only enable it against targets you are explicitly authorized to
> test. It is **off** by default. The scanner can also be run directly with
> `--verify` / `--only-verified`:
> ```bash
> python3 js_secrets.py js_links out.json 50 --verify         # tier + confirm live
> python3 js_secrets.py js_links out.json 50 --only-verified  # keep only confirmed-live
> ```

### Runner daemon & sync
```bash
./cHack.sh --daemon          # poll the central queue and execute jobs
./cHack.sh --sync example.com # push on-disk scan data to D1 + local SQLite
./cHack.sh --sync-all        # sync all targets
```

### Target & entity management
```bash
./cHack.sh -c "Acme Corp"      # add a company
./cHack.sh -p "Jane Doe"       # add a person
./cHack.sh -u analyst          # add a user
./cHack.sh -h                  # full help
```

### Search & analytics
Query everything the pipeline has stored — across hosts, services, tech stack,
exposed credential patterns, findings, and a derived risk score. Available from
the TUI **Database → Search & Analytics** menu, or directly via `db_sqlite.py`:

```bash
python3 db_sqlite.py search <term> [kind]
#   kind: all (default) | domain | service | tech | secret | finding | risk | asn

python3 db_sqlite.py search cloudflare tech     # hosts fingerprinted with a tech
python3 db_sqlite.py search nginx service       # network services / products
python3 db_sqlite.py search aws secret          # exposed credential rule/type (values redacted)
python3 db_sqlite.py search takeover finding    # findings by type / CVE / title
python3 db_sqlite.py search acme domain         # hosts by name, title, or webserver
python3 db_sqlite.py search 10 risk             # targets with risk score ≥ 10 (ranked)
```

Risk score is aggregated on demand as the weighted sum of open findings and
secrets by severity (critical 10 / high 6 / medium 3 / low 1). Credential match
snippets are masked in results. ASN is not yet captured by the pipeline, so the
`asn` kind falls back to a host/service keyword match and flags the gap.

---

## 🤖 Telegram Bot

Once the Worker is deployed and a runner daemon is online, control everything from Telegram:

| Command | Description |
| :--- | :--- |
| `/start` | Open the interactive control menu |
| `/recon <domain>` | Launch the full automated recon pipeline |
| `/infogather <domain>` | Subdomain discovery & live probing |
| `/web <domain>` | Web crawling & JS secret extraction |
| `/network <target>` | Port and network service scan |
| `/vulns [domain]` | List discovered vulnerabilities |
| `/secrets [domain]` | List leaked API keys & tokens |
| `/ports [domain]` | List open ports & network services |
| `/report <domain>` | Generate an executive recon summary |
| `/tools` | Check tool health and status |
| `/stop <job_id>` | Stop an active scan job |
| `/monitor <target> [interval] [type]` | Schedule recurring scans (continuous monitoring) |
| `/monitors` | List your active monitors |
| `/unmonitor <id>` | Remove a monitor |

---

## 🛰️ Continuous Attack-Surface Monitoring

cHack can watch a target over time, re-running scans on a schedule and alerting
you the moment the attack surface *changes* — not just the first time it's mapped.

### Schedule recurring scans

From Telegram:

```
/monitor example.com 12h            # re-scan every 12 hours (info-gather)
/monitor example.com 1d recon       # full pipeline once a day
/monitor 192.0.2.0/24 6h network    # port/service sweep of a CIDR every 6h
/monitor "Acme Corp" 1d             # fan out to every known domain of a company
/monitors                           # list what you're watching
/unmonitor <id>                     # stop watching
```

- **target** — a domain, a company name/slug (expands to all its known registrable
  domains), or an IP/CIDR.
- **interval** — `30m`, `6h`, `1d`, or a bare number of minutes. Default `1d`.
- **scan_type** — `recon` · `infogather` · `web` · `network`.

Monitors are stored in the central D1 database. A **Cloudflare
[Cron Trigger](https://developers.cloudflare.com/workers/configuration/cron-triggers/)**
(`*/15 * * * *`, configured in `back/wrangler.json`) wakes the Worker, enqueues any
due monitors into the same runner job queue as manual scans, and rolls each schedule
forward. Intervals are effectively rounded up to the 15-minute tick.

> After deploying the Worker, hit `GET /api/db/migrate` once to create the
> `monitors` table on an existing database.

### Drift detection between runs

Every monitored scan (and every manual re-scan) ends by diffing the freshly-collected
surface against a rolling, runner-local baseline (`surface_assets` in `local.db`). The
first scan of a target seeds the baseline silently; later scans report only what's
**new**:

| Drift category | How it's detected |
| :--- | :--- |
| **New subdomains** | New hosts under the target's company in the local DB |
| **Newly exposed ports** | New `ip:port` pairs from the port-scan phase |
| **New TLS certificates** | New certificate serials from Certificate Transparency (crt.sh) |
| **New cloud assets** | Subdomains whose CNAME newly points at a known cloud provider (AWS/Azure/GCP/Cloudflare/Heroku/Netlify/Vercel/…) via DNS-over-HTTPS |

Each new asset is recorded in the `drift_events` table and, when the scan was launched
by a monitor, pushed to the owner's Telegram chat as a drift alert.

Drift analysis is also available directly on a runner:

```bash
python3 db_sqlite.py drift example.com infogather [telegram_chat_id]
```

TLS-cert and cloud-asset collection are best-effort (network-dependent, with timeouts)
and never produce false "removed" signals. Set `CHACK_DRIFT_CLOUD=0` to skip the
DNS-over-HTTPS cloud-asset classification.

---

## 🔐 Access Control & Audit

cHack supports multiple operators with role-based access and a tamper-evident
audit trail across every surface (Telegram, CLI/TUI, and the runner daemon).

### Roles

| Role | Capabilities |
| :--- | :--- |
| **superadmin** | Everything, incl. DB reset and granting `admin`. Defined by `ADMIN_IDS`; never stored in the DB. |
| **admin** | Manage targets/contacts, grant roles & team scopes, view the audit log. |
| **operator** | Launch scans against in-scope targets (teams they belong to, or unclaimed targets). |
| **viewer** | Read-only: dashboards, findings, reports. Cannot scan. |
| *pending* | Registered but not yet granted access. Can do nothing until promoted. |

A target's **scope** is the company (team) that owns its domain. An operator may
only scan targets belonging to a team they are a member of (admins/superadmins
bypass scope). Membership is managed per team.

> **Backward compatibility:** with `ADMIN_IDS` empty the bot stays wide-open
> (single-tenant legacy mode — every caller is treated as an admin). As soon as
> any `ADMIN_IDS` value is set, multi-user RBAC is enforced and new users start
> as *pending*.

### Management commands (Telegram)

| Command | Role | Description |
| :--- | :--- | :--- |
| `/whoami` | viewer | Show your ID, global role, and team memberships |
| `/users` | admin | List registered users and their roles |
| `/role <id> <role>` | admin¹ | Set a user's global role (`pending\|viewer\|operator\|admin`) |
| `/grant <id> <company> [role]` | admin | Add a user to a team (default team role: `operator`) |
| `/revoke <id> <company>` | admin | Remove a user from a team |
| `/members [company]` | admin | List team memberships |
| `/audit [n]` | admin | Show the last `n` audit entries (default 15, max 50) |

¹ Only a superadmin may grant or change the `admin` role.

### Audit log

Every scan and sensitive action (role/scope changes, deletions, DB reset, and
denied attempts) is appended to the `audit_log` table with actor, source,
decision (allow/deny), target, and scope. The audit log is **not** cleared by a
database reset. Local CLI/TUI and daemon scans are recorded on each runner;
Telegram actions and runner dispatch are recorded centrally in D1.

---

## 👥 Team Workflows

For client engagements and acquisition pipelines, cHack models shared work on top
of the existing company/domain data. All four pieces live in the central D1 database
(and sync to each runner's local SQLite via `back/schema.sql`):

| Concept | What it is |
| :--- | :--- |
| **Campaigns** | A client *engagement* or *acquisition* workflow grouping targets, playbooks and findings under one authorized scope. Has a status (`prospect → active → won/lost/closed`) and an `authorized` gate. |
| **Shared target groups** | Reusable, team-visible sets of domains you can scan as one unit. |
| **Job templates** | Parameterized scan definitions whose `command_template` expands `{{target}}` / `{{sender}}` into a real `cHack.sh` invocation. |
| **Per-target playbooks** | Ordered sequences of template/phase steps, optionally bound to a specific domain or group. Running one expands into one queued job per step per target. |

> 🔒 **Authorization gate.** A playbook attached to a campaign refuses to launch
> until that campaign is explicitly marked `authorized` — a deliberate guard that
> keeps scans inside a scope you've confirmed you're allowed to test.

### From Telegram

```
/campaigns                         # list campaigns
/newcampaign Acme Pentest | engagement
/groups                            # list shared target groups
/templates                         # list job templates
/playbooks                         # list playbooks
/runplaybook <slug> <target>       # expand a playbook into queued jobs
```

### From the GraphQL API

The Worker's `/graphql` endpoint exposes full CRUD for `campaigns`, `targetGroups`,
`jobTemplates` and `playbooks`, plus `runTemplate` / `runPlaybook` mutations that
queue jobs the runners pick up. See `back/src/index.js` for the schema.

### Multi-user access & roles

Programmatic access is authenticated with **API tokens** (SHA-256 hashed at rest;
the plaintext is shown only once at creation). Roles rank `admin > member > viewer`,
with a dedicated `runner` role for result-push. Per-campaign membership adds
`lead / member / viewer` on top.

Enforcement is **off by default** so existing single-operator deployments keep
working. To turn it on:

```bash
# 1. While still unenforced (bootstrap), mint an admin token via the API:
#    mutation { createApiToken(name:"me", role:"admin"){ token } }
# 2. Flip the Worker binding and redeploy:
cd back && wrangler deploy   # with AUTH_ENFORCED="true"
```

Thereafter, team-workflow mutations require `Authorization: Bearer <token>`.
Optionally set a `RUNNER_TOKEN` secret on the Worker and the matching value in each
runner's `.env` to reject unregistered runners from the job queue.

---

## ⚙️ Configuration

### Runner (`.env`)

Each runner reads its config from `.env`:

```bash
cp .env.example .env
nano .env
```

```env
BACKEND_URL=https://your-worker.workers.dev
TELEGRAM_BOT_TOKEN=your_bot_token_from_botfather
ADMIN_IDS=your_telegram_user_id
RUNNER_NAME=VPS-1
```

### Cloudflare Worker (`back/`)

For **local** development, copy the template (git-ignored):

```bash
cp back/.dev.vars.example back/.dev.vars   # then fill in your real token
```

For a **deployed** Worker, set credentials as secrets — never as plaintext `vars` in `wrangler.json`:

```bash
cd back
wrangler secret put TELEGRAM_BOT_TOKEN
wrangler secret put ADMIN_IDS
wrangler deploy
```

> 🔒 **Never commit real tokens.** `.env` and `back/.dev.vars` are git-ignored on purpose.
> If a token is ever committed, revoke it immediately (BotFather `/revoke`) and rotate it —
> removing the file is not enough once it is in git history.

---

## 📁 Project Structure

```
cHack/
├── cHack.sh              # recon engine — TUI, CLI, and runner daemon
├── js_secrets.py         # JavaScript secret/credential scanner
├── db_sqlite.py          # local SQLite store + D1 sync layer
├── install.sh            # VPS provisioning (Go, toolchain, Python deps)
├── back/                 # Cloudflare Worker: Telegram bot + GraphQL API
│   ├── src/index.js
│   ├── schema.sql
│   └── wrangler.json
├── .env.example
└── .github/workflows/    # ShellCheck + Ruff CI
```

---

## 🧪 Development

CI runs [ShellCheck](https://www.shellcheck.net/) on the shell scripts and [Ruff](https://docs.astral.sh/ruff/) on the Python on every push and PR. To check locally:

```bash
shellcheck cHack.sh install.sh
ruff check .
python3 -m py_compile js_secrets.py db_sqlite.py
```

---

## 📄 License

[MIT](LICENSE) © Cheth
