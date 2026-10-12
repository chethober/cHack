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
- **Distributed runners** — point many VPS runners at one central queue; jobs are load-shared.
- **Parallel execution** — port scanning and web crawling run concurrently; tunable worker threads (`-t`).
- **JS secret mining** — dedicated scanner (`js_secrets.py`) with entropy checks, vendor filtering, false-positive suppression, tiered classification (confirmed-live / candidate / informational), and optional **active verification** that pings each provider's read-only API to confirm which credentials are actually live.
- **Central datastore** — per-runner SQLite synced to Cloudflare D1 for a single source of truth.
- **Self-provisioning** — missing Go tools are auto-installed and periodically updated.
- **Live job tracking** — stream logs, status, and executive summaries straight to Telegram.

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
