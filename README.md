# cHack

An automated, multi-phase reconnaissance and vulnerability assessment platform featuring an interactive TUI, CLI automation, and central Telegram bot orchestration.

> ⚠️ **Authorized use only.** cHack is an offensive security tool. Only run it against
> systems you own or are explicitly authorized to test (e.g. an in-scope bug-bounty
> program or a signed engagement). Unauthorized scanning may be illegal. You are solely
> responsible for how you use it.

---

## 🏗️ Architecture

cHack is a distributed recon system with three parts:

```
   Telegram ──► Cloudflare Worker ──► D1 (cloud DB)
   (operator)     (back/, job queue)        ▲
                         │                   │ sync
                         ▼                   │
                  VPS runners  ◄─────────────┘
                  (cHack.sh --daemon)
                   └─ local SQLite (local.db) via db_sqlite.py
```

- **`back/`** — a Cloudflare Worker (grammY Telegram bot + GraphQL) that receives
  operator commands and holds the central job queue in Cloudflare D1.
- **`cHack.sh`** — the recon engine. Runs standalone (TUI/CLI) or as a `--daemon`
  that polls the central queue for jobs and reports results back.
- **`db_sqlite.py`** — each runner's local SQLite store, synced up to D1.
- **`js_secrets.py`** — JS secret/credential scanner used by the web-recon phase.

---

## ⚡ 1-Liner VPS Install

Run on any Ubuntu/Debian/Linux VPS:

```bash
git clone https://github.com/chethober/cHack.git && cd cHack && chmod +x install.sh cHack.sh && ./install.sh
```

> **Note**: For GitHub CLI users with SSH/auth configured:
> ```bash
> gh repo clone chethober/cHack && cd cHack && chmod +x install.sh cHack.sh && ./install.sh
> ```

---

## 🚀 Quick Usage

### Interactive TUI
```bash
./cHack.sh
# or
./cHack.sh -i
```

### CLI Commands
```bash
# Full Recon Pipeline (Phases 1-6)
./cHack.sh -d example.com

# Information Gathering (Subdomains + Live Probing)
./cHack.sh --info-gather example.com

# Web Crawling & JS Secret Analysis
./cHack.sh --web example.com

# Port & Network Scan
./cHack.sh --network 192.168.1.1/24

# Directory & Sensitive File Fuzzing
./cHack.sh --fuzz example.com

# Vulnerability Scanning (Nuclei)
./cHack.sh --vuln example.com

# Start Runner Daemon (Polls Central Queue)
./cHack.sh --daemon
```

---

## 🤖 Telegram Bot

| Command | Description |
| :--- | :--- |
| `/start` | Open interactive control menu |
| `/recon <domain>` | Launch full automated recon pipeline |
| `/infogather <domain>` | Subdomain discovery & live probing |
| `/web <domain>` | Web crawling & JS secret extraction |
| `/network <target>` | Port and network service scan |
| `/vulns [domain]` | List discovered vulnerabilities |
| `/secrets [domain]` | List leaked API keys & tokens |
| `/ports [domain]` | List open ports & network services |
| `/report <domain>` | Generate executive recon summary |
| `/tools` | Check tool health and status |
| `/stop <job_id>` | Stop an active scan job |

---

## ⚙️ Configuration

Copy template to `.env` and set your credentials:

```bash
cp .env.example .env
nano .env
```

```env
BACKEND_URL=https://your-backend.workers.dev
TELEGRAM_BOT_TOKEN=your_bot_token
ADMIN_IDS=your_telegram_id
RUNNER_NAME=VPS-1
```

For the Cloudflare Worker's local secrets, copy the template too:

```bash
cp back/.dev.vars.example back/.dev.vars
# then fill in your real token — back/.dev.vars is git-ignored
```

For a deployed Worker, set the token and admin IDs as **secrets** (never in `wrangler.json`):

```bash
cd back
wrangler secret put TELEGRAM_BOT_TOKEN
wrangler secret put ADMIN_IDS
```

> 🔒 **Never commit real tokens.** `.env` and `back/.dev.vars` are git-ignored on
> purpose. If a token is ever committed, revoke it immediately (BotFather `/revoke`)
> and rotate it — removing the file is not enough once it is in git history.

---

## 📄 License

[MIT](LICENSE) © Cheth
