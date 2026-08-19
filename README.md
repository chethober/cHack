# cHack Recon Platform (Reconner Edition)

A distributed reconnaissance and vulnerability assessment platform featuring a Telegram + GraphQL backend deployed on Cloudflare Workers (D1 SQLite), a local scan runner daemon, and the upgraded `cHack.sh` automated recon pipeline (imported and integrated from Reconner).

---

## 🛠️ Main Components

1. **Cloudflare Workers Backend** (`back/`)
   - GraphQL API (Hono + GraphQL Yoga) with schemas for Targets, Domains, Findings, Secrets, Endpoints, and Network Services.
   - Interactive Telegram Bot (grammY) with direct commands (`/recon`, `/infogather`, `/web`, `/network`, `/vulns`, `/secrets`, `/ports`, `/report`, `/tools`, `/stop`) and inline menus.
   - Cloudflare D1 Serverless SQL Database with automated migrations.
2. **Local Runner Daemon & DB Sync** (`db_sqlite.py` & `cHack.sh`)
   - Polls the backend for queued scan jobs.
   - Synchronizes scan metrics, findings, endpoints, and secrets back to Cloudflare D1 and local SQLite.
3. **Multi-Phase Recon Script** (`cHack.sh` & `js_secrets.py`)
   - **Phase 1: Subdomain Discovery & Takeover**: `subfinder`, `assetfinder`, `findomain`, `gau`, `alterx`, `subzy`.
   - **Phase 2: Live HTTP Probing & Visual Recon**: `httpx`, `gowitness`.
   - **Phase 3: Port & Network Service Audit**: `naabu`, `nmap`.
   - **Phase 4: Web Crawling & JS Secret Analysis**: `katana`, `hakrawler`, `waymore`, `uro`, `js_secrets.py`.
   - **Phase 5: Directory & Sensitive Content Fuzzing**: `feroxbuster`, `dirsearch`, backup exposure scans.
   - **Phase 6: Vulnerability & DAST Scanning**: `nuclei` (v3), `dalfox`, `sqlmap`.

---

## 🚀 Usage & Commands

### Interactive TUI & CLI Workflows (`cHack.sh`)
```bash
# Launch Interactive Terminal User Interface (TUI)
./cHack.sh
# or explicitly:
./cHack.sh -i
./cHack.sh --tui

# Full Reconnaissance Pipeline (Phases 1-6)
./cHack.sh -d example.com

# Targeted Information Gathering (Phases 1-4)
./cHack.sh --info-gather example.com

# Web Recon & Crawling
./cHack.sh --web example.com

# Port & Network Service Auditing
./cHack.sh --network 192.168.1.1/24

# Directory & Sensitive File Discovery
./cHack.sh --fuzz example.com

# Vulnerability & DAST Scan (Nuclei)
./cHack.sh --vuln example.com

# Start Runner Daemon (polls central Cloudflare queue)
./cHack.sh --daemon
```

### Telegram Bot Commands
| Command | Description |
| :--- | :--- |
| `/start` | Open interactive main menu |
| `/recon <domain>` | Queue full recon scan |
| `/infogather <domain>` | Queue non-intrusive information gathering |
| `/web <domain>` | Queue web recon & crawling |
| `/network <target>` | Queue port & network scan |
| `/vulns [domain]` | List discovered vulnerabilities grouped by severity |
| `/secrets [domain]` | List leaked API keys & secrets from JS bundles |
| `/ports [domain]` | List open ports & network services |
| `/report <domain>` | Generate executive recon summary |
| `/tools` | List all integrated tools |
| `/stop <job_id>` | Cancel/stop an active scan job |

---

## 📝 Configuration (`.env`)
```env
BACKEND_URL=http://localhost:8787
RUNNER_NAME=VPS-1
TELEGRAM_BOT_TOKEN=your_bot_token
ADMIN_IDS=your_admin_id
```

