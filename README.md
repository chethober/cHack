# cHack

An automated, multi-phase reconnaissance and vulnerability assessment platform featuring an interactive TUI, CLI automation, and central Telegram bot orchestration.

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
