# cHack Recon Platform

A lightweight distributed reconnaissance platform featuring a Telegram + GraphQL backend deployed on Cloudflare Workers, a local scan runner daemon, and the main cHack automated recon script.

---

## 🛠️ Main Components

1. **Cloudflare Workers Backend** (`back/`)
   - GraphQL API (Hono + GraphQL Yoga) for recording target, scan, and host details.
   - Telegram Bot interface (grammY) for control, scan updates, and target management.
   - Cloudflare D1 Serverless SQL Database.
2. **Local Runner Daemon** (`runner.js`)
   - Polls the backend for queued scan jobs.
   - Executes scans via `cHack.sh` on the local machine/VPS.
   - Syncs logs and updates job status back to the backend.
3. **Recon Script** (`cHack.sh`)
   - Multi-phase automated subdomain takeover, HTTP probing, port scanning, link crawling, and vulnerability scanning.
   - Synchronizes scan metrics back to the central backend.

---

## 🚀 One-Liner Start & Deployment Commands

### 1. Central Backend (Cloudflare Workers)
Run these commands from the `back/` directory:

*   **Install Dependencies:**
    ```bash
    npm install
    ```
*   **Initialize Local D1 DB (Development):**
    ```bash
    npm run d1:init
    ```
*   **Start Local Dev Server:**
    ```bash
    npm run dev
    ```
*   **Deploy Backend to Production:**
    ```bash
    npm run deploy
    ```

### 2. Local Runner Daemon & Recon Script
Run from the workspace root:

*   **Start Runner Daemon (Central Queue Polling):**
    ```bash
    ./cHack.sh
    ```
    *(Ensure `.env` contains `BACKEND_URL` and `RUNNER_NAME`)*

*   **Install Binary Dependencies (Go):**
    ```bash
    ./req.sh
    ```
*   **Start a Scan Manually:**
    ```bash
    ./cHack.sh -d <domain>
    ```

---

## 📝 Configuration (`.env`)
Create a `.env` file in the root directory:
```env
BACKEND_URL=http://localhost:8787
RUNNER_NAME=VPS-1
TELEGRAM_BOT_TOKEN=your_bot_token
ADMIN_IDS=your_admin_id
```
