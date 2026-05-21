<div align="center">

# 🛡️ VulnGuard

### Ethical Vulnerability Scanner

**Real scan engines. AI-powered remediation. Zero mock data.**

[![Next.js 16](https://img.shields.io/badge/Next.js-16-black?logo=next.js)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Prisma](https://img.shields.io/badge/Prisma-6-2D3748?logo=prisma)](https://www.prisma.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

[Features](#-features) · [Quick Start](#-quick-start-local) · [Deployment](#-docker-deployment) · [API Reference](#-api-reference) · [Legal](#%EF%B8%8F-legal-disclaimer)

</div>

---

## 📖 Overview

VulnGuard is a full-stack ethical vulnerability scanning platform that runs **real security scans** — no simulations, no mock data. It integrates three industry-standard scan engines (Nmap, Nikto, Nuclei) behind a polished web UI and augments scan results with **AI-powered auto-remediation** that explains vulnerabilities in plain English and provides copy-paste fix commands.

Built for security engineers, penetration testers, and devops teams who need a self-hosted, one-stop dashboard for network and web vulnerability assessment.

---

## ✨ Features

| Category | Details |
|---|---|
| **3 Real Scan Engines** | Nmap (network/port), Nikto (web HTTP), Nuclei (template-based bug hunting) |
| **AI Auto-Remediation** | LLM-powered explanations, severity prioritization, step-by-step fix commands |
| **Scheduled Scans** | Hourly / daily / weekly / monthly recurring scans with pause/resume |
| **Scan History** | Persistent results in SQLite, browse past scans anytime |
| **Live Polling** | Real-time progress indicators while scans run in the background |
| **CVE Detection** | Automatic CVE extraction from all three engines with context snippets |
| **Authorization Gate** | Legal disclaimer checkbox + server-side target validation before any scan |
| **Dark-first UI** | Sleek, animated interface with Framer Motion, shadcn/ui, and Tailwind CSS |
| **Self-hosted** | Full Docker support; deploy on Fly.io, Railway, Render, or any VPS |
| **No Root Required** | Uses `nmap -sT` (TCP connect scan) — works without elevated privileges |

---

## 🧱 Tech Stack

| Layer | Technology |
|---|---|
| **Framework** | [Next.js 16](https://nextjs.org/) (App Router, standalone output) |
| **Language** | [TypeScript 5](https://www.typescriptlang.org/) |
| **Database** | [SQLite](https://www.sqlite.org/) via [Prisma 6](https://www.prisma.io/) |
| **Styling** | [Tailwind CSS 4](https://tailwindcss.com/) + [shadcn/ui](https://ui.shadcn.com/) |
| **Animation** | [Framer Motion](https://www.framer.com/motion/) |
| **AI** | [z-ai-web-dev-sdk](https://www.npmjs.com/package/z-ai-web-dev-sdk) (LLM chat completions) |
| **Scan Engines** | [Nmap](https://nmap.org/), [Nikto](https://github.com/sullo/nikto), [Nuclei](https://github.com/projectdiscovery/nuclei) |
| **Parsing** | [fast-xml-parser](https://www.npmjs.com/package/fast-xml-parser) (Nmap XML), custom CSV parser (Nikto), JSONL (Nuclei) |
| **Icons** | [Lucide React](https://lucide.dev/) |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      Browser (React)                         │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │ Scan Form │  │ Results View │  │ AI Remediation Panel │   │
│  └─────┬─────┘  └──────┬───────┘  └──────────┬───────────┘   │
│        │               │                      │               │
└────────┼───────────────┼──────────────────────┼───────────────┘
         │ POST /api/scan│ GET /api/scan/[id]   │ POST /api/
         │               │ (polling)            │ remediate
┌────────┼───────────────┼──────────────────────┼───────────────┐
│        ▼               ▼                      ▼               │
│  ┌──────────────────────────────────────────────────────┐     │
│  │              Next.js API Routes                       │     │
│  │  ┌─────────┐  ┌────────────┐  ┌──────────────────┐  │     │
│  │  │ /scan   │  │ /scan/[id] │  │ /remediate       │  │     │
│  │  └────┬────┘  └─────┬──────┘  └────────┬─────────┘  │     │
│  └───────┼─────────────┼──────────────────┼─────────────┘     │
│          │             │                  │                    │
│  ┌───────▼──────┐ ┌────▼─────┐ ┌────────▼──────────┐         │
│  │ Shell Script  │ │ Temp Dir │ │ z-ai-web-dev-sdk  │         │
│  │ (nohup bg)   │ │ /tmp/vg- │ │ LLM Completion    │         │
│  └───────┬──────┘ └────┬─────┘ └───────────────────┘         │
│          │             │                                        │
│  ┌───────▼─────────────▼──────┐                                │
│  │   Scanner Tools (system)    │                                │
│  │   nmap  ·  nikto  ·  nuclei │                                │
│  └────────────────────────────┘                                │
│                                                                │
│  ┌────────────────────────────┐                                │
│  │   SQLite (Prisma)          │                                │
│  │   Scan + Schedule models   │                                │
│  └────────────────────────────┘                                │
└────────────────────────────────────────────────────────────────┘
```

### How It Works

1. **User submits a scan** → `POST /api/scan` validates authorization, creates a DB record, and spawns a shell script via `nohup` in the background.
2. **Shell script runs independently** → The scanner binary (nmap/nikto/nuclei) executes outside the Node.js process. Output is written to temp files in `/tmp/vulnguard-scans/`.
3. **Frontend polls for results** → `GET /api/scan/[id]` checks the status file. When the scan completes, the API reads the output file, parses it (XML/CSV/JSONL), persists structured JSON to the database, and returns it.
4. **AI remediation on demand** → `POST /api/remediate` sends structured findings to an LLM which returns prioritized, actionable remediation guidance with fix commands.

---

## 🔍 Scanner Engines

### Nmap — Network & Port Scanner

| Flag | Purpose |
|---|---|
| `-sT` | TCP connect scan (no root required) |
| `-sV` | Service version detection |
| `--script vuln` | Run NSE vulnerability scripts on open ports |
| `-oX` | XML output for structured parsing |

**Execution strategy (adaptive):**

1. **Primary:** `nmap -sT -sV -oX` — service version scan with 60s host timeout
2. **Vuln pass:** `nmap -sT -sV --script vuln -oX -p <open_ports>` — CVE detection on discovered ports
3. **Fallback:** `nmap -sT -oX` — basic port scan if service detection fails

**Parsing:** Regex-based XML extraction of ports (state, service, version) and CVEs from NSE script output.

### Nikto — Web Vulnerability Scanner

| Flag | Purpose |
|---|---|
| `-h <target>` | Target host |
| `-p <port>` | Target port (default: 80) |
| `-Format csv` | CSV output for reliable parsing |
| `-C all` | Run all check modes |
| `-nointeractive` | Non-interactive mode |
| `-maxtime 90s` | 90-second scan timeout |

**Parsing:** Custom CSV parser handles quoted fields. Findings are classified by severity (high/medium/low/info) based on keyword heuristics. CVE references extracted from description and reference fields.

### Nuclei — Template-Based Bug Hunter

| Flag | Purpose |
|---|---|
| `-u <url>` | Target URL |
| `-jle <file>` | JSONL export to file |
| `-silent` | Only show findings |
| `-ot` | Omit template data (smaller output) |
| `-c 10` | 10 concurrent templates |
| `-rl 50` | Rate limit 50 req/s |

**Template categories scanned:**

- `http/cves/` — Known CVE exploits
- `http/vulnerabilities/` — Generic vulnerability detection
- `http/exposures/` — Exposed data, secrets, API keys
- `http/misconfiguration/` — Server misconfigurations
- `http/default-logins/` — Default credential detection
- `http/takeovers/` — Subdomain takeover checks

**Parsing:** Each JSONL line is parsed to extract template ID, severity, matched URL, curl reproduction command, and extracted results (e.g., leaked credentials).

---

## 🤖 AI Auto-Remediation

The remediation engine sends structured scan findings to an LLM via `z-ai-web-dev-sdk` with a specialized system prompt that enforces:

- **Plain-English explanations** of every vulnerability
- **Severity prioritization** (Critical → High → Medium → Low → Info)
- **Copy-paste fix commands** with actual values (no placeholders)
- **CVE context** — what the CVE is, CVSS impact
- **Service-specific hardening** — nginx/.htaccess configs, firewall rules
- **Secret rotation** steps for exposed credentials
- **WAF rule suggestions** for findings with curl reproduction

The response is structured JSON:

```json
{
  "summary": "Executive summary of security posture",
  "risk_level": "Critical | High | Medium | Low | Secure",
  "remediations": [
    {
      "finding": "Short title",
      "severity": "High",
      "explanation": "Plain English explanation",
      "fix_commands": ["sudo apt update && sudo apt upgrade -y"],
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXX"]
    }
  ],
  "hardening_recommendations": ["Rec 1", "Rec 2"]
}
```

---

## 📋 Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| **Node.js** | 18+ | 20+ recommended |
| **nmap** | 7.80+ | Network/port scanning |
| **nikto** | 2.5+ | Web vulnerability scanning |
| **nuclei** | 3.0+ | Template-based scanning |
| **nuclei-templates** | latest | Downloaded automatically by nuclei |

> **Note:** Scanner tools are only required on the host machine. The Docker image includes all three.

---

## 🚀 Quick Start (Local)

```bash
# 1. Clone the repository
git clone https://github.com/your-username/vulnguard.git
cd vulnguard

# 2. Install dependencies
npm install

# 3. Set up environment variables
cp .env .env.local
# Edit .env.local if needed (defaults work for local dev)

# 4. Initialize the database
npm run db:push

# 5. Start the development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) and start scanning.

---

## 🛠️ Installing Scanner Tools

### Ubuntu / Debian

```bash
# Nmap
sudo apt update && sudo apt install -y nmap

# Nikto
sudo apt install -y nikto

# Nuclei
curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o /tmp/nuclei.zip
sudo unzip /tmp/nuclei.zip -d /usr/local/bin/
sudo chmod +x /usr/local/bin/nuclei
rm /tmp/nuclei.zip

# Download nuclei templates
nuclei -update-templates
```

### macOS

```bash
# Nmap
brew install nmap

# Nikto
brew install nikto

# Nuclei
brew install nuclei
nuclei -update-templates
```

### From Source (Linux)

<details>
<summary>Build Nmap from source</summary>

```bash
wget https://nmap.org/dist/nmap-7.94.tar.bz2
tar -xjf nmap-7.94.tar.bz2
cd nmap-7.94
./configure
make
sudo make install
```

</details>

<details>
<summary>Build Nikto from source</summary>

```bash
git clone https://github.com/sullo/nikto.git /tmp/nikto
cd /tmp/nikto/program
chmod +x nikto.pl
# Add to PATH or set NIKTO_PATH env var
sudo ln -s /tmp/nikto/program/nikto.pl /usr/local/bin/nikto
```

</details>

<details>
<summary>Build Nuclei from source (Go required)</summary>

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

</details>

---

## 🔑 Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `file:./db/custom.db` | SQLite database path (Prisma connection string) |
| `NMAP_PATH` | *(auto-detected)* | Override path to nmap binary |
| `NUCLEI_TEMPLATES_DIR` | `~/nuclei-templates` | Path to nuclei template directory |
| `PORT` | `3000` | Server port |
| `NODE_ENV` | `development` | Node environment |

---

## 🐳 Docker Deployment

### Build & Run

```bash
# Build the image (includes nmap, nikto, nuclei)
docker build -t vulnguard .

# Run the container
docker run -d \
  --name vulnguard \
  -p 3000:3000 \
  -v vulnguard_data:/app/prisma/db \
  -e DATABASE_URL="file:./db/custom.db" \
  -e NUCLEI_TEMPLATES_DIR=/root/nuclei-templates \
  vulnguard
```

The Dockerfile uses a **3-stage build**:

1. **scanner-tools** — Installs nmap, nikto, nuclei, and pre-downloads templates
2. **builder** — Installs Node.js deps, generates Prisma client, builds Next.js
3. **runner** — Minimal production image with scanner binaries and standalone Next.js server

---

## ☁️ Cloud Deployment

VulnGuard includes ready-made configuration files for three platforms. All use the Dockerfile for a self-contained deployment with all scanner tools included.

### Fly.io

> **Free tier:** 3 shared-cpu-1x VMs, 160 GB bandwidth/month

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Launch (first time — uses fly.toml)
fly launch

# Create persistent volume for SQLite
fly volumes create vulnguard_data --region sin --size 1

# Set secrets
fly secrets set DATABASE_URL="file:./db/custom.db"

# Deploy
fly deploy
```

<details>
<summary>fly.toml reference</summary>

```toml
app = "vulnguard"
primary_region = "sin"

[build]
  dockerfile = "Dockerfile"

[env]
  PORT = "3000"
  DATABASE_URL = "file:./db/custom.db"
  NUCLEI_TEMPLATES_DIR = "/root/nuclei-templates"

[http_service]
  internal_port = 3000
  force_https = true
  auto_stop_machines = "stop"
  auto_start_machines = true
  min_machines_running = 0

[[mounts]]
  source = "vulnguard_data"
  destination = "/app/prisma/db"

[vm]
  cpu_kind = "shared"
  cpus = 1
  memory_mb = 512
```

</details>

### Railway

> **Free tier:** $5 credit/month

```bash
# Install Railway CLI
npm i -g @railway/cli

# Login & link
railway login
railway link

# Deploy (uses railway.json config)
railway up

# Add environment variables
railway variables set DATABASE_URL="file:./db/custom.db"
railway variables set NUCLEI_TEMPLATES_DIR="/root/nuclei-templates"
```

<details>
<summary>railway.json reference</summary>

```json
{
  "$schema": "https://railway.app/railway.schema.json",
  "build": {
    "builder": "DOCKERFILE",
    "dockerfilePath": "Dockerfile"
  },
  "deploy": {
    "startCommand": "node server.js",
    "restartPolicyType": "ON_FAILURE",
    "restartPolicyMaxRetries": 3
  }
}
```

</details>

### Render

> **Free tier:** Available with limitations

1. Connect your GitHub repository at [render.com](https://render.com)
2. Select **New → Web Service**
3. Render auto-detects the `render.yaml` blueprint
4. Set environment variables:
   - `DATABASE_URL` = `file:./db/custom.db`
   - `NUCLEI_TEMPLATES_DIR` = `/root/nuclei-templates`

<details>
<summary>render.yaml reference</summary>

```yaml
services:
  - type: web
    name: vulnguard
    runtime: docker
    plan: free
    dockerfilePath: ./Dockerfile
    envVars:
      - key: DATABASE_URL
        value: file:./db/custom.db
      - key: NUCLEI_TEMPLATES_DIR
        value: /root/nuclei-templates
      - key: PORT
        value: 3000
      - key: NODE_ENV
        value: production
```

</details>

---

## 📡 API Reference

### `POST /api/scan` — Create & Execute Scan

Starts a new vulnerability scan. The scan runs asynchronously in the background.

**Request body:**

```json
{
  "target": "scanme.nmap.org",
  "scanType": "nmap",
  "isAuthorized": true,
  "port": "80"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `target` | `string` | ✅ | IP, hostname, or CIDR range |
| `scanType` | `"nmap" \| "nikto" \| "nuclei"` | No | Default: `"nmap"` |
| `isAuthorized` | `boolean` | ✅ | Must be `true` to proceed |
| `port` | `string` | No | Target port for nikto/nuclei (default: `"80"`) |

**Response (201):**

```json
{
  "scan_id": "uuid",
  "target": "scanme.nmap.org",
  "scan_type": "nmap",
  "status": "Running",
  "message": "Nmap scan initiated. Poll GET /api/scan/[id] for results."
}
```

---

### `GET /api/scan/[id]` — Get Scan Status & Results

Poll this endpoint to check scan progress and retrieve results.

**Response (running):**

```json
{
  "id": "uuid",
  "status": "Running",
  "scan_type": "nmap",
  "target": "scanme.nmap.org"
}
```

**Response (completed):**

```json
{
  "id": "uuid",
  "status": "Completed",
  "scan_type": "nmap",
  "target": "scanme.nmap.org",
  "results": {
    "target": "scanme.nmap.org",
    "ports": [
      { "port_id": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.9" }
    ],
    "vulnerabilities": [
      { "port_id": 22, "cve_id": "CVE-2023-XXXX", "description": "..." }
    ]
  }
}
```

---

### `GET /api/scans` — List Scan History

Returns all past scans ordered by most recent first.

**Response:**

```json
{
  "scans": [
    {
      "id": "uuid",
      "target": "scanme.nmap.org",
      "scanType": "nmap",
      "status": "Completed",
      "results": "...",
      "createdAt": "2025-01-15T10:30:00.000Z",
      "updatedAt": "2025-01-15T10:31:00.000Z"
    }
  ]
}
```

---

### `POST /api/remediate` — AI Remediation

Sends scan results to the LLM for actionable remediation guidance.

**Request body:**

```json
{
  "scanResult": {
    "target": "192.168.1.1",
    "ports": [...],
    "vulnerabilities": [...]
  }
}
```

**Response:**

```json
{
  "summary": "2-3 sentence executive summary",
  "risk_level": "High",
  "remediations": [
    {
      "finding": "Outdated OpenSSH version",
      "severity": "High",
      "explanation": "The SSH server is running an outdated version...",
      "fix_commands": ["sudo apt update && sudo apt install openssh-server -y"],
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXX"]
    }
  ],
  "hardening_recommendations": ["Implement key-based SSH authentication", "..."]
}
```

---

### `GET /api/schedules` — List Schedules

Returns all scheduled scans.

### `POST /api/schedules` — Create Schedule

```json
{
  "target": "example.com",
  "scanType": "nmap",
  "port": "80",
  "frequency": "daily"
}
```

| Frequency | Description |
|---|---|
| `hourly` | Every hour |
| `daily` | Every day |
| `weekly` | Every week |
| `monthly` | Every month |

### `PUT /api/schedules?id=<uuid>` — Update Schedule

Toggles `isActive` or updates schedule parameters.

### `DELETE /api/schedules?id=<uuid>` — Delete Schedule

Removes a scheduled scan.

---

## 🗄️ Data Model

```prisma
model Scan {
  id        String   @id @default(uuid())
  target    String                         // IP, hostname, or CIDR
  scanType  String   @default("nmap")      // nmap | nikto | nuclei
  status    String   @default("Pending")   // Pending | Running | Completed | Failed
  results   String?                        // JSON stringified scan results
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}

model Schedule {
  id          String    @id @default(uuid())
  target      String                          // Domain or IP to scan
  scanType    String    @default("nmap")      // nmap | nikto | nuclei
  port        String    @default("80")        // Target port
  frequency   String                          // hourly | daily | weekly | monthly
  isActive    Boolean   @default(true)        // Pause/resume toggle
  lastRunAt   DateTime?                       // Last execution timestamp
  nextRunAt   DateTime                        // Next scheduled execution
  createdAt   DateTime  @default(now())
  updatedAt   DateTime  @updatedAt
}
```

---

## 📁 Project Structure

```
vulnguard/
├── prisma/
│   └── schema.prisma              # Database schema (Scan + Schedule models)
├── src/
│   ├── app/
│   │   ├── page.tsx               # Main UI — scan form, results, remediation
│   │   ├── layout.tsx             # Root layout
│   │   └── api/
│   │       ├── scan/
│   │       │   ├── route.ts       # POST /api/scan — create & execute scan
│   │       │   └── [id]/
│   │       │       └── route.ts   # GET /api/scan/[id] — poll status/results
│   │       ├── scans/
│   │       │   └── route.ts       # GET /api/scans — scan history
│   │       ├── remediate/
│   │       │   └── route.ts       # POST /api/remediate — AI remediation
│   │       └── schedules/
│   │           └── route.ts       # CRUD /api/schedules
│   ├── components/
│   │   └── ui/                    # shadcn/ui component library (45+ components)
│   ├── hooks/
│   │   ├── use-mobile.ts          # Mobile detection hook
│   │   └── use-toast.ts           # Toast notification hook
│   └── lib/
│       ├── db.ts                  # Prisma client singleton
│       ├── utils.ts               # Utility functions (cn, etc.)
│       ├── scan-manager.ts        # Scan orchestration logic
│       └── scanners/
│           ├── base.ts            # Abstract BaseScanner + type contracts
│           ├── nmap-scanner.ts    # Nmap direct execution + XML parsing
│           └── index.ts           # Scanner registry
├── run-nmap-scan.sh               # Standalone nmap shell script (nohup)
├── run-nikto-scan.sh              # Standalone nikto shell script (nohup)
├── run-nuclei-scan.sh             # Standalone nuclei shell script (nohup)
├── Dockerfile                     # Multi-stage build (3 stages)
├── fly.toml                       # Fly.io deployment config
├── railway.json                   # Railway deployment config
├── render.yaml                    # Render deployment config
├── next.config.ts                 # Next.js config (standalone output)
├── package.json                   # Dependencies & scripts
└── .env                           # Environment variables
```

---

## ⚠️ Legal Disclaimer

> **VulnGuard is an ethical hacking tool designed for authorized security testing ONLY.**

- You **must** have explicit, documented authorization before scanning any target.
- Unauthorized scanning of networks, systems, or web applications is **illegal** in most jurisdictions and may result in criminal prosecution.
- The authorization checkbox in the UI is a **reminder, not a legal shield** — the responsibility lies solely with the user.
- VulnGuard blocks known link-local and current-network addresses as a safety measure, but this is **not exhaustive**.
- The authors and contributors of VulnGuard assume **no liability** for misuse of this tool.

**Use responsibly. Scan only what you own or have written permission to test.**

---

## 📄 License

This project is licensed under the **MIT License**.

```
MIT License

Copyright (c) 2025 VulnGuard Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** the repository
2. **Create a feature branch:** `git checkout -b feature/my-feature`
3. **Make your changes** and add tests if applicable
4. **Lint your code:** `npm run lint`
5. **Test locally:** `npm run dev` — verify your changes work
6. **Commit** with a descriptive message: `git commit -m "Add X feature"`
7. **Push** to your fork: `git push origin feature/my-feature`
8. **Open a Pull Request** with a clear description of changes

### Contribution Ideas

- Additional scanner engine integrations (OpenVAS, ZAP, etc.)
- PDF/HTML scan report generation
- Email/Slack notifications for scheduled scans
- Multi-user authentication with NextAuth
- Dashboard analytics and trend charts
- Export scan results to CSV/JSON

---

<div align="center">

**Built with 🛡️ for ethical security testing**

[⬆ Back to top](#-vulnguard)

</div>
