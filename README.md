<div align="center">

# 🛡️ VulnGuard

### Ethical Vulnerability Scanner

**Real scan engines. AI-powered remediation. Unified security scoring. Zero mock data.**

[![Next.js 16](https://img.shields.io/badge/Next.js-16-black?logo=next.js)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Prisma](https://img.shields.io/badge/Prisma-6-2D3748?logo=prisma)](https://www.prisma.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

[Features](#-features) · [Run Locally](#-run-locally) · [Hybrid Deploy](#-hybrid-deployment-architecture) · [Deployment](#-docker-deployment) · [API Reference](#-api-reference) · [Legal](#%EF%B8%8F-legal-disclaimer)

</div>

---

## 📖 Overview

VulnGuard is a full-stack ethical vulnerability scanning platform that runs **real security scans** — no simulations, no mock data. It integrates three industry-standard scan engines (Nmap, Nikto, Nuclei) behind a polished web UI, adds a **unified Full Scan** mode that runs all engines in parallel with a computed security score, and augments results with **AI-powered auto-remediation** that explains vulnerabilities in plain English and provides copy-paste fix commands.

Built for security engineers, penetration testers, and devops teams who need a self-hosted, one-stop dashboard for network and web vulnerability assessment.

---

## ✨ Features

| Category | Details |
|---|---|
| **3 Real Scan Engines** | Nmap (network/port), Nikto (web HTTP), Nuclei (template-based bug hunting) |
| **Full Scan Mode** | Run all 3 engines in parallel → open ports, vulnerability hints, security score (A–F grade) |
| **AI Auto-Remediation** | LLM-powered explanations, severity prioritization, step-by-step fix commands |
| **Security Scoring** | Automatic score (0–100) with grade (A+–F) based on real findings — ports, CVEs, web issues |
| **Scheduled Scans** | Hourly / daily / weekly / monthly recurring scans with pause/resume |
| **Scan History** | Persistent results in SQLite, browse past scans anytime |
| **Live Polling** | Real-time progress indicators while scans run in the background |
| **CVE Detection** | Automatic CVE extraction from all three engines with context snippets |
| **Curl Reproduction** | Nuclei findings include `curl` commands to reproduce vulnerabilities |
| **Authorization Gate** | Legal disclaimer checkbox + server-side target validation before any scan |
| **Dark-first UI** | Sleek, animated interface with Framer Motion, shadcn/ui, and Tailwind CSS |
| **Self-hosted** | Full Docker support; deploy on Fly.io, Railway, Render, or any VPS |
| **No Root Required** | Uses `nmap -sT` (TCP connect scan) — works without elevated privileges |

---

## 🧱 Tech Stack

| Layer | Technology |
|---|---|
| **Framework** | [Next.js 16](https://nextjs.org/) (App Router, standalone output) |
| **Language** | [TypeScript 5](https://www.typescriptlang.org/) (strict) |
| **Database** | [SQLite](https://www.sqlite.org/) via [Prisma 6](https://www.prisma.io/) |
| **Styling** | [Tailwind CSS 4](https://tailwindcss.com/) + [shadcn/ui](https://ui.shadcn.com/) |
| **Animation** | [Framer Motion](https://www.framer.com/motion/) |
| **AI** | [z-ai-web-dev-sdk](https://www.npmjs.com/package/z-ai-web-dev-sdk) (LLM chat completions, backend only) |
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
│  │(nmap/nikto│  │ Ports/Vulns/ │  │ Fix Commands/CVEs/   │   │
│  │ /nuclei/  │  │ Score/Hints  │  │ Hardening Recs       │   │
│  │  full)    │  │              │  │                      │   │
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
4. **Full Scan mode** → `run-full-scan.sh` spawns all 3 engines in parallel. Each writes its own status file. When all 3 complete, the API merges results, computes a security score, and returns a unified report.
5. **AI remediation on demand** → `POST /api/remediate` sends structured findings (from any scan type including Full Scan) to an LLM which returns prioritized, actionable remediation guidance with fix commands.

---

## 🌐 Hybrid Deployment Architecture

VulnGuard supports **two deployment modes** — Local (scanner tools on the same server) and Hybrid (frontend on Vercel, scanner on GitHub Actions). Hybrid mode lets you run the UI on a serverless platform while offloading heavy scanning to GitHub's CI infrastructure.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Hybrid Deployment Mode                          │
│                                                                      │
│  ┌─────────────────────────────┐   ┌──────────────────────────────┐ │
│  │       Vercel (Frontend)      │   │   GitHub Actions (Scanner)   │ │
│  │                              │   │                              │ │
│  │  ┌──────────────────────┐   │   │  ┌────────────────────────┐  │ │
│  │  │  Next.js UI          │   │   │  │  ubuntu-latest runner  │  │ │
│  │  │  · Scan Form         │   │   │  │                        │  │ │
│  │  │  · Results View      │   │   │  │  · nmap (apt)          │  │ │
│  │  │  · AI Remediation    │   │   │  │  · nikto (apt)         │  │ │
│  │  └──────────┬───────────┘   │   │  │  · nuclei (go install) │  │ │
│  │             │                │   │  │                        │  │ │
│  │  ┌──────────▼───────────┐   │   │  └───────────┬────────────┘  │ │
│  │  │  /api/scan           │   │   │              │               │ │
│  │  │  mode=hybrid         │──┼───┼──► dispatch ──┤               │ │
│  │  └──────────┬───────────┘   │   │     repo_dispatch            │ │
│  │             │                │   │              │               │ │
│  │  ┌──────────▼───────────┐   │   │  ┌───────────▼────────────┐  │ │
│  │  │  /api/scan/callback  │◄──┼───┼──┤  curl POST results     │  │ │
│  │  │  (receives results)  │   │   │  └────────────────────────┘  │ │
│  │  └──────────┬───────────┘   │   │                              │ │
│  │             │                │   └──────────────────────────────┘ │
│  │  ┌──────────▼───────────┐   │                                      │
│  │  │  SQLite (Prisma)     │   │                                      │
│  │  │  Scan + Schedule     │   │                                      │
│  │  └──────────────────────┘   │                                      │
│  └─────────────────────────────┘                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### How Hybrid Mode Works

1. **User initiates scan** — Click "Start Scan" with the Deployment dropdown set to **"Hybrid (GitHub Actions)"**
2. **API dispatches scan** — Frontend calls `POST /api/scan` with `mode=hybrid`. The API creates a DB record and dispatches a `repository_dispatch` event to the configured GitHub repo
3. **GitHub Actions runs** — The workflow (`.github/workflows/vulnscan.yml`) triggers on the `vulnscan` event type. It runs on `ubuntu-latest` and installs nmap (apt), nikto (apt), and nuclei (`go install`)
4. **Scans execute** — All scanner tools run against the target. Nmap scans ports/services, Nikto checks web vulnerabilities, Nuclei runs template-based detection
5. **Results post back** — GitHub Actions posts the scan results via `curl` to the `/api/scan/callback` endpoint, authenticated with `CALLBACK_SECRET`
6. **Frontend displays results** — The UI polls `GET /api/scan/[id]` for status updates. When results arrive, they're parsed and displayed with full remediation support

### Local Mode (Default)

Local mode works when all scanner tools are installed directly on the server running VulnGuard. This is the default and simplest deployment — no GitHub Actions or callback configuration needed.

**Requirements:**
- Nuclei installed via `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
- Both `~/.local/bin` and `~/go/bin` must be in `PATH` so the server can locate scanner binaries
- Nmap and Nikto installed via system package manager (apt, brew, etc.)

**When to use Local mode:**
- Running VulnGuard on a VPS or in Docker (all tools bundled)
- Single-machine deployment where scanner tools are co-located with the web server
- Simplest setup — no external CI infrastructure needed

**When to use Hybrid mode:**
- Frontend deployed on Vercel or another serverless platform (no scanner binaries available)
- Want to leverage GitHub Actions' free CI minutes for scanning
- Need isolation between the web server and scanner infrastructure
- Running on a platform where installing nmap/nikto/nuclei isn't possible

### GitHub Actions Workflow

The hybrid mode relies on a GitHub Actions workflow file at `.github/workflows/vulnscan.yml` in the repository specified by `GITHUB_REPO`.

**Key workflow details:**

| Property | Value |
|---|---|
| **Trigger** | `repository_dispatch` event type `vulnscan` |
| **Runner** | `ubuntu-latest` |
| **nmap** | Installed via `apt-get install nmap` |
| **nikto** | Installed via `apt-get install nikto` |
| **nuclei** | Installed via `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| **Results delivery** | `curl POST` to `CALLBACK_URL` with `CALLBACK_SECRET` for authentication |

**Workflow input payload (sent via repository_dispatch):**

```json
{
  "event_type": "vulnscan",
  "client_payload": {
    "scan_id": "uuid",
    "target": "scanme.nmap.org",
    "scan_type": "full",
    "port": "80",
    "callback_url": "https://your-app.vercel.app/api/scan/callback",
    "callback_secret": "your-shared-secret"
  }
}
```

**Creating the workflow file:**

Create `.github/workflows/vulnscan.yml` in your GitHub repository:

```yaml
name: VulnGuard Scan
on:
  repository_dispatch:
    types: [vulnscan]

jobs:
  scan:
    runs-on: ubuntu-latest
    env:
      CALLBACK_URL: ${{ github.event.client_payload.callback_url }}
      CALLBACK_SECRET: ${{ github.event.client_payload.callback_secret }}
      SCAN_ID: ${{ github.event.client_payload.scan_id }}
      TARGET: ${{ github.event.client_payload.target }}
      SCAN_TYPE: ${{ github.event.client_payload.scan_type }}
      PORT: ${{ github.event.client_payload.port }}
      GOPATH: /home/runner/go

    steps:
      - name: Install scanner tools
        run: |
          sudo apt-get update
          sudo apt-get install -y nmap nikto
          go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
          nuclei -update-templates

      - name: Run scans
        run: |
          # Run scan logic here (nmap, nikto, nuclei based on SCAN_TYPE)
          # Post results back via curl
          curl -X POST "$CALLBACK_URL" \
            -H "Content-Type: application/json" \
            -H "X-Callback-Secret: $CALLBACK_SECRET" \
            -d "{\"scan_id\":\"$SCAN_ID\",\"results\":{...}}"
```

> **Note:** The above is a simplified example. The full workflow includes error handling, timeout management, and structured result formatting for all scan types.

### Setting Up Hybrid Deployment

#### Step 1: Deploy Frontend to Vercel

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy from project root
vercel

# Set environment variables in Vercel dashboard or CLI
vercel env add GITHUB_TOKEN
vercel env add GITHUB_REPO
vercel env add CALLBACK_URL
vercel env add CALLBACK_SECRET
```

#### Step 2: Prepare the GitHub Repository

1. Create a GitHub repository (or use an existing one)
2. Add the workflow file at `.github/workflows/vulnscan.yml`
3. Generate a Personal Access Token with `repo` scope at [github.com/settings/tokens](https://github.com/settings/tokens)

#### Step 3: Configure Environment Variables

Set the following in your Vercel project settings (or `.env` file):

```bash
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
GITHUB_REPO=your-username/vulnguard-scanner
CALLBACK_URL=https://your-app.vercel.app/api/scan/callback
CALLBACK_SECRET=your-random-shared-secret
GOPATH=/home/runner/go
```

#### Step 4: Test the Hybrid Scan

1. Open the VulnGuard UI on your Vercel deployment
2. Select **"Hybrid (GitHub Actions)"** from the Deployment dropdown
3. Enter a target and click **"Start Scan"**
4. Monitor the GitHub Actions tab in your repository for the running workflow
5. Results will appear in the UI once the callback posts them back

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

**Parsing:** `fast-xml-parser` for XML extraction of ports (state, service, version) and CVEs from NSE script output.

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

### Full Scan — All 3 Engines in Parallel

The **Full Scan** mode runs nmap, nikto, and nuclei simultaneously via `run-full-scan.sh`. Each engine writes its own output and status file. When all 3 complete, the API:

1. Parses all 3 output files
2. Computes a **security score** (0–100) with letter grade (A+–F)
3. Generates **vulnerability hints** aggregated from all engines
4. Returns a unified result with:
   - **Open ports** (from nmap)
   - **Vulnerability hints** (from all engines, with source badge)
   - **Security score** with breakdown (open ports, CVEs, web findings, nuclei severity)

**Security Score Breakdown:**

| Factor | Deduction |
|---|---|
| Each open port | -3 to -5 points |
| Each vulnerability/CVE | -10 to -20 points |
| Critical nuclei finding | -15 points each |
| High nuclei finding | -10 points each |
| Web finding (nikto/nuclei) | -5 points each |

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

**Works with all scan types:**
- ✅ Nmap scan results (ports + CVEs)
- ✅ Nikto scan results (web findings + CVEs)
- ✅ Nuclei scan results (template findings + extracted data)
- ✅ **Full Scan results** (all 3 engines combined — comprehensive remediation)

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
| **Bun** | 1.0+ | Package manager (recommended) or npm |
| **nmap** | 7.80+ | Network/port scanning |
| **nikto** | 2.5+ | Web vulnerability scanning |
| **nuclei** | 3.0+ | Template-based scanning |
| **nuclei-templates** | latest | Downloaded automatically by nuclei |

> **Note:** Scanner tools are only required on the host machine. The Docker image includes all three.

---

## 🚀 Run Locally

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-username/vulnguard.git
cd vulnguard
```

### Step 2: Install Scanner Tools

You need **nmap**, **nikto**, and **nuclei** installed on your system before running VulnGuard.

#### Ubuntu / Debian

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

# Download nuclei templates (required for scanning)
nuclei -update-templates
```

#### macOS

```bash
# Nmap
brew install nmap

# Nikto
brew install nikto

# Nuclei
brew install nuclei
nuclei -update-templates
```

#### From Source (Linux)

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
git clone https://github.com/sullo/nikto.git /opt/nikto
cd /opt/nikto/program
chmod +x nikto.pl
# Add to PATH
sudo ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto
```

> **Note:** If Nikto fails with `Can't locate JSON.pm`, patch it to use `JSON::PP` (bundled with Perl):
> ```bash
> sed -i 's/use JSON;/use JSON::PP;/g' /opt/nikto/program/nikto.pl
> ```

</details>

<details>
<summary>Build Nuclei from source (Go required)</summary>

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

</details>

#### Verify Scanner Installation

```bash
nmap --version     # Should show Nmap 7.80+
nikto -Version     # Should show Nikto 2.5+
nuclei -version    # Should show Nuclei 3.0+
```

### Step 3: Install Node.js Dependencies

Using **Bun** (recommended):

```bash
bun install
```

Using **npm**:

```bash
npm install
```

### Step 4: Set Up Environment Variables

Create a `.env` file in the project root (one is already included with defaults):

```bash
# .env
DATABASE_URL=file:./db/custom.db
```

That's the only required variable. Optional overrides:

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `file:./db/custom.db` | SQLite database path (Prisma connection string) |
| `NUCLEI_TEMPLATES_DIR` | `~/nuclei-templates` | Path to nuclei template directory |
| `PORT` | `3000` | Server port |

### Step 5: Initialize the Database

```bash
# Using Bun
bun run db:push

# Using npm
npm run db:push
```

This creates the SQLite database file at `db/custom.db` with the `Scan` and `Schedule` tables.

### Step 6: Start the Development Server

```bash
# Using Bun
bun run dev

# Using npm
npm run dev
```

Open **http://localhost:3000** in your browser. You should see the VulnGuard dashboard.

### Step 7: Run Your First Scan

1. **Check the authorization checkbox** — you must confirm you have permission to scan
2. **Select a scan engine** — Nmap, Nikto, Nuclei, or Full Scan
3. **Enter a target** — e.g., `scanme.nmap.org` (Nmap's authorized test target)
4. **Click "Start Scan"** — the scan runs in the background
5. **View results** — open ports, vulnerabilities, CVEs appear when the scan completes
6. **Click "Generate AI Remediation"** — get plain-English explanations and fix commands

> **Tip:** Use `scanme.nmap.org` for testing — it's Nmap's officially authorized test target.

---

## 🧪 Testing the API

You can test the API endpoints directly with `curl`:

### Run an Nmap Scan

```bash
curl -X POST http://localhost:3000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"scanme.nmap.org","scanType":"nmap","isAuthorized":true}'
```

### Run a Full Scan (All Engines)

```bash
curl -X POST http://localhost:3000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"scanme.nmap.org","scanType":"full","isAuthorized":true,"port":"80"}'
```

### Get AI Remediation

```bash
curl -X POST http://localhost:3000/api/remediate \
  -H "Content-Type: application/json" \
  -d '{
    "scanResult": {
      "target": "scanme.nmap.org",
      "ports": [
        {"port_id":22,"protocol":"tcp","state":"open","service":"OpenSSH","version":"6.6.1p1"}
      ],
      "vulnerabilities": [
        {"port_id":22,"cve_id":"CVE-2015-5600","description":"OpenSSH max auth bypass"}
      ]
    }
  }'
```

### List Scan History

```bash
curl http://localhost:3000/api/scans
```

---

## 🔑 Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `file:./db/custom.db` | SQLite database path (Prisma connection string) |
| `NMAP_PATH` | *(auto-detected)* | Override path to nmap binary |
| `NUCLEI_TEMPLATES_DIR` | `~/nuclei-templates` | Path to nuclei template directory |
| `PORT` | `3000` | Server port |
| `NODE_ENV` | `development` | Node environment |

### Hybrid Mode Variables

These environment variables are required **only** when using Hybrid (GitHub Actions) deployment mode. They are not needed for Local mode or Docker deployments.

| Variable | Default | Description |
|---|---|---|
| `GITHUB_TOKEN` | — | GitHub Personal Access Token with `repo` scope (used to dispatch workflows) |
| `GITHUB_REPO` | — | GitHub repository in `owner/repo` format (must contain `.github/workflows/vulnscan.yml`) |
| `CALLBACK_URL` | — | Public URL where GitHub Actions can post scan results back (e.g., `https://your-app.vercel.app/api/scan/callback`) |
| `CALLBACK_SECRET` | — | Shared secret for callback authentication — must match between the API and the GitHub Actions workflow |
| `GOPATH` | — | Go binary path for nuclei installed via `go install` on the GitHub Actions runner (typically `/home/runner/go`) |

---

## 📁 Project Structure

```
vulnguard/
├── prisma/
│   └── schema.prisma              # Database schema (Scan + Schedule models)
├── db/
│   └── custom.db                  # SQLite database file (auto-created)
├── src/
│   ├── app/
│   │   ├── page.tsx               # Main UI — scan form, results, remediation, schedules
│   │   ├── layout.tsx             # Root layout
│   │   ├── globals.css            # Global styles + Tailwind
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
│   │   └── ui/                    # shadcn/ui component library (50+ components)
│   ├── hooks/
│   │   ├── use-mobile.ts          # Mobile detection hook
│   │   └── use-toast.ts           # Toast notification hook
│   └── lib/
│       ├── db.ts                  # Prisma client singleton
│       ├── utils.ts               # Utility functions (cn, etc.)
│       ├── scan-manager.ts        # Scan orchestration logic
│       └── scanners/
│           ├── base.ts            # Abstract BaseScanner + type contracts
│           ├── nmap-scanner.ts    # Nmap XML execution + parsing
│           ├── nikto-scanner.ts   # Nikto CSV execution + parsing
│           ├── nuclei-scanner.ts  # Nuclei JSONL execution + parsing
│           └── index.ts           # Scanner registry
├── run-nmap-scan.sh               # Standalone nmap shell script (nohup bg)
├── run-nikto-scan.sh              # Standalone nikto shell script (nohup bg)
├── run-nuclei-scan.sh             # Standalone nuclei shell script (nohup bg)
├── run-full-scan.sh               # Full scan — runs all 3 engines in parallel
├── Dockerfile                     # Multi-stage build (3 stages)
├── fly.toml                       # Fly.io deployment config
├── railway.json                   # Railway deployment config
├── render.yaml                    # Render deployment config
├── next.config.ts                 # Next.js config (standalone output)
├── package.json                   # Dependencies & scripts
├── .env                           # Environment variables
└── README.md                      # This file
```

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

### Docker Compose (Optional)

```yaml
version: "3.8"
services:
  vulnguard:
    build: .
    ports:
      - "3000:3000"
    volumes:
      - vulnguard_data:/app/prisma/db
    environment:
      - DATABASE_URL=file:./db/custom.db
      - NUCLEI_TEMPLATES_DIR=/root/nuclei-templates
      - NODE_ENV=production

volumes:
  vulnguard_data:
```

The Dockerfile uses a **3-stage build**:

1. **scanner-tools** — Installs nmap, nikto, nuclei, and pre-downloads templates
2. **builder** — Installs Node.js deps, generates Prisma client, builds Next.js
3. **runner** — Minimal production image with scanner binaries and standalone Next.js server

---

## ☁️ Cloud Deployment

VulnGuard includes ready-made configuration files for three platforms. All use the Dockerfile for a self-contained deployment with all scanner tools included.

> **⚠️ Important:** VulnGuard uses **SQLite**, which requires a persistent filesystem. For **Local mode** (scanner tools on the same server), serverless platforms like Vercel and Netlify are NOT compatible — use container-based platforms instead. However, you **can** deploy to Vercel using **Hybrid mode**, which offloads scanning to GitHub Actions. See the [Hybrid Deployment Architecture](#-hybrid-deployment-architecture) section for details.

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

### Any VPS (Oracle Cloud, DigitalOcean, Hetzner)

```bash
# SSH into your VPS
ssh root@your-vps

# Install Docker
curl -fsSL https://get.docker.com | sh

# Clone & build
git clone https://github.com/your-username/vulnguard.git
cd vulnguard
docker build -t vulnguard .

# Run with auto-restart
docker run -d \
  --name vulnguard \
  --restart unless-stopped \
  -p 3000:3000 \
  -v /opt/vulnguard-data:/app/prisma/db \
  -e DATABASE_URL="file:./db/custom.db" \
  -e NUCLEI_TEMPLATES_DIR="/root/nuclei-templates" \
  vulnguard
```

> **Oracle Cloud Always Free** recommended — provides a free ARM VPS with 4 cores and 24GB RAM.

---

## 📡 API Reference

### `POST /api/scan` — Create & Execute Scan

Starts a new vulnerability scan. The scan runs asynchronously in the background.

**Request body:**

```json
{
  "target": "scanme.nmap.org",
  "scanType": "full",
  "isAuthorized": true,
  "port": "80"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `target` | `string` | ✅ | IP, hostname, or CIDR range |
| `scanType` | `"nmap" \| "nikto" \| "nuclei" \| "full"` | No | Default: `"nmap"` |
| `isAuthorized` | `boolean` | ✅ | Must be `true` to proceed |
| `port` | `string` | No | Target port for nikto/nuclei/full (default: `"80"`) |

**Response (201):**

```json
{
  "scan_id": "uuid",
  "target": "scanme.nmap.org",
  "scan_type": "full",
  "status": "Running",
  "message": "Full scan initiated. Poll GET /api/scan/[id] for results."
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
  "scan_type": "full",
  "target": "scanme.nmap.org"
}
```

**Response (completed — nmap):**

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

**Response (completed — full scan):**

```json
{
  "id": "uuid",
  "status": "Completed",
  "scan_type": "full",
  "target": "scanme.nmap.org",
  "results": {
    "target": "scanme.nmap.org",
    "scanType": "full",
    "nmap": { "target": "...", "ports": [...], "vulnerabilities": [...] },
    "nikto": { "target": "...", "scanType": "nikto", "findings": [...], "vulnerabilities": [...], "summary": {...} },
    "nuclei": { "target": "...", "scanType": "nuclei", "findings": [...], "vulnerabilities": [...], "summary": {...} },
    "securityScore": {
      "score": 65,
      "grade": "C",
      "label": "Moderate Risk",
      "breakdown": {
        "openPorts": { "count": 5, "deduction": 15, "details": "5 open ports detected" },
        "vulnerabilities": { "count": 2, "deduction": 20, "details": "2 vulnerabilities found" }
      }
    },
    "openPorts": [...],
    "vulnerabilityHints": [
      { "source": "nikto", "severity": "medium", "title": "...", "description": "...", "port": 80 }
    ],
    "summary": {
      "totalOpenPorts": 5,
      "totalVulnerabilities": 2,
      "totalCves": 1,
      "totalWebFindings": 3,
      "enginesCompleted": 3
    }
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
      "scanType": "full",
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

Sends scan results to the LLM for actionable remediation guidance. **Works with all scan types** including Full Scan results.

**Request body (nmap):**

```json
{
  "scanResult": {
    "target": "192.168.1.1",
    "ports": [{"port_id":22,"protocol":"tcp","state":"open","service":"OpenSSH","version":"6.6.1p1"}],
    "vulnerabilities": [{"port_id":22,"cve_id":"CVE-2015-5600","description":"OpenSSH max auth bypass"}]
  }
}
```

**Request body (full scan):**

```json
{
  "scanResult": {
    "target": "scanme.nmap.org",
    "scanType": "full",
    "nmap": {...},
    "nikto": {...},
    "nuclei": {...},
    "securityScore": {...},
    "openPorts": [...],
    "vulnerabilityHints": [...],
    "summary": {...}
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
  scanType  String   @default("nmap")      // nmap | nikto | nuclei | full
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

## 🔧 Available Scripts

| Script | Command | Description |
|---|---|---|
| **Dev server** | `bun run dev` | Start Next.js development server on port 3000 |
| **Build** | `bun run build` | Generate Prisma client + build Next.js for production |
| **Start** | `bun run start` | Start production server (after build) |
| **Lint** | `bun run lint` | Run ESLint to check code quality |
| **DB Push** | `bun run db:push` | Push Prisma schema to SQLite (creates/migrates tables) |
| **DB Generate** | `bun run db:generate` | Generate Prisma client from schema |
| **DB Migrate** | `bun run db:migrate` | Run Prisma migrations (dev mode) |
| **DB Reset** | `bun run db:reset` | Reset database (deletes all data!) |

> Replace `bun` with `npm` if you're using npm instead.

---

## 🐛 Troubleshooting

### Nmap scan returns no results

```bash
# Check nmap is installed and accessible
nmap --version

# If nmap is in a custom location, add to PATH
export PATH="$HOME/.local/bin:/usr/local/bin:$PATH"
```

### Nikto fails with "Can't locate JSON.pm"

Nikto requires the `JSON` Perl module which may not be installed. Fix by patching to use `JSON::PP` (bundled with Perl):

```bash
# Find nikto location
which nikto

# Patch to use JSON::PP instead of JSON
sed -i 's/use JSON;/use JSON::PP;/g' "$(which nikto)"
```

### Nuclei templates not found

```bash
# Download/update templates
nuclei -update-templates

# If templates are in a custom location, set env var
export NUCLEI_TEMPLATES_DIR="$HOME/nuclei-templates"
```

### AI Remediation returns an error

- The remediation engine uses `z-ai-web-dev-sdk` which requires network access
- Ensure the server can make outbound API calls
- The SDK is backend-only — never used on the client side
- If you see "Remediation engine failed", check the server logs for details

### SQLite database errors

```bash
# Reset the database
bun run db:push

# If that doesn't work, delete the DB file and re-create
rm db/custom.db
bun run db:push
```

### Port 3000 already in use

```bash
# Find and kill the process using port 3000
lsof -i :3000
kill -9 <PID>

# Or use a different port
PORT=3001 bun run dev
```

---

## ❓ FAQ

**Q: Can I deploy this on Vercel?**
A: Yes — with Hybrid mode! Use the **Hybrid (GitHub Actions)** deployment: the Next.js frontend runs on Vercel while scans execute on GitHub Actions infrastructure. The original Local mode still requires a persistent filesystem and scanner binaries on the host, so use container-based platforms (Fly.io, Railway, Render) for that mode.

**Q: What's the difference between Local and Hybrid mode?**
A: **Local mode** runs scanner tools (nmap, nikto, nuclei) directly on the same server as the web app — simplest setup, works in Docker or on a VPS. **Hybrid mode** splits the architecture: the frontend runs on Vercel (or any serverless platform) and dispatches scans to GitHub Actions, which runs the scanner tools on `ubuntu-latest` runners and posts results back via a callback API endpoint.

**Q: Does it work without root/sudo?**
A: Yes! Nmap uses `-sT` (TCP connect scan) which doesn't require elevated privileges. Nikto and Nuclei also work without root.

**Q: Is the AI remediation free?**
A: The `z-ai-web-dev-sdk` is included and works out of the box. No additional API keys are needed.

**Q: Can I scan any website?**
A: You must have explicit authorization to scan any target. The authorization checkbox is a reminder — the legal responsibility is yours. Use `scanme.nmap.org` for testing.

**Q: How long do scans take?**
A: Nmap: 30–60 seconds. Nikto: 30–90 seconds. Nuclei: 30–120 seconds. Full Scan (all 3 in parallel): 60–120 seconds.

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
4. **Lint your code:** `bun run lint`
5. **Test locally:** `bun run dev` — verify your changes work
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
- WebSocket-based real-time scan progress (no polling)
- Role-based access control for teams

---

<div align="center">

**Built with 🛡️ for ethical security testing**

[⬆ Back to top](#-vulnguard)

</div>
