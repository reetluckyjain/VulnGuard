<div align="center">

# 🛡️ VulnGuard

### Ethical Vulnerability Scanner — Real Engines, AI Remediation

**Real scan engines. AI-powered remediation. Unified security scoring. Zero mock data.**

![Next.js 16](https://img.shields.io/badge/Next.js-16-black?logo=next.js)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript)
![Prisma](https://img.shields.io/badge/Prisma-6-2D3748?logo=prisma)
![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-4-06B6D4?logo=tailwindcss)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?logo=sqlite)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

[Features](#-features) · [Architecture](#-architecture) · [Quick Start](#-quick-start-local-development) · [Hybrid Deploy](#-hybrid-deployment-github-actions) · [API Reference](#-api-reference) · [Scan Types](#-scan-types-explained) · [AI Remediation](#-ai-remediation-engine) · [Troubleshooting](#-troubleshooting)

</div>

---

## ✨ Features

| | Feature | Details |
|---|---|---|
| 🔍 | **Real Scanner Engines** | Nmap (port scanning), Nikto (web vuln scanning), Nuclei (template-based bug hunting) — no simulations, no mock data |
| 🤖 | **AI Auto-Remediation** | LLM-powered fix suggestions with copy-paste commands, severity prioritization, and hardening recommendations |
| ⚡ | **Hybrid Deployment** | Frontend on Vercel, scanner on GitHub Actions — run heavy scans on Ubuntu CI runners while your UI stays serverless |
| 📊 | **Security Score** | A+ to F grading system based on real findings — open ports, CVEs, web issues, and nuclei severity |
| 📅 | **Scheduled Scans** | Hourly, daily, weekly, and monthly recurring scans with pause/resume support |
| 🎯 | **4 Scan Types** | `nmap`, `nikto`, `nuclei`, and `full` (all 3 engines in parallel) |
| 🌙 | **Dark Mode** | Full light/dark theme support via next-themes |
| 📱 | **Responsive Design** | Mobile-first UI built with shadcn/ui, Tailwind CSS 4, and Framer Motion animations |
| 🔐 | **Authorization Gate** | Legal disclaimer checkbox + server-side target validation before any scan runs |
| 📋 | **CVE Detection** | Automatic CVE extraction from all three engines with context snippets |
| 🔄 | **Curl Reproduction** | Nuclei findings include `curl` commands to reproduce vulnerabilities |
| 🚫 | **No Root Required** | Uses `nmap -sT` (TCP connect scan) — works without elevated privileges |

---

## 🏗️ Architecture

VulnGuard supports two deployment modes: **Local** (all on one server) and **Hybrid** (frontend on Vercel, scanner on GitHub Actions).

### Local Deployment

```
┌──────────────────────────────────────────────────────────────┐
│                      Browser (React)                         │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │ Scan Form │  │ Results View │  │ AI Remediation Panel │   │
│  └─────┬─────┘  └──────┬───────┘  └──────────┬───────────┘   │
└────────┼───────────────┼──────────────────────┼───────────────┘
         │ POST /api/scan│ GET /api/scan/[id]   │ POST /api/
         │               │ (polling)            │ remediate
┌────────┼───────────────┼──────────────────────┼───────────────┐
│        ▼               ▼                      ▼               │
│  ┌──────────────────────────────────────────────────────┐     │
│  │              Next.js API Routes                       │     │
│  │  /scan   ·  /scan/[id]   ·  /remediate               │     │
│  └──────────────────────┬───────────────────────────────┘     │
│                         │                                     │
│  ┌──────────────────────▼───────────────────────────────┐     │
│  │   Scanner Tools (local system)                        │     │
│  │   nmap  ·  nikto  ·  nuclei                           │     │
│  └──────────────────────────────────────────────────────┘     │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐     │
│  │   SQLite (Prisma)  —  Scan + Schedule models         │     │
│  └──────────────────────────────────────────────────────┘     │
└───────────────────────────────────────────────────────────────┘
```

### Hybrid Deployment (GitHub Actions)

```
┌──────────────────────────────────────────────────────────────────────┐
│                      Hybrid Deployment Mode                           │
│                                                                       │
│  ┌──────────────────────────────┐    ┌────────────────────────────┐  │
│  │       Vercel (Frontend)       │    │   GitHub Actions (Scanner) │  │
│  │                               │    │                            │  │
│  │  ┌───────────────────────┐   │    │  ┌──────────────────────┐  │  │
│  │  │  Next.js UI           │   │    │  │  ubuntu-latest       │  │  │
│  │  │  · Scan Form          │   │    │  │                      │  │  │
│  │  │  · Results View       │   │    │  │  · nmap (apt)        │  │  │
│  │  │  · AI Remediation     │   │    │  │  · nikto (apt)       │  │  │
│  │  └──────────┬────────────┘   │    │  │  · nuclei (go install)│  │  │
│  │             │                 │    │  └───────────┬──────────┘  │  │
│  │  ┌──────────▼────────────┐   │    │              │             │  │
│  │  │  POST /api/scan       │───┼────┼──► dispatch ─┤             │  │
│  │  │  mode=hybrid          │   │    │   repo_dispatch            │  │
│  │  └──────────┬────────────┘   │    │              │             │  │
│  │             │                 │    │  ┌───────────▼──────────┐  │  │
│  │  ┌──────────▼────────────┐   │    │  │  curl POST results   │  │  │
│  │  │  /api/scan/callback   │◄──┼────┼──┤  to CALLBACK_URL     │  │  │
│  │  │  (receives results)   │   │    │  └──────────────────────┘  │  │
│  │  └──────────┬────────────┘   │    │                            │  │
│  │             │                 │    └────────────────────────────┘  │
│  │  ┌──────────▼────────────┐   │                                      │
│  │  │  SQLite (Prisma)      │   │                                      │
│  │  │  Scan + Schedule      │   │                                      │
│  │  └───────────────────────┘   │                                      │
│  └──────────────────────────────┘                                      │
└───────────────────────────────────────────────────────────────────────┘
```

### Hybrid Callback Flow

1. **Scan request** — User clicks "Start Scan" with Deployment set to "Hybrid (GitHub Actions)"
2. **API dispatch** — `POST /api/scan` with `mode=hybrid` creates a DB record and sends a `repository_dispatch` event to the GitHub repo
3. **GitHub Actions runs** — The `.github/workflows/vulnscan.yml` workflow triggers on the `vulnscan` event. It installs nmap, nikto, and nuclei on `ubuntu-latest`
4. **Scans execute** — All scanner tools run against the target on the Ubuntu runner
5. **Results post back** — GitHub Actions sends results via `curl POST` to `/api/scan/callback`, authenticated with `CALLBACK_SECRET`
6. **Frontend polls** — The UI polls `GET /api/scan/[id]` for status updates until results arrive

---

## 🚀 Quick Start (Local Development)

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/vulnguard.git
cd vulnguard
```

### 2. Install Dependencies

```bash
bun install
```

### 3. Set Up Database

```bash
bun run db:push
```

This creates the SQLite database at `db/custom.db` with the `Scan` and `Schedule` tables.

### 4. Install Scanner Tools (Linux/Ubuntu)

```bash
# Nmap — network/port scanner
sudo apt-get install nmap

# Nikto — web vulnerability scanner
sudo apt-get install nikto

# Nuclei — template-based vulnerability scanner (requires Go)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Download nuclei templates (required for scanning)
nuclei -update-templates
```

**Verify installation:**

```bash
nmap --version     # Should show Nmap 7.80+
nikto -Version     # Should show Nikto 2.5+
nuclei -version    # Should show Nuclei 3.0+
```

### 5. Start Dev Server

```bash
bun run dev
```

### 6. Open the App

Navigate to **http://localhost:3000** in your browser.

### 7. Run Your First Scan

1. **Check the authorization checkbox** — you must confirm you have permission to scan
2. **Select a scan engine** — Nmap, Nikto, Nuclei, or Full Scan
3. **Enter a target** — e.g., `scanme.nmap.org` (Nmap's authorized test target)
4. **Click "Start Scan"** — the scan runs in the background
5. **View results** — open ports, vulnerabilities, CVEs appear when the scan completes
6. **Click "Generate AI Remediation"** — get plain-English explanations and fix commands

> **Tip:** Use `scanme.nmap.org` for testing — it's Nmap's officially authorized test target.

### ⚠️ Windows Note

Nmap and Nikto cannot run natively on Windows. If you're developing on Windows, you have two options:

- **Use Hybrid mode** — Deploy the frontend locally and offload scanning to GitHub Actions (Ubuntu runners)
- **Use WSL2** — Install scanner tools inside Windows Subsystem for Linux and run VulnGuard there

---

## ⚡ Hybrid Deployment (GitHub Actions)

Hybrid mode lets you run the VulnGuard UI on Vercel (or any serverless platform) while offloading heavy scanning to GitHub's CI infrastructure on Ubuntu runners.

### Step 1: Fork/Push the Repo to GitHub

The repository must contain `.github/workflows/vulnscan.yml` — this is the workflow that runs the scanners.

### Step 2: Set GitHub Repository Secrets/Variables

In your GitHub repo, go to **Settings → Secrets and variables → Actions** and add:

| Secret | Description |
|---|---|
| `GITHUB_TOKEN` | A Personal Access Token with `repo` scope (generate at [github.com/settings/tokens](https://github.com/settings/tokens)) |
| `GITHUB_REPO` | Your repo in `owner/repo` format (e.g., `your-username/vulnguard`) |

### Step 3: Set Environment Variables in Vercel

In your Vercel project settings (or in a `.env` file):

```bash
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx       # Same PAT as above
GITHUB_REPO=your-username/vulnguard          # Same repo as above
CALLBACK_URL=https://your-app.vercel.app     # Your public app URL
CALLBACK_SECRET=your-random-shared-secret    # A shared secret for auth
```

### Step 4: Deploy to Vercel

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy from project root
vercel

# Set environment variables
vercel env add GITHUB_TOKEN
vercel env add GITHUB_REPO
vercel env add CALLBACK_URL
vercel env add CALLBACK_SECRET
```

### Step 5: Run a Hybrid Scan

1. Open the VulnGuard UI on your Vercel deployment
2. Select **"Hybrid (GitHub Actions)"** from the Deployment dropdown
3. Enter a target and click **"Start Scan"**
4. Monitor the GitHub Actions tab in your repository for the running workflow
5. Results will appear in the UI once the callback posts them back

### Callback Flow in Detail

```
User ──► POST /api/scan (mode=hybrid)
              │
              ├──► Create Scan record in DB (status: Running)
              └──► GitHub API: repository_dispatch (event_type: vulnscan)
                        │
                        ▼
              GitHub Actions Workflow (.github/workflows/vulnscan.yml)
                        │
                        ├──► Install nmap, nikto, nuclei on ubuntu-latest
                        ├──► Execute scans against target
                        └──► POST results to /api/scan/callback
                                  │
                                  ▼
              Callback endpoint verifies CALLBACK_SECRET
              Updates Scan record in DB (status: Completed)
                                  │
                                  ▼
              Frontend polling detects completion → displays results
```

---

## 🔑 Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | Yes | `file:./db/custom.db` | SQLite database path (Prisma connection string) |
| `GITHUB_TOKEN` | Hybrid only | — | GitHub Personal Access Token with `repo` scope |
| `GITHUB_REPO` | Hybrid only | — | GitHub repository in `owner/repo` format |
| `CALLBACK_URL` | Hybrid only | — | Public URL for GitHub Actions to post scan results (e.g., `https://your-app.vercel.app/api/scan/callback`) |
| `CALLBACK_SECRET` | Hybrid only | auto-generated | Shared secret for callback authentication — must match between API and GitHub Actions workflow |
| `NUCLEI_TEMPLATES_DIR` | No | `$HOME/nuclei-templates` | Custom nuclei templates directory path |
| `GOPATH` | No | `$HOME/go` | Go installation path (used to locate `nuclei` binary installed via `go install`) |

> **Note:** Only `DATABASE_URL` is required for Local mode. All `GITHUB_*` and `CALLBACK_*` variables are only needed for Hybrid (GitHub Actions) deployment.

---

## 📡 API Reference

### `POST /api/scan` — Create & Execute Scan

Starts a new vulnerability scan. Runs asynchronously in the background.

**Request body:**

```json
{
  "target": "scanme.nmap.org",
  "scanType": "full",
  "mode": "local",
  "port": "80",
  "isAuthorized": true
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `target` | `string` | ✅ | IP, hostname, or CIDR range |
| `scanType` | `"nmap" \| "nikto" \| "nuclei" \| "full"` | No | Default: `"nmap"` |
| `mode` | `"local" \| "hybrid"` | No | Default: `"local"` |
| `port` | `string` | No | Target port for nikto/nuclei/full (default: `"80"`) |
| `isAuthorized` | `boolean` | ✅ | Must be `true` to proceed |

**Response (201):**

```json
{
  "scan_id": "uuid",
  "status": "Running",
  "results": null
}
```

---

### `GET /api/scan/[id]` — Get Scan Status & Results

Poll this endpoint to check scan progress and retrieve results.

**Response (running):**

```json
{
  "scan_id": "uuid",
  "status": "Running",
  "results": null,
  "elapsed_seconds": 12
}
```

**Response (completed — full scan):**

```json
{
  "scan_id": "uuid",
  "status": "Completed",
  "results": {
    "target": "scanme.nmap.org",
    "scanType": "full",
    "nmap": { "ports": [...], "vulnerabilities": [...] },
    "nikto": { "findings": [...], "vulnerabilities": [...] },
    "nuclei": { "findings": [...], "vulnerabilities": [...] },
    "securityScore": {
      "score": 65,
      "grade": "C",
      "label": "Moderate Risk",
      "breakdown": { ... }
    },
    "openPorts": [...],
    "vulnerabilityHints": [...]
  },
  "elapsed_seconds": 47
}
```

---

### `POST /api/remediate` — AI Remediation

Sends scan results to the LLM for actionable remediation guidance. Works with **all scan types** including Full Scan results.

**Request body:**

```json
{
  "scanResult": {
    "target": "scanme.nmap.org",
    "ports": [
      { "port_id": 22, "protocol": "tcp", "state": "open", "service": "OpenSSH", "version": "8.9" }
    ],
    "vulnerabilities": [
      { "port_id": 22, "cve_id": "CVE-2023-XXXX", "description": "OpenSSH vulnerability" }
    ]
  }
}
```

**Response:**

```json
{
  "summary": "Executive summary of security posture",
  "risk_level": "High",
  "remediations": [
    {
      "finding": "OpenSSH 8.9 Vulnerability",
      "severity": "High",
      "explanation": "Plain English explanation of the vulnerability",
      "fix_commands": ["sudo apt update && sudo apt upgrade openssh-server -y"],
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-XXXX"]
    }
  ],
  "hardening_recommendations": [
    "Disable password authentication and use SSH keys only",
    "Implement fail2ban to prevent brute-force attacks"
  ]
}
```

---

### `POST /api/scan/dispatch` — Dispatch to GitHub Actions

Alternative endpoint specifically for dispatching scans to GitHub Actions.

**Request body:**

```json
{
  "scan_id": "uuid",
  "target": "scanme.nmap.org",
  "scan_type": "full",
  "port": "80"
}
```

---

### `POST /api/scan/callback` — Receive Results from GitHub Actions

Internal endpoint called by the GitHub Actions workflow to deliver scan results.

**Request headers:**

```
X-Callback-Secret: <CALLBACK_SECRET>
```

**Request body:**

```json
{
  "scan_id": "uuid",
  "results": { ... }
}
```

---

### `GET / POST / PUT / DELETE /api/schedules` — Scheduled Scan CRUD

Manage recurring scans with full CRUD operations.

**Create a schedule (POST):**

```json
{
  "target": "scanme.nmap.org",
  "scanType": "nmap",
  "port": "80",
  "frequency": "daily"
}
```

| Frequency | Description |
|---|---|
| `hourly` | Run every hour |
| `daily` | Run once per day |
| `weekly` | Run once per week |
| `monthly` | Run once per month |

---

## 🎯 Scan Types Explained

### Nmap — Network & Port Scanner

**Command:** `nmap -sT -sV -F --top-ports 100 <target>`

| Flag | Purpose |
|---|---|
| `-sT` | TCP connect scan (no root required) |
| `-sV` | Service version detection |
| `-F` | Fast mode — scan fewer ports |
| `--top-ports 100` | Scan top 100 most common ports |

**What it finds:** Open ports, service names, versions, and CVEs via NSE vulnerability scripts.

**Parsing:** XML output parsed with `fast-xml-parser` for structured port data and CVE extraction.

---

### Nikto — Web Vulnerability Scanner

**Command:** `nikto -h <target> -Format csv -C all`

| Flag | Purpose |
|---|---|
| `-h <target>` | Target host |
| `-Format csv` | CSV output for reliable parsing |
| `-C all` | Run all check modes |

**What it finds:** Outdated servers, misconfigurations, dangerous HTTP headers, default credentials, information leakage.

**Parsing:** Custom CSV parser handles quoted fields. Findings classified by severity (high/medium/low/info) based on keyword heuristics.

---

### Nuclei — Template-Based Vulnerability Scanner

**Command:** `nuclei -u <target> -jle <file>`

| Flag | Purpose |
|---|---|
| `-u <url>` | Target URL |
| `-jle <file>` | JSONL export to file |

**Installation:** `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`

**Template categories scanned:**

| Category | What It Detects |
|---|---|
| `http/cves/` | Known CVE exploits |
| `http/vulnerabilities/` | Generic vulnerability detection |
| `http/exposures/` | Exposed data, secrets, API keys |
| `http/misconfiguration/` | Server misconfigurations |
| `http/default-logins/` | Default credential detection |
| `http/takeovers/` | Subdomain takeover checks |

**What it finds:** XSS, SQLi, exposed secrets, CVEs, misconfigurations, default logins, subdomain takeovers. Includes `curl` commands to reproduce findings.

---

### Full Scan — All 3 Engines in Parallel

Runs **nmap**, **nikto**, and **nuclei** simultaneously. Each engine writes its own output. When all 3 complete, the API:

1. Parses all output files
2. Computes a **security score** (0–100) with letter grade (A+–F)
3. Generates aggregated **vulnerability hints** with source badges
4. Returns a unified result with open ports, web findings, CVEs, and security score

---

## 📊 Security Score Calculation

The security score starts at **100** and deductions are applied based on findings:

### Deductions

| Factor | Deduction | Details |
|---|---|---|
| Each open port | -2 | Standard ports |
| Each high-risk open port | -5 | e.g., telnet (23), ftp (21) |
| Each CVE found | -5 | From nmap NSE scripts, nikto, or nuclei |
| Each web finding (low/info) | -3 | Informational web issues |
| Each web finding (medium) | -5 | Moderate web vulnerabilities |
| Each web finding (high) | -8 | Serious web vulnerabilities |
| Each Nuclei critical finding | -15 | Critical-severity template match |
| Each Nuclei high finding | -8 | High-severity template match |

### Grading Scale

| Grade | Score Range | Label |
|---|---|---|
| **A+** | 95–100 | Excellent |
| **A** | 90–94 | Very Good |
| **B** | 80–89 | Good |
| **C** | 70–79 | Moderate Risk |
| **D** | 60–69 | Significant Risk |
| **E** | 40–59 | High Risk |
| **F** | 0–39 | Critical Risk |

---

## 🤖 AI Remediation Engine

VulnGuard's AI remediation engine uses **z-ai-web-dev-sdk** to power LLM-based vulnerability analysis and fix suggestions.

### How It Works

1. **Input** — Scan results (from any engine or Full Scan) are serialized into structured JSON
2. **Prompt engineering** — A specialized system prompt enforces plain-English explanations, severity prioritization, and copy-paste fix commands with actual values (no placeholders)
3. **LLM call** — The engine calls the LLM via `z-ai-web-dev-sdk` with a 45-second timeout per request
4. **Response parsing** — Robust JSON extraction from LLM response handles various output formats
5. **Retry logic** — 3 attempts with exponential backoff if the LLM call fails or returns malformed data

### Response Structure

```json
{
  "summary": "Executive summary of the target's security posture",
  "risk_level": "Critical | High | Medium | Low | Secure",
  "remediations": [
    {
      "finding": "Short title of the vulnerability",
      "severity": "Critical | High | Medium | Low | Info",
      "explanation": "Plain English explanation of what's wrong and why it matters",
      "fix_commands": ["sudo apt update && sudo apt upgrade -y", "ufw deny 23"],
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXX"]
    }
  ],
  "hardening_recommendations": [
    "Disable password authentication and use SSH keys only",
    "Implement a WAF with rate limiting"
  ]
}
```

### Key Features

- ✅ Works with all scan types: nmap, nikto, nuclei, and full scan results
- ✅ Prioritized remediations (Critical → High → Medium → Low → Info)
- ✅ Copy-paste fix commands with actual values — no placeholders
- ✅ CVE context with CVSS impact descriptions
- ✅ Service-specific hardening (nginx, Apache, SSH configs)
- ✅ Secret rotation steps for exposed credentials
- ✅ WAF rule suggestions for findings with curl reproduction

### Technical Details

| Parameter | Value |
|---|---|
| LLM Provider | z-ai-web-dev-sdk |
| Timeout per call | 45 seconds |
| Max retries | 3 |
| Backoff strategy | Exponential |
| Output format | JSON (robust extraction) |

---

## 🔧 Troubleshooting

### Common Issues

| Issue | Solution |
|---|---|
| **"nmap is not installed"** | Install nmap: `sudo apt-get install nmap`. Or switch to Hybrid mode (GitHub Actions on Ubuntu). |
| **"nuclei is not found"** | Add `~/go/bin` to your `PATH` or set the `GOPATH` environment variable. Nuclei is installed via `go install`. |
| **"Scan timed out"** | The target may be unreachable or blocking scans. Try a simpler scan type (nmap only) or a different target. |
| **"Remediation failed"** | Check that `z-ai-web-dev-sdk` is properly installed and the LLM service is reachable. The engine retries 3 times with backoff. |
| **"GitHub dispatch failed"** | Verify `GITHUB_TOKEN` has `repo` scope. Check that `GITHUB_REPO` is in `owner/repo` format. Ensure `.github/workflows/vulnscan.yml` exists in the repo. |
| **Callback not receiving results** | Ensure `CALLBACK_URL` is publicly accessible and `CALLBACK_SECRET` matches between Vercel env vars and the GitHub Actions workflow. |
| **Windows — scanners won't run** | Nmap and Nikto don't run natively on Windows. Use **Hybrid mode** (GitHub Actions on Ubuntu runners) or develop inside WSL2. |
| **Nikto fails with "Can't locate JSON.pm"** | Patch it to use `JSON::PP` (bundled with Perl): `sed -i 's/use JSON;/use JSON::PP;/g' /path/to/nikto.pl` |

### Verifying Scanner Installation

```bash
# Check all three scanners are available
which nmap && nmap --version
which nikto && nikto -Version
which nuclei && nuclei -version

# If nuclei is missing, check Go bin path
ls ~/go/bin/nuclei
export PATH="$HOME/go/bin:$PATH"
```

---

## ⚖️ Legal Disclaimer

**VulnGuard is intended solely for authorized security testing and educational purposes.**

- 🔴 **You MUST have explicit, written authorization** before scanning any target that you do not own or operate.
- 🔴 Unauthorized scanning of networks, systems, or web applications is **illegal** in most jurisdictions and may result in criminal prosecution.
- 🔴 The authorization checkbox in the UI is a **reminder**, not a legal safeguard. You are solely responsible for ensuring you have proper authorization.
- 🔴 The developers of VulnGuard assume **no liability** for misuse of this tool.
- 🟢 Use `scanme.nmap.org` for testing — it's Nmap's officially authorized test target.

**Always follow responsible disclosure practices and your organization's security policies.**

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
│   │       │   ├── [id]/route.ts  # GET /api/scan/[id] — poll status/results
│   │       │   ├── callback/route.ts  # POST — receive GitHub Actions results
│   │       │   └── dispatch/route.ts  # POST — dispatch to GitHub Actions
│   │       ├── scans/route.ts     # GET /api/scans — scan history
│   │       ├── remediate/route.ts # POST /api/remediate — AI remediation
│   │       └── schedules/route.ts # CRUD /api/schedules
│   ├── components/ui/             # shadcn/ui component library
│   ├── hooks/                     # Custom React hooks
│   └── lib/
│       ├── db.ts                  # Prisma client singleton
│       ├── utils.ts               # Utility functions
│       └── scanners/              # Scanner execution + parsing
│           ├── base.ts            # Abstract BaseScanner + type contracts
│           ├── nmap-scanner.ts    # Nmap XML execution + parsing
│           ├── nikto-scanner.ts   # Nikto CSV execution + parsing
│           ├── nuclei-scanner.ts  # Nuclei JSONL execution + parsing
│           └── index.ts           # Scanner registry
├── run-nmap-scan.sh               # Standalone nmap shell script
├── run-nikto-scan.sh              # Standalone nikto shell script
├── run-nuclei-scan.sh             # Standalone nuclei shell script
├── run-full-scan.sh               # Full scan — all 3 engines in parallel
├── .github/workflows/vulnscan.yml # GitHub Actions workflow (hybrid mode)
├── package.json
├── next.config.ts
├── .env
└── README.md
```

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](./LICENSE) file for details.

---

<div align="center">

**Built with ❤️ for security engineers, penetration testers, and devops teams.**

</div>
