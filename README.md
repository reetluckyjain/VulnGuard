<div align="center">

# 🛡️ VulnGuard

**Ethical Vulnerability Scanner — Real Engines, Real Data**

[![Next.js](https://img.shields.io/badge/Next.js-16-black?logo=next.js)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-blue?logo=typescript)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

*An AI-powered, full-stack vulnerability scanning platform that runs real security tools — no mocks, no simulations. Built for ethical hackers, penetration testers, and security teams.*

**Vibecoded by [Lucky Jain](https://github.com/luckyjain)** 🚀

</div>

---

## ⚠️ Ethical Use Disclaimer

> **This tool is designed exclusively for authorized security testing and educational purposes.**
>
> - You **MUST** have explicit written authorization before scanning any target.
> - Unauthorized scanning of networks, systems, or applications is **illegal** in most jurisdictions.
> - This tool includes built-in ethical safeguards (authorization gates, restricted target ranges).
> - The creators and contributors of VulnGuard **do not condone or support** any illegal or unethical use.
> - By using this software, you accept full responsibility for your actions and agree to comply with all applicable laws.
>
> **If you don't own it or don't have permission — don't scan it.**

---

## ✨ Features

### 🔍 Three Real Scanning Engines

| Engine | Tool | What It Finds | Output Format |
|--------|------|---------------|---------------|
| **Nmap** | `nmap -sT -sV --script vuln` | Open ports, service versions, CVEs | XML |
| **Nikto** | `nikto -h target -Format csv` | Web misconfigurations, outdated servers, headers | CSV |
| **Nuclei** | `nuclei -u target -jle` | XSS, SQLi, exposed secrets, CVEs, default logins | JSONL |

### 🤖 AI Auto-Remediation

Paste any scan result and get:
- **Plain-English explanations** of every vulnerability
- **Step-by-step fix commands** you can copy-paste
- **Severity prioritization** (Critical → Info)
- **Hardening recommendations** for ongoing security

### 📅 Scheduled Scans

Set up recurring scans (hourly / daily / weekly / monthly) for continuous monitoring.

### 🔒 Built-in Safeguards

- Authorization checkbox required before every scan
- Link-local and current-network addresses are blocked
- All scan data stored locally in SQLite

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Frontend (React)                  │
│         Next.js 16 + Tailwind CSS + shadcn/ui       │
└──────────────────────┬──────────────────────────────┘
                       │ API Routes
┌──────────────────────▼──────────────────────────────┐
│                  Backend (Next.js)                   │
│    ┌─────────┐  ┌──────────┐  ┌───────────────┐    │
│    │  Nmap   │  │  Nikto   │  │    Nuclei     │    │
│    │ Scanner │  │ Scanner  │  │   Scanner     │    │
│    └────┬────┘  └────┬─────┘  └──────┬────────┘    │
│         │            │               │              │
│    ┌────▼────────────▼───────────────▼────────┐     │
│    │          Shell Script Wrappers            │     │
│    │  run-nmap-scan.sh / run-nikto-scan.sh /   │     │
│    │          run-nuclei-scan.sh               │     │
│    └────────────────┬─────────────────────────┘     │
│                     │                               │
│    ┌────────────────▼─────────────────────────┐     │
│    │     Parsers (XML / CSV / JSONL)          │     │
│    └────────────────┬─────────────────────────┘     │
│                     │                               │
│    ┌────────────────▼─────────────────────────┐     │
│    │    SQLite (Prisma) + AI Remediation      │     │
│    └──────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

| Tool | Install |
|------|---------|
| **Node.js 18+** | `nvm install 18` |
| **Bun** | `curl -fsSL https://bun.sh/install \| bash` |
| **Nmap** | `sudo apt install nmap` or `brew install nmap` |
| **Nikto** | `sudo apt install nikto` or `brew install nikto` |
| **Nuclei** | Download from [GitHub Releases](https://github.com/projectdiscovery/nuclei/releases) |

### Setup

```bash
# Clone the repo
git clone https://github.com/luckyjain/vulnguard.git
cd vulnguard

# Install dependencies
bun install

# Set up environment
cp .env.example .env

# Initialize database
bun run db:push

# Start development server
bun run dev
```

Open [http://localhost:3000](http://localhost:3000) and start scanning.

### Verify Scanner Tools

```bash
nmap --version     # Should show Nmap 7.80+
nikto -Version     # Should show Nikto 2.5+
nuclei -version    # Should show Nuclei v3+
```

---

## 🌐 Deployment

### Vercel (UI + AI Remediation Only)

VulnGuard can be deployed to Vercel, but **scanning tools require a real server**. On Vercel:

- ✅ The full UI works
- ✅ AI Auto-Remediation works
- ❌ Nmap / Nikto / Nuclei scans won't run (no shell access)

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/luckyjain/vulnguard)

### Self-Hosted (Full Functionality)

For complete scanning capabilities, deploy on a VPS (DigitalOcean, AWS EC2, Hetzner, etc.):

```bash
# Build for production
bun run build

# Start the server
bun run start
```

Or use Docker (recommended for VPS):

```dockerfile
FROM node:18-slim
RUN apt-get update && apt-get install -y nmap nikto
# ... add your Dockerfile
```

---

## 🛠️ Tech Stack

| Category | Technology |
|----------|-----------|
| **Framework** | Next.js 16 (App Router) |
| **Language** | TypeScript 5 |
| **Styling** | Tailwind CSS 4 + shadcn/ui |
| **Database** | SQLite via Prisma ORM |
| **AI** | z-ai-web-dev-sdk (LLM) |
| **Animations** | Framer Motion |
| **Icons** | Lucide React |

---

## 📁 Project Structure

```
vulnguard/
├── prisma/
│   └── schema.prisma          # Database schema (Scan, Schedule)
├── src/
│   ├── app/
│   │   ├── api/
│   │   │   ├── scan/          # Scan initiation + status + results
│   │   │   ├── scans/         # Scan history
│   │   │   ├── schedules/     # CRUD for scheduled scans
│   │   │   └── remediate/     # AI auto-remediation endpoint
│   │   └── page.tsx           # Main dashboard UI
│   ├── components/ui/         # shadcn/ui components
│   └── lib/
│       └── db.ts              # Prisma client singleton
├── run-nmap-scan.sh           # Nmap shell wrapper
├── run-nikto-scan.sh          # Nikto shell wrapper
├── run-nuclei-scan.sh         # Nuclei shell wrapper
└── package.json
```

---

## 🧩 Adding a New Scanner

VulnGuard's modular architecture makes it easy to add new engines:

1. **Create a shell wrapper**: `run-<scanner>-scan.sh` that writes output to `/tmp/vulnguard-scans/`
2. **Add a parser** in `src/app/api/scan/route.ts` — parse the scanner's output format
3. **Add the scan type** to the `resolveScanType` function
4. **Update the frontend** — add engine selector option + results UI
5. Done! That's how Nuclei was added in just 4 file changes.

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

### Additional Terms

By using this software, you agree that:
- You will only use it for **authorized security testing**
- You will **not** use it to scan systems without explicit permission
- You accept full **legal responsibility** for your use of this tool
- The authors are **not liable** for any misuse or damage caused

---

<div align="center">

**Built with ❤️ and AI — Vibecoded by [Lucky Jain](https://github.com/luckyjain)**

*"With great power comes great responsibility."*

</div>
