---
Task ID: 1
Agent: Main Agent
Task: Implement Hybrid Deployment Architecture for VulnGuard

Work Log:
- Read current project state (scan route, page.tsx, prisma schema, remediation route)
- Verified all scanner tools available locally (nuclei v3.8.0, nmap 7.95, nikto 2.6.0)
- Created `.github/workflows/vulnscan.yml` - GitHub Actions workflow that runs on Ubuntu with all scanners
- Created `/api/scan/callback/route.ts` - Callback endpoint for GitHub Actions to POST results back
- Created `/api/scan/dispatch/route.ts` - Alternative dispatch endpoint
- Modified scan route to support both local and hybrid modes:
  - Added hybrid mode detection and GitHub Actions dispatch logic
  - Fixed nuclei path to include Go bin directory (`~/go/bin`)
  - Fixed nmap path to include Go bin directory
  - Improved tool availability check with multiple path checks
- Updated Prisma schema with `mode` and `githubRunId` fields
- Updated frontend page.tsx:
  - Added `scanMode` state (local/hybrid)
  - Added Deployment mode selector dropdown
  - Added hybrid mode badges and status indicators
  - Added Deployment Architecture info card explaining the hybrid model
  - Updated scan request to include mode parameter
  - Updated timeout for hybrid mode (10 minutes vs 3 minutes)
- Updated `.env.example` with all hybrid deployment env vars
- Verified lint passes cleanly
- Verified dev server running, remediation engine working

Stage Summary:
- Hybrid deployment architecture fully implemented
- GitHub Actions workflow dispatches scans to Ubuntu runners
- Callback API receives results from GitHub Actions
- Frontend supports both local and hybrid scan modes
- Nuclei Go-based installation path fixed (includes ~/go/bin in PATH)
- AI remediation engine confirmed working (LLM returns results in ~34s)
