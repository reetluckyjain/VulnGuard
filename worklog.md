---
Task ID: 1
Agent: Main Agent
Task: Integrate Nuclei as third scanning engine into VulnGuard

Work Log:
- Installed Nuclei v3.3.7 binary from GitHub releases to /home/z/.local/bin/nuclei
- Updated nuclei templates to /home/z/nuclei-templates/
- Created run-nuclei-scan.sh shell wrapper with JSONL output format (-jle flag)
- Script targets CVEs, vulnerabilities, exposures, misconfigurations, default-logins, and takeovers templates
- Added NucleiFinding and NucleiScanResult TypeScript interfaces to backend
- Created parseNucleiJsonl() parser that extracts: template-id, name, severity, type, matched-at, curl-command, extracted-results, tags, references
- Updated POST /api/scan to accept "nuclei" as scanType with resolveScanType helper
- Updated processScanResults() to handle nuclei JSONL files
- Updated GET /api/scan/[id] — already generic, handles nuclei through processScanResults
- Updated /api/remediate to handle Nuclei findings with specialized prompts for curl commands and extracted secrets
- Updated frontend with Nuclei types, engine selector, port input, info text
- Added comprehensive Nuclei results UI with severity grouping, curl reproduction blocks, extracted data pills
- Updated header badges, footer, schedule dropdown
- All lint checks pass, dev server running on port 3000

Stage Summary:
- Nuclei v3.3.7 fully integrated as third engine alongside Nmap and Nikto
- Real data only — nuclei binary executes actual template-based scans
- JSONL parser handles all key fields including curl-command and extracted-results
- Frontend displays findings grouped by severity with copy-able curl reproduction commands
- Modular plugin architecture proven: adding a new engine required changes to 4 files (scan script, API route, remediate route, page.tsx)
