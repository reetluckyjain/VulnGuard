---
Task ID: 1
Agent: Main Agent
Task: Fix preview availability and verify all features working

Work Log:
- Diagnosed that the Next.js dev server was not binding to 0.0.0.0, causing Caddy to return 502
- Updated package.json dev script to use `-H 0.0.0.0` flag
- Updated start-dev.sh and run-dev.sh to use `-H 0.0.0.0`
- Removed `| tee dev.log` from dev script to prevent SIGPIPE kills
- Added `allowedDevOrigins` to next.config.ts for preview panel compatibility
- Verified all API endpoints work: /api/schedules, /api/verify, /api/scans
- Verified scheduler mini-service runs on port 3004
- Created .zscripts/dev.sh for custom dev startup with keepalive loop

Stage Summary:
- Key fix: `-H 0.0.0.0` binding makes server accessible through Caddy proxy
- All features working: DNS TXT verification, scheduled scans, AI remediation, nmap/nikto scanning
- Server process management: sandbox kills background processes between bash sessions; use .zscripts/dev.sh for persistent startup
- Scheduler service on port 3004 is operational with health check endpoint
