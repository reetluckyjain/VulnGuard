#!/bin/bash
# Standalone Nuclei vulnerability scanner - completely independent of Next.js
# Runs with nohup for process independence
# REAL DATA ONLY - no mocks
#
# Usage: ./run-nuclei-scan.sh <scan_id> <target> [port]
#
# Nuclei scans for real web vulnerabilities: XSS, SQLi, exposed secrets, CVEs,
# misconfigurations, default logins, and more using community-maintained templates.

SCAN_ID="$1"
TARGET="$2"
PORT="${3:-}"
TMP_DIR="/tmp/vulnguard-scans"

# Auto-detect nuclei from PATH (include user-local bin)
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:$PATH"
NUCLEI="$(command -v nuclei 2>/dev/null || echo '/home/z/.local/bin/nuclei')"
NUCLEI_TEMPLATES="${NUCLEI_TEMPLATES_DIR:-$HOME/nuclei-templates}"

JSONL_FILE="${TMP_DIR}/${SCAN_ID}-nuclei.jsonl"
STATUS_FILE="${TMP_DIR}/${SCAN_ID}.status"

mkdir -p "$TMP_DIR"
echo "running" > "$STATUS_FILE"

# Build target URL — nuclei expects URLs (http/https)
if echo "$TARGET" | grep -qE '^https?://'; then
    SCAN_URL="$TARGET"
elif [ -n "$PORT" ] && [ "$PORT" != "80" ] && [ "$PORT" != "443" ]; then
    SCAN_URL="http://${TARGET}:${PORT}"
else
    SCAN_URL="http://${TARGET}"
fi

# Run Nuclei with JSONL output, silent mode
# -jle = JSONL export to file
# -silent = only show findings
# -ot = omit template data from output (smaller JSONL)
# -timeout 5 = per-request timeout
# -c 10 = 10 concurrent templates
# -rl 50 = rate limit 50 requests/sec
# -retries 1 = retry failed requests once
# -no-strict-syntax = be lenient with template parsing
# -bs = bulk size
timeout 120 "$NUCLEI" \
    -u "$SCAN_URL" \
    -jle "$JSONL_FILE" \
    -silent \
    -ot \
    -timeout 5 \
    -c 10 \
    -rl 50 \
    -retries 1 \
    -no-strict-syntax \
    -t "$NUCLEI_TEMPLATES/http/cves/" \
    -t "$NUCLEI_TEMPLATES/http/vulnerabilities/" \
    -t "$NUCLEI_TEMPLATES/http/exposures/" \
    -t "$NUCLEI_TEMPLATES/http/misconfiguration/" \
    -t "$NUCLEI_TEMPLATES/http/default-logins/" \
    -t "$NUCLEI_TEMPLATES/http/takeovers/" \
    2>/dev/null

# Nuclei may exit with non-zero but still produce valid output
# Check if JSONL file exists and has content
if [ ! -f "$JSONL_FILE" ]; then
    # No findings = create empty JSONL file (this is a valid result)
    touch "$JSONL_FILE"
fi

echo "completed" > "$STATUS_FILE"
