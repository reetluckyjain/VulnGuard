#!/bin/bash
# Standalone nmap scanner - completely independent of Next.js
# Runs with nohup for process independence
# REAL DATA ONLY - no mocks

SCAN_ID="$1"
TARGET="$2"
TMP_DIR="/tmp/vulnguard-scans"

# Auto-detect nmap from PATH (include user-local bin)
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:$PATH"
NMAP="$(command -v nmap 2>/dev/null || echo '/usr/bin/nmap')"

XML_FILE="${TMP_DIR}/${SCAN_ID}.xml"
STATUS_FILE="${TMP_DIR}/${SCAN_ID}.status"

mkdir -p "$TMP_DIR"
echo "running" > "$STATUS_FILE"

# Run nmap service version scan
"$NMAP" -sT -sV -oX "$XML_FILE" --max-retries 2 --host-timeout 60s "$TARGET" 2>/dev/null

if [ ! -f "$XML_FILE" ] || ! grep -q "</nmaprun>" "$XML_FILE" 2>/dev/null; then
    # Fallback: basic scan
    "$NMAP" -sT -oX "$XML_FILE" --max-retries 1 --host-timeout 60s "$TARGET" 2>/dev/null
fi

if [ ! -f "$XML_FILE" ] || ! grep -q "</nmaprun>" "$XML_FILE" 2>/dev/null; then
    echo "error:nmap produced no valid output" > "$STATUS_FILE"
    exit 1
fi

# Try vuln scan on open ports (with timeout)
OPEN_PORTS=$(grep -oP 'portid="\K\d+' "$XML_FILE" | head -10 | tr '\n' ',' | sed 's/,$//')
if [ -n "$OPEN_PORTS" ]; then
    VULN_XML_FILE="${TMP_DIR}/${SCAN_ID}-vuln.xml"
    timeout 60 "$NMAP" -sT -sV --script vuln -oX "$VULN_XML_FILE" -p "$OPEN_PORTS" --max-retries 1 --host-timeout 30s "$TARGET" 2>/dev/null || true
fi

echo "completed" > "$STATUS_FILE"
