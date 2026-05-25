#!/bin/bash
# VulnGuard Nmap Scanner — Fast Mode
# Uses -F (top 100 ports) and -sV only (NO --script vuln, too slow)
# REAL DATA ONLY - no mocks

SCAN_ID="$1"
TARGET="$2"
TMP_DIR="/tmp/vulnguard-scans"

export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:$PATH"
NMAP="$(command -v nmap 2>/dev/null || echo '/usr/bin/nmap')"

XML_FILE="${TMP_DIR}/${SCAN_ID}.xml"
STATUS_FILE="${TMP_DIR}/${SCAN_ID}.status"

mkdir -p "$TMP_DIR"
echo "running" > "$STATUS_FILE"

# Fast nmap scan: top 100 ports, service version detection, 30s host timeout
"$NMAP" -sT -sV -F --top-ports 100 --max-retries 1 --host-timeout 30s --min-rate 100 -oX "$XML_FILE" "$TARGET" 2>/dev/null

if [ ! -f "$XML_FILE" ] || ! grep -q "</nmaprun>" "$XML_FILE" 2>/dev/null; then
    # Fallback: basic scan without -sV
    "$NMAP" -sT -F --top-ports 100 --max-retries 1 --host-timeout 30s --min-rate 100 -oX "$XML_FILE" "$TARGET" 2>/dev/null
fi

if [ ! -f "$XML_FILE" ] || ! grep -q "</nmaprun>" "$XML_FILE" 2>/dev/null; then
    echo "error:nmap produced no valid output" > "$STATUS_FILE"
    exit 1
fi

echo "completed" > "$STATUS_FILE"
