#!/bin/bash
# Standalone Nikto web vulnerability scanner - completely independent of Next.js
# Runs with nohup for process independence
# REAL DATA ONLY - no mocks

SCAN_ID="$1"
TARGET="$2"
PORT="${3:-80}"
TMP_DIR="/tmp/vulnguard-scans"

# Auto-detect nikto from PATH (include user-local bin)
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:$PATH"
NIKTO="$(command -v nikto 2>/dev/null || echo '/tmp/nikto/program/nikto.pl')"

CSV_FILE="${TMP_DIR}/${SCAN_ID}-nikto.csv"
STATUS_FILE="${TMP_DIR}/${SCAN_ID}.status"

mkdir -p "$TMP_DIR"
echo "running" > "$STATUS_FILE"

# Build nikto command with CSV output (most reliable format)
NIKTO_OPTS="-h $TARGET -p $PORT -Format csv -o $CSV_FILE -nointeractive -C all -maxtime 90s"

# Run Nikto with timeout (max 120 seconds)
timeout 120 $NIKTO $NIKTO_OPTS 2>/dev/null

EXIT_CODE=$?

# Nikto may exit with non-zero but still produce valid output
if [ ! -f "$CSV_FILE" ] || [ ! -s "$CSV_FILE" ]; then
    echo "error:nikto produced no output" > "$STATUS_FILE"
    exit 1
fi

# Verify CSV has at least 2 lines (header + at least one finding)
LINE_COUNT=$(wc -l < "$CSV_FILE" 2>/dev/null || echo "0")
if [ "$LINE_COUNT" -lt 2 ]; then
    echo "error:nikto output was incomplete" > "$STATUS_FILE"
    exit 1
fi

echo "completed" > "$STATUS_FILE"
