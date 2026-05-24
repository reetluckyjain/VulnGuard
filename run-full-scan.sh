#!/bin/bash
# VulnGuard Full Scan — Runs all 3 engines in parallel
# Real data only — no mocks
#
# Usage: ./run-full-scan.sh <scan_id> <target> [port]
#
# Spawns nmap, nikto, and nuclei simultaneously.
# Each sub-scan uses a suffixed ID (scanid-nmap, scanid-nikto, scanid-nuclei)
# and writes its own output files.
# Individual done files track completion; a watcher checks when all 3 are done.

SCAN_ID="$1"
TARGET="$2"
PORT="${3:-80}"
TMP_DIR="/tmp/vulnguard-scans"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:$PATH"

mkdir -p "$TMP_DIR"

# ─── Status tracking ─────────────────────────────────────────────────────────
# Use individual "done" files per engine to avoid race conditions
echo "running" > "${TMP_DIR}/${SCAN_ID}.status"

# ─── Completion callback (atomic - each engine writes its own done file) ─────
on_subscan_done() {
    local engine="$1"
    echo "done" > "${TMP_DIR}/${SCAN_ID}-full-${engine}.done"
    echo "[FullScan] $engine completed"

    # Check if all 3 are done
    local done_count=0
    for eng in nmap nikto nuclei; do
        if [ -f "${TMP_DIR}/${SCAN_ID}-full-${eng}.done" ]; then
            done_count=$((done_count + 1))
        fi
    done

    echo "[FullScan] $done_count/3 engines completed"

    if [ "$done_count" -ge 3 ]; then
        echo "completed" > "${TMP_DIR}/${SCAN_ID}.status"
        echo "[FullScan] All 3 engines completed for $TARGET"
    fi
}

# ─── Nmap sub-scan (ID = scanid-nmap) ────────────────────────────────────────
(
    bash "${SCRIPT_DIR}/run-nmap-scan.sh" "${SCAN_ID}-nmap" "$TARGET" 2>/dev/null
    on_subscan_done "nmap"
) &

# ─── Nikto sub-scan (ID = scanid-nikto) ─────────────────────────────────────
(
    bash "${SCRIPT_DIR}/run-nikto-scan.sh" "${SCAN_ID}-nikto" "$TARGET" "$PORT" 2>/dev/null
    on_subscan_done "nikto"
) &

# ─── Nuclei sub-scan (ID = scanid-nuclei) ────────────────────────────────────
(
    bash "${SCRIPT_DIR}/run-nuclei-scan.sh" "${SCAN_ID}-nuclei" "$TARGET" "$PORT" 2>/dev/null
    on_subscan_done "nuclei"
) &

# Wait for background launcher processes to finish
wait

echo "[FullScan] All engines launched for $TARGET (scan ID: $SCAN_ID)"
