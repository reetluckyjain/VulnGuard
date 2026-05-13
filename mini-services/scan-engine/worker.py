#!/usr/bin/env python3
"""
VulnGuard Scan Engine — Database-Driven Worker

Polls the SQLite database for Pending scans, runs real nmap, and updates
results back to the database. No HTTP server — this avoids the SIGCHLD
issue that kills the parent process when nmap subprocess exits.

Architecture:
  Next.js API route → writes "Pending" scan to DB
  This worker        → polls DB, runs nmap, updates DB with results
  Next.js API route  → reads scan status from DB

Strict JSON Data Contract:
{
    "target": str,
    "ports": [{"port_id": int, "protocol": str, "state": str, "service": str, "version": str}],
    "vulnerabilities": [{"port_id": int, "cve_id": str, "description": str}]
}

NO MOCK DATA — All results come from real nmap scans.
"""

import os
import re
import sys
import json
import time
import signal
import sqlite3
import logging
import subprocess
import traceback
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

# ─── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [worker] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("worker")

# ─── Configuration ─────────────────────────────────────────────────────────────

DB_PATH = os.environ.get("DB_PATH", "/home/z/my-project/db/custom.db")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "2"))
NMAP_TIMEOUT_SERVICE = int(os.environ.get("NMAP_TIMEOUT_SERVICE", "45"))
NMAP_TIMEOUT_VULN = int(os.environ.get("NMAP_TIMEOUT_VULN", "120"))
NMAP_TIMEOUT_BASIC = int(os.environ.get("NMAP_TIMEOUT_BASIC", "45"))

# ─── Ensure nmap is on PATH ───────────────────────────────────────────────────

local_bin = os.path.expanduser("~/.local/bin")
current_path = os.environ.get("PATH", "")
if local_bin not in current_path:
    os.environ["PATH"] = f"{local_bin}:{current_path}"
    logger.info(f"Added {local_bin} to PATH")

# Verify nmap is available
NMAP_BIN = None
for candidate in ["nmap", os.path.expanduser("~/.local/bin/nmap"), "/usr/bin/nmap", "/usr/local/bin/nmap"]:
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        NMAP_BIN = candidate
        break
    # Check via PATH
    try:
        result = subprocess.run(["which", "nmap"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            NMAP_BIN = result.stdout.strip()
            break
    except Exception:
        pass

if NMAP_BIN:
    logger.info(f"nmap binary found: {NMAP_BIN}")
else:
    logger.error("nmap binary NOT FOUND — scans will fail!")

# ─── CVE Regex ─────────────────────────────────────────────────────────────────

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}")


# ─── Database Helpers ─────────────────────────────────────────────────────────


def get_db_connection() -> sqlite3.Connection:
    """Create a new SQLite connection with row factory for dict-like access."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def fetch_pending_scans(conn: sqlite3.Connection) -> list[dict]:
    """Fetch all scans with status 'Pending'."""
    cursor = conn.execute(
        'SELECT id, target, status FROM "Scan" WHERE status = ?',
        ("Pending",),
    )
    rows = cursor.fetchall()
    return [dict(row) for row in rows]


def update_scan_status(conn: sqlite3.Connection, scan_id: str, status: str, results: str | None = None):
    """Update a scan's status and optionally its results."""
    now = datetime.now(timezone.utc).isoformat()
    if results is not None:
        conn.execute(
            'UPDATE "Scan" SET status = ?, results = ?, "updatedAt" = ? WHERE id = ?',
            (status, results, now, scan_id),
        )
    else:
        conn.execute(
            'UPDATE "Scan" SET status = ?, "updatedAt" = ? WHERE id = ?',
            (status, now, scan_id),
        )
    conn.commit()


# ─── Result Builders ──────────────────────────────────────────────────────────


def make_port(port_id: int, protocol: str, state: str, service: str, version: str) -> dict:
    return {"port_id": port_id, "protocol": protocol, "state": state, "service": service, "version": version}


def make_vulnerability(port_id: int, cve_id: str, description: str) -> dict:
    return {"port_id": port_id, "cve_id": cve_id, "description": description}


def make_scan_result(target: str, ports: list, vulnerabilities: list) -> dict:
    return {"target": target, "ports": ports, "vulnerabilities": vulnerabilities}


# ─── CVE Description Extraction ───────────────────────────────────────────────


def _extract_cve_description(cve_id: str, text: str, script_id: str, port: int, proto: str) -> str:
    """Extract CVE description from surrounding context in nmap script output."""
    idx = text.find(cve_id)
    if idx >= 0:
        start = max(0, idx - 80)
        end = min(len(text), idx + len(cve_id) + 200)
        snippet = text[start:end].strip()
        snippet = re.sub(r"\s+", " ", snippet)
        if len(snippet) >= 15:
            return snippet[:400]
    return f"{cve_id} detected by nmap {script_id} script on port {port}/{proto}"


# ─── python-nmap Parser ──────────────────────────────────────────────────────


def parse_nmap_results(target: str, nm) -> dict:
    """
    Parse real python-nmap output using the dictionary structure:
        nm[host]['tcp'][port]['state']
        nm[host]['tcp'][port]['name']
        nm[host]['tcp'][port]['version']
        nm[host]['tcp'][port]['product']
        nm[host]['tcp'][port]['extrainfo']
        nm[host]['tcp'][port]['script']
    """
    ports = []
    vulnerabilities = []

    for host in nm.all_hosts():
        host_state = nm[host].state()
        logger.info(f"Host {host} state: {host_state}")

        if host_state == "down":
            continue

        for proto in nm[host].all_protocols():
            logger.info(f"  Protocol: {proto}, ports: {sorted(nm[host][proto].keys())}")
            for port in sorted(nm[host][proto].keys()):
                p = nm[host][proto][port]
                state = p.get("state", "unknown")
                service_name = p.get("name", "unknown")
                product = p.get("product", "")
                version = p.get("version", "")
                extrainfo = p.get("extrainfo", "")

                # Build version string from available components
                parts = []
                if product:
                    parts.append(product)
                if version:
                    parts.append(version)
                if extrainfo:
                    parts.append(f"({extrainfo})")

                version_str = " ".join(parts) if parts else "Unknown"

                ports.append(make_port(port, proto, state, service_name, version_str))

                # Parse script output for CVEs
                scripts = p.get("script", {})
                if scripts:
                    logger.info(f"    Port {port}/{proto} has {len(scripts)} script(s)")
                    for script_id, script_output in scripts.items():
                        if not script_output:
                            continue
                        combined_text = script_output
                        found_cves = CVE_REGEX.findall(combined_text)

                        seen = set()
                        for cve_id in found_cves:
                            if cve_id not in seen:
                                seen.add(cve_id)
                                desc = _extract_cve_description(cve_id, combined_text, script_id, port, proto)
                                vulnerabilities.append(make_vulnerability(port, cve_id, desc))

    logger.info(f"python-nmap parsed: {len(ports)} ports, {len(vulnerabilities)} vulns for {target}")
    return make_scan_result(target, ports, vulnerabilities)


# ─── Direct XML Parser (fallback) ────────────────────────────────────────────


def parse_nmap_xml(target: str, xml_string: str) -> dict:
    """Parse nmap XML output directly using ElementTree."""
    ports = []
    vulnerabilities = []

    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as e:
        logger.error(f"XML parse error: {e}")
        return make_scan_result(target, [], [])

    for host_elem in root.findall(".//host"):
        status = host_elem.find("status")
        host_state = status.get("state", "unknown") if status is not None else "unknown"
        logger.info(f"XML: Host state = {host_state}")

        if host_state == "down":
            continue

        for port_elem in host_elem.findall(".//port"):
            port_id = int(port_elem.get("portid", "0"))
            protocol = port_elem.get("protocol", "tcp")

            state_elem = port_elem.find("state")
            state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

            service_elem = port_elem.find("service")
            service_name = "unknown"
            version_str = "Unknown"
            if service_elem is not None:
                service_name = service_elem.get("name", "unknown")
                product = service_elem.get("product", "")
                version = service_elem.get("version", "")
                extrainfo = service_elem.get("extrainfo", "")

                parts = []
                if product:
                    parts.append(product)
                if version:
                    parts.append(version)
                if extrainfo:
                    parts.append(f"({extrainfo})")
                version_str = " ".join(parts) if parts else "Unknown"

            ports.append(make_port(port_id, protocol, state, service_name, version_str))

            # Parse script output for CVEs
            for script_elem in port_elem.findall("script"):
                script_id = script_elem.get("id", "unknown")
                script_output = script_elem.get("output", "")
                cve_texts = [script_output] if script_output else []
                for elem in script_elem.findall(".//elem"):
                    if elem.text:
                        cve_texts.append(elem.text)
                combined_text = " ".join(cve_texts)
                found_cves = CVE_REGEX.findall(combined_text)
                seen = set()
                for cve_id in found_cves:
                    if cve_id not in seen:
                        seen.add(cve_id)
                        desc = _extract_cve_description(cve_id, combined_text, script_id, port_id, protocol)
                        vulnerabilities.append(make_vulnerability(port_id, cve_id, desc))

    logger.info(f"XML parsed: {len(ports)} ports, {len(vulnerabilities)} vulns for {target}")
    return make_scan_result(target, ports, vulnerabilities)


# ─── nmap Execution ──────────────────────────────────────────────────────────


def run_nmap_subprocess(args: list[str], timeout: int) -> str | None:
    """
    Run nmap as a subprocess and return stdout (XML string).

    CRITICAL: We use subprocess.Popen + communicate() instead of subprocess.run()
    because subprocess.run() is incompatible with signal.SIGCHLD being set
    to SIG_IGN. With SIG_IGN, the OS auto-reaps child processes, which
    causes subprocess.run()'s internal wait() to fail. Popen + explicit
    communicate() handles this correctly.
    """
    logger.info(f"Running: {' '.join(args)}")
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()  # Clean up
            logger.warning(f"nmap timed out after {timeout}s")
            return None

        if stderr and proc.returncode not in (0, 1):
            logger.warning(f"nmap stderr: {stderr[:300]}")

        if proc.returncode not in (0, 1):  # 0=success, 1=host down (still valid XML)
            logger.warning(f"nmap exited with code {proc.returncode}")

        if stdout and "<nmaprun" in stdout:
            return stdout
        else:
            logger.warning("nmap output does not contain valid XML")
            return None

    except FileNotFoundError:
        logger.error(f"nmap binary not found! Tried: {args[0]}")
        return None
    except Exception as e:
        logger.error(f"nmap execution error: {e}")
        logger.error(traceback.format_exc())
        return None


def parse_xml_output(target: str, xml_string: str) -> dict | None:
    """
    Try to parse nmap XML output using python-nmap first,
    then fall back to direct ElementTree parsing.
    """
    result = None

    # Try python-nmap first (rich dictionary access)
    try:
        import nmap as nmap_lib
        nm = nmap_lib.PortScanner()
        nm.analyse_nmap_xml_scan(xml_string)
        if nm.all_hosts():
            result = parse_nmap_results(target, nm)
            logger.info(f"python-nmap parsed successfully for {target}")
        else:
            logger.warning(f"python-nmap found no hosts for {target}")
    except Exception as e:
        logger.warning(f"python-nmap parse failed: {e}")

    # Fallback to direct XML parsing
    if result is None:
        result = parse_nmap_xml(target, xml_string)
        logger.info(f"Direct XML parsed for {target}")

    return result


def execute_scan(scan_id: str, target: str) -> dict:
    """
    Execute a full nmap scan for a target.

    Strategy (adaptive, no root required):
    1. Primary: nmap -sT -sV -oX - --max-retries 2 --host-timeout 30s <target>
    2. Optional: nmap -sT -sV --script vuln -oX - -p <open_ports> --max-retries 1 --host-timeout 60s <target>
    3. Fallback: nmap -sT -oX - --max-retries 1 --host-timeout 30s <target>

    All parsing uses real nmap output. NO mock data.
    """
    nmap_cmd = NMAP_BIN or "nmap"

    # ── Attempt 1: Service version scan ──────────────────────────────
    logger.info(f"[Attempt 1] nmap -sT -sV for {target}")
    xml_output = run_nmap_subprocess(
        [nmap_cmd, "-sT", "-sV", "-oX", "-", "--max-retries", "2", "--host-timeout", "30s", target],
        timeout=NMAP_TIMEOUT_SERVICE,
    )

    if xml_output:
        result = parse_xml_output(target, xml_output)

        if not result["ports"]:
            logger.info(f"No ports found in service scan for {target}, returning empty result")
            return result

        # ── Attempt 2: Vuln scripts on open ports ───────────────────
        # Run vulnerability scripts on discovered open ports for CVE detection
        open_ports = [p for p in result["ports"] if p["state"] == "open"]
        if open_ports:
            port_list = ",".join(str(p["port_id"]) for p in open_ports)
            logger.info(f"[Attempt 2] Running vuln scripts on ports: {port_list}")
            vuln_xml = run_nmap_subprocess(
                [nmap_cmd, "-sT", "-sV", "--script", "vuln", "-oX", "-",
                 "-p", port_list, "--max-retries", "1", "--host-timeout", "60s", target],
                timeout=NMAP_TIMEOUT_VULN,
            )

            if vuln_xml:
                vuln_result = parse_xml_output(target, vuln_xml)
                if vuln_result and vuln_result.get("vulnerabilities"):
                    # Merge vuln results, keeping original port data
                    result["vulnerabilities"] = vuln_result["vulnerabilities"]
                    logger.info(f"Found {len(vuln_result['vulnerabilities'])} vulnerabilities for {target}")
                else:
                    logger.info(f"No vulnerabilities found by vuln scripts for {target}")
            else:
                logger.warning(f"Vuln scan produced no output for {target}")
        else:
            logger.info(f"No open ports found for {target}, skipping vuln scan")

        return result

    # ── Attempt 3: Basic port scan (fallback) ───────────────────────
    logger.info(f"[Attempt 3] Fallback: basic port scan for {target}")
    xml_output = run_nmap_subprocess(
        [nmap_cmd, "-sT", "-oX", "-", "--max-retries", "1", "--host-timeout", "30s", target],
        timeout=NMAP_TIMEOUT_BASIC,
    )

    if xml_output:
        result = parse_xml_output(target, xml_output)
        return result

    # All attempts failed
    raise RuntimeError(f"All nmap scan methods failed for {target}. Check nmap installation and target reachability.")


# ─── Main Worker Loop ─────────────────────────────────────────────────────────


def process_scan(scan_id: str, target: str):
    """Process a single pending scan: run nmap and update the database."""
    logger.info(f"=" * 40)
    logger.info(f"Processing scan {scan_id} for target {target}")
    logger.info(f"=" * 40)

    # Mark as Running (use a fresh connection)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        conn.execute('UPDATE "Scan" SET status = ?, "updatedAt" = ? WHERE id = ?',
                     ("Running", datetime.now(timezone.utc).isoformat(), scan_id))
        conn.commit()
    finally:
        conn.close()

    try:
        result = execute_scan(scan_id, target)
        result_json = json.dumps(result, ensure_ascii=False)

        logger.info(f"Scan result JSON length: {len(result_json)} bytes")
        logger.info(f"Result preview: {result_json[:200]}")

        # Save results (use a fresh connection)
        conn = sqlite3.connect(DB_PATH, timeout=10)
        try:
            conn.execute('UPDATE "Scan" SET status = ?, results = ?, "updatedAt" = ? WHERE id = ?',
                         ("Completed", result_json, datetime.now(timezone.utc).isoformat(), scan_id))
            conn.commit()
        finally:
            conn.close()

        logger.info(f"Scan {scan_id} COMPLETED: {len(result['ports'])} ports, {len(result['vulnerabilities'])} vulns")
    except Exception as e:
        logger.error(f"Scan {scan_id} FAILED: {e}")
        logger.error(traceback.format_exc())
        error_result = json.dumps({"error": str(e)}, ensure_ascii=False)

        # Save failure (use a fresh connection)
        try:
            conn = sqlite3.connect(DB_PATH, timeout=10)
            conn.execute('UPDATE "Scan" SET status = ?, results = ?, "updatedAt" = ? WHERE id = ?',
                         ("Failed", error_result, datetime.now(timezone.utc).isoformat(), scan_id))
            conn.commit()
            conn.close()
        except Exception as db_err:
            logger.error(f"Failed to save error state to DB: {db_err}")


def main():
    """Main worker loop: poll DB for pending scans and process them."""
    # ── Critical: Ignore SIGCHLD to prevent process crash ──
    # When nmap subprocess exits, SIGCHLD is sent to the parent process.
    # Without SIG_IGN, this signal can kill the worker process.
    # With SIG_IGN, the OS auto-reaps child processes.
    # NOTE: subprocess.run() is incompatible with SIG_IGN, so we use
    # subprocess.Popen + communicate() instead (see run_nmap_subprocess).
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)

    logger.info("=" * 60)
    logger.info("VulnGuard Scan Worker starting (REAL NMAP MODE)")
    logger.info(f"Database: {DB_PATH}")
    logger.info(f"Poll interval: {POLL_INTERVAL}s")
    logger.info(f"nmap binary: {NMAP_BIN or 'NOT FOUND'}")

    # Verify nmap is available
    if not NMAP_BIN:
        logger.error("nmap binary NOT FOUND! Scans will fail.")
        logger.error("Install nmap and ensure it's on PATH or at ~/.local/bin/nmap")

    # Verify database is accessible
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.execute('SELECT COUNT(*) FROM "Scan"')
        conn.close()
        logger.info("Database connection verified")
    except Exception as e:
        logger.error(f"Cannot connect to database: {e}")
        sys.exit(1)

    # Verify python-nmap is available
    try:
        import nmap as nmap_lib
        logger.info(f"python-nmap {nmap_lib.__version__} available")
    except ImportError:
        logger.warning("python-nmap not installed — will use XML fallback parser")

    logger.info("Worker is ready — polling for pending scans...")
    logger.info("=" * 60)

    consecutive_errors = 0
    max_consecutive_errors = 10

    while True:
        try:
            conn = get_db_connection()
            pending = fetch_pending_scans(conn)

            if pending:
                logger.info(f"Found {len(pending)} pending scan(s)")
                for scan in pending:
                    scan_id = scan["id"]
                    target = scan["target"]
                    conn.close()  # Close before scan (nmap subprocess)
                    process_scan(scan_id, target)
                    conn = get_db_connection()  # Reopen after scan

            conn.close()
            consecutive_errors = 0

        except Exception as e:
            consecutive_errors += 1
            logger.error(f"Worker loop error ({consecutive_errors}/{max_consecutive_errors}): {e}")
            logger.error(traceback.format_exc())

            if consecutive_errors >= max_consecutive_errors:
                logger.critical(f"Too many consecutive errors ({max_consecutive_errors}), shutting down")
                sys.exit(1)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
