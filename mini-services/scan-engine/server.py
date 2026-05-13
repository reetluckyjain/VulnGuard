#!/usr/bin/env python3
"""
VulnGuard Scan Engine — Production-Ready FastAPI Service

Uses python-nmap for real vulnerability scanning.
All results come from actual nmap scans — NO MOCK DATA.

Architecture:
  Next.js POST /api/scan → calls this FastAPI /scan → python-nmap scan → updates DB
  Next.js GET /api/scan/[id] → reads results from DB (Prisma)

Strict JSON Data Contract:
{
    "target": str,
    "ports": [{"port_id": int, "protocol": str, "state": str, "service": str, "version": str}],
    "vulnerabilities": [{"port_id": int, "cve_id": str, "description": str}]
}
"""

import os
import re
import sys
import json
import sqlite3
import logging
import signal
import subprocess
import traceback
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ─── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [scan-engine] %(levelname)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("scan-engine")

# ─── Configuration ─────────────────────────────────────────────────────────────

DB_PATH = os.environ.get("DB_PATH", "/home/z/my-project/db/custom.db")
PORT = 3001

# Ensure nmap is on PATH
local_bin = os.path.expanduser("~/.local/bin")
current_path = os.environ.get("PATH", "")
if local_bin not in current_path:
    os.environ["PATH"] = f"{local_bin}:{current_path}"
    logger.info(f"Added {local_bin} to PATH")

# Prevent SIGCHLD from killing the process when nmap child exits
try:
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
except (OSError, ValueError):
    pass

# Find nmap binary
NMAP_BIN = None
for candidate in [
    os.path.expanduser("~/.local/bin/nmap"),
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
    "nmap",
]:
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        NMAP_BIN = candidate
        break
    # Also try shutil.which
    if candidate == "nmap":
        import shutil
        found = shutil.which("nmap")
        if found:
            NMAP_BIN = found
            break

if NMAP_BIN:
    logger.info(f"nmap binary found: {NMAP_BIN}")
else:
    logger.error("nmap binary NOT FOUND — scans will fail!")

# ─── CVE Regex ─────────────────────────────────────────────────────────────────

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}")

# ─── Thread pool for running scans ────────────────────────────────────────────

executor = ThreadPoolExecutor(max_workers=2)

# ─── FastAPI App ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="VulnGuard Scan Engine",
    version="5.0.0",
    description="Production-ready nmap vulnerability scanner with python-nmap",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Pydantic Models ─────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    scan_id: str
    target: str

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class HealthResponse(BaseModel):
    status: str
    nmap_available: bool
    nmap_path: Optional[str]
    python_nmap: bool

# ─── Database Helpers ─────────────────────────────────────────────────────────

def update_scan_status(scan_id: str, status: str, results: Optional[str] = None):
    """Update a scan's status and optionally its results in the SQLite DB."""
    now = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(DB_PATH, timeout=15)
    try:
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
        logger.info(f"DB updated: scan {scan_id} → {status}")
    except Exception as e:
        logger.error(f"DB update failed for scan {scan_id}: {e}")
        raise
    finally:
        conn.close()

# ─── Result Builders (Strict JSON Contract) ──────────────────────────────────

def make_port(port_id: int, protocol: str, state: str, service: str, version: str) -> dict:
    """Build a port dict matching the strict JSON contract."""
    return {
        "port_id": port_id,
        "protocol": protocol,
        "state": state,
        "service": service,
        "version": version,
    }

def make_vulnerability(port_id: int, cve_id: str, description: str) -> dict:
    """Build a vulnerability dict matching the strict JSON contract."""
    return {
        "port_id": port_id,
        "cve_id": cve_id,
        "description": description,
    }

def make_scan_result(target: str, ports: list, vulnerabilities: list) -> dict:
    """Build a scan result dict matching the strict JSON contract."""
    return {
        "target": target,
        "ports": ports,
        "vulnerabilities": vulnerabilities,
    }

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

# ─── python-nmap Parser (Primary) ────────────────────────────────────────────

def parse_with_python_nmap(target: str, nm) -> Optional[dict]:
    """
    Parse real python-nmap output using the dictionary structure:
        nm[host]['tcp'][port]['state']
        nm[host]['tcp'][port]['name']
        nm[host]['tcp'][port]['version']
        nm[host]['tcp'][port]['product']
        nm[host]['tcp'][port]['extrainfo']
        nm[host]['tcp'][port]['script']

    This is the PRIMARY parser — uses the python-nmap library's dict output.
    """
    ports = []
    vulnerabilities = []

    for host in nm.all_hosts():
        host_state = nm[host].state()
        logger.info(f"python-nmap: Host {host} state={host_state}")

        if host_state == "down":
            continue

        for proto in nm[host].all_protocols():
            port_keys = sorted(nm[host][proto].keys())
            logger.info(f"  Protocol: {proto}, ports: {port_keys}")

            for port in port_keys:
                p = nm[host][proto][port]
                state = p.get("state", "unknown")
                service_name = p.get("name", "unknown")
                product = p.get("product", "")
                version = p.get("version", "")
                extrainfo = p.get("extrainfo", "")

                # Build version string from product + version + extrainfo
                parts = []
                if product:
                    parts.append(product)
                if version:
                    parts.append(version)
                if extrainfo:
                    parts.append(f"({extrainfo})")
                version_str = " ".join(parts) if parts else "Unknown"

                ports.append(make_port(port, proto, state, service_name, version_str))

                # Extract CVEs from script output
                scripts = p.get("script", {})
                if scripts:
                    logger.info(f"    Port {port}/{proto} has {len(scripts)} script(s)")
                    for script_id, script_output in scripts.items():
                        if not script_output:
                            continue
                        combined_text = str(script_output)
                        found_cves = CVE_REGEX.findall(combined_text)

                        seen = set()
                        for cve_id in found_cves:
                            if cve_id not in seen:
                                seen.add(cve_id)
                                desc = _extract_cve_description(
                                    cve_id, combined_text, script_id, port, proto
                                )
                                vulnerabilities.append(
                                    make_vulnerability(port, cve_id, desc)
                                )

    logger.info(
        f"python-nmap parsed: {len(ports)} ports, {len(vulnerabilities)} vulns for {target}"
    )
    return make_scan_result(target, ports, vulnerabilities)

# ─── Direct XML Parser (Fallback) ────────────────────────────────────────────

def parse_nmap_xml(target: str, xml_string: str) -> dict:
    """Parse nmap XML output directly using ElementTree (fallback parser)."""
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

            # Extract CVEs from script elements
            for script_elem in port_elem.findall("script"):
                script_id = script_elem.get("id", "unknown")
                script_output = script_elem.get("output", "")
                cve_texts = [script_output] if script_output else []
                for elem in script_elem.findall(".//elem"):
                    if elem.text:
                        cve_texts.append(elem.text)
                # Also check table elements for CVE data
                for table in script_elem.findall(".//table"):
                    for elem in table.findall(".//elem"):
                        if elem.text:
                            cve_texts.append(elem.text)
                combined_text = " ".join(cve_texts)
                found_cves = CVE_REGEX.findall(combined_text)
                seen = set()
                for cve_id in found_cves:
                    if cve_id not in seen:
                        seen.add(cve_id)
                        desc = _extract_cve_description(
                            cve_id, combined_text, script_id, port_id, protocol
                        )
                        vulnerabilities.append(make_vulnerability(port_id, cve_id, desc))

    logger.info(
        f"XML parsed: {len(ports)} ports, {len(vulnerabilities)} vulns for {target}"
    )
    return make_scan_result(target, ports, vulnerabilities)

# ─── XML Output Parser (Try python-nmap first, then ElementTree) ──────────────

def parse_xml_output(target: str, xml_string: str) -> dict:
    """Try python-nmap library first, then fallback to direct XML parsing."""
    result = None

    # Attempt 1: python-nmap library (preferred)
    try:
        import nmap as nmap_lib

        nm = nmap_lib.PortScanner()
        nm.analyse_nmap_xml_scan(xml_string)
        if nm.all_hosts():
            result = parse_with_python_nmap(target, nm)
            logger.info(f"python-nmap parsed successfully for {target}")
        else:
            logger.warning(f"python-nmap found no hosts for {target}")
    except Exception as e:
        logger.warning(f"python-nmap parse failed, falling back to XML: {e}")

    # Attempt 2: Direct XML parsing (fallback)
    if result is None:
        result = parse_nmap_xml(target, xml_string)
        logger.info(f"Direct XML parsed for {target}")

    return result

# ─── nmap Execution ──────────────────────────────────────────────────────────

def run_nmap_subprocess(args: list, timeout: int) -> Optional[str]:
    """Run nmap as a subprocess and return stdout (XML string)."""
    cmd_str = " ".join(args)
    logger.info(f"Running: {cmd_str}")
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            logger.warning(f"nmap timed out after {timeout}s")
            return None

        if stderr and proc.returncode not in (0, 1):
            logger.warning(f"nmap stderr: {stderr[:300]}")

        if proc.returncode not in (0, 1):
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


def execute_scan(scan_id: str, target: str) -> dict:
    """
    Execute a full nmap scan for a target using python-nmap.

    Strategy (adaptive, no root required):
    1. Primary: nmap -sT -sV -oX - --max-retries 2 --host-timeout 30s <target>
       (Service version detection — works without root)
    2. Optional: nmap -sT -sV --script vuln -oX - -p <open_ports> --max-retries 1 --host-timeout 60s <target>
       (Vulnerability scripts on open ports — may need root for some scripts)
    3. Fallback: nmap -sT -oX - --max-retries 1 --host-timeout 30s <target>
       (Basic port scan)

    All parsing uses real nmap output. NO MOCK DATA.
    """
    nmap_cmd = NMAP_BIN or "nmap"

    # Attempt 1: Service version scan
    logger.info(f"[Attempt 1] nmap -sT -sV for {target}")
    xml_output = run_nmap_subprocess(
        [nmap_cmd, "-sT", "-sV", "-oX", "-", "--max-retries", "2", "--host-timeout", "30s", target],
        timeout=60,
    )

    if xml_output:
        result = parse_xml_output(target, xml_output)

        if not result["ports"]:
            logger.info(f"No ports found in service scan for {target}")
            return result

        # Attempt 2: Vuln scripts on open ports
        open_ports = [p for p in result["ports"] if p["state"] == "open"]
        if open_ports:
            port_list = ",".join(str(p["port_id"]) for p in open_ports)
            logger.info(f"[Attempt 2] Running vuln scripts on ports: {port_list}")
            vuln_xml = run_nmap_subprocess(
                [nmap_cmd, "-sT", "-sV", "--script", "vuln", "-oX", "-",
                 "-p", port_list, "--max-retries", "1", "--host-timeout", "60s", target],
                timeout=180,
            )

            if vuln_xml:
                vuln_result = parse_xml_output(target, vuln_xml)
                if vuln_result and vuln_result.get("vulnerabilities"):
                    result["vulnerabilities"] = vuln_result["vulnerabilities"]
                    logger.info(f"Found {len(vuln_result['vulnerabilities'])} vulnerabilities for {target}")
            else:
                logger.warning(f"Vuln scan produced no output for {target}")
        else:
            logger.info(f"No open ports found for {target}, skipping vuln scan")

        return result

    # Attempt 3: Basic port scan (fallback)
    logger.info(f"[Attempt 3] Fallback: basic port scan for {target}")
    xml_output = run_nmap_subprocess(
        [nmap_cmd, "-sT", "-oX", "-", "--max-retries", "1", "--host-timeout", "30s", target],
        timeout=60,
    )

    if xml_output:
        return parse_xml_output(target, xml_output)

    raise RuntimeError(f"All nmap scan methods failed for {target}")

# ─── Background Scan Runner ──────────────────────────────────────────────────

def run_scan_background(scan_id: str, target: str):
    """Run nmap scan in background thread and update DB with results."""
    try:
        logger.info(f"Starting background scan for {target} (scan_id={scan_id})")
        update_scan_status(scan_id, "Running")

        result = execute_scan(scan_id, target)
        result_json = json.dumps(result, ensure_ascii=False)

        logger.info(f"Scan result JSON length: {len(result_json)} bytes")
        update_scan_status(scan_id, "Completed", result_json)

        logger.info(
            f"Scan {scan_id} COMPLETED: {len(result['ports'])} ports, "
            f"{len(result['vulnerabilities'])} vulns"
        )
    except Exception as e:
        logger.error(f"Scan {scan_id} FAILED: {e}")
        logger.error(traceback.format_exc())
        error_result = json.dumps({"error": str(e)}, ensure_ascii=False)
        try:
            update_scan_status(scan_id, "Failed", error_result)
        except Exception as db_err:
            logger.error(f"Failed to save error state to DB: {db_err}")

# ─── API Endpoints ────────────────────────────────────────────────────────────

@app.post("/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    """
    Start a real nmap scan for the given target.
    The scan runs in a background thread and results are saved to the DB.
    """
    if not NMAP_BIN:
        raise HTTPException(status_code=500, detail="nmap binary not found on this server")

    logger.info(f"Received scan request: scan_id={request.scan_id}, target={request.target}")

    # Submit the scan to the thread pool (non-blocking)
    executor.submit(run_scan_background, request.scan_id, request.target)

    return ScanResponse(
        scan_id=request.scan_id,
        status="Running",
        message=f"Real nmap scan started for {request.target} using python-nmap",
    )


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    python_nmap_available = False
    try:
        import nmap as nmap_lib
        python_nmap_available = True
    except ImportError:
        pass

    return HealthResponse(
        status="ok",
        nmap_available=NMAP_BIN is not None,
        nmap_path=NMAP_BIN,
        python_nmap=python_nmap_available,
    )


# ─── Startup ──────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    logger.info("=" * 60)
    logger.info("VulnGuard Scan Engine (FastAPI + python-nmap) starting")
    logger.info(f"Database: {DB_PATH}")
    logger.info(f"nmap binary: {NMAP_BIN or 'NOT FOUND'}")
    logger.info(f"Port: {PORT}")

    try:
        import nmap as nmap_lib
        logger.info(f"python-nmap {nmap_lib.__version__} available")
    except ImportError:
        logger.warning("python-nmap not installed — will use XML fallback parser")

    # Verify DB exists
    if os.path.exists(DB_PATH):
        logger.info(f"Database file found: {DB_PATH}")
    else:
        logger.warning(f"Database file NOT found: {DB_PATH}")

    logger.info("=" * 60)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
