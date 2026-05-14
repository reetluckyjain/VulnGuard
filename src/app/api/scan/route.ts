import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { v4 as uuidv4 } from "uuid";
import { execSync } from "child_process";
import { readFileSync, existsSync, unlinkSync, mkdirSync } from "fs";
import { join } from "path";

/**
 * POST /api/scan — Create and execute a new scan
 *
 * Supports two scan types:
 *   - nmap: Port scanning + service version detection + vuln scripts
 *   - nikto: Web vulnerability scanning (HTTP-level checks)
 *
 * Spawns the scanner via a standalone shell script that runs completely independently.
 * The script writes output to temp files, which are read by the GET route.
 *
 * NO MOCK DATA — Real scans only.
 */

// ─── Authorization ──────────────────────────────────────────────────────────

function verifyAuthorization(target: string): { authorized: boolean; reason?: string } {
  const blockedPatterns = [/^0\./, /^169\.254\./];
  for (const pattern of blockedPatterns) {
    if (pattern.test(target)) {
      return { authorized: false, reason: "Scanning link-local/current-network addresses is restricted" };
    }
  }
  return { authorized: true };
}

// ─── Types ──────────────────────────────────────────────────────────────────

interface PortInfo { port_id: number; protocol: string; state: string; service: string; version: string }
interface Vulnerability { port_id: number; cve_id: string; description: string }
interface ScanResult { target: string; ports: PortInfo[]; vulnerabilities: Vulnerability[] }

// ─── Nikto-specific types ───────────────────────────────────────────────────

interface NiktoFinding {
  id: string;
  host: string;
  ip: string;
  port: number;
  method: string;
  path: string;
  description: string;
  references: string[];
}

interface NiktoScanResult {
  target: string;
  scanType: "nikto";
  server: string;
  findings: NiktoFinding[];
  vulnerabilities: Vulnerability[];
  summary: { total: number; info: number; low: number; medium: number; high: number };
}

// ─── Shared ─────────────────────────────────────────────────────────────────

const CVE_REGEX = /CVE-\d{4}-\d{4,7}/g;

// ─── Nmap XML Parsing ───────────────────────────────────────────────────────

function extractCveDescription(cveId: string, text: string, scriptId: string, port: number, proto: string): string {
  const idx = text.indexOf(cveId);
  if (idx >= 0) {
    const start = Math.max(0, idx - 80);
    const end = Math.min(text.length, idx + cveId.length + 200);
    let snippet = text.slice(start, end).trim().replace(/\s+/g, " ");
    if (snippet.length >= 15) return snippet.slice(0, 400);
  }
  return `${cveId} detected by nmap ${scriptId} script on port ${port}/${proto}`;
}

function parseNmapXml(target: string, xml: string): ScanResult {
  const ports: PortInfo[] = [];
  const vulnerabilities: Vulnerability[] = [];

  const portRegex = /<port\s+protocol="([^"]*)"\s+portid="(\d+)">([\s\S]*?)<\/port>/g;
  let portMatch;

  while ((portMatch = portRegex.exec(xml)) !== null) {
    const protocol = portMatch[1];
    const portId = parseInt(portMatch[2], 10);
    const portBlock = portMatch[3];

    const stateMatch = portBlock.match(/<state\s+state="([^"]*)"/);
    const state = stateMatch?.[1] || "unknown";

    const svcMatch = portBlock.match(/<service\s+([^>]*?)(?:\/>|>)/);
    let serviceName = "unknown";
    let versionStr = "Unknown";

    if (svcMatch) {
      const svcAttrs = svcMatch[1];
      serviceName = svcAttrs.match(/name="([^"]*)"/)?.[1] || "unknown";
      const product = svcAttrs.match(/product="([^"]*)"/)?.[1] || "";
      const version = svcAttrs.match(/version="([^"]*)"/)?.[1] || "";
      const extrainfo = svcAttrs.match(/extrainfo="([^"]*)"/)?.[1] || "";
      const parts: string[] = [];
      if (product) parts.push(product);
      if (version) parts.push(version);
      if (extrainfo) parts.push(`(${extrainfo})`);
      versionStr = parts.length > 0 ? parts.join(" ") : "Unknown";
    }

    ports.push({ port_id: portId, protocol, state, service: serviceName, version: versionStr });

    const scriptRegex = /<script\s+id="([^"]*)"\s+output="([^"]*)"([\s\S]*?)<\/script>/g;
    let scriptMatch;
    while ((scriptMatch = scriptRegex.exec(portBlock)) !== null) {
      const scriptId = scriptMatch[1];
      const scriptOutput = scriptMatch[2].replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&").replace(/&quot;/g, '"');
      const scriptBody = scriptMatch[3];
      const textParts: string[] = [scriptOutput];
      const elemRegex = /<elem[^>]*>([\s\S]*?)<\/elem>/g;
      let elemMatch;
      while ((elemMatch = elemRegex.exec(scriptBody)) !== null) {
        if (elemMatch[1]) textParts.push(elemMatch[1].trim());
      }
      const combinedText = textParts.join(" ");
      CVE_REGEX.lastIndex = 0;
      const cveMatches = combinedText.match(CVE_REGEX);
      if (cveMatches) {
        const seen = new Set<string>();
        for (const cveId of cveMatches) {
          if (!seen.has(cveId)) {
            seen.add(cveId);
            vulnerabilities.push({ port_id: portId, cve_id: cveId, description: extractCveDescription(cveId, combinedText, scriptId, portId, protocol) });
          }
        }
      }
    }
  }
  return { target, ports, vulnerabilities };
}

// ─── Nikto CSV Parsing ──────────────────────────────────────────────────────

function parseNiktoCsv(target: string, csv: string): NiktoScanResult {
  const findings: NiktoFinding[] = [];
  const vulnerabilities: Vulnerability[] = [];
  let server = "Unknown";

  const lines = csv.split("\n").map(l => l.trim()).filter(Boolean);

  for (const line of lines) {
    // Parse quoted CSV: "field1","field2",...
    const fields: string[] = [];
    let current = "";
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQuotes && i + 1 < line.length && line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (ch === ',' && !inQuotes) {
        fields.push(current);
        current = "";
      } else {
        current += ch;
      }
    }
    fields.push(current);

    // Header line: "Nikto - v2.6.0/"
    if (fields.length <= 1 && fields[0]?.startsWith("Nikto")) continue;

    // Data line: hostname, ip, port, references, method, path, description
    if (fields.length >= 7) {
      const [host, ip, portStr, references, method, path, description] = fields;

      // Detect server header from description
      if (description?.includes("appears to be outdated") || description?.includes("Server:")) {
        const serverMatch = description.match(/(?:Server:\s*|^)([A-Za-z][^\s.]+)/);
        if (serverMatch) server = serverMatch[1];
      }

      const port = parseInt(portStr, 10) || 80;

      const finding: NiktoFinding = {
        id: `nikto-${findings.length + 1}`,
        host: host || target,
        ip: ip || "",
        port,
        method: method || "GET",
        path: path || "/",
        description: description || "",
        references: references ? references.split(",").map(r => r.trim()).filter(Boolean) : [],
      };
      findings.push(finding);

      // Extract CVEs from references and description
      CVE_REGEX.lastIndex = 0;
      const allText = `${references} ${description}`;
      const cveMatches = allText.match(CVE_REGEX);
      if (cveMatches) {
        const seen = new Set<string>();
        for (const cveId of cveMatches) {
          if (!seen.has(cveId)) {
            seen.add(cveId);
            const idx = allText.indexOf(cveId);
            const start = Math.max(0, idx - 60);
            const end = Math.min(allText.length, idx + cveId.length + 150);
            let snippet = allText.slice(start, end).trim().replace(/\s+/g, " ");
            if (snippet.length < 15) snippet = `${cveId} detected by Nikto on port ${port}`;
            vulnerabilities.push({
              port_id: port,
              cve_id: cveId,
              description: snippet.slice(0, 400),
            });
          }
        }
      }
    }
  }

  // Compute summary
  const summary = {
    total: findings.length,
    info: findings.filter(f =>
      f.description.toLowerCase().includes("suggested security header") ||
      f.description.toLowerCase().includes("uncommon header")
    ).length,
    low: findings.filter(f =>
      f.description.toLowerCase().includes("outdated") ||
      f.description.toLowerCase().includes("mod_negotiation")
    ).length,
    medium: findings.filter(f =>
      f.references.length > 0 &&
      !f.description.toLowerCase().includes("suggested security header") &&
      !f.description.toLowerCase().includes("uncommon header")
    ).length,
    high: findings.filter(f =>
      f.description.toLowerCase().includes("xss") ||
      f.description.toLowerCase().includes("sql") ||
      f.description.toLowerCase().includes("injection") ||
      f.description.toLowerCase().includes("rce") ||
      f.description.toLowerCase().includes("remote code")
    ).length,
  };

  return { target, scanType: "nikto", server, findings, vulnerabilities, summary };
}

// ─── Temp file helpers ──────────────────────────────────────────────────────

const TMP_DIR = "/tmp/vulnguard-scans";

function ensureTmpDir() {
  try { mkdirSync(TMP_DIR, { recursive: true }); } catch {}
}

// ─── Result Processor ───────────────────────────────────────────────────────

export async function processScanResults(scanId: string, scanType: string): Promise<{ status: string; results: ScanResult | NiktoScanResult | null; error: string | null }> {
  const statusFile = join(TMP_DIR, `${scanId}.status`);

  // Check status file for errors
  if (existsSync(statusFile)) {
    const status = readFileSync(statusFile, "utf-8").trim();
    if (status.startsWith("error:")) {
      return { status: "Failed", results: null, error: status.slice(6) };
    }
    if (status === "completed") {
      if (scanType === "nikto") {
        // Process Nikto CSV
        const csvFile = join(TMP_DIR, `${scanId}-nikto.csv`);
        let result: NiktoScanResult = { target: "", scanType: "nikto", server: "Unknown", findings: [], vulnerabilities: [], summary: { total: 0, info: 0, low: 0, medium: 0, high: 0 } };

        if (existsSync(csvFile)) {
          try {
            const csv = readFileSync(csvFile, "utf-8");
            if (csv.trim().length > 0) {
              result = parseNiktoCsv("", csv);
            }
          } catch (err) {
            console.error("[API] Error parsing Nikto CSV:", err);
          }
        }

        // Update DB
        try {
          await db.scan.update({
            where: { id: scanId },
            data: { status: "Completed", results: JSON.stringify(result) },
          });
        } catch {}

        // Clean up temp files
        try { unlinkSync(csvFile); } catch {}
        try { unlinkSync(statusFile); } catch {}

        return { status: "Completed", results: result, error: null };
      } else {
        // Process nmap XML files
        const xmlFile = join(TMP_DIR, `${scanId}.xml`);
        const vulnXmlFile = join(TMP_DIR, `${scanId}-vuln.xml`);
        let result: ScanResult = { target: "", ports: [], vulnerabilities: [] };

        if (existsSync(xmlFile)) {
          try {
            const xml = readFileSync(xmlFile, "utf-8");
            if (xml.includes("</nmaprun>")) {
              result = parseNmapXml("", xml);
            }
          } catch {}
        }

        // Also check vuln XML
        if (existsSync(vulnXmlFile)) {
          try {
            const vulnXml = readFileSync(vulnXmlFile, "utf-8");
            if (vulnXml.includes("</nmaprun>")) {
              const vulnResult = parseNmapXml("", vulnXml);
              if (vulnResult.vulnerabilities.length > 0) {
                result.vulnerabilities = vulnResult.vulnerabilities;
              }
              const existingPorts = new Set(result.ports.map(p => p.port_id));
              for (const p of vulnResult.ports) {
                if (!existingPorts.has(p.port_id)) {
                  result.ports.push(p);
                  existingPorts.add(p.port_id);
                }
              }
            }
          } catch {}
        }

        // Update DB
        try {
          await db.scan.update({
            where: { id: scanId },
            data: { status: "Completed", results: JSON.stringify(result) },
          });
        } catch {}

        // Clean up temp files
        try { unlinkSync(xmlFile); } catch {}
        try { unlinkSync(vulnXmlFile); } catch {}
        try { unlinkSync(statusFile); } catch {}

        return { status: "Completed", results: result, error: null };
      }
    }
  }

  return { status: "Running", results: null, error: null };
}

// ─── API Route Handler ─────────────────────────────────────────────────────

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { target, isAuthorized, scanType, port } = body;

    if (!target || typeof target !== "string") {
      return NextResponse.json({ error: "Target IP/hostname is required" }, { status: 400 });
    }

    const targetTrimmed = target.trim();
    if (targetTrimmed.length < 3 || targetTrimmed.length > 253) {
      return NextResponse.json({ error: "Invalid target format" }, { status: 400 });
    }

    if (!isAuthorized) {
      return NextResponse.json({ error: "You must confirm authorization before scanning" }, { status: 403 });
    }

    const auth = verifyAuthorization(targetTrimmed);
    if (!auth.authorized) {
      return NextResponse.json({ error: auth.reason || "Target not authorized for scanning" }, { status: 403 });
    }

    const effectiveScanType = scanType === "nikto" ? "nikto" : "nmap";
    const scanId = uuidv4();

    ensureTmpDir();

    await db.scan.create({
      data: { id: scanId, target: targetTrimmed, scanType: effectiveScanType, status: "Running" },
    });

    if (effectiveScanType === "nikto") {
      // Spawn Nikto via standalone shell script
      const scriptPath = "/home/z/my-project/run-nikto-scan.sh";
      const scanPort = port || "80";
      try {
        execSync(
          `nohup bash ${scriptPath} ${scanId} ${targetTrimmed} ${scanPort} &>/tmp/vulnguard-nikto-${scanId}.log &`,
          {
            timeout: 5000,
            shell: "/bin/bash",
            env: {
              ...process.env,
              HOME: process.env.HOME || "/home/z",
            },
          }
        );
      } catch {
        // Background & always returns 0 — the process runs independently
      }
      console.log(`[API] Spawned nikto script for scan ${scanId}, target ${targetTrimmed}:${scanPort}`);
    } else {
      // Spawn nmap via standalone shell script
      const scriptPath = "/home/z/my-project/run-nmap-scan.sh";
      try {
        execSync(
          `nohup bash ${scriptPath} ${scanId} ${targetTrimmed} &>/tmp/vulnguard-nmap-${scanId}.log &`,
          {
            timeout: 5000,
            shell: "/bin/bash",
            env: {
              ...process.env,
              PATH: `/home/z/.local/bin:${process.env.PATH}`,
              HOME: process.env.HOME || "/home/z",
            },
          }
        );
      } catch {
        // Background & always returns 0 — the process runs independently
      }
      console.log(`[API] Spawned nmap script for scan ${scanId}, target ${targetTrimmed}`);
    }

    return NextResponse.json({
      scan_id: scanId,
      target: targetTrimmed,
      scan_type: effectiveScanType,
      status: "Running",
      message: effectiveScanType === "nikto"
        ? "Nikto web vulnerability scan initiated. Poll GET /api/scan/[id] for results."
        : "Nmap scan initiated. Poll GET /api/scan/[id] for results.",
    }, { status: 201 });

  } catch (error) {
    console.error("[API] Error creating scan:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export { parseNmapXml, parseNiktoCsv };
