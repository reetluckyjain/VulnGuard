import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { v4 as uuidv4 } from "uuid";
import { execSync } from "child_process";
import { readFileSync, existsSync, unlinkSync, mkdirSync } from "fs";
import { join, resolve } from "path";

/**
 * POST /api/scan — Create and execute a new scan
 *
 * Supports three scan types:
 *   - nmap: Port scanning + service version detection + vuln scripts
 *   - nikto: Web vulnerability scanning (HTTP-level checks)
 *   - nuclei: Template-based bug hunting (XSS, SQLi, secrets, CVEs)
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

// ─── Nmap Types ──────────────────────────────────────────────────────────────

interface PortInfo { port_id: number; protocol: string; state: string; service: string; version: string }
interface Vulnerability { port_id: number; cve_id: string; description: string }
interface NmapScanResult { target: string; ports: PortInfo[]; vulnerabilities: Vulnerability[] }

// ─── Nikto Types ─────────────────────────────────────────────────────────────

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

// ─── Nuclei Types ────────────────────────────────────────────────────────────

interface NucleiFinding {
  templateId: string;
  name: string;
  severity: string;
  type: string;
  matchedAt: string;
  curlCommand: string | null;
  extractedResults: string[];
  description: string;
  tags: string[];
  reference: string[];
  host: string;
  timestamp: string;
}

interface NucleiScanResult {
  target: string;
  scanType: "nuclei";
  findings: NucleiFinding[];
  vulnerabilities: Vulnerability[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    withCurlCommand: number;
    withExtractedResults: number;
  };
}

// ─── Shared ─────────────────────────────────────────────────────────────────

const CVE_REGEX = /CVE-\d{4}-\d{4,7}/g;

type ScanResultType = NmapScanResult | NiktoScanResult | NucleiScanResult;

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

function parseNmapXml(target: string, xml: string): NmapScanResult {
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

    if (fields.length <= 1 && fields[0]?.startsWith("Nikto")) continue;

    if (fields.length >= 7) {
      const [host, ip, portStr, references, method, path, description] = fields;

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

// ─── Nuclei JSONL Parsing ───────────────────────────────────────────────────

function parseNucleiJsonl(target: string, jsonl: string): NucleiScanResult {
  const findings: NucleiFinding[] = [];
  const vulnerabilities: Vulnerability[] = [];
  const lines = jsonl.split("\n").filter(l => l.trim().length > 0);

  for (const line of lines) {
    try {
      const obj = JSON.parse(line) as Record<string, unknown>;

      const info = (obj.info as Record<string, unknown>) || {};

      const templateId = (obj["template-id"] as string) || (obj.templateID as string) || "";
      const name = (info.name as string) || templateId || "Unknown Finding";
      const severity = normalizeSeverity((info.severity as string) || "info");
      const type = (obj.type as string) || "http";
      const matchedAt = (obj["matched-at"] as string) || (obj.matched as string) || "";
      const host = (obj.host as string) || target;
      const timestamp = (obj.timestamp as string) || new Date().toISOString();

      const curlCommand = (obj["curl-command"] as string) || null;

      const extractedResults = Array.isArray(obj["extracted-results"])
        ? (obj["extracted-results"] as string[])
        : [];

      const tags = Array.isArray(info.tags)
        ? (info.tags as string[]).map(String)
        : typeof info.tags === "string"
          ? info.tags.split(",").map(t => t.trim()).filter(Boolean)
          : [];
      const reference = Array.isArray(info.reference)
        ? (info.reference as string[]).map(String)
        : [];

      let description = name;
      if (extractedResults.length > 0) {
        description += ` — Extracted: ${extractedResults.join(", ")}`;
      }
      if (matchedAt) {
        description += ` at ${matchedAt}`;
      }

      findings.push({
        templateId,
        name,
        severity,
        type,
        matchedAt,
        curlCommand,
        extractedResults,
        description,
        tags,
        reference,
        host,
        timestamp,
      });

      const cveText = `${templateId} ${tags.join(" ")} ${name}`;
      CVE_REGEX.lastIndex = 0;
      const cveMatches = cveText.match(CVE_REGEX);
      if (cveMatches) {
        const seen = new Set<string>();
        for (const cveId of cveMatches) {
          if (!seen.has(cveId)) {
            seen.add(cveId);
            vulnerabilities.push({
              port_id: 0,
              cve_id: cveId,
              description: `${cveId} detected by nuclei template ${templateId}: ${name}`,
            });
          }
        }
      }
    } catch {
      console.warn("[API] Skipping unparseable nuclei JSONL line");
    }
  }

  const summary = {
    total: findings.length,
    critical: findings.filter(f => f.severity === "critical").length,
    high: findings.filter(f => f.severity === "high").length,
    medium: findings.filter(f => f.severity === "medium").length,
    low: findings.filter(f => f.severity === "low").length,
    info: findings.filter(f => f.severity === "info").length,
    withCurlCommand: findings.filter(f => f.curlCommand).length,
    withExtractedResults: findings.filter(f => f.extractedResults.length > 0).length,
  };

  return { target, scanType: "nuclei", findings, vulnerabilities, summary };
}

function normalizeSeverity(severity: string): string {
  const s = severity.toLowerCase().trim();
  if (["critical", "high", "medium", "low", "info"].includes(s)) return s;
  if (s === "unknown" || s === "") return "info";
  return s;
}

// ─── Temp file helpers ──────────────────────────────────────────────────────

const TMP_DIR = "/tmp/vulnguard-scans";

function ensureTmpDir() {
  try { mkdirSync(TMP_DIR, { recursive: true }); } catch {}
}

// ─── Result Processor ───────────────────────────────────────────────────────

export async function processScanResults(scanId: string, scanType: string): Promise<{ status: string; results: ScanResultType | null; error: string | null }> {
  const statusFile = join(TMP_DIR, `${scanId}.status`);

  if (existsSync(statusFile)) {
    const status = readFileSync(statusFile, "utf-8").trim();
    if (status.startsWith("error:")) {
      return { status: "Failed", results: null, error: status.slice(6) };
    }
    if (status === "completed") {
      if (scanType === "nuclei") {
        const jsonlFile = join(TMP_DIR, `${scanId}-nuclei.jsonl`);
        let result: NucleiScanResult = {
          target: "", scanType: "nuclei",
          findings: [], vulnerabilities: [],
          summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, withCurlCommand: 0, withExtractedResults: 0 },
        };

        if (existsSync(jsonlFile)) {
          try {
            const jsonl = readFileSync(jsonlFile, "utf-8");
            if (jsonl.trim().length > 0) {
              result = parseNucleiJsonl("", jsonl);
            }
          } catch (err) {
            console.error("[API] Error parsing Nuclei JSONL:", err);
          }
        }

        try {
          await db.scan.update({
            where: { id: scanId },
            data: { status: "Completed", results: JSON.stringify(result) },
          });
        } catch {}

        try { unlinkSync(jsonlFile); } catch {}
        try { unlinkSync(statusFile); } catch {}

        return { status: "Completed", results: result, error: null };

      } else if (scanType === "nikto") {
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

        try {
          await db.scan.update({
            where: { id: scanId },
            data: { status: "Completed", results: JSON.stringify(result) },
          });
        } catch {}

        try { unlinkSync(csvFile); } catch {}
        try { unlinkSync(statusFile); } catch {}

        return { status: "Completed", results: result, error: null };

      } else {
        const xmlFile = join(TMP_DIR, `${scanId}.xml`);
        const vulnXmlFile = join(TMP_DIR, `${scanId}-vuln.xml`);
        let result: NmapScanResult = { target: "", ports: [], vulnerabilities: [] };

        if (existsSync(xmlFile)) {
          try {
            const xml = readFileSync(xmlFile, "utf-8");
            if (xml.includes("</nmaprun>")) {
              result = parseNmapXml("", xml);
            }
          } catch {}
        }

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

        try {
          await db.scan.update({
            where: { id: scanId },
            data: { status: "Completed", results: JSON.stringify(result) },
          });
        } catch {}

        try { unlinkSync(xmlFile); } catch {}
        try { unlinkSync(vulnXmlFile); } catch {}
        try { unlinkSync(statusFile); } catch {}

        return { status: "Completed", results: result, error: null };
      }
    }
  }

  return { status: "Running", results: null, error: null };
}

// ─── Scan Type Resolver ─────────────────────────────────────────────────────

function resolveScanType(scanType: string): "nmap" | "nikto" | "nuclei" {
  if (scanType === "nikto") return "nikto";
  if (scanType === "nuclei") return "nuclei";
  return "nmap";
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

    const effectiveScanType = resolveScanType(scanType || "nmap");
    const scanId = uuidv4();

    // Check if scanner script exists (won't exist on Vercel/serverless)
    const scriptMap: Record<string, string> = {
      nuclei: "run-nuclei-scan.sh",
      nikto: "run-nikto-scan.sh",
      nmap: "run-nmap-scan.sh",
    };
    const scriptFile = scriptMap[effectiveScanType];
    const scriptPath = resolve(process.cwd(), scriptFile);

    if (!existsSync(scriptPath)) {
      return NextResponse.json({
        error: `Scanner tool not available in this environment. The ${effectiveScanType} scanner requires a self-hosted server with the scanning tools installed. Deploy on a VPS for full functionality. See the README for setup instructions.`,
        scan_type: effectiveScanType,
        target: targetTrimmed,
        deployment_mode: "serverless",
      }, { status: 501 });
    }

    ensureTmpDir();

    await db.scan.create({
      data: { id: scanId, target: targetTrimmed, scanType: effectiveScanType, status: "Running" },
    });

    const scanPort = port || "80";

    if (effectiveScanType === "nuclei") {
      try {
        execSync(
          `nohup bash ${scriptPath} ${scanId} ${targetTrimmed} ${scanPort} &>/tmp/vulnguard-nuclei-${scanId}.log &`,
          { timeout: 5000, shell: "/bin/bash", env: { ...process.env, HOME: process.env.HOME || "/home/z" } }
        );
      } catch {
        // Background process — always returns 0
      }
      console.log(`[API] Spawned nuclei script for scan ${scanId}, target ${targetTrimmed}:${scanPort}`);

    } else if (effectiveScanType === "nikto") {
      try {
        execSync(
          `nohup bash ${scriptPath} ${scanId} ${targetTrimmed} ${scanPort} &>/tmp/vulnguard-nikto-${scanId}.log &`,
          { timeout: 5000, shell: "/bin/bash", env: { ...process.env, HOME: process.env.HOME || "/home/z" } }
        );
      } catch {
        // Background & always returns 0 — the process runs independently
      }
      console.log(`[API] Spawned nikto script for scan ${scanId}, target ${targetTrimmed}:${scanPort}`);

    } else {
      try {
        execSync(
          `nohup bash ${scriptPath} ${scanId} ${targetTrimmed} &>/tmp/vulnguard-nmap-${scanId}.log &`,
          { timeout: 5000, shell: "/bin/bash", env: { ...process.env, HOME: process.env.HOME || "/home/z" } }
        );
      } catch {
        // Background & always returns 0 — the process runs independently
      }
      console.log(`[API] Spawned nmap script for scan ${scanId}, target ${targetTrimmed}`);
    }

    const engineMessages: Record<string, string> = {
      nuclei: "Nuclei vulnerability scan initiated. Poll GET /api/scan/[id] for results.",
      nikto: "Nikto web vulnerability scan initiated. Poll GET /api/scan/[id] for results.",
      nmap: "Nmap scan initiated. Poll GET /api/scan/[id] for results.",
    };

    return NextResponse.json({
      scan_id: scanId,
      target: targetTrimmed,
      scan_type: effectiveScanType,
      status: "Running",
      message: engineMessages[effectiveScanType],
    }, { status: 201 });

  } catch (error) {
    console.error("[API] Error creating scan:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export { parseNmapXml, parseNiktoCsv, parseNucleiJsonl };
