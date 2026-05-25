import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { v4 as uuidv4 } from "uuid";
import { exec } from "child_process";
import { readFileSync, existsSync, unlinkSync, mkdirSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

/**
 * POST /api/scan — Create and execute a new scan
 *
 * IMPORTANT ARCHITECTURE CHANGE:
 * Scans now execute SYNCHRONOUSLY with timeout protection.
 * Results are returned immediately in the POST response.
 * No shell scripts needed — works cross-platform (Linux + Windows).
 *
 * Supports four scan types:
 *   - nmap: Fast port scanning + service version detection (NO --script vuln, too slow)
 *   - nikto: Web vulnerability scanning (HTTP-level checks)
 *   - nuclei: Template-based bug hunting (XSS, SQLi, secrets, CVEs)
 *   - full: All 3 engines in parallel → unified results + security score
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

// ─── Full Scan Types ────────────────────────────────────────────────────────

interface FullScanResult {
  target: string;
  scanType: "full";
  nmap: NmapScanResult | null;
  nikto: NiktoScanResult | null;
  nuclei: NucleiScanResult | null;
  securityScore: {
    score: number;
    grade: string;
    label: string;
    breakdown: {
      openPorts: { count: number; deduction: number; details: string };
      vulnerabilities: { count: number; deduction: number; details: string };
      cves: { count: number; deduction: number; details: string };
      webFindings: { count: number; deduction: number; details: string };
      nucleiCritical: { count: number; deduction: number; details: string };
      nucleiHigh: { count: number; deduction: number; details: string };
    };
  };
  openPorts: PortInfo[];
  vulnerabilityHints: Array<{
    source: "nmap" | "nikto" | "nuclei";
    severity: string;
    title: string;
    description: string;
    port?: number;
    reference?: string[];
  }>;
  summary: {
    totalOpenPorts: number;
    totalVulnerabilities: number;
    totalCves: number;
    totalWebFindings: number;
    enginesCompleted: number;
  };
}

// ─── Shared ─────────────────────────────────────────────────────────────────

const CVE_REGEX = /CVE-\d{4}-\d{4,7}/g;

type ScanResultType = NmapScanResult | NiktoScanResult | NucleiScanResult | FullScanResult;

// ─── Temp file helpers ──────────────────────────────────────────────────────

const TMP_DIR = join(tmpdir(), "vulnguard-scans");

function ensureTmpDir() {
  try { mkdirSync(TMP_DIR, { recursive: true }); } catch {}
}

// ─── Command Execution with Timeout ─────────────────────────────────────────

function execWithTimeout(command: string, timeoutMs: number, options?: Record<string, unknown>): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const child = exec(command, { maxBuffer: 10 * 1024 * 1024, ...options }, () => {
      if (!settled) {
        settled = true;
        resolve(); // Command completed (even with non-zero exit - OK for scanner tools)
      }
    });

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        try { child.kill(); } catch {}
        reject(new Error(`Scan timed out after ${Math.round(timeoutMs / 1000)}s`));
      }
    }, timeoutMs);

    // Handle spawn errors (e.g., command not found)
    child.on("error", (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(new Error(`Failed to execute scanner: ${err.message}`));
      }
    });
  });
}

// ─── Tool Availability Check ─────────────────────────────────────────────────

async function checkToolAvailable(tool: string): Promise<boolean> {
  const isWindows = process.platform === "win32";
  const envPath = `${process.env.HOME || ""}/.local/bin:${process.env.PATH || ""}`;
  const cmd = isWindows ? `where ${tool} 2>nul` : `which ${tool} 2>/dev/null`;
  try {
    await execWithTimeout(cmd, 5000, {
      env: { ...process.env, PATH: envPath, HOME: process.env.HOME || "/root" },
    });
    return true;
  } catch {
    return false;
  }
}

// ─── Scan Timeout Constants ─────────────────────────────────────────────────

const NMAP_TIMEOUT = 60_000;      // 60 seconds
const NIKTO_TIMEOUT = 90_000;     // 90 seconds
const NUCLEI_TIMEOUT = 90_000;    // 90 seconds
const FULL_SCAN_TIMEOUT = 120_000; // 120 seconds

// ─── Nmap Scan Executor ─────────────────────────────────────────────────────

async function runNmapScan(target: string, scanId: string): Promise<NmapScanResult> {
  ensureTmpDir();
  const xmlFile = join(TMP_DIR, `${scanId}.xml`);

  const homeDir = process.env.HOME || "/root";
  const goBinDir = process.env.GOPATH ? `${process.env.GOPATH}/bin` : `${homeDir}/go/bin`;
  const envPath = `${homeDir}/.local/bin:${goBinDir}:${process.env.PATH || ""}`;

  // Fast nmap scan: service version detection on top 100 ports only
  // NO --script vuln (too slow, causes 5-10 min hangs)
  const cmd = `nmap -sT -sV -F --top-ports 100 --max-retries 1 --host-timeout 30s --min-rate 100 -oX "${xmlFile}" "${target}"`;

  try {
    await execWithTimeout(cmd, NMAP_TIMEOUT, {
      env: { ...process.env, PATH: envPath, HOME: homeDir },
    });
  } catch {
    // Scan may have timed out but still produced partial output - check below
  }

  // Parse output if available
  if (existsSync(xmlFile)) {
    try {
      const xml = readFileSync(xmlFile, "utf-8");
      if (xml.includes("</nmaprun>")) {
        const result = parseNmapXml(target, xml);
        try { unlinkSync(xmlFile); } catch {}
        return result;
      }
    } catch {}
  }

  // Fallback: basic scan without -sV (faster, less info)
  const fallbackCmd = `nmap -sT -F --top-ports 100 --max-retries 1 --host-timeout 30s --min-rate 100 -oX "${xmlFile}" "${target}"`;
  try {
    await execWithTimeout(fallbackCmd, NMAP_TIMEOUT / 2, {
      env: { ...process.env, PATH: envPath, HOME: homeDir },
    });
  } catch {}

  if (existsSync(xmlFile)) {
    try {
      const xml = readFileSync(xmlFile, "utf-8");
      if (xml.includes("</nmaprun>")) {
        const result = parseNmapXml(target, xml);
        try { unlinkSync(xmlFile); } catch {}
        return result;
      }
    } catch {}
  }

  // No output at all
  try { unlinkSync(xmlFile); } catch {}
  return { target, ports: [], vulnerabilities: [] };
}

// ─── Nikto Scan Executor ────────────────────────────────────────────────────

async function runNiktoScan(target: string, port: string, scanId: string): Promise<NiktoScanResult> {
  ensureTmpDir();
  const csvFile = join(TMP_DIR, `${scanId}-nikto.csv`);

  const homeDir = process.env.HOME || "/root";
  const envPath = `${homeDir}/.local/bin:${process.env.PATH || ""}`;

  // Build nikto URL
  const niktoTarget = `http${port === "443" ? "s" : ""}://${target}:${port}`;

  const cmd = `nikto -h "${niktoTarget}" -Format csv -o "${csvFile}" -nointeractive -C all -maxtime 60s`;

  try {
    await execWithTimeout(cmd, NIKTO_TIMEOUT, {
      env: { ...process.env, PATH: envPath, HOME: homeDir, NIKTODIR: `${homeDir}/nikto/program`, PERL5LIB: `${homeDir}/nikto/program` },
    });
  } catch {
    // May have timed out but still produced output
  }

  if (existsSync(csvFile)) {
    try {
      const csv = readFileSync(csvFile, "utf-8");
      if (csv.trim().length > 0) {
        const result = parseNiktoCsv(target, csv);
        try { unlinkSync(csvFile); } catch {}
        return result;
      }
    } catch {}
  }

  try { unlinkSync(csvFile); } catch {}
  return { target, scanType: "nikto", server: "Unknown", findings: [], vulnerabilities: [], summary: { total: 0, info: 0, low: 0, medium: 0, high: 0 } };
}

// ─── Nuclei Scan Executor ───────────────────────────────────────────────────

async function runNucleiScan(target: string, port: string, scanId: string): Promise<NucleiScanResult> {
  ensureTmpDir();
  const jsonlFile = join(TMP_DIR, `${scanId}-nuclei.jsonl`);

  const homeDir = process.env.HOME || "/root";
  // Include Go bin path for nuclei installed via `go install`
  const goBinDir = process.env.GOPATH ? `${process.env.GOPATH}/bin` : `${homeDir}/go/bin`;
  const envPath = `${homeDir}/.local/bin:${goBinDir}:${process.env.PATH || ""}`;
  const templatesDir = process.env.NUCLEI_TEMPLATES_DIR || `${homeDir}/nuclei-templates`;

  // Build target URL
  let scanUrl: string;
  if (/^https?:\/\//.test(target)) {
    scanUrl = target;
  } else if (port && port !== "80" && port !== "443") {
    scanUrl = `http://${target}:${port}`;
  } else if (port === "443") {
    scanUrl = `https://${target}`;
  } else {
    scanUrl = `http://${target}`;
  }

  // Use limited templates for speed (don't scan ALL templates)
  // Nuclei v3.8.0 compatible — installed via `go install`
  const cmd = `nuclei -u "${scanUrl}" -jle "${jsonlFile}" -silent -timeout 5 -c 10 -rl 50 -retries 1 -t "${templatesDir}/http/cves/" -t "${templatesDir}/http/vulnerabilities/" -t "${templatesDir}/http/exposures/" -t "${templatesDir}/http/misconfiguration/"`;

  try {
    await execWithTimeout(cmd, NUCLEI_TIMEOUT, {
      env: { ...process.env, PATH: envPath, HOME: homeDir, NUCLEI_TEMPLATES_DIR: templatesDir },
    });
  } catch {
    // May have timed out but still produced output
  }

  // Nuclei: no findings = empty JSONL = valid result
  if (!existsSync(jsonlFile)) {
    // Create empty file so parsing doesn't fail
    try { mkdirSync(TMP_DIR, { recursive: true }); } catch {}
    const { writeFileSync } = await import("fs");
    writeFileSync(jsonlFile, "");
  }

  try {
    const jsonl = readFileSync(jsonlFile, "utf-8");
    const result = parseNucleiJsonl(target, jsonl);
    try { unlinkSync(jsonlFile); } catch {}
    return result;
  } catch {
    try { unlinkSync(jsonlFile); } catch {}
    return {
      target, scanType: "nuclei", findings: [], vulnerabilities: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, withCurlCommand: 0, withExtractedResults: 0 },
    };
  }
}

// ─── Full Scan Executor ─────────────────────────────────────────────────────

async function runFullScan(target: string, port: string, scanId: string): Promise<FullScanResult> {
  // Run all 3 engines in parallel
  const [nmapSettled, niktoSettled, nucleiSettled] = await Promise.allSettled([
    runNmapScan(target, `${scanId}-nmap`),
    runNiktoScan(target, port, `${scanId}-nikto`),
    runNucleiScan(target, port, `${scanId}-nuclei`),
  ]);

  const nmapResult = nmapSettled.status === "fulfilled" ? nmapSettled.value : null;
  const niktoResult = niktoSettled.status === "fulfilled" ? niktoSettled.value : null;
  const nucleiResult = nucleiSettled.status === "fulfilled" ? nucleiSettled.value : null;

  // Build unified result
  const securityScore = calculateSecurityScore(nmapResult, niktoResult, nucleiResult);
  const vulnerabilityHints = buildVulnerabilityHints(nmapResult, niktoResult, nucleiResult);
  const openPorts = nmapResult?.ports.filter(p => p.state.toLowerCase() === "open") || [];

  const allCves = new Set<string>();
  if (nmapResult) nmapResult.vulnerabilities.forEach(v => allCves.add(v.cve_id));
  if (niktoResult) niktoResult.vulnerabilities.forEach(v => allCves.add(v.cve_id));
  if (nucleiResult) nucleiResult.vulnerabilities.forEach(v => allCves.add(v.cve_id));

  const totalVulns = (nmapResult?.vulnerabilities.length || 0) +
    (niktoResult?.vulnerabilities.length || 0) +
    (nucleiResult?.vulnerabilities.length || 0);

  return {
    target: nmapResult?.target || niktoResult?.target || nucleiResult?.target || target,
    scanType: "full",
    nmap: nmapResult,
    nikto: niktoResult,
    nuclei: nucleiResult,
    securityScore,
    openPorts,
    vulnerabilityHints,
    summary: {
      totalOpenPorts: openPorts.length,
      totalVulnerabilities: totalVulns,
      totalCves: allCves.size,
      totalWebFindings: (niktoResult?.findings.length || 0) + (nucleiResult?.findings.length || 0),
      enginesCompleted: (nmapResult ? 1 : 0) + (niktoResult ? 1 : 0) + (nucleiResult ? 1 : 0),
    },
  };
}

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

// ─── Security Score Calculator ──────────────────────────────────────────────

function calculateSecurityScore(
  nmapResult: NmapScanResult | null,
  niktoResult: NiktoScanResult | null,
  nucleiResult: NucleiScanResult | null,
): FullScanResult["securityScore"] {
  let score = 100;
  const breakdown = {
    openPorts: { count: 0, deduction: 0, details: "" },
    vulnerabilities: { count: 0, deduction: 0, details: "" },
    cves: { count: 0, deduction: 0, details: "" },
    webFindings: { count: 0, deduction: 0, details: "" },
    nucleiCritical: { count: 0, deduction: 0, details: "" },
    nucleiHigh: { count: 0, deduction: 0, details: "" },
  };

  if (nmapResult) {
    const openPorts = nmapResult.ports.filter(p => p.state.toLowerCase() === "open");
    const highRiskPorts = [23, 21, 25, 445, 3389, 5900, 5432, 27017, 6379, 9200];
    const riskyOpen = openPorts.filter(p => highRiskPorts.includes(p.port_id));

    breakdown.openPorts.count = openPorts.length;
    const portDeduction = Math.min(30, openPorts.length * 2 + riskyOpen.length * 5);
    breakdown.openPorts.deduction = portDeduction;
    breakdown.openPorts.details = `${openPorts.length} open ports found${riskyOpen.length > 0 ? ` (${riskyOpen.length} high-risk: ${riskyOpen.map(p => p.port_id).join(", ")})` : ""}`;
    score -= portDeduction;

    const nmapVulns = nmapResult.vulnerabilities || [];
    const uniqueCves = new Set(nmapVulns.map(v => v.cve_id));
    breakdown.vulnerabilities.count = nmapVulns.length;
    breakdown.vulnerabilities.deduction = Math.min(20, nmapVulns.length * 5);
    breakdown.vulnerabilities.details = `${nmapVulns.length} vulnerabilities from nmap scripts`;
    score -= breakdown.vulnerabilities.deduction;

    breakdown.cves.count = uniqueCves.size;
    breakdown.cves.deduction = Math.min(20, uniqueCves.size * 5);
    breakdown.cves.details = `${uniqueCves.size} unique CVEs detected`;
    score -= breakdown.cves.deduction;
  }

  if (niktoResult) {
    const totalFindings = niktoResult.findings.length;
    const highFindings = niktoResult.summary.high;
    const medFindings = niktoResult.summary.medium;

    breakdown.webFindings.count = totalFindings;
    const niktoDeduction = Math.min(25, highFindings * 8 + medFindings * 3);
    breakdown.webFindings.deduction = niktoDeduction;
    breakdown.webFindings.details = `${totalFindings} web findings (${highFindings} high, ${medFindings} medium)`;
    score -= niktoDeduction;
  }

  if (nucleiResult) {
    const criticalCount = nucleiResult.summary.critical;
    const highCount = nucleiResult.summary.high;

    breakdown.nucleiCritical.count = criticalCount;
    breakdown.nucleiCritical.deduction = Math.min(30, criticalCount * 15);
    breakdown.nucleiCritical.details = `${criticalCount} critical severity findings`;

    breakdown.nucleiHigh.count = highCount;
    breakdown.nucleiHigh.deduction = Math.min(20, highCount * 8);
    breakdown.nucleiHigh.details = `${highCount} high severity findings`;

    score -= breakdown.nucleiCritical.deduction;
    score -= breakdown.nucleiHigh.deduction;
  }

  score = Math.max(0, Math.min(100, score));

  let grade: string;
  let label: string;
  if (score >= 95) { grade = "A+"; label = "Excellent"; }
  else if (score >= 90) { grade = "A"; label = "Very Good"; }
  else if (score >= 80) { grade = "B"; label = "Good"; }
  else if (score >= 70) { grade = "C"; label = "Fair"; }
  else if (score >= 60) { grade = "D"; label = "Poor"; }
  else if (score >= 40) { grade = "E"; label = "Bad"; }
  else { grade = "F"; label = "Critical"; }

  return { score, grade, label, breakdown };
}

// ─── Build Vulnerability Hints ──────────────────────────────────────────────

function buildVulnerabilityHints(
  nmapResult: NmapScanResult | null,
  niktoResult: NiktoScanResult | null,
  nucleiResult: NucleiScanResult | null,
): FullScanResult["vulnerabilityHints"] {
  const hints: FullScanResult["vulnerabilityHints"] = [];

  if (nmapResult) {
    for (const v of nmapResult.vulnerabilities) {
      hints.push({
        source: "nmap",
        severity: "high",
        title: v.cve_id,
        description: v.description,
        port: v.port_id,
      });
    }
    for (const p of nmapResult.ports) {
      if (p.state.toLowerCase() === "open" && p.version !== "Unknown") {
        const outdatedKeywords = ["old", "outdated", "2.4.7", "6.6.1", "1.1.1"];
        if (outdatedKeywords.some(k => p.version.toLowerCase().includes(k))) {
          hints.push({
            source: "nmap",
            severity: "medium",
            title: `Potentially outdated: ${p.service} on port ${p.port_id}`,
            description: `${p.service} ${p.version} may be outdated. Check vendor for latest version.`,
            port: p.port_id,
          });
        }
      }
    }
  }

  if (niktoResult) {
    for (const f of niktoResult.findings) {
      let severity = "info";
      if (f.description.toLowerCase().includes("xss") || f.description.toLowerCase().includes("sql") || f.description.toLowerCase().includes("injection")) {
        severity = "high";
      } else if (f.references.length > 0) {
        severity = "medium";
      } else if (f.description.toLowerCase().includes("outdated")) {
        severity = "low";
      }
      hints.push({
        source: "nikto",
        severity,
        title: f.description.slice(0, 120),
        description: f.description,
        port: f.port,
        reference: f.references,
      });
    }
  }

  if (nucleiResult) {
    for (const f of nucleiResult.findings) {
      hints.push({
        source: "nuclei",
        severity: f.severity,
        title: f.name,
        description: f.description,
        reference: f.reference,
      });
    }
  }

  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  hints.sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5));

  return hints;
}

// ─── Scan Type Resolver ─────────────────────────────────────────────────────

function resolveScanType(scanType: string): "nmap" | "nikto" | "nuclei" | "full" {
  if (scanType === "nikto") return "nikto";
  if (scanType === "nuclei") return "nuclei";
  if (scanType === "full") return "full";
  return "nmap";
}

// ─── Result Processor (for backward compatibility with polling GET route) ────

export async function processScanResults(scanId: string, scanType: string): Promise<{ status: string; results: ScanResultType | null; error: string | null }> {
  const statusFile = join(TMP_DIR, `${scanId}.status`);

  if (existsSync(statusFile)) {
    const status = readFileSync(statusFile, "utf-8").trim();
    if (status.startsWith("error:")) {
      return { status: "Failed", results: null, error: status.slice(6) };
    }
    if (status === "completed") {
      // Full Scan
      if (scanType === "full") {
        let nmapResult: NmapScanResult | null = null;
        let niktoResult: NiktoScanResult | null = null;
        let nucleiResult: NucleiScanResult | null = null;

        const nmapXml = join(TMP_DIR, `${scanId}-nmap.xml`);
        const nmapVulnXml = join(TMP_DIR, `${scanId}-nmap-vuln.xml`);
        if (existsSync(nmapXml)) {
          try {
            const xml = readFileSync(nmapXml, "utf-8");
            if (xml.includes("</nmaprun>")) {
              nmapResult = parseNmapXml("", xml);
            }
          } catch {}
        }
        if (nmapResult && existsSync(nmapVulnXml)) {
          try {
            const vulnXml = readFileSync(nmapVulnXml, "utf-8");
            if (vulnXml.includes("</nmaprun>")) {
              const vulnParsed = parseNmapXml("", vulnXml);
              if (vulnParsed.vulnerabilities.length > 0) {
                nmapResult.vulnerabilities = vulnParsed.vulnerabilities;
              }
              const existingPorts = new Set(nmapResult.ports.map(p => p.port_id));
              for (const p of vulnParsed.ports) {
                if (!existingPorts.has(p.port_id)) {
                  nmapResult.ports.push(p);
                  existingPorts.add(p.port_id);
                }
              }
            }
          } catch {}
        }

        const niktoCsv = join(TMP_DIR, `${scanId}-nikto-nikto.csv`);
        if (existsSync(niktoCsv)) {
          try {
            const csv = readFileSync(niktoCsv, "utf-8");
            if (csv.trim().length > 0) {
              niktoResult = parseNiktoCsv("", csv);
            }
          } catch {}
        }

        const nucleiJsonl = join(TMP_DIR, `${scanId}-nuclei-nuclei.jsonl`);
        if (existsSync(nucleiJsonl)) {
          try {
            const jsonl = readFileSync(nucleiJsonl, "utf-8");
            if (jsonl.trim().length > 0) {
              nucleiResult = parseNucleiJsonl("", jsonl);
            }
          } catch {}
        }

        const securityScore = calculateSecurityScore(nmapResult, niktoResult, nucleiResult);
        const vulnerabilityHints = buildVulnerabilityHints(nmapResult, niktoResult, nucleiResult);
        const openPorts = nmapResult?.ports.filter(p => p.state.toLowerCase() === "open") || [];

        const allCves = new Set<string>();
        if (nmapResult) nmapResult.vulnerabilities.forEach(v => allCves.add(v.cve_id));
        if (niktoResult) niktoResult.vulnerabilities.forEach(v => allCves.add(v.cve_id));
        if (nucleiResult) nucleiResult.vulnerabilities.forEach(v => allCves.add(v.cve_id));

        const totalVulns = (nmapResult?.vulnerabilities.length || 0) +
          (niktoResult?.vulnerabilities.length || 0) +
          (nucleiResult?.vulnerabilities.length || 0);

        const fullResult: FullScanResult = {
          target: nmapResult?.target || niktoResult?.target || nucleiResult?.target || "",
          scanType: "full",
          nmap: nmapResult,
          nikto: niktoResult,
          nuclei: nucleiResult,
          securityScore,
          openPorts,
          vulnerabilityHints,
          summary: {
            totalOpenPorts: openPorts.length,
            totalVulnerabilities: totalVulns,
            totalCves: allCves.size,
            totalWebFindings: (niktoResult?.findings.length || 0) + (nucleiResult?.findings.length || 0),
            enginesCompleted: (nmapResult ? 1 : 0) + (niktoResult ? 1 : 0) + (nucleiResult ? 1 : 0),
          },
        };

        try {
          await db.scan.update({
            where: { id: scanId },
            data: { status: "Completed", results: JSON.stringify(fullResult) },
          });
        } catch {}

        [nmapXml, nmapVulnXml, niktoCsv, nucleiJsonl, statusFile,
          join(TMP_DIR, `${scanId}-full.counter`),
          join(TMP_DIR, `${scanId}-nmap.status`),
          join(TMP_DIR, `${scanId}-nikto.status`),
          join(TMP_DIR, `${scanId}-nuclei.status`),
        ].forEach(f => { try { unlinkSync(f); } catch {} });

        return { status: "Completed", results: fullResult, error: null };
      }

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
    let scanId = uuidv4();
    const scanPort = port || "80";

    // Check if hybrid mode (GitHub Actions) is configured
    const isHybridMode = (body as Record<string, unknown>).mode === "hybrid" &&
      !!(process.env.GITHUB_TOKEN && process.env.GITHUB_REPO);

    if (isHybridMode) {
      // Hybrid mode: dispatch to GitHub Actions
      const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
      const GITHUB_REPO = process.env.GITHUB_REPO;
      const CALLBACK_URL = process.env.CALLBACK_URL || process.env.NEXT_PUBLIC_CALLBACK_URL;
      const CALLBACK_SECRET = process.env.CALLBACK_SECRET || process.env.VULNGUARD_CALLBACK_SECRET || uuidv4();

      // Create DB record
      await db.scan.create({
        data: { id: scanId, target: targetTrimmed, scanType: effectiveScanType, status: "Running", mode: "hybrid" },
      });

      const baseUrl = CALLBACK_URL || process.env.NEXT_PUBLIC_APP_URL || "https://your-app.vercel.app";
      const fullCallbackUrl = `${baseUrl}/api/scan/callback`;

      const dispatchUrl = `https://api.github.com/repos/${GITHUB_REPO}/dispatches`;
      const dispatchPayload = {
        event_type: "vulnscan",
        client_payload: {
          scan_id: scanId,
          scan_type: effectiveScanType,
          target: targetTrimmed,
          port: scanPort,
          callback_url: fullCallbackUrl,
          callback_secret: CALLBACK_SECRET,
        },
      };

      console.log(`[API] Dispatching hybrid scan: ${scanId} (${effectiveScanType}) for ${targetTrimmed}`);

      try {
        const dispatchResponse = await fetch(dispatchUrl, {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${GITHUB_TOKEN}`,
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
            "User-Agent": "VulnGuard-Scanner",
          },
          body: JSON.stringify(dispatchPayload),
        });

        if (!dispatchResponse.ok) {
          const errorText = await dispatchResponse.text();
          console.error(`[API] GitHub dispatch error: ${dispatchResponse.status}`, errorText);

          await db.scan.update({
            where: { id: scanId },
            data: { status: "Failed", results: JSON.stringify({ error: `GitHub Actions dispatch failed (HTTP ${dispatchResponse.status}). Check GITHUB_TOKEN and GITHUB_REPO.` }) },
          });

          return NextResponse.json({
            error: `Failed to dispatch scan to GitHub Actions (HTTP ${dispatchResponse.status}). Verify GITHUB_TOKEN has repo scope.`,
            scan_id: scanId,
          }, { status: 502 });
        }

        // Return immediately — results will come via callback
        return NextResponse.json({
          scan_id: scanId,
          target: targetTrimmed,
          scan_type: effectiveScanType,
          status: "Running",
          mode: "hybrid",
          message: "Scan dispatched to GitHub Actions. Results will be available once the workflow completes.",
        }, { status: 201 });

      } catch (dispatchError) {
        const errMsg = dispatchError instanceof Error ? dispatchError.message : "Dispatch failed";
        await db.scan.update({
          where: { id: scanId },
          data: { status: "Failed", results: JSON.stringify({ error: errMsg }) },
        });
        return NextResponse.json({ error: errMsg, scan_id: scanId }, { status: 500 });
      }
    }

    // Local mode — check tool availability
    const toolName = effectiveScanType === "full" ? "nmap" : effectiveScanType;
    const homeDir = process.env.HOME || "/root";
    const goBinDir = process.env.GOPATH ? `${process.env.GOPATH}/bin` : `${homeDir}/go/bin`;
    const envPath = `${homeDir}/.local/bin:${goBinDir}:${process.env.PATH || ""}`;
    let toolAvailable = false;
    try {
      const whichCmd = `which ${toolName} 2>/dev/null || ls ${homeDir}/.local/bin/${toolName} 2>/dev/null || ls ${goBinDir}/${toolName} 2>/dev/null`;
      await execWithTimeout(whichCmd, 5000, {
        env: { ...process.env, PATH: envPath, HOME: homeDir },
      });
      toolAvailable = true;
    } catch {
      toolAvailable = false;
    }

    if (!toolAvailable) {
      return NextResponse.json({
        error: `${toolName} is not installed or not in PATH. Install it or switch to Hybrid Mode (GitHub Actions) in the scan configuration.`,
        scan_type: effectiveScanType,
        target: targetTrimmed,
        hint: "Set GITHUB_TOKEN and GITHUB_REPO env vars to enable GitHub Actions hybrid mode.",
      }, { status: 501 });
    }

    // Create DB record
    ensureTmpDir();
    await db.scan.create({
      data: { id: scanId, target: targetTrimmed, scanType: effectiveScanType, status: "Running" },
    });

    console.log(`[API] Starting ${effectiveScanType} scan for ${scanId}, target ${targetTrimmed}`);

    try {
      // Execute scan synchronously with timeout
      let results: ScanResultType;

      switch (effectiveScanType) {
        case "nmap":
          results = await runNmapScan(targetTrimmed, scanId);
          break;
        case "nikto":
          results = await runNiktoScan(targetTrimmed, scanPort, scanId);
          break;
        case "nuclei":
          results = await runNucleiScan(targetTrimmed, scanPort, scanId);
          break;
        case "full":
          results = await runFullScan(targetTrimmed, scanPort, scanId);
          break;
        default:
          results = await runNmapScan(targetTrimmed, scanId);
      }

      // Save results to DB
      await db.scan.update({
        where: { id: scanId },
        data: { status: "Completed", results: JSON.stringify(results) },
      });

      console.log(`[API] ${effectiveScanType} scan ${scanId} completed successfully`);

      return NextResponse.json({
        scan_id: scanId,
        target: targetTrimmed,
        scan_type: effectiveScanType,
        status: "Completed",
        results,
      }, { status: 201 });

    } catch (scanError) {
      const errMsg = scanError instanceof Error ? scanError.message : "Scan execution failed";
      console.error(`[API] ${effectiveScanType} scan ${scanId} failed:`, errMsg);

      // Update DB with failure
      try {
        await db.scan.update({
          where: { id: scanId },
          data: { status: "Failed", results: JSON.stringify({ error: errMsg }) },
        });
      } catch {}

      return NextResponse.json({
        scan_id: scanId,
        target: targetTrimmed,
        scan_type: effectiveScanType,
        status: "Failed",
        error: errMsg,
      }, { status: 500 });
    }

  } catch (error) {
    console.error("[API] Error creating scan:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export { parseNmapXml, parseNiktoCsv, parseNucleiJsonl };
