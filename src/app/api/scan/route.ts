import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { v4 as uuidv4 } from "uuid";
import { exec } from "child_process";
import { readFileSync, existsSync, unlinkSync, mkdirSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

/**
 * POST /api/scan — Create and execute a new scan
 *
 * Architecture: Scans execute SYNCHRONOUSLY with timeout protection.
 * Results are returned immediately in the POST response.
 *
 * Supports four scan types:
 *   - nmap: Port scanning + service version detection + vuln scripts on open ports
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

function execWithTimeout(command: string, timeoutMs: number, options?: Record<string, unknown>): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const child = exec(command, { maxBuffer: 10 * 1024 * 1024, ...options }, (error, stdout, stderr) => {
      if (!settled) {
        settled = true;
        // For scanner tools, non-zero exit code is common (e.g., timeout, partial results)
        // We still resolve with whatever output we got
        resolve({ stdout: stdout || "", stderr: stderr || "" });
      }
    });

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        try { child.kill("SIGTERM"); } catch {}
        // Give it a moment to flush output, then SIGKILL
        setTimeout(() => { try { child.kill("SIGKILL"); } catch {} }, 2000);
        reject(new Error(`Scan timed out after ${Math.round(timeoutMs / 1000)}s`));
      }
    }, timeoutMs);

    child.on("error", (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(new Error(`Failed to execute scanner: ${err.message}`));
      }
    });
  });
}

// ─── Scan Timeout Constants ─────────────────────────────────────────────────

const NMAP_TIMEOUT = 90_000;        // 90 seconds (includes vuln scripts)
const NIKTO_TIMEOUT = 120_000;      // 120 seconds
const NUCLEI_TIMEOUT = 90_000;      // 90 seconds (focused templates)
const FULL_SCAN_TIMEOUT = 180_000;  // 180 seconds (all 3 engines)

// ─── Environment Path Setup ─────────────────────────────────────────────────

function getEnvPath(): string {
  const homeDir = process.env.HOME || "/root";
  const goBinDir = process.env.GOPATH ? `${process.env.GOPATH}/bin` : `${homeDir}/go/bin`;
  return `${homeDir}/.local/bin:${goBinDir}:${process.env.PATH || ""}`;
}

function getScanEnv(): Record<string, string> {
  const homeDir = process.env.HOME || "/root";
  return {
    ...process.env,
    PATH: getEnvPath(),
    HOME: homeDir,
  };
}

// ─── Nmap Scan Executor ─────────────────────────────────────────────────────

async function runNmapScan(target: string, scanId: string): Promise<NmapScanResult> {
  ensureTmpDir();
  const xmlFile = join(TMP_DIR, `${scanId}.xml`);
  const vulnXmlFile = join(TMP_DIR, `${scanId}-vuln.xml`);
  const env = getScanEnv();

  console.log(`[NmapScan] Starting scan for ${target}`);

  // Phase 1: Fast service version scan on top 1000 ports
  const fastCmd = `nmap -sT -sV --top-ports 1000 --max-retries 2 --host-timeout 60s --min-rate 100 -oX "${xmlFile}" "${target}"`;

  try {
    await execWithTimeout(fastCmd, NMAP_TIMEOUT, { env });
    console.log(`[NmapScan] Phase 1 complete (service version scan)`);
  } catch (e) {
    console.warn(`[NmapScan] Phase 1 error: ${e instanceof Error ? e.message : e}`);
  }

  // Parse phase 1 results
  let result: NmapScanResult = { target, ports: [], vulnerabilities: [] };

  if (existsSync(xmlFile)) {
    try {
      const xml = readFileSync(xmlFile, "utf-8");
      if (xml.includes("</nmaprun>")) {
        result = parseNmapXml(target, xml);
        console.log(`[NmapScan] Phase 1 parsed: ${result.ports.length} ports, ${result.vulnerabilities.length} vulns`);
      }
    } catch (e) {
      console.warn(`[NmapScan] Phase 1 parse error:`, e);
    }
  }

  // Phase 2: If open ports found, run vuln scripts on them for CVE detection
  const openPorts = result.ports.filter(p => p.state.toLowerCase() === "open");
  if (openPorts.length > 0) {
    const portList = openPorts.map(p => p.port_id).join(",");
    console.log(`[NmapScan] Phase 2: Running vuln scripts on open ports: ${portList}`);

    const vulnCmd = `nmap -sT -sV --script default,vuln -oX "${vulnXmlFile}" -p ${portList} --max-retries 1 --host-timeout 90s "${target}"`;

    try {
      await execWithTimeout(vulnCmd, NMAP_TIMEOUT, { env });
      console.log(`[NmapScan] Phase 2 complete (vuln scripts)`);
    } catch (e) {
      console.warn(`[NmapScan] Phase 2 error: ${e instanceof Error ? e.message : e}`);
    }

    // Parse phase 2 results (merge with phase 1)
    if (existsSync(vulnXmlFile)) {
      try {
        const vulnXml = readFileSync(vulnXmlFile, "utf-8");
        if (vulnXml.includes("</nmaprun>")) {
          const vulnResult = parseNmapXml(target, vulnXml);

          // Merge vulnerabilities from vuln scan
          if (vulnResult.vulnerabilities.length > 0) {
            const existingCves = new Set(result.vulnerabilities.map(v => v.cve_id));
            for (const v of vulnResult.vulnerabilities) {
              if (!existingCves.has(v.cve_id)) {
                result.vulnerabilities.push(v);
                existingCves.add(v.cve_id);
              }
            }
            console.log(`[NmapScan] Phase 2 found ${vulnResult.vulnerabilities.length} additional vulns`);
          }

          // Merge any additional port info from vuln scan
          const existingPortIds = new Set(result.ports.map(p => p.port_id));
          for (const p of vulnResult.ports) {
            if (!existingPortIds.has(p.port_id)) {
              result.ports.push(p);
              existingPortIds.add(p.port_id);
            } else {
              // Update existing port with more detailed info if available
              const existing = result.ports.find(ep => ep.port_id === p.port_id);
              if (existing && existing.version === "Unknown" && p.version !== "Unknown") {
                existing.version = p.version;
                existing.service = p.service;
              }
            }
          }
        }
      } catch (e) {
        console.warn(`[NmapScan] Phase 2 parse error:`, e);
      }
    }
  }

  // Clean up temp files
  try { unlinkSync(xmlFile); } catch {}
  try { unlinkSync(vulnXmlFile); } catch {}

  console.log(`[NmapScan] Final result: ${result.ports.length} ports (${openPorts.length} open), ${result.vulnerabilities.length} vulns`);
  return result;
}

// ─── Nikto Scan Executor ────────────────────────────────────────────────────

async function runNiktoScan(target: string, port: string, scanId: string): Promise<NiktoScanResult> {
  ensureTmpDir();
  const csvFile = join(TMP_DIR, `${scanId}-nikto.csv`);
  const env = getScanEnv();

  // Build nikto URL
  const niktoTarget = `http${port === "443" ? "s" : ""}://${target}:${port}`;

  // Nikto with extended timeout for thorough scanning
  const cmd = `nikto -h "${niktoTarget}" -Format csv -o "${csvFile}" -nointeractive -C all -maxtime 90s -Tuning 1234567890`;

  console.log(`[NiktoScan] Starting scan for ${niktoTarget}`);

  try {
    await execWithTimeout(cmd, NIKTO_TIMEOUT, {
      env: {
        ...env,
        NIKTODIR: `${process.env.HOME || "/root"}/nikto/program`,
        PERL5LIB: `${process.env.HOME || "/root"}/nikto/program`,
      },
    });
    console.log(`[NiktoScan] Scan complete`);
  } catch (e) {
    console.warn(`[NiktoScan] Scan error: ${e instanceof Error ? e.message : e}`);
  }

  if (existsSync(csvFile)) {
    try {
      const csv = readFileSync(csvFile, "utf-8");
      if (csv.trim().length > 0) {
        const result = parseNiktoCsv(target, csv);
        try { unlinkSync(csvFile); } catch {}
        console.log(`[NiktoScan] Parsed: ${result.findings.length} findings, ${result.vulnerabilities.length} vulns`);
        return result;
      }
    } catch (e) {
      console.warn(`[NiktoScan] Parse error:`, e);
    }
  }

  try { unlinkSync(csvFile); } catch {}
  console.log(`[NiktoScan] No results found`);
  return { target, scanType: "nikto", server: "Unknown", findings: [], vulnerabilities: [], summary: { total: 0, info: 0, low: 0, medium: 0, high: 0 } };
}

// ─── Nuclei Scan Executor ───────────────────────────────────────────────────

async function runNucleiScan(target: string, port: string, scanId: string): Promise<NucleiScanResult> {
  ensureTmpDir();
  const jsonlFile = join(TMP_DIR, `${scanId}-nuclei.jsonl`);
  const env = getScanEnv();
  const templatesDir = process.env.NUCLEI_TEMPLATES_DIR || `${process.env.HOME || "/root"}/nuclei-templates`;

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

  // Check which template directories exist
  const templateDirs = [
    "http/cves/",
    "http/vulnerabilities/",
    "http/exposures/",
    "http/misconfiguration/",
    "http/default-logins/",
    "http/exposed-panels/",
  ].filter(dir => existsSync(join(templatesDir, dir)));

  const templateArgs = templateDirs.map(d => `-t "${join(templatesDir, d)}"`).join(" ");

  // Focused scan: only medium/high/critical severity, reasonable concurrency
  const cmd = `nuclei -u "${scanUrl}" -jle "${jsonlFile}" -silent -timeout 5 -c 25 -rl 100 -retries 1 -severity low,medium,high,critical ${templateArgs}`;

  console.log(`[NucleiScan] Starting scan for ${scanUrl} with ${templateDirs.length} template dirs`);

  try {
    await execWithTimeout(cmd, NUCLEI_TIMEOUT, { env });
    console.log(`[NucleiScan] Scan complete`);
  } catch (e) {
    console.warn(`[NucleiScan] Scan error: ${e instanceof Error ? e.message : e}`);
  }

  // Parse results
  if (!existsSync(jsonlFile)) {
    try { mkdirSync(TMP_DIR, { recursive: true }); writeFileSync(jsonlFile, ""); } catch {}
  }

  try {
    const jsonl = readFileSync(jsonlFile, "utf-8");
    const result = parseNucleiJsonl(target, jsonl);
    try { unlinkSync(jsonlFile); } catch {}
    console.log(`[NucleiScan] Parsed: ${result.findings.length} findings, ${result.vulnerabilities.length} vulns`);
    return result;
  } catch {
    try { unlinkSync(jsonlFile); } catch {}
    console.log(`[NucleiScan] No results found`);
    return {
      target, scanType: "nuclei", findings: [], vulnerabilities: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, withCurlCommand: 0, withExtractedResults: 0 },
    };
  }
}

// ─── Full Scan Executor ─────────────────────────────────────────────────────

async function runFullScan(target: string, port: string, scanId: string): Promise<FullScanResult> {
  console.log(`[FullScan] Starting full scan for ${target}`);

  // Run all 3 engines in parallel
  const [nmapSettled, niktoSettled, nucleiSettled] = await Promise.allSettled([
    runNmapScan(target, `${scanId}-nmap`),
    runNiktoScan(target, port, `${scanId}-nikto`),
    runNucleiScan(target, port, `${scanId}-nuclei`),
  ]);

  const nmapResult = nmapSettled.status === "fulfilled" ? nmapSettled.value : null;
  const niktoResult = niktoSettled.status === "fulfilled" ? niktoSettled.value : null;
  const nucleiResult = nucleiSettled.status === "fulfilled" ? nucleiSettled.value : null;

  console.log(`[FullScan] Engines completed: nmap=${!!nmapResult}, nikto=${!!niktoResult}, nuclei=${!!nucleiResult}`);

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

    // Parse script output for CVEs (handles both compact and verbose XML formats)
    const scriptRegex = /<script\s+id="([^"]*)"\s+output="([^"]*)"([\s\S]*?)<\/script>/g;
    let scriptMatch;
    while ((scriptMatch = scriptRegex.exec(portBlock)) !== null) {
      const scriptId = scriptMatch[1];
      const scriptOutput = scriptMatch[2].replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&").replace(/&quot;/g, '"');
      const scriptBody = scriptMatch[3];
      const textParts: string[] = [scriptOutput];

      // Collect all text content from nested elements
      const elemRegex = /<elem[^>]*>([\s\S]*?)<\/elem>/g;
      let elemMatch;
      while ((elemMatch = elemRegex.exec(scriptBody)) !== null) {
        if (elemMatch[1]) textParts.push(elemMatch[1].trim());
      }

      // Also collect from table/elem structures
      const tableElemRegex = /<elem[^>]*key="([^"]*)"[^>]*>([\s\S]*?)<\/elem>/g;
      let tableElemMatch;
      while ((tableElemMatch = tableElemRegex.exec(scriptBody)) !== null) {
        if (tableElemMatch[2]) textParts.push(`${tableElemMatch[1]}: ${tableElemMatch[2].trim()}`);
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

    // Also check for CPE data which indicates known vulnerabilities
    const cpeRegex = /<cpe>([^<]+)<\/cpe>/g;
    let cpeMatch;
    while ((cpeMatch = cpeRegex.exec(portBlock)) !== null) {
      // CPE itself is not a CVE, but we note it for context
      // The vuln scripts will find the actual CVEs
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
    // Parse CSV with proper quote handling
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

    // Skip header/empty lines
    if (fields.length <= 1 && fields[0]?.startsWith("Nikto")) continue;
    if (fields.length < 7) continue;

    const [host, ip, portStr, references, method, path, description] = fields;

    // Extract server info
    if (description?.includes("appears to be outdated") || description?.includes("Server:")) {
      const serverMatch = description.match(/(?:Server:\s*|^)([A-Za-z][^\s.]+)/);
      if (serverMatch) server = serverMatch[1];
    }
    // Also extract from "Server:" header findings
    if (host?.includes("Server:") || description?.includes("Server:")) {
      const serverMatch = (host + " " + description).match(/Server:\s*([^\s,]+)/);
      if (serverMatch) server = serverMatch[1];
    }

    const port = parseInt(portStr, 10) || 80;

    // Skip truly empty findings
    if (!description || description.trim().length === 0) continue;

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

  // Classify findings by severity
  const summary = {
    total: findings.length,
    info: findings.filter(f =>
      f.description.toLowerCase().includes("suggested security header") ||
      f.description.toLowerCase().includes("uncommon header") ||
      f.description.toLowerCase().includes("server:") ||
      f.description.toLowerCase().includes("x-powered-by")
    ).length,
    low: findings.filter(f =>
      f.description.toLowerCase().includes("outdated") ||
      f.description.toLowerCase().includes("mod_negotiation") ||
      f.description.toLowerCase().includes("directory indexing")
    ).length,
    medium: findings.filter(f =>
      f.references.length > 0 &&
      !f.description.toLowerCase().includes("suggested security header") &&
      !f.description.toLowerCase().includes("uncommon header") &&
      !f.description.toLowerCase().includes("server:") &&
      !f.description.toLowerCase().includes("x-powered-by")
    ).length,
    high: findings.filter(f =>
      f.description.toLowerCase().includes("xss") ||
      f.description.toLowerCase().includes("sql") ||
      f.description.toLowerCase().includes("injection") ||
      f.description.toLowerCase().includes("rce") ||
      f.description.toLowerCase().includes("remote code") ||
      f.description.toLowerCase().includes("csrf") ||
      f.description.toLowerCase().includes("traversal")
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

      // Skip non-result lines (info, warnings etc)
      if (obj.type === "templates" || obj.type === "error") continue;

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

      // Extract CVEs from template ID, tags, and name
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
    // Flag potentially outdated services
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
    // Flag high-risk open ports
    const highRiskPorts: Record<number, string> = {
      23: "Telnet (unencrypted remote access)",
      21: "FTP (unencrypted file transfer)",
      25: "SMTP (mail relay, often misconfigured)",
      445: "SMB (Windows file sharing, frequently exploited)",
      3389: "RDP (Remote Desktop, frequently targeted)",
      5900: "VNC (remote desktop, often misconfigured)",
      5432: "PostgreSQL (database exposed to network)",
      27017: "MongoDB (database, often unauthenticated)",
      6379: "Redis (often deployed without auth)",
      9200: "Elasticsearch (often misconfigured)",
    };
    const openPorts = nmapResult.ports.filter(p => p.state.toLowerCase() === "open");
    for (const p of openPorts) {
      if (highRiskPorts[p.port_id]) {
        hints.push({
          source: "nmap",
          severity: "high",
          title: `High-risk port open: ${p.port_id} (${p.service})`,
          description: highRiskPorts[p.port_id],
          port: p.port_id,
        });
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
  // This is kept for backward compatibility with the GET polling route
  // but since scans now run synchronously, this mainly checks the DB
  try {
    const scan = await db.scan.findUnique({ where: { id: scanId } });
    if (!scan) return { status: "Unknown", results: null, error: null };

    if (scan.status === "Completed" && scan.results) {
      try {
        const results = JSON.parse(scan.results) as ScanResultType;
        return { status: "Completed", results, error: null };
      } catch {
        return { status: "Failed", results: null, error: "Failed to parse scan results" };
      }
    }

    if (scan.status === "Failed") {
      let error = "Scan failed";
      if (scan.results) {
        try {
          const parsed = JSON.parse(scan.results);
          if (parsed.error) error = parsed.error;
        } catch {}
      }
      return { status: "Failed", results: null, error };
    }

    return { status: scan.status, results: null, error: null };
  } catch (dbErr) {
    console.error(`[ScanManager] DB lookup failed for scan ${scanId}:`, dbErr);
    return { status: "Unknown", results: null, error: null };
  }
}

// ─── Main POST Handler ──────────────────────────────────────────────────────

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { target, isAuthorized, scanType, mode, port } = body as {
      target: string;
      isAuthorized: boolean;
      scanType: string;
      mode?: string;
      port?: string;
    };

    // Validate
    if (!target || typeof target !== "string") {
      return NextResponse.json({ error: "Target is required" }, { status: 400 });
    }

    const targetTrimmed = target.trim();
    if (!isAuthorized) {
      return NextResponse.json({ error: "Authorization required" }, { status: 403 });
    }

    const auth = verifyAuthorization(targetTrimmed);
    if (!auth.authorized) {
      return NextResponse.json({ error: auth.reason }, { status: 403 });
    }

    const effectiveScanType = resolveScanType(scanType);

    // ─── Hybrid Mode: Dispatch to GitHub Actions ───────────────────────────
    if (mode === "hybrid") {
      const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
      const GITHUB_REPO = process.env.GITHUB_REPO;

      if (!GITHUB_TOKEN || !GITHUB_REPO) {
        return NextResponse.json({
          error: "GitHub Actions hybrid mode is not configured. Set GITHUB_TOKEN and GITHUB_REPO environment variables.",
          hint: "See README for hybrid deployment setup instructions.",
        }, { status: 501 });
      }

      // Forward to dispatch endpoint
      const dispatchBody = {
        target: targetTrimmed,
        scanType: effectiveScanType,
        port: port || "80",
        isAuthorized: true,
      };

      const dispatchUrl = new URL("/api/scan/dispatch", request.url);
      const dispatchResponse = await fetch(dispatchUrl.toString(), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(dispatchBody),
      });

      const dispatchData = await dispatchResponse.json() as Record<string, unknown>;

      if (!dispatchResponse.ok) {
        return NextResponse.json({
          error: (dispatchData.error as string) || "Failed to dispatch scan to GitHub Actions",
          scan_id: dispatchData.scan_id,
        }, { status: dispatchResponse.status });
      }

      return NextResponse.json({
        scan_id: dispatchData.scan_id,
        target: targetTrimmed,
        scan_type: effectiveScanType,
        status: "running",
        mode: "hybrid",
      }, { status: 201 });
    }

    // ─── Local Mode: Run Scans Directly ────────────────────────────────────
    const scanId = uuidv4();
    const scanPort = port || "80";

    // Create DB record
    await db.scan.create({
      data: {
        id: scanId,
        target: targetTrimmed,
        scanType: effectiveScanType,
        status: "Running",
        mode: "local",
      },
    });

    console.log(`[API] Starting ${effectiveScanType} scan for ${targetTrimmed} (scanId: ${scanId})`);

    let scanResult: ScanResultType;
    let scanError: string | null = null;

    try {
      switch (effectiveScanType) {
        case "nmap":
          scanResult = await runNmapScan(targetTrimmed, scanId);
          break;
        case "nikto":
          scanResult = await runNiktoScan(targetTrimmed, scanPort, scanId);
          break;
        case "nuclei":
          scanResult = await runNucleiScan(targetTrimmed, scanPort, scanId);
          break;
        case "full":
          scanResult = await runFullScan(targetTrimmed, scanPort, scanId);
          break;
        default:
          scanResult = await runNmapScan(targetTrimmed, scanId);
      }
    } catch (err) {
      scanError = err instanceof Error ? err.message : "Scan execution failed";
      console.error(`[API] Scan error: ${scanError}`);

      // Create an empty result on error
      switch (effectiveScanType) {
        case "nikto":
          scanResult = { target: targetTrimmed, scanType: "nikto", server: "Unknown", findings: [], vulnerabilities: [], summary: { total: 0, info: 0, low: 0, medium: 0, high: 0 } };
          break;
        case "nuclei":
          scanResult = { target: targetTrimmed, scanType: "nuclei", findings: [], vulnerabilities: [], summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, withCurlCommand: 0, withExtractedResults: 0 } };
          break;
        case "full":
          scanResult = {
            target: targetTrimmed, scanType: "full", nmap: null, nikto: null, nuclei: null,
            securityScore: { score: 0, grade: "F", label: "Scan Failed", breakdown: { openPorts: { count: 0, deduction: 0, details: "" }, vulnerabilities: { count: 0, deduction: 0, details: "" }, cves: { count: 0, deduction: 0, details: "" }, webFindings: { count: 0, deduction: 0, details: "" }, nucleiCritical: { count: 0, deduction: 0, details: "" }, nucleiHigh: { count: 0, deduction: 0, details: "" } } },
            openPorts: [], vulnerabilityHints: [], summary: { totalOpenPorts: 0, totalVulnerabilities: 0, totalCves: 0, totalWebFindings: 0, enginesCompleted: 0 },
          };
          break;
        default:
          scanResult = { target: targetTrimmed, ports: [], vulnerabilities: [] };
      }
    }

    // Update DB record
    const finalStatus = scanError ? "Failed" : "Completed";
    try {
      await db.scan.update({
        where: { id: scanId },
        data: {
          status: finalStatus,
          results: JSON.stringify(scanResult),
          ...(scanError ? { results: JSON.stringify({ ...scanResult, error: scanError }) } : {}),
        },
      });
    } catch (dbErr) {
      console.error(`[API] Failed to update scan record:`, dbErr);
    }

    // Return results synchronously
    return NextResponse.json({
      scan_id: scanId,
      target: targetTrimmed,
      scan_type: effectiveScanType,
      status: scanError ? "failed" : "completed",
      results: scanResult,
      ...(scanError ? { error: scanError } : {}),
    });

  } catch (error) {
    console.error("[API] Scan POST error:", error);
    return NextResponse.json(
      { error: `Internal server error: ${error instanceof Error ? error.message : "Unknown error"}` },
      { status: 500 }
    );
  }
}
