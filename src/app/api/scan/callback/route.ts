import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";

/**
 * POST /api/scan/callback — Receive scan results from GitHub Actions
 *
 * Hybrid deployment callback endpoint. When scans run on GitHub Actions
 * (Ubuntu runner), the workflow posts results back here.
 *
 * Security: Requires CALLBACK_SECRET to match env var.
 *
 * Handles both raw output (XML, CSV, JSONL) from GitHub Actions
 * and pre-parsed JSON results.
 */

// ─── Types ──────────────────────────────────────────────────────────────────

interface PortInfo { port_id: number; protocol: string; state: string; service: string; version: string }
interface Vulnerability { port_id: number; cve_id: string; description: string }

interface NmapScanResult { target: string; ports: PortInfo[]; vulnerabilities: Vulnerability[] }

interface NiktoFinding {
  id: string; host: string; ip: string; port: number
  method: string; path: string; description: string; references: string[]
}

interface NiktoScanResult {
  target: string; scanType: "nikto"; server: string
  findings: NiktoFinding[]; vulnerabilities: Vulnerability[]
  summary: { total: number; info: number; low: number; medium: number; high: number }
}

interface NucleiFinding {
  templateId: string; name: string; severity: string; type: string
  matchedAt: string; curlCommand: string | null; extractedResults: string[]
  description: string; tags: string[]; reference: string[]
  host: string; timestamp: string
}

interface NucleiScanResult {
  target: string; scanType: "nuclei"
  findings: NucleiFinding[]; vulnerabilities: Vulnerability[]
  summary: {
    total: number; critical: number; high: number; medium: number
    low: number; info: number; withCurlCommand: number; withExtractedResults: number
  }
}

interface FullScanResult {
  target: string; scanType: "full"
  nmap: NmapScanResult | null; nikto: NiktoScanResult | null; nuclei: NucleiScanResult | null
  securityScore: {
    score: number; grade: string; label: string
    breakdown: {
      openPorts: { count: number; deduction: number; details: string }
      vulnerabilities: { count: number; deduction: number; details: string }
      cves: { count: number; deduction: number; details: string }
      webFindings: { count: number; deduction: number; details: string }
      nucleiCritical: { count: number; deduction: number; details: string }
      nucleiHigh: { count: number; deduction: number; details: string }
    }
  }
  openPorts: PortInfo[]
  vulnerabilityHints: Array<{
    source: "nmap" | "nikto" | "nuclei"
    severity: string; title: string; description: string
    port?: number; reference?: string[]
  }>
  summary: {
    totalOpenPorts: number; totalVulnerabilities: number; totalCves: number
    totalWebFindings: number; enginesCompleted: number
  }
}

type ScanResultType = NmapScanResult | NiktoScanResult | NucleiScanResult | FullScanResult;

const CVE_REGEX = /CVE-\d{4}-\d{4,7}/g;

// ─── Parsers (shared with scan route) ───────────────────────────────────────

function normalizeSeverity(severity: string): string {
  const s = severity.toLowerCase().trim();
  if (["critical", "high", "medium", "low", "info"].includes(s)) return s;
  if (s === "unknown" || s === "") return "info";
  return s;
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

    // Parse script output for CVEs
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
            vulnerabilities.push({
              port_id: portId,
              cve_id: cveId,
              description: `${cveId} detected by nmap ${scriptId} script on port ${portId}/${protocol}`,
            });
          }
        }
      }
    }
  }
  return { target, ports, vulnerabilities };
}

function mergeNmapResults(base: NmapScanResult, vuln: NmapScanResult): NmapScanResult {
  // Merge vulnerabilities (dedup by CVE ID)
  const existingCves = new Set(base.vulnerabilities.map(v => v.cve_id));
  for (const v of vuln.vulnerabilities) {
    if (!existingCves.has(v.cve_id)) {
      base.vulnerabilities.push(v);
      existingCves.add(v.cve_id);
    }
  }

  // Merge port info (update existing ports with more detail, add new ones)
  const existingPorts = new Map(base.ports.map(p => [p.port_id, p]));
  for (const p of vuln.ports) {
    const existing = existingPorts.get(p.port_id);
    if (existing) {
      if (existing.version === "Unknown" && p.version !== "Unknown") {
        existing.version = p.version;
        existing.service = p.service;
      }
    } else {
      base.ports.push(p);
      existingPorts.set(p.port_id, p);
    }
  }

  return base;
}

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
      if (ch === '"') { if (inQuotes && i + 1 < line.length && line[i + 1] === '"') { current += '"'; i++; } else { inQuotes = !inQuotes; } } else if (ch === ',' && !inQuotes) { fields.push(current); current = ""; } else { current += ch; }
    }
    fields.push(current);
    if (fields.length <= 1 && fields[0]?.startsWith("Nikto")) continue;
    if (fields.length < 7) continue;
    const [host, ip, portStr, references, method, path, description] = fields;
    if (!description || description.trim().length === 0) continue;
    const port = parseInt(portStr, 10) || 80;
    if (description?.includes("Server:")) {
      const serverMatch = description.match(/Server:\s*([^\s,]+)/);
      if (serverMatch) server = serverMatch[1];
    }
    findings.push({
      id: `nikto-${findings.length + 1}`, host: host || target, ip: ip || "", port,
      method: method || "GET", path: path || "/", description: description || "",
      references: references ? references.split(",").map(r => r.trim()).filter(Boolean) : [],
    });
    CVE_REGEX.lastIndex = 0;
    const allText = `${references} ${description}`;
    const cveMatches = allText.match(CVE_REGEX);
    if (cveMatches) {
      const seen = new Set<string>();
      for (const cveId of cveMatches) { if (!seen.has(cveId)) { seen.add(cveId); vulnerabilities.push({ port_id: port, cve_id: cveId, description: `${cveId} detected by Nikto on port ${port}` }); } }
    }
  }
  const summary = {
    total: findings.length,
    info: findings.filter(f => f.description.toLowerCase().includes("suggested security header") || f.description.toLowerCase().includes("uncommon header")).length,
    low: findings.filter(f => f.description.toLowerCase().includes("outdated")).length,
    medium: findings.filter(f => f.references.length > 0 && !f.description.toLowerCase().includes("suggested security header")).length,
    high: findings.filter(f => f.description.toLowerCase().includes("xss") || f.description.toLowerCase().includes("sql") || f.description.toLowerCase().includes("injection")).length,
  };
  return { target, scanType: "nikto", server, findings, vulnerabilities, summary };
}

function parseNucleiJsonl(target: string, jsonl: string): NucleiScanResult {
  const findings: NucleiFinding[] = [];
  const vulnerabilities: Vulnerability[] = [];
  const lines = jsonl.split("\n").filter(l => l.trim().length > 0);
  for (const line of lines) {
    try {
      const obj = JSON.parse(line) as Record<string, unknown>;
      if (obj.type === "templates" || obj.type === "error") continue;
      const info = (obj.info as Record<string, unknown>) || {};
      const templateId = (obj["template-id"] as string) || "";
      const name = (info.name as string) || templateId || "Unknown Finding";
      const severity = normalizeSeverity((info.severity as string) || "info");
      const type = (obj.type as string) || "http";
      const matchedAt = (obj["matched-at"] as string) || "";
      const host = (obj.host as string) || target;
      const timestamp = (obj.timestamp as string) || new Date().toISOString();
      const curlCommand = (obj["curl-command"] as string) || null;
      const extractedResults = Array.isArray(obj["extracted-results"]) ? (obj["extracted-results"] as string[]) : [];
      const tags = Array.isArray(info.tags) ? (info.tags as string[]).map(String) : typeof info.tags === "string" ? info.tags.split(",").map(t => t.trim()).filter(Boolean) : [];
      const reference = Array.isArray(info.reference) ? (info.reference as string[]).map(String) : [];
      let description = name;
      if (extractedResults.length > 0) description += ` — Extracted: ${extractedResults.join(", ")}`;
      if (matchedAt) description += ` at ${matchedAt}`;
      findings.push({ templateId, name, severity, type, matchedAt, curlCommand, extractedResults, description, tags, reference, host, timestamp });
      const cveText = `${templateId} ${tags.join(" ")} ${name}`;
      CVE_REGEX.lastIndex = 0;
      const cveMatches = cveText.match(CVE_REGEX);
      if (cveMatches) {
        const seen = new Set<string>();
        for (const cveId of cveMatches) { if (!seen.has(cveId)) { seen.add(cveId); vulnerabilities.push({ port_id: 0, cve_id: cveId, description: `${cveId} detected by nuclei template ${templateId}: ${name}` }); } }
      }
    } catch { /* skip */ }
  }
  const summary = {
    total: findings.length, critical: findings.filter(f => f.severity === "critical").length,
    high: findings.filter(f => f.severity === "high").length, medium: findings.filter(f => f.severity === "medium").length,
    low: findings.filter(f => f.severity === "low").length, info: findings.filter(f => f.severity === "info").length,
    withCurlCommand: findings.filter(f => f.curlCommand).length, withExtractedResults: findings.filter(f => f.extractedResults.length > 0).length,
  };
  return { target, scanType: "nuclei", findings, vulnerabilities, summary };
}

function calculateSecurityScore(
  nmapResult: NmapScanResult | null, niktoResult: NiktoScanResult | null, nucleiResult: NucleiScanResult | null,
): FullScanResult["securityScore"] {
  let score = 100;
  const breakdown = { openPorts: { count: 0, deduction: 0, details: "" }, vulnerabilities: { count: 0, deduction: 0, details: "" }, cves: { count: 0, deduction: 0, details: "" }, webFindings: { count: 0, deduction: 0, details: "" }, nucleiCritical: { count: 0, deduction: 0, details: "" }, nucleiHigh: { count: 0, deduction: 0, details: "" } };
  if (nmapResult) {
    const openPorts = nmapResult.ports.filter(p => p.state.toLowerCase() === "open");
    const highRiskPorts = [23, 21, 25, 445, 3389, 5900, 5432, 27017, 6379, 9200];
    const riskyOpen = openPorts.filter(p => highRiskPorts.includes(p.port_id));
    breakdown.openPorts.count = openPorts.length;
    breakdown.openPorts.deduction = Math.min(30, openPorts.length * 2 + riskyOpen.length * 5);
    breakdown.openPorts.details = `${openPorts.length} open ports found`;
    score -= breakdown.openPorts.deduction;
    breakdown.vulnerabilities.count = nmapResult.vulnerabilities.length;
    breakdown.vulnerabilities.deduction = Math.min(20, nmapResult.vulnerabilities.length * 5);
    score -= breakdown.vulnerabilities.deduction;
    const uniqueCves = new Set(nmapResult.vulnerabilities.map(v => v.cve_id));
    breakdown.cves.count = uniqueCves.size;
    breakdown.cves.deduction = Math.min(20, uniqueCves.size * 5);
    score -= breakdown.cves.deduction;
  }
  if (niktoResult) {
    breakdown.webFindings.count = niktoResult.findings.length;
    breakdown.webFindings.deduction = Math.min(25, niktoResult.summary.high * 8 + niktoResult.summary.medium * 3);
    score -= breakdown.webFindings.deduction;
  }
  if (nucleiResult) {
    breakdown.nucleiCritical.count = nucleiResult.summary.critical;
    breakdown.nucleiCritical.deduction = Math.min(30, nucleiResult.summary.critical * 15);
    breakdown.nucleiHigh.count = nucleiResult.summary.high;
    breakdown.nucleiHigh.deduction = Math.min(20, nucleiResult.summary.high * 8);
    score -= breakdown.nucleiCritical.deduction;
    score -= breakdown.nucleiHigh.deduction;
  }
  score = Math.max(0, Math.min(100, score));
  let grade: string, label: string;
  if (score >= 95) { grade = "A+"; label = "Excellent"; } else if (score >= 90) { grade = "A"; label = "Very Good"; } else if (score >= 80) { grade = "B"; label = "Good"; } else if (score >= 70) { grade = "C"; label = "Fair"; } else if (score >= 60) { grade = "D"; label = "Poor"; } else if (score >= 40) { grade = "E"; label = "Bad"; } else { grade = "F"; label = "Critical"; }
  return { score, grade, label, breakdown };
}

function buildVulnerabilityHints(
  nmapResult: NmapScanResult | null, niktoResult: NiktoScanResult | null, nucleiResult: NucleiScanResult | null,
): FullScanResult["vulnerabilityHints"] {
  const hints: FullScanResult["vulnerabilityHints"] = [];
  if (nmapResult) { for (const v of nmapResult.vulnerabilities) { hints.push({ source: "nmap", severity: "high", title: v.cve_id, description: v.description, port: v.port_id }); } }
  if (niktoResult) { for (const f of niktoResult.findings) { let severity = "info"; if (f.description.toLowerCase().includes("xss") || f.description.toLowerCase().includes("sql")) severity = "high"; else if (f.references.length > 0) severity = "medium"; hints.push({ source: "nikto", severity, title: f.description.slice(0, 120), description: f.description, port: f.port, reference: f.references }); } }
  if (nucleiResult) { for (const f of nucleiResult.findings) { hints.push({ source: "nuclei", severity: f.severity, title: f.name, description: f.description, reference: f.reference }); } }
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  hints.sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5));
  return hints;
}

// ─── API Handler ────────────────────────────────────────────────────────────

export async function POST(request: NextRequest) {
  try {
    const body = await request.json() as Record<string, unknown>;
    const { scan_id, scan_type, target, port, status, error, callback_secret, results } = body;

    // Verify callback secret
    const expectedSecret = process.env.CALLBACK_SECRET || process.env.VULNGUARD_CALLBACK_SECRET;
    if (expectedSecret && callback_secret !== expectedSecret) {
      return NextResponse.json({ error: "Invalid callback secret" }, { status: 403 });
    }

    if (!scan_id || typeof scan_id !== "string") {
      return NextResponse.json({ error: "scan_id is required" }, { status: 400 });
    }

    // Find the scan in DB
    const scan = await db.scan.findUnique({ where: { id: scan_id } });
    if (!scan) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 });
    }

    const scanType = (scan_type as string) || scan.scanType || "nmap";
    const targetHost = (target as string) || scan.target;

    // Handle failure
    if (status === "Failed") {
      await db.scan.update({
        where: { id: scan_id },
        data: { status: "Failed", results: JSON.stringify({ error: (error as string) || "GitHub Actions scan failed" }) },
      });
      return NextResponse.json({ ok: true, status: "Failed" });
    }

    // Parse results from GitHub Actions
    const rawResults = (results as Record<string, unknown>) || {};
    let parsedResult: ScanResultType;

    if (scanType === "nmap") {
      // Handle nmap results — could be raw XML or pre-parsed JSON
      let nmapResult: NmapScanResult = { target: targetHost, ports: [], vulnerabilities: [] };

      if (rawResults.nmap && typeof rawResults.nmap === "object" && !("raw" in rawResults.nmap)) {
        // Pre-parsed JSON
        nmapResult = rawResults.nmap as NmapScanResult;
      } else if (rawResults.nmap_xml && typeof rawResults.nmap_xml === "string") {
        // Raw XML from GitHub Actions
        nmapResult = parseNmapXml(targetHost, rawResults.nmap_xml);
      } else if (rawResults.nmap && typeof rawResults.nmap === "object" && "raw" in rawResults.nmap) {
        // Old format: { raw: "xml..." }
        const raw = (rawResults.nmap as { raw: string }).raw;
        if (raw) nmapResult = parseNmapXml(targetHost, raw);
      }

      // Merge vuln XML if available
      if (rawResults.nmap_vuln_xml && typeof rawResults.nmap_vuln_xml === "string") {
        const vulnResult = parseNmapXml(targetHost, rawResults.nmap_vuln_xml);
        nmapResult = mergeNmapResults(nmapResult, vulnResult);
      }

      parsedResult = nmapResult;

    } else if (scanType === "nikto") {
      if (rawResults.nikto_raw && typeof rawResults.nikto_raw === "string") {
        parsedResult = parseNiktoCsv(targetHost, rawResults.nikto_raw);
      } else if (rawResults.nikto && typeof rawResults.nikto === "object") {
        parsedResult = rawResults.nikto as NiktoScanResult;
      } else {
        parsedResult = { target: targetHost, scanType: "nikto", server: "Unknown", findings: [], vulnerabilities: [], summary: { total: 0, info: 0, low: 0, medium: 0, high: 0 } };
      }
    } else if (scanType === "nuclei") {
      if (rawResults.nuclei_raw && typeof rawResults.nuclei_raw === "string") {
        parsedResult = parseNucleiJsonl(targetHost, rawResults.nuclei_raw);
      } else if (rawResults.nuclei && typeof rawResults.nuclei === "object") {
        parsedResult = rawResults.nuclei as NucleiScanResult;
      } else {
        parsedResult = { target: targetHost, scanType: "nuclei", findings: [], vulnerabilities: [], summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, withCurlCommand: 0, withExtractedResults: 0 } };
      }
    } else {
      // Full scan
      let nmapResult: NmapScanResult | null = null;
      let niktoResult: NiktoScanResult | null = null;
      let nucleiResult: NucleiScanResult | null = null;

      // Parse nmap
      if (rawResults.nmap_xml && typeof rawResults.nmap_xml === "string") {
        nmapResult = parseNmapXml(targetHost, rawResults.nmap_xml);
        // Merge vuln XML
        if (rawResults.nmap_vuln_xml && typeof rawResults.nmap_vuln_xml === "string") {
          const vulnResult = parseNmapXml(targetHost, rawResults.nmap_vuln_xml);
          nmapResult = mergeNmapResults(nmapResult, vulnResult);
        }
      } else if (rawResults.nmap && typeof rawResults.nmap === "object") {
        if ("raw" in rawResults.nmap) {
          const raw = (rawResults.nmap as { raw: string }).raw;
          if (raw) nmapResult = parseNmapXml(targetHost, raw);
        } else {
          nmapResult = rawResults.nmap as NmapScanResult;
        }
      }

      // Parse nikto
      if (rawResults.nikto_raw && typeof rawResults.nikto_raw === "string") {
        niktoResult = parseNiktoCsv(targetHost, rawResults.nikto_raw);
      } else if (rawResults.nikto && typeof rawResults.nikto === "object") {
        niktoResult = rawResults.nikto as NiktoScanResult;
      }

      // Parse nuclei
      if (rawResults.nuclei_raw && typeof rawResults.nuclei_raw === "string") {
        nucleiResult = parseNucleiJsonl(targetHost, rawResults.nuclei_raw);
      } else if (rawResults.nuclei && typeof rawResults.nuclei === "object") {
        nucleiResult = rawResults.nuclei as NucleiScanResult;
      }

      const securityScore = calculateSecurityScore(nmapResult, niktoResult, nucleiResult);
      const vulnerabilityHints = buildVulnerabilityHints(nmapResult, niktoResult, nucleiResult);
      const openPorts = nmapResult?.ports.filter(p => p.state.toLowerCase() === "open") || [];
      const allCves = new Set<string>();
      if (nmapResult) nmapResult.vulnerabilities.forEach(v => allCves.add(v.cve_id));
      if (niktoResult) niktoResult.vulnerabilities.forEach(v => allCves.add(v.cve_id));
      if (nucleiResult) nucleiResult.vulnerabilities.forEach(v => allCves.add(v.cve_id));
      const totalVulns = (nmapResult?.vulnerabilities.length || 0) + (niktoResult?.vulnerabilities.length || 0) + (nucleiResult?.vulnerabilities.length || 0);

      parsedResult = {
        target: targetHost, scanType: "full", nmap: nmapResult, nikto: niktoResult, nuclei: nucleiResult,
        securityScore, openPorts, vulnerabilityHints,
        summary: { totalOpenPorts: openPorts.length, totalVulnerabilities: totalVulns, totalCves: allCves.size, totalWebFindings: (niktoResult?.findings.length || 0) + (nucleiResult?.findings.length || 0), enginesCompleted: (nmapResult ? 1 : 0) + (niktoResult ? 1 : 0) + (nucleiResult ? 1 : 0) },
      };
    }

    await db.scan.update({
      where: { id: scan_id },
      data: { status: "Completed", results: JSON.stringify(parsedResult) },
    });

    console.log(`[Callback] Scan ${scan_id} completed via GitHub Actions`);
    return NextResponse.json({ ok: true, status: "Completed", scan_id });

  } catch (error) {
    console.error("[Callback] Error processing scan results:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
