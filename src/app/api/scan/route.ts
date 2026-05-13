import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { v4 as uuidv4 } from "uuid";
import { execSync } from "child_process";
import { readFileSync, existsSync, unlinkSync, mkdirSync } from "fs";
import { join } from "path";

/**
 * POST /api/scan — Create and execute a new scan
 *
 * Spawns nmap via a standalone shell script that runs completely independently.
 * The script writes XML output to temp files, which are read by the GET route.
 * This ensures nmap survives even if the Next.js server process dies.
 *
 * NO MOCK DATA — Real nmap scans only.
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

const CVE_REGEX = /CVE-\d{4}-\d{4,7}/g;

// ─── XML Parsing ────────────────────────────────────────────────────────────

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

// ─── Temp file helpers ──────────────────────────────────────────────────────

const TMP_DIR = "/tmp/vulnguard-scans";

function ensureTmpDir() {
  try { mkdirSync(TMP_DIR, { recursive: true }); } catch {}
}

// ─── Result Processor ───────────────────────────────────────────────────────

export async function processScanResults(scanId: string, target: string): Promise<{ status: string; results: ScanResult | null; error: string | null }> {
  const xmlFile = join(TMP_DIR, `${scanId}.xml`);
  const vulnXmlFile = join(TMP_DIR, `${scanId}-vuln.xml`);
  const statusFile = join(TMP_DIR, `${scanId}.status`);

  // Check status file for errors
  if (existsSync(statusFile)) {
    const status = readFileSync(statusFile, "utf-8").trim();
    if (status.startsWith("error:")) {
      return { status: "Failed", results: null, error: status.slice(6) };
    }
    if (status === "completed") {
      // Process the XML files
      let result: ScanResult = { target, ports: [], vulnerabilities: [] };

      if (existsSync(xmlFile)) {
        try {
          const xml = readFileSync(xmlFile, "utf-8");
          if (xml.includes("</nmaprun>")) {
            result = parseNmapXml(target, xml);
          }
        } catch {}
      }

      // Also check vuln XML
      if (existsSync(vulnXmlFile)) {
        try {
          const vulnXml = readFileSync(vulnXmlFile, "utf-8");
          if (vulnXml.includes("</nmaprun>")) {
            const vulnResult = parseNmapXml(target, vulnXml);
            if (vulnResult.vulnerabilities.length > 0) {
              result.vulnerabilities = vulnResult.vulnerabilities;
            }
            // Also merge any additional ports from vuln scan
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

  // Check if XML file exists but nmap is still running
  if (existsSync(xmlFile)) {
    try {
      const xml = readFileSync(xmlFile, "utf-8");
      if (xml.includes("</nmaprun>")) {
        // XML is complete but status file hasn't been updated yet
        // This can happen if the shell script is running vuln scan
        // Process the main scan result but don't mark as complete yet
      }
    } catch {}
  }

  return { status: "Running", results: null, error: null };
}

// ─── API Route Handler ─────────────────────────────────────────────────────

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { target, isAuthorized } = body;

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

    const scanId = uuidv4();

    ensureTmpDir();

    await db.scan.create({
      data: { id: scanId, target: targetTrimmed, status: "Running" },
    });

    // Spawn nmap via standalone shell script using nohup + background &
    // execSync with & starts the process in background and returns immediately
    // The nmap process runs completely independently of Next.js
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
      // execSync throws on non-zero exit, but background & always returns 0
      // The nmap process is running in the background regardless
    }

    console.log(`[API] Spawned nmap script for scan ${scanId}, target ${targetTrimmed}`);

    return NextResponse.json({
      scan_id: scanId,
      target: targetTrimmed,
      status: "Running",
      message: "Scan initiated. Real nmap scan is running. Poll GET /api/scan/[id] for results.",
    }, { status: 201 });

  } catch (error) {
    console.error("[API] Error creating scan:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export { parseNmapXml };
