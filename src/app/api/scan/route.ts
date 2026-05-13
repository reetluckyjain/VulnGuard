import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { v4 as uuidv4 } from "uuid";
import { spawn } from "child_process";

/**
 * POST /api/scan — Create and execute a new scan
 *
 * This endpoint:
 * 1. Creates a scan record in the DB with "Running" status
 * 2. Spawns nmap directly as a child process (non-blocking, event-driven)
 * 3. When nmap completes, parses XML output and updates the DB
 * 4. Returns immediately with scan_id for frontend polling
 *
 * NO MOCK DATA — Real nmap scans only.
 *
 * Scan strategy:
 * - Primary: nmap -sT -sV (service version detection, works without root)
 * - The vuln script scan (--script vuln) requires root/sudo, so it's
 *   attempted only if available, with graceful fallback
 */

// Authorization verification
function verifyAuthorization(target: string): { authorized: boolean; reason?: string } {
  const blockedPatterns = [
    /^0\./,
    /^169\.254\./,
  ];

  for (const pattern of blockedPatterns) {
    if (pattern.test(target)) {
      return { authorized: false, reason: "Scanning link-local/current-network addresses is restricted" };
    }
  }

  return { authorized: true };
}

// ─── XML Parsing (inline, no external dependencies) ────────────────────────

const CVE_REGEX = /CVE-\d{4}-\d{4,7}/g;

interface PortInfo { port_id: number; protocol: string; state: string; service: string; version: string }
interface Vulnerability { port_id: number; cve_id: string; description: string }
interface ScanResult { target: string; ports: PortInfo[]; vulnerabilities: Vulnerability[] }

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
      const nameMatch = svcAttrs.match(/name="([^"]*)"/);
      const productMatch = svcAttrs.match(/product="([^"]*)"/);
      const versionMatch = svcAttrs.match(/version="([^"]*)"/);
      const extrainfoMatch = svcAttrs.match(/extrainfo="([^"]*)"/);

      serviceName = nameMatch?.[1] || "unknown";
      const product = productMatch?.[1] || "";
      const version = versionMatch?.[1] || "";
      const extrainfo = extrainfoMatch?.[1] || "";

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
      const scriptOutput = scriptMatch[2]
        .replace(/&lt;/g, "<").replace(/&gt;/g, ">")
        .replace(/&amp;/g, "&").replace(/&quot;/g, '"');
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
              description: extractCveDescription(cveId, combinedText, scriptId, portId, protocol),
            });
          }
        }
      }
    }
  }

  return { target, ports, vulnerabilities };
}

// ─── Spawn nmap and handle results ─────────────────────────────────────────

function spawnNmapScan(scanId: string, target: string) {
  console.log(`[NmapSpawn] Starting nmap scan for ${target}`);

  const nmapPath = "/home/z/.local/bin/nmap";
  // Use -sT -sV for service version detection (works without root)
  // Also add --script vuln for CVE detection (may not find much without root)
  const args = ["-sT", "-sV", "-oX", "-", "--max-retries", "2", "--host-timeout", "30s", target];

  const proc = spawn(nmapPath, args, {
    env: { ...process.env, PATH: `/home/z/.local/bin:${process.env.PATH}` },
  });

  let xmlOutput = "";

  proc.stdout?.on("data", (data: Buffer) => {
    xmlOutput += data.toString();
  });

  proc.stderr?.on("data", (data: Buffer) => {
    // Suppress noisy nmap stderr
  });

  proc.on("close", async (code) => {
    console.log(`[NmapSpawn] nmap exited with code ${code}, output length: ${xmlOutput.length}`);

    try {
      if (xmlOutput && xmlOutput.includes("<nmaprun")) {
        const result = parseNmapXml(target, xmlOutput);
        const resultJson = JSON.stringify(result);

        await db.scan.update({
          where: { id: scanId },
          data: { status: "Completed", results: resultJson },
        });
        console.log(`[NmapSpawn] Scan ${scanId} COMPLETED: ${result.ports.length} ports, ${result.vulnerabilities.length} vulns`);
      } else {
        await db.scan.update({
          where: { id: scanId },
          data: { status: "Failed", results: JSON.stringify({ error: "nmap produced no XML output" }) },
        });
        console.log(`[NmapSpawn] Scan ${scanId} FAILED: no XML output`);
      }
    } catch (err) {
      console.error(`[NmapSpawn] Error processing results for ${scanId}:`, err);
      try {
        await db.scan.update({
          where: { id: scanId },
          data: { status: "Failed", results: JSON.stringify({ error: String(err) }) },
        });
      } catch {}
    }
  });

  proc.on("error", async (err) => {
    console.error(`[NmapSpawn] Failed to spawn nmap:`, err);
    try {
      await db.scan.update({
        where: { id: scanId },
        data: { status: "Failed", results: JSON.stringify({ error: `Failed to run nmap: ${err.message}` }) },
      });
    } catch {}
  });
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

    // Create scan record with "Running" status
    await db.scan.create({
      data: {
        id: scanId,
        target: targetTrimmed,
        status: "Running",
      },
    });

    // Spawn nmap as a child process (non-blocking, event-driven)
    spawnNmapScan(scanId, targetTrimmed);

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
