import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { v4 as uuidv4 } from "uuid";

/**
 * POST /api/scan — Create and execute a new scan
 *
 * This endpoint:
 * 1. Validates the target and authorization
 * 2. Creates a scan record in the DB with "Running" status
 * 3. Sends the scan to the Python FastAPI backend (python-nmap engine)
 * 4. Returns immediately with scan_id for frontend polling
 *
 * NO MOCK DATA — Real nmap scans via python-nmap only.
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

// ─── API Route Handler ─────────────────────────────────────────────────────

const SCAN_ENGINE_PORT = 3001;
const SCAN_ENGINE_TIMEOUT = 10000; // 10s timeout for initial request to Python backend

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

    // Create scan record with "Pending" status
    await db.scan.create({
      data: {
        id: scanId,
        target: targetTrimmed,
        status: "Pending",
      },
    });

    // Send scan request to Python FastAPI backend (python-nmap engine)
    try {
      const engineResponse = await fetch(
        `http://localhost:${SCAN_ENGINE_PORT}/scan?XTransformPort=${SCAN_ENGINE_PORT}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ scan_id: scanId, target: targetTrimmed }),
          signal: AbortSignal.timeout(SCAN_ENGINE_TIMEOUT),
        }
      );

      if (!engineResponse.ok) {
        const errorData = await engineResponse.json().catch(() => ({}));
        console.error("[API] Python scan engine error:", errorData);

        // Update DB to Failed
        await db.scan.update({
          where: { id: scanId },
          data: {
            status: "Failed",
            results: JSON.stringify({ error: `Scan engine error: ${(errorData as Record<string, unknown>).detail || "Unknown error"}` }),
          },
        });

        return NextResponse.json({
          scan_id: scanId,
          target: targetTrimmed,
          status: "Failed",
          error: "Scan engine returned an error",
        }, { status: 500 });
      }

      const engineData = await engineResponse.json();
      console.log(`[API] Scan engine accepted: scan_id=${scanId}, status=${(engineData as Record<string, unknown>).status}`);
    } catch (fetchErr) {
      console.error("[API] Cannot reach Python scan engine:", fetchErr);

      // Fallback: try to run nmap directly (for resilience)
      console.log("[API] Attempting direct nmap fallback...");
      try {
        const { spawn } = await import("child_process");
        await runNmapDirectly(scanId, targetTrimmed, spawn);
      } catch (fallbackErr) {
        console.error("[API] Direct nmap fallback also failed:", fallbackErr);
        await db.scan.update({
          where: { id: scanId },
          data: {
            status: "Failed",
            results: JSON.stringify({ error: "Scan engine unavailable and direct nmap fallback failed" }),
          },
        });

        return NextResponse.json({
          scan_id: scanId,
          target: targetTrimmed,
          status: "Failed",
          error: "Scan engine unavailable",
        }, { status: 503 });
      }
    }

    return NextResponse.json({
      scan_id: scanId,
      target: targetTrimmed,
      status: "Running",
      message: "Scan initiated via python-nmap engine. Poll GET /api/scan/[id] for results.",
    }, { status: 201 });

  } catch (error) {
    console.error("[API] Error creating scan:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// ─── Direct nmap Fallback ──────────────────────────────────────────────────

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

function runNmapDirectly(scanId: string, target: string, spawn: typeof import("child_process").spawn): Promise<void> {
  return new Promise((resolve) => {
    console.log(`[Fallback] Starting direct nmap scan for ${target}`);

    const nmapPath = "/home/z/.local/bin/nmap";
    const args = ["-sT", "-sV", "-oX", "-", "--max-retries", "2", "--host-timeout", "30s", target];

    const proc = spawn(nmapPath, args, {
      env: { ...process.env, PATH: `/home/z/.local/bin:${process.env.PATH}` },
    });

    let xmlOutput = "";

    proc.stdout?.on("data", (data: Buffer) => {
      xmlOutput += data.toString();
    });

    proc.stderr?.on("data", () => {
      // Suppress noisy nmap stderr
    });

    proc.on("close", async (code) => {
      console.log(`[Fallback] nmap exited with code ${code}, output length: ${xmlOutput.length}`);

      try {
        if (xmlOutput && xmlOutput.includes("<nmaprun")) {
          const result = parseNmapXml(target, xmlOutput);
          const resultJson = JSON.stringify(result);

          await db.scan.update({
            where: { id: scanId },
            data: { status: "Completed", results: resultJson },
          });
          console.log(`[Fallback] Scan ${scanId} COMPLETED: ${result.ports.length} ports, ${result.vulnerabilities.length} vulns`);
        } else {
          await db.scan.update({
            where: { id: scanId },
            data: { status: "Failed", results: JSON.stringify({ error: "nmap produced no XML output" }) },
          });
          console.log(`[Fallback] Scan ${scanId} FAILED: no XML output`);
        }
      } catch (err) {
        console.error(`[Fallback] Error processing results for ${scanId}:`, err);
        try {
          await db.scan.update({
            where: { id: scanId },
            data: { status: "Failed", results: JSON.stringify({ error: String(err) }) },
          });
        } catch {}
      }
      resolve();
    });

    proc.on("error", async (err) => {
      console.error(`[Fallback] Failed to spawn nmap:`, err);
      try {
        await db.scan.update({
          where: { id: scanId },
          data: { status: "Failed", results: JSON.stringify({ error: `Failed to run nmap: ${err.message}` }) },
        });
      } catch {}
      resolve();
    });
  });
}
