// ─── Scan Engine Mini-Service ───────────────────────────────────────────────
// Runs as a separate process on port 3030.
// Accepts scan requests via HTTP, runs nmap in a child process,
// and serves results back when polling.
//
// This is separated from Next.js because nmap scans can take minutes
// and would block the Next.js event loop.

import { execFile } from "child_process";
import { accessSync, constants as fsConstants } from "fs";
import * as path from "path";
import * as os from "os";

// ─── Configuration ──────────────────────────────────────────────────────────

const PORT = 3030;
const CVE_REGEX = /CVE-\d{4}-\d{4,7}/g;

const NMAP_PATHS = [
  "/usr/bin",
  "/usr/local/bin",
  path.join(os.homedir(), ".local/bin"),
  "/opt/homebrew/bin",
];

function getEnrichedEnv(): Record<string, string> {
  const existingPath = process.env.PATH || "";
  const additionalPaths = NMAP_PATHS.filter((p) => !existingPath.includes(p)).join(":");
  return {
    ...process.env as Record<string, string>,
    PATH: additionalPaths ? `${additionalPaths}:${existingPath}` : existingPath,
  };
}

function resolveNmapPath(): string {
  const localBin = path.join(os.homedir(), ".local/bin/nmap");
  try {
    accessSync(localBin, fsConstants.X_OK);
    return localBin;
  } catch {
    return "nmap";
  }
}

// ─── Types ──────────────────────────────────────────────────────────────────

interface PortInfo {
  port_id: number;
  protocol: string;
  state: string;
  service: string;
  version: string;
}

interface Vulnerability {
  port_id: number;
  cve_id: string;
  description: string;
}

interface ScanResult {
  target: string;
  ports: PortInfo[];
  vulnerabilities: Vulnerability[];
}

interface ScanTask {
  id: string;
  target: string;
  status: "Pending" | "Running" | "Completed" | "Failed";
  results: ScanResult | null;
  error: string | null;
  startedAt: string;
  completedAt: string | null;
}

// ─── In-memory Task Store ───────────────────────────────────────────────────

const scanTasks = new Map<string, ScanTask>();

// ─── Nmap Execution ─────────────────────────────────────────────────────────

function unescapeXml(str: string): string {
  return str
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#39;/g, "'")
    .replace(/&#x2f;/g, "/")
    .replace(/&#xa;/g, "\n")
    .replace(/&#10;/g, "\n")
    .replace(/&#13;/g, "\r");
}

function parseNmapXml(target: string, xml: string): ScanResult {
  const ports: PortInfo[] = [];
  const vulnerabilities: Vulnerability[] = [];

  const hostRegex = /<host[\s>][\s\S]*?<\/host>/g;
  let hostMatch: RegExpExecArray | null;

  while ((hostMatch = hostRegex.exec(xml)) !== null) {
    const hostBlock = hostMatch[0];
    if (/<status[^>]*state="down"/.test(hostBlock)) continue;

    const portsBlockMatch = hostBlock.match(/<ports>[\s\S]*?<\/ports>/);
    if (!portsBlockMatch) continue;
    const portsBlock = portsBlockMatch[0];

    const portRegex = /<port\s+([^>]*)>([\s\S]*?)<\/port>/g;
    let portMatch: RegExpExecArray | null;

    while ((portMatch = portRegex.exec(portsBlock)) !== null) {
      const portAttrs = portMatch[1];
      const portContent = portMatch[2];

      const portIdMatch = portAttrs.match(/portid="(\d+)"/);
      const protocolMatch = portAttrs.match(/protocol="(\w+)"/);
      if (!portIdMatch || !protocolMatch) continue;

      const portId = parseInt(portIdMatch[1], 10);
      const protocol = protocolMatch[1];

      const stateMatch = portContent.match(/<state\s+[^>]*state="(\w+)"/);
      const state = stateMatch ? stateMatch[1] : "unknown";

      const serviceMatch = portContent.match(/<service\s+([^>]*?)\/?>/);
      let serviceName = "unknown";
      let version = "unknown";

      if (serviceMatch) {
        const sa = serviceMatch[1];
        const nm = sa.match(/name="([^"]*)"/);
        const pm = sa.match(/product="([^"]*)"/);
        const vm = sa.match(/version="([^"]*)"/);
        const em = sa.match(/extrainfo="([^"]*)"/);
        serviceName = nm ? nm[1] : "unknown";
        const product = pm ? pm[1] : "";
        const ver = vm ? vm[1] : "";
        const extra = em ? em[1] : "";
        if (product && ver) version = extra ? `${product} ${ver} (${extra})` : `${product} ${ver}`;
        else if (ver) version = extra ? `${ver} (${extra})` : ver;
        else if (product) version = product;
      }

      ports.push({ port_id: portId, protocol, state, service: serviceName, version });

      // Extract CVEs from script elements
      const scriptRegex = /<script\s+([^>]*)>([\s\S]*?)<\/script>/g;
      let scriptMatch: RegExpExecArray | null;
      while ((scriptMatch = scriptRegex.exec(portContent)) !== null) {
        const sAttrs = scriptMatch[1];
        const sBody = scriptMatch[2];
        const sidMatch = sAttrs.match(/id="([^"]*)"/);
        const sOutMatch = sAttrs.match(/output="([^"]*)"/);
        const scriptId = sidMatch ? sidMatch[1] : "unknown";
        const scriptOutput = sOutMatch ? sOutMatch[1] : "";

        const cveTexts: string[] = [];
        if (scriptOutput) cveTexts.push(unescapeXml(scriptOutput));
        const elemRegex = /<elem\s+key="[^"]*">([\s\S]*?)<\/elem>/g;
        let elemMatch: RegExpExecArray | null;
        while ((elemMatch = elemRegex.exec(sBody)) !== null) cveTexts.push(unescapeXml(elemMatch[1]));
        cveTexts.push(unescapeXml(sBody.replace(/<[^>]+>/g, " ")));

        const seen = new Set<string>();
        const combined = cveTexts.join(" ");
        CVE_REGEX.lastIndex = 0;
        let cveMatch: RegExpExecArray | null;
        while ((cveMatch = CVE_REGEX.exec(combined)) !== null) {
          const cveId = cveMatch[0];
          if (!seen.has(cveId)) {
            seen.add(cveId);
            const idx = combined.indexOf(cveId);
            const start = Math.max(0, idx - 80);
            const end = Math.min(combined.length, idx + cveId.length + 120);
            let desc = combined.slice(start, end).trim().replace(/\s+/g, " ").replace(/^[^A-Za-z]*/, "").slice(0, 200);
            if (!desc || desc.length < 10) desc = `${cveId} detected by nmap ${scriptId} script on port ${portId}/${protocol}`;
            vulnerabilities.push({ port_id: portId, cve_id: cveId, description: desc });
          }
        }
      }
    }
  }

  return { target, ports, vulnerabilities };
}

async function runNmapScan(scanId: string, target: string): Promise<void> {
  const task = scanTasks.get(scanId);
  if (!task) return;

  const nmapBin = resolveNmapPath();
  const env = getEnrichedEnv();

  console.log(`[ScanEngine] Starting nmap scan for ${target} (${scanId})`);

  let xmlOutput: string;

  // Attempt 1: Full vuln scan (with short timeout)
  try {
    xmlOutput = await new Promise<string>((resolve, reject) => {
      const child = execFile(
        nmapBin,
        ["-sV", "--script", "vuln", "-oX", "-", target],
        { timeout: 30000, maxBuffer: 10 * 1024 * 1024, env, killSignal: "SIGKILL" },
        (err, stdout, stderr) => {
          if (err && !stdout?.includes("<nmaprun")) {
            reject(err);
          } else {
            resolve(stdout || "");
          }
          if (stderr) console.warn(`[ScanEngine] nmap stderr: ${stderr.slice(0, 300)}`);
        }
      );
      // Ensure the process doesn't outlive the timeout
      child.on("error", (err) => reject(err));
    });

    if (xmlOutput.includes("<nmaprun")) {
      console.log(`[ScanEngine] Vuln scan completed for ${target}`);
      const result = parseNmapXml(target, xmlOutput);
      task.status = "Completed";
      task.results = result;
      task.completedAt = new Date().toISOString();
      return;
    }
  } catch (err) {
    console.warn(`[ScanEngine] Vuln scan failed/timed out for ${target}: ${(err as Error).message}`);
  }

  // Attempt 2: Service-only scan (faster, no root needed)
  try {
    xmlOutput = await new Promise<string>((resolve, reject) => {
      execFile(
        nmapBin,
        ["-sV", "-oX", "-", target],
        { timeout: 45000, maxBuffer: 10 * 1024 * 1024, env, killSignal: "SIGKILL" },
        (err, stdout, stderr) => {
          if (err && !stdout?.includes("<nmaprun")) {
            reject(err);
          } else {
            resolve(stdout || "");
          }
          if (stderr) console.warn(`[ScanEngine] nmap stderr: ${stderr.slice(0, 300)}`);
        }
      );
    });

    if (xmlOutput.includes("<nmaprun")) {
      console.log(`[ScanEngine] Service scan completed for ${target}`);
      const result = parseNmapXml(target, xmlOutput);
      task.status = "Completed";
      task.results = result;
      task.completedAt = new Date().toISOString();
      return;
    }
  } catch (err) {
    console.error(`[ScanEngine] Service scan also failed for ${target}: ${(err as Error).message}`);
  }

  // Both attempts failed
  task.status = "Failed";
  task.error = `nmap scan failed for ${target}. Ensure nmap is installed and the target is reachable.`;
  task.completedAt = new Date().toISOString();
}

// ─── HTTP Server ────────────────────────────────────────────────────────────

const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // POST /scan - Start a new scan
    if (url.pathname === "/scan" && req.method === "POST") {
      try {
        const body = await req.json() as { target: string; scan_id: string };
        if (!body.target || !body.scan_id) {
          return Response.json({ error: "Missing target or scan_id" }, { status: 400, headers: corsHeaders });
        }

        const task: ScanTask = {
          id: body.scan_id,
          target: body.target,
          status: "Running",
          results: null,
          error: null,
          startedAt: new Date().toISOString(),
          completedAt: null,
        };
        scanTasks.set(body.scan_id, task);

        // Run scan asynchronously — this is a separate process so it won't block Next.js
        runNmapScan(body.scan_id, body.target).catch((err) => {
          console.error(`[ScanEngine] Unhandled scan error:`, err);
        });

        return Response.json({ scan_id: body.scan_id, status: "Running" }, { headers: corsHeaders });
      } catch {
        return Response.json({ error: "Invalid request body" }, { status: 400, headers: corsHeaders });
      }
    }

    // GET /scan/:id - Get scan status
    const scanMatch = url.pathname.match(/^\/scan\/([a-f0-9-]+)$/);
    if (scanMatch && req.method === "GET") {
      const task = scanTasks.get(scanMatch[1]);
      if (!task) {
        return Response.json({ error: "Scan not found" }, { status: 404, headers: corsHeaders });
      }
      return Response.json({
        scan_id: task.id,
        target: task.target,
        status: task.status,
        results: task.results,
        error: task.error,
        started_at: task.startedAt,
        completed_at: task.completedAt,
      }, { headers: corsHeaders });
    }

    // GET /health
    if (url.pathname === "/health") {
      return Response.json({ status: "ok", service: "scan-engine", nmap: resolveNmapPath() }, { headers: corsHeaders });
    }

    return Response.json({ error: "Not found" }, { status: 404, headers: corsHeaders });
  },
});

console.log(`[ScanEngine] Running on port ${PORT}`);
console.log(`[ScanEngine] nmap binary: ${resolveNmapPath()}`);
