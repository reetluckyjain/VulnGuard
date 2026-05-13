/**
 * VulnGuard Scan Service — Bun HTTP Server
 *
 * A lightweight Bun HTTP server that runs real nmap scans.
 * This runs as a separate process to avoid crashing the Next.js server.
 *
 * Port: 3002
 * Endpoints:
 *   POST /scan  — Start a scan (runs nmap synchronously)
 *   GET /health — Health check
 */

const PORT = 3002;
const DB_PATH = "/home/z/my-project/db/custom.db";
const NMAP_PATH = "/home/z/.local/bin/nmap";
const CVE_REGEX = /CVE-\d{4}-\d{4,7}/g;

// ─── Helpers ───────────────────────────────────────────────────────────────

function ensureArray<T>(value: T | T[] | undefined | null): T[] {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

interface ScanResult {
  target: string;
  ports: Array<{
    port_id: number;
    protocol: string;
    state: string;
    service: string;
    version: string;
  }>;
  vulnerabilities: Array<{
    port_id: number;
    cve_id: string;
    description: string;
  }>;
}

// ─── XML Parsing (simple regex-based, no dependencies) ─────────────────────

function parseNmapXml(target: string, xml: string): ScanResult {
  const ports: ScanResult["ports"] = [];
  const vulnerabilities: ScanResult["vulnerabilities"] = [];

  // Extract all <port> blocks
  const portRegex = /<port\s+protocol="([^"]*)"\s+portid="(\d+)">([\s\S]*?)<\/port>/g;
  let portMatch;

  while ((portMatch = portRegex.exec(xml)) !== null) {
    const protocol = portMatch[1];
    const portId = parseInt(portMatch[2], 10);
    const portBlock = portMatch[3];

    // State
    const stateMatch = portBlock.match(/<state\s+state="([^"]*)"/);
    const state = stateMatch?.[1] || "unknown";

    // Service
    const svcMatch = portBlock.match(/<service\s+([^>]*)/);
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
      const scriptOutput = scriptMatch[2].replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&").replace(/&quot;/g, '"');
      const scriptBody = scriptMatch[3];

      // Collect all text from script output and nested elements
      const textParts: string[] = [scriptOutput];

      // Extract elem text
      const elemRegex = /<elem[^>]*>([\s\S]*?)<\/elem>/g;
      let elemMatch;
      while ((elemMatch = elemRegex.exec(scriptBody)) !== null) {
        if (elemMatch[1]) textParts.push(elemMatch[1].trim());
      }

      const combinedText = textParts.join(" ");
      const cveMatches = combinedText.match(CVE_REGEX);

      if (cveMatches) {
        const seen = new Set<string>();
        for (const cveId of cveMatches) {
          if (!seen.has(cveId)) {
            seen.add(cveId);
            const desc = extractCveDescription(cveId, combinedText, scriptId, portId, protocol);
            vulnerabilities.push({ port_id: portId, cve_id: cveId, description: desc });
          }
        }
      }
    }
  }

  console.log(`[ScanService] Parsed: ${ports.length} ports, ${vulnerabilities.length} vulns for ${target}`);
  return { target, ports, vulnerabilities };
}

function extractCveDescription(cveId: string, text: string, scriptId: string, port: number, proto: string): string {
  const idx = text.indexOf(cveId);
  if (idx >= 0) {
    const start = Math.max(0, idx - 80);
    const end = Math.min(text.length, idx + cveId.length + 200);
    let snippet = text.slice(start, end).trim();
    snippet = snippet.replace(/\s+/g, " ");
    if (snippet.length >= 15) return snippet.slice(0, 400);
  }
  return `${cveId} detected by nmap ${scriptId} script on port ${port}/${proto}`;
}

// ─── Run Nmap ──────────────────────────────────────────────────────────────

async function runNmap(args: string[], timeoutMs: number): Promise<string | null> {
  console.log(`[ScanService] Running: ${NMAP_PATH} ${args.join(" ")}`);

  try {
    const proc = Bun.spawn([NMAP_PATH, ...args], {
      stdout: "pipe",
      stderr: "pipe",
    });

    const stdout = await new Response(proc.stdout).text();
    const stderr = await new Response(proc.stderr).text();
    const exitCode = await proc.exited;

    if (exitCode !== 0 && exitCode !== 1) {
      console.warn(`[ScanService] nmap exited with code ${exitCode}: ${stderr.slice(0, 200)}`);
    }

    if (stdout && stdout.includes("<nmaprun")) {
      return stdout;
    }

    return null;
  } catch (err) {
    console.error(`[ScanService] nmap execution error:`, err);
    return null;
  }
}

// ─── Execute Scan ──────────────────────────────────────────────────────────

async function executeScan(target: string): Promise<ScanResult> {
  // Attempt 1: Service version scan
  let xmlOutput = await runNmap(
    ["-sT", "-sV", "-oX", "-", "--max-retries", "2", "--host-timeout", "30s", target],
    45000
  );

  if (xmlOutput) {
    const result = parseNmapXml(target, xmlOutput);

    if (result.ports.length === 0) return result;

    // Attempt 2: Vuln scripts on open ports
    const openPorts = result.ports.filter((p) => p.state === "open");
    if (openPorts.length > 0) {
      const portList = openPorts.map((p) => p.port_id).join(",");
      console.log(`[ScanService] Running vuln scripts on ports: ${portList}`);

      const vulnXml = await runNmap(
        ["-sT", "-sV", "--script", "vuln", "-oX", "-", "-p", portList, "--max-retries", "1", "--host-timeout", "60s", target],
        120000
      );

      if (vulnXml) {
        const vulnResult = parseNmapXml(target, vulnXml);
        if (vulnResult.vulnerabilities.length > 0) {
          result.vulnerabilities = vulnResult.vulnerabilities;
        }
      }
    }

    return result;
  }

  // Attempt 3: Basic port scan
  xmlOutput = await runNmap(
    ["-sT", "-oX", "-", "--max-retries", "1", "--host-timeout", "30s", target],
    45000
  );

  if (xmlOutput) {
    return parseNmapXml(target, xmlOutput);
  }

  throw new Error(`All nmap scan methods failed for ${target}`);
}

// ─── DB Helpers ────────────────────────────────────────────────────────────

function updateScanStatus(scanId: string, status: string, results: string | null = null) {
  // Use Bun's native SQLite
  const db = new (require("bun:sqlite") as typeof import("bun:sqlite")).Database(DB_PATH);
  const now = new Date().toISOString();

  if (results !== null) {
    db.run('UPDATE "Scan" SET status = ?, results = ?, "updatedAt" = ? WHERE id = ?', [status, results, now, scanId]);
  } else {
    db.run('UPDATE "Scan" SET status = ?, "updatedAt" = ? WHERE id = ?', [status, now, scanId]);
  }
  db.close();
}

// ─── HTTP Server ───────────────────────────────────────────────────────────

const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);

    // CORS
    if (req.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }

    // Health check
    if (url.pathname === "/health" && req.method === "GET") {
      return Response.json({
        status: "ok",
        nmap_available: true,
        nmap_path: NMAP_PATH,
        service: "bun-scan-service",
      });
    }

    // Scan endpoint
    if (url.pathname === "/scan" && req.method === "POST") {
      try {
        const body = await req.json() as { scan_id: string; target: string };
        const { scan_id, target } = body;

        console.log(`[ScanService] Starting scan for ${target} (scan_id: ${scan_id})`);

        // Update status to Running
        updateScanStatus(scan_id, "Running");

        // Run nmap scan
        const result = await executeScan(target);
        const resultJson = JSON.stringify(result);

        // Save results
        updateScanStatus(scan_id, "Completed", resultJson);

        console.log(`[ScanService] Scan ${scan_id} completed: ${result.ports.length} ports, ${result.vulnerabilities.length} vulns`);

        return Response.json({
          scan_id,
          status: "Completed",
          results: result,
        });
      } catch (err) {
        const error = err as Error;
        console.error(`[ScanService] Scan failed:`, error);

        try {
          const body = await req.json() as { scan_id: string };
          updateScanStatus(body.scan_id, "Failed", JSON.stringify({ error: error.message }));
        } catch {}

        return Response.json({ error: error.message }, { status: 500 });
      }
    }

    return Response.json({ error: "Not found" }, { status: 404 });
  },
});

console.log(`[ScanService] Bun scan service running on port ${PORT}`);
console.log(`[ScanService] nmap path: ${NMAP_PATH}`);
console.log(`[ScanService] DB path: ${DB_PATH}`);
