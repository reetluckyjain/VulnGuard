/**
 * VulnGuard Nmap Scanner — Direct Execution Module
 *
 * Runs real nmap scans directly from Node.js using child_process.
 * Parses XML output using fast-xml-parser and extracts ports, services, and CVE data.
 *
 * NO MOCK DATA — All results come from real nmap scans.
 *
 * Strict JSON Data Contract:
 * {
 *   target: string,
 *   ports: [{ port_id: number, protocol: string, state: string, service: string, version: string }],
 *   vulnerabilities: [{ port_id: number, cve_id: string, description: string }]
 * }
 */

import { execFile } from "child_process";
import { promisify } from "util";
import { XMLParser } from "fast-xml-parser";
import type { ScanResult, PortInfo, Vulnerability } from "./base";

const execFileAsync = promisify(execFile);

// ─── CVE Regex ─────────────────────────────────────────────────────────────

const CVE_REGEX = /CVE-\d{4}-\d{4,7}/g;

// ─── Nmap Binary Path ──────────────────────────────────────────────────────

function getNmapPath(): string {
  const candidates = [
    process.env.NMAP_PATH,
    "/home/z/.local/bin/nmap",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
    "nmap",
  ];

  for (const candidate of candidates) {
    if (candidate) return candidate;
  }

  return "nmap";
}

// ─── Helper: ensure value is always an array ────────────────────────────────

function ensureArray<T>(value: T | T[] | undefined): T[] {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

// ─── XML Parsing ───────────────────────────────────────────────────────────

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  textNodeName: "#text",
  // Don't force arrays - handle both single and multiple element cases
  isArray: () => false,
});

type XmlObj = Record<string, unknown> | string | number | boolean | undefined | null | XmlObj[];

/**
 * Parse nmap XML output and extract ports + vulnerabilities
 */
function parseNmapXml(target: string, xmlObj: XmlObj): ScanResult {
  const ports: PortInfo[] = [];
  const vulnerabilities: Vulnerability[] = [];

  const nmaprun = xmlObj?.nmaprun;
  if (!nmaprun) return { target, ports, vulnerabilities };

  const hosts = ensureArray<XmlObj>(nmaprun.host);

  for (const host of hosts) {
    // Check host state
    if (host?.state?.["@_state"] === "down") continue;

    const portList = ensureArray<XmlObj>(host?.ports?.port);

    for (const port of portList) {
      const portId = parseInt(port?.["@_portid"] || "0", 10);
      const protocol = port?.["@_protocol"] || "tcp";

      // State
      const state = port?.state?.["@_state"] || "unknown";

      // Service
      const svc = port?.service;
      const serviceName = svc?.["@_name"] || "unknown";
      const product = svc?.["@_product"] || "";
      const version = svc?.["@_version"] || "";
      const extrainfo = svc?.["@_extrainfo"] || "";

      // Build version string
      const versionParts: string[] = [];
      if (product) versionParts.push(product);
      if (version) versionParts.push(version);
      if (extrainfo) versionParts.push(`(${extrainfo})`);
      const versionStr = versionParts.length > 0 ? versionParts.join(" ") : "Unknown";

      ports.push({
        port_id: portId,
        protocol,
        state,
        service: serviceName,
        version: versionStr,
      });

      // Parse script output for CVEs
      const scripts = ensureArray<XmlObj>(port?.script);
      for (const script of scripts) {
        const scriptId = script?.["@_id"] || "unknown";
        const scriptOutput = script?.["@_output"] || "";

        // Collect all text from the script output and nested elements
        const textParts: string[] = [scriptOutput];

        // Check elem children
        const scriptElems = ensureArray<XmlObj>(script?.elem);
        for (const elem of scriptElems) {
          if (elem?.["#text"]) textParts.push(elem["#text"]);
        }

        // Check table children
        const scriptTables = ensureArray<XmlObj>(script?.table);
        for (const table of scriptTables) {
          const tableElems = ensureArray<XmlObj>(table?.elem);
          for (const elem of tableElems) {
            if (elem?.["#text"]) textParts.push(elem["#text"]);
          }
        }

        const combinedText = textParts.join(" ");

        // Find CVEs
        const cveMatches = combinedText.match(CVE_REGEX);
        if (cveMatches) {
          const seen = new Set<string>();
          for (const cveId of cveMatches) {
            if (!seen.has(cveId)) {
              seen.add(cveId);
              const desc = extractCveDescription(cveId, combinedText, scriptId, portId, protocol);
              vulnerabilities.push({
                port_id: portId,
                cve_id: cveId,
                description: desc,
              });
            }
          }
        }
      }
    }
  }

  console.log(`[NmapScanner] Parsed: ${ports.length} ports, ${vulnerabilities.length} vulns for ${target}`);
  return { target, ports, vulnerabilities };
}

/**
 * Extract CVE description from surrounding context in nmap script output
 */
function extractCveDescription(
  cveId: string,
  text: string,
  scriptId: string,
  port: number,
  proto: string
): string {
  const idx = text.indexOf(cveId);
  if (idx >= 0) {
    const start = Math.max(0, idx - 80);
    const end = Math.min(text.length, idx + cveId.length + 200);
    let snippet = text.slice(start, end).trim();
    snippet = snippet.replace(/\s+/g, " ");
    if (snippet.length >= 15) {
      return snippet.slice(0, 400);
    }
  }
  return `${cveId} detected by nmap ${scriptId} script on port ${port}/${proto}`;
}

// ─── Run Nmap ──────────────────────────────────────────────────────────────

/**
 * Run nmap as a subprocess and return raw XML stdout
 */
async function runNmap(args: string[], timeoutMs: number): Promise<string | null> {
  const nmapPath = getNmapPath();
  const allArgs = [nmapPath, ...args];

  console.log(`[NmapScanner] Running: ${allArgs.join(" ")}`);

  try {
    const { stdout, stderr } = await execFileAsync(nmapPath, args, {
      timeout: timeoutMs,
      maxBuffer: 10 * 1024 * 1024, // 10MB buffer
      env: { ...process.env, PATH: `/home/z/.local/bin:${process.env.PATH}` },
    });

    if (stdout && stdout.includes("<nmaprun")) {
      return stdout;
    }

    if (stderr) {
      console.warn(`[NmapScanner] nmap stderr: ${stderr.slice(0, 300)}`);
    }

    return null;
  } catch (err: unknown) {
    const error = err as Error & { code?: string; killed?: boolean };
    if (error.killed) {
      console.warn(`[NmapScanner] nmap timed out after ${timeoutMs}ms`);
    } else if (error.code === "ENOENT") {
      console.error(`[NmapScanner] nmap binary not found at ${nmapPath}`);
    } else {
      console.error(`[NmapScanner] nmap execution error:`, error.message);
    }
    return null;
  }
}

// ─── Main Scan Function ────────────────────────────────────────────────────

/**
 * Execute a full nmap scan for a target.
 *
 * Strategy (adaptive, no root required):
 * 1. Primary: nmap -sT -sV -oX - --max-retries 2 --host-timeout 30s <target>
 * 2. Optional: nmap -sT -sV --script vuln -oX - -p <open_ports> <target>
 * 3. Fallback: nmap -sT -oX - --max-retries 1 --host-timeout 30s <target>
 *
 * All parsing uses real nmap output. NO mock data.
 */
export async function executeNmapScan(target: string): Promise<ScanResult> {
  console.log(`[NmapScanner] Starting scan for ${target}`);

  // Attempt 1: Service version scan
  console.log(`[NmapScanner] Attempt 1: nmap -sT -sV for ${target}`);
  let xmlOutput = await runNmap(
    ["-sT", "-sV", "-oX", "-", "--max-retries", "2", "--host-timeout", "30s", target],
    45000
  );

  if (xmlOutput) {
    const parsed = xmlParser.parse(xmlOutput);
    const result = parseNmapXml(target, parsed);

    if (result.ports.length === 0) {
      console.log(`[NmapScanner] No ports found for ${target}`);
      return result;
    }

    // Attempt 2: Vuln scripts on open ports
    const openPorts = result.ports.filter((p) => p.state.toLowerCase() === "open");
    if (openPorts.length > 0) {
      const portList = openPorts.map((p) => p.port_id).join(",");
      console.log(`[NmapScanner] Attempt 2: Running vuln scripts on ports: ${portList}`);
      const vulnXml = await runNmap(
        ["-sT", "-sV", "--script", "vuln", "-oX", "-", "-p", portList, "--max-retries", "1", "--host-timeout", "60s", target],
        120000
      );

      if (vulnXml) {
        const vulnParsed = xmlParser.parse(vulnXml);
        const vulnResult = parseNmapXml(target, vulnParsed);

        if (vulnResult.vulnerabilities.length > 0) {
          result.vulnerabilities = vulnResult.vulnerabilities;
          console.log(`[NmapScanner] Found ${vulnResult.vulnerabilities.length} vulnerabilities for ${target}`);
        }
      }
    } else {
      console.log(`[NmapScanner] No open ports found for ${target}, skipping vuln scan`);
    }

    return result;
  }

  // Attempt 3: Basic port scan (fallback)
  console.log(`[NmapScanner] Attempt 3: Fallback basic port scan for ${target}`);
  xmlOutput = await runNmap(
    ["-sT", "-oX", "-", "--max-retries", "1", "--host-timeout", "30s", target],
    45000
  );

  if (xmlOutput) {
    const parsed = xmlParser.parse(xmlOutput);
    return parseNmapXml(target, parsed);
  }

  throw new Error(`All nmap scan methods failed for ${target}. Check nmap installation and target reachability.`);
}

/**
 * Check if nmap is available on this system
 */
export async function isNmapAvailable(): Promise<boolean> {
  try {
    const { stdout } = await execFileAsync(getNmapPath(), ["--version"], {
      timeout: 5000,
      env: { ...process.env, PATH: `/home/z/.local/bin:${process.env.PATH}` },
    });
    return stdout.includes("Nmap version");
  } catch {
    return false;
  }
}
