import { BaseScanner, ScanResult, PortInfo, Vulnerability } from "./base";
import { execFile } from "child_process";
import { promisify } from "util";
import { accessSync, constants } from "fs";
import * as path from "path";
import * as os from "os";

const execFileAsync = promisify(execFile);

// ─── CVE Regex ──────────────────────────────────────────────────────────────
// Matches CVE identifiers in nmap --script vuln output
const CVE_REGEX = /CVE-\d{4}-\d{4,7}/g;

// ─── PATH Configuration ────────────────────────────────────────────────────
const NMAP_PATHS = [
  "/usr/bin",
  "/usr/local/bin",
  path.join(os.homedir(), ".local/bin"),
  "/opt/homebrew/bin",
];

function getEnrichedEnv(): NodeJS.ProcessEnv {
  const existingPath = process.env.PATH || "";
  const additionalPaths = NMAP_PATHS.filter((p) => !existingPath.includes(p)).join(":");
  return {
    ...process.env,
    PATH: additionalPaths ? `${additionalPaths}:${existingPath}` : existingPath,
  };
}

function resolveNmapPath(): string {
  const localBin = path.join(os.homedir(), ".local/bin/nmap");
  try {
    accessSync(localBin, constants.X_OK);
    return localBin;
  } catch {
    return "nmap";
  }
}

/**
 * NmapScanner
 *
 * Real implementation that spawns nmap as a child process and parses the XML output.
 *
 * Scan strategy (adaptive):
 *  1. First attempt: `nmap -sV --script vuln -oX - <target>` (full vulnerability scan)
 *  2. If vuln scripts fail (require root, timeout, etc.), fall back to:
 *     `nmap -sV -oX - <target>` (service version detection only)
 *
 * The parser handles real nmap XML structure including:
 *  - <port> elements with portid, protocol, state
 *  - <service> elements with name, product, version
 *  - <script> elements with CVE extraction from output attribute and nested <elem> tags
 *
 * NO mock data. NO silent fallback. All errors are logged.
 */
export class NmapScanner extends BaseScanner {
  name = "Nmap";

  async runScan(target: string): Promise<ScanResult> {
    const nmapBin = resolveNmapPath();
    const env = getEnrichedEnv();

    // ── Step 1: Verify nmap is available ──────────────────────────────────
    const nmapAvailable = await this.checkNmapAvailable(nmapBin, env);
    if (!nmapAvailable) {
      const errMsg =
        `nmap binary not found on this system. ` +
        `Install it with: sudo apt-get install nmap (Debian/Ubuntu) ` +
        `or brew install nmap (macOS). ` +
        `The scanner requires a real nmap installation to function.`;
      console.error(`[NmapScanner] FATAL: ${errMsg}`);
      throw new Error(errMsg);
    }

    // ── Step 2: Try full vuln scan first, fall back to service scan ──────
    let xmlOutput: string;
    let usedVulnScan = false;

    // Attempt 1: Full vulnerability scan with --script vuln
    // NOTE: --script vuln can be very slow (minutes) and requires root for SYN scan.
    // We use a short timeout to avoid blocking the server, then fall back gracefully.
    console.log(`[NmapScanner] Attempting full vuln scan: ${nmapBin} -sV --script vuln -oX - ${target}`);
    try {
      const { stdout } = await execFileAsync(nmapBin, ["-sV", "--script", "vuln", "-oX", "-", target], {
        timeout: 30000, // 30 second timeout — vuln scan must respond quickly or we fall back
        maxBuffer: 10 * 1024 * 1024,
        env,
        killSignal: "SIGKILL", // Force-kill nmap if it times out
      });
      xmlOutput = stdout;
      usedVulnScan = true;
      console.log(`[NmapScanner] Full vuln scan completed for ${target}. XML length: ${xmlOutput.length}`);
    } catch (err: unknown) {
      const execErr = err as { code?: string; stderr?: string; message?: string; stdout?: string; killed?: boolean };

      // If we got partial XML from the vuln scan, use it
      if (execErr.stdout && execErr.stdout.includes("<nmaprun")) {
        xmlOutput = execErr.stdout;
        usedVulnScan = true;
        console.log(`[NmapScanner] Using partial XML from vuln scan (process exited with error)`);
      } else {
        // vuln scan failed — log why, then fall back to service-only scan
        if (execErr.killed) {
          console.warn(`[NmapScanner] Vuln scan TIMED OUT for ${target}. Falling back to service-only scan.`);
        } else if (execErr.code === "ENOENT") {
          throw new Error("nmap binary not found. Please install nmap.");
        } else {
          console.warn(
            `[NmapScanner] Vuln scan FAILED for ${target}: ${execErr.message || "Unknown error"}. ` +
            `Falling back to service-only scan.`
          );
          if (execErr.stderr) {
            console.warn(`[NmapScanner] nmap stderr: ${execErr.stderr.slice(0, 300)}`);
          }
        }

        // Attempt 2: Service version detection only (faster, no root needed)
        console.log(`[NmapScanner] Falling back to service scan: ${nmapBin} -sV -oX - ${target}`);
        try {
          const { stdout } = await execFileAsync(nmapBin, ["-sV", "-oX", "-", target], {
            timeout: 45000, // 45 second timeout for service-only scan
            maxBuffer: 10 * 1024 * 1024,
            env,
            killSignal: "SIGKILL",
          });
          xmlOutput = stdout;
          console.log(`[NmapScanner] Service scan completed for ${target}. XML length: ${xmlOutput.length}`);
        } catch (fallbackErr: unknown) {
          const fbErr = fallbackErr as { code?: string; stdout?: string; message?: string };
          // Even the service scan might fail but produce partial XML
          if (fbErr.stdout && fbErr.stdout.includes("<nmaprun")) {
            xmlOutput = fbErr.stdout;
            console.log(`[NmapScanner] Using partial XML from service scan`);
          } else {
            throw new Error(
              `nmap scan failed for ${target}: ${fbErr.message || "Unknown error"}. ` +
              `Ensure nmap is installed and the target is reachable.`
            );
          }
        }
      }
    }

    // ── Step 3: Parse the XML output ──────────────────────────────────────
    const result = this.parseNmapXml(target, xmlOutput);

    // Log a warning if no vuln scan was performed
    if (!usedVulnScan) {
      console.log(
        `[NmapScanner] NOTE: Vulnerability scripts were not used for ${target}. ` +
        `Run as root (sudo) for full CVE detection with --script vuln.`
      );
    }

    return result;
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Private helpers
  // ──────────────────────────────────────────────────────────────────────────

  private async checkNmapAvailable(nmapBin: string, env: NodeJS.ProcessEnv): Promise<boolean> {
    try {
      await execFileAsync(nmapBin, ["--version"], { timeout: 5000, env });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Parse nmap XML output and extract ports + vulnerabilities.
   *
   * Handles the real nmap XML structure:
   * <nmaprun>
   *   <host>
   *     <status state="up"/>
   *     <ports>
   *       <port protocol="tcp" portid="22">
   *         <state state="open" reason="syn-ack"/>
   *         <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu 4" method="probed" conf="10"/>
   *         <script id="vuln" output="CVE-2020-15778 ...">
   *           <table>
   *             <elem key="id">CVE-2020-15778</elem>
   *           </table>
   *         </script>
   *       </port>
   *     </ports>
   *   </host>
   * </nmaprun>
   */
  private parseNmapXml(target: string, xml: string): ScanResult {
    const ports: PortInfo[] = [];
    const vulnerabilities: Vulnerability[] = [];

    // ── Extract all <host> blocks ─────────────────────────────────────────
    const hostRegex = /<host[\s>][\s\S]*?<\/host>/g;
    let hostMatch: RegExpExecArray | null;

    while ((hostMatch = hostRegex.exec(xml)) !== null) {
      const hostBlock = hostMatch[0];

      // Skip hosts that are down
      if (/<status[^>]*state="down"/.test(hostBlock)) {
        console.log(`[NmapScanner] Skipping host marked as down`);
        continue;
      }

      // ── Extract the <ports> block ─────────────────────────────────────
      const portsBlockMatch = hostBlock.match(/<ports>[\s\S]*?<\/ports>/);
      if (!portsBlockMatch) {
        console.warn(`[NmapScanner] No <ports> block found for host in scan of ${target}`);
        continue;
      }
      const portsBlock = portsBlockMatch[0];

      // ── Extract each <port> element ───────────────────────────────────
      const portRegex = /<port\s+([^>]*)>([\s\S]*?)<\/port>/g;
      let portMatch: RegExpExecArray | null;

      while ((portMatch = portRegex.exec(portsBlock)) !== null) {
        const portAttrs = portMatch[1];
        const portContent = portMatch[2];

        // Extract port attributes: portid, protocol
        const portIdMatch = portAttrs.match(/portid="(\d+)"/);
        const protocolMatch = portAttrs.match(/protocol="(\w+)"/);

        if (!portIdMatch || !protocolMatch) {
          console.warn(`[NmapScanner] Skipping <port> with missing portid/protocol in scan of ${target}`);
          continue;
        }

        const portId = parseInt(portIdMatch[1], 10);
        const protocol = protocolMatch[1];

        // ── Extract <state> ────────────────────────────────────────────
        const stateMatch = portContent.match(/<state\s+[^>]*state="(\w+)"/);
        const state = stateMatch ? stateMatch[1] : "unknown";

        // ── Extract <service> name, product, version ───────────────────
        const serviceMatch = portContent.match(/<service\s+([^>]*?)\/?>/);
        let serviceName = "unknown";
        let version = "unknown";

        if (serviceMatch) {
          const serviceAttrs = serviceMatch[1];
          const nameMatch = serviceAttrs.match(/name="([^"]*)"/);
          const productMatch = serviceAttrs.match(/product="([^"]*)"/);
          const versionMatch = serviceAttrs.match(/version="([^"]*)"/);
          const extrainfoMatch = serviceAttrs.match(/extrainfo="([^"]*)"/);

          serviceName = nameMatch ? nameMatch[1] : "unknown";

          // Build version string: "Product Version (extrainfo)" or combinations
          const product = productMatch ? productMatch[1] : "";
          const ver = versionMatch ? versionMatch[1] : "";
          const extra = extrainfoMatch ? extrainfoMatch[1] : "";

          if (product && ver) {
            version = extra ? `${product} ${ver} (${extra})` : `${product} ${ver}`;
          } else if (ver) {
            version = extra ? `${ver} (${extra})` : ver;
          } else if (product) {
            version = product;
          }
        }

        // Add port to results
        ports.push({
          port_id: portId,
          protocol,
          state,
          service: serviceName,
          version,
        });

        // ── Extract CVEs from <script> elements ────────────────────────
        // The --script vuln output is stored in <script> elements.
        // Each script has:
        //   - id attribute (script name, e.g., "vuln", "ssl-heartbleed")
        //   - output attribute (summary text, may contain CVE IDs)
        //   - Nested <table>/<elem> elements with structured data

        const scriptRegex = /<script\s+([^>]*)>([\s\S]*?)<\/script>/g;
        let scriptMatch: RegExpExecArray | null;

        while ((scriptMatch = scriptRegex.exec(portContent)) !== null) {
          const scriptAttrs = scriptMatch[1];
          const scriptBody = scriptMatch[2];

          // Extract script id and output attributes
          const scriptIdMatch = scriptAttrs.match(/id="([^"]*)"/);
          const scriptOutputMatch = scriptAttrs.match(/output="([^"]*)"/);
          const scriptId = scriptIdMatch ? scriptIdMatch[1] : "unknown";
          const scriptOutput = scriptOutputMatch ? scriptOutputMatch[1] : "";

          // Collect all text from this script for CVE extraction
          const cveTexts: string[] = [];

          // From the output attribute (most reliable for CVE IDs)
          if (scriptOutput) {
            cveTexts.push(this.unescapeXml(scriptOutput));
          }

          // From nested <elem> elements (structured vuln data)
          const elemRegex = /<elem\s+key="[^"]*">([\s\S]*?)<\/elem>/g;
          let elemMatch: RegExpExecArray | null;
          while ((elemMatch = elemRegex.exec(scriptBody)) !== null) {
            cveTexts.push(this.unescapeXml(elemMatch[1]));
          }

          // From any text content inside the script body
          const textContent = scriptBody.replace(/<[^>]+>/g, " ");
          cveTexts.push(this.unescapeXml(textContent));

          // Search all collected text for CVE patterns using regex
          const seenCves = new Set<string>();
          const combinedText = cveTexts.join(" ");

          CVE_REGEX.lastIndex = 0; // Reset regex state
          let cveMatch: RegExpExecArray | null;
          while ((cveMatch = CVE_REGEX.exec(combinedText)) !== null) {
            const cveId = cveMatch[0];
            if (!seenCves.has(cveId)) {
              seenCves.add(cveId);

              // Extract surrounding text snippet for the description
              const cveIndex = combinedText.indexOf(cveId);
              const snippetStart = Math.max(0, cveIndex - 80);
              const snippetEnd = Math.min(combinedText.length, cveIndex + cveId.length + 120);
              let description = combinedText.slice(snippetStart, snippetEnd).trim();

              // Clean up the description
              description = description
                .replace(/\s+/g, " ")
                .replace(/^[^A-Za-z]*/, "")
                .slice(0, 200);

              // Fallback description if snippet is too short
              if (!description || description.length < 10) {
                description = `${cveId} detected by nmap ${scriptId} script on port ${portId}/${protocol}`;
              }

              vulnerabilities.push({
                port_id: portId,
                cve_id: cveId,
                description,
              });
            }
          }
        }
      }
    }

    // ── Handle case where no hosts/ports were found ──────────────────────
    if (ports.length === 0) {
      console.log(`[NmapScanner] No open ports found for ${target}. Host may be down or firewalled.`);
    }

    console.log(
      `[NmapScanner] Scan of ${target} complete: ${ports.length} ports, ${vulnerabilities.length} vulnerabilities`
    );

    return {
      target,
      ports,
      vulnerabilities,
    };
  }

  /**
   * Unescape common XML entities found in nmap output.
   * nmap encodes special characters in attribute values and text content.
   */
  private unescapeXml(str: string): string {
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
      .replace(/&#13;/g, "\r")
      .replace(/&#x9;/g, "\t");
  }
}
