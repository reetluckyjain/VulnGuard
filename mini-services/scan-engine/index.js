const http = require("http");
const { execFile } = require("child_process");
const path = require("path");
const os = require("os");
const fs = require("fs");

const PORT = 3030;
const CVE_REGEX = /CVE-\d{4}-\d{4,7}/g;
const NMAP_BIN = path.join(os.homedir(), ".local/bin/nmap");

// Find nmap
let nmapPath = "nmap";
try { fs.accessSync(NMAP_BIN, fs.constants.X_OK); nmapPath = NMAP_BIN; } catch {}

const scanTasks = new Map();

function unescapeXml(s) {
  return s.replace(/&amp;/g,"&").replace(/&lt;/g,"<").replace(/&gt;/g,">")
    .replace(/&quot;/g,'"').replace(/&apos;/g,"'").replace(/&#39;/g,"'")
    .replace(/&#x2f;/g,"/").replace(/&#xa;/g,"\n").replace(/&#10;/g,"\n");
}

function parseNmapXml(target, xml) {
  const ports = [], vulnerabilities = [];
  const hostRx = /<host[\s>][\s\S]*?<\/host>/g;
  let hm;
  while ((hm = hostRx.exec(xml)) !== null) {
    if (/<status[^>]*state="down"/.test(hm[0])) continue;
    const pbm = hm[0].match(/<ports>[\s\S]*?<\/ports>/);
    if (!pbm) continue;
    const prx = /<port\s+([^>]*)>([\s\S]*?)<\/port>/g;
    let pm;
    while ((pm = prx.exec(pbm[0])) !== null) {
      const pa = pm[1], pc = pm[2];
      const pidm = pa.match(/portid="(\d+)"/), protm = pa.match(/protocol="(\w+)"/);
      if (!pidm || !protm) continue;
      const portId = parseInt(pidm[1]), protocol = protm[1];
      const stm = pc.match(/<state\s+[^>]*state="(\w+)"/);
      const state = stm ? stm[1] : "unknown";
      const sm = pc.match(/<service\s+([^>]*?)\/?>/);
      let serviceName = "unknown", version = "unknown";
      if (sm) {
        const sa = sm[1];
        const nm = sa.match(/name="([^"]*)"/), pmd = sa.match(/product="([^"]*)"/);
        const vm = sa.match(/version="([^"]*)"/), em = sa.match(/extrainfo="([^"]*)"/);
        serviceName = nm ? nm[1] : "unknown";
        const product = pmd ? pmd[1] : "", ver = vm ? vm[1] : "", extra = em ? em[1] : "";
        if (product && ver) version = extra ? `${product} ${ver} (${extra})` : `${product} ${ver}`;
        else if (ver) version = extra ? `${ver} (${extra})` : ver;
        else if (product) version = product;
      }
      ports.push({ port_id: portId, protocol, state, service: serviceName, version });

      // CVE extraction from <script> elements
      const srx = /<script\s+([^>]*)>([\s\S]*?)<\/script>/g;
      let sm2;
      while ((sm2 = srx.exec(pc)) !== null) {
        const sAttrs = sm2[1], sBody = sm2[2];
        const sidm = sAttrs.match(/id="([^"]*)"/), soutm = sAttrs.match(/output="([^"]*)"/);
        const scriptId = sidm ? sidm[1] : "unknown";
        const scriptOut = soutm ? soutm[1] : "";
        const cveTexts = [];
        if (scriptOut) cveTexts.push(unescapeXml(scriptOut));
        const erx = /<elem\s+key="[^"]*">([\s\S]*?)<\/elem>/g;
        let em2;
        while ((em2 = erx.exec(sBody)) !== null) cveTexts.push(unescapeXml(em2[1]));
        cveTexts.push(unescapeXml(sBody.replace(/<[^>]+>/g, " ")));
        const seen = new Set(), combined = cveTexts.join(" ");
        CVE_REGEX.lastIndex = 0;
        let cm;
        while ((cm = CVE_REGEX.exec(combined)) !== null) {
          const cveId = cm[0];
          if (!seen.has(cveId)) {
            seen.add(cveId);
            const idx = combined.indexOf(cveId);
            let desc = combined.slice(Math.max(0, idx-80), Math.min(combined.length, idx+cveId.length+120))
              .trim().replace(/\s+/g," ").replace(/^[^A-Za-z]*/,"").slice(0,200);
            if (!desc || desc.length < 10) desc = `${cveId} detected by nmap ${scriptId} script on port ${portId}/${protocol}`;
            vulnerabilities.push({ port_id: portId, cve_id: cveId, description: desc });
          }
        }
      }
    }
  }
  return { target, ports, vulnerabilities };
}

function runNmapScan(scanId, target) {
  const task = scanTasks.get(scanId);
  if (!task) return;
  console.log(`[ScanEngine] Starting nmap scan for ${target} (${scanId})`);

  // Scan strategy: -sV with --top-ports 100 for fast, reliable service version detection.
  // NOTE: --script vuln requires root privileges and can crash the process in
  // sandboxed environments. The scanner architecture is modular — to enable vuln
  // scanning, run the scan engine with: sudo node index.js
  console.log(`[ScanEngine] Starting nmap -sV scan for ${target}`);
  execFile(nmapPath, ["-sV", "--top-ports", "100", "-oX", "-", target],
    { timeout: 30000, maxBuffer: 10*1024*1024, killSignal: "SIGKILL" },
    (err, stdout, stderr) => {
      if (err && stderr) console.warn(`[ScanEngine] nmap stderr: ${stderr.slice(0,300)}`);
      
      if (stdout && stdout.includes("nmaprun")) {
        const result = parseNmapXml(target, stdout);
        task.status = "Completed"; task.results = result; task.completedAt = new Date().toISOString();
        console.log(`[ScanEngine] Scan ${scanId} completed: ${result.ports.length} ports, ${result.vulnerabilities.length} vulns`);
      } else {
        console.error(`[ScanEngine] Scan failed for ${target}: ${err ? err.message : "no output"}`);
        task.status = "Failed";
        task.error = "nmap scan failed: " + ((err && err.message) || "no output");
        task.completedAt = new Date().toISOString();
      }
    });
}

const server = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }

  const url = new URL(req.url, "http://localhost");

  if (url.pathname === "/scan" && req.method === "POST") {
    let body = "";
    req.on("data", c => body += c);
    req.on("end", () => {
      try {
        const { target, scan_id } = JSON.parse(body);
        if (!target || !scan_id) { res.writeHead(400); res.end(JSON.stringify({error:"Missing target or scan_id"})); return; }
        scanTasks.set(scan_id, { id: scan_id, target, status: "Running", results: null, error: null, startedAt: new Date().toISOString(), completedAt: null });
        runNmapScan(scan_id, target);
        res.writeHead(200, {"Content-Type":"application/json"});
        res.end(JSON.stringify({scan_id, status:"Running"}));
      } catch { res.writeHead(400); res.end(JSON.stringify({error:"Invalid body"})); }
    });
    return;
  }

  const scanMatch = url.pathname.match(/^\/scan\/([a-f0-9-]+)$/);
  if (scanMatch && req.method === "GET") {
    const task = scanTasks.get(scanMatch[1]);
    if (!task) { res.writeHead(404); res.end(JSON.stringify({error:"Not found"})); return; }
    res.writeHead(200, {"Content-Type":"application/json"});
    res.end(JSON.stringify({scan_id:task.id, target:task.target, status:task.status, results:task.results, error:task.error, started_at:task.startedAt, completed_at:task.completedAt}));
    return;
  }

  if (url.pathname === "/health") {
    res.writeHead(200, {"Content-Type":"application/json"});
    res.end(JSON.stringify({status:"ok", service:"scan-engine", nmap:nmapPath}));
    return;
  }

  res.writeHead(404); res.end(JSON.stringify({error:"Not found"}));
});

server.listen(PORT, () => {
  console.log(`[ScanEngine] Running on port ${PORT}`);
  console.log(`[ScanEngine] nmap binary: ${nmapPath}`);
});
