import { BaseScanner, ScanResult, PortInfo, Vulnerability } from "./base";

// Realistic CVE database for simulation
const CVE_DATABASE: Record<string, { description: string; severity: "Critical" | "High" | "Medium" | "Low" }[]> = {
  "21": [
    { cve_id: "CVE-2021-36276", description: "vsftpd 2.3.4 backdoor allowing remote code execution", severity: "Critical" },
  ],
  "22": [
    { cve_id: "CVE-2023-38408", description: "OpenSSH ssh-agent PKCS#11 bypass", severity: "High" },
    { cve_id: "CVE-2023-28531", description: "OpenSSH buffer overflow in forwarder", severity: "Medium" },
  ],
  "80": [
    { cve_id: "CVE-2023-25690", description: "Apache HTTP Server HTTP Request Smuggling", severity: "Critical" },
    { cve_id: "CVE-2023-31122", description: "Apache HTTP Server out-of-bounds read", severity: "Medium" },
  ],
  "443": [
    { cve_id: "CVE-2023-3446", description: "OpenSSL DH parameter check excessive computation", severity: "Medium" },
    { cve_id: "CVE-2023-2975", description: "OpenSSL AES-SIV cipher buffer over-read", severity: "High" },
  ],
  "3306": [
    { cve_id: "CVE-2023-21980", description: "MySQL Server InnoDB vulnerability", severity: "High" },
    { cve_id: "CVE-2023-22056", description: "MySQL Server Optimizer vulnerability", severity: "Medium" },
  ],
  "5432": [
    { cve_id: "CVE-2023-39417", description: "PostgreSQL MERGE command privilege escalation", severity: "High" },
  ],
  "8080": [
    { cve_id: "CVE-2023-44487", description: "HTTP/2 Rapid Reset Attack (DDoS)", severity: "Critical" },
    { cve_id: "CVE-2023-41080", description: "Apache Tomcat OpenRedirect vulnerability", severity: "Medium" },
  ],
  "8443": [
    { cve_id: "CVE-2023-36664", description: "Ghostscript pipe command injection", severity: "Critical" },
  ],
  "27017": [
    { cve_id: "CVE-2023-32670", description: "MongoDB Server incomplete key revocation", severity: "High" },
  ],
};

// Common port/service mappings for realistic simulation
const COMMON_PORTS: { port: number; service: string; version: string }[] = [
  { port: 21, service: "ftp", version: "vsftpd 2.3.4" },
  { port: 22, service: "ssh", version: "OpenSSH 8.9p1 Ubuntu 3ubuntu0.6" },
  { port: 25, service: "smtp", version: "Postfix smtpd" },
  { port: 53, service: "domain", version: "ISC BIND 9.18.18" },
  { port: 80, service: "http", version: "Apache httpd 2.4.56" },
  { port: 110, service: "pop3", version: "Dovecot pop3d" },
  { port: 143, service: "imap", version: "Dovecot imapd" },
  { port: 443, service: "https", version: "nginx 1.24.0" },
  { port: 993, service: "imaps", version: "Dovecot imapd" },
  { port: 995, service: "pop3s", version: "Dovecot pop3d" },
  { port: 3306, service: "mysql", version: "MySQL 8.0.35" },
  { port: 3389, service: "ms-wbt-server", version: "Microsoft Terminal Services" },
  { port: 5432, service: "postgresql", version: "PostgreSQL 15.4" },
  { port: 5900, service: "vnc", version: "RealVNC 6.11.0" },
  { port: 6379, service: "redis", version: "Redis 7.2.3" },
  { port: 8080, service: "http-proxy", version: "Apache Tomcat 9.0.82" },
  { port: 8443, service: "https-alt", version: "Jetty 12.0.3" },
  { port: 27017, service: "mongodb", version: "MongoDB 7.0.4" },
];

export class NmapScanner extends BaseScanner {
  name = "Nmap";

  async runScan(target: string): Promise<ScanResult> {
    // Simulate realistic scanning delay
    const delay = 3000 + Math.random() * 5000;
    await new Promise(resolve => setTimeout(resolve, delay));

    // Generate deterministic but varied results based on target
    const hash = this.hashString(target);
    const numPorts = 3 + (hash % 8); // 3-10 open ports

    // Select ports deterministically based on target hash
    const selectedPorts: typeof COMMON_PORTS[number][] = [];
    const usedIndices = new Set<number>();
    for (let i = 0; i < numPorts && i < COMMON_PORTS.length; i++) {
      const idx = (hash + i * 7) % COMMON_PORTS.length;
      if (!usedIndices.has(idx)) {
        usedIndices.add(idx);
        selectedPorts.push(COMMON_PORTS[idx]);
      }
    }

    const ports: PortInfo[] = selectedPorts.map(p => ({
      port_number: p.port,
      protocol: "tcp",
      state: "open",
      service_name: p.service,
      version: p.version,
    }));

    // Map vulnerabilities from our CVE database
    const vulnerabilities: Vulnerability[] = [];
    for (const port of selectedPorts) {
      const cves = CVE_DATABASE[String(port.port)];
      if (cves) {
        for (const cve of cves) {
          vulnerabilities.push({
            cve_id: cve.cve_id,
            description: cve.description,
            port: port.port,
            severity: cve.severity,
          });
        }
      }
    }

    return {
      target,
      scan_time: new Date().toISOString(),
      ports,
      vulnerabilities,
    };
  }

  private hashString(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return Math.abs(hash);
  }
}
