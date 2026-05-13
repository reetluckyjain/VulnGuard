// ─── Strict JSON Data Contract ─────────────────────────────────────────────
// This contract MUST match what the Python scan engine produces.
// Every scanner plugin must conform to these exact shapes.

export interface ScanResult {
  target: string;
  ports: PortInfo[];
  vulnerabilities: Vulnerability[];
}

export interface PortInfo {
  port_id: number;
  protocol: string;
  state: string;
  service: string;
  version: string;
}

export interface Vulnerability {
  port_id: number;
  cve_id: string;
  description: string;
}

export abstract class BaseScanner {
  abstract name: string;
  abstract runScan(target: string): Promise<ScanResult>;
}
