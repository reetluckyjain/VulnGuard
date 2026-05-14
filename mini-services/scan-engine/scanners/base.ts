// Abstract base scanner interface - modular architecture for plugging in tools
export interface ScanResult {
  target: string;
  scan_time: string;
  ports: PortInfo[];
  vulnerabilities: Vulnerability[];
}

export interface PortInfo {
  port_number: number;
  protocol: string;
  state: string;
  service_name: string;
  version: string;
}

export interface Vulnerability {
  cve_id: string;
  description: string;
  port: number;
  severity: "Critical" | "High" | "Medium" | "Low";
}

export abstract class BaseScanner {
  abstract name: string;
  abstract runScan(target: string): Promise<ScanResult>;
}
