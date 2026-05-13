import type { ScanResult } from "./scanners/base";
import { db } from "./db";

/**
 * VulnGuard Scan Manager — Database Reader
 *
 * Architecture:
 *   1. Next.js POST /api/scan creates scan record + calls Bun scan service
 *   2. Bun scan service runs real nmap and updates the DB
 *   3. This manager provides read access to scan status from the DB
 *   4. Frontend polls GET /api/scan/[id] for status updates
 *
 * NO MOCK DATA — All results come from real nmap scans.
 */

/**
 * Get the current status of a scan by reading directly from the database.
 */
export async function getScanStatus(scanId: string): Promise<{
  status: string;
  results: ScanResult | null;
  error: string | null;
}> {
  try {
    const scan = await db.scan.findUnique({ where: { id: scanId } });

    if (!scan) {
      return { status: "Unknown", results: null, error: null };
    }

    let parsedResults: ScanResult | null = null;
    if (scan.results) {
      try {
        parsedResults = JSON.parse(scan.results) as ScanResult;
      } catch (parseErr) {
        console.error(`[ScanManager] JSON.parse failed for scan ${scanId}:`, parseErr);
      }
    }

    // Check if the parsed results contain an error indicator
    let error: string | null = null;
    if (scan.status === "Failed" && parsedResults && "error" in parsedResults) {
      error = (parsedResults as unknown as { error: string }).error;
      parsedResults = null;
    }

    return { status: scan.status, results: parsedResults, error };
  } catch (dbErr) {
    console.error(`[ScanManager] DB lookup failed for scan ${scanId}:`, dbErr);
    return { status: "Unknown", results: null, error: null };
  }
}
