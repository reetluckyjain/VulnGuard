import { NmapScanner } from "./scanners/nmap-scanner";
import type { ScanResult } from "./scanners/base";
import { db } from "./db";

// In-memory task store for tracking active scans
interface ScanTask {
  id: string;
  target: string;
  status: "Pending" | "Running" | "Completed" | "Failed";
  results: ScanResult | null;
  error: string | null;
  startedAt: Date;
  completedAt: Date | null;
}

const scanTasks = new Map<string, ScanTask>();
const scanner = new NmapScanner();

/**
 * Start an asynchronous scan task.
 * Returns immediately while the scan runs in the background.
 */
export async function startScan(scanId: string, target: string): Promise<void> {
  const task: ScanTask = {
    id: scanId,
    target,
    status: "Running",
    results: null,
    error: null,
    startedAt: new Date(),
    completedAt: null,
  };
  scanTasks.set(scanId, task);

  // Run scan asynchronously (fire-and-forget with DB updates)
  scanner.runScan(target).then(async (results) => {
    task.status = "Completed";
    task.results = results;
    task.completedAt = new Date();

    // Update database
    try {
      await db.scan.update({
        where: { id: scanId },
        data: {
          status: "Completed",
          results: JSON.stringify(results),
        },
      });
    } catch (err) {
      console.error("[ScanManager] Failed to update DB:", err);
    }

    console.log(`[ScanManager] Scan ${scanId} completed for ${target}`);
  }).catch(async (err) => {
    task.status = "Failed";
    task.error = err.message || "Unknown error";
    task.completedAt = new Date();

    // Update database
    try {
      await db.scan.update({
        where: { id: scanId },
        data: {
          status: "Failed",
        },
      });
    } catch (dbErr) {
      console.error("[ScanManager] Failed to update DB:", dbErr);
    }

    console.error(`[ScanManager] Scan ${scanId} failed:`, err);
  });
}

/**
 * Get the current status of a scan task.
 * Checks in-memory store first, then falls back to database.
 */
export function getScanStatus(scanId: string): {
  status: string;
  results: ScanResult | null;
  error: string | null;
} {
  const task = scanTasks.get(scanId);

  if (task) {
    return {
      status: task.status,
      results: task.results,
      error: task.error,
    };
  }

  // Not in memory - might be a stale/old scan
  return {
    status: "Unknown",
    results: null,
    error: null,
  };
}
