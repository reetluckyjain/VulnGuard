import type { ScanResult } from "./scanners/base";
import { db } from "./db";

// ─── Scan Engine URL ────────────────────────────────────────────────────────
// The scan engine runs as a separate Node.js process on port 3030.
// Since both Next.js and the scan engine are Node.js processes,
// they can communicate directly via localhost.
const SCAN_ENGINE_URL = "http://127.0.0.1:3030";

// ─── In-memory cache for active scans ───────────────────────────────────────
const scanCache = new Map<string, { status: string; results: ScanResult | null; error: string | null; fetchedAt: number }>();
const CACHE_TTL = 5_000; // 5 seconds

/**
 * Start an asynchronous scan task by delegating to the scan engine mini-service.
 * The scan engine runs nmap in a separate process, so it won't block Next.js.
 */
export async function startScan(scanId: string, target: string): Promise<void> {
  console.log(`[ScanManager] Triggering scan ${scanId} for target ${target} via scan engine`);

  try {
    const response = await fetch(`${SCAN_ENGINE_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, scan_id: scanId }),
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({})) as { error?: string };
      throw new Error(`Scan engine returned ${response.status}: ${errorData.error || "Unknown"}`);
    }

    console.log(`[ScanManager] Scan ${scanId} triggered successfully via engine`);
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    console.error(`[ScanManager] Failed to trigger scan ${scanId}:`, errorMessage);

    // Mark as failed in DB
    try {
      await db.scan.update({
        where: { id: scanId },
        data: {
          status: "Failed",
          results: JSON.stringify({ error: `Scan engine unavailable: ${errorMessage}` }),
        },
      });
    } catch (dbErr) {
      console.error(`[ScanManager] DB update failed for ${scanId}:`, dbErr);
    }
    throw err;
  }
}

/**
 * Get the current status of a scan task.
 * Polls the scan engine mini-service, with database fallback.
 */
export async function getScanStatus(scanId: string): Promise<{
  status: string;
  results: ScanResult | null;
  error: string | null;
}> {
  // Check cache first
  const cached = scanCache.get(scanId);
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL) {
    return { status: cached.status, results: cached.results, error: cached.error };
  }

  // Poll the scan engine for live status
  try {
    const response = await fetch(`${SCAN_ENGINE_URL}/scan/${scanId}`, {
      signal: AbortSignal.timeout(3000),
    });

    if (response.ok) {
      const data = await response.json() as {
        status: string;
        results: ScanResult | null;
        error: string | null;
      };

      // If completed, update the database
      if (data.status === "Completed" && data.results) {
        try {
          await db.scan.update({
            where: { id: scanId },
            data: { status: "Completed", results: JSON.stringify(data.results) },
          });
        } catch (dbErr) {
          console.error(`[ScanManager] DB update failed for completed scan ${scanId}:`, dbErr);
        }
      } else if (data.status === "Failed") {
        try {
          await db.scan.update({
            where: { id: scanId },
            data: { status: "Failed", results: JSON.stringify({ error: data.error }) },
          });
        } catch (dbErr) {
          console.error(`[ScanManager] DB update failed for failed scan ${scanId}:`, dbErr);
        }
      }

      // Update cache
      scanCache.set(scanId, {
        status: data.status,
        results: data.results,
        error: data.error,
        fetchedAt: Date.now(),
      });

      return { status: data.status, results: data.results, error: data.error };
    }
  } catch {
    // Scan engine unreachable — fall back to database
  }

  // Database fallback
  try {
    const scan = await db.scan.findUnique({ where: { id: scanId } });
    if (scan) {
      let parsedResults: ScanResult | null = null;
      if (scan.results) {
        try {
          parsedResults = JSON.parse(scan.results);
        } catch (parseErr) {
          console.error(`[ScanManager] JSON.parse failed for scan ${scanId}:`, parseErr);
        }
      }
      return { status: scan.status, results: parsedResults, error: null };
    }
  } catch (dbErr) {
    console.error(`[ScanManager] DB lookup failed for scan ${scanId}:`, dbErr);
  }

  return { status: "Unknown", results: null, error: null };
}
