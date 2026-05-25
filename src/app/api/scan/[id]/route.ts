import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { processScanResults } from "../route";

/**
 * GET /api/scan/[id] — Get scan status and results
 *
 * Checks for scanner output files and processes them into results.
 * Also auto-fails scans that have been running for more than 3 minutes
 * to prevent infinite polling.
 */

const MAX_SCAN_DURATION_MS = 3 * 60 * 1000; // 3 minutes

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;

    // First check the DB for existing completed results
    const scan = await db.scan.findUnique({ where: { id } });

    if (!scan) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 });
    }

    const scanType = scan.scanType || "nmap";

    // If already completed or failed, return from DB
    if (scan.status === "Completed") {
      let parsedResults = null;
      if (scan.results) {
        try { parsedResults = JSON.parse(scan.results); } catch {}
      }
      return NextResponse.json({
        scan_id: scan.id,
        target: scan.target,
        scan_type: scanType,
        status: "Completed",
        results: parsedResults,
        created_at: scan.createdAt,
        updated_at: scan.updatedAt,
      });
    }

    if (scan.status === "Failed") {
      let error = "Scan failed";
      if (scan.results) {
        try {
          const parsed = JSON.parse(scan.results);
          if (parsed.error) error = parsed.error;
        } catch {}
      }
      return NextResponse.json({
        scan_id: scan.id,
        target: scan.target,
        scan_type: scanType,
        status: "Failed",
        error,
        created_at: scan.createdAt,
        updated_at: scan.updatedAt,
      });
    }

    // Check if scan has been running too long (auto-timeout)
    const runningDuration = Date.now() - new Date(scan.createdAt).getTime();
    if (runningDuration > MAX_SCAN_DURATION_MS) {
      // Auto-fail the scan
      const timeoutMsg = `Scan timed out after ${Math.round(MAX_SCAN_DURATION_MS / 1000)}s. The target may be unreachable or the scan engine is too slow.`;
      try {
        await db.scan.update({
          where: { id },
          data: { status: "Failed", results: JSON.stringify({ error: timeoutMsg }) },
        });
      } catch {}

      return NextResponse.json({
        scan_id: scan.id,
        target: scan.target,
        scan_type: scanType,
        status: "Failed",
        error: timeoutMsg,
        created_at: scan.createdAt,
        updated_at: new Date(),
      });
    }

    // Scan is still Running or Pending — check for output files (backward compat)
    const processed = await processScanResults(id, scanType);

    if (processed.status === "Completed" && processed.results) {
      return NextResponse.json({
        scan_id: scan.id,
        target: scan.target,
        scan_type: scanType,
        status: "Completed",
        results: processed.results,
        created_at: scan.createdAt,
        updated_at: new Date(),
      });
    }

    if (processed.status === "Failed") {
      return NextResponse.json({
        scan_id: scan.id,
        target: scan.target,
        scan_type: scanType,
        status: "Failed",
        error: processed.error || "Scan failed",
        created_at: scan.createdAt,
        updated_at: new Date(),
      });
    }

    // Still running — include elapsed time in response
    const elapsedSec = Math.round(runningDuration / 1000);
    return NextResponse.json({
      scan_id: scan.id,
      target: scan.target,
      scan_type: scanType,
      status: "Running",
      results: null,
      elapsed_seconds: elapsedSec,
      created_at: scan.createdAt,
      updated_at: scan.updatedAt,
    });

  } catch (error) {
    console.error("[API] Error fetching scan:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
