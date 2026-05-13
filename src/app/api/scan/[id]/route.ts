import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { processScanResults } from "../route";

/**
 * GET /api/scan/[id] — Get scan status and results
 *
 * Checks for nmap XML output files and processes them into results.
 * The nmap process runs detached and writes to temp files.
 * This route reads those files and updates the DB.
 */

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

    // If already completed or failed, return from DB
    if (scan.status === "Completed") {
      let parsedResults = null;
      if (scan.results) {
        try { parsedResults = JSON.parse(scan.results); } catch {}
      }
      return NextResponse.json({
        scan_id: scan.id,
        target: scan.target,
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
        status: "Failed",
        error,
        created_at: scan.createdAt,
        updated_at: scan.updatedAt,
      });
    }

    // Scan is still Running or Pending — check for nmap output files
    const processed = await processScanResults(id);

    if (processed.status === "Completed" && processed.results) {
      return NextResponse.json({
        scan_id: scan.id,
        target: scan.target,
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
        status: "Failed",
        error: processed.error || "Scan failed",
        created_at: scan.createdAt,
        updated_at: new Date(),
      });
    }

    // Still running
    return NextResponse.json({
      scan_id: scan.id,
      target: scan.target,
      status: "Running",
      results: null,
      created_at: scan.createdAt,
      updated_at: scan.updatedAt,
    });

  } catch (error) {
    console.error("[API] Error fetching scan:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
