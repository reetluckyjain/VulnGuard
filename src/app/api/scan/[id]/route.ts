import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { getScanStatus } from "@/lib/scan-manager";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;

    // First check the in-memory scan manager for active scans
    const liveStatus = getScanStatus(id);

    if (liveStatus.status !== "Unknown") {
      // Active scan - return live data
      return NextResponse.json({
        scan_id: id,
        status: liveStatus.status,
        results: liveStatus.results,
        error: liveStatus.error,
      });
    }

    // Fall back to database for completed/historical scans
    const scan = await db.scan.findUnique({
      where: { id },
    });

    if (!scan) {
      return NextResponse.json(
        { error: "Scan not found" },
        { status: 404 }
      );
    }

    let parsedResults = null;
    if (scan.results) {
      try {
        parsedResults = JSON.parse(scan.results);
      } catch {
        parsedResults = null;
      }
    }

    return NextResponse.json({
      scan_id: scan.id,
      target: scan.target,
      status: scan.status,
      results: parsedResults,
      created_at: scan.createdAt,
      updated_at: scan.updatedAt,
    });

  } catch (error) {
    console.error("[API] Error fetching scan:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
