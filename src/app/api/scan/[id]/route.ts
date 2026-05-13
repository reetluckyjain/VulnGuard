import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { getScanStatus } from "@/lib/scan-manager";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;

    // Check live status from scan engine + database
    const liveStatus = await getScanStatus(id);

    if (liveStatus.status !== "Unknown") {
      return NextResponse.json({
        scan_id: id,
        status: liveStatus.status,
        results: liveStatus.results,
        error: liveStatus.error,
      });
    }

    // Final fallback: direct database query
    const scan = await db.scan.findUnique({ where: { id } });

    if (!scan) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 });
    }

    let parsedResults = null;
    if (scan.results) {
      try {
        parsedResults = JSON.parse(scan.results);
      } catch (parseError) {
        console.error(
          `[API] JSON.parse FAILED for scan ${id}:`,
          parseError,
          `\nRaw (first 200): ${scan.results.slice(0, 200)}`
        );
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
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
