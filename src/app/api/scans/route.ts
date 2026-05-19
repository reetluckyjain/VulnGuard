import { NextResponse } from "next/server";
import { db, isDatabaseAvailable } from "@/lib/db";

/**
 * GET /api/scans — List scan history
 *
 * On Vercel/serverless: Returns empty list if database is not configured.
 * On self-hosted VPS: Returns scan history from DB.
 */

export async function GET() {
  try {
    const dbAvailable = await isDatabaseAvailable();
    if (!dbAvailable) {
      return NextResponse.json({
        scans: [],
        notice: "Database not configured. Set DATABASE_URL environment variable to enable scan history. See README for setup instructions.",
        deployment_mode: "serverless",
      });
    }

    const scans = await db.scan.findMany({
      orderBy: { createdAt: "desc" },
      take: 50,
    });

    return NextResponse.json({
      scans: scans.map(scan => ({
        id: scan.id,
        target: scan.target,
        scan_type: scan.scanType || "nmap",
        status: scan.status,
        created_at: scan.createdAt,
        updated_at: scan.updatedAt,
        has_results: !!scan.results,
      })),
    });
  } catch (error) {
    console.error("[API] Error listing scans:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
