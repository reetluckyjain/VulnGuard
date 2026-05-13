import { NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function GET() {
  try {
    const scans = await db.scan.findMany({
      orderBy: { createdAt: "desc" },
      take: 50,
    });

    return NextResponse.json({
      scans: scans.map(scan => ({
        id: scan.id,
        target: scan.target,
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
