import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { startScan } from "@/lib/scan-manager";
import { v4 as uuidv4 } from "uuid";

// Authorization verification - ensure user has permission to scan the target
function verifyAuthorization(target: string): { authorized: boolean; reason?: string } {
  // Block reserved/private ranges that should never be scanned without explicit permission
  const blockedPatterns = [
    /^127\./,           // Loopback
    /^0\./,             // Current network
    /^169\.254\./,      // Link-local
  ];

  for (const pattern of blockedPatterns) {
    if (pattern.test(target)) {
      return { authorized: false, reason: "Scanning loopback/link-local addresses is restricted" };
    }
  }

  return { authorized: true };
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { target, isAuthorized } = body;

    if (!target || typeof target !== "string") {
      return NextResponse.json(
        { error: "Target IP/hostname is required" },
        { status: 400 }
      );
    }

    // Validate target format (basic check)
    const targetTrimmed = target.trim();
    if (targetTrimmed.length < 3 || targetTrimmed.length > 253) {
      return NextResponse.json(
        { error: "Invalid target format" },
        { status: 400 }
      );
    }

    // Ethical gate: must explicitly confirm authorization
    if (!isAuthorized) {
      return NextResponse.json(
        { error: "You must confirm authorization before scanning" },
        { status: 403 }
      );
    }

    // Verify authorization for this target
    const auth = verifyAuthorization(targetTrimmed);
    if (!auth.authorized) {
      return NextResponse.json(
        { error: auth.reason || "Target not authorized for scanning" },
        { status: 403 }
      );
    }

    const scanId = uuidv4();

    // Create scan record in database
    const scan = await db.scan.create({
      data: {
        id: scanId,
        target: targetTrimmed,
        status: "Pending",
      },
    });

    // Start the scan asynchronously (fire-and-forget)
    // The scan manager handles the background execution and DB updates
    startScan(scanId, targetTrimmed).catch((err) => {
      console.error("[API] Scan start error:", err);
    });

    return NextResponse.json({
      scan_id: scan.id,
      target: scan.target,
      status: "Running",
      message: "Scan initiated successfully",
    }, { status: 201 });

  } catch (error) {
    console.error("[API] Error creating scan:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
