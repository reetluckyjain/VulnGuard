import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { execSync } from "child_process";

/**
 * DNS TXT Target Ownership Verification API
 *
 * POST /api/verify — Generate a verification code for a target domain
 *   - Creates a unique code like "vg-verify-a1b2c3d4"
 *   - User must add a DNS TXT record: _vulnguard.<target> TXT "vg-verify-a1b2c3d4"
 *   - Code expires after 48 hours
 *
 * PUT /api/verify — Verify ownership by checking DNS TXT records
 *   - Looks up the verification code in DNS
 *   - If found, marks target as "verified"
 *
 * GET /api/verify?target=<domain> — Check verification status for a target
 */

// ─── Helpers ────────────────────────────────────────────────────────────────

function generateCode(): string {
  // Generate random hex without importing crypto module (crashes Next.js)
  const chars = "0123456789abcdef";
  let result = "vg-verify-";
  for (let i = 0; i < 8; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

function isIP(target: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(target);
}

function lookupDnsTxt(domain: string): string[] {
  try {
    const output = execSync(`dig -t TXT "${domain}" +short +timeout=5 +tries=2 2>/dev/null`, {
      encoding: "utf-8",
      timeout: 10000,
    });
    return output
      .split("\n")
      .map(l => l.trim().replace(/^"|"$/g, ""))
      .filter(Boolean);
  } catch {
    return [];
  }
}

// ─── POST: Generate verification code ──────────────────────────────────────

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { target } = body as { target: string };

    if (!target || typeof target !== "string") {
      return NextResponse.json({ error: "Target domain is required" }, { status: 400 });
    }

    const targetTrimmed = target.trim().toLowerCase();

    // Only allow hostname verification (not IP addresses)
    if (isIP(targetTrimmed)) {
      return NextResponse.json({
        error: "DNS verification is only supported for domain names, not IP addresses. IP targets use the checkbox authorization instead.",
      }, { status: 400 });
    }

    // Check if already verified
    const existing = await db.targetVerification.findUnique({
      where: { target: targetTrimmed },
    });

    if (existing && existing.status === "verified") {
      return NextResponse.json({
        target: targetTrimmed,
        status: "verified",
        verifiedAt: existing.verifiedAt,
        message: "Target is already verified",
      });
    }

    // Generate new code
    const code = generateCode();
    const expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000); // 48 hours

    // Upsert: create new or replace pending
    if (existing) {
      await db.targetVerification.update({
        where: { target: targetTrimmed },
        data: { verificationCode: code, status: "pending", expiresAt, verifiedAt: null },
      });
    } else {
      await db.targetVerification.create({
        data: { target: targetTrimmed, verificationCode: code, status: "pending", expiresAt },
      });
    }

    const txtRecordName = `_vulnguard.${targetTrimmed}`;

    return NextResponse.json({
      target: targetTrimmed,
      verificationCode: code,
      txtRecordName,
      txtRecordValue: code,
      instructions: `Add a DNS TXT record:\n  Name: ${txtRecordName}\n  Type: TXT\n  Value: "${code}"\n\nThen click "Verify DNS" to confirm ownership.`,
      expiresAt,
    });

  } catch (error) {
    console.error("[API] Verification generate error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// ─── PUT: Verify DNS TXT record ────────────────────────────────────────────

export async function PUT(request: NextRequest) {
  try {
    const body = await request.json();
    const { target } = body as { target: string };

    if (!target || typeof target !== "string") {
      return NextResponse.json({ error: "Target domain is required" }, { status: 400 });
    }

    const targetTrimmed = target.trim().toLowerCase();

    const verification = await db.targetVerification.findUnique({
      where: { target: targetTrimmed },
    });

    if (!verification) {
      return NextResponse.json({
        status: "not_found",
        error: "No verification pending for this target. Generate a code first.",
      }, { status: 404 });
    }

    if (verification.status === "verified") {
      return NextResponse.json({
        target: targetTrimmed,
        status: "verified",
        verifiedAt: verification.verifiedAt,
      });
    }

    // Check expiration
    if (verification.expiresAt < new Date()) {
      await db.targetVerification.update({
        where: { target: targetTrimmed },
        data: { status: "expired" },
      });
      return NextResponse.json({
        status: "expired",
        error: "Verification code has expired. Generate a new one.",
      }, { status: 410 });
    }

    // Look up DNS TXT record
    const txtRecordName = `_vulnguard.${targetTrimmed}`;
    const txtRecords = lookupDnsTxt(txtRecordName);

    // Also check the bare domain for TXT records (some users may put it there)
    const bareRecords = lookupDnsTxt(targetTrimmed);
    const allRecords = [...txtRecords, ...bareRecords];

    const found = allRecords.some(
      record => record.trim() === verification.verificationCode
    );

    if (found) {
      await db.targetVerification.update({
        where: { target: targetTrimmed },
        data: { status: "verified", verifiedAt: new Date() },
      });

      return NextResponse.json({
        target: targetTrimmed,
        status: "verified",
        verifiedAt: new Date(),
        message: "Target ownership verified via DNS TXT record!",
      });
    }

    return NextResponse.json({
      target: targetTrimmed,
      status: "pending",
      verificationCode: verification.verificationCode,
      txtRecordName,
      dnsRecordsFound: allRecords,
      message: `DNS TXT record not found. Make sure "${verification.verificationCode}" is set at ${txtRecordName}. DNS propagation may take a few minutes.`,
    });

  } catch (error) {
    console.error("[API] Verification check error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// ─── GET: Check verification status ────────────────────────────────────────

export async function GET(request: NextRequest) {
  try {
    const target = request.nextUrl.searchParams.get("target");

    if (!target) {
      return NextResponse.json({ error: "Target parameter is required" }, { status: 400 });
    }

    const targetTrimmed = target.trim().toLowerCase();

    // IP addresses are always "authorized" (use checkbox)
    if (isIP(targetTrimmed)) {
      return NextResponse.json({
        target: targetTrimmed,
        status: "ip_address",
        message: "IP addresses use checkbox authorization, not DNS verification",
      });
    }

    const verification = await db.targetVerification.findUnique({
      where: { target: targetTrimmed },
    });

    if (!verification) {
      return NextResponse.json({
        target: targetTrimmed,
        status: "unverified",
        message: "No verification found for this target",
      });
    }

    // Check if expired
    if (verification.status === "pending" && verification.expiresAt < new Date()) {
      await db.targetVerification.update({
        where: { target: targetTrimmed },
        data: { status: "expired" },
      });
      return NextResponse.json({
        target: targetTrimmed,
        status: "expired",
        verificationCode: verification.verificationCode,
        message: "Verification code has expired",
      });
    }

    return NextResponse.json({
      target: targetTrimmed,
      status: verification.status,
      verificationCode: verification.status === "pending" ? verification.verificationCode : undefined,
      verifiedAt: verification.verifiedAt,
      expiresAt: verification.expiresAt,
    });

  } catch (error) {
    console.error("[API] Verification status error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
