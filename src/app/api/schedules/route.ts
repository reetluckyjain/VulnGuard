import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";

/**
 * Schedule CRUD API
 *
 * POST   /api/schedules          — Create a new scheduled scan
 * GET    /api/schedules          — List all schedules
 * PUT    /api/schedules?id=xxx   — Update a schedule (toggle active, change frequency)
 * DELETE /api/schedules?id=xxx   — Delete a schedule
 *
 * Frequency maps to nextRunAt:
 *   - hourly  → next run in 1 hour
 *   - daily   → next run in 24 hours
 *   - weekly  → next run in 7 days
 *   - monthly → next run in 30 days
 */

// ─── Helpers ────────────────────────────────────────────────────────────────

function computeNextRun(frequency: string): Date {
  const now = new Date();
  switch (frequency) {
    case "hourly": return new Date(now.getTime() + 60 * 60 * 1000);
    case "daily": return new Date(now.getTime() + 24 * 60 * 60 * 1000);
    case "weekly": return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    case "monthly": return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
    default: return new Date(now.getTime() + 24 * 60 * 60 * 1000);
  }
}

// ─── POST: Create schedule ─────────────────────────────────────────────────

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { target, scanType, port, frequency } = body as {
      target: string; scanType?: string; port?: string; frequency: string;
    };

    if (!target || typeof target !== "string") {
      return NextResponse.json({ error: "Target is required" }, { status: 400 });
    }

    const validFreqs = ["hourly", "daily", "weekly", "monthly"];
    if (!frequency || !validFreqs.includes(frequency)) {
      return NextResponse.json({ error: `Frequency must be one of: ${validFreqs.join(", ")}` }, { status: 400 });
    }

    const effectiveScanType = scanType === "nikto" ? "nikto" : "nmap";
    const nextRunAt = computeNextRun(frequency);

    const schedule = await db.schedule.create({
      data: {
        target: target.trim(),
        scanType: effectiveScanType,
        port: port || "80",
        frequency,
        nextRunAt,
      },
    });

    return NextResponse.json({
      id: schedule.id,
      target: schedule.target,
      scanType: schedule.scanType,
      port: schedule.port,
      frequency: schedule.frequency,
      isActive: schedule.isActive,
      nextRunAt: schedule.nextRunAt,
      createdAt: schedule.createdAt,
    }, { status: 201 });

  } catch (error) {
    console.error("[API] Schedule create error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// ─── GET: List schedules ───────────────────────────────────────────────────

export async function GET() {
  try {
    const schedules = await db.schedule.findMany({
      orderBy: { nextRunAt: "asc" },
      take: 100,
    });

    return NextResponse.json({
      schedules: schedules.map(s => ({
        id: s.id,
        target: s.target,
        scanType: s.scanType,
        port: s.port,
        frequency: s.frequency,
        isActive: s.isActive,
        lastRunAt: s.lastRunAt,
        nextRunAt: s.nextRunAt,
        createdAt: s.createdAt,
      })),
    });

  } catch (error) {
    console.error("[API] Schedule list error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// ─── PUT: Update schedule ──────────────────────────────────────────────────

export async function PUT(request: NextRequest) {
  try {
    const id = request.nextUrl.searchParams.get("id");
    if (!id) {
      return NextResponse.json({ error: "Schedule ID is required" }, { status: 400 });
    }

    const body = await request.json();
    const { isActive, frequency, scanType, port } = body as {
      isActive?: boolean; frequency?: string; scanType?: string; port?: string;
    };

    const existing = await db.schedule.findUnique({ where: { id } });
    if (!existing) {
      return NextResponse.json({ error: "Schedule not found" }, { status: 404 });
    }

    const updateData: Record<string, unknown> = {};

    if (typeof isActive === "boolean") {
      updateData.isActive = isActive;
      // If re-activating, recalculate nextRunAt
      if (isActive) {
        updateData.nextRunAt = computeNextRun(existing.frequency);
      }
    }

    if (frequency && ["hourly", "daily", "weekly", "monthly"].includes(frequency)) {
      updateData.frequency = frequency;
      updateData.nextRunAt = computeNextRun(frequency);
    }

    if (scanType) updateData.scanType = scanType === "nikto" ? "nikto" : "nmap";
    if (port) updateData.port = port;

    const updated = await db.schedule.update({
      where: { id },
      data: updateData,
    });

    return NextResponse.json({
      id: updated.id,
      target: updated.target,
      scanType: updated.scanType,
      port: updated.port,
      frequency: updated.frequency,
      isActive: updated.isActive,
      lastRunAt: updated.lastRunAt,
      nextRunAt: updated.nextRunAt,
    });

  } catch (error) {
    console.error("[API] Schedule update error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// ─── DELETE: Delete schedule ───────────────────────────────────────────────

export async function DELETE(request: NextRequest) {
  try {
    const id = request.nextUrl.searchParams.get("id");
    if (!id) {
      return NextResponse.json({ error: "Schedule ID is required" }, { status: 400 });
    }

    const existing = await db.schedule.findUnique({ where: { id } });
    if (!existing) {
      return NextResponse.json({ error: "Schedule not found" }, { status: 404 });
    }

    await db.schedule.delete({ where: { id } });

    return NextResponse.json({ success: true, message: "Schedule deleted" });

  } catch (error) {
    console.error("[API] Schedule delete error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
