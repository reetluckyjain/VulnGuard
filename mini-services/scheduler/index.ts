/**
 * VulnGuard Scheduler Service
 *
 * Runs on port 3004. Checks every 60 seconds for schedules that are due
 * and triggers scans via the Next.js API.
 *
 * The scheduler uses skipVerification=true when triggering scans because
 * targets must be verified before a schedule can be created.
 */

import { execSync } from "child_process";

const PORT = 3004;
const NEXTJS_API_BASE = "http://localhost:3000";
const CHECK_INTERVAL_MS = 60 * 1000; // 1 minute

// ─── Simple SQLite reader ──────────────────────────────────────────────────
// We read the DB directly to avoid importing Prisma (which needs Next.js context)

interface ScheduleRow {
  id: string;
  target: string;
  scanType: string;
  port: string;
  frequency: string;
  isActive: number;
  lastRunAt: string | null;
  nextRunAt: string;
}

function readDueSchedules(): ScheduleRow[] {
  const now = new Date().toISOString();
  try {
    const output = execSync(
      `sqlite3 /home/z/my-project/db/custom.db "SELECT id, target, scanType, port, frequency, isActive, lastRunAt, nextRunAt FROM Schedule WHERE isActive = 1 AND nextRunAt <= '${now}'" -json`,
      { encoding: "utf-8", timeout: 5000 }
    );
    if (!output.trim()) return [];
    return JSON.parse(output) as ScheduleRow[];
  } catch {
    return [];
  }
}

function updateScheduleAfterRun(id: string, frequency: string): void {
  const nextRun = computeNextRun(frequency);
  const now = new Date().toISOString();
  try {
    execSync(
      `sqlite3 /home/z/my-project/db/custom.db "UPDATE Schedule SET lastRunAt = '${now}', nextRunAt = '${nextRun}', updatedAt = '${now}' WHERE id = '${id}'"`,
      { timeout: 5000 }
    );
  } catch (err) {
    console.error(`[Scheduler] Error updating schedule ${id}:`, err);
  }
}

function computeNextRun(frequency: string): string {
  const now = new Date();
  switch (frequency) {
    case "hourly": return new Date(now.getTime() + 60 * 60 * 1000).toISOString();
    case "daily": return new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString();
    case "weekly": return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString();
    case "monthly": return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
    default: return new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString();
  }
}

// ─── Trigger scan via Next.js API ──────────────────────────────────────────

async function triggerScan(schedule: ScheduleRow): Promise<boolean> {
  try {
    const body: Record<string, unknown> = {
      target: schedule.target,
      isAuthorized: true,
      scanType: schedule.scanType,
      skipVerification: true, // Schedules are only created for verified targets
    };

    if (schedule.scanType === "nikto") {
      body.port = schedule.port || "80";
    }

    const response = await fetch(`${NEXTJS_API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (response.ok) {
      const data = await response.json() as Record<string, unknown>;
      console.log(`[Scheduler] Triggered scan for ${schedule.target} (${schedule.scanType}) — scan_id: ${data.scan_id}`);
      return true;
    } else {
      const errData = await response.json().catch(() => ({})) as Record<string, unknown>;
      console.error(`[Scheduler] Scan trigger failed for ${schedule.target}:`, errData.error || response.status);
      return false;
    }
  } catch (err) {
    console.error(`[Scheduler] Error triggering scan for ${schedule.target}:`, err);
    return false;
  }
}

// ─── Main loop ─────────────────────────────────────────────────────────────

async function tick() {
  const dueSchedules = readDueSchedules();

  if (dueSchedules.length > 0) {
    console.log(`[Scheduler] Found ${dueSchedules.length} due schedule(s) at ${new Date().toISOString()}`);
  }

  for (const schedule of dueSchedules) {
    const success = await triggerScan(schedule);
    if (success) {
      updateScheduleAfterRun(schedule.id, schedule.frequency);
    }
  }
}

// Start the scheduler
console.log(`[Scheduler] VulnGuard Scheduler starting on port ${PORT}`);
console.log(`[Scheduler] Checking every ${CHECK_INTERVAL_MS / 1000}s for due schedules`);

// Initial tick
tick();

// Set up interval
setInterval(tick, CHECK_INTERVAL_MS);

// Simple HTTP health check
const server = Bun.serve({
  port: PORT,
  fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/health") {
      return Response.json({
        status: "running",
        checkInterval: CHECK_INTERVAL_MS,
        uptime: process.uptime(),
      });
    }
    if (url.pathname === "/trigger") {
      // Manual trigger endpoint for testing
      tick();
      return Response.json({ message: "Manual tick triggered" });
    }
    return Response.json({ error: "Not found" }, { status: 404 });
  },
});

console.log(`[Scheduler] Health check available at http://localhost:${PORT}/health`);
