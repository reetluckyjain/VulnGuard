import { NmapScanner } from "./scanners/nmap_scanner.ts";
import type { ScanResult } from "./scanners/base.ts";

const PORT = 3030;

// In-memory task store for background scan tracking
interface ScanTask {
  id: string;
  target: string;
  status: "Pending" | "Running" | "Completed" | "Failed";
  results: ScanResult | null;
  error: string | null;
  startedAt: string;
  completedAt: string | null;
}

const scanTasks = new Map<string, ScanTask>();

const scanner = new NmapScanner();

const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);

    // CORS headers
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // POST /scan - Start a new scan
    if (url.pathname === "/scan" && req.method === "POST") {
      try {
        const body = await req.json() as { target: string; scan_id: string };
        const { target, scan_id } = body;

        if (!target || !scan_id) {
          return Response.json(
            { error: "Missing target or scan_id" },
            { status: 400, headers: corsHeaders }
          );
        }

        // Create task entry
        const task: ScanTask = {
          id: scan_id,
          target,
          status: "Running",
          results: null,
          error: null,
          startedAt: new Date().toISOString(),
          completedAt: null,
        };
        scanTasks.set(scan_id, task);

        // Run scan asynchronously (background task)
        scanner.runScan(target).then((results) => {
          task.status = "Completed";
          task.results = results;
          task.completedAt = new Date().toISOString();
          console.log(`[ScanEngine] Scan ${scan_id} completed for ${target}`);
        }).catch((err) => {
          task.status = "Failed";
          task.error = err.message || "Unknown error";
          task.completedAt = new Date().toISOString();
          console.error(`[ScanEngine] Scan ${scan_id} failed:`, err);
        });

        return Response.json(
          { scan_id, status: "Running", message: "Scan started" },
          { headers: corsHeaders }
        );
      } catch (err) {
        return Response.json(
          { error: "Invalid request body" },
          { status: 400, headers: corsHeaders }
        );
      }
    }

    // GET /scan/:id - Get scan status
    const scanMatch = url.pathname.match(/^\/scan\/([a-f0-9-]+)$/);
    if (scanMatch && req.method === "GET") {
      const scanId = scanMatch[1];
      const task = scanTasks.get(scanId);

      if (!task) {
        return Response.json(
          { error: "Scan not found" },
          { status: 404, headers: corsHeaders }
        );
      }

      return Response.json(
        {
          scan_id: task.id,
          target: task.target,
          status: task.status,
          results: task.results,
          error: task.error,
          started_at: task.startedAt,
          completed_at: task.completedAt,
        },
        { headers: corsHeaders }
      );
    }

    // GET /health - Health check
    if (url.pathname === "/health" && req.method === "GET") {
      return Response.json(
        { status: "ok", service: "scan-engine", scanner: scanner.name },
        { headers: corsHeaders }
      );
    }

    return Response.json(
      { error: "Not found" },
      { status: 404, headers: corsHeaders }
    );
  },
});

console.log(`[ScanEngine] 🛡️ Vulnerability Scanner Engine running on port ${PORT}`);
console.log(`[ScanEngine] Scanner: ${scanner.name}`);
console.log(`[ScanEngine] Endpoints: POST /scan, GET /scan/:id, GET /health`);
