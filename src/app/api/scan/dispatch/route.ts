import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { v4 as uuidv4 } from "uuid";

/**
 * POST /api/scan/dispatch — Dispatch a scan to GitHub Actions (Hybrid Mode)
 *
 * Instead of running scanners locally, this triggers a GitHub Actions
 * workflow via repository_dispatch. The workflow runs on Ubuntu with
 * nmap, nikto, and nuclei installed, then posts results back via
 * the /api/scan/callback endpoint.
 *
 * Required env vars:
 *   - GITHUB_TOKEN: Personal access token with repo scope
 *   - GITHUB_REPO: e.g., "username/vulnguard"
 *   - CALLBACK_URL: Public URL of the VulnGuard instance (for GitHub Actions to post results)
 *   - CALLBACK_SECRET: Shared secret for callback authentication
 */

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { target, scanType, port, isAuthorized } = body as {
      target: string; scanType: string; port: string; isAuthorized: boolean;
    };

    if (!target || typeof target !== "string") {
      return NextResponse.json({ error: "Target is required" }, { status: 400 });
    }

    if (!isAuthorized) {
      return NextResponse.json({ error: "Authorization required" }, { status: 403 });
    }

    const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
    const GITHUB_REPO = process.env.GITHUB_REPO;
    const CALLBACK_URL = process.env.CALLBACK_URL || process.env.NEXT_PUBLIC_CALLBACK_URL;
    const CALLBACK_SECRET = process.env.CALLBACK_SECRET || process.env.VULNGUARD_CALLBACK_SECRET || uuidv4();

    if (!GITHUB_TOKEN || !GITHUB_REPO) {
      return NextResponse.json({
        error: "GitHub Actions hybrid mode is not configured. Set GITHUB_TOKEN and GITHUB_REPO environment variables.",
        hint: "See README for hybrid deployment setup instructions.",
      }, { status: 501 });
    }

    const targetTrimmed = target.trim();
    const effectiveScanType = ["nmap", "nikto", "nuclei", "full"].includes(scanType) ? scanType : "nmap";
    const scanPort = port || "80";
    const scanId = uuidv4();

    // Create DB record
    await db.scan.create({
      data: {
        id: scanId,
        target: targetTrimmed,
        scanType: effectiveScanType,
        status: "Running",
      },
    });

    // Build callback URL
    const baseUrl = CALLBACK_URL || `${process.env.NEXT_PUBLIC_APP_URL || "https://your-app.vercel.app"}`;
    const fullCallbackUrl = `${baseUrl}/api/scan/callback`;

    // Dispatch GitHub Actions workflow
    const dispatchUrl = `https://api.github.com/repos/${GITHUB_REPO}/dispatches`;

    const dispatchPayload = {
      event_type: "vulnscan",
      client_payload: {
        scan_id: scanId,
        scan_type: effectiveScanType,
        target: targetTrimmed,
        port: scanPort,
        callback_url: fullCallbackUrl,
        callback_secret: CALLBACK_SECRET,
      },
    };

    console.log(`[Dispatch] Triggering GitHub Actions scan: ${scanId} (${effectiveScanType}) for ${targetTrimmed}`);

    const dispatchResponse = await fetch(dispatchUrl, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${GITHUB_TOKEN}`,
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json",
        "User-Agent": "VulnGuard-Scanner",
      },
      body: JSON.stringify(dispatchPayload),
    });

    if (!dispatchResponse.ok) {
      const errorText = await dispatchResponse.text();
      console.error(`[Dispatch] GitHub API error: ${dispatchResponse.status}`, errorText);

      // Update scan as failed
      await db.scan.update({
        where: { id: scanId },
        data: {
          status: "Failed",
          results: JSON.stringify({
            error: `Failed to dispatch GitHub Actions workflow: ${dispatchResponse.status}. Check GITHUB_TOKEN and GITHUB_REPO settings.`,
          }),
        },
      });

      return NextResponse.json({
        error: `Failed to dispatch scan to GitHub Actions (HTTP ${dispatchResponse.status}). Verify your GITHUB_TOKEN has repo scope and GITHUB_REPO is correct.`,
        scan_id: scanId,
      }, { status: 502 });
    }

    console.log(`[Dispatch] GitHub Actions workflow triggered for scan ${scanId}`);

    return NextResponse.json({
      scan_id: scanId,
      target: targetTrimmed,
      scan_type: effectiveScanType,
      status: "Running",
      mode: "hybrid",
      message: "Scan dispatched to GitHub Actions. Results will be available once the workflow completes.",
    }, { status: 201 });

  } catch (error) {
    console.error("[Dispatch] Error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
