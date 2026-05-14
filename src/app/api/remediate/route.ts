import { NextRequest, NextResponse } from "next/server";
import ZAI from "z-ai-web-dev-sdk";

/**
 * POST /api/remediate — AI Auto-Remediation Engine
 *
 * Takes raw scan findings (nmap or nikto) and generates:
 *   - Plain-English explanations of each vulnerability/finding
 *   - Step-by-step fix commands for remediation
 *
 * Uses z-ai-web-dev-sdk LLM (backend only — never client-side).
 * NO MOCK DATA — Real AI-generated remediation advice.
 */

// ─── Types ──────────────────────────────────────────────────────────────────

interface PortInfo { port_id: number; protocol: string; state: string; service: string; version: string }
interface Vulnerability { port_id: number; cve_id: string; description: string }

interface NmapScanResult {
  target: string; ports: PortInfo[]; vulnerabilities: Vulnerability[]
}

interface NiktoFinding {
  id: string; host: string; ip: string; port: number
  method: string; path: string; description: string; references: string[]
}

interface NiktoScanResult {
  target: string; scanType: "nikto"; server: string
  findings: NiktoFinding[]; vulnerabilities: Vulnerability[]
  summary: { total: number; info: number; low: number; medium: number; high: number }
}

type ScanResult = NmapScanResult | NiktoScanResult

function isNiktoResult(result: ScanResult): result is NiktoScanResult {
  return "scanType" in result && result.scanType === "nikto"
}

// ─── System Prompt ──────────────────────────────────────────────────────────

const REMEDIATION_SYSTEM_PROMPT = `You are an elite cybersecurity remediation expert. Your job is to analyze vulnerability scan findings and produce actionable, plain-English remediation guidance.

RULES:
1. Explain EVERY vulnerability/finding in plain English that a junior sysadmin can understand.
2. For each finding, provide step-by-step fix commands that can be copy-pasted into a terminal.
3. Prioritize by severity: Critical → High → Medium → Low → Info.
4. If a CVE is mentioned, briefly explain what the CVE is about and its CVSS impact if known.
5. For service/version findings, recommend the specific upgrade path or configuration change.
6. For web findings (Nikto), provide .htaccess, nginx config, or application-level fixes.
7. Always include the EXACT commands — no placeholders like "YOUR_IP" without showing the actual value from the findings.
8. Format your response as valid JSON with this exact structure:

{
  "summary": "2-3 sentence executive summary of the security posture",
  "risk_level": "Critical" | "High" | "Medium" | "Low" | "Secure",
  "remediations": [
    {
      "finding": "Short title of the finding",
      "severity": "Critical" | "High" | "Medium" | "Low" | "Info",
      "explanation": "Plain English explanation (2-4 sentences)",
      "fix_commands": ["command1", "command2"],
      "references": ["URL1", "URL2"]
    }
  ],
  "hardening_recommendations": ["Rec 1", "Rec 2"]
}

RESPOND WITH VALID JSON ONLY. No markdown fences, no extra text.`

// ─── Build LLM Prompt from Findings ─────────────────────────────────────────

function buildRemediationPrompt(result: ScanResult): string {
  if (isNiktoResult(result)) {
    const findingsText = result.findings.map((f, i) =>
      `[${i + 1}] ${f.description} (Port: ${f.port}, Method: ${f.method}, Path: ${f.path}${f.references.length ? ", Refs: " + f.references.join(", ") : ""})`
    ).join("\n")

    const vulnsText = result.vulnerabilities.map(v =>
      `- ${v.cve_id} on port ${v.port_id}: ${v.description}`
    ).join("\n")

    return `Analyze these Nikto web vulnerability scan results for target "${result.target}" (Server: ${result.server}):

FINDINGS (${result.findings.length} total — ${result.summary.high} High, ${result.summary.medium} Medium, ${result.summary.low} Low, ${result.summary.info} Info):
${findingsText || "No findings"}

CVEs (${result.vulnerabilities.length}):
${vulnsText || "No CVEs detected"}

Generate remediation guidance with fix commands.`
  } else {
    const portsText = result.ports.map(p =>
      `- Port ${p.port_id}/${p.protocol}: ${p.state} — ${p.service} ${p.version}`
    ).join("\n")

    const vulnsText = result.vulnerabilities.map(v =>
      `- ${v.cve_id} on port ${v.port_id}: ${v.description}`
    ).join("\n")

    return `Analyze these nmap network scan results for target "${result.target}":

OPEN/SCANNED PORTS:
${portsText || "No ports found"}

VULNERABILITIES (${result.vulnerabilities.length}):
${vulnsText || "No vulnerabilities detected by nmap vuln scripts"}

Generate remediation guidance. For open services, recommend hardening even if no CVEs were found. Provide specific commands for service configuration, firewall rules, and updates.`
  }
}

// ─── API Route Handler ─────────────────────────────────────────────────────

let zaiInstance: Awaited<ReturnType<typeof ZAI.create>> | null = null

async function getZAI() {
  if (!zaiInstance) {
    zaiInstance = await ZAI.create()
  }
  return zaiInstance
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { scanResult: rawResult } = body as { scanResult: ScanResult }

    if (!rawResult || typeof rawResult !== "object") {
      return NextResponse.json(
        { error: "scanResult is required and must be an object" },
        { status: 400 }
      )
    }

    // Quick check: if there are zero findings and zero vulns and zero ports,
    // no need to call the LLM
    const hasNikto = isNiktoResult(rawResult)
    const totalFindings = hasNikto
      ? (rawResult as NiktoScanResult).findings.length + (rawResult as NiktoScanResult).vulnerabilities.length
      : (rawResult as NmapScanResult).ports.length + (rawResult as NmapScanResult).vulnerabilities.length

    if (totalFindings === 0) {
      return NextResponse.json({
        summary: "No vulnerabilities or findings were detected in this scan. The target appears to have a clean security posture.",
        risk_level: "Secure",
        remediations: [],
        hardening_recommendations: [
          "Continue regular vulnerability scanning on a schedule",
          "Keep all services and software up to date",
          "Implement network segmentation and least-privilege access controls",
        ],
      })
    }

    // Build prompt and call LLM
    const userPrompt = buildRemediationPrompt(rawResult)
    const zai = await getZAI()

    const completion = await zai.chat.completions.create({
      messages: [
        { role: "assistant", content: REMEDIATION_SYSTEM_PROMPT },
        { role: "user", content: userPrompt },
      ],
      thinking: { type: "disabled" },
    })

    const aiResponse = completion.choices[0]?.message?.content

    if (!aiResponse || aiResponse.trim().length === 0) {
      return NextResponse.json(
        { error: "AI remediation engine returned an empty response. Please try again." },
        { status: 502 }
      )
    }

    // Parse the JSON response from LLM
    let parsed: Record<string, unknown>
    try {
      // Strip markdown code fences if present
      const cleaned = aiResponse.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "")
      parsed = JSON.parse(cleaned)
    } catch {
      // If parsing fails, wrap the raw text
      return NextResponse.json({
        summary: aiResponse.slice(0, 300),
        risk_level: "Medium",
        remediations: [],
        hardening_recommendations: [],
        raw_response: aiResponse,
      })
    }

    return NextResponse.json(parsed)

  } catch (error) {
    console.error("[API] Remediation error:", error)
    const message = error instanceof Error ? error.message : "Internal server error"
    return NextResponse.json(
      { error: `Remediation engine failed: ${message}` },
      { status: 500 }
    )
  }
}
