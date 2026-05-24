import { NextRequest, NextResponse } from "next/server";
import ZAI from "z-ai-web-dev-sdk";

/**
 * POST /api/remediate — AI Auto-Remediation Engine
 *
 * Takes raw scan findings (nmap, nikto, nuclei, or full) and generates:
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

interface NucleiFinding {
  templateId: string; name: string; severity: string; type: string
  matchedAt: string; curlCommand: string | null; extractedResults: string[]
  description: string; tags: string[]; reference: string[]
  host: string; timestamp: string
}

interface NucleiScanResult {
  target: string; scanType: "nuclei"
  findings: NucleiFinding[]; vulnerabilities: Vulnerability[]
  summary: {
    total: number; critical: number; high: number; medium: number
    low: number; info: number; withCurlCommand: number; withExtractedResults: number
  }
}

interface VulnerabilityHint {
  source: "nmap" | "nikto" | "nuclei";
  severity: string;
  title: string;
  description: string;
  port?: number;
  reference?: string[];
}

interface FullScanResult {
  target: string;
  scanType: "full";
  nmap: NmapScanResult | null;
  nikto: NiktoScanResult | null;
  nuclei: NucleiScanResult | null;
  securityScore: {
    score: number;
    grade: string;
    label: string;
    breakdown: Record<string, { count: number; deduction: number; details: string }>;
  };
  openPorts: PortInfo[];
  vulnerabilityHints: VulnerabilityHint[];
  summary: {
    totalOpenPorts: number;
    totalVulnerabilities: number;
    totalCves: number;
    totalWebFindings: number;
    enginesCompleted: number;
  };
}

type ScanResult = NmapScanResult | NiktoScanResult | NucleiScanResult | FullScanResult

function isNiktoResult(result: ScanResult): result is NiktoScanResult {
  return "scanType" in result && result.scanType === "nikto"
}

function isNucleiResult(result: ScanResult): result is NucleiScanResult {
  return "scanType" in result && result.scanType === "nuclei"
}

function isFullResult(result: ScanResult): result is FullScanResult {
  return "scanType" in result && result.scanType === "full"
}

// ─── System Prompt ──────────────────────────────────────────────────────────

const REMEDIATION_SYSTEM_PROMPT = `You are an elite cybersecurity remediation expert. Your job is to analyze vulnerability scan findings and produce actionable, plain-English remediation guidance.

RULES:
1. Explain EVERY vulnerability/finding in plain English that a junior sysadmin can understand.
2. For each finding, provide step-by-step fix commands that can be copy-pasted into a terminal.
3. Prioritize by severity: Critical → High → Medium → Low → Info.
4. If a CVE is mentioned, briefly explain what the CVE is about and its CVSS impact if known.
5. For service/version findings, recommend the specific upgrade path or configuration change.
6. For web findings (Nikto/Nuclei), provide .htaccess, nginx config, or application-level fixes.
7. For Nuclei findings with curl-command reproduction, analyze the exact request and suggest WAF rules or code fixes.
8. For exposed secrets/API keys found by Nuclei, recommend immediate rotation and revocation steps.
9. Always include the EXACT commands — no placeholders like "YOUR_IP" without showing the actual value from the findings.
10. Format your response as valid JSON with this exact structure:

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
  if (isFullResult(result)) {
    return buildFullScanPrompt(result)
  } else if (isNucleiResult(result)) {
    return buildNucleiPrompt(result)
  } else if (isNiktoResult(result)) {
    return buildNiktoPrompt(result)
  } else {
    return buildNmapPrompt(result)
  }
}

function buildNmapPrompt(result: NmapScanResult): string {
  const ports = result.ports ?? []
  const vulns = result.vulnerabilities ?? []

  const portsText = ports.map(p =>
    `- Port ${p.port_id}/${p.protocol}: ${p.state} — ${p.service} ${p.version}`
  ).join("\n")

  const vulnsText = vulns.map(v =>
    `- ${v.cve_id} on port ${v.port_id}: ${v.description}`
  ).join("\n")

  return `Analyze these nmap network scan results for target "${result.target}":

OPEN/SCANNED PORTS:
${portsText || "No ports found"}

VULNERABILITIES (${vulns.length}):
${vulnsText || "No vulnerabilities detected by nmap vuln scripts"}

Generate remediation guidance. For open services, recommend hardening even if no CVEs were found. Provide specific commands for service configuration, firewall rules, and updates.`
}

function buildNiktoPrompt(result: NiktoScanResult): string {
  const findings = result.findings ?? []
  const vulns = result.vulnerabilities ?? []

  const findingsText = findings.map((f, i) =>
    `[${i + 1}] ${f.description} (Port: ${f.port}, Method: ${f.method}, Path: ${f.path}${f.references?.length ? ", Refs: " + f.references.join(", ") : ""})`
  ).join("\n")

  const vulnsText = vulns.map(v =>
    `- ${v.cve_id} on port ${v.port_id}: ${v.description}`
  ).join("\n")

  return `Analyze these Nikto web vulnerability scan results for target "${result.target}" (Server: ${result.server}):

FINDINGS (${findings.length} total — ${result.summary?.high ?? 0} High, ${result.summary?.medium ?? 0} Medium, ${result.summary?.low ?? 0} Low, ${result.summary?.info ?? 0} Info):
${findingsText || "No findings"}

CVEs (${vulns.length}):
${vulnsText || "No CVEs detected"}

Generate remediation guidance with fix commands.`
}

function buildNucleiPrompt(result: NucleiScanResult): string {
  const findings = result.findings ?? []
  const vulns = result.vulnerabilities ?? []

  const findingsText = findings.map((f, i) => {
    let line = `[${i + 1}] [${(f.severity ?? "info").toUpperCase()}] ${f.name ?? "Unknown"}`;
    if (f.matchedAt) line += `\n    Matched at: ${f.matchedAt}`;
    if (f.curlCommand) line += `\n    Reproduce: ${f.curlCommand}`;
    if (f.extractedResults?.length > 0) line += `\n    Extracted: ${f.extractedResults.join(", ")}`;
    if (f.tags?.length > 0) line += `\n    Tags: ${f.tags.join(", ")}`;
    if (f.reference?.length > 0) line += `\n    Refs: ${f.reference.join(", ")}`;
    line += `\n    Template: ${f.templateId}`;
    return line;
  }).join("\n\n")

  const vulnsText = vulns.map(v =>
    `- ${v.cve_id}: ${v.description}`
  ).join("\n")

  return `Analyze these Nuclei vulnerability scan results for target "${result.target}":

FINDINGS (${findings.length} total — ${result.summary?.critical ?? 0} Critical, ${result.summary?.high ?? 0} High, ${result.summary?.medium ?? 0} Medium, ${result.summary?.low ?? 0} Low, ${result.summary?.info ?? 0} Info):
${findingsText || "No findings"}

CVEs (${vulns.length}):
${vulnsText || "No CVEs detected"}

${(result.summary?.withCurlCommand ?? 0) > 0 ? `${result.summary.withCurlCommand} findings have curl reproduction commands.` : ""}
${(result.summary?.withExtractedResults ?? 0) > 0 ? `${result.summary.withExtractedResults} findings have extracted data (secrets/keys/versions).` : ""}

Generate remediation guidance. For findings with curl commands, analyze the exact HTTP request and suggest code-level or WAF-level fixes. For exposed secrets, recommend immediate rotation.`
}

function buildFullScanPrompt(result: FullScanResult): string {
  const sections: string[] = []
  sections.push(`Analyze this COMPREHENSIVE security scan of target "${result.target}" that ran all 3 scan engines (nmap, nikto, nuclei) simultaneously:`)

  // Security Score
  sections.push(`\nSECURITY SCORE: ${result.securityScore?.score ?? 0}/100 (Grade: ${result.securityScore?.grade ?? "?"}, ${result.securityScore?.label ?? "Unknown"})`)

  // Summary
  const summary = result.summary
  if (summary) {
    sections.push(`\nOVERALL SUMMARY: ${summary.totalOpenPorts ?? 0} open ports, ${summary.totalVulnerabilities ?? 0} vulnerabilities, ${summary.totalCves ?? 0} CVEs, ${summary.totalWebFindings ?? 0} web findings. ${summary.enginesCompleted ?? 0}/3 engines completed.`)
  }

  // Nmap section
  if (result.nmap) {
    const nmapPorts = result.nmap.ports ?? []
    const nmapVulns = result.nmap.vulnerabilities ?? []
    if (nmapPorts.length > 0 || nmapVulns.length > 0) {
      const portsText = nmapPorts.map(p =>
        `- Port ${p.port_id}/${p.protocol}: ${p.state} — ${p.service} ${p.version}`
      ).join("\n")
      const vulnsText = nmapVulns.map(v =>
        `- ${v.cve_id} on port ${v.port_id}: ${v.description}`
      ).join("\n")
      sections.push(`\n=== NMAP RESULTS ===
OPEN/SCANNED PORTS:
${portsText || "None"}
VULNERABILITIES (${nmapVulns.length}):
${vulnsText || "None"}`)
    }
  }

  // Open ports (from full scan summary)
  if (result.openPorts?.length > 0 && !result.nmap) {
    const portsText = result.openPorts.map(p =>
      `- Port ${p.port_id}/${p.protocol}: ${p.state} — ${p.service} ${p.version}`
    ).join("\n")
    sections.push(`\n=== OPEN PORTS ===\n${portsText}`)
  }

  // Nikto section
  if (result.nikto) {
    const findings = result.nikto.findings ?? []
    const vulns = result.nikto.vulnerabilities ?? []
    if (findings.length > 0 || vulns.length > 0) {
      const findingsText = findings.map((f, i) =>
        `[${i + 1}] ${f.description} (Port: ${f.port}, Method: ${f.method}, Path: ${f.path})`
      ).join("\n")
      const vulnsText = vulns.map(v =>
        `- ${v.cve_id} on port ${v.port_id}: ${v.description}`
      ).join("\n")
      sections.push(`\n=== NIKTO RESULTS (Server: ${result.nikto.server ?? "unknown"}) ===
FINDINGS (${findings.length}):
${findingsText || "None"}
CVEs (${vulns.length}):
${vulnsText || "None"}`)
    }
  }

  // Nuclei section
  if (result.nuclei) {
    const findings = result.nuclei.findings ?? []
    const vulns = result.nuclei.vulnerabilities ?? []
    if (findings.length > 0 || vulns.length > 0) {
      const findingsText = findings.map((f, i) => {
        let line = `[${i + 1}] [${(f.severity ?? "info").toUpperCase()}] ${f.name ?? "Unknown"}`;
        if (f.matchedAt) line += ` — Matched: ${f.matchedAt}`;
        if (f.curlCommand) line += ` — Reproduce: ${f.curlCommand}`;
        if (f.extractedResults?.length > 0) line += ` — Extracted: ${f.extractedResults.join(", ")}`;
        line += ` [${f.templateId}]`;
        return line;
      }).join("\n")
      const vulnsText = vulns.map(v =>
        `- ${v.cve_id}: ${v.description}`
      ).join("\n")
      sections.push(`\n=== NUCLEI RESULTS ===
FINDINGS (${findings.length} — ${(result.nuclei.summary?.critical ?? 0)} Critical, ${(result.nuclei.summary?.high ?? 0)} High, ${(result.nuclei.summary?.medium ?? 0)} Medium, ${(result.nuclei.summary?.low ?? 0)} Low, ${(result.nuclei.summary?.info ?? 0)} Info):
${findingsText || "None"}
CVEs (${vulns.length}):
${vulnsText || "None"}`)
    }
  }

  // Vulnerability hints
  if (result.vulnerabilityHints?.length > 0) {
    const hintsText = result.vulnerabilityHints.map((h, i) =>
      `[${i + 1}] [${h.source}] [${h.severity}] ${h.title}${h.port ? ` (Port: ${h.port})` : ""}: ${h.description}`
    ).join("\n")
    sections.push(`\n=== VULNERABILITY HINTS ===\n${hintsText}`)
  }

  sections.push(`\nGenerate comprehensive remediation guidance covering ALL findings from ALL scan engines. Prioritize by severity. Provide specific fix commands for each finding.`)

  return sections.join("\n")
}

// ─── Count total findings across any scan type ──────────────────────────────

function countTotalFindings(rawResult: ScanResult): number {
  if (isFullResult(rawResult)) {
    let total = 0
    if (rawResult.nmap) {
      total += (rawResult.nmap.ports?.length ?? 0) + (rawResult.nmap.vulnerabilities?.length ?? 0)
    }
    if (rawResult.nikto) {
      total += (rawResult.nikto.findings?.length ?? 0) + (rawResult.nikto.vulnerabilities?.length ?? 0)
    }
    if (rawResult.nuclei) {
      total += (rawResult.nuclei.findings?.length ?? 0) + (rawResult.nuclei.vulnerabilities?.length ?? 0)
    }
    total += rawResult.openPorts?.length ?? 0
    total += rawResult.vulnerabilityHints?.length ?? 0
    return total
  } else if (isNucleiResult(rawResult)) {
    return (rawResult.findings?.length ?? 0) + (rawResult.vulnerabilities?.length ?? 0)
  } else if (isNiktoResult(rawResult)) {
    return (rawResult.findings?.length ?? 0) + (rawResult.vulnerabilities?.length ?? 0)
  } else {
    return (rawResult.ports?.length ?? 0) + (rawResult.vulnerabilities?.length ?? 0)
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
    const totalFindings = countTotalFindings(rawResult)

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
