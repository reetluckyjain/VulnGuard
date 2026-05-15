'use client'

import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Shield, Search, Server, AlertTriangle, Clock, ChevronRight,
  RotateCcw, ExternalLink, AlertCircle, CheckCircle2, Wifi,
  WifiOff, Loader2, Info, Globe, Bug, FileWarning, ExternalLinkIcon,
  Sparkles, Terminal, Copy, Check, Zap, Wrench,
  Fingerprint, Calendar, Play, Pause, Trash2, Timer, KeyRound,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { toast } from '@/hooks/use-toast'

// ─── Types ──────────────────────────────────────────────────────────────────

interface PortInfo { port_id: number; protocol: string; state: string; service: string; version: string }
interface Vulnerability { port_id: number; cve_id: string; description: string }
interface NmapScanResult { target: string; ports: PortInfo[]; vulnerabilities: Vulnerability[] }

interface NiktoFinding {
  id: string; host: string; ip: string; port: number
  method: string; path: string; description: string; references: string[]
}
interface NiktoScanResult {
  target: string; scanType: 'nikto'; server: string
  findings: NiktoFinding[]; vulnerabilities: Vulnerability[]
  summary: { total: number; info: number; low: number; medium: number; high: number }
}

interface NucleiFinding {
  templateId: string
  name: string
  severity: string  // critical, high, medium, low, info
  type: string      // http, dns, etc.
  matchedAt: string // The exact vulnerable URL
  curlCommand: string | null  // Reproduction command - gold mine for bug hunters
  extractedResults: string[]  // Extracted data (API keys, DB versions)
  description: string
  tags: string[]
  reference: string[]
  host: string
  timestamp: string
}

interface NucleiScanResult {
  target: string
  scanType: 'nuclei'
  findings: NucleiFinding[]
  vulnerabilities: Vulnerability[]
  summary: {
    total: number; critical: number; high: number; medium: number
    low: number; info: number; withCurlCommand: number; withExtractedResults: number
  }
}

type ScanResult = NmapScanResult | NiktoScanResult | NucleiScanResult

interface RemediationItem {
  finding: string
  severity: string
  explanation: string
  fix_commands: string[]
  references: string[]
}

interface RemediationData {
  summary: string
  risk_level: string
  remediations: RemediationItem[]
  hardening_recommendations: string[]
  raw_response?: string
}

interface ScanHistoryEntry {
  id: string; target: string; scanType: 'nmap' | 'nikto' | 'nuclei'; status: 'pending'|'running'|'completed'|'failed'; timestamp: string; results?: ScanResult
}

interface VerificationData {
  target: string
  verificationCode: string
  txtRecordName: string
  txtRecordValue: string
  instructions: string
  expiresAt: string
}

interface VerificationStatus {
  target: string
  status: 'unverified' | 'pending' | 'verified' | 'expired' | 'ip_address' | 'not_found'
  verificationCode?: string
  verifiedAt?: string | null
  expiresAt?: string
}

interface ScheduleEntry {
  id: string; target: string; scanType: string; port: string
  frequency: string; isActive: boolean
  lastRunAt: string | null; nextRunAt: string; createdAt: string
}

function isNiktoResult(result: ScanResult | null): result is NiktoScanResult {
  return !!result && typeof result === 'object' && 'scanType' in result && result.scanType === 'nikto'
}

function isNucleiResult(result: ScanResult | null): result is NucleiScanResult {
  return !!result && typeof result === 'object' && 'scanType' in result && result.scanType === 'nuclei'
}

function stateColor(state: string): string {
  switch (state.toLowerCase()) {
    case 'open': return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
    case 'closed': return 'bg-red-500/20 text-red-400 border-red-500/30'
    case 'filtered': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    default: return 'bg-muted text-muted-foreground border-border'
  }
}

function severityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical': return 'bg-red-600/20 text-red-500 border-red-600/30'
    case 'high': return 'bg-red-500/20 text-red-400 border-red-500/30'
    case 'medium': return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
    case 'low': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    case 'info': return 'bg-blue-500/20 text-blue-400 border-blue-500/30'
    default: return 'bg-muted text-muted-foreground border-border'
  }
}

const cardVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: (i: number) => ({ opacity: 1, y: 0, transition: { delay: i * 0.1, duration: 0.4, ease: 'easeOut' } }),
}
const staggerContainer = { hidden: { opacity: 0 }, visible: { opacity: 1, transition: { staggerChildren: 0.08 } } }
const staggerItem = { hidden: { opacity: 0, x: -10 }, visible: { opacity: 1, x: 0, transition: { duration: 0.3 } } }

function normalizeStatus(status: string): ScanHistoryEntry['status'] {
  const s = status.toLowerCase()
  if (s === 'pending') return 'pending'
  if (s === 'running') return 'running'
  if (s === 'completed') return 'completed'
  if (s === 'failed') return 'failed'
  return 'pending'
}

export default function Home() {
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState<'nmap' | 'nikto' | 'nuclei'>('nmap')
  const [niktoPort, setNiktoPort] = useState('80')
  const [isAuthorized, setIsAuthorized] = useState(false)
  const [validationError, setValidationError] = useState('')
  const [isScanning, setIsScanning] = useState(false)
  const [currentScanTarget, setCurrentScanTarget] = useState('')
  const [currentScanType, setCurrentScanType] = useState<'nmap' | 'nikto' | 'nuclei'>('nmap')
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [scanHistory, setScanHistory] = useState<ScanHistoryEntry[]>([])
  const [activeScanId, setActiveScanId] = useState<string | null>(null)
  const [pollCount, setPollCount] = useState(0)
  const [scanStatusText, setScanStatusText] = useState('Initializing...')
  const [remediation, setRemediation] = useState<RemediationData | null>(null)
  const [isRemediating, setIsRemediating] = useState(false)
  const [remediationError, setRemediationError] = useState('')
  const [copiedIdx, setCopiedIdx] = useState<string | null>(null)

  // Verification state
  const [verificationData, setVerificationData] = useState<VerificationData | null>(null)
  const [verificationStatus, setVerificationStatus] = useState<VerificationStatus | null>(null)
  const [isVerifying, setIsVerifying] = useState(false)
  const [isGeneratingCode, setIsGeneratingCode] = useState(false)

  // Scheduling state
  const [schedules, setSchedules] = useState<ScheduleEntry[]>([])
  const [scheduleTarget, setScheduleTarget] = useState('')
  const [scheduleScanType, setScheduleScanType] = useState<'nmap' | 'nikto' | 'nuclei'>('nmap')
  const [scheduleFrequency, setScheduleFrequency] = useState('daily')
  const [isCreatingSchedule, setIsCreatingSchedule] = useState(false)

  const isIPAddress = (t: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(t)

  // Nmap stats
  const nmapResult = scanResult && !isNiktoResult(scanResult) && !isNucleiResult(scanResult) ? scanResult as NmapScanResult : null
  const openPortCount = nmapResult?.ports?.filter(p => p.state?.toLowerCase() === 'open').length ?? 0
  const closedPortCount = nmapResult?.ports?.filter(p => p.state?.toLowerCase() === 'closed').length ?? 0
  const filteredPortCount = nmapResult?.ports?.filter(p => p.state?.toLowerCase() === 'filtered').length ?? 0
  const nmapVulnCount = nmapResult?.vulnerabilities?.length ?? 0
  const nmapCveCount = new Set(nmapResult?.vulnerabilities?.map(v => v.cve_id) ?? []).size

  // Nikto stats
  const niktoResult = scanResult && isNiktoResult(scanResult) ? scanResult : null
  const niktoFindingsCount = niktoResult?.findings?.length ?? 0
  const niktoVulnCount = niktoResult?.vulnerabilities?.length ?? 0
  const niktoSummary = niktoResult?.summary ?? { total: 0, info: 0, low: 0, medium: 0, high: 0 }

  // Nuclei stats
  const nucleiResult = scanResult && isNucleiResult(scanResult) ? scanResult : null
  const nucleiFindingsCount = nucleiResult?.findings?.length ?? 0
  const nucleiVulnCount = nucleiResult?.vulnerabilities?.length ?? 0
  const nucleiSummary = nucleiResult?.summary ?? { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, withCurlCommand: 0, withExtractedResults: 0 }

  const vulnCount = isNucleiResult(scanResult) ? nucleiVulnCount : isNiktoResult(scanResult) ? niktoVulnCount : nmapVulnCount

  const handleStartScan = useCallback(async () => {
    if (!target.trim()) { setValidationError('Please enter a target IP or hostname'); return }
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/
    const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/
    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/
    if (!ipRegex.test(target.trim()) && !hostnameRegex.test(target.trim()) && !cidrRegex.test(target.trim())) {
      setValidationError('Please enter a valid IP address, hostname, or CIDR range'); return
    }
    if (scanType === 'nikto' && niktoPort && !/^\d+$/.test(niktoPort)) {
      setValidationError('Port must be a number'); return
    }
    if (!isAuthorized) { setValidationError('You must confirm authorization before scanning'); return }
    setValidationError('')
    setIsScanning(true)
    setCurrentScanTarget(target.trim())
    setCurrentScanType(scanType)
    setScanResult(null)
    setScanStatusText(scanType === 'nikto' ? 'Running real Nikto web scan...' : scanType === 'nuclei' ? 'Running real Nuclei bug hunt...' : 'Running real nmap scan...')
    const scanId = `scan-${Date.now()}`
    const historyEntry: ScanHistoryEntry = { id: scanId, target: target.trim(), scanType, status: 'running', timestamp: new Date().toISOString() }
    setScanHistory(prev => [historyEntry, ...prev])
    try {
      let response: Response | null = null
      let lastError: string = ''
      for (let attempt = 1; attempt <= 3; attempt++) {
        try {
          setScanStatusText(`Starting ${scanType} scan (attempt ${attempt}/3)...`)
          response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              target: target.trim(),
              isAuthorized: true,
              scanType,
              port: (scanType === 'nikto' || scanType === 'nuclei') ? niktoPort : undefined,
            }),
          })
          if (response.ok) break
          const contentType = response.headers.get('content-type') || ''
          if (contentType.includes('application/json')) break
          lastError = `Server returned ${response.status}`
          response = null
        } catch (fetchErr) {
          lastError = fetchErr instanceof Error ? fetchErr.message : 'Connection failed'
          response = null
        }
        if (attempt < 3) await new Promise(r => setTimeout(r, 2000))
      }

      if (!response || !response.ok) {
        const errorData = response ? await response.json().catch(() => ({})) : {}
        throw new Error((errorData as Record<string,string>).error || lastError || 'Scan request failed after 3 attempts')
      }
      const data = await response.json() as Record<string, unknown>
      const returnedScanId = (data.scan_id as string) || scanId
      const returnedStatus = normalizeStatus((data.status as string) || '')
      if (data.results) {
        setScanResult(data.results as ScanResult)
        setIsScanning(false); setCurrentScanTarget(''); setActiveScanId(null)
        setScanHistory(prev => prev.map(e => e.id === scanId ? { ...e, id: returnedScanId, status: (returnedStatus || 'completed') as ScanHistoryEntry['status'], results: data.results as ScanResult } : e))
        const engine = scanType === 'nikto' ? 'Nikto' : scanType === 'nuclei' ? 'Nuclei' : 'Nmap'
        toast({ title: 'Scan Complete', description: `${engine} scan of ${target.trim()} completed` })
      } else if (returnedStatus === 'failed') {
        setIsScanning(false); setCurrentScanTarget('')
        setScanHistory(prev => prev.map(e => e.id === scanId ? { ...e, id: returnedScanId, status: 'failed' as const } : e))
        toast({ title: 'Scan Failed', description: (data.error as string) || 'The scan encountered an error', variant: 'destructive' })
      } else {
        setActiveScanId(returnedScanId); setPollCount(0); setScanStatusText('Scan submitted — waiting for results...')
        setScanHistory(prev => prev.map(e => e.id === scanId ? { ...e, id: returnedScanId } : e))
      }
    } catch (err) {
      setIsScanning(false); setCurrentScanTarget('')
      toast({ title: 'Scan Failed', description: err instanceof Error ? err.message : 'Failed to start scan', variant: 'destructive' })
      setScanHistory(prev => prev.map(e => e.id === scanId ? { ...e, status: 'failed' as const } : e))
    }
  }, [target, isAuthorized, scanType, niktoPort])

  useEffect(() => {
    if (!activeScanId || !isScanning) return
    const pollInterval = setInterval(async () => {
      try {
        const response = await fetch(`/api/scan/${activeScanId}`)
        if (!response.ok) throw new Error('Failed to fetch scan status')
        const data = await response.json() as Record<string, unknown>
        setPollCount(prev => prev + 1)
        const statusLower = ((data.status as string) || '').toLowerCase()
        const type = (data.scan_type as string) || 'nmap'
        if (statusLower === 'pending') setScanStatusText('Scan queued — waiting for processing...')
        else if (statusLower === 'running') setScanStatusText(`Real ${type} scan in progress — analyzing target...`)
        if (statusLower === 'completed' && data.results) {
          setScanResult(data.results as ScanResult); setIsScanning(false); setCurrentScanTarget(''); setActiveScanId(null)
          setScanHistory(prev => prev.map(e => e.id === activeScanId ? { ...e, status: 'completed' as const, results: data.results as ScanResult } : e))
          toast({ title: 'Scan Complete', description: `${type} scan completed` })
        } else if (statusLower === 'failed') {
          setIsScanning(false); setCurrentScanTarget(''); setActiveScanId(null)
          setScanHistory(prev => prev.map(e => e.id === activeScanId ? { ...e, status: 'failed' as const } : e))
          toast({ title: 'Scan Failed', description: (data.error as string) || 'The scan encountered an error', variant: 'destructive' })
        }
      } catch { /* continue polling */ }
    }, 5000)
    return () => clearInterval(pollInterval)
  }, [activeScanId, isScanning])

  const loadHistoryResult = (entry: ScanHistoryEntry) => {
    if (entry.results) { setScanResult(entry.results); window.scrollTo({ top: 0, behavior: 'smooth' }) }
  }
  const handleReset = () => { setTarget(''); setIsAuthorized(false); setValidationError(''); setScanResult(null); setRemediation(null); setRemediationError(''); setVerificationData(null); setVerificationStatus(null) }

  // ─── Verification handlers ────────────────────────────────────────────
  const handleGenerateVerification = useCallback(async () => {
    if (!target.trim()) { setValidationError('Enter a target domain first'); return }
    if (isIPAddress(target.trim())) { setValidationError('DNS verification is for domain names only. IP addresses use checkbox authorization.'); return }
    setIsGeneratingCode(true)
    try {
      const response = await fetch('/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim() }),
      })
      const data = await response.json() as Record<string, unknown>
      if (!response.ok) throw new Error((data as Record<string,string>).error || 'Verification failed')
      if ((data as Record<string,string>).status === 'verified') {
        setVerificationStatus({ target: target.trim(), status: 'verified', verifiedAt: (data as Record<string,string>).verifiedAt })
        toast({ title: 'Already Verified', description: `${target.trim()} is already verified` })
      } else {
        setVerificationData(data as unknown as VerificationData)
        setVerificationStatus({ target: target.trim(), status: 'pending', verificationCode: (data as Record<string,string>).verificationCode })
        toast({ title: 'Verification Code Generated', description: 'Add the DNS TXT record, then click Verify DNS' })
      }
    } catch (err) {
      toast({ title: 'Verification Failed', description: err instanceof Error ? err.message : 'Failed', variant: 'destructive' })
    } finally { setIsGeneratingCode(false) }
  }, [target])

  const handleVerifyDns = useCallback(async () => {
    if (!target.trim()) return
    setIsVerifying(true)
    try {
      const response = await fetch('/api/verify', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim() }),
      })
      const data = await response.json() as Record<string, unknown>
      if ((data as Record<string,string>).status === 'verified') {
        setVerificationStatus({ target: target.trim(), status: 'verified', verifiedAt: (data as Record<string,string>).verifiedAt as string })
        toast({ title: 'Target Verified!', description: `${target.trim()} is now verified via DNS TXT` })
      } else {
        toast({ title: 'DNS Not Found', description: (data as Record<string,string>).message || 'TXT record not found yet. DNS propagation may take a few minutes.', variant: 'destructive' })
      }
    } catch (err) {
      toast({ title: 'Verification Check Failed', description: err instanceof Error ? err.message : 'Failed', variant: 'destructive' })
    } finally { setIsVerifying(false) }
  }, [target])

  // ─── Schedule handlers ────────────────────────────────────────────────
  const loadSchedules = useCallback(async () => {
    try {
      const response = await fetch('/api/schedules')
      if (response.ok) {
        const data = await response.json() as Record<string, unknown>
        setSchedules((data.schedules as ScheduleEntry[]) || [])
      }
    } catch { /* ignore */ }
  }, [])

  const handleCreateSchedule = useCallback(async () => {
    if (!scheduleTarget.trim()) { toast({ title: 'Error', description: 'Enter a target domain', variant: 'destructive' }); return }
    setIsCreatingSchedule(true)
    try {
      const response = await fetch('/api/schedules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: scheduleTarget.trim(), scanType: scheduleScanType, port: (scheduleScanType === 'nikto' || scheduleScanType === 'nuclei') ? '80' : undefined, frequency: scheduleFrequency }),
      })
      if (!response.ok) {
        const err = await response.json().catch(() => ({})) as Record<string, string>
        throw new Error(err.error || 'Failed')
      }
      toast({ title: 'Schedule Created', description: `${scheduleFrequency} ${scheduleScanType} scan for ${scheduleTarget.trim()}` })
      setScheduleTarget('')
      loadSchedules()
    } catch (err) {
      toast({ title: 'Schedule Failed', description: err instanceof Error ? err.message : 'Failed', variant: 'destructive' })
    } finally { setIsCreatingSchedule(false) }
  }, [scheduleTarget, scheduleScanType, scheduleFrequency, loadSchedules])

  const handleToggleSchedule = useCallback(async (id: string, isActive: boolean) => {
    try {
      await fetch(`/api/schedules?id=${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ isActive: !isActive }) })
      loadSchedules()
    } catch { /* ignore */ }
  }, [loadSchedules])

  const handleDeleteSchedule = useCallback(async (id: string) => {
    try {
      await fetch(`/api/schedules?id=${id}`, { method: 'DELETE' })
      loadSchedules()
      toast({ title: 'Schedule Deleted' })
    } catch { /* ignore */ }
  }, [loadSchedules])

  useEffect(() => { loadSchedules() }, [loadSchedules])

  // Check verification status when target changes
  useEffect(() => {
    if (!target.trim() || isIPAddress(target.trim())) { setVerificationStatus(null); return }
    const check = async () => {
      try {
        const r = await fetch(`/api/verify?target=${encodeURIComponent(target.trim())}`)
        if (r.ok) { const d = await r.json() as VerificationStatus; setVerificationStatus(d) }
      } catch { /* ignore */ }
    }
    const t = setTimeout(check, 500)
    return () => clearTimeout(t)
  }, [target])

  const handleGetRemediation = useCallback(async () => {
    if (!scanResult) return
    setIsRemediating(true)
    setRemediationError('')
    setRemediation(null)
    try {
      const response = await fetch('/api/remediate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scanResult }),
      })
      if (!response.ok) {
        const errData = await response.json().catch(() => ({})) as Record<string, string>
        throw new Error(errData.error || `Remediation failed: ${response.status}`)
      }
      const data = await response.json() as RemediationData
      setRemediation(data)
      toast({ title: 'AI Remediation Complete', description: 'Plain-English explanations and fix commands are ready' })
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Remediation engine failed'
      setRemediationError(msg)
      toast({ title: 'Remediation Failed', description: msg, variant: 'destructive' })
    } finally {
      setIsRemediating(false)
    }
  }, [scanResult])

  const copyToClipboard = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopiedIdx(id)
      setTimeout(() => setCopiedIdx(null), 2000)
    } catch { /* fallback: ignore */ }
  }

  function riskLevelColor(level: string): string {
    switch (level.toLowerCase()) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30'
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
      case 'low': return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
      case 'secure': return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
      default: return 'bg-muted text-muted-foreground border-border'
    }
  }

  const scanEngineLabel = scanType === 'nikto' ? 'Nikto' : scanType === 'nuclei' ? 'Nuclei' : 'Nmap'
  const scanEngineDesc = scanType === 'nikto'
    ? 'nikto -h target -Format csv — Web vulnerability scanner'
    : scanType === 'nuclei'
    ? 'nuclei -u target -jsonl — Template-based bug hunter'
    : 'nmap -sT -sV --script vuln — Network/port scanner'

  return (
    <div className="min-h-screen flex flex-col bg-background">
      <header className="border-b border-border/50 bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center gap-3">
            <div className="relative"><Shield className="h-8 w-8 text-primary" /><div className="absolute -top-0.5 -right-0.5 h-3 w-3 bg-primary rounded-full animate-pulse-dot" /></div>
            <div><h1 className="text-xl font-bold tracking-tight text-foreground">VulnGuard</h1><p className="text-xs text-muted-foreground">Ethical Vulnerability Scanner — Real Engines</p></div>
            <div className="ml-auto flex items-center gap-2">
              <Badge variant="outline" className="text-xs bg-emerald-500/10 text-emerald-400 border-emerald-500/30"><CheckCircle2 className="h-3 w-3 mr-1" />Real Data Only</Badge>
              <Badge variant="outline" className="text-xs bg-primary/10 text-primary border-primary/30">Nmap + Nikto + Nuclei</Badge>
              <Badge variant="outline" className="text-xs bg-amber-500/10 text-amber-400 border-amber-500/30"><Sparkles className="h-3 w-3 mr-1" />AI Remediation</Badge>
              <Badge variant="outline" className="text-xs bg-cyan-500/10 text-cyan-400 border-cyan-500/30"><Fingerprint className="h-3 w-3 mr-1" />DNS Verify</Badge>
            </div>
          </div>
        </div>
      </header>
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Authorization */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
          <Card className="border-yellow-500/30 bg-yellow-500/5">
            <CardContent className="p-4 sm:p-6">
              <div className="flex items-start gap-3">
                <AlertCircle className="h-5 w-5 text-yellow-500 mt-0.5 shrink-0" />
                <div className="flex-1 space-y-3">
                  <div><h3 className="font-semibold text-yellow-400 text-sm">Legal Disclaimer & Authorization Required</h3><p className="text-xs text-muted-foreground mt-1">Scanning networks without explicit permission is illegal. You must confirm authorization before proceeding. This tool runs <strong>real nmap and Nikto scans</strong>.</p></div>
                  <div className="flex items-start gap-3">
                    <Checkbox id="authorization" checked={isAuthorized} onCheckedChange={checked => { setIsAuthorized(checked === true); if (checked) setValidationError('') }} className="mt-0.5 data-[state=checked]:bg-yellow-500 data-[state=checked]:border-yellow-500" />
                    <label htmlFor="authorization" className="text-sm leading-relaxed cursor-pointer select-none">I confirm I have explicit authorization to scan this target. I understand unauthorized scanning is illegal.</label>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Scan Config */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, delay: 0.1 }}>
          <Card>
            <CardHeader><CardTitle className="text-base">Start New Scan</CardTitle><CardDescription>Choose a scan engine and enter a target. All engines run real scans — no simulation.</CardDescription></CardHeader>
            <CardContent>
              <div className="flex flex-col gap-4">
                {/* Engine selector row */}
                <div className="flex flex-col sm:flex-row gap-3 items-start sm:items-center">
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-sm font-medium text-muted-foreground">Engine:</span>
                    <Select value={scanType} onValueChange={(v) => setScanType(v as 'nmap' | 'nikto' | 'nuclei')}>
                      <SelectTrigger className="w-[180px]"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="nmap">
                          <span className="flex items-center gap-2"><Server className="h-3.5 w-3.5" />Nmap</span>
                        </SelectItem>
                        <SelectItem value="nikto">
                          <span className="flex items-center gap-2"><Globe className="h-3.5 w-3.5" />Nikto</span>
                        </SelectItem>
                        <SelectItem value="nuclei">
                          <span className="flex items-center gap-2"><Bug className="h-3.5 w-3.5" />Nuclei</span>
                        </SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  {(scanType === 'nikto' || scanType === 'nuclei') && (
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-muted-foreground shrink-0">Port:</span>
                      <Input type="text" value={niktoPort} onChange={e => setNiktoPort(e.target.value)} className="w-20 font-mono" placeholder="80" aria-label="Nikto target port" />
                    </div>
                  )}
                </div>
                {/* Target + scan button */}
                <div className="flex flex-col sm:flex-row gap-3">
                  <div className="flex-1">
                    <Input type="text" placeholder={scanType === 'nikto' ? 'e.g., scanme.nmap.org or 192.168.1.1' : 'e.g., scanme.nmap.org or 192.168.1.1'} value={target} onChange={e => { setTarget(e.target.value); if (validationError) setValidationError('') }} onKeyDown={e => { if (e.key === 'Enter') handleStartScan() }} disabled={isScanning} className="font-mono" aria-label="Target IP or hostname" />
                    {/* Verification status indicator */}
                    {target.trim() && !isIPAddress(target.trim()) && verificationStatus && (
                      <div className="flex items-center gap-1.5 mt-1.5">
                        {verificationStatus.status === 'verified' ? (
                          <Badge variant="outline" className="text-xs bg-emerald-500/10 text-emerald-400 border-emerald-500/30"><CheckCircle2 className="h-3 w-3 mr-1" />DNS Verified</Badge>
                        ) : verificationStatus.status === 'pending' ? (
                          <Badge variant="outline" className="text-xs bg-yellow-500/10 text-yellow-400 border-yellow-500/30"><KeyRound className="h-3 w-3 mr-1" />Verification Pending</Badge>
                        ) : verificationStatus.status === 'expired' ? (
                          <Badge variant="outline" className="text-xs bg-red-500/10 text-red-400 border-red-500/30"><AlertCircle className="h-3 w-3 mr-1" />Verification Expired</Badge>
                        ) : (
                          <Badge variant="outline" className="text-xs bg-orange-500/10 text-orange-400 border-orange-500/30"><Fingerprint className="h-3 w-3 mr-1" />DNS Verification Required</Badge>
                        )}
                      </div>
                    )}
                    {validationError && <p className="text-sm text-red-400 mt-1.5 flex items-center gap-1.5"><AlertCircle className="h-3.5 w-3.5" />{validationError}</p>}
                  </div>
                  <div className="flex gap-2">
                    <Button onClick={handleStartScan} disabled={!isAuthorized || isScanning || !target.trim()} className="bg-primary hover:bg-primary/90 text-primary-foreground min-w-[140px]">
                      {isScanning ? <span className="flex items-center gap-2"><Loader2 className="h-4 w-4 animate-spin" />Scanning...</span> : <span className="flex items-center gap-2"><Search className="h-4 w-4" />Start Scan</span>}
                    </Button>
                    {scanResult && <Button variant="outline" onClick={handleReset}><RotateCcw className="h-4 w-4" /></Button>}
                  </div>
                </div>
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Info className="h-3.5 w-3.5 shrink-0" />
                  {scanType === 'nikto' ? (
                    <span>Scan uses <code className="bg-muted px-1 py-0.5 rounded">nikto -h target -Format csv -C all</code> — Web vulnerability scanner, 100% real data.</span>
                  ) : scanType === 'nuclei' ? (
                    <span>Scan uses <code className="bg-muted px-1 py-0.5 rounded">nuclei -u target -jle results.jsonl</code> — Template-based bug hunter (XSS, SQLi, secrets, CVEs), 100% real data.</span>
                  ) : (
                    <span>Scan uses <code className="bg-muted px-1 py-0.5 rounded">nmap -sT -sV --script vuln</code> — Network/port scanner, 100% real data.</span>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* ─── DNS Verification Gate ───────────────────────────────────────── */}
        {target.trim() && !isIPAddress(target.trim()) && verificationStatus?.status !== 'verified' && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
            <Card className="border-cyan-500/30 bg-gradient-to-br from-cyan-500/5 via-transparent to-transparent">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2"><Fingerprint className="h-4 w-4 text-cyan-400" />Target Ownership Verification</CardTitle>
                <CardDescription>Prove you own this domain by adding a DNS TXT record. This prevents unauthorized scanning of third-party targets.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {!verificationData ? (
                  <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
                    <p className="text-sm text-muted-foreground flex-1">Generate a unique verification code, add it as a DNS TXT record, then verify ownership.</p>
                    <Button onClick={handleGenerateVerification} disabled={isGeneratingCode} className="bg-cyan-600 hover:bg-cyan-700 text-white min-w-[180px]">
                      {isGeneratingCode ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <KeyRound className="h-4 w-4 mr-2" />}
                      {isGeneratingCode ? 'Generating...' : 'Generate Code'}
                    </Button>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div className="rounded-lg border border-cyan-500/20 bg-muted/20 p-4 space-y-3">
                      <p className="text-sm font-medium">Add this DNS TXT record to your domain:</p>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        <div className="rounded bg-zinc-950 border border-zinc-800 p-2.5">
                          <p className="text-xs text-zinc-500 mb-1">Name / Host</p>
                          <p className="text-sm font-mono text-cyan-400">{verificationData.txtRecordName}</p>
                        </div>
                        <div className="rounded bg-zinc-950 border border-zinc-800 p-2.5 relative group">
                          <p className="text-xs text-zinc-500 mb-1">Value / TXT Data</p>
                          <p className="text-sm font-mono text-emerald-400">{verificationData.txtRecordValue}</p>
                          <button onClick={() => copyToClipboard(verificationData.txtRecordValue, 'verify-code')} className="absolute top-2 right-2 p-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-400 hover:text-white transition-colors opacity-0 group-hover:opacity-100" aria-label="Copy code">
                            {copiedIdx === 'verify-code' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                          </button>
                        </div>
                      </div>
                      <p className="text-xs text-muted-foreground">Code expires: {new Date(verificationData.expiresAt).toLocaleString()}</p>
                    </div>
                    <div className="flex flex-col sm:flex-row gap-2">
                      <Button onClick={handleVerifyDns} disabled={isVerifying} className="bg-cyan-600 hover:bg-cyan-700 text-white min-w-[160px]">
                        {isVerifying ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <CheckCircle2 className="h-4 w-4 mr-2" />}
                        {isVerifying ? 'Checking DNS...' : 'Verify DNS'}
                      </Button>
                      <Button variant="outline" onClick={handleGenerateVerification} disabled={isGeneratingCode} className="text-xs">
                        <RotateCcw className="h-3.5 w-3.5 mr-1.5" />Regenerate Code
                      </Button>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </motion.div>
        )}

        {/* ─── Scheduled Scans ──────────────────────────────────────────────── */}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, delay: 0.15 }}>
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2"><Calendar className="h-4 w-4 text-primary" />Scheduled Scans</CardTitle>
              <CardDescription>Set up recurring scans for continuous monitoring. Only verified targets can be scheduled.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Create schedule form */}
              <div className="flex flex-col sm:flex-row gap-3 items-end">
                <div className="flex-1">
                  <label className="text-xs text-muted-foreground mb-1 block">Target Domain</label>
                  <Input type="text" value={scheduleTarget} onChange={e => setScheduleTarget(e.target.value)} placeholder="e.g., example.com" className="font-mono text-sm" aria-label="Schedule target" />
                </div>
                <div className="w-[130px]">
                  <label className="text-xs text-muted-foreground mb-1 block">Engine</label>
                  <Select value={scheduleScanType} onValueChange={v => setScheduleScanType(v as 'nmap' | 'nikto' | 'nuclei')}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="nmap">Nmap</SelectItem>
                      <SelectItem value="nikto">Nikto</SelectItem>
                      <SelectItem value="nuclei">Nuclei</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="w-[130px]">
                  <label className="text-xs text-muted-foreground mb-1 block">Frequency</label>
                  <Select value={scheduleFrequency} onValueChange={setScheduleFrequency}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="hourly">Hourly</SelectItem>
                      <SelectItem value="daily">Daily</SelectItem>
                      <SelectItem value="weekly">Weekly</SelectItem>
                      <SelectItem value="monthly">Monthly</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <Button onClick={handleCreateSchedule} disabled={isCreatingSchedule || !scheduleTarget.trim()} className="bg-primary hover:bg-primary/90 text-primary-foreground min-w-[120px]">
                  {isCreatingSchedule ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Timer className="h-4 w-4 mr-2" />}
                  {isCreatingSchedule ? 'Creating...' : 'Schedule'}
                </Button>
              </div>

              {/* Schedule list */}
              {schedules.length > 0 ? (
                <div className="space-y-2 max-h-64 overflow-y-auto custom-scrollbar">
                  {schedules.map((schedule) => (
                    <div key={schedule.id} className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-3 p-3 rounded-lg border border-border/50 bg-muted/20 hover:bg-muted/30 transition-colors">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono text-sm font-medium">{schedule.target}</span>
                          <Badge variant="outline" className="text-xs">{schedule.scanType}</Badge>
                          <Badge variant="outline" className="text-xs bg-primary/10 text-primary border-primary/30">{schedule.frequency}</Badge>
                          <Badge variant="outline" className={schedule.isActive ? 'text-xs bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'text-xs bg-muted text-muted-foreground border-border'}>
                            {schedule.isActive ? 'Active' : 'Paused'}
                          </Badge>
                        </div>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          Next: {new Date(schedule.nextRunAt).toLocaleString()}
                          {schedule.lastRunAt && <> · Last: {new Date(schedule.lastRunAt).toLocaleString()}</>}
                        </p>
                      </div>
                      <div className="flex gap-1.5 shrink-0">
                        <Button variant="ghost" size="sm" onClick={() => handleToggleSchedule(schedule.id, schedule.isActive)} className="h-8 w-8 p-0">
                          {schedule.isActive ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
                        </Button>
                        <Button variant="ghost" size="sm" onClick={() => handleDeleteSchedule(schedule.id)} className="h-8 w-8 p-0 text-red-400 hover:text-red-300">
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-4">No scheduled scans yet. Create one above for continuous monitoring.</p>
              )}
            </CardContent>
          </Card>
        </motion.div>

        {/* Scanning progress */}
        <AnimatePresence>
          {isScanning && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} transition={{ duration: 0.3 }}>
              <Card className="border-primary/20 bg-primary/5">
                <CardContent className="p-4 sm:p-6 space-y-4">
                  <div className="flex items-center gap-3">
                    <div className="relative"><div className="h-3 w-3 bg-emerald-500 rounded-full animate-pulse-dot" /><div className="absolute inset-0 h-3 w-3 bg-emerald-500 rounded-full animate-ping opacity-30" /></div>
                    <span className="text-sm font-medium">Scanning <span className="font-mono text-primary">{currentScanTarget}</span> <Badge variant="outline" className="ml-1 text-xs">{currentScanType}</Badge></span>
                    {activeScanId && <span className="text-xs text-muted-foreground ml-auto">Poll #{pollCount}</span>}
                  </div>
                  <div className="relative h-2 w-full overflow-hidden rounded-full bg-primary/10"><div className="absolute inset-0 h-full w-1/3 rounded-full bg-primary animate-indeterminate" /></div>
                  <div className="space-y-1">
                    <p className="text-sm text-muted-foreground">{scanStatusText}</p>
                    <p className="text-xs text-muted-foreground/60">
                      {currentScanType === 'nikto'
                        ? 'Running real Nikto web scan — this may take 1-2 minutes.'
                        : currentScanType === 'nuclei'
                        ? 'Running real Nuclei bug hunt — this may take 2-5 minutes.'
                        : 'Running real nmap scan — this may take 1-3 minutes.'}
                    </p>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ─── Results ────────────────────────────────────────────────────── */}
        <AnimatePresence>
          {scanResult && !isScanning && (
            <motion.div variants={staggerContainer} initial="hidden" animate="visible" className="space-y-8">

              {/* Nmap Results */}
              {nmapResult && (
                <>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <motion.div custom={0} variants={cardVariants}><Card className="hover:border-primary/30 transition-colors"><CardContent className="p-4 sm:p-6"><div className="flex items-center justify-between"><div><p className="text-sm text-muted-foreground">Open Ports</p><p className="text-3xl font-bold mt-1">{openPortCount}</p></div><div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center"><Server className="h-5 w-5 text-primary" /></div></div>{(closedPortCount > 0 || filteredPortCount > 0) && <p className="text-xs text-muted-foreground mt-2">+{closedPortCount} closed, {filteredPortCount} filtered</p>}</CardContent></Card></motion.div>
                    <motion.div custom={1} variants={cardVariants}><Card className={nmapVulnCount > 0 ? 'border-orange-500/30 hover:border-orange-500/50' : 'border-emerald-500/30 hover:border-emerald-500/50'}><CardContent className="p-4 sm:p-6"><div className="flex items-center justify-between"><div><p className="text-sm text-muted-foreground">Vulnerabilities</p><p className={`text-3xl font-bold mt-1 ${nmapVulnCount > 0 ? 'text-orange-400' : 'text-emerald-400'}`}>{nmapVulnCount}</p></div><div className={`h-10 w-10 rounded-lg flex items-center justify-center ${nmapVulnCount > 0 ? 'bg-orange-500/10' : 'bg-emerald-500/10'}`}>{nmapVulnCount > 0 ? <AlertTriangle className="h-5 w-5 text-orange-400" /> : <CheckCircle2 className="h-5 w-5 text-emerald-400" />}</div></div></CardContent></Card></motion.div>
                    <motion.div custom={2} variants={cardVariants}><Card className={nmapCveCount > 0 ? 'border-red-500/20 bg-red-500/5' : 'border-emerald-500/20 bg-emerald-500/5'}><CardContent className="p-4 sm:p-6"><div className="flex items-center justify-between"><div><p className="text-sm text-muted-foreground">Unique CVEs</p><p className={`text-3xl font-bold mt-1 ${nmapCveCount > 0 ? 'text-red-400' : 'text-emerald-400'}`}>{nmapCveCount}</p></div><div className={`h-10 w-10 rounded-lg flex items-center justify-center ${nmapCveCount > 0 ? 'bg-red-500/10' : 'bg-emerald-500/10'}`}>{nmapCveCount > 0 ? <AlertTriangle className="h-5 w-5 text-red-400" /> : <CheckCircle2 className="h-5 w-5 text-emerald-400" />}</div></div></CardContent></Card></motion.div>
                    <motion.div custom={3} variants={cardVariants}><Card className="hover:border-primary/30 transition-colors"><CardContent className="p-4 sm:p-6"><div className="flex items-center justify-between"><div><p className="text-sm text-muted-foreground">Target</p><p className="text-lg font-semibold mt-1 font-mono truncate max-w-[180px]">{nmapResult.target || 'N/A'}</p></div><div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center"><Server className="h-5 w-5 text-primary" /></div></div><p className="text-xs text-muted-foreground mt-2">{nmapResult.ports?.length ?? 0} total ports scanned</p></CardContent></Card></motion.div>
                  </div>
                  <motion.div custom={4} variants={cardVariants}>
                    <Card>
                      <CardHeader><CardTitle className="text-base flex items-center gap-2"><Server className="h-4 w-4 text-primary" />Port Scan Results</CardTitle><CardDescription>Discovered services on {nmapResult.target || 'target'} (real nmap output)</CardDescription></CardHeader>
                      <CardContent>
                        {nmapResult.ports && nmapResult.ports.length > 0 ? (
                          <div className="max-h-96 overflow-y-auto custom-scrollbar"><Table><TableHeader><TableRow><TableHead>Port</TableHead><TableHead>Protocol</TableHead><TableHead>State</TableHead><TableHead>Service</TableHead><TableHead>Version</TableHead></TableRow></TableHeader><TableBody>{nmapResult.ports.map((port, idx) => (
                            <TableRow key={`${port.port_id}-${port.protocol}-${idx}`}><TableCell className="font-mono font-medium">{port.port_id ?? '—'}</TableCell><TableCell className="font-mono text-muted-foreground">{port.protocol || '—'}</TableCell><TableCell><Badge variant="outline" className={stateColor(port.state || '')}>{port.state || 'unknown'}</Badge></TableCell><TableCell>{port.service || 'unknown'}</TableCell><TableCell className="text-muted-foreground text-xs max-w-[200px] truncate">{port.version || 'Unknown'}</TableCell></TableRow>
                          ))}</TableBody></Table></div>
                        ) : (
                          <div className="text-center py-8"><WifiOff className="h-10 w-10 text-muted-foreground/30 mx-auto mb-3" /><p className="text-sm text-muted-foreground font-medium">No ports found.</p></div>
                        )}
                      </CardContent>
                    </Card>
                  </motion.div>
                  <motion.div custom={5} variants={cardVariants}>
                    <Card>
                      <CardHeader><CardTitle className="text-base flex items-center gap-2">{nmapVulnCount > 0 ? <AlertTriangle className="h-4 w-4 text-orange-400" /> : <CheckCircle2 className="h-4 w-4 text-emerald-400" />}Vulnerabilities</CardTitle><CardDescription>Security issues from nmap vuln scripts</CardDescription></CardHeader>
                      <CardContent>
                        {nmapResult.vulnerabilities && nmapResult.vulnerabilities.length > 0 ? (
                          <div className="space-y-3 max-h-96 overflow-y-auto custom-scrollbar pr-1">{nmapResult.vulnerabilities.map((vuln, idx) => (
                            <motion.div key={`${vuln.cve_id}-${vuln.port_id}-${idx}`} initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: idx * 0.04, duration: 0.3 }}>
                              <div className="rounded-lg border border-border/50 bg-muted/30 p-4 hover:bg-muted/50 transition-colors">
                                <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-3"><Badge variant="destructive" className="font-mono text-xs shrink-0 w-fit">{vuln.cve_id || 'UNKNOWN-CVE'}</Badge><Badge variant="outline" className="text-xs w-fit">Port {vuln.port_id ?? '?'}</Badge></div>
                                <p className="text-sm text-muted-foreground mt-2 leading-relaxed">{vuln.description || 'No description available'}</p>
                              </div>
                            </motion.div>
                          ))}</div>
                        ) : (
                          <div className="text-center py-8"><Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30 text-sm px-4 py-1.5"><CheckCircle2 className="h-4 w-4 mr-2" />Secure — No vulnerabilities detected</Badge></div>
                        )}
                      </CardContent>
                    </Card>
                  </motion.div>
                </>
              )}

              {/* Nikto Results */}
              {niktoResult && (
                <>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
                    <motion.div custom={0} variants={cardVariants}><Card className="hover:border-primary/30 transition-colors"><CardContent className="p-4 sm:p-6"><div className="flex items-center justify-between"><div><p className="text-sm text-muted-foreground">Findings</p><p className="text-3xl font-bold mt-1">{niktoFindingsCount}</p></div><div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center"><FileWarning className="h-5 w-5 text-primary" /></div></div></CardContent></Card></motion.div>
                    <motion.div custom={1} variants={cardVariants}><Card className="border-red-500/20 bg-red-500/5"><CardContent className="p-4 sm:p-6"><div className="flex items-center justify-between"><div><p className="text-sm text-muted-foreground">High</p><p className="text-3xl font-bold mt-1 text-red-400">{niktoSummary.high}</p></div><div className="h-10 w-10 rounded-lg bg-red-500/10 flex items-center justify-center"><AlertTriangle className="h-5 w-5 text-red-400" /></div></div></CardContent></Card></motion.div>
                    <motion.div custom={2} variants={cardVariants}><Card className="border-orange-500/20 bg-orange-500/5"><CardContent className="p-4 sm:p-6"><div className="flex items-center justify-between"><div><p className="text-sm text-muted-foreground">Medium</p><p className="text-3xl font-bold mt-1 text-orange-400">{niktoSummary.medium}</p></div><div className="h-10 w-10 rounded-lg bg-orange-500/10 flex items-center justify-center"><AlertTriangle className="h-5 w-5 text-orange-400" /></div></div></CardContent></Card></motion.div>
                    <motion.div custom={3} variants={cardVariants}><Card className="border-yellow-500/20 bg-yellow-500/5"><CardContent className="p-4 sm:p-6"><div className="flex items-center justify-between"><div><p className="text-sm text-muted-foreground">Low / Info</p><p className="text-3xl font-bold mt-1 text-yellow-400">{niktoSummary.low + niktoSummary.info}</p></div><div className="h-10 w-10 rounded-lg bg-yellow-500/10 flex items-center justify-center"><Info className="h-5 w-5 text-yellow-400" /></div></div></CardContent></Card></motion.div>
                    <motion.div custom={4} variants={cardVariants}><Card className={niktoVulnCount > 0 ? 'border-red-500/20' : 'border-emerald-500/20'}><CardContent className="p-4 sm:p-6"><div className="flex items-center justify-between"><div><p className="text-sm text-muted-foreground">CVEs</p><p className={`text-3xl font-bold mt-1 ${niktoVulnCount > 0 ? 'text-red-400' : 'text-emerald-400'}`}>{niktoVulnCount}</p></div><div className={`h-10 w-10 rounded-lg flex items-center justify-center ${niktoVulnCount > 0 ? 'bg-red-500/10' : 'bg-emerald-500/10'}`}>{niktoVulnCount > 0 ? <Bug className="h-5 w-5 text-red-400" /> : <CheckCircle2 className="h-5 w-5 text-emerald-400" />}</div></div></CardContent></Card></motion.div>
                  </div>

                  {/* Nikto Findings List */}
                  <motion.div custom={5} variants={cardVariants}>
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-base flex items-center gap-2"><Globe className="h-4 w-4 text-primary" />Nikto Web Findings</CardTitle>
                        <CardDescription>Web vulnerability findings from Nikto scan on {niktoResult.target || 'target'} {niktoResult.server && niktoResult.server !== 'Unknown' && <span>(Server: <span className="font-mono">{niktoResult.server}</span>)</span>}</CardDescription>
                      </CardHeader>
                      <CardContent>
                        {niktoResult.findings && niktoResult.findings.length > 0 ? (
                          <div className="space-y-3 max-h-[500px] overflow-y-auto custom-scrollbar pr-1">
                            {niktoResult.findings.map((finding, idx) => {
                              const isInfo = finding.description.toLowerCase().includes('suggested security header') || finding.description.toLowerCase().includes('uncommon header')
                              const isLow = finding.description.toLowerCase().includes('outdated') || finding.description.toLowerCase().includes('mod_negotiation')
                              const isHigh = finding.description.toLowerCase().includes('xss') || finding.description.toLowerCase().includes('sql') || finding.description.toLowerCase().includes('injection') || finding.description.toLowerCase().includes('rce') || finding.description.toLowerCase().includes('remote code')
                              const severity = isHigh ? 'high' : (finding.references.length > 0 && !isInfo && !isLow) ? 'medium' : isLow ? 'low' : 'info'
                              return (
                                <motion.div key={finding.id} initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: idx * 0.03, duration: 0.3 }}>
                                  <div className="rounded-lg border border-border/50 bg-muted/30 p-4 hover:bg-muted/50 transition-colors">
                                    <div className="flex flex-col sm:flex-row sm:items-start gap-2 sm:gap-3">
                                      <div className="flex items-center gap-2 shrink-0">
                                        <Badge variant="outline" className={severityColor(severity)}>{severity.toUpperCase()}</Badge>
                                        <Badge variant="outline" className="text-xs font-mono">Port {finding.port}</Badge>
                                      </div>
                                      <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2 mb-1">
                                          <span className="font-mono text-xs bg-muted px-1.5 py-0.5 rounded">{finding.method}</span>
                                          <span className="font-mono text-xs text-muted-foreground truncate">{finding.path}</span>
                                        </div>
                                        <p className="text-sm text-muted-foreground leading-relaxed">{finding.description}</p>
                                        {finding.references.length > 0 && (
                                          <div className="mt-2 flex flex-wrap gap-1.5">
                                            {finding.references.slice(0, 3).map((ref, rIdx) => (
                                              <a key={rIdx} href={ref} target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline flex items-center gap-1">
                                                <ExternalLinkIcon className="h-3 w-3" />{ref.length > 50 ? ref.slice(0, 50) + '...' : ref}
                                              </a>
                                            ))}
                                          </div>
                                        )}
                                      </div>
                                    </div>
                                  </div>
                                </motion.div>
                              )
                            })}
                          </div>
                        ) : (
                          <div className="text-center py-8"><Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30 text-sm px-4 py-1.5"><CheckCircle2 className="h-4 w-4 mr-2" />Clean — No web findings</Badge></div>
                        )}
                      </CardContent>
                    </Card>
                  </motion.div>

                  {/* Nikto CVEs */}
                  {niktoResult.vulnerabilities && niktoResult.vulnerabilities.length > 0 && (
                    <motion.div custom={6} variants={cardVariants}>
                      <Card>
                        <CardHeader><CardTitle className="text-base flex items-center gap-2"><Bug className="h-4 w-4 text-red-400" />CVEs from Nikto</CardTitle><CardDescription>CVE references extracted from Nikto findings</CardDescription></CardHeader>
                        <CardContent>
                          <div className="space-y-3 max-h-96 overflow-y-auto custom-scrollbar pr-1">{niktoResult.vulnerabilities.map((vuln, idx) => (
                            <motion.div key={`${vuln.cve_id}-${vuln.port_id}-${idx}`} initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: idx * 0.04, duration: 0.3 }}>
                              <div className="rounded-lg border border-border/50 bg-muted/30 p-4 hover:bg-muted/50 transition-colors">
                                <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-3"><Badge variant="destructive" className="font-mono text-xs shrink-0 w-fit">{vuln.cve_id}</Badge><Badge variant="outline" className="text-xs w-fit">Port {vuln.port_id}</Badge></div>
                                <p className="text-sm text-muted-foreground mt-2 leading-relaxed">{vuln.description}</p>
                              </div>
                            </motion.div>
                          ))}</div>
                        </CardContent>
                      </Card>
                    </motion.div>
                  )}
                </>
              )}

              {/* ─── Nuclei Bug Hunt Results ──────────────────────────────────────── */}
              {nucleiResult && nucleiResult.findings.length > 0 && (
                <motion.div variants={staggerContainer} initial="hidden" animate="visible" className="space-y-4">
                  {/* Nuclei Summary Stats */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
                    {[
                      { label: 'Critical', value: nucleiSummary.critical, color: 'text-red-500' },
                      { label: 'High', value: nucleiSummary.high, color: 'text-red-400' },
                      { label: 'Medium', value: nucleiSummary.medium, color: 'text-orange-400' },
                      { label: 'Low', value: nucleiSummary.low, color: 'text-yellow-400' },
                      { label: 'Info', value: nucleiSummary.info, color: 'text-blue-400' },
                      { label: 'Total', value: nucleiSummary.total, color: 'text-foreground' },
                      { label: 'With curl', value: nucleiSummary.withCurlCommand, color: 'text-emerald-400' },
                      { label: 'Extracted', value: nucleiSummary.withExtractedResults, color: 'text-cyan-400' },
                    ].map(stat => (
                      <motion.div key={stat.label} variants={staggerItem}>
                        <Card className="border-border/50">
                          <CardContent className="p-3 text-center">
                            <div className={`text-2xl font-bold ${stat.color}`}>{stat.value}</div>
                            <div className="text-xs text-muted-foreground">{stat.label}</div>
                          </CardContent>
                        </Card>
                      </motion.div>
                    ))}
                  </div>

                  {/* Nuclei Findings List — grouped by severity */}
                  {['critical', 'high', 'medium', 'low', 'info'].map(sev => {
                    const sevFindings = nucleiResult.findings.filter(f => f.severity === sev)
                    if (sevFindings.length === 0) return null
                    return (
                      <div key={sev} className="space-y-3">
                        <h3 className="text-sm font-semibold flex items-center gap-2">
                          <Badge variant="outline" className={severityColor(sev)}>{sev.toUpperCase()}</Badge>
                          <span className="text-muted-foreground">{sevFindings.length} finding{sevFindings.length !== 1 ? 's' : ''}</span>
                        </h3>
                        <div className="space-y-2 max-h-[600px] overflow-y-auto">
                          {sevFindings.map((finding, idx) => (
                            <motion.div key={`${finding.templateId}-${idx}`} variants={staggerItem}>
                              <Card className="border-border/50 hover:border-border transition-colors">
                                <CardContent className="p-4 space-y-3">
                                  {/* Finding Header */}
                                  <div className="flex flex-col sm:flex-row sm:items-start gap-2">
                                    <div className="flex-1 min-w-0">
                                      <div className="flex items-center gap-2 flex-wrap">
                                        <Badge variant="outline" className={severityColor(finding.severity)}>{finding.severity.toUpperCase()}</Badge>
                                        <Badge variant="outline" className="text-xs bg-muted/50">{finding.type.toUpperCase()}</Badge>
                                        <span className="font-semibold text-sm">{finding.name}</span>
                                      </div>
                                      <p className="text-xs text-muted-foreground font-mono mt-1">{finding.templateId}</p>
                                    </div>
                                  </div>

                                  {/* Matched At */}
                                  {finding.matchedAt && (
                                    <div className="flex items-start gap-2">
                                      <ExternalLink className="h-3.5 w-3.5 text-muted-foreground mt-0.5 shrink-0" />
                                      <p className="text-sm font-mono text-primary break-all">{finding.matchedAt}</p>
                                    </div>
                                  )}

                                  {/* Curl Reproduction Command */}
                                  {finding.curlCommand && (
                                    <div className="rounded-md bg-zinc-950 border border-zinc-800 p-3 relative group">
                                      <div className="flex items-center gap-1.5 mb-1.5">
                                        <Terminal className="h-3.5 w-3.5 text-emerald-400" />
                                        <span className="text-xs text-emerald-400 font-semibold">Reproduce with curl</span>
                                      </div>
                                      <pre className="text-xs font-mono text-zinc-300 whitespace-pre-wrap break-all">{finding.curlCommand}</pre>
                                      <button
                                        onClick={() => copyToClipboard(finding.curlCommand!, `nuclei-curl-${idx}`)}
                                        className="absolute top-2 right-2 p-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-400 hover:text-white transition-colors opacity-0 group-hover:opacity-100"
                                        aria-label="Copy curl command"
                                      >
                                        {copiedIdx === `nuclei-curl-${idx}` ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                                      </button>
                                    </div>
                                  )}

                                  {/* Extracted Results */}
                                  {finding.extractedResults.length > 0 && (
                                    <div className="space-y-1.5">
                                      <div className="flex items-center gap-1.5">
                                        <Zap className="h-3.5 w-3.5 text-amber-400" />
                                        <span className="text-xs text-amber-400 font-semibold">Extracted Data</span>
                                      </div>
                                      <div className="flex flex-wrap gap-1.5">
                                        {finding.extractedResults.map((er, erIdx) => (
                                          <span key={erIdx} className="inline-block text-xs font-mono bg-amber-500/10 text-amber-300 border border-amber-500/30 rounded px-2 py-0.5 break-all max-w-full">{er}</span>
                                        ))}
                                      </div>
                                    </div>
                                  )}

                                  {/* Tags */}
                                  {finding.tags.length > 0 && (
                                    <div className="flex flex-wrap gap-1">
                                      {finding.tags.map((tag, tagIdx) => (
                                        <Badge key={tagIdx} variant="outline" className="text-xs bg-muted/30">{tag}</Badge>
                                      ))}
                                    </div>
                                  )}

                                  {/* References */}
                                  {finding.reference.length > 0 && (
                                    <div className="flex flex-wrap gap-1.5">
                                      {finding.reference.slice(0, 3).map((ref, refIdx) => (
                                        <a key={refIdx} href={ref} target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline flex items-center gap-1">
                                          <ExternalLinkIcon className="h-3 w-3" />{ref.length > 50 ? ref.slice(0, 50) + '...' : ref}
                                        </a>
                                      ))}
                                    </div>
                                  )}
                                </CardContent>
                              </Card>
                            </motion.div>
                          ))}
                        </div>
                      </div>
                    )
                  })}
                </motion.div>
              )}

              {/* Scan Info Card */}
              <motion.div custom={7} variants={cardVariants}>
                <Card>
                  <CardHeader><CardTitle className="text-base flex items-center gap-2"><Info className="h-4 w-4 text-muted-foreground" />Scan Information</CardTitle></CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                      <div><span className="text-muted-foreground">Target:</span> <span className="font-mono">{scanResult?.target || 'N/A'}</span></div>
                      <div><span className="text-muted-foreground">Engine:</span> <span className="font-mono">{isNucleiResult(scanResult) ? 'Nuclei (Bug Hunter)' : isNiktoResult(scanResult) ? 'Nikto (Web Scanner)' : 'Nmap (Network Scanner)'}</span></div>
                      {isNiktoResult(scanResult) && niktoResult?.server && niktoResult.server !== 'Unknown' && (
                        <div><span className="text-muted-foreground">Server:</span> <span className="font-mono">{niktoResult.server}</span></div>
                      )}
                      {!isNiktoResult(scanResult) && !isNucleiResult(scanResult) && (
                        <>
                          <div><span className="text-muted-foreground">Ports Found:</span> <span className="font-mono">{nmapResult?.ports?.length ?? 0}</span></div>
                          <div><span className="text-muted-foreground">Open Ports:</span> <span className="font-mono text-emerald-400">{openPortCount}</span></div>
                        </>
                      )}
                      <div><span className="text-muted-foreground">Vulnerabilities:</span> <span className={`font-mono ${vulnCount > 0 ? 'text-orange-400' : 'text-emerald-400'}`}>{vulnCount}</span></div>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>

              {/* ─── AI Auto-Remediation Engine ─────────────────────────────── */}
              <motion.div custom={8} variants={cardVariants}>
                <Card className="border-amber-500/30 bg-gradient-to-br from-amber-500/5 via-transparent to-transparent">
                  <CardHeader>
                    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                      <div>
                        <CardTitle className="text-base flex items-center gap-2">
                          <Sparkles className="h-4 w-4 text-amber-400" />
                          AI Auto-Remediation Engine
                        </CardTitle>
                        <CardDescription className="mt-1">Get plain-English explanations and copy-paste fix commands for every finding</CardDescription>
                      </div>
                      {!remediation && !isRemediating && (
                        <Button onClick={handleGetRemediation} className="bg-amber-600 hover:bg-amber-700 text-white min-w-[200px]">
                          <Zap className="h-4 w-4 mr-2" />Generate AI Remediation
                        </Button>
                      )}
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {/* Loading state */}
                    {isRemediating && (
                      <div className="space-y-4 py-4">
                        <div className="flex items-center gap-3">
                          <div className="relative">
                            <Sparkles className="h-5 w-5 text-amber-400 animate-pulse" />
                          </div>
                          <div>
                            <p className="text-sm font-medium">AI is analyzing your findings...</p>
                            <p className="text-xs text-muted-foreground">Generating plain-English explanations and fix commands</p>
                          </div>
                        </div>
                        <div className="relative h-2 w-full overflow-hidden rounded-full bg-amber-500/10">
                          <div className="absolute inset-0 h-full w-1/3 rounded-full bg-amber-500 animate-indeterminate" />
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                          {[1,2,3].map(i => (
                            <div key={i} className="rounded-lg border border-border/30 bg-muted/20 p-4 space-y-2">
                              <div className="h-4 w-3/4 bg-muted/40 rounded animate-pulse" />
                              <div className="h-3 w-full bg-muted/30 rounded animate-pulse" />
                              <div className="h-3 w-5/6 bg-muted/30 rounded animate-pulse" />
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Error state */}
                    {remediationError && !isRemediating && (
                      <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-4">
                        <div className="flex items-start gap-3">
                          <AlertCircle className="h-5 w-5 text-red-400 mt-0.5 shrink-0" />
                          <div>
                            <p className="text-sm font-medium text-red-400">Remediation Engine Error</p>
                            <p className="text-xs text-muted-foreground mt-1">{remediationError}</p>
                            <Button variant="outline" size="sm" onClick={handleGetRemediation} className="mt-3 text-xs">
                              <RotateCcw className="h-3 w-3 mr-1" />Retry
                            </Button>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Remediation Results */}
                    {remediation && !isRemediating && (
                      <div className="space-y-6">
                        {/* Summary & Risk Level */}
                        <div className="flex flex-col sm:flex-row gap-4">
                          <div className="flex-1 rounded-lg border border-border/50 bg-muted/20 p-4">
                            <div className="flex items-center gap-2 mb-2">
                              <AlertTriangle className="h-4 w-4 text-amber-400" />
                              <span className="text-sm font-semibold">Executive Summary</span>
                            </div>
                            <p className="text-sm text-muted-foreground leading-relaxed">{remediation.summary}</p>
                          </div>
                          <div className="shrink-0 rounded-lg border border-border/50 bg-muted/20 p-4 flex flex-col items-center justify-center min-w-[140px]">
                            <span className="text-xs text-muted-foreground mb-1">Risk Level</span>
                            <Badge variant="outline" className={`text-sm px-3 py-1 ${riskLevelColor(remediation.risk_level)}`}>
                              {remediation.risk_level}
                            </Badge>
                          </div>
                        </div>

                        {/* Individual Remediations */}
                        {remediation.remediations.length > 0 && (
                          <div>
                            <h4 className="text-sm font-semibold flex items-center gap-2 mb-3">
                              <Wrench className="h-4 w-4 text-amber-400" />
                              Remediation Steps ({remediation.remediations.length})
                            </h4>
                            <div className="space-y-4 max-h-[600px] overflow-y-auto custom-scrollbar pr-1">
                              {remediation.remediations.map((item, idx) => (
                                <motion.div
                                  key={idx}
                                  initial={{ opacity: 0, y: 8 }}
                                  animate={{ opacity: 1, y: 0 }}
                                  transition={{ delay: idx * 0.05, duration: 0.3 }}
                                >
                                  <div className="rounded-lg border border-border/50 bg-muted/20 p-4 hover:bg-muted/30 transition-colors">
                                    {/* Finding title + severity */}
                                    <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-3 mb-3">
                                      <Badge variant="outline" className={severityColor(item.severity)}>{item.severity}</Badge>
                                      <h5 className="text-sm font-semibold">{item.finding}</h5>
                                    </div>

                                    {/* Plain English explanation */}
                                    <div className="mb-3">
                                      <p className="text-sm text-muted-foreground leading-relaxed">{item.explanation}</p>
                                    </div>

                                    {/* Fix commands */}
                                    {item.fix_commands && item.fix_commands.length > 0 && (
                                      <div className="space-y-2">
                                        <span className="text-xs font-medium text-muted-foreground flex items-center gap-1.5">
                                          <Terminal className="h-3.5 w-3.5" />Fix Commands
                                        </span>
                                        {item.fix_commands.map((cmd, cmdIdx) => (
                                          <div key={cmdIdx} className="relative group">
                                            <pre className="rounded-md bg-zinc-950 border border-zinc-800 p-3 pr-10 text-xs text-emerald-400 font-mono overflow-x-auto whitespace-pre-wrap break-all">
                                              {cmd}
                                            </pre>
                                            <button
                                              onClick={() => copyToClipboard(cmd, `${idx}-${cmdIdx}`)}
                                              className="absolute top-2 right-2 p-1.5 rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-400 hover:text-white transition-colors opacity-0 group-hover:opacity-100 focus:opacity-100"
                                              aria-label="Copy command"
                                            >
                                              {copiedIdx === `${idx}-${cmdIdx}` ? (
                                                <Check className="h-3.5 w-3.5 text-emerald-400" />
                                              ) : (
                                                <Copy className="h-3.5 w-3.5" />
                                              )}
                                            </button>
                                          </div>
                                        ))}
                                      </div>
                                    )}

                                    {/* References */}
                                    {item.references && item.references.length > 0 && (
                                      <div className="mt-3 flex flex-wrap gap-1.5">
                                        {item.references.slice(0, 3).map((ref, rIdx) => (
                                          <a key={rIdx} href={ref} target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline flex items-center gap-1">
                                            <ExternalLinkIcon className="h-3 w-3" />{ref.length > 50 ? ref.slice(0, 50) + '...' : ref}
                                          </a>
                                        ))}
                                      </div>
                                    )}
                                  </div>
                                </motion.div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Hardening Recommendations */}
                        {remediation.hardening_recommendations && remediation.hardening_recommendations.length > 0 && (
                          <div>
                            <h4 className="text-sm font-semibold flex items-center gap-2 mb-3">
                              <Shield className="h-4 w-4 text-emerald-400" />
                              Hardening Recommendations
                            </h4>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                              {remediation.hardening_recommendations.map((rec, idx) => (
                                <div key={idx} className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3 flex items-start gap-2">
                                  <CheckCircle2 className="h-4 w-4 text-emerald-400 mt-0.5 shrink-0" />
                                  <span className="text-sm text-muted-foreground">{rec}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Raw response fallback */}
                        {remediation.raw_response && (
                          <details className="rounded-lg border border-border/30 bg-muted/10">
                            <summary className="p-3 text-xs text-muted-foreground cursor-pointer hover:text-foreground transition-colors">Raw AI Response</summary>
                            <div className="p-3 pt-0">
                              <pre className="text-xs text-muted-foreground whitespace-pre-wrap break-words max-h-64 overflow-y-auto custom-scrollbar">{remediation.raw_response}</pre>
                            </div>
                          </details>
                        )}

                        {/* Regenerate button */}
                        <div className="flex justify-center pt-2">
                          <Button variant="outline" onClick={handleGetRemediation} className="text-xs">
                            <RotateCcw className="h-3.5 w-3.5 mr-1.5" />Regenerate Remediation
                          </Button>
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Scan History */}
        {scanHistory.length > 0 && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, delay: 0.3 }}>
            <Card>
              <CardHeader><CardTitle className="text-base">Scan History</CardTitle><CardDescription>Previous scans in this session</CardDescription></CardHeader>
              <CardContent>
                <div className="space-y-2 max-h-64 overflow-y-auto custom-scrollbar">
                  {scanHistory.map((entry, idx) => (
                    <motion.div key={entry.id} variants={staggerItem} initial="hidden" animate="visible" transition={{ delay: idx * 0.05 }}>
                      <button onClick={() => loadHistoryResult(entry)} disabled={!entry.results} className="w-full flex items-center gap-3 p-3 rounded-lg border border-border/50 bg-muted/20 hover:bg-muted/40 transition-colors disabled:opacity-50 disabled:cursor-not-allowed text-left">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-sm font-medium truncate">{entry.target}</span>
                            <Badge variant="outline" className={entry.scanType === 'nikto' ? 'bg-purple-500/10 text-purple-400 border-purple-500/30 text-xs' : 'bg-primary/10 text-primary border-primary/30 text-xs'}>
                              {entry.scanType}
                            </Badge>
                            <Badge variant="outline" className={entry.status === 'completed' ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' : entry.status === 'running' || entry.status === 'pending' ? 'bg-primary/20 text-primary border-primary/30' : 'bg-red-500/20 text-red-400 border-red-500/30'}>
                              {(entry.status === 'running' || entry.status === 'pending') && <span className="h-1.5 w-1.5 bg-primary rounded-full animate-pulse-dot mr-1" />}{entry.status}
                            </Badge>
                          </div>
                          <p className="text-xs text-muted-foreground mt-0.5">{new Date(entry.timestamp).toLocaleString()}</p>
                        </div>
                        {entry.results && <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />}
                      </button>
                    </motion.div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}

        {/* Empty state */}
        {!scanResult && !isScanning && scanHistory.length === 0 && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.5 }} className="text-center py-16">
            <Shield className="h-16 w-16 text-muted-foreground/20 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-muted-foreground">No scan results yet</h3>
            <p className="text-sm text-muted-foreground/60 mt-1">Choose a scan engine and enter a target to start scanning</p>
            <div className="mt-4 flex items-center justify-center gap-2 text-xs text-muted-foreground/40">
              <Badge variant="outline" className="text-xs">100% Real Data</Badge>
              <Badge variant="outline" className="text-xs">Nmap</Badge>
              <Badge variant="outline" className="text-xs">Nikto</Badge>
              <Badge variant="outline" className="text-xs">No Simulation</Badge>
            </div>
          </motion.div>
        )}
      </main>
      <footer className="mt-auto border-t border-border/50 bg-card/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-muted-foreground">
            <span className="flex items-center gap-1.5"><Shield className="h-3.5 w-3.5 text-primary" />VulnGuard &copy; 2025 — Real Nmap + Nikto + Nuclei + AI Remediation</span>
            <span className="flex items-center gap-1.5"><Sparkles className="h-3 w-3 text-amber-400" />AI-powered explanations and fix commands — For authorized security testing only</span>
          </div>
        </div>
      </footer>
    </div>
  )
}
