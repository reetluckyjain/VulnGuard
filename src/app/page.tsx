'use client'

import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Shield,
  Search,
  Server,
  AlertTriangle,
  Clock,
  ChevronRight,
  RotateCcw,
  ExternalLink,
  AlertCircle,
} from 'lucide-react'

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Separator } from '@/components/ui/separator'
import { toast } from '@/hooks/use-toast'

// ─── Types ───────────────────────────────────────────────────────────────────

interface PortResult {
  port_number: number
  protocol: string
  state: string
  service_name: string
  version: string
}

interface VulnerabilityResult {
  cve_id: string
  description: string
  port: number
  severity: 'Critical' | 'High' | 'Medium' | 'Low'
}

interface ScanResult {
  target: string
  scan_time: string
  ports: PortResult[]
  vulnerabilities: VulnerabilityResult[]
}

interface ScanHistoryEntry {
  id: string
  target: string
  status: 'running' | 'completed' | 'failed'
  timestamp: string
  results?: ScanResult
}

// ─── Severity Helpers ────────────────────────────────────────────────────────

function severityColor(severity: VulnerabilityResult['severity']): string {
  switch (severity) {
    case 'Critical':
      return 'bg-red-500/20 text-red-400 border-red-500/30'
    case 'High':
      return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
    case 'Medium':
      return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    case 'Low':
      return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
  }
}

function severityDot(severity: VulnerabilityResult['severity']): string {
  switch (severity) {
    case 'Critical':
      return 'bg-red-500'
    case 'High':
      return 'bg-orange-500'
    case 'Medium':
      return 'bg-yellow-500'
    case 'Low':
      return 'bg-emerald-500'
  }
}

function stateColor(state: string): string {
  switch (state.toLowerCase()) {
    case 'open':
      return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
    case 'closed':
      return 'bg-red-500/20 text-red-400 border-red-500/30'
    case 'filtered':
      return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    default:
      return 'bg-muted text-muted-foreground border-border'
  }
}

// ─── Animation Variants ─────────────────────────────────────────────────────

const cardVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: {
      delay: i * 0.1,
      duration: 0.4,
      ease: 'easeOut',
    },
  }),
}

const staggerContainer = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.08,
    },
  },
}

const staggerItem = {
  hidden: { opacity: 0, x: -10 },
  visible: { opacity: 1, x: 0, transition: { duration: 0.3 } },
}

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function Home() {
  const [target, setTarget] = useState('')
  const [isAuthorized, setIsAuthorized] = useState(false)
  const [validationError, setValidationError] = useState('')
  const [isScanning, setIsScanning] = useState(false)
  const [currentScanTarget, setCurrentScanTarget] = useState('')
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [scanHistory, setScanHistory] = useState<ScanHistoryEntry[]>([])
  const [activeScanId, setActiveScanId] = useState<string | null>(null)
  const [pollCount, setPollCount] = useState(0)

  // ─── Start Scan ─────────────────────────────────────────────────────────

  const startScan = useCallback(async () => {
    // Validation
    if (!target.trim()) {
      setValidationError('Please enter a target IP or hostname')
      return
    }

    // Basic IP/hostname validation
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/
    const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/

    if (!ipRegex.test(target.trim()) && !hostnameRegex.test(target.trim())) {
      setValidationError('Please enter a valid IP address or hostname')
      return
    }

    if (!isAuthorized) {
      setValidationError('You must confirm authorization before scanning')
      return
    }

    setValidationError('')
    setIsScanning(true)
    setCurrentScanTarget(target.trim())
    setScanResult(null)

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim(), isAuthorized: true }),
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.error || errorData.message || 'Scan request failed')
      }

      const data = await response.json()
      const scanId = data.scan_id

      setActiveScanId(scanId)
      setPollCount(0)

      // Add to history
      const historyEntry: ScanHistoryEntry = {
        id: scanId,
        target: target.trim(),
        status: 'running',
        timestamp: new Date().toISOString(),
      }
      setScanHistory((prev) => [historyEntry, ...prev])
    } catch (err) {
      setIsScanning(false)
      setCurrentScanTarget('')
      const message = err instanceof Error ? err.message : 'Failed to start scan'
      toast({
        title: 'Scan Failed',
        description: message,
        variant: 'destructive',
      })

      // Update history entry as failed
      setScanHistory((prev) =>
        prev.map((entry) =>
          entry.status === 'running' ? { ...entry, status: 'failed' as const } : entry
        )
      )
    }
  }, [target, isAuthorized])

  // ─── Poll for Results ───────────────────────────────────────────────────

  useEffect(() => {
    if (!activeScanId || !isScanning) return

    const pollInterval = setInterval(async () => {
      try {
        const response = await fetch(`/api/scan/${activeScanId}`)

        if (!response.ok) {
          throw new Error('Failed to fetch scan status')
        }

        const data = await response.json()
        setPollCount((prev) => prev + 1)

        if ((data.status === 'completed' || data.status === 'Completed') && data.results) {
          setScanResult(data.results)
          setIsScanning(false)
          setCurrentScanTarget('')
          setActiveScanId(null)

          // Update history entry
          setScanHistory((prev) =>
            prev.map((entry) =>
              entry.id === activeScanId
                ? { ...entry, status: 'completed' as const, results: data.results }
                : entry
            )
          )

          toast({
            title: 'Scan Complete',
            description: `Scan of ${data.results.target} completed successfully`,
          })
        } else if (data.status === 'failed' || data.status === 'Failed') {
          setIsScanning(false)
          setCurrentScanTarget('')
          setActiveScanId(null)

          setScanHistory((prev) =>
            prev.map((entry) =>
              entry.id === activeScanId ? { ...entry, status: 'failed' as const } : entry
            )
          )

          toast({
            title: 'Scan Failed',
            description: 'The scan encountered an error',
            variant: 'destructive',
          })
        }
      } catch {
        // Silently continue polling on network errors
      }
    }, 3000)

    return () => clearInterval(pollInterval)
  }, [activeScanId, isScanning])

  // ─── Load History Result ────────────────────────────────────────────────

  const loadHistoryResult = (entry: ScanHistoryEntry) => {
    if (entry.results) {
      setScanResult(entry.results)
      window.scrollTo({ top: 0, behavior: 'smooth' })
    }
  }

  // ─── Reset ──────────────────────────────────────────────────────────────

  const handleReset = () => {
    setTarget('')
    setIsAuthorized(false)
    setValidationError('')
    setScanResult(null)
  }

  // ─── Derived Stats ──────────────────────────────────────────────────────

  const criticalCount = scanResult?.vulnerabilities.filter((v) => v.severity === 'Critical').length ?? 0

  return (
    <div className="min-h-screen flex flex-col bg-background">
      {/* ── Header ──────────────────────────────────────────────────────── */}
      <header className="border-b border-border/50 bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Shield className="h-8 w-8 text-primary" />
              <div className="absolute -top-0.5 -right-0.5 h-3 w-3 bg-primary rounded-full animate-pulse-dot" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-foreground">
                VulnGuard
              </h1>
              <p className="text-xs text-muted-foreground">
                Ethical Vulnerability Scanner
              </p>
            </div>
          </div>
        </div>
      </header>

      {/* ── Main Content ────────────────────────────────────────────────── */}
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* ── Authorization Gate ───────────────────────────────────────── */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
        >
          <Card className="border-yellow-500/30 bg-yellow-500/5">
            <CardContent className="p-4 sm:p-6">
              <div className="flex items-start gap-3">
                <AlertCircle className="h-5 w-5 text-yellow-500 mt-0.5 shrink-0" />
                <div className="flex-1 space-y-3">
                  <div>
                    <h3 className="font-semibold text-yellow-400 text-sm">
                      Legal Disclaimer & Authorization Required
                    </h3>
                    <p className="text-xs text-muted-foreground mt-1">
                      Scanning networks without explicit permission is illegal in most jurisdictions.
                      You must confirm you have proper authorization before proceeding.
                    </p>
                  </div>
                  <div className="flex items-start gap-3">
                    <Checkbox
                      id="authorization"
                      checked={isAuthorized}
                      onCheckedChange={(checked) => {
                        setIsAuthorized(checked === true)
                        if (checked) setValidationError('')
                      }}
                      className="mt-0.5 data-[state=checked]:bg-yellow-500 data-[state=checked]:border-yellow-500"
                    />
                    <label
                      htmlFor="authorization"
                      className="text-sm leading-relaxed cursor-pointer select-none"
                    >
                      I confirm I have explicit authorization to scan this target. I understand that
                      unauthorized scanning is illegal.
                    </label>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* ── Scan Input Section ───────────────────────────────────────── */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.1 }}
        >
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Start New Scan</CardTitle>
              <CardDescription>
                Enter a target IP address or hostname to scan for open ports and vulnerabilities
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="flex-1">
                  <Input
                    type="text"
                    placeholder="e.g., 192.168.1.1 or example.com"
                    value={target}
                    onChange={(e) => {
                      setTarget(e.target.value)
                      if (validationError) setValidationError('')
                    }}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') startScan()
                    }}
                    disabled={isScanning}
                    className="font-mono"
                    aria-label="Target IP or hostname"
                  />
                  {validationError && (
                    <p className="text-sm text-red-400 mt-1.5 flex items-center gap-1.5">
                      <AlertCircle className="h-3.5 w-3.5" />
                      {validationError}
                    </p>
                  )}
                </div>
                <div className="flex gap-2">
                  <Button
                    onClick={startScan}
                    disabled={!isAuthorized || isScanning || !target.trim()}
                    className="bg-primary hover:bg-primary/90 text-primary-foreground min-w-[140px]"
                  >
                    {isScanning ? (
                      <span className="flex items-center gap-2">
                        <span className="h-4 w-4 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin" />
                        Scanning...
                      </span>
                    ) : (
                      <span className="flex items-center gap-2">
                        <Search className="h-4 w-4" />
                        Start Scan
                      </span>
                    )}
                  </Button>
                  {scanResult && (
                    <Button
                      variant="outline"
                      onClick={handleReset}
                      className="border-border"
                    >
                      <RotateCcw className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* ── Active Scan Status ───────────────────────────────────────── */}
        <AnimatePresence>
          {isScanning && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.3 }}
            >
              <Card className="border-primary/20 bg-primary/5">
                <CardContent className="p-4 sm:p-6 space-y-4">
                  <div className="flex items-center gap-3">
                    <div className="relative">
                      <div className="h-3 w-3 bg-emerald-500 rounded-full animate-pulse-dot" />
                      <div className="absolute inset-0 h-3 w-3 bg-emerald-500 rounded-full animate-ping opacity-30" />
                    </div>
                    <span className="text-sm font-medium">
                      Scanning <span className="font-mono text-primary">{currentScanTarget}</span>...
                    </span>
                    <span className="text-xs text-muted-foreground ml-auto">
                      Poll #{pollCount}
                    </span>
                  </div>
                  <div className="relative h-2 w-full overflow-hidden rounded-full bg-primary/10">
                    <div className="absolute inset-0 h-full w-1/3 rounded-full bg-primary animate-indeterminate" />
                  </div>
                  <p className="text-xs text-muted-foreground">
                    This may take a few minutes. Results will appear automatically when the scan completes.
                  </p>
                </CardContent>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ── Results Dashboard ────────────────────────────────────────── */}
        <AnimatePresence>
          {scanResult && !isScanning && (
            <motion.div
              variants={staggerContainer}
              initial="hidden"
              animate="visible"
              className="space-y-8"
            >
              {/* ── Summary Cards ──────────────────────────────────────── */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                {/* Open Ports */}
                <motion.div custom={0} variants={cardVariants}>
                  <Card className="hover:border-primary/30 transition-colors">
                    <CardContent className="p-4 sm:p-6">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm text-muted-foreground">Open Ports</p>
                          <p className="text-3xl font-bold mt-1">
                            {scanResult.ports.filter((p) => p.state.toLowerCase() === 'open').length}
                          </p>
                        </div>
                        <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
                          <Server className="h-5 w-5 text-primary" />
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>

                {/* Vulnerabilities */}
                <motion.div custom={1} variants={cardVariants}>
                  <Card className="hover:border-orange-500/30 transition-colors">
                    <CardContent className="p-4 sm:p-6">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm text-muted-foreground">Vulnerabilities</p>
                          <p className="text-3xl font-bold mt-1">
                            {scanResult.vulnerabilities.length}
                          </p>
                        </div>
                        <div className="h-10 w-10 rounded-lg bg-orange-500/10 flex items-center justify-center">
                          <AlertTriangle className="h-5 w-5 text-orange-400" />
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>

                {/* Critical */}
                <motion.div custom={2} variants={cardVariants}>
                  <Card className="border-red-500/20 hover:border-red-500/40 transition-colors bg-red-500/5">
                    <CardContent className="p-4 sm:p-6">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm text-muted-foreground">Critical</p>
                          <p className="text-3xl font-bold mt-1 text-red-400">
                            {criticalCount}
                          </p>
                        </div>
                        <div className="h-10 w-10 rounded-lg bg-red-500/10 flex items-center justify-center">
                          <AlertTriangle className="h-5 w-5 text-red-400" />
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>

                {/* Scan Time */}
                <motion.div custom={3} variants={cardVariants}>
                  <Card className="hover:border-primary/30 transition-colors">
                    <CardContent className="p-4 sm:p-6">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm text-muted-foreground">Scan Time</p>
                          <p className="text-lg font-semibold mt-1">
                            {scanResult.scan_time
                              ? new Date(scanResult.scan_time).toLocaleString()
                              : 'N/A'}
                          </p>
                        </div>
                        <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
                          <Clock className="h-5 w-5 text-primary" />
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>
              </div>

              {/* ── Open Ports Table ───────────────────────────────────── */}
              <motion.div custom={4} variants={cardVariants}>
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <Server className="h-4 w-4 text-primary" />
                      Open Ports
                    </CardTitle>
                    <CardDescription>
                      Discovered network services on {scanResult.target}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {scanResult.ports.length > 0 ? (
                      <div className="max-h-96 overflow-y-auto custom-scrollbar">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Port</TableHead>
                              <TableHead>Protocol</TableHead>
                              <TableHead>State</TableHead>
                              <TableHead>Service</TableHead>
                              <TableHead>Version</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {scanResult.ports.map((port, idx) => (
                              <TableRow key={idx}>
                                <TableCell className="font-mono font-medium">
                                  {port.port_number}
                                </TableCell>
                                <TableCell className="font-mono text-muted-foreground">
                                  {port.protocol}
                                </TableCell>
                                <TableCell>
                                  <Badge
                                    variant="outline"
                                    className={stateColor(port.state)}
                                  >
                                    {port.state}
                                  </Badge>
                                </TableCell>
                                <TableCell>{port.service_name}</TableCell>
                                <TableCell className="text-muted-foreground text-xs">
                                  {port.version || '—'}
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground text-center py-8">
                        No open ports detected
                      </p>
                    )}
                  </CardContent>
                </Card>
              </motion.div>

              {/* ── Vulnerabilities Section ────────────────────────────── */}
              <motion.div custom={5} variants={cardVariants}>
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-orange-400" />
                      Vulnerabilities
                    </CardTitle>
                    <CardDescription>
                      Security issues detected on {scanResult.target}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {scanResult.vulnerabilities.length > 0 ? (
                      <div className="space-y-3 max-h-96 overflow-y-auto custom-scrollbar pr-1">
                        {scanResult.vulnerabilities.map((vuln, idx) => (
                          <motion.div
                            key={idx}
                            initial={{ opacity: 0, y: 5 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: idx * 0.05, duration: 0.3 }}
                          >
                            <div className="rounded-lg border border-border/50 bg-muted/30 p-4 hover:bg-muted/50 transition-colors">
                              <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-3">
                                <div className="flex items-center gap-2 min-w-0">
                                  <div className={`h-2 w-2 rounded-full shrink-0 ${severityDot(vuln.severity)}`} />
                                  <Badge variant="destructive" className="font-mono text-xs shrink-0">
                                    {vuln.cve_id}
                                  </Badge>
                                </div>
                                <div className="flex items-center gap-2 sm:ml-auto shrink-0">
                                  <Badge
                                    variant="outline"
                                    className={severityColor(vuln.severity)}
                                  >
                                    {vuln.severity}
                                  </Badge>
                                  <Badge variant="outline" className="text-xs">
                                    Port {vuln.port}
                                  </Badge>
                                </div>
                              </div>
                              <p className="text-sm text-muted-foreground mt-2 leading-relaxed">
                                {vuln.description}
                              </p>
                            </div>
                          </motion.div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground text-center py-8">
                        No vulnerabilities detected
                      </p>
                    )}
                  </CardContent>
                </Card>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ── Scan History ──────────────────────────────────────────────── */}
        {scanHistory.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.3 }}
          >
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Scan History</CardTitle>
                <CardDescription>Previous scans performed in this session</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 max-h-64 overflow-y-auto custom-scrollbar">
                  {scanHistory.map((entry, idx) => (
                    <motion.div
                      key={entry.id}
                      variants={staggerItem}
                      initial="hidden"
                      animate="visible"
                      transition={{ delay: idx * 0.05 }}
                    >
                      <button
                        onClick={() => loadHistoryResult(entry)}
                        disabled={!entry.results}
                        className="w-full flex items-center gap-3 p-3 rounded-lg border border-border/50 bg-muted/20 hover:bg-muted/40 transition-colors disabled:opacity-50 disabled:cursor-not-allowed text-left"
                      >
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-sm font-medium truncate">
                              {entry.target}
                            </span>
                            <Badge
                              variant="outline"
                              className={
                                entry.status === 'completed'
                                  ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                                  : entry.status === 'running'
                                    ? 'bg-primary/20 text-primary border-primary/30'
                                    : 'bg-red-500/20 text-red-400 border-red-500/30'
                              }
                            >
                              {entry.status === 'running' && (
                                <span className="h-1.5 w-1.5 bg-primary rounded-full animate-pulse-dot mr-1" />
                              )}
                              {entry.status}
                            </Badge>
                          </div>
                          <p className="text-xs text-muted-foreground mt-0.5">
                            {new Date(entry.timestamp).toLocaleString()}
                            {entry.results && (
                              <span className="ml-2">
                                — {entry.results.ports.length} ports, {entry.results.vulnerabilities.length} vulns
                              </span>
                            )}
                          </p>
                        </div>
                        {entry.results && (
                          <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />
                        )}
                      </button>
                    </motion.div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}

        {/* ── Empty State ───────────────────────────────────────────────── */}
        {!scanResult && !isScanning && scanHistory.length === 0 && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
            className="text-center py-16"
          >
            <Shield className="h-16 w-16 text-muted-foreground/20 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-muted-foreground">
              No scan results yet
            </h3>
            <p className="text-sm text-muted-foreground/60 mt-1">
              Enter a target above and start scanning to see results
            </p>
          </motion.div>
        )}
      </main>

      {/* ── Footer ────────────────────────────────────────────────────────── */}
      <footer className="mt-auto border-t border-border/50 bg-card/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-muted-foreground">
            <span className="flex items-center gap-1.5">
              <Shield className="h-3.5 w-3.5 text-primary" />
              VulnGuard &copy; 2024
            </span>
            <span className="flex items-center gap-1.5">
              <ExternalLink className="h-3 w-3" />
              For authorized security testing only
            </span>
          </div>
        </div>
      </footer>
    </div>
  )
}
