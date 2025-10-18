import React, { useState, useEffect } from 'react'
import { 
  Globe, 
  Shield, 
  Eye, 
  Play, 
  Pause, 
  AlertTriangle, 
  CheckCircle, 
  Filter,
  Download,
  Upload,
  Search,
  Zap,
  Lock,
  Code,
  Network,
  Settings
} from 'lucide-react'
import toast from 'react-hot-toast'

interface WebProxyScannerProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

interface HttpRequest {
  id: string
  timestamp: string
  method: string
  url: string
  status: number
  contentType: string
  responseTime: number
  requestHeaders: { [key: string]: string }
  requestBody?: string
  responseHeaders: { [key: string]: string }
  responseBody: string
  vulnerabilities?: VulnerabilityFinding[]
}

interface VulnerabilityFinding {
  type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  title: string
  description: string
  evidence?: string
  solution: string
  parameter?: string
  payload?: string
}

interface ScanResult {
  totalRequests: number
  vulnerabilities: VulnerabilityFinding[]
  executiveSummary: {
    criticalCount: number
    highCount: number
    mediumCount: number
    lowCount: number
    riskScore: number
    topVulnerabilities: string[]
    recommendations: string[]
  }
}

const WebProxyScanner: React.FC<WebProxyScannerProps> = ({ onToolExecute }) => {
  const [activeTab, setActiveTab] = useState<'proxy' | 'spider' | 'scanner' | 'intruder'>('proxy')
  
  // Proxy Tab
  const [proxyHost, setProxyHost] = useState<string>('127.0.0.1')
  const [proxyPort, setProxyPort] = useState<number>(8080)
  const [isProxyRunning, setIsProxyRunning] = useState<boolean>(false)
  const [interceptEnabled, setInterceptEnabled] = useState<boolean>(false)
  const [httpHistory, setHttpHistory] = useState<HttpRequest[]>([])
  const [selectedRequest, setSelectedRequest] = useState<HttpRequest | null>(null)
  
  // Spider Tab
  const [spiderUrl, setSpiderUrl] = useState<string>('')
  const [maxDepth, setMaxDepth] = useState<number>(3)
  const [isSpiderRunning, setIsSpiderRunning] = useState<boolean>(false)
  const [discoveredUrls, setDiscoveredUrls] = useState<string[]>([])
  const [spiderProgress, setSpiderProgress] = useState<number>(0)
  
  // Scanner Tab
  const [scanTarget, setScanTarget] = useState<string>('')
  const [scanTypes, setScanTypes] = useState({
    sqli: true,
    xss: true,
    csrf: true,
    lfi: true,
    xxe: true,
    ssrf: true,
    openRedirect: true,
    commandInjection: true
  })
  const [isScanning, setIsScanning] = useState<boolean>(false)
  const [scanResults, setScanResults] = useState<ScanResult | null>(null)
  const [scanProgress, setScanProgress] = useState<number>(0)
  
  // Intruder Tab
  const [intruderUrl, setIntruderUrl] = useState<string>('')
  const [intruderPayload, setIntruderPayload] = useState<string>('')
  const [intruderPosition, setIntruderPosition] = useState<string>('')
  const [intruderType, setIntruderType] = useState<'sniper' | 'battering_ram' | 'pitchfork'>('sniper')
  const [isIntruderRunning, setIsIntruderRunning] = useState<boolean>(false)

  const vulnerabilityTypes = [
    { key: 'sqli', label: 'SQL Injection', description: 'Test for SQL injection vulnerabilities' },
    { key: 'xss', label: 'Cross-Site Scripting', description: 'Test for XSS vulnerabilities' },
    { key: 'csrf', label: 'CSRF', description: 'Test for Cross-Site Request Forgery' },
    { key: 'lfi', label: 'Local File Inclusion', description: 'Test for LFI vulnerabilities' },
    { key: 'xxe', label: 'XML External Entity', description: 'Test for XXE vulnerabilities' },
    { key: 'ssrf', label: 'Server-Side Request Forgery', description: 'Test for SSRF vulnerabilities' },
    { key: 'openRedirect', label: 'Open Redirect', description: 'Test for open redirect vulnerabilities' },
    { key: 'commandInjection', label: 'Command Injection', description: 'Test for command injection' }
  ]

  const startProxy = async () => {
    try {
      const result = await onToolExecute('start_web_proxy', {
        host: proxyHost,
        port: proxyPort,
        intercept: interceptEnabled
      })
      
      if (result.success) {
        setIsProxyRunning(true)
        toast.success(`Proxy started on ${proxyHost}:${proxyPort}`)
      }
    } catch (error) {
      console.error('Failed to start proxy:', error)
      toast.error('Failed to start proxy')
    }
  }

  const stopProxy = async () => {
    try {
      await onToolExecute('stop_web_proxy', {})
      setIsProxyRunning(false)
      toast.success('Proxy stopped')
    } catch (error) {
      console.error('Failed to stop proxy:', error)
      toast.error('Failed to stop proxy')
    }
  }

  const startSpider = async () => {
    if (!spiderUrl.trim()) {
      toast.error('Please enter a URL to spider')
      return
    }

    setIsSpiderRunning(true)
    setSpiderProgress(0)
    setDiscoveredUrls([])

    let progressInterval: NodeJS.Timeout | null = null

    try {
      // Simulate spider progress
      progressInterval = setInterval(() => {
        setSpiderProgress(prev => Math.min(prev + Math.random() * 15, 95))
      }, 1000)

      const result = await onToolExecute('spider_crawl', {
        url: spiderUrl,
        maxDepth,
        followRedirects: true
      })

      setSpiderProgress(100)

      if (result.urls) {
        setDiscoveredUrls(result.urls)
        toast.success(`Spider completed. Found ${result.urls.length} URLs`)
      }
    } catch (error) {
      console.error('Spider failed:', error)
      toast.error('Spider crawl failed')
    } finally {
      // Always clear the interval
      if (progressInterval) {
        clearInterval(progressInterval)
      }
      setIsSpiderRunning(false)
    }
  }

  const startScan = async () => {
    if (!scanTarget.trim()) {
      toast.error('Please enter a target URL to scan')
      return
    }

    setIsScanning(true)
    setScanProgress(0)

    let progressInterval: NodeJS.Timeout | null = null

    try {
      const enabledScanTypes = Object.entries(scanTypes)
        .filter(([key, enabled]) => enabled)
        .map(([key]) => key)

      // Simulate scan progress
      progressInterval = setInterval(() => {
        setScanProgress(prev => Math.min(prev + Math.random() * 8, 95))
      }, 1500)

      const result = await onToolExecute('web_vulnerability_scan', {
        target: scanTarget,
        scanTypes: enabledScanTypes,
        maxRequests: 1000
      })

      setScanProgress(100)

      if (result) {
        setScanResults(result)
        toast.success('Vulnerability scan completed')
      }
    } catch (error) {
      console.error('Scan failed:', error)
      toast.error('Vulnerability scan failed')
    } finally {
      // Always clear the interval
      if (progressInterval) {
        clearInterval(progressInterval)
      }
      setIsScanning(false)
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-500'
      case 'high': return 'text-orange-500'
      case 'medium': return 'text-yellow-500'
      case 'low': return 'text-blue-500'
      default: return 'text-gray-500'
    }
  }

  const getSeverityBg = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 border-red-500/30'
      case 'high': return 'bg-orange-500/20 border-orange-500/30'
      case 'medium': return 'bg-yellow-500/20 border-yellow-500/30'
      case 'low': return 'bg-blue-500/20 border-blue-500/30'
      default: return 'bg-gray-500/20 border-gray-500/30'
    }
  }

  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return 'text-green-400'
    if (status >= 300 && status < 400) return 'text-yellow-400'
    if (status >= 400 && status < 500) return 'text-orange-400'
    if (status >= 500) return 'text-red-400'
    return 'text-gray-400'
  }

  return (
    <div className="space-y-6">
      {/* Tab Navigation */}
      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex items-center space-x-2 mb-4">
          <Globe className="w-5 h-5 text-cyan-400" />
          <h3 className="text-lg font-medium text-white">Web Application Security Scanner</h3>
        </div>

        <div className="flex space-x-2 mb-6">
          {[
            { id: 'proxy', label: 'Proxy', icon: Network },
            { id: 'spider', label: 'Spider', icon: Search },
            { id: 'scanner', label: 'Scanner', icon: Shield },
            { id: 'intruder', label: 'Intruder', icon: Zap }
          ].map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id as any)}
              className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-colors ${
                activeTab === id
                  ? 'bg-cyan-600 text-white'
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{label}</span>
            </button>
          ))}
        </div>

        {/* Proxy Tab */}
        {activeTab === 'proxy' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Proxy Host
                </label>
                <input
                  type="text"
                  value={proxyHost}
                  onChange={(e) => setProxyHost(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Proxy Port
                </label>
                <input
                  type="number"
                  value={proxyPort}
                  onChange={(e) => setProxyPort(parseInt(e.target.value))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
              </div>

              <div className="flex items-end space-x-2">
                <button
                  onClick={isProxyRunning ? stopProxy : startProxy}
                  className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-colors ${
                    isProxyRunning
                      ? 'bg-red-600 hover:bg-red-700 text-white'
                      : 'bg-cyan-600 hover:bg-cyan-700 text-white'
                  }`}
                >
                  {isProxyRunning ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                  <span>{isProxyRunning ? 'Stop Proxy' : 'Start Proxy'}</span>
                </button>
              </div>
            </div>

            <div className="flex items-center space-x-4">
              <div className="flex items-center">
                <input
                  type="checkbox"
                  id="interceptEnabled"
                  checked={interceptEnabled}
                  onChange={(e) => setInterceptEnabled(e.target.checked)}
                  className="rounded bg-gray-700 border-gray-600"
                />
                <label htmlFor="interceptEnabled" className="ml-2 text-sm text-gray-300">
                  Enable Intercept
                </label>
              </div>

              <div className={`px-3 py-1 rounded text-sm ${
                isProxyRunning ? 'bg-green-600 text-white' : 'bg-gray-600 text-gray-300'
              }`}>
                Status: {isProxyRunning ? 'Running' : 'Stopped'}
              </div>
            </div>

            {/* HTTP History */}
            <div className="bg-gray-700 rounded-lg p-4">
              <h4 className="font-medium text-white mb-3">HTTP History</h4>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-600">
                      <th className="text-left py-2 text-gray-300">Method</th>
                      <th className="text-left py-2 text-gray-300">URL</th>
                      <th className="text-left py-2 text-gray-300">Status</th>
                      <th className="text-left py-2 text-gray-300">Length</th>
                      <th className="text-left py-2 text-gray-300">Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {httpHistory.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="py-4 text-center text-gray-400">
                          No requests captured yet. Start the proxy and configure your browser.
                        </td>
                      </tr>
                    ) : (
                      httpHistory.map((request) => (
                        <tr
                          key={request.id}
                          onClick={() => setSelectedRequest(request)}
                          className="border-b border-gray-700 hover:bg-gray-600 cursor-pointer"
                        >
                          <td className="py-2 text-cyan-400">{request.method}</td>
                          <td className="py-2 text-white truncate max-w-xs">{request.url}</td>
                          <td className={`py-2 ${getStatusColor(request.status)}`}>{request.status}</td>
                          <td className="py-2 text-gray-300">{request.responseBody.length}B</td>
                          <td className="py-2 text-gray-400">{request.responseTime}ms</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* Spider Tab */}
        {activeTab === 'spider' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Target URL
                </label>
                <input
                  type="text"
                  value={spiderUrl}
                  onChange={(e) => setSpiderUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Max Depth: {maxDepth}
                </label>
                <input
                  type="range"
                  min="1"
                  max="10"
                  value={maxDepth}
                  onChange={(e) => setMaxDepth(parseInt(e.target.value))}
                  className="w-full"
                />
              </div>

              <div className="flex items-end">
                <button
                  onClick={startSpider}
                  disabled={isSpiderRunning}
                  className="flex items-center space-x-2 px-4 py-2 bg-cyan-600 text-white rounded-md hover:bg-cyan-700 transition-colors disabled:opacity-50"
                >
                  <Search className="w-4 h-4" />
                  <span>{isSpiderRunning ? 'Crawling...' : 'Start Spider'}</span>
                </button>
              </div>
            </div>

            {/* Spider Progress */}
            {isSpiderRunning && (
              <div className="bg-gray-700 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-300">Crawl Progress</span>
                  <span className="text-sm text-gray-400">{Math.round(spiderProgress)}%</span>
                </div>
                <div className="w-full bg-gray-600 rounded-full h-2">
                  <div 
                    className="bg-cyan-600 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${spiderProgress}%` }}
                  />
                </div>
              </div>
            )}

            {/* Discovered URLs */}
            {discoveredUrls.length > 0 && (
              <div className="bg-gray-700 rounded-lg p-4">
                <h4 className="font-medium text-white mb-3">
                  Discovered URLs ({discoveredUrls.length})
                </h4>
                <div className="max-h-64 overflow-y-auto space-y-1">
                  {discoveredUrls.map((url, index) => (
                    <div key={index} className="text-sm text-cyan-400 hover:text-cyan-300">
                      {url}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Scanner Tab */}
        {activeTab === 'scanner' && (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Target URL
              </label>
              <input
                type="text"
                value={scanTarget}
                onChange={(e) => setScanTarget(e.target.value)}
                placeholder="https://example.com"
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-3">
                Vulnerability Tests
              </label>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {vulnerabilityTypes.map(({ key, label, description }) => (
                  <div key={key} className="flex items-start space-x-2">
                    <input
                      type="checkbox"
                      id={key}
                      checked={scanTypes[key as keyof typeof scanTypes]}
                      onChange={(e) => setScanTypes(prev => ({ ...prev, [key]: e.target.checked }))}
                      className="mt-1 rounded bg-gray-700 border-gray-600"
                    />
                    <div>
                      <label htmlFor={key} className="text-sm text-gray-300 cursor-pointer">
                        {label}
                      </label>
                      <p className="text-xs text-gray-500">{description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <button
              onClick={startScan}
              disabled={isScanning}
              className="flex items-center space-x-2 px-4 py-2 bg-cyan-600 text-white rounded-md hover:bg-cyan-700 transition-colors disabled:opacity-50"
            >
              {isScanning ? (
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                <Shield className="w-4 h-4" />
              )}
              <span>{isScanning ? 'Scanning...' : 'Start Scan'}</span>
            </button>

            {/* Scan Progress */}
            {isScanning && (
              <div className="bg-gray-700 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-300">Scan Progress</span>
                  <span className="text-sm text-gray-400">{Math.round(scanProgress)}%</span>
                </div>
                <div className="w-full bg-gray-600 rounded-full h-2">
                  <div 
                    className="bg-cyan-600 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${scanProgress}%` }}
                  />
                </div>
              </div>
            )}

            {/* Scan Results */}
            {scanResults && (
              <div className="bg-gray-700 rounded-lg p-4">
                <h4 className="font-medium text-white mb-4">Vulnerability Scan Results</h4>

                <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
                  <div className="bg-red-900/20 border border-red-500/30 rounded p-3 text-center">
                    <div className="text-2xl font-bold text-red-400">
                      {scanResults.executiveSummary.criticalCount}
                    </div>
                    <div className="text-sm text-red-300">Critical</div>
                  </div>
                  <div className="bg-orange-900/20 border border-orange-500/30 rounded p-3 text-center">
                    <div className="text-2xl font-bold text-orange-400">
                      {scanResults.executiveSummary.highCount}
                    </div>
                    <div className="text-sm text-orange-300">High</div>
                  </div>
                  <div className="bg-yellow-900/20 border border-yellow-500/30 rounded p-3 text-center">
                    <div className="text-2xl font-bold text-yellow-400">
                      {scanResults.executiveSummary.mediumCount}
                    </div>
                    <div className="text-sm text-yellow-300">Medium</div>
                  </div>
                  <div className="bg-blue-900/20 border border-blue-500/30 rounded p-3 text-center">
                    <div className="text-2xl font-bold text-blue-400">
                      {scanResults.executiveSummary.lowCount}
                    </div>
                    <div className="text-sm text-blue-300">Low</div>
                  </div>
                  <div className="bg-gray-600 rounded p-3 text-center">
                    <div className="text-2xl font-bold text-white">
                      {scanResults.executiveSummary.riskScore}/10
                    </div>
                    <div className="text-sm text-gray-300">Risk Score</div>
                  </div>
                </div>

                {/* Vulnerabilities List */}
                <div className="space-y-3">
                  {scanResults.vulnerabilities.map((vuln, index) => (
                    <div key={index} className={`rounded-lg border p-4 ${getSeverityBg(vuln.severity)}`}>
                      <div className="flex items-start justify-between mb-2">
                        <h5 className="font-medium text-white">{vuln.title}</h5>
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(vuln.severity)}`}>
                          {vuln.severity.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-gray-300 text-sm mb-2">{vuln.description}</p>
                      {vuln.parameter && (
                        <p className="text-gray-400 text-sm">Parameter: <span className="font-mono">{vuln.parameter}</span></p>
                      )}
                      {vuln.evidence && (
                        <div className="mt-2 p-2 bg-gray-800 rounded text-xs font-mono text-green-400">
                          {vuln.evidence}
                        </div>
                      )}
                      <div className="mt-3 p-2 bg-gray-800 rounded">
                        <p className="text-sm text-blue-300"><strong>Solution:</strong> {vuln.solution}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Intruder Tab */}
        {activeTab === 'intruder' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Target URL
                </label>
                <input
                  type="text"
                  value={intruderUrl}
                  onChange={(e) => setIntruderUrl(e.target.value)}
                  placeholder="https://example.com/login?username=§payload§"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
                <p className="text-xs text-gray-400 mt-1">Use § to mark payload positions</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Attack Type
                </label>
                <select
                  value={intruderType}
                  onChange={(e) => setIntruderType(e.target.value as any)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                >
                  <option value="sniper">Sniper</option>
                  <option value="battering_ram">Battering Ram</option>
                  <option value="pitchfork">Pitchfork</option>
                </select>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Payloads (one per line)
              </label>
              <textarea
                value={intruderPayload}
                onChange={(e) => setIntruderPayload(e.target.value)}
                placeholder="admin&#10;administrator&#10;root&#10;test"
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                rows={6}
              />
            </div>

            <button
              onClick={() => setIsIntruderRunning(!isIntruderRunning)}
              className="flex items-center space-x-2 px-4 py-2 bg-cyan-600 text-white rounded-md hover:bg-cyan-700 transition-colors"
            >
              <Zap className="w-4 h-4" />
              <span>{isIntruderRunning ? 'Stop Attack' : 'Start Attack'}</span>
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

export default WebProxyScanner
