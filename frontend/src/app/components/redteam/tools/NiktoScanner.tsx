import React, { useState, useEffect } from 'react'
import { Globe, Search, AlertTriangle, CheckCircle, Info, Server, Brain, Download, Shield, Eye, Clock } from 'lucide-react'

interface NiktoFinding {
  id: string
  osvdbId?: string
  method: string
  uri: string
  message: string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  category: string
  references: string[]
  solution?: string
  gptAnalysis?: {
    explanation: string
    riskLevel: string
    remediationSteps: string[]
    businessImpact: string
  }
}

interface ServerInfo {
  serverHeader: string
  poweredBy: string[]
  technologies: string[]
  ports: number[]
  ssl: boolean
  redirects: string[]
}

interface ScanSummary {
  totalTests: number
  findings: number
  hostsScanned: number
  elapsedTime: string
  riskDistribution: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
}

interface GPTWebAnalysis {
  overallRisk: number
  topVulnerabilities: string[]
  serverHardening: string[]
  complianceIssues: string[]
  remediationPriority: Array<{
    finding: string
    priority: number
    effort: 'low' | 'medium' | 'high'
    impact: string
  }>
}

interface NiktoScannerProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

const NiktoScanner: React.FC<NiktoScannerProps> = ({ onToolExecute }) => {
  const [target, setTarget] = useState<string>('')
  const [port, setPort] = useState<string>('80')
  const [ssl, setSsl] = useState<boolean>(false)
  const [scanOptions, setScanOptions] = useState<string[]>(['basic'])
  const [isScanning, setIsScanning] = useState(false)
  const [findings, setFindings] = useState<NiktoFinding[]>([])
  const [serverInfo, setServerInfo] = useState<ServerInfo | null>(null)
  const [scanSummary, setScanSummary] = useState<ScanSummary | null>(null)
  const [gptAnalysis, setGptAnalysis] = useState<GPTWebAnalysis | null>(null)
  const [selectedFinding, setSelectedFinding] = useState<NiktoFinding | null>(null)
  const [filterSeverity, setFilterSeverity] = useState<string>('all')
  const [viewMode, setViewMode] = useState<'scan' | 'findings' | 'analysis'>('scan')

  const scanOptionsList = [
    { value: 'basic', label: 'Basic Tests', description: 'Common vulnerabilities and misconfigurations' },
    { value: 'extended', label: 'Extended Tests', description: 'Comprehensive vulnerability testing' },
    { value: 'outdated', label: 'Outdated Software', description: 'Check for outdated server components' },
    { value: 'dangerous', label: 'Dangerous Files', description: 'Search for potentially dangerous files' },
    { value: 'headers', label: 'Security Headers', description: 'Analyze HTTP security headers' },
    { value: 'cookies', label: 'Cookie Security', description: 'Check cookie configuration' },
    { value: 'ssl', label: 'SSL/TLS Tests', description: 'SSL configuration analysis' },
    { value: 'auth', label: 'Authentication', description: 'Authentication bypass tests' }
  ]

  const startScan = async () => {
    if (!target.trim()) return

    setIsScanning(true)
    try {
      const result = await onToolExecute('nikto_scan', {
        target: target.trim(),
        port: parseInt(port) || 80,
        ssl,
        options: scanOptions
      })

      if (result.findings) {
        setFindings(result.findings)
        setServerInfo(result.serverInfo)
        setScanSummary(result.scanSummary)
        setGptAnalysis(result.gptWebAnalysis)
        setViewMode('findings')
      }
    } catch (error) {
      console.error('Nikto scan failed:', error)
    } finally {
      setIsScanning(false)
    }
  }

  const toggleScanOption = (option: string) => {
    setScanOptions(prev => 
      prev.includes(option)
        ? prev.filter(o => o !== option)
        : [...prev, option]
    )
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-600/20 border-red-600/30'
      case 'high': return 'text-red-500 bg-red-500/20 border-red-500/30'
      case 'medium': return 'text-yellow-500 bg-yellow-500/20 border-yellow-500/30'
      case 'low': return 'text-blue-500 bg-blue-500/20 border-blue-500/30'
      case 'info': return 'text-gray-500 bg-gray-500/20 border-gray-500/30'
      default: return 'text-gray-500 bg-gray-500/20 border-gray-500/30'
    }
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return <AlertTriangle className="w-4 h-4" />
      case 'medium':
        return <Clock className="w-4 h-4" />
      case 'low':
      case 'info':
        return <Info className="w-4 h-4" />
      default:
        return <CheckCircle className="w-4 h-4" />
    }
  }

  const filteredFindings = findings.filter(finding => 
    filterSeverity === 'all' || finding.severity === filterSeverity
  )

  const getRiskScoreColor = (score: number) => {
    if (score >= 8) return 'text-red-600'
    if (score >= 6) return 'text-red-500'
    if (score >= 4) return 'text-yellow-500'
    if (score >= 2) return 'text-blue-500'
    return 'text-green-500'
  }

  return (
    <div className="space-y-6">
      {/* Nikto Header */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h3 className="text-xl font-bold text-terminal-text mb-4 flex items-center">
          <Globe className="w-6 h-6 mr-3 text-blue-500" />
          Nikto Web Scanner
          <span className="ml-3 px-3 py-1 bg-blue-500 text-white text-sm rounded-full">AI-ENHANCED</span>
        </h3>
        <p className="text-terminal-muted">
          Advanced web server vulnerability scanner with GPT-powered analysis and actionable remediation
        </p>
      </div>

      {/* Tab Navigation */}
      <div className="flex space-x-2">
        <button
          onClick={() => setViewMode('scan')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'scan' 
              ? 'bg-blue-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Search className="w-4 h-4" />
          <span>Scan Setup</span>
        </button>
        <button
          onClick={() => setViewMode('findings')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'findings' 
              ? 'bg-blue-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <AlertTriangle className="w-4 h-4" />
          <span>Findings ({findings.length})</span>
        </button>
        <button
          onClick={() => setViewMode('analysis')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'analysis' 
              ? 'bg-blue-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Brain className="w-4 h-4" />
          <span>AI Analysis</span>
        </button>
      </div>

      {/* Scan Setup Tab */}
      {viewMode === 'scan' && (
        <div className="space-y-6">
          {/* Target Configuration */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">Target Configuration</h4>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              <div className="md:col-span-2">
                <label className="block text-terminal-text font-medium mb-2">
                  Target URL or IP
                </label>
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://example.com or 192.168.1.100"
                  className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
                />
              </div>

              <div>
                <label className="block text-terminal-text font-medium mb-2">
                  Port
                </label>
                <input
                  type="number"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  min="1"
                  max="65535"
                  className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
                />
              </div>
            </div>

            <div className="mb-6">
              <div className="flex items-center space-x-3">
                <input
                  type="checkbox"
                  id="ssl-enabled"
                  checked={ssl}
                  onChange={(e) => setSsl(e.target.checked)}
                  className="text-blue-500"
                />
                <label htmlFor="ssl-enabled" className="text-terminal-text font-medium flex items-center">
                  <Shield className="w-4 h-4 mr-2 text-green-500" />
                  Force SSL/HTTPS
                </label>
              </div>
              <p className="text-terminal-muted text-sm mt-1">
                Use HTTPS even if target doesn't specify protocol
              </p>
            </div>
          </div>

          {/* Scan Options */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">Scan Options</h4>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {scanOptionsList.map((option) => (
                <div
                  key={option.value}
                  className={`border rounded-lg p-4 cursor-pointer transition-all ${
                    scanOptions.includes(option.value)
                      ? 'border-blue-500 bg-blue-500/10'
                      : 'border-terminal-border hover:border-blue-500/50'
                  }`}
                  onClick={() => toggleScanOption(option.value)}
                >
                  <div className="flex items-center space-x-2 mb-2">
                    <input
                      type="checkbox"
                      checked={scanOptions.includes(option.value)}
                      onChange={() => toggleScanOption(option.value)}
                      className="text-blue-500"
                    />
                    <span className="font-medium text-terminal-text">{option.label}</span>
                  </div>
                  <p className="text-terminal-muted text-sm">{option.description}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="flex justify-center">
            <button
              onClick={startScan}
              disabled={isScanning || !target.trim()}
              className="px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white rounded-lg flex items-center space-x-3 transition-colors transform hover:scale-105"
            >
              {isScanning ? (
                <>
                  <Search className="w-5 h-5 animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <Server className="w-5 h-5" />
                  <span>Start Web Scan</span>
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {/* Findings Tab */}
      {viewMode === 'findings' && (
        <div className="space-y-6">
          {/* Server Information */}
          {serverInfo && (
            <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
              <h4 className="text-lg font-semibold text-terminal-text mb-4">Server Information</h4>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-3">
                  <div>
                    <span className="text-terminal-muted">Server:</span>
                    <span className="ml-2 text-terminal-text">{serverInfo.serverHeader || 'Unknown'}</span>
                  </div>
                  <div>
                    <span className="text-terminal-muted">SSL Enabled:</span>
                    <span className={`ml-2 ${serverInfo.ssl ? 'text-green-400' : 'text-red-400'}`}>
                      {serverInfo.ssl ? 'Yes' : 'No'}
                    </span>
                  </div>
                  <div>
                    <span className="text-terminal-muted">Powered By:</span>
                    <div className="ml-2 flex flex-wrap gap-1">
                      {serverInfo.poweredBy.map((tech, index) => (
                        <span key={index} className="px-2 py-1 bg-blue-500/20 text-blue-400 text-xs rounded">
                          {tech}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
                
                <div className="space-y-3">
                  <div>
                    <span className="text-terminal-muted">Technologies:</span>
                    <div className="ml-2 flex flex-wrap gap-1">
                      {serverInfo.technologies.map((tech, index) => (
                        <span key={index} className="px-2 py-1 bg-green-500/20 text-green-400 text-xs rounded">
                          {tech}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div>
                    <span className="text-terminal-muted">Open Ports:</span>
                    <span className="ml-2 text-terminal-text">{serverInfo.ports.join(', ')}</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Scan Summary */}
          {scanSummary && (
            <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
              <h4 className="text-lg font-semibold text-terminal-text mb-4">Scan Summary</h4>
              
              <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
                {Object.entries(scanSummary.riskDistribution).map(([severity, count]) => (
                  <div key={severity} className={`border rounded p-3 text-center ${getSeverityColor(severity)}`}>
                    <div className="flex items-center justify-center mb-1">
                      {getSeverityIcon(severity)}
                    </div>
                    <div className="font-bold text-lg">{count}</div>
                    <div className="text-xs uppercase">{severity}</div>
                  </div>
                ))}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
                <div className="text-center">
                  <div className="text-2xl font-bold text-terminal-text">{scanSummary.totalTests}</div>
                  <div className="text-terminal-muted text-sm">Tests Performed</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-terminal-text">{scanSummary.hostsScanned}</div>
                  <div className="text-terminal-muted text-sm">Hosts Scanned</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-terminal-text">{scanSummary.elapsedTime}</div>
                  <div className="text-terminal-muted text-sm">Scan Duration</div>
                </div>
              </div>
            </div>
          )}

          {/* Filter Controls */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <span className="text-terminal-text font-medium">Filter by Severity:</span>
                <select
                  value={filterSeverity}
                  onChange={(e) => setFilterSeverity(e.target.value)}
                  className="bg-terminal-bg border border-terminal-border rounded px-3 py-1 text-terminal-text"
                >
                  <option value="all">All Severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
              </div>
              <span className="text-terminal-muted text-sm">
                {filteredFindings.length} findings
              </span>
            </div>
          </div>

          {/* Findings List */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">Security Findings</h4>
            
            {filteredFindings.length === 0 ? (
              <div className="text-center py-8">
                <CheckCircle className="w-12 h-12 text-green-500 mx-auto mb-4" />
                <p className="text-terminal-muted">No findings for the selected severity level.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {filteredFindings.map((finding) => (
                  <div
                    key={finding.id}
                    className={`border rounded-lg p-4 cursor-pointer transition-all hover:border-blue-500 ${
                      selectedFinding?.id === finding.id ? 'border-blue-500 bg-blue-500/5' : 'border-terminal-border'
                    }`}
                    onClick={() => setSelectedFinding(finding)}
                  >
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center space-x-3">
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(finding.severity)}`}>
                          {finding.severity.toUpperCase()}
                        </span>
                        <span className="font-medium text-terminal-text">{finding.category}</span>
                      </div>
                      <span className="text-terminal-muted text-sm">{finding.method}</span>
                    </div>

                    <div className="mb-2">
                      <span className="text-terminal-muted">URI:</span>
                      <span className="ml-2 text-terminal-text font-mono">{finding.uri}</span>
                    </div>

                    <p className="text-terminal-muted text-sm">{finding.message}</p>

                    {finding.gptAnalysis && (
                      <div className="mt-3 bg-blue-500/10 border border-blue-500/20 rounded p-3">
                        <h6 className="font-medium text-blue-300 mb-2 flex items-center">
                          <Brain className="w-4 h-4 mr-2" />
                          AI Analysis
                        </h6>
                        <p className="text-blue-200 text-sm mb-2">{finding.gptAnalysis.explanation}</p>
                        <div className="text-blue-300 text-sm">
                          <strong>Business Impact:</strong> {finding.gptAnalysis.businessImpact}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* AI Analysis Tab */}
      {viewMode === 'analysis' && gptAnalysis && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <Brain className="w-5 h-5 mr-2 text-blue-500" />
            GPT Web Security Analysis
          </h4>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div className="bg-terminal-bg border border-terminal-border rounded p-4">
              <h5 className="font-medium text-terminal-text mb-2">Overall Risk Score</h5>
              <div className="flex items-center space-x-3">
                <div className={`text-3xl font-bold ${getRiskScoreColor(gptAnalysis.overallRisk)}`}>
                  {gptAnalysis.overallRisk}/10
                </div>
                <div className="w-full bg-gray-600 rounded-full h-3">
                  <div
                    className={`h-3 rounded-full ${
                      gptAnalysis.overallRisk >= 7 ? 'bg-red-500' :
                      gptAnalysis.overallRisk >= 5 ? 'bg-yellow-500' : 'bg-green-500'
                    }`}
                    style={{ width: `${gptAnalysis.overallRisk * 10}%` }}
                  ></div>
                </div>
              </div>
            </div>

            <div className="bg-terminal-bg border border-terminal-border rounded p-4">
              <h5 className="font-medium text-terminal-text mb-2">Remediation Priority</h5>
              <div className="space-y-2">
                {gptAnalysis.remediationPriority.slice(0, 3).map((item, index) => (
                  <div key={index} className="flex items-center justify-between text-sm">
                    <span className="text-terminal-muted">{item.finding}</span>
                    <span className={`px-2 py-1 rounded text-xs ${
                      item.priority === 1 ? 'bg-red-500/20 text-red-400' :
                      item.priority === 2 ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-green-500/20 text-green-400'
                    }`}>
                      P{item.priority}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <h5 className="font-medium text-terminal-text mb-2">Top Vulnerabilities</h5>
              <ul className="space-y-1">
                {gptAnalysis.topVulnerabilities.map((vuln, index) => (
                  <li key={index} className="text-red-400 text-sm flex items-start space-x-2">
                    <AlertTriangle className="w-3 h-3 mt-1 flex-shrink-0" />
                    <span>{vuln}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <h5 className="font-medium text-terminal-text mb-2">Server Hardening Recommendations</h5>
              <ul className="space-y-1">
                {gptAnalysis.serverHardening.map((rec, index) => (
                  <li key={index} className="text-terminal-muted text-sm flex items-start space-x-2">
                    <Shield className="w-3 h-3 mt-1 flex-shrink-0 text-green-500" />
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <h5 className="font-medium text-terminal-text mb-2">Compliance Issues</h5>
              <ul className="space-y-1">
                {gptAnalysis.complianceIssues.map((issue, index) => (
                  <li key={index} className="text-yellow-400 text-sm flex items-start space-x-2">
                    <Eye className="w-3 h-3 mt-1 flex-shrink-0" />
                    <span>{issue}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="bg-green-500/10 border border-green-500/20 rounded p-4">
              <h5 className="font-medium text-green-300 mb-2">Quick Wins</h5>
              <div className="space-y-2">
                {gptAnalysis.remediationPriority
                  .filter(item => item.effort === 'low')
                  .slice(0, 3)
                  .map((item, index) => (
                    <div key={index} className="text-green-200 text-sm">
                      <strong>{item.finding}:</strong> {item.impact}
                    </div>
                  ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Selected Finding Details */}
      {selectedFinding && (
        <div className="bg-terminal-card border border-blue-500/20 rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">
            Finding Details: {selectedFinding.category}
          </h4>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div>
                <h5 className="font-medium text-terminal-text mb-2">Technical Details</h5>
                <div className="space-y-2 text-sm">
                  <div><span className="text-terminal-muted">Method:</span> <span className="ml-2 text-terminal-text">{selectedFinding.method}</span></div>
                  <div><span className="text-terminal-muted">URI:</span> <span className="ml-2 text-terminal-text font-mono">{selectedFinding.uri}</span></div>
                  <div><span className="text-terminal-muted">Severity:</span> <span className={`ml-2 font-medium ${getSeverityColor(selectedFinding.severity).split(' ')[0]}`}>{selectedFinding.severity.toUpperCase()}</span></div>
                  {selectedFinding.osvdbId && (
                    <div><span className="text-terminal-muted">OSVDB ID:</span> <span className="ml-2 text-terminal-text">{selectedFinding.osvdbId}</span></div>
                  )}
                </div>
              </div>

              <div>
                <h5 className="font-medium text-terminal-text mb-2">Description</h5>
                <p className="text-terminal-muted text-sm">{selectedFinding.message}</p>
              </div>
            </div>

            <div className="space-y-4">
              {selectedFinding.references.length > 0 && (
                <div>
                  <h5 className="font-medium text-terminal-text mb-2">References</h5>
                  <div className="space-y-1">
                    {selectedFinding.references.map((ref, index) => (
                      <a key={index} href={ref} target="_blank" rel="noopener noreferrer" className="text-blue-400 text-sm hover:underline block">
                        {ref}
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {selectedFinding.solution && (
                <div>
                  <h5 className="font-medium text-terminal-text mb-2">Solution</h5>
                  <div className="bg-green-500/10 border border-green-500/20 rounded p-3">
                    <p className="text-green-300 text-sm">{selectedFinding.solution}</p>
                  </div>
                </div>
              )}
            </div>
          </div>

          {selectedFinding.gptAnalysis && (
            <div className="mt-6 pt-6 border-t border-terminal-border">
              <h5 className="font-medium text-terminal-text mb-3 flex items-center">
                <Brain className="w-4 h-4 mr-2 text-blue-500" />
                Detailed AI Analysis
              </h5>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h6 className="font-medium text-blue-300 mb-2">Risk Assessment</h6>
                  <p className="text-blue-200 text-sm mb-3">{selectedFinding.gptAnalysis.explanation}</p>
                  
                  <h6 className="font-medium text-blue-300 mb-2">Business Impact</h6>
                  <p className="text-blue-200 text-sm">{selectedFinding.gptAnalysis.businessImpact}</p>
                </div>
                
                <div>
                  <h6 className="font-medium text-blue-300 mb-2">Remediation Steps</h6>
                  <ul className="space-y-1">
                    {selectedFinding.gptAnalysis.remediationSteps.map((step, index) => (
                      <li key={index} className="text-blue-200 text-sm">
                        {index + 1}. {step}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Export Options */}
      {findings.length > 0 && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-4">
          <div className="flex items-center justify-between">
            <span className="text-terminal-text font-medium">Export Results</span>
            <div className="flex space-x-2">
              <button className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>JSON</span>
              </button>
              <button className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>HTML Report</span>
              </button>
              <button className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>Executive Summary</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default NiktoScanner