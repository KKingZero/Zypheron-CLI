import React, { useState, useEffect } from 'react'
import { Shield, Play, Pause, Download, AlertTriangle, CheckCircle, Clock, Target, Brain, FileText } from 'lucide-react'

interface Vulnerability {
  id: string
  name: string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  cvss: number
  port: number
  protocol: string
  description: string
  solution: string
  cve: string[]
  exploitable: boolean
  businessImpact: string
}

interface ScanResult {
  scanId: string
  target: string
  scanPolicy: string
  status: 'running' | 'completed' | 'failed'
  startTime: string
  endTime?: string
  vulnerabilities: Vulnerability[]
  summary: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
  overallRisk: number
  compliance: {
    pci: boolean
    hipaa: boolean
    iso27001: boolean
  }
}

interface ExecutiveSummary {
  riskScore: number
  criticalFindings: string[]
  businessImpact: string
  recommendations: string[]
  complianceStatus: string
  timeToRemediate: string
}

interface NessusScannerProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

const NessusScanner: React.FC<NessusScannerProps> = ({ onToolExecute }) => {
  const [target, setTarget] = useState<string>('')
  const [scanPolicy, setScanPolicy] = useState<string>('basic_network_scan')
  const [credentials, setCredentials] = useState<{ username: string, password: string }>({ username: '', password: '' })
  const [isScanning, setIsScanning] = useState(false)
  const [scanResults, setScanResults] = useState<ScanResult | null>(null)
  const [executiveSummary, setExecutiveSummary] = useState<ExecutiveSummary | null>(null)
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null)
  const [filterSeverity, setFilterSeverity] = useState<string>('all')
  const [viewMode, setViewMode] = useState<'summary' | 'detailed' | 'executive'>('summary')

  const scanPolicies = [
    { value: 'basic_network_scan', label: 'Basic Network Scan', description: 'General vulnerability assessment' },
    { value: 'advanced_scan', label: 'Advanced Scan', description: 'Comprehensive vulnerability assessment' },
    { value: 'web_application_tests', label: 'Web Application Tests', description: 'Web-specific vulnerabilities' },
    { value: 'malware_scan', label: 'Malware Scan', description: 'Malware and backdoor detection' },
    { value: 'pci_dss', label: 'PCI DSS Compliance', description: 'Payment card industry compliance' },
    { value: 'hipaa_audit', label: 'HIPAA Audit', description: 'Healthcare compliance assessment' }
  ]

  const startScan = async () => {
    if (!target.trim()) return

    setIsScanning(true)
    try {
      const result = await onToolExecute('nessus_scan', {
        target: target.trim(),
        scanPolicy,
        credentials: credentials.username ? credentials : undefined
      })

      if (result.scanId) {
        setScanResults(result)
        setExecutiveSummary(result.executiveSummary)
      }
    } catch (error) {
      console.error('Nessus scan failed:', error)
    } finally {
      setIsScanning(false)
    }
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
        return <CheckCircle className="w-4 h-4" />
      default:
        return <Shield className="w-4 h-4" />
    }
  }

  const filteredVulnerabilities = scanResults?.vulnerabilities.filter(vuln => 
    filterSeverity === 'all' || vuln.severity === filterSeverity
  ) || []

  const getRiskScoreColor = (score: number) => {
    if (score >= 9) return 'text-red-600'
    if (score >= 7) return 'text-red-500'
    if (score >= 5) return 'text-yellow-500'
    if (score >= 3) return 'text-blue-500'
    return 'text-green-500'
  }

  return (
    <div className="space-y-6">
      {/* Nessus Header */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h3 className="text-xl font-bold text-terminal-text mb-4 flex items-center">
          <Shield className="w-6 h-6 mr-3 text-orange-500" />
          Nessus Professional Scanner
          <span className="ml-3 px-3 py-1 bg-orange-500 text-white text-sm rounded-full">ENTERPRISE</span>
        </h3>
        <p className="text-terminal-muted">
          Professional vulnerability scanning with AI-powered executive summaries and compliance reporting
        </p>
      </div>

      {/* Scan Configuration */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h4 className="text-lg font-semibold text-terminal-text mb-4">Scan Configuration</h4>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
          <div>
            <label className="block text-terminal-text font-medium mb-2">
              Target (IP, Range, or Domain)
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="192.168.1.0/24, example.com"
              className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
            />
          </div>

          <div>
            <label className="block text-terminal-text font-medium mb-2">
              Scan Policy
            </label>
            <select
              value={scanPolicy}
              onChange={(e) => setScanPolicy(e.target.value)}
              className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
            >
              {scanPolicies.map((policy) => (
                <option key={policy.value} value={policy.value}>
                  {policy.label}
                </option>
              ))}
            </select>
            <p className="text-terminal-muted text-sm mt-1">
              {scanPolicies.find(p => p.value === scanPolicy)?.description}
            </p>
          </div>
        </div>

        {/* Credentials (Optional) */}
        <div className="mb-6">
          <h5 className="font-medium text-terminal-text mb-3">Authenticated Scanning (Optional)</h5>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-terminal-text font-medium mb-2">Username</label>
              <input
                type="text"
                value={credentials.username}
                onChange={(e) => setCredentials(prev => ({ ...prev, username: e.target.value }))}
                placeholder="admin, root, etc."
                className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
              />
            </div>
            <div>
              <label className="block text-terminal-text font-medium mb-2">Password</label>
              <input
                type="password"
                value={credentials.password}
                onChange={(e) => setCredentials(prev => ({ ...prev, password: e.target.value }))}
                className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
              />
            </div>
          </div>
        </div>

        <div className="flex justify-center">
          <button
            onClick={startScan}
            disabled={isScanning || !target.trim()}
            className="px-6 py-3 bg-orange-600 hover:bg-orange-700 disabled:bg-gray-600 text-white rounded-lg flex items-center space-x-3 transition-colors transform hover:scale-105"
          >
            {isScanning ? (
              <>
                <Play className="w-5 h-5 animate-spin" />
                <span>Scanning...</span>
              </>
            ) : (
              <>
                <Target className="w-5 h-5" />
                <span>Start Vulnerability Scan</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* View Mode Toggle */}
      {scanResults && (
        <div className="flex space-x-2">
          <button
            onClick={() => setViewMode('summary')}
            className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
              viewMode === 'summary' 
                ? 'bg-orange-600 text-white' 
                : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
            }`}
          >
            <Shield className="w-4 h-4" />
            <span>Summary</span>
          </button>
          <button
            onClick={() => setViewMode('detailed')}
            className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
              viewMode === 'detailed' 
                ? 'bg-orange-600 text-white' 
                : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
            }`}
          >
            <AlertTriangle className="w-4 h-4" />
            <span>Detailed</span>
          </button>
          <button
            onClick={() => setViewMode('executive')}
            className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
              viewMode === 'executive' 
                ? 'bg-orange-600 text-white' 
                : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
            }`}
          >
            <Brain className="w-4 h-4" />
            <span>Executive</span>
          </button>
        </div>
      )}

      {/* Executive Summary View */}
      {viewMode === 'executive' && executiveSummary && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <Brain className="w-5 h-5 mr-2 text-blue-500" />
            AI-Generated Executive Summary
          </h4>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div className="bg-terminal-bg border border-terminal-border rounded p-4">
              <h5 className="font-medium text-terminal-text mb-2">Overall Risk Score</h5>
              <div className="flex items-center space-x-3">
                <div className={`text-3xl font-bold ${getRiskScoreColor(executiveSummary.riskScore)}`}>
                  {executiveSummary.riskScore}/10
                </div>
                <div className="w-full bg-gray-600 rounded-full h-3">
                  <div
                    className={`h-3 rounded-full ${
                      executiveSummary.riskScore >= 7 ? 'bg-red-500' :
                      executiveSummary.riskScore >= 5 ? 'bg-yellow-500' : 'bg-green-500'
                    }`}
                    style={{ width: `${executiveSummary.riskScore * 10}%` }}
                  ></div>
                </div>
              </div>
            </div>

            <div className="bg-terminal-bg border border-terminal-border rounded p-4">
              <h5 className="font-medium text-terminal-text mb-2">Time to Remediate</h5>
              <div className="text-2xl font-bold text-terminal-text">{executiveSummary.timeToRemediate}</div>
              <div className="text-terminal-muted text-sm">Estimated remediation time</div>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <h5 className="font-medium text-terminal-text mb-2">Business Impact Assessment</h5>
              <p className="text-terminal-muted">{executiveSummary.businessImpact}</p>
            </div>

            <div>
              <h5 className="font-medium text-terminal-text mb-2">Critical Findings</h5>
              <ul className="space-y-1">
                {executiveSummary.criticalFindings.map((finding, index) => (
                  <li key={index} className="text-red-400 text-sm flex items-start space-x-2">
                    <AlertTriangle className="w-3 h-3 mt-1 flex-shrink-0" />
                    <span>{finding}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <h5 className="font-medium text-terminal-text mb-2">Strategic Recommendations</h5>
              <ul className="space-y-1">
                {executiveSummary.recommendations.map((rec, index) => (
                  <li key={index} className="text-terminal-muted text-sm flex items-start space-x-2">
                    <CheckCircle className="w-3 h-3 mt-1 flex-shrink-0 text-green-500" />
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <h5 className="font-medium text-terminal-text mb-2">Compliance Status</h5>
              <p className="text-terminal-muted">{executiveSummary.complianceStatus}</p>
            </div>
          </div>
        </div>
      )}

      {/* Summary View */}
      {viewMode === 'summary' && scanResults && (
        <div className="space-y-6">
          {/* Scan Overview */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">Scan Overview</h4>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              <div className="bg-terminal-bg border border-terminal-border rounded p-4">
                <h5 className="font-medium text-terminal-text">Target</h5>
                <p className="text-terminal-muted text-sm">{scanResults.target}</p>
              </div>
              <div className="bg-terminal-bg border border-terminal-border rounded p-4">
                <h5 className="font-medium text-terminal-text">Scan Policy</h5>
                <p className="text-terminal-muted text-sm">{scanResults.scanPolicy}</p>
              </div>
              <div className="bg-terminal-bg border border-terminal-border rounded p-4">
                <h5 className="font-medium text-terminal-text">Overall Risk</h5>
                <div className={`text-xl font-bold ${getRiskScoreColor(scanResults.overallRisk)}`}>
                  {scanResults.overallRisk}/10
                </div>
              </div>
            </div>

            {/* Vulnerability Summary */}
            <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
              {Object.entries(scanResults.summary).map(([severity, count]) => (
                <div key={severity} className={`border rounded p-3 text-center ${getSeverityColor(severity)}`}>
                  <div className="flex items-center justify-center mb-1">
                    {getSeverityIcon(severity)}
                  </div>
                  <div className="font-bold text-lg">{count}</div>
                  <div className="text-xs uppercase">{severity}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Compliance Status */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">Compliance Status</h4>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {Object.entries(scanResults.compliance).map(([standard, compliant]) => (
                <div key={standard} className="flex items-center justify-between p-3 bg-terminal-bg border border-terminal-border rounded">
                  <span className="font-medium text-terminal-text uppercase">{standard}</span>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${
                    compliant ? 'bg-green-500/20 text-green-500' : 'bg-red-500/20 text-red-500'
                  }`}>
                    {compliant ? 'Compliant' : 'Non-Compliant'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Detailed View */}
      {viewMode === 'detailed' && scanResults && (
        <div className="space-y-6">
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
                {filteredVulnerabilities.length} vulnerabilities found
              </span>
            </div>
          </div>

          {/* Vulnerabilities List */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">Vulnerabilities</h4>
            
            <div className="space-y-3">
              {filteredVulnerabilities.map((vuln) => (
                <div
                  key={vuln.id}
                  className={`border rounded-lg p-4 cursor-pointer transition-all hover:border-orange-500 ${
                    selectedVuln?.id === vuln.id ? 'border-orange-500 bg-orange-500/5' : 'border-terminal-border'
                  }`}
                  onClick={() => setSelectedVuln(vuln)}
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(vuln.severity)}`}>
                        {vuln.severity.toUpperCase()}
                      </span>
                      <span className="font-medium text-terminal-text">{vuln.name}</span>
                      {vuln.exploitable && (
                        <span className="px-2 py-1 bg-red-500 text-white text-xs rounded">EXPLOITABLE</span>
                      )}
                    </div>
                    <span className="text-terminal-muted text-sm">CVSS: {vuln.cvss}</span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                    <div>
                      <span className="text-terminal-muted">Port:</span>
                      <span className="ml-2 text-terminal-text">{vuln.port}/{vuln.protocol}</span>
                    </div>
                    <div>
                      <span className="text-terminal-muted">CVE:</span>
                      <span className="ml-2 text-terminal-text">{vuln.cve.slice(0, 2).join(', ')}</span>
                    </div>
                    <div>
                      <span className="text-terminal-muted">Business Impact:</span>
                      <span className="ml-2 text-terminal-text">{vuln.businessImpact}</span>
                    </div>
                  </div>

                  <p className="text-terminal-muted text-sm mt-2">{vuln.description.slice(0, 200)}...</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Selected Vulnerability Details */}
      {selectedVuln && (
        <div className="bg-terminal-card border border-orange-500/20 rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <AlertTriangle className="w-5 h-5 mr-2 text-orange-500" />
            Vulnerability Details: {selectedVuln.name}
          </h4>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div>
                <h5 className="font-medium text-terminal-text mb-2">Technical Details</h5>
                <div className="space-y-2 text-sm">
                  <div><span className="text-terminal-muted">Severity:</span> <span className={`ml-2 font-medium ${getSeverityColor(selectedVuln.severity).split(' ')[0]}`}>{selectedVuln.severity.toUpperCase()}</span></div>
                  <div><span className="text-terminal-muted">CVSS Score:</span> <span className="ml-2 text-terminal-text">{selectedVuln.cvss}/10</span></div>
                  <div><span className="text-terminal-muted">Port/Protocol:</span> <span className="ml-2 text-terminal-text">{selectedVuln.port}/{selectedVuln.protocol}</span></div>
                  <div><span className="text-terminal-muted">Exploitable:</span> <span className={`ml-2 ${selectedVuln.exploitable ? 'text-red-400' : 'text-green-400'}`}>{selectedVuln.exploitable ? 'Yes' : 'No'}</span></div>
                </div>
              </div>

              <div>
                <h5 className="font-medium text-terminal-text mb-2">CVE References</h5>
                <div className="flex flex-wrap gap-1">
                  {selectedVuln.cve.map((cve, index) => (
                    <span key={index} className="px-2 py-1 bg-blue-500/20 text-blue-400 text-xs rounded">
                      {cve}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <h5 className="font-medium text-terminal-text mb-2">Business Impact</h5>
                <p className="text-terminal-muted text-sm">{selectedVuln.businessImpact}</p>
              </div>

              <div>
                <h5 className="font-medium text-terminal-text mb-2">Description</h5>
                <p className="text-terminal-muted text-sm">{selectedVuln.description}</p>
              </div>
            </div>
          </div>

          <div className="mt-6 pt-6 border-t border-terminal-border">
            <h5 className="font-medium text-terminal-text mb-2">Remediation Steps</h5>
            <div className="bg-green-500/10 border border-green-500/20 rounded p-3">
              <p className="text-green-300 text-sm">{selectedVuln.solution}</p>
            </div>
          </div>
        </div>
      )}

      {/* Export and Actions */}
      {scanResults && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-4">
          <div className="flex items-center justify-between">
            <span className="text-terminal-text font-medium">Export Results</span>
            <div className="flex space-x-2">
              <button className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>PDF Report</span>
              </button>
              <button className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>CSV Data</span>
              </button>
              <button className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded flex items-center space-x-1">
                <FileText className="w-3 h-3" />
                <span>Executive Report</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default NessusScanner