import React, { useState, useEffect } from 'react'
import { 
  Database, 
  Play, 
  Pause, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  Eye,
  Download,
  FileText,
  Shield,
  Target,
  Settings,
  Code
} from 'lucide-react'
import toast from 'react-hot-toast'

interface SqlmapScannerProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

interface SqlInjectionResult {
  vulnerable: boolean
  injectionType: string
  payload: string
  dbms: string
  databases?: string[]
  tables?: { [key: string]: string[] }
  data?: { [key: string]: any[] }
  executiveSummary: {
    totalVulns: number
    criticalFindings: string[]
    recommendations: string[]
    riskScore: number
  }
}

const SqlmapScanner: React.FC<SqlmapScannerProps> = ({ onToolExecute }) => {
  const [target, setTarget] = useState<string>('')
  const [scanType, setScanType] = useState<string>('basic')
  const [httpMethod, setHttpMethod] = useState<'GET' | 'POST'>('GET')
  const [postData, setPostData] = useState<string>('')
  const [cookies, setCookies] = useState<string>('')
  const [userAgent, setUserAgent] = useState<string>('')
  const [level, setLevel] = useState<number>(1)
  const [risk, setRisk] = useState<number>(1)
  const [isScanning, setIsScanning] = useState(false)
  const [scanResults, setScanResults] = useState<SqlInjectionResult | null>(null)
  const [selectedDatabase, setSelectedDatabase] = useState<string>('')
  const [selectedTable, setSelectedTable] = useState<string>('')
  const [scanProgress, setScanProgress] = useState<number>(0)
  const [currentPhase, setCurrentPhase] = useState<string>('Ready')
  const [viewMode, setViewMode] = useState<'summary' | 'databases' | 'payloads' | 'report'>('summary')

  const scanTypes = [
    { value: 'basic', label: 'Basic Detection', description: 'Standard SQL injection detection' },
    { value: 'advanced', label: 'Advanced Scanning', description: 'Deep SQL injection analysis with multiple techniques' },
    { value: 'time_based', label: 'Time-based Blind', description: 'Time-based blind SQL injection' },
    { value: 'union_based', label: 'Union-based', description: 'UNION query injection' },
    { value: 'boolean_based', label: 'Boolean-based Blind', description: 'Boolean-based blind injection' },
    { value: 'error_based', label: 'Error-based', description: 'Error-based SQL injection' }
  ]

  const startScan = async () => {
    if (!target.trim()) {
      toast.error('Please enter a target URL')
      return
    }

    setIsScanning(true)
    setScanProgress(0)
    setCurrentPhase('Initializing scan...')
    
    let progressInterval: NodeJS.Timeout | null = null
    
    try {
      const params = {
        url: target.trim(),
        scanType,
        method: httpMethod,
        postData: postData || undefined,
        cookies: cookies || undefined,
        userAgent: userAgent || undefined,
        level,
        risk
      }

      // Simulate scan progress
      progressInterval = setInterval(() => {
        setScanProgress(prev => {
          const newProgress = Math.min(prev + Math.random() * 15, 95)
          if (newProgress < 30) setCurrentPhase('Analyzing target parameters...')
          else if (newProgress < 60) setCurrentPhase('Testing SQL injection vectors...')
          else if (newProgress < 80) setCurrentPhase('Enumerating database structure...')
          else setCurrentPhase('Generating report...')
          return newProgress
        })
      }, 500)

      const result = await onToolExecute('sqlmap_scan', params)
      
      setScanProgress(100)
      setCurrentPhase('Scan completed')
      
      if (result) {
        setScanResults(result)
        if (result.databases && result.databases.length > 0) {
          setSelectedDatabase(result.databases[0])
        }
      }
    } catch (error) {
      console.error('SQL injection scan failed:', error)
      toast.error('SQL injection scan failed')
      setCurrentPhase('Scan failed')
    } finally {
      // Always clear the interval
      if (progressInterval) {
        clearInterval(progressInterval)
      }
      setIsScanning(false)
    }
  }

  const pauseScan = () => {
    setIsScanning(false)
    setCurrentPhase('Scan paused')
  }

  const getSeverityColor = (riskScore: number) => {
    if (riskScore >= 8) return 'text-red-500'
    if (riskScore >= 6) return 'text-orange-500'
    if (riskScore >= 4) return 'text-yellow-500'
    return 'text-green-500'
  }

  const exportReport = () => {
    if (!scanResults) return
    
    const report = {
      target,
      timestamp: new Date().toISOString(),
      results: scanResults
    }
    
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `sqlmap_report_${Date.now()}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6">
      {/* Configuration Panel */}
      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex items-center space-x-2 mb-4">
          <Database className="w-5 h-5 text-blue-400" />
          <h3 className="text-lg font-medium text-white">SQL Injection Scanner</h3>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Target URL
              </label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="https://target.com/page?id=1"
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  HTTP Method
                </label>
                <select
                  value={httpMethod}
                  onChange={(e) => setHttpMethod(e.target.value as 'GET' | 'POST')}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Scan Type
                </label>
                <select
                  value={scanType}
                  onChange={(e) => setScanType(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  {scanTypes.map(type => (
                    <option key={type.value} value={type.value}>
                      {type.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {httpMethod === 'POST' && (
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  POST Data
                </label>
                <textarea
                  value={postData}
                  onChange={(e) => setPostData(e.target.value)}
                  placeholder="param1=value1&param2=value2"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  rows={3}
                />
              </div>
            )}
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Cookies (optional)
              </label>
              <input
                type="text"
                value={cookies}
                onChange={(e) => setCookies(e.target.value)}
                placeholder="PHPSESSID=abc123; auth=token"
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                User Agent (optional)
              </label>
              <input
                type="text"
                value={userAgent}
                onChange={(e) => setUserAgent(e.target.value)}
                placeholder="Mozilla/5.0 (compatible; scanner)"
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Level (1-5)
                </label>
                <input
                  type="range"
                  min="1"
                  max="5"
                  value={level}
                  onChange={(e) => setLevel(parseInt(e.target.value))}
                  className="w-full"
                />
                <div className="text-center text-sm text-gray-400">Level {level}</div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Risk (1-3)
                </label>
                <input
                  type="range"
                  min="1"
                  max="3"
                  value={risk}
                  onChange={(e) => setRisk(parseInt(e.target.value))}
                  className="w-full"
                />
                <div className="text-center text-sm text-gray-400">Risk {risk}</div>
              </div>
            </div>
          </div>
        </div>

        <div className="flex justify-between items-center mt-6">
          <div className="flex items-center space-x-4">
            {!isScanning ? (
              <button
                onClick={startScan}
                className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
              >
                <Play className="w-4 h-4" />
                <span>Start Scan</span>
              </button>
            ) : (
              <button
                onClick={pauseScan}
                className="flex items-center space-x-2 px-4 py-2 bg-orange-600 text-white rounded-md hover:bg-orange-700 transition-colors"
              >
                <Pause className="w-4 h-4" />
                <span>Pause Scan</span>
              </button>
            )}
          </div>

          {scanResults && (
            <button
              onClick={exportReport}
              className="flex items-center space-x-2 px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors"
            >
              <Download className="w-4 h-4" />
              <span>Export Report</span>
            </button>
          )}
        </div>
      </div>

      {/* Progress Bar */}
      {isScanning && (
        <div className="bg-gray-800 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-gray-300">Scan Progress</span>
            <span className="text-sm text-gray-400">{Math.round(scanProgress)}%</span>
          </div>
          <div className="w-full bg-gray-700 rounded-full h-2">
            <div 
              className="bg-blue-600 h-2 rounded-full transition-all duration-300"
              style={{ width: `${scanProgress}%` }}
            />
          </div>
          <div className="mt-2 text-sm text-gray-400">{currentPhase}</div>
        </div>
      )}

      {/* Results Panel */}
      {scanResults && (
        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-medium text-white">Scan Results</h3>
            <div className="flex space-x-2">
              {['summary', 'databases', 'payloads', 'report'].map((mode) => (
                <button
                  key={mode}
                  onClick={() => setViewMode(mode as any)}
                  className={`px-3 py-1 rounded text-sm ${
                    viewMode === mode
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  {mode.charAt(0).toUpperCase() + mode.slice(1)}
                </button>
              ))}
            </div>
          </div>

          {viewMode === 'summary' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-gray-700 rounded-lg p-4">
                  <div className="flex items-center space-x-2">
                    {scanResults.vulnerable ? (
                      <AlertTriangle className="w-5 h-5 text-red-400" />
                    ) : (
                      <CheckCircle className="w-5 h-5 text-green-400" />
                    )}
                    <h4 className="font-medium text-white">Vulnerability Status</h4>
                  </div>
                  <p className={`mt-2 ${scanResults.vulnerable ? 'text-red-400' : 'text-green-400'}`}>
                    {scanResults.vulnerable ? 'Vulnerable' : 'Not Vulnerable'}
                  </p>
                  {scanResults.vulnerable && (
                    <p className="text-sm text-gray-400 mt-1">
                      Type: {scanResults.injectionType}
                    </p>
                  )}
                </div>

                <div className="bg-gray-700 rounded-lg p-4">
                  <div className="flex items-center space-x-2">
                    <Database className="w-5 h-5 text-blue-400" />
                    <h4 className="font-medium text-white">Database Type</h4>
                  </div>
                  <p className="mt-2 text-blue-400">{scanResults.dbms || 'Unknown'}</p>
                </div>

                <div className="bg-gray-700 rounded-lg p-4">
                  <div className="flex items-center space-x-2">
                    <Shield className="w-5 h-5 text-yellow-400" />
                    <h4 className="font-medium text-white">Risk Score</h4>
                  </div>
                  <p className={`mt-2 font-bold ${getSeverityColor(scanResults.executiveSummary.riskScore)}`}>
                    {scanResults.executiveSummary.riskScore}/10
                  </p>
                </div>
              </div>

              {scanResults.executiveSummary.criticalFindings.length > 0 && (
                <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4">
                  <h4 className="font-medium text-red-400 mb-2">Critical Findings</h4>
                  <ul className="space-y-1">
                    {scanResults.executiveSummary.criticalFindings.map((finding, index) => (
                      <li key={index} className="text-red-300 text-sm">• {finding}</li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-4">
                <h4 className="font-medium text-blue-400 mb-2">Recommendations</h4>
                <ul className="space-y-1">
                  {scanResults.executiveSummary.recommendations.map((rec, index) => (
                    <li key={index} className="text-blue-300 text-sm">• {rec}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}

          {viewMode === 'databases' && scanResults.databases && (
            <div className="space-y-4">
              <div className="flex space-x-4">
                <select
                  value={selectedDatabase}
                  onChange={(e) => setSelectedDatabase(e.target.value)}
                  className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white"
                >
                  {scanResults.databases.map(db => (
                    <option key={db} value={db}>{db}</option>
                  ))}
                </select>

                {selectedDatabase && scanResults.tables && scanResults.tables[selectedDatabase] && (
                  <select
                    value={selectedTable}
                    onChange={(e) => setSelectedTable(e.target.value)}
                    className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white"
                  >
                    <option value="">Select Table</option>
                    {scanResults.tables[selectedDatabase].map(table => (
                      <option key={table} value={table}>{table}</option>
                    ))}
                  </select>
                )}
              </div>

              {selectedDatabase && (
                <div className="bg-gray-700 rounded-lg p-4">
                  <h4 className="font-medium text-white mb-2">Database: {selectedDatabase}</h4>
                  {scanResults.tables && scanResults.tables[selectedDatabase] && (
                    <div className="space-y-2">
                      <p className="text-gray-300">Tables found:</p>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                        {scanResults.tables[selectedDatabase].map(table => (
                          <div key={table} className="bg-gray-600 rounded px-2 py-1 text-sm">
                            {table}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {viewMode === 'payloads' && (
            <div className="space-y-4">
              <div className="bg-gray-700 rounded-lg p-4">
                <h4 className="font-medium text-white mb-2">Successful Payload</h4>
                <div className="bg-gray-900 rounded p-3 font-mono text-sm text-green-400">
                  {scanResults.payload || 'No payload information available'}
                </div>
              </div>
            </div>
          )}

          {viewMode === 'report' && (
            <div className="space-y-4">
              <div className="bg-gray-700 rounded-lg p-4">
                <h4 className="font-medium text-white mb-4">Executive Summary</h4>
                <div className="space-y-3 text-gray-300">
                  <p><strong>Target:</strong> {target}</p>
                  <p><strong>Scan Date:</strong> {new Date().toLocaleString()}</p>
                  <p><strong>Total Vulnerabilities:</strong> {scanResults.executiveSummary.totalVulns}</p>
                  <p><strong>Risk Assessment:</strong> <span className={getSeverityColor(scanResults.executiveSummary.riskScore)}>{scanResults.executiveSummary.riskScore}/10</span></p>
                  
                  {scanResults.vulnerable && (
                    <div className="mt-4 p-3 bg-red-900/20 border border-red-500/30 rounded">
                      <p className="text-red-400 font-medium">⚠️ SQL Injection Vulnerability Detected</p>
                      <p className="text-sm text-red-300 mt-1">
                        The application is vulnerable to {scanResults.injectionType} SQL injection attacks.
                        Immediate remediation is required to prevent data breach.
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default SqlmapScanner
