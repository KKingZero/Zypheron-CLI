import React, { useState, useEffect } from 'react'
import { 
  Globe, 
  Play, 
  Pause, 
  Wifi, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Clock,
  Network,
  Server,
  Lock,
  Eye,
  Download,
  Settings
} from 'lucide-react'
import toast from 'react-hot-toast'

interface WebPortScannerProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

interface PortScanResult {
  host: string
  ports: {
    port: number
    state: 'open' | 'closed' | 'filtered'
    service: string
    version?: string
    banner?: string
    ssl?: boolean
  }[]
  hostInfo: {
    os?: string
    hostname?: string
    uptime?: string
  }
  executiveSummary: {
    totalPorts: number
    openPorts: number
    vulnerableServices: string[]
    recommendations: string[]
    riskScore: number
  }
}

const WebPortScanner: React.FC<WebPortScannerProps> = ({ onToolExecute }) => {
  const [target, setTarget] = useState<string>('')
  const [scanType, setScanType] = useState<string>('tcp_syn')
  const [portRange, setPortRange] = useState<string>('1-1000')
  const [timing, setTiming] = useState<number>(3)
  const [detectOS, setDetectOS] = useState<boolean>(false)
  const [detectServices, setDetectServices] = useState<boolean>(true)
  const [aggressiveScan, setAggressiveScan] = useState<boolean>(false)
  const [customPorts, setCustomPorts] = useState<string>('')
  const [isScanning, setIsScanning] = useState(false)
  const [scanResults, setScanResults] = useState<PortScanResult | null>(null)
  const [scanProgress, setScanProgress] = useState<number>(0)
  const [currentPhase, setCurrentPhase] = useState<string>('Ready')
  const [viewMode, setViewMode] = useState<'summary' | 'detailed' | 'services' | 'report'>('summary')

  const scanTypes = [
    { value: 'tcp_syn', label: 'TCP SYN Scan', description: 'Stealthy half-open connection scan' },
    { value: 'tcp_connect', label: 'TCP Connect Scan', description: 'Full TCP connection scan' },
    { value: 'udp', label: 'UDP Scan', description: 'UDP port scanning' },
    { value: 'stealth', label: 'Stealth Scan', description: 'FIN, NULL, Xmas scans' },
    { value: 'ping_sweep', label: 'Ping Sweep', description: 'Host discovery scan' },
    { value: 'comprehensive', label: 'Comprehensive', description: 'All scan types combined' }
  ]

  const commonPorts = [
    '1-1024', '1-65535', '80,443', '21,22,23,25,53,80,110,443,993,995',
    '135,139,445', '1433,1521,3306,5432', '6000-6063', '8080,8443,9090'
  ]

  const startScan = async () => {
    if (!target.trim()) {
      toast.error('Please enter a target host or IP')
      return
    }

    setIsScanning(true)
    setScanProgress(0)
    setCurrentPhase('Initializing scan...')
    
    let progressInterval: NodeJS.Timeout | null = null
    
    try {
      const params = {
        target: target.trim(),
        scanType,
        portRange: customPorts || portRange,
        timing,
        detectOS,
        detectServices,
        aggressive: aggressiveScan
      }

      // Simulate scan progress
      progressInterval = setInterval(() => {
        setScanProgress(prev => {
          const newProgress = Math.min(prev + Math.random() * 10, 95)
          if (newProgress < 20) setCurrentPhase('Resolving hostname...')
          else if (newProgress < 40) setCurrentPhase('Discovering host...')
          else if (newProgress < 70) setCurrentPhase('Scanning ports...')
          else if (newProgress < 90) setCurrentPhase('Service detection...')
          else setCurrentPhase('Generating report...')
          return newProgress
        })
      }, 800)

      const result = await onToolExecute('web_port_scan', params)
      
      setScanProgress(100)
      setCurrentPhase('Scan completed')
      
      if (result) {
        setScanResults(result)
      }
    } catch (error) {
      console.error('Port scan failed:', error)
      toast.error('Port scan failed')
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

  const getPortStateColor = (state: string) => {
    switch (state) {
      case 'open': return 'text-green-400'
      case 'closed': return 'text-gray-400'
      case 'filtered': return 'text-yellow-400'
      default: return 'text-gray-400'
    }
  }

  const getPortStateIcon = (state: string) => {
    switch (state) {
      case 'open': return <CheckCircle className="w-4 h-4 text-green-400" />
      case 'closed': return <X className="w-4 h-4 text-gray-400" />
      case 'filtered': return <AlertTriangle className="w-4 h-4 text-yellow-400" />
      default: return <Clock className="w-4 h-4 text-gray-400" />
    }
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
      scanType,
      results: scanResults
    }
    
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `port_scan_${target.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}.json`
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
          <Network className="w-5 h-5 text-green-400" />
          <h3 className="text-lg font-medium text-white">Web Port Scanner</h3>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Target Host/IP
              </label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com or 192.168.1.1"
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Scan Type
              </label>
              <select
                value={scanType}
                onChange={(e) => setScanType(e.target.value)}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-green-500"
              >
                {scanTypes.map(type => (
                  <option key={type.value} value={type.value}>
                    {type.label}
                  </option>
                ))}
              </select>
              <p className="text-xs text-gray-400 mt-1">
                {scanTypes.find(t => t.value === scanType)?.description}
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Port Range
              </label>
              <select
                value={portRange}
                onChange={(e) => setPortRange(e.target.value)}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-green-500"
              >
                {commonPorts.map(range => (
                  <option key={range} value={range}>
                    {range}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Custom Ports (optional)
              </label>
              <input
                type="text"
                value={customPorts}
                onChange={(e) => setCustomPorts(e.target.value)}
                placeholder="80,443,8080 or 8000-8100"
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-500"
              />
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Timing Template (1=Slow, 5=Fast)
              </label>
              <input
                type="range"
                min="1"
                max="5"
                value={timing}
                onChange={(e) => setTiming(parseInt(e.target.value))}
                className="w-full"
              />
              <div className="flex justify-between text-xs text-gray-400">
                <span>Paranoid</span>
                <span>Sneaky</span>
                <span>Polite</span>
                <span>Normal</span>
                <span>Aggressive</span>
                <span>Insane</span>
              </div>
              <div className="text-center text-sm text-gray-400 mt-1">T{timing}</div>
            </div>

            <div className="space-y-3">
              <div className="flex items-center">
                <input
                  type="checkbox"
                  id="detectServices"
                  checked={detectServices}
                  onChange={(e) => setDetectServices(e.target.checked)}
                  className="rounded bg-gray-700 border-gray-600"
                />
                <label htmlFor="detectServices" className="ml-2 text-sm text-gray-300">
                  Service Version Detection
                </label>
              </div>

              <div className="flex items-center">
                <input
                  type="checkbox"
                  id="detectOS"
                  checked={detectOS}
                  onChange={(e) => setDetectOS(e.target.checked)}
                  className="rounded bg-gray-700 border-gray-600"
                />
                <label htmlFor="detectOS" className="ml-2 text-sm text-gray-300">
                  OS Detection
                </label>
              </div>

              <div className="flex items-center">
                <input
                  type="checkbox"
                  id="aggressiveScan"
                  checked={aggressiveScan}
                  onChange={(e) => setAggressiveScan(e.target.checked)}
                  className="rounded bg-gray-700 border-gray-600"
                />
                <label htmlFor="aggressiveScan" className="ml-2 text-sm text-gray-300">
                  Aggressive Scan (OS + Service + Script + Traceroute)
                </label>
              </div>
            </div>
          </div>
        </div>

        <div className="flex justify-between items-center mt-6">
          <div className="flex items-center space-x-4">
            {!isScanning ? (
              <button
                onClick={startScan}
                className="flex items-center space-x-2 px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors"
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
              className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
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
              className="bg-green-600 h-2 rounded-full transition-all duration-300"
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
            <h3 className="text-lg font-medium text-white">Scan Results - {scanResults.host}</h3>
            <div className="flex space-x-2">
              {['summary', 'detailed', 'services', 'report'].map((mode) => (
                <button
                  key={mode}
                  onClick={() => setViewMode(mode as any)}
                  className={`px-3 py-1 rounded text-sm ${
                    viewMode === mode
                      ? 'bg-green-600 text-white'
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
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="bg-gray-700 rounded-lg p-4">
                  <div className="flex items-center space-x-2">
                    <Globe className="w-5 h-5 text-blue-400" />
                    <h4 className="font-medium text-white">Host</h4>
                  </div>
                  <p className="mt-2 text-blue-400">{scanResults.host}</p>
                  {scanResults.hostInfo.hostname && (
                    <p className="text-sm text-gray-400">{scanResults.hostInfo.hostname}</p>
                  )}
                </div>

                <div className="bg-gray-700 rounded-lg p-4">
                  <div className="flex items-center space-x-2">
                    <CheckCircle className="w-5 h-5 text-green-400" />
                    <h4 className="font-medium text-white">Open Ports</h4>
                  </div>
                  <p className="mt-2 text-green-400 font-bold text-2xl">
                    {scanResults.executiveSummary.openPorts}
                  </p>
                  <p className="text-sm text-gray-400">
                    of {scanResults.executiveSummary.totalPorts} scanned
                  </p>
                </div>

                <div className="bg-gray-700 rounded-lg p-4">
                  <div className="flex items-center space-x-2">
                    <Server className="w-5 h-5 text-purple-400" />
                    <h4 className="font-medium text-white">Services</h4>
                  </div>
                  <p className="mt-2 text-purple-400 font-bold text-2xl">
                    {new Set(scanResults.ports.filter(p => p.state === 'open').map(p => p.service)).size}
                  </p>
                  <p className="text-sm text-gray-400">unique services</p>
                </div>

                <div className="bg-gray-700 rounded-lg p-4">
                  <div className="flex items-center space-x-2">
                    <Shield className="w-5 h-5 text-yellow-400" />
                    <h4 className="font-medium text-white">Risk Score</h4>
                  </div>
                  <p className={`mt-2 font-bold text-2xl ${getSeverityColor(scanResults.executiveSummary.riskScore)}`}>
                    {scanResults.executiveSummary.riskScore}/10
                  </p>
                </div>
              </div>

              {scanResults.hostInfo.os && (
                <div className="bg-gray-700 rounded-lg p-4">
                  <h4 className="font-medium text-white mb-2">Operating System</h4>
                  <p className="text-gray-300">{scanResults.hostInfo.os}</p>
                </div>
              )}

              {scanResults.executiveSummary.vulnerableServices.length > 0 && (
                <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4">
                  <h4 className="font-medium text-red-400 mb-2">Potentially Vulnerable Services</h4>
                  <ul className="space-y-1">
                    {scanResults.executiveSummary.vulnerableServices.map((service, index) => (
                      <li key={index} className="text-red-300 text-sm">• {service}</li>
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

          {viewMode === 'detailed' && (
            <div className="space-y-4">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-gray-600">
                      <th className="text-left py-2 text-gray-300">Port</th>
                      <th className="text-left py-2 text-gray-300">State</th>
                      <th className="text-left py-2 text-gray-300">Service</th>
                      <th className="text-left py-2 text-gray-300">Version</th>
                      <th className="text-left py-2 text-gray-300">SSL</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanResults.ports.map((port, index) => (
                      <tr key={index} className="border-b border-gray-700">
                        <td className="py-2 text-white font-mono">{port.port}</td>
                        <td className="py-2">
                          <div className="flex items-center space-x-2">
                            {getPortStateIcon(port.state)}
                            <span className={getPortStateColor(port.state)}>
                              {port.state}
                            </span>
                          </div>
                        </td>
                        <td className="py-2 text-gray-300">{port.service}</td>
                        <td className="py-2 text-gray-400 text-sm">{port.version || '-'}</td>
                        <td className="py-2">
                          {port.ssl && <Lock className="w-4 h-4 text-green-400" />}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {viewMode === 'services' && (
            <div className="space-y-4">
              {Array.from(new Set(scanResults.ports.filter(p => p.state === 'open').map(p => p.service))).map((service) => {
                const servicePorts = scanResults.ports.filter(p => p.service === service && p.state === 'open')
                return (
                  <div key={service} className="bg-gray-700 rounded-lg p-4">
                    <h4 className="font-medium text-white mb-2 capitalize">{service}</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                      {servicePorts.map((port, index) => (
                        <div key={index} className="bg-gray-600 rounded p-3">
                          <div className="flex items-center justify-between mb-2">
                            <span className="font-mono text-green-400">:{port.port}</span>
                            {port.ssl && <Lock className="w-4 h-4 text-green-400" />}
                          </div>
                          {port.version && (
                            <p className="text-sm text-gray-300 mb-2">{port.version}</p>
                          )}
                          {port.banner && (
                            <p className="text-xs text-gray-400 font-mono">{port.banner}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )
              })}
            </div>
          )}

          {viewMode === 'report' && (
            <div className="space-y-4">
              <div className="bg-gray-700 rounded-lg p-4">
                <h4 className="font-medium text-white mb-4">Port Scan Report</h4>
                <div className="space-y-3 text-gray-300">
                  <p><strong>Target:</strong> {scanResults.host}</p>
                  <p><strong>Scan Date:</strong> {new Date().toLocaleString()}</p>
                  <p><strong>Scan Type:</strong> {scanTypes.find(t => t.value === scanType)?.label}</p>
                  <p><strong>Ports Scanned:</strong> {scanResults.executiveSummary.totalPorts}</p>
                  <p><strong>Open Ports:</strong> {scanResults.executiveSummary.openPorts}</p>
                  <p><strong>Risk Assessment:</strong> <span className={getSeverityColor(scanResults.executiveSummary.riskScore)}>{scanResults.executiveSummary.riskScore}/10</span></p>
                  
                  {scanResults.executiveSummary.openPorts > 0 && (
                    <div className="mt-4 p-3 bg-yellow-900/20 border border-yellow-500/30 rounded">
                      <p className="text-yellow-400 font-medium">Open Ports Detected</p>
                      <p className="text-sm text-yellow-300 mt-1">
                        {scanResults.executiveSummary.openPorts} open ports found. Review services and apply security hardening measures.
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

export default WebPortScanner
