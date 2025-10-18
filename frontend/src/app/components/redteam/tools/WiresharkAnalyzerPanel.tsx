import React, { useState, useEffect } from 'react'
import { Activity, Upload, Play, Pause, Download, Filter, AlertTriangle, Network, Eye, Brain } from 'lucide-react'

interface PacketData {
  id: string
  timestamp: string
  source: string
  destination: string
  protocol: string
  length: number
  info: string
  suspicious: boolean
  threatLevel: 'low' | 'medium' | 'high'
}

interface SuspiciousFlow {
  id: string
  flowType: string
  source: string
  destination: string
  protocol: string
  threat: string
  severity: 'low' | 'medium' | 'high'
  alertLevel: string
  description: string
  recommendedMitigation: string
}

interface GPTExplanation {
  flowId: string
  explanation: string
  severity: string
  mitigation: string
}

interface WiresharkAnalyzerPanelProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

const WiresharkAnalyzerPanel: React.FC<WiresharkAnalyzerPanelProps> = ({ onToolExecute }) => {
  const [analysisMode, setAnalysisMode] = useState<'live' | 'file'>('live')
  const [interface_, setInterface] = useState<string>('eth0')
  const [captureFile, setCaptureFile] = useState<string>('')
  const [filter, setFilter] = useState<string>('')
  const [isCapturing, setIsCapturing] = useState(false)
  const [packetData, setPacketData] = useState<PacketData[]>([])
  const [suspiciousFlows, setSuspiciousFlows] = useState<SuspiciousFlow[]>([])
  const [gptExplanations, setGptExplanations] = useState<GPTExplanation[]>([])
  const [selectedPacket, setSelectedPacket] = useState<PacketData | null>(null)
  const [protocolStats, setProtocolStats] = useState<Record<string, number>>({})

  const networkInterfaces = [
    'eth0', 'eth1', 'wlan0', 'wlan1', 'lo', 'any'
  ]

  const commonFilters = [
    'http',
    'https',
    'tcp',
    'udp',
    'dns',
    'ssh',
    'ftp',
    'telnet',
    'smtp',
    'pop3'
  ]

  const startLiveCapture = async () => {
    setIsCapturing(true)
    try {
      const result = await onToolExecute('wireshark_analyze', {
        interface: interface_,
        filter: filter || undefined
      })

      if (result.packetStats) {
        setPacketData(result.packetStats.packets || [])
        setSuspiciousFlows(result.suspiciousFlows || [])
        setGptExplanations(result.gptTranslations?.explanations || [])
        setProtocolStats(result.visualization?.protocolDistribution || {})
      }
    } catch (error) {
      console.error('Live capture failed:', error)
    } finally {
      setIsCapturing(false)
    }
  }

  const analyzeFile = async () => {
    if (!captureFile) return

    try {
      const result = await onToolExecute('wireshark_analyze', {
        captureFile,
        filter: filter || undefined
      })

      if (result.packetStats) {
        setPacketData(result.packetStats.packets || [])
        setSuspiciousFlows(result.suspiciousFlows || [])
        setGptExplanations(result.gptTranslations?.explanations || [])
        setProtocolStats(result.visualization?.protocolDistribution || {})
      }
    } catch (error) {
      console.error('File analysis failed:', error)
    }
  }

  const stopCapture = () => {
    setIsCapturing(false)
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high': return 'text-red-500 bg-red-500/20'
      case 'medium': return 'text-yellow-500 bg-yellow-500/20'
      case 'low': return 'text-green-500 bg-green-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  const getProtocolColor = (protocol: string) => {
    const colors = {
      'HTTP': 'bg-blue-500',
      'HTTPS': 'bg-green-500',
      'TCP': 'bg-purple-500',
      'UDP': 'bg-orange-500',
      'DNS': 'bg-yellow-500',
      'SSH': 'bg-red-500',
      'FTP': 'bg-pink-500'
    }
    return colors[protocol as keyof typeof colors] || 'bg-gray-500'
  }

  return (
    <div className="space-y-6">
      {/* Wireshark Header */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h3 className="text-xl font-bold text-terminal-text mb-4 flex items-center">
          <Network className="w-6 h-6 mr-3 text-blue-500" />
          Wireshark AI Packet Analyzer
          <span className="ml-3 px-3 py-1 bg-blue-500 text-white text-sm rounded-full">GPT-ENHANCED</span>
        </h3>
        <p className="text-terminal-muted">
          Advanced packet analysis with AI-powered threat detection and explanation
        </p>
      </div>

      {/* Analysis Mode Selection */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h4 className="text-lg font-semibold text-terminal-text mb-4">Analysis Configuration</h4>
        
        <div className="flex space-x-4 mb-6">
          <button
            onClick={() => setAnalysisMode('live')}
            className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
              analysisMode === 'live' 
                ? 'bg-blue-600 text-white' 
                : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>Live Capture</span>
          </button>
          <button
            onClick={() => setAnalysisMode('file')}
            className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
              analysisMode === 'file' 
                ? 'bg-blue-600 text-white' 
                : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
            }`}
          >
            <Upload className="w-4 h-4" />
            <span>File Analysis</span>
          </button>
        </div>

        {analysisMode === 'live' ? (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-terminal-text font-medium mb-2">
                Network Interface
              </label>
              <select
                value={interface_}
                onChange={(e) => setInterface(e.target.value)}
                className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
              >
                {networkInterfaces.map((iface) => (
                  <option key={iface} value={iface}>{iface}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-terminal-text font-medium mb-2">
                Capture Filter
              </label>
              <input
                type="text"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="tcp port 80"
                className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
              />
            </div>

            <div className="md:col-span-2 flex items-end space-x-2">
              <button
                onClick={startLiveCapture}
                disabled={isCapturing}
                className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 text-white rounded-lg flex items-center space-x-2 transition-colors"
              >
                {isCapturing ? (
                  <>
                    <Activity className="w-4 h-4 animate-spin" />
                    <span>Capturing...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4" />
                    <span>Start Capture</span>
                  </>
                )}
              </button>
              
              {isCapturing && (
                <button
                  onClick={stopCapture}
                  className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg flex items-center space-x-2 transition-colors"
                >
                  <Pause className="w-4 h-4" />
                  <span>Stop</span>
                </button>
              )}
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-2">
              <label className="block text-terminal-text font-medium mb-2">
                Capture File (.pcap, .pcapng)
              </label>
              <input
                type="text"
                value={captureFile}
                onChange={(e) => setCaptureFile(e.target.value)}
                placeholder="/path/to/capture.pcap"
                className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
              />
            </div>
            
            <div className="flex items-end">
              <button
                onClick={analyzeFile}
                disabled={!captureFile}
                className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white rounded-lg flex items-center justify-center space-x-2 transition-colors"
              >
                <Eye className="w-4 h-4" />
                <span>Analyze File</span>
              </button>
            </div>
          </div>
        )}

        {/* Quick Filters */}
        <div className="mt-4">
          <label className="block text-terminal-text font-medium mb-2">Quick Filters:</label>
          <div className="flex flex-wrap gap-2">
            {commonFilters.map((quickFilter) => (
              <button
                key={quickFilter}
                onClick={() => setFilter(quickFilter)}
                className="px-3 py-1 bg-gray-600 hover:bg-gray-500 text-white text-sm rounded transition-colors"
              >
                {quickFilter}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Protocol Statistics */}
      {Object.keys(protocolStats).length > 0 && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">Protocol Distribution</h4>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
            {Object.entries(protocolStats).map(([protocol, count]) => (
              <div key={protocol} className="bg-terminal-bg border border-terminal-border rounded p-3 text-center">
                <div className={`w-full h-2 rounded mb-2 ${getProtocolColor(protocol)}`}></div>
                <div className="font-medium text-terminal-text">{protocol}</div>
                <div className="text-terminal-muted text-sm">{count} packets</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Suspicious Flows */}
      {suspiciousFlows.length > 0 && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <AlertTriangle className="w-5 h-5 mr-2 text-red-500" />
            Suspicious Network Flows
          </h4>
          
          <div className="space-y-3">
            {suspiciousFlows.map((flow) => (
              <div
                key={flow.id}
                className={`border border-terminal-border rounded-lg p-4 ${
                  flow.severity === 'high' ? 'border-red-500/50 bg-red-500/5' :
                  flow.severity === 'medium' ? 'border-yellow-500/50 bg-yellow-500/5' :
                  'border-green-500/50 bg-green-500/5'
                }`}
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-3">
                    <span className="font-medium text-terminal-text">{flow.flowType}</span>
                    <span className="text-terminal-muted text-sm">{flow.protocol}</span>
                  </div>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(flow.severity)}`}>
                    {flow.severity.toUpperCase()}
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-3">
                  <div>
                    <span className="text-terminal-muted">Source:</span>
                    <span className="ml-2 text-terminal-text font-mono">{flow.source}</span>
                  </div>
                  <div>
                    <span className="text-terminal-muted">Destination:</span>
                    <span className="ml-2 text-terminal-text font-mono">{flow.destination}</span>
                  </div>
                </div>

                <div className="mb-3">
                  <span className="text-terminal-muted">Threat:</span>
                  <span className="ml-2 text-terminal-text">{flow.threat}</span>
                </div>

                {/* GPT Explanation */}
                {gptExplanations.find(exp => exp.flowId === flow.id) && (
                  <div className="bg-blue-500/10 border border-blue-500/20 rounded p-3">
                    <h5 className="font-medium text-blue-300 mb-2 flex items-center">
                      <Brain className="w-4 h-4 mr-2" />
                      AI Analysis
                    </h5>
                    <p className="text-blue-200 text-sm mb-2">
                      {gptExplanations.find(exp => exp.flowId === flow.id)?.explanation}
                    </p>
                    <div className="text-blue-300 text-sm">
                      <strong>Recommended Action:</strong> {gptExplanations.find(exp => exp.flowId === flow.id)?.mitigation}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Packet Table */}
      {packetData.length > 0 && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">Captured Packets</h4>
          
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-terminal-border">
                  <th className="text-left p-2 text-terminal-text">Time</th>
                  <th className="text-left p-2 text-terminal-text">Source</th>
                  <th className="text-left p-2 text-terminal-text">Destination</th>
                  <th className="text-left p-2 text-terminal-text">Protocol</th>
                  <th className="text-left p-2 text-terminal-text">Length</th>
                  <th className="text-left p-2 text-terminal-text">Info</th>
                  <th className="text-left p-2 text-terminal-text">Risk</th>
                </tr>
              </thead>
              <tbody>
                {packetData.slice(0, 50).map((packet) => (
                  <tr
                    key={packet.id}
                    className={`border-b border-terminal-border hover:bg-terminal-bg cursor-pointer ${
                      packet.suspicious ? 'bg-red-500/5' : ''
                    }`}
                    onClick={() => setSelectedPacket(packet)}
                  >
                    <td className="p-2 text-terminal-muted font-mono text-xs">
                      {new Date(packet.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="p-2 text-terminal-text font-mono">{packet.source}</td>
                    <td className="p-2 text-terminal-text font-mono">{packet.destination}</td>
                    <td className="p-2">
                      <span className={`px-2 py-1 rounded text-xs text-white ${getProtocolColor(packet.protocol)}`}>
                        {packet.protocol}
                      </span>
                    </td>
                    <td className="p-2 text-terminal-muted">{packet.length}</td>
                    <td className="p-2 text-terminal-text max-w-xs truncate">{packet.info}</td>
                    <td className="p-2">
                      {packet.suspicious && (
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(packet.threatLevel)}`}>
                          {packet.threatLevel.toUpperCase()}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {packetData.length > 50 && (
            <div className="mt-4 text-center">
              <span className="text-terminal-muted text-sm">
                Showing first 50 of {packetData.length} packets
              </span>
            </div>
          )}
        </div>
      )}

      {/* Packet Details */}
      {selectedPacket && (
        <div className="bg-terminal-card border border-blue-500/20 rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">
            Packet Details: {selectedPacket.id}
          </h4>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-3">
              <div><span className="text-terminal-muted">Timestamp:</span> <span className="ml-2 text-terminal-text">{selectedPacket.timestamp}</span></div>
              <div><span className="text-terminal-muted">Source:</span> <span className="ml-2 text-terminal-text font-mono">{selectedPacket.source}</span></div>
              <div><span className="text-terminal-muted">Destination:</span> <span className="ml-2 text-terminal-text font-mono">{selectedPacket.destination}</span></div>
            </div>
            <div className="space-y-3">
              <div><span className="text-terminal-muted">Protocol:</span> <span className="ml-2 text-terminal-text">{selectedPacket.protocol}</span></div>
              <div><span className="text-terminal-muted">Length:</span> <span className="ml-2 text-terminal-text">{selectedPacket.length} bytes</span></div>
              <div><span className="text-terminal-muted">Suspicious:</span> <span className={`ml-2 ${selectedPacket.suspicious ? 'text-red-400' : 'text-green-400'}`}>{selectedPacket.suspicious ? 'Yes' : 'No'}</span></div>
            </div>
          </div>
          
          <div className="mt-4">
            <span className="text-terminal-muted">Info:</span>
            <div className="mt-2 bg-terminal-bg border border-terminal-border rounded p-3">
              <pre className="text-terminal-text text-sm whitespace-pre-wrap">{selectedPacket.info}</pre>
            </div>
          </div>
        </div>
      )}

      {/* Export Options */}
      {packetData.length > 0 && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-4">
          <div className="flex items-center justify-between">
            <span className="text-terminal-text font-medium">Export Results</span>
            <div className="flex space-x-2">
              <button className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>PCAP</span>
              </button>
              <button className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>CSV</span>
              </button>
              <button className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>Report</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default WiresharkAnalyzerPanel