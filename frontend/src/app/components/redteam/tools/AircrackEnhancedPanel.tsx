import React, { useState, useEffect } from 'react'
import { Wifi, Target, Shield, Zap, Activity, TrendingUp, AlertTriangle, CheckCircle } from 'lucide-react'

interface WirelessTarget {
  id: string
  bssid: string
  essid: string
  channel: number
  signalStrength: number
  encryption: string
  exploitability: 'low' | 'medium' | 'high'
  rank: number
  clients: number
  aiAnalysis: string
}

interface HandshakeAnalysis {
  handshakeStrength: string
  crackability: string
  estimatedTime: string
  crackedPasswords: string[]
  recommendations: string[]
}

interface AircrackEnhancedPanelProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

const AircrackEnhancedPanel: React.FC<AircrackEnhancedPanelProps> = ({ onToolExecute }) => {
  const [activeInterface, setActiveInterface] = useState<string>('wlan0')
  const [wirelessTargets, setWirelessTargets] = useState<WirelessTarget[]>([])
  const [selectedTarget, setSelectedTarget] = useState<WirelessTarget | null>(null)
  const [handshakeFile, setHandshakeFile] = useState<string>('')
  const [handshakeAnalysis, setHandshakeAnalysis] = useState<HandshakeAnalysis | null>(null)
  const [isScanning, setIsScanning] = useState(false)
  const [scanMode, setScanMode] = useState<'passive' | 'active'>('passive')
  const [liveVisualization, setLiveVisualization] = useState(false)

  const startWirelessScan = async () => {
    setIsScanning(true)
    try {
      const result = await onToolExecute('aircrack_enhanced', {
        interface: activeInterface,
        mode: scanMode
      })

      if (result.targets) {
        setWirelessTargets(result.targets)
        setLiveVisualization(result.liveVisualization)
      }
    } catch (error) {
      console.error('Wireless scan failed:', error)
    } finally {
      setIsScanning(false)
    }
  }

  const analyzeHandshake = async () => {
    if (!handshakeFile) return

    try {
      const result = await onToolExecute('aircrack_enhanced', {
        handshakeFile,
        interface: activeInterface
      })

      if (result.analysis) {
        setHandshakeAnalysis(result.analysis)
      }
    } catch (error) {
      console.error('Handshake analysis failed:', error)
    }
  }

  const getSignalBars = (strength: number) => {
    const bars = Math.ceil((strength + 100) / 20) // Convert dBm to 1-5 bars
    return Array.from({ length: 5 }, (_, i) => (
      <div
        key={i}
        className={`w-1 bg-gray-600 rounded-sm ${
          i < bars ? 'bg-green-500' : ''
        }`}
        style={{ height: `${(i + 1) * 3}px` }}
      />
    ))
  }

  const getExploitabilityColor = (level: string) => {
    switch (level) {
      case 'high': return 'text-red-500 bg-red-500/20'
      case 'medium': return 'text-yellow-500 bg-yellow-500/20'
      case 'low': return 'text-green-500 bg-green-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  return (
    <div className="space-y-6">
      {/* Enhanced Aircrack-ng Header */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h3 className="text-xl font-bold text-terminal-text mb-4 flex items-center">
          <Wifi className="w-6 h-6 mr-3 text-blue-500" />
          Enhanced Aircrack-ng Suite
          <span className="ml-3 px-3 py-1 bg-blue-500 text-white text-sm rounded-full">AI-POWERED</span>
        </h3>
        <p className="text-terminal-muted">
          Advanced wireless security assessment with AI-based target ranking and handshake analysis
        </p>
      </div>

      {/* Control Panel */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div>
            <label className="block text-terminal-text font-medium mb-2">
              Wireless Interface
            </label>
            <select
              value={activeInterface}
              onChange={(e) => setActiveInterface(e.target.value)}
              className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
            >
              <option value="wlan0">wlan0 (Primary)</option>
              <option value="wlan1">wlan1 (Secondary)</option>
              <option value="wlan0mon">wlan0mon (Monitor Mode)</option>
            </select>
          </div>

          <div>
            <label className="block text-terminal-text font-medium mb-2">
              Scan Mode
            </label>
            <select
              value={scanMode}
              onChange={(e) => setScanMode(e.target.value as 'passive' | 'active')}
              className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
            >
              <option value="passive">Passive Scanning</option>
              <option value="active">Active Scanning</option>
            </select>
          </div>

          <div className="flex items-end">
            <button
              onClick={startWirelessScan}
              disabled={isScanning}
              className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white rounded-lg flex items-center justify-center space-x-2 transition-colors"
            >
              {isScanning ? (
                <>
                  <Activity className="w-4 h-4 animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <Target className="w-4 h-4" />
                  <span>Start Scan</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Wireless Targets */}
      {wirelessTargets.length > 0 && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <TrendingUp className="w-5 h-5 mr-2 text-green-500" />
            AI-Ranked Wireless Targets
          </h4>
          
          <div className="space-y-3">
            {wirelessTargets
              .sort((a, b) => b.rank - a.rank)
              .map((target) => (
                <div
                  key={target.id}
                  className={`border border-terminal-border rounded-lg p-4 cursor-pointer transition-all hover:border-blue-500 ${
                    selectedTarget?.id === target.id ? 'border-blue-500 bg-blue-500/5' : ''
                  }`}
                  onClick={() => setSelectedTarget(target)}
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <div className="flex space-x-1">
                        {getSignalBars(target.signalStrength)}
                      </div>
                      <div>
                        <h5 className="font-medium text-terminal-text">
                          {target.essid || 'Hidden Network'}
                        </h5>
                        <p className="text-sm text-terminal-muted">{target.bssid}</p>
                      </div>
                    </div>
                    
                    <div className="flex items-center space-x-3">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getExploitabilityColor(target.exploitability)}`}>
                        {target.exploitability.toUpperCase()}
                      </span>
                      <span className="text-terminal-text font-bold">#{target.rank}</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div>
                      <span className="text-terminal-muted">Channel:</span>
                      <span className="ml-2 text-terminal-text">{target.channel}</span>
                    </div>
                    <div>
                      <span className="text-terminal-muted">Encryption:</span>
                      <span className="ml-2 text-terminal-text">{target.encryption}</span>
                    </div>
                    <div>
                      <span className="text-terminal-muted">Clients:</span>
                      <span className="ml-2 text-terminal-text">{target.clients}</span>
                    </div>
                    <div>
                      <span className="text-terminal-muted">Signal:</span>
                      <span className="ml-2 text-terminal-text">{target.signalStrength} dBm</span>
                    </div>
                  </div>

                  {target.aiAnalysis && (
                    <div className="mt-3 p-3 bg-blue-500/10 border border-blue-500/20 rounded">
                      <p className="text-sm text-blue-300">
                        <strong>AI Analysis:</strong> {target.aiAnalysis}
                      </p>
                    </div>
                  )}
                </div>
              ))}
          </div>
        </div>
      )}

      {/* Handshake Analysis */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h4 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
          <Shield className="w-5 h-5 mr-2 text-orange-500" />
          Handshake Analysis
        </h4>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div className="md:col-span-2">
            <label className="block text-terminal-text font-medium mb-2">
              Handshake File (.cap)
            </label>
            <input
              type="text"
              value={handshakeFile}
              onChange={(e) => setHandshakeFile(e.target.value)}
              placeholder="/path/to/handshake.cap"
              className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
            />
          </div>
          
          <div className="flex items-end">
            <button
              onClick={analyzeHandshake}
              disabled={!handshakeFile}
              className="w-full px-4 py-2 bg-orange-600 hover:bg-orange-700 disabled:bg-gray-600 text-white rounded-lg flex items-center justify-center space-x-2 transition-colors"
            >
              <Zap className="w-4 h-4" />
              <span>Analyze</span>
            </button>
          </div>
        </div>

        {handshakeAnalysis && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-terminal-bg border border-terminal-border rounded p-4">
                <h5 className="font-medium text-terminal-text mb-2">Handshake Strength</h5>
                <p className="text-terminal-muted">{handshakeAnalysis.handshakeStrength}</p>
              </div>
              <div className="bg-terminal-bg border border-terminal-border rounded p-4">
                <h5 className="font-medium text-terminal-text mb-2">Crackability</h5>
                <p className="text-terminal-muted">{handshakeAnalysis.crackability}</p>
              </div>
              <div className="bg-terminal-bg border border-terminal-border rounded p-4">
                <h5 className="font-medium text-terminal-text mb-2">Estimated Time</h5>
                <p className="text-terminal-muted">{handshakeAnalysis.estimatedTime}</p>
              </div>
            </div>

            {handshakeAnalysis.crackedPasswords.length > 0 && (
              <div className="bg-green-500/10 border border-green-500/20 rounded p-4">
                <h5 className="font-medium text-green-300 mb-2 flex items-center">
                  <CheckCircle className="w-4 h-4 mr-2" />
                  Cracked Passwords
                </h5>
                <div className="space-y-1">
                  {handshakeAnalysis.crackedPasswords.map((password, index) => (
                    <p key={index} className="text-green-200 font-mono">{password}</p>
                  ))}
                </div>
              </div>
            )}

            <div className="bg-yellow-500/10 border border-yellow-500/20 rounded p-4">
              <h5 className="font-medium text-yellow-300 mb-2 flex items-center">
                <AlertTriangle className="w-4 h-4 mr-2" />
                AI Recommendations
              </h5>
              <ul className="space-y-1">
                {handshakeAnalysis.recommendations.map((rec, index) => (
                  <li key={index} className="text-yellow-200 text-sm">• {rec}</li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </div>

      {/* Live Visualization Status */}
      {liveVisualization && (
        <div className="bg-terminal-card border border-green-500/20 rounded-lg p-4">
          <div className="flex items-center space-x-3">
            <div className="w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
            <span className="text-green-300 font-medium">Live Packet Visualization Active</span>
            <span className="text-terminal-muted text-sm">Real-time wireless traffic analysis in progress</span>
          </div>
        </div>
      )}
    </div>
  )
}

export default AircrackEnhancedPanel