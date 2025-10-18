import React, { useState, useEffect } from 'react'
import { 
  Radar, 
  Target, 
  Search, 
  Globe, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Play, 
  Eye,
  Network,
  Brain,
  Cpu,
  MapPin,
  Clock
} from 'lucide-react'
import toast from 'react-hot-toast'

interface ReconStageProps {
  operation: any
  onOperationStart: (target: string, operationName: string) => void
  onStageComplete: () => void
  toolsStatus: any
}

interface TargetInfo {
  domain: string
  ip: string
  ports: Array<{ port: number; service: string; state: string }>
  technologies: string[]
  osFingerprint: string
  firewalls: string[]
  subdomains: string[]
}

interface AIRecommendation {
  priority: 'high' | 'medium' | 'low'
  type: 'vulnerability' | 'configuration' | 'technique'
  title: string
  description: string
  confidence: number
}

const ReconStage: React.FC<ReconStageProps> = ({ 
  operation, 
  onOperationStart, 
  onStageComplete, 
  toolsStatus 
}) => {
  const [target, setTarget] = useState('')
  const [operationName, setOperationName] = useState('')
  const [scanType, setScanType] = useState<'basic' | 'aggressive' | 'stealth'>('basic')
  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [targetInfo, setTargetInfo] = useState<TargetInfo | null>(null)
  const [aiRecommendations, setAiRecommendations] = useState<AIRecommendation[]>([])
  const [riskScore, setRiskScore] = useState(0)
  const [scanLogs, setScanLogs] = useState<string[]>([])

  // AI-driven scan options
  const [osintEnabled, setOsintEnabled] = useState(true)
  const [osintSources, setOsintSources] = useState({
    shodan: true,
    censys: false,
    passiveDns: true,
    whois: true,
    subdomains: true
  })

  const startReconnaissance = async () => {
    if (!target.trim() || !operationName.trim()) {
      toast.error('Please provide target and operation name')
      return
    }

    if (!operation) {
      onOperationStart(target, operationName)
    }

    setIsScanning(true)
    setScanProgress(0)
    setScanLogs(['🧠 AI-Augmented Reconnaissance initiated...'])

    try {
      // Step 1: Basic target validation and initial AI assessment
      setScanProgress(10)
      setScanLogs(prev => [...prev, '🎯 Validating target and performing initial AI risk assessment...'])

      const aiAssessmentResponse = await fetch('/api/redteam/recon/ai-assessment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, scanType })
      })
      const aiAssessment = await aiAssessmentResponse.json()

      setScanProgress(25)
      setScanLogs(prev => [...prev, `🤖 AI Risk Assessment: ${aiAssessment.riskLevel} (${aiAssessment.confidence}% confidence)`])

      // Step 2: OSINT gathering if enabled
      if (osintEnabled) {
        setScanProgress(40)
        setScanLogs(prev => [...prev, '🔍 Gathering OSINT intelligence...'])

        const osintResponse = await fetch('/api/redteam/recon/osint', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target, sources: osintSources })
        })
        const osintData = await osintResponse.json()

        setScanLogs(prev => [...prev, `📊 OSINT Complete: Found ${osintData.findings.length} data points`])
      }

      // Step 3: Nmap scanning with AI optimization
      setScanProgress(60)
      setScanLogs(prev => [...prev, '🛡️ Running AI-optimized Nmap scan...'])

      const nmapResponse = await fetch('/api/redteam/recon/nmap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          target, 
          scanType,
          aiOptimized: true,
          riskTolerance: aiAssessment.riskLevel 
        })
      })
      const nmapData = await nmapResponse.json()

      setScanProgress(80)
      setScanLogs(prev => [...prev, `🔍 Port scan complete: ${nmapData.openPorts} open ports discovered`])

      // Step 4: AI analysis and recommendations
      setScanProgress(90)
      setScanLogs(prev => [...prev, '🧠 AI analyzing findings and generating recommendations...'])

      const aiAnalysisResponse = await fetch('/api/redteam/recon/ai-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          target,
          nmapData,
          osintData: osintEnabled ? osintData : null,
          scanType
        })
      })
      const analysis = await aiAnalysisResponse.json()

      setTargetInfo(analysis.targetInfo)
      setAiRecommendations(analysis.recommendations)
      setRiskScore(analysis.riskScore)

      setScanProgress(100)
      setScanLogs(prev => [...prev, `✅ Reconnaissance complete! Risk Score: ${analysis.riskScore}/10`])

      toast.success('AI-Augmented Reconnaissance completed successfully')

    } catch (error) {
      console.error('Reconnaissance failed:', error)
      toast.error('Reconnaissance failed. Please check your target and try again.')
      setScanLogs(prev => [...prev, `❌ Error: ${error.message}`])
    } finally {
      setIsScanning(false)
    }
  }

  const getScanTypeDescription = (type: string) => {
    switch (type) {
      case 'basic':
        return 'Standard reconnaissance with common ports and services'
      case 'aggressive':
        return 'Comprehensive scan with OS detection and service enumeration'
      case 'stealth':
        return 'Low-profile scanning to avoid detection systems'
      default:
        return ''
    }
  }

  const getRiskColor = (score: number) => {
    if (score >= 8) return 'text-red-500'
    if (score >= 5) return 'text-yellow-500'
    return 'text-green-500'
  }

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'high': return 'border-red-500 bg-red-500/10'
      case 'medium': return 'border-yellow-500 bg-yellow-500/10'
      case 'low': return 'border-green-500 bg-green-500/10'
      default: return 'border-terminal-border bg-terminal-card'
    }
  }

  return (
    <div className="space-y-6">
      {/* Stage Header */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h2 className="text-2xl font-bold text-terminal-text mb-2 flex items-center">
          <Radar className="w-6 h-6 mr-3 text-cobra-500" />
          Stage 1: AI-Augmented Reconnaissance
        </h2>
        <p className="text-terminal-muted text-lg">
          Use AI for pre-scan risk assessment, target fingerprinting, and weak point prediction
        </p>
      </div>

      {/* Operation Setup (only show if no operation is running) */}
      {!operation && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <Target className="w-5 h-5 mr-2 text-cobra-500" />
            Initialize Red Team Operation
          </h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm font-medium text-terminal-text mb-2">
                Operation Name
              </label>
              <input
                type="text"
                value={operationName}
                onChange={(e) => setOperationName(e.target.value)}
                placeholder="e.g., Corporate Security Assessment 2024"
                className="w-full px-4 py-3 bg-terminal-bg border border-terminal-border rounded-lg text-terminal-text placeholder-terminal-muted focus:border-cobra-500 focus:ring-1 focus:ring-cobra-500 transition-colors"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-terminal-text mb-2">
                Target Domain/IP
              </label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com or 192.168.1.1"
                className="w-full px-4 py-3 bg-terminal-bg border border-terminal-border rounded-lg text-terminal-text placeholder-terminal-muted focus:border-cobra-500 focus:ring-1 focus:ring-cobra-500 transition-colors"
              />
            </div>
          </div>
        </div>
      )}

      {/* Scan Configuration */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
          <Search className="w-5 h-5 mr-2 text-cobra-500" />
          AI-Powered Scan Configuration
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Scan Type Selection */}
          <div>
            <label className="block text-sm font-medium text-terminal-text mb-3">
              Scan Intensity
            </label>
            <div className="space-y-3">
              {[
                { id: 'basic', label: 'Basic Reconnaissance', icon: Eye },
                { id: 'aggressive', label: 'Aggressive Scanning', icon: Cpu },
                { id: 'stealth', label: 'Stealth Mode', icon: Shield }
              ].map(({ id, label, icon: Icon }) => (
                <label key={id} className="flex items-center space-x-3 cursor-pointer">
                  <input
                    type="radio"
                    name="scanType"
                    value={id}
                    checked={scanType === id}
                    onChange={(e) => setScanType(e.target.value as any)}
                    className="text-cobra-500 focus:ring-cobra-500"
                  />
                  <Icon className="w-4 h-4 text-terminal-muted" />
                  <div>
                    <p className="text-terminal-text font-medium">{label}</p>
                    <p className="text-xs text-terminal-muted">
                      {getScanTypeDescription(id)}
                    </p>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* OSINT Configuration */}
          <div>
            <label className="flex items-center space-x-2 mb-3 cursor-pointer">
              <input
                type="checkbox"
                checked={osintEnabled}
                onChange={(e) => setOsintEnabled(e.target.checked)}
                className="text-cobra-500 focus:ring-cobra-500"
              />
              <span className="text-sm font-medium text-terminal-text">
                Enable OSINT Intelligence Gathering
              </span>
            </label>
            
            {osintEnabled && (
              <div className="space-y-2 ml-6">
                {Object.entries(osintSources).map(([source, enabled]) => (
                  <label key={source} className="flex items-center space-x-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={enabled}
                      onChange={(e) => setOsintSources(prev => ({
                        ...prev,
                        [source]: e.target.checked
                      }))}
                      className="text-cobra-500 focus:ring-cobra-500"
                    />
                    <span className="text-sm text-terminal-text capitalize">
                      {source.replace(/([A-Z])/g, ' $1').trim()}
                    </span>
                  </label>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="mt-6">
          <button
            onClick={startReconnaissance}
            disabled={isScanning || (!target.trim() || (!operation && !operationName.trim()))}
            className="px-6 py-3 bg-cobra-600 hover:bg-cobra-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg flex items-center space-x-2 transition-colors"
          >
            <Play className="w-4 h-4" />
            <span>{isScanning ? 'Scanning...' : 'Start AI Reconnaissance'}</span>
          </button>
        </div>
      </div>

      {/* Scan Progress */}
      {isScanning && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <Clock className="w-5 h-5 mr-2 text-cobra-500" />
            Reconnaissance Progress
          </h3>
          
          <div className="mb-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-terminal-muted">Progress</span>
              <span className="text-sm text-terminal-text">{scanProgress}%</span>
            </div>
            <div className="w-full bg-terminal-bg rounded-full h-2">
              <div 
                className="bg-cobra-500 h-2 rounded-full transition-all duration-300"
                style={{ width: `${scanProgress}%` }}
              />
            </div>
          </div>

          <div className="max-h-48 overflow-y-auto space-y-1">
            {scanLogs.map((log, index) => (
              <p key={index} className="text-sm text-terminal-text font-mono">
                {log}
              </p>
            ))}
          </div>
        </div>
      )}

      {/* Results Display */}
      {targetInfo && (
        <>
          {/* Target Information */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
              <Globe className="w-5 h-5 mr-2 text-cobra-500" />
              Target Analysis Results
            </h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <div>
                  <label className="text-sm text-terminal-muted">Domain/IP</label>
                  <p className="text-terminal-text font-medium">{targetInfo.domain} ({targetInfo.ip})</p>
                </div>
                <div>
                  <label className="text-sm text-terminal-muted">OS Fingerprint</label>
                  <p className="text-terminal-text font-medium">{targetInfo.osFingerprint || 'Unknown'}</p>
                </div>
                <div>
                  <label className="text-sm text-terminal-muted">Risk Score</label>
                  <p className={`font-bold text-lg ${getRiskColor(riskScore)}`}>
                    {riskScore.toFixed(1)}/10
                  </p>
                </div>
              </div>
              
              <div className="space-y-4">
                <div>
                  <label className="text-sm text-terminal-muted">Open Ports</label>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {targetInfo.ports.slice(0, 10).map((port, index) => (
                      <span 
                        key={index}
                        className="px-2 py-1 bg-cobra-500/20 text-cobra-400 text-xs rounded"
                      >
                        {port.port}/{port.service}
                      </span>
                    ))}
                    {targetInfo.ports.length > 10 && (
                      <span className="px-2 py-1 bg-terminal-bg text-terminal-muted text-xs rounded">
                        +{targetInfo.ports.length - 10} more
                      </span>
                    )}
                  </div>
                </div>
                <div>
                  <label className="text-sm text-terminal-muted">Technologies</label>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {targetInfo.technologies.map((tech, index) => (
                      <span 
                        key={index}
                        className="px-2 py-1 bg-blue-500/20 text-blue-400 text-xs rounded"
                      >
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* AI Recommendations */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
              <Brain className="w-5 h-5 mr-2 text-cobra-500" />
              AI Attack Recommendations
            </h3>
            
            <div className="space-y-4">
              {aiRecommendations.map((rec, index) => (
                <div 
                  key={index}
                  className={`border rounded-lg p-4 ${getPriorityColor(rec.priority)}`}
                >
                  <div className="flex items-start justify-between mb-2">
                    <h4 className="font-semibold text-terminal-text">{rec.title}</h4>
                    <div className="flex items-center space-x-2">
                      <span className={`text-xs px-2 py-1 rounded ${
                        rec.priority === 'high' ? 'bg-red-500/20 text-red-400' :
                        rec.priority === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-green-500/20 text-green-400'
                      }`}>
                        {rec.priority.toUpperCase()}
                      </span>
                      <span className="text-xs text-terminal-muted">
                        {rec.confidence}% confidence
                      </span>
                    </div>
                  </div>
                  <p className="text-terminal-muted text-sm">{rec.description}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Stage Completion */}
          <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <CheckCircle className="w-6 h-6 text-green-500" />
                <div>
                  <h3 className="text-lg font-semibold text-green-400">
                    Reconnaissance Complete
                  </h3>
                  <p className="text-green-300/80">
                    AI has analyzed the target and provided {aiRecommendations.length} attack recommendations
                  </p>
                </div>
              </div>
              
              <button
                onClick={onStageComplete}
                className="px-6 py-3 bg-green-600 hover:bg-green-700 text-white rounded-lg flex items-center space-x-2 transition-colors"
              >
                <span>Proceed to Exploit Analysis</span>
                <Target className="w-4 h-4" />
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

export default ReconStage 