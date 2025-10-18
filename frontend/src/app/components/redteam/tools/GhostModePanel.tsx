import React, { useState, useEffect } from 'react'
import { Zap, Play, Pause, SkipForward, Eye, Target, Shield, FileText, Activity, CheckCircle, AlertTriangle } from 'lucide-react'

interface GhostPhase {
  phase: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  findings: any[]
  data: any
  startTime?: Date
  endTime?: Date
  duration?: number
}

interface CinematicResults {
  visualGraph: any
  gptNarration: string
  timeline: any[]
  recommendations: string[]
}

interface GhostSession {
  sessionId: string
  target: string
  missionType: string
  phases: GhostPhase[]
  cinematicResults?: CinematicResults
  ethicalCompliance: boolean
  operationComplete: boolean
}

interface GhostModePanelProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

const GhostModePanel: React.FC<GhostModePanelProps> = ({ onToolExecute }) => {
  const [target, setTarget] = useState<string>('')
  const [missionType, setMissionType] = useState<string>('full_spectrum')
  const [scope, setScope] = useState<string[]>(['recon', 'vuln_assessment', 'osint'])
  const [ghostSession, setGhostSession] = useState<GhostSession | null>(null)
  const [isRunning, setIsRunning] = useState(false)
  const [currentPhase, setCurrentPhase] = useState<string>('')
  const [autoMode, setAutoMode] = useState(true)
  const [cinematicMode, setCinematicMode] = useState(true)
  const [ethicalSafeguards, setEthicalSafeguards] = useState(true)

  const missionTypes = [
    { value: 'full_spectrum', label: 'Full Spectrum Assessment', description: 'Complete OSINT → Recon → Vuln → Report chain' },
    { value: 'stealth_recon', label: 'Stealth Reconnaissance', description: 'Passive intelligence gathering only' },
    { value: 'vulnerability_focus', label: 'Vulnerability Assessment', description: 'Deep dive vulnerability analysis' },
    { value: 'osint_intensive', label: 'OSINT Intelligence', description: 'Comprehensive open-source intelligence' },
    { value: 'network_mapping', label: 'Network Cartography', description: 'Complete network topology mapping' }
  ]

  const scopeOptions = [
    { id: 'osint', label: 'OSINT Gathering', tools: ['Shodan', 'Maltego', 'Recon-ng'] },
    { id: 'recon', label: 'Reconnaissance', tools: ['Sn1per', 'Nmap', 'Nikto'] },
    { id: 'vuln_assessment', label: 'Vulnerability Assessment', tools: ['Nessus', 'Nuclei'] },
    { id: 'network_analysis', label: 'Network Analysis', tools: ['Wireshark', 'Ettercap'] },
    { id: 'wireless', label: 'Wireless Assessment', tools: ['Aircrack-ng Enhanced'] },
    { id: 'reporting', label: 'Report Generation', tools: ['Dradis', 'Faraday'] }
  ]

  const startGhostMode = async () => {
    if (!target.trim()) return

    setIsRunning(true)
    setCurrentPhase('initialization')

    try {
      const result = await onToolExecute('ghost_mode', {
        target: target.trim(),
        missionType,
        scope
      })

      if (result.sessionId) {
        setGhostSession(result)
        setCurrentPhase('completed')
      }
    } catch (error) {
      console.error('Ghost Mode failed:', error)
    } finally {
      setIsRunning(false)
    }
  }

  const getPhaseIcon = (phase: string) => {
    switch (phase) {
      case 'osint': return <Eye className="w-4 h-4" />
      case 'recon': return <Target className="w-4 h-4" />
      case 'vulnerability': return <Shield className="w-4 h-4" />
      case 'exploitation': return <Zap className="w-4 h-4" />
      case 'reporting': return <FileText className="w-4 h-4" />
      default: return <Activity className="w-4 h-4" />
    }
  }

  const getPhaseColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-green-500 bg-green-500/20'
      case 'running': return 'text-blue-500 bg-blue-500/20'
      case 'failed': return 'text-red-500 bg-red-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  const handleScopeChange = (optionId: string) => {
    setScope(prev => 
      prev.includes(optionId) 
        ? prev.filter(id => id !== optionId)
        : [...prev, optionId]
    )
  }

  return (
    <div className="space-y-6">
      {/* Ghost Mode Header */}
      <div className="bg-gradient-to-r from-purple-900/20 to-blue-900/20 border border-purple-500/30 rounded-lg p-6">
        <h3 className="text-2xl font-bold text-transparent bg-gradient-to-r from-purple-400 to-blue-400 bg-clip-text mb-4 flex items-center">
          <div className="w-8 h-8 mr-3 rounded-full bg-gradient-to-r from-purple-500 to-blue-500 flex items-center justify-center">
            <Zap className="w-4 h-4 text-white" />
          </div>
          Ghost Mode - Autonomous Cyber Operations
          <span className="ml-3 px-3 py-1 bg-gradient-to-r from-purple-500 to-blue-500 text-white text-sm rounded-full animate-pulse">
            CINEMATIC AI
          </span>
        </h3>
        <p className="text-terminal-muted">
          Single-click recon-exploit-report chain with AI narration and cinematic visualization
        </p>
        
        {ethicalSafeguards && (
          <div className="mt-4 p-3 bg-yellow-500/10 border border-yellow-500/20 rounded flex items-center space-x-2">
            <Shield className="w-4 h-4 text-yellow-500" />
            <span className="text-yellow-300 text-sm">
              <strong>Ethical Mode:</strong> All operations conducted with safety controls and user confirmation for exploitative actions
            </span>
          </div>
        )}
      </div>

      {/* Configuration Panel */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h4 className="text-lg font-semibold text-terminal-text mb-4">Mission Configuration</h4>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
          <div>
            <label className="block text-terminal-text font-medium mb-2">
              Target
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="example.com or 192.168.1.0/24"
              className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
            />
          </div>

          <div>
            <label className="block text-terminal-text font-medium mb-2">
              Mission Type
            </label>
            <select
              value={missionType}
              onChange={(e) => setMissionType(e.target.value)}
              className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
            >
              {missionTypes.map((mission) => (
                <option key={mission.value} value={mission.value}>
                  {mission.label}
                </option>
              ))}
            </select>
            <p className="text-terminal-muted text-sm mt-1">
              {missionTypes.find(m => m.value === missionType)?.description}
            </p>
          </div>
        </div>

        {/* Scope Selection */}
        <div className="mb-6">
          <label className="block text-terminal-text font-medium mb-3">
            Operation Scope
          </label>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {scopeOptions.map((option) => (
              <div
                key={option.id}
                className={`border rounded-lg p-3 cursor-pointer transition-all ${
                  scope.includes(option.id)
                    ? 'border-purple-500 bg-purple-500/10'
                    : 'border-terminal-border hover:border-purple-500/50'
                }`}
                onClick={() => handleScopeChange(option.id)}
              >
                <div className="flex items-center space-x-2 mb-2">
                  <input
                    type="checkbox"
                    checked={scope.includes(option.id)}
                    onChange={() => handleScopeChange(option.id)}
                    className="text-purple-500"
                  />
                  <span className="text-terminal-text font-medium">{option.label}</span>
                </div>
                <div className="text-terminal-muted text-xs">
                  Tools: {option.tools.join(', ')}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Options */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <label className="flex items-center space-x-2 cursor-pointer">
            <input
              type="checkbox"
              checked={autoMode}
              onChange={(e) => setAutoMode(e.target.checked)}
              className="text-purple-500"
            />
            <span className="text-terminal-text">Full Automation</span>
          </label>
          
          <label className="flex items-center space-x-2 cursor-pointer">
            <input
              type="checkbox"
              checked={cinematicMode}
              onChange={(e) => setCinematicMode(e.target.checked)}
              className="text-purple-500"
            />
            <span className="text-terminal-text">Cinematic Visualization</span>
          </label>
          
          <label className="flex items-center space-x-2 cursor-pointer">
            <input
              type="checkbox"
              checked={ethicalSafeguards}
              onChange={(e) => setEthicalSafeguards(e.target.checked)}
              className="text-purple-500"
            />
            <span className="text-terminal-text">Ethical Safeguards</span>
          </label>
        </div>

        {/* Launch Button */}
        <div className="flex justify-center">
          <button
            onClick={startGhostMode}
            disabled={isRunning || !target.trim() || scope.length === 0}
            className="px-8 py-3 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 disabled:from-gray-600 disabled:to-gray-600 text-white rounded-lg flex items-center space-x-3 transition-all transform hover:scale-105 disabled:hover:scale-100"
          >
            {isRunning ? (
              <>
                <Activity className="w-5 h-5 animate-spin" />
                <span className="text-lg font-medium">Executing Ghost Protocol...</span>
              </>
            ) : (
              <>
                <Zap className="w-5 h-5" />
                <span className="text-lg font-medium">Initiate Ghost Mode</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Phase Progress */}
      {(isRunning || ghostSession) && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <Activity className="w-5 h-5 mr-2 text-purple-500" />
            Operation Timeline
          </h4>

          <div className="space-y-3">
            {(ghostSession?.phases || []).map((phase, index) => (
              <div
                key={index}
                className={`flex items-center space-x-4 p-3 rounded-lg border ${
                  phase.status === 'running' ? 'border-blue-500/50 bg-blue-500/5' :
                  phase.status === 'completed' ? 'border-green-500/50 bg-green-500/5' :
                  phase.status === 'failed' ? 'border-red-500/50 bg-red-500/5' :
                  'border-terminal-border'
                }`}
              >
                <div className={`p-2 rounded ${getPhaseColor(phase.status)}`}>
                  {getPhaseIcon(phase.phase)}
                </div>
                
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <h5 className="font-medium text-terminal-text capitalize">
                      Phase {index + 1}: {phase.phase.replace('_', ' ')}
                    </h5>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getPhaseColor(phase.status)}`}>
                      {phase.status.toUpperCase()}
                    </span>
                  </div>
                  
                  {phase.findings && phase.findings.length > 0 && (
                    <p className="text-terminal-muted text-sm mt-1">
                      {phase.findings.length} findings collected
                    </p>
                  )}
                  
                  {phase.duration && (
                    <p className="text-terminal-muted text-xs mt-1">
                      Duration: {phase.duration}ms
                    </p>
                  )}
                </div>

                {phase.status === 'running' && (
                  <div className="w-4 h-4 bg-blue-500 rounded-full animate-pulse"></div>
                )}
                {phase.status === 'completed' && (
                  <CheckCircle className="w-4 h-4 text-green-500" />
                )}
                {phase.status === 'failed' && (
                  <AlertTriangle className="w-4 h-4 text-red-500" />
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Cinematic Results */}
      {ghostSession?.cinematicResults && (
        <div className="bg-gradient-to-r from-purple-900/20 to-blue-900/20 border border-purple-500/30 rounded-lg p-6">
          <h4 className="text-lg font-semibold text-transparent bg-gradient-to-r from-purple-400 to-blue-400 bg-clip-text mb-4 flex items-center">
            <Eye className="w-5 h-5 mr-2 text-purple-500" />
            Cinematic Operation Results
          </h4>

          <div className="space-y-6">
            {/* AI Narration */}
            <div className="bg-terminal-bg border border-purple-500/20 rounded-lg p-4">
              <h5 className="font-medium text-purple-300 mb-2">AI Mission Narration</h5>
              <p className="text-terminal-text italic">"{ghostSession.cinematicResults.gptNarration}"</p>
            </div>

            {/* Timeline Visualization */}
            <div className="bg-terminal-bg border border-blue-500/20 rounded-lg p-4">
              <h5 className="font-medium text-blue-300 mb-3">Operation Timeline</h5>
              <div className="space-y-2">
                {ghostSession.cinematicResults.timeline.map((event, index) => (
                  <div key={index} className="flex items-center space-x-3 text-sm">
                    <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                    <span className="text-terminal-muted">{event.timestamp}</span>
                    <span className="text-terminal-text">{event.event}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Recommendations */}
            <div className="bg-terminal-bg border border-green-500/20 rounded-lg p-4">
              <h5 className="font-medium text-green-300 mb-3">Strategic Recommendations</h5>
              <ul className="space-y-1">
                {ghostSession.cinematicResults.recommendations.map((rec, index) => (
                  <li key={index} className="text-terminal-text text-sm flex items-start space-x-2">
                    <span className="text-green-500 mt-1">•</span>
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Session Summary */}
      {ghostSession?.operationComplete && (
        <div className="bg-terminal-card border border-green-500/20 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h4 className="text-lg font-semibold text-green-400 flex items-center">
              <CheckCircle className="w-5 h-5 mr-2" />
              Operation Complete
            </h4>
            <span className="text-terminal-muted text-sm">
              Session ID: {ghostSession.sessionId}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-terminal-bg border border-terminal-border rounded p-3">
              <h5 className="font-medium text-terminal-text">Target</h5>
              <p className="text-terminal-muted text-sm">{ghostSession.target}</p>
            </div>
            <div className="bg-terminal-bg border border-terminal-border rounded p-3">
              <h5 className="font-medium text-terminal-text">Mission Type</h5>
              <p className="text-terminal-muted text-sm">{ghostSession.missionType}</p>
            </div>
            <div className="bg-terminal-bg border border-terminal-border rounded p-3">
              <h5 className="font-medium text-terminal-text">Phases Completed</h5>
              <p className="text-terminal-muted text-sm">{ghostSession.phases.length}</p>
            </div>
          </div>

          {ghostSession.ethicalCompliance && (
            <div className="mt-4 p-3 bg-green-500/10 border border-green-500/20 rounded flex items-center space-x-2">
              <Shield className="w-4 h-4 text-green-500" />
              <span className="text-green-300 text-sm">
                <strong>Ethical Compliance:</strong> All operations conducted within authorized scope and safety parameters
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default GhostModePanel