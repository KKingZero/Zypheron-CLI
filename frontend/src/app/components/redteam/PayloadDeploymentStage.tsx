import React, { useState, useEffect } from 'react'
import { 
  Zap, 
  Target, 
  Brain, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Play, 
  Pause,
  Terminal,
  Network,
  Lock,
  Unlock,
  Code,
  FileText,
  Download,
  Upload,
  Settings,
  Activity,
  Cpu,
  Server
} from 'lucide-react'
import toast from 'react-hot-toast'

interface PayloadDeploymentStageProps {
  operation: any
  onStageComplete: () => void
  onUpdateOperation: (operation: any) => void
  toolsStatus: any
}

interface AIPayload {
  id: string
  name: string
  type: 'reverse_shell' | 'bind_shell' | 'web_shell' | 'privilege_escalation' | 'persistence'
  platform: string
  exploitTarget: string
  confidence: number
  payload: string
  description: string
  requirements: string[]
  parameters: { [key: string]: any }
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
  aiGenerated: boolean
}

interface DeploymentResult {
  payloadId: string
  success: boolean
  target: string
  timestamp: Date
  output: string[]
  shellId?: string
  access?: {
    type: string
    privileges: string
    system: string
  }
}

const PayloadDeploymentStage: React.FC<PayloadDeploymentStageProps> = ({ 
  operation, 
  onStageComplete, 
  onUpdateOperation,
  toolsStatus 
}) => {
  const [isGenerating, setIsGenerating] = useState(false)
  const [isDeploying, setIsDeploying] = useState(false)
  const [aiPayloads, setAiPayloads] = useState<AIPayload[]>([])
  const [selectedPayload, setSelectedPayload] = useState<AIPayload | null>(null)
  const [deploymentResults, setDeploymentResults] = useState<DeploymentResult[]>([])
  const [activeSessions, setActiveSessions] = useState<any[]>([])
  const [deploymentLogs, setDeploymentLogs] = useState<string[]>([])
  
  // Payload generation settings
  const [targetPlatform, setTargetPlatform] = useState('auto')
  const [payloadTypes, setPayloadTypes] = useState({
    reverse_shell: true,
    bind_shell: false,
    web_shell: true,
    privilege_escalation: true,
    persistence: false
  })
  
  // Deployment options
  const [deploymentMode, setDeploymentMode] = useState<'test' | 'live'>('test')
  const [ethicalToggle, setEthicalToggle] = useState(true)

  useEffect(() => {
    generateAIPayloads()
  }, [])

  const generateAIPayloads = async () => {
    if (!operation) return

    setIsGenerating(true)
    setDeploymentLogs(['🧠 AI generating customized payloads...'])

    try {
      const response = await fetch('/api/redteam/payload/ai-generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operationId: operation.id,
          target: operation.target,
          vulnerabilities: operation.findings,
          platform: targetPlatform,
          payloadTypes,
          ethicalMode: ethicalToggle
        })
      })

      const result = await response.json()
      setAiPayloads(result.payloads)
      setDeploymentLogs(prev => [...prev, `✅ Generated ${result.payloads.length} AI-optimized payloads`])
      
      toast.success(`Generated ${result.payloads.length} AI payloads`)
    } catch (error) {
      console.error('Payload generation failed:', error)
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred'
      toast.error('Failed to generate AI payloads')
      setDeploymentLogs(prev => [...prev, `❌ Error: ${errorMessage}`])
    } finally {
      setIsGenerating(false)
    }
  }

  const deployPayload = async (payload: AIPayload) => {
    if (!toolsStatus.metasploit.installed) {
      toast.error('Metasploit is not installed')
      return
    }

    if (!ethicalToggle) {
      toast.error('Ethical use toggle must be enabled')
      return
    }

    setIsDeploying(true)
    setDeploymentLogs(prev => [...prev, `🚀 Deploying payload: ${payload.name}`])

    try {
      // Step 1: Initialize Metasploit RPC
      setDeploymentLogs(prev => [...prev, '🔧 Initializing Metasploit RPC connection...'])
      
      const initResponse = await fetch('/api/redteam/payload/metasploit/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ operationId: operation.id })
      })
      const initResult = await initResponse.json()

      setDeploymentLogs(prev => [...prev, `✅ Metasploit RPC initialized: ${initResult.version}`])

      // Step 2: Configure payload in Metasploit
      setDeploymentLogs(prev => [...prev, '⚙️ Configuring payload parameters...'])

      const configResponse = await fetch('/api/redteam/payload/metasploit/configure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operationId: operation.id,
          payload: payload,
          target: operation.target,
          mode: deploymentMode
        })
      })
      const configResult = await configResponse.json()

      setDeploymentLogs(prev => [...prev, `📋 Payload configured: ${configResult.module}`])

      // Step 3: Deploy payload (with safety checks)
      setDeploymentLogs(prev => [...prev, '🎯 Executing payload deployment...'])

      const deployResponse = await fetch('/api/redteam/payload/metasploit/deploy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operationId: operation.id,
          payloadId: payload.id,
          ethicalMode: ethicalToggle,
          testMode: deploymentMode === 'test'
        })
      })
      const deployResult = await deployResponse.json()

      const result: DeploymentResult = {
        payloadId: payload.id,
        success: deployResult.success,
        target: operation.target,
        timestamp: new Date(),
        output: deployResult.output,
        shellId: deployResult.shellId,
        access: deployResult.access
      }

      setDeploymentResults(prev => [...prev, result])

      if (deployResult.success) {
        setDeploymentLogs(prev => [...prev, `✅ Payload deployed successfully! Session ID: ${deployResult.shellId}`])
        
        if (deployResult.access) {
          setActiveSessions(prev => [...prev, {
            id: deployResult.shellId,
            type: deployResult.access.type,
            privileges: deployResult.access.privileges,
            system: deployResult.access.system,
            timestamp: new Date(),
            payload: payload.name
          }])
        }

        toast.success('Payload deployed successfully')
      } else {
        setDeploymentLogs(prev => [...prev, `❌ Payload deployment failed: ${deployResult.error}`])
        toast.error('Payload deployment failed')
      }

      // Update operation with deployment results
      const updatedOperation = {
        ...operation,
        findings: [
          ...operation.findings,
          {
            stage: 'payload',
            deployedPayloads: [...deploymentResults, result],
            activeSessions,
            timestamp: new Date()
          }
        ]
      }
      onUpdateOperation(updatedOperation)

    } catch (error) {
      console.error('Deployment failed:', error)
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred'
      toast.error('Deployment failed')
      setDeploymentLogs(prev => [...prev, `❌ Error: ${errorMessage}`])
    } finally {
      setIsDeploying(false)
    }
  }

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'critical': return 'text-red-500 bg-red-500/10 border-red-500'
      case 'high': return 'text-orange-500 bg-orange-500/10 border-orange-500'
      case 'medium': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500'
      case 'low': return 'text-green-500 bg-green-500/10 border-green-500'
      default: return 'text-gray-500 bg-gray-500/10 border-gray-500'
    }
  }

  const getPayloadTypeIcon = (type: string) => {
    switch (type) {
      case 'reverse_shell': return <Terminal className="w-4 h-4" />
      case 'bind_shell': return <Network className="w-4 h-4" />
      case 'web_shell': return <Code className="w-4 h-4" />
      case 'privilege_escalation': return <Unlock className="w-4 h-4" />
      case 'persistence': return <Server className="w-4 h-4" />
      default: return <Target className="w-4 h-4" />
    }
  }

  return (
    <div className="space-y-6">
      {/* Stage Header */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h2 className="text-2xl font-bold text-terminal-text mb-2 flex items-center">
          <Zap className="w-6 h-6 mr-3 text-cobra-500" />
          Stage 3: Payload Deployment
        </h2>
        <p className="text-terminal-muted text-lg">
          AI-generated payloads with one-click Metasploit deployment and real-time monitoring
        </p>
      </div>

      {/* Ethical Use Warning */}
      <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-6">
        <div className="flex items-start space-x-3">
          <AlertTriangle className="w-6 h-6 text-yellow-500 flex-shrink-0 mt-1" />
          <div className="flex-1">
            <h3 className="text-lg font-semibold text-yellow-400 mb-2">
              Ethical Use Requirements
            </h3>
            <p className="text-yellow-300/80 mb-4">
              This tool is designed for authorized security testing only. Ensure you have explicit written 
              permission before testing any systems. Unauthorized access is illegal and unethical.
            </p>
            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="checkbox"
                checked={ethicalToggle}
                onChange={(e) => setEthicalToggle(e.target.checked)}
                className="text-yellow-500 focus:ring-yellow-500"
              />
              <span className="text-yellow-300 font-medium">
                I confirm I have authorization to test the target systems
              </span>
            </label>
          </div>
        </div>
      </div>

      {/* Metasploit Status */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
          <Shield className="w-5 h-5 mr-2 text-cobra-500" />
          Metasploit Framework Status
        </h3>
        
        <div className={`p-4 rounded-lg border ${
          toolsStatus.metasploit.installed 
            ? 'border-green-500/20 bg-green-500/10' 
            : 'border-red-500/20 bg-red-500/10'
        }`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className={`w-3 h-3 rounded-full ${
                toolsStatus.metasploit.installed ? 'bg-green-500' : 'bg-red-500'
              }`} />
              <span className="font-medium text-terminal-text">Metasploit Framework</span>
            </div>
            <span className="text-sm text-terminal-muted">
              {toolsStatus.metasploit.installed ? `v${toolsStatus.metasploit.version}` : 'Not installed'}
            </span>
          </div>
        </div>
      </div>

      {/* Payload Generation Configuration */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
          <Brain className="w-5 h-5 mr-2 text-cobra-500" />
          AI Payload Generation
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="block text-sm font-medium text-terminal-text mb-3">
              Target Platform
            </label>
            <select
              value={targetPlatform}
              onChange={(e) => setTargetPlatform(e.target.value)}
              className="w-full px-4 py-3 bg-terminal-bg border border-terminal-border rounded-lg text-terminal-text focus:border-cobra-500 focus:ring-1 focus:ring-cobra-500"
            >
              <option value="auto">Auto-detect from reconnaissance</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="macos">macOS</option>
              <option value="web">Web Application</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-terminal-text mb-3">
              Payload Types
            </label>
            <div className="space-y-2">
              {Object.entries(payloadTypes).map(([type, enabled]) => (
                <label key={type} className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enabled}
                    onChange={(e) => setPayloadTypes(prev => ({
                      ...prev,
                      [type]: e.target.checked
                    }))}
                    className="text-cobra-500 focus:ring-cobra-500"
                  />
                  {getPayloadTypeIcon(type)}
                  <span className="text-sm text-terminal-text">
                    {type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                  </span>
                </label>
              ))}
            </div>
          </div>
        </div>

        <div className="mt-6">
          <button
            onClick={generateAIPayloads}
            disabled={isGenerating || !ethicalToggle}
            className="px-6 py-3 bg-cobra-600 hover:bg-cobra-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg flex items-center space-x-2 transition-colors"
          >
            <Brain className="w-4 h-4" />
            <span>{isGenerating ? 'Generating...' : 'Generate AI Payloads'}</span>
          </button>
        </div>
      </div>

      {/* AI Generated Payloads */}
      {aiPayloads.length > 0 && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <Target className="w-5 h-5 mr-2 text-cobra-500" />
            AI-Generated Payloads ({aiPayloads.length})
          </h3>
          
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
            {aiPayloads.map((payload) => (
              <div 
                key={payload.id}
                className={`p-4 rounded-lg border cursor-pointer transition-all hover:border-cobra-500 ${
                  selectedPayload?.id === payload.id ? 'border-cobra-500 bg-cobra-500/5' : 'border-terminal-border'
                } ${getRiskColor(payload.riskLevel)}`}
                onClick={() => setSelectedPayload(payload)}
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    {getPayloadTypeIcon(payload.type)}
                    <h4 className="font-semibold text-terminal-text">{payload.name}</h4>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className={`text-xs px-2 py-1 rounded ${getRiskColor(payload.riskLevel)}`}>
                      {payload.riskLevel.toUpperCase()}
                    </span>
                    {payload.aiGenerated && (
                      <span className="text-xs px-2 py-1 bg-cobra-500/20 text-cobra-400 rounded">
                        AI
                      </span>
                    )}
                  </div>
                </div>
                
                <p className="text-sm text-terminal-muted mb-2">{payload.platform} • {payload.exploitTarget}</p>
                <p className="text-sm text-terminal-text mb-3 line-clamp-2">{payload.description}</p>
                
                <div className="flex items-center justify-between">
                  <span className="text-xs text-terminal-muted">
                    Confidence: {payload.confidence}%
                  </span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      deployPayload(payload)
                    }}
                    disabled={isDeploying || !ethicalToggle || !toolsStatus.metasploit.installed}
                    className="px-3 py-1.5 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white text-xs rounded transition-colors"
                  >
                    {isDeploying ? 'Deploying...' : 'Deploy'}
                  </button>
                </div>
              </div>
            ))}
          </div>

          {/* Deployment Mode Toggle */}
          <div className="border-t border-terminal-border pt-4">
            <label className="block text-sm font-medium text-terminal-text mb-3">
              Deployment Mode
            </label>
            <div className="flex items-center space-x-4">
              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="radio"
                  name="deploymentMode"
                  value="test"
                  checked={deploymentMode === 'test'}
                  onChange={(e) => setDeploymentMode(e.target.value as any)}
                  className="text-cobra-500 focus:ring-cobra-500"
                />
                <span className="text-sm text-terminal-text">Test Mode (Safe)</span>
              </label>
              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="radio"
                  name="deploymentMode"
                  value="live"
                  checked={deploymentMode === 'live'}
                  onChange={(e) => setDeploymentMode(e.target.value as any)}
                  className="text-red-500 focus:ring-red-500"
                />
                <span className="text-sm text-red-400">Live Mode (Caution)</span>
              </label>
            </div>
          </div>
        </div>
      )}

      {/* Deployment Logs */}
      {deploymentLogs.length > 0 && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <Activity className="w-5 h-5 mr-2 text-cobra-500" />
            Deployment Logs
          </h3>
          
          <div className="max-h-48 overflow-y-auto space-y-1">
            {deploymentLogs.map((log, index) => (
              <p key={index} className="text-sm text-terminal-text font-mono">
                {log}
              </p>
            ))}
          </div>
        </div>
      )}

      {/* Active Sessions */}
      {activeSessions.length > 0 && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <Terminal className="w-5 h-5 mr-2 text-cobra-500" />
            Active Sessions ({activeSessions.length})
          </h3>
          
          <div className="space-y-3">
            {activeSessions.map((session) => (
              <div key={session.id} className="bg-green-500/10 border border-green-500/20 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="font-semibold text-green-400">Session {session.id}</h4>
                  <span className="text-xs text-green-300">
                    {session.timestamp.toLocaleTimeString()}
                  </span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                  <div>
                    <span className="text-terminal-muted">Type:</span>
                    <p className="text-terminal-text">{session.type}</p>
                  </div>
                  <div>
                    <span className="text-terminal-muted">Privileges:</span>
                    <p className="text-terminal-text">{session.privileges}</p>
                  </div>
                  <div>
                    <span className="text-terminal-muted">System:</span>
                    <p className="text-terminal-text">{session.system}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Stage Completion */}
      {deploymentResults.length > 0 && (
        <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <CheckCircle className="w-6 h-6 text-green-500" />
              <div>
                <h3 className="text-lg font-semibold text-green-400">
                  Payload Deployment Complete
                </h3>
                <p className="text-green-300/80">
                  Deployed {deploymentResults.length} payloads with {activeSessions.length} active sessions
                </p>
              </div>
            </div>
            
            <button
              onClick={onStageComplete}
              className="px-6 py-3 bg-green-600 hover:bg-green-700 text-white rounded-lg flex items-center space-x-2 transition-colors"
            >
              <span>Proceed to AI Learning</span>
              <Brain className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Payload Details Modal */}
      {selectedPayload && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-terminal-card border border-terminal-border rounded-lg max-w-4xl w-full max-h-[80vh] overflow-y-auto">
            <div className="p-6">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="text-xl font-bold text-terminal-text">{selectedPayload.name}</h3>
                  <div className="flex items-center space-x-2 mt-2">
                    <span className={`text-xs px-2 py-1 rounded ${getRiskColor(selectedPayload.riskLevel)}`}>
                      {selectedPayload.riskLevel.toUpperCase()}
                    </span>
                    <span className="text-xs px-2 py-1 bg-blue-500/20 text-blue-400 rounded">
                      {selectedPayload.platform}
                    </span>
                    {selectedPayload.aiGenerated && (
                      <span className="text-xs px-2 py-1 bg-cobra-500/20 text-cobra-400 rounded">
                        AI GENERATED
                      </span>
                    )}
                  </div>
                </div>
                <button
                  onClick={() => setSelectedPayload(null)}
                  className="text-terminal-muted hover:text-terminal-text"
                >
                  ✕
                </button>
              </div>
              
              <div className="space-y-4">
                <div>
                  <label className="text-sm font-medium text-terminal-muted">Description</label>
                  <p className="text-terminal-text">{selectedPayload.description}</p>
                </div>
                
                <div>
                  <label className="text-sm font-medium text-terminal-muted">Target</label>
                  <p className="text-terminal-text">{selectedPayload.exploitTarget}</p>
                </div>
                
                <div>
                  <label className="text-sm font-medium text-terminal-muted">Requirements</label>
                  <ul className="text-terminal-text list-disc list-inside">
                    {selectedPayload.requirements.map((req, index) => (
                      <li key={index}>{req}</li>
                    ))}
                  </ul>
                </div>
                
                <div>
                  <label className="text-sm font-medium text-terminal-muted">Payload Code</label>
                  <pre className="text-terminal-text font-mono bg-terminal-bg p-4 rounded text-sm overflow-x-auto">
                    {selectedPayload.payload}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default PayloadDeploymentStage 