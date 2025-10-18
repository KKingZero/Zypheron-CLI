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
  Activity,
  Cpu,
  Server,
  Eye,
  FileText,
  Clock,
  TrendingUp,
  AlertCircle
} from 'lucide-react'
import RobotIcon from '../../../components/icons/RobotIcon'
import toast from 'react-hot-toast'

interface ExecutionStageProps {
  operation: any
  onStageComplete: () => void
  onUpdateOperation: (operation: any) => void
  toolsStatus: any
  agentMode?: boolean
}

interface ExecutionResult {
  id: string
  payloadName: string
  target: string
  success: boolean
  timestamp: Date
  damageAssessment: {
    dataExfiltrated: string[]
    systemsCompromised: string[]
    privilegesGained: string[]
    persistenceEstablished: boolean
    lateralMovement: string[]
  }
  metrics: {
    executionTime: number
    detectionProbability: number
    coveragePecentage: number
    riskScore: number
  }
  logs: string[]
}

interface DamageTracker {
  totalSystems: number
  compromisedSystems: number
  dataExposed: number
  criticalVulns: number
  timeToDetection: number
  impactScore: number
}

const ExecutionStage: React.FC<ExecutionStageProps> = ({ 
  operation, 
  onStageComplete, 
  onUpdateOperation,
  toolsStatus,
  agentMode = false
}) => {
  const [isExecuting, setIsExecuting] = useState(false)
  const [executionResults, setExecutionResults] = useState<ExecutionResult[]>([])
  const [damageTracker, setDamageTracker] = useState<DamageTracker>({
    totalSystems: 0,
    compromisedSystems: 0,
    dataExposed: 0,
    criticalVulns: 0,
    timeToDetection: 0,
    impactScore: 0
  })
  const [executionLogs, setExecutionLogs] = useState<string[]>([])
  const [selectedPayloads, setSelectedPayloads] = useState<string[]>([])
  const [realTimeMetrics, setRealTimeMetrics] = useState({
    cpuUsage: 0,
    networkTraffic: 0,
    memoryUsage: 0,
    diskIO: 0
  })

  // Agent Mode specific states
  const [agentActions, setAgentActions] = useState<string[]>([])
  const [autonomousMode, setAutonomousMode] = useState(false)
  const [agentConfidence, setAgentConfidence] = useState(0)

  useEffect(() => {
    if (agentMode) {
      setExecutionLogs(prev => [...prev, '🤖 Agent Mode activated - Autonomous execution enabled'])
    }
  }, [agentMode])

  const startExecution = async () => {
    if (selectedPayloads.length === 0) {
      toast.error('Please select at least one payload to execute')
      return
    }

    setIsExecuting(true)
    setExecutionLogs(['🎯 Initiating payload execution phase...'])

    if (agentMode) {
      setExecutionLogs(prev => [...prev, '🤖 AI Agent taking control of execution sequence'])
      setAgentActions(['Analyzing target environment', 'Selecting optimal attack vectors', 'Preparing stealth execution'])
    }

    try {
      // Simulate execution process
      for (let i = 0; i < selectedPayloads.length; i++) {
        const payloadId = selectedPayloads[i]
        setExecutionLogs(prev => [...prev, `⚡ Executing payload: ${payloadId}`])
        
        if (agentMode) {
          setExecutionLogs(prev => [...prev, `🤖 Agent adapting execution strategy for payload ${i + 1}`])
        }

        await new Promise(resolve => setTimeout(resolve, 2000))

        const result: ExecutionResult = {
          id: `exec-${Date.now()}-${i}`,
          payloadName: `Payload-${payloadId}`,
          target: operation.target,
          success: Math.random() > 0.3,
          timestamp: new Date(),
          damageAssessment: {
            dataExfiltrated: ['user_credentials.db', 'config_files', 'log_data'],
            systemsCompromised: ['web-server-01', 'db-primary'],
            privilegesGained: ['user', 'admin'],
            persistenceEstablished: true,
            lateralMovement: ['internal-network', 'domain-controller']
          },
          metrics: {
            executionTime: Math.floor(Math.random() * 300) + 60,
            detectionProbability: Math.random() * 0.4,
            coveragePecentage: Math.random() * 100,
            riskScore: Math.random() * 10
          },
          logs: [
            'Connection established',
            'Payload deployed successfully', 
            'Privilege escalation attempted',
            'Data exfiltration in progress'
          ]
        }

        setExecutionResults(prev => [...prev, result])
        updateDamageTracker(result)
      }

      setExecutionLogs(prev => [...prev, '✅ Execution phase completed'])
      toast.success('Payload execution completed')
      
    } catch (error) {
      setExecutionLogs(prev => [...prev, `❌ Execution failed: ${error}`])
      toast.error('Execution failed')
    } finally {
      setIsExecuting(false)
    }
  }

  const updateDamageTracker = (result: ExecutionResult) => {
    setDamageTracker(prev => ({
      totalSystems: prev.totalSystems + 1,
      compromisedSystems: result.success ? prev.compromisedSystems + 1 : prev.compromisedSystems,
      dataExposed: prev.dataExposed + result.damageAssessment.dataExfiltrated.length,
      criticalVulns: prev.criticalVulns + (result.metrics.riskScore > 7 ? 1 : 0),
      timeToDetection: Math.max(prev.timeToDetection, result.metrics.executionTime),
      impactScore: Math.max(prev.impactScore, result.metrics.riskScore)
    }))
  }

  const DamageAssessmentPanel = () => (
    <div className="bg-terminal-card border border-terminal-border rounded-lg p-6 mb-6">
      <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
        <AlertTriangle className="w-5 h-5 mr-2 text-red-500" />
        Real-Time Damage Assessment
      </h3>
      
      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
        <div className="bg-terminal-bg p-4 rounded-lg border border-terminal-border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-terminal-muted text-sm">Systems Compromised</span>
            <Server className="w-4 h-4 text-red-500" />
          </div>
          <div className="text-2xl font-bold text-red-500">
            {damageTracker.compromisedSystems}/{damageTracker.totalSystems}
          </div>
        </div>
        
        <div className="bg-terminal-bg p-4 rounded-lg border border-terminal-border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-terminal-muted text-sm">Data Exposed</span>
            <FileText className="w-4 h-4 text-orange-500" />
          </div>
          <div className="text-2xl font-bold text-orange-500">
            {damageTracker.dataExposed} files
          </div>
        </div>
        
        <div className="bg-terminal-bg p-4 rounded-lg border border-terminal-border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-terminal-muted text-sm">Impact Score</span>
            <TrendingUp className="w-4 h-4 text-yellow-500" />
          </div>
          <div className="text-2xl font-bold text-yellow-500">
            {damageTracker.impactScore.toFixed(1)}/10
          </div>
        </div>
      </div>
    </div>
  )

  const ExecutionControlPanel = () => (
    <div className="bg-terminal-card border border-terminal-border rounded-lg p-6 mb-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-terminal-text flex items-center">
          <Zap className="w-5 h-5 mr-2 text-cobra-500" />
          Execution Control
          {agentMode && (
            <span className="ml-2 px-2 py-1 bg-cobra-500 text-white text-xs rounded-full flex items-center">
              <RobotIcon size={12} className="mr-1" />
              AGENT MODE
            </span>
          )}
        </h3>
        
        <div className="flex items-center space-x-2">
          {agentMode && (
            <button
              onClick={() => setAutonomousMode(!autonomousMode)}
              className={`px-3 py-1 rounded-lg text-sm transition-colors ${
                autonomousMode 
                  ? 'bg-green-600 text-white' 
                  : 'bg-gray-600 text-gray-300'
              }`}
            >
              <RobotIcon size={14} className="inline mr-1" />
              Auto
            </button>
          )}
          
          <button
            onClick={startExecution}
            disabled={isExecuting || selectedPayloads.length === 0}
            className="px-4 py-2 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 text-white rounded-lg flex items-center space-x-2 transition-colors"
          >
            {isExecuting ? (
              <>
                <Activity className="w-4 h-4 animate-spin" />
                <span>Executing...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                <span>Execute Payloads</span>
              </>
            )}
          </button>
        </div>
      </div>

      {agentMode && (
        <div className="bg-cobra-500/10 border border-cobra-500/30 rounded-lg p-4 mb-4">
          <div className="flex items-center mb-2">
            <RobotIcon size={16} className="mr-2 text-cobra-500" />
            <span className="text-sm font-medium text-cobra-500">AI Agent Status</span>
          </div>
          <div className="space-y-2">
            {agentActions.map((action, index) => (
              <div key={index} className="text-sm text-terminal-text flex items-center">
                <div className="w-2 h-2 bg-cobra-500 rounded-full mr-2 animate-pulse" />
                {action}
              </div>
            ))}
            <div className="text-xs text-terminal-muted">
              Agent Confidence: {agentConfidence.toFixed(1)}%
            </div>
          </div>
        </div>
      )}
    </div>
  )

  const ExecutionResultsPanel = () => (
    <div className="bg-terminal-card border border-terminal-border rounded-lg p-6 mb-6">
      <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
        <Activity className="w-5 h-5 mr-2 text-cobra-500" />
        Execution Results
      </h3>
      
      <div className="space-y-4">
        {executionResults.map((result) => (
          <div key={result.id} className="bg-terminal-bg border border-terminal-border rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <h4 className="font-medium text-terminal-text">{result.payloadName}</h4>
              <div className={`px-2 py-1 rounded text-xs ${
                result.success 
                  ? 'bg-green-500/20 text-green-500' 
                  : 'bg-red-500/20 text-red-500'
              }`}>
                {result.success ? 'SUCCESS' : 'FAILED'}
              </div>
            </div>
            
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <span className="text-terminal-muted">Systems Compromised:</span>
                <p className="text-terminal-text">{result.damageAssessment.systemsCompromised.length}</p>
              </div>
              <div>
                <span className="text-terminal-muted">Data Exfiltrated:</span>
                <p className="text-terminal-text">{result.damageAssessment.dataExfiltrated.length} files</p>
              </div>
              <div>
                <span className="text-terminal-muted">Execution Time:</span>
                <p className="text-terminal-text">{result.metrics.executionTime}s</p>
              </div>
              <div>
                <span className="text-terminal-muted">Risk Score:</span>
                <p className={`${
                  result.metrics.riskScore >= 8 ? 'text-red-500' :
                  result.metrics.riskScore >= 5 ? 'text-yellow-500' : 'text-green-500'
                }`}>
                  {result.metrics.riskScore.toFixed(1)}/10
                </p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )

  const ExecutionLogsPanel = () => (
    <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
      <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
        <Terminal className="w-5 h-5 mr-2 text-cobra-500" />
        Execution Logs
      </h3>
      
      <div className="bg-black rounded-lg p-4 h-64 overflow-y-auto font-mono text-sm">
        {executionLogs.map((log, index) => (
          <div key={index} className="text-green-400 mb-1">
            <span className="text-gray-500">[{new Date().toLocaleTimeString()}]</span> {log}
          </div>
        ))}
      </div>
    </div>
  )

  return (
    <div className="space-y-6">
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h2 className="text-2xl font-bold text-terminal-text mb-4 flex items-center">
          <Zap className="w-6 h-6 mr-3 text-cobra-500" />
          Stage 3: Payload Execution & Damage Tracking
          {agentMode && (
            <span className="ml-3 px-3 py-1 bg-cobra-500 text-white text-sm rounded-full flex items-center">
              <RobotIcon size={16} className="mr-2" />
              AI AGENT MODE
            </span>
          )}
        </h2>
        <p className="text-terminal-muted">
          Execute selected payloads against targets and track real-time damage assessment
        </p>
      </div>

      <ExecutionControlPanel />
      <DamageAssessmentPanel />
      <ExecutionResultsPanel />
      <ExecutionLogsPanel />

      <div className="flex justify-between">
        <button
          onClick={() => window.history.back()}
          className="px-6 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg transition-colors"
        >
          Back to Payload Stage
        </button>
        
        <button
          onClick={onStageComplete}
          className="px-6 py-2 bg-cobra-600 hover:bg-cobra-700 text-white rounded-lg transition-colors"
        >
          Continue to Patch Stage
        </button>
      </div>
    </div>
  )
}

export default ExecutionStage