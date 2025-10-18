import React, { useState, useEffect } from 'react'
import { useAuth } from '../../contexts/AuthContext'
import { useChat } from '../../contexts/ChatContext'
import { shouldBypassAuth } from '../../utils/devMode'
import { useSubscriptionAccess } from '../../hooks/useSubscriptionAccess'
import UpgradePrompt from '../../components/UpgradePrompt'
import LiveTerminalOutput from '../../components/LiveTerminalOutput'
import AdvancedToolsDashboard from '../components/redteam/AdvancedToolsDashboard'
import ActiveSessionsPanel from '../components/redteam/ActiveSessionsPanel'
import { 
  Shield, 
  Target, 
  Brain,
  Terminal,
  Activity,
  Wrench,
  Play,
  Square,
  Download,
  RefreshCw
} from 'lucide-react'
import RobotIcon from '../../components/icons/RobotIcon'
import toast from 'react-hot-toast'
import SEOOptimizer, { seoConfigs } from '../../components/SEOOptimizer'

interface RedTeamOperation {
  id: string
  name: string
  target: string
  status: 'idle' | 'running' | 'completed' | 'failed'
  startTime?: Date
  endTime?: Date
  toolsUsed: string[]
  findings: any[]
  agentMode?: boolean
}

const RedTeamOps: React.FC = () => {
  const { addAssistantMessage } = useChat()
  const { session } = useAuth()
  const { canAccessFeature, getUpgradeMessage } = useSubscriptionAccess()
  
  // State management
  const [operation, setOperation] = useState<RedTeamOperation | null>(null)
  const [operationName, setOperationName] = useState('')
  const [targetUrl, setTargetUrl] = useState('')
  const [agentMode, setAgentMode] = useState(false)
  const [isRunning, setIsRunning] = useState(false)
  const [terminalOutput, setTerminalOutput] = useState<string[]>([])
  const [showUpgradePrompt, setShowUpgradePrompt] = useState(false)
  const [operationHistory, setOperationHistory] = useState<RedTeamOperation[]>([])

  useEffect(() => {
    loadOperationHistory()
    
    // Welcome message
    if (addAssistantMessage) {
      addAssistantMessage(`🛡️ **Welcome to Red Team Operations**\n\nComplete professional security testing suite:\n\n🤖 **Agent Mode:** AI-powered autonomous testing\n🔧 **Professional Suite:** 16+ security tools\n📊 **Live Terminal:** Real-time tool output\n\n**Available Tools:**\n• SQL Injection Scanner • Web Port Scanner • Password Analyzer\n• Brute Force Scanner • Payload Generator • Hash Cracking\n• Network Analysis • Vulnerability Assessment • And more!\n\n**Quick Start:** Configure operation above, then use tools below.`, {
        welcome: true,
        redTeamOps: true
      })
    }
  }, [])

  const loadOperationHistory = () => {
    try {
      const saved = localStorage.getItem('red_team_operation_history')
      if (saved) {
        const history = JSON.parse(saved)
        setOperationHistory(history)
      }
    } catch (error) {
      console.error('Failed to load operation history:', error)
    }
  }

  const saveOperationHistory = (updatedHistory: RedTeamOperation[]) => {
    try {
      localStorage.setItem('red_team_operation_history', JSON.stringify(updatedHistory))
      setOperationHistory(updatedHistory)
    } catch (error) {
      console.error('Failed to save operation history:', error)
    }
  }

  const handleStartOperation = () => {
    if (!operationName.trim() || !targetUrl.trim()) {
      toast.error('Please provide operation name and target URL')
      return
    }

    // Check subscription access
    if (!canAccessFeature('red_team_ops')) {
      setShowUpgradePrompt(true)
      return
    }

    const newOperation: RedTeamOperation = {
      id: Date.now().toString(),
      name: operationName,
      target: targetUrl,
      status: 'running',
      startTime: new Date(),
      toolsUsed: [],
      findings: [],
      agentMode
    }

    setOperation(newOperation)
    setIsRunning(true)
    setTerminalOutput([])
    
    addTerminalOutput(`[+] Operation "${operationName}" started`)
    addTerminalOutput(`[+] Target: ${targetUrl}`)
    addTerminalOutput(`[+] Agent Mode: ${agentMode ? 'ENABLED' : 'DISABLED'}`)
    addTerminalOutput(`[+] Status: Ready for tool execution`)
    addTerminalOutput(``)
    addTerminalOutput(`Use the Professional Suite tools below to begin security testing.`)
    addTerminalOutput(`All tool outputs will appear here in real-time.`)
    
    toast.success(`Operation "${operationName}" started`)
  }

  const handleStopOperation = () => {
    if (!operation) return

    const completedOperation: RedTeamOperation = {
      ...operation,
      status: 'completed',
      endTime: new Date()
    }

    setOperation(completedOperation)
    setIsRunning(false)
    
    addTerminalOutput(``)
    addTerminalOutput(`[+] Operation "${operation.name}" stopped`)
    addTerminalOutput(`[+] Duration: ${calculateDuration(operation.startTime!, new Date())}`)
    addTerminalOutput(`[+] Tools used: ${operation.toolsUsed.length}`)
    addTerminalOutput(`[+] Findings: ${operation.findings.length}`)

    // Save to history
    const updatedHistory = [completedOperation, ...operationHistory.slice(0, 9)] // Keep last 10
    saveOperationHistory(updatedHistory)
    
    toast.success(`Operation completed`)
  }

  const handleResetOperation = () => {
    setOperation(null)
    setOperationName('')
    setTargetUrl('')
    setIsRunning(false)
    setTerminalOutput([])
    toast.info('Operation reset')
  }

  const handleExportResults = () => {
    if (!operation) {
      toast.error('No operation to export')
      return
    }

    const exportData = {
      operation: operation.name,
      target: operation.target,
      startTime: operation.startTime,
      endTime: operation.endTime,
      duration: operation.startTime && operation.endTime 
        ? calculateDuration(operation.startTime, operation.endTime)
        : 'N/A',
      toolsUsed: operation.toolsUsed,
      findings: operation.findings,
      terminalLog: terminalOutput,
      agentMode: operation.agentMode
    }

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `redteam_${operation.name.replace(/\s+/g, '_')}_${Date.now()}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    
    toast.success('Results exported')
  }

  const addTerminalOutput = (message: string) => {
    setTerminalOutput(prev => [...prev, message])
  }

  const calculateDuration = (start: Date, end: Date): string => {
    const diff = end.getTime() - start.getTime()
    const minutes = Math.floor(diff / 60000)
    const seconds = Math.floor((diff % 60000) / 1000)
    return `${minutes}m ${seconds}s`
  }

  // Tool integration handler - called from AdvancedToolsDashboard
  const handleToolExecution = (toolName: string, output: string) => {
    addTerminalOutput(``)
    addTerminalOutput(`[${new Date().toLocaleTimeString()}] Tool: ${toolName}`)
    addTerminalOutput(output)
    
    if (operation && !operation.toolsUsed.includes(toolName)) {
      setOperation({
        ...operation,
        toolsUsed: [...operation.toolsUsed, toolName]
      })
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#0a0a0a] via-[#1a0a0a] to-[#0a0a0a]">
      <SEOOptimizer config={seoConfigs.redTeamOps} />
      
      <div className="max-w-[1920px] mx-auto p-4 md:p-6">
        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center space-x-3 mb-2">
            <div className="w-12 h-12 bg-red-500/10 rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6 text-red-500" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">Red Team Operations</h1>
              <p className="text-terminal-muted">Professional security testing & penetration testing suite</p>
            </div>
          </div>
        </div>

        {/* Operation Control Panel */}
        <div className="bg-[#1a1a1a] border border-terminal-border rounded-lg p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white flex items-center space-x-2">
              <Target className="w-5 h-5 text-red-500" />
              <span>Operation Control</span>
            </h2>
            
            {operation && (
              <div className={`flex items-center space-x-2 px-3 py-1 rounded-lg ${
                isRunning 
                  ? 'bg-green-500/10 border border-green-500/30 text-green-400'
                  : 'bg-terminal-surface border border-terminal-border text-terminal-muted'
              }`}>
                <Activity className={`w-4 h-4 ${isRunning ? 'animate-pulse' : ''}`} />
                <span className="text-sm font-medium">
                  {isRunning ? 'Running' : 'Stopped'}
                </span>
              </div>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div>
              <label className="block text-sm font-medium text-white mb-2">
                Operation Name
              </label>
              <input
                type="text"
                value={operationName}
                onChange={(e) => setOperationName(e.target.value)}
                disabled={isRunning}
                placeholder="e.g., Production Server Assessment"
                className="w-full px-3 py-2 bg-[#0d0d0d] border border-terminal-border rounded-lg text-white placeholder-terminal-muted focus:outline-none focus:border-red-500 disabled:opacity-50"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-white mb-2">
                Target URL
              </label>
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                disabled={isRunning}
                placeholder="example.com or 192.168.1.1"
                className="w-full px-3 py-2 bg-[#0d0d0d] border border-terminal-border rounded-lg text-white placeholder-terminal-muted focus:outline-none focus:border-red-500 disabled:opacity-50"
              />
            </div>
          </div>

          <div className="flex items-center justify-between mb-4 p-3 bg-terminal-surface/50 border border-terminal-border rounded-lg">
            <div className="flex items-center space-x-2">
              <Brain className={`w-4 h-4 ${agentMode ? 'text-purple-400' : 'text-terminal-muted'}`} />
              <div>
                <span className="text-sm text-terminal-text font-medium">Agent Mode</span>
                <p className="text-xs text-terminal-muted">AI-powered autonomous security testing</p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setAgentMode(!agentMode)}
              disabled={isRunning}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors disabled:opacity-50 ${
                agentMode ? 'bg-purple-600' : 'bg-terminal-border'
              }`}
            >
              <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                agentMode ? 'translate-x-6' : 'translate-x-1'
              }`} />
            </button>
          </div>

          <div className="flex space-x-3">
            {!operation || !isRunning ? (
              <button
                onClick={handleStartOperation}
                disabled={!operationName.trim() || !targetUrl.trim()}
                className="flex items-center space-x-2 px-4 py-2 bg-green-500 hover:bg-green-600 disabled:bg-green-500/50 text-white rounded-lg transition-colors disabled:cursor-not-allowed"
              >
                <Play className="w-4 h-4" />
                <span>Start Operation</span>
              </button>
            ) : (
              <button
                onClick={handleStopOperation}
                className="flex items-center space-x-2 px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg transition-colors"
              >
                <Square className="w-4 h-4" />
                <span>Stop Operation</span>
              </button>
            )}
            
            {operation && !isRunning && (
              <>
                <button
                  onClick={handleExportResults}
                  className="flex items-center space-x-2 px-4 py-2 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/30 text-blue-400 rounded-lg transition-colors"
                >
                  <Download className="w-4 h-4" />
                  <span>Export Results</span>
                </button>
                <button
                  onClick={handleResetOperation}
                  className="flex items-center space-x-2 px-4 py-2 bg-terminal-surface hover:bg-terminal-border text-terminal-text rounded-lg transition-colors"
                >
                  <RefreshCw className="w-4 h-4" />
                  <span>New Operation</span>
                </button>
              </>
            )}
          </div>
        </div>

        {/* Active Sessions Panel */}
        <ActiveSessionsPanel />

        {/* Live Terminal Output */}
        {operation && (
          <div className="mb-6">
            <LiveTerminalOutput
              toolName={`Operation: ${operation.name}`}
              output={terminalOutput}
              isRunning={isRunning}
              onStop={isRunning ? handleStopOperation : undefined}
              maxHeight="500px"
              showTimestamps={true}
              enableSearch={true}
              autoScroll={true}
            />
          </div>
        )}

        {/* Professional Suite - Always Available */}
        <div className="bg-[#1a1a1a] border border-terminal-border rounded-lg p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg font-semibold text-white flex items-center space-x-2">
              <Wrench className="w-5 h-5 text-cyan-500" />
              <span>Professional Security Tools</span>
            </h2>
            <div className="flex items-center space-x-2 text-sm text-terminal-muted">
              <Terminal className="w-4 h-4" />
              <span>16+ Tools Available</span>
            </div>
          </div>

          <AdvancedToolsDashboard 
            operation={operation}
            onToolExecute={handleToolExecution}
            addToTerminal={addTerminalOutput}
          />
        </div>

        {/* Operation History */}
        {operationHistory.length > 0 && (
          <div className="mt-6 bg-[#1a1a1a] border border-terminal-border rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Recent Operations</h3>
            <div className="space-y-2">
              {operationHistory.slice(0, 5).map((op) => (
                <div key={op.id} className="p-3 bg-terminal-surface border border-terminal-border rounded-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-white font-medium">{op.name}</p>
                      <p className="text-sm text-terminal-muted">Target: {op.target}</p>
                    </div>
                    <div className="text-right">
                      <p className="text-sm text-terminal-muted">
                        {op.startTime && new Date(op.startTime).toLocaleDateString()}
                      </p>
                      <p className="text-xs text-terminal-muted">
                        {op.toolsUsed.length} tools • {op.findings.length} findings
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Upgrade Prompt */}
      {showUpgradePrompt && (
        <UpgradePrompt
          message={getUpgradeMessage('red_team_ops')}
          onClose={() => setShowUpgradePrompt(false)}
          onUpgrade={() => {
            setShowUpgradePrompt(false)
            window.open('/billing', '_blank')
          }}
        />
      )}
    </div>
  )
}

export default RedTeamOps
