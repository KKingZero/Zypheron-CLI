import React, { useState, useEffect } from 'react'
import { 
  Shield, 
  Target, 
  Brain, 
  CheckCircle, 
  AlertTriangle, 
  Settings, 
  Lock,
  Unlock,
  FileText,
  Terminal,
  Download,
  Upload,
  Activity,
  Cpu,
  Server,
  Code,
  Wrench,
  ShieldCheck,
  Bug,
  Zap,
  Eye,
  ArrowRight
} from 'lucide-react'
import RobotIcon from '../../../components/icons/RobotIcon'
import toast from 'react-hot-toast'

interface PatchStageProps {
  operation: any
  onOperationComplete: () => void
  onUpdateOperation: (operation: any) => void
  agentMode?: boolean
}

interface Vulnerability {
  id: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  category: string
  cve?: string
  description: string
  affectedSystems: string[]
  exploitedBy: string[]
  patchAvailable: boolean
  patchComplexity: 'low' | 'medium' | 'high'
  businessImpact: string
  remediationSteps: string[]
  estimatedFixTime: number
}

interface PatchAction {
  id: string
  type: 'patch' | 'configuration' | 'policy' | 'monitoring'
  title: string
  description: string
  vulnerabilityIds: string[]
  automated: boolean
  status: 'pending' | 'in_progress' | 'completed' | 'failed'
  priority: number
  commands: string[]
  verification: string[]
  rollbackPlan: string[]
}

interface SecurityRecommendation {
  id: string
  category: 'network' | 'system' | 'application' | 'policy'
  title: string
  description: string
  impact: string
  implementation: string[]
  priority: 'immediate' | 'short_term' | 'long_term'
  cost: 'low' | 'medium' | 'high'
}

const PatchStage: React.FC<PatchStageProps> = ({ 
  operation, 
  onOperationComplete, 
  onUpdateOperation,
  agentMode = false
}) => {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([])
  const [patchActions, setPatchActions] = useState<PatchAction[]>([])
  const [securityRecommendations, setSecurityRecommendations] = useState<SecurityRecommendation[]>([])
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [isPatching, setIsPatching] = useState(false)
  const [patchLogs, setPatchLogs] = useState<string[]>([])
  const [selectedActions, setSelectedActions] = useState<string[]>([])
  const [automatedMode, setAutomatedMode] = useState(false)
  
  // Metrics
  const [patchMetrics, setPatchMetrics] = useState({
    totalVulnerabilities: 0,
    criticalVulnerabilities: 0,
    patchedVulnerabilities: 0,
    systemsSecured: 0,
    riskReduction: 0
  })

  // Agent Mode specific states
  const [agentActions, setAgentActions] = useState<string[]>([])
  const [agentRecommendations, setAgentRecommendations] = useState<string[]>([])

  useEffect(() => {
    analyzeVulnerabilities()
    if (agentMode) {
      setPatchLogs(prev => [...prev, '🤖 AI Agent initiating intelligent patch analysis'])
      setAgentActions(['Analyzing attack patterns', 'Identifying critical vulnerabilities', 'Generating remediation strategies'])
    }
  }, [agentMode])

  const analyzeVulnerabilities = async () => {
    setIsAnalyzing(true)
    setPatchLogs(['🔍 Analyzing vulnerabilities and generating patch recommendations...'])

    try {
      // Simulate vulnerability analysis
      await new Promise(resolve => setTimeout(resolve, 2000))

      const mockVulnerabilities: Vulnerability[] = [
        {
          id: 'vuln-001',
          severity: 'critical',
          category: 'Remote Code Execution',
          cve: 'CVE-2024-12345',
          description: 'Buffer overflow in web server allowing remote code execution',
          affectedSystems: ['web-server-01', 'web-server-02'],
          exploitedBy: ['Payload-001'],
          patchAvailable: true,
          patchComplexity: 'low',
          businessImpact: 'High - Direct system compromise',
          remediationSteps: [
            'Update web server to latest version',
            'Apply security patches',
            'Restart affected services',
            'Verify patch installation'
          ],
          estimatedFixTime: 30
        },
        {
          id: 'vuln-002',
          severity: 'high',
          category: 'Privilege Escalation',
          cve: 'CVE-2024-54321',
          description: 'Local privilege escalation via misconfigured service',
          affectedSystems: ['db-primary', 'app-server-01'],
          exploitedBy: ['Payload-002'],
          patchAvailable: true,
          patchComplexity: 'medium',
          businessImpact: 'Medium - Potential data access',
          remediationSteps: [
            'Update service configuration',
            'Apply principle of least privilege',
            'Update system packages',
            'Monitor service logs'
          ],
          estimatedFixTime: 60
        }
      ]

      const mockPatchActions: PatchAction[] = [
        {
          id: 'patch-001',
          type: 'patch',
          title: 'Critical Web Server Security Update',
          description: 'Apply security patches to address remote code execution vulnerability',
          vulnerabilityIds: ['vuln-001'],
          automated: true,
          status: 'pending',
          priority: 1,
          commands: [
            'sudo apt update',
            'sudo apt upgrade nginx',
            'sudo systemctl restart nginx',
            'sudo systemctl status nginx'
          ],
          verification: [
            'Check nginx version',
            'Verify service status',
            'Test vulnerability scanner'
          ],
          rollbackPlan: [
            'sudo apt install nginx=previous-version',
            'sudo systemctl restart nginx'
          ]
        },
        {
          id: 'patch-002',
          type: 'configuration',
          title: 'Database Service Hardening',
          description: 'Reconfigure database service to prevent privilege escalation',
          vulnerabilityIds: ['vuln-002'],
          automated: false,
          status: 'pending',
          priority: 2,
          commands: [
            'sudo nano /etc/mysql/mysql.conf.d/mysqld.cnf',
            'sudo systemctl restart mysql',
            'mysql -u root -p < security_updates.sql'
          ],
          verification: [
            'Check mysql configuration',
            'Verify user privileges',
            'Test access controls'
          ],
          rollbackPlan: [
            'Restore original configuration',
            'Restart services'
          ]
        }
      ]

      const mockRecommendations: SecurityRecommendation[] = [
        {
          id: 'rec-001',
          category: 'network',
          title: 'Implement Network Segmentation',
          description: 'Isolate critical systems to prevent lateral movement',
          impact: 'Reduces attack surface and contains potential breaches',
          implementation: [
            'Deploy firewall rules',
            'Create network VLANs',
            'Implement micro-segmentation',
            'Monitor network traffic'
          ],
          priority: 'short_term',
          cost: 'medium'
        },
        {
          id: 'rec-002',
          category: 'monitoring',
          title: 'Enhanced Security Monitoring',
          description: 'Deploy comprehensive security monitoring and alerting',
          impact: 'Faster detection and response to security incidents',
          implementation: [
            'Deploy SIEM solution',
            'Configure security alerts',
            'Implement log aggregation',
            'Train security team'
          ],
          priority: 'immediate',
          cost: 'high'
        }
      ]

      setVulnerabilities(mockVulnerabilities)
      setPatchActions(mockPatchActions)
      setSecurityRecommendations(mockRecommendations)

      setPatchMetrics({
        totalVulnerabilities: mockVulnerabilities.length,
        criticalVulnerabilities: mockVulnerabilities.filter(v => v.severity === 'critical').length,
        patchedVulnerabilities: 0,
        systemsSecured: 0,
        riskReduction: 0
      })

      setPatchLogs(prev => [...prev, '✅ Vulnerability analysis completed'])
      
      if (agentMode) {
        setAgentRecommendations([
          'Prioritize critical vulnerabilities first',
          'Apply patches during maintenance window',
          'Implement continuous monitoring',
          'Establish patch management process'
        ])
      }

    } catch (error) {
      setPatchLogs(prev => [...prev, `❌ Analysis failed: ${error}`])
      toast.error('Vulnerability analysis failed')
    } finally {
      setIsAnalyzing(false)
    }
  }

  const executePatchActions = async () => {
    if (selectedActions.length === 0) {
      toast.error('Please select patch actions to execute')
      return
    }

    setIsPatching(true)
    setPatchLogs(prev => [...prev, '🔧 Executing patch actions...'])

    if (agentMode) {
      setPatchLogs(prev => [...prev, '🤖 AI Agent orchestrating automated patch deployment'])
    }

    try {
      for (const actionId of selectedActions) {
        const action = patchActions.find(a => a.id === actionId)
        if (!action) continue

        setPatchLogs(prev => [...prev, `🔧 Executing: ${action.title}`])
        
        // Update action status
        setPatchActions(prev => prev.map(a => 
          a.id === actionId ? { ...a, status: 'in_progress' } : a
        ))

        // Simulate patch execution
        await new Promise(resolve => setTimeout(resolve, 3000))

        // Mark as completed
        setPatchActions(prev => prev.map(a => 
          a.id === actionId ? { ...a, status: 'completed' } : a
        ))

        setPatchLogs(prev => [...prev, `✅ Completed: ${action.title}`])

        // Update metrics
        const vulnsPatched = action.vulnerabilityIds.length
        setPatchMetrics(prev => ({
          ...prev,
          patchedVulnerabilities: prev.patchedVulnerabilities + vulnsPatched,
          systemsSecured: prev.systemsSecured + 1,
          riskReduction: Math.min(100, prev.riskReduction + 25)
        }))
      }

      setPatchLogs(prev => [...prev, '🎉 All selected patch actions completed successfully'])
      toast.success('Patch deployment completed')

    } catch (error) {
      setPatchLogs(prev => [...prev, `❌ Patch execution failed: ${error}`])
      toast.error('Patch execution failed')
    } finally {
      setIsPatching(false)
    }
  }

  const VulnerabilityOverview = () => (
    <div className="bg-terminal-card border border-terminal-border rounded-lg p-6 mb-6">
      <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
        <Bug className="w-5 h-5 mr-2 text-red-500" />
        Vulnerability Assessment
      </h3>
      
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-terminal-bg p-4 rounded-lg border border-terminal-border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-terminal-muted text-sm">Total Vulnerabilities</span>
            <AlertTriangle className="w-4 h-4 text-orange-500" />
          </div>
          <div className="text-2xl font-bold text-orange-500">
            {patchMetrics.totalVulnerabilities}
          </div>
        </div>
        
        <div className="bg-terminal-bg p-4 rounded-lg border border-terminal-border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-terminal-muted text-sm">Critical</span>
            <AlertTriangle className="w-4 h-4 text-red-500" />
          </div>
          <div className="text-2xl font-bold text-red-500">
            {patchMetrics.criticalVulnerabilities}
          </div>
        </div>
        
        <div className="bg-terminal-bg p-4 rounded-lg border border-terminal-border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-terminal-muted text-sm">Patched</span>
            <CheckCircle className="w-4 h-4 text-green-500" />
          </div>
          <div className="text-2xl font-bold text-green-500">
            {patchMetrics.patchedVulnerabilities}
          </div>
        </div>
        
        <div className="bg-terminal-bg p-4 rounded-lg border border-terminal-border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-terminal-muted text-sm">Risk Reduction</span>
            <ShieldCheck className="w-4 h-4 text-blue-500" />
          </div>
          <div className="text-2xl font-bold text-blue-500">
            {patchMetrics.riskReduction.toFixed(0)}%
          </div>
        </div>
      </div>

      <div className="space-y-4">
        {vulnerabilities.map((vuln) => (
          <div key={vuln.id} className="bg-terminal-bg border border-terminal-border rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center space-x-3">
                <div className={`px-2 py-1 rounded text-xs font-medium ${
                  vuln.severity === 'critical' ? 'bg-red-500/20 text-red-500' :
                  vuln.severity === 'high' ? 'bg-orange-500/20 text-orange-500' :
                  vuln.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-500' :
                  'bg-blue-500/20 text-blue-500'
                }`}>
                  {vuln.severity.toUpperCase()}
                </div>
                <h4 className="font-medium text-terminal-text">{vuln.category}</h4>
                {vuln.cve && (
                  <span className="text-xs text-terminal-muted bg-terminal-card px-2 py-1 rounded">
                    {vuln.cve}
                  </span>
                )}
              </div>
              {vuln.patchAvailable && (
                <div className="px-2 py-1 bg-green-500/20 text-green-500 rounded text-xs">
                  PATCH AVAILABLE
                </div>
              )}
            </div>
            
            <p className="text-terminal-muted text-sm mb-3">{vuln.description}</p>
            
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
              <div>
                <span className="text-terminal-muted">Affected Systems:</span>
                <p className="text-terminal-text">{vuln.affectedSystems.join(', ')}</p>
              </div>
              <div>
                <span className="text-terminal-muted">Exploited By:</span>
                <p className="text-terminal-text">{vuln.exploitedBy.join(', ')}</p>
              </div>
              <div>
                <span className="text-terminal-muted">Fix Time:</span>
                <p className="text-terminal-text">{vuln.estimatedFixTime} minutes</p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )

  const PatchControlPanel = () => (
    <div className="bg-terminal-card border border-terminal-border rounded-lg p-6 mb-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-terminal-text flex items-center">
          <Wrench className="w-5 h-5 mr-2 text-cobra-500" />
          Patch Management
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
              onClick={() => setAutomatedMode(!automatedMode)}
              className={`px-3 py-1 rounded-lg text-sm transition-colors ${
                automatedMode 
                  ? 'bg-green-600 text-white' 
                  : 'bg-gray-600 text-gray-300'
              }`}
            >
              <RobotIcon size={14} className="inline mr-1" />
              Auto-Patch
            </button>
          )}
          
          <button
            onClick={executePatchActions}
            disabled={isPatching || selectedActions.length === 0}
            className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 text-white rounded-lg flex items-center space-x-2 transition-colors"
          >
            {isPatching ? (
              <>
                <Activity className="w-4 h-4 animate-spin" />
                <span>Patching...</span>
              </>
            ) : (
              <>
                <Wrench className="w-4 h-4" />
                <span>Deploy Patches</span>
              </>
            )}
          </button>
        </div>
      </div>

      {agentMode && agentRecommendations.length > 0 && (
        <div className="bg-cobra-500/10 border border-cobra-500/30 rounded-lg p-4 mb-4">
          <div className="flex items-center mb-2">
            <RobotIcon size={16} className="mr-2 text-cobra-500" />
            <span className="text-sm font-medium text-cobra-500">AI Agent Recommendations</span>
          </div>
          <div className="space-y-1">
            {agentRecommendations.map((rec, index) => (
              <div key={index} className="text-sm text-terminal-text flex items-center">
                <ArrowRight className="w-3 h-3 mr-2 text-cobra-500" />
                {rec}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="space-y-4">
        {patchActions.map((action) => (
          <div key={action.id} className="bg-terminal-bg border border-terminal-border rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center space-x-3">
                <input
                  type="checkbox"
                  checked={selectedActions.includes(action.id)}
                  onChange={(e) => {
                    if (e.target.checked) {
                      setSelectedActions(prev => [...prev, action.id])
                    } else {
                      setSelectedActions(prev => prev.filter(id => id !== action.id))
                    }
                  }}
                  className="w-4 h-4 text-cobra-500"
                />
                <h4 className="font-medium text-terminal-text">{action.title}</h4>
                {action.automated && (
                  <span className="px-2 py-1 bg-blue-500/20 text-blue-500 rounded text-xs">
                    AUTOMATED
                  </span>
                )}
              </div>
              <div className={`px-2 py-1 rounded text-xs ${
                action.status === 'completed' ? 'bg-green-500/20 text-green-500' :
                action.status === 'in_progress' ? 'bg-yellow-500/20 text-yellow-500' :
                action.status === 'failed' ? 'bg-red-500/20 text-red-500' :
                'bg-gray-500/20 text-gray-500'
              }`}>
                {action.status.replace('_', ' ').toUpperCase()}
              </div>
            </div>
            
            <p className="text-terminal-muted text-sm mb-3">{action.description}</p>
            
            <div className="text-sm">
              <span className="text-terminal-muted">Addresses: </span>
              <span className="text-terminal-text">
                {action.vulnerabilityIds.length} vulnerability(s)
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )

  const SecurityRecommendationsPanel = () => (
    <div className="bg-terminal-card border border-terminal-border rounded-lg p-6 mb-6">
      <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
        <ShieldCheck className="w-5 h-5 mr-2 text-blue-500" />
        Security Hardening Recommendations
      </h3>
      
      <div className="space-y-4">
        {securityRecommendations.map((rec) => (
          <div key={rec.id} className="bg-terminal-bg border border-terminal-border rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <h4 className="font-medium text-terminal-text">{rec.title}</h4>
              <div className="flex items-center space-x-2">
                <div className={`px-2 py-1 rounded text-xs ${
                  rec.priority === 'immediate' ? 'bg-red-500/20 text-red-500' :
                  rec.priority === 'short_term' ? 'bg-yellow-500/20 text-yellow-500' :
                  'bg-blue-500/20 text-blue-500'
                }`}>
                  {rec.priority.replace('_', ' ').toUpperCase()}
                </div>
                <div className={`px-2 py-1 rounded text-xs ${
                  rec.cost === 'high' ? 'bg-red-500/20 text-red-500' :
                  rec.cost === 'medium' ? 'bg-yellow-500/20 text-yellow-500' :
                  'bg-green-500/20 text-green-500'
                }`}>
                  {rec.cost.toUpperCase()} COST
                </div>
              </div>
            </div>
            
            <p className="text-terminal-muted text-sm mb-3">{rec.description}</p>
            <p className="text-terminal-text text-sm mb-3"><strong>Impact:</strong> {rec.impact}</p>
            
            <div className="text-sm">
              <span className="text-terminal-muted font-medium">Implementation Steps:</span>
              <ul className="list-disc list-inside mt-2 space-y-1">
                {rec.implementation.map((step, index) => (
                  <li key={index} className="text-terminal-text">{step}</li>
                ))}
              </ul>
            </div>
          </div>
        ))}
      </div>
    </div>
  )

  const PatchLogsPanel = () => (
    <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
      <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
        <Terminal className="w-5 h-5 mr-2 text-cobra-500" />
        Patch Execution Logs
      </h3>
      
      <div className="bg-black rounded-lg p-4 h-64 overflow-y-auto font-mono text-sm">
        {patchLogs.map((log, index) => (
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
          <Shield className="w-6 h-6 mr-3 text-cobra-500" />
          Stage 4: Fix & Patch Management
          {agentMode && (
            <span className="ml-3 px-3 py-1 bg-cobra-500 text-white text-sm rounded-full flex items-center">
              <RobotIcon size={16} className="mr-2" />
              AI AGENT MODE
            </span>
          )}
        </h2>
        <p className="text-terminal-muted">
          Automatically identify, prioritize, and deploy security patches for discovered vulnerabilities
        </p>
      </div>

      <VulnerabilityOverview />
      <PatchControlPanel />
      <SecurityRecommendationsPanel />
      <PatchLogsPanel />

      <div className="flex justify-between">
        <button
          onClick={() => window.history.back()}
          className="px-6 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg transition-colors"
        >
          Back to Execution Stage
        </button>
        
        <button
          onClick={onOperationComplete}
          className="px-6 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors"
        >
          Complete Red Team Operation
        </button>
      </div>
    </div>
  )
}

export default PatchStage