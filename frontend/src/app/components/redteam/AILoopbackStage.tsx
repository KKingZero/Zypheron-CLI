import React, { useState, useEffect } from 'react'
import { 
  Brain, 
  Target, 
  RotateCcw, 
  CheckCircle, 
  TrendingUp, 
  Database,
  Settings,
  Activity,
  FileText,
  Zap,
  Eye,
  Shield,
  Network
} from 'lucide-react'
import toast from 'react-hot-toast'

interface AILoopbackStageProps {
  operation: any
  onOperationComplete: () => void
  onUpdateOperation: (operation: any) => void
}

interface LearningInsight {
  category: 'technique' | 'payload' | 'vulnerability' | 'evasion'
  insight: string
  confidence: number
  impact: 'high' | 'medium' | 'low'
  recommendation: string
}

interface ModelUpdate {
  model: string
  previousAccuracy: number
  newAccuracy: number
  improvement: number
  updatedFeatures: string[]
}

const AILoopbackStage: React.FC<AILoopbackStageProps> = ({ 
  operation, 
  onOperationComplete, 
  onUpdateOperation 
}) => {
  const [isLearning, setIsLearning] = useState(false)
  const [learningProgress, setLearningProgress] = useState(0)
  const [insights, setInsights] = useState<LearningInsight[]>([])
  const [modelUpdates, setModelUpdates] = useState<ModelUpdate[]>([])
  const [learningLogs, setLearningLogs] = useState<string[]>([])
  const [selectedInsight, setSelectedInsight] = useState<LearningInsight | null>(null)
  
  // Learning configuration
  const [learningOptions, setLearningOptions] = useState({
    exploitRanking: true,
    payloadOptimization: true,
    evasionTechniques: true,
    vulnerabilityPrioritization: true,
    industrySpecific: true
  })
  
  const [industryContext, setIndustryContext] = useState('general')
  const [dataRetention, setDataRetention] = useState('sanitized') // 'sanitized' | 'anonymized' | 'none'

  useEffect(() => {
    startAILearning()
  }, [])

  const startAILearning = async () => {
    if (!operation) return

    setIsLearning(true)
    setLearningProgress(0)
    setLearningLogs(['🧠 Initializing AI learning and retraining systems...'])

    try {
      // Step 1: Data sanitization and preparation
      setLearningProgress(10)
      setLearningLogs(prev => [...prev, '🧹 Sanitizing operation data for AI learning...'])

      const sanitizeResponse = await fetch('/api/redteam/ai/sanitize-data', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operationId: operation.id,
          retentionPolicy: dataRetention,
          industryContext
        })
      })
      const sanitizedData = await sanitizeResponse.json()

      setLearningLogs(prev => [...prev, `✅ Data sanitized: ${sanitizedData.recordCount} learning points extracted`])

      // Step 2: Extract learning insights
      setLearningProgress(30)
      setLearningLogs(prev => [...prev, '📊 Analyzing operation patterns and extracting insights...'])

      const insightsResponse = await fetch('/api/redteam/ai/extract-insights', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operationData: sanitizedData.data,
          analysisTypes: learningOptions,
          industryContext
        })
      })
      const extractedInsights = await insightsResponse.json()

      setInsights(extractedInsights.insights)
      setLearningLogs(prev => [...prev, `🎯 Extracted ${extractedInsights.insights.length} actionable insights`])

      // Step 3: Update exploit ranking algorithms
      if (learningOptions.exploitRanking) {
        setLearningProgress(50)
        setLearningLogs(prev => [...prev, '🔄 Retraining exploit ranking algorithms...'])

        const rankingUpdateResponse = await fetch('/api/redteam/ai/update-ranking', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            operationResults: sanitizedData.data,
            successMetrics: operation.findings,
            industryContext
          })
        })
        const rankingUpdate = await rankingUpdateResponse.json()

        setModelUpdates(prev => [...prev, rankingUpdate.modelUpdate])
        setLearningLogs(prev => [...prev, `📈 Exploit ranking model updated: ${rankingUpdate.improvement}% improvement`])
      }

      // Step 4: Optimize payload generation
      if (learningOptions.payloadOptimization) {
        setLearningProgress(70)
        setLearningLogs(prev => [...prev, '⚙️ Optimizing payload generation algorithms...'])

        const payloadOptResponse = await fetch('/api/redteam/ai/optimize-payloads', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            deploymentResults: operation.findings,
            successPatterns: sanitizedData.successPatterns,
            industryContext
          })
        })
        const payloadUpdate = await payloadOptResponse.json()

        setModelUpdates(prev => [...prev, payloadUpdate.modelUpdate])
        setLearningLogs(prev => [...prev, `🚀 Payload generation model enhanced: ${payloadUpdate.improvement}% accuracy`])
      }

      // Step 5: Learn evasion techniques
      if (learningOptions.evasionTechniques) {
        setLearningProgress(85)
        setLearningLogs(prev => [...prev, '🎭 Learning new evasion and stealth techniques...'])

        const evasionResponse = await fetch('/api/redteam/ai/learn-evasion', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            detectionEvents: sanitizedData.detectionEvents,
            bypassSuccess: sanitizedData.bypassSuccess,
            industryContext
          })
        })
        const evasionUpdate = await evasionResponse.json()

        setModelUpdates(prev => [...prev, evasionUpdate.modelUpdate])
        setLearningLogs(prev => [...prev, `🛡️ Evasion techniques database updated with ${evasionUpdate.newTechniques} methods`])
      }

      // Step 6: Industry-specific learning
      if (learningOptions.industrySpecific && industryContext !== 'general') {
        setLearningProgress(95)
        setLearningLogs(prev => [...prev, `🏢 Adapting models for ${industryContext} industry patterns...`])

        const industryResponse = await fetch('/api/redteam/ai/industry-adaptation', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            industryContext,
            operationData: sanitizedData.data,
            specificPatterns: sanitizedData.industryPatterns
          })
        })
        const industryUpdate = await industryResponse.json()

        setModelUpdates(prev => [...prev, industryUpdate.modelUpdate])
        setLearningLogs(prev => [...prev, `🎯 Industry-specific model updated: ${industryUpdate.specialization}% specialization`])
      }

      // Step 7: Save learning results
      setLearningProgress(100)
      setLearningLogs(prev => [...prev, '💾 Saving AI learning results and model updates...'])

      const saveResponse = await fetch('/api/redteam/ai/save-learning', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operationId: operation.id,
          insights,
          modelUpdates,
          learningMetrics: {
            totalInsights: insights.length,
            modelImprovements: modelUpdates.length,
            industryContext
          }
        })
      })

      // Update operation with learning results
      const updatedOperation = {
        ...operation,
        findings: [
          ...operation.findings,
          {
            stage: 'loopback',
            aiLearning: {
              insights,
              modelUpdates,
              timestamp: new Date()
            }
          }
        ],
        status: 'completed'
      }
      onUpdateOperation(updatedOperation)

      setLearningLogs(prev => [...prev, '✅ AI learning cycle completed successfully!'])
      toast.success('AI learning and model updates completed')

    } catch (error) {
      console.error('AI learning failed:', error)
      toast.error('AI learning process failed')
      setLearningLogs(prev => [...prev, `❌ Error: ${error.message}`])
    } finally {
      setIsLearning(false)
    }
  }

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'technique': return <Zap className="w-4 h-4" />
      case 'payload': return <Target className="w-4 h-4" />
      case 'vulnerability': return <Shield className="w-4 h-4" />
      case 'evasion': return <Eye className="w-4 h-4" />
      default: return <Brain className="w-4 h-4" />
    }
  }

  const getImpactColor = (impact: string) => {
    switch (impact) {
      case 'high': return 'text-red-500 bg-red-500/10 border-red-500'
      case 'medium': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500'
      case 'low': return 'text-green-500 bg-green-500/10 border-green-500'
      default: return 'text-gray-500 bg-gray-500/10 border-gray-500'
    }
  }

  return (
    <div className="space-y-6">
      {/* Stage Header */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h2 className="text-2xl font-bold text-terminal-text mb-2 flex items-center">
          <Brain className="w-6 h-6 mr-3 text-cobra-500" />
          BONUS Stage: AI Loopback & Learning
        </h2>
        <p className="text-terminal-muted text-lg">
          Auto-learn and retrain exploit ranking algorithms based on operation results
        </p>
      </div>

      {/* Learning Configuration */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
          <Settings className="w-5 h-5 mr-2 text-cobra-500" />
          AI Learning Configuration
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="block text-sm font-medium text-terminal-text mb-3">
              Learning Modules
            </label>
            <div className="space-y-2">
              {Object.entries(learningOptions).map(([option, enabled]) => (
                <label key={option} className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enabled}
                    onChange={(e) => setLearningOptions(prev => ({
                      ...prev,
                      [option]: e.target.checked
                    }))}
                    disabled={isLearning}
                    className="text-cobra-500 focus:ring-cobra-500"
                  />
                  <span className="text-sm text-terminal-text">
                    {option.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                  </span>
                </label>
              ))}
            </div>
          </div>

          <div>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-terminal-text mb-2">
                  Industry Context
                </label>
                <select
                  value={industryContext}
                  onChange={(e) => setIndustryContext(e.target.value)}
                  disabled={isLearning}
                  className="w-full px-4 py-2 bg-terminal-bg border border-terminal-border rounded-lg text-terminal-text focus:border-cobra-500"
                >
                  <option value="general">General</option>
                  <option value="finance">Financial Services</option>
                  <option value="healthcare">Healthcare</option>
                  <option value="technology">Technology</option>
                  <option value="government">Government</option>
                  <option value="retail">Retail</option>
                  <option value="manufacturing">Manufacturing</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-terminal-text mb-2">
                  Data Retention Policy
                </label>
                <select
                  value={dataRetention}
                  onChange={(e) => setDataRetention(e.target.value)}
                  disabled={isLearning}
                  className="w-full px-4 py-2 bg-terminal-bg border border-terminal-border rounded-lg text-terminal-text focus:border-cobra-500"
                >
                  <option value="sanitized">Sanitized (Remove PII)</option>
                  <option value="anonymized">Anonymized (Hash identifiers)</option>
                  <option value="none">No Retention</option>
                </select>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Learning Progress */}
      {isLearning && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <Activity className="w-5 h-5 mr-2 text-cobra-500" />
            AI Learning Progress
          </h3>
          
          <div className="mb-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-terminal-muted">Learning Progress</span>
              <span className="text-sm text-terminal-text">{learningProgress}%</span>
            </div>
            <div className="w-full bg-terminal-bg rounded-full h-2">
              <div 
                className="bg-cobra-500 h-2 rounded-full transition-all duration-300"
                style={{ width: `${learningProgress}%` }}
              />
            </div>
          </div>

          <div className="max-h-48 overflow-y-auto space-y-1">
            {learningLogs.map((log, index) => (
              <p key={index} className="text-sm text-terminal-text font-mono">
                {log}
              </p>
            ))}
          </div>
        </div>
      )}

      {/* Learning Insights */}
      {insights.length > 0 && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <TrendingUp className="w-5 h-5 mr-2 text-cobra-500" />
            AI Learning Insights ({insights.length})
          </h3>
          
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {insights.map((insight, index) => (
              <div 
                key={index}
                onClick={() => setSelectedInsight(insight)}
                className={`p-4 rounded-lg border cursor-pointer transition-all hover:border-cobra-500 ${getImpactColor(insight.impact)}`}
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    {getCategoryIcon(insight.category)}
                    <h4 className="font-semibold text-terminal-text capitalize">{insight.category}</h4>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className={`text-xs px-2 py-1 rounded ${getImpactColor(insight.impact)}`}>
                      {insight.impact.toUpperCase()}
                    </span>
                    <span className="text-xs text-terminal-muted">
                      {insight.confidence}%
                    </span>
                  </div>
                </div>
                <p className="text-sm text-terminal-text line-clamp-3">{insight.insight}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Model Updates */}
      {modelUpdates.length > 0 && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <Database className="w-5 h-5 mr-2 text-cobra-500" />
            AI Model Updates ({modelUpdates.length})
          </h3>
          
          <div className="space-y-4">
            {modelUpdates.map((update, index) => (
              <div key={index} className="bg-green-500/10 border border-green-500/20 rounded-lg p-4">
                <div className="flex items-center justify-between mb-3">
                  <h4 className="font-semibold text-green-400">{update.model}</h4>
                  <span className="text-green-300 font-mono">
                    +{update.improvement.toFixed(1)}% accuracy
                  </span>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                  <div>
                    <span className="text-terminal-muted">Previous:</span>
                    <p className="text-terminal-text">{update.previousAccuracy.toFixed(1)}%</p>
                  </div>
                  <div>
                    <span className="text-terminal-muted">Updated:</span>
                    <p className="text-terminal-text">{update.newAccuracy.toFixed(1)}%</p>
                  </div>
                  <div>
                    <span className="text-terminal-muted">Features:</span>
                    <p className="text-terminal-text">{update.updatedFeatures.length} updated</p>
                  </div>
                </div>
                
                {update.updatedFeatures.length > 0 && (
                  <div className="mt-3">
                    <div className="flex flex-wrap gap-1">
                      {update.updatedFeatures.slice(0, 5).map((feature, idx) => (
                        <span 
                          key={idx}
                          className="px-2 py-1 bg-cobra-500/20 text-cobra-400 text-xs rounded"
                        >
                          {feature}
                        </span>
                      ))}
                      {update.updatedFeatures.length > 5 && (
                        <span className="px-2 py-1 bg-terminal-bg text-terminal-muted text-xs rounded">
                          +{update.updatedFeatures.length - 5} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Stage Completion */}
      {!isLearning && insights.length > 0 && (
        <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <CheckCircle className="w-6 h-6 text-green-500" />
              <div>
                <h3 className="text-lg font-semibold text-green-400">
                  AI Learning Cycle Complete
                </h3>
                <p className="text-green-300/80">
                  Extracted {insights.length} insights and updated {modelUpdates.length} AI models
                </p>
              </div>
            </div>
            
            <button
              onClick={onOperationComplete}
              className="px-6 py-3 bg-green-600 hover:bg-green-700 text-white rounded-lg flex items-center space-x-2 transition-colors"
            >
              <CheckCircle className="w-4 h-4" />
              <span>Complete Operation</span>
            </button>
          </div>
        </div>
      )}

      {/* Insight Detail Modal */}
      {selectedInsight && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-terminal-card border border-terminal-border rounded-lg max-w-2xl w-full max-h-[80vh] overflow-y-auto">
            <div className="p-6">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="text-xl font-bold text-terminal-text capitalize">
                    {selectedInsight.category} Insight
                  </h3>
                  <div className="flex items-center space-x-2 mt-2">
                    <span className={`text-xs px-2 py-1 rounded ${getImpactColor(selectedInsight.impact)}`}>
                      {selectedInsight.impact.toUpperCase()} IMPACT
                    </span>
                    <span className="text-xs px-2 py-1 bg-blue-500/20 text-blue-400 rounded">
                      {selectedInsight.confidence}% CONFIDENCE
                    </span>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedInsight(null)}
                  className="text-terminal-muted hover:text-terminal-text"
                >
                  ✕
                </button>
              </div>
              
              <div className="space-y-4">
                <div>
                  <label className="text-sm font-medium text-terminal-muted">Insight</label>
                  <p className="text-terminal-text">{selectedInsight.insight}</p>
                </div>
                
                <div>
                  <label className="text-sm font-medium text-terminal-muted">AI Recommendation</label>
                  <p className="text-terminal-text">{selectedInsight.recommendation}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default AILoopbackStage 