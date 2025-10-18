import React, { useState, useEffect } from 'react'
import { AlertTriangle, Eye, TrendingUp, Shield, Brain, Download, RefreshCw, Filter, Search } from 'lucide-react'

interface ThreatAlert {
  id: string
  timestamp: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  category: string
  title: string
  description: string
  sourceIp: string
  destinationIp: string
  protocol: string
  port: number
  confidence: number
  riskScore: number
  iocMatches: string[]
  gptAnalysis?: GPTThreatAnalysis
  status: 'open' | 'investigating' | 'resolved' | 'false_positive'
}

interface GPTThreatAnalysis {
  summary: string
  attackVector: string
  recommendation: string
  urgency: 'low' | 'medium' | 'high' | 'critical'
  relatedThreats: string[]
  mitigation: string[]
}

interface IOCIndicator {
  id: string
  type: 'ip' | 'domain' | 'hash' | 'url' | 'email'
  value: string
  source: string
  confidence: number
  lastSeen: string
  threatType: string
  description: string
  reputation: 'malicious' | 'suspicious' | 'unknown' | 'benign'
}

interface LogCorrelation {
  id: string
  timeWindow: string
  pattern: string
  eventCount: number
  uniqueSources: number
  severity: string
  description: string
  correlatedEvents: Array<{
    timestamp: string
    source: string
    event: string
  }>
}

interface ThreatIntelligence {
  feeds: Array<{
    name: string
    status: 'active' | 'inactive' | 'error'
    lastUpdate: string
    indicators: number
  }>
  summary: {
    totalIndicators: number
    activeThreats: number
    newThreatsToday: number
    highPriorityAlerts: number
  }
}

interface OssimPanelProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

const OssimPanel: React.FC<OssimPanelProps> = ({ onToolExecute }) => {
  const [alerts, setAlerts] = useState<ThreatAlert[]>([])
  const [iocIndicators, setIocIndicators] = useState<IOCIndicator[]>([])
  const [correlations, setCorrelations] = useState<LogCorrelation[]>([])
  const [threatIntel, setThreatIntel] = useState<ThreatIntelligence | null>(null)
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlert | null>(null)
  const [viewMode, setViewMode] = useState<'dashboard' | 'alerts' | 'ioc' | 'correlation' | 'intel'>('dashboard')
  const [filterSeverity, setFilterSeverity] = useState<string>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [autoRefresh, setAutoRefresh] = useState(true)

  const severityLevels = ['all', 'low', 'medium', 'high', 'critical']

  const loadThreatData = async () => {
    setIsLoading(true)
    try {
      const result = await onToolExecute('ossim_intelligence', {
        includeAlerts: true,
        includeIOC: true,
        includeCorrelation: true,
        timeRange: '24h'
      })

      if (result) {
        setAlerts(result.alerts || [])
        setIocIndicators(result.iocIndicators || [])
        setCorrelations(result.correlations || [])
        setThreatIntel(result.threatIntelligence)
      }
    } catch (error) {
      console.error('Failed to load threat data:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const analyzeAlertWithGPT = async (alert: ThreatAlert) => {
    try {
      const result = await onToolExecute('ossim_gpt_analyze', {
        alertId: alert.id,
        alertData: {
          title: alert.title,
          description: alert.description,
          sourceIp: alert.sourceIp,
          destinationIp: alert.destinationIp,
          protocol: alert.protocol,
          iocMatches: alert.iocMatches
        }
      })

      if (result.analysis) {
        setAlerts(prev => 
          prev.map(a => 
            a.id === alert.id 
              ? { ...a, gptAnalysis: result.analysis }
              : a
          )
        )
      }
    } catch (error) {
      console.error('GPT analysis failed:', error)
    }
  }

  const updateAlertStatus = async (alertId: string, status: ThreatAlert['status']) => {
    try {
      await onToolExecute('ossim_update_alert', { alertId, status })
      
      setAlerts(prev => 
        prev.map(a => 
          a.id === alertId 
            ? { ...a, status }
            : a
        )
      )
    } catch (error) {
      console.error('Failed to update alert status:', error)
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-600/20'
      case 'high': return 'text-red-500 bg-red-500/20'
      case 'medium': return 'text-yellow-500 bg-yellow-500/20'
      case 'low': return 'text-green-500 bg-green-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'text-red-500 bg-red-500/20'
      case 'investigating': return 'text-yellow-500 bg-yellow-500/20'
      case 'resolved': return 'text-green-500 bg-green-500/20'
      case 'false_positive': return 'text-gray-500 bg-gray-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  const getReputationColor = (reputation: string) => {
    switch (reputation) {
      case 'malicious': return 'text-red-600 bg-red-600/20'
      case 'suspicious': return 'text-yellow-500 bg-yellow-500/20'
      case 'unknown': return 'text-gray-500 bg-gray-500/20'
      case 'benign': return 'text-green-500 bg-green-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  const filteredAlerts = alerts.filter(alert => {
    const matchesSeverity = filterSeverity === 'all' || alert.severity === filterSeverity
    const matchesSearch = alert.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         alert.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         alert.sourceIp.includes(searchQuery) ||
                         alert.destinationIp.includes(searchQuery)
    return matchesSeverity && matchesSearch
  })

  useEffect(() => {
    loadThreatData()
    
    if (autoRefresh) {
      const interval = setInterval(loadThreatData, 30000) // Refresh every 30 seconds
      return () => clearInterval(interval)
    }
  }, [autoRefresh])

  return (
    <div className="space-y-6">
      {/* OSSIM Header */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h3 className="text-xl font-bold text-terminal-text mb-4 flex items-center">
          <AlertTriangle className="w-6 h-6 mr-3 text-red-500" />
          AlienVault OSSIM
          <span className="ml-3 px-3 py-1 bg-red-500 text-white text-sm rounded-full">LIVE MONITORING</span>
        </h3>
        <p className="text-terminal-muted">
          Unified threat intelligence and log correlation with AI-powered analysis and real-time alerts
        </p>
        
        {/* Controls */}
        <div className="mt-4 flex items-center space-x-4">
          <button
            onClick={loadThreatData}
            disabled={isLoading}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white rounded flex items-center space-x-2"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          
          <div className="flex items-center space-x-2">
            <input
              type="checkbox"
              id="auto-refresh"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="text-red-500"
            />
            <label htmlFor="auto-refresh" className="text-terminal-text text-sm">
              Auto-refresh (30s)
            </label>
          </div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex space-x-2">
        <button
          onClick={() => setViewMode('dashboard')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'dashboard' 
              ? 'bg-red-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <TrendingUp className="w-4 h-4" />
          <span>Dashboard</span>
        </button>
        <button
          onClick={() => setViewMode('alerts')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'alerts' 
              ? 'bg-red-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <AlertTriangle className="w-4 h-4" />
          <span>Alerts ({alerts.length})</span>
        </button>
        <button
          onClick={() => setViewMode('ioc')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'ioc' 
              ? 'bg-red-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Eye className="w-4 h-4" />
          <span>IOC ({iocIndicators.length})</span>
        </button>
        <button
          onClick={() => setViewMode('correlation')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'correlation' 
              ? 'bg-red-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Shield className="w-4 h-4" />
          <span>Correlation ({correlations.length})</span>
        </button>
        <button
          onClick={() => setViewMode('intel')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'intel' 
              ? 'bg-red-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Brain className="w-4 h-4" />
          <span>Intelligence</span>
        </button>
      </div>

      {/* Dashboard Tab */}
      {viewMode === 'dashboard' && threatIntel && (
        <div className="space-y-6">
          {/* Threat Overview */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-terminal-card border border-terminal-border rounded-lg p-4 text-center">
              <div className="text-3xl font-bold text-red-500">{threatIntel.summary.activeThreats}</div>
              <div className="text-terminal-muted text-sm">Active Threats</div>
            </div>
            <div className="bg-terminal-card border border-terminal-border rounded-lg p-4 text-center">
              <div className="text-3xl font-bold text-yellow-500">{threatIntel.summary.newThreatsToday}</div>
              <div className="text-terminal-muted text-sm">New Today</div>
            </div>
            <div className="bg-terminal-card border border-terminal-border rounded-lg p-4 text-center">
              <div className="text-3xl font-bold text-purple-500">{threatIntel.summary.totalIndicators}</div>
              <div className="text-terminal-muted text-sm">Total IOCs</div>
            </div>
            <div className="bg-terminal-card border border-terminal-border rounded-lg p-4 text-center">
              <div className="text-3xl font-bold text-orange-500">{threatIntel.summary.highPriorityAlerts}</div>
              <div className="text-terminal-muted text-sm">High Priority</div>
            </div>
          </div>

          {/* Recent High Priority Alerts */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">Recent High Priority Alerts</h4>
            <div className="space-y-3">
              {alerts.filter(a => a.severity === 'high' || a.severity === 'critical').slice(0, 5).map((alert) => (
                <div key={alert.id} className="border border-terminal-border rounded-lg p-3">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center space-x-3">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(alert.severity)}`}>
                        {alert.severity.toUpperCase()}
                      </span>
                      <span className="font-medium text-terminal-text">{alert.title}</span>
                    </div>
                    <span className="text-terminal-muted text-sm">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="text-terminal-muted text-sm">{alert.description}</p>
                  <div className="mt-2 flex items-center space-x-4 text-xs">
                    <span className="text-terminal-muted">
                      <strong>Source:</strong> {alert.sourceIp}
                    </span>
                    <span className="text-terminal-muted">
                      <strong>Risk:</strong> {alert.riskScore}/100
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Threat Feed Status */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">Threat Intelligence Feeds</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {threatIntel.feeds.map((feed, index) => (
                <div key={index} className="border border-terminal-border rounded-lg p-3">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-medium text-terminal-text">{feed.name}</span>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      feed.status === 'active' ? 'text-green-500 bg-green-500/20' :
                      feed.status === 'error' ? 'text-red-500 bg-red-500/20' :
                      'text-gray-500 bg-gray-500/20'
                    }`}>
                      {feed.status.toUpperCase()}
                    </span>
                  </div>
                  <div className="text-terminal-muted text-sm">
                    <div>Last Update: {new Date(feed.lastUpdate).toLocaleString()}</div>
                    <div>Indicators: {feed.indicators.toLocaleString()}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Alerts Tab */}
      {viewMode === 'alerts' && (
        <div className="space-y-6">
          {/* Filters */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-4">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <Filter className="w-4 h-4 text-gray-400" />
                <select
                  value={filterSeverity}
                  onChange={(e) => setFilterSeverity(e.target.value)}
                  className="bg-terminal-bg border border-terminal-border rounded px-3 py-1 text-terminal-text"
                >
                  {severityLevels.map(level => (
                    <option key={level} value={level}>
                      {level === 'all' ? 'All Severities' : level.charAt(0).toUpperCase() + level.slice(1)}
                    </option>
                  ))}
                </select>
              </div>
              
              <div className="flex items-center space-x-2">
                <Search className="w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search alerts..."
                  className="bg-terminal-bg border border-terminal-border rounded px-3 py-1 text-terminal-text w-64"
                />
              </div>
            </div>
          </div>

          {/* Alerts List */}
          <div className="space-y-4">
            {filteredAlerts.map((alert) => (
              <div
                key={alert.id}
                className={`bg-terminal-card border border-terminal-border rounded-lg p-4 cursor-pointer transition-all ${
                  selectedAlert?.id === alert.id ? 'border-red-500 bg-red-500/5' : ''
                }`}
                onClick={() => setSelectedAlert(alert)}
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-3">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(alert.severity)}`}>
                      {alert.severity.toUpperCase()}
                    </span>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(alert.status)}`}>
                      {alert.status.replace('_', ' ').toUpperCase()}
                    </span>
                    <span className="font-medium text-terminal-text">{alert.title}</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="text-terminal-muted text-sm">Risk: {alert.riskScore}/100</span>
                    <span className="text-terminal-muted text-sm">
                      {new Date(alert.timestamp).toLocaleString()}
                    </span>
                  </div>
                </div>

                <p className="text-terminal-muted text-sm mb-3">{alert.description}</p>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm mb-3">
                  <div>
                    <span className="text-terminal-muted">Source:</span>
                    <span className="ml-2 text-terminal-text font-mono">{alert.sourceIp}</span>
                  </div>
                  <div>
                    <span className="text-terminal-muted">Destination:</span>
                    <span className="ml-2 text-terminal-text font-mono">{alert.destinationIp}</span>
                  </div>
                  <div>
                    <span className="text-terminal-muted">Protocol:</span>
                    <span className="ml-2 text-terminal-text">{alert.protocol}</span>
                  </div>
                  <div>
                    <span className="text-terminal-muted">Port:</span>
                    <span className="ml-2 text-terminal-text">{alert.port}</span>
                  </div>
                </div>

                {alert.iocMatches.length > 0 && (
                  <div className="mb-3">
                    <span className="text-terminal-muted text-sm">IOC Matches:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {alert.iocMatches.map((ioc, idx) => (
                        <span key={idx} className="px-2 py-1 bg-red-500/20 text-red-400 text-xs rounded">
                          {ioc}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {alert.gptAnalysis && (
                  <div className="mt-3 p-3 bg-terminal-bg border border-terminal-border rounded">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-terminal-text font-medium">AI Analysis</span>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(alert.gptAnalysis.urgency)}`}>
                        {alert.gptAnalysis.urgency.toUpperCase()} URGENCY
                      </span>
                    </div>
                    <p className="text-terminal-muted text-sm mb-2">{alert.gptAnalysis.summary}</p>
                    <div className="text-terminal-muted text-sm">
                      <strong>Attack Vector:</strong> {alert.gptAnalysis.attackVector}
                    </div>
                    <div className="text-terminal-muted text-sm">
                      <strong>Recommendation:</strong> {alert.gptAnalysis.recommendation}
                    </div>
                  </div>
                )}

                <div className="mt-3 flex space-x-2">
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      analyzeAlertWithGPT(alert)
                    }}
                    className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded"
                  >
                    <Brain className="w-3 h-3 inline mr-1" />
                    AI Analyze
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      updateAlertStatus(alert.id, 'investigating')
                    }}
                    className="px-3 py-1 bg-yellow-600 hover:bg-yellow-700 text-white text-sm rounded"
                  >
                    Investigate
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      updateAlertStatus(alert.id, 'resolved')
                    }}
                    className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded"
                  >
                    Resolve
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      updateAlertStatus(alert.id, 'false_positive')
                    }}
                    className="px-3 py-1 bg-gray-600 hover:bg-gray-700 text-white text-sm rounded"
                  >
                    False Positive
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* IOC Tab */}
      {viewMode === 'ioc' && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">Indicators of Compromise</h4>
          
          <div className="space-y-3">
            {iocIndicators.map((ioc) => (
              <div key={ioc.id} className="border border-terminal-border rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      ioc.type === 'ip' ? 'text-blue-500 bg-blue-500/20' :
                      ioc.type === 'domain' ? 'text-green-500 bg-green-500/20' :
                      ioc.type === 'hash' ? 'text-purple-500 bg-purple-500/20' :
                      'text-orange-500 bg-orange-500/20'
                    }`}>
                      {ioc.type.toUpperCase()}
                    </span>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getReputationColor(ioc.reputation)}`}>
                      {ioc.reputation.toUpperCase()}
                    </span>
                    <span className="font-mono text-terminal-text">{ioc.value}</span>
                  </div>
                  <div className="text-terminal-muted text-sm">
                    Confidence: {(ioc.confidence * 100).toFixed(0)}%
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                  <div>
                    <span className="text-terminal-muted">Source:</span>
                    <span className="ml-2 text-terminal-text">{ioc.source}</span>
                  </div>
                  <div>
                    <span className="text-terminal-muted">Threat Type:</span>
                    <span className="ml-2 text-terminal-text">{ioc.threatType}</span>
                  </div>
                  <div>
                    <span className="text-terminal-muted">Last Seen:</span>
                    <span className="ml-2 text-terminal-text">{new Date(ioc.lastSeen).toLocaleDateString()}</span>
                  </div>
                </div>

                <div className="mt-2">
                  <p className="text-terminal-muted text-sm">{ioc.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Correlation Tab */}
      {viewMode === 'correlation' && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">Log Correlation Analysis</h4>
          
          <div className="space-y-4">
            {correlations.map((correlation) => (
              <div key={correlation.id} className="border border-terminal-border rounded-lg p-4">
                <div className="flex items-center justify-between mb-3">
                  <span className="font-medium text-terminal-text">{correlation.pattern}</span>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(correlation.severity)}`}>
                    {correlation.severity.toUpperCase()}
                  </span>
                </div>

                <p className="text-terminal-muted text-sm mb-3">{correlation.description}</p>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm mb-3">
                  <div>
                    <span className="text-terminal-muted">Time Window:</span>
                    <span className="ml-2 text-terminal-text">{correlation.timeWindow}</span>
                  </div>
                  <div>
                    <span className="text-terminal-muted">Events:</span>
                    <span className="ml-2 text-terminal-text">{correlation.eventCount}</span>
                  </div>
                  <div>
                    <span className="text-terminal-muted">Sources:</span>
                    <span className="ml-2 text-terminal-text">{correlation.uniqueSources}</span>
                  </div>
                </div>

                <div>
                  <span className="text-terminal-muted text-sm">Recent Events:</span>
                  <div className="mt-2 space-y-1">
                    {correlation.correlatedEvents.slice(0, 3).map((event, idx) => (
                      <div key={idx} className="text-xs bg-terminal-bg border border-terminal-border rounded p-2">
                        <span className="text-terminal-muted">{new Date(event.timestamp).toLocaleString()}</span>
                        <span className="mx-2 text-terminal-text font-mono">{event.source}</span>
                        <span className="text-terminal-text">{event.event}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Intelligence Tab */}
      {viewMode === 'intel' && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <Brain className="w-5 h-5 mr-2 text-blue-500" />
            AI-Powered Threat Intelligence
          </h4>

          <div className="space-y-6">
            <div>
              <h5 className="font-medium text-terminal-text mb-3">Threat Landscape Summary</h5>
              <div className="bg-terminal-bg border border-terminal-border rounded p-4">
                <p className="text-terminal-muted text-sm leading-relaxed">
                  Current threat analysis indicates elevated APT activity targeting infrastructure services. 
                  Multiple campaigns utilizing supply chain compromises have been detected. Recommended 
                  immediate actions include enhanced monitoring of administrative accounts and implementation 
                  of additional network segmentation controls.
                </p>
              </div>
            </div>

            <div>
              <h5 className="font-medium text-terminal-text mb-3">Key Threat Indicators</h5>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-terminal-bg border border-terminal-border rounded p-3">
                  <div className="text-red-500 font-bold text-lg">High</div>
                  <div className="text-terminal-muted text-sm">Ransomware Activity</div>
                  <div className="text-terminal-text text-xs mt-1">
                    Increased targeting of backup systems
                  </div>
                </div>
                <div className="bg-terminal-bg border border-terminal-border rounded p-3">
                  <div className="text-yellow-500 font-bold text-lg">Medium</div>
                  <div className="text-terminal-muted text-sm">Phishing Campaigns</div>
                  <div className="text-terminal-text text-xs mt-1">
                    Business email compromise attempts
                  </div>
                </div>
              </div>
            </div>

            <div>
              <h5 className="font-medium text-terminal-text mb-3">Recommended Actions</h5>
              <ul className="space-y-2">
                <li className="text-terminal-muted text-sm flex items-start space-x-2">
                  <Shield className="w-3 h-3 mt-1 text-green-500" />
                  <span>Enable advanced logging for privileged account activities</span>
                </li>
                <li className="text-terminal-muted text-sm flex items-start space-x-2">
                  <Shield className="w-3 h-3 mt-1 text-green-500" />
                  <span>Implement additional MFA controls for administrative access</span>
                </li>
                <li className="text-terminal-muted text-sm flex items-start space-x-2">
                  <Shield className="w-3 h-3 mt-1 text-green-500" />
                  <span>Review and update incident response procedures</span>
                </li>
                <li className="text-terminal-muted text-sm flex items-start space-x-2">
                  <Shield className="w-3 h-3 mt-1 text-green-500" />
                  <span>Conduct targeted threat hunting for known IOCs</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Export Options */}
      {(alerts.length > 0 || iocIndicators.length > 0) && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-4">
          <div className="flex items-center justify-between">
            <span className="text-terminal-text font-medium">Export Threat Intelligence</span>
            <div className="flex space-x-2">
              <button className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>STIX/TAXII</span>
              </button>
              <button className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>IOC List</span>
              </button>
              <button className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>Threat Report</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default OssimPanel