import React, { useState, useEffect } from 'react'
import { Users, Mail, Globe, Phone, AlertTriangle, Brain, Play, Pause, Download, Target, Shield, Eye } from 'lucide-react'

interface PhishingCampaign {
  id: string
  name: string
  type: 'email' | 'website' | 'sms' | 'social_media'
  template: string
  targetCount: number
  status: 'draft' | 'active' | 'completed' | 'paused'
  successRate: number
  createdAt: string
  ethicalLures: string[]
  gptGenerated: boolean
}

interface PhishingTemplate {
  id: string
  name: string
  type: 'email' | 'website' | 'sms'
  description: string
  effectiveness: number
  ethicalRating: 'low' | 'medium' | 'high'
  preview: string
}

interface CampaignResult {
  campaignId: string
  totalTargets: number
  opened: number
  clicked: number
  submitted: number
  reported: number
  engagementRate: number
  riskLevel: string
  insights: string[]
}

interface GPTCampaignAnalysis {
  effectiveness: number
  ethicalConcerns: string[]
  improvements: string[]
  detectionLikelihood: string
  recommendations: string[]
}

interface SetoolkitPanelProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

const SetoolkitPanel: React.FC<SetoolkitPanelProps> = ({ onToolExecute }) => {
  const [campaignType, setCampaignType] = useState<string>('email')
  const [targetList, setTargetList] = useState<string>('')
  const [selectedTemplate, setSelectedTemplate] = useState<string>('')
  const [customMessage, setCustomMessage] = useState<string>('')
  const [ethicalMode, setEthicalMode] = useState<boolean>(true)
  const [activeCampaigns, setActiveCampaigns] = useState<PhishingCampaign[]>([])
  const [templates, setTemplates] = useState<PhishingTemplate[]>([])
  const [campaignResults, setCampaignResults] = useState<CampaignResult[]>([])
  const [gptAnalysis, setGptAnalysis] = useState<GPTCampaignAnalysis | null>(null)
  const [selectedCampaign, setSelectedCampaign] = useState<PhishingCampaign | null>(null)
  const [viewMode, setViewMode] = useState<'create' | 'campaigns' | 'results' | 'analysis'>('create')

  const campaignTypes = [
    { value: 'email', label: 'Email Phishing', icon: <Mail className="w-4 h-4" />, description: 'Traditional email-based campaigns' },
    { value: 'website', label: 'Website Cloning', icon: <Globe className="w-4 h-4" />, description: 'Clone legitimate websites' },
    { value: 'sms', label: 'SMS Phishing', icon: <Phone className="w-4 h-4" />, description: 'Text message campaigns' },
    { value: 'social_media', label: 'Social Media', icon: <Users className="w-4 h-4" />, description: 'Social platform attacks' }
  ]

  const ethicalTemplates: PhishingTemplate[] = [
    {
      id: 'security_awareness',
      name: 'Security Awareness Training',
      type: 'email',
      description: 'Educational phishing simulation for training',
      effectiveness: 85,
      ethicalRating: 'high',
      preview: 'Your IT department is conducting security awareness training...'
    },
    {
      id: 'password_update',
      name: 'Password Update Notice',
      type: 'email',
      description: 'Simulated password update requirement',
      effectiveness: 70,
      ethicalRating: 'medium',
      preview: 'Your password will expire in 3 days...'
    },
    {
      id: 'policy_update',
      name: 'Policy Update',
      type: 'email',
      description: 'Company policy update notification',
      effectiveness: 60,
      ethicalRating: 'high',
      preview: 'Please review the updated company policies...'
    },
    {
      id: 'training_portal',
      name: 'Training Portal',
      type: 'website',
      description: 'Simulated training login portal',
      effectiveness: 75,
      ethicalRating: 'high',
      preview: 'Employee Training Portal - Please log in to continue...'
    }
  ]

  const createCampaign = async () => {
    if (!targetList.trim() || !selectedTemplate) return

    try {
      const result = await onToolExecute('setoolkit_campaign', {
        type: campaignType,
        template: selectedTemplate,
        targets: targetList.split('\n').filter(t => t.trim()),
        customMessage: customMessage || undefined,
        ethicalMode
      })

      if (result.campaignId) {
        const newCampaign: PhishingCampaign = {
          id: result.campaignId,
          name: result.campaignName || `Campaign ${Date.now()}`,
          type: campaignType as any,
          template: selectedTemplate,
          targetCount: result.targetCount || 0,
          status: 'active',
          successRate: 0,
          createdAt: new Date().toISOString(),
          ethicalLures: result.ethicalLures || [],
          gptGenerated: result.gptGenerated || false
        }
        
        setActiveCampaigns(prev => [...prev, newCampaign])
        setGptAnalysis(result.gptCampaignAnalysis)
        setViewMode('campaigns')
      }
    } catch (error) {
      console.error('Campaign creation failed:', error)
    }
  }

  const generateEthicalLures = async () => {
    try {
      const result = await onToolExecute('generate_ethical_lures', {
        targetType: campaignType,
        industry: 'general',
        ethicalMode: true
      })

      if (result.lures) {
        setCustomMessage(result.lures[0] || '')
      }
    } catch (error) {
      console.error('Lure generation failed:', error)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'text-green-500 bg-green-500/20'
      case 'completed': return 'text-blue-500 bg-blue-500/20'
      case 'paused': return 'text-yellow-500 bg-yellow-500/20'
      case 'draft': return 'text-gray-500 bg-gray-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  const getEthicalRatingColor = (rating: string) => {
    switch (rating) {
      case 'high': return 'text-green-500 bg-green-500/20'
      case 'medium': return 'text-yellow-500 bg-yellow-500/20'
      case 'low': return 'text-red-500 bg-red-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  useEffect(() => {
    setTemplates(ethicalTemplates)
  }, [])

  return (
    <div className="space-y-6">
      {/* Setoolkit Header */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h3 className="text-xl font-bold text-terminal-text mb-4 flex items-center">
          <Users className="w-6 h-6 mr-3 text-purple-500" />
          Social Engineer Toolkit (SET)
          <span className="ml-3 px-3 py-1 bg-purple-500 text-white text-sm rounded-full">ETHICAL MODE</span>
        </h3>
        <p className="text-terminal-muted">
          Ethical social engineering campaigns with AI-generated content for security awareness training
        </p>
        
        {/* Ethical Warning */}
        <div className="mt-4 p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
          <div className="flex items-start space-x-3">
            <AlertTriangle className="w-5 h-5 text-yellow-500 mt-0.5" />
            <div>
              <h4 className="font-medium text-yellow-300">Ethical Usage Only</h4>
              <p className="text-yellow-200 text-sm mt-1">
                This tool is designed for authorized security testing and employee awareness training only. 
                Always ensure you have explicit permission and legal authorization before conducting any campaigns.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex space-x-2">
        <button
          onClick={() => setViewMode('create')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'create' 
              ? 'bg-purple-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Target className="w-4 h-4" />
          <span>Create Campaign</span>
        </button>
        <button
          onClick={() => setViewMode('campaigns')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'campaigns' 
              ? 'bg-purple-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Users className="w-4 h-4" />
          <span>Campaigns ({activeCampaigns.length})</span>
        </button>
        <button
          onClick={() => setViewMode('results')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'results' 
              ? 'bg-purple-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Eye className="w-4 h-4" />
          <span>Results</span>
        </button>
        <button
          onClick={() => setViewMode('analysis')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'analysis' 
              ? 'bg-purple-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Brain className="w-4 h-4" />
          <span>AI Analysis</span>
        </button>
      </div>

      {/* Create Campaign Tab */}
      {viewMode === 'create' && (
        <div className="space-y-6">
          {/* Campaign Type Selection */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">Campaign Type</h4>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {campaignTypes.map((type) => (
                <div
                  key={type.value}
                  className={`border rounded-lg p-4 cursor-pointer transition-all ${
                    campaignType === type.value
                      ? 'border-purple-500 bg-purple-500/10'
                      : 'border-terminal-border hover:border-purple-500/50'
                  }`}
                  onClick={() => setCampaignType(type.value)}
                >
                  <div className="flex items-center space-x-3 mb-2">
                    <div className="text-purple-400">{type.icon}</div>
                    <span className="font-medium text-terminal-text">{type.label}</span>
                  </div>
                  <p className="text-terminal-muted text-sm">{type.description}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Template Selection */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">Ethical Templates</h4>
            
            <div className="space-y-3">
              {templates.filter(t => t.type === campaignType || campaignType === 'social_media').map((template) => (
                <div
                  key={template.id}
                  className={`border rounded-lg p-4 cursor-pointer transition-all ${
                    selectedTemplate === template.id
                      ? 'border-purple-500 bg-purple-500/10'
                      : 'border-terminal-border hover:border-purple-500/50'
                  }`}
                  onClick={() => setSelectedTemplate(template.id)}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-medium text-terminal-text">{template.name}</span>
                    <div className="flex items-center space-x-2">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getEthicalRatingColor(template.ethicalRating)}`}>
                        {template.ethicalRating.toUpperCase()} ETHICS
                      </span>
                      <span className="text-terminal-muted text-sm">{template.effectiveness}% effective</span>
                    </div>
                  </div>
                  <p className="text-terminal-muted text-sm mb-2">{template.description}</p>
                  <div className="bg-terminal-bg border border-terminal-border rounded p-2">
                    <p className="text-terminal-text text-sm italic">"{template.preview}"</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Target Configuration */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">Target Configuration</h4>
            
            <div className="space-y-4">
              <div>
                <label className="block text-terminal-text font-medium mb-2">
                  Target List (one per line)
                </label>
                <textarea
                  value={targetList}
                  onChange={(e) => setTargetList(e.target.value)}
                  placeholder="user1@company.com&#10;user2@company.com&#10;+1234567890"
                  rows={6}
                  className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text font-mono"
                />
              </div>

              <div>
                <label className="block text-terminal-text font-medium mb-2">
                  Custom Message (Optional)
                </label>
                <div className="flex space-x-2">
                  <textarea
                    value={customMessage}
                    onChange={(e) => setCustomMessage(e.target.value)}
                    placeholder="Enter custom message or use AI generation..."
                    rows={4}
                    className="flex-1 bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
                  />
                  <button
                    onClick={generateEthicalLures}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg flex items-center space-x-2 transition-colors"
                  >
                    <Brain className="w-4 h-4" />
                    <span>Generate</span>
                  </button>
                </div>
              </div>

              <div className="flex items-center space-x-3">
                <input
                  type="checkbox"
                  id="ethical-mode"
                  checked={ethicalMode}
                  onChange={(e) => setEthicalMode(e.target.checked)}
                  className="text-purple-500"
                />
                <label htmlFor="ethical-mode" className="text-terminal-text font-medium flex items-center">
                  <Shield className="w-4 h-4 mr-2 text-green-500" />
                  Ethical Mode (Training & Education Only)
                </label>
              </div>
            </div>
          </div>

          <div className="flex justify-center">
            <button
              onClick={createCampaign}
              disabled={!targetList.trim() || !selectedTemplate || !ethicalMode}
              className="px-6 py-3 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 text-white rounded-lg flex items-center space-x-3 transition-colors transform hover:scale-105"
            >
              <Play className="w-5 h-5" />
              <span>Launch Ethical Campaign</span>
            </button>
          </div>
        </div>
      )}

      {/* Campaigns Tab */}
      {viewMode === 'campaigns' && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">Active Campaigns</h4>
          
          {activeCampaigns.length === 0 ? (
            <div className="text-center py-8">
              <Users className="w-12 h-12 text-gray-500 mx-auto mb-4" />
              <p className="text-terminal-muted">No active campaigns. Create your first ethical phishing campaign.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {activeCampaigns.map((campaign) => (
                <div
                  key={campaign.id}
                  className={`border rounded-lg p-4 cursor-pointer transition-all ${
                    selectedCampaign?.id === campaign.id ? 'border-purple-500 bg-purple-500/5' : 'border-terminal-border'
                  }`}
                  onClick={() => setSelectedCampaign(campaign)}
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(campaign.status)}`}>
                        {campaign.status.toUpperCase()}
                      </span>
                      <span className="font-medium text-terminal-text">{campaign.name}</span>
                      {campaign.gptGenerated && (
                        <span className="px-2 py-1 bg-blue-500 text-white text-xs rounded">AI-GENERATED</span>
                      )}
                    </div>
                    <span className="text-terminal-muted text-sm">
                      {campaign.targetCount} targets
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm">
                    <div>
                      <span className="text-terminal-muted">Type:</span>
                      <span className="ml-2 text-terminal-text capitalize">{campaign.type}</span>
                    </div>
                    <div>
                      <span className="text-terminal-muted">Success Rate:</span>
                      <span className="ml-2 text-terminal-text">{campaign.successRate}%</span>
                    </div>
                    <div>
                      <span className="text-terminal-muted">Created:</span>
                      <span className="ml-2 text-terminal-text">
                        {new Date(campaign.createdAt).toLocaleDateString()}
                      </span>
                    </div>
                    <div>
                      <span className="text-terminal-muted">Template:</span>
                      <span className="ml-2 text-terminal-text">{campaign.template}</span>
                    </div>
                  </div>

                  {campaign.ethicalLures.length > 0 && (
                    <div className="mt-3">
                      <span className="text-terminal-muted text-sm">AI-Generated Lures:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {campaign.ethicalLures.slice(0, 3).map((lure, idx) => (
                          <span key={idx} className="px-2 py-1 bg-blue-500/20 text-blue-400 text-xs rounded">
                            {lure.slice(0, 30)}...
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Results Tab */}
      {viewMode === 'results' && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">Campaign Results</h4>
          
          {campaignResults.length === 0 ? (
            <div className="text-center py-8">
              <Eye className="w-12 h-12 text-gray-500 mx-auto mb-4" />
              <p className="text-terminal-muted">No campaign results yet. Results will appear here as campaigns complete.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {campaignResults.map((result) => (
                <div key={result.campaignId} className="border border-terminal-border rounded-lg p-4">
                  <h5 className="font-medium text-terminal-text mb-3">Campaign Results</h5>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-4">
                    <div className="bg-terminal-bg border border-terminal-border rounded p-3 text-center">
                      <div className="text-2xl font-bold text-terminal-text">{result.opened}</div>
                      <div className="text-terminal-muted text-sm">Opened</div>
                    </div>
                    <div className="bg-terminal-bg border border-terminal-border rounded p-3 text-center">
                      <div className="text-2xl font-bold text-yellow-500">{result.clicked}</div>
                      <div className="text-terminal-muted text-sm">Clicked</div>
                    </div>
                    <div className="bg-terminal-bg border border-terminal-border rounded p-3 text-center">
                      <div className="text-2xl font-bold text-red-500">{result.submitted}</div>
                      <div className="text-terminal-muted text-sm">Submitted Info</div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-terminal-muted">Engagement Rate:</span>
                      <span className="text-terminal-text">{result.engagementRate}%</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-terminal-muted">Risk Level:</span>
                      <span className={`font-medium ${
                        result.riskLevel === 'high' ? 'text-red-500' :
                        result.riskLevel === 'medium' ? 'text-yellow-500' : 'text-green-500'
                      }`}>
                        {result.riskLevel.toUpperCase()}
                      </span>
                    </div>
                  </div>

                  <div className="mt-4">
                    <h6 className="font-medium text-terminal-text mb-2">Key Insights:</h6>
                    <ul className="space-y-1">
                      {result.insights.map((insight, idx) => (
                        <li key={idx} className="text-terminal-muted text-sm">• {insight}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* AI Analysis Tab */}
      {viewMode === 'analysis' && gptAnalysis && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <Brain className="w-5 h-5 mr-2 text-blue-500" />
            GPT Campaign Analysis
          </h4>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div className="bg-terminal-bg border border-terminal-border rounded p-4">
              <h5 className="font-medium text-terminal-text mb-2">Effectiveness Score</h5>
              <div className="flex items-center space-x-3">
                <div className="text-3xl font-bold text-terminal-text">{gptAnalysis.effectiveness}%</div>
                <div className="w-full bg-gray-600 rounded-full h-3">
                  <div
                    className={`h-3 rounded-full ${
                      gptAnalysis.effectiveness >= 70 ? 'bg-green-500' :
                      gptAnalysis.effectiveness >= 50 ? 'bg-yellow-500' : 'bg-red-500'
                    }`}
                    style={{ width: `${gptAnalysis.effectiveness}%` }}
                  ></div>
                </div>
              </div>
            </div>

            <div className="bg-terminal-bg border border-terminal-border rounded p-4">
              <h5 className="font-medium text-terminal-text mb-2">Detection Likelihood</h5>
              <div className="text-xl font-bold text-terminal-text">{gptAnalysis.detectionLikelihood}</div>
              <div className="text-terminal-muted text-sm">Probability of detection</div>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <h5 className="font-medium text-terminal-text mb-2">Ethical Concerns</h5>
              <ul className="space-y-1">
                {gptAnalysis.ethicalConcerns.map((concern, index) => (
                  <li key={index} className="text-yellow-400 text-sm flex items-start space-x-2">
                    <AlertTriangle className="w-3 h-3 mt-1 flex-shrink-0" />
                    <span>{concern}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <h5 className="font-medium text-terminal-text mb-2">Improvement Suggestions</h5>
              <ul className="space-y-1">
                {gptAnalysis.improvements.map((improvement, index) => (
                  <li key={index} className="text-terminal-muted text-sm flex items-start space-x-2">
                    <Brain className="w-3 h-3 mt-1 flex-shrink-0 text-blue-500" />
                    <span>{improvement}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <h5 className="font-medium text-terminal-text mb-2">Recommendations</h5>
              <ul className="space-y-1">
                {gptAnalysis.recommendations.map((rec, index) => (
                  <li key={index} className="text-green-400 text-sm flex items-start space-x-2">
                    <Shield className="w-3 h-3 mt-1 flex-shrink-0" />
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Export Options */}
      {(activeCampaigns.length > 0 || campaignResults.length > 0) && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-4">
          <div className="flex items-center justify-between">
            <span className="text-terminal-text font-medium">Export Campaign Data</span>
            <div className="flex space-x-2">
              <button className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>CSV</span>
              </button>
              <button className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>Training Report</span>
              </button>
              <button className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>Awareness Metrics</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default SetoolkitPanel