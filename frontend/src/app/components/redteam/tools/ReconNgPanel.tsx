import React, { useState, useEffect } from 'react'
import { Terminal, Search, Database, Users, Mail, Globe, Phone, Building, Eye, Brain, Download } from 'lucide-react'

interface ReconModule {
  name: string
  category: string
  description: string
  required_keys?: string[]
  status: 'available' | 'requires_api' | 'premium'
}

interface ReconResult {
  module: string
  type: 'whois' | 'breach' | 'email' | 'social' | 'domain' | 'phone'
  data: any
  timestamp: string
  source: string
}

interface WorkspaceData {
  domains: string[]
  hosts: string[]
  contacts: string[]
  credentials: string[]
  companies: string[]
  netblocks: string[]
}

interface ReconNgPanelProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

const ReconNgPanel: React.FC<ReconNgPanelProps> = ({ onToolExecute }) => {
  const [target, setTarget] = useState<string>('')
  const [workspace, setWorkspace] = useState<string>('default')
  const [selectedModules, setSelectedModules] = useState<string[]>([])
  const [isRunning, setIsRunning] = useState(false)
  const [results, setResults] = useState<ReconResult[]>([])
  const [workspaceData, setWorkspaceData] = useState<WorkspaceData | null>(null)
  const [gptAnalysis, setGptAnalysis] = useState<any>(null)
  const [activeTab, setActiveTab] = useState<'modules' | 'results' | 'workspace'>('modules')

  const reconModules: ReconModule[] = [
    // WHOIS and Domain modules
    { name: 'whois_pocs', category: 'recon/domains-hosts', description: 'Extract POC data from WHOIS records', status: 'available' },
    { name: 'hackertarget', category: 'recon/domains-hosts', description: 'Subdomain enumeration via HackerTarget', status: 'available' },
    { name: 'netcraft', category: 'recon/domains-hosts', description: 'Domain enumeration via Netcraft', status: 'available' },
    { name: 'threatcrowd', category: 'recon/domains-hosts', description: 'Domain enumeration via ThreatCrowd', status: 'available' },
    
    // Email modules
    { name: 'email_validator', category: 'recon/contacts-emails', description: 'Validate email addresses', status: 'available' },
    { name: 'hibp_breach', category: 'recon/contacts-emails', description: 'Check emails against HaveIBeenPwned', required_keys: ['hibp_api'], status: 'requires_api' },
    { name: 'hunter_io', category: 'recon/contacts-emails', description: 'Email discovery via Hunter.io', required_keys: ['hunter_api'], status: 'requires_api' },
    { name: 'clearbit', category: 'recon/contacts-emails', description: 'Email enrichment via Clearbit', required_keys: ['clearbit_api'], status: 'requires_api' },
    
    // Social media modules
    { name: 'twitter_mentions', category: 'recon/contacts-social', description: 'Twitter mentions and profiles', required_keys: ['twitter_api'], status: 'requires_api' },
    { name: 'linkedin_employees', category: 'recon/contacts-social', description: 'LinkedIn employee enumeration', status: 'premium' },
    { name: 'facebook_profiles', category: 'recon/contacts-social', description: 'Facebook profile enumeration', status: 'available' },
    
    // Company modules
    { name: 'whoxy_whois', category: 'recon/companies', description: 'Company WHOIS data via Whoxy', required_keys: ['whoxy_api'], status: 'requires_api' },
    { name: 'crunchbase', category: 'recon/companies', description: 'Company data via Crunchbase', required_keys: ['crunchbase_api'], status: 'requires_api' },
    
    // Credential modules
    { name: 'pwnedlist', category: 'recon/credentials', description: 'Check credentials in breach databases', status: 'available' },
    { name: 'dehashed', category: 'recon/credentials', description: 'Credential search via DeHashed', required_keys: ['dehashed_api'], status: 'requires_api' }
  ]

  const moduleCategories = [...new Set(reconModules.map(m => m.category))]

  const startRecon = async () => {
    if (!target.trim() || selectedModules.length === 0) return

    setIsRunning(true)
    try {
      const result = await onToolExecute('recon_ng', {
        target: target.trim(),
        modules: selectedModules,
        workspace
      })

      if (result.whoisData || result.breachData || result.emailHarvests) {
        const newResults: ReconResult[] = []
        
        if (result.whoisData) {
          newResults.push({
            module: 'whois',
            type: 'whois',
            data: result.whoisData,
            timestamp: new Date().toISOString(),
            source: 'whois_pocs'
          })
        }

        if (result.breachData) {
          newResults.push({
            module: 'hibp_breach',
            type: 'breach',
            data: result.breachData,
            timestamp: new Date().toISOString(),
            source: 'haveibeenpwned'
          })
        }

        if (result.emailHarvests) {
          newResults.push({
            module: 'email_harvest',
            type: 'email',
            data: result.emailHarvests,
            timestamp: new Date().toISOString(),
            source: 'hunter_io'
          })
        }

        if (result.socialFootprint) {
          newResults.push({
            module: 'social_media',
            type: 'social',
            data: result.socialFootprint,
            timestamp: new Date().toISOString(),
            source: 'twitter_linkedin'
          })
        }

        setResults(prev => [...prev, ...newResults])
        setWorkspaceData({
          domains: result.correlatedFindings?.domains || [],
          hosts: result.correlatedFindings?.hosts || [],
          contacts: result.correlatedFindings?.contacts || [],
          credentials: result.correlatedFindings?.credentials || [],
          companies: result.correlatedFindings?.companies || [],
          netblocks: result.correlatedFindings?.netblocks || []
        })
        setGptAnalysis(result.gptAnalysis)
        setActiveTab('results')
      }
    } catch (error) {
      console.error('Recon-ng scan failed:', error)
    } finally {
      setIsRunning(false)
    }
  }

  const toggleModule = (moduleName: string) => {
    setSelectedModules(prev => 
      prev.includes(moduleName)
        ? prev.filter(m => m !== moduleName)
        : [...prev, moduleName]
    )
  }

  const getModuleStatusColor = (status: string) => {
    switch (status) {
      case 'available': return 'text-green-500 bg-green-500/20'
      case 'requires_api': return 'text-yellow-500 bg-yellow-500/20'
      case 'premium': return 'text-blue-500 bg-blue-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  const getResultIcon = (type: string) => {
    switch (type) {
      case 'whois': return <Database className="w-4 h-4" />
      case 'breach': return <Eye className="w-4 h-4" />
      case 'email': return <Mail className="w-4 h-4" />
      case 'social': return <Users className="w-4 h-4" />
      case 'domain': return <Globe className="w-4 h-4" />
      case 'phone': return <Phone className="w-4 h-4" />
      default: return <Search className="w-4 h-4" />
    }
  }

  return (
    <div className="space-y-6">
      {/* Recon-ng Header */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h3 className="text-xl font-bold text-terminal-text mb-4 flex items-center">
          <Terminal className="w-6 h-6 mr-3 text-green-500" />
          Recon-ng Framework
          <span className="ml-3 px-3 py-1 bg-green-500 text-white text-sm rounded-full">OSINT ENGINE</span>
        </h3>
        <p className="text-terminal-muted">
          Advanced reconnaissance framework with WHOIS, breach lookups, email harvesting, and social footprinting
        </p>
      </div>

      {/* Configuration Panel */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h4 className="text-lg font-semibold text-terminal-text mb-4">Reconnaissance Configuration</h4>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div>
            <label className="block text-terminal-text font-medium mb-2">
              Target Domain/Company
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="example.com, @company"
              className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
            />
          </div>

          <div>
            <label className="block text-terminal-text font-medium mb-2">
              Workspace
            </label>
            <input
              type="text"
              value={workspace}
              onChange={(e) => setWorkspace(e.target.value)}
              placeholder="default, project_name"
              className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
            />
          </div>

          <div className="flex items-end">
            <button
              onClick={startRecon}
              disabled={isRunning || !target.trim() || selectedModules.length === 0}
              className="w-full px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 text-white rounded-lg flex items-center justify-center space-x-2 transition-colors"
            >
              {isRunning ? (
                <>
                  <Search className="w-4 h-4 animate-spin" />
                  <span>Running...</span>
                </>
              ) : (
                <>
                  <Terminal className="w-4 h-4" />
                  <span>Execute Recon</span>
                </>
              )}
            </button>
          </div>
        </div>

        <div className="text-sm text-terminal-muted">
          Selected modules: {selectedModules.length} | Target: {target || 'None'} | Workspace: {workspace}
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex space-x-2">
        <button
          onClick={() => setActiveTab('modules')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            activeTab === 'modules' 
              ? 'bg-green-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Database className="w-4 h-4" />
          <span>Modules</span>
        </button>
        <button
          onClick={() => setActiveTab('results')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            activeTab === 'results' 
              ? 'bg-green-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Search className="w-4 h-4" />
          <span>Results ({results.length})</span>
        </button>
        <button
          onClick={() => setActiveTab('workspace')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            activeTab === 'workspace' 
              ? 'bg-green-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Building className="w-4 h-4" />
          <span>Workspace</span>
        </button>
      </div>

      {/* Modules Tab */}
      {activeTab === 'modules' && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">Available Modules</h4>
          
          <div className="space-y-4">
            {moduleCategories.map((category) => (
              <div key={category}>
                <h5 className="font-medium text-terminal-text mb-3 capitalize">
                  {category.replace('recon/', '').replace('-', ' & ')}
                </h5>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {reconModules.filter(m => m.category === category).map((module) => (
                    <div
                      key={module.name}
                      className={`border rounded-lg p-3 cursor-pointer transition-all ${
                        selectedModules.includes(module.name)
                          ? 'border-green-500 bg-green-500/10'
                          : 'border-terminal-border hover:border-green-500/50'
                      }`}
                      onClick={() => toggleModule(module.name)}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-2">
                          <input
                            type="checkbox"
                            checked={selectedModules.includes(module.name)}
                            onChange={() => toggleModule(module.name)}
                            className="text-green-500"
                          />
                          <span className="font-medium text-terminal-text">{module.name}</span>
                        </div>
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getModuleStatusColor(module.status)}`}>
                          {module.status.replace('_', ' ').toUpperCase()}
                        </span>
                      </div>
                      <p className="text-terminal-muted text-sm">{module.description}</p>
                      {module.required_keys && (
                        <div className="mt-2">
                          <span className="text-yellow-400 text-xs">Requires: {module.required_keys.join(', ')}</span>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          <div className="mt-6 p-4 bg-blue-500/10 border border-blue-500/20 rounded">
            <h5 className="font-medium text-blue-300 mb-2">Module Selection Tips</h5>
            <ul className="text-blue-200 text-sm space-y-1">
              <li>• Start with free modules (green status) for basic reconnaissance</li>
              <li>• API modules require registration but provide richer data</li>
              <li>• Premium modules offer advanced corporate intelligence</li>
              <li>• Combine multiple modules for comprehensive coverage</li>
            </ul>
          </div>
        </div>
      )}

      {/* Results Tab */}
      {activeTab === 'results' && (
        <div className="space-y-6">
          {/* GPT Analysis */}
          {gptAnalysis && (
            <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
              <h4 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
                <Brain className="w-5 h-5 mr-2 text-blue-500" />
                AI Reconnaissance Analysis
              </h4>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h5 className="font-medium text-terminal-text mb-2">Key Correlations</h5>
                  <ul className="space-y-1">
                    {(gptAnalysis.correlations || []).slice(0, 5).map((correlation: string, index: number) => (
                      <li key={index} className="text-terminal-muted text-sm">• {correlation}</li>
                    ))}
                  </ul>
                </div>

                <div>
                  <h5 className="font-medium text-terminal-text mb-2">Risk Assessment</h5>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-terminal-muted">Overall Risk Level:</span>
                      <span className={`font-bold ${
                        gptAnalysis.riskLevel === 'high' ? 'text-red-500' :
                        gptAnalysis.riskLevel === 'medium' ? 'text-yellow-500' : 'text-green-500'
                      }`}>
                        {gptAnalysis.riskLevel?.toUpperCase() || 'LOW'}
                      </span>
                    </div>
                    <div className="w-full bg-gray-600 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${
                          gptAnalysis.riskLevel === 'high' ? 'bg-red-500' :
                          gptAnalysis.riskLevel === 'medium' ? 'bg-yellow-500' : 'bg-green-500'
                        }`}
                        style={{ width: `${gptAnalysis.riskScore || 30}%` }}
                      ></div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Results List */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">Reconnaissance Results</h4>
            
            {results.length === 0 ? (
              <div className="text-center py-8">
                <Search className="w-12 h-12 text-gray-500 mx-auto mb-4" />
                <p className="text-terminal-muted">No results yet. Execute reconnaissance modules to see data here.</p>
              </div>
            ) : (
              <div className="space-y-4">
                {results.map((result, index) => (
                  <div key={index} className="border border-terminal-border rounded-lg p-4">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center space-x-3">
                        <div className="text-green-500">
                          {getResultIcon(result.type)}
                        </div>
                        <div>
                          <span className="font-medium text-terminal-text capitalize">{result.type} Data</span>
                          <span className="text-terminal-muted text-sm ml-2">from {result.source}</span>
                        </div>
                      </div>
                      <span className="text-terminal-muted text-xs">
                        {new Date(result.timestamp).toLocaleString()}
                      </span>
                    </div>

                    <div className="bg-terminal-bg border border-terminal-border rounded p-3">
                      <pre className="text-terminal-text text-sm whitespace-pre-wrap overflow-x-auto">
                        {typeof result.data === 'object' 
                          ? JSON.stringify(result.data, null, 2)
                          : result.data
                        }
                      </pre>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Workspace Tab */}
      {activeTab === 'workspace' && workspaceData && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">Workspace: {workspace}</h4>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <div className="bg-terminal-bg border border-terminal-border rounded p-4">
              <h5 className="font-medium text-terminal-text mb-3 flex items-center">
                <Globe className="w-4 h-4 mr-2" />
                Domains ({workspaceData.domains.length})
              </h5>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {workspaceData.domains.map((domain, index) => (
                  <div key={index} className="text-terminal-muted text-sm font-mono">{domain}</div>
                ))}
              </div>
            </div>

            <div className="bg-terminal-bg border border-terminal-border rounded p-4">
              <h5 className="font-medium text-terminal-text mb-3 flex items-center">
                <Database className="w-4 h-4 mr-2" />
                Hosts ({workspaceData.hosts.length})
              </h5>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {workspaceData.hosts.map((host, index) => (
                  <div key={index} className="text-terminal-muted text-sm font-mono">{host}</div>
                ))}
              </div>
            </div>

            <div className="bg-terminal-bg border border-terminal-border rounded p-4">
              <h5 className="font-medium text-terminal-text mb-3 flex items-center">
                <Mail className="w-4 h-4 mr-2" />
                Contacts ({workspaceData.contacts.length})
              </h5>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {workspaceData.contacts.map((contact, index) => (
                  <div key={index} className="text-terminal-muted text-sm">{contact}</div>
                ))}
              </div>
            </div>

            <div className="bg-terminal-bg border border-terminal-border rounded p-4">
              <h5 className="font-medium text-terminal-text mb-3 flex items-center">
                <Eye className="w-4 h-4 mr-2" />
                Credentials ({workspaceData.credentials.length})
              </h5>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {workspaceData.credentials.map((cred, index) => (
                  <div key={index} className="text-red-400 text-sm font-mono">{cred}</div>
                ))}
              </div>
            </div>

            <div className="bg-terminal-bg border border-terminal-border rounded p-4">
              <h5 className="font-medium text-terminal-text mb-3 flex items-center">
                <Building className="w-4 h-4 mr-2" />
                Companies ({workspaceData.companies.length})
              </h5>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {workspaceData.companies.map((company, index) => (
                  <div key={index} className="text-terminal-muted text-sm">{company}</div>
                ))}
              </div>
            </div>

            <div className="bg-terminal-bg border border-terminal-border rounded p-4">
              <h5 className="font-medium text-terminal-text mb-3 flex items-center">
                <Globe className="w-4 h-4 mr-2" />
                Netblocks ({workspaceData.netblocks.length})
              </h5>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {workspaceData.netblocks.map((netblock, index) => (
                  <div key={index} className="text-terminal-muted text-sm font-mono">{netblock}</div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Export Options */}
      {(results.length > 0 || workspaceData) && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-4">
          <div className="flex items-center justify-between">
            <span className="text-terminal-text font-medium">Export Data</span>
            <div className="flex space-x-2">
              <button className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>JSON</span>
              </button>
              <button className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>CSV</span>
              </button>
              <button className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>Report</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default ReconNgPanel