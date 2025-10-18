import React, { useState } from 'react'
import { Search, Globe, Shield, AlertTriangle, Server, MapPin, TrendingUp, Eye } from 'lucide-react'

interface ThreatCard {
  ip: string
  port: number
  service: string
  exploitability: number
  threatCategory: string
  gptSummary: string
  country?: string
  org?: string
  banner?: string
  vulns?: string[]
}

interface ShodanResult {
  ip: string
  port: number
  service: string
  exploitabilityScore: number
  threatCategory: string
  aiAnalysis: string
  location: {
    country: string
    city: string
    coords: [number, number]
  }
  organization: string
  banner: string
  vulns: string[]
  lastSeen: string
}

interface ShodanSearchPanelProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

const ShodanSearchPanel: React.FC<ShodanSearchPanelProps> = ({ onToolExecute }) => {
  const [searchQuery, setSearchQuery] = useState<string>('')
  const [country, setCountry] = useState<string>('')
  const [organization, setOrganization] = useState<string>('')
  const [results, setResults] = useState<ShodanResult[]>([])
  const [threatCards, setThreatCards] = useState<ThreatCard[]>([])
  const [isSearching, setIsSearching] = useState(false)
  const [totalResults, setTotalResults] = useState(0)
  const [selectedResult, setSelectedResult] = useState<ShodanResult | null>(null)
  const [filterCategory, setFilterCategory] = useState<string>('all')
  const [sortBy, setSortBy] = useState<'exploitability' | 'date' | 'port'>('exploitability')

  const performShodanSearch = async () => {
    if (!searchQuery.trim()) return

    setIsSearching(true)
    try {
      const result = await onToolExecute('shodan_search', {
        query: searchQuery.trim(),
        country: country || undefined,
        org: organization || undefined
      })

      if (result.results) {
        setResults(result.results)
        setThreatCards(result.threatCards || [])
        setTotalResults(result.totalResults || 0)
      }
    } catch (error) {
      console.error('Shodan search failed:', error)
    } finally {
      setIsSearching(false)
    }
  }

  const getExploitabilityColor = (score: number) => {
    if (score >= 8) return 'text-red-500 bg-red-500/20'
    if (score >= 6) return 'text-orange-500 bg-orange-500/20'
    if (score >= 4) return 'text-yellow-500 bg-yellow-500/20'
    return 'text-green-500 bg-green-500/20'
  }

  const getCategoryIcon = (category: string) => {
    switch (category.toLowerCase()) {
      case 'database': return <Server className="w-4 h-4" />
      case 'webcam': return <Eye className="w-4 h-4" />
      case 'industrial': return <Shield className="w-4 h-4" />
      case 'network': return <Globe className="w-4 h-4" />
      default: return <Search className="w-4 h-4" />
    }
  }

  const filteredResults = results.filter(result => 
    filterCategory === 'all' || result.threatCategory.toLowerCase() === filterCategory.toLowerCase()
  ).sort((a, b) => {
    switch (sortBy) {
      case 'exploitability':
        return b.exploitabilityScore - a.exploitabilityScore
      case 'date':
        return new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime()
      case 'port':
        return a.port - b.port
      default:
        return 0
    }
  })

  const commonSearches = [
    'apache',
    'nginx',
    'mysql',
    'ssh',
    'mongodb',
    'elasticsearch',
    'rdp',
    'webcam'
  ]

  return (
    <div className="space-y-6">
      {/* Shodan Search Header */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h3 className="text-xl font-bold text-terminal-text mb-4 flex items-center">
          <Globe className="w-6 h-6 mr-3 text-green-500" />
          Shodan Internet Intelligence
          <span className="ml-3 px-3 py-1 bg-green-500 text-white text-sm rounded-full">GLOBAL SCAN</span>
        </h3>
        <p className="text-terminal-muted">
          Search for vulnerable and misconfigured internet-facing devices worldwide
        </p>
      </div>

      {/* Search Controls */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-4">
          <div className="md:col-span-2">
            <label className="block text-terminal-text font-medium mb-2">
              Search Query
            </label>
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="apache, port:22, product:mysql..."
              className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
              onKeyPress={(e) => e.key === 'Enter' && performShodanSearch()}
            />
          </div>

          <div>
            <label className="block text-terminal-text font-medium mb-2">
              Country Filter
            </label>
            <input
              type="text"
              value={country}
              onChange={(e) => setCountry(e.target.value)}
              placeholder="US, CN, RU..."
              className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
            />
          </div>

          <div>
            <label className="block text-terminal-text font-medium mb-2">
              Organization
            </label>
            <input
              type="text"
              value={organization}
              onChange={(e) => setOrganization(e.target.value)}
              placeholder="Google, Amazon..."
              className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
            />
          </div>

          <div className="flex items-end">
            <button
              onClick={performShodanSearch}
              disabled={isSearching || !searchQuery.trim()}
              className="w-full px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 text-white rounded-lg flex items-center justify-center space-x-2 transition-colors"
            >
              {isSearching ? (
                <>
                  <Search className="w-4 h-4 animate-spin" />
                  <span>Searching...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>Search</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Quick Search Buttons */}
        <div className="flex flex-wrap gap-2">
          <span className="text-terminal-muted text-sm mr-2">Quick searches:</span>
          {commonSearches.map((search) => (
            <button
              key={search}
              onClick={() => setSearchQuery(search)}
              className="px-3 py-1 bg-gray-600 hover:bg-gray-500 text-white text-sm rounded transition-colors"
            >
              {search}
            </button>
          ))}
        </div>
      </div>

      {/* Results Summary */}
      {totalResults > 0 && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <span className="text-terminal-text font-medium">
                Found {totalResults.toLocaleString()} results
              </span>
              <div className="flex space-x-2">
                <select
                  value={filterCategory}
                  onChange={(e) => setFilterCategory(e.target.value)}
                  className="bg-terminal-bg border border-terminal-border rounded px-2 py-1 text-terminal-text text-sm"
                >
                  <option value="all">All Categories</option>
                  <option value="database">Database</option>
                  <option value="webcam">Webcam</option>
                  <option value="industrial">Industrial</option>
                  <option value="network">Network</option>
                </select>
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value as any)}
                  className="bg-terminal-bg border border-terminal-border rounded px-2 py-1 text-terminal-text text-sm"
                >
                  <option value="exploitability">Exploitability</option>
                  <option value="date">Last Seen</option>
                  <option value="port">Port Number</option>
                </select>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Threat Cards Grid */}
      {filteredResults.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredResults.slice(0, 12).map((result) => (
            <div
              key={`${result.ip}-${result.port}`}
              className={`bg-terminal-card border border-terminal-border rounded-lg p-4 cursor-pointer transition-all hover:border-green-500 hover:shadow-lg ${
                selectedResult?.ip === result.ip && selectedResult?.port === result.port
                  ? 'border-green-500 bg-green-500/5'
                  : ''
              }`}
              onClick={() => setSelectedResult(result)}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center space-x-2">
                  <div className="text-green-500">
                    {getCategoryIcon(result.threatCategory)}
                  </div>
                  <span className="text-terminal-text font-medium">
                    {result.ip}:{result.port}
                  </span>
                </div>
                <span className={`px-2 py-1 rounded text-xs font-bold ${getExploitabilityColor(result.exploitabilityScore)}`}>
                  {result.exploitabilityScore}/10
                </span>
              </div>

              <div className="space-y-2 mb-3">
                <div className="flex items-center space-x-2 text-sm">
                  <Server className="w-3 h-3 text-gray-400" />
                  <span className="text-terminal-muted">{result.service}</span>
                </div>
                <div className="flex items-center space-x-2 text-sm">
                  <MapPin className="w-3 h-3 text-gray-400" />
                  <span className="text-terminal-muted">
                    {result.location.city}, {result.location.country}
                  </span>
                </div>
                <div className="text-sm text-terminal-muted">
                  <span className="font-medium">Org:</span> {result.organization}
                </div>
              </div>

              {result.vulns.length > 0 && (
                <div className="mb-3">
                  <div className="flex items-center space-x-1 mb-1">
                    <AlertTriangle className="w-3 h-3 text-red-500" />
                    <span className="text-red-400 text-xs font-medium">
                      {result.vulns.length} Known Vulnerabilities
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {result.vulns.slice(0, 2).map((vuln, index) => (
                      <span
                        key={index}
                        className="px-1 py-0.5 bg-red-500/20 text-red-400 text-xs rounded"
                      >
                        {vuln}
                      </span>
                    ))}
                    {result.vulns.length > 2 && (
                      <span className="text-red-400 text-xs">
                        +{result.vulns.length - 2} more
                      </span>
                    )}
                  </div>
                </div>
              )}

              <div className="bg-blue-500/10 border border-blue-500/20 rounded p-2">
                <p className="text-blue-300 text-xs">
                  <strong>AI Analysis:</strong> {result.aiAnalysis.slice(0, 120)}...
                </p>
              </div>

              <div className="mt-3 pt-3 border-t border-terminal-border">
                <div className="flex items-center justify-between text-xs text-terminal-muted">
                  <span>Category: {result.threatCategory}</span>
                  <span>Updated: {new Date(result.lastSeen).toLocaleDateString()}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Selected Result Details */}
      {selectedResult && (
        <div className="bg-terminal-card border border-green-500/20 rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <Globe className="w-5 h-5 mr-2 text-green-500" />
            Device Details: {selectedResult.ip}:{selectedResult.port}
          </h4>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div className="bg-terminal-bg border border-terminal-border rounded p-4">
                <h5 className="font-medium text-terminal-text mb-2">Network Information</h5>
                <div className="space-y-2 text-sm">
                  <div><span className="text-terminal-muted">IP Address:</span> <span className="text-terminal-text ml-2">{selectedResult.ip}</span></div>
                  <div><span className="text-terminal-muted">Port:</span> <span className="text-terminal-text ml-2">{selectedResult.port}</span></div>
                  <div><span className="text-terminal-muted">Service:</span> <span className="text-terminal-text ml-2">{selectedResult.service}</span></div>
                  <div><span className="text-terminal-muted">Organization:</span> <span className="text-terminal-text ml-2">{selectedResult.organization}</span></div>
                </div>
              </div>

              <div className="bg-terminal-bg border border-terminal-border rounded p-4">
                <h5 className="font-medium text-terminal-text mb-2">Geolocation</h5>
                <div className="space-y-2 text-sm">
                  <div><span className="text-terminal-muted">Country:</span> <span className="text-terminal-text ml-2">{selectedResult.location.country}</span></div>
                  <div><span className="text-terminal-muted">City:</span> <span className="text-terminal-text ml-2">{selectedResult.location.city}</span></div>
                  <div><span className="text-terminal-muted">Coordinates:</span> <span className="text-terminal-text ml-2">{selectedResult.location.coords.join(', ')}</span></div>
                </div>
              </div>
            </div>

            <div className="space-y-4">
              <div className="bg-terminal-bg border border-terminal-border rounded p-4">
                <h5 className="font-medium text-terminal-text mb-2">Risk Assessment</h5>
                <div className="space-y-3">
                  <div>
                    <div className="flex items-center justify-between text-sm mb-1">
                      <span className="text-terminal-muted">Exploitability Score</span>
                      <span className="text-terminal-text font-bold">{selectedResult.exploitabilityScore}/10</span>
                    </div>
                    <div className="w-full bg-gray-600 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${
                          selectedResult.exploitabilityScore >= 8 ? 'bg-red-500' :
                          selectedResult.exploitabilityScore >= 6 ? 'bg-orange-500' :
                          selectedResult.exploitabilityScore >= 4 ? 'bg-yellow-500' : 'bg-green-500'
                        }`}
                        style={{ width: `${selectedResult.exploitabilityScore * 10}%` }}
                      ></div>
                    </div>
                  </div>
                  <div><span className="text-terminal-muted">Threat Category:</span> <span className="text-terminal-text ml-2">{selectedResult.threatCategory}</span></div>
                  <div><span className="text-terminal-muted">Last Seen:</span> <span className="text-terminal-text ml-2">{new Date(selectedResult.lastSeen).toLocaleString()}</span></div>
                </div>
              </div>

              {selectedResult.vulns.length > 0 && (
                <div className="bg-red-500/10 border border-red-500/20 rounded p-4">
                  <h5 className="font-medium text-red-400 mb-2 flex items-center">
                    <AlertTriangle className="w-4 h-4 mr-2" />
                    Known Vulnerabilities
                  </h5>
                  <div className="space-y-1">
                    {selectedResult.vulns.map((vuln, index) => (
                      <div key={index} className="text-red-300 text-sm">• {vuln}</div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="mt-6 pt-6 border-t border-terminal-border">
            <h5 className="font-medium text-terminal-text mb-2">Service Banner</h5>
            <div className="bg-terminal-bg border border-terminal-border rounded p-3">
              <pre className="text-terminal-muted text-sm whitespace-pre-wrap">{selectedResult.banner}</pre>
            </div>
          </div>

          <div className="mt-6 pt-6 border-t border-terminal-border">
            <h5 className="font-medium text-terminal-text mb-2">AI Security Analysis</h5>
            <div className="bg-blue-500/10 border border-blue-500/20 rounded p-3">
              <p className="text-blue-300 text-sm">{selectedResult.aiAnalysis}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default ShodanSearchPanel