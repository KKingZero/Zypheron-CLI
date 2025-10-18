import React, { useState, useEffect } from 'react'
import { Card } from './ui/card'
import { Button } from './ui/button'
import { Input } from './ui/input'
import useDebounce from '../hooks/useDebounce'

interface KnowledgeStats {
  tools: number
  techniques: number
  vulnerabilities: number
  bestPractices: number
  categories: number
  totalEntries: number
}

interface Tool {
  name: string
  category: string
  description: string
  usage: string
  examples: string[]
  installation: string
  platforms: string[]
  alternatives: string[]
}

interface Technique {
  name: string
  category: string
  description: string
  steps: string[]
  tools: string[]
  mitigations: string[]
  references: string[]
}

interface KnowledgeBaseProps {
  className?: string
}

export const KnowledgeBase: React.FC<KnowledgeBaseProps> = ({ className = '' }) => {
  const [stats, setStats] = useState<KnowledgeStats | null>(null)
  const [categories, setCategories] = useState<string[]>([])
  const [tools, setTools] = useState<Tool[]>([])
  const [techniques, setTechniques] = useState<Technique[]>([])
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('')
  const [activeTab, setActiveTab] = useState<'overview' | 'tools' | 'techniques' | 'search'>('overview')
  const [loading, setLoading] = useState(false)
  
  // Debounce search query for better performance
  const debouncedSearchQuery = useDebounce(searchQuery, 500)

  // Fetch knowledge base overview
  const fetchOverview = async () => {
    try {
      setLoading(true)
      const response = await fetch(`${import.meta.env.VITE_API_URL || 'http://localhost:3001'}/api/chat/knowledge`)
      const data = await response.json()
      
      if (data.success) {
        setStats(data.data.stats)
        setCategories(data.data.categories)
        setTools(data.data.recentTools || [])
        setTechniques(data.data.recentTechniques || [])
      }
    } catch (error) {
      console.error('Failed to fetch knowledge base overview:', error)
    } finally {
      setLoading(false)
    }
  }

  // Fetch all tools
  const fetchTools = async () => {
    try {
      setLoading(true)
      const response = await fetch(`${import.meta.env.VITE_API_URL || 'http://localhost:3001'}/api/chat/knowledge?type=tools`)
      const data = await response.json()
      
      if (data.success) {
        setTools(data.data.tools || [])
      }
    } catch (error) {
      console.error('Failed to fetch tools:', error)
    } finally {
      setLoading(false)
    }
  }

  // Fetch all techniques
  const fetchTechniques = async () => {
    try {
      setLoading(true)
      const response = await fetch(`${import.meta.env.VITE_API_URL || 'http://localhost:3001'}/api/chat/knowledge?type=techniques`)
      const data = await response.json()
      
      if (data.success) {
        setTechniques(data.data.techniques || [])
      }
    } catch (error) {
      console.error('Failed to fetch techniques:', error)
    } finally {
      setLoading(false)
    }
  }

  // Search knowledge base
  const searchKnowledge = async () => {
    if (!searchQuery.trim()) return
    
    try {
      setLoading(true)
      const response = await fetch(`${import.meta.env.VITE_API_URL || 'http://localhost:3001'}/api/chat/knowledge?search=${encodeURIComponent(searchQuery)}`)
      const data = await response.json()
      
      if (data.success) {
        setTools(data.data.tools || [])
        setTechniques(data.data.techniques || [])
      }
    } catch (error) {
      console.error('Failed to search knowledge base:', error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchOverview()
  }, [])

  useEffect(() => {
    if (activeTab === 'tools') {
      fetchTools()
    } else if (activeTab === 'techniques') {
      fetchTechniques()
    }
  }, [activeTab])
  
  // Auto-search when debounced query changes
  useEffect(() => {
    if (debouncedSearchQuery && activeTab === 'search') {
      searchKnowledge()
    }
  }, [debouncedSearchQuery])

  const handleTabChange = (tab: 'overview' | 'tools' | 'techniques' | 'search') => {
    setActiveTab(tab)
    if (tab === 'overview') {
      fetchOverview()
    }
  }

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setActiveTab('search')
    searchKnowledge()
  }

  return (
    <div className={`knowledge-base ${className}`}>
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-white mb-2">🧠 Zypheron Knowledge Base</h2>
        <p className="text-gray-400">Comprehensive cybersecurity tools, techniques, and vulnerability database</p>
      </div>

      {/* Navigation Tabs */}
      <div className="flex space-x-2 mb-6">
        {(['overview', 'tools', 'techniques', 'search'] as const).map((tab) => (
          <Button
            key={tab}
            onClick={() => handleTabChange(tab)}
            variant={activeTab === tab ? 'default' : 'outline'}
            className={`capitalize ${activeTab === tab ? 'bg-red-600 hover:bg-red-700' : 'border-gray-600 text-gray-300 hover:bg-gray-800'}`}
          >
            {tab}
          </Button>
        ))}
      </div>

      {/* Search Form */}
      {activeTab === 'search' && (
        <form onSubmit={handleSearch} className="mb-6">
          <div className="flex space-x-2">
            <Input
              type="text"
              placeholder="Search tools, techniques, vulnerabilities..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="flex-1 bg-gray-800 border-gray-600 text-white"
            />
            <Button type="submit" className="bg-red-600 hover:bg-red-700">
              Search
            </Button>
          </div>
        </form>
      )}

      {loading && (
        <div className="text-center py-8">
          <div className="text-gray-400">Loading knowledge base...</div>
        </div>
      )}

      {/* Overview Tab */}
      {activeTab === 'overview' && stats && (
        <div className="space-y-6">
          <Card className="p-6 bg-gray-800 border-gray-700">
            <h3 className="text-lg font-semibold text-white mb-4">📊 Knowledge Base Statistics</h3>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-red-500">{stats.tools}</div>
                <div className="text-sm text-gray-400">Security Tools</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-500">{stats.techniques}</div>
                <div className="text-sm text-gray-400">Attack Techniques</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-yellow-500">{stats.vulnerabilities}</div>
                <div className="text-sm text-gray-400">Vulnerabilities</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-500">{stats.bestPractices}</div>
                <div className="text-sm text-gray-400">Best Practices</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-purple-500">{stats.categories}</div>
                <div className="text-sm text-gray-400">Categories</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-cyan-500">{stats.totalEntries}</div>
                <div className="text-sm text-gray-400">Total Entries</div>
              </div>
            </div>
          </Card>

          <Card className="p-6 bg-gray-800 border-gray-700">
            <h3 className="text-lg font-semibold text-white mb-4">📂 Categories</h3>
            <div className="flex flex-wrap gap-2">
              {categories.map((category) => (
                <span
                  key={category}
                  className="px-3 py-1 bg-gray-700 text-gray-300 rounded-full text-sm"
                >
                  {category}
                </span>
              ))}
            </div>
          </Card>
        </div>
      )}

      {/* Tools Tab */}
      {activeTab === 'tools' && (
        <div className="space-y-4">
          {tools.map((tool) => (
            <Card key={tool.name} className="p-6 bg-gray-800 border-gray-700">
              <div className="flex justify-between items-start mb-3">
                <h3 className="text-lg font-semibold text-white">{tool.name}</h3>
                <span className="px-2 py-1 bg-red-600 text-white rounded text-sm">
                  {tool.category}
                </span>
              </div>
              <p className="text-gray-300 mb-3">{tool.description}</p>
              
              <div className="mb-3">
                <strong className="text-white">Usage:</strong>
                <code className="ml-2 px-2 py-1 bg-gray-900 text-green-400 rounded text-sm">
                  {tool.usage}
                </code>
              </div>

              <div className="mb-3">
                <strong className="text-white">Examples:</strong>
                <div className="mt-1 space-y-1">
                  {tool.examples.slice(0, 2).map((example, idx) => (
                    <code key={idx} className="block px-2 py-1 bg-gray-900 text-green-400 rounded text-sm">
                      {example}
                    </code>
                  ))}
                </div>
              </div>

              <div className="flex flex-wrap gap-2 mb-3">
                <strong className="text-white">Platforms:</strong>
                {tool.platforms.map((platform) => (
                  <span key={platform} className="px-2 py-1 bg-blue-600 text-white rounded text-xs">
                    {platform}
                  </span>
                ))}
              </div>

              <div className="text-sm text-gray-400">
                <strong>Installation:</strong> {tool.installation}
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Techniques Tab */}
      {activeTab === 'techniques' && (
        <div className="space-y-4">
          {techniques.map((technique) => (
            <Card key={technique.name} className="p-6 bg-gray-800 border-gray-700">
              <div className="flex justify-between items-start mb-3">
                <h3 className="text-lg font-semibold text-white">{technique.name}</h3>
                <span className="px-2 py-1 bg-orange-600 text-white rounded text-sm">
                  {technique.category}
                </span>
              </div>
              <p className="text-gray-300 mb-4">{technique.description}</p>
              
              <div className="grid md:grid-cols-2 gap-4">
                <div>
                  <strong className="text-white">Steps:</strong>
                  <ol className="mt-1 list-decimal list-inside text-gray-300 text-sm space-y-1">
                    {technique.steps.map((step, idx) => (
                      <li key={idx}>{step}</li>
                    ))}
                  </ol>
                </div>

                <div>
                  <div className="mb-3">
                    <strong className="text-white">Tools:</strong>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {technique.tools.map((tool) => (
                        <span key={tool} className="px-2 py-1 bg-red-600 text-white rounded text-xs">
                          {tool}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <strong className="text-white">Mitigations:</strong>
                    <ul className="mt-1 list-disc list-inside text-gray-300 text-sm space-y-1">
                      {technique.mitigations.slice(0, 3).map((mitigation, idx) => (
                        <li key={idx}>{mitigation}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Search Results */}
      {activeTab === 'search' && !loading && (
        <div className="space-y-6">
          {tools.length > 0 && (
            <div>
              <h3 className="text-lg font-semibold text-white mb-3">🔧 Tools ({tools.length})</h3>
              <div className="space-y-3">
                {tools.map((tool) => (
                  <Card key={tool.name} className="p-4 bg-gray-800 border-gray-700">
                    <div className="flex justify-between items-start">
                      <div>
                        <h4 className="font-semibold text-white">{tool.name}</h4>
                        <p className="text-gray-300 text-sm">{tool.description}</p>
                      </div>
                      <span className="px-2 py-1 bg-red-600 text-white rounded text-xs">
                        {tool.category}
                      </span>
                    </div>
                  </Card>
                ))}
              </div>
            </div>
          )}

          {techniques.length > 0 && (
            <div>
              <h3 className="text-lg font-semibold text-white mb-3">⚔️ Techniques ({techniques.length})</h3>
              <div className="space-y-3">
                {techniques.map((technique) => (
                  <Card key={technique.name} className="p-4 bg-gray-800 border-gray-700">
                    <div className="flex justify-between items-start">
                      <div>
                        <h4 className="font-semibold text-white">{technique.name}</h4>
                        <p className="text-gray-300 text-sm">{technique.description}</p>
                      </div>
                      <span className="px-2 py-1 bg-orange-600 text-white rounded text-xs">
                        {technique.category}
                      </span>
                    </div>
                  </Card>
                ))}
              </div>
            </div>
          )}

          {tools.length === 0 && techniques.length === 0 && searchQuery && (
            <div className="text-center py-8">
              <div className="text-gray-400">No results found for "{searchQuery}"</div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default KnowledgeBase
