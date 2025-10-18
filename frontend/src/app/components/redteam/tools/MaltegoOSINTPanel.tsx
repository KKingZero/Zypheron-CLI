import React, { useState, useEffect, useRef } from 'react'
import { Network, Search, Eye, MapPin, Users, Link, Brain, Target } from 'lucide-react'

interface Entity {
  id: string
  name: string
  type: 'domain' | 'ip' | 'email' | 'person' | 'company' | 'phone' | 'social'
  properties: Record<string, any>
  risk: 'low' | 'medium' | 'high'
}

interface Relationship {
  id: string
  source: string
  target: string
  type: string
  confidence: number
  description: string
}

interface GraphData {
  nodes: Array<{ id: string; label: string; type: string; group?: number }>
  edges: Array<{ from: string; to: string; label: string }>
}

interface GPTAnalysis {
  summary: string
  keyFindings: string[]
  riskAssessment: {
    score: number
    factors: string[]
  }
  recommendations: string[]
}

interface MaltegoOSINTPanelProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

const MaltegoOSINTPanel: React.FC<MaltegoOSINTPanelProps> = ({ onToolExecute }) => {
  const [target, setTarget] = useState<string>('')
  const [entities, setEntities] = useState<Entity[]>([])
  const [relationships, setRelationships] = useState<Relationship[]>([])
  const [graphData, setGraphData] = useState<GraphData | null>(null)
  const [gptAnalysis, setGptAnalysis] = useState<GPTAnalysis | null>(null)
  const [selectedEntity, setSelectedEntity] = useState<Entity | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [transformSet, setTransformSet] = useState<string>('standard')
  const [viewMode, setViewMode] = useState<'graph' | 'table'>('graph')
  const graphRef = useRef<HTMLDivElement>(null)

  const startOSINTAnalysis = async () => {
    if (!target.trim()) return

    setIsAnalyzing(true)
    try {
      const result = await onToolExecute('maltego_osint', {
        target: target.trim(),
        transformSet
      })

      if (result.entities) {
        setEntities(result.entities)
        setRelationships(result.relationships || [])
        setGraphData(result.graphData)
        setGptAnalysis(result.gptAnalysis)
      }
    } catch (error) {
      console.error('OSINT analysis failed:', error)
    } finally {
      setIsAnalyzing(false)
    }
  }

  const getEntityIcon = (type: string) => {
    switch (type) {
      case 'domain': return <Network className="w-4 h-4" />
      case 'ip': return <MapPin className="w-4 h-4" />
      case 'email': return <Users className="w-4 h-4" />
      case 'person': return <Users className="w-4 h-4" />
      case 'company': return <Target className="w-4 h-4" />
      case 'phone': return <Users className="w-4 h-4" />
      case 'social': return <Link className="w-4 h-4" />
      default: return <Search className="w-4 h-4" />
    }
  }

  const getEntityColor = (type: string) => {
    const colors = {
      domain: 'text-blue-500 bg-blue-500/20',
      ip: 'text-green-500 bg-green-500/20',
      email: 'text-purple-500 bg-purple-500/20',
      person: 'text-orange-500 bg-orange-500/20',
      company: 'text-red-500 bg-red-500/20',
      phone: 'text-yellow-500 bg-yellow-500/20',
      social: 'text-pink-500 bg-pink-500/20'
    }
    return colors[type as keyof typeof colors] || 'text-gray-500 bg-gray-500/20'
  }

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'high': return 'text-red-500 bg-red-500/20'
      case 'medium': return 'text-yellow-500 bg-yellow-500/20'
      case 'low': return 'text-green-500 bg-green-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  // Simple SVG-based graph visualization
  const renderGraphVisualization = () => {
    if (!graphData || !graphData.nodes.length) return null

    const width = 800
    const height = 600
    const centerX = width / 2
    const centerY = height / 2
    const radius = 200

    // Position nodes in a circle
    const nodePositions = graphData.nodes.map((node, index) => {
      const angle = (index / graphData.nodes.length) * 2 * Math.PI
      return {
        ...node,
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius
      }
    })

    return (
      <div className="bg-terminal-bg border border-terminal-border rounded-lg p-4 overflow-auto">
        <svg width={width} height={height} className="border border-terminal-border rounded">
          {/* Render edges */}
          {graphData.edges.map((edge, index) => {
            const sourceNode = nodePositions.find(n => n.id === edge.from)
            const targetNode = nodePositions.find(n => n.id === edge.to)
            
            if (!sourceNode || !targetNode) return null

            return (
              <g key={index}>
                <line
                  x1={sourceNode.x}
                  y1={sourceNode.y}
                  x2={targetNode.x}
                  y2={targetNode.y}
                  stroke="#4B5563"
                  strokeWidth="1"
                  opacity="0.6"
                />
                <text
                  x={(sourceNode.x + targetNode.x) / 2}
                  y={(sourceNode.y + targetNode.y) / 2}
                  fill="#9CA3AF"
                  fontSize="10"
                  textAnchor="middle"
                >
                  {edge.label}
                </text>
              </g>
            )
          })}

          {/* Render nodes */}
          {nodePositions.map((node, index) => (
            <g key={index}>
              <circle
                cx={node.x}
                cy={node.y}
                r="20"
                fill="#1F2937"
                stroke="#4B5563"
                strokeWidth="2"
                className="cursor-pointer hover:stroke-blue-500"
                onClick={() => {
                  const entity = entities.find(e => e.id === node.id)
                  if (entity) setSelectedEntity(entity)
                }}
              />
              <text
                x={node.x}
                y={node.y + 5}
                fill="#F3F4F6"
                fontSize="10"
                textAnchor="middle"
                className="pointer-events-none"
              >
                {node.type.slice(0, 3).toUpperCase()}
              </text>
              <text
                x={node.x}
                y={node.y + 35}
                fill="#D1D5DB"
                fontSize="8"
                textAnchor="middle"
                className="pointer-events-none"
              >
                {node.label.length > 12 ? node.label.slice(0, 12) + '...' : node.label}
              </text>
            </g>
          ))}
        </svg>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Maltego OSINT Header */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h3 className="text-xl font-bold text-terminal-text mb-4 flex items-center">
          <Network className="w-6 h-6 mr-3 text-purple-500" />
          Maltego OSINT Intelligence
          <span className="ml-3 px-3 py-1 bg-purple-500 text-white text-sm rounded-full">GPT-ENHANCED</span>
        </h3>
        <p className="text-terminal-muted">
          Graphical entity relationship mapping with AI-powered contextual analysis
        </p>
      </div>

      {/* Control Panel */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
          <div className="md:col-span-2">
            <label className="block text-terminal-text font-medium mb-2">
              Investigation Target
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="domain.com, email@example.com, company name..."
              className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
            />
          </div>

          <div>
            <label className="block text-terminal-text font-medium mb-2">
              Transform Set
            </label>
            <select
              value={transformSet}
              onChange={(e) => setTransformSet(e.target.value)}
              className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
            >
              <option value="standard">Standard Transforms</option>
              <option value="aggressive">Aggressive OSINT</option>
              <option value="stealth">Stealth Mode</option>
              <option value="social">Social Media Focus</option>
            </select>
          </div>

          <div className="flex items-end">
            <button
              onClick={startOSINTAnalysis}
              disabled={isAnalyzing || !target.trim()}
              className="w-full px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 text-white rounded-lg flex items-center justify-center space-x-2 transition-colors"
            >
              {isAnalyzing ? (
                <>
                  <Eye className="w-4 h-4 animate-spin" />
                  <span>Analyzing...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>Investigate</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Results */}
      {entities.length > 0 && (
        <>
          {/* View Mode Toggle */}
          <div className="flex space-x-2">
            <button
              onClick={() => setViewMode('graph')}
              className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
                viewMode === 'graph' 
                  ? 'bg-purple-600 text-white' 
                  : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
              }`}
            >
              <Network className="w-4 h-4" />
              <span>Graph View</span>
            </button>
            <button
              onClick={() => setViewMode('table')}
              className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
                viewMode === 'table' 
                  ? 'bg-purple-600 text-white' 
                  : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
              }`}
            >
              <Users className="w-4 h-4" />
              <span>Table View</span>
            </button>
          </div>

          {/* Graph Visualization */}
          {viewMode === 'graph' && (
            <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
              <h4 className="text-lg font-semibold text-terminal-text mb-4">
                Entity Relationship Graph
              </h4>
              {renderGraphVisualization()}
            </div>
          )}

          {/* Table View */}
          {viewMode === 'table' && (
            <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
              <h4 className="text-lg font-semibold text-terminal-text mb-4">
                Discovered Entities
              </h4>
              <div className="space-y-3">
                {entities.map((entity) => (
                  <div
                    key={entity.id}
                    className={`border border-terminal-border rounded-lg p-4 cursor-pointer transition-all hover:border-purple-500 ${
                      selectedEntity?.id === entity.id ? 'border-purple-500 bg-purple-500/5' : ''
                    }`}
                    onClick={() => setSelectedEntity(entity)}
                  >
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center space-x-3">
                        <div className={`p-2 rounded ${getEntityColor(entity.type)}`}>
                          {getEntityIcon(entity.type)}
                        </div>
                        <div>
                          <h5 className="font-medium text-terminal-text">{entity.name}</h5>
                          <p className="text-sm text-terminal-muted capitalize">{entity.type}</p>
                        </div>
                      </div>
                      
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getRiskColor(entity.risk)}`}>
                        {entity.risk.toUpperCase()} RISK
                      </span>
                    </div>

                    {Object.keys(entity.properties).length > 0 && (
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-sm">
                        {Object.entries(entity.properties).slice(0, 3).map(([key, value]) => (
                          <div key={key}>
                            <span className="text-terminal-muted capitalize">{key}:</span>
                            <span className="ml-2 text-terminal-text">{String(value)}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* GPT Analysis */}
          {gptAnalysis && (
            <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
              <h4 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
                <Brain className="w-5 h-5 mr-2 text-blue-500" />
                AI Intelligence Analysis
              </h4>

              <div className="space-y-4">
                <div>
                  <h5 className="font-medium text-terminal-text mb-2">Executive Summary</h5>
                  <p className="text-terminal-muted">{gptAnalysis.summary}</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <h5 className="font-medium text-terminal-text mb-2">Key Findings</h5>
                    <ul className="space-y-1">
                      {gptAnalysis.keyFindings.map((finding, index) => (
                        <li key={index} className="text-terminal-muted text-sm">• {finding}</li>
                      ))}
                    </ul>
                  </div>

                  <div>
                    <h5 className="font-medium text-terminal-text mb-2">Risk Assessment</h5>
                    <div className="mb-2">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-terminal-muted">Risk Score:</span>
                        <span className="text-terminal-text font-bold">{gptAnalysis.riskAssessment.score}/10</span>
                      </div>
                      <div className="w-full bg-gray-600 rounded-full h-2 mt-1">
                        <div
                          className="bg-red-500 h-2 rounded-full"
                          style={{ width: `${gptAnalysis.riskAssessment.score * 10}%` }}
                        ></div>
                      </div>
                    </div>
                    <ul className="space-y-1">
                      {gptAnalysis.riskAssessment.factors.slice(0, 3).map((factor, index) => (
                        <li key={index} className="text-terminal-muted text-sm">• {factor}</li>
                      ))}
                    </ul>
                  </div>
                </div>

                <div>
                  <h5 className="font-medium text-terminal-text mb-2">Recommendations</h5>
                  <ul className="space-y-1">
                    {gptAnalysis.recommendations.map((rec, index) => (
                      <li key={index} className="text-terminal-muted text-sm">• {rec}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* Selected Entity Details */}
          {selectedEntity && (
            <div className="bg-terminal-card border border-purple-500/20 rounded-lg p-6">
              <h4 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
                <div className={`p-2 rounded mr-3 ${getEntityColor(selectedEntity.type)}`}>
                  {getEntityIcon(selectedEntity.type)}
                </div>
                Entity Details: {selectedEntity.name}
              </h4>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {Object.entries(selectedEntity.properties).map(([key, value]) => (
                  <div key={key} className="bg-terminal-bg border border-terminal-border rounded p-3">
                    <div className="font-medium text-terminal-text capitalize">{key}</div>
                    <div className="text-terminal-muted text-sm mt-1">{String(value)}</div>
                  </div>
                ))}
              </div>

              <div className="mt-4 pt-4 border-t border-terminal-border">
                <h5 className="font-medium text-terminal-text mb-2">Connected Entities</h5>
                <div className="flex flex-wrap gap-2">
                  {relationships
                    .filter(rel => rel.source === selectedEntity.id || rel.target === selectedEntity.id)
                    .slice(0, 5)
                    .map((rel, index) => (
                      <span
                        key={index}
                        className="px-2 py-1 bg-purple-500/20 text-purple-300 text-xs rounded"
                      >
                        {rel.type} → {rel.target === selectedEntity.id ? rel.source : rel.target}
                      </span>
                    ))}
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}

export default MaltegoOSINTPanel