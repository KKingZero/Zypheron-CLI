import React, { useState, useEffect } from 'react'
import { Network, Shield, Eye, Play, Pause, Users, AlertTriangle, Globe, Download, Brain, Target } from 'lucide-react'

interface NetworkNode {
  id: string
  ip: string
  mac: string
  hostname?: string
  vendor?: string
  os?: string
  ports: number[]
  isGateway: boolean
  isTarget: boolean
  status: 'online' | 'offline' | 'unknown'
  lastSeen: string
}

interface MitmAttack {
  id: string
  type: 'arp_spoofing' | 'dns_spoofing' | 'ssl_strip' | 'session_hijack'
  source: string
  target: string
  gateway: string
  status: 'active' | 'stopped' | 'failed'
  startTime: string
  capturedData: CapturedData[]
  traffic: TrafficData[]
}

interface CapturedData {
  id: string
  timestamp: string
  type: 'credentials' | 'cookies' | 'form_data' | 'headers'
  source: string
  destination: string
  protocol: string
  data: string
  sensitive: boolean
}

interface TrafficData {
  timestamp: string
  source: string
  destination: string
  protocol: string
  bytes: number
  packets: number
}

interface NetworkMap {
  nodes: NetworkNode[]
  connections: Array<{
    source: string
    target: string
    type: 'direct' | 'routed'
    strength: number
  }>
}

interface EttercapMitmPanelProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

const EttercapMitmPanel: React.FC<EttercapMitmPanelProps> = ({ onToolExecute }) => {
  const [interface_, setInterface] = useState<string>('eth0')
  const [networkRange, setNetworkRange] = useState<string>('192.168.1.0/24')
  const [isScanning, setIsScanning] = useState(false)
  const [networkMap, setNetworkMap] = useState<NetworkMap | null>(null)
  const [activeAttacks, setActiveAttacks] = useState<MitmAttack[]>([])
  const [selectedNodes, setSelectedNodes] = useState<string[]>([])
  const [attackType, setAttackType] = useState<string>('arp_spoofing')
  const [capturedData, setCapturedData] = useState<CapturedData[]>([])
  const [isMonitoring, setIsMonitoring] = useState(false)
  const [viewMode, setViewMode] = useState<'network' | 'attacks' | 'capture' | 'analysis'>('network')

  const networkInterfaces = [
    'eth0', 'eth1', 'wlan0', 'wlan1', 'br0'
  ]

  const attackTypes = [
    {
      value: 'arp_spoofing',
      name: 'ARP Spoofing',
      description: 'Intercept traffic by poisoning ARP tables',
      risk: 'medium',
      icon: <Network className="w-4 h-4" />
    },
    {
      value: 'dns_spoofing',
      name: 'DNS Spoofing',
      description: 'Redirect DNS queries to malicious servers',
      risk: 'high',
      icon: <Globe className="w-4 h-4" />
    },
    {
      value: 'ssl_strip',
      name: 'SSL Strip',
      description: 'Downgrade HTTPS connections to HTTP',
      risk: 'high',
      icon: <Shield className="w-4 h-4" />
    },
    {
      value: 'session_hijack',
      name: 'Session Hijacking',
      description: 'Capture and replay user sessions',
      risk: 'critical',
      icon: <Eye className="w-4 h-4" />
    }
  ]

  const scanNetwork = async () => {
    setIsScanning(true)
    try {
      const result = await onToolExecute('ettercap_scan', {
        interface: interface_,
        range: networkRange
      })

      if (result.networkMap) {
        setNetworkMap(result.networkMap)
        setViewMode('network')
      }
    } catch (error) {
      console.error('Network scan failed:', error)
    } finally {
      setIsScanning(false)
    }
  }

  const startMitmAttack = async () => {
    if (selectedNodes.length < 1) return

    try {
      const gateway = networkMap?.nodes.find(n => n.isGateway)?.ip
      const target = selectedNodes[0]

      const result = await onToolExecute('ettercap_mitm', {
        type: attackType,
        interface: interface_,
        target,
        gateway,
        monitoring: true
      })

      if (result.attackId) {
        const newAttack: MitmAttack = {
          id: result.attackId,
          type: attackType as any,
          source: gateway || 'unknown',
          target,
          gateway: gateway || 'unknown',
          status: 'active',
          startTime: new Date().toISOString(),
          capturedData: [],
          traffic: []
        }

        setActiveAttacks(prev => [...prev, newAttack])
        setIsMonitoring(true)
        setViewMode('attacks')
      }
    } catch (error) {
      console.error('MITM attack failed:', error)
    }
  }

  const stopAttack = async (attackId: string) => {
    try {
      await onToolExecute('ettercap_stop', { attackId })
      
      setActiveAttacks(prev => 
        prev.map(attack => 
          attack.id === attackId 
            ? { ...attack, status: 'stopped' as const }
            : attack
        )
      )
    } catch (error) {
      console.error('Failed to stop attack:', error)
    }
  }

  const toggleNodeSelection = (nodeId: string) => {
    setSelectedNodes(prev => 
      prev.includes(nodeId)
        ? prev.filter(id => id !== nodeId)
        : [...prev, nodeId]
    )
  }

  const getNodeStatusColor = (status: string) => {
    switch (status) {
      case 'online': return 'text-green-500 bg-green-500/20'
      case 'offline': return 'text-red-500 bg-red-500/20'
      case 'unknown': return 'text-gray-500 bg-gray-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  const getAttackStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'text-green-500 bg-green-500/20'
      case 'stopped': return 'text-gray-500 bg-gray-500/20'
      case 'failed': return 'text-red-500 bg-red-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'critical': return 'text-red-600 bg-red-600/20'
      case 'high': return 'text-red-500 bg-red-500/20'
      case 'medium': return 'text-yellow-500 bg-yellow-500/20'
      case 'low': return 'text-green-500 bg-green-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  return (
    <div className="space-y-6">
      {/* Ettercap Header */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h3 className="text-xl font-bold text-terminal-text mb-4 flex items-center">
          <Network className="w-6 h-6 mr-3 text-red-500" />
          Ettercap MITM Suite
          <span className="ml-3 px-3 py-1 bg-red-500 text-white text-sm rounded-full">HIGH RISK</span>
        </h3>
        <p className="text-terminal-muted">
          Advanced man-in-the-middle attack toolkit with visual network mapping for LAN security testing
        </p>
        
        {/* Warning */}
        <div className="mt-4 p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
          <div className="flex items-start space-x-3">
            <AlertTriangle className="w-5 h-5 text-red-500 mt-0.5" />
            <div>
              <h4 className="font-medium text-red-300">Authorized Testing Only</h4>
              <p className="text-red-200 text-sm mt-1">
                MITM attacks can disrupt network traffic and capture sensitive data. Only use on networks you own or have explicit authorization to test.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Configuration Panel */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h4 className="text-lg font-semibold text-terminal-text mb-4">Network Configuration</h4>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div>
            <label className="block text-terminal-text font-medium mb-2">
              Network Interface
            </label>
            <select
              value={interface_}
              onChange={(e) => setInterface(e.target.value)}
              className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
            >
              {networkInterfaces.map((iface) => (
                <option key={iface} value={iface}>{iface}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-terminal-text font-medium mb-2">
              Network Range
            </label>
            <input
              type="text"
              value={networkRange}
              onChange={(e) => setNetworkRange(e.target.value)}
              placeholder="192.168.1.0/24"
              className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
            />
          </div>

          <div className="flex items-end">
            <button
              onClick={scanNetwork}
              disabled={isScanning}
              className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white rounded-lg flex items-center justify-center space-x-2 transition-colors"
            >
              {isScanning ? (
                <>
                  <Network className="w-4 h-4 animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <Target className="w-4 h-4" />
                  <span>Scan Network</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex space-x-2">
        <button
          onClick={() => setViewMode('network')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'network' 
              ? 'bg-red-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Network className="w-4 h-4" />
          <span>Network Map</span>
        </button>
        <button
          onClick={() => setViewMode('attacks')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'attacks' 
              ? 'bg-red-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Shield className="w-4 h-4" />
          <span>Attacks ({activeAttacks.length})</span>
        </button>
        <button
          onClick={() => setViewMode('capture')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'capture' 
              ? 'bg-red-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Eye className="w-4 h-4" />
          <span>Captured Data ({capturedData.length})</span>
        </button>
        <button
          onClick={() => setViewMode('analysis')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'analysis' 
              ? 'bg-red-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Brain className="w-4 h-4" />
          <span>Analysis</span>
        </button>
      </div>

      {/* Network Map Tab */}
      {viewMode === 'network' && networkMap && (
        <div className="space-y-6">
          {/* Network Overview */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">Network Topology</h4>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              <div className="bg-terminal-bg border border-terminal-border rounded p-3 text-center">
                <div className="text-2xl font-bold text-terminal-text">{networkMap.nodes.length}</div>
                <div className="text-terminal-muted text-sm">Total Hosts</div>
              </div>
              <div className="bg-terminal-bg border border-terminal-border rounded p-3 text-center">
                <div className="text-2xl font-bold text-green-500">
                  {networkMap.nodes.filter(n => n.status === 'online').length}
                </div>
                <div className="text-terminal-muted text-sm">Online</div>
              </div>
              <div className="bg-terminal-bg border border-terminal-border rounded p-3 text-center">
                <div className="text-2xl font-bold text-purple-500">{selectedNodes.length}</div>
                <div className="text-terminal-muted text-sm">Selected</div>
              </div>
            </div>

            {/* Visual Network Map */}
            <div className="bg-terminal-bg border border-terminal-border rounded p-4 min-h-64">
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                {networkMap.nodes.map((node) => (
                  <div
                    key={node.id}
                    className={`border rounded-lg p-3 cursor-pointer transition-all ${
                      selectedNodes.includes(node.id)
                        ? 'border-purple-500 bg-purple-500/10'
                        : node.isGateway
                        ? 'border-yellow-500 bg-yellow-500/10'
                        : 'border-terminal-border hover:border-gray-400'
                    }`}
                    onClick={() => toggleNodeSelection(node.id)}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        {node.isGateway ? (
                          <Globe className="w-4 h-4 text-yellow-500" />
                        ) : (
                          <Users className="w-4 h-4 text-gray-400" />
                        )}
                        <span className={`px-1 py-0.5 rounded text-xs font-medium ${getNodeStatusColor(node.status)}`}>
                          {node.status}
                        </span>
                      </div>
                      {node.isGateway && (
                        <span className="px-1 py-0.5 bg-yellow-500 text-black text-xs rounded">GW</span>
                      )}
                    </div>

                    <div className="space-y-1 text-sm">
                      <div className="font-mono text-terminal-text">{node.ip}</div>
                      <div className="text-terminal-muted text-xs">{node.mac}</div>
                      {node.hostname && (
                        <div className="text-terminal-text">{node.hostname}</div>
                      )}
                      {node.vendor && (
                        <div className="text-blue-400 text-xs">{node.vendor}</div>
                      )}
                      {node.ports.length > 0 && (
                        <div className="text-green-400 text-xs">
                          Ports: {node.ports.slice(0, 3).join(', ')}
                          {node.ports.length > 3 && '...'}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Attack Configuration */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">MITM Attack Configuration</h4>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
              <div>
                <label className="block text-terminal-text font-medium mb-3">Attack Type</label>
                <div className="space-y-2">
                  {attackTypes.map((type) => (
                    <div
                      key={type.value}
                      className={`border rounded-lg p-3 cursor-pointer transition-all ${
                        attackType === type.value
                          ? 'border-red-500 bg-red-500/10'
                          : 'border-terminal-border hover:border-red-500/50'
                      }`}
                      onClick={() => setAttackType(type.value)}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center space-x-2">
                          <div className="text-red-400">{type.icon}</div>
                          <span className="font-medium text-terminal-text">{type.name}</span>
                        </div>
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getRiskColor(type.risk)}`}>
                          {type.risk.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-terminal-muted text-sm">{type.description}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-terminal-text font-medium mb-3">Target Selection</label>
                <div className="bg-terminal-bg border border-terminal-border rounded p-3">
                  {selectedNodes.length === 0 ? (
                    <p className="text-terminal-muted text-sm">Select targets from the network map</p>
                  ) : (
                    <div className="space-y-2">
                      <p className="text-terminal-text text-sm font-medium">Selected Targets:</p>
                      {selectedNodes.slice(0, 5).map((nodeId) => {
                        const node = networkMap.nodes.find(n => n.id === nodeId)
                        return node ? (
                          <div key={nodeId} className="flex items-center justify-between p-2 bg-terminal-card rounded">
                            <div>
                              <span className="text-terminal-text font-mono">{node.ip}</span>
                              {node.hostname && (
                                <span className="text-terminal-muted ml-2">({node.hostname})</span>
                              )}
                            </div>
                            <button
                              onClick={() => toggleNodeSelection(nodeId)}
                              className="text-red-400 hover:text-red-300"
                            >
                              ×
                            </button>
                          </div>
                        ) : null
                      })}
                      {selectedNodes.length > 5 && (
                        <p className="text-terminal-muted text-xs">And {selectedNodes.length - 5} more...</p>
                      )}
                    </div>
                  )}
                </div>

                <button
                  onClick={startMitmAttack}
                  disabled={selectedNodes.length === 0}
                  className="w-full mt-4 px-4 py-2 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 text-white rounded-lg flex items-center justify-center space-x-2 transition-colors"
                >
                  <Play className="w-4 h-4" />
                  <span>Launch MITM Attack</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Attacks Tab */}
      {viewMode === 'attacks' && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">Active MITM Attacks</h4>
          
          {activeAttacks.length === 0 ? (
            <div className="text-center py-8">
              <Shield className="w-12 h-12 text-gray-500 mx-auto mb-4" />
              <p className="text-terminal-muted">No active attacks. Configure and launch MITM attacks from the Network Map.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {activeAttacks.map((attack) => (
                <div key={attack.id} className="border border-terminal-border rounded-lg p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getAttackStatusColor(attack.status)}`}>
                        {attack.status.toUpperCase()}
                      </span>
                      <span className="font-medium text-terminal-text capitalize">
                        {attack.type.replace('_', ' ')}
                      </span>
                    </div>
                    <div className="flex space-x-2">
                      {attack.status === 'active' && (
                        <button
                          onClick={() => stopAttack(attack.id)}
                          className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-sm rounded"
                        >
                          <Pause className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                    <div>
                      <span className="text-terminal-muted">Target:</span>
                      <span className="ml-2 text-terminal-text font-mono">{attack.target}</span>
                    </div>
                    <div>
                      <span className="text-terminal-muted">Gateway:</span>
                      <span className="ml-2 text-terminal-text font-mono">{attack.gateway}</span>
                    </div>
                    <div>
                      <span className="text-terminal-muted">Duration:</span>
                      <span className="ml-2 text-terminal-text">
                        {Math.floor((Date.now() - new Date(attack.startTime).getTime()) / 60000)}m
                      </span>
                    </div>
                  </div>

                  <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-terminal-bg border border-terminal-border rounded p-3">
                      <h6 className="font-medium text-terminal-text mb-2">Traffic Intercepted</h6>
                      <div className="text-2xl font-bold text-red-500">{attack.traffic.length}</div>
                      <div className="text-terminal-muted text-xs">packets</div>
                    </div>
                    <div className="bg-terminal-bg border border-terminal-border rounded p-3">
                      <h6 className="font-medium text-terminal-text mb-2">Data Captured</h6>
                      <div className="text-2xl font-bold text-yellow-500">{attack.capturedData.length}</div>
                      <div className="text-terminal-muted text-xs">items</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Captured Data Tab */}
      {viewMode === 'capture' && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">Captured Network Data</h4>
          
          {capturedData.length === 0 ? (
            <div className="text-center py-8">
              <Eye className="w-12 h-12 text-gray-500 mx-auto mb-4" />
              <p className="text-terminal-muted">No data captured yet. Active MITM attacks will populate this section.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {capturedData.map((item) => (
                <div key={item.id} className={`border rounded-lg p-4 ${
                  item.sensitive ? 'border-red-500/50 bg-red-500/5' : 'border-terminal-border'
                }`}>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center space-x-3">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        item.type === 'credentials' ? 'bg-red-500/20 text-red-400' :
                        item.type === 'cookies' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-blue-500/20 text-blue-400'
                      }`}>
                        {item.type.toUpperCase()}
                      </span>
                      <span className="text-terminal-text font-medium">{item.protocol}</span>
                      {item.sensitive && (
                        <span className="px-2 py-1 bg-red-500 text-white text-xs rounded">SENSITIVE</span>
                      )}
                    </div>
                    <span className="text-terminal-muted text-sm">
                      {new Date(item.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm mb-3">
                    <div>
                      <span className="text-terminal-muted">Source:</span>
                      <span className="ml-2 text-terminal-text font-mono">{item.source}</span>
                    </div>
                    <div>
                      <span className="text-terminal-muted">Destination:</span>
                      <span className="ml-2 text-terminal-text font-mono">{item.destination}</span>
                    </div>
                  </div>

                  <div className="bg-terminal-bg border border-terminal-border rounded p-3">
                    <pre className="text-terminal-text text-sm whitespace-pre-wrap overflow-x-auto">
                      {item.data.length > 200 ? `${item.data.slice(0, 200)}...` : item.data}
                    </pre>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Analysis Tab */}
      {viewMode === 'analysis' && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <Brain className="w-5 h-5 mr-2 text-blue-500" />
            AI Network Analysis
          </h4>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h5 className="font-medium text-terminal-text mb-3">Attack Effectiveness</h5>
              <div className="space-y-3">
                <div className="bg-terminal-bg border border-terminal-border rounded p-3">
                  <div className="flex justify-between">
                    <span className="text-terminal-muted">Success Rate:</span>
                    <span className="text-terminal-text font-bold">87%</span>
                  </div>
                </div>
                <div className="bg-terminal-bg border border-terminal-border rounded p-3">
                  <div className="flex justify-between">
                    <span className="text-terminal-muted">Data Intercepted:</span>
                    <span className="text-terminal-text font-bold">2.3 MB</span>
                  </div>
                </div>
                <div className="bg-terminal-bg border border-terminal-border rounded p-3">
                  <div className="flex justify-between">
                    <span className="text-terminal-muted">Detection Risk:</span>
                    <span className="text-yellow-500 font-bold">Medium</span>
                  </div>
                </div>
              </div>
            </div>

            <div>
              <h5 className="font-medium text-terminal-text mb-3">Security Recommendations</h5>
              <ul className="space-y-2">
                <li className="text-terminal-muted text-sm flex items-start space-x-2">
                  <Shield className="w-3 h-3 mt-1 text-green-500" />
                  <span>Implement static ARP entries for critical hosts</span>
                </li>
                <li className="text-terminal-muted text-sm flex items-start space-x-2">
                  <Shield className="w-3 h-3 mt-1 text-green-500" />
                  <span>Enable network segmentation and VLANs</span>
                </li>
                <li className="text-terminal-muted text-sm flex items-start space-x-2">
                  <Shield className="w-3 h-3 mt-1 text-green-500" />
                  <span>Deploy network monitoring and IDS systems</span>
                </li>
                <li className="text-terminal-muted text-sm flex items-start space-x-2">
                  <Shield className="w-3 h-3 mt-1 text-green-500" />
                  <span>Force HTTPS and certificate pinning</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Export Options */}
      {(activeAttacks.length > 0 || capturedData.length > 0) && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-4">
          <div className="flex items-center justify-between">
            <span className="text-terminal-text font-medium">Export Results</span>
            <div className="flex space-x-2">
              <button className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>PCAP</span>
              </button>
              <button className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>JSON</span>
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

export default EttercapMitmPanel