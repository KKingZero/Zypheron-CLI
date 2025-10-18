import React, { useState, useEffect } from 'react'
import { Users, MessageSquare, Database, Share2, FileText, Clock, UserCheck, Activity, Target, Shield, Download, Upload } from 'lucide-react'

interface TeamMember {
  id: string
  name: string
  role: 'lead' | 'pentester' | 'analyst' | 'client'
  status: 'online' | 'away' | 'offline'
  avatar: string
  lastActivity: string
  currentTask?: string
}

interface WorkspaceData {
  id: string
  name: string
  description: string
  hosts: number
  vulnerabilities: number
  services: number
  created: string
  lastUpdate: string
  participants: TeamMember[]
  status: 'active' | 'completed' | 'archived'
}

interface CollaborationEvent {
  id: string
  type: 'discovery' | 'vulnerability' | 'note' | 'task' | 'chat'
  user: string
  timestamp: string
  content: string
  data?: any
  priority: 'low' | 'medium' | 'high' | 'critical'
}

interface TaskItem {
  id: string
  title: string
  description: string
  assignee: string
  status: 'todo' | 'in_progress' | 'review' | 'completed'
  priority: 'low' | 'medium' | 'high' | 'critical'
  dueDate: string
  tags: string[]
  relatedHosts: string[]
}

interface FaradayCollabPanelProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

const FaradayCollabPanel: React.FC<FaradayCollabPanelProps> = ({ onToolExecute }) => {
  const [workspaces, setWorkspaces] = useState<WorkspaceData[]>([])
  const [selectedWorkspace, setSelectedWorkspace] = useState<WorkspaceData | null>(null)
  const [teamMembers, setTeamMembers] = useState<TeamMember[]>([])
  const [collaborationEvents, setCollaborationEvents] = useState<CollaborationEvent[]>([])
  const [tasks, setTasks] = useState<TaskItem[]>([])
  const [chatMessage, setChatMessage] = useState('')
  const [viewMode, setViewMode] = useState<'workspaces' | 'collaboration' | 'tasks' | 'data'>('workspaces')
  const [isConnected, setIsConnected] = useState(false)

  const connectToFaraday = async () => {
    try {
      const result = await onToolExecute('faraday_connect', {
        server: 'localhost:5985',
        workspace: selectedWorkspace?.name || 'default'
      })

      if (result.connected) {
        setIsConnected(true)
        setTeamMembers(result.teamMembers || [])
        setCollaborationEvents(result.events || [])
        setTasks(result.tasks || [])
      }
    } catch (error) {
      console.error('Faraday connection failed:', error)
    }
  }

  const createWorkspace = async (name: string, description: string) => {
    try {
      const result = await onToolExecute('faraday_create_workspace', {
        name,
        description,
        template: 'pentest'
      })

      if (result.workspace) {
        setWorkspaces(prev => [...prev, result.workspace])
      }
    } catch (error) {
      console.error('Workspace creation failed:', error)
    }
  }

  const ingestScanResults = async (toolName: string, results: any) => {
    try {
      const result = await onToolExecute('faraday_ingest', {
        workspace: selectedWorkspace?.id,
        tool: toolName,
        data: results,
        autoClassify: true
      })

      if (result.ingested) {
        // Update workspace statistics
        if (selectedWorkspace) {
          setSelectedWorkspace({
            ...selectedWorkspace,
            hosts: result.stats.hosts,
            vulnerabilities: result.stats.vulnerabilities,
            services: result.stats.services,
            lastUpdate: new Date().toISOString()
          })
        }

        // Add collaboration event
        const newEvent: CollaborationEvent = {
          id: Date.now().toString(),
          type: 'discovery',
          user: 'Current User',
          timestamp: new Date().toISOString(),
          content: `Ingested ${result.stats.newFindings} new findings from ${toolName}`,
          data: result.stats,
          priority: 'medium'
        }
        setCollaborationEvents(prev => [newEvent, ...prev])
      }
    } catch (error) {
      console.error('Data ingestion failed:', error)
    }
  }

  const sendChatMessage = async () => {
    if (!chatMessage.trim()) return

    const newEvent: CollaborationEvent = {
      id: Date.now().toString(),
      type: 'chat',
      user: 'Current User',
      timestamp: new Date().toISOString(),
      content: chatMessage,
      priority: 'low'
    }

    setCollaborationEvents(prev => [newEvent, ...prev])
    setChatMessage('')

    try {
      await onToolExecute('faraday_chat', {
        workspace: selectedWorkspace?.id,
        message: chatMessage
      })
    } catch (error) {
      console.error('Chat message failed:', error)
    }
  }

  const addTask = async (task: Omit<TaskItem, 'id'>) => {
    const newTask: TaskItem = {
      ...task,
      id: Date.now().toString()
    }

    setTasks(prev => [...prev, newTask])

    try {
      await onToolExecute('faraday_add_task', {
        workspace: selectedWorkspace?.id,
        task: newTask
      })
    } catch (error) {
      console.error('Task creation failed:', error)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return 'text-green-500 bg-green-500/20'
      case 'away': return 'text-yellow-500 bg-yellow-500/20'
      case 'offline': return 'text-gray-500 bg-gray-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical': return 'text-red-600 bg-red-600/20'
      case 'high': return 'text-red-500 bg-red-500/20'
      case 'medium': return 'text-yellow-500 bg-yellow-500/20'
      case 'low': return 'text-green-500 bg-green-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  const getTaskStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-green-500 bg-green-500/20'
      case 'in_progress': return 'text-blue-500 bg-blue-500/20'
      case 'review': return 'text-purple-500 bg-purple-500/20'
      case 'todo': return 'text-gray-500 bg-gray-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  useEffect(() => {
    // Initialize with demo data
    setWorkspaces([
      {
        id: '1',
        name: 'Corporate Pentest 2024',
        description: 'Internal infrastructure assessment',
        hosts: 45,
        vulnerabilities: 23,
        services: 156,
        created: '2024-02-01',
        lastUpdate: new Date().toISOString(),
        participants: [],
        status: 'active'
      },
      {
        id: '2',
        name: 'Web App Security Review',
        description: 'External application security testing',
        hosts: 12,
        vulnerabilities: 8,
        services: 34,
        created: '2024-02-10',
        lastUpdate: new Date().toISOString(),
        participants: [],
        status: 'active'
      }
    ])

    setTeamMembers([
      {
        id: '1',
        name: 'Alice Johnson',
        role: 'lead',
        status: 'online',
        avatar: '👨‍💻',
        lastActivity: '2 minutes ago',
        currentTask: 'Network reconnaissance'
      },
      {
        id: '2',
        name: 'Bob Smith',
        role: 'pentester',
        status: 'online',
        avatar: '👩‍🔬',
        lastActivity: '5 minutes ago',
        currentTask: 'Web application testing'
      },
      {
        id: '3',
        name: 'Carol Davis',
        role: 'analyst',
        status: 'away',
        avatar: '🧑‍💼',
        lastActivity: '1 hour ago'
      }
    ])
  }, [])

  return (
    <div className="space-y-6">
      {/* Faraday Header */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h3 className="text-xl font-bold text-terminal-text mb-4 flex items-center">
          <Users className="w-6 h-6 mr-3 text-teal-500" />
          Faraday Collaborative IDE
          <span className="ml-3 px-3 py-1 bg-teal-500 text-white text-sm rounded-full">TEAM-SYNC</span>
        </h3>
        <p className="text-terminal-muted">
          Real-time collaboration platform for penetration testing teams with automated data ingestion
        </p>
        
        {/* Connection Status */}
        <div className="mt-4 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className={`w-3 h-3 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`}></div>
            <span className="text-terminal-text">
              {isConnected ? 'Connected to Faraday Server' : 'Disconnected'}
            </span>
          </div>
          <button
            onClick={connectToFaraday}
            className="px-4 py-2 bg-teal-600 hover:bg-teal-700 text-white rounded"
          >
            {isConnected ? 'Reconnect' : 'Connect'}
          </button>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex space-x-2">
        <button
          onClick={() => setViewMode('workspaces')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'workspaces' 
              ? 'bg-teal-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Database className="w-4 h-4" />
          <span>Workspaces</span>
        </button>
        <button
          onClick={() => setViewMode('collaboration')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'collaboration' 
              ? 'bg-teal-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <MessageSquare className="w-4 h-4" />
          <span>Live Activity</span>
        </button>
        <button
          onClick={() => setViewMode('tasks')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'tasks' 
              ? 'bg-teal-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Target className="w-4 h-4" />
          <span>Tasks ({tasks.length})</span>
        </button>
        <button
          onClick={() => setViewMode('data')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'data' 
              ? 'bg-teal-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Share2 className="w-4 h-4" />
          <span>Data Ingestion</span>
        </button>
      </div>

      {/* Workspaces Tab */}
      {viewMode === 'workspaces' && (
        <div className="space-y-6">
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">Active Workspaces</h4>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {workspaces.map((workspace) => (
                <div
                  key={workspace.id}
                  className={`border rounded-lg p-4 cursor-pointer transition-all ${
                    selectedWorkspace?.id === workspace.id
                      ? 'border-teal-500 bg-teal-500/10'
                      : 'border-terminal-border hover:border-teal-500/50'
                  }`}
                  onClick={() => setSelectedWorkspace(workspace)}
                >
                  <div className="flex items-center justify-between mb-3">
                    <h5 className="font-medium text-terminal-text">{workspace.name}</h5>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      workspace.status === 'active' ? 'text-green-500 bg-green-500/20' :
                      workspace.status === 'completed' ? 'text-blue-500 bg-blue-500/20' :
                      'text-gray-500 bg-gray-500/20'
                    }`}>
                      {workspace.status.toUpperCase()}
                    </span>
                  </div>
                  
                  <p className="text-terminal-muted text-sm mb-4">{workspace.description}</p>
                  
                  <div className="grid grid-cols-3 gap-4 text-center">
                    <div>
                      <div className="text-lg font-bold text-terminal-text">{workspace.hosts}</div>
                      <div className="text-xs text-terminal-muted">Hosts</div>
                    </div>
                    <div>
                      <div className="text-lg font-bold text-red-500">{workspace.vulnerabilities}</div>
                      <div className="text-xs text-terminal-muted">Vulnerabilities</div>
                    </div>
                    <div>
                      <div className="text-lg font-bold text-blue-500">{workspace.services}</div>
                      <div className="text-xs text-terminal-muted">Services</div>
                    </div>
                  </div>
                  
                  <div className="mt-3 text-xs text-terminal-muted">
                    Last updated: {new Date(workspace.lastUpdate).toLocaleString()}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Team Members */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">Team Members</h4>
            
            <div className="space-y-3">
              {teamMembers.map((member) => (
                <div key={member.id} className="flex items-center space-x-4 p-3 border border-terminal-border rounded">
                  <div className="text-2xl">{member.avatar}</div>
                  <div className="flex-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-medium text-terminal-text">{member.name}</span>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(member.status)}`}>
                        {member.status}
                      </span>
                      <span className="px-2 py-1 bg-purple-500/20 text-purple-400 text-xs rounded">
                        {member.role.toUpperCase()}
                      </span>
                    </div>
                    <div className="text-sm text-terminal-muted">{member.lastActivity}</div>
                    {member.currentTask && (
                      <div className="text-sm text-blue-400">Working on: {member.currentTask}</div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Collaboration Tab */}
      {viewMode === 'collaboration' && (
        <div className="space-y-6">
          {/* Live Activity Feed */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
              <Activity className="w-5 h-5 mr-2 text-green-500" />
              Live Activity Feed
            </h4>
            
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {collaborationEvents.map((event) => (
                <div key={event.id} className="border-l-4 border-teal-500 pl-4 py-2">
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-medium text-terminal-text">{event.user}</span>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getPriorityColor(event.priority)}`}>
                        {event.type.toUpperCase()}
                      </span>
                    </div>
                    <span className="text-xs text-terminal-muted">
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="text-terminal-muted text-sm">{event.content}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Team Chat */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">Team Chat</h4>
            
            <div className="flex space-x-2">
              <input
                type="text"
                value={chatMessage}
                onChange={(e) => setChatMessage(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && sendChatMessage()}
                placeholder="Type a message..."
                className="flex-1 bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
              />
              <button
                onClick={sendChatMessage}
                className="px-4 py-2 bg-teal-600 hover:bg-teal-700 text-white rounded"
              >
                Send
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Tasks Tab */}
      {viewMode === 'tasks' && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">Task Management</h4>
          
          <div className="space-y-3">
            {tasks.map((task) => (
              <div key={task.id} className="border border-terminal-border rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    <span className="font-medium text-terminal-text">{task.title}</span>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getTaskStatusColor(task.status)}`}>
                      {task.status.replace('_', ' ').toUpperCase()}
                    </span>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getPriorityColor(task.priority)}`}>
                      {task.priority.toUpperCase()}
                    </span>
                  </div>
                  <span className="text-terminal-muted text-sm">{task.assignee}</span>
                </div>
                <p className="text-terminal-muted text-sm mb-2">{task.description}</p>
                <div className="text-xs text-terminal-muted">
                  Due: {new Date(task.dueDate).toLocaleDateString()}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Data Ingestion Tab */}
      {viewMode === 'data' && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">Data Ingestion Hub</h4>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h5 className="font-medium text-terminal-text mb-3">Supported Tools</h5>
              <div className="space-y-2">
                {['Nmap', 'Nessus', 'OpenVAS', 'Burp Suite', 'OWASP ZAP', 'Metasploit', 'Nikto'].map(tool => (
                  <div key={tool} className="flex items-center justify-between p-2 border border-terminal-border rounded">
                    <span className="text-terminal-text">{tool}</span>
                    <button
                      onClick={() => ingestScanResults(tool, {})}
                      className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded"
                    >
                      Import
                    </button>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <h5 className="font-medium text-terminal-text mb-3">Recent Imports</h5>
              <div className="space-y-2">
                <div className="p-2 border border-terminal-border rounded">
                  <div className="font-medium text-terminal-text">Nmap XML Report</div>
                  <div className="text-xs text-terminal-muted">45 hosts, 156 services discovered</div>
                  <div className="text-xs text-terminal-muted">2 minutes ago</div>
                </div>
                <div className="p-2 border border-terminal-border rounded">
                  <div className="font-medium text-terminal-text">Nessus Scan Results</div>
                  <div className="text-xs text-terminal-muted">23 vulnerabilities identified</div>
                  <div className="text-xs text-terminal-muted">15 minutes ago</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Export Options */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-4">
        <div className="flex items-center justify-between">
          <span className="text-terminal-text font-medium">Export & Reports</span>
          <div className="flex space-x-2">
            <button className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded flex items-center space-x-1">
              <Download className="w-3 h-3" />
              <span>Executive Report</span>
            </button>
            <button className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded flex items-center space-x-1">
              <Download className="w-3 h-3" />
              <span>Technical Report</span>
            </button>
            <button className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded flex items-center space-x-1">
              <Upload className="w-3 h-3" />
              <span>Share Workspace</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export default FaradayCollabPanel