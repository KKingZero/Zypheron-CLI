import React, { useState, useEffect } from 'react'
import { Target, Activity, Server, AlertTriangle, CheckCircle, XCircle, Plus, ChevronRight } from 'lucide-react'
import { getApiUrl } from '../../config/api.config'
import toast from 'react-hot-toast'
import { useNavigate } from 'react-router-dom'

interface Session {
  id: string
  target: string
  hostname: string
  os: 'windows' | 'linux' | 'macos' | 'unknown'
  osVersion: string
  architecture: string
  user: string
  privileges: 'low' | 'medium' | 'high' | 'system'
  domain?: string
  ip: string
  established: Date
  lastSeen: Date
}

const CommandControl: React.FC = () => {
  const navigate = useNavigate()
  const [sessions, setSessions] = useState<Session[]>([])
  const [selectedSession, setSelectedSession] = useState<Session | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<'sessions' | 'credentials' | 'persistence'>('sessions')

  useEffect(() => {
    loadSessions()
    const interval = setInterval(loadSessions, 5000) // Refresh every 5 seconds
    return () => clearInterval(interval)
  }, [])

  const loadSessions = async () => {
    try {
      const response = await fetch(getApiUrl('/api/advanced-pentest/sessions/list'))
      const data = await response.json()
      setSessions(data.sessions || [])
    } catch (error) {
      console.error('Failed to load sessions:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const registerNewSession = () => {
    // Show modal to register new session
    toast.success('Session registration modal would open here')
  }

  const handleEscalatePrivileges = async () => {
    if (!selectedSession) return
    
    if (!confirm(`Escalate privileges on ${selectedSession.hostname}? This requires authorization.`)) {
      return
    }

    toast.loading('Escalating privileges...', { id: 'escalate' })
    try {
      const response = await fetch(getApiUrl('/api/advanced-pentest/post-exploit/escalate'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId: selectedSession.id })
      })

      const data = await response.json()
      
      if (response.ok && data.success) {
        toast.success(`Privileges escalated: ${data.originalPrivileges} → ${data.newPrivileges}`, { id: 'escalate' })
      } else {
        toast.error(data.message || 'Escalation failed', { id: 'escalate' })
      }
    } catch (error) {
      toast.error('Escalation request failed', { id: 'escalate' })
    }
  }

  const handleHarvestCredentials = async () => {
    if (!selectedSession) return
    
    if (!confirm(`Harvest credentials on ${selectedSession.hostname}? This requires authorization.`)) {
      return
    }

    toast.loading('Harvesting credentials...', { id: 'harvest' })
    try {
      const response = await fetch(getApiUrl('/api/advanced-pentest/post-exploit/harvest-credentials'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId: selectedSession.id })
      })

      const data = await response.json()
      
      if (response.ok) {
        const credCount = Array.isArray(data) ? data.length : (data.credentials?.length || 0)
        toast.success(`Harvested ${credCount} credentials`, { id: 'harvest' })
      } else {
        toast.error('Credential harvesting failed', { id: 'harvest' })
      }
    } catch (error) {
      toast.error('Harvesting request failed', { id: 'harvest' })
    }
  }

  const handleEstablishPersistence = async () => {
    if (!selectedSession) return
    
    if (!confirm(`Establish persistence on ${selectedSession.hostname}? This requires authorization.`)) {
      return
    }

    toast.loading('Establishing persistence...', { id: 'persistence' })
    try {
      const response = await fetch(getApiUrl('/api/advanced-pentest/post-exploit/establish-persistence'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId: selectedSession.id })
      })

      const data = await response.json()
      
      if (response.ok && data.success) {
        toast.success(`Persistence established using ${data.method}`, { id: 'persistence' })
      } else {
        toast.error('Persistence establishment failed', { id: 'persistence' })
      }
    } catch (error) {
      toast.error('Persistence request failed', { id: 'persistence' })
    }
  }

  const getPrivilegeColor = (priv: string) => {
    switch (priv) {
      case 'system': return 'text-red-500'
      case 'high': return 'text-orange-500'
      case 'medium': return 'text-yellow-500'
      default: return 'text-gray-500'
    }
  }

  const getOSIcon = (os: string) => {
    return <Server className="w-4 h-4" />
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold flex items-center gap-3">
              <Target className="w-8 h-8 text-red-500" />
              Command & Control Dashboard
            </h1>
            <p className="text-gray-400 mt-2">
              Manage compromised systems and execute post-exploitation operations
            </p>
          </div>
          <button
            onClick={registerNewSession}
            className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded flex items-center gap-2 transition-colors"
          >
            <Plus className="w-4 h-4" />
            Register Session
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-6 border-b border-gray-700">
        <div className="flex gap-4">
          <button
            onClick={() => setActiveTab('sessions')}
            className={`px-4 py-2 border-b-2 transition-colors ${
              activeTab === 'sessions'
                ? 'border-red-500 text-red-500'
                : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            Active Sessions ({sessions.length})
          </button>
          <button
            onClick={() => setActiveTab('credentials')}
            className={`px-4 py-2 border-b-2 transition-colors ${
              activeTab === 'credentials'
                ? 'border-red-500 text-red-500'
                : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            Harvested Credentials
          </button>
          <button
            onClick={() => setActiveTab('persistence')}
            className={`px-4 py-2 border-b-2 transition-colors ${
              activeTab === 'persistence'
                ? 'border-red-500 text-red-500'
                : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            Persistence Mechanisms
          </button>
        </div>
      </div>

      {/* Active Sessions Panel */}
      {activeTab === 'sessions' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Sessions List */}
          <div className="space-y-4">
            <h2 className="text-xl font-semibold mb-4">Compromised Systems</h2>
            {isLoading ? (
              <div className="text-center py-8 text-gray-400">Loading sessions...</div>
            ) : sessions.length === 0 ? (
              <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-8 text-center">
                <Target className="w-12 h-12 text-gray-600 mx-auto mb-3" />
                <p className="text-gray-400">No active sessions</p>
                <p className="text-sm text-gray-500 mt-2">
                  Register a compromised system to begin post-exploitation operations
                </p>
              </div>
            ) : (
              sessions.map((session) => (
                <div
                  key={session.id}
                  onClick={() => setSelectedSession(session)}
                  className={`bg-gray-800/50 border rounded-lg p-4 cursor-pointer transition-all hover:border-red-500/50 ${
                    selectedSession?.id === session.id
                      ? 'border-red-500'
                      : 'border-gray-700'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3">
                      {getOSIcon(session.os)}
                      <div>
                        <h3 className="font-semibold">{session.hostname}</h3>
                        <p className="text-sm text-gray-400">{session.ip}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Activity className="w-4 h-4 text-green-500 animate-pulse" />
                      <span className="text-xs text-green-400">Active</span>
                    </div>
                  </div>
                  <div className="mt-3 flex items-center gap-4 text-xs">
                    <span className="text-gray-400">
                      User: <span className="text-white">{session.user}</span>
                    </span>
                    <span className="text-gray-400">
                      Privileges: <span className={getPrivilegeColor(session.privileges)}>{session.privileges}</span>
                    </span>
                    <span className="text-gray-400">
                      OS: <span className="text-white">{session.os} {session.osVersion}</span>
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Session Details */}
          <div>
            <h2 className="text-xl font-semibold mb-4">Session Operations</h2>
            {selectedSession ? (
              <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-6">
                <h3 className="text-lg font-semibold mb-4">{selectedSession.hostname}</h3>
                
                <div className="space-y-3">
                  <button 
                    onClick={handleEscalatePrivileges}
                    className="w-full px-4 py-3 bg-orange-600 hover:bg-orange-700 rounded text-left flex items-center gap-3 transition-colors"
                  >
                    <CheckCircle className="w-5 h-5" />
                    <div>
                      <div className="font-medium">Escalate Privileges</div>
                      <div className="text-xs text-orange-200">Attempt automated privilege escalation</div>
                    </div>
                    <ChevronRight className="w-5 h-5 ml-auto" />
                  </button>

                  <button 
                    onClick={handleHarvestCredentials}
                    className="w-full px-4 py-3 bg-purple-600 hover:bg-purple-700 rounded text-left flex items-center gap-3 transition-colors"
                  >
                    <Server className="w-5 h-5" />
                    <div>
                      <div className="font-medium">Harvest Credentials</div>
                      <div className="text-xs text-purple-200">Extract credentials from memory and files</div>
                    </div>
                    <ChevronRight className="w-5 h-5 ml-auto" />
                  </button>

                  <button 
                    onClick={() => navigate('/red-team-ops')}
                    className="w-full px-4 py-3 bg-blue-600 hover:bg-blue-700 rounded text-left flex items-center gap-3 transition-colors"
                  >
                    <Activity className="w-5 h-5" />
                    <div>
                      <div className="font-medium">Lateral Movement</div>
                      <div className="text-xs text-blue-200">Move to other systems in the network</div>
                    </div>
                    <ChevronRight className="w-5 h-5 ml-auto" />
                  </button>

                  <button 
                    onClick={handleEstablishPersistence}
                    className="w-full px-4 py-3 bg-green-600 hover:bg-green-700 rounded text-left flex items-center gap-3 transition-colors"
                  >
                    <Target className="w-5 h-5" />
                    <div>
                      <div className="font-medium">Establish Persistence</div>
                      <div className="text-xs text-green-200">Create persistence mechanisms</div>
                    </div>
                    <ChevronRight className="w-5 h-5 ml-auto" />
                  </button>

                  <button className="w-full px-4 py-3 bg-red-600 hover:bg-red-700 rounded text-left flex items-center gap-3 transition-colors">
                    <XCircle className="w-5 h-5" />
                    <div>
                      <div className="font-medium">Terminate Session</div>
                      <div className="text-xs text-red-200">Close this session and clean up</div>
                    </div>
                    <ChevronRight className="w-5 h-5 ml-auto" />
                  </button>
                </div>
              </div>
            ) : (
              <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-8 text-center">
                <AlertTriangle className="w-12 h-12 text-gray-600 mx-auto mb-3" />
                <p className="text-gray-400">Select a session to view operations</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Credentials Tab */}
      {activeTab === 'credentials' && (
        <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-6">
          <h2 className="text-xl font-semibold mb-4">Harvested Credentials</h2>
          <p className="text-gray-400">No credentials harvested yet. Run credential harvesting on active sessions.</p>
        </div>
      )}

      {/* Persistence Tab */}
      {activeTab === 'persistence' && (
        <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-6">
          <h2 className="text-xl font-semibold mb-4">Persistence Mechanisms</h2>
          <p className="text-gray-400">No persistence mechanisms established. Run persistence operations on active sessions.</p>
        </div>
      )}

      {/* Legal Warning */}
      <div className="mt-8 bg-amber-900/20 border border-amber-600/30 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-500 mt-0.5" />
          <div>
            <h3 className="font-semibold text-amber-400 mb-1">Legal Authorization Required</h3>
            <p className="text-sm text-amber-200">
              All post-exploitation operations require explicit written authorization. Unauthorized access
              to computer systems is illegal and may result in criminal charges.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default CommandControl

