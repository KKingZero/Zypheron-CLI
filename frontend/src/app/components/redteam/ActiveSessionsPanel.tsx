import React, { useState, useEffect } from 'react'
import { Activity, ChevronRight } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { getApiUrl } from '../../../config/api.config'

interface Session {
  id: string
  target: string
  hostname: string
  os: 'windows' | 'linux' | 'macos' | 'unknown'
  osVersion: string
  user: string
  privileges: 'low' | 'medium' | 'high' | 'system'
  ip: string
}

const ActiveSessionsPanel: React.FC = () => {
  const navigate = useNavigate()
  const [sessions, setSessions] = useState<Session[]>([])
  const [isLoading, setIsLoading] = useState(true)

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

  const getPrivilegeColor = (priv: string) => {
    switch (priv) {
      case 'system': return 'text-red-500'
      case 'high': return 'text-orange-500'
      case 'medium': return 'text-yellow-500'
      default: return 'text-gray-500'
    }
  }

  return (
    <div className="bg-[#1a1a1a] border border-terminal-border rounded-lg p-6 mb-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Activity className="w-5 h-5 text-green-500" />
          <h3 className="text-lg font-semibold text-white">Active Sessions</h3>
          <span className="px-2 py-1 bg-green-500/20 text-green-400 text-xs rounded">
            {sessions.length} Active
          </span>
        </div>
        <button
          onClick={() => navigate('/command-control')}
          className="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors"
        >
          View All
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>

      {isLoading ? (
        <div className="text-center py-4 text-gray-400 text-sm">
          Loading sessions...
        </div>
      ) : sessions.length === 0 ? (
        <div className="text-center py-4 text-gray-400 text-sm">
          No active sessions. Register a compromised system in Command & Control.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {sessions.slice(0, 3).map((session) => (
            <div
              key={session.id}
              onClick={() => navigate('/command-control')}
              className="bg-[#0d0d0d] border border-terminal-border rounded p-3 cursor-pointer hover:border-red-500/50 transition-colors"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="font-medium text-sm text-white">{session.hostname}</span>
                <Activity className="w-3 h-3 text-green-500 animate-pulse" />
              </div>
              <div className="text-xs text-gray-400 space-y-1">
                <div>IP: {session.ip}</div>
                <div>User: {session.user}</div>
                <div>
                  Privileges: <span className={getPrivilegeColor(session.privileges)}>{session.privileges}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default ActiveSessionsPanel

