import React, { useState } from 'react'
import { Activity, Lock, AlertTriangle, CheckCircle } from 'lucide-react'
import toast from 'react-hot-toast'
import { getApiUrl } from '../../../../config/api.config'

interface PersistencePanelProps {
  onResult?: (result: any) => void
}

const PersistencePanel: React.FC<PersistencePanelProps> = ({ onResult }) => {
  const [sessionId, setSessionId] = useState('')
  const [method, setMethod] = useState('')
  const [isRunning, setIsRunning] = useState(false)
  const [result, setResult] = useState<any>(null)

  const methods = [
    { value: '', label: 'Auto-select Best Method' },
    { value: 'registry', label: 'Registry Run Keys (Windows)' },
    { value: 'scheduled_task', label: 'Scheduled Task (Windows)' },
    { value: 'service', label: 'Windows Service' },
    { value: 'wmi', label: 'WMI Event Subscription (Windows)' },
    { value: 'cron', label: 'Cron Job (Linux)' },
    { value: 'systemd', label: 'Systemd Service (Linux)' },
    { value: 'bashrc', label: '.bashrc/.profile (Linux)' },
    { value: 'ssh_keys', label: 'SSH Authorized Keys' },
  ]

  const handleEstablish = async () => {
    if (!sessionId.trim()) {
      toast.error('Please enter a session ID')
      return
    }

    if (!confirm(`Are you authorized to establish persistence on session ${sessionId}? This action requires explicit permission.`)) {
      toast('Persistence establishment cancelled', { icon: '⚠️' })
      return
    }

    setIsRunning(true)
    try {
      const response = await fetch(getApiUrl('/api/advanced-pentest/post-exploit/establish-persistence'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId, method: method || undefined })
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || 'Persistence establishment failed')
      }

      setResult(data)
      onResult?.(data)
      
      if (data.success) {
        toast.success(`Persistence established using ${data.method || 'selected method'}`)
      } else {
        toast.error(data.message || 'Persistence establishment failed')
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      toast.error(`Failed to establish persistence: ${message}`)
    } finally {
      setIsRunning(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <Activity className="w-6 h-6 text-green-500" />
          <h3 className="text-xl font-semibold">Establish Persistence</h3>
        </div>

        <p className="text-gray-400 text-sm mb-6">
          Create persistence mechanisms on compromised systems to maintain access across reboots 
          and user logouts using registry keys, scheduled tasks, services, cron jobs, and more.
        </p>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Session ID</label>
            <input
              type="text"
              value={sessionId}
              onChange={(e) => setSessionId(e.target.value)}
              placeholder="e.g., session-001"
              className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:border-green-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Persistence Method</label>
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value)}
              className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white focus:border-green-500 focus:outline-none"
            >
              {methods.map((m) => (
                <option key={m.value} value={m.value}>
                  {m.label}
                </option>
              ))}
            </select>
            <p className="text-xs text-gray-500 mt-1">
              Auto-select will choose the best method based on OS and current privileges
            </p>
          </div>

          <button
            onClick={handleEstablish}
            disabled={isRunning}
            className="w-full px-4 py-3 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded flex items-center justify-center gap-2 font-medium transition-colors"
          >
            {isRunning ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Establishing...
              </>
            ) : (
              <>
                <Lock className="w-5 h-5" />
                Establish Persistence
              </>
            )}
          </button>

          {result && (
            <div className="mt-6 p-4 bg-gray-900 border border-gray-700 rounded-lg">
              <div className="flex items-center gap-2 mb-3">
                {result.success ? (
                  <CheckCircle className="w-5 h-5 text-green-500" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-red-500" />
                )}
                <h4 className="font-semibold text-white">
                  {result.success ? 'Persistence Established' : 'Persistence Failed'}
                </h4>
              </div>
              
              <div className="space-y-2 text-sm">
                {result.method && (
                  <div className="flex justify-between items-center py-1">
                    <span className="text-gray-400">Method Used:</span>
                    <span className="text-green-400 font-mono">{result.method}</span>
                  </div>
                )}
                {result.location && (
                  <div className="py-1">
                    <span className="text-gray-400 block mb-1">Location:</span>
                    <code className="text-blue-400 text-xs bg-gray-950 px-2 py-1 rounded">
                      {result.location}
                    </code>
                  </div>
                )}
                {result.command && (
                  <div className="py-1">
                    <span className="text-gray-400 block mb-1">Command:</span>
                    <code className="text-purple-400 text-xs bg-gray-950 px-2 py-1 rounded block overflow-x-auto">
                      {result.command}
                    </code>
                  </div>
                )}
                {result.cleanup && (
                  <div className="mt-3 p-3 bg-red-900/20 border border-red-700/30 rounded">
                    <p className="text-red-300 text-xs font-semibold mb-1">Cleanup Instructions:</p>
                    <code className="text-red-200 text-xs">{result.cleanup}</code>
                  </div>
                )}
                {result.message && (
                  <div className="mt-3 p-3 bg-gray-800 rounded">
                    <p className="text-gray-300 text-xs">{result.message}</p>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="bg-amber-900/20 border border-amber-600/30 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" />
          <div className="text-sm text-amber-200">
            <strong className="block mb-1">User Confirmation Required</strong>
            <p>Persistence establishment requires explicit authorization. Document all persistence mechanisms for proper cleanup after testing.</p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default PersistencePanel

