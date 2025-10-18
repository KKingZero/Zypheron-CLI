import React, { useState } from 'react'
import { Shield, ChevronUp, AlertTriangle, CheckCircle, XCircle } from 'lucide-react'
import toast from 'react-hot-toast'
import { getApiUrl } from '../../../../config/api.config'

interface PrivilegeEscalationPanelProps {
  onResult?: (result: any) => void
}

const PrivilegeEscalationPanel: React.FC<PrivilegeEscalationPanelProps> = ({ onResult }) => {
  const [sessionId, setSessionId] = useState('')
  const [isRunning, setIsRunning] = useState(false)
  const [result, setResult] = useState<any>(null)

  const handleEscalate = async () => {
    if (!sessionId.trim()) {
      toast.error('Please enter a session ID')
      return
    }

    // User confirmation check
    if (!confirm(`Are you authorized to escalate privileges on session ${sessionId}? This action requires explicit permission.`)) {
      toast('Privilege escalation cancelled', { icon: '⚠️' })
      return
    }

    setIsRunning(true)
    try {
      const response = await fetch(getApiUrl('/api/advanced-pentest/post-exploit/escalate'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId })
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || 'Escalation failed')
      }

      setResult(data)
      onResult?.(data)
      
      if (data.success) {
        toast.success(`Privileges escalated: ${data.originalPrivileges || 'low'} → ${data.newPrivileges || 'high'}`)
      } else {
        toast.error(data.message || 'Privilege escalation failed')
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      toast.error(`Failed to escalate privileges: ${message}`)
    } finally {
      setIsRunning(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <Shield className="w-6 h-6 text-orange-500" />
          <h3 className="text-xl font-semibold">Privilege Escalation</h3>
        </div>

        <p className="text-gray-400 text-sm mb-6">
          Automatically escalate privileges on a compromised system using multiple techniques including 
          kernel exploits, misconfigurations, SUID binaries, and token manipulation.
        </p>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Session ID</label>
            <input
              type="text"
              value={sessionId}
              onChange={(e) => setSessionId(e.target.value)}
              placeholder="e.g., session-001"
              className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:border-orange-500 focus:outline-none"
            />
            <p className="text-xs text-gray-500 mt-1">
              Enter the session ID of the compromised system
            </p>
          </div>

          <button
            onClick={handleEscalate}
            disabled={isRunning}
            className="w-full px-4 py-3 bg-orange-600 hover:bg-orange-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded flex items-center justify-center gap-2 font-medium transition-colors"
          >
            {isRunning ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Escalating...
              </>
            ) : (
              <>
                <ChevronUp className="w-5 h-5" />
                Escalate Privileges
              </>
            )}
          </button>

          {result && (
            <div className="mt-6 p-4 bg-gray-900 border border-gray-700 rounded-lg">
              <div className="flex items-center gap-2 mb-3">
                {result.success ? (
                  <CheckCircle className="w-5 h-5 text-green-500" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-500" />
                )}
                <h4 className="font-semibold text-white">
                  {result.success ? 'Escalation Successful' : 'Escalation Failed'}
                </h4>
              </div>
              
              <div className="space-y-2 text-sm">
                {result.method && (
                  <div className="flex justify-between items-center py-1">
                    <span className="text-gray-400">Method:</span>
                    <span className="text-green-400 font-mono">{result.method}</span>
                  </div>
                )}
                {result.originalPrivileges && (
                  <div className="flex justify-between items-center py-1">
                    <span className="text-gray-400">Original Privileges:</span>
                    <span className="text-yellow-400">{result.originalPrivileges}</span>
                  </div>
                )}
                {result.newPrivileges && (
                  <div className="flex justify-between items-center py-1">
                    <span className="text-gray-400">New Privileges:</span>
                    <span className="text-green-400 font-semibold">{result.newPrivileges}</span>
                  </div>
                )}
                {result.evidence && result.evidence.length > 0 && (
                  <div className="mt-4">
                    <span className="text-gray-400 block mb-2">Evidence:</span>
                    <div className="text-xs text-gray-300 space-y-1 bg-gray-950 p-3 rounded">
                      {result.evidence.map((e: string, i: number) => (
                        <div key={i} className="flex items-start gap-2">
                          <span className="text-green-500">•</span>
                          <span>{e}</span>
                        </div>
                      ))}
                    </div>
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
            <p>Privilege escalation requires explicit authorization. Only use on systems you have permission to test.</p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default PrivilegeEscalationPanel

