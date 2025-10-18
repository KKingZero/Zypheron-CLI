import React, { useState } from 'react'
import { Key, Database, AlertTriangle, CheckCircle } from 'lucide-react'
import toast from 'react-hot-toast'
import { getApiUrl } from '../../../../config/api.config'

interface CredentialHarvestingPanelProps {
  onResult?: (result: any) => void
}

const CredentialHarvestingPanel: React.FC<CredentialHarvestingPanelProps> = ({ onResult }) => {
  const [sessionId, setSessionId] = useState('')
  const [isRunning, setIsRunning] = useState(false)
  const [result, setResult] = useState<any>(null)

  const handleHarvest = async () => {
    if (!sessionId.trim()) {
      toast.error('Please enter a session ID')
      return
    }

    if (!confirm(`Are you authorized to harvest credentials on session ${sessionId}? This action requires explicit permission.`)) {
      toast('Credential harvesting cancelled', { icon: '⚠️' })
      return
    }

    setIsRunning(true)
    try {
      const response = await fetch(getApiUrl('/api/advanced-pentest/post-exploit/harvest-credentials'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId })
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || 'Harvesting failed')
      }

      setResult(data)
      onResult?.(data)
      
      const credCount = Array.isArray(data) ? data.length : (data.credentials?.length || 0)
      toast.success(`Harvested ${credCount} credentials`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      toast.error(`Failed to harvest credentials: ${message}`)
    } finally {
      setIsRunning(false)
    }
  }

  const credentials = Array.isArray(result) ? result : (result?.credentials || [])

  return (
    <div className="space-y-4">
      <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <Key className="w-6 h-6 text-purple-500" />
          <h3 className="text-xl font-semibold">Credential Harvesting</h3>
        </div>

        <p className="text-gray-400 text-sm mb-6">
          Extract credentials from memory, files, and system stores using techniques like Mimikatz, 
          browser password extraction, SSH key discovery, and cached credential extraction.
        </p>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Session ID</label>
            <input
              type="text"
              value={sessionId}
              onChange={(e) => setSessionId(e.target.value)}
              placeholder="e.g., session-001"
              className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:border-purple-500 focus:outline-none"
            />
          </div>

          <button
            onClick={handleHarvest}
            disabled={isRunning}
            className="w-full px-4 py-3 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded flex items-center justify-center gap-2 font-medium transition-colors"
          >
            {isRunning ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Harvesting...
              </>
            ) : (
              <>
                <Database className="w-5 h-5" />
                Harvest Credentials
              </>
            )}
          </button>

          {credentials.length > 0 && (
            <div className="mt-6 p-4 bg-gray-900 border border-gray-700 rounded-lg">
              <div className="flex items-center gap-2 mb-4">
                <CheckCircle className="w-5 h-5 text-green-500" />
                <h4 className="font-semibold text-white">
                  Harvested {credentials.length} Credential{credentials.length !== 1 ? 's' : ''}
                </h4>
              </div>
              
              <div className="space-y-3">
                {credentials.map((cred: any, index: number) => (
                  <div key={index} className="p-3 bg-gray-800 rounded border border-gray-700">
                    <div className="grid grid-cols-2 gap-2 text-sm">
                      {cred.type && (
                        <div>
                          <span className="text-gray-500">Type:</span>
                          <span className="ml-2 text-green-400 font-mono">{cred.type}</span>
                        </div>
                      )}
                      {cred.username && (
                        <div>
                          <span className="text-gray-500">Username:</span>
                          <span className="ml-2 text-blue-400 font-mono">{cred.username}</span>
                        </div>
                      )}
                      {cred.domain && (
                        <div>
                          <span className="text-gray-500">Domain:</span>
                          <span className="ml-2 text-yellow-400">{cred.domain}</span>
                        </div>
                      )}
                      {cred.source && (
                        <div>
                          <span className="text-gray-500">Source:</span>
                          <span className="ml-2 text-purple-400">{cred.source}</span>
                        </div>
                      )}
                    </div>
                    {cred.password && (
                      <div className="mt-2 pt-2 border-t border-gray-700">
                        <span className="text-gray-500 text-xs">Password:</span>
                        <code className="ml-2 text-red-400 text-xs">{'*'.repeat(16)}</code>
                      </div>
                    )}
                  </div>
                ))}
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
            <p>Credential harvesting requires explicit authorization. Handle extracted credentials responsibly.</p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default CredentialHarvestingPanel

