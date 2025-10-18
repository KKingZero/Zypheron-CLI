import React, { useState } from 'react'
import { Shield, Play, CheckCircle } from 'lucide-react'
import toast from 'react-hot-toast'
import { getApiUrl } from '../../../../config/api.config'

const IDSEvasionPanel: React.FC<{onResult?: (result: any) => void}> = ({ onResult }) => {
  const [payload, setPayload] = useState('')
  const [target, setTarget] = useState('')
  const [isRunning, setIsRunning] = useState(false)
  const [result, setResult] = useState<any>(null)

  const handleEvade = async () => {
    if (!payload.trim() || !target.trim()) {
      toast.error('Please enter payload and target')
      return
    }

    setIsRunning(true)
    try {
      const response = await fetch(getApiUrl('/api/advanced-pentest/evasion/evade-ids'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload, target })
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || 'IDS evasion failed')
      }

      setResult(data)
      onResult?.(data)
      toast.success('IDS evasion payload generated')
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      toast.error(`IDS evasion failed: ${message}`)
    } finally {
      setIsRunning(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <Shield className="w-6 h-6 text-indigo-500" />
          <h3 className="text-xl font-semibold">IDS/IPS Evasion</h3>
        </div>

        <p className="text-gray-400 text-sm mb-6">
          Generate evasive payloads using packet fragmentation, protocol manipulation, timing attacks, 
          and polymorphic techniques to bypass intrusion detection systems.
        </p>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Original Payload</label>
            <textarea
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              rows={3}
              placeholder="Enter your original payload..."
              className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:border-indigo-500 focus:outline-none font-mono text-sm"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Target System</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g., 192.168.1.100"
              className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:border-indigo-500 focus:outline-none"
            />
          </div>

          <button
            onClick={handleEvade}
            disabled={isRunning}
            className="w-full px-4 py-3 bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded flex items-center justify-center gap-2 font-medium transition-colors"
          >
            {isRunning ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Generating...
              </>
            ) : (
              <>
                <Play className="w-5 h-5" />
                Generate Evasive Payload
              </>
            )}
          </button>

          {result && (
            <div className="mt-6 p-4 bg-gray-900 border border-gray-700 rounded-lg">
              <div className="flex items-center gap-2 mb-3">
                <CheckCircle className="w-5 h-5 text-green-500" />
                <h4 className="font-semibold text-white">Evasive Payload Generated</h4>
              </div>

              {result.evadedPayload && (
                <div className="space-y-3">
                  <div>
                    <div className="text-xs text-gray-400 mb-2">Evasion Technique:</div>
                    <div className="text-sm text-green-400 font-mono">{result.technique || 'Multiple techniques'}</div>
                  </div>
                  
                  <div>
                    <div className="text-xs text-gray-400 mb-2">Evaded Payload:</div>
                    <pre className="bg-gray-950 p-3 rounded text-xs text-green-300 overflow-x-auto">
                      {result.evadedPayload}
                    </pre>
                  </div>

                  {result.notes && (
                    <div className="p-3 bg-blue-900/20 rounded text-xs text-blue-300">
                      <strong>Note:</strong> {result.notes}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default IDSEvasionPanel

