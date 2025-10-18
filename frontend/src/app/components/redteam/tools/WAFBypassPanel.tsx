import React, { useState } from 'react'
import { Shield, Play, CheckCircle } from 'lucide-react'
import toast from 'react-hot-toast'
import { getApiUrl } from '../../../../config/api.config'

const WAFBypassPanel: React.FC<{onResult?: (result: any) => void}> = ({ onResult }) => {
  const [payload, setPayload] = useState('')
  const [attackType, setAttackType] = useState('sql')
  const [isRunning, setIsRunning] = useState(false)
  const [result, setResult] = useState<any>(null)

  const attackTypes = [
    { value: 'sql', label: 'SQL Injection' },
    { value: 'xss', label: 'Cross-Site Scripting (XSS)' },
    { value: 'cmd', label: 'Command Injection' },
    { value: 'path', label: 'Path Traversal' },
    { value: 'xxe', label: 'XXE Injection' },
  ]

  const handleBypass = async () => {
    if (!payload.trim()) {
      toast.error('Please enter a payload')
      return
    }

    setIsRunning(true)
    try {
      const response = await fetch(getApiUrl('/api/advanced-pentest/evasion/bypass-waf'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload, attackType })
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || 'WAF bypass failed')
      }

      setResult(data)
      onResult?.(data)
      
      const variantCount = data.variants?.length || 0
      toast.success(`Generated ${variantCount} WAF bypass variants`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      toast.error(`WAF bypass failed: ${message}`)
    } finally {
      setIsRunning(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <Shield className="w-6 h-6 text-red-500" />
          <h3 className="text-xl font-semibold">WAF Bypass</h3>
        </div>

        <p className="text-gray-400 text-sm mb-6">
          Generate WAF bypass payloads using encoding variations, character set manipulation, 
          HTTP parameter pollution, multipart encoding abuse, and other advanced techniques.
        </p>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Attack Type</label>
            <select
              value={attackType}
              onChange={(e) => setAttackType(e.target.value)}
              className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white focus:border-red-500 focus:outline-none"
            >
              {attackTypes.map((type) => (
                <option key={type.value} value={type.value}>
                  {type.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Original Payload</label>
            <textarea
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              rows={4}
              placeholder="Enter your original attack payload..."
              className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:border-red-500 focus:outline-none font-mono text-sm"
            />
          </div>

          <button
            onClick={handleBypass}
            disabled={isRunning}
            className="w-full px-4 py-3 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded flex items-center justify-center gap-2 font-medium transition-colors"
          >
            {isRunning ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Generating Bypasses...
              </>
            ) : (
              <>
                <Play className="w-5 h-5" />
                Generate WAF Bypasses
              </>
            )}
          </button>

          {result && result.variants && result.variants.length > 0 && (
            <div className="mt-6 p-4 bg-gray-900 border border-gray-700 rounded-lg">
              <div className="flex items-center gap-2 mb-3">
                <CheckCircle className="w-5 h-5 text-green-500" />
                <h4 className="font-semibold text-white">
                  Generated {result.variants.length} Bypass Variants
                </h4>
              </div>

              <div className="space-y-2 max-h-96 overflow-y-auto">
                {result.variants.map((variant: any, index: number) => (
                  <div key={index} className="p-3 bg-gray-950 border border-gray-800 rounded">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs text-gray-400">Variant #{index + 1}</span>
                      <span className="text-xs px-2 py-1 bg-red-900/30 text-red-300 rounded">
                        {variant.technique || 'Encoding'}
                      </span>
                    </div>
                    <pre className="bg-gray-900 p-2 rounded text-xs text-green-300 overflow-x-auto">
                      {variant.payload}
                    </pre>
                    {variant.description && (
                      <div className="mt-2 text-xs text-gray-400">
                        {variant.description}
                      </div>
                    )}
                  </div>
                ))}
              </div>

              {result.recommendation && (
                <div className="mt-4 p-3 bg-blue-900/20 rounded text-xs text-blue-300">
                  <strong>Testing Tip:</strong> {result.recommendation}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default WAFBypassPanel

