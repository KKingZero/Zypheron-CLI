import React, { useState } from 'react'
import { Zap, Play, AlertCircle } from 'lucide-react'
import toast from 'react-hot-toast'
import { getApiUrl } from '../../../../config/api.config'

interface IntelligentFuzzingPanelProps {
  onResult?: (result: any) => void
}

const IntelligentFuzzingPanel: React.FC<IntelligentFuzzingPanelProps> = ({ onResult }) => {
  const [target, setTarget] = useState('')
  const [params, setParams] = useState('{"id": "1"}')
  const [isRunning, setIsRunning] = useState(false)
  const [result, setResult] = useState<any>(null)

  const handleFuzz = async () => {
    if (!target.trim()) {
      toast.error('Please enter a target URL')
      return
    }

    let parsedParams
    try {
      parsedParams = JSON.parse(params)
    } catch (e) {
      toast.error('Invalid JSON parameters')
      return
    }

    setIsRunning(true)
    try {
      const response = await fetch(getApiUrl('/api/advanced-pentest/web-security/intelligent-fuzzing'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, params: parsedParams })
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || 'Fuzzing failed')
      }

      setResult(data)
      onResult?.(data)
      
      const vulnCount = data.findings?.length || 0
      if (vulnCount > 0) {
        toast.success(`Found ${vulnCount} potential vulnerabilities`)
      } else {
        toast.success('Fuzzing completed')
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      toast.error(`Fuzzing failed: ${message}`)
    } finally {
      setIsRunning(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <Zap className="w-6 h-6 text-yellow-500" />
          <h3 className="text-xl font-semibold">AI-Powered Intelligent Fuzzing</h3>
        </div>

        <p className="text-gray-400 text-sm mb-6">
          Context-aware fuzzing with AI-powered payload generation. Tests for injection, XSS, SSRF, 
          command injection, type confusion, and more using mutation and grammar-based strategies.
        </p>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Target URL</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g., https://example.com/api/user"
              className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:border-yellow-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Parameters (JSON)</label>
            <textarea
              value={params}
              onChange={(e) => setParams(e.target.value)}
              rows={4}
              placeholder='{"id": "1", "name": "test"}'
              className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:border-yellow-500 focus:outline-none font-mono text-sm"
            />
            <p className="text-xs text-gray-500 mt-1">
              Specify parameters to fuzz in JSON format
            </p>
          </div>

          <button
            onClick={handleFuzz}
            disabled={isRunning}
            className="w-full px-4 py-3 bg-yellow-600 hover:bg-yellow-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded flex items-center justify-center gap-2 font-medium transition-colors"
          >
            {isRunning ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Fuzzing...
              </>
            ) : (
              <>
                <Play className="w-5 h-5" />
                Start Fuzzing
              </>
            )}
          </button>

          {result && (
            <div className="mt-6 p-4 bg-gray-900 border border-gray-700 rounded-lg">
              <h4 className="font-semibold text-white mb-3">Fuzzing Results</h4>
              
              <div className="grid grid-cols-3 gap-3 mb-4">
                <div className="p-2 bg-gray-800 rounded text-center">
                  <div className="text-xs text-gray-400">Requests</div>
                  <div className="text-lg font-semibold text-blue-400">{result.totalRequests || 0}</div>
                </div>
                <div className="p-2 bg-gray-800 rounded text-center">
                  <div className="text-xs text-gray-400">Anomalies</div>
                  <div className="text-lg font-semibold text-yellow-400">{result.anomalies || 0}</div>
                </div>
                <div className="p-2 bg-gray-800 rounded text-center">
                  <div className="text-xs text-gray-400">Findings</div>
                  <div className="text-lg font-semibold text-red-400">{result.findings?.length || 0}</div>
                </div>
              </div>

              {result.findings && result.findings.length > 0 && (
                <div className="space-y-2">
                  <h5 className="text-sm font-semibold text-gray-300">Potential Vulnerabilities:</h5>
                  {result.findings.map((finding: any, index: number) => (
                    <div key={index} className="p-3 bg-gray-950 border border-gray-800 rounded">
                      <div className="flex items-start gap-2 mb-2">
                        <AlertCircle className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
                        <div>
                          <div className="text-white font-medium text-sm">{finding.type}</div>
                          <div className="text-gray-400 text-xs mt-1">{finding.description}</div>
                          {finding.payload && (
                            <code className="block mt-2 text-xs bg-gray-900 p-2 rounded text-green-400 overflow-x-auto">
                              {finding.payload}
                            </code>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default IntelligentFuzzingPanel

