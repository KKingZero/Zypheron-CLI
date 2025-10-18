import React, { useState } from 'react'
import { Lock, Eye, AlertCircle, CheckCircle } from 'lucide-react'
import toast from 'react-hot-toast'
import { getApiUrl } from '../../../../config/api.config'

interface JWTAnalyzerPanelProps {
  onResult?: (result: any) => void
}

const JWTAnalyzerPanel: React.FC<JWTAnalyzerPanelProps> = ({ onResult }) => {
  const [token, setToken] = useState('')
  const [isRunning, setIsRunning] = useState(false)
  const [result, setResult] = useState<any>(null)

  const handleAnalyze = async () => {
    if (!token.trim()) {
      toast.error('Please enter a JWT token')
      return
    }

    setIsRunning(true)
    try {
      const response = await fetch(getApiUrl('/api/advanced-pentest/web-security/test-jwt'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || 'JWT analysis failed')
      }

      setResult(data)
      onResult?.(data)
      
      const vulnCount = data.vulnerabilities?.length || 0
      if (vulnCount > 0) {
        toast.success(`Found ${vulnCount} JWT vulnerabilities`, { icon: '⚠️' })
      } else {
        toast.success('JWT analysis completed')
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      toast.error(`JWT analysis failed: ${message}`)
    } finally {
      setIsRunning(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <Lock className="w-6 h-6 text-indigo-500" />
          <h3 className="text-xl font-semibold">JWT/OAuth Analyzer</h3>
        </div>

        <p className="text-gray-400 text-sm mb-6">
          Analyze JWT tokens for algorithm confusion, weak secrets, token manipulation, 
          missing validation, expired tokens, and insecure claims.
        </p>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">JWT Token</label>
            <textarea
              value={token}
              onChange={(e) => setToken(e.target.value)}
              rows={5}
              placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
              className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:border-indigo-500 focus:outline-none font-mono text-xs"
            />
          </div>

          <button
            onClick={handleAnalyze}
            disabled={isRunning}
            className="w-full px-4 py-3 bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded flex items-center justify-center gap-2 font-medium transition-colors"
          >
            {isRunning ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Analyzing...
              </>
            ) : (
              <>
                <Eye className="w-5 h-5" />
                Analyze JWT Token
              </>
            )}
          </button>

          {result && (
            <div className="mt-6 space-y-4">
              {/* Decoded Token */}
              {result.decoded && (
                <div className="p-4 bg-gray-900 border border-gray-700 rounded-lg">
                  <h4 className="font-semibold text-white mb-3 flex items-center gap-2">
                    <CheckCircle className="w-5 h-5 text-green-500" />
                    Decoded Token
                  </h4>
                  
                  <div className="space-y-3">
                    {result.decoded.header && (
                      <div>
                        <div className="text-xs text-gray-400 mb-1">Header:</div>
                        <pre className="bg-gray-950 p-3 rounded text-xs text-blue-300 overflow-x-auto">
                          {JSON.stringify(result.decoded.header, null, 2)}
                        </pre>
                      </div>
                    )}
                    {result.decoded.payload && (
                      <div>
                        <div className="text-xs text-gray-400 mb-1">Payload:</div>
                        <pre className="bg-gray-950 p-3 rounded text-xs text-green-300 overflow-x-auto">
                          {JSON.stringify(result.decoded.payload, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Analysis Results */}
              <div className="p-4 bg-gray-900 border border-gray-700 rounded-lg">
                <h4 className="font-semibold text-white mb-3">Security Analysis</h4>
                
                <div className="grid grid-cols-2 gap-3 mb-4">
                  <div className="p-3 bg-gray-800 rounded">
                    <div className="text-xs text-gray-400">Algorithm</div>
                    <div className={`font-semibold ${
                      result.algorithm === 'none' ? 'text-red-400' : 
                      result.algorithm === 'HS256' ? 'text-yellow-400' : 
                      'text-green-400'
                    }`}>
                      {result.algorithm || 'Unknown'}
                    </div>
                  </div>
                  <div className="p-3 bg-gray-800 rounded">
                    <div className="text-xs text-gray-400">Expired</div>
                    <div className={`font-semibold ${result.expired ? 'text-red-400' : 'text-green-400'}`}>
                      {result.expired ? 'Yes' : 'No'}
                    </div>
                  </div>
                </div>

                {result.vulnerabilities && result.vulnerabilities.length > 0 && (
                  <div className="space-y-2">
                    <h5 className="text-sm font-semibold text-gray-300">Vulnerabilities:</h5>
                    {result.vulnerabilities.map((vuln: any, index: number) => (
                      <div key={index} className="p-3 bg-gray-950 border border-gray-800 rounded">
                        <div className="flex items-start gap-2">
                          <AlertCircle className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
                          <div className="flex-1">
                            <div className="text-white font-medium text-sm">{vuln.type}</div>
                            <div className="text-gray-400 text-xs mt-1">{vuln.description}</div>
                            {vuln.severity && (
                              <span className={`inline-block mt-2 text-xs px-2 py-0.5 rounded ${
                                vuln.severity === 'critical' ? 'bg-red-900/50 text-red-300' :
                                vuln.severity === 'high' ? 'bg-orange-900/50 text-orange-300' :
                                vuln.severity === 'medium' ? 'bg-yellow-900/50 text-yellow-300' :
                                'bg-blue-900/50 text-blue-300'
                              }`}>
                                {vuln.severity}
                              </span>
                            )}
                            {vuln.recommendation && (
                              <div className="mt-2 p-2 bg-green-900/20 rounded text-xs text-green-300">
                                <strong>Fix:</strong> {vuln.recommendation}
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {(!result.vulnerabilities || result.vulnerabilities.length === 0) && (
                  <div className="p-3 bg-green-900/20 border border-green-700/30 rounded text-center">
                    <CheckCircle className="w-6 h-6 text-green-500 mx-auto mb-2" />
                    <p className="text-green-300 text-sm">No obvious vulnerabilities detected</p>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default JWTAnalyzerPanel

