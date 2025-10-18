import React, { useState } from 'react'
import { Code, Database, AlertCircle, CheckCircle } from 'lucide-react'
import toast from 'react-hot-toast'
import { getApiUrl } from '../../../../config/api.config'

interface GraphQLSecurityPanelProps {
  onResult?: (result: any) => void
}

const GraphQLSecurityPanel: React.FC<GraphQLSecurityPanelProps> = ({ onResult }) => {
  const [endpoint, setEndpoint] = useState('')
  const [isRunning, setIsRunning] = useState(false)
  const [result, setResult] = useState<any>(null)

  const handleTest = async () => {
    if (!endpoint.trim()) {
      toast.error('Please enter a GraphQL endpoint')
      return
    }

    setIsRunning(true)
    try {
      const response = await fetch(getApiUrl('/api/advanced-pentest/web-security/test-graphql'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ endpoint })
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || 'GraphQL testing failed')
      }

      setResult(data)
      onResult?.(data)
      
      const vulnCount = data.vulnerabilities?.length || 0
      if (vulnCount > 0) {
        toast.success(`Found ${vulnCount} GraphQL vulnerabilities`)
      } else {
        toast.success('GraphQL security test completed')
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      toast.error(`Failed to test GraphQL: ${message}`)
    } finally {
      setIsRunning(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <Code className="w-6 h-6 text-cyan-500" />
          <h3 className="text-xl font-semibold">GraphQL Security Testing</h3>
        </div>

        <p className="text-gray-400 text-sm mb-6">
          Test GraphQL endpoints for vulnerabilities including introspection leaks, query complexity attacks, 
          batching abuse, field duplication, directive overloading, and injection flaws.
        </p>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">GraphQL Endpoint URL</label>
            <input
              type="text"
              value={endpoint}
              onChange={(e) => setEndpoint(e.target.value)}
              placeholder="e.g., https://example.com/graphql"
              className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <button
            onClick={handleTest}
            disabled={isRunning}
            className="w-full px-4 py-3 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded flex items-center justify-center gap-2 font-medium transition-colors"
          >
            {isRunning ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Testing GraphQL...
              </>
            ) : (
              <>
                <Database className="w-5 h-5" />
                Test GraphQL Security
              </>
            )}
          </button>

          {result && (
            <div className="mt-6 space-y-4">
              <div className="p-4 bg-gray-900 border border-gray-700 rounded-lg">
                <h4 className="font-semibold text-white mb-3 flex items-center gap-2">
                  <CheckCircle className="w-5 h-5 text-green-500" />
                  Test Results
                </h4>
                
                <div className="grid grid-cols-2 gap-4 text-sm mb-4">
                  <div className="p-3 bg-gray-800 rounded">
                    <div className="text-gray-400 text-xs">Introspection</div>
                    <div className={`font-semibold ${result.introspectionEnabled ? 'text-red-400' : 'text-green-400'}`}>
                      {result.introspectionEnabled ? 'Enabled (Risk)' : 'Disabled'}
                    </div>
                  </div>
                  <div className="p-3 bg-gray-800 rounded">
                    <div className="text-gray-400 text-xs">Vulnerabilities</div>
                    <div className="font-semibold text-yellow-400">
                      {result.vulnerabilities?.length || 0} Found
                    </div>
                  </div>
                </div>

                {result.vulnerabilities && result.vulnerabilities.length > 0 && (
                  <div className="space-y-2">
                    <h5 className="text-sm font-semibold text-gray-300">Vulnerabilities:</h5>
                    {result.vulnerabilities.map((vuln: any, index: number) => (
                      <div key={index} className="p-3 bg-gray-950 border border-gray-800 rounded">
                        <div className="flex items-start gap-2 mb-2">
                          <AlertCircle className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
                          <div className="flex-1">
                            <div className="text-white font-medium text-sm">{vuln.type || 'Vulnerability'}</div>
                            {vuln.severity && (
                              <span className={`text-xs px-2 py-0.5 rounded ${
                                vuln.severity === 'high' ? 'bg-red-900/50 text-red-300' :
                                vuln.severity === 'medium' ? 'bg-yellow-900/50 text-yellow-300' :
                                'bg-blue-900/50 text-blue-300'
                              }`}>
                                {vuln.severity}
                              </span>
                            )}
                          </div>
                        </div>
                        {vuln.description && (
                          <p className="text-gray-400 text-xs mb-2">{vuln.description}</p>
                        )}
                        {vuln.recommendation && (
                          <div className="text-xs text-green-400 mt-2">
                            <strong>Fix:</strong> {vuln.recommendation}
                          </div>
                        )}
                      </div>
                    ))}
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

export default GraphQLSecurityPanel

