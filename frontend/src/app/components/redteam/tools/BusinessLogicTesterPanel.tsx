import React, { useState } from 'react'
import { AlertTriangle, Play, CheckCircle } from 'lucide-react'
import toast from 'react-hot-toast'
import { getApiUrl } from '../../../../config/api.config'

interface BusinessLogicTesterPanelProps {
  onResult?: (result: any) => void
}

const BusinessLogicTesterPanel: React.FC<BusinessLogicTesterPanelProps> = ({ onResult }) => {
  const [appUrl, setAppUrl] = useState('')
  const [appName, setAppName] = useState('')
  const [hasPayments, setHasPayments] = useState(false)
  const [endpoints, setEndpoints] = useState('')
  const [isRunning, setIsRunning] = useState(false)
  const [result, setResult] = useState<any>(null)

  const handleTest = async () => {
    if (!appUrl.trim() || !appName.trim()) {
      toast.error('Please enter application URL and name')
      return
    }

    const endpointList = endpoints.split('\n').map(e => e.trim()).filter(Boolean)

    setIsRunning(true)
    try {
      const response = await fetch(getApiUrl('/api/advanced-pentest/web-security/test-business-logic'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          appUrl, 
          appName, 
          hasPayments, 
          endpoints: endpointList 
        })
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || 'Testing failed')
      }

      setResult(data)
      onResult?.(data)
      
      const flawCount = data.flaws?.length || 0
      if (flawCount > 0) {
        toast.success(`Found ${flawCount} business logic flaws`)
      } else {
        toast.success('Business logic testing completed')
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      toast.error(`Testing failed: ${message}`)
    } finally {
      setIsRunning(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <AlertTriangle className="w-6 h-6 text-orange-500" />
          <h3 className="text-xl font-semibold">Business Logic Testing</h3>
        </div>

        <p className="text-gray-400 text-sm mb-6">
          Test for business logic vulnerabilities including race conditions, payment manipulation, 
          privilege escalation, workflow bypass, and resource exhaustion.
        </p>

        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Application URL</label>
              <input
                type="text"
                value={appUrl}
                onChange={(e) => setAppUrl(e.target.value)}
                placeholder="e.g., https://shop.example.com"
                className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:border-orange-500 focus:outline-none"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Application Name</label>
              <input
                type="text"
                value={appName}
                onChange={(e) => setAppName(e.target.value)}
                placeholder="e.g., E-Commerce Shop"
                className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:border-orange-500 focus:outline-none"
              />
            </div>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="hasPayments"
              checked={hasPayments}
              onChange={(e) => setHasPayments(e.target.checked)}
              className="w-4 h-4 rounded border-gray-700 bg-gray-900 text-orange-500 focus:ring-orange-500"
            />
            <label htmlFor="hasPayments" className="text-sm text-gray-300">
              Application has payment processing
            </label>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Endpoints (one per line, optional)
            </label>
            <textarea
              value={endpoints}
              onChange={(e) => setEndpoints(e.target.value)}
              rows={4}
              placeholder="/api/checkout&#10;/api/cart&#10;/api/orders"
              className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:border-orange-500 focus:outline-none font-mono text-sm"
            />
          </div>

          <button
            onClick={handleTest}
            disabled={isRunning}
            className="w-full px-4 py-3 bg-orange-600 hover:bg-orange-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded flex items-center justify-center gap-2 font-medium transition-colors"
          >
            {isRunning ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Testing...
              </>
            ) : (
              <>
                <Play className="w-5 h-5" />
                Test Business Logic
              </>
            )}
          </button>

          {result && (
            <div className="mt-6 p-4 bg-gray-900 border border-gray-700 rounded-lg">
              <div className="flex items-center gap-2 mb-4">
                <CheckCircle className="w-5 h-5 text-green-500" />
                <h4 className="font-semibold text-white">Test Results</h4>
              </div>
              
              <div className="grid grid-cols-4 gap-2 mb-4">
                <div className="p-2 bg-gray-800 rounded text-center">
                  <div className="text-xs text-gray-400">Race Conditions</div>
                  <div className="text-lg font-semibold text-red-400">{result.raceConditions || 0}</div>
                </div>
                <div className="p-2 bg-gray-800 rounded text-center">
                  <div className="text-xs text-gray-400">Payment Flaws</div>
                  <div className="text-lg font-semibold text-yellow-400">{result.paymentFlaws || 0}</div>
                </div>
                <div className="p-2 bg-gray-800 rounded text-center">
                  <div className="text-xs text-gray-400">Workflow Bypass</div>
                  <div className="text-lg font-semibold text-orange-400">{result.workflowBypass || 0}</div>
                </div>
                <div className="p-2 bg-gray-800 rounded text-center">
                  <div className="text-xs text-gray-400">Total Flaws</div>
                  <div className="text-lg font-semibold text-purple-400">{result.flaws?.length || 0}</div>
                </div>
              </div>

              {result.flaws && result.flaws.length > 0 && (
                <div className="space-y-2">
                  <h5 className="text-sm font-semibold text-gray-300">Business Logic Flaws:</h5>
                  {result.flaws.map((flaw: any, index: number) => (
                    <div key={index} className="p-3 bg-gray-950 border border-gray-800 rounded">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
                        <div className="flex-1">
                          <div className="text-white font-medium text-sm">{flaw.type}</div>
                          <div className="text-gray-400 text-xs mt-1">{flaw.description}</div>
                          {flaw.impact && (
                            <div className="mt-2 text-xs">
                              <span className="text-gray-500">Impact:</span>
                              <span className="text-red-300 ml-2">{flaw.impact}</span>
                            </div>
                          )}
                          {flaw.recommendation && (
                            <div className="mt-2 p-2 bg-green-900/20 rounded text-xs text-green-300">
                              <strong>Fix:</strong> {flaw.recommendation}
                            </div>
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

export default BusinessLogicTesterPanel

