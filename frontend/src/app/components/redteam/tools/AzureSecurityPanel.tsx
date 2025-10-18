import React, { useState } from 'react'
import { Cloud, Play, AlertCircle } from 'lucide-react'
import toast from 'react-hot-toast'
import { getApiUrl } from '../../../../config/api.config'

const AzureSecurityPanel: React.FC<{onResult?: (result: any) => void}> = ({ onResult }) => {
  const [isRunning, setIsRunning] = useState(false)
  const [result, setResult] = useState<any>(null)

  const handleAssess = async () => {
    setIsRunning(true)
    try {
      const response = await fetch(getApiUrl('/api/advanced-pentest/cloud-security/assess-azure'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || 'Azure assessment failed')
      }

      setResult(data)
      onResult?.(data)
      
      const issueCount = data.findings?.length || 0
      toast.success(`Azure assessment complete. Found ${issueCount} issues`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      toast.error(`Azure assessment failed: ${message}`)
    } finally {
      setIsRunning(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <Cloud className="w-6 h-6 text-blue-500" />
          <h3 className="text-xl font-semibold">Azure Security Assessment</h3>
        </div>

        <p className="text-gray-400 text-sm mb-6">
          Comprehensive Azure security assessment covering Azure AD, Storage Accounts, Virtual Machines, 
          Managed Identity, Network Security Groups, Key Vault, and more (40+ checks).
        </p>

        <button
          onClick={handleAssess}
          disabled={isRunning}
          className="w-full px-4 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded flex items-center justify-center gap-2 font-medium transition-colors"
        >
          {isRunning ? (
            <>
              <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              Assessing Azure...
            </>
          ) : (
            <>
              <Play className="w-5 h-5" />
              Start Azure Assessment
            </>
          )}
        </button>

        {result && (
          <div className="mt-6 p-4 bg-gray-900 border border-gray-700 rounded-lg">
            <h4 className="font-semibold text-white mb-3">Assessment Results</h4>
            
            <div className="grid grid-cols-4 gap-2 mb-4">
              <div className="p-2 bg-gray-800 rounded text-center">
                <div className="text-xs text-gray-400">Critical</div>
                <div className="text-lg font-semibold text-red-400">
                  {result.findings?.filter((f: any) => f.severity === 'critical').length || 0}
                </div>
              </div>
              <div className="p-2 bg-gray-800 rounded text-center">
                <div className="text-xs text-gray-400">High</div>
                <div className="text-lg font-semibold text-orange-400">
                  {result.findings?.filter((f: any) => f.severity === 'high').length || 0}
                </div>
              </div>
              <div className="p-2 bg-gray-800 rounded text-center">
                <div className="text-xs text-gray-400">Medium</div>
                <div className="text-lg font-semibold text-yellow-400">
                  {result.findings?.filter((f: any) => f.severity === 'medium').length || 0}
                </div>
              </div>
              <div className="p-2 bg-gray-800 rounded text-center">
                <div className="text-xs text-gray-400">Low</div>
                <div className="text-lg font-semibold text-blue-400">
                  {result.findings?.filter((f: any) => f.severity === 'low').length || 0}
                </div>
              </div>
            </div>

            {result.findings && result.findings.length > 0 && (
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {result.findings.slice(0, 10).map((finding: any, index: number) => (
                  <div key={index} className="p-3 bg-gray-950 border border-gray-800 rounded text-sm">
                    <div className="flex items-start gap-2">
                      <AlertCircle className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className="text-white font-medium">{finding.title || finding.type}</span>
                          <span className={`text-xs px-2 py-0.5 rounded ${
                            finding.severity === 'critical' ? 'bg-red-900/50 text-red-300' :
                            finding.severity === 'high' ? 'bg-orange-900/50 text-orange-300' :
                            finding.severity === 'medium' ? 'bg-yellow-900/50 text-yellow-300' :
                            'bg-blue-900/50 text-blue-300'
                          }`}>
                            {finding.severity}
                          </span>
                        </div>
                        <div className="text-gray-400 text-xs mt-1">{finding.description}</div>
                        {finding.resource && (
                          <div className="text-xs text-blue-400 mt-1 font-mono">{finding.resource}</div>
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
  )
}

export default AzureSecurityPanel

