import React, { useState } from 'react'
import { Network, ArrowRight, AlertTriangle, CheckCircle } from 'lucide-react'
import toast from 'react-hot-toast'
import { getApiUrl } from '../../../../config/api.config'

interface LateralMovementPanelProps {
  onResult?: (result: any) => void
}

const LateralMovementPanel: React.FC<LateralMovementPanelProps> = ({ onResult }) => {
  const [sessionId, setSessionId] = useState('')
  const [targetHost, setTargetHost] = useState('')
  const [method, setMethod] = useState('')
  const [isRunning, setIsRunning] = useState(false)
  const [result, setResult] = useState<any>(null)

  const methods = [
    { value: '', label: 'Auto-detect' },
    { value: 'psexec', label: 'PsExec (Windows)' },
    { value: 'wmi', label: 'WMI (Windows)' },
    { value: 'winrm', label: 'WinRM (Windows)' },
    { value: 'ssh', label: 'SSH (Linux/Unix)' },
    { value: 'pth', label: 'Pass-the-Hash' },
    { value: 'ptt', label: 'Pass-the-Ticket' },
  ]

  const handleMove = async () => {
    if (!sessionId.trim() || !targetHost.trim()) {
      toast.error('Please enter session ID and target host')
      return
    }

    if (!confirm(`Are you authorized to perform lateral movement from session ${sessionId} to ${targetHost}?`)) {
      toast('Lateral movement cancelled', { icon: '⚠️' })
      return
    }

    setIsRunning(true)
    try {
      const response = await fetch(getApiUrl('/api/advanced-pentest/post-exploit/lateral-movement'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId, targetHost, method: method || undefined })
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || 'Lateral movement failed')
      }

      setResult(data)
      onResult?.(data)
      
      if (data.success) {
        toast.success(`Successfully moved to ${targetHost} using ${data.method || 'auto-detected method'}`)
      } else {
        toast.error(data.message || 'Lateral movement failed')
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      toast.error(`Failed to perform lateral movement: ${message}`)
    } finally {
      setIsRunning(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <Network className="w-6 h-6 text-blue-500" />
          <h3 className="text-xl font-semibold">Lateral Movement</h3>
        </div>

        <p className="text-gray-400 text-sm mb-6">
          Move laterally from one compromised system to another using techniques like PsExec, 
          WMI, WinRM, SSH, Pass-the-Hash, Pass-the-Ticket, and Kerberos attacks.
        </p>

        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Source Session ID</label>
              <input
                type="text"
                value={sessionId}
                onChange={(e) => setSessionId(e.target.value)}
                placeholder="e.g., session-001"
                className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Target Host</label>
              <input
                type="text"
                value={targetHost}
                onChange={(e) => setTargetHost(e.target.value)}
                placeholder="e.g., 192.168.1.100"
                className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Movement Method</label>
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value)}
              className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white focus:border-blue-500 focus:outline-none"
            >
              {methods.map((m) => (
                <option key={m.value} value={m.value}>
                  {m.label}
                </option>
              ))}
            </select>
            <p className="text-xs text-gray-500 mt-1">
              Auto-detect will choose the best method based on the target OS
            </p>
          </div>

          <button
            onClick={handleMove}
            disabled={isRunning}
            className="w-full px-4 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded flex items-center justify-center gap-2 font-medium transition-colors"
          >
            {isRunning ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Moving...
              </>
            ) : (
              <>
                <ArrowRight className="w-5 h-5" />
                Initiate Lateral Movement
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
                  {result.success ? 'Movement Successful' : 'Movement Failed'}
                </h4>
              </div>
              
              <div className="space-y-2 text-sm">
                {result.method && (
                  <div className="flex justify-between items-center py-1">
                    <span className="text-gray-400">Method Used:</span>
                    <span className="text-green-400 font-mono">{result.method}</span>
                  </div>
                )}
                {result.newSessionId && (
                  <div className="flex justify-between items-center py-1">
                    <span className="text-gray-400">New Session ID:</span>
                    <span className="text-blue-400 font-mono">{result.newSessionId}</span>
                  </div>
                )}
                {result.targetHost && (
                  <div className="flex justify-between items-center py-1">
                    <span className="text-gray-400">Target:</span>
                    <span className="text-white">{result.targetHost}</span>
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
            <p>Lateral movement requires explicit authorization. Only target systems within your authorized scope.</p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default LateralMovementPanel

