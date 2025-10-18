import React, { useState } from 'react'
import { Eye, Play, CheckCircle } from 'lucide-react'
import toast from 'react-hot-toast'
import { getApiUrl } from '../../../../config/api.config'

const AVEvasionPanel: React.FC<{onResult?: (result: any) => void}> = ({ onResult }) => {
  const [code, setCode] = useState('')
  const [language, setLanguage] = useState('powershell')
  const [isRunning, setIsRunning] = useState(false)
  const [result, setResult] = useState<any>(null)

  const languages = [
    { value: 'powershell', label: 'PowerShell' },
    { value: 'python', label: 'Python' },
    { value: 'bash', label: 'Bash' },
    { value: 'csharp', label: 'C#' },
  ]

  const handleEvade = async () => {
    if (!code.trim()) {
      toast.error('Please enter code to obfuscate')
      return
    }

    setIsRunning(true)
    try {
      const response = await fetch(getApiUrl('/api/advanced-pentest/evasion/evade-av'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, language })
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || 'AV evasion failed')
      }

      setResult(data)
      onResult?.(data)
      toast.success('Code obfuscated successfully')
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      toast.error(`AV evasion failed: ${message}`)
    } finally {
      setIsRunning(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
        <div className="flex items-center gap-3 mb-4">
          <Eye className="w-6 h-6 text-purple-500" />
          <h3 className="text-xl font-semibold">AV/EDR Evasion</h3>
        </div>

        <p className="text-gray-400 text-sm mb-6">
          Obfuscate code to evade antivirus and EDR detection using signature avoidance, 
          behavioral evasion, in-memory execution, and advanced obfuscation techniques.
        </p>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Language</label>
            <select
              value={language}
              onChange={(e) => setLanguage(e.target.value)}
              className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white focus:border-purple-500 focus:outline-none"
            >
              {languages.map((lang) => (
                <option key={lang.value} value={lang.value}>
                  {lang.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Code to Obfuscate</label>
            <textarea
              value={code}
              onChange={(e) => setCode(e.target.value)}
              rows={8}
              placeholder="Enter your code here..."
              className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:border-purple-500 focus:outline-none font-mono text-sm"
            />
          </div>

          <button
            onClick={handleEvade}
            disabled={isRunning}
            className="w-full px-4 py-3 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded flex items-center justify-center gap-2 font-medium transition-colors"
          >
            {isRunning ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Obfuscating...
              </>
            ) : (
              <>
                <Play className="w-5 h-5" />
                Obfuscate Code
              </>
            )}
          </button>

          {result && (
            <div className="mt-6 p-4 bg-gray-900 border border-gray-700 rounded-lg">
              <div className="flex items-center gap-2 mb-3">
                <CheckCircle className="w-5 h-5 text-green-500" />
                <h4 className="font-semibold text-white">Obfuscated Code</h4>
              </div>

              {result.obfuscatedCode && (
                <div className="space-y-3">
                  <div>
                    <div className="text-xs text-gray-400 mb-2">Obfuscation Techniques Applied:</div>
                    <div className="flex flex-wrap gap-2">
                      {(result.techniques || ['String encoding', 'Variable renaming', 'Control flow obfuscation']).map((tech: string, i: number) => (
                        <span key={i} className="px-2 py-1 bg-purple-900/30 text-purple-300 text-xs rounded">
                          {tech}
                        </span>
                      ))}
                    </div>
                  </div>
                  
                  <div>
                    <div className="text-xs text-gray-400 mb-2">Obfuscated Code:</div>
                    <pre className="bg-gray-950 p-3 rounded text-xs text-purple-300 overflow-x-auto max-h-96">
                      {result.obfuscatedCode}
                    </pre>
                  </div>

                  {result.detectionRate && (
                    <div className="p-3 bg-green-900/20 rounded">
                      <div className="text-xs text-green-300">
                        <strong>Detection Rate:</strong> {result.detectionRate}
                      </div>
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

export default AVEvasionPanel

