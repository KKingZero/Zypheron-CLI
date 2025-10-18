import React, { useState, useEffect } from 'react'
import { Key, Hash, AlertTriangle, Loader, XCircle, Brain } from 'lucide-react'
import toast from 'react-hot-toast'
import { useAuth } from '../contexts/AuthContext'
import { shouldBypassAuth } from '../utils/devMode'
import { getApiUrl } from '../config/api.config'

interface BruteForceProps {
  target?: string
  onClose: () => void
}

const BruteForcePanel: React.FC<BruteForceProps> = ({ target, onClose }) => {
  const { session } = useAuth()
  const [activeTab, setActiveTab] = useState<'hydra' | 'hashcat'>('hydra')
  const [isLoading, setIsLoading] = useState(false)
  const [useAI, setUseAI] = useState(true)
  const [useNative, setUseNative] = useState(true) // Default to native implementation
  
  // Hydra state
  const [hydraTarget, setHydraTarget] = useState(target || '')
  const [selectedService, setSelectedService] = useState('ssh')
  const [userList, setUserList] = useState<string>('')
  const [passwordList, setPasswordList] = useState<string>('')
  const [threads, setThreads] = useState(16)
  const [services, setServices] = useState<any[]>([])
  
  // Hashcat state
  const [hashes, setHashes] = useState<string>('')
  const [hashType, setHashType] = useState<number | null>(null)
  const [attackMode, setAttackMode] = useState(0)
  const [wordlist, setWordlist] = useState('')
  const [mask, setMask] = useState('?a?a?a?a?a?a')
  const [hashTypes, setHashTypes] = useState<any[]>([])
  
  // Results state
  const [results, setResults] = useState<any>(null)
  const [progress, setProgress] = useState<any>(null)

  useEffect(() => {
    // Load available services and hash types
    loadServices()
    loadHashTypes()
    if (!useNative) {
      checkToolStatus()
    }
  }, [useNative])

  const loadServices = async () => {
    try {
      // Load native services by default, fallback to hydra services
      const endpoint = useNative ? '/api/bruteforce/native/services' : '/api/bruteforce/hydra/services'
      
      // Create abort controller for timeout
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), 5000)
      
      const response = await fetch(getApiUrl(endpoint), {
        signal: controller.signal
      })
      
      clearTimeout(timeoutId)
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }
      
      const data = await response.json()
      setServices(data.services)
    } catch (error) {
      console.error('Failed to load services:', error)
      
      // Use fallback static data
      const fallbackServices = [
        { value: 'ssh', label: 'SSH', port: 22 },
        { value: 'ftp', label: 'FTP', port: 21 },
        { value: 'http', label: 'HTTP', port: 80 },
        { value: 'https', label: 'HTTPS', port: 443 },
        { value: 'smtp', label: 'SMTP', port: 587 },
        { value: 'telnet', label: 'Telnet', port: 23 }
      ]
      
      setServices(fallbackServices)
    }
  }

  const loadHashTypes = async () => {
    try {
      // Load native hash types by default, fallback to hashcat hash types
      const endpoint = useNative ? '/api/bruteforce/native/hashtypes' : '/api/bruteforce/hashcat/hashtypes'
      
      // Create abort controller for timeout
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), 5000)
      
      const response = await fetch(getApiUrl(endpoint), {
        signal: controller.signal
      })
      
      clearTimeout(timeoutId)
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }
      
      const data = await response.json()
      setHashTypes(data.hashTypes)
    } catch (error) {
      console.error('Failed to load hash types:', error)
      
      // Use fallback static data
      const fallbackHashTypes = [
        { value: 'md5', label: 'MD5', example: '5d41402abc4b2a76b9719d911017c592' },
        { value: 'sha1', label: 'SHA1', example: 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d' },
        { value: 'sha256', label: 'SHA256', example: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae' },
        { value: 'sha512', label: 'SHA512', example: '9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043' },
        { value: 'ntlm', label: 'NTLM', example: 'b4b9b02e6f09a9bd760f388b67351e2b' }
      ]
      
      setHashTypes(fallbackHashTypes)
    }
  }

  const checkToolStatus = async () => {
    try {
      const response = await fetch(getApiUrl('/api/bruteforce/tools/status'))
      const status = await response.json()
      
      if (!status.hydra.installed || !status.hashcat.installed) {
        toast.error('Some tools are not installed. Please check installation paths.')
      }
    } catch (error) {
      console.error('Failed to check tool status:', error)
    }
  }

  const handleHydraAttack = async () => {
    if (!hydraTarget || !selectedService) {
      toast.error('Please provide target and service')
      return
    }

    // Check authentication (with dev mode bypass)
    if (!session?.access_token && !shouldBypassAuth()) {
      toast.error('Please log in to use brute force tools')
      return
    }

    setIsLoading(true)
    setResults(null)
    setProgress(null)

    try {
      // Choose endpoint based on native/external tool preference
      const endpoint = useNative ? '/api/bruteforce/native/attack' : '/api/bruteforce/hydra/attack'
      
      const response = await fetch(getApiUrl(endpoint), {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          ...(session?.access_token
            ? { 'Authorization': `Bearer ${session.access_token}` }
            : { 'Authorization': 'Bearer localhost-dev-token', 'x-dev-bypass': 'true' })
        },
        body: JSON.stringify({
          target: hydraTarget,
          service: selectedService,
          userList: userList ? userList.split('\n').filter(u => u.trim()) : null,
          passwordList: passwordList ? passwordList.split('\n').filter(p => p.trim()) : null,
          threads,
          timeout: useNative ? 10000 : 30, // Different timeout formats for native vs external
          useAI,
          verbose: true // Enable verbose mode for better feedback
        })
      })

      if (!response.ok) {
        throw new Error('Attack failed')
      }

      // Handle Server-Sent Events for real-time progress
      const reader = response.body?.getReader()
      const decoder = new TextDecoder()

      while (reader) {
        const { done, value } = await reader.read()
        if (done) break

        const chunk = decoder.decode(value)
        const lines = chunk.split('\n')
        
        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const data = JSON.parse(line.slice(6))
              
              if (data.type === 'progress') {
                setProgress(data)
              } else if (data.type === 'credential-found') {
                toast.success(`Found credentials: ${data.username}:${data.password}`)
              } else if (data.type === 'complete') {
                setResults(data.result)
                setIsLoading(false)
              } else if (data.type === 'error') {
                toast.error(data.error)
              }
            } catch (e) {
              // Ignore parse errors
            }
          }
        }
      }
    } catch (error) {
      console.error('Hydra attack error:', error)
      toast.error('Failed to perform brute force attack')
      setIsLoading(false)
    }
  }

  const handleHashcatCrack = async () => {
    if (!hashes) {
      toast.error('Please provide hashes to crack')
      return
    }

    // Check authentication (with dev mode bypass)
    if (!session?.access_token && !shouldBypassAuth()) {
      toast.error('Please log in to use brute force tools')
      return
    }

    setIsLoading(true)
    setResults(null)
    setProgress(null)

    try {
      // Choose endpoint based on native/external tool preference
      const endpoint = useNative ? '/api/bruteforce/native/hashcrack' : '/api/bruteforce/hashcat/crack'
      
      const response = await fetch(getApiUrl(endpoint), {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${session.access_token}`
        },
        body: JSON.stringify(useNative ? {
          // Native hash cracker format
          hashes: hashes.split('\n').filter(h => h.trim()),
          hashType: typeof hashType === 'string' ? hashType : 'auto',
          attackMode: attackMode === 0 ? 'dictionary' : attackMode === 3 ? 'brute-force' : 'hybrid',
          wordlist: wordlist ? wordlist.split('\n').filter(w => w.trim()) : undefined,
          charset: attackMode === 3 ? mask : undefined,
          maxLength: 8,
          useAI
        } : {
          // External hashcat format
          hashes: hashes.split('\n').filter(h => h.trim()),
          attackMode,
          hashType,
          wordlist: wordlist || undefined,
          mask: attackMode === 3 ? mask : undefined,
          useAI
        })
      })

      if (!response.ok) {
        throw new Error('Cracking failed')
      }

      // Handle Server-Sent Events for real-time progress
      const reader = response.body?.getReader()
      const decoder = new TextDecoder()

      while (reader) {
        const { done, value } = await reader.read()
        if (done) break

        const chunk = decoder.decode(value)
        const lines = chunk.split('\n')
        
        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const data = JSON.parse(line.slice(6))
              
              if (data.type === 'progress') {
                setProgress(data)
              } else if (data.type === 'complete') {
                setResults(data.result)
                setIsLoading(false)
              } else if (data.type === 'error') {
                toast.error(data.error)
              }
            } catch (e) {
              // Ignore parse errors
            }
          }
        }
      }
    } catch (error) {
      console.error('Hashcat crack error:', error)
      toast.error('Failed to crack hashes')
      setIsLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-[#1a1a1a] border border-terminal-border rounded-lg w-full max-w-4xl mx-4 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-terminal-border">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 bg-red-500/10 rounded-lg flex items-center justify-center">
              <Key className="w-5 h-5 text-red-500" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-white">Brute Force Tools</h2>
              <p className="text-sm text-terminal-muted">Credential attacks with Hydra & Hashcat</p>
            </div>
          </div>
          <button onClick={onClose} className="text-terminal-muted hover:text-white transition-colors">
            <XCircle className="w-5 h-5" />
          </button>
        </div>

        {/* AI Toggle */}
        <div className="px-6 py-3 bg-terminal-surface/50 border-b border-terminal-border flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Brain className={`w-4 h-4 ${useAI ? 'text-purple-400' : 'text-terminal-muted'}`} />
            <span className="text-sm text-terminal-text">AI Enhancement</span>
          </div>
          <button
            onClick={() => setUseAI(!useAI)}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              useAI ? 'bg-purple-600' : 'bg-terminal-border'
            }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                useAI ? 'translate-x-6' : 'translate-x-1'
              }`}
            />
          </button>
        </div>

        {/* Native/External Toggle */}
        <div className="px-6 py-3 bg-terminal-surface/50 border-b border-terminal-border flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <div className={`w-4 h-4 rounded ${useNative ? 'bg-green-400' : 'bg-orange-400'}`} />
            <span className="text-sm text-terminal-text">
              {useNative ? 'Native Implementation' : 'External Tools'}
            </span>
            <span className="text-xs text-terminal-muted">
              {useNative ? '(No setup required)' : '(Requires tool installation)'}
            </span>
          </div>
          <button
            onClick={() => setUseNative(!useNative)}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              useNative ? 'bg-green-600' : 'bg-orange-600'
            }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                useNative ? 'translate-x-6' : 'translate-x-1'
              }`}
            />
          </button>
        </div>

        {/* Tabs */}
        <div className="border-b border-terminal-border">
          <div className="flex px-6">
            <button
              onClick={() => setActiveTab('hydra')}
              className={`flex items-center space-x-2 px-4 py-3 border-b-2 transition-colors ${
                activeTab === 'hydra'
                  ? 'border-red-500 text-red-400 bg-red-500/5'
                  : 'border-transparent text-terminal-muted hover:text-white'
              }`}
            >
              <Key className="w-4 h-4" />
              <div>
                <span className="font-medium">Login Brute Force</span>
                <div className="text-xs text-terminal-muted">
                  {useNative ? 'Native' : 'THC Hydra'}
                </div>
              </div>
            </button>
            <button
              onClick={() => setActiveTab('hashcat')}
              className={`flex items-center space-x-2 px-4 py-3 border-b-2 transition-colors ${
                activeTab === 'hashcat'
                  ? 'border-orange-500 text-orange-400 bg-orange-500/5'
                  : 'border-transparent text-terminal-muted hover:text-white'
              }`}
            >
              <Hash className="w-4 h-4" />
              <div>
                <span className="font-medium">Hash Cracking</span>
                <div className="text-xs text-terminal-muted">
                  {useNative ? 'Native' : 'Hashcat'}
                </div>
              </div>
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6">
          {activeTab === 'hydra' ? (
            <div className="space-y-6">
              {/* Hydra Configuration */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-white mb-2">Target</label>
                  <input
                    type="text"
                    value={hydraTarget}
                    onChange={(e) => setHydraTarget(e.target.value)}
                    placeholder="192.168.1.1 or example.com"
                    className="w-full px-3 py-2 bg-[#0d0d0d] border border-terminal-border rounded-lg text-white placeholder-terminal-muted focus:outline-none focus:border-red-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-white mb-2">Service</label>
                  <select
                    value={selectedService}
                    onChange={(e) => setSelectedService(e.target.value)}
                    className="w-full px-3 py-2 bg-[#0d0d0d] border border-terminal-border rounded-lg text-white focus:outline-none focus:border-red-500"
                  >
                    {services.map(service => (
                      <option key={service.value} value={service.value}>
                        {service.label} (Port {service.port})
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-white mb-2">
                    Username List (one per line)
                    {useAI && <span className="text-purple-400 text-xs ml-2">AI will enhance if empty</span>}
                  </label>
                  <textarea
                    value={userList}
                    onChange={(e) => setUserList(e.target.value)}
                    placeholder="admin&#10;root&#10;user&#10;..."
                    className="w-full h-32 px-3 py-2 bg-[#0d0d0d] border border-terminal-border rounded-lg text-white placeholder-terminal-muted focus:outline-none focus:border-red-500 font-mono text-sm"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-white mb-2">
                    Password List (one per line)
                    {useAI && <span className="text-purple-400 text-xs ml-2">AI will enhance if empty</span>}
                  </label>
                  <textarea
                    value={passwordList}
                    onChange={(e) => setPasswordList(e.target.value)}
                    placeholder="password&#10;123456&#10;admin&#10;..."
                    className="w-full h-32 px-3 py-2 bg-[#0d0d0d] border border-terminal-border rounded-lg text-white placeholder-terminal-muted focus:outline-none focus:border-red-500 font-mono text-sm"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-white mb-2">Threads</label>
                <input
                  type="number"
                  value={threads}
                  onChange={(e) => setThreads(parseInt(e.target.value))}
                  min="1"
                  max="64"
                  className="w-32 px-3 py-2 bg-[#0d0d0d] border border-terminal-border rounded-lg text-white focus:outline-none focus:border-red-500"
                />
              </div>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Hashcat Configuration */}
              <div>
                <label className="block text-sm font-medium text-white mb-2">
                  Hashes (one per line)
                  {useAI && <span className="text-purple-400 text-xs ml-2">AI will auto-detect type</span>}
                </label>
                <textarea
                  value={hashes}
                  onChange={(e) => setHashes(e.target.value)}
                  placeholder="5f4dcc3b5aa765d61d8327deb882cf99&#10;e10adc3949ba59abbe56e057f20f883e&#10;..."
                  className="w-full h-32 px-3 py-2 bg-[#0d0d0d] border border-terminal-border rounded-lg text-white placeholder-terminal-muted focus:outline-none focus:border-orange-500 font-mono text-sm"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-white mb-2">Hash Type</label>
                  <select
                    value={hashType || ''}
                    onChange={(e) => setHashType(e.target.value ? parseInt(e.target.value) : null)}
                    className="w-full px-3 py-2 bg-[#0d0d0d] border border-terminal-border rounded-lg text-white focus:outline-none focus:border-orange-500"
                  >
                    <option value="">Auto-detect</option>
                    {hashTypes.map(type => (
                      <option key={type.value} value={type.value}>
                        {type.label}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-white mb-2">Attack Mode</label>
                  <select
                    value={attackMode}
                    onChange={(e) => setAttackMode(parseInt(e.target.value))}
                    className="w-full px-3 py-2 bg-[#0d0d0d] border border-terminal-border rounded-lg text-white focus:outline-none focus:border-orange-500"
                  >
                    <option value={0}>Dictionary Attack</option>
                    <option value={3}>Brute Force</option>
                    <option value={1}>Combination</option>
                    <option value={6}>Hybrid Wordlist + Mask</option>
                    <option value={7}>Hybrid Mask + Wordlist</option>
                  </select>
                </div>
              </div>

              {attackMode === 0 && (
                <div>
                  <label className="block text-sm font-medium text-white mb-2">
                    Wordlist Path
                    {useAI && <span className="text-purple-400 text-xs ml-2">AI will suggest if empty</span>}
                  </label>
                  <input
                    type="text"
                    value={wordlist}
                    onChange={(e) => setWordlist(e.target.value)}
                    placeholder="C:\wordlists\rockyou.txt"
                    className="w-full px-3 py-2 bg-[#0d0d0d] border border-terminal-border rounded-lg text-white placeholder-terminal-muted focus:outline-none focus:border-orange-500"
                  />
                </div>
              )}

              {attackMode === 3 && (
                <div>
                  <label className="block text-sm font-medium text-white mb-2">Mask Pattern</label>
                  <input
                    type="text"
                    value={mask}
                    onChange={(e) => setMask(e.target.value)}
                    placeholder="?a?a?a?a?a?a"
                    className="w-full px-3 py-2 bg-[#0d0d0d] border border-terminal-border rounded-lg text-white placeholder-terminal-muted focus:outline-none focus:border-orange-500 font-mono"
                  />
                  <p className="text-xs text-terminal-muted mt-1">
                    ?l=lowercase, ?u=uppercase, ?d=digit, ?s=special, ?a=all
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Progress Display */}
          {progress && (
            <div className="mt-6 p-4 bg-terminal-surface border border-terminal-border rounded-lg">
              <h3 className="text-sm font-medium text-white mb-2">Progress</h3>
              <div className="space-y-2 text-sm">
                {progress.attempts && (
                  <div>Attempts: <span className="text-yellow-400">{progress.attempts}</span></div>
                )}
                {progress.progress && (
                  <div>Progress: <span className="text-green-400">{progress.progress}%</span></div>
                )}
                {progress.speed && (
                  <div>Speed: <span className="text-blue-400">{progress.speed}</span></div>
                )}
                {progress.timeRemaining && (
                  <div>Time Remaining: <span className="text-purple-400">{progress.timeRemaining}</span></div>
                )}
              </div>
            </div>
          )}

          {/* Results Display */}
          {results && (
            <div className="mt-6 p-4 bg-terminal-surface border border-terminal-border rounded-lg">
              <h3 className="text-sm font-medium text-white mb-2">Results</h3>
              {results.success ? (
                <div className="space-y-2">
                  {results.credentials && results.credentials.length > 0 && (
                    <div>
                      <p className="text-green-400 font-medium mb-2">Found Credentials:</p>
                      {results.credentials.map((cred: any, index: number) => (
                        <div key={index} className="text-sm font-mono bg-green-500/10 p-2 rounded">
                          {cred.username}:{cred.password}
                        </div>
                      ))}
                    </div>
                  )}
                  {results.crackedHashes && results.crackedHashes.length > 0 && (
                    <div>
                      <p className="text-green-400 font-medium mb-2">Cracked Hashes:</p>
                      {results.crackedHashes.map((hash: any, index: number) => (
                        <div key={index} className="text-sm font-mono bg-green-500/10 p-2 rounded break-all">
                          {hash.hash} → {hash.plaintext}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-red-400">No results found</p>
              )}
              
              {results.aiSuggestions && results.aiSuggestions.length > 0 && (
                <div className="mt-4">
                  <p className="text-purple-400 font-medium mb-2">AI Suggestions:</p>
                  <ul className="list-disc list-inside space-y-1">
                    {results.aiSuggestions.map((suggestion: string, index: number) => (
                      <li key={index} className="text-sm text-terminal-muted">{suggestion}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Warning */}
          <div className="mt-6 border rounded-lg p-4 bg-amber-500/10 border-amber-500/30">
            <div className="flex items-start space-x-3">
              <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5 text-amber-500" />
              <div>
                <h3 className="font-medium text-sm text-amber-500">Legal Warning</h3>
                <p className="text-sm mt-1 text-amber-200/80">
                  Only use these tools on systems you own or have explicit permission to test.
                  Unauthorized access attempts are illegal and unethical.
                </p>
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="mt-6 flex justify-end space-x-3">
            <button
              onClick={onClose}
              className="px-4 py-2 text-terminal-muted hover:text-white transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={activeTab === 'hydra' ? handleHydraAttack : handleHashcatCrack}
              disabled={isLoading}
              className={`px-6 py-2 disabled:cursor-not-allowed text-white rounded-lg transition-colors flex items-center space-x-2 ${
                activeTab === 'hydra'
                  ? 'bg-red-500 hover:bg-red-600 disabled:bg-red-500/50'
                  : 'bg-orange-500 hover:bg-orange-600 disabled:bg-orange-500/50'
              }`}
            >
              {isLoading ? (
                <>
                  <Loader className="w-4 h-4 animate-spin" />
                  <span>Running...</span>
                </>
              ) : (
                <>
                  {activeTab === 'hydra' ? <Key className="w-4 h-4" /> : <Hash className="w-4 h-4" />}
                  <span>Start {activeTab === 'hydra' ? 'Attack' : 'Cracking'}</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export default BruteForcePanel 