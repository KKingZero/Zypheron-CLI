import React, { useState, useEffect } from 'react'
import { 
  Lock, 
  Key, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Eye,
  EyeOff,
  Clock,
  Cpu,
  Zap,
  Download,
  Upload,
  Play,
  Hash
} from 'lucide-react'
import toast from 'react-hot-toast'

interface PasswordAnalyzerProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

interface PasswordStrengthResult {
  password: string
  strength: 'very_weak' | 'weak' | 'moderate' | 'strong' | 'very_strong'
  score: number
  timeTocrack: {
    online: string
    offline: string
    gpu_cluster: string
  }
  entropy: number
  analysis: {
    length: number
    hasLowercase: boolean
    hasUppercase: boolean
    hasNumbers: boolean
    hasSpecial: boolean
    commonPassword: boolean
    dictionaryMatch: boolean
    patternMatch: string[]
  }
  recommendations: string[]
}

interface HashCrackResult {
  hash: string
  hashType: string
  cracked: boolean
  plaintext?: string
  attempts: number
  timeElapsed: string
  method: string
  confidence: number
}

const PasswordAnalyzer: React.FC<PasswordAnalyzerProps> = ({ onToolExecute }) => {
  const [activeTab, setActiveTab] = useState<'strength' | 'hash' | 'generator'>('strength')
  
  // Password Strength Analysis
  const [password, setPassword] = useState<string>('')
  const [showPassword, setShowPassword] = useState<boolean>(false)
  const [strengthResult, setStrengthResult] = useState<PasswordStrengthResult | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false)
  
  // Hash Cracking
  const [hashInput, setHashInput] = useState<string>('')
  const [hashType, setHashType] = useState<string>('md5')
  const [crackMethod, setCrackMethod] = useState<string>('dictionary')
  const [wordlistFile, setWordlistFile] = useState<File | null>(null)
  const [isCracking, setIsCracking] = useState<boolean>(false)
  const [crackResult, setCrackResult] = useState<HashCrackResult | null>(null)
  const [crackProgress, setCrackProgress] = useState<number>(0)
  
  // Password Generator
  const [genLength, setGenLength] = useState<number>(12)
  const [genOptions, setGenOptions] = useState({
    uppercase: true,
    lowercase: true,
    numbers: true,
    special: true,
    excludeAmbiguous: false
  })
  const [generatedPasswords, setGeneratedPasswords] = useState<string[]>([])

  const hashTypes = [
    { value: 'md5', label: 'MD5', description: '32-character hex string' },
    { value: 'sha1', label: 'SHA1', description: '40-character hex string' },
    { value: 'sha256', label: 'SHA256', description: '64-character hex string' },
    { value: 'sha512', label: 'SHA512', description: '128-character hex string' },
    { value: 'ntlm', label: 'NTLM', description: 'Windows NTLM hash' },
    { value: 'bcrypt', label: 'bcrypt', description: 'bcrypt hash format' },
    { value: 'pbkdf2', label: 'PBKDF2', description: 'PBKDF2 hash format' }
  ]

  const crackMethods = [
    { value: 'dictionary', label: 'Dictionary Attack', description: 'Use wordlist to crack passwords' },
    { value: 'brute_force', label: 'Brute Force', description: 'Try all possible combinations' },
    { value: 'hybrid', label: 'Hybrid Attack', description: 'Dictionary + rules/mutations' },
    { value: 'mask', label: 'Mask Attack', description: 'Pattern-based brute force' }
  ]

  const analyzePassword = async () => {
    if (!password.trim()) {
      toast.error('Please enter a password to analyze')
      return
    }

    setIsAnalyzing(true)
    try {
      const result = await onToolExecute('password_strength_analysis', {
        password: password
      })
      
      if (result) {
        setStrengthResult(result)
      }
    } catch (error) {
      console.error('Password analysis failed:', error)
      toast.error('Password analysis failed')
    } finally {
      setIsAnalyzing(false)
    }
  }

  const crackHash = async () => {
    if (!hashInput.trim()) {
      toast.error('Please enter a hash to crack')
      return
    }

    setIsCracking(true)
    setCrackProgress(0)
    
    let progressInterval: NodeJS.Timeout | null = null
    
    try {
      const params = {
        hash: hashInput.trim(),
        hashType,
        method: crackMethod,
        wordlist: wordlistFile ? await wordlistFile.text() : undefined
      }

      // Simulate cracking progress
      progressInterval = setInterval(() => {
        setCrackProgress(prev => Math.min(prev + Math.random() * 5, 95))
      }, 1000)

      const result = await onToolExecute('hash_crack', params)
      
      setCrackProgress(100)
      
      if (result) {
        setCrackResult(result)
      }
    } catch (error) {
      console.error('Hash cracking failed:', error)
      toast.error('Hash cracking failed')
    } finally {
      // Always clear the interval
      if (progressInterval) {
        clearInterval(progressInterval)
      }
      setIsCracking(false)
    }
  }

  const generatePasswords = () => {
    const charset = {
      uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
      lowercase: 'abcdefghijklmnopqrstuvwxyz',
      numbers: '0123456789',
      special: '!@#$%^&*()_+-=[]{}|;:,.<>?'
    }

    let chars = ''
    if (genOptions.uppercase) chars += charset.uppercase
    if (genOptions.lowercase) chars += charset.lowercase
    if (genOptions.numbers) chars += charset.numbers
    if (genOptions.special) chars += charset.special

    if (genOptions.excludeAmbiguous) {
      chars = chars.replace(/[0O1lI]/g, '')
    }

    if (chars === '') {
      toast.error('Please select at least one character type')
      return
    }

    const passwords = []
    for (let i = 0; i < 10; i++) {
      let password = ''
      for (let j = 0; j < genLength; j++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length))
      }
      passwords.push(password)
    }
    
    setGeneratedPasswords(passwords)
  }

  const getStrengthColor = (strength: string) => {
    switch (strength) {
      case 'very_weak': return 'text-red-500'
      case 'weak': return 'text-orange-500'
      case 'moderate': return 'text-yellow-500'
      case 'strong': return 'text-blue-500'
      case 'very_strong': return 'text-green-500'
      default: return 'text-gray-500'
    }
  }

  const getStrengthBg = (strength: string) => {
    switch (strength) {
      case 'very_weak': return 'bg-red-500'
      case 'weak': return 'bg-orange-500'
      case 'moderate': return 'bg-yellow-500'
      case 'strong': return 'bg-blue-500'
      case 'very_strong': return 'bg-green-500'
      default: return 'bg-gray-500'
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast.success('Copied to clipboard')
  }

  return (
    <div className="space-y-6">
      {/* Tab Navigation */}
      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex items-center space-x-2 mb-4">
          <Key className="w-5 h-5 text-purple-400" />
          <h3 className="text-lg font-medium text-white">Password Security Analyzer</h3>
        </div>

        <div className="flex space-x-2 mb-6">
          {[
            { id: 'strength', label: 'Strength Analysis', icon: Shield },
            { id: 'hash', label: 'Hash Cracking', icon: Hash },
            { id: 'generator', label: 'Password Generator', icon: Key }
          ].map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id as any)}
              className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-colors ${
                activeTab === id
                  ? 'bg-purple-600 text-white'
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{label}</span>
            </button>
          ))}
        </div>

        {/* Password Strength Analysis Tab */}
        {activeTab === 'strength' && (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Enter Password to Analyze
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter password here..."
                  className="w-full px-3 py-2 pr-10 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 px-3 flex items-center text-gray-400 hover:text-white"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              onClick={analyzePassword}
              disabled={isAnalyzing}
              className="flex items-center space-x-2 px-4 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition-colors disabled:opacity-50"
            >
              {isAnalyzing ? (
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                <Shield className="w-4 h-4" />
              )}
              <span>{isAnalyzing ? 'Analyzing...' : 'Analyze Strength'}</span>
            </button>

            {/* Strength Results */}
            {strengthResult && (
              <div className="bg-gray-700 rounded-lg p-4">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="font-medium text-white">Password Strength Analysis</h4>
                  <div className="flex items-center space-x-2">
                    <div className={`px-3 py-1 rounded text-sm font-medium ${getStrengthColor(strengthResult.strength)}`}>
                      {strengthResult.strength.replace('_', ' ').toUpperCase()}
                    </div>
                    <span className="text-gray-300">{strengthResult.score}/10</span>
                  </div>
                </div>

                <div className="w-full bg-gray-600 rounded-full h-3 mb-4">
                  <div 
                    className={`h-3 rounded-full transition-all duration-300 ${getStrengthBg(strengthResult.strength)}`}
                    style={{ width: `${(strengthResult.score / 10) * 100}%` }}
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                  <div className="bg-gray-600 rounded p-3">
                    <h5 className="text-sm font-medium text-gray-300 mb-2">Time to Crack</h5>
                    <div className="space-y-1 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-400">Online:</span>
                        <span className="text-white">{strengthResult.timeTocrack.online}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Offline:</span>
                        <span className="text-white">{strengthResult.timeTocrack.offline}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">GPU Cluster:</span>
                        <span className="text-white">{strengthResult.timeTocrack.gpu_cluster}</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gray-600 rounded p-3">
                    <h5 className="text-sm font-medium text-gray-300 mb-2">Composition</h5>
                    <div className="space-y-1 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-400">Length:</span>
                        <span className="text-white">{strengthResult.analysis.length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Entropy:</span>
                        <span className="text-white">{strengthResult.entropy} bits</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gray-600 rounded p-3">
                    <h5 className="text-sm font-medium text-gray-300 mb-2">Character Types</h5>
                    <div className="grid grid-cols-2 gap-1 text-sm">
                      <div className="flex items-center space-x-2">
                        {strengthResult.analysis.hasLowercase ? (
                          <CheckCircle className="w-3 h-3 text-green-400" />
                        ) : (
                          <div className="w-3 h-3 rounded-full border border-gray-500" />
                        )}
                        <span className="text-gray-300">a-z</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        {strengthResult.analysis.hasUppercase ? (
                          <CheckCircle className="w-3 h-3 text-green-400" />
                        ) : (
                          <div className="w-3 h-3 rounded-full border border-gray-500" />
                        )}
                        <span className="text-gray-300">A-Z</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        {strengthResult.analysis.hasNumbers ? (
                          <CheckCircle className="w-3 h-3 text-green-400" />
                        ) : (
                          <div className="w-3 h-3 rounded-full border border-gray-500" />
                        )}
                        <span className="text-gray-300">0-9</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        {strengthResult.analysis.hasSpecial ? (
                          <CheckCircle className="w-3 h-3 text-green-400" />
                        ) : (
                          <div className="w-3 h-3 rounded-full border border-gray-500" />
                        )}
                        <span className="text-gray-300">!@#</span>
                      </div>
                    </div>
                  </div>
                </div>

                {strengthResult.analysis.commonPassword && (
                  <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-3 mb-4">
                    <div className="flex items-center space-x-2">
                      <AlertTriangle className="w-4 h-4 text-red-400" />
                      <span className="text-red-400 font-medium">Common Password Detected</span>
                    </div>
                    <p className="text-red-300 text-sm mt-1">This password appears in common password lists.</p>
                  </div>
                )}

                {strengthResult.recommendations.length > 0 && (
                  <div className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-3">
                    <h5 className="font-medium text-blue-400 mb-2">Recommendations</h5>
                    <ul className="space-y-1">
                      {strengthResult.recommendations.map((rec, index) => (
                        <li key={index} className="text-blue-300 text-sm">• {rec}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Hash Cracking Tab */}
        {activeTab === 'hash' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Hash to Crack
                </label>
                <textarea
                  value={hashInput}
                  onChange={(e) => setHashInput(e.target.value)}
                  placeholder="Enter hash here (e.g., 5d41402abc4b2a76b9719d911017c592)"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500"
                  rows={3}
                />
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Hash Type
                  </label>
                  <select
                    value={hashType}
                    onChange={(e) => setHashType(e.target.value)}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
                  >
                    {hashTypes.map(type => (
                      <option key={type.value} value={type.value}>
                        {type.label}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Cracking Method
                  </label>
                  <select
                    value={crackMethod}
                    onChange={(e) => setCrackMethod(e.target.value)}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
                  >
                    {crackMethods.map(method => (
                      <option key={method.value} value={method.value}>
                        {method.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            {crackMethod === 'dictionary' && (
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Wordlist File (optional)
                </label>
                <input
                  type="file"
                  accept=".txt,.dic,.lst"
                  onChange={(e) => setWordlistFile(e.target.files?.[0] || null)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white file:mr-4 file:py-1 file:px-3 file:rounded file:border-0 file:bg-purple-600 file:text-white"
                />
              </div>
            )}

            <button
              onClick={crackHash}
              disabled={isCracking}
              className="flex items-center space-x-2 px-4 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition-colors disabled:opacity-50"
            >
              {isCracking ? (
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                <Zap className="w-4 h-4" />
              )}
              <span>{isCracking ? 'Cracking...' : 'Start Cracking'}</span>
            </button>

            {/* Cracking Progress */}
            {isCracking && (
              <div className="bg-gray-700 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-300">Cracking Progress</span>
                  <span className="text-sm text-gray-400">{Math.round(crackProgress)}%</span>
                </div>
                <div className="w-full bg-gray-600 rounded-full h-2">
                  <div 
                    className="bg-purple-600 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${crackProgress}%` }}
                  />
                </div>
              </div>
            )}

            {/* Crack Results */}
            {crackResult && (
              <div className="bg-gray-700 rounded-lg p-4">
                <h4 className="font-medium text-white mb-4">Cracking Results</h4>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-3">
                    <div>
                      <label className="text-sm text-gray-400">Status:</label>
                      <div className="flex items-center space-x-2 mt-1">
                        {crackResult.cracked ? (
                          <CheckCircle className="w-4 h-4 text-green-400" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-red-400" />
                        )}
                        <span className={crackResult.cracked ? 'text-green-400' : 'text-red-400'}>
                          {crackResult.cracked ? 'Successfully Cracked' : 'Not Cracked'}
                        </span>
                      </div>
                    </div>

                    {crackResult.cracked && crackResult.plaintext && (
                      <div>
                        <label className="text-sm text-gray-400">Plaintext:</label>
                        <div className="mt-1 p-2 bg-gray-800 rounded font-mono text-green-400">
                          {crackResult.plaintext}
                          <button
                            onClick={() => copyToClipboard(crackResult.plaintext!)}
                            className="ml-2 text-gray-400 hover:text-white"
                          >
                            📋
                          </button>
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="space-y-3">
                    <div>
                      <label className="text-sm text-gray-400">Method:</label>
                      <p className="text-white mt-1">{crackResult.method}</p>
                    </div>
                    
                    <div>
                      <label className="text-sm text-gray-400">Time Elapsed:</label>
                      <p className="text-white mt-1">{crackResult.timeElapsed}</p>
                    </div>
                    
                    <div>
                      <label className="text-sm text-gray-400">Attempts:</label>
                      <p className="text-white mt-1">{crackResult.attempts.toLocaleString()}</p>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Password Generator Tab */}
        {activeTab === 'generator' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Password Length: {genLength}
                  </label>
                  <input
                    type="range"
                    min="4"
                    max="128"
                    value={genLength}
                    onChange={(e) => setGenLength(parseInt(e.target.value))}
                    className="w-full"
                  />
                </div>

                <div className="space-y-3">
                  <label className="block text-sm font-medium text-gray-300">Character Types:</label>
                  
                  {[
                    { key: 'uppercase', label: 'Uppercase Letters (A-Z)' },
                    { key: 'lowercase', label: 'Lowercase Letters (a-z)' },
                    { key: 'numbers', label: 'Numbers (0-9)' },
                    { key: 'special', label: 'Special Characters (!@#$...)' }
                  ].map(({ key, label }) => (
                    <div key={key} className="flex items-center">
                      <input
                        type="checkbox"
                        id={key}
                        checked={genOptions[key as keyof typeof genOptions]}
                        onChange={(e) => setGenOptions(prev => ({ ...prev, [key]: e.target.checked }))}
                        className="rounded bg-gray-700 border-gray-600"
                      />
                      <label htmlFor={key} className="ml-2 text-sm text-gray-300">
                        {label}
                      </label>
                    </div>
                  ))}

                  <div className="flex items-center">
                    <input
                      type="checkbox"
                      id="excludeAmbiguous"
                      checked={genOptions.excludeAmbiguous}
                      onChange={(e) => setGenOptions(prev => ({ ...prev, excludeAmbiguous: e.target.checked }))}
                      className="rounded bg-gray-700 border-gray-600"
                    />
                    <label htmlFor="excludeAmbiguous" className="ml-2 text-sm text-gray-300">
                      Exclude Ambiguous Characters (0, O, 1, l, I)
                    </label>
                  </div>
                </div>
              </div>

              <div>
                <button
                  onClick={generatePasswords}
                  className="flex items-center space-x-2 px-4 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition-colors mb-4"
                >
                  <Key className="w-4 h-4" />
                  <span>Generate Passwords</span>
                </button>

                {generatedPasswords.length > 0 && (
                  <div className="bg-gray-700 rounded-lg p-4">
                    <h4 className="font-medium text-white mb-3">Generated Passwords:</h4>
                    <div className="space-y-2">
                      {generatedPasswords.map((pwd, index) => (
                        <div key={index} className="flex items-center justify-between p-2 bg-gray-800 rounded">
                          <span className="font-mono text-green-400">{pwd}</span>
                          <button
                            onClick={() => copyToClipboard(pwd)}
                            className="text-gray-400 hover:text-white text-sm"
                          >
                            📋
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default PasswordAnalyzer
