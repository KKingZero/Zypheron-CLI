import React, { useState, useEffect } from 'react'
import { Key, Cpu, Zap, Upload, Play, Pause, Download, AlertTriangle, Eye, Brain, Shield, Clock } from 'lucide-react'

interface HashFile {
  name: string
  type: 'md5' | 'sha1' | 'sha256' | 'ntlm' | 'bcrypt' | 'other'
  hashCount: number
  sampleHash: string
}

interface CrackingJob {
  id: string
  hashFile: string
  hashType: string
  attack: 'wordlist' | 'brute_force' | 'hybrid' | 'mask'
  status: 'queued' | 'running' | 'paused' | 'completed' | 'failed'
  progress: number
  startTime: string
  estimatedTime: string
  crackedCount: number
  totalHashes: number
  currentRate: string
  gpuAcceleration: boolean
}

interface CrackedPassword {
  hash: string
  password: string
  algorithm: string
  crackTime: string
  strength: 'very_weak' | 'weak' | 'medium' | 'strong' | 'very_strong'
  patterns: string[]
  recommendations: string[]
}

interface GPTPasswordAnalysis {
  overallStrength: number
  commonPatterns: string[]
  securityRecommendations: string[]
  policyCompliance: {
    length: boolean
    complexity: boolean
    dictionary: boolean
  }
  riskAssessment: string
}

interface JohnRipperPanelProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

const JohnRipperPanel: React.FC<JohnRipperPanelProps> = ({ onToolExecute }) => {
  const [hashFile, setHashFile] = useState<string>('')
  const [hashType, setHashType] = useState<string>('auto')
  const [attackMode, setAttackMode] = useState<string>('wordlist')
  const [wordlistPath, setWordlistPath] = useState<string>('')
  const [customRules, setCustomRules] = useState<string>('')
  const [gpuEnabled, setGpuEnabled] = useState<boolean>(true)
  const [maskPattern, setMaskPattern] = useState<string>('')
  const [activeJobs, setActiveJobs] = useState<CrackingJob[]>([])
  const [crackedPasswords, setCrackedPasswords] = useState<CrackedPassword[]>([])
  const [gptAnalysis, setGptAnalysis] = useState<GPTPasswordAnalysis | null>(null)
  const [selectedJob, setSelectedJob] = useState<CrackingJob | null>(null)
  const [viewMode, setViewMode] = useState<'setup' | 'jobs' | 'results' | 'analysis'>('setup')

  const hashTypes = [
    { value: 'auto', label: 'Auto-detect' },
    { value: 'md5', label: 'MD5' },
    { value: 'sha1', label: 'SHA-1' },
    { value: 'sha256', label: 'SHA-256' },
    { value: 'sha512', label: 'SHA-512' },
    { value: 'ntlm', label: 'NTLM' },
    { value: 'bcrypt', label: 'bcrypt' },
    { value: 'scrypt', label: 'scrypt' },
    { value: 'pbkdf2', label: 'PBKDF2' }
  ]

  const wordlists = [
    { value: 'rockyou', label: 'RockYou (14M passwords)', size: '14M' },
    { value: 'top1000', label: 'Top 1000 passwords', size: '1K' },
    { value: 'common_passwords', label: 'Common passwords', size: '100K' },
    { value: 'leaked_passwords', label: 'Leaked password database', size: '500M' },
    { value: 'custom', label: 'Custom wordlist', size: 'Variable' }
  ]

  const maskPatterns = [
    { pattern: '?l?l?l?l?d?d?d?d', description: '4 letters + 4 digits' },
    { pattern: '?u?l?l?l?l?l?d?d', description: 'Uppercase + 5 lowercase + 2 digits' },
    { pattern: '?d?d?d?d?d?d?d?d', description: '8 digits' },
    { pattern: '?l?l?l?l?l?l?l?l', description: '8 lowercase letters' },
    { pattern: '?a?a?a?a?a?a?a?a', description: '8 characters (any)' }
  ]

  const startCracking = async () => {
    if (!hashFile.trim()) return

    try {
      const result = await onToolExecute('john_ripper', {
        hashFile: hashFile.trim(),
        hashType,
        attackMode,
        wordlistPath: wordlistPath || undefined,
        customRules: customRules || undefined,
        gpuAcceleration: gpuEnabled,
        maskPattern: maskPattern || undefined
      })

      if (result.jobId) {
        const newJob: CrackingJob = {
          id: result.jobId,
          hashFile: hashFile.trim(),
          hashType,
          attack: attackMode as any,
          status: 'running',
          progress: 0,
          startTime: new Date().toISOString(),
          estimatedTime: result.estimatedTime || 'Unknown',
          crackedCount: 0,
          totalHashes: result.totalHashes || 0,
          currentRate: result.initialRate || '0 p/s',
          gpuAcceleration: gpuEnabled
        }
        
        setActiveJobs(prev => [...prev, newJob])
        
        if (result.crackedPasswords) {
          setCrackedPasswords(result.crackedPasswords)
          setGptAnalysis(result.gptPasswordAnalysis)
        }
        
        setViewMode('jobs')
      }
    } catch (error) {
      console.error('John the Ripper execution failed:', error)
    }
  }

  const getStrengthColor = (strength: string) => {
    switch (strength) {
      case 'very_weak': return 'text-red-600 bg-red-600/20'
      case 'weak': return 'text-red-500 bg-red-500/20'
      case 'medium': return 'text-yellow-500 bg-yellow-500/20'
      case 'strong': return 'text-green-500 bg-green-500/20'
      case 'very_strong': return 'text-green-600 bg-green-600/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  const getJobStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'text-blue-500 bg-blue-500/20'
      case 'completed': return 'text-green-500 bg-green-500/20'
      case 'paused': return 'text-yellow-500 bg-yellow-500/20'
      case 'failed': return 'text-red-500 bg-red-500/20'
      case 'queued': return 'text-gray-500 bg-gray-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  const formatCrackTime = (timeString: string) => {
    // Convert crack time to human readable format
    return timeString || 'Instant'
  }

  return (
    <div className="space-y-6">
      {/* John the Ripper Header */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h3 className="text-xl font-bold text-terminal-text mb-4 flex items-center">
          <Key className="w-6 h-6 mr-3 text-yellow-500" />
          John the Ripper GPU Accelerated
          <span className="ml-3 px-3 py-1 bg-yellow-500 text-black text-sm rounded-full">GPU-POWERED</span>
        </h3>
        <p className="text-terminal-muted">
          Advanced password cracking with GPU acceleration and AI-powered strength analysis
        </p>
      </div>

      {/* Tab Navigation */}
      <div className="flex space-x-2">
        <button
          onClick={() => setViewMode('setup')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'setup' 
              ? 'bg-yellow-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Key className="w-4 h-4" />
          <span>Setup</span>
        </button>
        <button
          onClick={() => setViewMode('jobs')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'jobs' 
              ? 'bg-yellow-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Cpu className="w-4 h-4" />
          <span>Jobs ({activeJobs.length})</span>
        </button>
        <button
          onClick={() => setViewMode('results')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'results' 
              ? 'bg-yellow-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Eye className="w-4 h-4" />
          <span>Results ({crackedPasswords.length})</span>
        </button>
        <button
          onClick={() => setViewMode('analysis')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'analysis' 
              ? 'bg-yellow-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Brain className="w-4 h-4" />
          <span>AI Analysis</span>
        </button>
      </div>

      {/* Setup Tab */}
      {viewMode === 'setup' && (
        <div className="space-y-6">
          {/* Hash File Configuration */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">Hash File Configuration</h4>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
              <div>
                <label className="block text-terminal-text font-medium mb-2">
                  Hash File Path
                </label>
                <input
                  type="text"
                  value={hashFile}
                  onChange={(e) => setHashFile(e.target.value)}
                  placeholder="/path/to/hashes.txt or paste hashes"
                  className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
                />
              </div>

              <div>
                <label className="block text-terminal-text font-medium mb-2">
                  Hash Type
                </label>
                <select
                  value={hashType}
                  onChange={(e) => setHashType(e.target.value)}
                  className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
                >
                  {hashTypes.map((type) => (
                    <option key={type.value} value={type.value}>
                      {type.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* GPU Configuration */}
            <div className="mb-6">
              <div className="flex items-center space-x-3">
                <input
                  type="checkbox"
                  id="gpu-enabled"
                  checked={gpuEnabled}
                  onChange={(e) => setGpuEnabled(e.target.checked)}
                  className="text-yellow-500"
                />
                <label htmlFor="gpu-enabled" className="text-terminal-text font-medium flex items-center">
                  <Zap className="w-4 h-4 mr-2 text-yellow-500" />
                  Enable GPU Acceleration
                </label>
              </div>
              <p className="text-terminal-muted text-sm mt-1">
                Significantly faster cracking with CUDA/OpenCL support
              </p>
            </div>
          </div>

          {/* Attack Configuration */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">Attack Configuration</h4>
            
            <div className="mb-6">
              <label className="block text-terminal-text font-medium mb-2">Attack Mode</label>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {['wordlist', 'brute_force', 'hybrid', 'mask'].map((mode) => (
                  <button
                    key={mode}
                    onClick={() => setAttackMode(mode)}
                    className={`p-3 rounded-lg border transition-colors ${
                      attackMode === mode
                        ? 'border-yellow-500 bg-yellow-500/20 text-yellow-300'
                        : 'border-terminal-border bg-terminal-bg text-terminal-text hover:border-yellow-500/50'
                    }`}
                  >
                    <div className="text-center">
                      <div className="font-medium capitalize">{mode.replace('_', ' ')}</div>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Wordlist Configuration */}
            {(attackMode === 'wordlist' || attackMode === 'hybrid') && (
              <div className="mb-6">
                <label className="block text-terminal-text font-medium mb-2">Wordlist</label>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <select
                    value={wordlistPath}
                    onChange={(e) => setWordlistPath(e.target.value)}
                    className="bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
                  >
                    <option value="">Select a wordlist...</option>
                    {wordlists.map((wordlist) => (
                      <option key={wordlist.value} value={wordlist.value}>
                        {wordlist.label} ({wordlist.size})
                      </option>
                    ))}
                  </select>
                  
                  {wordlistPath === 'custom' && (
                    <input
                      type="text"
                      placeholder="/path/to/custom_wordlist.txt"
                      className="bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
                    />
                  )}
                </div>
              </div>
            )}

            {/* Mask Pattern Configuration */}
            {(attackMode === 'mask' || attackMode === 'hybrid') && (
              <div className="mb-6">
                <label className="block text-terminal-text font-medium mb-2">Mask Pattern</label>
                <div className="space-y-3">
                  <input
                    type="text"
                    value={maskPattern}
                    onChange={(e) => setMaskPattern(e.target.value)}
                    placeholder="?l?l?l?l?d?d?d?d"
                    className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text font-mono"
                  />
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {maskPatterns.map((pattern, index) => (
                      <button
                        key={index}
                        onClick={() => setMaskPattern(pattern.pattern)}
                        className="p-2 bg-terminal-bg border border-terminal-border rounded text-left hover:border-yellow-500/50 transition-colors"
                      >
                        <div className="font-mono text-yellow-400 text-sm">{pattern.pattern}</div>
                        <div className="text-terminal-muted text-xs">{pattern.description}</div>
                      </button>
                    ))}
                  </div>
                  
                  <div className="text-terminal-muted text-sm">
                    <strong>Mask characters:</strong> ?l (lowercase), ?u (uppercase), ?d (digit), ?s (symbol), ?a (all)
                  </div>
                </div>
              </div>
            )}

            {/* Custom Rules */}
            <div className="mb-6">
              <label className="block text-terminal-text font-medium mb-2">Custom Rules (Optional)</label>
              <textarea
                value={customRules}
                onChange={(e) => setCustomRules(e.target.value)}
                placeholder="John rules syntax..."
                rows={3}
                className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text font-mono"
              />
            </div>

            <div className="flex justify-center">
              <button
                onClick={startCracking}
                disabled={!hashFile.trim()}
                className="px-6 py-3 bg-yellow-600 hover:bg-yellow-700 disabled:bg-gray-600 text-white rounded-lg flex items-center space-x-3 transition-colors transform hover:scale-105"
              >
                <Play className="w-5 h-5" />
                <span>Start Cracking</span>
                {gpuEnabled && <Zap className="w-4 h-4" />}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Jobs Tab */}
      {viewMode === 'jobs' && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">Active Cracking Jobs</h4>
          
          {activeJobs.length === 0 ? (
            <div className="text-center py-8">
              <Cpu className="w-12 h-12 text-gray-500 mx-auto mb-4" />
              <p className="text-terminal-muted">No active cracking jobs. Start a new job in the Setup tab.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {activeJobs.map((job) => (
                <div
                  key={job.id}
                  className={`border rounded-lg p-4 cursor-pointer transition-all ${
                    selectedJob?.id === job.id ? 'border-yellow-500 bg-yellow-500/5' : 'border-terminal-border'
                  }`}
                  onClick={() => setSelectedJob(job)}
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getJobStatusColor(job.status)}`}>
                        {job.status.toUpperCase()}
                      </span>
                      <span className="font-medium text-terminal-text">{job.attack.replace('_', ' ')} Attack</span>
                      {job.gpuAcceleration && (
                        <span className="px-2 py-1 bg-yellow-500 text-black text-xs rounded">GPU</span>
                      )}
                    </div>
                    <span className="text-terminal-muted text-sm">
                      {job.crackedCount}/{job.totalHashes} cracked
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm mb-3">
                    <div>
                      <span className="text-terminal-muted">Progress:</span>
                      <div className="mt-1">
                        <div className="w-full bg-gray-600 rounded-full h-2">
                          <div
                            className="bg-yellow-500 h-2 rounded-full transition-all"
                            style={{ width: `${job.progress}%` }}
                          ></div>
                        </div>
                        <span className="text-terminal-text">{job.progress.toFixed(1)}%</span>
                      </div>
                    </div>
                    <div>
                      <span className="text-terminal-muted">Rate:</span>
                      <span className="ml-2 text-terminal-text font-mono">{job.currentRate}</span>
                    </div>
                    <div>
                      <span className="text-terminal-muted">ETA:</span>
                      <span className="ml-2 text-terminal-text">{job.estimatedTime}</span>
                    </div>
                    <div>
                      <span className="text-terminal-muted">Runtime:</span>
                      <span className="ml-2 text-terminal-text">
                        {new Date(Date.now() - new Date(job.startTime).getTime()).toISOString().substr(11, 8)}
                      </span>
                    </div>
                  </div>

                  <div className="text-terminal-muted text-sm">
                    Hash File: {job.hashFile} | Type: {job.hashType}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Results Tab */}
      {viewMode === 'results' && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">Cracked Passwords</h4>
          
          {crackedPasswords.length === 0 ? (
            <div className="text-center py-8">
              <Eye className="w-12 h-12 text-gray-500 mx-auto mb-4" />
              <p className="text-terminal-muted">No passwords cracked yet. Results will appear here as they're found.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {crackedPasswords.map((result, index) => (
                <div key={index} className="border border-terminal-border rounded-lg p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <span className="font-mono text-terminal-text bg-terminal-bg px-2 py-1 rounded">
                        {result.password}
                      </span>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getStrengthColor(result.strength)}`}>
                        {result.strength.replace('_', ' ').toUpperCase()}
                      </span>
                    </div>
                    <span className="text-terminal-muted text-sm">
                      Cracked in {formatCrackTime(result.crackTime)}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-terminal-muted">Hash:</span>
                      <div className="font-mono text-terminal-text text-xs break-all">{result.hash}</div>
                    </div>
                    <div>
                      <span className="text-terminal-muted">Algorithm:</span>
                      <span className="ml-2 text-terminal-text">{result.algorithm}</span>
                    </div>
                  </div>

                  {result.patterns.length > 0 && (
                    <div className="mt-3">
                      <span className="text-terminal-muted text-sm">Patterns detected:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {result.patterns.map((pattern, idx) => (
                          <span key={idx} className="px-2 py-1 bg-blue-500/20 text-blue-400 text-xs rounded">
                            {pattern}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {result.recommendations.length > 0 && (
                    <div className="mt-3 bg-yellow-500/10 border border-yellow-500/20 rounded p-3">
                      <h6 className="font-medium text-yellow-300 mb-2">Security Recommendations:</h6>
                      <ul className="text-yellow-200 text-sm space-y-1">
                        {result.recommendations.map((rec, idx) => (
                          <li key={idx}>• {rec}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* AI Analysis Tab */}
      {viewMode === 'analysis' && gptAnalysis && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <Brain className="w-5 h-5 mr-2 text-blue-500" />
            GPT Password Strength Analysis
          </h4>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div className="bg-terminal-bg border border-terminal-border rounded p-4">
              <h5 className="font-medium text-terminal-text mb-2">Overall Strength Score</h5>
              <div className="flex items-center space-x-3">
                <div className="text-3xl font-bold text-terminal-text">{gptAnalysis.overallStrength}/10</div>
                <div className="w-full bg-gray-600 rounded-full h-3">
                  <div
                    className={`h-3 rounded-full ${
                      gptAnalysis.overallStrength >= 7 ? 'bg-green-500' :
                      gptAnalysis.overallStrength >= 5 ? 'bg-yellow-500' : 'bg-red-500'
                    }`}
                    style={{ width: `${gptAnalysis.overallStrength * 10}%` }}
                  ></div>
                </div>
              </div>
            </div>

            <div className="bg-terminal-bg border border-terminal-border rounded p-4">
              <h5 className="font-medium text-terminal-text mb-2">Policy Compliance</h5>
              <div className="space-y-2">
                {Object.entries(gptAnalysis.policyCompliance).map(([policy, compliant]) => (
                  <div key={policy} className="flex items-center justify-between">
                    <span className="text-terminal-muted capitalize">{policy}:</span>
                    <span className={`text-sm font-medium ${compliant ? 'text-green-400' : 'text-red-400'}`}>
                      {compliant ? 'Pass' : 'Fail'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <h5 className="font-medium text-terminal-text mb-2">Common Patterns Detected</h5>
              <div className="flex flex-wrap gap-2">
                {gptAnalysis.commonPatterns.map((pattern, index) => (
                  <span key={index} className="px-3 py-1 bg-red-500/20 text-red-400 text-sm rounded">
                    {pattern}
                  </span>
                ))}
              </div>
            </div>

            <div>
              <h5 className="font-medium text-terminal-text mb-2">Security Recommendations</h5>
              <ul className="space-y-2">
                {gptAnalysis.securityRecommendations.map((rec, index) => (
                  <li key={index} className="text-terminal-muted text-sm flex items-start space-x-2">
                    <Shield className="w-3 h-3 mt-1 flex-shrink-0 text-green-500" />
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="bg-blue-500/10 border border-blue-500/20 rounded p-4">
              <h5 className="font-medium text-blue-300 mb-2">Risk Assessment</h5>
              <p className="text-blue-200 text-sm">{gptAnalysis.riskAssessment}</p>
            </div>
          </div>
        </div>
      )}

      {/* Export Options */}
      {(crackedPasswords.length > 0 || activeJobs.length > 0) && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-4">
          <div className="flex items-center justify-between">
            <span className="text-terminal-text font-medium">Export Results</span>
            <div className="flex space-x-2">
              <button className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>CSV</span>
              </button>
              <button className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>John Pot</span>
              </button>
              <button className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>Analysis Report</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default JohnRipperPanel