import React, { useState, useEffect } from 'react'
import { Package, FileText, Eye, Search, Download, AlertTriangle, Brain, Shield, Upload, Zap } from 'lucide-react'

interface ExtractedFile {
  id: string
  name: string
  path: string
  size: number
  type: string
  offset: string
  description: string
  entropy: number
  suspicious: boolean
  secrets?: string[]
  analysis?: GPTAnalysis
}

interface GPTAnalysis {
  purpose: string
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
  findings: string[]
  recommendations: string[]
  obfuscation: boolean
  malwareIndicators: string[]
}

interface FirmwareInfo {
  filename: string
  size: number
  architecture: string
  endianness: string
  baseAddress: string
  fileType: string
  compression: string[]
  filesystems: string[]
  bootloaders: string[]
  kernelVersion?: string
  buildInfo?: string
}

interface SecretDetection {
  type: 'password' | 'api_key' | 'certificate' | 'private_key' | 'config'
  value: string
  location: string
  confidence: number
  context: string
}

interface BinwalkPanelProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

const BinwalkPanel: React.FC<BinwalkPanelProps> = ({ onToolExecute }) => {
  const [firmwareFile, setFirmwareFile] = useState<File | null>(null)
  const [analysisMode, setAnalysisMode] = useState<string>('full')
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [firmwareInfo, setFirmwareInfo] = useState<FirmwareInfo | null>(null)
  const [extractedFiles, setExtractedFiles] = useState<ExtractedFile[]>([])
  const [detectedSecrets, setDetectedSecrets] = useState<SecretDetection[]>([])
  const [selectedFile, setSelectedFile] = useState<ExtractedFile | null>(null)
  const [viewMode, setViewMode] = useState<'overview' | 'files' | 'secrets' | 'analysis'>('overview')
  const [searchQuery, setSearchQuery] = useState('')

  const analysisModes = [
    {
      value: 'full',
      name: 'Full Analysis',
      description: 'Complete firmware extraction and analysis',
      duration: '5-15 minutes'
    },
    {
      value: 'quick',
      name: 'Quick Scan',
      description: 'Basic file identification and entropy analysis',
      duration: '1-3 minutes'
    },
    {
      value: 'secrets',
      name: 'Secret Detection',
      description: 'Focus on finding hardcoded secrets and credentials',
      duration: '2-5 minutes'
    },
    {
      value: 'malware',
      name: 'Malware Analysis',
      description: 'Deep analysis for malicious components',
      duration: '10-20 minutes'
    }
  ]

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) {
      setFirmwareFile(file)
      setExtractedFiles([])
      setDetectedSecrets([])
      setFirmwareInfo(null)
    }
  }

  const analyzeFirmware = async () => {
    if (!firmwareFile) return

    setIsAnalyzing(true)
    try {
      const formData = new FormData()
      formData.append('firmware', firmwareFile)
      formData.append('mode', analysisMode)

      const result = await onToolExecute('binwalk_analyze', {
        filename: firmwareFile.name,
        size: firmwareFile.size,
        mode: analysisMode
      })

      if (result) {
        setFirmwareInfo(result.firmwareInfo)
        setExtractedFiles(result.extractedFiles || [])
        setDetectedSecrets(result.secrets || [])
        setViewMode('overview')
      }
    } catch (error) {
      console.error('Firmware analysis failed:', error)
    } finally {
      setIsAnalyzing(false)
    }
  }

  const analyzeFileWithGPT = async (file: ExtractedFile) => {
    try {
      const result = await onToolExecute('binwalk_gpt_analyze', {
        fileId: file.id,
        filename: file.name,
        type: file.type,
        size: file.size,
        entropy: file.entropy
      })

      if (result.analysis) {
        setExtractedFiles(prev => 
          prev.map(f => 
            f.id === file.id 
              ? { ...f, analysis: result.analysis }
              : f
          )
        )
      }
    } catch (error) {
      console.error('GPT analysis failed:', error)
    }
  }

  const getEntropyColor = (entropy: number) => {
    if (entropy > 7.5) return 'text-red-500 bg-red-500/20'
    if (entropy > 6.5) return 'text-yellow-500 bg-yellow-500/20'
    if (entropy > 5.0) return 'text-blue-500 bg-blue-500/20'
    return 'text-green-500 bg-green-500/20'
  }

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'critical': return 'text-red-600 bg-red-600/20'
      case 'high': return 'text-red-500 bg-red-500/20'
      case 'medium': return 'text-yellow-500 bg-yellow-500/20'
      case 'low': return 'text-green-500 bg-green-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  const getSecretTypeColor = (type: string) => {
    switch (type) {
      case 'private_key': return 'text-red-500 bg-red-500/20'
      case 'password': return 'text-red-400 bg-red-400/20'
      case 'api_key': return 'text-yellow-500 bg-yellow-500/20'
      case 'certificate': return 'text-blue-500 bg-blue-500/20'
      case 'config': return 'text-purple-500 bg-purple-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  const filteredFiles = extractedFiles.filter(file => 
    file.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    file.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
    file.description.toLowerCase().includes(searchQuery.toLowerCase())
  )

  return (
    <div className="space-y-6">
      {/* Binwalk Header */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h3 className="text-xl font-bold text-terminal-text mb-4 flex items-center">
          <Package className="w-6 h-6 mr-3 text-orange-500" />
          Binwalk Firmware Analyzer
          <span className="ml-3 px-3 py-1 bg-orange-500 text-white text-sm rounded-full">AI-ENHANCED</span>
        </h3>
        <p className="text-terminal-muted">
          Advanced firmware unpacking and analysis with GPT-powered binary inspection and secret detection
        </p>
        
        {/* Warning */}
        <div className="mt-4 p-4 bg-orange-500/10 border border-orange-500/20 rounded-lg">
          <div className="flex items-start space-x-3">
            <AlertTriangle className="w-5 h-5 text-orange-500 mt-0.5" />
            <div>
              <h4 className="font-medium text-orange-300">Firmware Analysis Notice</h4>
              <p className="text-orange-200 text-sm mt-1">
                Only analyze firmware files you own or have explicit permission to examine. 
                Extracted files may contain sensitive information or intellectual property.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* File Upload and Configuration */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h4 className="text-lg font-semibold text-terminal-text mb-4">Firmware Upload & Configuration</h4>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* File Upload */}
          <div>
            <label className="block text-terminal-text font-medium mb-3">
              Firmware File
            </label>
            <div className="border-2 border-dashed border-terminal-border rounded-lg p-6 text-center">
              <Upload className="w-8 h-8 text-gray-400 mx-auto mb-2" />
              <div className="space-y-2">
                <p className="text-terminal-muted text-sm">
                  Upload firmware binary (.bin, .img, .rom, etc.)
                </p>
                <label className="inline-block px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded cursor-pointer transition-colors">
                  Choose File
                  <input
                    type="file"
                    onChange={handleFileUpload}
                    accept=".bin,.img,.rom,.fw,.dat,.efi,.uefi"
                    className="hidden"
                  />
                </label>
              </div>
            </div>
            
            {firmwareFile && (
              <div className="mt-3 p-3 bg-terminal-bg border border-terminal-border rounded">
                <div className="flex items-center space-x-2">
                  <FileText className="w-4 h-4 text-blue-400" />
                  <span className="text-terminal-text font-medium">{firmwareFile.name}</span>
                </div>
                <div className="text-terminal-muted text-sm mt-1">
                  Size: {(firmwareFile.size / (1024 * 1024)).toFixed(2)} MB
                </div>
              </div>
            )}
          </div>

          {/* Analysis Mode */}
          <div>
            <label className="block text-terminal-text font-medium mb-3">
              Analysis Mode
            </label>
            <div className="space-y-2">
              {analysisModes.map((mode) => (
                <div
                  key={mode.value}
                  className={`border rounded-lg p-3 cursor-pointer transition-all ${
                    analysisMode === mode.value
                      ? 'border-orange-500 bg-orange-500/10'
                      : 'border-terminal-border hover:border-orange-500/50'
                  }`}
                  onClick={() => setAnalysisMode(mode.value)}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-medium text-terminal-text">{mode.name}</span>
                    <span className="text-terminal-muted text-xs">{mode.duration}</span>
                  </div>
                  <p className="text-terminal-muted text-sm">{mode.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="mt-6 flex justify-center">
          <button
            onClick={analyzeFirmware}
            disabled={!firmwareFile || isAnalyzing}
            className="px-6 py-3 bg-orange-600 hover:bg-orange-700 disabled:bg-gray-600 text-white rounded-lg flex items-center space-x-3 transition-colors transform hover:scale-105"
          >
            {isAnalyzing ? (
              <>
                <Package className="w-5 h-5 animate-spin" />
                <span>Analyzing Firmware...</span>
              </>
            ) : (
              <>
                <Zap className="w-5 h-5" />
                <span>Start Analysis</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Results Navigation */}
      {firmwareInfo && (
        <div className="flex space-x-2">
          <button
            onClick={() => setViewMode('overview')}
            className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
              viewMode === 'overview' 
                ? 'bg-orange-600 text-white' 
                : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
            }`}
          >
            <Package className="w-4 h-4" />
            <span>Overview</span>
          </button>
          <button
            onClick={() => setViewMode('files')}
            className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
              viewMode === 'files' 
                ? 'bg-orange-600 text-white' 
                : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
            }`}
          >
            <FileText className="w-4 h-4" />
            <span>Files ({extractedFiles.length})</span>
          </button>
          <button
            onClick={() => setViewMode('secrets')}
            className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
              viewMode === 'secrets' 
                ? 'bg-orange-600 text-white' 
                : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
            }`}
          >
            <Shield className="w-4 h-4" />
            <span>Secrets ({detectedSecrets.length})</span>
          </button>
          <button
            onClick={() => setViewMode('analysis')}
            className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
              viewMode === 'analysis' 
                ? 'bg-orange-600 text-white' 
                : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
            }`}
          >
            <Brain className="w-4 h-4" />
            <span>AI Analysis</span>
          </button>
        </div>
      )}

      {/* Overview Tab */}
      {viewMode === 'overview' && firmwareInfo && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">Firmware Overview</h4>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div className="bg-terminal-bg border border-terminal-border rounded p-4">
              <h5 className="font-medium text-terminal-text mb-3">Basic Information</h5>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-terminal-muted">Filename:</span>
                  <span className="text-terminal-text font-mono">{firmwareInfo.filename}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-terminal-muted">Size:</span>
                  <span className="text-terminal-text">{(firmwareInfo.size / (1024 * 1024)).toFixed(2)} MB</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-terminal-muted">Architecture:</span>
                  <span className="text-terminal-text">{firmwareInfo.architecture}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-terminal-muted">Endianness:</span>
                  <span className="text-terminal-text">{firmwareInfo.endianness}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-terminal-muted">File Type:</span>
                  <span className="text-terminal-text">{firmwareInfo.fileType}</span>
                </div>
              </div>
            </div>

            <div className="bg-terminal-bg border border-terminal-border rounded p-4">
              <h5 className="font-medium text-terminal-text mb-3">Components Found</h5>
              <div className="space-y-3">
                <div>
                  <span className="text-terminal-muted text-sm">Filesystems:</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {firmwareInfo.filesystems.map((fs, idx) => (
                      <span key={idx} className="px-2 py-1 bg-blue-500/20 text-blue-400 text-xs rounded">
                        {fs}
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <span className="text-terminal-muted text-sm">Bootloaders:</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {firmwareInfo.bootloaders.map((boot, idx) => (
                      <span key={idx} className="px-2 py-1 bg-green-500/20 text-green-400 text-xs rounded">
                        {boot}
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <span className="text-terminal-muted text-sm">Compression:</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {firmwareInfo.compression.map((comp, idx) => (
                      <span key={idx} className="px-2 py-1 bg-purple-500/20 text-purple-400 text-xs rounded">
                        {comp}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-terminal-bg border border-terminal-border rounded p-3 text-center">
              <div className="text-2xl font-bold text-terminal-text">{extractedFiles.length}</div>
              <div className="text-terminal-muted text-sm">Files Extracted</div>
            </div>
            <div className="bg-terminal-bg border border-terminal-border rounded p-3 text-center">
              <div className="text-2xl font-bold text-red-500">{detectedSecrets.length}</div>
              <div className="text-terminal-muted text-sm">Secrets Found</div>
            </div>
            <div className="bg-terminal-bg border border-terminal-border rounded p-3 text-center">
              <div className="text-2xl font-bold text-yellow-500">
                {extractedFiles.filter(f => f.suspicious).length}
              </div>
              <div className="text-terminal-muted text-sm">Suspicious Files</div>
            </div>
          </div>
        </div>
      )}

      {/* Files Tab */}
      {viewMode === 'files' && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h4 className="text-lg font-semibold text-terminal-text">Extracted Files</h4>
            <div className="flex items-center space-x-2">
              <Search className="w-4 h-4 text-gray-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search files..."
                className="bg-terminal-bg border border-terminal-border rounded px-3 py-1 text-terminal-text text-sm w-64"
              />
            </div>
          </div>
          
          <div className="space-y-3">
            {filteredFiles.map((file) => (
              <div
                key={file.id}
                className={`border rounded-lg p-4 cursor-pointer transition-all ${
                  selectedFile?.id === file.id ? 'border-orange-500 bg-orange-500/5' : 'border-terminal-border'
                } ${file.suspicious ? 'border-red-500/50 bg-red-500/5' : ''}`}
                onClick={() => setSelectedFile(file)}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    <FileText className="w-4 h-4 text-gray-400" />
                    <span className="font-medium text-terminal-text">{file.name}</span>
                    {file.suspicious && (
                      <span className="px-2 py-1 bg-red-500 text-white text-xs rounded">SUSPICIOUS</span>
                    )}
                    {file.secrets && file.secrets.length > 0 && (
                      <span className="px-2 py-1 bg-yellow-500 text-black text-xs rounded">
                        {file.secrets.length} SECRETS
                      </span>
                    )}
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getEntropyColor(file.entropy)}`}>
                      Entropy: {file.entropy.toFixed(2)}
                    </span>
                    <span className="text-terminal-muted text-sm">{file.size} bytes</span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                  <div>
                    <span className="text-terminal-muted">Type:</span>
                    <span className="ml-2 text-terminal-text">{file.type}</span>
                  </div>
                  <div>
                    <span className="text-terminal-muted">Offset:</span>
                    <span className="ml-2 text-terminal-text font-mono">{file.offset}</span>
                  </div>
                  <div>
                    <span className="text-terminal-muted">Path:</span>
                    <span className="ml-2 text-terminal-text font-mono">{file.path}</span>
                  </div>
                </div>

                <div className="mt-2">
                  <p className="text-terminal-muted text-sm">{file.description}</p>
                </div>

                {file.analysis && (
                  <div className="mt-3 p-3 bg-terminal-bg border border-terminal-border rounded">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-terminal-text font-medium">AI Analysis</span>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getRiskColor(file.analysis.riskLevel)}`}>
                        {file.analysis.riskLevel.toUpperCase()} RISK
                      </span>
                    </div>
                    <p className="text-terminal-muted text-sm mb-2">{file.analysis.purpose}</p>
                    {file.analysis.findings.length > 0 && (
                      <div>
                        <span className="text-terminal-text text-sm font-medium">Key Findings:</span>
                        <ul className="mt-1 space-y-1">
                          {file.analysis.findings.slice(0, 3).map((finding, idx) => (
                            <li key={idx} className="text-terminal-muted text-xs">• {finding}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}

                <div className="mt-3 flex space-x-2">
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      analyzeFileWithGPT(file)
                    }}
                    className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded"
                  >
                    <Brain className="w-3 h-3 inline mr-1" />
                    AI Analyze
                  </button>
                  <button className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded">
                    <Download className="w-3 h-3 inline mr-1" />
                    Download
                  </button>
                  <button className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded">
                    <Eye className="w-3 h-3 inline mr-1" />
                    Hex View
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Secrets Tab */}
      {viewMode === 'secrets' && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">Detected Secrets</h4>
          
          {detectedSecrets.length === 0 ? (
            <div className="text-center py-8">
              <Shield className="w-12 h-12 text-gray-500 mx-auto mb-4" />
              <p className="text-terminal-muted">No hardcoded secrets detected in the firmware.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {detectedSecrets.map((secret, index) => (
                <div key={index} className="border border-terminal-border rounded-lg p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getSecretTypeColor(secret.type)}`}>
                        {secret.type.toUpperCase().replace('_', ' ')}
                      </span>
                      <span className="text-terminal-text font-medium">{secret.location}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className="text-terminal-muted text-sm">
                        Confidence: {(secret.confidence * 100).toFixed(0)}%
                      </span>
                    </div>
                  </div>

                  <div className="bg-terminal-bg border border-terminal-border rounded p-3 mb-3">
                    <div className="font-mono text-terminal-text text-sm break-all">
                      {secret.value.length > 100 ? `${secret.value.slice(0, 100)}...` : secret.value}
                    </div>
                  </div>

                  <div className="text-terminal-muted text-sm">
                    <span className="font-medium">Context:</span> {secret.context}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* AI Analysis Tab */}
      {viewMode === 'analysis' && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <Brain className="w-5 h-5 mr-2 text-blue-500" />
            AI-Powered Firmware Analysis
          </h4>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div>
              <h5 className="font-medium text-terminal-text mb-3">Security Assessment</h5>
              <div className="space-y-3">
                <div className="bg-terminal-bg border border-terminal-border rounded p-3">
                  <div className="flex justify-between">
                    <span className="text-terminal-muted">Overall Risk:</span>
                    <span className="text-red-500 font-bold">MEDIUM</span>
                  </div>
                </div>
                <div className="bg-terminal-bg border border-terminal-border rounded p-3">
                  <div className="flex justify-between">
                    <span className="text-terminal-muted">Encryption Level:</span>
                    <span className="text-yellow-500 font-bold">PARTIAL</span>
                  </div>
                </div>
                <div className="bg-terminal-bg border border-terminal-border rounded p-3">
                  <div className="flex justify-between">
                    <span className="text-terminal-muted">Code Obfuscation:</span>
                    <span className="text-green-500 font-bold">LOW</span>
                  </div>
                </div>
              </div>
            </div>

            <div>
              <h5 className="font-medium text-terminal-text mb-3">Security Recommendations</h5>
              <ul className="space-y-2">
                <li className="text-terminal-muted text-sm flex items-start space-x-2">
                  <Shield className="w-3 h-3 mt-1 text-green-500" />
                  <span>Implement full-disk encryption for sensitive data</span>
                </li>
                <li className="text-terminal-muted text-sm flex items-start space-x-2">
                  <Shield className="w-3 h-3 mt-1 text-green-500" />
                  <span>Remove hardcoded credentials and use secure storage</span>
                </li>
                <li className="text-terminal-muted text-sm flex items-start space-x-2">
                  <Shield className="w-3 h-3 mt-1 text-green-500" />
                  <span>Enable secure boot and code signing</span>
                </li>
                <li className="text-terminal-muted text-sm flex items-start space-x-2">
                  <Shield className="w-3 h-3 mt-1 text-green-500" />
                  <span>Implement runtime application self-protection</span>
                </li>
              </ul>
            </div>
          </div>

          <div>
            <h5 className="font-medium text-terminal-text mb-3">Detailed Analysis</h5>
            <div className="bg-terminal-bg border border-terminal-border rounded p-4">
              <p className="text-terminal-muted text-sm leading-relaxed">
                The firmware appears to be a standard embedded Linux system with several concerning security 
                findings. Multiple hardcoded credentials were discovered, including default SSH keys and 
                administrative passwords. The bootloader lacks signature verification, making it vulnerable 
                to tampering. Several outdated libraries with known vulnerabilities are present. 
                The overall architecture suggests minimal security hardening measures were implemented.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Export Options */}
      {firmwareInfo && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-4">
          <div className="flex items-center justify-between">
            <span className="text-terminal-text font-medium">Export Analysis Results</span>
            <div className="flex space-x-2">
              <button className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>JSON Report</span>
              </button>
              <button className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>Files Archive</span>
              </button>
              <button className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>Security Report</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default BinwalkPanel