import React, { useState, useEffect } from 'react'
import { Code, Brain, Eye, Search, Download, Play, Pause, Target, AlertTriangle, FileText, Zap } from 'lucide-react'

interface BinaryFunction {
  name: string
  address: string
  size: number
  complexity: number
  calls: number
  suspicious: boolean
  gptAnalysis?: string
}

interface DisassemblyLine {
  address: string
  opcode: string
  instruction: string
  operands: string
  comment?: string
  gptExplanation?: string
  suspicious: boolean
  type: 'instruction' | 'function' | 'data' | 'string'
}

interface GPTAnalysis {
  summary: string
  suspiciousPatterns: string[]
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
  recommendations: string[]
  malwareIndicators: string[]
}

interface Radare2PanelProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

const Radare2Panel: React.FC<Radare2PanelProps> = ({ onToolExecute }) => {
  const [binaryFile, setBinaryFile] = useState<File | null>(null)
  const [functions, setFunctions] = useState<BinaryFunction[]>([])
  const [disassembly, setDisassembly] = useState<DisassemblyLine[]>([])
  const [selectedFunction, setSelectedFunction] = useState<BinaryFunction | null>(null)
  const [gptAnalysis, setGptAnalysis] = useState<GPTAnalysis | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [viewMode, setViewMode] = useState<'overview' | 'disasm' | 'analysis' | 'strings'>('overview')
  const [selectedAddress, setSelectedAddress] = useState<string>('')
  const [searchTerm, setSearchTerm] = useState('')

  const analyzeWithRadare2 = async () => {
    if (!binaryFile) return

    setIsAnalyzing(true)
    try {
      const formData = new FormData()
      formData.append('binary', binaryFile)

      const result = await onToolExecute('radare2_analyze', {
        filename: binaryFile.name,
        analysis_level: 'comprehensive',
        gpt_annotations: true
      })

      if (result) {
        setFunctions(result.functions || [])
        setDisassembly(result.disassembly || [])
        setGptAnalysis(result.gptAnalysis)
        setViewMode('overview')
      }
    } catch (error) {
      console.error('Radare2 analysis failed:', error)
    } finally {
      setIsAnalyzing(false)
    }
  }

  const disassembleFunction = async (func: BinaryFunction) => {
    try {
      const result = await onToolExecute('radare2_disassemble', {
        address: func.address,
        size: func.size,
        gpt_explain: true
      })

      if (result.disassembly) {
        setDisassembly(result.disassembly)
        setSelectedFunction(func)
        setViewMode('disasm')
      }
    } catch (error) {
      console.error('Function disassembly failed:', error)
    }
  }

  const analyzeOpcodeWithGPT = async (line: DisassemblyLine) => {
    try {
      const result = await onToolExecute('radare2_gpt_explain', {
        instruction: line.instruction,
        operands: line.operands,
        context: {
          address: line.address,
          function: selectedFunction?.name
        }
      })

      if (result.explanation) {
        setDisassembly(prev => 
          prev.map(l => 
            l.address === line.address 
              ? { ...l, gptExplanation: result.explanation }
              : l
          )
        )
      }
    } catch (error) {
      console.error('GPT opcode analysis failed:', error)
    }
  }

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) {
      setBinaryFile(file)
      setFunctions([])
      setDisassembly([])
      setGptAnalysis(null)
    }
  }

  const getSuspiciousColor = (suspicious: boolean) => {
    return suspicious ? 'text-red-500 bg-red-500/20' : 'text-green-500 bg-green-500/20'
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

  const getInstructionColor = (type: string) => {
    switch (type) {
      case 'function': return 'text-blue-500 bg-blue-500/20'
      case 'instruction': return 'text-purple-500 bg-purple-500/20'
      case 'data': return 'text-orange-500 bg-orange-500/20'
      case 'string': return 'text-green-500 bg-green-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  const filteredDisassembly = disassembly.filter(line =>
    searchTerm === '' || 
    line.instruction.toLowerCase().includes(searchTerm.toLowerCase()) ||
    line.operands.toLowerCase().includes(searchTerm.toLowerCase()) ||
    line.address.includes(searchTerm)
  )

  return (
    <div className="space-y-6">
      {/* Radare2 Header */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h3 className="text-xl font-bold text-terminal-text mb-4 flex items-center">
          <Code className="w-6 h-6 mr-3 text-green-500" />
          Radare2 Binary Analyzer
          <span className="ml-3 px-3 py-1 bg-green-500 text-white text-sm rounded-full">GPT-ENHANCED</span>
        </h3>
        <p className="text-terminal-muted">
          Advanced binary disassembly and reverse engineering with AI-powered opcode explanations
        </p>
        
        {/* Warning */}
        <div className="mt-4 p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
          <div className="flex items-start space-x-3">
            <AlertTriangle className="w-5 h-5 text-yellow-500 mt-0.5" />
            <div>
              <h4 className="font-medium text-yellow-300">Malware Analysis Warning</h4>
              <p className="text-yellow-200 text-sm mt-1">
                Only analyze binaries you trust or in a sandboxed environment. Malicious code can be dangerous.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* File Upload */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h4 className="text-lg font-semibold text-terminal-text mb-4">Binary Upload & Analysis</h4>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="block text-terminal-text font-medium mb-3">
              Select Binary File
            </label>
            <input
              type="file"
              onChange={handleFileUpload}
              accept=".exe,.dll,.so,.bin,.elf"
              className="w-full bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:bg-blue-600 file:text-white hover:file:bg-blue-700"
            />
            
            {binaryFile && (
              <div className="mt-3 p-3 bg-terminal-bg border border-terminal-border rounded">
                <div className="flex items-center space-x-2">
                  <FileText className="w-4 h-4 text-blue-400" />
                  <span className="text-terminal-text font-medium">{binaryFile.name}</span>
                </div>
                <div className="text-terminal-muted text-sm mt-1">
                  Size: {(binaryFile.size / 1024).toFixed(2)} KB
                </div>
              </div>
            )}
          </div>

          <div className="flex items-end">
            <button
              onClick={analyzeWithRadare2}
              disabled={!binaryFile || isAnalyzing}
              className="w-full px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 text-white rounded-lg flex items-center justify-center space-x-2 transition-colors"
            >
              {isAnalyzing ? (
                <>
                  <Code className="w-4 h-4 animate-spin" />
                  <span>Analyzing...</span>
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4" />
                  <span>Analyze Binary</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Results Navigation */}
      {(functions.length > 0 || disassembly.length > 0) && (
        <div className="flex space-x-2">
          <button
            onClick={() => setViewMode('overview')}
            className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
              viewMode === 'overview' 
                ? 'bg-green-600 text-white' 
                : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
            }`}
          >
            <Target className="w-4 h-4" />
            <span>Overview</span>
          </button>
          <button
            onClick={() => setViewMode('disasm')}
            className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
              viewMode === 'disasm' 
                ? 'bg-green-600 text-white' 
                : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
            }`}
          >
            <Code className="w-4 h-4" />
            <span>Disassembly</span>
          </button>
          <button
            onClick={() => setViewMode('analysis')}
            className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
              viewMode === 'analysis' 
                ? 'bg-green-600 text-white' 
                : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
            }`}
          >
            <Brain className="w-4 h-4" />
            <span>AI Analysis</span>
          </button>
          <button
            onClick={() => setViewMode('strings')}
            className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
              viewMode === 'strings' 
                ? 'bg-green-600 text-white' 
                : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
            }`}
          >
            <FileText className="w-4 h-4" />
            <span>Strings</span>
          </button>
        </div>
      )}

      {/* Overview Tab */}
      {viewMode === 'overview' && functions.length > 0 && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">Function Overview</h4>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <div className="bg-terminal-bg border border-terminal-border rounded p-3 text-center">
              <div className="text-2xl font-bold text-terminal-text">{functions.length}</div>
              <div className="text-terminal-muted text-sm">Total Functions</div>
            </div>
            <div className="bg-terminal-bg border border-terminal-border rounded p-3 text-center">
              <div className="text-2xl font-bold text-red-500">
                {functions.filter(f => f.suspicious).length}
              </div>
              <div className="text-terminal-muted text-sm">Suspicious</div>
            </div>
            <div className="bg-terminal-bg border border-terminal-border rounded p-3 text-center">
              <div className="text-2xl font-bold text-yellow-500">
                {functions.filter(f => f.complexity > 10).length}
              </div>
              <div className="text-terminal-muted text-sm">High Complexity</div>
            </div>
          </div>

          <div className="space-y-3">
            {functions.map((func) => (
              <div
                key={func.address}
                className={`border rounded-lg p-4 cursor-pointer transition-all ${
                  selectedFunction?.address === func.address 
                    ? 'border-green-500 bg-green-500/5' 
                    : 'border-terminal-border hover:border-green-500/50'
                } ${func.suspicious ? 'border-red-500/50 bg-red-500/5' : ''}`}
                onClick={() => disassembleFunction(func)}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    <span className="font-mono text-terminal-text">{func.name}</span>
                    {func.suspicious && (
                      <span className="px-2 py-1 bg-red-500 text-white text-xs rounded">SUSPICIOUS</span>
                    )}
                  </div>
                  <div className="flex items-center space-x-3 text-sm">
                    <span className="text-terminal-muted">Size: {func.size}</span>
                    <span className="text-terminal-muted">Calls: {func.calls}</span>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      func.complexity > 15 ? 'text-red-500 bg-red-500/20' :
                      func.complexity > 10 ? 'text-yellow-500 bg-yellow-500/20' :
                      'text-green-500 bg-green-500/20'
                    }`}>
                      Complexity: {func.complexity}
                    </span>
                  </div>
                </div>
                
                <div className="text-terminal-muted text-sm">
                  Address: <span className="font-mono">{func.address}</span>
                </div>

                {func.gptAnalysis && (
                  <div className="mt-2 p-2 bg-terminal-bg border border-terminal-border rounded">
                    <span className="text-blue-400 text-sm">AI Analysis: </span>
                    <span className="text-terminal-muted text-sm">{func.gptAnalysis}</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Disassembly Tab */}
      {viewMode === 'disasm' && (
        <div className="space-y-6">
          {/* Search and Controls */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-4">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2 flex-1">
                <Search className="w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search instructions, operands, or addresses..."
                  className="flex-1 bg-terminal-bg border border-terminal-border rounded px-3 py-1 text-terminal-text"
                />
              </div>
              {selectedFunction && (
                <span className="text-terminal-text font-mono">
                  Function: {selectedFunction.name}
                </span>
              )}
            </div>
          </div>

          {/* Disassembly View */}
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
            <h4 className="text-lg font-semibold text-terminal-text mb-4">Assembly Code</h4>
            
            <div className="space-y-1 max-h-96 overflow-y-auto font-mono text-sm">
              {filteredDisassembly.map((line, index) => (
                <div
                  key={index}
                  className={`grid grid-cols-12 gap-2 p-2 rounded hover:bg-terminal-bg transition-colors ${
                    line.suspicious ? 'border-l-4 border-red-500 bg-red-500/5' : ''
                  }`}
                >
                  {/* Address */}
                  <div className="col-span-2 text-blue-400">{line.address}</div>
                  
                  {/* Opcode */}
                  <div className="col-span-2 text-gray-400">{line.opcode}</div>
                  
                  {/* Instruction */}
                  <div className={`col-span-2 font-medium ${
                    line.type === 'function' ? 'text-blue-500' :
                    line.type === 'data' ? 'text-orange-500' :
                    'text-terminal-text'
                  }`}>
                    {line.instruction}
                  </div>
                  
                  {/* Operands */}
                  <div className="col-span-3 text-green-400">{line.operands}</div>
                  
                  {/* Comment/GPT */}
                  <div className="col-span-2 text-purple-400 text-xs">
                    {line.comment || ''}
                  </div>
                  
                  {/* GPT Button */}
                  <div className="col-span-1 flex justify-end">
                    <button
                      onClick={() => analyzeOpcodeWithGPT(line)}
                      className="p-1 text-blue-400 hover:text-blue-300 transition-colors"
                      title="Explain with AI"
                    >
                      <Brain className="w-3 h-3" />
                    </button>
                  </div>

                  {/* GPT Explanation */}
                  {line.gptExplanation && (
                    <div className="col-span-12 mt-1 p-2 bg-blue-500/10 border border-blue-500/20 rounded text-xs">
                      <span className="text-blue-400 font-medium">AI Explanation: </span>
                      <span className="text-terminal-text">{line.gptExplanation}</span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* AI Analysis Tab */}
      {viewMode === 'analysis' && gptAnalysis && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <Brain className="w-5 h-5 mr-2 text-blue-500" />
            AI Security Analysis
          </h4>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div className="bg-terminal-bg border border-terminal-border rounded p-4">
              <h5 className="font-medium text-terminal-text mb-2">Risk Assessment</h5>
              <div className="flex items-center space-x-3">
                <div className={`text-2xl font-bold ${
                  gptAnalysis.riskLevel === 'critical' ? 'text-red-600' :
                  gptAnalysis.riskLevel === 'high' ? 'text-red-500' :
                  gptAnalysis.riskLevel === 'medium' ? 'text-yellow-500' :
                  'text-green-500'
                }`}>
                  {gptAnalysis.riskLevel.toUpperCase()}
                </div>
                <span className={`px-2 py-1 rounded text-xs font-medium ${getRiskColor(gptAnalysis.riskLevel)}`}>
                  RISK LEVEL
                </span>
              </div>
            </div>

            <div className="bg-terminal-bg border border-terminal-border rounded p-4">
              <h5 className="font-medium text-terminal-text mb-2">Malware Indicators</h5>
              <div className="text-2xl font-bold text-red-500">{gptAnalysis.malwareIndicators.length}</div>
              <div className="text-terminal-muted text-sm">Suspicious patterns detected</div>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <h5 className="font-medium text-terminal-text mb-2">Analysis Summary</h5>
              <div className="bg-terminal-bg border border-terminal-border rounded p-3">
                <p className="text-terminal-muted text-sm">{gptAnalysis.summary}</p>
              </div>
            </div>

            <div>
              <h5 className="font-medium text-terminal-text mb-2">Suspicious Patterns</h5>
              <ul className="space-y-1">
                {gptAnalysis.suspiciousPatterns.map((pattern, index) => (
                  <li key={index} className="text-red-400 text-sm flex items-start space-x-2">
                    <AlertTriangle className="w-3 h-3 mt-1 flex-shrink-0" />
                    <span>{pattern}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <h5 className="font-medium text-terminal-text mb-2">Recommendations</h5>
              <ul className="space-y-1">
                {gptAnalysis.recommendations.map((rec, index) => (
                  <li key={index} className="text-blue-400 text-sm flex items-start space-x-2">
                    <Brain className="w-3 h-3 mt-1 flex-shrink-0" />
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Export Options */}
      {(functions.length > 0 || disassembly.length > 0) && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-4">
          <div className="flex items-center justify-between">
            <span className="text-terminal-text font-medium">Export Analysis</span>
            <div className="flex space-x-2">
              <button className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>Assembly</span>
              </button>
              <button className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>Analysis Report</span>
              </button>
              <button className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded flex items-center space-x-1">
                <Download className="w-3 h-3" />
                <span>JSON Data</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Radare2Panel