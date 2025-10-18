import React, { useState, useEffect } from 'react'
import { 
  Code, 
  Zap, 
  Download, 
  Copy, 
  Settings,
  Terminal,
  Shield,
  AlertTriangle,
  CheckCircle,
  Eye,
  EyeOff,
  Play,
  Cpu,
  Globe,
  Lock
} from 'lucide-react'
import toast from 'react-hot-toast'

interface PayloadGeneratorProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

interface PayloadConfig {
  type: string
  platform: string
  architecture: string
  format: string
  encoder?: string
  iterations?: number
  lhost?: string
  lport?: number
  options?: { [key: string]: string }
}

interface GeneratedPayload {
  payload: string
  size: number
  md5: string
  sha256: string
  description: string
  usage: string
  evasionTechniques: string[]
  detectionRisk: 'low' | 'medium' | 'high'
}

const PayloadGenerator: React.FC<PayloadGeneratorProps> = ({ onToolExecute }) => {
  const [activeTab, setActiveTab] = useState<'generate' | 'encode' | 'listener'>('generate')
  
  // Payload Generation
  const [payloadType, setPayloadType] = useState<string>('windows/meterpreter/reverse_tcp')
  const [platform, setPlatform] = useState<string>('windows')
  const [architecture, setArchitecture] = useState<string>('x86')
  const [format, setFormat] = useState<string>('exe')
  const [lhost, setLhost] = useState<string>('')
  const [lport, setLport] = useState<number>(4444)
  const [badChars, setBadChars] = useState<string>('\\x00\\x0a\\x0d')
  const [customOptions, setCustomOptions] = useState<string>('')
  const [generatedPayload, setGeneratedPayload] = useState<GeneratedPayload | null>(null)
  const [isGenerating, setIsGenerating] = useState<boolean>(false)
  
  // Payload Encoding
  const [encoder, setEncoder] = useState<string>('x86/shikata_ga_nai')
  const [iterations, setIterations] = useState<number>(1)
  const [templateFile, setTemplateFile] = useState<File | null>(null)
  const [encodedPayload, setEncodedPayload] = useState<string>('')
  
  // Listener Setup
  const [listenerType, setListenerType] = useState<string>('multi/handler')
  const [listenerHost, setListenerHost] = useState<string>('0.0.0.0')
  const [listenerPort, setListenerPort] = useState<number>(4444)
  const [isListenerRunning, setIsListenerRunning] = useState<boolean>(false)

  const payloadTypes = {
    windows: [
      { value: 'windows/meterpreter/reverse_tcp', label: 'Meterpreter Reverse TCP', description: 'Full-featured Meterpreter shell' },
      { value: 'windows/meterpreter/reverse_https', label: 'Meterpreter Reverse HTTPS', description: 'HTTPS encrypted Meterpreter' },
      { value: 'windows/shell/reverse_tcp', label: 'Command Shell Reverse TCP', description: 'Basic command shell' },
      { value: 'windows/vncinject/reverse_tcp', label: 'VNC Inject Reverse TCP', description: 'VNC screen sharing' },
      { value: 'windows/powershell_reverse_tcp', label: 'PowerShell Reverse TCP', description: 'PowerShell-based payload' }
    ],
    linux: [
      { value: 'linux/x86/meterpreter/reverse_tcp', label: 'Meterpreter Reverse TCP', description: 'Linux Meterpreter shell' },
      { value: 'linux/x86/shell/reverse_tcp', label: 'Command Shell Reverse TCP', description: 'Basic Linux shell' },
      { value: 'linux/x64/shell_reverse_tcp', label: 'x64 Shell Reverse TCP', description: '64-bit Linux shell' }
    ],
    android: [
      { value: 'android/meterpreter/reverse_tcp', label: 'Android Meterpreter', description: 'Android device control' },
      { value: 'android/meterpreter/reverse_https', label: 'Android Meterpreter HTTPS', description: 'Encrypted Android control' }
    ],
    java: [
      { value: 'java/meterpreter/reverse_tcp', label: 'Java Meterpreter', description: 'Cross-platform Java payload' },
      { value: 'java/jsp_shell_reverse_tcp', label: 'JSP Shell', description: 'Java Server Pages shell' }
    ],
    php: [
      { value: 'php/meterpreter/reverse_tcp', label: 'PHP Meterpreter', description: 'PHP-based Meterpreter' },
      { value: 'php/reverse_php', label: 'PHP Reverse Shell', description: 'Simple PHP reverse shell' }
    ]
  }

  const formats = {
    windows: ['exe', 'dll', 'msi', 'exe-service', 'powershell', 'vba', 'hta'],
    linux: ['elf', 'bash', 'python', 'perl'],
    android: ['apk'],
    java: ['jar', 'war', 'jsp'],
    php: ['raw']
  }

  const encoders = [
    { value: 'x86/shikata_ga_nai', label: 'Shikata Ga Nai', platform: 'x86', description: 'Polymorphic XOR additive feedback encoder' },
    { value: 'x64/xor', label: 'x64 XOR', platform: 'x64', description: 'Simple XOR encoder for x64' },
    { value: 'x86/alpha_mixed', label: 'Alpha Mixed', platform: 'x86', description: 'Alphanumeric mixed case encoder' },
    { value: 'x86/unicode_mixed', label: 'Unicode Mixed', platform: 'x86', description: 'Unicode mixed case encoder' },
    { value: 'cmd/powershell_base64', label: 'PowerShell Base64', platform: 'windows', description: 'Base64 encoded PowerShell' }
  ]

  const generatePayload = async () => {
    if (!lhost.trim()) {
      toast.error('Please enter LHOST (attacker IP)')
      return
    }

    setIsGenerating(true)
    try {
      const config: PayloadConfig = {
        type: payloadType,
        platform,
        architecture,
        format,
        lhost: lhost.trim(),
        lport,
        options: customOptions ? JSON.parse(`{${customOptions}}`) : undefined
      }

      const result = await onToolExecute('generate_payload', config)
      
      if (result) {
        setGeneratedPayload(result)
        toast.success('Payload generated successfully!')
      }
    } catch (error) {
      console.error('Payload generation failed:', error)
      toast.error('Payload generation failed')
    } finally {
      setIsGenerating(false)
    }
  }

  const encodePayload = async () => {
    if (!generatedPayload) {
      toast.error('Please generate a payload first')
      return
    }

    try {
      const result = await onToolExecute('encode_payload', {
        payload: generatedPayload.payload,
        encoder,
        iterations,
        badChars: badChars.split('\\x').filter(c => c).map(c => parseInt(c, 16)),
        template: templateFile ? await templateFile.arrayBuffer() : undefined
      })
      
      if (result) {
        setEncodedPayload(result.encoded)
        toast.success('Payload encoded successfully!')
      }
    } catch (error) {
      console.error('Payload encoding failed:', error)
      toast.error('Payload encoding failed')
    }
  }

  const startListener = async () => {
    try {
      const result = await onToolExecute('start_listener', {
        type: listenerType,
        host: listenerHost,
        port: listenerPort,
        payload: payloadType
      })
      
      if (result.success) {
        setIsListenerRunning(true)
        toast.success(`Listener started on ${listenerHost}:${listenerPort}`)
      }
    } catch (error) {
      console.error('Failed to start listener:', error)
      toast.error('Failed to start listener')
    }
  }

  const stopListener = async () => {
    try {
      await onToolExecute('stop_listener', {})
      setIsListenerRunning(false)
      toast.success('Listener stopped')
    } catch (error) {
      console.error('Failed to stop listener:', error)
      toast.error('Failed to stop listener')
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast.success('Copied to clipboard')
  }

  const downloadPayload = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'application/octet-stream' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'high': return 'text-red-400'
      case 'medium': return 'text-yellow-400'
      case 'low': return 'text-green-400'
      default: return 'text-gray-400'
    }
  }

  return (
    <div className="space-y-6">
      {/* Tab Navigation */}
      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex items-center space-x-2 mb-4">
          <Code className="w-5 h-5 text-red-400" />
          <h3 className="text-lg font-medium text-white">Payload Generation Framework</h3>
        </div>

        <div className="flex space-x-2 mb-6">
          {[
            { id: 'generate', label: 'Generate', icon: Code },
            { id: 'encode', label: 'Encode', icon: Shield },
            { id: 'listener', label: 'Listener', icon: Terminal }
          ].map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id as any)}
              className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-colors ${
                activeTab === id
                  ? 'bg-red-600 text-white'
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{label}</span>
            </button>
          ))}
        </div>

        {/* Generate Tab */}
        {activeTab === 'generate' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Platform
                  </label>
                  <select
                    value={platform}
                    onChange={(e) => {
                      setPlatform(e.target.value)
                      setPayloadType(payloadTypes[e.target.value as keyof typeof payloadTypes][0].value)
                    }}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                  >
                    {Object.keys(payloadTypes).map(plat => (
                      <option key={plat} value={plat}>
                        {plat.charAt(0).toUpperCase() + plat.slice(1)}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Payload Type
                  </label>
                  <select
                    value={payloadType}
                    onChange={(e) => setPayloadType(e.target.value)}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                  >
                    {payloadTypes[platform as keyof typeof payloadTypes].map(payload => (
                      <option key={payload.value} value={payload.value}>
                        {payload.label}
                      </option>
                    ))}
                  </select>
                  <p className="text-xs text-gray-400 mt-1">
                    {payloadTypes[platform as keyof typeof payloadTypes].find(p => p.value === payloadType)?.description}
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Architecture
                    </label>
                    <select
                      value={architecture}
                      onChange={(e) => setArchitecture(e.target.value)}
                      className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                    >
                      <option value="x86">x86 (32-bit)</option>
                      <option value="x64">x64 (64-bit)</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Format
                    </label>
                    <select
                      value={format}
                      onChange={(e) => setFormat(e.target.value)}
                      className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                    >
                      {formats[platform as keyof typeof formats].map(fmt => (
                        <option key={fmt} value={fmt}>
                          {fmt.toUpperCase()}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    LHOST (Attacker IP)
                  </label>
                  <input
                    type="text"
                    value={lhost}
                    onChange={(e) => setLhost(e.target.value)}
                    placeholder="192.168.1.100"
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    LPORT (Listening Port)
                  </label>
                  <input
                    type="number"
                    value={lport}
                    onChange={(e) => setLport(parseInt(e.target.value))}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Bad Characters
                  </label>
                  <input
                    type="text"
                    value={badChars}
                    onChange={(e) => setBadChars(e.target.value)}
                    placeholder="\\x00\\x0a\\x0d"
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Custom Options (JSON)
                  </label>
                  <textarea
                    value={customOptions}
                    onChange={(e) => setCustomOptions(e.target.value)}
                    placeholder='"EXITFUNC": "thread", "PrependMigrate": "true"'
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500"
                    rows={3}
                  />
                </div>
              </div>
            </div>

            <button
              onClick={generatePayload}
              disabled={isGenerating}
              className="flex items-center space-x-2 px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors disabled:opacity-50"
            >
              {isGenerating ? (
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                <Code className="w-4 h-4" />
              )}
              <span>{isGenerating ? 'Generating...' : 'Generate Payload'}</span>
            </button>

            {/* Generated Payload Display */}
            {generatedPayload && (
              <div className="bg-gray-700 rounded-lg p-4">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="font-medium text-white">Generated Payload</h4>
                  <div className="flex space-x-2">
                    <button
                      onClick={() => copyToClipboard(generatedPayload.payload)}
                      className="flex items-center space-x-1 px-3 py-1 bg-gray-600 text-white rounded text-sm hover:bg-gray-500"
                    >
                      <Copy className="w-3 h-3" />
                      <span>Copy</span>
                    </button>
                    <button
                      onClick={() => downloadPayload(generatedPayload.payload, `payload.${format}`)}
                      className="flex items-center space-x-1 px-3 py-1 bg-blue-600 text-white rounded text-sm hover:bg-blue-500"
                    >
                      <Download className="w-3 h-3" />
                      <span>Download</span>
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
                  <div className="text-center">
                    <div className="text-sm text-gray-400">Size</div>
                    <div className="text-white font-mono">{generatedPayload.size} bytes</div>
                  </div>
                  <div className="text-center">
                    <div className="text-sm text-gray-400">Detection Risk</div>
                    <div className={`font-medium ${getRiskColor(generatedPayload.detectionRisk)}`}>
                      {generatedPayload.detectionRisk.toUpperCase()}
                    </div>
                  </div>
                  <div className="text-center">
                    <div className="text-sm text-gray-400">MD5</div>
                    <div className="text-white font-mono text-xs">{generatedPayload.md5}</div>
                  </div>
                  <div className="text-center">
                    <div className="text-sm text-gray-400">SHA256</div>
                    <div className="text-white font-mono text-xs">{generatedPayload.sha256.substring(0, 16)}...</div>
                  </div>
                </div>

                {generatedPayload.evasionTechniques.length > 0 && (
                  <div className="bg-green-900/20 border border-green-500/30 rounded p-3 mb-4">
                    <h5 className="text-green-400 font-medium mb-2">Evasion Techniques Applied</h5>
                    <ul className="text-green-300 text-sm space-y-1">
                      {generatedPayload.evasionTechniques.map((technique, index) => (
                        <li key={index}>• {technique}</li>
                      ))}
                    </ul>
                  </div>
                )}

                <div className="bg-gray-800 rounded p-3">
                  <h5 className="text-white font-medium mb-2">Usage Instructions</h5>
                  <p className="text-gray-300 text-sm">{generatedPayload.usage}</p>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Encode Tab */}
        {activeTab === 'encode' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Encoder
                  </label>
                  <select
                    value={encoder}
                    onChange={(e) => setEncoder(e.target.value)}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                  >
                    {encoders.map(enc => (
                      <option key={enc.value} value={enc.value}>
                        {enc.label}
                      </option>
                    ))}
                  </select>
                  <p className="text-xs text-gray-400 mt-1">
                    {encoders.find(e => e.value === encoder)?.description}
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Encoding Iterations: {iterations}
                  </label>
                  <input
                    type="range"
                    min="1"
                    max="20"
                    value={iterations}
                    onChange={(e) => setIterations(parseInt(e.target.value))}
                    className="w-full"
                  />
                  <div className="flex justify-between text-xs text-gray-400">
                    <span>Fast</span>
                    <span>Secure</span>
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Template File (optional)
                  </label>
                  <input
                    type="file"
                    accept=".exe,.dll,.bin"
                    onChange={(e) => setTemplateFile(e.target.files?.[0] || null)}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white file:mr-4 file:py-1 file:px-3 file:rounded file:border-0 file:bg-red-600 file:text-white"
                  />
                  <p className="text-xs text-gray-400 mt-1">
                    Template for payload injection
                  </p>
                </div>
              </div>
            </div>

            <button
              onClick={encodePayload}
              className="flex items-center space-x-2 px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors"
            >
              <Shield className="w-4 h-4" />
              <span>Encode Payload</span>
            </button>

            {encodedPayload && (
              <div className="bg-gray-700 rounded-lg p-4">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="font-medium text-white">Encoded Payload</h4>
                  <div className="flex space-x-2">
                    <button
                      onClick={() => copyToClipboard(encodedPayload)}
                      className="flex items-center space-x-1 px-3 py-1 bg-gray-600 text-white rounded text-sm hover:bg-gray-500"
                    >
                      <Copy className="w-3 h-3" />
                      <span>Copy</span>
                    </button>
                    <button
                      onClick={() => downloadPayload(encodedPayload, `encoded_payload.${format}`)}
                      className="flex items-center space-x-1 px-3 py-1 bg-blue-600 text-white rounded text-sm hover:bg-blue-500"
                    >
                      <Download className="w-3 h-3" />
                      <span>Download</span>
                    </button>
                  </div>
                </div>
                
                <div className="bg-gray-800 rounded p-3 font-mono text-sm text-green-400 max-h-64 overflow-y-auto">
                  {encodedPayload}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Listener Tab */}
        {activeTab === 'listener' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Listener Type
                </label>
                <select
                  value={listenerType}
                  onChange={(e) => setListenerType(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-red-500"
                >
                  <option value="multi/handler">Multi Handler</option>
                  <option value="exploit/multi/handler">Exploit Multi Handler</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Listen Host
                </label>
                <input
                  type="text"
                  value={listenerHost}
                  onChange={(e) => setListenerHost(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Listen Port
                </label>
                <input
                  type="number"
                  value={listenerPort}
                  onChange={(e) => setListenerPort(parseInt(e.target.value))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-red-500"
                />
              </div>
            </div>

            <div className="flex items-center space-x-4">
              {!isListenerRunning ? (
                <button
                  onClick={startListener}
                  className="flex items-center space-x-2 px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors"
                >
                  <Play className="w-4 h-4" />
                  <span>Start Listener</span>
                </button>
              ) : (
                <button
                  onClick={stopListener}
                  className="flex items-center space-x-2 px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors"
                >
                  <Pause className="w-4 h-4" />
                  <span>Stop Listener</span>
                </button>
              )}

              <div className={`px-3 py-2 rounded text-sm ${
                isListenerRunning ? 'bg-green-600 text-white' : 'bg-gray-600 text-gray-300'
              }`}>
                Status: {isListenerRunning ? 'Running' : 'Stopped'}
              </div>
            </div>

            {isListenerRunning && (
              <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-4">
                <div className="flex items-center space-x-2 mb-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span className="text-green-400 font-medium">Listener Active</span>
                </div>
                <p className="text-green-300 text-sm">
                  Listening on {listenerHost}:{listenerPort} for incoming connections.
                </p>
                <p className="text-green-200 text-xs mt-2">
                  Sessions will appear here when payloads connect back.
                </p>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Warning Banner */}
      <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4">
        <div className="flex items-start space-x-3">
          <AlertTriangle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
          <div>
            <h4 className="font-medium text-red-400 mb-1">Legal and Ethical Notice</h4>
            <p className="text-red-200 text-sm">
              This payload generation tool is intended for authorized penetration testing, 
              red team exercises, and educational purposes only. Using generated payloads 
              against systems without explicit permission is illegal and unethical. 
              Always ensure you have proper authorization before conducting any security testing.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default PayloadGenerator
