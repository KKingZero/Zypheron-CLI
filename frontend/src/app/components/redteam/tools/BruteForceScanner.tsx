import React, { useState, useEffect } from 'react'
import { 
  Zap, 
  Shield, 
  Lock, 
  Play, 
  Pause, 
  Upload,
  Download,
  Target,
  Users,
  Key,
  Clock,
  AlertTriangle,
  CheckCircle,
  Server,
  Wifi
} from 'lucide-react'
import toast from 'react-hot-toast'

interface BruteForceScannerProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

interface BruteForceResult {
  target: string
  protocol: string
  successful: boolean
  credentials?: {
    username: string
    password: string
  }[]
  attempts: number
  timeElapsed: string
  speed: number // attempts per second
  executiveSummary: {
    totalAttempts: number
    successfulLogins: number
    vulnerableAccounts: string[]
    recommendedActions: string[]
    riskScore: number
  }
}

const BruteForceScanner: React.FC<BruteForceScannerProps> = ({ onToolExecute }) => {
  const [target, setTarget] = useState<string>('')
  const [protocol, setProtocol] = useState<string>('ssh')
  const [port, setPort] = useState<number>(22)
  const [usernames, setUsernames] = useState<string>('admin\nroot\nuser\nadministrator\ntest')
  const [passwords, setPasswords] = useState<string>('admin\npassword\n123456\nroot\ntest')
  const [useUserFile, setUseUserFile] = useState<boolean>(false)
  const [usePassFile, setUsePassFile] = useState<boolean>(false)
  const [userFile, setUserFile] = useState<File | null>(null)
  const [passFile, setPassFile] = useState<File | null>(null)
  const [threads, setThreads] = useState<number>(4)
  const [timeout, setTimeout] = useState<number>(30)
  const [isBruteForcing, setIsBruteForcing] = useState<boolean>(false)
  const [bruteResults, setBruteResults] = useState<BruteForceResult | null>(null)
  const [progress, setProgress] = useState<number>(0)
  const [currentAttempt, setCurrentAttempt] = useState<string>('')
  const [speed, setSpeed] = useState<number>(0)

  const protocols = [
    { value: 'ssh', label: 'SSH', defaultPort: 22, description: 'Secure Shell protocol' },
    { value: 'ftp', label: 'FTP', defaultPort: 21, description: 'File Transfer Protocol' },
    { value: 'telnet', label: 'Telnet', defaultPort: 23, description: 'Telnet protocol' },
    { value: 'http-get', label: 'HTTP GET', defaultPort: 80, description: 'HTTP GET form' },
    { value: 'http-post', label: 'HTTP POST', defaultPort: 80, description: 'HTTP POST form' },
    { value: 'https-get', label: 'HTTPS GET', defaultPort: 443, description: 'HTTPS GET form' },
    { value: 'https-post', label: 'HTTPS POST', defaultPort: 443, description: 'HTTPS POST form' },
    { value: 'smb', label: 'SMB', defaultPort: 445, description: 'Server Message Block' },
    { value: 'rdp', label: 'RDP', defaultPort: 3389, description: 'Remote Desktop Protocol' },
    { value: 'mysql', label: 'MySQL', defaultPort: 3306, description: 'MySQL database' },
    { value: 'postgres', label: 'PostgreSQL', defaultPort: 5432, description: 'PostgreSQL database' },
    { value: 'mssql', label: 'MSSQL', defaultPort: 1433, description: 'Microsoft SQL Server' }
  ]

  const handleProtocolChange = (selectedProtocol: string) => {
    setProtocol(selectedProtocol)
    const protocolInfo = protocols.find(p => p.value === selectedProtocol)
    if (protocolInfo) {
      setPort(protocolInfo.defaultPort)
    }
  }

  const startBruteForce = async () => {
    if (!target.trim()) {
      toast.error('Please enter a target host or IP')
      return
    }

    const usernameList = useUserFile && userFile ? 
      (await userFile.text()).split('\n').filter(u => u.trim()) :
      usernames.split('\n').filter(u => u.trim())

    const passwordList = usePassFile && passFile ?
      (await passFile.text()).split('\n').filter(p => p.trim()) :
      passwords.split('\n').filter(p => p.trim())

    if (usernameList.length === 0 || passwordList.length === 0) {
      toast.error('Please provide usernames and passwords')
      return
    }

    setIsBruteForcing(true)
    setProgress(0)
    setSpeed(0)
    setBruteResults(null)

    let progressInterval: NodeJS.Timeout | null = null
    
    try {
      const params = {
        target: target.trim(),
        protocol,
        port,
        usernames: usernameList,
        passwords: passwordList,
        threads,
        timeout
      }

      // Simulate brute force progress
      const totalAttempts = usernameList.length * passwordList.length
      let attemptCount = 0
      const startTime = Date.now()

      progressInterval = setInterval(() => {
        attemptCount += Math.floor(Math.random() * threads) + 1
        const newProgress = Math.min((attemptCount / totalAttempts) * 100, 95)
        setProgress(newProgress)
        
        // Update current attempt
        const randomUser = usernameList[Math.floor(Math.random() * usernameList.length)]
        const randomPass = passwordList[Math.floor(Math.random() * passwordList.length)]
        setCurrentAttempt(`${randomUser}:${randomPass}`)
        
        // Calculate speed
        const elapsed = (Date.now() - startTime) / 1000
        const currentSpeed = Math.floor(attemptCount / elapsed)
        setSpeed(currentSpeed)

        // Don't clear interval here - let finally block handle it
        // if (newProgress >= 95) {
        //   clearInterval(progressInterval)
        // }
      }, 500)

      const result = await onToolExecute('brute_force_attack', params)
      
      setProgress(100)
      setCurrentAttempt('')
      
      if (result) {
        setBruteResults(result)
        if (result.successful) {
          toast.success('Brute force attack completed - credentials found!')
        } else {
          toast.error('Brute force attack completed - no credentials found')
        }
      }
    } catch (error) {
      console.error('Brute force attack failed:', error)
      toast.error('Brute force attack failed')
    } finally {
      // Always clear the interval
      if (progressInterval) {
        clearInterval(progressInterval)
      }
      setIsBruteForcing(false)
    }
  }

  const stopBruteForce = () => {
    setIsBruteForcing(false)
    toast.info('Brute force attack stopped')
  }

  const exportResults = () => {
    if (!bruteResults) return
    
    const report = {
      target,
      protocol,
      port,
      timestamp: new Date().toISOString(),
      results: bruteResults
    }
    
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `brute_force_${target.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const getRiskColor = (riskScore: number) => {
    if (riskScore >= 8) return 'text-red-500'
    if (riskScore >= 6) return 'text-orange-500'
    if (riskScore >= 4) return 'text-yellow-500'
    return 'text-green-500'
  }

  return (
    <div className="space-y-6">
      {/* Configuration Panel */}
      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex items-center space-x-2 mb-4">
          <Zap className="w-5 h-5 text-yellow-400" />
          <h3 className="text-lg font-medium text-white">Brute Force Attack Simulator</h3>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Target Host/IP
              </label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="192.168.1.100 or example.com"
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-yellow-500"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Protocol
                </label>
                <select
                  value={protocol}
                  onChange={(e) => handleProtocolChange(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-yellow-500"
                >
                  {protocols.map(proto => (
                    <option key={proto.value} value={proto.value}>
                      {proto.label}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Port
                </label>
                <input
                  type="number"
                  value={port}
                  onChange={(e) => setPort(parseInt(e.target.value))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-yellow-500"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Threads: {threads}
                </label>
                <input
                  type="range"
                  min="1"
                  max="64"
                  value={threads}
                  onChange={(e) => setThreads(parseInt(e.target.value))}
                  className="w-full"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Timeout (s): {timeout}
                </label>
                <input
                  type="range"
                  min="1"
                  max="120"
                  value={timeout}
                  onChange={(e) => setTimeout(parseInt(e.target.value))}
                  className="w-full"
                />
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm font-medium text-gray-300">
                  Usernames
                </label>
                <div className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    id="useUserFile"
                    checked={useUserFile}
                    onChange={(e) => setUseUserFile(e.target.checked)}
                    className="rounded bg-gray-700 border-gray-600"
                  />
                  <label htmlFor="useUserFile" className="text-sm text-gray-400">
                    Use file
                  </label>
                </div>
              </div>
              
              {useUserFile ? (
                <input
                  type="file"
                  accept=".txt,.lst,.dic"
                  onChange={(e) => setUserFile(e.target.files?.[0] || null)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white file:mr-4 file:py-1 file:px-3 file:rounded file:border-0 file:bg-yellow-600 file:text-white"
                />
              ) : (
                <textarea
                  value={usernames}
                  onChange={(e) => setUsernames(e.target.value)}
                  placeholder="admin&#10;root&#10;user"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-yellow-500"
                  rows={4}
                />
              )}
            </div>

            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm font-medium text-gray-300">
                  Passwords
                </label>
                <div className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    id="usePassFile"
                    checked={usePassFile}
                    onChange={(e) => setUsePassFile(e.target.checked)}
                    className="rounded bg-gray-700 border-gray-600"
                  />
                  <label htmlFor="usePassFile" className="text-sm text-gray-400">
                    Use file
                  </label>
                </div>
              </div>
              
              {usePassFile ? (
                <input
                  type="file"
                  accept=".txt,.lst,.dic"
                  onChange={(e) => setPassFile(e.target.files?.[0] || null)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white file:mr-4 file:py-1 file:px-3 file:rounded file:border-0 file:bg-yellow-600 file:text-white"
                />
              ) : (
                <textarea
                  value={passwords}
                  onChange={(e) => setPasswords(e.target.value)}
                  placeholder="password&#10;123456&#10;admin"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-yellow-500"
                  rows={4}
                />
              )}
            </div>
          </div>
        </div>

        <div className="flex justify-between items-center mt-6">
          <div className="flex items-center space-x-4">
            {!isBruteForcing ? (
              <button
                onClick={startBruteForce}
                className="flex items-center space-x-2 px-4 py-2 bg-yellow-600 text-white rounded-md hover:bg-yellow-700 transition-colors"
              >
                <Play className="w-4 h-4" />
                <span>Start Attack</span>
              </button>
            ) : (
              <button
                onClick={stopBruteForce}
                className="flex items-center space-x-2 px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors"
              >
                <Pause className="w-4 h-4" />
                <span>Stop Attack</span>
              </button>
            )}
            
            <div className="text-sm text-gray-400">
              Protocol: {protocols.find(p => p.value === protocol)?.description}
            </div>
          </div>

          {bruteResults && (
            <button
              onClick={exportResults}
              className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
            >
              <Download className="w-4 h-4" />
              <span>Export Results</span>
            </button>
          )}
        </div>
      </div>

      {/* Progress Panel */}
      {isBruteForcing && (
        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-gray-300">Attack Progress</span>
            <span className="text-sm text-gray-400">{Math.round(progress)}%</span>
          </div>
          <div className="w-full bg-gray-700 rounded-full h-3">
            <div 
              className="bg-yellow-600 h-3 rounded-full transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
          
          <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="flex items-center space-x-2">
              <Clock className="w-4 h-4 text-gray-400" />
              <span className="text-sm text-gray-300">
                Speed: {speed} attempts/sec
              </span>
            </div>
            <div className="flex items-center space-x-2">
              <Target className="w-4 h-4 text-gray-400" />
              <span className="text-sm text-gray-300">
                Target: {target}:{port}
              </span>
            </div>
            <div className="flex items-center space-x-2">
              <Key className="w-4 h-4 text-gray-400" />
              <span className="text-sm text-gray-300 font-mono">
                Trying: {currentAttempt}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Results Panel */}
      {bruteResults && (
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-medium text-white mb-4">Attack Results</h3>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-gray-700 rounded-lg p-4">
              <div className="flex items-center space-x-2">
                {bruteResults.successful ? (
                  <CheckCircle className="w-5 h-5 text-green-400" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-red-400" />
                )}
                <h4 className="font-medium text-white">Status</h4>
              </div>
              <p className={`mt-2 ${bruteResults.successful ? 'text-green-400' : 'text-red-400'}`}>
                {bruteResults.successful ? 'Success' : 'Failed'}
              </p>
            </div>

            <div className="bg-gray-700 rounded-lg p-4">
              <div className="flex items-center space-x-2">
                <Zap className="w-5 h-5 text-yellow-400" />
                <h4 className="font-medium text-white">Attempts</h4>
              </div>
              <p className="mt-2 text-yellow-400 font-bold">
                {bruteResults.attempts.toLocaleString()}
              </p>
            </div>

            <div className="bg-gray-700 rounded-lg p-4">
              <div className="flex items-center space-x-2">
                <Clock className="w-5 h-5 text-blue-400" />
                <h4 className="font-medium text-white">Time Elapsed</h4>
              </div>
              <p className="mt-2 text-blue-400">{bruteResults.timeElapsed}</p>
            </div>

            <div className="bg-gray-700 rounded-lg p-4">
              <div className="flex items-center space-x-2">
                <Shield className="w-5 h-5 text-purple-400" />
                <h4 className="font-medium text-white">Risk Score</h4>
              </div>
              <p className={`mt-2 font-bold ${getRiskColor(bruteResults.executiveSummary.riskScore)}`}>
                {bruteResults.executiveSummary.riskScore}/10
              </p>
            </div>
          </div>

          {bruteResults.successful && bruteResults.credentials && (
            <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-4 mb-4">
              <h4 className="font-medium text-green-400 mb-3 flex items-center">
                <CheckCircle className="w-4 h-4 mr-2" />
                Valid Credentials Found
              </h4>
              <div className="space-y-2">
                {bruteResults.credentials.map((cred, index) => (
                  <div key={index} className="bg-gray-800 rounded p-3 font-mono text-sm">
                    <span className="text-green-400">{cred.username}</span>
                    <span className="text-gray-400">:</span>
                    <span className="text-green-400">{cred.password}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {bruteResults.executiveSummary.vulnerableAccounts.length > 0 && (
            <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4 mb-4">
              <h4 className="font-medium text-red-400 mb-2">Vulnerable Accounts</h4>
              <ul className="space-y-1">
                {bruteResults.executiveSummary.vulnerableAccounts.map((account, index) => (
                  <li key={index} className="text-red-300 text-sm">• {account}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-4">
            <h4 className="font-medium text-blue-400 mb-2">Security Recommendations</h4>
            <ul className="space-y-1">
              {bruteResults.executiveSummary.recommendedActions.map((action, index) => (
                <li key={index} className="text-blue-300 text-sm">• {action}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* Warning Banner */}
      <div className="bg-yellow-900/20 border border-yellow-500/30 rounded-lg p-4">
        <div className="flex items-start space-x-3">
          <AlertTriangle className="w-5 h-5 text-yellow-400 mt-0.5 flex-shrink-0" />
          <div>
            <h4 className="font-medium text-yellow-400 mb-1">Ethical Use Warning</h4>
            <p className="text-yellow-200 text-sm">
              This tool is for authorized penetration testing and educational purposes only. 
              Only use against systems you own or have explicit permission to test. 
              Unauthorized access to computer systems is illegal and may result in criminal prosecution.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default BruteForceScanner
