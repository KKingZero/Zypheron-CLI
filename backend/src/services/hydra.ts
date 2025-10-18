import { exec, spawn } from 'child_process'
import { promisify } from 'util'
import * as fs from 'fs'
import * as path from 'path'
import { EventEmitter } from 'events'

const execAsync = promisify(exec)
const fsAsync = {
  readFile: promisify(fs.readFile),
  writeFile: promisify(fs.writeFile),
  unlink: promisify(fs.unlink),
  exists: promisify(fs.exists)
}

export interface HydraOptions {
  target: string
  service: string
  userList?: string[]
  passwordList?: string[]
  threads?: number
  timeout?: number
  verbose?: boolean
  useAI?: boolean
  customWordlist?: string
}

export interface HydraResult {
  success: boolean
  credentials?: {
    username: string
    password: string
  }[]
  attempts: number
  duration: number
  errors?: string[]
  aiSuggestions?: string[]
}

export class HydraService extends EventEmitter {
  private hydraPath: string
  private tempDir: string
  private aiEnabled: boolean

  constructor(hydraPath: string = 'C:\\thc-hydra-master\\hydra.exe', aiEnabled: boolean = true) {
    super()
    this.hydraPath = hydraPath
    this.tempDir = path.join(process.cwd(), 'temp', 'hydra')
    this.aiEnabled = aiEnabled
    
    // Ensure temp directory exists
    if (!fs.existsSync(this.tempDir)) {
      fs.mkdirSync(this.tempDir, { recursive: true })
    }
  }

  async checkInstallation(): Promise<boolean> {
    try {
      const { stdout } = await execAsync(`"${this.hydraPath}" -h`)
      return stdout.includes('Hydra')
    } catch (error) {
      console.error('Hydra not found at:', this.hydraPath)
      return false
    }
  }

  async runAttack(options: HydraOptions): Promise<HydraResult> {
    const startTime = Date.now()
    const result: HydraResult = {
      success: false,
      attempts: 0,
      duration: 0,
      credentials: [],
      errors: []
    }

    try {
      // Validate Hydra installation
      const isInstalled = await this.checkInstallation()
      if (!isInstalled) {
        throw new Error('Hydra is not installed or not found at the specified path')
      }

      // Create temporary wordlist files
      const userFile = await this.createWordlistFile('users', options.userList || this.getDefaultUserList())
      const passFile = await this.createWordlistFile('passwords', options.passwordList || this.getDefaultPasswordList())

      // Build Hydra command
      const args = [
        '-L', userFile,
        '-P', passFile,
        '-t', (options.threads || 16).toString(),
        '-w', (options.timeout || 30).toString(),
        '-f', // Stop on first found
        '-V', // Verbose
        options.target,
        options.service
      ]

      if (options.verbose) {
        args.push('-v')
      }

      // Run Hydra attack
      const hydraProcess = spawn(this.hydraPath, args)
      
      let output = ''
      let errorOutput = ''

      hydraProcess.stdout.on('data', (data) => {
        const chunk = data.toString()
        output += chunk
        
        // Parse real-time results
        const attemptMatch = chunk.match(/\[ATTEMPT\]/g)
        if (attemptMatch) {
          result.attempts += attemptMatch.length
        }

        // Check for successful credentials
        const credMatch = chunk.match(/\[(\d+)\]\[(\w+)\] host: ([\w\.]+)\s+login: (\w+)\s+password: (\w+)/g)
        if (credMatch) {
          credMatch.forEach((match: string) => {
            const parsed = match.match(/\[(\d+)\]\[(\w+)\] host: ([\w\.]+)\s+login: (\w+)\s+password: (\w+)/)
            if (parsed) {
              const [, , service, host, username, password] = parsed
              if (username && password) {
                result.credentials!.push({ username, password })
              }
              result.success = true
              
              this.emit('credential-found', { username, password, service, host })
            }
          })
        }

        this.emit('progress', { attempts: result.attempts, output: chunk })
      })

      hydraProcess.stderr.on('data', (data) => {
        errorOutput += data.toString()
      })

      await new Promise((resolve, reject) => {
        hydraProcess.on('close', (code) => {
          if (code === 0 || result.success) {
            resolve(code)
          } else {
            reject(new Error(`Hydra exited with code ${code}`))
          }
        })

        hydraProcess.on('error', reject)
      })

      // Clean up temp files
      await this.cleanupTempFiles([userFile, passFile])

      // Get AI suggestions if enabled
      if (this.aiEnabled && options.useAI) {
        result.aiSuggestions = await this.getAISuggestions(options, result)
      }

      result.duration = Date.now() - startTime

    } catch (error) {
      result.errors!.push(error instanceof Error ? error.message : 'Unknown error')
      this.emit('error', error)
    }

    return result
  }

  async createWordlistFile(prefix: string, words: string[]): Promise<string> {
    const filename = path.join(this.tempDir, `${prefix}_${Date.now()}.txt`)
    await fsAsync.writeFile(filename, words.join('\n'))
    return filename
  }

  async cleanupTempFiles(files: string[]): Promise<void> {
    for (const file of files) {
      try {
        if (fs.existsSync(file)) {
          await fsAsync.unlink(file)
        }
      } catch (error) {
        console.error(`Failed to delete temp file: ${file}`)
      }
    }
  }

  getDefaultUserList(): string[] {
    return [
      'admin', 'administrator', 'root', 'user', 'test', 'guest',
      'demo', 'oracle', 'postgres', 'mysql', 'web', 'www',
      'ftp', 'mail', 'email', 'sa', 'support', 'operator',
      'manager', 'service', 'system', 'tech', 'technician'
    ]
  }

  getDefaultPasswordList(): string[] {
    return [
      'password', '123456', 'password123', 'admin', 'letmein',
      'welcome', 'monkey', '1234567890', 'qwerty', 'abc123',
      'Password1', 'password1', '123456789', 'welcome123',
      'admin123', 'root', 'toor', 'pass', 'test', 'guest',
      'changeme', 'master', 'default', '12345', '1234'
    ]
  }

  async getAISuggestions(options: HydraOptions, result: HydraResult): Promise<string[]> {
    // This would integrate with the AI service to get intelligent suggestions
    const suggestions = []
    
    if (!result.success) {
      suggestions.push('Consider using a larger wordlist or custom passwords based on target reconnaissance')
      suggestions.push('Try social engineering or OSINT to gather potential usernames')
      suggestions.push(`For ${options.service} service, common default credentials might include service-specific defaults`)
    }

    if (result.attempts > 1000 && !result.success) {
      suggestions.push('High number of attempts without success - consider rate limiting or account lockout policies')
    }

    return suggestions
  }

  // Service-specific attack methods
  async attackSSH(target: string, options: Partial<HydraOptions> = {}): Promise<HydraResult> {
    return this.runAttack({
      target,
      service: 'ssh',
      ...options
    })
  }

  async attackFTP(target: string, options: Partial<HydraOptions> = {}): Promise<HydraResult> {
    return this.runAttack({
      target,
      service: 'ftp',
      ...options
    })
  }

  async attackHTTP(target: string, loginPath: string, options: Partial<HydraOptions> = {}): Promise<HydraResult> {
    return this.runAttack({
      target: `${target}${loginPath}`,
      service: 'http-post-form',
      ...options
    })
  }

  async attackRDP(target: string, options: Partial<HydraOptions> = {}): Promise<HydraResult> {
    return this.runAttack({
      target,
      service: 'rdp',
      ...options
    })
  }

  async attackMySQL(target: string, options: Partial<HydraOptions> = {}): Promise<HydraResult> {
    return this.runAttack({
      target,
      service: 'mysql',
      ...options
    })
  }
}

export default HydraService 