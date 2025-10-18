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

export interface HashcatOptions {
  hashFile?: string
  hashes?: string[]
  attackMode?: number // 0=straight, 1=combination, 3=brute-force, 6=hybrid wordlist+mask, 7=hybrid mask+wordlist
  hashType?: number
  wordlist?: string
  rules?: string
  mask?: string
  increment?: boolean
  incrementMin?: number
  incrementMax?: number
  optimized?: boolean
  workloadProfile?: number // 1=low, 2=default, 3=high, 4=nightmare
  useAI?: boolean
}

export interface HashcatResult {
  success: boolean
  crackedHashes?: {
    hash: string
    plaintext: string
    hashType?: string
  }[]
  totalHashes: number
  crackedCount: number
  speed?: string
  timeRemaining?: string
  progress?: number
  duration: number
  errors?: string[]
  aiSuggestions?: string[]
}

export class HashcatService extends EventEmitter {
  private hashcatPath: string
  private tempDir: string
  private potFile: string
  private aiEnabled: boolean

  constructor(hashcatPath: string = 'C:\\hashcat-master\\hashcat.exe', aiEnabled: boolean = true) {
    super()
    this.hashcatPath = hashcatPath
    this.tempDir = path.join(process.cwd(), 'temp', 'hashcat')
    this.potFile = path.join(this.tempDir, 'hashcat.potfile')
    this.aiEnabled = aiEnabled
    
    // Ensure temp directory exists
    if (!fs.existsSync(this.tempDir)) {
      fs.mkdirSync(this.tempDir, { recursive: true })
    }
  }

  async checkInstallation(): Promise<boolean> {
    try {
      const { stdout } = await execAsync(`"${this.hashcatPath}" --version`)
      return stdout.includes('hashcat')
    } catch (error) {
      console.error('Hashcat not found at:', this.hashcatPath)
      return false
    }
  }

  async identifyHashType(hash: string): Promise<number | null> {
    // Common hash type identification
    const hashPatterns = [
      { pattern: /^[a-f0-9]{32}$/i, type: 0 }, // MD5
      { pattern: /^[a-f0-9]{40}$/i, type: 100 }, // SHA1
      { pattern: /^[a-f0-9]{64}$/i, type: 1400 }, // SHA256
      { pattern: /^[a-f0-9]{128}$/i, type: 1700 }, // SHA512
      { pattern: /^\$2[ayb]\$.{56}$/i, type: 3200 }, // bcrypt
      { pattern: /^\$1\$.{8}\$.{22}$/i, type: 500 }, // MD5 crypt
      { pattern: /^\$5\$.{16}\$.{43}$/i, type: 7400 }, // SHA256 crypt
      { pattern: /^\$6\$.{16}\$.{86}$/i, type: 1800 }, // SHA512 crypt
      { pattern: /^[a-f0-9]{32}:[a-f0-9]+$/i, type: 0 }, // MD5 with salt
      { pattern: /^[a-z0-9\/.]{13}$/i, type: 1500 }, // DES crypt
      { pattern: /^NTLM:/i, type: 1000 }, // NTLM
    ]

    for (const { pattern, type } of hashPatterns) {
      if (pattern.test(hash)) {
        return type
      }
    }

    // If AI is enabled, use AI to identify hash type
    if (this.aiEnabled) {
      return await this.identifyHashTypeWithAI(hash)
    }

    return null
  }

  async runAttack(options: HashcatOptions): Promise<HashcatResult> {
    const startTime = Date.now()
    const result: HashcatResult = {
      success: false,
      totalHashes: 0,
      crackedCount: 0,
      duration: 0,
      crackedHashes: [],
      errors: []
    }

    try {
      // Validate Hashcat installation
      const isInstalled = await this.checkInstallation()
      if (!isInstalled) {
        throw new Error('Hashcat is not installed or not found at the specified path')
      }

      // Create hash file if hashes provided
      let hashFile = options.hashFile
      if (!hashFile && options.hashes) {
        hashFile = await this.createHashFile(options.hashes)
      }

      if (!hashFile) {
        throw new Error('No hash file or hashes provided')
      }

      // Auto-detect hash type if not provided
      if (!options.hashType && options.hashes && options.hashes.length > 0) {
        const firstHash = options.hashes[0]
        if (firstHash) {
          options.hashType = await this.identifyHashType(firstHash) || 0
        }
      }

      // Build Hashcat command
      const args = [
        '-m', (options.hashType || 0).toString(),
        '-a', (options.attackMode || 0).toString(),
        '--potfile-path', this.potFile,
        '--status',
        '--status-timer', '1',
        '-o', path.join(this.tempDir, 'cracked.txt'),
        '--outfile-format', '3'
      ]

      if (options.optimized) {
        args.push('-O')
      }

      if (options.workloadProfile) {
        args.push('-w', options.workloadProfile.toString())
      }

      args.push(hashFile)

      // Add attack-specific parameters
      if (options.attackMode === 0 && options.wordlist) {
        args.push(options.wordlist)
        if (options.rules) {
          args.push('-r', options.rules)
        }
      } else if (options.attackMode === 3 && options.mask) {
        args.push(options.mask)
        if (options.increment) {
          args.push('--increment')
          if (options.incrementMin) {
            args.push('--increment-min', options.incrementMin.toString())
          }
          if (options.incrementMax) {
            args.push('--increment-max', options.incrementMax.toString())
          }
        }
      }

      // Run Hashcat attack
      const hashcatProcess = spawn(this.hashcatPath, args)
      
      let output = ''
      let errorOutput = ''

      hashcatProcess.stdout.on('data', (data) => {
        const chunk = data.toString()
        output += chunk
        
        // Parse status updates
        const statusMatch = chunk.match(/Status\.+: (.+)/g)
        if (statusMatch) {
          this.parseStatus(chunk, result)
        }

        // Check for cracked hashes
        const crackedMatch = chunk.match(/(.+):(.+)/g)
        if (crackedMatch && chunk.includes('Recovered')) {
          this.parseCrackedHashes(chunk, result)
        }

        this.emit('progress', { 
          progress: result.progress, 
          speed: result.speed,
          timeRemaining: result.timeRemaining,
          output: chunk 
        })
      })

      hashcatProcess.stderr.on('data', (data) => {
        errorOutput += data.toString()
      })

      await new Promise((resolve, reject) => {
        hashcatProcess.on('close', (code) => {
          if (code === 0 || code === 1) { // 0 = cracked, 1 = exhausted
            resolve(code)
          } else {
            reject(new Error(`Hashcat exited with code ${code}`))
          }
        })

        hashcatProcess.on('error', reject)
      })

      // Read cracked hashes from output file
      const crackedFile = path.join(this.tempDir, 'cracked.txt')
      if (fs.existsSync(crackedFile)) {
        const crackedData = await fsAsync.readFile(crackedFile, 'utf8')
        result.crackedHashes = this.parseCrackedFile(crackedData)
        result.crackedCount = result.crackedHashes.length
        result.success = result.crackedCount > 0
      }

      // Clean up temp files
      if (options.hashes) {
        await this.cleanupTempFiles([hashFile!])
      }

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

  async createHashFile(hashes: string[]): Promise<string> {
    const filename = path.join(this.tempDir, `hashes_${Date.now()}.txt`)
    await fsAsync.writeFile(filename, hashes.join('\n'))
    return filename
  }

  parseStatus(output: string, result: HashcatResult): void {
    // Parse progress
    const progressMatch = output.match(/Progress\.+: (\d+)\/(\d+) \((\d+\.\d+)%\)/)
    if (progressMatch && progressMatch[3] && progressMatch[2]) {
      result.progress = parseFloat(progressMatch[3])
      result.totalHashes = parseInt(progressMatch[2])
    }

    // Parse speed
    const speedMatch = output.match(/Speed\.+: (.+)/)
    if (speedMatch) {
      result.speed = speedMatch[1]
    }

    // Parse time remaining
    const timeMatch = output.match(/Time\.Estimated\.+: (.+)/)
    if (timeMatch) {
      result.timeRemaining = timeMatch[1]
    }

    // Parse recovered
    const recoveredMatch = output.match(/Recovered\.+: (\d+)\/(\d+)/)
    if (recoveredMatch && recoveredMatch[1] && recoveredMatch[2]) {
      result.crackedCount = parseInt(recoveredMatch[1])
      result.totalHashes = parseInt(recoveredMatch[2])
    }
  }

  parseCrackedFile(data: string): { hash: string; plaintext: string }[] {
    const lines = data.trim().split('\n')
    return lines.map(line => {
      const [hash, plaintext] = line.split(':')
      return { hash: hash || '', plaintext: plaintext || '' }
    }).filter(item => item.hash && item.plaintext)
  }

  parseCrackedHashes(output: string, result: HashcatResult): void {
    const lines = output.split('\n')
    lines.forEach(line => {
      if (line.includes(':') && !line.includes('Status') && !line.includes('Speed')) {
        const [hash, plaintext] = line.split(':')
        if (hash && plaintext) {
          result.crackedHashes!.push({ hash: hash.trim(), plaintext: plaintext.trim() })
        }
      }
    })
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

  async identifyHashTypeWithAI(hash: string): Promise<number | null> {
    // This would integrate with AI to identify complex hash types
    // For now, return null to use default
    return null
  }

  async getAISuggestions(options: HashcatOptions, result: HashcatResult): Promise<string[]> {
    const suggestions = []
    
    if (!result.success && options.attackMode === 0) {
      suggestions.push('Try using rule-based attacks with common password mutations')
      suggestions.push('Consider hybrid attacks combining wordlists with masks')
      suggestions.push('Use larger wordlists like rockyou.txt or custom wordlists based on target')
    }

    if (!result.success && options.attackMode === 3) {
      suggestions.push('Brute force failed - consider using targeted masks based on password policy')
      suggestions.push('Try incremental mode starting with shorter lengths')
    }

    if (result.crackedCount > 0 && result.crackedCount < result.totalHashes) {
      suggestions.push(`${result.crackedCount}/${result.totalHashes} hashes cracked - remaining hashes may use stronger passwords`)
      suggestions.push('Analyze cracked passwords for patterns to improve attack strategy')
    }

    return suggestions
  }

  // Common attack presets
  async crackMD5(hashes: string[], wordlist?: string): Promise<HashcatResult> {
    return this.runAttack({
      hashes,
      hashType: 0,
      attackMode: 0,
      wordlist: wordlist || 'C:\\hashcat-master\\wordlists\\rockyou.txt',
      optimized: true
    })
  }

  async crackNTLM(hashes: string[], wordlist?: string): Promise<HashcatResult> {
    return this.runAttack({
      hashes,
      hashType: 1000,
      attackMode: 0,
      wordlist: wordlist || 'C:\\hashcat-master\\wordlists\\rockyou.txt',
      optimized: true
    })
  }

  async crackWPA2(handshakeFile: string, wordlist?: string): Promise<HashcatResult> {
    return this.runAttack({
      hashFile: handshakeFile,
      hashType: 2500,
      attackMode: 0,
      wordlist: wordlist || 'C:\\hashcat-master\\wordlists\\rockyou.txt',
      workloadProfile: 3
    })
  }

  async bruteForceNumeric(hashes: string[], length: number): Promise<HashcatResult> {
    return this.runAttack({
      hashes,
      attackMode: 3,
      mask: '?d'.repeat(length),
      optimized: true
    })
  }
}

export default HashcatService 