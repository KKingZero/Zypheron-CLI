import { EventEmitter } from 'events'
import * as crypto from 'crypto'
import * as fs from 'fs'
import * as path from 'path'

export interface HashCrackOptions {
  hashes: string[]
  hashType: 'md5' | 'sha1' | 'sha256' | 'sha512' | 'ntlm' | 'auto'
  attackMode: 'dictionary' | 'brute-force' | 'hybrid'
  wordlist?: string[]
  customWordlist?: string
  charset?: string
  minLength?: number
  maxLength?: number
  useAI?: boolean
  threads?: number
  timeout?: number
}

export interface HashCrackResult {
  success: boolean
  crackedHashes: {
    hash: string
    plaintext: string
    hashType: string
    crackTime: number
  }[]
  totalHashes: number
  crackedCount: number
  attempts: number
  duration: number
  speed: number // hashes per second
  errors: string[]
  aiSuggestions?: string[]
}

export interface HashCrackAttempt {
  plaintext: string
  hash: string
  expectedHash: string
  success: boolean
  hashType: string
}

export class NativeHashCrackerService extends EventEmitter {
  private defaultWordlist = [
    'password', '123456', 'admin', 'root', 'toor', 'pass', 'test', 'guest',
    '1234', '12345', 'qwerty', 'abc123', 'letmein', 'welcome', 'login',
    'changeme', 'password123', 'admin123', 'administrator', 'default',
    'secret', 'monkey', 'dragon', 'master', 'hello', 'shadow', 'mustang',
    '654321', 'superman', '1qaz2wsx', 'michael', 'football', 'baseball',
    'liverpool', 'jordan', 'freedom', 'princess', 'maggie', 'computer',
    'password1', 'password!', 'Password123', 'sunshine', 'iloveyou'
  ]

  private commonPatterns = [
    '{word}', '{word}123', '{word}!', '{word}1', '{word}01',
    '{WORD}', '{Word}', '123{word}', '{word}2023', '{word}2024',
    '{word}@', '{word}#', '{word}$', '{word}%'
  ]

  private charsets = {
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    digits: '0123456789',
    special: '!@#$%^&*()_+-=[]{}|;:,.<>?',
    all: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?'
  }

  async crackHashes(options: HashCrackOptions): Promise<HashCrackResult> {
    const startTime = Date.now()
    const result: HashCrackResult = {
      success: false,
      crackedHashes: [],
      totalHashes: options.hashes.length,
      crackedCount: 0,
      attempts: 0,
      duration: 0,
      speed: 0,
      errors: []
    }

    try {
      // Auto-detect hash types if needed
      const hashesWithTypes = await this.analyzeHashes(options.hashes, options.hashType)

      this.emit('progress', {
        message: `Starting hash cracking for ${options.hashes.length} hashes`,
        progress: 0,
        totalHashes: options.hashes.length
      })

      // Choose attack strategy
      switch (options.attackMode) {
        case 'dictionary':
          await this.dictionaryAttack(hashesWithTypes, options, result)
          break
        case 'brute-force':
          await this.bruteForceAttack(hashesWithTypes, options, result)
          break
        case 'hybrid':
          // Try dictionary first, then brute force
          await this.dictionaryAttack(hashesWithTypes, options, result)
          if (result.crackedCount < result.totalHashes) {
            await this.bruteForceAttack(hashesWithTypes, options, result)
          }
          break
      }

      result.duration = Date.now() - startTime
      result.speed = Math.round(result.attempts / (result.duration / 1000))
      result.success = result.crackedCount > 0

      // Add AI suggestions if enabled
      if (options.useAI && result.crackedCount === 0) {
        result.aiSuggestions = this.generateAISuggestions(hashesWithTypes, result.errors)
      }

      this.emit('complete', result)
      return result

    } catch (error: any) {
      result.errors.push(error.message)
      result.duration = Date.now() - startTime
      this.emit('error', error)
      return result
    }
  }

  private async analyzeHashes(hashes: string[], hashType: string): Promise<{ hash: string, type: string }[]> {
    if (hashType !== 'auto') {
      return hashes.map(hash => ({ hash, type: hashType }))
    }

    // Auto-detect hash types based on length and format
    return hashes.map(hash => {
      const cleanHash = hash.trim().toLowerCase()
      let detectedType = 'unknown'

      if (cleanHash.length === 32 && /^[a-f0-9]+$/.test(cleanHash)) {
        detectedType = 'md5'
      } else if (cleanHash.length === 40 && /^[a-f0-9]+$/.test(cleanHash)) {
        detectedType = 'sha1'
      } else if (cleanHash.length === 64 && /^[a-f0-9]+$/.test(cleanHash)) {
        detectedType = 'sha256'
      } else if (cleanHash.length === 128 && /^[a-f0-9]+$/.test(cleanHash)) {
        detectedType = 'sha512'
      } else if (cleanHash.length === 32 && /^[a-f0-9A-F]+$/.test(hash.trim())) {
        detectedType = 'ntlm'
      }

      return { hash: cleanHash, type: detectedType }
    })
  }

  private async dictionaryAttack(
    hashesWithTypes: { hash: string, type: string }[],
    options: HashCrackOptions,
    result: HashCrackResult
  ): Promise<void> {
    // Get wordlist
    let wordlist = options.wordlist || this.defaultWordlist

    // Load custom wordlist if provided
    if (options.customWordlist) {
      try {
        const customWords = await this.loadWordlistFile(options.customWordlist)
        wordlist = [...wordlist, ...customWords]
      } catch (error: any) {
        result.errors.push(`Failed to load custom wordlist: ${error.message}`)
      }
    }

    // Remove duplicates and sort by frequency/length
    wordlist = [...new Set(wordlist)].sort((a, b) => a.length - b.length)

    this.emit('progress', {
      message: `Starting dictionary attack with ${wordlist.length} words`,
      progress: 0
    })

    const totalAttempts = wordlist.length * this.commonPatterns.length * hashesWithTypes.length
    let currentAttempt = 0

    // Try each word with common patterns
    for (const baseWord of wordlist) {
      for (const pattern of this.commonPatterns) {
        const plaintext = this.applyPattern(pattern, baseWord)
        
        for (const hashData of hashesWithTypes) {
          if (result.crackedHashes.some(c => c.hash === hashData.hash)) {
            continue // Already cracked
          }

          currentAttempt++
          result.attempts++

          const attempt = await this.tryPlaintext(plaintext, hashData.hash, hashData.type)
          
          if (attempt.success) {
            const crackTime = Date.now()
            result.crackedHashes.push({
              hash: hashData.hash,
              plaintext,
              hashType: hashData.type,
              crackTime
            })
            result.crackedCount++

            this.emit('success', {
              hash: hashData.hash,
              plaintext,
              hashType: hashData.type
            })

            // Stop if all hashes are cracked
            if (result.crackedCount === result.totalHashes) {
              return
            }
          }

          // Update progress
          const progress = Math.round((currentAttempt / totalAttempts) * 100)
          this.emit('progress', {
            message: `Dictionary: ${plaintext} (${result.crackedCount}/${result.totalHashes} cracked)`,
            progress,
            crackedCount: result.crackedCount,
            totalHashes: result.totalHashes,
            currentWord: plaintext
          })

          // Small delay to prevent overwhelming
          if (currentAttempt % 1000 === 0) {
            await new Promise(resolve => setTimeout(resolve, 10))
          }
        }
      }
    }
  }

  private async bruteForceAttack(
    hashesWithTypes: { hash: string, type: string }[],
    options: HashCrackOptions,
    result: HashCrackResult
  ): Promise<void> {
    const charset = options.charset || this.charsets.all
    const minLength = options.minLength || 1
    const maxLength = options.maxLength || 8

    this.emit('progress', {
      message: `Starting brute force attack (length ${minLength}-${maxLength})`,
      progress: 0
    })

    // Calculate total combinations for progress tracking
    let totalCombinations = 0
    for (let len = minLength; len <= maxLength; len++) {
      totalCombinations += Math.pow(charset.length, len)
    }

    let currentAttempt = 0

    // Try all combinations from minLength to maxLength
    for (let length = minLength; length <= maxLength; length++) {
      if (result.crackedCount === result.totalHashes) {
        break // All hashes cracked
      }

      await this.bruteForceLength(charset, length, hashesWithTypes, result, (attempt) => {
        currentAttempt++
        const progress = Math.round((currentAttempt / totalCombinations) * 100)
        
        this.emit('progress', {
          message: `Brute force: ${attempt} (${result.crackedCount}/${result.totalHashes} cracked)`,
          progress,
          crackedCount: result.crackedCount,
          totalHashes: result.totalHashes,
          currentAttempt: attempt
        })
      })
    }
  }

  private async bruteForceLength(
    charset: string,
    length: number,
    hashesWithTypes: { hash: string, type: string }[],
    result: HashCrackResult,
    progressCallback: (attempt: string) => void
  ): Promise<void> {
    const generateCombinations = function* (chars: string, len: number): Generator<string> {
      if (len === 1) {
        for (const char of chars) {
          yield char
        }
      } else {
        for (const char of chars) {
          for (const rest of generateCombinations(chars, len - 1)) {
            yield char + rest
          }
        }
      }
    }

    for (const combination of generateCombinations(charset, length)) {
      result.attempts++
      progressCallback(combination)

      for (const hashData of hashesWithTypes) {
        if (result.crackedHashes.some(c => c.hash === hashData.hash)) {
          continue // Already cracked
        }

        const attempt = await this.tryPlaintext(combination, hashData.hash, hashData.type)
        
        if (attempt.success) {
          const crackTime = Date.now()
          result.crackedHashes.push({
            hash: hashData.hash,
            plaintext: combination,
            hashType: hashData.type,
            crackTime
          })
          result.crackedCount++

          this.emit('success', {
            hash: hashData.hash,
            plaintext: combination,
            hashType: hashData.type
          })

          // Stop if all hashes are cracked
          if (result.crackedCount === result.totalHashes) {
            return
          }
        }
      }

      // Small delay every 1000 attempts
      if (result.attempts % 1000 === 0) {
        await new Promise(resolve => setTimeout(resolve, 10))
      }
    }
  }

  private async tryPlaintext(plaintext: string, expectedHash: string, hashType: string): Promise<HashCrackAttempt> {
    try {
      const computedHash = this.computeHash(plaintext, hashType)
      const success = computedHash.toLowerCase() === expectedHash.toLowerCase()

      return {
        plaintext,
        hash: computedHash,
        expectedHash,
        success,
        hashType
      }
    } catch (error: any) {
      return {
        plaintext,
        hash: '',
        expectedHash,
        success: false,
        hashType
      }
    }
  }

  private computeHash(plaintext: string, hashType: string): string {
    switch (hashType.toLowerCase()) {
      case 'md5':
        return crypto.createHash('md5').update(plaintext).digest('hex')
      case 'sha1':
        return crypto.createHash('sha1').update(plaintext).digest('hex')
      case 'sha256':
        return crypto.createHash('sha256').update(plaintext).digest('hex')
      case 'sha512':
        return crypto.createHash('sha512').update(plaintext).digest('hex')
      case 'ntlm':
        // NTLM is MD4 of UTF-16LE encoded password
        const utf16le = Buffer.from(plaintext, 'utf16le')
        return crypto.createHash('md4').update(utf16le).digest('hex')
      default:
        throw new Error(`Unsupported hash type: ${hashType}`)
    }
  }

  private applyPattern(pattern: string, word: string): string {
    return pattern
      .replace(/{word}/g, word)
      .replace(/{WORD}/g, word.toUpperCase())
      .replace(/{Word}/g, word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
  }

  private async loadWordlistFile(filePath: string): Promise<string[]> {
    try {
      const content = await fs.promises.readFile(filePath, 'utf8')
      return content
        .split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0)
    } catch (error) {
      throw new Error(`Failed to load wordlist file: ${filePath}`)
    }
  }

  private generateAISuggestions(hashesWithTypes: { hash: string, type: string }[], errors: string[]): string[] {
    const suggestions: string[] = []

    // Analyze hash types
    const hashTypes = [...new Set(hashesWithTypes.map(h => h.type))]
    
    suggestions.push('Try using a larger wordlist with common passwords for your target')
    suggestions.push('Consider using rules to modify dictionary words (leetspeak, years, etc.)')

    if (hashTypes.includes('unknown')) {
      suggestions.push('Some hash types could not be identified - verify hash format')
    }

    if (hashTypes.includes('md5') || hashTypes.includes('sha1')) {
      suggestions.push('MD5/SHA1 hashes are weak - try rainbow tables or online databases')
    }

    if (hashTypes.includes('ntlm')) {
      suggestions.push('NTLM hashes are case-insensitive - focus on lowercase attacks first')
    }

    suggestions.push('Try hybrid attacks combining dictionary words with numbers/symbols')
    suggestions.push('Consider mask attacks if you know password patterns (e.g., company name + year)')
    suggestions.push('Use statistical analysis to prioritize common password patterns')

    if (errors.length > 0) {
      suggestions.push('Check hash format and ensure proper encoding (hex, base64, etc.)')
    }

    return suggestions
  }

  // Utility methods for external access
  async identifyHashType(hash: string): Promise<string> {
    const analysis = await this.analyzeHashes([hash], 'auto')
    return analysis[0]?.type || 'unknown'
  }

  async validateHash(hash: string, hashType: string): Promise<boolean> {
    try {
      const analyzed = await this.analyzeHashes([hash], hashType)
      return analyzed[0]?.type !== 'unknown'
    } catch {
      return false
    }
  }

  getSupportedHashTypes(): string[] {
    return ['md5', 'sha1', 'sha256', 'sha512', 'ntlm']
  }

  getDefaultWordlist(): string[] {
    return [...this.defaultWordlist]
  }
}

// Export singleton instance
export const nativeHashCracker = new NativeHashCrackerService() 