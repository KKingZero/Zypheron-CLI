import crypto from 'crypto'
import fs from 'fs'
import path from 'path'

// Encryption configuration
const ALGORITHM = 'aes-256-gcm'
const KEY_LENGTH = 32
const IV_LENGTH = 16
const TAG_LENGTH = 16

export interface EncryptedData {
  iv: string
  tag: string
  data: string
}

export class EncryptionService {
  private encryptionKey: Buffer

  constructor() {
    // Initialize encryption key from environment or generate one
    this.encryptionKey = this.getOrCreateEncryptionKey()
  }

  /**
   * Get or create the master encryption key
   */
  private getOrCreateEncryptionKey(): Buffer {
    const keyPath = path.join(process.cwd(), '.encryption-key')
    
    // Try to get key from environment first
    if (process.env.ENCRYPTION_MASTER_KEY) {
      return Buffer.from(process.env.ENCRYPTION_MASTER_KEY, 'hex')
    }

    // Try to load existing key file
    if (fs.existsSync(keyPath)) {
      try {
        const keyData = fs.readFileSync(keyPath, 'utf8')
        return Buffer.from(keyData.trim(), 'hex')
      } catch (error) {
        console.warn('Failed to load existing encryption key, generating new one')
      }
    }

    // Generate new key
    const newKey = crypto.randomBytes(KEY_LENGTH)
    
    // Save key to file (this should be secured in production)
    try {
      fs.writeFileSync(keyPath, newKey.toString('hex'), { mode: 0o600 })
      console.log('Generated new encryption key and saved to .encryption-key')
      console.warn('IMPORTANT: Back up your .encryption-key file securely!')
    } catch (error) {
      console.error('Failed to save encryption key to file:', error)
    }

    return newKey
  }

  /**
   * Encrypt sensitive data
   */
  encrypt(plaintext: string): EncryptedData {
    const iv = crypto.randomBytes(IV_LENGTH)
    const cipher = crypto.createCipher(ALGORITHM, this.encryptionKey)
    cipher.setAAD(Buffer.from('cobra-ai-api-keys'))
    
    let encrypted = cipher.update(plaintext, 'utf8', 'hex')
    encrypted += cipher.final('hex')
    
    const tag = cipher.getAuthTag()

    return {
      iv: iv.toString('hex'),
      tag: tag.toString('hex'),
      data: encrypted
    }
  }

  /**
   * Decrypt sensitive data
   */
  decrypt(encryptedData: EncryptedData): string {
    const decipher = crypto.createDecipher(ALGORITHM, this.encryptionKey)
    decipher.setAAD(Buffer.from('cobra-ai-api-keys'))
    decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'))

    let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8')
    decrypted += decipher.final('utf8')

    return decrypted
  }

  /**
   * Securely get API key with fallback to environment variables
   */
  getApiKey(keyName: string): string | undefined {
    // First try environment variable (primary method)
    const envValue = process.env[keyName]
    if (envValue) {
      return envValue
    }

    // Try encrypted storage as fallback
    const encryptedPath = path.join(process.cwd(), '.encrypted-keys.json')
    if (fs.existsSync(encryptedPath)) {
      try {
        const encryptedKeys = JSON.parse(fs.readFileSync(encryptedPath, 'utf8'))
        if (encryptedKeys[keyName]) {
          return this.decrypt(encryptedKeys[keyName])
        }
      } catch (error) {
        console.error(`Failed to decrypt key ${keyName}:`, error)
      }
    }

    return undefined
  }

  /**
   * Store encrypted API key (for backup/fallback only)
   */
  storeEncryptedKey(keyName: string, keyValue: string): void {
    const encryptedPath = path.join(process.cwd(), '.encrypted-keys.json')
    let encryptedKeys: Record<string, EncryptedData> = {}

    // Load existing encrypted keys
    if (fs.existsSync(encryptedPath)) {
      try {
        encryptedKeys = JSON.parse(fs.readFileSync(encryptedPath, 'utf8'))
      } catch (error) {
        console.error('Failed to load existing encrypted keys:', error)
      }
    }

    // Encrypt and store the new key
    encryptedKeys[keyName] = this.encrypt(keyValue)

    // Save back to file
    try {
      fs.writeFileSync(encryptedPath, JSON.stringify(encryptedKeys, null, 2), { mode: 0o600 })
      console.log(`Encrypted key ${keyName} stored successfully`)
    } catch (error) {
      console.error(`Failed to store encrypted key ${keyName}:`, error)
    }
  }
}

// Global instance
export const encryptionService = new EncryptionService()

/**
 * Secure API key getter that prioritizes environment variables
 * and falls back to encrypted storage
 */
export function getSecureApiKey(keyName: string): string | undefined {
  return encryptionService.getApiKey(keyName)
}

/**
 * Helper function to validate required API keys are present
 */
export function validateRequiredApiKeys(requiredKeys: string[]): void {
  const missingKeys: string[] = []
  
  for (const keyName of requiredKeys) {
    const value = getSecureApiKey(keyName)
    if (!value) {
      missingKeys.push(keyName)
    }
  }

  if (missingKeys.length > 0) {
    console.warn(`Missing required API keys: ${missingKeys.join(', ')}`)
    console.warn('Please set these as environment variables or use the encryption service')
  }
} 