/**
 * Secure Storage Utility
 * Provides encrypted storage for sensitive data like API keys
 * 
 * Fixes: CRITICAL BUG #1 - API Key Security Vulnerability
 * 
 * NOTE: This is a client-side encryption solution. For maximum security,
 * API keys should be stored on the backend with proper encryption at rest.
 * This solution provides a significant improvement over plaintext localStorage.
 */

// Simple encryption/decryption using Web Crypto API
class SecureStorage {
  private static readonly STORAGE_PREFIX = 'zypheron_secure_'
  private static readonly SALT_KEY = 'zypheron_salt'
  
  /**
   * Generate a unique device fingerprint to use as encryption key seed
   * This combines multiple browser/system properties for uniqueness
   */
  private static async getDeviceFingerprint(): Promise<string> {
    const components = [
      navigator.userAgent,
      navigator.language,
      new Date().getTimezoneOffset().toString(),
      screen.colorDepth.toString(),
      screen.width.toString(),
      screen.height.toString(),
    ]
    
    const fingerprint = components.join('|')
    const encoder = new TextEncoder()
    const data = encoder.encode(fingerprint)
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
  }

  /**
   * Get or create a salt for key derivation
   */
  private static getSalt(): Uint8Array {
    let salt = localStorage.getItem(this.SALT_KEY)
    
    if (!salt) {
      // Generate new salt
      const saltArray = crypto.getRandomValues(new Uint8Array(16))
      salt = Array.from(saltArray).map(b => b.toString(16).padStart(2, '0')).join('')
      localStorage.setItem(this.SALT_KEY, salt)
    }
    
    // Convert hex string back to Uint8Array
    const matches = salt.match(/.{1,2}/g)
    return new Uint8Array(matches?.map(byte => parseInt(byte, 16)) || [])
  }

  /**
   * Derive an encryption key from device fingerprint
   */
  private static async deriveKey(): Promise<CryptoKey> {
    const fingerprint = await this.getDeviceFingerprint()
    const salt = this.getSalt()
    
    const encoder = new TextEncoder()
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(fingerprint),
      'PBKDF2',
      false,
      ['deriveKey']
    )
    
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    )
  }

  /**
   * Encrypt data using AES-GCM
   */
  private static async encrypt(data: string): Promise<string> {
    try {
      const key = await this.deriveKey()
      const encoder = new TextEncoder()
      const iv = crypto.getRandomValues(new Uint8Array(12)) // 96-bit IV for AES-GCM
      
      const encryptedBuffer = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        encoder.encode(data)
      )
      
      // Combine IV and encrypted data
      const encryptedArray = new Uint8Array(encryptedBuffer)
      const combined = new Uint8Array(iv.length + encryptedArray.length)
      combined.set(iv, 0)
      combined.set(encryptedArray, iv.length)
      
      // Convert to base64 for storage
      return btoa(String.fromCharCode(...combined))
    } catch (error) {
      console.error('Encryption failed:', error)
      throw new Error('Failed to encrypt data')
    }
  }

  /**
   * Decrypt data using AES-GCM
   */
  private static async decrypt(encryptedData: string): Promise<string> {
    try {
      const key = await this.deriveKey()
      
      // Decode from base64
      const combined = new Uint8Array(
        atob(encryptedData).split('').map(c => c.charCodeAt(0))
      )
      
      // Extract IV and encrypted data
      const iv = combined.slice(0, 12)
      const data = combined.slice(12)
      
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        data
      )
      
      const decoder = new TextDecoder()
      return decoder.decode(decryptedBuffer)
    } catch (error) {
      console.error('Decryption failed:', error)
      throw new Error('Failed to decrypt data')
    }
  }

  /**
   * Store encrypted data in localStorage
   */
  public static async setItem(key: string, value: string): Promise<void> {
    try {
      const encrypted = await this.encrypt(value)
      localStorage.setItem(this.STORAGE_PREFIX + key, encrypted)
    } catch (error) {
      console.error('SecureStorage.setItem failed:', error)
      throw error
    }
  }

  /**
   * Retrieve and decrypt data from localStorage
   */
  public static async getItem(key: string): Promise<string | null> {
    try {
      const encrypted = localStorage.getItem(this.STORAGE_PREFIX + key)
      if (!encrypted) {
        return null
      }
      return await this.decrypt(encrypted)
    } catch (error) {
      console.error('SecureStorage.getItem failed:', error)
      // If decryption fails, remove the corrupted data
      localStorage.removeItem(this.STORAGE_PREFIX + key)
      return null
    }
  }

  /**
   * Remove item from storage
   */
  public static removeItem(key: string): void {
    localStorage.removeItem(this.STORAGE_PREFIX + key)
  }

  /**
   * Clear all secure storage items
   */
  public static clear(): void {
    const keys = Object.keys(localStorage)
    keys.forEach(key => {
      if (key.startsWith(this.STORAGE_PREFIX)) {
        localStorage.removeItem(key)
      }
    })
  }

  /**
   * Check if a key exists in secure storage
   */
  public static hasItem(key: string): boolean {
    return localStorage.getItem(this.STORAGE_PREFIX + key) !== null
  }

  /**
   * Migrate existing plaintext data to encrypted storage
   */
  public static async migratePlaintextToSecure(key: string): Promise<boolean> {
    try {
      // Check if already migrated
      if (this.hasItem(key)) {
        return true
      }
      
      // Get plaintext data
      const plaintext = localStorage.getItem(key)
      if (!plaintext) {
        return false
      }
      
      // Encrypt and store
      await this.setItem(key, plaintext)
      
      // Remove plaintext version
      localStorage.removeItem(key)
      
      console.log(`Successfully migrated ${key} to secure storage`)
      return true
    } catch (error) {
      console.error(`Failed to migrate ${key}:`, error)
      return false
    }
  }
}

export default SecureStorage

/**
 * Hook for secure storage of API keys and sensitive data
 */
export const useSecureStorage = () => {
  const setSecureItem = async (key: string, value: string): Promise<void> => {
    return SecureStorage.setItem(key, value)
  }

  const getSecureItem = async (key: string): Promise<string | null> => {
    return SecureStorage.getItem(key)
  }

  const removeSecureItem = (key: string): void => {
    SecureStorage.removeItem(key)
  }

  const clearSecureStorage = (): void => {
    SecureStorage.clear()
  }

  return {
    setSecureItem,
    getSecureItem,
    removeSecureItem,
    clearSecureStorage,
  }
}

