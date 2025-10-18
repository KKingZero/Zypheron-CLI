#!/usr/bin/env node

/**
 * COBRA AI API Key Management Script
 * 
 * This script helps you securely manage API keys with encryption for double protection.
 * It provides utilities to encrypt/decrypt keys and set up environment variables.
 */

const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const readline = require('readline')

// Encryption configuration
const ALGORITHM = 'aes-256-gcm'
const KEY_LENGTH = 32
const IV_LENGTH = 16

class SecureKeyManager {
  constructor() {
    this.keyPath = path.join(process.cwd(), '.encryption-key')
    this.encryptedPath = path.join(process.cwd(), '.encrypted-keys.json')
    this.encryptionKey = this.getOrCreateEncryptionKey()
  }

  getOrCreateEncryptionKey() {
    if (fs.existsSync(this.keyPath)) {
      try {
        const keyData = fs.readFileSync(this.keyPath, 'utf8')
        return Buffer.from(keyData.trim(), 'hex')
      } catch (error) {
        console.error('Failed to load encryption key:', error.message)
      }
    }

    console.log('🔑 Generating new encryption key...')
    const newKey = crypto.randomBytes(KEY_LENGTH)
    fs.writeFileSync(this.keyPath, newKey.toString('hex'), { mode: 0o600 })
    console.log('✅ Encryption key saved to .encryption-key')
    console.log('⚠️  IMPORTANT: Back up this file securely!')
    return newKey
  }

  encrypt(plaintext) {
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

  decrypt(encryptedData) {
    const decipher = crypto.createDecipher(ALGORITHM, this.encryptionKey)
    decipher.setAAD(Buffer.from('cobra-ai-api-keys'))
    decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'))

    let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8')
    decrypted += decipher.final('utf8')
    return decrypted
  }

  storeEncryptedKey(keyName, keyValue) {
    let encryptedKeys = {}
    
    if (fs.existsSync(this.encryptedPath)) {
      try {
        encryptedKeys = JSON.parse(fs.readFileSync(this.encryptedPath, 'utf8'))
      } catch (error) {
        console.error('Failed to load existing encrypted keys:', error.message)
      }
    }

    encryptedKeys[keyName] = this.encrypt(keyValue)
    fs.writeFileSync(this.encryptedPath, JSON.stringify(encryptedKeys, null, 2), { mode: 0o600 })
    console.log(`✅ Encrypted key '${keyName}' stored successfully`)
  }

  getEncryptedKey(keyName) {
    if (!fs.existsSync(this.encryptedPath)) {
      return null
    }

    try {
      const encryptedKeys = JSON.parse(fs.readFileSync(this.encryptedPath, 'utf8'))
      if (encryptedKeys[keyName]) {
        return this.decrypt(encryptedKeys[keyName])
      }
    } catch (error) {
      console.error(`Failed to decrypt key '${keyName}':`, error.message)
    }

    return null
  }

  listEncryptedKeys() {
    if (!fs.existsSync(this.encryptedPath)) {
      console.log('No encrypted keys found.')
      return []
    }

    try {
      const encryptedKeys = JSON.parse(fs.readFileSync(this.encryptedPath, 'utf8'))
      return Object.keys(encryptedKeys)
    } catch (error) {
      console.error('Failed to list encrypted keys:', error.message)
      return []
    }
  }
}

// CLI Interface
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
})

async function askQuestion(question) {
  return new Promise((resolve) => {
    rl.question(question, resolve)
  })
}

async function main() {
  const manager = new SecureKeyManager()
  
  console.log('\n🛡️  COBRA AI Secure API Key Manager')
  console.log('===================================\n')

  while (true) {
    console.log('Choose an option:')
    console.log('1. Encrypt and store an API key')
    console.log('2. View stored encrypted keys')
    console.log('3. Retrieve an encrypted key')
    console.log('4. Generate environment variables template')
    console.log('5. Exit')
    
    const choice = await askQuestion('\nEnter your choice (1-5): ')

    switch (choice) {
      case '1':
        const keyName = await askQuestion('Enter API key name (e.g., OPENAI_API_KEY): ')
        const keyValue = await askQuestion('Enter API key value: ')
        manager.storeEncryptedKey(keyName, keyValue)
        console.log('✅ Key encrypted and stored!\n')
        break

      case '2':
        const keys = manager.listEncryptedKeys()
        if (keys.length === 0) {
          console.log('No encrypted keys found.\n')
        } else {
          console.log('Stored encrypted keys:')
          keys.forEach(key => console.log(`  - ${key}`))
          console.log('')
        }
        break

      case '3':
        const keysList = manager.listEncryptedKeys()
        if (keysList.length === 0) {
          console.log('No encrypted keys found.\n')
          break
        }
        
        console.log('Available keys:')
        keysList.forEach((key, index) => console.log(`  ${index + 1}. ${key}`))
        
        const keyChoice = await askQuestion('Enter key number: ')
        const selectedKey = keysList[parseInt(keyChoice) - 1]
        
        if (selectedKey) {
          const value = manager.getEncryptedKey(selectedKey)
          console.log(`\n${selectedKey}: ${value}\n`)
        } else {
          console.log('Invalid selection.\n')
        }
        break

      case '4':
        console.log('\n📋 Environment Variables Template:')
        console.log('================================')
        const allKeys = manager.listEncryptedKeys()
        allKeys.forEach(key => {
          console.log(`${key}=your_${key.toLowerCase()}_here`)
        })
        console.log('')
        break

      case '5':
        console.log('👋 Goodbye!')
        rl.close()
        return

      default:
        console.log('Invalid choice. Please try again.\n')
    }
  }
}

if (require.main === module) {
  main().catch(console.error)
}

module.exports = { SecureKeyManager } 