import { Router, Request, Response } from 'express'
import HydraService from '../services/hydra'
import HashcatService from '../services/hashcat'
import { nativeBruteForce } from '../services/nativeBruteforce'
import { nativeHashCracker } from '../services/nativeHashcracker'
import { AISecurityAnalyzer } from '../services/aiSecurityAnalyzer'
import { authMiddleware } from '../middleware/auth'

const aiSecurityAnalyzer = new AISecurityAnalyzer()

const router = Router()

// Initialize services with fallback to native implementations
const hydraService = new HydraService(process.env.HYDRA_PATH || 'C:\\thc-hydra-master\\hydra.exe')
const hashcatService = new HashcatService(process.env.HASHCAT_PATH || 'C:\\hashcat-master\\hashcat.exe')

// Hydra brute force attack
router.post('/hydra/attack', authMiddleware, async (req: Request, res: Response): Promise<Response | void> => {
  try {
    const { 
      target, 
      service, 
      userList, 
      passwordList, 
      threads, 
      timeout,
      useAI = true 
    } = req.body

    if (!target || !service) {
      return res.status(400).json({ 
        error: 'Target and service are required' 
      })
    }

    // Check if Hydra is installed
    const isInstalled = await hydraService.checkInstallation()
    if (!isInstalled) {
      return res.status(500).json({ 
        error: 'Hydra is not installed or not found',
        suggestion: 'Please ensure THC Hydra is installed at the configured path'
      })
    }

    // If AI is enabled, get intelligent wordlist suggestions
    let enhancedUserList = userList
    let enhancedPasswordList = passwordList

    if (useAI && (!userList || !passwordList)) {
      const aiSuggestions = await aiSecurityAnalyzer.generateBruteForceWordlists({
        target,
        service,
        context: 'credential-attack'
      })

      enhancedUserList = userList || aiSuggestions.usernames
      enhancedPasswordList = passwordList || aiSuggestions.passwords
    }

    // Set up real-time progress streaming
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    })

    // Listen to Hydra events
    hydraService.on('progress', (data) => {
      res.write(`data: ${JSON.stringify({ type: 'progress', ...data })}\n\n`)
    })

    hydraService.on('credential-found', (data) => {
      res.write(`data: ${JSON.stringify({ type: 'credential-found', ...data })}\n\n`)
    })

    hydraService.on('error', (error) => {
      res.write(`data: ${JSON.stringify({ type: 'error', error: error.message })}\n\n`)
    })

    // Run the attack
    const result = await hydraService.runAttack({
      target,
      service,
      userList: enhancedUserList,
      passwordList: enhancedPasswordList,
      threads,
      timeout,
      useAI
    })

    // Send final result
    res.write(`data: ${JSON.stringify({ type: 'complete', result })}\n\n`)
    res.end()

  } catch (error) {
    console.error('Hydra attack error:', error)
    res.status(500).json({ 
      error: 'Failed to perform brute force attack',
      details: error instanceof Error ? error.message : 'Unknown error'
    })
  }
})

// Hashcat hash cracking
router.post('/hashcat/crack', authMiddleware, async (req: Request, res: Response): Promise<Response | void> => {
  try {
    const {
      hashes,
      hashFile,
      attackMode = 0,
      hashType,
      wordlist,
      mask,
      rules,
      useAI = true
    } = req.body

    if (!hashes && !hashFile) {
      return res.status(400).json({ 
        error: 'Hashes or hash file required' 
      })
    }

    // Check if Hashcat is installed
    const isInstalled = await hashcatService.checkInstallation()
    if (!isInstalled) {
      return res.status(500).json({ 
        error: 'Hashcat is not installed or not found',
        suggestion: 'Please ensure Hashcat is installed at the configured path'
      })
    }

    // Auto-detect hash type if not provided
    let detectedHashType = hashType
    if (!detectedHashType && hashes && hashes.length > 0) {
      detectedHashType = await hashcatService.identifyHashType(hashes[0])
      
      if (!detectedHashType && useAI) {
        // Use AI to identify complex hash types
        const aiIdentification = await aiSecurityAnalyzer.identifyHashType(hashes[0])
        detectedHashType = aiIdentification.hashType
      }
    }

    // Set up real-time progress streaming
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    })

    // Listen to Hashcat events
    hashcatService.on('progress', (data) => {
      res.write(`data: ${JSON.stringify({ type: 'progress', ...data })}\n\n`)
    })

    hashcatService.on('error', (error) => {
      res.write(`data: ${JSON.stringify({ type: 'error', error: error.message })}\n\n`)
    })

    // Run the attack
    const result = await hashcatService.runAttack({
      hashes,
      hashFile,
      attackMode,
      hashType: detectedHashType,
      wordlist,
      mask,
      rules,
      useAI
    })

    // Send final result
    res.write(`data: ${JSON.stringify({ type: 'complete', result })}\n\n`)
    res.end()

  } catch (error) {
    console.error('Hashcat crack error:', error)
    res.status(500).json({ 
      error: 'Failed to crack hashes',
      details: error instanceof Error ? error.message : 'Unknown error'
    })
  }
})

// Check tool installation status
router.get('/tools/status', async (req: Request, res: Response) => {
  try {
    const hydraInstalled = await hydraService.checkInstallation()
    const hashcatInstalled = await hashcatService.checkInstallation()

    res.json({
      hydra: {
        installed: hydraInstalled,
        path: process.env.HYDRA_PATH || 'C:\\thc-hydra-master\\hydra.exe'
      },
      hashcat: {
        installed: hashcatInstalled,
        path: process.env.HASHCAT_PATH || 'C:\\hashcat-master\\hashcat.exe'
      }
    })
  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to check tool status',
      details: error instanceof Error ? error.message : 'Unknown error'
    })
  }
})

// Get supported services for Hydra
router.get('/hydra/services', (req: Request, res: Response) => {
  res.json({
    services: [
      { value: 'ssh', label: 'SSH', port: 22 },
      { value: 'ftp', label: 'FTP', port: 21 },
      { value: 'telnet', label: 'Telnet', port: 23 },
      { value: 'http-get', label: 'HTTP GET', port: 80 },
      { value: 'http-post-form', label: 'HTTP POST Form', port: 80 },
      { value: 'https-get', label: 'HTTPS GET', port: 443 },
      { value: 'https-post-form', label: 'HTTPS POST Form', port: 443 },
      { value: 'mysql', label: 'MySQL', port: 3306 },
      { value: 'mssql', label: 'MS SQL', port: 1433 },
      { value: 'postgres', label: 'PostgreSQL', port: 5432 },
      { value: 'rdp', label: 'RDP', port: 3389 },
      { value: 'smb', label: 'SMB', port: 445 },
      { value: 'smtp', label: 'SMTP', port: 25 },
      { value: 'pop3', label: 'POP3', port: 110 },
      { value: 'imap', label: 'IMAP', port: 143 },
      { value: 'vnc', label: 'VNC', port: 5900 }
    ]
  })
})

// Get supported hash types for Hashcat
router.get('/hashcat/hashtypes', (req: Request, res: Response) => {
  res.json({
    hashTypes: [
      { value: 0, label: 'MD5', example: '8743b52063cd84097a65d1633f5c74f5' },
      { value: 100, label: 'SHA1', example: 'b89eaac7e61417341b710b727768294d0e6a277b' },
      { value: 1400, label: 'SHA256', example: '127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935' },
      { value: 1700, label: 'SHA512', example: '82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f' },
      { value: 3200, label: 'bcrypt', example: '$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6' },
      { value: 1000, label: 'NTLM', example: 'b4b9b02e6f09a9bd760f388b67351e2b' },
      { value: 5500, label: 'NetNTLMv1', example: 'u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c' },
      { value: 5600, label: 'NetNTLMv2', example: 'admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030' },
      { value: 2500, label: 'WPA/WPA2', example: 'WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***' },
      { value: 1800, label: 'sha512crypt', example: '$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/' },
      { value: 500, label: 'md5crypt', example: '$1$28772684$iEwNOgGugqO9.bIz5sk8k/' },
      { value: 13100, label: 'Kerberos 5 TGS-REP', example: '$krb5tgs$23$*user$realm$test/spn*$63386d22d359fe42230300d56852c9eb$891ad31d09ab89c6b3b8c5e5de6c06a7f49fd559d7a9a3c32576c8fedf705376cea582ab5938f7fc8bc741acf05c5990741b36ef4311fe3562a41b70a4ec6ecba849905f2385bb3799d92499909658c7287c49160276bca0006c350b0db4fd387adc27c01e9e9ad0c20ed53a7e6356dee2452e35eca2a6a1d1432796fc5c19d068978df74d3d0baf35c77de12456bf1144b6a750d11f55805f5a16ece2975246e2d026dce997fba34ac8757312e9e4e6272de35e20d52fb668c5ed' }
    ]
  })
})

// Native brute force attack (no external tools required)
router.post('/native/attack', authMiddleware, async (req: Request, res: Response): Promise<Response | void> => {
  try {
    const {
      target,
      service,
      port,
      userList,
      passwordList,
      threads = 5,
      timeout = 10000,
      useAI = true,
      loginPath = '/login',
      userAgent,
      verbose = false
    } = req.body

    if (!target || !service) {
      return res.status(400).json({
        error: 'Target and service are required'
      })
    }

    // Set up event streaming for real-time updates
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Cache-Control'
    })

    // Send initial status
    res.write(`data: ${JSON.stringify({
      type: 'status',
      message: 'Starting native brute force attack...',
      progress: 0
    })}\n\n`)

    // Configure attack options
    const attackOptions = {
      target,
      service: service as any,
      port,
      userList,
      passwordList,
      threads,
      timeout,
      useAI,
      loginPath,
      userAgent,
      verbose
    }

    // Set up event listeners
    nativeBruteForce.on('progress', (data) => {
      res.write(`data: ${JSON.stringify({
        type: 'progress',
        ...data
      })}\n\n`)
    })

    nativeBruteForce.on('attempt', (attempt) => {
      if (verbose) {
        res.write(`data: ${JSON.stringify({
          type: 'attempt',
          username: attempt.username,
          password: attempt.password,
          success: attempt.success,
          responseTime: attempt.responseTime
        })}\n\n`)
      }
    })

    nativeBruteForce.on('success', (success) => {
      res.write(`data: ${JSON.stringify({
        type: 'success',
        message: `Found credentials: ${success.username}:${success.password}`,
        credentials: success
      })}\n\n`)
    })

    // Run the attack
    const result = await nativeBruteForce.runBruteForce(attackOptions)

    // Send final results
    res.write(`data: ${JSON.stringify({
      type: 'complete',
      result
    })}\n\n`)

    res.end()

  } catch (error: any) {
    res.write(`data: ${JSON.stringify({
      type: 'error',
      error: error.message
    })}\n\n`)
    res.end()
  }
})

// Native hash cracking (no external tools required)
router.post('/native/hashcrack', authMiddleware, async (req: Request, res: Response): Promise<Response | void> => {
  try {
    const {
      hashes,
      hashType = 'auto',
      attackMode = 'hybrid',
      wordlist,
      customWordlist,
      charset,
      minLength = 1,
      maxLength = 8,
      useAI = true,
      threads = 1,
      timeout
    } = req.body

    if (!hashes || !Array.isArray(hashes) || hashes.length === 0) {
      return res.status(400).json({
        error: 'Hashes array is required'
      })
    }

    // Set up event streaming for real-time updates
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Cache-Control'
    })

    // Send initial status
    res.write(`data: ${JSON.stringify({
      type: 'status',
      message: 'Starting native hash cracking...',
      progress: 0,
      totalHashes: hashes.length
    })}\n\n`)

    // Configure crack options
    const crackOptions = {
      hashes,
      hashType: hashType as any,
      attackMode: attackMode as any,
      wordlist,
      customWordlist,
      charset,
      minLength,
      maxLength,
      useAI,
      threads,
      timeout
    }

    // Set up event listeners
    nativeHashCracker.on('progress', (data) => {
      res.write(`data: ${JSON.stringify({
        type: 'progress',
        ...data
      })}\n\n`)
    })

    nativeHashCracker.on('success', (success) => {
      res.write(`data: ${JSON.stringify({
        type: 'success',
        message: `Cracked hash: ${success.hash} = ${success.plaintext}`,
        crackedHash: success
      })}\n\n`)
    })

    // Run the hash cracking
    const result = await nativeHashCracker.crackHashes(crackOptions)

    // Send final results
    res.write(`data: ${JSON.stringify({
      type: 'complete',
      result
    })}\n\n`)

    res.end()

  } catch (error: any) {
    res.write(`data: ${JSON.stringify({
      type: 'error',
      error: error.message
    })}\n\n`)
    res.end()
  }
})

// Get supported services for native brute force
router.get('/native/services', async (req: Request, res: Response) => {
  res.json({
    services: [
      { value: 'ssh', label: 'SSH', port: 22 },
      { value: 'ftp', label: 'FTP', port: 21 },
      { value: 'http', label: 'HTTP', port: 80 },
      { value: 'https', label: 'HTTPS', port: 443 },
      { value: 'smtp', label: 'SMTP', port: 587 },
      { value: 'pop3', label: 'POP3', port: 110 },
      { value: 'imap', label: 'IMAP', port: 143 },
      { value: 'telnet', label: 'Telnet', port: 23 },
      { value: 'mysql', label: 'MySQL', port: 3306 },
      { value: 'postgres', label: 'PostgreSQL', port: 5432 }
    ]
  })
})

// Get supported hash types for native hash cracking
router.get('/native/hashtypes', (req: Request, res: Response) => {
  const supportedTypes = ['md5', 'sha1', 'sha256', 'sha512', 'ntlm']
  
  res.json({
    hashTypes: supportedTypes.map(type => ({
      value: type,
      label: type.toUpperCase(),
      example: type === 'md5' ? '5d41402abc4b2a76b9719d911017c592' :
               type === 'sha1' ? 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d' :
               type === 'sha256' ? '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae' :
               type === 'sha512' ? '9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043' :
               type === 'ntlm' ? 'b4b9b02e6f09a9bd760f388b67351e2b' : ''
    }))
  })
})

export default router 