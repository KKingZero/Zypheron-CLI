import { Router, Request, Response } from 'express'
import { authMiddleware } from '../middleware/auth'
import axios from 'axios'

const router = Router()

// Red Team Operations endpoints
router.get('/status', authMiddleware, async (req: Request, res: Response) => {
  try {
    res.json({
      success: true,
      message: 'Red Team Operations API is active',
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Red Team status error:', error)
    res.status(500).json({
      success: false,
      message: 'Failed to get red team status'
    })
  }
})

// Reconnaissance operations
router.post('/recon', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { target, options } = req.body
    
    if (!target) {
      return res.status(400).json({
        success: false,
        message: 'Target is required'
      })
    }

    // Placeholder for recon operations
    res.json({
      success: true,
      message: 'Reconnaissance initiated',
      target,
      options,
      results: {
        status: 'initialized',
        timestamp: new Date().toISOString()
      }
    })
  } catch (error) {
    console.error('Recon error:', error)
    res.status(500).json({
      success: false,
      message: 'Failed to perform reconnaissance'
    })
  }
})

// Payload deployment operations
router.post('/payload', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { payload, target, options } = req.body
    
    if (!payload || !target) {
      return res.status(400).json({
        success: false,
        message: 'Payload and target are required'
      })
    }

    // Placeholder for payload deployment
    res.json({
      success: true,
      message: 'Payload deployment initiated',
      payload,
      target,
      options,
      results: {
        status: 'initialized',
        timestamp: new Date().toISOString()
      }
    })
  } catch (error) {
    console.error('Payload deployment error:', error)
    res.status(500).json({
      success: false,
      message: 'Failed to deploy payload'
    })
  }
})

// AI loopback operations
router.post('/ai-loopback', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { query, options } = req.body
    
    if (!query) {
      return res.status(400).json({
        success: false,
        message: 'Query is required'
      })
    }

    // Placeholder for AI loopback
    res.json({
      success: true,
      message: 'AI loopback analysis initiated',
      query,
      options,
      results: {
        status: 'initialized',
        timestamp: new Date().toISOString()
      }
    })
  } catch (error) {
    console.error('AI loopback error:', error)
    res.status(500).json({
      success: false,
      message: 'Failed to perform AI loopback analysis'
    })
  }
})

// Nikto web vulnerability scanning
router.post('/nikto-scan', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { target, options = {} } = req.body
    
    if (!target) {
      return res.status(400).json({
        success: false,
        message: 'Target URL is required'
      })
    }

    console.log(`🕷️ [RED-TEAM] Nikto scan requested for: ${target}`)

    const response = await axios.post('http://localhost:8002/api/scan/nikto', {
      target,
      options
    })

    res.json({
      success: true,
      message: 'Nikto vulnerability scan completed',
      data: response.data
    })
  } catch (error) {
    console.error('Nikto scan error:', error)
    res.status(500).json({
      success: false,
      message: 'Failed to perform Nikto scan',
      error: error.response?.data || error.message
    })
  }
})

// SQLMap SQL injection testing
router.post('/sqlmap-scan', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { 
      target_url, 
      data = '', 
      cookie = '', 
      technique = 'B',
      dbms = 'auto',
      level = 1,
      risk = 1 
    } = req.body
    
    if (!target_url) {
      return res.status(400).json({
        success: false,
        message: 'Target URL is required'
      })
    }

    console.log(`💉 [RED-TEAM] SQLMap scan requested for: ${target_url}`)

    const response = await axios.post('http://localhost:8002/api/scan/sqlmap', {
      target_url,
      data,
      cookie,
      technique,
      dbms,
      level,
      risk
    })

    res.json({
      success: true,
      message: 'SQLMap injection test completed',
      data: response.data
    })
  } catch (error) {
    console.error('SQLMap scan error:', error)
    res.status(500).json({
      success: false,
      message: 'Failed to perform SQLMap scan',
      error: error.response?.data || error.message
    })
  }
})

// John the Ripper hash cracking
router.post('/john-ripper', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { 
      hashes = [], 
      hash_type = 'auto',
      wordlist = 'rockyou',
      rules = false,
      incremental = false,
      max_time = 300 
    } = req.body
    
    if (!hashes.length) {
      return res.status(400).json({
        success: false,
        message: 'Hash list is required'
      })
    }

    console.log(`🔓 [RED-TEAM] John the Ripper hash cracking requested for ${hashes.length} hashes`)

    const response = await axios.post('http://localhost:8002/api/scan/john-ripper', {
      hashes,
      hash_type,
      wordlist,
      rules,
      incremental,
      max_time
    })

    res.json({
      success: true,
      message: 'Hash cracking completed',
      data: response.data
    })
  } catch (error) {
    console.error('John the Ripper error:', error)
    res.status(500).json({
      success: false,
      message: 'Failed to crack hashes',
      error: error.response?.data || error.message
    })
  }
})

// Brute force login attacks
router.post('/bruteforce-login', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { 
      target, 
      service = 'SSH (Port 22)',
      usernames = [], 
      passwords = [],
      threads = 16,
      delay = 1000,
      ai_enhancement = false 
    } = req.body
    
    if (!target) {
      return res.status(400).json({
        success: false,
        message: 'Target is required'
      })
    }

    if (!usernames.length || !passwords.length) {
      return res.status(400).json({
        success: false,
        message: 'Username and password lists are required'
      })
    }

    console.log(`🔓 [RED-TEAM] Brute force login attack requested for: ${target}`)

    const response = await axios.post('http://localhost:8005/api/bruteforce/login', {
      target,
      service,
      usernames,
      passwords,
      threads,
      delay,
      ai_enhancement
    })

    res.json({
      success: true,
      message: 'Brute force attack completed',
      data: response.data
    })
  } catch (error) {
    console.error('Brute force login error:', error)
    res.status(500).json({
      success: false,
      message: 'Failed to perform brute force attack',
      error: error.response?.data || error.message
    })
  }
})

// Service enumeration
router.post('/enumerate-services', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { target } = req.body
    
    if (!target) {
      return res.status(400).json({
        success: false,
        message: 'Target is required'
      })
    }

    console.log(`🔍 [RED-TEAM] Service enumeration requested for: ${target}`)

    const response = await axios.post('http://localhost:8005/api/bruteforce/enumerate-services', {
      target
    })

    res.json({
      success: true,
      message: 'Service enumeration completed',
      data: response.data
    })
  } catch (error) {
    console.error('Service enumeration error:', error)
    res.status(500).json({
      success: false,
      message: 'Failed to enumerate services',
      error: error.response?.data || error.message
    })
  }
})

// Get session status
router.get('/session/:sessionId', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { sessionId } = req.params

    const response = await axios.get(`http://localhost:8005/api/bruteforce/session/${sessionId}`)

    res.json({
      success: true,
      data: response.data
    })
  } catch (error) {
    console.error('Session status error:', error)
    res.status(500).json({
      success: false,
      message: 'Failed to get session status',
      error: error.response?.data || error.message
    })
  }
})

export default router 

// Lightweight patch planner/apply endpoints to unblock UI in dev
import express from 'express'
const patchRouter = express.Router()

patchRouter.post('/plan', authMiddleware, async (req, res) => {
  try {
    const { target } = req.body || {}
    // Return a minimal patch plan structure
    return res.json({
      target,
      generatedAt: new Date().toISOString(),
      vulnerabilities: [
        { id: 'CWE-79', title: 'Reflected XSS', severity: 'high', description: 'Unsanitized input reflected in response.' },
        { id: 'CWE-200', title: 'Information Disclosure', severity: 'medium', description: 'Headers reveal technology stack.' }
      ]
    })
  } catch (e: any) {
    return res.status(500).json({ error: 'Failed to build patch plan', message: e.message })
  }
})

patchRouter.post('/generate-fix', authMiddleware, async (req, res) => {
  try {
    const { target, vulnerabilityId } = req.body || {}
    const fixMarkdown = `### Fix for ${vulnerabilityId} @ ${target}\n\n- Encode untrusted data before rendering.\n- Use CSP with script-src 'self'.\n- Validate inputs server-side.\n\n> Apply fix, deploy, and retest.`
    return res.json({ fixMarkdown })
  } catch (e: any) {
    return res.status(500).json({ error: 'Failed to generate fix', message: e.message })
  }
})

export { patchRouter }