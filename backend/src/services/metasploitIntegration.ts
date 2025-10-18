/**
 * Metasploit Framework Integration
 * Automated exploit selection, payload generation, and execution
 * Integrates with Metasploit RPC API for programmatic control
 */

import axios, { AxiosInstance } from 'axios'
import { EventEmitter } from 'events'
import { getAuditLogger } from './auditLogger'

export interface MetasploitConfig {
  host: string
  port: number
  username: string
  password: string
  ssl?: boolean
}

export interface ExploitModule {
  name: string
  fullname: string
  rank: string
  disclosureDate?: string
  description: string
  references: string[]
  targets: string[]
  payloads: string[]
  options: Record<string, ExploitOption>
}

export interface ExploitOption {
  type: string
  required: boolean
  default?: any
  description: string
}

export interface ExploitResult {
  success: boolean
  sessionId?: number
  error?: string
  output: string
  exploitUsed: string
  payloadUsed: string
  targetInfo: any
}

export interface Session {
  id: number
  type: string
  tunnel_local: string
  tunnel_peer: string
  via_exploit: string
  via_payload: string
  desc: string
  info: string
  workspace: string
  session_host: string
  session_port: number
  target_host: string
  username: string
  uuid: string
  exploit_uuid: string
  routes: string
}

class MetasploitClient extends EventEmitter {
  private client: AxiosInstance
  private token: string | null = null
  private readonly auditLogger = getAuditLogger()
  private readonly config: MetasploitConfig

  constructor(config: MetasploitConfig) {
    super()
    this.config = config

    const baseURL = `${config.ssl ? 'https' : 'http'}://${config.host}:${config.port}/api/v1`
    
    this.client = axios.create({
      baseURL,
      headers: {
        'Content-Type': 'application/json'
      },
      timeout: 30000
    })

    console.log(`🎯 Metasploit client initialized: ${baseURL}`)
  }

  /**
   * Authenticate with Metasploit RPC
   */
  async authenticate(): Promise<boolean> {
    try {
      const response = await this.client.post('/auth/login', {
        username: this.config.username,
        password: this.config.password
      })

      if (response.data && response.data.token) {
        this.token = response.data.token
        
        // Update client headers with token
        this.client.defaults.headers.common['Authorization'] = `Bearer ${this.token}`
        
        console.log('✅ Metasploit authentication successful')
        return true
      }

      return false
    } catch (error) {
      console.error('❌ Metasploit authentication failed:', error)
      return false
    }
  }

  /**
   * Search for exploits matching vulnerability
   */
  async searchExploits(query: string): Promise<ExploitModule[]> {
    if (!this.token) {
      await this.authenticate()
    }

    try {
      const response = await this.client.post('/modules/search', {
        query,
        type: 'exploit'
      })

      return response.data.modules || []
    } catch (error) {
      console.error('Failed to search exploits:', error)
      return []
    }
  }

  /**
   * Get exploit module details
   */
  async getExploitInfo(moduleName: string): Promise<ExploitModule | null> {
    if (!this.token) {
      await this.authenticate()
    }

    try {
      const response = await this.client.get(`/modules/exploit/${encodeURIComponent(moduleName)}`)
      return response.data || null
    } catch (error) {
      console.error('Failed to get exploit info:', error)
      return null
    }
  }

  /**
   * Execute exploit against target
   */
  async executeExploit(
    exploitModule: string,
    target: string,
    options: Record<string, any> = {},
    userId: string = 'system'
  ): Promise<ExploitResult> {
    if (!this.token) {
      await this.authenticate()
    }

    const startTime = Date.now()

    try {
      // Log exploit execution
      await this.auditLogger.logToolExecution({
        userId,
        toolName: 'metasploit',
        target,
        parameters: {
          exploit: exploitModule,
          ...options
        },
        result: 'success',
        severity: 'high',
        complianceNote: 'Metasploit exploit execution initiated'
      })

      // Set required options
      const exploitOptions = {
        RHOST: target,
        ...options
      }

      // Execute exploit
      const response = await this.client.post('/modules/exploit/execute', {
        module: exploitModule,
        options: exploitOptions
      })

      const duration = Date.now() - startTime

      if (response.data.job_id) {
        // Wait for job completion
        const jobResult = await this.waitForJobCompletion(response.data.job_id)

        // Log completion
        await this.auditLogger.logToolExecution({
          userId,
          toolName: 'metasploit',
          target,
          parameters: { exploit: exploitModule },
          result: jobResult.success ? 'success' : 'failure',
          duration,
          severity: 'high'
        })

        return {
          success: jobResult.success,
          sessionId: jobResult.sessionId,
          output: jobResult.output,
          exploitUsed: exploitModule,
          payloadUsed: options.PAYLOAD || 'default',
          targetInfo: {
            target,
            port: options.RPORT
          }
        }
      }

      return {
        success: false,
        error: 'Failed to start exploit job',
        output: '',
        exploitUsed: exploitModule,
        payloadUsed: options.PAYLOAD || 'default',
        targetInfo: { target }
      }
    } catch (error) {
      // Log failure
      await this.auditLogger.logToolExecution({
        userId,
        toolName: 'metasploit',
        target,
        parameters: { exploit: exploitModule },
        result: 'error',
        errorMessage: error instanceof Error ? error.message : String(error),
        duration: Date.now() - startTime,
        severity: 'high'
      })

      return {
        success: false,
        error: error instanceof Error ? error.message : String(error),
        output: '',
        exploitUsed: exploitModule,
        payloadUsed: options.PAYLOAD || 'default',
        targetInfo: { target }
      }
    }
  }

  /**
   * Wait for job to complete
   */
  private async waitForJobCompletion(jobId: number, maxWait: number = 300000): Promise<any> {
    const startTime = Date.now()

    while (Date.now() - startTime < maxWait) {
      try {
        const response = await this.client.get(`/jobs/${jobId}`)
        
        if (response.data.status === 'completed') {
          return {
            success: true,
            sessionId: response.data.session_id,
            output: response.data.output || ''
          }
        }

        if (response.data.status === 'failed') {
          return {
            success: false,
            error: response.data.error,
            output: response.data.output || ''
          }
        }

        // Still running, wait and check again
        await new Promise(resolve => setTimeout(resolve, 2000))
      } catch (error) {
        console.error('Error checking job status:', error)
        break
      }
    }

    return {
      success: false,
      error: 'Job timeout',
      output: ''
    }
  }

  /**
   * List active sessions
   */
  async listSessions(): Promise<Session[]> {
    if (!this.token) {
      await this.authenticate()
    }

    try {
      const response = await this.client.get('/sessions')
      return response.data.sessions || []
    } catch (error) {
      console.error('Failed to list sessions:', error)
      return []
    }
  }

  /**
   * Execute command in session
   */
  async executeCommand(sessionId: number, command: string): Promise<string> {
    if (!this.token) {
      await this.authenticate()
    }

    try {
      const response = await this.client.post(`/sessions/${sessionId}/shell`, {
        command
      })

      return response.data.output || ''
    } catch (error) {
      console.error('Failed to execute command:', error)
      return ''
    }
  }

  /**
   * Kill session
   */
  async killSession(sessionId: number): Promise<boolean> {
    if (!this.token) {
      await this.authenticate()
    }

    try {
      await this.client.delete(`/sessions/${sessionId}`)
      return true
    } catch (error) {
      console.error('Failed to kill session:', error)
      return false
    }
  }

  /**
   * AI-powered exploit recommendation
   */
  async recommendExploits(vulnerabilityInfo: {
    cve?: string
    service?: string
    version?: string
    os?: string
  }): Promise<ExploitModule[]> {
    // Build search query
    const searchTerms: string[] = []
    
    if (vulnerabilityInfo.cve) {
      searchTerms.push(vulnerabilityInfo.cve)
    }
    
    if (vulnerabilityInfo.service) {
      searchTerms.push(vulnerabilityInfo.service)
    }
    
    if (vulnerabilityInfo.version) {
      searchTerms.push(vulnerabilityInfo.version)
    }

    const query = searchTerms.join(' ')

    if (!query) {
      return []
    }

    // Search for matching exploits
    const exploits = await this.searchExploits(query)

    // Sort by rank (excellent > great > good > normal > average > low)
    const rankOrder = ['excellent', 'great', 'good', 'normal', 'average', 'low']
    
    return exploits.sort((a, b) => {
      const aRank = rankOrder.indexOf(a.rank.toLowerCase())
      const bRank = rankOrder.indexOf(b.rank.toLowerCase())
      return aRank - bRank
    })
  }

  /**
   * Generate payload for exploit
   */
  async generatePayload(
    payloadType: string,
    lhost: string,
    lport: number,
    format: string = 'raw'
  ): Promise<Buffer | null> {
    if (!this.token) {
      await this.authenticate()
    }

    try {
      const response = await this.client.post('/payloads/generate', {
        payload: payloadType,
        options: {
          LHOST: lhost,
          LPORT: lport
        },
        format
      })

      if (response.data.payload) {
        return Buffer.from(response.data.payload, 'base64')
      }

      return null
    } catch (error) {
      console.error('Failed to generate payload:', error)
      return null
    }
  }

  /**
   * Close Metasploit connection
   */
  async disconnect(): Promise<void> {
    if (this.token) {
      try {
        await this.client.post('/auth/logout')
        this.token = null
        console.log('👋 Metasploit connection closed')
      } catch (error) {
        console.error('Error disconnecting from Metasploit:', error)
      }
    }
  }
}

// Singleton instance
let metasploitInstance: MetasploitClient | null = null

/**
 * Get Metasploit client instance
 */
export function getMetasploitClient(config?: MetasploitConfig): MetasploitClient {
  if (!metasploitInstance) {
    const defaultConfig: MetasploitConfig = {
      host: process.env.METASPLOIT_HOST || 'localhost',
      port: parseInt(process.env.METASPLOIT_PORT || '55553'),
      username: process.env.METASPLOIT_USER || 'msf',
      password: process.env.METASPLOIT_PASS || 'msf',
      ssl: process.env.METASPLOIT_SSL === 'true'
    }

    metasploitInstance = new MetasploitClient(config || defaultConfig)
  }

  return metasploitInstance
}

export default MetasploitClient

