/**
 * Kali Linux Tools Executor
 * Provides interface to execute security tools from Kali container
 */

import { spawn, ChildProcess } from 'child_process'
import Docker from 'dockerode'
import { EventEmitter } from 'events'

const docker = new Docker()

export interface ToolExecutionOptions {
  target: string
  arguments: string[]
  timeout?: number // milliseconds
  outputFormat?: 'json' | 'xml' | 'text'
  env?: Record<string, string>
}

export interface ToolExecutionResult {
  success: boolean
  stdout: string
  stderr: string
  exitCode: number
  duration: number
  parsedOutput?: any
}

export class KaliToolExecutor extends EventEmitter {
  private containerName = 'cobra-ai-kali-pentest'
  private container: Docker.Container | null = null

  /**
   * Initialize and start Kali container
   */
  async initialize(): Promise<void> {
    try {
      // Check if container exists
      this.container = docker.getContainer(this.containerName)
      const info = await this.container.inspect()
      
      if (!info.State.Running) {
        await this.container.start()
      }
    } catch (error) {
      // Container doesn't exist, create it
      this.container = await docker.createContainer({
        Image: 'cobra-ai-kali-pentest:latest',
        name: this.containerName,
        Tty: true,
        AttachStdin: true,
        AttachStdout: true,
        AttachStderr: true,
        OpenStdin: true,
        HostConfig: {
          NetworkMode: 'bridge',
          Memory: 2 * 1024 * 1024 * 1024, // 2GB
          MemorySwap: 4 * 1024 * 1024 * 1024, // 4GB
          CpuQuota: 100000,
          AutoRemove: false,
          CapDrop: ['ALL'],
          CapAdd: ['NET_RAW', 'NET_ADMIN'], // Needed for nmap SYN scans
          SecurityOpt: ['no-new-privileges']
        }
      })

      await this.container.start()
    }

    console.log('✅ Kali Linux container initialized')
  }

  /**
   * Execute nmap scan
   */
  async executeNmap(target: string, options: {
    ports?: string
    scanType?: string
    timing?: number
    scripts?: string[]
  }): Promise<ToolExecutionResult> {
    const args = ['-oX', '-'] // Output XML to stdout
    
    // Scan type
    switch (options.scanType) {
      case 'syn':
        args.push('-sS')
        break
      case 'tcp':
        args.push('-sT')
        break
      case 'udp':
        args.push('-sU')
        break
      case 'version':
        args.push('-sV')
        break
      default:
        args.push('-sS')
    }

    // Timing
    if (options.timing) {
      args.push(`-T${options.timing}`)
    }

    // Ports
    if (options.ports) {
      args.push('-p', options.ports)
    }

    // Scripts
    if (options.scripts && options.scripts.length > 0) {
      args.push('--script', options.scripts.join(','))
    }

    // Service detection
    args.push('-sV', '--version-intensity', '5')

    // OS detection
    args.push('-O')

    // Target
    args.push(target)

    return this.executeCommand('nmap', args)
  }

  /**
   * Execute Nuclei scan
   */
  async executeNuclei(target: string, options: {
    templates?: string[]
    severity?: string[]
    tags?: string[]
  }): Promise<ToolExecutionResult> {
    const args = ['-u', target, '-json']

    if (options.templates && options.templates.length > 0) {
      args.push('-t', options.templates.join(','))
    }

    if (options.severity && options.severity.length > 0) {
      args.push('-severity', options.severity.join(','))
    }

    if (options.tags && options.tags.length > 0) {
      args.push('-tags', options.tags.join(','))
    }

    return this.executeCommand('nuclei', args)
  }

  /**
   * Execute SQLMap
   */
  async executeSQLMap(target: string, options: {
    method?: string
    data?: string
    cookie?: string
    level?: number
    risk?: number
  }): Promise<ToolExecutionResult> {
    const args = ['-u', target, '--batch', '--random-agent', '--output-dir=/tmp/sqlmap']

    if (options.method) {
      args.push('--method', options.method)
    }

    if (options.data) {
      args.push('--data', options.data)
    }

    if (options.cookie) {
      args.push('--cookie', options.cookie)
    }

    if (options.level) {
      args.push('--level', options.level.toString())
    }

    if (options.risk) {
      args.push('--risk', options.risk.toString())
    }

    return this.executeCommand('sqlmap', args)
  }

  /**
   * Execute WPScan (WordPress scanner)
   */
  async executeWPScan(target: string, options: {
    enumerate?: string
    apiToken?: string
  }): Promise<ToolExecutionResult> {
    const args = ['--url', target, '--format', 'json']

    if (options.enumerate) {
      args.push('--enumerate', options.enumerate)
    }

    if (options.apiToken) {
      args.push('--api-token', options.apiToken)
    }

    return this.executeCommand('wpscan', args)
  }

  /**
   * Execute ffuf (web fuzzer)
   */
  async executeFfuf(target: string, options: {
    wordlist: string
    extensions?: string[]
    matchCode?: number[]
    threads?: number
  }): Promise<ToolExecutionResult> {
    const args = ['-u', `${target}/FUZZ`, '-w', options.wordlist, '-json']

    if (options.extensions && options.extensions.length > 0) {
      args.push('-e', options.extensions.join(','))
    }

    if (options.matchCode && options.matchCode.length > 0) {
      args.push('-mc', options.matchCode.join(','))
    }

    if (options.threads) {
      args.push('-t', options.threads.toString())
    }

    return this.executeCommand('ffuf', args)
  }

  /**
   * Execute Amass (subdomain enumeration)
   */
  async executeAmass(domain: string, options: {
    passive?: boolean
    sources?: string[]
  }): Promise<ToolExecutionResult> {
    const args = ['enum', '-d', domain, '-json', '/dev/stdout']

    if (options.passive) {
      args.push('-passive')
    }

    if (options.sources && options.sources.length > 0) {
      args.push('-src')
    }

    return this.executeCommand('amass', args)
  }

  /**
   * Execute Trivy (container/IaC scanner)
   */
  async executeTrivy(target: string, options: {
    scanType: 'image' | 'filesystem' | 'repository'
    severity?: string[]
  }): Promise<ToolExecutionResult> {
    const args = [options.scanType, target, '-f', 'json']

    if (options.severity && options.severity.length > 0) {
      args.push('--severity', options.severity.join(','))
    }

    return this.executeCommand('trivy', args)
  }

  /**
   * Execute Semgrep (SAST)
   */
  async executeSemgrep(path: string, options: {
    config?: string
    rules?: string[]
  }): Promise<ToolExecutionResult> {
    const args = ['scan', path, '--json']

    if (options.config) {
      args.push('--config', options.config)
    } else {
      args.push('--config', 'auto')
    }

    return this.executeCommand('semgrep', args)
  }

  /**
   * Generic command execution in Kali container
   */
  private async executeCommand(tool: string, args: string[], timeout: number = 300000): Promise<ToolExecutionResult> {
    if (!this.container) {
      throw new Error('Container not initialized. Call initialize() first.')
    }

    const startTime = Date.now()
    let stdout = ''
    let stderr = ''

    try {
      const exec = await this.container.exec({
        Cmd: [tool, ...args],
        AttachStdout: true,
        AttachStderr: true,
      })

      const stream = await exec.start({ Detach: false, Tty: false })

      // Collect output
      await new Promise<void>((resolve, reject) => {
        const timeoutId = setTimeout(() => {
          stream.destroy()
          reject(new Error('Execution timeout'))
        }, timeout)

        stream.on('data', (chunk: Buffer) => {
          const data = chunk.toString()
          if (data.includes('stdout')) {
            stdout += data.replace(/^.*stdout.*$/gm, '')
          } else if (data.includes('stderr')) {
            stderr += data.replace(/^.*stderr.*$/gm, '')
          } else {
            stdout += data
          }

          this.emit('output', { tool, data })
        })

        stream.on('end', () => {
          clearTimeout(timeoutId)
          resolve()
        })

        stream.on('error', (error: Error) => {
          clearTimeout(timeoutId)
          reject(error)
        })
      })

      const inspectResult = await exec.inspect()
      const duration = Date.now() - startTime

      // Try to parse output as JSON
      let parsedOutput
      try {
        parsedOutput = JSON.parse(stdout)
      } catch {
        // Not JSON, leave as text
      }

      return {
        success: inspectResult.ExitCode === 0,
        stdout,
        stderr,
        exitCode: inspectResult.ExitCode || 0,
        duration,
        parsedOutput
      }
    } catch (error) {
      const duration = Date.now() - startTime
      return {
        success: false,
        stdout,
        stderr: stderr + '\n' + (error as Error).message,
        exitCode: 1,
        duration
      }
    }
  }

  /**
   * Stop and remove container
   */
  async cleanup(): Promise<void> {
    if (this.container) {
      try {
        await this.container.stop()
        await this.container.remove()
      } catch (error) {
        console.error('Error cleaning up container:', error)
      }
    }
  }
}

// Singleton instance
let executorInstance: KaliToolExecutor | null = null

export function getKaliToolExecutor(): KaliToolExecutor {
  if (!executorInstance) {
    executorInstance = new KaliToolExecutor()
  }
  return executorInstance
}

