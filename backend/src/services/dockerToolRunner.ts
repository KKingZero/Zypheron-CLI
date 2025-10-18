/**
 * Docker Sandboxed Tool Runner
 * Executes security tools in isolated Docker containers
 * Provides network isolation, resource limits, and automatic cleanup
 */

import { spawn, ChildProcess } from 'child_process'
import { EventEmitter } from 'events'
import * as path from 'path'
import * as fs from 'fs'

export interface DockerToolConfig {
  image: string
  toolName: string
  command: string[]
  timeout?: number
  networkMode?: 'none' | 'bridge' | 'host'
  memoryLimit?: string
  cpuLimit?: string
  readOnly?: boolean
  volumeMounts?: { host: string; container: string; mode?: 'ro' | 'rw' }[]
}

export interface DockerToolResult {
  success: boolean
  stdout: string
  stderr: string
  exitCode: number | null
  executionTime: number
  containerId?: string
  error?: string
}

// Docker images for different tool categories
export const TOOL_IMAGES: Record<string, string> = {
  // Network scanners
  'nmap': 'instrumentisto/nmap:latest',
  'masscan': 'analogj/masscan:latest',
  
  // Web vulnerability scanners
  'nikto': 'frapsoft/nikto:latest',
  'sqlmap': 'paoloo/sqlmap:latest',
  'nuclei': 'projectdiscovery/nuclei:latest',
  'gobuster': 'ojack/gobuster:latest',
  
  // Password cracking
  'john': 'zacheller/john:latest',
  'hashcat': 'dizcza/docker-hashcat:latest',
  'hydra': 'vanhauser/hydra:latest',
  
  // Wireless security
  'aircrack-ng': 'tomgracey/aircrack:latest',
  
  // OSINT
  'recon-ng': 'abhartiya/tools_recon-ng:latest',
  'shodan': 'programmingenthusiast/shodan-cli:latest',
  'maltego': 'alpine:latest', // Custom commands
  
  // Binary analysis
  'radare2': 'radare/radare2:latest',
  'binwalk': 'rjocoleman/binwalk:latest',
  
  // General purpose
  'kali': 'kalilinux/kali-rolling:latest',
  'parrot': 'parrotsec/security:latest'
}

export class DockerToolRunner extends EventEmitter {
  private runningContainers: Map<string, ChildProcess> = new Map()
  private resultsCache: Map<string, DockerToolResult> = new Map()
  private readonly workspaceDir: string

  constructor(workspaceDir: string = '/tmp/zypheron-tools') {
    super()
    this.workspaceDir = workspaceDir
    this.ensureWorkspaceExists()
  }

  /**
   * Ensure workspace directory exists for tool outputs
   */
  private ensureWorkspaceExists() {
    if (!fs.existsSync(this.workspaceDir)) {
      fs.mkdirSync(this.workspaceDir, { recursive: true, mode: 0o700 })
    }
  }

  /**
   * Check if Docker is available
   */
  async checkDockerAvailable(): Promise<boolean> {
    return new Promise((resolve) => {
      const docker = spawn('docker', ['--version'])
      docker.on('error', () => resolve(false))
      docker.on('close', (code) => resolve(code === 0))
    })
  }

  /**
   * Pull Docker image if not already available
   */
  async pullImageIfNeeded(image: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      console.log(`🐳 Checking Docker image: ${image}`)
      
      const checkImage = spawn('docker', ['images', '-q', image])
      let imageId = ''

      checkImage.stdout.on('data', (data) => {
        imageId += data.toString()
      })

      checkImage.on('close', (code) => {
        if (code === 0 && imageId.trim()) {
          console.log(`✅ Image ${image} already exists`)
          resolve(true)
        } else {
          console.log(`📥 Pulling image ${image}...`)
          
          const pullImage = spawn('docker', ['pull', image])
          
          pullImage.stdout.on('data', (data) => {
            this.emit('pull-progress', data.toString())
          })

          pullImage.on('close', (pullCode) => {
            if (pullCode === 0) {
              console.log(`✅ Successfully pulled ${image}`)
              resolve(true)
            } else {
              reject(new Error(`Failed to pull image ${image}`))
            }
          })

          pullImage.on('error', (error) => {
            reject(new Error(`Docker pull error: ${error.message}`))
          })
        }
      })
    })
  }

  /**
   * Execute tool in Docker container with full isolation
   */
  async executeToolInDocker(config: DockerToolConfig): Promise<DockerToolResult> {
    const startTime = Date.now()
    const containerId = `zypheron-${config.toolName}-${Date.now()}`

    // Check Docker availability
    const dockerAvailable = await this.checkDockerAvailable()
    if (!dockerAvailable) {
      return {
        success: false,
        stdout: '',
        stderr: 'Docker is not available on this system',
        exitCode: null,
        executionTime: 0,
        error: 'Docker not installed or not running'
      }
    }

    // Pull image if needed
    try {
      await this.pullImageIfNeeded(config.image)
    } catch (error) {
      return {
        success: false,
        stdout: '',
        stderr: `Failed to pull Docker image: ${error}`,
        exitCode: null,
        executionTime: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error)
      }
    }

    // Build Docker run command with security constraints
    const dockerArgs = [
      'run',
      '--rm', // Auto-remove container after execution
      '--name', containerId,
      '--network', config.networkMode || 'bridge', // Network isolation
      '-m', config.memoryLimit || '512m', // Memory limit
      '--cpus', config.cpuLimit || '1.0', // CPU limit
      '--security-opt', 'no-new-privileges', // Prevent privilege escalation
      '--cap-drop', 'ALL', // Drop all capabilities
      '--cap-add', 'NET_RAW', // Only allow network raw sockets (for scanners)
      '--cap-add', 'NET_ADMIN', // Network administration (for some tools)
    ]

    // Add read-only root filesystem if specified
    if (config.readOnly) {
      dockerArgs.push('--read-only')
      // Add tmpfs for /tmp since root is read-only
      dockerArgs.push('--tmpfs', '/tmp:rw,noexec,nosuid,size=100m')
    }

    // Add volume mounts
    if (config.volumeMounts) {
      for (const mount of config.volumeMounts) {
        dockerArgs.push('-v', `${mount.host}:${mount.container}:${mount.mode || 'ro'}`)
      }
    } else {
      // Default: mount workspace directory
      dockerArgs.push('-v', `${this.workspaceDir}:/workspace:rw`)
      dockerArgs.push('-w', '/workspace')
    }

    // Add image and command
    dockerArgs.push(config.image)
    dockerArgs.push(...config.command)

    console.log(`🔧 Executing: docker ${dockerArgs.join(' ')}`)

    return new Promise((resolve) => {
      let stdout = ''
      let stderr = ''
      let timedOut = false

      const process = spawn('docker', dockerArgs, {
        stdio: ['pipe', 'pipe', 'pipe']
      })

      // Store process for potential cleanup
      this.runningContainers.set(containerId, process)

      // Capture stdout
      process.stdout.on('data', (data) => {
        const output = data.toString()
        stdout += output
        this.emit('stdout', config.toolName, output)
      })

      // Capture stderr
      process.stderr.on('data', (data) => {
        const output = data.toString()
        stderr += output
        this.emit('stderr', config.toolName, output)
      })

      // Set timeout
      const timeoutHandle = setTimeout(() => {
        timedOut = true
        console.warn(`⏱️ Tool ${config.toolName} timed out, killing container...`)
        this.killContainer(containerId)
      }, config.timeout || 300000) // Default 5 minutes

      // Handle process completion
      process.on('close', (code) => {
        clearTimeout(timeoutHandle)
        this.runningContainers.delete(containerId)

        const executionTime = Date.now() - startTime
        const result: DockerToolResult = {
          success: code === 0 && !timedOut,
          stdout,
          stderr,
          exitCode: code,
          executionTime,
          containerId,
          error: timedOut ? 'Execution timed out' : undefined
        }

        // Cache result
        this.resultsCache.set(containerId, result)

        this.emit('completed', config.toolName, result)
        resolve(result)
      })

      // Handle errors
      process.on('error', (error) => {
        clearTimeout(timeoutHandle)
        this.runningContainers.delete(containerId)

        resolve({
          success: false,
          stdout,
          stderr: stderr + '\n' + error.message,
          exitCode: null,
          executionTime: Date.now() - startTime,
          error: error.message
        })
      })
    })
  }

  /**
   * Kill a running container
   */
  async killContainer(containerId: string): Promise<void> {
    const process = this.runningContainers.get(containerId)
    if (process) {
      process.kill('SIGKILL')
    }

    // Force remove container
    spawn('docker', ['rm', '-f', containerId])
  }

  /**
   * Kill all running containers
   */
  async killAllContainers(): Promise<void> {
    const promises = Array.from(this.runningContainers.keys()).map(id => this.killContainer(id))
    await Promise.all(promises)
  }

  /**
   * Get tool result from cache
   */
  getResult(containerId: string): DockerToolResult | undefined {
    return this.resultsCache.get(containerId)
  }

  /**
   * Cleanup old results from cache
   */
  cleanupCache(maxAgeMs: number = 3600000): void {
    // Remove results older than 1 hour by default
    for (const [id, result] of this.resultsCache.entries()) {
      if (Date.now() - result.executionTime > maxAgeMs) {
        this.resultsCache.delete(id)
      }
    }
  }
}

/**
 * Pre-configured tool executions with Docker
 */
export class DockerizedKaliTools {
  private runner: DockerToolRunner

  constructor(workspaceDir?: string) {
    this.runner = new DockerToolRunner(workspaceDir)
  }

  /**
   * Nmap port scan
   */
  async nmapScan(target: string, ports?: string, scanType: string = 'sV'): Promise<DockerToolResult> {
    const command = ['nmap', `-${scanType}`]
    if (ports) {
      command.push('-p', ports)
    }
    command.push(target)

    return this.runner.executeToolInDocker({
      image: TOOL_IMAGES.nmap,
      toolName: 'nmap',
      command,
      timeout: 600000, // 10 minutes
      networkMode: 'bridge',
      memoryLimit: '256m',
      readOnly: true
    })
  }

  /**
   * Nikto web scanner
   */
  async niktoScan(target: string, options: string[] = []): Promise<DockerToolResult> {
    return this.runner.executeToolInDocker({
      image: TOOL_IMAGES.nikto,
      toolName: 'nikto',
      command: ['nikto', '-h', target, ...options],
      timeout: 900000, // 15 minutes
      networkMode: 'bridge',
      memoryLimit: '512m',
      readOnly: true
    })
  }

  /**
   * SQLMap injection testing
   */
  async sqlmapScan(url: string, options: string[] = []): Promise<DockerToolResult> {
    return this.runner.executeToolInDocker({
      image: TOOL_IMAGES.sqlmap,
      toolName: 'sqlmap',
      command: ['sqlmap', '-u', url, '--batch', ...options],
      timeout: 1800000, // 30 minutes
      networkMode: 'bridge',
      memoryLimit: '1g',
      readOnly: false // Needs to write results
    })
  }

  /**
   * Gobuster directory enumeration
   */
  async gobusterScan(url: string, wordlist: string = '/usr/share/wordlists/dirb/common.txt'): Promise<DockerToolResult> {
    return this.runner.executeToolInDocker({
      image: TOOL_IMAGES.gobuster,
      toolName: 'gobuster',
      command: ['gobuster', 'dir', '-u', url, '-w', wordlist, '-q'],
      timeout: 600000, // 10 minutes
      networkMode: 'bridge',
      memoryLimit: '256m',
      readOnly: true
    })
  }

  /**
   * Access the underlying runner
   */
  getRunner(): DockerToolRunner {
    return this.runner
  }
}

export default DockerToolRunner

