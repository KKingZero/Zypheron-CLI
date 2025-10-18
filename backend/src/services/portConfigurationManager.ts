/**
 * Port Configuration Manager
 * Dynamically loads port lists from configuration
 */

import * as fs from 'fs'
import * as path from 'path'

export interface PortInfo {
  port: number
  service: string
  protocol: string
  risk: 'critical' | 'high' | 'medium' | 'low'
}

export interface ScanProfile {
  name: string
  description: string
  ports: string | number[]
}

export class PortConfigurationManager {
  private config: any
  private configPath: string

  constructor(configPath?: string) {
    this.configPath = configPath || path.join(__dirname, '../../config/ports.json')
    this.loadConfiguration()
  }

  /**
   * Load configuration from file
   */
  private loadConfiguration() {
    try {
      const configData = fs.readFileSync(this.configPath, 'utf8')
      this.config = JSON.parse(configData)
      console.log('✅ Port configuration loaded')
    } catch (error) {
      console.error('❌ Failed to load port configuration:', error)
      // Fallback to minimal default
      this.config = {
        common_ports: [
          { port: 80, service: 'HTTP', protocol: 'TCP', risk: 'low' },
          { port: 443, service: 'HTTPS', protocol: 'TCP', risk: 'low' }
        ],
        top_1000: [80, 443]
      }
    }
  }

  /**
   * Get ports by profile name
   */
  getPortsByProfile(profileName: string): number[] {
    const profile = this.config.scan_profiles?.[profileName]
    if (!profile) {
      console.warn(`Profile ${profileName} not found, using common ports`)
      return this.getCommonPorts().map(p => p.port)
    }

    return this.resolvePortList(profile.ports)
  }

  /**
   * Resolve port list from string or array
   */
  private resolvePortList(ports: string | number[]): number[] {
    if (Array.isArray(ports)) {
      return ports
    }

    // Check if it's a reference to another list
    if (this.config[ports]) {
      const list = this.config[ports]
      if (Array.isArray(list)) {
        // Could be array of numbers or port info objects
        if (typeof list[0] === 'number') {
          return list
        } else if (list[0].port) {
          return list.map((p: PortInfo) => p.port)
        }
      }
    }

    // Parse port range (e.g., "1-65535")
    if (ports.includes('-')) {
      const [start, end] = ports.split('-').map(Number)
      const portList: number[] = []
      for (let i = start; i <= end; i++) {
        portList.push(i)
      }
      return portList
    }

    // Parse comma-separated ports
    if (ports.includes(',')) {
      return ports.split(',').map(Number)
    }

    return []
  }

  /**
   * Get common ports with info
   */
  getCommonPorts(): PortInfo[] {
    return this.config.common_ports || []
  }

  /**
   * Get web ports
   */
  getWebPorts(): number[] {
    return this.config.web_ports || [80, 443]
  }

  /**
   * Get database ports
   */
  getDatabasePorts(): number[] {
    return this.config.database_ports || [3306, 5432, 27017]
  }

  /**
   * Get admin ports
   */
  getAdminPorts(): number[] {
    return this.config.admin_ports || [22, 3389]
  }

  /**
   * Get top 1000 ports
   */
  getTop1000Ports(): number[] {
    return this.config.top_1000 || []
  }

  /**
   * Get port info
   */
  getPortInfo(port: number): PortInfo | null {
    const commonPort = this.config.common_ports?.find((p: PortInfo) => p.port === port)
    return commonPort || null
  }

  /**
   * Get risk level for port
   */
  getPortRisk(port: number): 'critical' | 'high' | 'medium' | 'low' {
    const info = this.getPortInfo(port)
    return info?.risk || 'low'
  }

  /**
   * Get all available profiles
   */
  getAvailableProfiles(): Record<string, ScanProfile> {
    return this.config.scan_profiles || {}
  }

  /**
   * Add custom port
   */
  addCustomPort(portInfo: PortInfo): void {
    if (!this.config.common_ports) {
      this.config.common_ports = []
    }

    // Check if port already exists
    const existingIndex = this.config.common_ports.findIndex((p: PortInfo) => p.port === portInfo.port)
    
    if (existingIndex >= 0) {
      this.config.common_ports[existingIndex] = portInfo
    } else {
      this.config.common_ports.push(portInfo)
    }

    this.saveConfiguration()
  }

  /**
   * Add custom profile
   */
  addCustomProfile(name: string, profile: ScanProfile): void {
    if (!this.config.scan_profiles) {
      this.config.scan_profiles = {}
    }

    this.config.scan_profiles[name] = profile
    this.saveConfiguration()
  }

  /**
   * Save configuration to file
   */
  private saveConfiguration(): void {
    try {
      fs.writeFileSync(this.configPath, JSON.stringify(this.config, null, 2))
      console.log('✅ Port configuration saved')
    } catch (error) {
      console.error('❌ Failed to save port configuration:', error)
    }
  }

  /**
   * Reload configuration
   */
  reload(): void {
    this.loadConfiguration()
  }
}

// Singleton instance
let configManagerInstance: PortConfigurationManager | null = null

export function getPortConfigurationManager(): PortConfigurationManager {
  if (!configManagerInstance) {
    configManagerInstance = new PortConfigurationManager()
  }
  return configManagerInstance
}

