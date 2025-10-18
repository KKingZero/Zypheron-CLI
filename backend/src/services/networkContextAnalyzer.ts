/**
 * Network Context Analyzer
 * Determines network position and adjusts risk scores accordingly
 */

import * as dns from 'dns'
import { promisify } from 'util'
import axios from 'axios'

const dnsResolve = promisify(dns.resolve)
const dnsReverse = promisify(dns.reverse)

export interface NetworkContext {
  target: string
  ipAddress: string
  position: 'external' | 'dmz' | 'internal' | 'unknown'
  exposure: 'internet-facing' | 'restricted' | 'private'
  cloudProvider?: 'aws' | 'azure' | 'gcp' | 'digitalocean' | 'cloudflare' | 'other'
  asn?: string
  organization?: string
  country?: string
  riskModifier: number // Multiplier for risk scores
  contextualFactors: string[]
}

export class NetworkContextAnalyzer {
  private ipInfoCache: Map<string, any> = new Map()

  /**
   * Analyze network context for a target
   */
  async analyzeContext(target: string): Promise<NetworkContext> {
    console.log(`🔍 Analyzing network context for ${target}...`)

    // Resolve to IP
    const ipAddress = await this.resolveToIP(target)

    // Determine network position
    const position = this.determineNetworkPosition(ipAddress)

    // Determine exposure level
    const exposure = this.determineExposure(ipAddress, position)

    // Get IP information
    const ipInfo = await this.getIPInformation(ipAddress)

    // Calculate risk modifier
    const riskModifier = this.calculateRiskModifier(position, exposure, ipInfo)

    // Generate contextual factors
    const contextualFactors = this.generateContextualFactors(position, exposure, ipInfo)

    return {
      target,
      ipAddress,
      position,
      exposure,
      cloudProvider: ipInfo.cloudProvider,
      asn: ipInfo.asn,
      organization: ipInfo.organization,
      country: ipInfo.country,
      riskModifier,
      contextualFactors
    }
  }

  /**
   * Resolve target to IP address
   */
  private async resolveToIP(target: string): Promise<string> {
    // Already an IP?
    if (/^\d+\.\d+\.\d+\.\d+$/.test(target)) {
      return target
    }

    // Extract hostname from URL
    let hostname = target
    try {
      const url = new URL(target.startsWith('http') ? target : `http://${target}`)
      hostname = url.hostname
    } catch {
      // Not a URL, use as-is
    }

    // Resolve DNS
    try {
      const addresses = await dnsResolve(hostname, 'A') as string[]
      return addresses[0] || target
    } catch (error) {
      console.error(`DNS resolution failed for ${hostname}:`, error)
      return target
    }
  }

  /**
   * Determine network position
   */
  private determineNetworkPosition(ip: string): 'external' | 'dmz' | 'internal' | 'unknown' {
    // RFC 1918 private address spaces
    const privateRanges = [
      /^10\./,                    // 10.0.0.0/8
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12
      /^192\.168\./               // 192.168.0.0/16
    ]

    // Check if private
    const isPrivate = privateRanges.some(range => range.test(ip))
    if (isPrivate) {
      return 'internal'
    }

    // Loopback
    if (ip.startsWith('127.')) {
      return 'internal'
    }

    // Link-local
    if (ip.startsWith('169.254.')) {
      return 'internal'
    }

    // DMZ detection (heuristic)
    // DMZ systems often have specific IP patterns or hostnames
    // This is a simplified check
    const isDMZ = this.isDMZSystem(ip)
    if (isDMZ) {
      return 'dmz'
    }

    // Public IP
    return 'external'
  }

  /**
   * Determine exposure level
   */
  private determineExposure(
    ip: string,
    position: 'external' | 'dmz' | 'internal' | 'unknown'
  ): 'internet-facing' | 'restricted' | 'private' {
    switch (position) {
      case 'external':
        return 'internet-facing'
      
      case 'dmz':
        return 'restricted'
      
      case 'internal':
        return 'private'
      
      default:
        return 'internet-facing' // Assume worst case
    }
  }

  /**
   * Check if system appears to be in DMZ
   */
  private isDMZSystem(ip: string): boolean {
    // DMZ heuristics (this is simplified)
    // Real implementation would check reverse DNS, known DMZ ranges, etc.
    
    // Common DMZ port assignments
    // This is a placeholder - real implementation would be more sophisticated
    return false
  }

  /**
   * Get IP information from public databases
   */
  private async getIPInformation(ip: string): Promise<any> {
    // Check cache
    if (this.ipInfoCache.has(ip)) {
      return this.ipInfoCache.get(ip)
    }

    const info: any = {
      cloudProvider: undefined,
      asn: undefined,
      organization: undefined,
      country: undefined
    }

    try {
      // Try ip-api.com (free, no API key needed)
      const response = await axios.get(`http://ip-api.com/json/${ip}`, {
        timeout: 5000
      })

      if (response.data.status === 'success') {
        info.asn = response.data.as
        info.organization = response.data.org
        info.country = response.data.country

        // Detect cloud provider
        info.cloudProvider = this.detectCloudProvider(response.data.org, response.data.as)
      }
    } catch (error) {
      console.warn(`IP lookup failed for ${ip}:`, error)
    }

    // Cache for 1 hour
    this.ipInfoCache.set(ip, info)
    setTimeout(() => this.ipInfoCache.delete(ip), 3600000)

    return info
  }

  /**
   * Detect cloud provider from organization/ASN
   */
  private detectCloudProvider(org?: string, asn?: string): string | undefined {
    if (!org && !asn) return undefined

    const text = `${org || ''} ${asn || ''}`.toLowerCase()

    if (text.includes('amazon') || text.includes('aws')) return 'aws'
    if (text.includes('microsoft') || text.includes('azure')) return 'azure'
    if (text.includes('google') || text.includes('gcp')) return 'gcp'
    if (text.includes('digitalocean')) return 'digitalocean'
    if (text.includes('cloudflare')) return 'cloudflare'
    if (text.includes('akamai')) return 'other'
    if (text.includes('ovh')) return 'other'

    return undefined
  }

  /**
   * Calculate risk modifier
   */
  private calculateRiskModifier(
    position: string,
    exposure: string,
    ipInfo: any
  ): number {
    let modifier = 1.0

    // Position modifiers
    switch (position) {
      case 'external':
        modifier *= 1.5 // Internet-facing = higher risk
        break
      case 'dmz':
        modifier *= 1.2 // DMZ = moderate risk increase
        break
      case 'internal':
        modifier *= 0.7 // Internal = lower risk
        break
    }

    // Exposure modifiers
    switch (exposure) {
      case 'internet-facing':
        modifier *= 1.3
        break
      case 'restricted':
        modifier *= 1.0
        break
      case 'private':
        modifier *= 0.8
        break
    }

    // Cloud provider considerations
    if (ipInfo.cloudProvider) {
      // Cloud systems often have better security posture
      modifier *= 0.9
    }

    return modifier
  }

  /**
   * Generate contextual factors
   */
  private generateContextualFactors(
    position: string,
    exposure: string,
    ipInfo: any
  ): string[] {
    const factors: string[] = []

    // Position factors
    switch (position) {
      case 'external':
        factors.push('Internet-facing system - exposed to global threat actors')
        factors.push('Higher likelihood of automated scanning and exploitation')
        break
      case 'dmz':
        factors.push('DMZ system - some network protection in place')
        factors.push('May have limited access to internal resources')
        break
      case 'internal':
        factors.push('Internal system - requires prior network access')
        factors.push('Risk reduced due to network segmentation')
        break
    }

    // Cloud factors
    if (ipInfo.cloudProvider) {
      factors.push(`Hosted on ${ipInfo.cloudProvider.toUpperCase()} - cloud security features may apply`)
    }

    // Geographic factors
    if (ipInfo.country) {
      factors.push(`Located in ${ipInfo.country} - regional compliance and threat landscape`)
    }

    // ASN factors
    if (ipInfo.asn) {
      factors.push(`Network: ${ipInfo.asn}`)
    }

    return factors
  }

  /**
   * Adjust vulnerability score based on context
   */
  adjustVulnerabilityScore(
    baseScore: number,
    context: NetworkContext,
    vulnerability: any
  ): number {
    let adjustedScore = baseScore * context.riskModifier

    // Additional adjustments based on vulnerability type and context

    // Remote exploits are more dangerous on internet-facing systems
    if (vulnerability.attackVector === 'NETWORK' && context.exposure === 'internet-facing') {
      adjustedScore *= 1.2
    }

    // Local exploits are less dangerous on external systems
    if (vulnerability.attackVector === 'LOCAL' && context.position === 'external') {
      adjustedScore *= 0.7
    }

    // Exploits requiring user interaction are less dangerous
    if (vulnerability.userInteraction === 'REQUIRED') {
      adjustedScore *= 0.85
    }

    // Cap at 10.0
    return Math.min(10.0, adjustedScore)
  }

  /**
   * Get risk summary
   */
  getRiskSummary(context: NetworkContext): string {
    const riskLevel = context.riskModifier >= 1.3 ? 'HIGH' : 
                     context.riskModifier >= 1.0 ? 'MEDIUM' : 'LOW'

    return `${riskLevel} risk due to ${context.exposure} exposure at ${context.position} network position. ` +
           `Risk modifier: ${context.riskModifier.toFixed(2)}x`
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.ipInfoCache.clear()
  }
}

// Singleton instance
let analyzerInstance: NetworkContextAnalyzer | null = null

export function getNetworkContextAnalyzer(): NetworkContextAnalyzer {
  if (!analyzerInstance) {
    analyzerInstance = new NetworkContextAnalyzer()
  }
  return analyzerInstance
}

