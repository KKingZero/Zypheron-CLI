/**
 * Threat Intelligence Aggregator
 * Real-time CVE updates from multiple sources
 */

import axios from 'axios'
import { EventEmitter } from 'events'
import { getNVDClient } from './nvdClient'

export interface ThreatIntelSource {
  name: string
  url: string
  updateInterval: number // milliseconds
  parser: (data: any) => ThreatIntelUpdate[]
}

export interface ThreatIntelUpdate {
  source: string
  type: 'cve' | 'exploit' | 'advisory' | 'threat'
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  published: Date
  description: string
  affectedProducts: string[]
  references: string[]
  exploitAvailable: boolean
  metadata?: Record<string, any>
}

export class ThreatIntelligenceAggregator extends EventEmitter {
  private sources: Map<string, ThreatIntelSource> = new Map()
  private updates: Map<string, ThreatIntelUpdate> = new Map()
  private updateIntervals: Map<string, NodeJS.Timeout> = new Map()
  private isRunning = false

  constructor() {
    super()
    this.initializeSources()
  }

  /**
   * Initialize threat intelligence sources
   */
  private initializeSources() {
    // NVD Recent CVEs
    this.registerSource({
      name: 'nvd',
      url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
      updateInterval: 3600000, // 1 hour
      parser: this.parseNVDFeed.bind(this)
    })

    // CISA Known Exploited Vulnerabilities
    this.registerSource({
      name: 'cisa-kev',
      url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      updateInterval: 7200000, // 2 hours
      parser: this.parseCISAKEV.bind(this)
    })

    // Exploit-DB Recent
    this.registerSource({
      name: 'exploit-db',
      url: 'https://www.exploit-db.com/rss.xml',
      updateInterval: 3600000, // 1 hour
      parser: this.parseExploitDB.bind(this)
    })

    console.log(`🔌 Initialized ${this.sources.size} threat intelligence sources`)
  }

  /**
   * Register a threat intelligence source
   */
  registerSource(source: ThreatIntelSource) {
    this.sources.set(source.name, source)
  }

  /**
   * Start continuous updates
   */
  start() {
    if (this.isRunning) {
      console.log('⚠️  Threat intelligence aggregator already running')
      return
    }

    this.isRunning = true
    console.log('🚀 Starting threat intelligence aggregator...')

    // Initial fetch for all sources
    this.sources.forEach((source, name) => {
      this.fetchSource(name)

      // Schedule recurring updates
      const interval = setInterval(() => {
        this.fetchSource(name)
      }, source.updateInterval)

      this.updateIntervals.set(name, interval)
    })
  }

  /**
   * Stop updates
   */
  stop() {
    this.isRunning = false
    
    // Clear all intervals
    this.updateIntervals.forEach(interval => clearInterval(interval))
    this.updateIntervals.clear()

    console.log('🛑 Threat intelligence aggregator stopped')
  }

  /**
   * Fetch updates from specific source
   */
  private async fetchSource(sourceName: string) {
    const source = this.sources.get(sourceName)
    if (!source) return

    try {
      console.log(`📡 Fetching updates from ${sourceName}...`)

      const response = await axios.get(source.url, {
        timeout: 30000,
        headers: {
          'User-Agent': 'Cobra-AI-Security-Scanner/1.0'
        }
      })

      const updates = source.parser(response.data)
      
      // Store updates
      updates.forEach(update => {
        const key = `${update.source}:${update.id}`
        if (!this.updates.has(key)) {
          this.updates.set(key, update)
          this.emit('new-threat', update)
        }
      })

      console.log(`✅ Fetched ${updates.length} updates from ${sourceName}`)
      this.emit('source-updated', sourceName, updates.length)

    } catch (error) {
      console.error(`❌ Error fetching from ${sourceName}:`, error)
      this.emit('source-error', sourceName, error)
    }
  }

  /**
   * Parse NVD feed
   */
  private parseNVDFeed(data: any): ThreatIntelUpdate[] {
    if (!data.vulnerabilities) return []

    return data.vulnerabilities.map((item: any) => {
      const cve = item.cve
      const cvss = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0]

      return {
        source: 'nvd',
        type: 'cve' as const,
        id: cve.id,
        title: cve.descriptions?.[0]?.value || cve.id,
        severity: this.mapSeverity(cvss?.cvssData?.baseSeverity || 'MEDIUM'),
        published: new Date(cve.published),
        description: cve.descriptions?.[0]?.value || '',
        affectedProducts: this.extractProductsFromCVE(cve),
        references: cve.references?.map((r: any) => r.url) || [],
        exploitAvailable: this.checkExploitAvailability(cve.references || []),
        metadata: {
          cvss: cvss?.cvssData?.baseScore,
          cvssVector: cvss?.cvssData?.vectorString
        }
      }
    })
  }

  /**
   * Parse CISA Known Exploited Vulnerabilities
   */
  private parseCISAKEV(data: any): ThreatIntelUpdate[] {
    if (!data.vulnerabilities) return []

    return data.vulnerabilities.map((vuln: any) => ({
      source: 'cisa-kev',
      type: 'exploit' as const,
      id: vuln.cveID,
      title: vuln.vulnerabilityName,
      severity: 'high' as const, // CISA KEV are all high/critical
      published: new Date(vuln.dateAdded),
      description: vuln.shortDescription,
      affectedProducts: [vuln.product],
      references: [vuln.vendorProject],
      exploitAvailable: true, // All CISA KEV have known exploits
      metadata: {
        requiredAction: vuln.requiredAction,
        dueDate: vuln.dueDate,
        knownRansomwareCampaignUse: vuln.knownRansomwareCampaignUse
      }
    }))
  }

  /**
   * Parse Exploit-DB RSS
   */
  private parseExploitDB(data: any): ThreatIntelUpdate[] {
    // Parse XML RSS feed
    const parser = require('xml2js')
    const updates: ThreatIntelUpdate[] = []

    parser.parseString(data, (err: any, result: any) => {
      if (err || !result.rss?.channel?.[0]?.item) return

      result.rss.channel[0].item.forEach((item: any) => {
        const title = item.title?.[0] || ''
        const cveMatch = title.match(/CVE-\d{4}-\d+/i)

        updates.push({
          source: 'exploit-db',
          type: 'exploit' as const,
          id: item.guid?.[0]?._ || item.link?.[0],
          title,
          severity: 'high' as const, // Exploits are high severity
          published: new Date(item.pubDate?.[0]),
          description: item.description?.[0] || '',
          affectedProducts: [],
          references: [item.link?.[0]],
          exploitAvailable: true,
          metadata: {
            cve: cveMatch ? cveMatch[0] : null,
            type: item.category?.[0] || 'unknown'
          }
        })
      })
    })

    return updates
  }

  /**
   * Get recent updates
   */
  getRecentUpdates(hours: number = 24): ThreatIntelUpdate[] {
    const cutoff = Date.now() - (hours * 60 * 60 * 1000)
    
    return Array.from(this.updates.values())
      .filter(update => update.published.getTime() > cutoff)
      .sort((a, b) => b.published.getTime() - a.published.getTime())
  }

  /**
   * Get updates by severity
   */
  getUpdatesBySeverity(severity: 'critical' | 'high' | 'medium' | 'low'): ThreatIntelUpdate[] {
    return Array.from(this.updates.values())
      .filter(update => update.severity === severity)
      .sort((a, b) => b.published.getTime() - a.published.getTime())
  }

  /**
   * Search updates by product
   */
  searchByProduct(product: string): ThreatIntelUpdate[] {
    const productLower = product.toLowerCase()
    
    return Array.from(this.updates.values())
      .filter(update => 
        update.affectedProducts.some(p => p.toLowerCase().includes(productLower)) ||
        update.title.toLowerCase().includes(productLower) ||
        update.description.toLowerCase().includes(productLower)
      )
      .sort((a, b) => b.published.getTime() - a.published.getTime())
  }

  /**
   * Get exploit updates
   */
  getExploitUpdates(): ThreatIntelUpdate[] {
    return Array.from(this.updates.values())
      .filter(update => update.exploitAvailable)
      .sort((a, b) => b.published.getTime() - a.published.getTime())
  }

  /**
   * Helper methods
   */
  
  private extractProductsFromCVE(cve: any): string[] {
    const products = new Set<string>()

    cve.configurations?.forEach((config: any) => {
      config.nodes?.forEach((node: any) => {
        node.cpeMatch?.forEach((match: any) => {
          if (match.criteria) {
            // Parse CPE format: cpe:2.3:a:vendor:product:version...
            const parts = match.criteria.split(':')
            if (parts.length >= 5) {
              products.add(`${parts[3]}:${parts[4]}`)
            }
          }
        })
      })
    })

    return Array.from(products)
  }

  private checkExploitAvailability(references: any[]): boolean {
    return references.some((ref: any) => {
      const url = ref.url || ref
      return url.includes('exploit-db') ||
             url.includes('exploitdb') ||
             url.includes('metasploit') ||
             url.includes('packetstorm')
    })
  }

  private mapSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' {
    const severityLower = severity.toLowerCase()
    if (severityLower === 'critical') return 'critical'
    if (severityLower === 'high') return 'high'
    if (severityLower === 'medium') return 'medium'
    return 'low'
  }

  /**
   * Get statistics
   */
  getStatistics() {
    const updates = Array.from(this.updates.values())
    
    return {
      total: updates.length,
      critical: updates.filter(u => u.severity === 'critical').length,
      high: updates.filter(u => u.severity === 'high').length,
      medium: updates.filter(u => u.severity === 'medium').length,
      low: updates.filter(u => u.severity === 'low').length,
      withExploits: updates.filter(u => u.exploitAvailable).length,
      sources: Array.from(this.sources.keys()),
      lastUpdate: updates.length > 0 
        ? Math.max(...updates.map(u => u.published.getTime()))
        : null
    }
  }
}

// Singleton instance
let aggregatorInstance: ThreatIntelligenceAggregator | null = null

export function getThreatIntelligenceAggregator(): ThreatIntelligenceAggregator {
  if (!aggregatorInstance) {
    aggregatorInstance = new ThreatIntelligenceAggregator()
  }
  return aggregatorInstance
}

