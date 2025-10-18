/**
 * NVD (National Vulnerability Database) Client
 * Real CVE database integration with version matching and CVSS scoring
 */

import axios, { AxiosInstance } from 'axios'
import * as semver from 'semver'
import NodeCache from 'node-cache'

export interface CVEData {
  id: string
  description: string
  published: string
  lastModified: string
  cvss2?: CVSSScore
  cvss3?: CVSSScore
  cvss31?: CVSSScore
  weaknesses: string[] // CWE IDs
  references: string[]
  configurations: CPEConfiguration[]
  exploitAvailable: boolean
  exploitMaturity?: 'unproven' | 'proof-of-concept' | 'functional' | 'high'
}

export interface CVSSScore {
  version: string
  vectorString: string
  baseScore: number
  baseSeverity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  exploitabilityScore: number
  impactScore: number
  attackVector: string
  attackComplexity: string
  privilegesRequired: string
  userInteraction: string
  scope: string
  confidentialityImpact: string
  integrityImpact: string
  availabilityImpact: string
}

export interface CPEConfiguration {
  operator: 'AND' | 'OR'
  cpeMatch: CPEMatch[]
}

export interface CPEMatch {
  vulnerable: boolean
  criteria: string
  versionStartIncluding?: string
  versionStartExcluding?: string
  versionEndIncluding?: string
  versionEndExcluding?: string
  matchCriteriaId: string
}

export interface SearchOptions {
  keyword?: string
  cpeMatchString?: string
  cvssV3Severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  lastModStartDate?: Date
  lastModEndDate?: Date
  pubStartDate?: Date
  pubEndDate?: Date
  resultsPerPage?: number
}

export class NVDClient {
  private baseURL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
  private apiKey?: string
  private client: AxiosInstance
  private cache: NodeCache
  private requestQueue: Promise<any>[] = []
  private lastRequestTime = 0
  private requestDelay = 6000 // 6 seconds between requests (NVD rate limit)

  constructor(apiKey?: string) {
    this.apiKey = apiKey || process.env.NVD_API_KEY
    
    // With API key: 50 requests per 30 seconds
    // Without: 5 requests per 30 seconds
    this.requestDelay = this.apiKey ? 600 : 6000

    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: 30000,
      headers: this.apiKey ? { 'apiKey': this.apiKey } : {}
    })

    // Cache CVE data for 24 hours
    this.cache = new NodeCache({ stdTTL: 86400, checkperiod: 3600 })

    console.log(`🔍 NVD Client initialized ${this.apiKey ? 'with API key' : 'without API key'}`)
  }

  /**
   * Search CVEs by keyword or CPE
   */
  async searchCVEs(options: SearchOptions): Promise<CVEData[]> {
    const cacheKey = JSON.stringify(options)
    const cached = this.cache.get<CVEData[]>(cacheKey)
    if (cached) {
      console.log('📦 Returning cached CVE data')
      return cached
    }

    await this.rateLimitDelay()

    try {
      const params: any = {
        resultsPerPage: options.resultsPerPage || 100
      }

      if (options.keyword) {
        params.keywordSearch = options.keyword
      }

      if (options.cpeMatchString) {
        params.cpeName = options.cpeMatchString
      }

      if (options.cvssV3Severity) {
        params.cvssV3Severity = options.cvssV3Severity
      }

      if (options.lastModStartDate) {
        params.lastModStartDate = options.lastModStartDate.toISOString()
      }

      if (options.lastModEndDate) {
        params.lastModEndDate = options.lastModEndDate.toISOString()
      }

      const response = await this.client.get('', { params })
      const cves = this.parseCVEResponse(response.data)

      this.cache.set(cacheKey, cves)
      return cves
    } catch (error) {
      console.error('❌ NVD API error:', error)
      return []
    }
  }

  /**
   * Get specific CVE by ID
   */
  async getCVE(cveId: string): Promise<CVEData | null> {
    const cached = this.cache.get<CVEData>(cveId)
    if (cached) {
      return cached
    }

    await this.rateLimitDelay()

    try {
      const response = await this.client.get('', {
        params: { cveId }
      })

      const cves = this.parseCVEResponse(response.data)
      if (cves.length > 0) {
        this.cache.set(cveId, cves[0])
        return cves[0]
      }

      return null
    } catch (error) {
      console.error(`❌ Error fetching CVE ${cveId}:`, error)
      return null
    }
  }

  /**
   * Search vulnerabilities for specific product and version
   */
  async searchByProductVersion(product: string, version: string, vendor?: string): Promise<CVEData[]> {
    const cacheKey = `product:${vendor}:${product}:${version}`
    const cached = this.cache.get<CVEData[]>(cacheKey)
    if (cached) {
      return cached
    }

    // Search by keyword first
    const keyword = vendor ? `${vendor} ${product}` : product
    let cves = await this.searchCVEs({ keyword })

    // Filter by version
    const matchingCVEs = cves.filter(cve => 
      this.isVersionAffected(version, cve.configurations)
    )

    this.cache.set(cacheKey, matchingCVEs)
    return matchingCVEs
  }

  /**
   * Check if version is affected by CVE
   */
  isVersionAffected(version: string, configurations: CPEConfiguration[]): boolean {
    for (const config of configurations) {
      for (const match of config.cpeMatch) {
        if (!match.vulnerable) continue

        // If no version constraints, assume affected
        if (!match.versionStartIncluding && 
            !match.versionStartExcluding &&
            !match.versionEndIncluding &&
            !match.versionEndExcluding) {
          return true
        }

        // Try semantic versioning comparison
        try {
          const cleanVersion = semver.clean(version) || version

          // Check version ranges
          if (match.versionStartIncluding) {
            const start = semver.clean(match.versionStartIncluding) || match.versionStartIncluding
            if (semver.lt(cleanVersion, start)) continue
          }

          if (match.versionStartExcluding) {
            const start = semver.clean(match.versionStartExcluding) || match.versionStartExcluding
            if (semver.lte(cleanVersion, start)) continue
          }

          if (match.versionEndIncluding) {
            const end = semver.clean(match.versionEndIncluding) || match.versionEndIncluding
            if (semver.gt(cleanVersion, end)) continue
          }

          if (match.versionEndExcluding) {
            const end = semver.clean(match.versionEndExcluding) || match.versionEndExcluding
            if (semver.gte(cleanVersion, end)) continue
          }

          // If we made it here, version is in affected range
          return true
        } catch (error) {
          // Semantic versioning failed, try string comparison
          if (this.compareVersionStrings(version, match)) {
            return true
          }
        }
      }
    }

    return false
  }

  /**
   * Fallback version comparison for non-semver versions
   */
  private compareVersionStrings(version: string, match: CPEMatch): boolean {
    if (match.versionStartIncluding && version < match.versionStartIncluding) return false
    if (match.versionStartExcluding && version <= match.versionStartExcluding) return false
    if (match.versionEndIncluding && version > match.versionEndIncluding) return false
    if (match.versionEndExcluding && version >= match.versionEndExcluding) return false
    return true
  }

  /**
   * Get recently published CVEs
   */
  async getRecentCVEs(days: number = 30): Promise<CVEData[]> {
    const endDate = new Date()
    const startDate = new Date()
    startDate.setDate(startDate.getDate() - days)

    return this.searchCVEs({
      pubStartDate: startDate,
      pubEndDate: endDate,
      resultsPerPage: 100
    })
  }

  /**
   * Get recently modified CVEs
   */
  async getRecentlyModifiedCVEs(days: number = 7): Promise<CVEData[]> {
    const endDate = new Date()
    const startDate = new Date()
    startDate.setDate(startDate.getDate() - days)

    return this.searchCVEs({
      lastModStartDate: startDate,
      lastModEndDate: endDate,
      resultsPerPage: 100
    })
  }

  /**
   * Parse NVD API response
   */
  private parseCVEResponse(data: any): CVEData[] {
    if (!data.vulnerabilities) return []

    return data.vulnerabilities.map((item: any) => {
      const cve = item.cve

      // Get descriptions
      const description = cve.descriptions?.find((d: any) => d.lang === 'en')?.value || ''

      // Get CVSS scores
      const cvss2 = cve.metrics?.cvssMetricV2?.[0]
      const cvss3 = cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV31?.[0]
      const cvss31 = cve.metrics?.cvssMetricV31?.[0]

      // Get weaknesses (CWE)
      const weaknesses = cve.weaknesses?.flatMap((w: any) => 
        w.description.map((d: any) => d.value)
      ) || []

      // Get references
      const references = cve.references?.map((r: any) => r.url) || []

      // Parse configurations
      const configurations = cve.configurations?.map((config: any) => ({
        operator: config.operator,
        cpeMatch: config.nodes?.flatMap((node: any) => 
          node.cpeMatch?.map((match: any) => ({
            vulnerable: match.vulnerable,
            criteria: match.criteria,
            versionStartIncluding: match.versionStartIncluding,
            versionStartExcluding: match.versionStartExcluding,
            versionEndIncluding: match.versionEndIncluding,
            versionEndExcluding: match.versionEndExcluding,
            matchCriteriaId: match.matchCriteriaId
          })) || []
        ) || []
      })) || []

      // Check exploit availability (from references)
      const exploitAvailable = references.some(ref => 
        ref.includes('exploit-db') || 
        ref.includes('exploitdb') ||
        ref.includes('metasploit') ||
        ref.includes('packetstorm')
      )

      return {
        id: cve.id,
        description,
        published: cve.published,
        lastModified: cve.lastModified,
        cvss2: cvss2 ? this.parseCVSSMetric(cvss2, '2.0') : undefined,
        cvss3: cvss3 ? this.parseCVSSMetric(cvss3, '3.0') : undefined,
        cvss31: cvss31 ? this.parseCVSSMetric(cvss31, '3.1') : undefined,
        weaknesses,
        references,
        configurations,
        exploitAvailable,
        exploitMaturity: this.determineExploitMaturity(references)
      }
    })
  }

  /**
   * Parse CVSS metric
   */
  private parseCVSSMetric(metric: any, version: string): CVSSScore {
    const cvssData = metric.cvssData

    return {
      version,
      vectorString: cvssData.vectorString,
      baseScore: cvssData.baseScore,
      baseSeverity: cvssData.baseSeverity || this.scoreToSeverity(cvssData.baseScore),
      exploitabilityScore: metric.exploitabilityScore || 0,
      impactScore: metric.impactScore || 0,
      attackVector: cvssData.attackVector || 'UNKNOWN',
      attackComplexity: cvssData.attackComplexity || 'UNKNOWN',
      privilegesRequired: cvssData.privilegesRequired || 'UNKNOWN',
      userInteraction: cvssData.userInteraction || 'UNKNOWN',
      scope: cvssData.scope || 'UNCHANGED',
      confidentialityImpact: cvssData.confidentialityImpact || 'NONE',
      integrityImpact: cvssData.integrityImpact || 'NONE',
      availabilityImpact: cvssData.availabilityImpact || 'NONE'
    }
  }

  /**
   * Convert CVSS score to severity
   */
  private scoreToSeverity(score: number): 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    if (score === 0) return 'NONE'
    if (score < 4.0) return 'LOW'
    if (score < 7.0) return 'MEDIUM'
    if (score < 9.0) return 'HIGH'
    return 'CRITICAL'
  }

  /**
   * Determine exploit maturity from references
   */
  private determineExploitMaturity(references: string[]): 'unproven' | 'proof-of-concept' | 'functional' | 'high' {
    if (references.some(r => r.includes('metasploit'))) return 'high'
    if (references.some(r => r.includes('exploit-db'))) return 'functional'
    if (references.some(r => r.includes('packetstorm') || r.includes('github'))) return 'proof-of-concept'
    return 'unproven'
  }

  /**
   * Rate limiting delay
   */
  private async rateLimitDelay(): Promise<void> {
    const now = Date.now()
    const timeSinceLastRequest = now - this.lastRequestTime

    if (timeSinceLastRequest < this.requestDelay) {
      const delay = this.requestDelay - timeSinceLastRequest
      await new Promise(resolve => setTimeout(resolve, delay))
    }

    this.lastRequestTime = Date.now()
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.cache.flushAll()
  }
}

// Singleton instance
let nvdClientInstance: NVDClient | null = null

export function getNVDClient(apiKey?: string): NVDClient {
  if (!nvdClientInstance) {
    nvdClientInstance = new NVDClient(apiKey)
  }
  return nvdClientInstance
}

