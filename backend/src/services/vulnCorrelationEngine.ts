/**
 * Vulnerability Correlation Engine
 * Cross-tool analysis, deduplication, and risk scoring
 * Correlates findings from multiple security tools
 */

import { EventEmitter } from 'events'
import { VulnerabilityAssessment } from './aiPentestOrchestrator'

export interface CorrelatedVulnerability {
  id: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  cvss: number
  cve?: string[]
  cwe?: string[]
  affectedComponents: string[]
  discoveredBy: string[] // List of tools that found this
  confidence: number // 0-1 scale
  exploitAvailable: boolean
  exploitDifficulty: 'trivial' | 'easy' | 'moderate' | 'hard'
  impact: {
    confidentiality: 'none' | 'low' | 'high'
    integrity: 'none' | 'low' | 'high'
    availability: 'none' | 'low' | 'high'
  }
  remediation: string[]
  references: string[]
  relatedVulnerabilities: string[] // IDs of related vulns
  attackChainPosition?: number // Position in potential attack chain
  businessRiskScore: number // 0-10 scale
}

export interface AttackChain {
  id: string
  name: string
  vulnerabilities: CorrelatedVulnerability[]
  estimatedImpact: string
  likelihood: number
  overallRisk: number
  steps: string[]
}

export interface CorrelationReport {
  totalFindings: number
  uniqueVulnerabilities: number
  duplicatesRemoved: number
  correlatedVulnerabilities: CorrelatedVulnerability[]
  attackChains: AttackChain[]
  riskDistribution: {
    critical: number
    high: number
    medium: number
    low: number
  }
  topRisks: CorrelatedVulnerability[]
  recommendations: string[]
  generatedAt: string
}

class VulnerabilityCorrelationEngine extends EventEmitter {
  private vulnerabilities: Map<string, CorrelatedVulnerability> = new Map()
  private rawFindings: Map<string, any[]> = new Map() // tool -> findings

  /**
   * Ingest findings from a security tool
   */
  async ingestFindings(toolName: string, findings: any[]): Promise<void> {
    console.log(`📥 Ingesting ${findings.length} findings from ${toolName}`)

    // Store raw findings
    this.rawFindings.set(toolName, findings)

    // Process and correlate each finding
    for (const finding of findings) {
      await this.processFinding(toolName, finding)
    }

    this.emit('findings-ingested', toolName, findings.length)
  }

  /**
   * Process a single finding
   */
  private async processFinding(toolName: string, finding: any): Promise<void> {
    // Normalize finding to standard format
    const normalized = this.normalizeFinding(toolName, finding)

    if (!normalized) {
      return
    }

    // Check for duplicates/correlations
    const existing = this.findCorrelatedVulnerability(normalized)

    if (existing) {
      // Merge with existing vulnerability
      this.mergeVulnerabilities(existing, normalized, toolName)
    } else {
      // Add as new vulnerability
      const vulnId = `vuln-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
      const correlated: CorrelatedVulnerability = {
        id: vulnId,
        title: normalized.title || 'Unknown Vulnerability',
        ...normalized,
        discoveredBy: [toolName],
        confidence: 0.8, // Initial confidence
        relatedVulnerabilities: [],
        businessRiskScore: this.calculateBusinessRisk(normalized)
      }

      this.vulnerabilities.set(vulnId, correlated)
    }
  }

  /**
   * Normalize finding from different tools to standard format
   */
  private normalizeFinding(toolName: string, finding: any): Partial<CorrelatedVulnerability> | null {
    // Tool-specific normalization
    switch (toolName) {
      case 'nmap':
        return this.normalizeNmapFinding(finding)
      
      case 'nikto':
        return this.normalizeNiktoFinding(finding)
      
      case 'nessus':
        return this.normalizeNessusFinding(finding)
      
      case 'nuclei':
        return this.normalizeNucleiFinding(finding)
      
      case 'sqlmap':
        return this.normalizeSqlmapFinding(finding)
      
      default:
        // Generic normalization
        return {
          title: finding.title || finding.name || 'Unknown Vulnerability',
          description: finding.description || finding.message || '',
          severity: finding.severity || 'medium',
          cvss: finding.cvss || 5.0,
          cve: finding.cve ? [finding.cve] : [],
          cwe: finding.cwe ? [finding.cwe] : [],
          affectedComponents: [finding.component || 'unknown'],
          exploitAvailable: finding.exploitAvailable || false,
          exploitDifficulty: finding.difficulty || 'moderate',
          impact: {
            confidentiality: 'low',
            integrity: 'low',
            availability: 'low'
          },
          remediation: finding.remediation ? [finding.remediation] : [],
          references: finding.references || []
        }
    }
  }

  /**
   * Normalize Nmap finding
   */
  private normalizeNmapFinding(finding: any): Partial<CorrelatedVulnerability> | null {
    if (!finding.port || finding.state !== 'open') {
      return null
    }

    return {
      title: `Open Port: ${finding.port}/${finding.protocol}`,
      description: `Service ${finding.service || 'unknown'} running on port ${finding.port}`,
      severity: this.calculatePortSeverity(finding.port),
      cvss: this.calculatePortCVSS(finding.port),
      affectedComponents: [`${finding.service}:${finding.port}`],
      exploitAvailable: false,
      exploitDifficulty: 'moderate',
      impact: {
        confidentiality: 'low',
        integrity: 'none',
        availability: 'none'
      },
      remediation: [`Close port ${finding.port} if not required`, 'Implement firewall rules'],
      references: []
    }
  }

  /**
   * Normalize Nikto finding
   */
  private normalizeNiktoFinding(finding: any): Partial<CorrelatedVulnerability> | null {
    return {
      title: finding.msg || 'Web Vulnerability',
      description: finding.description || finding.msg || '',
      severity: this.mapOSVDBSeverity(finding.OSVDB),
      cvss: 5.0, // Default
      cve: finding.CVE ? [finding.CVE] : [],
      affectedComponents: [finding.uri || '/'],
      exploitAvailable: false,
      exploitDifficulty: 'easy',
      impact: {
        confidentiality: 'low',
        integrity: 'low',
        availability: 'none'
      },
      remediation: ['Update web server', 'Apply security patches'],
      references: finding.refs || []
    }
  }

  /**
   * Normalize Nessus finding
   */
  private normalizeNessusFinding(finding: any): Partial<CorrelatedVulnerability> | null {
    return {
      title: finding.plugin_name || finding.name,
      description: finding.description || '',
      severity: finding.severity || 'medium',
      cvss: finding.cvss_base_score || 5.0,
      cve: finding.cve || [],
      cwe: finding.cwe || [],
      affectedComponents: [finding.plugin_family || 'unknown'],
      exploitAvailable: finding.exploit_available || false,
      exploitDifficulty: 'moderate',
      impact: {
        confidentiality: finding.cvss_vector?.includes('C:H') ? 'high' : 'low',
        integrity: finding.cvss_vector?.includes('I:H') ? 'high' : 'low',
        availability: finding.cvss_vector?.includes('A:H') ? 'high' : 'low'
      },
      remediation: finding.solution ? [finding.solution] : [],
      references: finding.see_also || []
    }
  }

  /**
   * Normalize Nuclei finding
   */
  private normalizeNucleiFinding(finding: any): Partial<CorrelatedVulnerability> | null {
    return {
      title: finding.info?.name || 'Nuclei Detection',
      description: finding.info?.description || '',
      severity: finding.info?.severity || 'medium',
      cvss: this.mapNucleiSeverityToCVSS(finding.info?.severity),
      cve: finding.info?.classification?.cve ? [finding.info.classification.cve] : [],
      cwe: finding.info?.classification?.cwe ? [finding.info.classification.cwe] : [],
      affectedComponents: [finding.matched_at || finding.host || 'unknown'],
      exploitAvailable: finding.info?.tags?.includes('exploit') || false,
      exploitDifficulty: 'easy',
      impact: {
        confidentiality: 'low',
        integrity: 'low',
        availability: 'none'
      },
      remediation: ['Apply security updates', 'Review configuration'],
      references: finding.info?.reference || []
    }
  }

  /**
   * Normalize SQLMap finding
   */
  private normalizeSqlmapFinding(finding: any): Partial<CorrelatedVulnerability> | null {
    if (!finding.vulnerable) {
      return null
    }

    return {
      title: 'SQL Injection Vulnerability',
      description: `SQL injection found in parameter: ${finding.parameter}`,
      severity: 'high',
      cvss: 8.5,
      cve: [],
      cwe: ['CWE-89'],
      affectedComponents: [finding.url || 'unknown'],
      exploitAvailable: true,
      exploitDifficulty: 'easy',
      impact: {
        confidentiality: 'high',
        integrity: 'high',
        availability: 'high'
      },
      remediation: [
        'Use parameterized queries',
        'Implement input validation',
        'Apply least privilege principle to database accounts'
      ],
      references: ['https://owasp.org/www-community/attacks/SQL_Injection']
    }
  }

  /**
   * Find correlated vulnerability
   */
  private findCorrelatedVulnerability(vuln: Partial<CorrelatedVulnerability>): CorrelatedVulnerability | null {
    for (const existing of this.vulnerabilities.values()) {
      // Check CVE match
      if (vuln.cve && vuln.cve.length > 0 && existing.cve) {
        const cveMatch = vuln.cve.some(cve => existing.cve?.includes(cve))
        if (cveMatch) {
          return existing
        }
      }

      // Check title similarity
      if (vuln.title && existing.title) {
        const similarity = this.calculateStringSimilarity(vuln.title, existing.title)
        if (similarity > 0.8) {
          return existing
        }
      }

      // Check component overlap
      if (vuln.affectedComponents && existing.affectedComponents) {
        const overlap = vuln.affectedComponents.filter(c => 
          existing.affectedComponents.includes(c)
        )
        if (overlap.length > 0 && existing.severity === vuln.severity) {
          return existing
        }
      }
    }

    return null
  }

  /**
   * Merge two vulnerabilities
   */
  private mergeVulnerabilities(
    existing: CorrelatedVulnerability,
    newVuln: Partial<CorrelatedVulnerability>,
    toolName: string
  ): void {
    // Add tool to discoveredBy
    if (!existing.discoveredBy.includes(toolName)) {
      existing.discoveredBy.push(toolName)
    }

    // Increase confidence with more tool confirmations
    existing.confidence = Math.min(1.0, existing.confidence + 0.1)

    // Merge CVEs
    if (newVuln.cve) {
      existing.cve = [...new Set([...(existing.cve || []), ...newVuln.cve])]
    }

    // Merge CWEs
    if (newVuln.cwe) {
      existing.cwe = [...new Set([...(existing.cwe || []), ...newVuln.cwe])]
    }

    // Take highest severity
    if (newVuln.severity) {
      const severityOrder = ['critical', 'high', 'medium', 'low']
      const existingIdx = severityOrder.indexOf(existing.severity)
      const newIdx = severityOrder.indexOf(newVuln.severity)
      
      if (newIdx < existingIdx) {
        existing.severity = newVuln.severity
      }
    }

    // Take highest CVSS
    if (newVuln.cvss && newVuln.cvss > existing.cvss) {
      existing.cvss = newVuln.cvss
    }

    // Merge remediations
    if (newVuln.remediation) {
      existing.remediation = [...new Set([...existing.remediation, ...newVuln.remediation])]
    }

    // Merge references
    if (newVuln.references) {
      existing.references = [...new Set([...existing.references, ...newVuln.references])]
    }

    // Update business risk
    existing.businessRiskScore = this.calculateBusinessRisk(existing)
  }

  /**
   * Generate correlation report
   */
  async generateReport(): Promise<CorrelationReport> {
    const vulnerabilities = Array.from(this.vulnerabilities.values())

    // Calculate risk distribution
    const riskDistribution = {
      critical: vulnerabilities.filter(v => v.severity === 'critical').length,
      high: vulnerabilities.filter(v => v.severity === 'high').length,
      medium: vulnerabilities.filter(v => v.severity === 'medium').length,
      low: vulnerabilities.filter(v => v.severity === 'low').length
    }

    // Get top risks
    const topRisks = vulnerabilities
      .sort((a, b) => b.businessRiskScore - a.businessRiskScore)
      .slice(0, 10)

    // Identify attack chains
    const attackChains = await this.identifyAttackChains(vulnerabilities)

    // Generate recommendations
    const recommendations = this.generateRecommendations(vulnerabilities, attackChains)

    // Calculate duplicates removed
    const totalRawFindings = Array.from(this.rawFindings.values())
      .reduce((sum, findings) => sum + findings.length, 0)
    const duplicatesRemoved = totalRawFindings - vulnerabilities.length

    return {
      totalFindings: totalRawFindings,
      uniqueVulnerabilities: vulnerabilities.length,
      duplicatesRemoved,
      correlatedVulnerabilities: vulnerabilities,
      attackChains,
      riskDistribution,
      topRisks,
      recommendations,
      generatedAt: new Date().toISOString()
    }
  }

  /**
   * Identify potential attack chains
   */
  private async identifyAttackChains(vulnerabilities: CorrelatedVulnerability[]): Promise<AttackChain[]> {
    const chains: AttackChain[] = []

    // Look for common attack patterns
    
    // Pattern 1: Initial Access -> Privilege Escalation -> Data Exfiltration
    const initialAccess = vulnerabilities.filter(v => 
      v.exploitAvailable && (v.severity === 'critical' || v.severity === 'high')
    )

    for (const access of initialAccess) {
      const chain: AttackChain = {
        id: `chain-${chains.length + 1}`,
        name: `Attack Chain via ${access.title}`,
        vulnerabilities: [access],
        estimatedImpact: 'High',
        likelihood: access.exploitDifficulty === 'trivial' || access.exploitDifficulty === 'easy' ? 0.8 : 0.5,
        overallRisk: access.businessRiskScore,
        steps: [
          `1. Exploit ${access.title} for initial access`,
          '2. Escalate privileges using local vulnerabilities',
          '3. Move laterally through network',
          '4. Exfiltrate sensitive data'
        ]
      }

      chains.push(chain)
    }

    return chains
  }

  /**
   * Generate recommendations
   */
  private generateRecommendations(
    vulnerabilities: CorrelatedVulnerability[],
    attackChains: AttackChain[]
  ): string[] {
    const recommendations: string[] = []

    // Critical vulnerabilities
    const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length
    if (criticalCount > 0) {
      recommendations.push(
        `🚨 Address ${criticalCount} critical vulnerabilities immediately to prevent system compromise`
      )
    }

    // Exploitable vulnerabilities
    const exploitable = vulnerabilities.filter(v => v.exploitAvailable).length
    if (exploitable > 0) {
      recommendations.push(
        `⚠️  ${exploitable} vulnerabilities have public exploits available - prioritize patching`
      )
    }

    // Attack chains
    if (attackChains.length > 0) {
      recommendations.push(
        `🔗 ${attackChains.length} potential attack chains identified - implement defense in depth`
      )
    }

    // Common remediations
    const allRemediations = vulnerabilities.flatMap(v => v.remediation)
    const commonRemediations = this.findCommonItems(allRemediations, 3)
    
    commonRemediations.forEach(rem => {
      recommendations.push(`📋 ${rem}`)
    })

    return recommendations
  }

  /**
   * Helper methods
   */
  
  private calculateBusinessRisk(vuln: Partial<CorrelatedVulnerability>): number {
    let risk = vuln.cvss || 5.0

    // Boost for exploitability
    if (vuln.exploitAvailable) {
      risk += 2.0
    }

    if (vuln.exploitDifficulty === 'trivial' || vuln.exploitDifficulty === 'easy') {
      risk += 1.0
    }

    // Cap at 10
    return Math.min(10, risk)
  }

  private calculatePortSeverity(port: number): 'critical' | 'high' | 'medium' | 'low' {
    const criticalPorts = [22, 23, 3389, 5900] // SSH, Telnet, RDP, VNC
    const highPorts = [21, 445, 3306, 5432, 27017] // FTP, SMB, MySQL, PostgreSQL, MongoDB
    
    if (criticalPorts.includes(port)) return 'high'
    if (highPorts.includes(port)) return 'medium'
    return 'low'
  }

  private calculatePortCVSS(port: number): number {
    const criticalPorts = [22, 23, 3389, 5900]
    const highPorts = [21, 445, 3306, 5432, 27017]
    
    if (criticalPorts.includes(port)) return 7.5
    if (highPorts.includes(port)) return 5.5
    return 3.0
  }

  private mapOSVDBSeverity(osvdb: any): 'critical' | 'high' | 'medium' | 'low' {
    // Simplified mapping
    return 'medium'
  }

  private mapNucleiSeverityToCVSS(severity: string): number {
    const mapping: Record<string, number> = {
      'critical': 9.0,
      'high': 7.5,
      'medium': 5.0,
      'low': 3.0,
      'info': 0.0
    }
    return mapping[severity?.toLowerCase()] || 5.0
  }

  private calculateStringSimilarity(str1: string, str2: string): number {
    const longer = str1.length > str2.length ? str1 : str2
    const shorter = str1.length > str2.length ? str2 : str1
    
    if (longer.length === 0) return 1.0
    
    const editDistance = this.levenshteinDistance(longer, shorter)
    return (longer.length - editDistance) / longer.length
  }

  private levenshteinDistance(str1: string, str2: string): number {
    const matrix: number[][] = []
    
    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i]
    }
    
    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j
    }
    
    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1]
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          )
        }
      }
    }
    
    return matrix[str2.length][str1.length]
  }

  private findCommonItems(items: string[], minOccurrences: number): string[] {
    const counts = new Map<string, number>()
    
    items.forEach(item => {
      counts.set(item, (counts.get(item) || 0) + 1)
    })
    
    return Array.from(counts.entries())
      .filter(([_, count]) => count >= minOccurrences)
      .sort((a, b) => b[1] - a[1])
      .map(([item, _]) => item)
      .slice(0, 5)
  }

  /**
   * Get all vulnerabilities
   */
  getVulnerabilities(): CorrelatedVulnerability[] {
    return Array.from(this.vulnerabilities.values())
  }

  /**
   * Clear all data
   */
  clear(): void {
    this.vulnerabilities.clear()
    this.rawFindings.clear()
  }
}

// Singleton instance
let correlationEngineInstance: VulnerabilityCorrelationEngine | null = null

/**
 * Get correlation engine instance
 */
export function getVulnCorrelationEngine(): VulnerabilityCorrelationEngine {
  if (!correlationEngineInstance) {
    correlationEngineInstance = new VulnerabilityCorrelationEngine()
  }
  return correlationEngineInstance
}

export default VulnerabilityCorrelationEngine

