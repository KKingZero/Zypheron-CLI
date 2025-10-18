/**
 * Remediation Prioritization System
 * Intelligently prioritizes vulnerability fixes based on multiple factors
 */

export interface RemediationTask {
  id: string
  vulnerability: any
  priority: number // 0-100
  urgency: 'immediate' | 'high' | 'medium' | 'low'
  effort: 'trivial' | 'low' | 'medium' | 'high' | 'very-high'
  impact: 'critical' | 'high' | 'medium' | 'low'
  dependencies: string[]
  estimatedTime: number // hours
  resources: string[]
  steps: string[]
  cost: number // estimated cost in $
  riskReduction: number // 0-100
}

export interface PrioritizationFactors {
  cvssScore: number
  exploitability: number
  businessImpact: number
  remediationComplexity: number
  assetCriticality: number
  threatLevel: number
  compliance: number
}

export class RemediationPrioritizer {
  /**
   * Prioritize vulnerabilities for remediation
   */
  prioritizeVulnerabilities(vulnerabilities: any[]): RemediationTask[] {
    const tasks: RemediationTask[] = []

    for (const vuln of vulnerabilities) {
      const task = this.createRemediationTask(vuln)
      tasks.push(task)
    }

    // Sort by priority (highest first)
    return tasks.sort((a, b) => b.priority - a.priority)
  }

  /**
   * Create remediation task for vulnerability
   */
  private createRemediationTask(vuln: any): RemediationTask {
    const factors = this.calculateFactors(vuln)
    const priority = this.calculatePriority(factors)
    const urgency = this.determineUrgency(priority, vuln)
    const effort = this.estimateEffort(vuln)
    const impact = this.determineImpact(vuln)
    const steps = this.generateRemediationSteps(vuln)
    const resources = this.identifyRequiredResources(vuln)
    const dependencies = this.identifyDependencies(vuln)
    const estimatedTime = this.estimateTime(effort, vuln)
    const cost = this.estimateCost(effort, estimatedTime)
    const riskReduction = this.calculateRiskReduction(vuln, factors)

    return {
      id: vuln.id || vuln.cve,
      vulnerability: vuln,
      priority,
      urgency,
      effort,
      impact,
      dependencies,
      estimatedTime,
      resources,
      steps,
      cost,
      riskReduction
    }
  }

  /**
   * Calculate prioritization factors
   */
  private calculateFactors(vuln: any): PrioritizationFactors {
    // CVSS Score Factor (0-100)
    const cvssScore = (vuln.cvss || 5) * 10

    // Exploitability Factor (0-100)
    let exploitability = 50
    if (vuln.exploitAvailable) {
      const maturityScores = {
        'high': 100,
        'functional': 85,
        'proof-of-concept': 65,
        'unproven': 40
      }
      exploitability = maturityScores[vuln.exploitMaturity as keyof typeof maturityScores] || 50
    }

    // Business Impact Factor (0-100)
    const businessImpact = this.assessBusinessImpact(vuln)

    // Remediation Complexity Factor (0-100, inverted - lower complexity = higher score)
    const remediationComplexity = 100 - this.assessRemediationComplexity(vuln)

    // Asset Criticality Factor (0-100)
    const assetCriticality = this.assessAssetCriticality(vuln)

    // Threat Level Factor (0-100)
    const threatLevel = this.assessThreatLevel(vuln)

    // Compliance Factor (0-100)
    const compliance = this.assessComplianceRequirement(vuln)

    return {
      cvssScore,
      exploitability,
      businessImpact,
      remediationComplexity,
      assetCriticality,
      threatLevel,
      compliance
    }
  }

  /**
   * Calculate final priority score
   */
  private calculatePriority(factors: PrioritizationFactors): number {
    // Weighted calculation
    const weights = {
      cvssScore: 0.25,
      exploitability: 0.20,
      businessImpact: 0.15,
      remediationComplexity: 0.15,
      assetCriticality: 0.10,
      threatLevel: 0.10,
      compliance: 0.05
    }

    const priority = 
      factors.cvssScore * weights.cvssScore +
      factors.exploitability * weights.exploitability +
      factors.businessImpact * weights.businessImpact +
      factors.remediationComplexity * weights.remediationComplexity +
      factors.assetCriticality * weights.assetCriticality +
      factors.threatLevel * weights.threatLevel +
      factors.compliance * weights.compliance

    return Math.min(100, Math.max(0, priority))
  }

  /**
   * Assess business impact
   */
  private assessBusinessImpact(vuln: any): number {
    let impact = 50

    // Data confidentiality impact
    if (vuln.impact?.confidentiality === 'HIGH') impact += 20
    else if (vuln.impact?.confidentiality === 'MEDIUM') impact += 10

    // System availability impact
    if (vuln.impact?.availability === 'HIGH') impact += 15
    else if (vuln.impact?.availability === 'MEDIUM') impact += 7

    // Data integrity impact
    if (vuln.impact?.integrity === 'HIGH') impact += 15
    else if (vuln.impact?.integrity === 'MEDIUM') impact += 7

    return Math.min(100, impact)
  }

  /**
   * Assess remediation complexity
   */
  private assessRemediationComplexity(vuln: any): number {
    let complexity = 50

    // Simple patch available
    if (vuln.remediation?.some((r: string) => r.toLowerCase().includes('update') || r.toLowerCase().includes('patch'))) {
      complexity = 20
    }

    // Configuration change
    else if (vuln.remediation?.some((r: string) => r.toLowerCase().includes('configure') || r.toLowerCase().includes('disable'))) {
      complexity = 40
    }

    // Code changes required
    else if (vuln.remediation?.some((r: string) => r.toLowerCase().includes('code') || r.toLowerCase().includes('rewrite'))) {
      complexity = 80
    }

    // Architecture changes
    else if (vuln.remediation?.some((r: string) => r.toLowerCase().includes('architecture') || r.toLowerCase().includes('redesign'))) {
      complexity = 95
    }

    return complexity
  }

  /**
   * Assess asset criticality
   */
  private assessAssetCriticality(vuln: any): number {
    // Production systems
    if (vuln.target?.environment === 'production') return 90

    // Staging/pre-prod
    if (vuln.target?.environment === 'staging') return 60

    // Development
    if (vuln.target?.environment === 'development') return 30

    // External-facing
    if (vuln.target?.exposure === 'external') return 85

    return 50
  }

  /**
   * Assess active threat level
   */
  private assessThreatLevel(vuln: any): number {
    let threatLevel = 30

    // CISA KEV listed
    if (vuln.cisaKEV) threatLevel = 100

    // Known ransomware usage
    if (vuln.knownRansomwareCampaignUse) threatLevel = 95

    // Public exploit available
    if (vuln.exploitAvailable) threatLevel += 30

    // Recent CVE (< 30 days)
    if (vuln.published) {
      const daysOld = (Date.now() - new Date(vuln.published).getTime()) / (1000 * 60 * 60 * 24)
      if (daysOld < 30) threatLevel += 20
    }

    return Math.min(100, threatLevel)
  }

  /**
   * Assess compliance requirement
   */
  private assessComplianceRequirement(vuln: any): number {
    let complianceScore = 0

    // PCI-DSS requirements
    if (vuln.compliance?.includes('PCI-DSS')) complianceScore += 30

    // HIPAA requirements
    if (vuln.compliance?.includes('HIPAA')) complianceScore += 30

    // SOC 2 requirements
    if (vuln.compliance?.includes('SOC2')) complianceScore += 20

    // GDPR requirements
    if (vuln.compliance?.includes('GDPR')) complianceScore += 20

    return Math.min(100, complianceScore)
  }

  /**
   * Determine urgency level
   */
  private determineUrgency(priority: number, vuln: any): 'immediate' | 'high' | 'medium' | 'low' {
    // Immediate: Active exploitation or CISA KEV
    if (vuln.cisaKEV || vuln.knownRansomwareCampaignUse) {
      return 'immediate'
    }

    // Based on priority score
    if (priority >= 85) return 'immediate'
    if (priority >= 70) return 'high'
    if (priority >= 50) return 'medium'
    return 'low'
  }

  /**
   * Estimate remediation effort
   */
  private estimateEffort(vuln: any): 'trivial' | 'low' | 'medium' | 'high' | 'very-high' {
    const complexity = this.assessRemediationComplexity(vuln)

    if (complexity <= 20) return 'trivial'
    if (complexity <= 40) return 'low'
    if (complexity <= 60) return 'medium'
    if (complexity <= 80) return 'high'
    return 'very-high'
  }

  /**
   * Determine impact level
   */
  private determineImpact(vuln: any): 'critical' | 'high' | 'medium' | 'low' {
    const severity = vuln.severity?.toLowerCase()
    if (severity === 'critical') return 'critical'
    if (severity === 'high') return 'high'
    if (severity === 'medium') return 'medium'
    return 'low'
  }

  /**
   * Generate remediation steps
   */
  private generateRemediationSteps(vuln: any): string[] {
    const steps: string[] = []

    // Start with assessment
    steps.push('Verify vulnerability existence on target system')
    steps.push('Assess impact on production systems')

    // Add specific remediation steps from vulnerability data
    if (vuln.remediation && vuln.remediation.length > 0) {
      vuln.remediation.forEach((step: string) => {
        steps.push(step)
      })
    } else {
      // Generic steps
      steps.push('Research vendor patches and fixes')
      steps.push('Test fix in non-production environment')
      steps.push('Create rollback plan')
      steps.push('Apply fix during maintenance window')
      steps.push('Verify fix effectiveness')
    }

    // Always end with verification
    steps.push('Re-scan to confirm vulnerability is remediated')
    steps.push('Update documentation and compliance records')

    return steps
  }

  /**
   * Identify required resources
   */
  private identifyRequiredResources(vuln: any): string[] {
    const resources: string[] = []

    // Service/component specific
    if (vuln.service?.includes('web') || vuln.service?.includes('http')) {
      resources.push('Web application team')
      resources.push('Load balancer configuration access')
    }

    if (vuln.service?.includes('database')) {
      resources.push('Database administrator')
      resources.push('Backup and restore capability')
    }

    // General resources
    if (vuln.severity === 'critical' || vuln.severity === 'high') {
      resources.push('Security team approval')
      resources.push('Change management ticket')
    }

    resources.push('Testing environment')
    resources.push('Monitoring and alerting access')

    return resources
  }

  /**
   * Identify dependencies
   */
  private identifyDependencies(vuln: any): string[] {
    const dependencies: string[] = []

    // Check if other vulnerabilities should be fixed first
    // This would be populated by analyzing the full vulnerability set
    
    return dependencies
  }

  /**
   * Estimate time to remediate
   */
  private estimateTime(effort: string, vuln: any): number {
    const baseHours = {
      'trivial': 1,
      'low': 4,
      'medium': 16,
      'high': 40,
      'very-high': 80
    }

    let hours = baseHours[effort as keyof typeof baseHours] || 16

    // Add time for testing
    hours *= 1.5

    // Add time for high-criticality systems
    if (vuln.target?.criticality === 'high') {
      hours *= 1.3
    }

    return Math.ceil(hours)
  }

  /**
   * Estimate cost
   */
  private estimateCost(effort: string, hours: number): number {
    const hourlyRate = 150 // Average security engineer hourly rate

    let cost = hours * hourlyRate

    // Add overhead for coordination and management
    cost *= 1.2

    return Math.ceil(cost)
  }

  /**
   * Calculate risk reduction
   */
  private calculateRiskReduction(vuln: any, factors: PrioritizationFactors): number {
    // Risk reduction is based on the vulnerability's risk
    const baseRisk = (factors.cvssScore + factors.exploitability + factors.businessImpact) / 3

    // Multiply by likelihood of successful remediation
    const successLikelihood = factors.remediationComplexity / 100

    return baseRisk * successLikelihood
  }

  /**
   * Generate remediation roadmap
   */
  generateRoadmap(tasks: RemediationTask[]): {
    immediate: RemediationTask[]
    sprint1: RemediationTask[]
    sprint2: RemediationTask[]
    backlog: RemediationTask[]
  } {
    const roadmap = {
      immediate: tasks.filter(t => t.urgency === 'immediate'),
      sprint1: tasks.filter(t => t.urgency === 'high').slice(0, 10),
      sprint2: tasks.filter(t => t.urgency === 'medium').slice(0, 15),
      backlog: tasks.filter(t => t.urgency === 'low' || (t.urgency === 'medium' && tasks.indexOf(t) >= 15))
    }

    return roadmap
  }

  /**
   * Calculate total remediation metrics
   */
  calculateMetrics(tasks: RemediationTask[]): {
    totalTasks: number
    totalTime: number
    totalCost: number
    totalRiskReduction: number
    byUrgency: Record<string, number>
    byEffort: Record<string, number>
  } {
    return {
      totalTasks: tasks.length,
      totalTime: tasks.reduce((sum, t) => sum + t.estimatedTime, 0),
      totalCost: tasks.reduce((sum, t) => sum + t.cost, 0),
      totalRiskReduction: tasks.reduce((sum, t) => sum + t.riskReduction, 0) / tasks.length,
      byUrgency: {
        immediate: tasks.filter(t => t.urgency === 'immediate').length,
        high: tasks.filter(t => t.urgency === 'high').length,
        medium: tasks.filter(t => t.urgency === 'medium').length,
        low: tasks.filter(t => t.urgency === 'low').length
      },
      byEffort: {
        trivial: tasks.filter(t => t.effort === 'trivial').length,
        low: tasks.filter(t => t.effort === 'low').length,
        medium: tasks.filter(t => t.effort === 'medium').length,
        high: tasks.filter(t => t.effort === 'high').length,
        'very-high': tasks.filter(t => t.effort === 'very-high').length
      }
    }
  }
}

// Singleton instance
let prioritizerInstance: RemediationPrioritizer | null = null

export function getRemediationPrioritizer(): RemediationPrioritizer {
  if (!prioritizerInstance) {
    prioritizerInstance = new RemediationPrioritizer()
  }
  return prioritizerInstance
}

