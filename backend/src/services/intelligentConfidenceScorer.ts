/**
 * Intelligent Confidence Scorer
 * Replaces random confidence scoring with intelligent analysis
 */

export interface ConfidenceFactors {
  versionMatch: number // 0-1: How well version matches
  multiToolConfirmation: number // 0-1: Multiple tools found it
  exploitAvailability: number // 0-1: Public exploit exists
  cveAge: number // 0-1: How recent the CVE is
  serviceFingerprint: number // 0-1: Service identification confidence
  verificationResult: number // 0-1: Active verification success
  contextualRelevance: number // 0-1: Relevant to target type
  falsePositiveHistory: number // 0-1: Known FP pattern
}

export interface ConfidenceScore {
  overall: number // 0-1: Final confidence
  factors: ConfidenceFactors
  reasoning: string[]
  recommendation: 'high-confidence' | 'medium-confidence' | 'low-confidence' | 'likely-false-positive'
}

export class IntelligentConfidenceScorer {
  private falsePositivePatterns: Map<string, number> = new Map()
  private historicalAccuracy: Map<string, { correct: number; total: number }> = new Map()

  /**
   * Calculate confidence score for a vulnerability finding
   */
  calculateConfidence(
    vulnerability: any,
    context: {
      service?: any
      discoveredBy?: string[]
      verificationResult?: any
      targetType?: string
      bannerInfo?: string
    }
  ): ConfidenceScore {
    const factors: ConfidenceFactors = {
      versionMatch: this.scoreVersionMatch(vulnerability, context.service, context.bannerInfo),
      multiToolConfirmation: this.scoreMultiToolConfirmation(context.discoveredBy || []),
      exploitAvailability: this.scoreExploitAvailability(vulnerability),
      cveAge: this.scoreCVEAge(vulnerability),
      serviceFingerprint: this.scoreServiceFingerprint(context.service),
      verificationResult: this.scoreVerificationResult(context.verificationResult),
      contextualRelevance: this.scoreContextualRelevance(vulnerability, context.targetType),
      falsePositiveHistory: this.scoreFalsePositiveHistory(vulnerability)
    }

    // Weighted calculation
    const weights = {
      versionMatch: 0.25,
      multiToolConfirmation: 0.15,
      exploitAvailability: 0.10,
      cveAge: 0.05,
      serviceFingerprint: 0.15,
      verificationResult: 0.20,
      contextualRelevance: 0.05,
      falsePositiveHistory: 0.05
    }

    let overall = 0
    for (const [factor, score] of Object.entries(factors)) {
      overall += score * weights[factor as keyof typeof weights]
    }

    // Generate reasoning
    const reasoning = this.generateReasoning(factors)

    // Determine recommendation
    const recommendation = this.determineRecommendation(overall, factors)

    return {
      overall: Math.max(0, Math.min(1, overall)),
      factors,
      reasoning,
      recommendation
    }
  }

  /**
   * Score version matching accuracy
   */
  private scoreVersionMatch(vuln: any, service: any, banner?: string): number {
    let score = 0.5 // Base score

    // Has exact version
    if (service?.version) {
      score += 0.2
    }

    // Version from banner
    if (banner && banner.match(/\d+\.\d+/)) {
      score += 0.1
    }

    // Version range specified in CVE
    if (vuln.versionStartIncluding || vuln.versionEndExcluding) {
      score += 0.1
    }

    // Semantic version match confirmed
    if (vuln.versionConfirmed) {
      score += 0.1
    }

    return Math.min(1, score)
  }

  /**
   * Score multi-tool confirmation
   */
  private scoreMultiToolConfirmation(discoveredBy: string[]): number {
    const toolCount = discoveredBy.length

    if (toolCount === 0) return 0.3
    if (toolCount === 1) return 0.5
    if (toolCount === 2) return 0.75
    if (toolCount >= 3) return 0.95

    return 0.5
  }

  /**
   * Score exploit availability
   */
  private scoreExploitAvailability(vuln: any): number {
    if (!vuln.exploitAvailable) return 0.3

    // Score based on exploit maturity
    const maturityScores = {
      'high': 1.0,
      'functional': 0.9,
      'proof-of-concept': 0.7,
      'unproven': 0.5
    }

    return maturityScores[vuln.exploitMaturity as keyof typeof maturityScores] || 0.6
  }

  /**
   * Score CVE age (newer = more relevant)
   */
  private scoreCVEAge(vuln: any): number {
    if (!vuln.published) return 0.5

    const publishedDate = new Date(vuln.published)
    const monthsOld = (Date.now() - publishedDate.getTime()) / (1000 * 60 * 60 * 24 * 30)

    // Newer CVEs are more likely to be accurate
    if (monthsOld < 6) return 0.9
    if (monthsOld < 12) return 0.8
    if (monthsOld < 24) return 0.7
    if (monthsOld < 36) return 0.6
    return 0.5
  }

  /**
   * Score service fingerprint accuracy
   */
  private scoreServiceFingerprint(service: any): number {
    if (!service) return 0.3

    let score = 0.5

    // Has detailed banner
    if (service.banner && service.banner.length > 20) {
      score += 0.2
    }

    // Service name identified
    if (service.service && service.service !== 'unknown') {
      score += 0.1
    }

    // Product identified
    if (service.product) {
      score += 0.1
    }

    // Version identified
    if (service.version) {
      score += 0.1
    }

    return Math.min(1, score)
  }

  /**
   * Score verification result
   */
  private scoreVerificationResult(result: any): number {
    if (!result) return 0.5

    if (result.verified) {
      return Math.min(1, 0.7 + (result.confidence || 0) * 0.3)
    }

    return 0.3
  }

  /**
   * Score contextual relevance
   */
  private scoreContextualRelevance(vuln: any, targetType?: string): number {
    if (!targetType) return 0.5

    // Web vulnerability on web target
    if (targetType === 'web' && vuln.cwe?.includes('CWE-79')) return 0.9
    if (targetType === 'web' && vuln.cwe?.includes('CWE-89')) return 0.9

    // Database vulnerability on database target
    if (targetType === 'database' && vuln.service?.includes('sql')) return 0.9

    // Network vulnerability on network target
    if (targetType === 'network' && vuln.port) return 0.8

    return 0.6
  }

  /**
   * Score based on false positive history
   */
  private scoreFalsePositiveHistory(vuln: any): number {
    const key = `${vuln.cve}:${vuln.service}:${vuln.version}`
    
    // Check if this pattern is known false positive
    const fpRate = this.falsePositivePatterns.get(key) || 0
    
    // Higher FP rate = lower confidence
    return 1 - fpRate
  }

  /**
   * Generate reasoning text
   */
  private generateReasoning(factors: ConfidenceFactors): string[] {
    const reasoning: string[] = []

    if (factors.versionMatch > 0.7) {
      reasoning.push('Strong version match with CVE affected range')
    } else if (factors.versionMatch < 0.4) {
      reasoning.push('Weak or no version match - version detection may be inaccurate')
    }

    if (factors.multiToolConfirmation > 0.8) {
      reasoning.push('Confirmed by multiple security tools')
    } else if (factors.multiToolConfirmation < 0.6) {
      reasoning.push('Single tool detection - requires additional verification')
    }

    if (factors.exploitAvailability > 0.8) {
      reasoning.push('Public exploit available - high risk')
    }

    if (factors.verificationResult > 0.7) {
      reasoning.push('Active verification successful')
    } else if (factors.verificationResult < 0.4) {
      reasoning.push('Verification failed or not performed')
    }

    if (factors.falsePositiveHistory < 0.5) {
      reasoning.push('WARNING: This pattern has high false positive rate')
    }

    if (factors.serviceFingerprint < 0.5) {
      reasoning.push('Service fingerprint unclear - may affect accuracy')
    }

    return reasoning
  }

  /**
   * Determine recommendation
   */
  private determineRecommendation(
    overall: number,
    factors: ConfidenceFactors
  ): 'high-confidence' | 'medium-confidence' | 'low-confidence' | 'likely-false-positive' {
    // Check for false positive indicators
    if (factors.falsePositiveHistory < 0.3 || 
        (factors.verificationResult < 0.3 && factors.multiToolConfirmation < 0.6)) {
      return 'likely-false-positive'
    }

    if (overall >= 0.75) return 'high-confidence'
    if (overall >= 0.55) return 'medium-confidence'
    return 'low-confidence'
  }

  /**
   * Record vulnerability outcome for learning
   */
  recordOutcome(
    vulnerability: any,
    wasActualVulnerability: boolean
  ): void {
    const key = `${vulnerability.cve}:${vulnerability.service}:${vulnerability.version}`

    // Update historical accuracy
    const history = this.historicalAccuracy.get(key) || { correct: 0, total: 0 }
    history.total++
    if (wasActualVulnerability) {
      history.correct++
    }
    this.historicalAccuracy.set(key, history)

    // Update false positive patterns
    if (!wasActualVulnerability) {
      const currentFPRate = this.falsePositivePatterns.get(key) || 0
      this.falsePositivePatterns.set(key, Math.min(1, currentFPRate + 0.1))
    }
  }

  /**
   * Get accuracy statistics
   */
  getAccuracyStats(): { totalAssessed: number; overallAccuracy: number } {
    let totalCorrect = 0
    let totalAssessed = 0

    this.historicalAccuracy.forEach(history => {
      totalCorrect += history.correct
      totalAssessed += history.total
    })

    return {
      totalAssessed,
      overallAccuracy: totalAssessed > 0 ? totalCorrect / totalAssessed : 0
    }
  }

  /**
   * Export false positive patterns
   */
  exportFalsePositivePatterns(): Record<string, number> {
    return Object.fromEntries(this.falsePositivePatterns)
  }

  /**
   * Import false positive patterns
   */
  importFalsePositivePatterns(patterns: Record<string, number>): void {
    for (const [key, rate] of Object.entries(patterns)) {
      this.falsePositivePatterns.set(key, rate)
    }
  }
}

// Singleton instance
let scorerInstance: IntelligentConfidenceScorer | null = null

export function getIntelligentConfidenceScorer(): IntelligentConfidenceScorer {
  if (!scorerInstance) {
    scorerInstance = new IntelligentConfidenceScorer()
  }
  return scorerInstance
}

