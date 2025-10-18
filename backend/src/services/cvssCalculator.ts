/**
 * CVSS v3.1 Calculator
 * Calculates CVSS scores according to official specification
 */

export interface CVSSv31Metrics {
  // Base Metrics
  attackVector: 'N' | 'A' | 'L' | 'P' // Network, Adjacent, Local, Physical
  attackComplexity: 'L' | 'H' // Low, High
  privilegesRequired: 'N' | 'L' | 'H' // None, Low, High
  userInteraction: 'N' | 'R' // None, Required
  scope: 'U' | 'C' // Unchanged, Changed
  confidentialityImpact: 'N' | 'L' | 'H' // None, Low, High
  integrityImpact: 'N' | 'L' | 'H'
  availabilityImpact: 'N' | 'L' | 'H'
  
  // Temporal Metrics (optional)
  exploitCodeMaturity?: 'X' | 'U' | 'P' | 'F' | 'H' // Not Defined, Unproven, Proof-of-Concept, Functional, High
  remediationLevel?: 'X' | 'O' | 'T' | 'W' | 'U' // Not Defined, Official Fix, Temporary Fix, Workaround, Unavailable
  reportConfidence?: 'X' | 'U' | 'R' | 'C' // Not Defined, Unknown, Reasonable, Confirmed
  
  // Environmental Metrics (optional)
  confidentialityRequirement?: 'X' | 'L' | 'M' | 'H' // Not Defined, Low, Medium, High
  integrityRequirement?: 'X' | 'L' | 'M' | 'H'
  availabilityRequirement?: 'X' | 'L' | 'M' | 'H'
}

export interface CVSSScore {
  baseScore: number
  baseSeverity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  temporalScore?: number
  environmentalScore?: number
  vectorString: string
  impactScore: number
  exploitabilityScore: number
}

export class CVSSCalculator {
  // Base Metric numerical values
  private readonly attackVectorValues = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }
  private readonly attackComplexityValues = { L: 0.77, H: 0.44 }
  private readonly privilegesRequiredValues = {
    U: { N: 0.85, L: 0.62, H: 0.27 }, // Unchanged scope
    C: { N: 0.85, L: 0.68, H: 0.50 }  // Changed scope
  }
  private readonly userInteractionValues = { N: 0.85, R: 0.62 }
  private readonly impactValues = { N: 0, L: 0.22, H: 0.56 }

  // Temporal Metric numerical values
  private readonly exploitCodeMaturityValues = { X: 1, U: 0.91, P: 0.94, F: 0.97, H: 1 }
  private readonly remediationLevelValues = { X: 1, O: 0.95, T: 0.96, W: 0.97, U: 1 }
  private readonly reportConfidenceValues = { X: 1, U: 0.92, R: 0.96, C: 1 }

  // Environmental Metric numerical values
  private readonly requirementValues = { X: 1, L: 0.5, M: 1, H: 1.5 }

  /**
   * Calculate CVSS v3.1 scores
   */
  calculateScore(metrics: CVSSv31Metrics): CVSSScore {
    // Calculate Base Score
    const baseScore = this.calculateBaseScore(metrics)
    const baseSeverity = this.scoreToSeverity(baseScore)
    const impactScore = this.calculateImpactScore(metrics)
    const exploitabilityScore = this.calculateExploitabilityScore(metrics)
    
    // Calculate Temporal Score
    let temporalScore: number | undefined
    if (this.hasTemporalMetrics(metrics)) {
      temporalScore = this.calculateTemporalScore(baseScore, metrics)
    }

    // Calculate Environmental Score
    let environmentalScore: number | undefined
    if (this.hasEnvironmentalMetrics(metrics)) {
      environmentalScore = this.calculateEnvironmentalScore(metrics)
    }

    // Generate vector string
    const vectorString = this.generateVectorString(metrics)

    return {
      baseScore: this.roundUp(baseScore),
      baseSeverity,
      temporalScore: temporalScore ? this.roundUp(temporalScore) : undefined,
      environmentalScore: environmentalScore ? this.roundUp(environmentalScore) : undefined,
      vectorString,
      impactScore: this.roundUp(impactScore),
      exploitabilityScore: this.roundUp(exploitabilityScore)
    }
  }

  /**
   * Calculate Base Score
   */
  private calculateBaseScore(metrics: CVSSv31Metrics): number {
    const impactScore = this.calculateImpactScore(metrics)
    const exploitabilityScore = this.calculateExploitabilityScore(metrics)

    if (impactScore <= 0) {
      return 0
    }

    if (metrics.scope === 'U') {
      return Math.min(impactScore + exploitabilityScore, 10)
    } else {
      return Math.min(1.08 * (impactScore + exploitabilityScore), 10)
    }
  }

  /**
   * Calculate Impact Score
   */
  private calculateImpactScore(metrics: CVSSv31Metrics): number {
    const confImpact = this.impactValues[metrics.confidentialityImpact]
    const integImpact = this.impactValues[metrics.integrityImpact]
    const availImpact = this.impactValues[metrics.availabilityImpact]

    const iscBase = 1 - ((1 - confImpact) * (1 - integImpact) * (1 - availImpact))

    if (metrics.scope === 'U') {
      return 6.42 * iscBase
    } else {
      return 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15)
    }
  }

  /**
   * Calculate Exploitability Score
   */
  private calculateExploitabilityScore(metrics: CVSSv31Metrics): number {
    const av = this.attackVectorValues[metrics.attackVector]
    const ac = this.attackComplexityValues[metrics.attackComplexity]
    const pr = metrics.scope === 'U' 
      ? this.privilegesRequiredValues.U[metrics.privilegesRequired]
      : this.privilegesRequiredValues.C[metrics.privilegesRequired]
    const ui = this.userInteractionValues[metrics.userInteraction]

    return 8.22 * av * ac * pr * ui
  }

  /**
   * Calculate Temporal Score
   */
  private calculateTemporalScore(baseScore: number, metrics: CVSSv31Metrics): number {
    const e = this.exploitCodeMaturityValues[metrics.exploitCodeMaturity || 'X']
    const rl = this.remediationLevelValues[metrics.remediationLevel || 'X']
    const rc = this.reportConfidenceValues[metrics.reportConfidence || 'X']

    return baseScore * e * rl * rc
  }

  /**
   * Calculate Environmental Score
   */
  private calculateEnvironmentalScore(metrics: CVSSv31Metrics): number {
    // Calculate modified impact
    const cr = this.requirementValues[metrics.confidentialityRequirement || 'X']
    const ir = this.requirementValues[metrics.integrityRequirement || 'X']
    const ar = this.requirementValues[metrics.availabilityRequirement || 'X']

    const confImpact = this.impactValues[metrics.confidentialityImpact]
    const integImpact = this.impactValues[metrics.integrityImpact]
    const availImpact = this.impactValues[metrics.availabilityImpact]

    const modifiedIscBase = Math.min(
      1 - ((1 - cr * confImpact) * (1 - ir * integImpact) * (1 - ar * availImpact)),
      0.915
    )

    const modifiedImpact = metrics.scope === 'U'
      ? 6.42 * modifiedIscBase
      : 7.52 * (modifiedIscBase - 0.029) - 3.25 * Math.pow(modifiedIscBase - 0.02, 15)

    const exploitabilityScore = this.calculateExploitabilityScore(metrics)

    const modifiedBase = modifiedImpact + exploitabilityScore

    // Apply temporal metrics
    const e = this.exploitCodeMaturityValues[metrics.exploitCodeMaturity || 'X']
    const rl = this.remediationLevelValues[metrics.remediationLevel || 'X']
    const rc = this.reportConfidenceValues[metrics.reportConfidence || 'X']

    if (modifiedImpact <= 0) {
      return 0
    }

    if (metrics.scope === 'U') {
      return this.roundUp(this.roundUp(Math.min(modifiedBase, 10)) * e * rl * rc)
    } else {
      return this.roundUp(this.roundUp(Math.min(1.08 * modifiedBase, 10)) * e * rl * rc)
    }
  }

  /**
   * Generate CVSS vector string
   */
  private generateVectorString(metrics: CVSSv31Metrics): string {
    let vector = 'CVSS:3.1'
    
    // Base metrics (required)
    vector += `/AV:${metrics.attackVector}`
    vector += `/AC:${metrics.attackComplexity}`
    vector += `/PR:${metrics.privilegesRequired}`
    vector += `/UI:${metrics.userInteraction}`
    vector += `/S:${metrics.scope}`
    vector += `/C:${metrics.confidentialityImpact}`
    vector += `/I:${metrics.integrityImpact}`
    vector += `/A:${metrics.availabilityImpact}`

    // Temporal metrics (optional)
    if (metrics.exploitCodeMaturity && metrics.exploitCodeMaturity !== 'X') {
      vector += `/E:${metrics.exploitCodeMaturity}`
    }
    if (metrics.remediationLevel && metrics.remediationLevel !== 'X') {
      vector += `/RL:${metrics.remediationLevel}`
    }
    if (metrics.reportConfidence && metrics.reportConfidence !== 'X') {
      vector += `/RC:${metrics.reportConfidence}`
    }

    // Environmental metrics (optional)
    if (metrics.confidentialityRequirement && metrics.confidentialityRequirement !== 'X') {
      vector += `/CR:${metrics.confidentialityRequirement}`
    }
    if (metrics.integrityRequirement && metrics.integrityRequirement !== 'X') {
      vector += `/IR:${metrics.integrityRequirement}`
    }
    if (metrics.availabilityRequirement && metrics.availabilityRequirement !== 'X') {
      vector += `/AR:${metrics.availabilityRequirement}`
    }

    return vector
  }

  /**
   * Parse CVSS vector string
   */
  parseVectorString(vectorString: string): CVSSv31Metrics | null {
    try {
      const parts = vectorString.split('/')
      
      if (parts[0] !== 'CVSS:3.1' && parts[0] !== 'CVSS:3.0') {
        return null
      }

      const metrics: any = {}

      for (let i = 1; i < parts.length; i++) {
        const [key, value] = parts[i].split(':')
        
        switch (key) {
          case 'AV': metrics.attackVector = value; break
          case 'AC': metrics.attackComplexity = value; break
          case 'PR': metrics.privilegesRequired = value; break
          case 'UI': metrics.userInteraction = value; break
          case 'S': metrics.scope = value; break
          case 'C': metrics.confidentialityImpact = value; break
          case 'I': metrics.integrityImpact = value; break
          case 'A': metrics.availabilityImpact = value; break
          case 'E': metrics.exploitCodeMaturity = value; break
          case 'RL': metrics.remediationLevel = value; break
          case 'RC': metrics.reportConfidence = value; break
          case 'CR': metrics.confidentialityRequirement = value; break
          case 'IR': metrics.integrityRequirement = value; break
          case 'AR': metrics.availabilityRequirement = value; break
        }
      }

      return metrics as CVSSv31Metrics
    } catch (error) {
      console.error('Error parsing CVSS vector:', error)
      return null
    }
  }

  /**
   * Convert score to severity rating
   */
  private scoreToSeverity(score: number): 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    if (score === 0) return 'NONE'
    if (score < 4.0) return 'LOW'
    if (score < 7.0) return 'MEDIUM'
    if (score < 9.0) return 'HIGH'
    return 'CRITICAL'
  }

  /**
   * Round up to one decimal place
   */
  private roundUp(value: number): number {
    return Math.ceil(value * 10) / 10
  }

  /**
   * Check if temporal metrics are defined
   */
  private hasTemporalMetrics(metrics: CVSSv31Metrics): boolean {
    return !!(
      (metrics.exploitCodeMaturity && metrics.exploitCodeMaturity !== 'X') ||
      (metrics.remediationLevel && metrics.remediationLevel !== 'X') ||
      (metrics.reportConfidence && metrics.reportConfidence !== 'X')
    )
  }

  /**
   * Check if environmental metrics are defined
   */
  private hasEnvironmentalMetrics(metrics: CVSSv31Metrics): boolean {
    return !!(
      (metrics.confidentialityRequirement && metrics.confidentialityRequirement !== 'X') ||
      (metrics.integrityRequirement && metrics.integrityRequirement !== 'X') ||
      (metrics.availabilityRequirement && metrics.availabilityRequirement !== 'X')
    )
  }
}

// Singleton instance
let calculatorInstance: CVSSCalculator | null = null

export function getCVSSCalculator(): CVSSCalculator {
  if (!calculatorInstance) {
    calculatorInstance = new CVSSCalculator()
  }
  return calculatorInstance
}

