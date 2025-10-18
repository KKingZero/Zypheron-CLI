/**
 * AI Orchestrator Learning System
 * Learns from pentest results and adapts strategies
 */

import { EventEmitter } from 'events'
import * as fs from 'fs'
import * as path from 'path'

export interface PentestOutcome {
  sessionId: string
  target: string
  strategy: string
  toolsUsed: string[]
  vulnerabilitiesFound: number
  falsePositives: number
  duration: number
  success: boolean
  failures: string[]
  timestamp: Date
}

export interface StrategyEffectiveness {
  strategyName: string
  successRate: number
  avgVulnerabilitiesFound: number
  avgFalsePositiveRate: number
  avgDuration: number
  timesUsed: number
  targetTypes: Map<string, number> // target type -> success count
}

export interface LearningInsights {
  mostEffectiveStrategy: string
  leastEffectiveStrategy: string
  bestToolCombinations: string[][]
  commonFailures: Map<string, number>
  targetSpecificStrategies: Map<string, string>
  avgSuccessRate: number
  totalSessions: number
}

export class AIOrchestratorLearning extends EventEmitter {
  private outcomes: PentestOutcome[] = []
  private strategyStats: Map<string, StrategyEffectiveness> = new Map()
  private toolEffectiveness: Map<string, { success: number; total: number }> = new Map()
  private failurePatterns: Map<string, number> = new Map()
  private dataPath: string

  constructor(dataPath?: string) {
    super()
    this.dataPath = dataPath || path.join(__dirname, '../../data/learning')
    this.ensureDataDirectory()
    this.loadLearningData()
    console.log('🧠 AI Orchestrator Learning System initialized')
  }

  /**
   * Ensure data directory exists
   */
  private ensureDataDirectory() {
    if (!fs.existsSync(this.dataPath)) {
      fs.mkdirSync(this.dataPath, { recursive: true })
    }
  }

  /**
   * Record pentest outcome
   */
  recordOutcome(outcome: PentestOutcome): void {
    this.outcomes.push(outcome)

    // Update strategy statistics
    this.updateStrategyStats(outcome)

    // Update tool effectiveness
    this.updateToolEffectiveness(outcome)

    // Update failure patterns
    this.updateFailurePatterns(outcome)

    // Emit learning event
    this.emit('outcome-recorded', outcome)

    // Auto-save every 10 outcomes
    if (this.outcomes.length % 10 === 0) {
      this.saveLearningData()
    }

    console.log(`📝 Recorded outcome for session ${outcome.sessionId}`)
  }

  /**
   * Update strategy statistics
   */
  private updateStrategyStats(outcome: PentestOutcome) {
    let stats = this.strategyStats.get(outcome.strategy)

    if (!stats) {
      stats = {
        strategyName: outcome.strategy,
        successRate: 0,
        avgVulnerabilitiesFound: 0,
        avgFalsePositiveRate: 0,
        avgDuration: 0,
        timesUsed: 0,
        targetTypes: new Map()
      }
      this.strategyStats.set(outcome.strategy, stats)
    }

    // Update cumulative averages
    const n = stats.timesUsed
    stats.successRate = (stats.successRate * n + (outcome.success ? 1 : 0)) / (n + 1)
    stats.avgVulnerabilitiesFound = (stats.avgVulnerabilitiesFound * n + outcome.vulnerabilitiesFound) / (n + 1)
    stats.avgFalsePositiveRate = (stats.avgFalsePositiveRate * n + outcome.falsePositives) / (n + 1)
    stats.avgDuration = (stats.avgDuration * n + outcome.duration) / (n + 1)
    stats.timesUsed++

    // Track target type effectiveness
    const targetType = this.inferTargetType(outcome.target)
    const currentCount = stats.targetTypes.get(targetType) || 0
    stats.targetTypes.set(targetType, currentCount + (outcome.success ? 1 : 0))
  }

  /**
   * Update tool effectiveness
   */
  private updateToolEffectiveness(outcome: PentestOutcome) {
    for (const tool of outcome.toolsUsed) {
      let stats = this.toolEffectiveness.get(tool)
      
      if (!stats) {
        stats = { success: 0, total: 0 }
        this.toolEffectiveness.set(tool, stats)
      }

      stats.total++
      if (outcome.success) {
        stats.success++
      }
    }
  }

  /**
   * Update failure patterns
   */
  private updateFailurePatterns(outcome: PentestOutcome) {
    if (!outcome.success) {
      for (const failure of outcome.failures) {
        const count = this.failurePatterns.get(failure) || 0
        this.failurePatterns.set(failure, count + 1)
      }
    }
  }

  /**
   * Get recommended strategy for target
   */
  getRecommendedStrategy(target: string, targetType?: string): string {
    const type = targetType || this.inferTargetType(target)

    // Find strategy with best success rate for this target type
    let bestStrategy: string | null = null
    let bestScore = -1

    for (const [strategyName, stats] of this.strategyStats.entries()) {
      const typeSuccesses = stats.targetTypes.get(type) || 0
      const typeAttempts = stats.timesUsed
      
      // Calculate score: success rate * confidence (based on sample size)
      const confidence = Math.min(1, typeAttempts / 10) // Max confidence at 10+ attempts
      const score = (typeSuccesses / Math.max(1, typeAttempts)) * confidence

      if (score > bestScore) {
        bestScore = score
        bestStrategy = strategyName
      }
    }

    // Fallback to most successful strategy overall
    if (!bestStrategy) {
      bestStrategy = this.getMostEffectiveStrategy()
    }

    return bestStrategy || 'balanced' // Ultimate fallback
  }

  /**
   * Get recommended tools for target
   */
  getRecommendedTools(target: string, maxTools: number = 5): string[] {
    const targetType = this.inferTargetType(target)

    // Calculate tool scores based on effectiveness and target type
    const toolScores: Map<string, number> = new Map()

    for (const [tool, stats] of this.toolEffectiveness.entries()) {
      const successRate = stats.success / Math.max(1, stats.total)
      const confidence = Math.min(1, stats.total / 10)
      const score = successRate * confidence

      toolScores.set(tool, score)
    }

    // Sort by score and return top N
    return Array.from(toolScores.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, maxTools)
      .map(([tool]) => tool)
  }

  /**
   * Get learning insights
   */
  getLearningInsights(): LearningInsights {
    const insights: LearningInsights = {
      mostEffectiveStrategy: this.getMostEffectiveStrategy(),
      leastEffectiveStrategy: this.getLeastEffectiveStrategy(),
      bestToolCombinations: this.getBestToolCombinations(),
      commonFailures: this.failurePatterns,
      targetSpecificStrategies: this.getTargetSpecificStrategies(),
      avgSuccessRate: this.calculateOverallSuccessRate(),
      totalSessions: this.outcomes.length
    }

    return insights
  }

  /**
   * Get most effective strategy
   */
  private getMostEffectiveStrategy(): string {
    let bestStrategy = 'balanced'
    let bestScore = 0

    for (const [name, stats] of this.strategyStats.entries()) {
      // Weight success rate by sample size
      const confidence = Math.min(1, stats.timesUsed / 10)
      const score = stats.successRate * confidence

      if (score > bestScore) {
        bestScore = score
        bestStrategy = name
      }
    }

    return bestStrategy
  }

  /**
   * Get least effective strategy
   */
  private getLeastEffectiveStrategy(): string {
    let worstStrategy = 'aggressive'
    let worstScore = 1

    for (const [name, stats] of this.strategyStats.entries()) {
      if (stats.timesUsed >= 5) { // Only consider strategies with enough data
        if (stats.successRate < worstScore) {
          worstScore = stats.successRate
          worstStrategy = name
        }
      }
    }

    return worstStrategy
  }

  /**
   * Get best tool combinations
   */
  private getBestToolCombinations(): string[][] {
    // Analyze which tools are frequently used together in successful pentests
    const combinations: Map<string, { success: number; total: number }> = new Map()

    for (const outcome of this.outcomes) {
      if (outcome.toolsUsed.length >= 2) {
        const combo = outcome.toolsUsed.sort().join(',')
        const stats = combinations.get(combo) || { success: 0, total: 0 }
        stats.total++
        if (outcome.success) stats.success++
        combinations.set(combo, stats)
      }
    }

    // Get top 3 combinations by success rate
    return Array.from(combinations.entries())
      .filter(([_, stats]) => stats.total >= 3) // Min 3 uses
      .sort((a, b) => (b[1].success / b[1].total) - (a[1].success / a[1].total))
      .slice(0, 3)
      .map(([combo]) => combo.split(','))
  }

  /**
   * Get target-specific strategies
   */
  private getTargetSpecificStrategies(): Map<string, string> {
    const strategies: Map<string, string> = new Map()

    const targetTypes = ['web', 'api', 'network', 'database', 'cloud']

    for (const type of targetTypes) {
      let bestStrategy = 'balanced'
      let bestScore = 0

      for (const [strategyName, stats] of this.strategyStats.entries()) {
        const typeSuccesses = stats.targetTypes.get(type) || 0
        const typeAttempts = Array.from(stats.targetTypes.values()).reduce((sum, count) => sum + count, 0)
        
        if (typeAttempts > 0) {
          const score = typeSuccesses / typeAttempts
          if (score > bestScore) {
            bestScore = score
            bestStrategy = strategyName
          }
        }
      }

      strategies.set(type, bestStrategy)
    }

    return strategies
  }

  /**
   * Calculate overall success rate
   */
  private calculateOverallSuccessRate(): number {
    if (this.outcomes.length === 0) return 0
    const successes = this.outcomes.filter(o => o.success).length
    return successes / this.outcomes.length
  }

  /**
   * Infer target type from URL/hostname
   */
  private inferTargetType(target: string): string {
    const targetLower = target.toLowerCase()

    if (targetLower.includes('api') || targetLower.includes('rest') || targetLower.includes('graphql')) {
      return 'api'
    }

    if (targetLower.match(/\.(com|org|net|io|dev)/)) {
      return 'web'
    }

    if (targetLower.includes('db') || targetLower.includes('mysql') || targetLower.includes('postgres')) {
      return 'database'
    }

    if (targetLower.includes('aws') || targetLower.includes('azure') || targetLower.includes('gcp')) {
      return 'cloud'
    }

    if (/^\d+\.\d+\.\d+\.\d+$/.test(target)) {
      return 'network'
    }

    return 'web' // Default
  }

  /**
   * Save learning data to disk
   */
  private saveLearningData(): void {
    try {
      const data = {
        outcomes: this.outcomes.map(o => ({
          ...o,
          timestamp: o.timestamp.toISOString()
        })),
        strategyStats: Array.from(this.strategyStats.entries()).map(([name, stats]) => ({
          name,
          ...stats,
          targetTypes: Array.from(stats.targetTypes.entries())
        })),
        toolEffectiveness: Array.from(this.toolEffectiveness.entries()),
        failurePatterns: Array.from(this.failurePatterns.entries())
      }

      const filePath = path.join(this.dataPath, 'learning-data.json')
      fs.writeFileSync(filePath, JSON.stringify(data, null, 2))
      console.log('💾 Learning data saved')
    } catch (error) {
      console.error('Failed to save learning data:', error)
    }
  }

  /**
   * Load learning data from disk
   */
  private loadLearningData(): void {
    try {
      const filePath = path.join(this.dataPath, 'learning-data.json')
      
      if (fs.existsSync(filePath)) {
        const data = JSON.parse(fs.readFileSync(filePath, 'utf8'))

        this.outcomes = data.outcomes.map((o: any) => ({
          ...o,
          timestamp: new Date(o.timestamp)
        }))

        this.strategyStats = new Map(
          data.strategyStats.map((s: any) => [
            s.name,
            {
              ...s,
              targetTypes: new Map(s.targetTypes)
            }
          ])
        )

        this.toolEffectiveness = new Map(data.toolEffectiveness)
        this.failurePatterns = new Map(data.failurePatterns)

        console.log(`📚 Loaded ${this.outcomes.length} historical outcomes`)
      }
    } catch (error) {
      console.error('Failed to load learning data:', error)
    }
  }

  /**
   * Export learning data
   */
  exportData(): any {
    return {
      outcomes: this.outcomes,
      strategyStats: Object.fromEntries(this.strategyStats),
      toolEffectiveness: Object.fromEntries(this.toolEffectiveness),
      failurePatterns: Object.fromEntries(this.failurePatterns),
      insights: this.getLearningInsights()
    }
  }

  /**
   * Clear all learning data
   */
  clearData(): void {
    this.outcomes = []
    this.strategyStats.clear()
    this.toolEffectiveness.clear()
    this.failurePatterns.clear()
    this.saveLearningData()
    console.log('🗑️  Learning data cleared')
  }
}

// Singleton instance
let learningInstance: AIOrchestratorLearning | null = null

export function getAIOrchestratorLearning(dataPath?: string): AIOrchestratorLearning {
  if (!learningInstance) {
    learningInstance = new AIOrchestratorLearning(dataPath)
  }
  return learningInstance
}

