/**
 * Intelligent Priority Queue
 * Smart job prioritization based on multiple factors
 */

import Bull, { Queue, Job } from 'bull'
import { EventEmitter } from 'events'

export interface JobPriority {
  critical: number // 0-100: Criticality score
  urgency: number // 0-100: Time sensitivity
  impact: number // 0-100: Potential impact
  exploitability: number // 0-100: How exploitable
  businessValue: number // 0-100: Business importance
}

export interface PrioritizedJob {
  id: string
  type: string
  data: any
  priority: JobPriority
  finalScore: number
  estimatedDuration: number
  dependencies: string[]
  userId: string
}

export class IntelligentPriorityQueue extends EventEmitter {
  private queue: Queue
  private jobs: Map<string, PrioritizedJob> = new Map()
  private completedJobs: Set<string> = new Set()

  constructor(redisUrl: string = 'redis://localhost:6379') {
    super()
    
    this.queue = new Bull('pentest-intelligent-queue', redisUrl, {
      settings: {
        stalledInterval: 30000,
        maxStalledCount: 3
      }
    })

    this.setupEventHandlers()
    console.log('🧠 Intelligent Priority Queue initialized')
  }

  /**
   * Setup event handlers
   */
  private setupEventHandlers() {
    this.queue.on('completed', (job: Job) => {
      this.completedJobs.add(job.id.toString())
      this.emit('job-completed', job.id, job.returnvalue)
      
      // Check if any dependent jobs can now run
      this.processDependentJobs(job.id.toString())
    })

    this.queue.on('failed', (job: Job, error: Error) => {
      this.emit('job-failed', job.id, error)
    })

    this.queue.on('active', (job: Job) => {
      this.emit('job-started', job.id)
    })
  }

  /**
   * Add job with intelligent prioritization
   */
  async addJob(jobData: {
    type: string
    data: any
    userId: string
    vulnerability?: any
    target?: any
    estimatedDuration?: number
    dependencies?: string[]
  }): Promise<string> {
    // Calculate priority
    const priority = this.calculatePriority(jobData)
    
    // Calculate final priority score
    const finalScore = this.calculateFinalScore(priority)

    const prioritizedJob: PrioritizedJob = {
      id: `job-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type: jobData.type,
      data: jobData.data,
      priority,
      finalScore,
      estimatedDuration: jobData.estimatedDuration || 60000,
      dependencies: jobData.dependencies || [],
      userId: jobData.userId
    }

    // Store job metadata
    this.jobs.set(prioritizedJob.id, prioritizedJob)

    // Add to Bull queue with calculated priority
    // Bull uses priority 1-10, we scale our 0-100 score
    const bullPriority = Math.ceil(finalScore / 10)

    const job = await this.queue.add(
      prioritizedJob.type,
      {
        ...prioritizedJob.data,
        jobId: prioritizedJob.id,
        userId: prioritizedJob.userId
      },
      {
        priority: 10 - bullPriority, // Bull: lower number = higher priority
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 2000
        },
        timeout: prioritizedJob.estimatedDuration * 2
      }
    )

    console.log(`📋 Job ${prioritizedJob.id} queued with priority ${finalScore.toFixed(2)}`)

    return prioritizedJob.id
  }

  /**
   * Calculate priority factors
   */
  private calculatePriority(jobData: any): JobPriority {
    const vulnerability = jobData.vulnerability
    const target = jobData.target

    // Critical factors
    let critical = 50
    if (vulnerability) {
      // CVSS score influence
      if (vulnerability.cvss) {
        critical = (vulnerability.cvss / 10) * 100
      }

      // Severity influence
      const severityScores = {
        'critical': 95,
        'high': 80,
        'medium': 50,
        'low': 25
      }
      critical = Math.max(critical, severityScores[vulnerability.severity as keyof typeof severityScores] || 50)
    }

    // Urgency factors
    let urgency = 50
    if (vulnerability?.exploitAvailable) {
      urgency += 30
    }
    if (vulnerability?.exploitMaturity === 'high') {
      urgency += 20
    }
    if (this.isActivelyExploitedInWild(vulnerability)) {
      urgency = 100
    }

    // Impact factors
    let impact = 50
    if (vulnerability) {
      const impactScores = {
        'HIGH': 100,
        'MEDIUM': 60,
        'LOW': 30,
        'NONE': 0
      }

      const avgImpact = (
        (impactScores[vulnerability.impact?.confidentiality as keyof typeof impactScores] || 50) +
        (impactScores[vulnerability.impact?.integrity as keyof typeof impactScores] || 50) +
        (impactScores[vulnerability.impact?.availability as keyof typeof impactScores] || 50)
      ) / 3

      impact = avgImpact
    }

    // Exploitability factors
    let exploitability = 50
    if (vulnerability?.exploitAvailable) {
      exploitability = 80

      const maturityScores = {
        'high': 100,
        'functional': 85,
        'proof-of-concept': 60,
        'unproven': 30
      }
      exploitability = maturityScores[vulnerability.exploitMaturity as keyof typeof maturityScores] || 50
    }

    if (vulnerability?.attackComplexity === 'LOW') {
      exploitability = Math.min(100, exploitability + 10)
    }

    // Business value factors
    let businessValue = 50
    if (target) {
      // Production systems = higher priority
      if (target.environment === 'production') {
        businessValue = 90
      } else if (target.environment === 'staging') {
        businessValue = 60
      } else if (target.environment === 'development') {
        businessValue = 30
      }

      // Internet-facing = higher priority
      if (target.exposure === 'external') {
        businessValue = Math.min(100, businessValue + 20)
      }

      // Critical services = higher priority
      if (target.criticality === 'high') {
        businessValue = Math.min(100, businessValue + 10)
      }
    }

    return {
      critical: Math.min(100, Math.max(0, critical)),
      urgency: Math.min(100, Math.max(0, urgency)),
      impact: Math.min(100, Math.max(0, impact)),
      exploitability: Math.min(100, Math.max(0, exploitability)),
      businessValue: Math.min(100, Math.max(0, businessValue))
    }
  }

  /**
   * Calculate final priority score
   */
  private calculateFinalScore(priority: JobPriority): number {
    // Weighted scoring
    const weights = {
      critical: 0.30,
      urgency: 0.25,
      impact: 0.20,
      exploitability: 0.15,
      businessValue: 0.10
    }

    const score = 
      priority.critical * weights.critical +
      priority.urgency * weights.urgency +
      priority.impact * weights.impact +
      priority.exploitability * weights.exploitability +
      priority.businessValue * weights.businessValue

    return Math.min(100, Math.max(0, score))
  }

  /**
   * Check if vulnerability is actively exploited
   */
  private isActivelyExploitedInWild(vulnerability: any): boolean {
    if (!vulnerability) return false

    // Check for CISA KEV listing
    if (vulnerability.cisaKEV) return true

    // Check for ransomware campaigns
    if (vulnerability.knownRansomwareCampaignUse) return true

    // Check references for active exploitation mentions
    if (vulnerability.references) {
      const activeKeywords = ['active', 'wild', 'exploitation', 'ransomware', 'apt']
      return vulnerability.references.some((ref: string) => 
        activeKeywords.some(keyword => ref.toLowerCase().includes(keyword))
      )
    }

    return false
  }

  /**
   * Process dependent jobs
   */
  private async processDependentJobs(completedJobId: string) {
    // Find jobs waiting for this dependency
    for (const [jobId, job] of this.jobs.entries()) {
      if (job.dependencies.includes(completedJobId)) {
        // Check if all dependencies are complete
        const allDepsComplete = job.dependencies.every(depId => 
          this.completedJobs.has(depId)
        )

        if (allDepsComplete) {
          console.log(`✅ All dependencies complete for job ${jobId}, promoting priority`)
          
          // Increase priority
          job.finalScore = Math.min(100, job.finalScore + 20)
          
          // Reschedule with higher priority
          await this.reprioritizeJob(jobId, job.finalScore)
        }
      }
    }
  }

  /**
   * Reprioritize existing job
   */
  private async reprioritizeJob(jobId: string, newScore: number) {
    const job = this.jobs.get(jobId)
    if (!job) return

    job.finalScore = newScore

    // Update Bull job priority
    const bullJobs = await this.queue.getJobs(['waiting', 'delayed'])
    const bullJob = bullJobs.find(j => j.data.jobId === jobId)
    
    if (bullJob) {
      const newBullPriority = 10 - Math.ceil(newScore / 10)
      await bullJob.changePriority({ priority: newBullPriority })
      console.log(`🔄 Job ${jobId} reprioritized to ${newScore.toFixed(2)}`)
    }
  }

  /**
   * Get queue statistics
   */
  async getStatistics() {
    const waiting = await this.queue.getWaitingCount()
    const active = await this.queue.getActiveCount()
    const completed = await this.queue.getCompletedCount()
    const failed = await this.queue.getFailedCount()
    const delayed = await this.queue.getDelayedCount()

    // Calculate average priority of waiting jobs
    const waitingJobs = await this.queue.getWaiting()
    const avgPriority = waitingJobs.length > 0
      ? waitingJobs.reduce((sum, j) => sum + (j.opts.priority || 5), 0) / waitingJobs.length
      : 0

    return {
      waiting,
      active,
      completed,
      failed,
      delayed,
      total: waiting + active + completed + failed + delayed,
      averagePriority: avgPriority,
      jobsInMemory: this.jobs.size
    }
  }

  /**
   * Get job details
   */
  getJobDetails(jobId: string): PrioritizedJob | null {
    return this.jobs.get(jobId) || null
  }

  /**
   * Get high priority jobs
   */
  getHighPriorityJobs(threshold: number = 75): PrioritizedJob[] {
    return Array.from(this.jobs.values())
      .filter(job => job.finalScore >= threshold)
      .sort((a, b) => b.finalScore - a.finalScore)
  }

  /**
   * Pause queue
   */
  async pause(): Promise<void> {
    await this.queue.pause()
    console.log('⏸️  Queue paused')
  }

  /**
   * Resume queue
   */
  async resume(): Promise<void> {
    await this.queue.resume()
    console.log('▶️  Queue resumed')
  }

  /**
   * Clear completed jobs
   */
  async clearCompleted(): Promise<void> {
    await this.queue.clean(0, 'completed')
    this.completedJobs.clear()
    console.log('🧹 Completed jobs cleared')
  }

  /**
   * Shutdown queue
   */
  async shutdown(): Promise<void> {
    await this.queue.close()
    console.log('🛑 Queue shutdown')
  }
}

// Singleton instance
let queueInstance: IntelligentPriorityQueue | null = null

export function getIntelligentPriorityQueue(redisUrl?: string): IntelligentPriorityQueue {
  if (!queueInstance) {
    queueInstance = new IntelligentPriorityQueue(redisUrl)
  }
  return queueInstance
}

