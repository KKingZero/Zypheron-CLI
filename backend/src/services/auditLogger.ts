/**
 * Comprehensive Audit Logging System
 * Tracks all penetration testing activities for compliance and forensics
 * Implements structured logging with Winston
 */

import winston from 'winston'
import * as path from 'path'
import * as fs from 'fs'

export interface AuditEvent {
  eventType: 'tool_execution' | 'session_start' | 'session_end' | 'authorization_check' | 'security_alert' | 'user_action'
  userId: string
  username?: string
  toolName?: string
  target?: string
  parameters?: any
  result?: 'success' | 'failure' | 'timeout' | 'error'
  severity?: 'low' | 'medium' | 'high' | 'critical'
  timestamp: string
  ipAddress?: string
  userAgent?: string
  sessionId?: string
  duration?: number
  errorMessage?: string
  complianceNote?: string
}

export interface ComplianceReport {
  reportId: string
  generatedAt: string
  timeRange: { start: string; end: string }
  totalEvents: number
  eventsByType: Record<string, number>
  eventsBySeverity: Record<string, number>
  userActivity: Array<{ userId: string; eventCount: number; tools: string[] }>
  securityAlerts: AuditEvent[]
  recommendations: string[]
}

class AuditLogger {
  private logger: winston.Logger
  private readonly logsDir: string
  private eventCache: AuditEvent[] = []
  private readonly maxCacheSize = 1000

  constructor(logsDir: string = path.join(process.cwd(), 'logs', 'audit')) {
    this.logsDir = logsDir
    this.ensureLogsDirExists()
    this.initializeLogger()
  }

  /**
   * Ensure logs directory exists
   */
  private ensureLogsDirExists() {
    if (!fs.existsSync(this.logsDir)) {
      fs.mkdirSync(this.logsDir, { recursive: true, mode: 0o700 })
    }
  }

  /**
   * Initialize Winston logger with multiple transports
   */
  private initializeLogger() {
    const logFormat = winston.format.combine(
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
      winston.format.errors({ stack: true }),
      winston.format.json()
    )

    this.logger = winston.createLogger({
      level: 'info',
      format: logFormat,
      defaultMeta: { service: 'zypheron-pentest' },
      transports: [
        // Write all logs to combined.log
        new winston.transports.File({
          filename: path.join(this.logsDir, 'combined.log'),
          maxsize: 10485760, // 10MB
          maxFiles: 10,
          tailable: true
        }),
        
        // Write security alerts to separate file
        new winston.transports.File({
          filename: path.join(this.logsDir, 'security-alerts.log'),
          level: 'warn',
          maxsize: 10485760,
          maxFiles: 10
        }),
        
        // Write audit trail to dedicated file
        new winston.transports.File({
          filename: path.join(this.logsDir, 'audit-trail.log'),
          maxsize: 52428800, // 50MB
          maxFiles: 50, // Keep 50 files for compliance
          tailable: true
        }),
        
        // Console output for development
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          ),
          level: process.env.NODE_ENV === 'production' ? 'error' : 'info'
        })
      ]
    })
  }

  /**
   * Log tool execution
   */
  async logToolExecution(event: Omit<AuditEvent, 'eventType' | 'timestamp'>): Promise<void> {
    const auditEvent: AuditEvent = {
      eventType: 'tool_execution',
      timestamp: new Date().toISOString(),
      ...event
    }

    this.logger.info('Tool Execution', auditEvent)
    this.addToCache(auditEvent)
  }

  /**
   * Log session events
   */
  async logSession(type: 'start' | 'end', event: Omit<AuditEvent, 'eventType' | 'timestamp'>): Promise<void> {
    const auditEvent: AuditEvent = {
      eventType: type === 'start' ? 'session_start' : 'session_end',
      timestamp: new Date().toISOString(),
      ...event
    }

    this.logger.info(`Session ${type === 'start' ? 'Started' : 'Ended'}`, auditEvent)
    this.addToCache(auditEvent)
  }

  /**
   * Log authorization checks
   */
  async logAuthorizationCheck(event: Omit<AuditEvent, 'eventType' | 'timestamp'>): Promise<void> {
    const auditEvent: AuditEvent = {
      eventType: 'authorization_check',
      timestamp: new Date().toISOString(),
      ...event
    }

    if (event.result === 'failure') {
      this.logger.warn('Authorization Failed', auditEvent)
    } else {
      this.logger.info('Authorization Check', auditEvent)
    }

    this.addToCache(auditEvent)
  }

  /**
   * Log security alerts
   */
  async logSecurityAlert(event: Omit<AuditEvent, 'eventType' | 'timestamp'>): Promise<void> {
    const auditEvent: AuditEvent = {
      eventType: 'security_alert',
      timestamp: new Date().toISOString(),
      severity: event.severity || 'high',
      ...event
    }

    this.logger.warn('Security Alert', auditEvent)
    this.addToCache(auditEvent)

    // Immediate notification for critical alerts
    if (event.severity === 'critical') {
      this.triggerCriticalAlertNotification(auditEvent)
    }
  }

  /**
   * Log user actions
   */
  async logUserAction(event: Omit<AuditEvent, 'eventType' | 'timestamp'>): Promise<void> {
    const auditEvent: AuditEvent = {
      eventType: 'user_action',
      timestamp: new Date().toISOString(),
      ...event
    }

    this.logger.info('User Action', auditEvent)
    this.addToCache(auditEvent)
  }

  /**
   * Add event to in-memory cache for quick queries
   */
  private addToCache(event: AuditEvent) {
    this.eventCache.push(event)
    
    // Trim cache if too large
    if (this.eventCache.length > this.maxCacheSize) {
      this.eventCache = this.eventCache.slice(-this.maxCacheSize)
    }
  }

  /**
   * Generate compliance report
   */
  async generateComplianceReport(startDate: Date, endDate: Date): Promise<ComplianceReport> {
    // Filter events by date range
    const events = this.eventCache.filter(e => {
      const eventDate = new Date(e.timestamp)
      return eventDate >= startDate && eventDate <= endDate
    })

    // Analyze events
    const eventsByType: Record<string, number> = {}
    const eventsBySeverity: Record<string, number> = {}
    const userActivity: Map<string, { eventCount: number; tools: Set<string> }> = new Map()
    const securityAlerts: AuditEvent[] = []

    for (const event of events) {
      // Count by type
      eventsByType[event.eventType] = (eventsByType[event.eventType] || 0) + 1

      // Count by severity
      if (event.severity) {
        eventsBySeverity[event.severity] = (eventsBySeverity[event.severity] || 0) + 1
      }

      // Track user activity
      if (event.userId) {
        const userStats = userActivity.get(event.userId) || { eventCount: 0, tools: new Set<string>() }
        userStats.eventCount++
        if (event.toolName) {
          userStats.tools.add(event.toolName)
        }
        userActivity.set(event.userId, userStats)
      }

      // Collect security alerts
      if (event.eventType === 'security_alert') {
        securityAlerts.push(event)
      }
    }

    // Generate recommendations
    const recommendations: string[] = []
    
    if (securityAlerts.length > 10) {
      recommendations.push('High number of security alerts detected. Review security policies.')
    }

    if (eventsBySeverity.critical && eventsBySeverity.critical > 0) {
      recommendations.push(`${eventsBySeverity.critical} critical events require immediate attention.`)
    }

    // Check for unauthorized tool usage patterns
    const toolExecutions = events.filter(e => e.eventType === 'tool_execution')
    const failedExecutions = toolExecutions.filter(e => e.result === 'failure' || e.result === 'error')
    
    if (failedExecutions.length / toolExecutions.length > 0.3) {
      recommendations.push('High failure rate detected. Review tool configurations and permissions.')
    }

    const report: ComplianceReport = {
      reportId: `report-${Date.now()}`,
      generatedAt: new Date().toISOString(),
      timeRange: {
        start: startDate.toISOString(),
        end: endDate.toISOString()
      },
      totalEvents: events.length,
      eventsByType,
      eventsBySeverity,
      userActivity: Array.from(userActivity.entries()).map(([userId, stats]) => ({
        userId,
        eventCount: stats.eventCount,
        tools: Array.from(stats.tools)
      })),
      securityAlerts,
      recommendations
    }

    // Write report to file
    const reportPath = path.join(this.logsDir, 'compliance-reports', `${report.reportId}.json`)
    const reportDir = path.dirname(reportPath)
    
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true, mode: 0o700 })
    }

    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2), { mode: 0o600 })

    return report
  }

  /**
   * Query audit logs
   */
  async queryLogs(filters: Partial<AuditEvent>): Promise<AuditEvent[]> {
    return this.eventCache.filter(event => {
      for (const [key, value] of Object.entries(filters)) {
        if (value !== undefined && event[key as keyof AuditEvent] !== value) {
          return false
        }
      }
      return true
    })
  }

  /**
   * Get recent events
   */
  async getRecentEvents(limit: number = 100): Promise<AuditEvent[]> {
    return this.eventCache.slice(-limit)
  }

  /**
   * Trigger critical alert notification
   */
  private triggerCriticalAlertNotification(event: AuditEvent) {
    // Log to console immediately
    console.error('🚨 CRITICAL SECURITY ALERT:', {
      userId: event.userId,
      toolName: event.toolName,
      target: event.target,
      message: event.errorMessage,
      timestamp: event.timestamp
    })

    // In production, this would:
    // - Send email to security team
    // - Trigger PagerDuty/Slack notifications
    // - Write to SIEM system
    // - Create incident ticket
  }

  /**
   * Export logs to JSON for external systems
   */
  async exportLogsToJson(startDate: Date, endDate: Date, outputPath: string): Promise<void> {
    const events = this.eventCache.filter(e => {
      const eventDate = new Date(e.timestamp)
      return eventDate >= startDate && eventDate <= endDate
    })

    fs.writeFileSync(outputPath, JSON.stringify(events, null, 2), { mode: 0o600 })
    
    this.logger.info('Logs exported', {
      eventCount: events.length,
      outputPath,
      timeRange: { start: startDate.toISOString(), end: endDate.toISOString() }
    })
  }

  /**
   * Get logger instance for custom logging
   */
  getLogger(): winston.Logger {
    return this.logger
  }

  /**
   * Cleanup old logs
   */
  async cleanupOldLogs(daysToKeep: number = 90): Promise<void> {
    // This is handled by Winston's maxFiles configuration
    // But we can add additional cleanup logic here if needed
    this.logger.info('Log cleanup initiated', { daysToKeep })
  }
}

// Singleton instance
let auditLoggerInstance: AuditLogger | null = null

/**
 * Get audit logger instance
 */
export function getAuditLogger(logsDir?: string): AuditLogger {
  if (!auditLoggerInstance) {
    auditLoggerInstance = new AuditLogger(logsDir)
  }
  return auditLoggerInstance
}

export default AuditLogger

