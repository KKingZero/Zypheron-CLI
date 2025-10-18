/**
 * Production-Safe Logger Utility
 * Automatically strips logs in production builds
 */

import { isDevelopment } from '../config/api.config'

type LogLevel = 'log' | 'warn' | 'error' | 'debug' | 'info'

class Logger {
  private isDev: boolean

  constructor() {
    this.isDev = isDevelopment()
  }

  /**
   * Log general information (only in development)
   */
  log(...args: any[]): void {
    if (this.isDev) {
      console.log(...args)
    }
  }

  /**
   * Log debug information (only in development)
   */
  debug(...args: any[]): void {
    if (this.isDev) {
      console.debug(...args)
    }
  }

  /**
   * Log informational messages (only in development)
   */
  info(...args: any[]): void {
    if (this.isDev) {
      console.info(...args)
    }
  }

  /**
   * Log warnings (always logged, but sent to monitoring in production)
   */
  warn(...args: any[]): void {
    if (this.isDev) {
      console.warn(...args)
    } else {
      // TODO: Send to error monitoring service (Sentry, etc.)
      this.sendToMonitoring('warn', args)
    }
  }

  /**
   * Log errors (always logged, sent to monitoring in production)
   */
  error(...args: any[]): void {
    if (this.isDev) {
      console.error(...args)
    } else {
      // TODO: Send to error monitoring service (Sentry, etc.)
      this.sendToMonitoring('error', args)
    }
  }

  /**
   * Log with timestamp prefix
   */
  timestamped(level: LogLevel, ...args: any[]): void {
    const timestamp = new Date().toISOString()
    this[level](`[${timestamp}]`, ...args)
  }

  /**
   * Log performance metrics
   */
  perf(label: string, startTime: number): void {
    if (this.isDev) {
      const duration = performance.now() - startTime
      console.log(`⚡ ${label}: ${duration.toFixed(2)}ms`)
    }
  }

  /**
   * Group logs (only in development)
   */
  group(label: string): void {
    if (this.isDev) {
      console.group(label)
    }
  }

  /**
   * End log group
   */
  groupEnd(): void {
    if (this.isDev) {
      console.groupEnd()
    }
  }

  /**
   * Send logs to monitoring service in production
   * @private
   */
  private sendToMonitoring(level: string, args: any[]): void {
    // TODO: Implement actual error monitoring service integration
    // Example: Sentry.captureMessage(args.join(' '), level)
    
    // For now, store critical errors in localStorage for later analysis
    try {
      const errorLog = {
        timestamp: new Date().toISOString(),
        level,
        message: args.map(arg => 
          typeof arg === 'object' ? JSON.stringify(arg) : String(arg)
        ).join(' ')
      }
      
      const existingLogs = localStorage.getItem('app-error-logs')
      const logs = existingLogs ? JSON.parse(existingLogs) : []
      logs.push(errorLog)
      
      // Keep only last 50 errors
      if (logs.length > 50) {
        logs.shift()
      }
      
      localStorage.setItem('app-error-logs', JSON.stringify(logs))
    } catch (e) {
      // Silently fail - don't break the app due to logging issues
    }
  }
}

// Export singleton instance
export const logger = new Logger()

// Export for use as drop-in replacement
export default logger

/**
 * Usage Examples:
 * 
 * // Instead of console.log()
 * logger.log('User logged in:', user)
 * 
 * // Instead of console.error()
 * logger.error('API request failed:', error)
 * 
 * // Performance logging
 * const start = performance.now()
 * // ... some operation
 * logger.perf('Data fetch', start)
 * 
 * // Grouped logs
 * logger.group('User Actions')
 * logger.log('Action 1')
 * logger.log('Action 2')
 * logger.groupEnd()
 */

