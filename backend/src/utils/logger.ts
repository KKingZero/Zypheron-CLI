/**
 * Centralized Winston Logger
 * Replaces console.log with structured logging
 */
import winston from 'winston'
import path from 'path'
import config from '../services/config'

// Define log levels
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
}

// Define colors for each level
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'blue',
}

winston.addColors(colors)

// Define log format
const format = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.colorize({ all: true }),
  winston.format.printf((info) => {
    const { timestamp, level, message, ...meta } = info
    const metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : ''
    return `${timestamp} [${level}]: ${message} ${metaStr}`
  })
)

// Define transports
const transports: winston.transport[] = [
  // Console transport
  new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }),
  
  // Error log file
  new winston.transports.File({
    filename: path.join(process.cwd(), 'logs', 'error.log'),
    level: 'error',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.json()
    )
  }),
  
  // Combined log file
  new winston.transports.File({
    filename: path.join(process.cwd(), 'logs', 'combined.log'),
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.json()
    )
  }),
]

// Create logger instance
const logger = winston.createLogger({
  level: config.NODE_ENV === 'development' ? 'debug' : 'info',
  levels,
  format,
  transports,
  exitOnError: false,
})

// Create a stream for Morgan HTTP logging
export const stream = {
  write: (message: string) => {
    logger.http(message.trim())
  },
}

// Convenience methods with emojis for better visibility
export const log = {
  error: (message: string, meta?: any) => {
    logger.error(`❌ ${message}`, meta)
  },
  warn: (message: string, meta?: any) => {
    logger.warn(`⚠️  ${message}`, meta)
  },
  info: (message: string, meta?: any) => {
    logger.info(`ℹ️  ${message}`, meta)
  },
  success: (message: string, meta?: any) => {
    logger.info(`✅ ${message}`, meta)
  },
  debug: (message: string, meta?: any) => {
    logger.debug(`🔍 ${message}`, meta)
  },
  http: (message: string, meta?: any) => {
    logger.http(`🌐 ${message}`, meta)
  },
  security: (message: string, meta?: any) => {
    logger.info(`🔐 ${message}`, meta)
  },
  ai: (message: string, meta?: any) => {
    logger.info(`🤖 ${message}`, meta)
  },
  pentest: (message: string, meta?: any) => {
    logger.info(`🎯 ${message}`, meta)
  },
  database: (message: string, meta?: any) => {
    logger.debug(`💾 ${message}`, meta)
  },
}

// Export default logger
export default logger

