/**
 * Command Injection Prevention Middleware
 * Implements whitelist-based validation and sanitization for all security tool executions
 * Critical Security Component - Prevents arbitrary command execution
 */

import { Request, Response, NextFunction } from 'express'
import validator from 'validator'

// Whitelist of allowed security tools
const ALLOWED_TOOLS = [
  'nmap', 'nikto', 'sqlmap', 'metasploit', 'john', 'aircrack-ng',
  'wireshark', 'ettercap', 'burpsuite', 'gobuster', 'nuclei',
  'maltego', 'shodan', 'recon-ng', 'sn1per', 'nessus',
  'setoolkit', 'binwalk', 'radare2', 'faraday', 'dradis',
  'hydra', 'hashcat', 'masscan', 'zap', 'dirb'
]

// Whitelist of allowed tool parameters (no shell metacharacters)
const SAFE_PARAM_PATTERN = /^[a-zA-Z0-9._\-/:@]+$/

// Dangerous shell metacharacters
const DANGEROUS_CHARS = /[;&|`$(){}[\]<>\\'"!*?~#]/

/**
 * Validates tool name against whitelist
 */
export function isValidToolName(toolName: string): boolean {
  if (!toolName || typeof toolName !== 'string') {
    return false
  }
  
  const normalized = toolName.toLowerCase().trim()
  return ALLOWED_TOOLS.includes(normalized)
}

/**
 * Sanitizes command parameters to prevent injection
 */
export function sanitizeParameters(params: any): { valid: boolean; sanitized: any; errors: string[] } {
  const errors: string[] = []
  const sanitized: any = {}
  
  if (!params || typeof params !== 'object') {
    return { valid: false, sanitized: null, errors: ['Invalid parameters object'] }
  }

  for (const [key, value] of Object.entries(params)) {
    // Skip null/undefined
    if (value === null || value === undefined) {
      continue
    }

    // Handle different types
    if (typeof value === 'string') {
      // Check for dangerous characters
      if (DANGEROUS_CHARS.test(value)) {
        errors.push(`Parameter '${key}' contains dangerous characters`)
        continue
      }

      // Validate URLs separately
      if (key.toLowerCase().includes('url') || key.toLowerCase().includes('target')) {
        if (!isValidTarget(value)) {
          errors.push(`Parameter '${key}' contains invalid URL/target`)
          continue
        }
      }

      sanitized[key] = value.trim()
    } 
    else if (typeof value === 'number') {
      // Numbers are safe
      sanitized[key] = value
    }
    else if (typeof value === 'boolean') {
      // Booleans are safe
      sanitized[key] = value
    }
    else if (Array.isArray(value)) {
      // Validate array elements
      const sanitizedArray: any[] = []
      for (const item of value) {
        if (typeof item === 'string') {
          if (DANGEROUS_CHARS.test(item)) {
            errors.push(`Array parameter '${key}' contains dangerous characters`)
            break
          }
          sanitizedArray.push(item.trim())
        } else if (typeof item === 'number' || typeof item === 'boolean') {
          sanitizedArray.push(item)
        }
      }
      if (sanitizedArray.length === value.length) {
        sanitized[key] = sanitizedArray
      }
    }
    else if (typeof value === 'object') {
      // Recursively sanitize nested objects
      const nested = sanitizeParameters(value)
      if (nested.valid) {
        sanitized[key] = nested.sanitized
      } else {
        errors.push(...nested.errors.map(e => `${key}.${e}`))
      }
    }
  }

  return {
    valid: errors.length === 0,
    sanitized,
    errors
  }
}

/**
 * Validates target URLs/IPs/domains
 */
export function isValidTarget(target: string): boolean {
  if (!target || typeof target !== 'string') {
    return false
  }

  const trimmed = target.trim()

  // Check for URL
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    try {
      const url = new URL(trimmed)
      // Prevent file:// and other dangerous protocols
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        return false
      }
      return validator.isURL(trimmed, {
        protocols: ['http', 'https'],
        require_protocol: true,
        require_valid_protocol: true
      })
    } catch {
      return false
    }
  }

  // Check for IP address
  if (validator.isIP(trimmed, '4') || validator.isIP(trimmed, '6')) {
    // Prevent localhost/internal IPs without explicit authorization
    if (trimmed.startsWith('127.') || trimmed.startsWith('0.') || 
        trimmed === 'localhost' || trimmed.startsWith('10.') ||
        trimmed.startsWith('192.168.') || 
        (trimmed.startsWith('172.') && parseInt(trimmed.split('.')[1]) >= 16 && parseInt(trimmed.split('.')[1]) <= 31)) {
      // Internal IP - should have explicit authorization flag
      return false // Strict: block by default
    }
    return true
  }

  // Check for domain name
  if (validator.isFQDN(trimmed)) {
    return true
  }

  return false
}

/**
 * Rate limiting per tool per user
 */
const toolRateLimits = new Map<string, Map<string, { count: number; resetTime: number }>>()

export function checkRateLimit(userId: string, toolName: string, maxRequests: number = 10, windowMs: number = 60000): boolean {
  const now = Date.now()
  
  if (!toolRateLimits.has(toolName)) {
    toolRateLimits.set(toolName, new Map())
  }

  const toolLimits = toolRateLimits.get(toolName)!
  const userLimit = toolLimits.get(userId)

  if (!userLimit || now > userLimit.resetTime) {
    toolLimits.set(userId, {
      count: 1,
      resetTime: now + windowMs
    })
    return true
  }

  if (userLimit.count >= maxRequests) {
    return false
  }

  userLimit.count++
  return true
}

/**
 * Express middleware for command sanitization
 */
export function commandSanitizerMiddleware(req: Request, res: Response, next: NextFunction) {
  // Extract tool execution parameters from different endpoints
  const toolName = req.body.toolName || req.body.tool || req.params.tool
  const parameters = req.body.parameters || req.body.params || req.body

  // Skip if no tool execution detected
  if (!toolName) {
    return next()
  }

  // Validate tool name
  if (!isValidToolName(toolName)) {
    return res.status(400).json({
      error: 'Invalid Tool',
      message: `Tool '${toolName}' is not in the allowed whitelist`,
      allowedTools: ALLOWED_TOOLS
    })
  }

  // Sanitize parameters
  const sanitizationResult = sanitizeParameters(parameters)
  if (!sanitizationResult.valid) {
    return res.status(400).json({
      error: 'Invalid Parameters',
      message: 'Command parameters contain dangerous characters or invalid values',
      details: sanitizationResult.errors
    })
  }

  // Check rate limit
  const userId = (req as any).user?.id || (req as any).user?.sub || 'anonymous'
  if (!checkRateLimit(userId, toolName)) {
    return res.status(429).json({
      error: 'Rate Limit Exceeded',
      message: `Too many requests for tool '${toolName}'. Please try again later.`
    })
  }

  // Attach sanitized parameters to request
  req.body.sanitizedParams = sanitizationResult.sanitized
  req.body.validatedTool = toolName

  next()
}

export default commandSanitizerMiddleware

