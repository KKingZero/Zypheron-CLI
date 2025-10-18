/**
 * Error Sanitizer Utility
 * Prevents information disclosure by sanitizing error messages
 * Never expose internal implementation details, stack traces, or system paths
 */

export interface SanitizedError {
  message: string
  statusCode: number
  logMessage?: string // Full error for logging only
}

/**
 * Sanitize error for client response
 * Removes sensitive information while providing helpful feedback
 */
export function sanitizeError(error: any, context?: string): SanitizedError {
  // Default safe error message
  let message = 'An unexpected error occurred. Please try again.'
  let statusCode = 500
  let logMessage = error?.stack || error?.message || String(error)

  // Check for common error types
  if (error?.name === 'ValidationError') {
    message = 'Invalid input provided. Please check your request and try again.'
    statusCode = 400
  } else if (error?.name === 'UnauthorizedError' || error?.status === 401) {
    message = 'Authentication required. Please sign in and try again.'
    statusCode = 401
  } else if (error?.name === 'ForbiddenError' || error?.status === 403) {
    message = 'Access denied. You do not have permission to perform this action.'
    statusCode = 403
  } else if (error?.name === 'NotFoundError' || error?.status === 404) {
    message = 'The requested resource was not found.'
    statusCode = 404
  } else if (error?.status === 429) {
    message = 'Too many requests. Please wait a moment and try again.'
    statusCode = 429
  } else if (error?.code === 'ECONNREFUSED') {
    message = 'Service temporarily unavailable. Please try again later.'
    statusCode = 503
  } else if (error?.code === 'ETIMEDOUT' || error?.code === 'ESOCKETTIMEDOUT') {
    message = 'Request timeout. Please try again.'
    statusCode = 504
  } else if (error?.message) {
    // Check if error message is safe to expose
    const msg = error.message.toLowerCase()
    const unsafeKeywords = [
      'stack', 'at ', 'node_modules', 'file://', 'line ', 
      'column ', 'errno', 'syscall', 'path:', 'code:', 
      'internal', 'database', 'sql', 'query', 'connection',
      'api key', 'token', 'secret', 'password', 'credentials'
    ]
    
    const isSafe = !unsafeKeywords.some(keyword => msg.includes(keyword))
    
    if (isSafe && error.message.length < 150) {
      message = error.message
    }
  }

  // Add context if provided
  if (context) {
    logMessage = `[${context}] ${logMessage}`
  }

  return {
    message,
    statusCode,
    logMessage
  }
}

/**
 * Express error handler middleware
 */
export function errorHandler(err: any, req: any, res: any, next: any) {
  const sanitized = sanitizeError(err, req.path)
  
  // Log the full error for debugging
  console.error('Error:', sanitized.logMessage)
  
  // Send sanitized error to client
  res.status(sanitized.statusCode).json({
    error: true,
    message: sanitized.message,
    requestId: req.id || 'unknown'
  })
}

/**
 * Async error wrapper for route handlers
 */
export function asyncHandler(fn: Function) {
  return (req: any, res: any, next: any) => {
    Promise.resolve(fn(req, res, next)).catch(next)
  }
}

/**
 * Safe error logging
 */
export function logError(error: any, context?: string) {
  const sanitized = sanitizeError(error, context)
  console.error('Error Log:', {
    message: sanitized.message,
    context,
    timestamp: new Date().toISOString(),
    fullError: sanitized.logMessage
  })
}

export default {
  sanitizeError,
  errorHandler,
  asyncHandler,
  logError
}

