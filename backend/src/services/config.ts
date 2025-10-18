// Centralized configuration with validation
import dotenv from 'dotenv'
dotenv.config({ path: '.env' })

// Helper function to get environment variable with default
const getEnv = (key: string, defaultValue: string = ''): string => {
  return process.env[key] || defaultValue
}

// Helper function to get required environment variable (throws if missing)
const getRequiredEnv = (key: string): string => {
  const value = process.env[key]
  if (!value) {
    throw new Error(`Required environment variable ${key} is not set`)
  }
  return value
}

// Helper function to get numeric environment variable
const getNumericEnv = (key: string, defaultValue: number): number => {
  const value = process.env[key]
  if (!value) return defaultValue
  const parsed = parseInt(value, 10)
  return isNaN(parsed) ? defaultValue : parsed
}

// Helper function to get boolean environment variable
const getBooleanEnv = (key: string, defaultValue: boolean): boolean => {
  const value = process.env[key]
  if (!value) return defaultValue
  return value.toLowerCase() === 'true'
}

// Application configuration
export const config = {
  // Server configuration
  PORT: getNumericEnv('PORT', 3001),
  NODE_ENV: getEnv('NODE_ENV', 'development'),
  
  // Database configuration
  SUPABASE_URL: getEnv('SUPABASE_URL', ''),
  SUPABASE_ANON_KEY: getEnv('SUPABASE_ANON_KEY', ''),
  SUPABASE_SERVICE_ROLE_KEY: getEnv('SUPABASE_SERVICE_ROLE_KEY', ''),
  
  // Redis configuration
  REDIS_URL: getEnv('REDIS_URL', 'redis://localhost:6379'),
  
  // AI API Keys
  OPENAI_API_KEY: getEnv('OPENAI_API_KEY', ''),
  GEMINI_API_KEY: getEnv('GEMINI_API_KEY', '') || getEnv('GOOGLE_API_KEY', ''),
  XAI_API_KEY: getEnv('XAI_API_KEY', ''),
  MOONSHOT_API_KEY: getEnv('MOONSHOT_API_KEY', ''),
  ANTHROPIC_API_KEY: getEnv('ANTHROPIC_API_KEY', ''),
  
  // Security configuration
  JWT_SECRET: getEnv('JWT_SECRET', 'development-secret-change-in-production'),
  JWT_EXTENDED_SECRET: getEnv('JWT_EXTENDED_SECRET', 'extended-dev-secret-change-in-production'),
  
  // Email configuration
  SMTP_HOST: getEnv('SMTP_HOST', ''),
  SMTP_PORT: getNumericEnv('SMTP_PORT', 587),
  SMTP_USER: getEnv('SMTP_USER', ''),
  SMTP_PASS: getEnv('SMTP_PASS', ''),
  EMAIL_FROM: getEnv('EMAIL_FROM', 'noreply@zypheron.com'),
  
  // Stripe configuration
  STRIPE_SECRET_KEY: getEnv('STRIPE_SECRET_KEY', ''),
  STRIPE_PUBLISHABLE_KEY: getEnv('STRIPE_PUBLISHABLE_KEY', ''),
  STRIPE_WEBHOOK_SECRET: getEnv('STRIPE_WEBHOOK_SECRET', ''),
  
  // Feature flags
  ENABLE_AI_DEFENSE: getBooleanEnv('ENABLE_AI_DEFENSE', true),
  ENABLE_AGENT_MODE: getBooleanEnv('ENABLE_AGENT_MODE', true),
  ENABLE_DOCKER_TOOLS: getBooleanEnv('ENABLE_DOCKER_TOOLS', false),
  
  // Rate limiting
  RATE_LIMIT_WINDOW_MS: getNumericEnv('RATE_LIMIT_WINDOW_MS', 60000),
  RATE_LIMIT_MAX_REQUESTS: getNumericEnv('RATE_LIMIT_MAX_REQUESTS', 100),
} as const

// Validation function
export const validateConfig = (): { valid: boolean; errors: string[] } => {
  const errors: string[] = []
  
  // Warn about missing optional configurations
  if (!config.SUPABASE_URL || config.SUPABASE_URL === 'your_supabase_project_url_here') {
    errors.push('SUPABASE_URL is not configured')
  }
  
  if (!config.SUPABASE_SERVICE_ROLE_KEY) {
    errors.push('SUPABASE_SERVICE_ROLE_KEY is not configured')
  }
  
  if (config.NODE_ENV === 'production' && config.JWT_SECRET === 'development-secret-change-in-production') {
    errors.push('JWT_SECRET must be changed in production')
  }
  
  return {
    valid: errors.length === 0,
    errors
  }
}

export const hasKey = (key: keyof typeof config): boolean => {
  const value = config[key]
  return typeof value === 'string' && value.length > 0
}

// Export for convenience
export default config


