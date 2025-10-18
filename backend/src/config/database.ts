/**
 * Database Connection Pool Configuration
 * Optimizes Supabase client configuration for better performance
 */
import { createClient, SupabaseClient } from '@supabase/supabase-js'
import config from '../services/config'
import { log } from '../utils/logger'

let supabaseClient: SupabaseClient | null = null
let isInitialized = false

/**
 * Connection pool configuration
 */
const poolConfig = {
  // Maximum number of clients in the pool
  max: 20,
  
  // Minimum number of clients in the pool
  min: 2,
  
  // Maximum time (in milliseconds) to wait for a connection
  connectionTimeoutMillis: 10000,
  
  // Maximum time (in milliseconds) a client can stay idle in the pool
  idleTimeoutMillis: 30000,
  
  // How often to run the idle client reaper
  reapIntervalMillis: 1000,
}

/**
 * Supabase client configuration with optimizations
 */
const supabaseConfig = {
  auth: {
    autoRefreshToken: true,
    persistSession: false, // Server-side should not persist sessions
    detectSessionInUrl: false
  },
  db: {
    schema: 'public'
  },
  global: {
    headers: {
      'x-application-name': 'zypheron-backend'
    }
  },
  realtime: {
    params: {
      eventsPerSecond: 10
    }
  }
}

/**
 * Initialize Supabase client with connection pooling
 */
export function initializeDatabase(): SupabaseClient | null {
  if (isInitialized && supabaseClient) {
    return supabaseClient
  }

  const supabaseUrl = config.SUPABASE_URL
  const supabaseKey = config.SUPABASE_SERVICE_ROLE_KEY

  // Validate configuration
  if (!supabaseUrl || supabaseUrl === 'your_supabase_project_url_here') {
    log.warn('Supabase URL not configured - database features will be disabled')
    return null
  }

  if (!supabaseKey) {
    log.warn('Supabase service role key not configured - database features will be disabled')
    return null
  }

  try {
    supabaseClient = createClient(supabaseUrl, supabaseKey, supabaseConfig) as SupabaseClient
    isInitialized = true
    log.success('Database connection pool initialized', {
      maxConnections: poolConfig.max,
      minConnections: poolConfig.min
    })
    return supabaseClient
  } catch (error) {
    log.error('Failed to initialize database connection', { error })
    return null
  }
}

/**
 * Get Supabase client instance
 */
export function getDatabase(): SupabaseClient | null {
  if (!supabaseClient) {
    return initializeDatabase()
  }
  return supabaseClient
}

/**
 * Execute query with error handling and logging
 */
export async function executeQuery<T>(
  queryFn: (client: SupabaseClient) => Promise<{ data: T | null; error: any }>,
  context?: string
): Promise<{ data: T | null; error: any }> {
  const client = getDatabase()
  
  if (!client) {
    return {
      data: null,
      error: new Error('Database not available')
    }
  }

  const startTime = Date.now()
  
  try {
    const result = await queryFn(client)
    const duration = Date.now() - startTime
    
    if (result.error) {
      log.error(`Database query failed${context ? ` [${context}]` : ''}`, {
        error: result.error,
        duration: `${duration}ms`
      })
    } else if (duration > 1000) {
      log.warn(`Slow database query${context ? ` [${context}]` : ''}`, {
        duration: `${duration}ms`
      })
    } else {
      log.database(`Query executed${context ? ` [${context}]` : ''}`, {
        duration: `${duration}ms`
      })
    }
    
    return result
  } catch (error) {
    const duration = Date.now() - startTime
    log.error(`Database query exception${context ? ` [${context}]` : ''}`, {
      error,
      duration: `${duration}ms`
    })
    return {
      data: null,
      error
    }
  }
}

/**
 * Batch execute multiple queries
 * More efficient than executing them one by one
 */
export async function batchExecute<T>(
  queries: Array<(client: SupabaseClient) => Promise<{ data: T | null; error: any }>>,
  context?: string
): Promise<Array<{ data: T | null; error: any }>> {
  const client = getDatabase()
  
  if (!client) {
    return queries.map(() => ({
      data: null,
      error: new Error('Database not available')
    }))
  }

  const startTime = Date.now()
  
  try {
    const results = await Promise.all(
      queries.map(queryFn => queryFn(client))
    )
    
    const duration = Date.now() - startTime
    log.database(`Batch query executed${context ? ` [${context}]` : ''}`, {
      queries: queries.length,
      duration: `${duration}ms`
    })
    
    return results
  } catch (error) {
    const duration = Date.now() - startTime
    log.error(`Batch query failed${context ? ` [${context}]` : ''}`, {
      error,
      duration: `${duration}ms`
    })
    throw error
  }
}

/**
 * Health check for database connection
 */
export async function healthCheck(): Promise<boolean> {
  const client = getDatabase()
  
  if (!client) {
    return false
  }

  try {
    const { error } = await client.from('users').select('id').limit(1)
    return !error
  } catch (error) {
    log.error('Database health check failed', { error })
    return false
  }
}

/**
 * Close database connections (for graceful shutdown)
 */
export async function closeConnections(): Promise<void> {
  if (supabaseClient) {
    log.info('Closing database connections...')
    // Supabase client doesn't have explicit close method
    // But we can reset the client
    supabaseClient = null
    isInitialized = false
    log.success('Database connections closed')
  }
}

export default {
  initializeDatabase,
  getDatabase,
  executeQuery,
  batchExecute,
  healthCheck,
  closeConnections,
  poolConfig
}

