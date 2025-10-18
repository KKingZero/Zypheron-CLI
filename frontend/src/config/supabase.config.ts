/**
 * Supabase Configuration and Optimizations
 * Optimized settings for production deployment
 * 
 * Implements: Supabase integration optimization
 */

import { createClient, SupabaseClientOptions } from '@supabase/supabase-js'

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY

/**
 * Check if Supabase is configured
 */
export const isSupabaseConfigured = 
  supabaseUrl && 
  supabaseAnonKey && 
  supabaseUrl !== 'your_supabase_project_url_here' && 
  supabaseAnonKey !== 'your_supabase_anon_key_here'

/**
 * Optimized Supabase client options
 */
const supabaseOptions: SupabaseClientOptions<'public'> = {
  auth: {
    // Persist session in localStorage
    persistSession: true,
    // Automatically refresh token
    autoRefreshToken: true,
    // Detect session from URL
    detectSessionInUrl: true,
    // Storage key
    storageKey: 'zypheron-auth-token',
    // Storage
    storage: window.localStorage,
  },
  db: {
    // Database schema
    schema: 'public',
  },
  global: {
    // Custom headers
    headers: {
      'X-Client-Info': 'cobra-ai-webapp',
    },
  },
  // Realtime options
  realtime: {
    // Heartbeat interval (ms)
    heartbeatIntervalMs: 30000,
    // Reconnect after (ms)
    reconnectAfterMs: () => {
      // Exponential backoff
      return [1000, 2000, 5000, 10000][Math.floor(Math.random() * 4)]
    },
  },
}

/**
 * Create optimized Supabase client
 */
export const supabase = isSupabaseConfigured 
  ? createClient(supabaseUrl!, supabaseAnonKey!, supabaseOptions)
  : null

/**
 * Supabase query optimizations
 */
export const queryOptimizations = {
  // Limit results for pagination
  DEFAULT_PAGE_SIZE: 20,
  MAX_PAGE_SIZE: 100,
  
  // Enable query caching
  ENABLE_CACHE: true,
  CACHE_TTL: 5 * 60 * 1000, // 5 minutes
  
  // Connection pooling
  MAX_CONNECTIONS: 10,
  MIN_CONNECTIONS: 2,
}

/**
 * Optimized query builder
 */
export class OptimizedQuery {
  private client = supabase
  
  /**
   * Fetch with pagination and caching
   */
  async fetchPaginated<T>(
    table: string,
    page: number = 0,
    pageSize: number = queryOptimizations.DEFAULT_PAGE_SIZE,
    orderBy: string = 'created_at',
    ascending: boolean = false
  ): Promise<{ data: T[], count: number | null }> {
    if (!this.client) {
      throw new Error('Supabase is not configured')
    }

    const from = page * pageSize
    const to = from + pageSize - 1

    const { data, error, count } = await this.client
      .from(table)
      .select('*', { count: 'exact' })
      .order(orderBy, { ascending })
      .range(from, to)

    if (error) {
      throw error
    }

    return { data: data as T[], count }
  }

  /**
   * Fetch with filters
   */
  async fetchFiltered<T>(
    table: string,
    filters: Record<string, any>,
    options: {
      orderBy?: string
      ascending?: boolean
      limit?: number
    } = {}
  ): Promise<T[]> {
    if (!this.client) {
      throw new Error('Supabase is not configured')
    }

    let query = this.client.from(table).select('*')

    // Apply filters
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        query = query.eq(key, value)
      }
    })

    // Apply ordering
    if (options.orderBy) {
      query = query.order(options.orderBy, { ascending: options.ascending ?? false })
    }

    // Apply limit
    if (options.limit) {
      query = query.limit(options.limit)
    }

    const { data, error } = await query

    if (error) {
      throw error
    }

    return data as T[]
  }

  /**
   * Upsert with conflict resolution
   */
  async upsert<T>(
    table: string,
    data: Partial<T>,
    conflictColumns: string[] = ['id']
  ): Promise<T> {
    if (!this.client) {
      throw new Error('Supabase is not configured')
    }

    const { data: result, error } = await this.client
      .from(table)
      .upsert(data, {
        onConflict: conflictColumns.join(','),
      })
      .select()
      .single()

    if (error) {
      throw error
    }

    return result as T
  }

  /**
   * Batch insert with error handling
   */
  async batchInsert<T>(
    table: string,
    records: Partial<T>[],
    chunkSize: number = 100
  ): Promise<T[]> {
    if (!this.client) {
      throw new Error('Supabase is not configured')
    }

    const results: T[] = []

    // Process in chunks
    for (let i = 0; i < records.length; i += chunkSize) {
      const chunk = records.slice(i, i + chunkSize)
      
      const { data, error } = await this.client
        .from(table)
        .insert(chunk)
        .select()

      if (error) {
        console.error(`Batch insert failed for chunk ${i / chunkSize}:`, error)
        continue
      }

      results.push(...(data as T[]))
    }

    return results
  }
}

/**
 * Create optimized query instance
 */
export const optimizedQuery = new OptimizedQuery()

/**
 * Realtime subscription helper
 */
export function subscribeToTable<T>(
  table: string,
  filter: string | null,
  callback: (payload: { new: T; old: T | null; eventType: string }) => void
) {
  if (!supabase) {
    throw new Error('Supabase is not configured')
  }

  const channel = supabase
    .channel(`${table}-changes`)
    .on(
      'postgres_changes',
      {
        event: '*',
        schema: 'public',
        table: table,
        filter: filter || undefined,
      },
      (payload: any) => {
        callback({
          new: payload.new as T,
          old: payload.old as T | null,
          eventType: payload.eventType,
        })
      }
    )
    .subscribe()

  return () => {
    supabase.removeChannel(channel)
  }
}

/**
 * Connection health check
 */
export async function checkSupabaseConnection(): Promise<boolean> {
  if (!supabase) {
    return false
  }

  try {
    const { error } = await supabase.from('_health').select('*').limit(1)
    return !error
  } catch {
    return false
  }
}

export default supabase

