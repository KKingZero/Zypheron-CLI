/**
 * Request Queue Manager
 * Manages concurrent API requests to prevent race conditions
 * 
 * Fixes: HIGH PRIORITY #5 - Race Conditions in Message State
 */

interface QueuedRequest<T> {
  id: string
  execute: () => Promise<T>
  resolve: (value: T) => void
  reject: (reason: any) => void
  timestamp: number
  priority: number
}

/**
 * Request Queue with priority support
 * Ensures requests are processed in order and prevents concurrent execution
 */
class RequestQueue {
  private queue: QueuedRequest<any>[] = []
  private isProcessing: boolean = false
  private concurrentLimit: number
  private activeRequests: number = 0
  private requestMap: Map<string, QueuedRequest<any>> = new Map()

  constructor(concurrentLimit: number = 1) {
    this.concurrentLimit = concurrentLimit
  }

  /**
   * Add request to queue
   */
  async enqueue<T>(
    execute: () => Promise<T>,
    options: { id?: string; priority?: number } = {}
  ): Promise<T> {
    const requestId = options.id || `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    const priority = options.priority || 0

    // Check if request with same ID is already queued
    if (options.id && this.requestMap.has(options.id)) {
      console.warn(`Request with ID ${options.id} is already in queue`)
      const existingRequest = this.requestMap.get(options.id)!
      return new Promise((resolve, reject) => {
        existingRequest.resolve = resolve
        existingRequest.reject = reject
      })
    }

    return new Promise<T>((resolve, reject) => {
      const request: QueuedRequest<T> = {
        id: requestId,
        execute,
        resolve,
        reject,
        timestamp: Date.now(),
        priority,
      }

      this.queue.push(request)
      this.requestMap.set(requestId, request)

      // Sort by priority (higher priority first) and timestamp (older first)
      this.queue.sort((a, b) => {
        if (a.priority !== b.priority) {
          return b.priority - a.priority
        }
        return a.timestamp - b.timestamp
      })

      this.processQueue()
    })
  }

  /**
   * Process queued requests
   */
  private async processQueue(): Promise<void> {
    if (this.isProcessing || this.activeRequests >= this.concurrentLimit || this.queue.length === 0) {
      return
    }

    this.isProcessing = true

    while (this.queue.length > 0 && this.activeRequests < this.concurrentLimit) {
      const request = this.queue.shift()
      if (!request) break

      this.activeRequests++
      this.executeRequest(request)
    }

    this.isProcessing = false
  }

  /**
   * Execute a single request
   */
  private async executeRequest<T>(request: QueuedRequest<T>): Promise<void> {
    try {
      const result = await request.execute()
      request.resolve(result)
    } catch (error) {
      request.reject(error)
    } finally {
      this.activeRequests--
      this.requestMap.delete(request.id)
      this.processQueue()
    }
  }

  /**
   * Cancel a specific request by ID
   */
  cancel(id: string): boolean {
    const index = this.queue.findIndex(req => req.id === id)
    if (index !== -1) {
      const request = this.queue[index]
      this.queue.splice(index, 1)
      this.requestMap.delete(id)
      request.reject(new Error('Request cancelled'))
      return true
    }
    return false
  }

  /**
   * Cancel all pending requests
   */
  cancelAll(): void {
    while (this.queue.length > 0) {
      const request = this.queue.shift()
      if (request) {
        this.requestMap.delete(request.id)
        request.reject(new Error('Request cancelled'))
      }
    }
  }

  /**
   * Get queue status
   */
  getStatus(): {
    queuedRequests: number
    activeRequests: number
    totalRequests: number
  } {
    return {
      queuedRequests: this.queue.length,
      activeRequests: this.activeRequests,
      totalRequests: this.queue.length + this.activeRequests,
    }
  }

  /**
   * Check if queue is empty
   */
  isEmpty(): boolean {
    return this.queue.length === 0 && this.activeRequests === 0
  }

  /**
   * Wait for all requests to complete
   */
  async waitForAll(): Promise<void> {
    return new Promise<void>((resolve) => {
      const checkInterval = setInterval(() => {
        if (this.isEmpty()) {
          clearInterval(checkInterval)
          resolve()
        }
      }, 100)
    })
  }
}

/**
 * Global request queue instances
 */
export const chatRequestQueue = new RequestQueue(1) // Serial execution for chat messages
export const apiRequestQueue = new RequestQueue(3) // Allow 3 concurrent API requests

/**
 * Request deduplication utility
 * Prevents duplicate requests with the same parameters
 */
class RequestDeduplicator {
  private pendingRequests: Map<string, Promise<any>> = new Map()

  /**
   * Execute request with deduplication
   * If the same request is already in progress, return its promise
   */
  async deduplicate<T>(
    key: string,
    execute: () => Promise<T>
  ): Promise<T> {
    // Check if request is already pending
    if (this.pendingRequests.has(key)) {
      console.log(`Deduplicating request: ${key}`)
      return this.pendingRequests.get(key)
    }

    // Create new request promise
    const promise = execute().finally(() => {
      // Remove from pending when complete
      this.pendingRequests.delete(key)
    })

    this.pendingRequests.set(key, promise)
    return promise
  }

  /**
   * Clear specific request
   */
  clear(key: string): void {
    this.pendingRequests.delete(key)
  }

  /**
   * Clear all pending requests
   */
  clearAll(): void {
    this.pendingRequests.clear()
  }

  /**
   * Get pending request count
   */
  getPendingCount(): number {
    return this.pendingRequests.size
  }
}

export const requestDeduplicator = new RequestDeduplicator()

/**
 * Debounce utility for user inputs
 * Fixes: OPTIMIZATION #11 - No Request Debouncing
 */
export function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: NodeJS.Timeout | null = null

  return function executedFunction(...args: Parameters<T>) {
    const later = () => {
      timeout = null
      func(...args)
    }

    if (timeout) {
      clearTimeout(timeout)
    }
    timeout = setTimeout(later, wait)
  }
}

/**
 * Throttle utility
 * Limits the rate at which a function can be called
 */
export function throttle<T extends (...args: any[]) => any>(
  func: T,
  limit: number
): (...args: Parameters<T>) => void {
  let inThrottle: boolean = false

  return function executedFunction(...args: Parameters<T>) {
    if (!inThrottle) {
      func(...args)
      inThrottle = true
      setTimeout(() => {
        inThrottle = false
      }, limit)
    }
  }
}

/**
 * Request cancellation token
 */
export class CancellationToken {
  private cancelled: boolean = false
  private callbacks: (() => void)[] = []

  cancel(): void {
    if (this.cancelled) return
    this.cancelled = true
    this.callbacks.forEach(cb => cb())
    this.callbacks = []
  }

  isCancelled(): boolean {
    return this.cancelled
  }

  onCancel(callback: () => void): void {
    if (this.cancelled) {
      callback()
    } else {
      this.callbacks.push(callback)
    }
  }

  throwIfCancelled(): void {
    if (this.cancelled) {
      throw new Error('Operation cancelled')
    }
  }
}

export { RequestQueue }

