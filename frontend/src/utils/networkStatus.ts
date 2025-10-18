/**
 * Network Status Utility
 * Detects online/offline status and handles network-related functionality
 * 
 * Fixes: HIGH PRIORITY #7 - No Offline Handling
 */

import { useState, useEffect } from 'react'

export type NetworkStatus = 'online' | 'offline' | 'slow'

export interface NetworkInfo {
  status: NetworkStatus
  downlink?: number  // Effective bandwidth estimate in Mbps
  rtt?: number       // Round-trip time in ms
  effectiveType?: string  // Connection type (4g, 3g, 2g, slow-2g)
  saveData?: boolean // User has data saver enabled
}

/**
 * Get current network information
 */
export const getNetworkInfo = (): NetworkInfo => {
  const isOnline = navigator.onLine
  
  // Get connection information if available (not supported in all browsers)
  const connection = (navigator as any).connection || 
                     (navigator as any).mozConnection || 
                     (navigator as any).webkitConnection

  const info: NetworkInfo = {
    status: isOnline ? 'online' : 'offline',
  }

  if (connection) {
    info.downlink = connection.downlink
    info.rtt = connection.rtt
    info.effectiveType = connection.effectiveType
    info.saveData = connection.saveData

    // Classify as slow if RTT > 500ms or effective type is slow
    if (isOnline && (connection.rtt > 500 || connection.effectiveType === 'slow-2g' || connection.effectiveType === '2g')) {
      info.status = 'slow'
    }
  }

  return info
}

/**
 * React hook for monitoring network status
 */
export const useNetworkStatus = () => {
  const [networkInfo, setNetworkInfo] = useState<NetworkInfo>(getNetworkInfo())

  useEffect(() => {
    const updateNetworkStatus = () => {
      setNetworkInfo(getNetworkInfo())
    }

    // Listen for online/offline events
    window.addEventListener('online', updateNetworkStatus)
    window.addEventListener('offline', updateNetworkStatus)

    // Listen for connection changes (if supported)
    const connection = (navigator as any).connection || 
                       (navigator as any).mozConnection || 
                       (navigator as any).webkitConnection

    if (connection) {
      connection.addEventListener('change', updateNetworkStatus)
    }

    // Cleanup listeners
    return () => {
      window.removeEventListener('online', updateNetworkStatus)
      window.removeEventListener('offline', updateNetworkStatus)
      
      if (connection) {
        connection.removeEventListener('change', updateNetworkStatus)
      }
    }
  }, [])

  return networkInfo
}

/**
 * Message queue for offline requests
 */
interface QueuedRequest {
  id: string
  url: string
  options: RequestInit
  timestamp: number
  retries: number
}

class RequestQueue {
  private static readonly QUEUE_KEY = 'zypheron_request_queue'
  private static readonly MAX_RETRIES = 3
  private static readonly MAX_QUEUE_SIZE = 50

  /**
   * Add request to queue
   */
  static enqueue(url: string, options: RequestInit): string {
    const queue = this.getQueue()
    
    // Check queue size limit
    if (queue.length >= this.MAX_QUEUE_SIZE) {
      console.warn('Request queue is full, removing oldest item')
      queue.shift()
    }

    const request: QueuedRequest = {
      id: `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      url,
      options,
      timestamp: Date.now(),
      retries: 0,
    }

    queue.push(request)
    this.saveQueue(queue)
    
    return request.id
  }

  /**
   * Process queued requests when online
   */
  static async processQueue(): Promise<void> {
    if (!navigator.onLine) {
      return
    }

    const queue = this.getQueue()
    if (queue.length === 0) {
      return
    }

    console.log(`Processing ${queue.length} queued requests...`)

    const processed: string[] = []
    const failed: QueuedRequest[] = []

    for (const request of queue) {
      try {
        const response = await fetch(request.url, request.options)
        
        if (response.ok) {
          processed.push(request.id)
          console.log(`Successfully processed queued request: ${request.id}`)
        } else {
          throw new Error(`HTTP ${response.status}`)
        }
      } catch (error) {
        console.error(`Failed to process queued request ${request.id}:`, error)
        
        // Retry logic
        request.retries++
        if (request.retries < this.MAX_RETRIES) {
          failed.push(request)
        } else {
          console.warn(`Max retries reached for request ${request.id}, discarding`)
          processed.push(request.id)
        }
      }
    }

    // Update queue with only failed requests
    this.saveQueue(failed)
    
    if (processed.length > 0) {
      console.log(`Processed ${processed.length} requests, ${failed.length} failed`)
    }
  }

  /**
   * Clear the entire queue
   */
  static clearQueue(): void {
    localStorage.removeItem(this.QUEUE_KEY)
  }

  /**
   * Get current queue
   */
  static getQueue(): QueuedRequest[] {
    try {
      const data = localStorage.getItem(this.QUEUE_KEY)
      return data ? JSON.parse(data) : []
    } catch (error) {
      console.error('Failed to parse request queue:', error)
      return []
    }
  }

  /**
   * Save queue to storage
   */
  private static saveQueue(queue: QueuedRequest[]): void {
    try {
      localStorage.setItem(this.QUEUE_KEY, JSON.stringify(queue))
    } catch (error) {
      console.error('Failed to save request queue:', error)
    }
  }

  /**
   * Get queue size
   */
  static getQueueSize(): number {
    return this.getQueue().length
  }
}

export { RequestQueue }

/**
 * Enhanced fetch with offline support and request queuing
 */
export const fetchWithOfflineSupport = async (
  url: string,
  options: RequestInit = {},
  queueIfOffline: boolean = true
): Promise<Response> => {
  // Check if online
  if (!navigator.onLine) {
    if (queueIfOffline) {
      const requestId = RequestQueue.enqueue(url, options)
      console.log(`Request queued for later (ID: ${requestId})`)
      
      throw new Error('You are currently offline. This request will be sent when you reconnect.')
    } else {
      throw new Error('No internet connection available')
    }
  }

  // Try to process any queued requests first
  RequestQueue.processQueue().catch(err => {
    console.error('Error processing request queue:', err)
  })

  // Make the actual request
  try {
    return await fetch(url, options)
  } catch (error) {
    // If fetch fails and we should queue, add to queue
    if (queueIfOffline) {
      const requestId = RequestQueue.enqueue(url, options)
      console.log(`Request failed, queued for retry (ID: ${requestId})`)
    }
    throw error
  }
}

/**
 * Setup automatic queue processing when coming online
 */
export const setupOfflineSupport = (): (() => void) => {
  const handleOnline = () => {
    console.log('Network connection restored, processing queued requests...')
    RequestQueue.processQueue()
  }

  window.addEventListener('online', handleOnline)

  // Return cleanup function
  return () => {
    window.removeEventListener('online', handleOnline)
  }
}

