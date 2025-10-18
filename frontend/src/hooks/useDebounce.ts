/**
 * useDebounce Hook
 * Custom React hook for debouncing values
 * 
 * Implements: OPTIMIZATION #11 - Request Debouncing
 */

import { useState, useEffect } from 'react'

/**
 * Debounce a value - updates only after specified delay
 */
export function useDebounce<T>(value: T, delay: number = 500): T {
  const [debouncedValue, setDebouncedValue] = useState<T>(value)

  useEffect(() => {
    // Set up the timeout
    const handler = setTimeout(() => {
      setDebouncedValue(value)
    }, delay)

    // Clean up the timeout if value changes before delay expires
    return () => {
      clearTimeout(handler)
    }
  }, [value, delay])

  return debouncedValue
}

/**
 * Debounce a callback function
 */
export function useDebouncedCallback<T extends (...args: any[]) => any>(
  callback: T,
  delay: number = 500
): (...args: Parameters<T>) => void {
  const [timeoutId, setTimeoutId] = useState<NodeJS.Timeout | null>(null)

  useEffect(() => {
    // Cleanup on unmount
    return () => {
      if (timeoutId) {
        clearTimeout(timeoutId)
      }
    }
  }, [timeoutId])

  return (...args: Parameters<T>) => {
    if (timeoutId) {
      clearTimeout(timeoutId)
    }

    const newTimeoutId = setTimeout(() => {
      callback(...args)
      setTimeoutId(null)
    }, delay)

    setTimeoutId(newTimeoutId)
  }
}

/**
 * Throttle a callback function
 */
export function useThrottledCallback<T extends (...args: any[]) => any>(
  callback: T,
  limit: number = 500
): (...args: Parameters<T>) => void {
  const [inThrottle, setInThrottle] = useState(false)

  return (...args: Parameters<T>) => {
    if (!inThrottle) {
      callback(...args)
      setInThrottle(true)
      setTimeout(() => setInThrottle(false), limit)
    }
  }
}

export default useDebounce

