/**
 * Lazy Image Component
 * Implements lazy loading for images with placeholder
 * 
 * Implements: OPTIMIZATION #12 - Unoptimized Images
 */

import React, { useState, useEffect, useRef } from 'react'
import { Skeleton } from './LoadingSpinner'

export interface LazyImageProps extends React.ImgHTMLAttributes<HTMLImageElement> {
  src: string
  alt: string
  placeholderSrc?: string
  threshold?: number
  className?: string
  onLoad?: () => void
  onError?: () => void
}

/**
 * LazyImage component with Intersection Observer
 */
export const LazyImage: React.FC<LazyImageProps> = ({
  src,
  alt,
  placeholderSrc,
  threshold = 0.1,
  className = '',
  onLoad,
  onError,
  ...props
}) => {
  const [imageSrc, setImageSrc] = useState<string | undefined>(placeholderSrc)
  const [isLoading, setIsLoading] = useState(true)
  const [isError, setIsError] = useState(false)
  const imgRef = useRef<HTMLImageElement>(null)

  useEffect(() => {
    // Check if IntersectionObserver is supported
    if (!('IntersectionObserver' in window)) {
      // Fallback: load image immediately
      setImageSrc(src)
      return
    }

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            // Start loading the image
            setImageSrc(src)
            // Stop observing once image is loading
            if (imgRef.current) {
              observer.unobserve(imgRef.current)
            }
          }
        })
      },
      {
        threshold,
        rootMargin: '50px', // Start loading 50px before entering viewport
      }
    )

    if (imgRef.current) {
      observer.observe(imgRef.current)
    }

    return () => {
      if (imgRef.current) {
        observer.unobserve(imgRef.current)
      }
    }
  }, [src, threshold])

  const handleLoad = () => {
    setIsLoading(false)
    if (onLoad) {
      onLoad()
    }
  }

  const handleError = () => {
    setIsLoading(false)
    setIsError(true)
    if (onError) {
      onError()
    }
  }

  return (
    <div className={`relative ${className}`}>
      {isLoading && !isError && (
        <div className="absolute inset-0">
          <Skeleton variant="rect" className="w-full h-full" />
        </div>
      )}
      <img
        ref={imgRef}
        src={imageSrc}
        alt={alt}
        className={`${className} ${isLoading ? 'opacity-0' : 'opacity-100'} transition-opacity duration-300`}
        onLoad={handleLoad}
        onError={handleError}
        loading="lazy" // Native lazy loading as backup
        {...props}
      />
      {isError && (
        <div className="absolute inset-0 flex items-center justify-center bg-gray-800 text-gray-400">
          <span className="text-sm">Failed to load image</span>
        </div>
      )}
    </div>
  )
}

/**
 * Optimized background image component
 */
export interface LazyBackgroundImageProps {
  src: string
  children?: React.ReactNode
  className?: string
  placeholder?: string
}

export const LazyBackgroundImage: React.FC<LazyBackgroundImageProps> = ({
  src,
  children,
  className = '',
  placeholder = 'linear-gradient(to bottom, #1a1a1a, #0d0d0d)',
}) => {
  const [bgImage, setBgImage] = useState<string>(placeholder)
  const [isLoaded, setIsLoaded] = useState(false)
  const divRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!('IntersectionObserver' in window)) {
      setBgImage(`url(${src})`)
      return
    }

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            // Preload the image
            const img = new Image()
            img.src = src
            img.onload = () => {
              setBgImage(`url(${src})`)
              setIsLoaded(true)
            }
            if (divRef.current) {
              observer.unobserve(divRef.current)
            }
          }
        })
      },
      {
        threshold: 0.1,
        rootMargin: '50px',
      }
    )

    if (divRef.current) {
      observer.observe(divRef.current)
    }

    return () => {
      if (divRef.current) {
        observer.unobserve(divRef.current)
      }
    }
  }, [src])

  return (
    <div
      ref={divRef}
      className={`${className} ${isLoaded ? 'bg-loaded' : 'bg-loading'} transition-all duration-300`}
      style={{
        backgroundImage: bgImage,
        backgroundSize: 'cover',
        backgroundPosition: 'center',
      }}
    >
      {children}
    </div>
  )
}

export default LazyImage

