/**
 * Loading Spinner Component
 * Provides visual feedback during loading states
 * 
 * Fixes: HIGH PRIORITY #6 - Missing Loading States
 */

import React from 'react'
import { Loader } from 'lucide-react'

export interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg' | 'xl'
  text?: string
  fullScreen?: boolean
  variant?: 'default' | 'minimal' | 'dots' | 'pulse'
}

const sizeClasses = {
  sm: 'w-4 h-4',
  md: 'w-8 h-8',
  lg: 'w-12 h-12',
  xl: 'w-16 h-16',
}

/**
 * Default spinner with icon
 */
export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  size = 'md',
  text,
  fullScreen = false,
  variant = 'default',
}) => {
  const spinner = (() => {
    switch (variant) {
      case 'minimal':
        return (
          <div className={`${sizeClasses[size]} border-2 border-terminal-border border-t-zypheron-500 rounded-full animate-spin`} />
        )
      
      case 'dots':
        return (
          <div className="flex space-x-2">
            <div className="w-2 h-2 bg-zypheron-500 rounded-full animate-bounce" />
            <div className="w-2 h-2 bg-zypheron-500 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }} />
            <div className="w-2 h-2 bg-zypheron-500 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }} />
          </div>
        )
      
      case 'pulse':
        return (
          <div className={`${sizeClasses[size]} bg-zypheron-500 rounded-full animate-pulse`} />
        )
      
      default:
        return <Loader className={`${sizeClasses[size]} text-zypheron-500 animate-spin`} />
    }
  })()

  const content = (
    <div className="flex flex-col items-center justify-center space-y-3">
      {spinner}
      {text && (
        <p className="text-terminal-muted text-sm">{text}</p>
      )}
    </div>
  )

  if (fullScreen) {
    return (
      <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
        <div className="bg-terminal-surface border border-terminal-border rounded-lg p-8">
          {content}
        </div>
      </div>
    )
  }

  return content
}

/**
 * Loading bar component
 */
export interface LoadingBarProps {
  progress?: number // 0-100
  indeterminate?: boolean
  color?: string
  height?: string
}

export const LoadingBar: React.FC<LoadingBarProps> = ({
  progress = 0,
  indeterminate = false,
  color = 'bg-zypheron-500',
  height = 'h-1',
}) => {
  return (
    <div className={`w-full ${height} bg-terminal-border rounded-full overflow-hidden`}>
      <div
        className={`${height} ${color} rounded-full transition-all duration-300 ${
          indeterminate ? 'animate-pulse w-1/3' : ''
        }`}
        style={!indeterminate ? { width: `${Math.min(100, Math.max(0, progress))}%` } : undefined}
      />
    </div>
  )
}

/**
 * Skeleton loader for content placeholders
 */
export interface SkeletonProps {
  width?: string
  height?: string
  className?: string
  count?: number
  variant?: 'text' | 'rect' | 'circle'
}

export const Skeleton: React.FC<SkeletonProps> = ({
  width = 'w-full',
  height = 'h-4',
  className = '',
  count = 1,
  variant = 'rect',
}) => {
  const baseClass = 'bg-terminal-border animate-pulse'
  
  const variantClass = {
    text: 'rounded',
    rect: 'rounded-lg',
    circle: 'rounded-full',
  }[variant]

  return (
    <>
      {Array.from({ length: count }).map((_, i) => (
        <div
          key={i}
          className={`${baseClass} ${variantClass} ${width} ${height} ${className}`}
        />
      ))}
    </>
  )
}

/**
 * Loading overlay for specific components
 */
export interface LoadingOverlayProps {
  isLoading: boolean
  children: React.ReactNode
  text?: string
}

export const LoadingOverlay: React.FC<LoadingOverlayProps> = ({
  isLoading,
  children,
  text,
}) => {
  return (
    <div className="relative">
      {children}
      {isLoading && (
        <div className="absolute inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center rounded-lg z-10">
          <LoadingSpinner text={text} />
        </div>
      )}
    </div>
  )
}

/**
 * Inline loading indicator
 */
export interface InlineLoadingProps {
  text?: string
}

export const InlineLoading: React.FC<InlineLoadingProps> = ({ text = 'Loading...' }) => {
  return (
    <div className="flex items-center space-x-2 text-terminal-muted">
      <div className="w-4 h-4 border-2 border-terminal-border border-t-zypheron-500 rounded-full animate-spin" />
      <span className="text-sm">{text}</span>
    </div>
  )
}

/**
 * Progress steps indicator
 */
export interface ProgressStepsProps {
  steps: string[]
  currentStep: number
}

export const ProgressSteps: React.FC<ProgressStepsProps> = ({ steps, currentStep }) => {
  return (
    <div className="space-y-2">
      {steps.map((step, index) => {
        const isCompleted = index < currentStep
        const isCurrent = index === currentStep
        const isUpcoming = index > currentStep

        return (
          <div key={index} className="flex items-center space-x-3">
            <div
              className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-medium ${
                isCompleted
                  ? 'bg-green-500 text-white'
                  : isCurrent
                  ? 'bg-zypheron-500 text-white'
                  : 'bg-terminal-border text-terminal-muted'
              }`}
            >
              {isCompleted ? '✓' : index + 1}
            </div>
            <span
              className={`text-sm ${
                isCurrent ? 'text-terminal-text font-medium' : 'text-terminal-muted'
              }`}
            >
              {step}
            </span>
            {isCurrent && <InlineLoading text="" />}
          </div>
        )
      })}
    </div>
  )
}

/**
 * ChunkLoader Component
 * Specialized loading indicator for lazy-loaded code chunks
 * Shows while React.lazy() components are loading
 */
export interface ChunkLoaderProps {
  page?: string
  fullHeight?: boolean
}

export const ChunkLoader: React.FC<ChunkLoaderProps> = ({ 
  page = 'component',
  fullHeight = true 
}) => {
  return (
    <div className={`flex items-center justify-center ${fullHeight ? 'min-h-screen' : 'min-h-[400px]'} bg-terminal-bg`}>
      <div className="text-center">
        <div className="w-12 h-12 border-2 border-terminal-border border-t-zypheron-500 rounded-full animate-spin mx-auto mb-4" />
        <p className="text-terminal-muted text-sm">Loading {page}...</p>
        <p className="text-terminal-muted text-xs mt-2 opacity-60">Optimizing performance</p>
      </div>
    </div>
  )
}

export default LoadingSpinner

