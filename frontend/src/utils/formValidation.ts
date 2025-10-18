/**
 * Form Validation Utilities
 * Comprehensive form validation with Zod schemas
 * 
 * Implements: IMPROVEMENT #17 - Missing Input Validation
 */

import { z } from 'zod'

/**
 * Common validation schemas
 */
export const emailSchema = z.string().email('Invalid email address')

export const passwordSchema = z
  .string()
  .min(8, 'Password must be at least 8 characters')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
  .regex(/[0-9]/, 'Password must contain at least one number')
  .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character')

export const urlSchema = z.string().url('Invalid URL format')

export const ipAddressSchema = z
  .string()
  .regex(
    /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
    'Invalid IP address'
  )

export const domainSchema = z
  .string()
  .regex(
    /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i,
    'Invalid domain name'
  )

export const targetSchema = z.union([urlSchema, ipAddressSchema, domainSchema])

/**
 * Login form schema
 */
export const loginFormSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, 'Password is required'),
})

export type LoginFormData = z.infer<typeof loginFormSchema>

/**
 * Signup form schema
 */
export const signupFormSchema = z
  .object({
    email: emailSchema,
    password: passwordSchema,
    confirmPassword: z.string(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords don't match",
    path: ['confirmPassword'],
  })

export type SignupFormData = z.infer<typeof signupFormSchema>

/**
 * Penetration test form schema
 */
export const pentestFormSchema = z.object({
  target: targetSchema,
  tests: z.array(z.string()).min(1, 'Select at least one test'),
  options: z.object({
    useTor: z.boolean().optional(),
    useOsint: z.boolean().optional(),
    firewallBypass: z.boolean().optional(),
  }).optional(),
})

export type PentestFormData = z.infer<typeof pentestFormSchema>

/**
 * Search form schema
 */
export const searchFormSchema = z.object({
  query: z.string().min(2, 'Search query must be at least 2 characters'),
  filters: z.object({
    category: z.string().optional(),
    sortBy: z.string().optional(),
  }).optional(),
})

export type SearchFormData = z.infer<typeof searchFormSchema>

/**
 * Settings form schema
 */
export const settingsFormSchema = z.object({
  email: emailSchema.optional(),
  currentPassword: z.string().optional(),
  newPassword: passwordSchema.optional(),
  confirmNewPassword: z.string().optional(),
  notifications: z.boolean().optional(),
  darkMode: z.boolean().optional(),
}).refine(
  (data) => {
    if (data.newPassword && data.confirmNewPassword) {
      return data.newPassword === data.confirmNewPassword
    }
    return true
  },
  {
    message: "Passwords don't match",
    path: ['confirmNewPassword'],
  }
)

export type SettingsFormData = z.infer<typeof settingsFormSchema>

/**
 * API Key form schema
 */
export const apiKeyFormSchema = z.object({
  provider: z.enum(['openai', 'anthropic', 'google', 'custom']),
  apiKey: z.string().min(20, 'API key must be at least 20 characters'),
  name: z.string().min(1, 'Name is required').optional(),
})

export type ApiKeyFormData = z.infer<typeof apiKeyFormSchema>

/**
 * Contact form schema
 */
export const contactFormSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  email: emailSchema,
  subject: z.string().min(5, 'Subject must be at least 5 characters'),
  message: z.string().min(10, 'Message must be at least 10 characters'),
})

export type ContactFormData = z.infer<typeof contactFormSchema>

/**
 * Generic form validation hook
 */
export interface ValidationResult {
  isValid: boolean
  errors: Record<string, string>
}

export function validateForm<T>(
  schema: z.ZodSchema<T>,
  data: unknown
): ValidationResult {
  try {
    schema.parse(data)
    return { isValid: true, errors: {} }
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errors: Record<string, string> = {}
      error.errors.forEach((err) => {
        const path = err.path.join('.')
        errors[path] = err.message
      })
      return { isValid: false, errors }
    }
    return { isValid: false, errors: { _general: 'Validation failed' } }
  }
}

/**
 * Sanitize input to prevent XSS
 */
export function sanitizeInput(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;')
}

/**
 * Validate and sanitize input
 */
export function validateAndSanitize<T>(
  schema: z.ZodSchema<T>,
  data: unknown
): { success: boolean; data?: T; errors?: Record<string, string> } {
  const validation = validateForm(schema, data)
  
  if (!validation.isValid) {
    return { success: false, errors: validation.errors }
  }

  // For string fields, apply sanitization
  const sanitizedData = JSON.parse(
    JSON.stringify(data),
    (key, value) => {
      if (typeof value === 'string') {
        return sanitizeInput(value)
      }
      return value
    }
  )

  try {
    const parsedData = schema.parse(sanitizedData)
    return { success: true, data: parsedData }
  } catch {
    return { success: false, errors: { _general: 'Sanitization failed' } }
  }
}

/**
 * Real-time field validation
 */
export function validateField<T>(
  schema: z.ZodSchema<T>,
  fieldName: string,
  value: unknown
): string | null {
  try {
    const fieldSchema = (schema as any).shape?.[fieldName]
    if (fieldSchema) {
      fieldSchema.parse(value)
    }
    return null
  } catch (error) {
    if (error instanceof z.ZodError) {
      return error.errors[0]?.message || 'Invalid input'
    }
    return 'Validation error'
  }
}

/**
 * React hook for form validation
 */
import { useState, useCallback } from 'react'

export function useFormValidation<T>(schema: z.ZodSchema<T>) {
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [isValid, setIsValid] = useState(false)

  const validate = useCallback((data: unknown): boolean => {
    const result = validateForm(schema, data)
    setErrors(result.errors)
    setIsValid(result.isValid)
    return result.isValid
  }, [schema])

  const validateField = useCallback((fieldName: string, value: unknown): string | null => {
    const error = validateField(schema, fieldName, value)
    setErrors(prev => ({
      ...prev,
      [fieldName]: error || '',
    }))
    return error
  }, [schema])

  const clearErrors = useCallback(() => {
    setErrors({})
    setIsValid(false)
  }, [])

  return { errors, isValid, validate, validateField, clearErrors }
}

