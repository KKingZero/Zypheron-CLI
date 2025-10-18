import React, { createContext, useContext, useState, useCallback } from 'react'
import { shouldBypassAuth } from '../utils/devMode'
import { useAuth } from './AuthContext'
import { API_CONFIG } from '../config/api.config'

export interface Message {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp: Date
  model?: string
  provider?: 'cloud' | 'local'
  attachment?: string 
  metadata?: {
    threatLevel?: 'high' | 'medium' | 'low' | 'unknown'
    command?: string
    tool?: string
    target?: string
    analysisType?: string
    vulnerabilityId?: string
  }
}

export interface PentestCache {
  results: any
  target: string
  timestamp: Date
  sessionId: string
}

export interface ChatSession {
  id: string
  title: string
  messages: Message[]
  model: string
  createdAt: Date
  updatedAt: Date
}

export type LocalProvider = 'lm-studio' | 'docker' | 'ollama'

export const LOCAL_PROVIDER_ENDPOINTS: Record<LocalProvider, string> = {
  'lm-studio': API_CONFIG.LM_STUDIO_URL,
  'docker': API_CONFIG.DOCKER_OLLAMA_URL,
  'ollama': API_CONFIG.OLLAMA_URL
}

export const LOCAL_PROVIDER_NAMES: Record<LocalProvider, string> = {
  'lm-studio': 'LM Studio',
  'docker': 'Docker',
  'ollama': 'Ollama'
}

export const LOCAL_PROVIDER_DESCRIPTIONS: Record<LocalProvider, string> = {
  'lm-studio': 'Local GUI-based model hosting with automatic detection and manual model management',
  'docker': 'Containerized AI models running via Docker services',
  'ollama': 'Native Ollama runtime for local models (default)'
}

// Model-Platform Compatibility Matrix - Simplified for LM Studio and Docker only
export const MODEL_PLATFORM_COMPATIBILITY: Record<string, Array<'cloud' | LocalProvider>> = {
  // Cloud models - only work with cloud provider
  'gpt-4': ['cloud'],
  'gpt-3.5-turbo': ['cloud'],
  'claude-4-sonnet': ['cloud'],
  'gemini-2.5-flash': ['cloud'],
  'gemini-2.5-pro': ['cloud'],
  'grok-3': ['cloud'],
  'moonshot-v1-128k': ['cloud'],

  // Local models optimized for specific platforms
  'deepseek-r1-8b': ['lm-studio', 'docker', 'ollama'],
  'deepseek-r1-7b': ['lm-studio', 'docker', 'ollama'],
  'qwen-2.5': ['lm-studio', 'docker', 'ollama'],
  'llama-3-8b': ['lm-studio', 'docker', 'ollama'],
  'llama-3-70b': ['lm-studio', 'docker', 'ollama'],
  'llama-2-7b': ['lm-studio', 'docker', 'ollama'],
  'llama-2-13b': ['lm-studio', 'docker', 'ollama'],
  'codellama': ['lm-studio', 'docker', 'ollama'],
  'mistral-7b': ['lm-studio', 'docker', 'ollama'],
  'mixtral-8x7b': ['lm-studio', 'docker', 'ollama'],
  'phi-3': ['lm-studio', 'docker', 'ollama'],
  'gpt4all-falcon': ['lm-studio', 'docker', 'ollama'],
  'vicuna-7b': ['lm-studio', 'docker', 'ollama'],
  'alpaca-7b': ['lm-studio', 'docker', 'ollama'],
  // Kimi K2 local alias (user can wire a custom local endpoint)
  'kimi-k2-local': ['lm-studio', 'docker', 'ollama'],
}

// Get compatible models for a given provider
export const getCompatibleModels = (provider: 'cloud' | 'local', localProvider?: LocalProvider) => {
  if (provider === 'cloud') {
    return Object.entries(MODEL_PLATFORM_COMPATIBILITY)
      .filter(([_, platforms]) => platforms.includes('cloud'))
      .map(([model]) => model)
  }
  
  if (provider === 'local' && localProvider) {
    return Object.entries(MODEL_PLATFORM_COMPATIBILITY)
      .filter(([_, platforms]) => platforms.includes(localProvider))
      .map(([model]) => model)
  }
  
  return []
}

// Check if a model is compatible with a provider
export const isModelCompatible = (model: string, provider: 'cloud' | 'local', localProvider?: LocalProvider): boolean => {
  const compatibility = MODEL_PLATFORM_COMPATIBILITY[model]
  if (!compatibility) return false
  
  if (provider === 'cloud') {
    return compatibility.includes('cloud')
  }
  
  if (provider === 'local' && localProvider) {
    return compatibility.includes(localProvider)
  }
  
  return false
}

// LM Studio model detection
export interface LMStudioModel {
  id: string
  name: string
  size?: string
  quantization?: string
  available: boolean
  isCustom?: boolean // Flag for manually added models
}

// Custom model interface for manual additions
export interface CustomModel {
  id: string
  name: string
  displayName?: string
  provider: LocalProvider
  size?: string
  quantization?: string
  description?: string
  endpoint?: string // Custom endpoint for this model
}

// Fetch available models from LM Studio
export const fetchLMStudioModels = async (endpoint: string): Promise<LMStudioModel[]> => {
  try {
    const response = await fetch(`${endpoint}/models`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    })
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`)
    }
    
    const data = await response.json()
    
    // LM Studio returns models in OpenAI format
    if (data.data && Array.isArray(data.data)) {
      return data.data.map((model: any) => ({
        id: model.id,
        name: model.id.split('/').pop() || model.id,
        size: extractModelSize(model.id),
        quantization: extractQuantization(model.id),
        available: true,
        isCustom: false
      }))
    }
    
    return []
  } catch (error) {
    console.error('Failed to fetch LM Studio models:', error)
    return []
  }
}

// Helper functions to extract model info from LM Studio model IDs
const extractModelSize = (modelId: string): string | undefined => {
  const sizeMatch = modelId.match(/(\d+[bB])/i)
  return sizeMatch ? sizeMatch[1].toUpperCase() : undefined
}

const extractQuantization = (modelId: string): string | undefined => {
  const quantMatch = modelId.match(/(q\d+[_-]?[kmhg]?[_-]?[slm]?)/i)
  return quantMatch ? quantMatch[1].toUpperCase() : undefined
}

interface ChatContextType {
  sessions: ChatSession[]
  currentSession: ChatSession | null
  currentModel: string
  modelProvider: 'cloud' | 'local'
  localProvider: LocalProvider
  localEndpoint: string
  lmStudioModels: LMStudioModel[]
  customModels: CustomModel[]
  isLoading: boolean
  pentestCache: PentestCache | null
  createNewSession: () => void
  switchSession: (sessionId: string) => void
  deleteSession: (sessionId: string) => void
  updateSessionTitle: (sessionId: string, title: string) => void
  switchModel: (model: string) => void
  switchModelProvider: (provider: 'cloud' | 'local') => void
  switchLocalProvider: (provider: LocalProvider) => void
  setLocalEndpoint: (endpoint: string) => void
  refreshLMStudioModels: () => Promise<void>
  addCustomModel: (model: Omit<CustomModel, 'id'>) => void
  removeCustomModel: (modelId: string) => void
  sendMessage: (content: string, attachment?: string | null) => Promise<void>
  addAssistantMessage: (content: string, metadata?: any) => void
  exportSession: (sessionId: string) => void
  clearContext: () => void
  restartChat: () => void
  wipeAllData: () => void
  cachePentestResults: (results: any, target: string) => void
  getCachedPentestResults: () => PentestCache | null
  clearPentestCache: () => void
}

const ChatContext = createContext<ChatContextType | undefined>(undefined)

export const useChat = () => {
  const context = useContext(ChatContext)
  if (context === undefined) {
    throw new Error('useChat must be used within a ChatProvider')
  }
  return context
}

interface ChatProviderProps {
  children: React.ReactNode
}

export const ChatProvider: React.FC<ChatProviderProps> = ({ children }) => {
  const { session } = useAuth()
  const [sessions, setSessions] = useState<ChatSession[]>([])
  const [currentSession, setCurrentSession] = useState<ChatSession | null>(null)
  const [currentModel, setCurrentModel] = useState('claude-4-sonnet')
  const [modelProvider, setModelProvider] = useState<'cloud' | 'local'>('cloud')
  const [localProvider, setLocalProvider] = useState<LocalProvider>('ollama')
  const [localEndpoint, setLocalEndpoint] = useState(LOCAL_PROVIDER_ENDPOINTS['ollama'])
  const [lmStudioModels, setLMStudioModels] = useState<LMStudioModel[]>([])
  const [customModels, setCustomModels] = useState<CustomModel[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [pentestCache, setPentestCache] = useState<PentestCache | null>(null)

  // Load custom models from localStorage on init
  React.useEffect(() => {
    const savedCustomModels = localStorage.getItem('cobra-custom-models')
    if (savedCustomModels) {
      try {
        setCustomModels(JSON.parse(savedCustomModels))
      } catch (error) {
        console.error('Failed to load custom models from localStorage:', error)
      }
    }
  }, [])

  // Save custom models to localStorage whenever they change
  React.useEffect(() => {
    localStorage.setItem('cobra-custom-models', JSON.stringify(customModels))
  }, [customModels])

  // Load pentest cache from localStorage on init
  React.useEffect(() => {
    const savedPentestCache = localStorage.getItem('cobra-pentest-cache')
    if (savedPentestCache) {
      try {
        const cache = JSON.parse(savedPentestCache)
        // Convert timestamp back to Date object
        if (cache.timestamp) {
          cache.timestamp = new Date(cache.timestamp)
        }
        setPentestCache(cache)
      } catch (error) {
        console.error('Failed to load pentest cache from localStorage:', error)
      }
    }
  }, [])

  // Save pentest cache to localStorage whenever it changes
  React.useEffect(() => {
    if (pentestCache) {
      localStorage.setItem('cobra-pentest-cache', JSON.stringify(pentestCache))
    } else {
      localStorage.removeItem('cobra-pentest-cache')
    }
  }, [pentestCache])

  // Initialize with a default session if none exist
  React.useEffect(() => {
    if (sessions.length === 0 && !currentSession) {
      const defaultSession: ChatSession = {
        id: `session-${Date.now()}`,
        title: 'New Chat',
        messages: [],
        model: currentModel,
        createdAt: new Date(),
        updatedAt: new Date(),
      }
      setSessions([defaultSession])
      setCurrentSession(defaultSession)
    }
  }, [sessions.length, currentSession, currentModel])

  // Auto-refresh LM Studio models when provider is selected
  React.useEffect(() => {
    if (localProvider === 'lm-studio') {
      refreshLMStudioModels()
    }
  }, [localProvider, localEndpoint])

  const createNewSession = useCallback(() => {
    const newSession: ChatSession = {
      id: `session-${Date.now()}`,
      title: 'New Chat',
      messages: [],
      model: currentModel,
      createdAt: new Date(),
      updatedAt: new Date(),
    }
    
    setSessions(prev => [newSession, ...prev])
    setCurrentSession(newSession)
    // Clear pentest cache when creating new session
    clearPentestCache()
  }, [currentModel])

  const switchSession = useCallback((sessionId: string) => {
    const session = sessions.find(s => s.id === sessionId)
    if (session) {
      setCurrentSession(session)
      // Don't clear cache when switching sessions - let it persist
      // The getCachedPentestResults function will handle session-specific filtering
    }
  }, [sessions])

  const deleteSession = useCallback((sessionId: string) => {
    setSessions(prev => prev.filter(s => s.id !== sessionId))
    if (currentSession?.id === sessionId) {
      setCurrentSession(null)
    }
  }, [currentSession])

  const updateSessionTitle = useCallback((sessionId: string, title: string) => {
    // Update local state - this is all we need for a simple UI component
    setSessions(prev => prev.map(s => 
      s.id === sessionId 
        ? { ...s, title: title.trim(), updatedAt: new Date() }
        : s
    ))
    if (currentSession?.id === sessionId) {
      setCurrentSession(prev => prev ? { ...prev, title: title.trim(), updatedAt: new Date() } : null)
    }
  }, [currentSession])

  const switchModel = useCallback((model: string) => {
    setCurrentModel(model)
    if (currentSession) {
      const updatedSession = { ...currentSession, model }
      setCurrentSession(updatedSession)
      setSessions(prev => prev.map(s => s.id === currentSession.id ? updatedSession : s))
    }
  }, [currentSession])

  const switchModelProvider = useCallback((provider: 'cloud' | 'local') => {
    setModelProvider(provider)
    // Switch to first compatible model of the new provider
    const compatibleModels = getCompatibleModels(provider, provider === 'local' ? localProvider : undefined)
    if (compatibleModels.length > 0) {
      setCurrentModel(compatibleModels[0])
    }
  }, [localProvider])

  const switchLocalProvider = useCallback((provider: LocalProvider) => {
    setLocalProvider(provider)
    setLocalEndpoint(LOCAL_PROVIDER_ENDPOINTS[provider])
    // Switch to first compatible model for the new provider
    const compatibleModels = getCompatibleModels('local', provider)
    if (compatibleModels.length > 0 && !isModelCompatible(currentModel, 'local', provider)) {
      setCurrentModel(compatibleModels[0])
    }
  }, [currentModel])

  const refreshLMStudioModels = useCallback(async () => {
    if (localProvider === 'lm-studio') {
      const models = await fetchLMStudioModels(localEndpoint)
      setLMStudioModels(models)
    }
  }, [localProvider, localEndpoint])

  const addCustomModel = useCallback((model: Omit<CustomModel, 'id'>) => {
    const newModel: CustomModel = {
      ...model,
      id: `custom-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    }
    setCustomModels(prev => [...prev, newModel])
  }, [])

  const removeCustomModel = useCallback((modelId: string) => {
    setCustomModels(prev => prev.filter(m => m.id !== modelId))
    // If the removed model was currently selected, switch to a default
    if (currentModel === modelId) {
      const compatibleModels = getCompatibleModels('local', localProvider)
      if (compatibleModels.length > 0) {
        setCurrentModel(compatibleModels[0])
      }
    }
  }, [currentModel, localProvider])

  const sendMessage = useCallback(async (content: string, attachment?: string | null) => {
    if (!currentSession) return
    
    setIsLoading(true)
    
    const userMessage: Message = {
      id: `msg-${Date.now()}`,
      role: 'user',
      content,
      attachment: modelProvider === 'cloud' && currentModel === 'gpt-4' ? attachment || undefined : undefined,
      timestamp: new Date(),
      provider: modelProvider,
    }

    // Update session with user message
    const updatedSession = {
      ...currentSession,
      messages: [...currentSession.messages, userMessage],
      updatedAt: new Date(),
      title: currentSession.messages.length === 0 ? content.slice(0, 50) + '...' : currentSession.title,
    }
    
    setCurrentSession(updatedSession)
    setSessions(prev => prev.map(s => s.id === currentSession.id ? updatedSession : s))

    try {
      let response: Response
      
      if (modelProvider === 'local') {
        // Check if this is a custom model with its own endpoint
        const customModel = customModels.find(m => m.id === currentModel)
        const endpoint = customModel?.endpoint || localEndpoint
        
        // Adjust API path based on provider
        let apiPath = '/chat/completions'
        if (localProvider === 'docker') {
          apiPath = '/generate'
        }
        
        // For local models, use provider-specific endpoint
        const finalEndpoint = endpoint.endsWith('/') ? endpoint.slice(0, -1) : endpoint
        response = await fetch(`${finalEndpoint}${apiPath}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(
            localProvider === 'docker'
              ? {
                  model: currentModel,
                  prompt: [...currentSession.messages, userMessage].map(msg => 
                    `${msg.role}: ${msg.content}`
                  ).join('\n'),
                  stream: false
                }
              : {
                  model: currentModel,
                  messages: [...currentSession.messages, userMessage].map(msg => ({
                    role: msg.role,
                    content: msg.content
                  })),
                  temperature: 0.7,
                  max_tokens: 2048,
                  stream: false
                }
          ),
        })
      } else {
        // For cloud models, use our backend API
        const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:3001'
        response = await fetch(`${baseUrl}/api/chat/message`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(session?.access_token
              ? { 'Authorization': `Bearer ${session.access_token}` }
              : shouldBypassAuth()
                ? { 'Authorization': 'Bearer localhost-dev-token', 'x-dev-bypass': 'true' }
                : {})
          },
          body: JSON.stringify({
            messages: [...currentSession.messages, userMessage].map(msg => ({
              role: msg.role,
              content: msg.content,
              attachment: msg.attachment
            })),
            model: currentModel,
          }),
        })
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }))
        // Enrich error with status for better UX
        const enrichedMessage = errorData.message || `HTTP ${response.status}: ${response.statusText}`
        const err: any = new Error(enrichedMessage)
        err.status = response.status
        throw err
      }

      const data = await response.json()
      
      let assistantContent: string
      let metadata: any = {}
      
      if (modelProvider === 'local') {
        // Handle different response formats
        if (localProvider === 'docker') {
          assistantContent = data.response
        } else {
          // OpenAI-compatible format (LM Studio)
          assistantContent = data.choices[0].message.content
        }
      } else {
        assistantContent = data.message
        metadata = data.metadata
      }
      
      const assistantMessage: Message = {
        id: `msg-${Date.now()}-assistant`,
        role: 'assistant',
        content: assistantContent,
        timestamp: new Date(),
        model: currentModel,
        provider: modelProvider,
        metadata,
      }

      // Update session with assistant message
      const finalSession = {
        ...updatedSession,
        messages: [...updatedSession.messages, assistantMessage],
        updatedAt: new Date(),
      }
      
      setCurrentSession(finalSession)
      setSessions(prev => prev.map(s => s.id === currentSession.id ? finalSession : s))
      
    } catch (error: any) {
      console.error('Error sending message:', error)
      
      // Sanitize error messages to prevent information disclosure
      let errorMsg = 'Sorry, I encountered an error while processing your message.'
      
      if (modelProvider === 'local') {
        errorMsg = `Unable to connect to ${LOCAL_PROVIDER_NAMES[localProvider]}. Please ensure the service is running at ${localEndpoint}.`
      } else if (error?.status === 401) {
        errorMsg = 'Authentication required. Please sign in and try again.'
      } else if (error?.status === 403) {
        errorMsg = 'Access denied. You may have reached your plan limit. Please upgrade or contact support.'
      } else if (error?.status === 429) {
        errorMsg = 'Rate limit exceeded. Please wait a moment and try again.'
      } else if (error?.status === 500 || error?.status === 502 || error?.status === 503) {
        errorMsg = 'Service temporarily unavailable. Please try again in a moment.'
      } else if (error?.message && !error.message.includes('stack') && !error.message.includes('at ')) {
        // Only include error message if it's safe (doesn't contain stack traces)
        errorMsg = `An error occurred: ${error.message.substring(0, 100)}`
      }
      
      const errorMessage: Message = {
        id: `msg-${Date.now()}-error`,
        role: 'assistant',
        content: errorMsg,
        timestamp: new Date(),
        model: currentModel,
        provider: modelProvider,
      }

      const errorSession = {
        ...updatedSession,
        messages: [...updatedSession.messages, errorMessage],
        updatedAt: new Date(),
      }
      
      setCurrentSession(errorSession)
      setSessions(prev => prev.map(s => s.id === currentSession.id ? errorSession : s))
    } finally {
      setIsLoading(false)
    }
  }, [currentSession, currentModel, modelProvider, localProvider, localEndpoint, customModels])

  const exportSession = useCallback((sessionId: string) => {
    const session = sessions.find(s => s.id === sessionId)
    if (!session) return

    const exportData = {
      title: session.title,
      model: session.model,
      createdAt: session.createdAt.toISOString(),
      messages: session.messages.map(msg => ({
        role: msg.role,
        content: msg.content,
        timestamp: msg.timestamp.toISOString(),
        model: msg.model,
        metadata: msg.metadata,
      })),
    }

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `cobra-ai-${session.title.replace(/[^a-zA-Z0-9]/g, '-')}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }, [sessions])

  const clearContext = useCallback(() => {
    if (currentSession) {
      const clearedSession = {
        ...currentSession,
        messages: [],
        updatedAt: new Date(),
      }
      setCurrentSession(clearedSession)
      setSessions(prev => prev.map(s => s.id === currentSession.id ? clearedSession : s))
      // Clear pentest cache when context is cleared
      clearPentestCache()
    }
  }, [currentSession])

  const restartChat = useCallback(() => {
    // Clear current session and create a new one
    const newSession: ChatSession = {
      id: `session-${Date.now()}`,
      title: 'New Chat',
      messages: [],
      model: currentModel,
      createdAt: new Date(),
      updatedAt: new Date(),
    }
    
    setCurrentSession(newSession)
    setSessions(prev => [newSession, ...prev])
    setIsLoading(false)
    // Clear pentest cache when restarting chat
    clearPentestCache()
  }, [currentModel])

  const wipeAllData = useCallback(() => {
    // Clear all sessions and start fresh
    setSessions([])
    setCurrentSession(null)
    setIsLoading(false)
    setCurrentModel('gpt-4')
    
    // Create a new fresh session
    const newSession: ChatSession = {
      id: `session-${Date.now()}`,
      title: 'New Chat',
      messages: [],
      model: 'gpt-4',
      createdAt: new Date(),
      updatedAt: new Date(),
    }
    
    setSessions([newSession])
    setCurrentSession(newSession)
    // Clear pentest cache when wiping all data
    clearPentestCache()
  }, [])

  const addAssistantMessage = useCallback((content: string, metadata?: any) => {
    if (!currentSession) return

    const assistantMessage: Message = {
      id: `msg-${Date.now()}-assistant`,
      role: 'assistant',
      content,
      timestamp: new Date(),
      model: currentModel,
      provider: modelProvider,
      metadata,
    }

    const updatedSession = {
      ...currentSession,
      messages: [...currentSession.messages, assistantMessage],
      updatedAt: new Date(),
    }
    
    setCurrentSession(updatedSession)
    setSessions(prev => prev.map(s => s.id === currentSession.id ? updatedSession : s))
  }, [currentSession, currentModel, modelProvider])

  const cachePentestResults = useCallback((results: any, target: string) => {
    if (!currentSession) return

    const cache: PentestCache = {
      results,
      target,
      timestamp: new Date(),
      sessionId: currentSession.id,
    }
    
    setPentestCache(cache)
  }, [currentSession])

  const getCachedPentestResults = useCallback((): PentestCache | null => {
    if (!currentSession || !pentestCache) return null
    
    // Return cache only if it's for the current session
    if (pentestCache.sessionId === currentSession.id) {
      return pentestCache
    }
    
    return null
  }, [currentSession, pentestCache])

  const clearPentestCache = useCallback(() => {
    setPentestCache(null)
  }, [])

  const value = {
    sessions,
    currentSession,
    currentModel,
    modelProvider,
    localProvider,
    localEndpoint,
    lmStudioModels,
    customModels,
    isLoading,
    pentestCache,
    createNewSession,
    switchSession,
    deleteSession,
    updateSessionTitle,
    switchModel,
    switchModelProvider,
    switchLocalProvider,
    setLocalEndpoint,
    refreshLMStudioModels,
    addCustomModel,
    removeCustomModel,
    sendMessage,
    addAssistantMessage,
    exportSession,
    clearContext,
    restartChat,
    wipeAllData,
    cachePentestResults,
    getCachedPentestResults,
    clearPentestCache,
  }

  return <ChatContext.Provider value={value}>{children}</ChatContext.Provider>
} 