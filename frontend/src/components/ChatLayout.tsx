import React, { useState, useEffect } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useChat } from '../contexts/ChatContext'
import { useAuth } from '../contexts/AuthContext'
import { useSubscriptionAccess } from '../hooks/useSubscriptionAccess'
import { 
  Shield, 
  Search, 
  ChevronDown, 
  Plus, 
  MessageSquare, 
  Trash2, 
  Edit3,
  Cloud,
  Crown,
  RefreshCw,
  RotateCcw,
  Save,
  FileSearch,
  Menu,
  X,
  LogOut,
  Settings,
  Target
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

interface ChatLayoutProps {
  children: React.ReactNode
}

interface ModelInfo {
  id: string
  name: string
  available: boolean
  premium?: boolean
}

const ChatLayout: React.FC<ChatLayoutProps> = ({ children }) => {
  const navigate = useNavigate()
  const location = useLocation()
  const { 
    currentModel, 
    switchModel,
    clearContext, 
    exportSession, 
    currentSession, 
    restartChat, 
    wipeAllData,
    sessions,
    createNewSession,
    switchSession,
    deleteSession,
    updateSessionTitle,
    getCachedPentestResults,
    clearPentestCache
  } = useChat()
  
  const { signOut, session } = useAuth()
  const { hasAccess, isDeveloper, canAccessFeature } = useSubscriptionAccess()

  const [editingSessionId, setEditingSessionId] = useState<string | null>(null)
  const [editTitle, setEditTitle] = useState('')

  // Cloud models only
  const cloudModels: ModelInfo[] = [
    { id: 'gpt-4', name: 'GPT-4', available: true },
    { id: 'gpt-3.5-turbo', name: 'GPT-3.5', available: true },
    { id: 'gpt-5', name: 'GPT-5', available: true, premium: true },
    { id: 'claude-4-sonnet', name: 'Claude-4 Sonnet', available: true },
    { id: 'claude-4-opus', name: 'Claude-4 Opus', available: true, premium: true },
    { id: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash', available: true },
    { id: 'gemini-2.5-pro', name: 'Gemini 2.5 Pro', available: true },
    { id: 'grok-3', name: 'Grok 3', available: true },
    { id: 'grok-4', name: 'Grok 4', available: true, premium: true },
  ]

  const navigationItems = [
    { 
      path: '/dashboard', 
      name: 'Chat Dashboard', 
      icon: MessageSquare,
      description: 'AI-powered cybersecurity chat'
    },
    { 
      path: '/red-team-ops', 
      name: 'Red Team Ops', 
      icon: Target,
      description: 'Offensive security operations'
    },
    { 
      path: '/command-control', 
      name: 'Command & Control', 
      icon: Search,
      description: 'Reconnaissance and information gathering'
    }
  ]

  const handleEditSession = (sessionId: string, currentTitle: string) => {
    setEditingSessionId(sessionId)
    setEditTitle(currentTitle)
  }

  const handleSaveTitle = async () => {
    if (editingSessionId && editTitle.trim()) {
      await updateSessionTitle(editingSessionId, editTitle.trim())
      setEditingSessionId(null)
      setEditTitle('')
    }
  }

  const handleCancelEdit = () => {
    setEditingSessionId(null)
    setEditTitle('')
  }

  const handleDeleteSession = async (sessionId: string) => {
    if (confirm('Are you sure you want to delete this session?')) {
      await deleteSession(sessionId)
    }
  }

  const handleLogout = async () => {
    try {
      await signOut()
      navigate('/login')
    } catch (error) {
      console.error('Logout error:', error)
    }
  }

  return (
    <div className="min-h-screen bg-[#0d0d0d] text-terminal-text flex overflow-x-hidden w-full max-w-full">
      {/* Sidebar */}
      <div className="w-80 bg-[#1a1a1a] border-r border-terminal-border flex flex-col shrink-0 hidden lg:flex">
        {/* Logo Header */}
        <div className="p-4 border-b border-terminal-border">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8">
              <img 
                src="/ZypheronX.jpg" 
                alt="Zypheron Logo" 
                className="w-full h-full object-contain"
                onError={(e) => {
                  e.currentTarget.src = "/ZypheronX.jpg";
                }}
              />
            </div>
            <h1 className="text-xl font-orbitron font-bold text-zypheron-500">
              Zypheron
            </h1>
          </div>
        </div>

        {/* Navigation */}
        <div className="flex-1 flex flex-col">
          <div className="p-4">
            <h2 className="text-sm font-medium text-terminal-muted mb-3">Navigation</h2>
            <div className="space-y-1">
              {navigationItems.map((item) => {
                const Icon = item.icon
                const isActive = location.pathname === item.path || 
                               (item.path === '/dashboard' && (location.pathname === '/' || location.pathname === '/chat'))
                
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    className={`
                      flex items-center space-x-3 px-3 py-2 rounded-lg transition-colors group
                      ${isActive 
                        ? 'bg-zypheron-500 text-white' 
                        : 'text-terminal-muted hover:text-terminal-text hover:bg-terminal-surface'
                      }
                    `}
                  >
                    <Icon className="w-4 h-4" />
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-sm">{item.name}</div>
                      <div className="text-xs opacity-75 truncate">{item.description}</div>
                    </div>
                  </Link>
                )
              })}
            </div>
          </div>

          {/* Sessions */}
          <div className="flex-1 px-4 pb-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-medium text-terminal-muted">Chat Sessions</h2>
              <button
                onClick={createNewSession}
                className="p-1 text-zypheron-500 hover:text-zypheron-400 transition-colors"
                title="New Session"
              >
                <Plus className="w-4 h-4" />
              </button>
            </div>
            <div className="space-y-1 max-h-64 overflow-y-auto">
              {sessions.map((sessionItem) => (
                <div
                  key={sessionItem.id}
                  className={`
                    group flex items-center space-x-2 px-3 py-2 rounded-lg cursor-pointer transition-colors
                    ${currentSession?.id === sessionItem.id 
                      ? 'bg-terminal-surface border border-zypheron-500/30' 
                      : 'hover:bg-terminal-surface'
                    }
                  `}
                  onClick={() => switchSession(sessionItem.id)}
                >
                  {editingSessionId === sessionItem.id ? (
                    <div className="flex-1 flex items-center space-x-2">
                      <input
                        type="text"
                        value={editTitle}
                        onChange={(e) => setEditTitle(e.target.value)}
                        className="flex-1 bg-terminal-bg border border-terminal-border rounded px-2 py-1 text-xs"
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') handleSaveTitle()
                          if (e.key === 'Escape') handleCancelEdit()
                        }}
                        autoFocus
                      />
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          handleSaveTitle()
                        }}
                        className="p-1 text-green-500 hover:text-green-400"
                      >
                        <Save className="w-3 h-3" />
                      </button>
                    </div>
                  ) : (
                    <>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm truncate">{sessionItem.title}</div>
                        <div className="text-xs text-terminal-muted">
                          {formatDistanceToNow(sessionItem.updatedAt, { addSuffix: true })}
                        </div>
                      </div>
                      <div className="flex items-center space-x-1 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            handleEditSession(sessionItem.id, sessionItem.title)
                          }}
                          className="p-1 text-terminal-muted hover:text-terminal-text"
                        >
                          <Edit3 className="w-3 h-3" />
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            handleDeleteSession(sessionItem.id)
                          }}
                          className="p-1 text-red-500 hover:text-red-400"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    </>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* AI Model Selector & Controls - Fixed at bottom */}
        <div className="border-t border-terminal-border p-4 flex-shrink-0">
          {/* Cloud Models Only */}
          <div className="mb-3">
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs text-terminal-muted">Cloud AI Models</label>
            </div>
          </div>

          {/* Model Selector */}
          <div className="mb-3">
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs text-terminal-muted">
                AI Model
              </label>
            </div>
            <div className="relative">
              <select
                value={currentModel}
                onChange={(e) => switchModel(e.target.value)}
                className="w-full bg-terminal-surface border border-terminal-border rounded-lg px-3 py-2 text-terminal-text appearance-none cursor-pointer pr-10 text-sm"
              >
                {cloudModels.map((model) => (
                  <option key={model.id} value={model.id} disabled={!model.available}>
                    {model.name}
                    {model.premium && ' 👑'}
                    {!model.available && ' (Coming Soon)'}
                  </option>
                ))}
              </select>
              <ChevronDown className="absolute right-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-terminal-muted pointer-events-none" />
            </div>
          </div>

          {/* Controls */}
          <div className="space-y-2">
            <button
              onClick={clearContext}
              className="w-full text-left px-3 py-2 text-sm text-terminal-muted hover:text-terminal-text hover:bg-terminal-surface rounded-lg transition-colors"
            >
              Clear Context
            </button>
            <button
              onClick={restartChat}
              className="w-full text-left px-3 py-2 text-sm text-terminal-muted hover:text-terminal-text hover:bg-terminal-surface rounded-lg transition-colors"
            >
              Restart Chat
            </button>
            <button
              onClick={() => currentSession && exportSession(currentSession.id)}
              className="w-full text-left px-3 py-2 text-sm text-terminal-muted hover:text-terminal-text hover:bg-terminal-surface rounded-lg transition-colors"
              disabled={!currentSession}
            >
              Export Session
            </button>
            <button
              onClick={() => {
                if (confirm('Are you sure you want to wipe all chat data? This cannot be undone.')) {
                  wipeAllData()
                }
              }}
              className="w-full text-left px-3 py-2 text-sm text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded-lg transition-colors"
            >
              Wipe All Data
            </button>
          </div>

          {/* User Controls */}
          <div className="border-t border-terminal-border pt-3 mt-3 space-y-1">
            <Link
              to="/settings"
              className="flex items-center space-x-2 px-3 py-2 text-sm text-terminal-muted hover:text-terminal-text hover:bg-terminal-surface rounded-lg transition-colors"
            >
              <Settings className="w-4 h-4" />
              <span>Settings</span>
            </Link>
            <button
              onClick={handleLogout}
              className="w-full flex items-center space-x-2 px-3 py-2 text-sm text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded-lg transition-colors"
            >
              <LogOut className="w-4 h-4" />
              <span>Logout</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-h-screen overflow-x-hidden w-full min-w-0">
        {children}
      </div>
    </div>
  )
}

export default ChatLayout