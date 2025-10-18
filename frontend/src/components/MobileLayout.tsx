import React, { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { useChat } from '../contexts/ChatContext'
import { useAuth } from '../contexts/AuthContext'
import { useSubscriptionAccess } from '../hooks/useSubscriptionAccess'
import {
  Shield,
  Search,
  ChevronDown,
  MessageSquare,
  Cloud,
  Crown,
  FileSearch,
  Target,
  Menu,
  X,
  Settings,
  LogOut
} from 'lucide-react'

interface MobileLayoutProps {
  children: React.ReactNode
}

interface ModelInfo {
  id: string
  name: string
  available: boolean
  premium?: boolean
}

const MobileLayout: React.FC<MobileLayoutProps> = ({ children }) => {
  const navigate = useNavigate()
  const location = useLocation()
  const { signOut } = useAuth()
  const { hasAccess, isDeveloper } = useSubscriptionAccess()
  const { currentModel, switchModel } = useChat()
  
  const [showMobileMenu, setShowMobileMenu] = useState(false)

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
      color: 'text-zypheron-400'
    },
    { 
      path: '/red-team-ops', 
      name: 'Red Team Ops', 
      icon: Target,
      color: 'text-red-400'
    },
    { 
      path: '/command-control', 
      name: 'Command & Control', 
      icon: Search,
      color: 'text-green-400'
    }
  ]

  const handleLogout = async () => {
    try {
      await signOut()
      navigate('/login')
    } catch (error) {
      console.error('Logout error:', error)
    }
  }

  return (
    <div className="min-h-screen bg-terminal-bg text-terminal-text flex flex-col">
      {/* Mobile Header */}
      <div className="lg:hidden bg-[#1a1a1a] border-b border-terminal-border p-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <img 
            src="/ZypheronX.jpg" 
            alt="Zypheron" 
            className="w-6 h-6"
            onError={(e) => e.currentTarget.src = "/ZypheronX.jpg"}
          />
          <h1 className="text-lg font-orbitron font-bold text-zypheron-500">Zypheron</h1>
        </div>
        <button
          onClick={() => setShowMobileMenu(!showMobileMenu)}
          className="p-2 text-terminal-text hover:text-zypheron-500 transition-colors"
        >
          {showMobileMenu ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
        </button>
      </div>

      {/* Mobile Menu Overlay */}
      {showMobileMenu && (
        <div className="lg:hidden fixed inset-0 z-50 bg-black/50" onClick={() => setShowMobileMenu(false)}>
          <div className="bg-[#1a1a1a] w-80 h-full border-r border-terminal-border p-4" onClick={(e) => e.stopPropagation()}>
            {/* Navigation */}
            <div className="mb-6">
              <h2 className="text-sm font-medium text-terminal-muted mb-3">Navigation</h2>
              <div className="space-y-2">
                {navigationItems.map((item) => {
                  const Icon = item.icon
                  const isActive = location.pathname === item.path || 
                                 (item.path === '/dashboard' && (location.pathname === '/' || location.pathname === '/chat'))
                  
                  return (
                    <button
                      key={item.path}
                      onClick={() => {
                        navigate(item.path)
                        setShowMobileMenu(false)
                      }}
                      className={`
                        w-full flex items-center space-x-3 px-3 py-3 rounded-lg transition-colors
                        ${isActive 
                          ? 'bg-zypheron-500 text-white' 
                          : 'text-terminal-muted hover:text-terminal-text hover:bg-terminal-surface'
                        }
                      `}
                    >
                      <Icon className="w-5 h-5" />
                      <span className="font-medium">{item.name}</span>
                    </button>
                  )
                })}
              </div>
            </div>

            {/* Cloud AI Model Selector */}
            <div className="mb-6">
              <h3 className="text-sm font-medium text-terminal-muted mb-3">Cloud AI Model</h3>
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

            {/* User Controls */}
            <div className="border-t border-terminal-border pt-4 space-y-2">
              <button
                onClick={() => {
                  navigate('/settings')
                  setShowMobileMenu(false)
                }}
                className="w-full flex items-center space-x-3 px-3 py-2 text-terminal-muted hover:text-terminal-text hover:bg-terminal-surface rounded-lg transition-colors"
              >
                <Settings className="w-5 h-5" />
                <span>Settings</span>
              </button>
              <button
                onClick={handleLogout}
                className="w-full flex items-center space-x-3 px-3 py-2 text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded-lg transition-colors"
              >
                <LogOut className="w-5 h-5" />
                <span>Logout</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Main Tools Grid (Mobile) */}
      <div className="lg:hidden px-4 py-6">
        <h2 className="text-xl font-bold text-terminal-text mb-6 text-center">Security Tools</h2>
        <div className="grid grid-cols-2 gap-4 mb-6">
          {navigationItems.map((item) => {
            const Icon = item.icon
            const isActive = location.pathname === item.path
            
            return (
              <button
                key={item.path}
                onClick={() => navigate(item.path)}
                className={`
                  flex flex-col items-center justify-center p-6 rounded-xl border-2 transition-all
                  ${isActive
                    ? 'bg-zypheron-500/20 border-zypheron-500 text-zypheron-400'
                    : 'bg-terminal-surface border-terminal-border text-terminal-muted hover:text-terminal-text hover:border-terminal-border'
                  }
                `}
              >
                <Icon className={`w-8 h-8 mb-3 ${item.color}`} />
                <span className="text-sm font-medium text-center">{item.name}</span>
              </button>
            )
          })}
        </div>

        {/* Quick Model Selector */}
        <div className="bg-terminal-surface rounded-lg p-4 border border-terminal-border">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-medium text-terminal-text">Current AI Model</h3>
            <Cloud className="w-4 h-4 text-zypheron-500" />
          </div>
          <div className="relative">
            <select
              value={currentModel}
              onChange={(e) => switchModel(e.target.value)}
              className="w-full bg-terminal-bg border border-terminal-border rounded-lg px-3 py-2 text-terminal-text appearance-none cursor-pointer pr-10 text-sm"
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
      </div>

      {/* Main Content */}
      <div className="flex-1">
        {children}
      </div>
    </div>
  )
}

export default MobileLayout