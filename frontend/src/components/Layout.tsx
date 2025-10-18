import React, { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useChat } from '../contexts/ChatContext'
import { useSubscriptionAccess } from '../hooks/useSubscriptionAccess'
import { Shield, MessageSquare, Search, ChevronDown, FileSearch, Menu, X, Target } from 'lucide-react'

interface LayoutProps {
  children: React.ReactNode
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const location = useLocation()
  const { currentModel, switchModel, clearContext, exportSession, currentSession, restartChat, wipeAllData } = useChat()
  const { hasAccess, isDeveloper, canAccessFeature } = useSubscriptionAccess()
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = useState(false)

  const models = [
    { id: 'gpt-4', name: 'GPT-4', available: true },
    { id: 'gpt-3.5-turbo', name: 'GPT-3.5', available: true },
    { id: 'gpt-5', name: 'GPT-5', available: true, premium: true },
    { id: 'claude-4-sonnet', name: 'Claude-4 Sonnet', available: false },
    { id: 'claude-4-opus', name: 'Claude-4 Opus', available: true, premium: true },
    { id: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash', available: false },
    { id: 'gemini-2.5-pro', name: 'Gemini 2.5 Pro', available: false },
    { id: 'grok-3', name: 'Grok 3', available: false },
    { id: 'grok-4', name: 'Grok 4', available: true, premium: true },
  ]

  const navigationItems = [
    { 
      path: '/dashboard', 
      name: 'Chat Dashboard', 
      icon: MessageSquare,
      priority: 1
    },
    { 
      path: '/red-team-ops', 
      name: 'Red Team Ops', 
      icon: Target,
      priority: 2
    },
    { 
      path: '/command-control', 
      name: 'Command & Control', 
      icon: Target,
      priority: 3
    },
  ].sort((a, b) => a.priority - b.priority)

  // Close mobile sidebar when screen size changes
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth >= 1024) {
        setIsMobileSidebarOpen(false)
      }
    }

    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [])

  return (
    <div className="min-h-screen bg-[#0d0d0d] text-terminal-text flex overflow-x-hidden w-full max-w-full">
      {/* Mobile Hamburger Button */}
      <button
        onClick={() => setIsMobileSidebarOpen(!isMobileSidebarOpen)}
        className="lg:hidden fixed top-4 left-4 z-50 p-2 bg-[#1a1a1a] border border-terminal-border rounded-lg text-terminal-text hover:text-zypheron-500 hamburger-button"
      >
        {isMobileSidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
      </button>

      {/* Mobile Overlay */}
      {isMobileSidebarOpen && (
        <div 
          className="lg:hidden fixed inset-0 bg-black/50 z-30 mobile-overlay"
          onClick={() => setIsMobileSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <div className={`
        w-64 bg-[#1a1a1a] border-r border-terminal-border flex flex-col shrink-0
        lg:relative lg:translate-x-0
        fixed inset-y-0 left-0 z-40 transition-transform duration-300 ease-in-out
        mobile-sidebar overflow-x-hidden
        ${isMobileSidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
      `}>
        {/* Logo Header */}
        <div className="p-6 border-b border-terminal-border">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8">
              <img 
                src="/ZypheronX.jpg" 
                alt="Zypheron Logo" 
                className="w-full h-full object-contain"
                onError={(e) => {
                  // Fallback to SVG if PNG doesn't exist
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
        <nav className="flex-1 p-6">
          <div className="space-y-2">
            {navigationItems.map((item) => {
              const Icon = item.icon
              const isActive = location.pathname === item.path || 
                              (item.path === '/dashboard' && (location.pathname === '/' || location.pathname === '/chat'))
              const needsSubscription = !['/settings'].includes(item.path)
              const canAccess = true // Remove subscription checks for dedicated app
              
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`
                    flex items-center space-x-3 px-4 py-3 rounded-lg transition-colors
                    ${isActive 
                      ? 'bg-zypheron-500 text-white' 
                      : canAccess
                        ? 'text-terminal-muted hover:text-terminal-text hover:bg-terminal-surface'
                        : 'text-gray-600 cursor-not-allowed opacity-60'
                    }
                  `}
                  onClick={() => setIsMobileSidebarOpen(false)} // Close mobile sidebar on navigation
                >
                  <Icon className="w-5 h-5" />
                  <span className="font-medium">{item.name}</span>

                </Link>
              )
            })}
          </div>
        </nav>

        {/* AI Model Selector */}
        <div className="p-6 border-t border-terminal-border">
          <div className="mb-4">
            <label className="text-sm text-terminal-muted">AI Model</label>
            <div className="relative">
              <select
                value={currentModel}
                onChange={(e) => {
                  const selectedModel = models.find(m => m.id === e.target.value);
                  // Allow all models in dedicated app
                  if (selectedModel?.premium && !canAccessFeature('premiumModels')) {
                    console.log(`Selected premium model: ${selectedModel.name} - allowing access in dedicated app`);
                  }
                  switchModel(e.target.value);
                }}
                className="w-full bg-terminal-surface border border-terminal-border rounded-lg px-3 py-2 text-terminal-text appearance-none focus:outline-none focus:ring-2 focus:ring-zypheron-500"
              >
                {models.map((model) => (
                  <option key={model.id} value={model.id} disabled={!model.available}>
                    {model.name} {model.premium ? ' 👑' : ''} {!model.available && '(Coming Soon)'}
                  </option>
                ))}
              </select>
              <ChevronDown className="absolute right-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-terminal-muted pointer-events-none" />
            </div>
          </div>

          <div className="space-y-2">
            <button
              onClick={clearContext}
              className="w-full text-left px-3 py-2 text-sm text-terminal-muted hover:text-terminal-text hover:bg-terminal-surface rounded-lg transition-colors"
            >
              Clear Chat
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
              Export Chat
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
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-h-screen overflow-x-hidden w-full min-w-0">
        {children}
      </div>
    </div>
  )
}

export default Layout 