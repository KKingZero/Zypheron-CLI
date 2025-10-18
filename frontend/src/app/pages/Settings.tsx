import React from 'react'
import { useNavigate } from 'react-router-dom'
import { 
  Settings as SettingsIcon, 
  User, 
  CreditCard, 
  Shield, 
  ArrowLeft,
  Check,
  Lock,
  Crown,
  Zap,
  Database,
  RefreshCw,
  Trash2,
  Eye,
  HardDrive,
  XCircle
} from 'lucide-react'
import zypheronLogo from '../../ZypheronX.jpg'
import { useSubscriptionAccess } from '../../hooks/useSubscriptionAccess'
import SubscriptionAccessVerifier from '../../components/SubscriptionAccessVerifier'

const Settings: React.FC = () => {
  const navigate = useNavigate()
  const { hasAccess, isDeveloper, planName, loading } = useSubscriptionAccess()

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-800 text-white">
      <div className="max-w-4xl mx-auto px-6 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center space-x-4">
            <button
              onClick={() => navigate(-1)}
              className="p-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
            </button>
            <div className="flex items-center space-x-3">
              <img 
                src={zypheronLogo} 
                alt="Zypheron Logo" 
                className="w-10 h-10 object-contain"
                onError={(e) => {
                  e.currentTarget.src = "/ZypheronX.jpg";
                }}
              />
              <div>
                <h1 className="text-2xl font-bold text-zypheron-500 font-orbitron">Settings</h1>
                <p className="text-sm text-gray-400">Manage Zypheron</p>
              </div>
            </div>
          </div>
        </div>

        <div className="grid lg:grid-cols-3 gap-8">
          {/* Main Settings */}
          <div className="lg:col-span-2 space-y-6">
            {/* Account Information */}
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <div className="flex items-center space-x-3 mb-4">
                <User className="w-5 h-5 text-zypheron-500" />
                <h2 className="text-xl font-semibold">Account Information</h2>
              </div>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Email</label>
                  <div className="text-white">Loading...</div>
                </div>
                
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Current Plan</label>
                  <div className="flex items-center space-x-2">
                    <span className="text-white">{loading ? 'Loading...' : planName}</span>
                    {isDeveloper && (
                      <span className="px-2 py-1 bg-green-500/20 text-green-400 text-xs rounded-full">
                        🔧 Developer
                      </span>
                    )}
                    {!hasAccess && !isDeveloper && !loading && (
                      <span className="px-2 py-1 bg-red-500/20 text-red-400 text-xs rounded-full">
                        No Access
                      </span>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* Subscription Tier Management */}
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center space-x-3">
                  <CreditCard className="w-5 h-5 text-zypheron-500" />
                  <h2 className="text-xl font-semibold">Subscription Management</h2>
                </div>
                <button
                  onClick={() => navigate('/billing')}
                  className="px-4 py-2 bg-zypheron-500 hover:bg-zypheron-600 text-white rounded-lg text-sm transition-colors"
                >
                  Manage Billing
                </button>
              </div>
              
              <p className="text-gray-400 text-sm mb-6">
                Choose your subscription tier to unlock different features and capabilities. 
                Your current active tier determines which tools and limits are available.
              </p>

              <div className="space-y-4">
                {/* Light Tier */}
                <div className="p-4 rounded-lg border-2 border-blue-400 bg-blue-400 bg-opacity-10">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start space-x-3">
                      <div className="p-2 rounded-lg bg-blue-500/20">
                        <Shield className="w-5 h-5 text-blue-400" />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-2">
                          <h3 className="text-lg font-semibold">Light</h3>
                          <Check className="w-5 h-5 text-green-400" />
                        </div>
                        <ul className="space-y-1">
                          <li className="text-sm text-gray-300 flex items-center space-x-2">
                            <Check className="w-3 h-3 text-green-400 flex-shrink-0" />
                            <span>Stage 1 Security Tools</span>
                          </li>
                          <li className="text-sm text-gray-300 flex items-center space-x-2">
                            <Check className="w-3 h-3 text-green-400 flex-shrink-0" />
                            <span>Basic AI Chat</span>
                          </li>
                          <li className="text-sm text-gray-300 flex items-center space-x-2">
                            <Check className="w-3 h-3 text-green-400 flex-shrink-0" />
                            <span>Vulnerability Scanning</span>
                          </li>
                          <li className="text-sm text-gray-300 flex items-center space-x-2">
                            <Check className="w-3 h-3 text-green-400 flex-shrink-0" />
                            <span>100K Total Tokens</span>
                          </li>
                          <li className="text-sm text-gray-300 flex items-center space-x-2">
                            <Check className="w-3 h-3 text-green-400 flex-shrink-0" />
                            <span>Standard Support</span>
                          </li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Pro Tier */}
                <div className="p-4 rounded-lg border-2 border-gray-700 bg-gray-800/50 opacity-60 cursor-not-allowed">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start space-x-3">
                      <div className="p-2 rounded-lg bg-gray-600">
                        <Zap className="w-5 h-5" />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-2">
                          <h3 className="text-lg font-semibold">Pro</h3>
                          <Lock className="w-4 h-4 text-gray-500" />
                        </div>
                        <ul className="space-y-1">
                          <li className="text-sm text-gray-300 flex items-center space-x-2">
                            <Check className="w-3 h-3 text-green-400 flex-shrink-0" />
                            <span>Stage 1-2 Security Tools</span>
                          </li>
                          <li className="text-sm text-gray-300 flex items-center space-x-2">
                            <Check className="w-3 h-3 text-green-400 flex-shrink-0" />
                            <span>Advanced AI Analysis</span>
                          </li>
                          <li className="text-sm text-gray-300 flex items-center space-x-2">
                            <Check className="w-3 h-3 text-green-400 flex-shrink-0" />
                            <span>Custom Wordlists</span>
                          </li>
                          <li className="text-sm text-gray-300 flex items-center space-x-2">
                            <Check className="w-3 h-3 text-green-400 flex-shrink-0" />
                            <span>1M Total Tokens</span>
                          </li>
                          <li className="text-sm text-gray-300 flex items-center space-x-2">
                            <Check className="w-3 h-3 text-green-400 flex-shrink-0" />
                            <span>Priority Support</span>
                          </li>
                          <li className="text-sm text-gray-300 flex items-center space-x-2">
                            <Check className="w-3 h-3 text-green-400 flex-shrink-0" />
                            <span>Export Reports</span>
                          </li>
                        </ul>
                      </div>
                    </div>
                  </div>
                  <div className="mt-3 pt-3 border-t border-gray-600">
                    <button
                      onClick={() => navigate('/billing')}
                      className="text-sm text-zypheron-500 hover:text-zypheron-400 transition-colors"
                    >
                      Upgrade to unlock →
                    </button>
                  </div>
                </div>

                {/* Enterprise Tier */}
                <div className="p-4 rounded-lg border-2 border-gray-700 bg-gray-800/50 opacity-60 cursor-not-allowed">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start space-x-3">
                      <div className="p-2 rounded-lg bg-gray-600">
                        <Crown className="w-5 h-5" />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-2">
                          <h3 className="text-lg font-semibold">Enterprise</h3>
                          <Lock className="w-4 h-4 text-gray-500" />
                        </div>
                        <ul className="space-y-1">
                          <li className="text-sm text-gray-300 flex items-center space-x-2">
                            <Check className="w-3 h-3 text-green-400 flex-shrink-0" />
                            <span>All Security Tools (Stage 1-3)</span>
                          </li>
                          <li className="text-sm text-gray-300 flex items-center space-x-2">
                            <Check className="w-3 h-3 text-green-400 flex-shrink-0" />
                            <span>Unlimited AI Access</span>
                          </li>
                          <li className="text-sm text-gray-300 flex items-center space-x-2">
                            <Check className="w-3 h-3 text-green-400 flex-shrink-0" />
                            <span>Custom Models</span>
                          </li>
                          <li className="text-sm text-gray-300 flex items-center space-x-2">
                            <Check className="w-3 h-3 text-green-400 flex-shrink-0" />
                            <span>Unlimited Tokens</span>
                          </li>
                          <li className="text-sm text-gray-300 flex items-center space-x-2">
                            <Check className="w-3 h-3 text-green-400 flex-shrink-0" />
                            <span>Dedicated Support</span>
                          </li>
                          <li className="text-sm text-gray-300 flex items-center space-x-2">
                            <Check className="w-3 h-3 text-green-400 flex-shrink-0" />
                            <span>On-Premise Options</span>
                          </li>
                          <li className="text-sm text-gray-300 flex items-center space-x-2">
                            <Check className="w-3 h-3 text-green-400 flex-shrink-0" />
                            <span>Advanced Integrations</span>
                          </li>
                        </ul>
                      </div>
                    </div>
                  </div>
                  <div className="mt-3 pt-3 border-t border-gray-600">
                    <button
                      onClick={() => navigate('/billing')}
                      className="text-sm text-zypheron-500 hover:text-zypheron-400 transition-colors"
                    >
                      Upgrade to unlock →
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Subscription Access Verification */}
            <SubscriptionAccessVerifier />

            {/* Cache Management */}
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <div className="flex items-center space-x-3 mb-6">
                <Database className="w-5 h-5 text-zypheron-500" />
                <h2 className="text-xl font-semibold">Cache Management</h2>
              </div>
              
              <p className="text-gray-400 text-sm mb-6">
                Debug and manage pentest result cache and local storage data.
              </p>

              {/* Cache Status */}
              <div className="mb-6">
                <h3 className="text-lg font-semibold mb-4">Cache Status</h3>
                <div className="bg-gray-900 rounded-lg p-4 border border-gray-600">
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-400">Session ID:</span>
                      <span className="text-sm text-red-400 font-mono">
                        session-{Date.now().toString().slice(-12)}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-400">Has Cache:</span>
                      <span className="text-sm text-red-400">No</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Cache Actions */}
              <div className="grid md:grid-cols-2 gap-4">
                <button
                  onClick={() => {
                    // Get cached pentest results
                    const cache = localStorage.getItem('zypheron-pentest-cache')
                    if (cache) {
                      try {
                        const data = JSON.parse(cache)
                        const info = `Target: ${data.target || 'Unknown'}\nSession: ${data.sessionId || 'Unknown'}\nTimestamp: ${data.timestamp ? new Date(data.timestamp).toLocaleString() : 'Unknown'}\nData: ${JSON.stringify(data.results || {}, null, 2)}`
                        alert(info)
                      } catch (e) {
                        alert('Cache data found but corrupted')
                      }
                    } else {
                      alert('No pentest cache found for current session')
                    }
                  }}
                  className="flex items-center justify-center space-x-2 p-3 bg-gray-700 hover:bg-gray-600 border border-gray-600 text-white rounded-lg transition-colors"
                >
                  <Eye className="w-4 h-4" />
                  <span>View Full Cache Data</span>
                </button>

                <button
                  onClick={() => {
                    if (confirm('Are you sure you want to clear the pentest cache?')) {
                      localStorage.removeItem('zypheron-pentest-cache')
                      alert('Pentest cache cleared')
                    }
                  }}
                  className="flex items-center justify-center space-x-2 p-3 bg-red-600/20 border border-red-600/30 text-red-400 rounded-lg hover:bg-red-600/30 transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                  <span>Clear Cache</span>
                </button>

                <button
                  onClick={() => {
                    const localStorage = window.localStorage
                    const keys = Object.keys(localStorage).filter(key => key.startsWith('zypheron-'))
                    const info = keys.map(key => `${key}: ${localStorage[key]?.length || 0} chars`).join('\n')
                    alert(`LocalStorage Keys:\n${info || 'No Zypheron data found'}`)
                  }}
                  className="flex items-center justify-center space-x-2 p-3 bg-gray-700 hover:bg-gray-600 border border-gray-600 text-white rounded-lg transition-colors"
                >
                  <HardDrive className="w-4 h-4" />
                  <span>View localStorage</span>
                </button>

                <button
                  onClick={() => {
                    // Refresh cache (simulate)
                    const newSessionId = `session-${Date.now().toString().slice(-12)}`
                    alert(`Cache refreshed with new session: ${newSessionId}`)
                  }}
                  className="flex items-center justify-center space-x-2 p-3 bg-blue-600/20 border border-blue-600/30 text-blue-400 rounded-lg hover:bg-blue-600/30 transition-colors"
                >
                  <RefreshCw className="w-4 h-4" />
                  <span>Refresh Cache</span>
                </button>
              </div>

              {/* Advanced Cache Options */}
              <div className="mt-6 pt-6 border-t border-gray-700">
                <h3 className="text-lg font-semibold mb-4">Advanced Options</h3>
                <div className="space-y-3">
                  <button
                    onClick={() => {
                      if (confirm('This will clear ALL Zypheron data from localStorage. Continue?')) {
                        const keys = Object.keys(localStorage).filter(key => key.startsWith('zypheron-'))
                        keys.forEach(key => localStorage.removeItem(key))
                        alert(`Cleared ${keys.length} Zypheron storage items`)
                      }
                    }}
                    className="w-full flex items-center justify-center space-x-2 p-3 bg-red-600/20 border border-red-600/30 text-red-400 rounded-lg hover:bg-red-600/30 transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                    <span>Clear All Zypheron Data</span>
                  </button>
                  
                  <button
                    onClick={() => {
                      const data = {
                        userAgent: navigator.userAgent,
                        localStorage: Object.keys(localStorage).filter(key => key.startsWith('zypheron-')),
                        sessionStorage: Object.keys(sessionStorage).filter(key => key.startsWith('zypheron-')),
                        timestamp: new Date().toISOString(),
                        url: window.location.href
                      }
                      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
                      const url = URL.createObjectURL(blob)
                      const a = document.createElement('a')
                      a.href = url
                      a.download = `zypheron-ai-debug-${Date.now()}.json`
                      document.body.appendChild(a)
                      a.click()
                      document.body.removeChild(a)
                      URL.revokeObjectURL(url)
                    }}
                    className="w-full flex items-center justify-center space-x-2 p-3 bg-gray-700 hover:bg-gray-600 border border-gray-600 text-white rounded-lg transition-colors"
                  >
                    <Database className="w-4 h-4" />
                    <span>Export Debug Data</span>
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Sidebar Actions */}
          <div className="space-y-6">
            {/* Quick Actions */}
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h3 className="text-lg font-semibold mb-4">Quick Actions</h3>
              <div className="space-y-3">
                <button
                  onClick={() => navigate('/billing')}
                  className="w-full flex items-center space-x-3 p-3 bg-zypheron-500 hover:bg-zypheron-600 text-white rounded-lg transition-colors"
                >
                  <CreditCard className="w-4 h-4" />
                  <span>Upgrade Subscription</span>
                </button>
                
                <button
                  onClick={() => {
                    if (hasAccess || isDeveloper) {
                      navigate('/dashboard')
                    } else {
                      navigate('/billing')
                    }
                  }}
                  className={`w-full flex items-center space-x-3 p-3 rounded-lg transition-colors ${
                    hasAccess || isDeveloper 
                      ? 'bg-gray-700 hover:bg-gray-600 text-white' 
                      : 'bg-gray-800/50 border border-gray-600 text-gray-400 cursor-not-allowed'
                  }`}
                  disabled={loading}
                >
                  <SettingsIcon className="w-4 h-4" />
                  <span>
                    {hasAccess || isDeveloper ? 'Back to Dashboard' : 'Upgrade Required'}
                  </span>
                </button>
              </div>
            </div>

            {/* Development Mode (Localhost Only) */}
            {typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') && (
              <div className="bg-yellow-900/20 border border-yellow-500 rounded-lg p-6">
                <div className="flex items-center space-x-3 mb-4">
                  <Shield className="w-5 h-5 text-yellow-500" />
                  <h3 className="text-lg font-semibold text-yellow-400">Development Mode</h3>
                </div>
                
                <p className="text-yellow-200 text-sm mb-4">
                  <strong>⚠️ Dev Mode Required:</strong> Since you're on localhost, you need to enable Development Mode to bypass authentication and access chat features.
                </p>
                
                <div className="bg-yellow-900/30 rounded-lg p-4 mb-4">
                  <h4 className="text-yellow-300 font-medium mb-2">How to Enable Dev Mode:</h4>
                  <ol className="text-yellow-200 text-sm space-y-1">
                    <li>1. Look for the "Dev Mode" toggle in the <strong>bottom-right corner</strong> of your screen</li>
                    <li>2. Click the toggle to turn it <strong>ON</strong> (should show green)</li>
                    <li>3. The page will automatically refresh</li>
                    <li>4. You'll then have full access to all chat features</li>
                  </ol>
                </div>
                
                <div className="flex items-center justify-between p-3 bg-gray-800 rounded-lg">
                  <span className="text-sm text-gray-300">Current Dev Mode Status:</span>
                  <span className="text-sm font-mono" id="dev-mode-status">
                    {typeof window !== 'undefined' && (window as any).COBRA_DEV_MODE === true ? (
                      <span className="text-green-400">🟢 ENABLED</span>
                    ) : (
                      <span className="text-red-400">🔴 DISABLED</span>
                    )}
                  </span>
                </div>
                
                <button
                  onClick={() => {
                    if (typeof window !== 'undefined') {
                      (window as any).COBRA_DEV_MODE = true;
                      localStorage.setItem('COBRA_DEV_MODE', 'true');
                      alert('✅ Dev Mode ENABLED! Page will refresh in 1 second...');
                      setTimeout(() => window.location.reload(), 1000);
                    }
                  }}
                  className="w-full mt-3 flex items-center justify-center space-x-2 p-3 bg-yellow-500 hover:bg-yellow-600 text-black rounded-lg transition-colors font-medium"
                >
                  <span>🔧 Enable Dev Mode Now</span>
                </button>
              </div>
            )}

            {/* Legal Documents */}
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h3 className="text-lg font-semibold mb-4">Legal Documents</h3>
              <div className="space-y-3">
                <button
                  onClick={() => navigate('/terms-of-service')}
                  className="w-full flex items-center space-x-3 p-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
                >
                  <Shield className="w-4 h-4" />
                  <span>Terms of Service</span>
                </button>
                
                <button
                  onClick={() => navigate('/terms-of-use')}
                  className="w-full flex items-center space-x-3 p-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
                >
                  <Shield className="w-4 h-4" />
                  <span>Terms of Use</span>
                </button>
                
                <button
                  onClick={async () => {
                    if (confirm('Are you sure you want to sign out?')) {
                      try {
                        // Simple signout - just redirect to home
                        window.location.href = '/'
                      } catch (error) {
                        console.error('Failed to sign out:', error)
                      }
                    }
                  }}
                  className="w-full flex items-center space-x-3 p-3 bg-red-600/20 border border-red-600/30 text-red-400 rounded-lg hover:bg-red-600/30 transition-colors"
                >
                  <ArrowLeft className="w-4 h-4" />
                  <span>Sign Out</span>
                </button>
              </div>
            </div>

            {/* Current Tier Info */}
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h3 className="text-lg font-semibold mb-4">Active Tier</h3>
              <div className="p-4 rounded-lg border-2 border-blue-400 bg-blue-400 bg-opacity-10">
                <div className="flex items-center space-x-3 mb-3">
                  <Shield className="w-5 h-5 text-blue-400" />
                  <span className="font-semibold">Light</span>
                </div>
                <div className="text-sm text-gray-300 mb-4">
                  Currently using Light tier features and limitations.
                </div>
                <button
                  onClick={() => navigate('/billing')}
                  className="w-full flex items-center justify-center space-x-2 p-3 bg-red-600/20 border border-red-600/30 text-red-400 rounded-lg hover:bg-red-600/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  disabled={false}
                >
                  <XCircle className="w-4 h-4" />
                  <span>Manage Subscription</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Settings 