import React, { useState } from 'react'
import { useAuth } from '../contexts/AuthContext'
import DeveloperBypassBanner from '../components/DeveloperBypassBanner'

/**
 * Example component demonstrating RBAC usage in React
 */
const RBACExamples: React.FC = () => {
  const { 
    user, 
    userPermissions, 
    isDeveloperBypassActive, 
    signIn, 
    extendSession,
    refreshUserInfo 
  } = useAuth()
  
  const [email, setEmail] = useState('shabblezam@gmail.com')
  const [password, setPassword] = useState('')
  const [requestExtended, setRequestExtended] = useState(false)
  const [loading, setLoading] = useState(false)

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    
    try {
      const result = await signIn(email, password, requestExtended)
      if (result.error) {
        alert('Login failed: ' + result.error)
      } else {
        alert('Login successful!')
      }
    } catch (error) {
      alert('Login error: ' + error)
    } finally {
      setLoading(false)
    }
  }

  const handleExtendSession = async () => {
    const result = await extendSession()
    if (result.error) {
      alert('Failed to extend session: ' + result.error)
    } else {
      alert('Session extended successfully!')
      await refreshUserInfo()
    }
  }

  // Role-based feature rendering
  const renderFeaturesByRole = () => {
    if (!userPermissions) return null

    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {/* Basic Features - All Users */}
        <div className="bg-blue-50 p-4 rounded-lg">
          <h3 className="font-bold text-blue-900 mb-2">📱 Basic Features</h3>
          <ul className="text-sm space-y-1">
            <li className={userPermissions.features.basic_chat ? 'text-green-600' : 'text-gray-400'}>
              {userPermissions.features.basic_chat ? '✅' : '❌'} Basic Chat
            </li>
            <li className="text-green-600">✅ User Profile</li>
            <li className="text-green-600">✅ Settings</li>
          </ul>
        </div>

        {/* Analyst Features */}
        <div className="bg-purple-50 p-4 rounded-lg">
          <h3 className="font-bold text-purple-900 mb-2">🔍 Analyst Features</h3>
          <ul className="text-sm space-y-1">
            <li className={userPermissions.features.advanced_pentest ? 'text-green-600' : 'text-gray-400'}>
              {userPermissions.features.advanced_pentest ? '✅' : '❌'} Advanced Pentest
            </li>
            <li className={userPermissions.features.threat_intelligence ? 'text-green-600' : 'text-gray-400'}>
              {userPermissions.features.threat_intelligence ? '✅' : '❌'} Threat Intelligence
            </li>
            <li className={userPermissions.features.premium_osint ? 'text-green-600' : 'text-gray-400'}>
              {userPermissions.features.premium_osint ? '✅' : '❌'} Premium OSINT
            </li>
          </ul>
        </div>

        {/* Admin Features */}
        <div className="bg-red-50 p-4 rounded-lg">
          <h3 className="font-bold text-red-900 mb-2">👑 Admin Features</h3>
          <ul className="text-sm space-y-1">
            <li className={userPermissions.features.admin_panel ? 'text-green-600' : 'text-gray-400'}>
              {userPermissions.features.admin_panel ? '✅' : '❌'} Admin Panel
            </li>
            <li className={userPermissions.features.user_management ? 'text-green-600' : 'text-gray-400'}>
              {userPermissions.features.user_management ? '✅' : '❌'} User Management
            </li>
            <li className={userPermissions.features.system_monitoring ? 'text-green-600' : 'text-gray-400'}>
              {userPermissions.features.system_monitoring ? '✅' : '❌'} System Monitoring
            </li>
          </ul>
        </div>

        {/* Developer Features */}
        {userPermissions.role === 'admin_dev' && (
          <div className="bg-yellow-50 p-4 rounded-lg border-2 border-yellow-400">
            <h3 className="font-bold text-yellow-900 mb-2">🔧 Developer Features</h3>
            <ul className="text-sm space-y-1">
              <li className="text-green-600">✅ All Features</li>
              <li className="text-green-600">✅ Debug Mode</li>
              <li className="text-green-600">✅ Security Bypass</li>
              <li className="text-green-600">✅ Extended Sessions</li>
            </ul>
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Developer Bypass Banner */}
      <DeveloperBypassBanner />

      <div className="container mx-auto px-4 py-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-8">
          🔐 RBAC System Demo
        </h1>

        {!user ? (
          /* Login Form */
          <div className="max-w-md mx-auto bg-white rounded-lg shadow-md p-6">
            <h2 className="text-2xl font-bold mb-6">Login</h2>
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Email
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Password
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
                />
              </div>

              <div className="flex items-center">
                <input
                  type="checkbox"
                  id="requestExtended"
                  checked={requestExtended}
                  onChange={(e) => setRequestExtended(e.target.checked)}
                  className="mr-2"
                />
                <label htmlFor="requestExtended" className="text-sm text-gray-700">
                  Request extended session (admin_dev only)
                </label>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50"
              >
                {loading ? 'Logging in...' : 'Login'}
              </button>
            </form>

            <div className="mt-4 p-3 bg-gray-100 rounded text-sm">
              <p className="font-medium">Test Accounts:</p>
              <p>• Admin Dev: shabblezam@gmail.com</p>
              <p>• Regular User: test@example.com</p>
            </div>
          </div>
        ) : (
          /* User Dashboard */
          <div className="space-y-8">
            {/* User Info */}
            <div className="bg-white rounded-lg shadow-md p-6">
              <h2 className="text-2xl font-bold mb-4">User Information</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <p><strong>Email:</strong> {user.email}</p>
                  <p><strong>Role:</strong> 
                    <span className={`ml-2 px-2 py-1 rounded text-sm font-medium ${
                      userPermissions?.role === 'admin_dev' ? 'bg-yellow-100 text-yellow-800' :
                      userPermissions?.role === 'admin' ? 'bg-red-100 text-red-800' :
                      userPermissions?.role === 'analyst' ? 'bg-purple-100 text-purple-800' :
                      'bg-blue-100 text-blue-800'
                    }`}>
                      {userPermissions?.role?.toUpperCase()}
                    </span>
                  </p>
                  <p><strong>Bypass Active:</strong> 
                    <span className={`ml-2 ${isDeveloperBypassActive ? 'text-yellow-600' : 'text-gray-600'}`}>
                      {isDeveloperBypassActive ? '🔧 YES' : '❌ NO'}
                    </span>
                  </p>
                </div>
                <div>
                  <p><strong>Max Session:</strong> {userPermissions?.maxSessionHours}h</p>
                  <p><strong>MFA Bypass:</strong> {userPermissions?.canBypassMFA ? '✅' : '❌'}</p>
                  <p><strong>Unlimited Tokens:</strong> {userPermissions?.hasUnlimitedTokens ? '✅' : '❌'}</p>
                  <p><strong>Can Extend Session:</strong> {userPermissions?.canExtendSession ? '✅' : '❌'}</p>
                </div>
              </div>

              {userPermissions?.canExtendSession && (
                <div className="mt-4">
                  <button
                    onClick={handleExtendSession}
                    className="bg-yellow-600 text-white px-4 py-2 rounded hover:bg-yellow-700"
                  >
                    🔧 Extend Session
                  </button>
                </div>
              )}
            </div>

            {/* Features by Role */}
            <div className="bg-white rounded-lg shadow-md p-6">
              <h2 className="text-2xl font-bold mb-4">Available Features</h2>
              {renderFeaturesByRole()}
            </div>

            {/* Code Examples */}
            <div className="bg-white rounded-lg shadow-md p-6">
              <h2 className="text-2xl font-bold mb-4">Code Examples</h2>
              <div className="space-y-4">
                <div>
                  <h3 className="font-semibold mb-2">Role-based Conditional Rendering:</h3>
                  <pre className="bg-gray-100 p-4 rounded text-sm overflow-x-auto">
{`// Show admin panel only to admin and admin_dev
{['admin', 'admin_dev'].includes(userPermissions?.role) && (
  <AdminPanel />
)}

// Show feature based on permission
{userPermissions?.features.advanced_pentest && (
  <AdvancedPentestTools />
)}

// Check developer bypass
{isDeveloperBypassActive && (
  <DeveloperBypassBanner />
)}`}
                  </pre>
                </div>

                <div>
                  <h3 className="font-semibold mb-2">Extended Session Login:</h3>
                  <pre className="bg-gray-100 p-4 rounded text-sm overflow-x-auto">
{`// Request extended session for admin_dev
const result = await signIn(email, password, true)

// Extend existing session
const extendResult = await extendSession()`}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default RBACExamples
