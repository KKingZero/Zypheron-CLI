import React, { useState } from 'react'
import { useAuth } from '../contexts/AuthContext'

const DeveloperBypassBanner: React.FC = () => {
  const { userPermissions, isDeveloperBypassActive, extendSession, refreshUserInfo } = useAuth()
  const [isExtending, setIsExtending] = useState(false)
  const [showDetails, setShowDetails] = useState(false)

  if (!isDeveloperBypassActive || userPermissions?.role !== 'admin_dev') {
    return null
  }

  const handleExtendSession = async () => {
    setIsExtending(true)
    try {
      const result = await extendSession()
      if (result.error) {
        console.error('Failed to extend session:', result.error)
        alert('Failed to extend session: ' + result.error)
      } else {
        await refreshUserInfo()
        alert('Session extended successfully!')
      }
    } catch (error) {
      console.error('Session extension error:', error)
      alert('Error extending session')
    } finally {
      setIsExtending(false)
    }
  }

  return (
    <div className="bg-gradient-to-r from-yellow-400 via-orange-500 to-red-500 text-white py-2 px-4 shadow-lg">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-white rounded-full animate-pulse"></div>
            <span className="font-bold text-lg">🔧 DEVELOPER BYPASS ACTIVE</span>
          </div>
          
          <div className="text-sm opacity-90">
            Role: {userPermissions?.role?.toUpperCase()} | 
            Session: {userPermissions?.maxSessionHours}h | 
            MFA: {userPermissions?.canBypassMFA ? 'BYPASSED' : 'REQUIRED'}
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => setShowDetails(!showDetails)}
            className="px-3 py-1 bg-white bg-opacity-20 hover:bg-opacity-30 rounded text-sm font-medium transition-all duration-200"
          >
            {showDetails ? 'Hide' : 'Details'}
          </button>
          
          {userPermissions?.canExtendSession && (
            <button
              onClick={handleExtendSession}
              disabled={isExtending}
              className="px-3 py-1 bg-white bg-opacity-20 hover:bg-opacity-30 rounded text-sm font-medium transition-all duration-200 disabled:opacity-50"
            >
              {isExtending ? 'Extending...' : 'Extend Session'}
            </button>
          )}
          
          <div className="text-xs opacity-75">
            Security Override Enabled
          </div>
        </div>
      </div>

      {showDetails && (
        <div className="mt-3 p-3 bg-black bg-opacity-20 rounded-lg text-sm">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <h4 className="font-semibold mb-2">🛡️ Security Bypasses</h4>
              <ul className="space-y-1 text-xs">
                <li>✅ MFA Bypass: {userPermissions?.canBypassMFA ? 'Enabled' : 'Disabled'}</li>
                <li>⏰ Extended Sessions: {userPermissions?.canExtendSession ? 'Enabled' : 'Disabled'}</li>
                <li>🚀 Unlimited Tokens: {userPermissions?.hasUnlimitedTokens ? 'Yes' : 'No'}</li>
              </ul>
            </div>
            
            <div>
              <h4 className="font-semibold mb-2">🎯 Available Features</h4>
              <ul className="space-y-1 text-xs">
                {Object.entries(userPermissions?.features || {}).map(([key, enabled]) => (
                  <li key={key}>
                    {enabled ? '✅' : '❌'} {key.replace(/_/g, ' ').toUpperCase()}
                  </li>
                ))}
              </ul>
            </div>
            
            <div>
              <h4 className="font-semibold mb-2">⚠️ Security Notice</h4>
              <p className="text-xs opacity-90">
                This bypass is for development purposes only. All actions are logged for security auditing.
                Do not use in production environments.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default DeveloperBypassBanner
