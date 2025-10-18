import React, { useState, useEffect } from 'react'
import { Settings, Shield, Zap } from 'lucide-react'
import { getDevInfo, hasLocalhostAccess, shouldBypassAuth, canShowAdminDevFeatures, getSelectedDevPlan, getMockAccessLevel } from '../utils/devMode'

interface DevDebugInfoProps {
  onTogglePlanSelector?: () => void
}

const DevDebugInfo: React.FC<DevDebugInfoProps> = ({ onTogglePlanSelector }) => {
  const [showDebug, setShowDebug] = useState(false)
  const [debugInfo, setDebugInfo] = useState<any>(null)

  useEffect(() => {
    // Only show when dev mode is explicitly enabled for security
    if (canShowAdminDevFeatures()) {
      setShowDebug(true)
      updateDebugInfo()
      
      // Update debug info every second
      const interval = setInterval(updateDebugInfo, 1000)
      return () => clearInterval(interval)
    } else {
      setShowDebug(false)
    }
  }, [])

  // Re-check dev mode status periodically in case it changes
  useEffect(() => {
    const checkDevMode = () => {
      if (!canShowAdminDevFeatures()) {
        setShowDebug(false)
      }
    }
    
    const interval = setInterval(checkDevMode, 2000)
    return () => clearInterval(interval)
  }, [])

  const updateDebugInfo = () => {
    const mockAccess = getMockAccessLevel()
    setDebugInfo({
      ...getDevInfo(),
      hasLocalhostAccess: hasLocalhostAccess(),
      shouldBypassAuth: shouldBypassAuth(),
      selectedDevPlan: getSelectedDevPlan(),
      mockAccess: mockAccess,
      timestamp: new Date().toLocaleTimeString()
    })
  }

  if (!showDebug || !debugInfo) return null

  return (
    <div className="fixed bottom-20 right-4 z-40 max-w-sm">
      <div className="bg-black/90 border border-gray-600 rounded-lg p-3 text-xs text-white">
        <div className="font-bold mb-2 text-green-400">🐛 Dev Debug Info</div>
        <div className="space-y-1">
          <div className="flex justify-between">
            <span>Localhost:</span>
            <span className={debugInfo.isLocalhost ? 'text-green-400' : 'text-red-400'}>
              {debugInfo.isLocalhost ? '✅' : '❌'}
            </span>
          </div>
          <div className="flex justify-between">
            <span>Dev Mode:</span>
            <span className={debugInfo.runtimeOverride ? 'text-green-400' : 'text-red-400'}>
              {debugInfo.runtimeOverride ? '✅ ON' : '❌ OFF'}
            </span>
          </div>
          <div className="flex justify-between">
            <span>Full Access:</span>
            <span className={debugInfo.hasLocalhostAccess ? 'text-green-400' : 'text-red-400'}>
              {debugInfo.hasLocalhostAccess ? '✅' : '❌'}
            </span>
          </div>
          
          {/* Plan Information */}
          <div className="border-t border-gray-600 pt-2 mt-2">
            <div className="flex justify-between items-center mb-1">
              <button
                onClick={onTogglePlanSelector}
                className="flex items-center space-x-1 text-blue-400 hover:text-blue-300 hover:bg-blue-500/10 px-1 py-0.5 rounded transition-colors cursor-pointer"
                title="Click to open Dev Plan Selector"
              >
                <Settings className="w-3 h-3" />
                <span>Dev Plan:</span>
              </button>
              <span className={`capitalize font-medium ${
                debugInfo.selectedDevPlan === 'enterprise' ? 'text-purple-400' :
                debugInfo.selectedDevPlan === 'pro' ? 'text-red-400' : 'text-blue-400'
              }`}>
                {debugInfo.selectedDevPlan}
              </span>
            </div>
            
            {/* Usage Stats */}
            {debugInfo.mockAccess && (
              <div className="text-xs space-y-1">
                <div className="flex justify-between">
                  <span className="flex items-center space-x-1">
                    <Zap className="w-3 h-3 text-yellow-400" />
                    <span>Tokens:</span>
                  </span>
                  <span className="text-yellow-400">
                    {debugInfo.mockAccess.limits.tokens_total === -1 ? 
                      'Unlimited' : 
                      `${debugInfo.mockAccess.limits.tokens_remaining.toLocaleString()}/${debugInfo.mockAccess.limits.tokens_total.toLocaleString()}`
                    }
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="flex items-center space-x-1">
                    <Shield className="w-3 h-3 text-green-400" />
                    <span>Scans:</span>
                  </span>
                  <span className="text-green-400">
                    {debugInfo.mockAccess.limits.scans === -1 ? 
                      'Unlimited' : 
                      `${debugInfo.mockAccess.limits.scans - (debugInfo.mockAccess.limits.scans_used || 0)}/${debugInfo.mockAccess.limits.scans}`
                    }
                  </span>
                </div>
              </div>
            )}
          </div>
          
          <div className="text-gray-400 text-center mt-2 pt-2 border-t border-gray-600">
            {debugInfo.timestamp}
          </div>
        </div>
      </div>
    </div>
  )
}

export default DevDebugInfo 