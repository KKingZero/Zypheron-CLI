import React, { useState, useEffect } from 'react'
import { Settings, ToggleLeft, ToggleRight } from 'lucide-react'
import { isLocalhost, isDevModeEnabled } from '../utils/devMode'

const DevModeToggle: React.FC = () => {
  const [devModeEnabled, setDevModeEnabled] = useState(() => {
    // Auto-enable on localhost for better UX
    if (isLocalhost()) {
      // Check for existing runtime override first
      const runtimeOverride = (window as any).COBRA_DEV_MODE
      if (typeof runtimeOverride === 'boolean') {
        return runtimeOverride
      }
      // Check localStorage for saved state
      const savedDevMode = localStorage.getItem('COBRA_DEV_MODE')
      if (savedDevMode !== null) {
        return savedDevMode === 'true'
      }
      // Auto-enable dev mode on localhost
      return true
    }
    // Default to OFF for non-localhost
    return false
  })
  const [showToggle, setShowToggle] = useState(false)

  useEffect(() => {
    // Only show dev mode toggle on localhost for security
    if (isLocalhost()) {
      setShowToggle(true)
      
      // Initialize runtime override if not set
      if (typeof (window as any).COBRA_DEV_MODE === 'undefined') {
        const savedDevMode = localStorage.getItem('COBRA_DEV_MODE')
        if (savedDevMode !== null) {
          (window as any).COBRA_DEV_MODE = savedDevMode === 'true'
        } else {
          // Auto-enable dev mode on localhost
          (window as any).COBRA_DEV_MODE = true
          localStorage.setItem('COBRA_DEV_MODE', 'true')
          setDevModeEnabled(true)
          console.log('🔧 Auto-enabled dev mode on localhost')
        }
      }
    }
  }, [])

  const toggleDevMode = () => {
    const newValue = !devModeEnabled;
    setDevModeEnabled(newValue);
    
    // Update the global dev config and save to localStorage
    (window as any).COBRA_DEV_MODE = newValue;
    localStorage.setItem('COBRA_DEV_MODE', newValue.toString());
    
    // Show confirmation
    if (newValue) {
      console.log('🔧 Dev Mode ENABLED - Full bypass activated');
    } else {
      console.log('🔒 Dev Mode DISABLED - Authentication required');
    }
    
    // Emit custom event for other components to react
    window.dispatchEvent(new CustomEvent('devModeToggled', {
      detail: { enabled: newValue }
    }));
    
    // Trigger a page refresh to apply changes (still needed for routing changes)
    setTimeout(() => {
      window.location.reload();
    }, 500);
  };

  if (!showToggle) return null

  return (
    <div className="fixed bottom-4 right-4 z-50">
      <div className="bg-gray-800 border border-gray-600 rounded-lg p-3 shadow-lg">
        <div className="flex items-center space-x-3">
          <Settings className="w-4 h-4 text-gray-400" />
          <span className="text-sm text-gray-300">Dev Mode</span>
          <button
            onClick={toggleDevMode}
            className={`flex items-center transition-colors ${
              devModeEnabled ? 'text-green-400' : 'text-gray-500'
            }`}
            title={devModeEnabled ? 'Disable Dev Mode' : 'Enable Dev Mode'}
          >
            {devModeEnabled ? (
              <ToggleRight className="w-6 h-6" />
            ) : (
              <ToggleLeft className="w-6 h-6" />
            )}
          </button>
        </div>
        <div className="text-xs text-gray-500 mt-1">
          {devModeEnabled ? '🔧 Localhost Access' : '🔒 Auth Required'}
        </div>
      </div>
    </div>
  )
}

export default DevModeToggle 