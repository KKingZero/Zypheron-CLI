import React, { useState, useEffect } from 'react'
import { CreditCard, ToggleLeft, ToggleRight, X } from 'lucide-react'
import { canShowAdminDevFeatures } from '../utils/devMode'

type PlanType = 'light' | 'pro' | 'enterprise'

interface Plan {
  id: PlanType
  name: string
  color: string
}

const PLANS: Plan[] = [
  { id: 'light', name: 'Light', color: 'text-blue-400' },
  { id: 'pro', name: 'Pro', color: 'text-red-400' },
  { id: 'enterprise', name: 'Enterprise', color: 'text-purple-400' }
]

interface DevPlanSelectorProps {
  isVisible?: boolean
  onClose?: () => void
}

const DevPlanSelector: React.FC<DevPlanSelectorProps> = ({ isVisible, onClose }) => {
  const [showSelector, setShowSelector] = useState(false)
  const [selectedPlan, setSelectedPlan] = useState<PlanType>(() => {
    // Get saved plan from localStorage
    const savedPlan = localStorage.getItem('COBRA_DEV_PLAN')
    return (savedPlan as PlanType) || 'light'
  })

  useEffect(() => {
    // Only show when dev mode is explicitly enabled for security and parent component requests visibility
    if (canShowAdminDevFeatures()) {
      setShowSelector(isVisible ?? false)
      
      // Initialize dev plan in localStorage if not set
      if (!localStorage.getItem('COBRA_DEV_PLAN')) {
        localStorage.setItem('COBRA_DEV_PLAN', 'light')
        ;(window as any).COBRA_DEV_PLAN = 'light'
      } else {
        ;(window as any).COBRA_DEV_PLAN = selectedPlan
      }
    } else {
      setShowSelector(false)
    }
  }, [selectedPlan, isVisible])

  // Re-check dev mode status periodically in case it changes
  useEffect(() => {
    const checkDevMode = () => {
      if (!canShowAdminDevFeatures()) {
        setShowSelector(false)
      }
    }
    
    const interval = setInterval(checkDevMode, 2000)
    return () => clearInterval(interval)
  }, [])

  const handlePlanToggle = (planId: PlanType) => {
    const newPlan = selectedPlan === planId ? 'light' : planId
    setSelectedPlan(newPlan)
    
    // Save to localStorage and global variable
    localStorage.setItem('COBRA_DEV_PLAN', newPlan)
    ;(window as any).COBRA_DEV_PLAN = newPlan
    
    console.log(`🔧 Dev Plan changed to: ${newPlan.toUpperCase()}`)
    
    // Emit custom events for other components to react
    window.dispatchEvent(new CustomEvent('devPlanChanged', {
      detail: { plan: newPlan }
    }));
    
    // Also emit storage event for broader compatibility
    window.dispatchEvent(new StorageEvent('storage', {
      key: 'COBRA_DEV_PLAN',
      newValue: newPlan,
      oldValue: selectedPlan,
      storageArea: localStorage
    }));
    
    // Refresh the page to apply plan changes (still needed for some routing changes)
    setTimeout(() => {
      window.location.reload()
    }, 500)
  }

  const isPlanActive = (planId: PlanType) => selectedPlan === planId

  if (!showSelector) return null

  return (
    <div className="fixed bottom-36 right-4 z-40">
      <div className="bg-gray-800 border border-gray-600 rounded-lg p-4 shadow-lg min-w-[200px]">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-2">
            <CreditCard className="w-4 h-4 text-gray-400" />
            <span className="text-sm text-gray-300 font-medium">Dev Plan Selector</span>
          </div>
          {onClose && (
            <button
              onClick={onClose}
              className="w-5 h-5 flex items-center justify-center text-gray-400 hover:text-gray-300 hover:bg-gray-700 rounded transition-colors"
              title="Close"
            >
              <X className="w-3 h-3" />
            </button>
          )}
        </div>
        
        <div className="space-y-3">
          {PLANS.map((plan) => (
            <div key={plan.id} className="flex items-center justify-between">
              <span className={`text-sm font-medium ${isPlanActive(plan.id) ? plan.color : 'text-gray-400'}`}>
                {plan.name}
              </span>
              <button
                onClick={() => handlePlanToggle(plan.id)}
                className={`flex items-center transition-colors ${
                  isPlanActive(plan.id) ? plan.color : 'text-gray-500 hover:text-gray-400'
                }`}
                title={`${isPlanActive(plan.id) ? 'Deactivate' : 'Activate'} ${plan.name} plan`}
              >
                {isPlanActive(plan.id) ? (
                  <ToggleRight className="w-5 h-5" />
                ) : (
                  <ToggleLeft className="w-5 h-5" />
                )}
              </button>
            </div>
          ))}
        </div>
        
        <div className="text-xs text-gray-500 mt-3 pt-2 border-t border-gray-600 text-center">
          Active: <span className={PLANS.find(p => p.id === selectedPlan)?.color}>
            {PLANS.find(p => p.id === selectedPlan)?.name}
          </span>
        </div>
      </div>
    </div>
  )
}

export default DevPlanSelector
