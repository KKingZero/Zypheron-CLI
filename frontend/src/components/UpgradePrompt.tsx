import React from 'react'
import { Crown, ArrowRight, X } from 'lucide-react'
import { motion } from 'framer-motion'

interface UpgradePromptProps {
  message: string
  feature?: string
  onUpgrade?: () => void
  onClose?: () => void
  inline?: boolean
  size?: 'small' | 'medium' | 'large'
}

const UpgradePrompt: React.FC<UpgradePromptProps> = ({
  message,
  feature = 'premium feature',
  onUpgrade,
  onClose,
  inline = false,
  size = 'medium'
}) => {
  const handleUpgrade = () => {
    if (onUpgrade) {
      onUpgrade()
    } else {
      window.open('/billing', '_blank')
    }
  }

  const sizeClasses = {
    small: 'p-3 text-sm',
    medium: 'p-4 text-base',
    large: 'p-6 text-lg'
  }

  const iconSizes = {
    small: 'w-4 h-4',
    medium: 'w-5 h-5',
    large: 'w-6 h-6'
  }

  if (inline) {
    return (
      <div className="bg-gradient-to-r from-amber-500/10 to-orange-500/10 border border-amber-500/30 rounded-lg p-3 my-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-amber-500/20 rounded-lg flex items-center justify-center">
              <Crown className="w-4 h-4 text-amber-400" />
            </div>
            <div>
              <p className="text-amber-200 text-sm font-medium">Premium Feature</p>
              <p className="text-amber-300/80 text-xs">{message}</p>
            </div>
          </div>
          <button
            onClick={handleUpgrade}
            className="px-3 py-1.5 bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 rounded-lg text-amber-300 hover:text-amber-200 transition-colors text-sm font-medium flex items-center space-x-1"
          >
            <span>Upgrade</span>
            <ArrowRight className="w-3 h-3" />
          </button>
        </div>
      </div>
    )
  }

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.95 }}
      className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4"
    >
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className={`bg-[#1a1a1a] border border-amber-500/30 rounded-xl shadow-2xl max-w-md w-full ${sizeClasses[size]}`}
      >
        {onClose && (
          <div className="flex justify-end mb-2">
            <button
              onClick={onClose}
              className="w-6 h-6 flex items-center justify-center rounded-lg bg-gray-500/10 hover:bg-gray-500/20 text-gray-400 hover:text-gray-300 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        <div className="text-center">
          <div className="w-16 h-16 bg-gradient-to-br from-amber-500/20 to-orange-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
            <Crown className={`${iconSizes[size]} text-amber-400`} />
          </div>

          <h3 className="text-xl font-bold text-white mb-2">Premium Feature</h3>
          <p className="text-gray-300 mb-6">{message}</p>

          <div className="flex flex-col sm:flex-row gap-3">
            {onClose && (
              <button
                onClick={onClose}
                className="px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg transition-colors"
              >
                Continue with Basic
              </button>
            )}
            <button
              onClick={handleUpgrade}
              className="px-6 py-2 bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-600 hover:to-orange-600 text-white rounded-lg transition-colors font-medium flex items-center justify-center space-x-2"
            >
              <Crown className="w-4 h-4" />
              <span>Upgrade Now</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </motion.div>
    </motion.div>
  )
}

export default UpgradePrompt
