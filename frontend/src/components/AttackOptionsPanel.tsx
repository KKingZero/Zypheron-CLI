import React, { useState } from 'react';
import { 
  AlertTriangle, Target, Code, Loader, X, Sparkles, Send, 
  ChevronDown, ChevronUp, BrainCircuit 
} from 'lucide-react';
import toast from 'react-hot-toast';
import { motion, AnimatePresence } from 'framer-motion';
import { AttackVector, attackCategories, allAttackVectors } from '../utils/attackVectors';
import { useSubscriptionAccess } from '../hooks/useSubscriptionAccess';
import UpgradePrompt from './UpgradePrompt';

interface AttackOptionsPanelProps {
  targetUrl: string;
  pentestResults?: any;
  onGeneratePayload: (attackType: string, targetUrl: string, customDescription?: string) => void;
  onClose: () => void;
}

const originalAttackIds = ['botnet', 'dos', 'mitm', 'session_hijacking', 'credential_reuse', 'insider_threat'];
const originalAttacks = allAttackVectors.filter(a => originalAttackIds.includes(a.id));

const AttackCard = ({ attack, onAttackClick, loadingAttack, generatingCustom }: {
  attack: AttackVector;
  onAttackClick: (id: string) => void;
  loadingAttack: string | null;
  generatingCustom: boolean;
}) => {
  const getRiskLevelColor = (riskLevel: string) => {
    switch (riskLevel) {
      case 'critical': return 'text-red-500 bg-red-500/10 border-red-500/30';
      case 'high': return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'medium': return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'low': return 'text-green-400 bg-green-500/10 border-green-500/30';
      default: return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
    }
  };

  return (
    <motion.button
      layout
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      transition={{ duration: 0.2 }}
      key={attack.id}
      onClick={() => onAttackClick(attack.id)}
      disabled={loadingAttack !== null || generatingCustom}
      className={`group relative p-3 border rounded-lg text-left transition-all duration-200 hover:border-zypheron-500/50 hover:bg-zypheron-500/5 disabled:opacity-50 disabled:cursor-not-allowed ${loadingAttack === attack.id ? 'border-zypheron-500 bg-zypheron-500/10' : 'border-terminal-border'}`}
    >
      <div className="flex items-start space-x-3">
        <div className={`w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 ${getRiskLevelColor(attack.riskLevel)}`}>
          {loadingAttack === attack.id ? <Loader className="w-3 h-3 animate-spin" /> : React.cloneElement(attack.icon as React.ReactElement, { className: "w-3 h-3" })}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between mb-1">
            <h4 className="font-medium text-white group-hover:text-zypheron-400 transition-colors text-sm">{attack.name}</h4>
            <span className={`px-1.5 py-0.5 text-xs rounded border text-right flex-shrink-0 ${getRiskLevelColor(attack.riskLevel)}`}>{attack.riskLevel.toUpperCase()}</span>
          </div>
          <p className="text-xs text-terminal-muted mb-2 line-clamp-2">{attack.description}</p>
          <div className="flex items-center justify-between">
            {attack.osint && (
              <span className="flex items-center space-x-1 text-xs text-cyan-400 bg-cyan-500/10 px-1.5 py-0.5 rounded">
                <BrainCircuit className="w-3 h-3" />
                <span>OSINT</span>
              </span>
            )}
            {!attack.osint && <div />}
            <div className="flex items-center space-x-1 text-xs text-zypheron-400">
              {attack.id === 'social_engineering' ? (
                <>
                  <BrainCircuit className="w-3 h-3" />
                  <span className="text-xs">Generate Plan</span>
                </>
              ) : (
                <>
                  <Code className="w-3 h-3" />
                  <span className="text-xs">Generate Payload</span>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </motion.button>
  );
};

const AttackCategory = ({ categoryId, attacks, ...props }: {
  categoryId: keyof typeof attackCategories;
  attacks: AttackVector[];
  onAttackClick: (id: string) => void;
  loadingAttack: string | null;
  generatingCustom: boolean;
}) => {
  const [isOpen, setIsOpen] = useState(categoryId === 'social' || categoryId === 'web' || categoryId === 'network'); // Open by default

  return (
    <div className="bg-terminal-bg/50 border border-terminal-border rounded-lg mb-3">
      <button onClick={() => setIsOpen(!isOpen)} className="w-full flex items-center justify-between p-3 text-white font-medium hover:bg-terminal-bg transition-colors">
        <span>{attackCategories[categoryId]}</span>
        {isOpen ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
      </button>
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 p-3 pt-0">
              {attacks.map(attack => <AttackCard key={attack.id} attack={attack} {...props} />)}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

const AttackOptionsPanel: React.FC<AttackOptionsPanelProps> = ({ 
  targetUrl, 
  onGeneratePayload,
  onClose 
}) => {
  const { canAccessFeature, getUpgradeMessage } = useSubscriptionAccess();
  const [loadingAttack, setLoadingAttack] = useState<string | null>(null);
  const [customAttack, setCustomAttack] = useState('');
  const [generatingCustom, setGeneratingCustom] = useState(false);
  const [showMore, setShowMore] = useState(false);
  const [showUpgradePrompt, setShowUpgradePrompt] = useState(false);

  const handleAttackClick = async (attackType: string) => {
    // Check if Stage 2 feature access is required
    if (!canAccessFeature('stage2')) {
      setShowUpgradePrompt(true);
      return;
    }

    setLoadingAttack(attackType);
    try {
      await onGeneratePayload(attackType, targetUrl);
      toast.success(`${allAttackVectors.find(a => a.id === attackType)?.name} payload generated`);
    } catch (error) {
      toast.error('Failed to generate attack payload');
      console.error('Attack generation error:', error);
    } finally {
      setLoadingAttack(null);
    }
  };

  const handleCustomAttackGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Check if Stage 2 feature access is required
    if (!canAccessFeature('stage2')) {
      setShowUpgradePrompt(true);
      return;
    }

    if (!customAttack.trim()) {
      toast.error('Please enter an attack type');
      return;
    }

    setGeneratingCustom(true);
    try {
      await onGeneratePayload('custom', targetUrl, customAttack.trim());
      toast.success('Custom attack payload generated');
      setCustomAttack('');
    } catch (error) {
      toast.error('Failed to generate custom attack payload');
      console.error('Custom attack generation error:', error);
    } finally {
      setGeneratingCustom(false);
    }
  };

  const groupedAttacks = allAttackVectors.reduce((acc, attack) => {
    const category = attack.category as keyof typeof attackCategories;
    if (!acc[category]) {
      acc[category] = [];
    }
    acc[category].push(attack);
    return acc;
  }, {} as Record<keyof typeof attackCategories, AttackVector[]>);

  return (
    <div className="bg-[#1a1a1a] border border-terminal-border rounded-lg p-6 my-4 relative">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 bg-red-500/10 rounded-lg flex items-center justify-center">
            <Target className="w-5 h-5 text-red-500" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-white">COBRA AI - Stage 2 Attack Vectors</h3>
            <p className="text-sm text-terminal-muted">
              Select an attack vector to generate payload for: <span className="text-zypheron-400">{targetUrl}</span>
            </p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="w-8 h-8 flex items-center justify-center rounded-lg bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 hover:text-red-300 transition-colors"
          title="Close attack options"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Warning Banner */}
      <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4 mb-6">
        <div className="flex items-start space-x-3">
          <AlertTriangle className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" />
          <div>
            <h4 className="text-amber-500 font-medium text-sm">⚠️ Legal Authorization Required</h4>
            <p className="text-amber-200/80 text-sm mt-1">
              This penetration test was performed for authorized security assessment purposes only.
              Ensure explicit authorization before deploying any attack vectors.
            </p>
          </div>
        </div>
      </div>

      {/* Attack Options */}
      <AnimatePresence mode="wait">
        <motion.div
          key={showMore ? 'more' : 'less'}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.3 }}
        >
          {!showMore && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 mb-4">
              {originalAttacks.map(attack => (
                <AttackCard 
                  key={attack.id} 
                  attack={attack} 
                  onAttackClick={handleAttackClick} 
                  loadingAttack={loadingAttack}
                  generatingCustom={generatingCustom}
                />
              ))}
            </div>
          )}

          {showMore && (
            <div>
              {Object.entries(groupedAttacks).map(([categoryId, attacks]) => (
                <AttackCategory 
                  key={categoryId} 
                  categoryId={categoryId as keyof typeof attackCategories}
                  attacks={attacks}
                  onAttackClick={handleAttackClick}
                  loadingAttack={loadingAttack}
                  generatingCustom={generatingCustom}
                />
              ))}
            </div>
          )}
        </motion.div>
      </AnimatePresence>
      
      <div className="flex justify-center mt-4">
        <button
          onClick={() => setShowMore(!showMore)}
          className="text-sm text-zypheron-400 hover:text-zypheron-300 flex items-center space-x-2"
        >
          {showMore ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          <span>{showMore ? 'Show Fewer Attack Vectors' : 'Show More Attack Vectors'}</span>
        </button>
      </div>

      {/* Custom Attack Generator */}
      <div className="bg-[#0d0d0d] border border-amber-500/30 rounded-lg p-4 mt-8">
        <div className="flex items-center space-x-3 mb-4">
          <div className="w-8 h-8 bg-amber-500/10 rounded-lg flex items-center justify-center">
            <Sparkles className="w-4 h-4 text-amber-500" />
          </div>
          <div>
            <h4 className="text-amber-500 font-medium text-sm">Generate Unique Attack</h4>
            <p className="text-amber-200/80 text-xs">
              Describe a specific attack type for AI-powered payload generation
            </p>
          </div>
        </div>

        <form onSubmit={handleCustomAttackGenerate} className="space-y-3">
          <div>
            <textarea
              value={customAttack}
              onChange={(e) => setCustomAttack(e.target.value)}
              placeholder="e.g., SQL injection attack targeting login forms, XML External Entity (XXE) attack, Buffer overflow exploit for web servers..."
              className="w-full px-3 py-2 bg-[#1a1a1a] border border-terminal-border rounded-lg text-white placeholder-terminal-muted text-sm resize-none focus:outline-none focus:border-amber-500 transition-colors"
              rows={3}
              disabled={generatingCustom || loadingAttack !== null}
            />
          </div>
          <button
            type="submit"
            disabled={!customAttack.trim() || generatingCustom || loadingAttack !== null}
            className="w-full flex items-center justify-center space-x-2 px-4 py-2 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 rounded-lg text-amber-400 hover:text-amber-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {generatingCustom ? (
              <>
                <Loader className="w-4 h-4 animate-spin" />
                <span className="text-sm">Generating Custom Payload...</span>
              </>
            ) : (
              <>
                <Send className="w-4 h-4" />
                <span className="text-sm font-medium">Generate Custom Attack Payload</span>
              </>
            )}
          </button>
        </form>
      </div>

      {/* Footer Note */}
      <div className="mt-6 pt-4 border-t border-terminal-border">
        <p className="text-xs text-terminal-muted text-center">
          💡 For targeted attacks like Spear Phishing, ensure OSINT has been performed for best results.
        </p>
      </div>

      {/* Upgrade Prompt Modal */}
      {showUpgradePrompt && (
        <UpgradePrompt
          message={getUpgradeMessage('stage2')}
          onClose={() => setShowUpgradePrompt(false)}
          onUpgrade={() => {
            setShowUpgradePrompt(false);
            window.open('/billing', '_blank');
          }}
        />
      )}
    </div>
  );
};

export default AttackOptionsPanel; 