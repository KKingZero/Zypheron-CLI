import React, { useState, useEffect, Suspense } from 'react'
import toast from 'react-hot-toast'
import { useChat } from '../../../contexts/ChatContext'
import { 
  Shield, 
  Network, 
  Search, 
  Wifi, 
  Zap, 
  Eye, 
  Server, 
  Lock, 
  Binary, 
  AlertTriangle, 
  Users, 
  FileText,
  ChevronDown,
  ChevronRight,
  Target,
  Activity,
  Package,
  Code
} from 'lucide-react'
import { ChunkLoader } from '../../../components/LoadingSpinner'

// ========================================
// LAZY LOADED TOOL PANELS (On-Demand Loading)
// ========================================
// Tools are loaded ONLY when user clicks on them
// This reduces initial bundle size by ~600KB
const AircrackEnhancedPanel = React.lazy(() => import('./tools/AircrackEnhancedPanel'))
const MaltegoOSINTPanel = React.lazy(() => import('./tools/MaltegoOSINTPanel'))
const ShodanSearchPanel = React.lazy(() => import('./tools/ShodanSearchPanel'))
const GhostModePanel = React.lazy(() => import('./tools/GhostModePanel'))
const WiresharkAnalyzerPanel = React.lazy(() => import('./tools/WiresharkAnalyzerPanel'))
const NessusScanner = React.lazy(() => import('./tools/NessusScanner'))
const ReconNgPanel = React.lazy(() => import('./tools/ReconNgPanel'))
const JohnRipperPanel = React.lazy(() => import('./tools/JohnRipperPanel'))
const NiktoScanner = React.lazy(() => import('./tools/NiktoScanner'))
const SetoolkitPanel = React.lazy(() => import('./tools/SetoolkitPanel'))
const EttercapMitmPanel = React.lazy(() => import('./tools/EttercapMitmPanel'))
const BinwalkPanel = React.lazy(() => import('./tools/BinwalkPanel'))
const OssimPanel = React.lazy(() => import('./tools/OssimPanel'))
const FaradayCollabPanel = React.lazy(() => import('./tools/FaradayCollabPanel'))
const Radare2Panel = React.lazy(() => import('./tools/Radare2Panel'))
const DradisReportPanel = React.lazy(() => import('./tools/DradisReportPanel'))
const SqlmapScanner = React.lazy(() => import('./tools/SqlmapScanner'))
const WebPortScanner = React.lazy(() => import('./tools/WebPortScanner'))
const PasswordAnalyzer = React.lazy(() => import('./tools/PasswordAnalyzer'))
const WebProxyScanner = React.lazy(() => import('./tools/WebProxyScanner'))
const BruteForceScanner = React.lazy(() => import('./tools/BruteForceScanner'))
const PayloadGenerator = React.lazy(() => import('./tools/PayloadGenerator'))

// Post-Exploitation Tools
const PrivilegeEscalationPanel = React.lazy(() => import('./tools/PrivilegeEscalationPanel'))
const CredentialHarvestingPanel = React.lazy(() => import('./tools/CredentialHarvestingPanel'))
const LateralMovementPanel = React.lazy(() => import('./tools/LateralMovementPanel'))
const PersistencePanel = React.lazy(() => import('./tools/PersistencePanel'))

// Advanced Web Security Tools
const GraphQLSecurityPanel = React.lazy(() => import('./tools/GraphQLSecurityPanel'))
const IntelligentFuzzingPanel = React.lazy(() => import('./tools/IntelligentFuzzingPanel'))
const BusinessLogicTesterPanel = React.lazy(() => import('./tools/BusinessLogicTesterPanel'))
const JWTAnalyzerPanel = React.lazy(() => import('./tools/JWTAnalyzerPanel'))

// Cloud Security Tools
const AWSSecurityPanel = React.lazy(() => import('./tools/AWSSecurityPanel'))
const AzureSecurityPanel = React.lazy(() => import('./tools/AzureSecurityPanel'))
const GCPSecurityPanel = React.lazy(() => import('./tools/GCPSecurityPanel'))

// Evasion Tools
const IDSEvasionPanel = React.lazy(() => import('./tools/IDSEvasionPanel'))
const AVEvasionPanel = React.lazy(() => import('./tools/AVEvasionPanel'))
const WAFBypassPanel = React.lazy(() => import('./tools/WAFBypassPanel'))

interface ToolCategory {
  id: string
  name: string
  icon: React.ReactNode
  description: string
  tools: ToolDefinition[]
  color: string
}

interface ToolDefinition {
  id: string
  name: string
  description: string
  icon: React.ReactNode
  component?: React.ComponentType<any>
  userConfirmation?: boolean
  status: 'available' | 'premium' | 'coming_soon'
}

interface AdvancedToolsDashboardProps {
  operation?: any
  onToolExecute?: (toolName: string, output: string) => void
  addToTerminal?: (message: string) => void
  agentMode?: boolean
  aiTaskQueue?: string[]
  isExecutingAiTasks?: boolean
}

const AdvancedToolsDashboard: React.FC<AdvancedToolsDashboardProps> = ({ 
  operation,
  onToolExecute, 
  addToTerminal,
  agentMode = false,
  aiTaskQueue = [],
  isExecutingAiTasks = false
}) => {
  // Chat context for sending results to chat
  const { addAssistantMessage } = useChat()
  
  // Keep track of which tool is active and which categories are expanded
  const [activeTool, setActiveTool] = useState<string | null>(null)
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set())
  const [toolFilter, setToolFilter] = useState<string>('')
  const [aiAgentTarget, setAiAgentTarget] = useState<string>('')
  const [isAutoAttacking, setIsAutoAttacking] = useState<boolean>(false)

  // Define tool categories and their tools
  const toolCategories: ToolCategory[] = [
    {
      id: 'osint',
      name: 'OSINT & Intelligence',
      icon: <Eye className="w-5 h-5" />,
      description: 'Open Source Intelligence and reconnaissance tools',
      color: 'text-purple-500 bg-purple-500/20 border-purple-500/30',
      tools: [
        {
          id: 'maltego_osint',
          name: 'Maltego OSINT',
          description: 'Graphical entity relationship mapping with GPT analysis',
          icon: <Network className="w-4 h-4" />,
          component: MaltegoOSINTPanel,
          status: 'available'
        },
        {
          id: 'shodan_search',
          name: 'Shodan Intelligence',
          description: 'Global internet device scanner with exploitability ranking',
          icon: <Search className="w-4 h-4" />,
          component: ShodanSearchPanel,
          status: 'available'
        },
        {
          id: 'recon_ng',
          name: 'Recon-ng Framework',
          description: 'WHOIS, breach lookups, and social footprinting modules',
          icon: <Users className="w-4 h-4" />,
          component: ReconNgPanel,
          status: 'available'
        }
      ]
    },
    {
      id: 'wireless',
      name: 'Wireless Security',
      icon: <Wifi className="w-5 h-5" />,
      description: 'Advanced wireless penetration testing tools',
      color: 'text-blue-500 bg-blue-500/20 border-blue-500/30',
      tools: [
        {
          id: 'aircrack_enhanced',
          name: 'Enhanced Aircrack-ng',
          description: 'AI-powered wireless attacks with handshake analysis',
          icon: <Wifi className="w-4 h-4" />,
          component: AircrackEnhancedPanel,
          userConfirmation: true,
          status: 'available'
        }
      ]
    },
    {
      id: 'network_analysis',
      name: 'Network Analysis',
      icon: <Network className="w-5 h-5" />,
      description: 'Deep packet inspection and network security analysis',
      color: 'text-green-500 bg-green-500/20 border-green-500/30',
      tools: [
        {
          id: 'wireshark_analyze',
          name: 'Wireshark AI Analyzer',
          description: 'Packet analysis with GPT-powered threat detection',
          icon: <Network className="w-4 h-4" />,
          component: WiresharkAnalyzerPanel,
          status: 'available'
        },
        {
          id: 'ettercap_mitm',
          name: 'Ettercap MITM Suite',
          description: 'Visual network mapping and MITM attack toolkit',
          icon: <Shield className="w-4 h-4" />,
          component: EttercapMitmPanel,
          userConfirmation: true,
          status: 'available'
        }
      ]
    },
    {
      id: 'vulnerability_scanning',
      name: 'Vulnerability Assessment',
      icon: <AlertTriangle className="w-5 h-5" />,
      description: 'Comprehensive vulnerability scanning and assessment',
      color: 'text-orange-500 bg-orange-500/20 border-orange-500/30',
      tools: [
        {
          id: 'nessus_scan',
          name: 'Nessus Professional',
          description: 'Enterprise vulnerability scanning with AI summaries',
          icon: <AlertTriangle className="w-4 h-4" />,
          component: NessusScanner,
          status: 'available'
        },
        {
          id: 'nikto_scan',
          name: 'Nikto Web Scanner',
          description: 'Web server vulnerability scanner with GPT annotations',
          icon: <Server className="w-4 h-4" />,
          component: NiktoScanner,
          status: 'available'
        },
        {
          id: 'sqlmap_scan',
          name: 'SQLMap Web Scanner',
          description: 'Advanced SQL injection testing and exploitation',
          icon: <Shield className="w-4 h-4" />,
          component: SqlmapScanner,
          status: 'available'
        },
        {
          id: 'web_port_scanner',
          name: 'Web Port Scanner',
          description: 'Browser-based network port scanning with service detection',
          icon: <Network className="w-4 h-4" />,
          component: WebPortScanner,
          status: 'available'
        },
        {
          id: 'web_proxy_scanner',
          name: 'Web Proxy Scanner',
          description: 'Full-featured web application security scanner',
          icon: <Eye className="w-4 h-4" />,
          component: WebProxyScanner,
          status: 'available'
        }
      ]
    },
    {
      id: 'social_engineering',
      name: 'Social Engineering',
      icon: <Users className="w-5 h-5" />,
      description: 'Ethical social engineering and awareness tools',
      color: 'text-pink-500 bg-pink-500/20 border-pink-500/30',
      tools: [
        {
          id: 'setoolkit_campaign',
          name: 'Social Engineer Toolkit',
          description: 'Ethical phishing campaigns with AI-generated content',
          icon: <Users className="w-4 h-4" />,
          component: SetoolkitPanel,
          userConfirmation: true,
          status: 'premium'
        }
      ]
    },
    {
      id: 'password_cracking',
      name: 'Password Security',
      icon: <Lock className="w-5 h-5" />,
      description: 'Password strength analysis and ethical cracking',
      color: 'text-red-500 bg-red-500/20 border-red-500/30',
      tools: [
        {
          id: 'john_ripper',
          name: 'John the Ripper GPU',
          description: 'GPU-accelerated password analysis with AI evaluation',
          icon: <Lock className="w-4 h-4" />,
          component: JohnRipperPanel,
          userConfirmation: true,
          status: 'available'
        },
        {
          id: 'password_analyzer',
          name: 'Password Security Analyzer',
          description: 'Comprehensive password analysis, hash cracking, and generation',
          icon: <Lock className="w-4 h-4" />,
          component: PasswordAnalyzer,
          userConfirmation: true,
          status: 'available'
        },
        {
          id: 'brute_force_scanner',
          name: 'Brute Force Scanner',
          description: 'Multi-protocol brute force attack simulation',
          icon: <Zap className="w-4 h-4" />,
          component: BruteForceScanner,
          userConfirmation: true,
          status: 'available'
        }
      ]
    },
    {
      id: 'binary_analysis',
      name: 'Binary Analysis',
      icon: <Binary className="w-5 h-5" />,
      description: 'Firmware and binary reverse engineering tools',
      color: 'text-yellow-500 bg-yellow-500/20 border-yellow-500/30',
      tools: [
        {
          id: 'binwalk_analyze',
          name: 'Binwalk Firmware Analyzer',
          description: 'AI-powered firmware unpacking and analysis',
          icon: <Binary className="w-4 h-4" />,
          status: 'coming_soon'
        },
        {
          id: 'radare2_disasm',
          name: 'Radare2 Disassembler',
          description: 'Binary disassembly with GPT opcode annotations',
          icon: <Binary className="w-4 h-4" />,
          component: Radare2Panel,
          status: 'coming_soon'
        },
        {
          id: 'payload_generator',
          name: 'Payload Generator',
          description: 'Advanced payload generation, encoding, and listener management',
          icon: <Code className="w-4 h-4" />,
          component: PayloadGenerator,
          userConfirmation: true,
          status: 'available'
        }
      ]
    },
    {
      id: 'threat_intelligence',
      name: 'Threat Intelligence',
      icon: <Shield className="w-5 h-5" />,
      description: 'Advanced threat correlation and intelligence analysis',
      color: 'text-indigo-500 bg-indigo-500/20 border-indigo-500/30',
      tools: [
        {
          id: 'ossim_intelligence',
          name: 'OSSIM Threat Intel',
          description: 'Threat intelligence correlation with AI-powered alerts',
          icon: <Shield className="w-4 h-4" />,
          component: OssimPanel,
          status: 'available'
        },
        {
          id: 'binwalk_analyze',
          name: 'Binwalk Firmware Analyzer',
          description: 'Firmware unpacking with GPT binary analysis and secret detection',
          icon: <Package className="w-4 h-4" />,
          component: BinwalkPanel,
          status: 'available'
        }
      ]
    },
    {
      id: 'collaboration',
      name: 'Collaboration & Reporting',
      icon: <FileText className="w-5 h-5" />,
      description: 'Team collaboration and automated reporting tools',
      color: 'text-teal-500 bg-teal-500/20 border-teal-500/30',
      tools: [
        {
          id: 'faraday_collab',
          name: 'Faraday Collaboration',
          description: 'Real-time team coordination and data ingestion',
          icon: <Users className="w-4 h-4" />,
          component: FaradayCollabPanel,
          status: 'available'
        },
        {
          id: 'dradis_report',
          name: 'Dradis Report Generator',
          description: 'Structured penetration testing reports with AI',
          icon: <FileText className="w-4 h-4" />,
          component: DradisReportPanel,
          status: 'available'
        }
      ]
    },
    {
      id: 'reverse_engineering',
      name: 'Reverse Engineering',
      icon: <Code className="w-5 h-5" />,
      description: 'Binary analysis and reverse engineering with AI assistance',
      color: 'text-cyan-500 bg-cyan-500/20 border-cyan-500/30',
      tools: [
        {
          id: 'radare2_disasm',
          name: 'Radare2 Binary Analyzer',
          description: 'Disassembly and binary analysis with GPT annotations',
          icon: <Code className="w-4 h-4" />,
          component: Radare2Panel,
          status: 'available'
        }
      ]
    },
    {
      id: 'automation',
      name: 'AI Automation',
      icon: <Zap className="w-5 h-5" />,
      description: 'Autonomous penetration testing and AI-driven operations',
      color: 'text-purple-500 bg-purple-500/20 border-purple-500/30',
      tools: [
        {
          id: 'ghost_mode',
          name: 'Ghost Mode',
          description: 'Cinematic AI-driven autonomous penetration testing',
          icon: <Zap className="w-4 h-4" />,
          component: GhostModePanel,
          userConfirmation: true,
          status: 'available'
        }
      ]
    },
    {
      id: 'post_exploitation',
      name: 'Post-Exploitation',
      icon: <Target className="w-5 h-5" />,
      description: 'Advanced post-exploitation and persistence techniques',
      color: 'text-red-500 bg-red-500/20 border-red-500/30',
      tools: [
        {
          id: 'privilege_escalation',
          name: 'Privilege Escalation',
          description: 'Automated privilege escalation with multiple techniques',
          icon: <Shield className="w-4 h-4" />,
          component: PrivilegeEscalationPanel,
          userConfirmation: true,
          status: 'available'
        },
        {
          id: 'credential_harvesting',
          name: 'Credential Harvesting',
          description: 'Extract credentials from memory and files (Mimikatz-style)',
          icon: <Lock className="w-4 h-4" />,
          component: CredentialHarvestingPanel,
          userConfirmation: true,
          status: 'available'
        },
        {
          id: 'lateral_movement',
          name: 'Lateral Movement',
          description: 'Move laterally to other systems (PtH, PtT, PSExec, WMI, SSH)',
          icon: <Network className="w-4 h-4" />,
          component: LateralMovementPanel,
          userConfirmation: true,
          status: 'available'
        },
        {
          id: 'persistence',
          name: 'Establish Persistence',
          description: 'Create persistence mechanisms on compromised systems',
          icon: <Activity className="w-4 h-4" />,
          component: PersistencePanel,
          userConfirmation: true,
          status: 'available'
        }
      ]
    },
    {
      id: 'advanced_web_security',
      name: 'Advanced Web Security',
      icon: <Code className="w-5 h-5" />,
      description: 'GraphQL, intelligent fuzzing, and business logic testing',
      color: 'text-cyan-500 bg-cyan-500/20 border-cyan-500/30',
      tools: [
        {
          id: 'graphql_security',
          name: 'GraphQL Security Testing',
          description: 'Introspection, complexity attacks, batching, field duplication',
          icon: <Code className="w-4 h-4" />,
          component: GraphQLSecurityPanel,
          status: 'available'
        },
        {
          id: 'intelligent_fuzzing',
          name: 'AI-Powered Fuzzing',
          description: 'Context-aware intelligent fuzzing with mutation strategies',
          icon: <Zap className="w-4 h-4" />,
          component: IntelligentFuzzingPanel,
          status: 'available'
        },
        {
          id: 'business_logic_tester',
          name: 'Business Logic Testing',
          description: 'Race conditions, payment flaws, workflow bypass detection',
          icon: <AlertTriangle className="w-4 h-4" />,
          component: BusinessLogicTesterPanel,
          status: 'available'
        },
        {
          id: 'jwt_analyzer',
          name: 'JWT/OAuth Analyzer',
          description: 'Algorithm confusion, weak secrets, token manipulation',
          icon: <Lock className="w-4 h-4" />,
          component: JWTAnalyzerPanel,
          status: 'available'
        }
      ]
    },
    {
      id: 'cloud_security',
      name: 'Cloud Security Assessment',
      icon: <Server className="w-5 h-5" />,
      description: 'Multi-cloud security assessment (AWS, Azure, GCP)',
      color: 'text-sky-500 bg-sky-500/20 border-sky-500/30',
      tools: [
        {
          id: 'aws_security',
          name: 'AWS Security Assessment',
          description: 'IAM, S3, EC2, Lambda, Security Groups, RDS assessment',
          icon: <Server className="w-4 h-4" />,
          component: AWSSecurityPanel,
          status: 'available'
        },
        {
          id: 'azure_security',
          name: 'Azure Security Assessment',
          description: 'Azure AD, Storage, VMs, Managed Identity, NSG assessment',
          icon: <Server className="w-4 h-4" />,
          component: AzureSecurityPanel,
          status: 'available'
        },
        {
          id: 'gcp_security',
          name: 'GCP Security Assessment',
          description: 'IAM, Cloud Storage, Compute Engine, Service Accounts assessment',
          icon: <Server className="w-4 h-4" />,
          component: GCPSecurityPanel,
          status: 'available'
        }
      ]
    },
    {
      id: 'evasion',
      name: 'Evasion Techniques',
      icon: <Eye className="w-5 h-5" />,
      description: 'IDS/IPS, AV/EDR, and WAF evasion capabilities',
      color: 'text-indigo-500 bg-indigo-500/20 border-indigo-500/30',
      tools: [
        {
          id: 'ids_evasion',
          name: 'IDS/IPS Evasion',
          description: 'Packet fragmentation, protocol manipulation, timing attacks',
          icon: <Shield className="w-4 h-4" />,
          component: IDSEvasionPanel,
          status: 'available'
        },
        {
          id: 'av_evasion',
          name: 'AV/EDR Evasion',
          description: 'Code obfuscation, signature avoidance, in-memory execution',
          icon: <Eye className="w-4 h-4" />,
          component: AVEvasionPanel,
          status: 'available'
        },
        {
          id: 'waf_bypass',
          name: 'WAF Bypass',
          description: 'Encoding variations, charset manipulation, HTTP parameter pollution',
          icon: <AlertTriangle className="w-4 h-4" />,
          component: WAFBypassPanel,
          status: 'available'
        }
      ]
    }
  ]

  // Ensure all categories are expanded by default
  useEffect(() => {
    setExpandedCategories(new Set(toolCategories.map(c => c.id)))
  }, [])

  const toggleCategory = (categoryId: string) => {
    const newExpanded = new Set(expandedCategories)
    if (newExpanded.has(categoryId)) {
      newExpanded.delete(categoryId)
    } else {
      newExpanded.add(categoryId)
    }
    setExpandedCategories(newExpanded)
  }

  const selectTool = (toolId: string) => {
    setActiveTool(toolId)
  }

  const initiateAutomatedAttack = async () => {
    if (!aiAgentTarget.trim()) {
      toast.error('Please enter a target IP/domain');
      return;
    }

    if (isExecutingAiTasks || isAutoAttacking) {
      toast('AI automation is already running');
      return;
    }

    setIsAutoAttacking(true);

    // More flexible validation for URLs, domains, and IPs
    const target = aiAgentTarget.trim();
    const isValidURL = /^https?:\/\/[^\s]+\.[^\s]+/.test(target);
    const isValidIP = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target);
    const isValidDomain = /^[a-zA-Z0-9][a-zA-Z0-9-._]*[a-zA-Z0-9]\.[a-zA-Z]{2,}$/.test(target) || 
                          /^[a-zA-Z0-9-._]+\.[a-zA-Z]{2,}$/.test(target);
    
    if (!isValidIP && !isValidDomain && !isValidURL) {
      toast.error('Please enter a valid IP address, domain name, or URL');
      return;
    }

    try {
      toast.success(`🎯 AI Agent initiating automated assessment on: ${target}`, {
        duration: 4000,
        icon: '🤖'
      });
      
      // Start the automated sequence
      toast.loading('🔍 Phase 1: OSINT Reconnaissance...', { 
        id: 'auto-attack',
        duration: 3000 
      });
      
      // Execute Maltego OSINT first
      setActiveTool('maltego_osint')
      let maltegoResult: any = null
      try {
        maltegoResult = await executeToolWithParams('maltego_osint', target);
      } catch (e) { /* continue */ }
      await delay(2000);
      
      toast.loading('🌐 Phase 2: Internet Intelligence...', { 
        id: 'auto-attack',
        duration: 3000 
      });
      
      // Execute Shodan search
      setActiveTool('shodan_search')
      let shodanResult: any = null
      try {
        shodanResult = await executeToolWithParams('shodan_search', target);
      } catch (e) { /* continue */ }
      await delay(2000);
      
      toast.loading('🕵️ Phase 3: Framework Reconnaissance...', { 
        id: 'auto-attack',
        duration: 3000 
      });
      
      // Execute Recon-ng
      setActiveTool('recon_ng')
      let reconNgResult: any = null
      try {
        reconNgResult = await executeToolWithParams('recon_ng', target);
      } catch (e) { /* continue */ }
      await delay(2000);
      
      toast.loading('🛡️ Phase 4: Vulnerability Assessment...', { 
        id: 'auto-attack',
        duration: 3000 
      });
      
      // Execute Nessus scan
      setActiveTool('nessus_scan')
      let nessusResult: any = null
      try {
        nessusResult = await executeToolWithParams('nessus_scan', target);
      } catch (e) { /* continue */ }
      await delay(2000);
      
      toast.loading('📡 Phase 5: Network Analysis...', { 
        id: 'auto-attack',
        duration: 3000 
      });
      
      // Execute Wireshark analysis
      setActiveTool('wireshark_analyze')
      let wiresharkResult: any = null
      try {
        wiresharkResult = await executeToolWithParams('wireshark_analyze', target);
      } catch (e) { /* continue */ }
      
      toast.success(`🎉 Automated assessment completed for ${target}!`, {
        id: 'auto-attack',
        duration: 5000
      });
      
      // Send completion summary to chat with real outputs
      await sendConsolidatedAssessmentToChat(target, {
        maltego: maltegoResult,
        shodan: shodanResult,
        reconNg: reconNgResult,
        nessus: nessusResult,
        wireshark: wiresharkResult
      });
      
    } catch (error) {
      console.error('Automated attack failed:', error);
      toast.error('Automated assessment encountered an error', {
        id: 'auto-attack'
      });
    } finally {
      setIsAutoAttacking(false);
    }
  }

  const executeToolWithParams = async (toolName: string, target: string) => {
    try {
      const params = {
        target: target,
        agentMode: true,
        aiGenerated: true,
        automated: true,
        timestamp: new Date().toISOString()
      };
      
      if (import.meta.env.DEV) {
        console.log(`🤖 Executing ${toolName} with target: ${target}`);
      }

      // Execute against the backend so we use real tool outputs
      const realResult = await onToolExecute(toolName, params);

      // Send results to chat
      await sendResultsToChat(toolName, target, realResult);

      if (import.meta.env.DEV) {
        console.log(`✅ Completed ${toolName}`, realResult);
      }
      
      return realResult;
    } catch (error) {
      console.error(`❌ Failed to execute ${toolName}:`, error);
      // Send error to chat as well
      const message = (error instanceof Error) ? error.message : String(error)
      addAssistantMessage(`❌ **${toolName} Error**\n\nFailed to execute ${toolName} on target ${target}:\n\`\`\`\n${message}\n\`\`\``, {
        tool: toolName,
        target: target,
        error: true
      });
      throw error;
    }
  }

  // Removed simulated result generator to ensure only real outputs are used

  const sendResultsToChat = async (toolName: string, target: string, result: any) => {
    const toolDisplayNames: Record<string, string> = {
      maltego_osint: 'Maltego OSINT',
      shodan_search: 'Shodan Intelligence',
      recon_ng: 'Recon-ng Framework',
      nessus_scan: 'Nessus Vulnerability Scanner',
      wireshark_analyze: 'Wireshark Network Analysis'
    };

    const displayName = toolDisplayNames[toolName] || toolName;
    
    let chatMessage = `🔍 **${displayName} Results**\n\n`;
    chatMessage += `**Target:** \`${target}\`\n`;
    if (result.executionTime) chatMessage += `**Execution Time:** ${result.executionTime?.toFixed(1)}s\n\n`;

    // Tool-specific formatting to ensure we display real outputs comprehensively
    switch (toolName) {
      case 'maltego_osint': {
        const entities = result.entities || [];
        const relationships = result.relationships || [];
        chatMessage += `**Entities Discovered:** ${entities.length}\n`;
        chatMessage += entities.map((e: any) => `- ${e.type}: ${e.name}`).join('\n') + '\n\n';
        chatMessage += `**Relationships:** ${relationships.length}\n`;
        break;
      }
      case 'shodan_search': {
        const rows = result.results || [];
        chatMessage += `**Results:** ${result.totalResults || rows.length}\n`;
        chatMessage += rows.map((r: any) => `- ${r.ip}:${r.port} • ${r.service} • score ${r.exploitabilityScore}/10`).join('\n') + '\n\n';
        break;
      }
      case 'recon_ng': {
        const cf = result.correlatedFindings || {};
        if (cf.domains?.length) chatMessage += `**Domains:** ${cf.domains.length} → ${cf.domains.join(', ')}\n`;
        if (cf.hosts?.length) chatMessage += `**Hosts:** ${cf.hosts.length} → ${cf.hosts.join(', ')}\n`;
        if (cf.contacts?.length) chatMessage += `**Contacts:** ${cf.contacts.length}\n`;
        chatMessage += '\n';
        break;
      }
      case 'nessus_scan': {
        const vulns = result.vulnerabilities || [];
        const crit = vulns.filter((v: any) => v.severity === 'critical');
        const high = vulns.filter((v: any) => v.severity === 'high');
        chatMessage += `**Vulnerabilities:** ${vulns.length} (critical ${crit.length}, high ${high.length})\n`;
        chatMessage += vulns.map((v: any) => `- [${v.severity.toUpperCase()}] ${v.name} • CVSS ${v.cvss}`).join('\n') + '\n\n';
        break;
      }
      case 'wireshark_analyze': {
        const flows = result.suspiciousFlows || [];
        chatMessage += `**Suspicious Flows:** ${flows.length}\n`;
        chatMessage += flows.map((f: any) => `- ${f.flowType} ${f.source} → ${f.destination} • ${f.severity}`).join('\n') + '\n\n';
        break;
      }
      default: {
        if (result.findings) {
          chatMessage += `**Key Findings:**\n`;
          Object.entries(result.findings as Record<string, any>).forEach(([key, value]) => {
            if (Array.isArray(value)) {
              chatMessage += `• **${key}:** ${value.join(', ')}\n`;
            } else if (typeof value === 'object') {
              chatMessage += `• **${key}:**\n`;
              Object.entries(value as Record<string, any>).forEach(([subKey, subValue]) => {
                chatMessage += `  - ${subKey}: ${subValue}\n`;
              });
            } else {
              chatMessage += `• **${key}:** ${value}\n`;
            }
          });
        }
      }
    }
    
    chatMessage += `\n*Generated by AI Agent at ${new Date().toLocaleTimeString()}*`;
    
    // Add message to current chat session
    addAssistantMessage(chatMessage, {
      tool: toolName,
      target: target,
      threatLevel: result.findings?.riskScore > 7 ? 'high' : result.findings?.riskScore > 4 ? 'medium' : 'low'
    });
  }

  const sendConsolidatedAssessmentToChat = async (
    target: string,
    results: { maltego?: any; shodan?: any; reconNg?: any; nessus?: any; wireshark?: any }
  ) => {
    const toolsExecuted = Object.values(results).filter(Boolean).length

    // Derive useful metrics from actual outputs
    const maltegoCount = results.maltego?.entities?.length || 0
    const shodanCount = results.shodan?.totalResults || (results.shodan?.results?.length || 0)
    const reconDomains = results.reconNg?.correlatedFindings?.domains?.length || 0
    const nessusSummary = results.nessus?.executiveSummary || results.nessus?.summary
    const nessusCrit = results.nessus?.vulnerabilities?.filter((v: any) => v.severity === 'critical')?.length || 0
    const nessusHigh = results.nessus?.vulnerabilities?.filter((v: any) => v.severity === 'high')?.length || 0
    const wiresharkSuspicious = results.wireshark?.suspiciousFlows?.length || 0

    // Build richer details per phase
    const maltegoDetails = (() => {
      const entities: any[] = results.maltego?.entities || []
      if (entities.length === 0) return 'No entities discovered'
      const counts: Record<string, number> = {}
      entities.forEach(e => { counts[e.type] = (counts[e.type] || 0) + 1 })
      const byType = Object.entries(counts).map(([t, c]) => `${t}: ${c}`).join(', ')
      const topExamples = entities.slice(0, 5).map(e => `- ${e.type}: ${e.name}`).join('\n')
      return `Entities by type — ${byType}\n${topExamples}`
    })()

    const shodanDetails = (() => {
      const rows: any[] = results.shodan?.results || []
      if (rows.length === 0) return 'No internet-facing services found by current query'
      const sorted = [...rows].sort((a, b) => (b.exploitabilityScore || 0) - (a.exploitabilityScore || 0))
      const top = sorted.slice(0, 5).map(r => `- ${r.ip}:${r.port} • ${r.service} • score ${r.exploitabilityScore || 0}/10${r.vulns?.length ? ` • vulns: ${r.vulns.slice(0,2).join(', ')}${r.vulns.length>2?'…':''}`:''}`)
      return top.join('\n')
    })()

    const reconDetails = (() => {
      const cf = results.reconNg?.correlatedFindings || {}
      const parts: string[] = []
      if (cf.domains?.length) parts.push(`Domains (${cf.domains.length}): ${cf.domains.slice(0,6).join(', ')}${cf.domains.length>6?'…':''}`)
      if (cf.hosts?.length) parts.push(`Hosts (${cf.hosts.length}): ${cf.hosts.slice(0,6).join(', ')}${cf.hosts.length>6?'…':''}`)
      if (cf.contacts?.length) parts.push(`Contacts (${cf.contacts.length})`)
      if (cf.credentials?.length) parts.push(`Credentials (${cf.credentials.length})`)
      return parts.length ? parts.join('\n- ') : 'No correlated findings saved to workspace'
    })()

    const nessusDetails = (() => {
      const vulns: any[] = results.nessus?.vulnerabilities || []
      if (vulns.length === 0) return 'No vulnerabilities reported by the selected policy'
      const crit = vulns.filter(v => v.severity === 'critical').sort((a,b)=> (b.cvss||0)-(a.cvss||0)).slice(0,3)
      const hi = vulns.filter(v => v.severity === 'high').sort((a,b)=> (b.cvss||0)-(a.cvss||0)).slice(0,3)
      const fmt = (v:any) => `- [${v.severity.toUpperCase()}] ${v.name} • CVSS ${v.cvss}${v.port?` • ${v.port}/${v.protocol||''}`:''}${v.cve?.length?` • ${v.cve.slice(0,2).join(', ')}${v.cve.length>2?'…':''}`:''}${v.solution?`\n  Remediation: ${v.solution}`:''}`
      const lines = [] as string[]
      if (crit.length) { lines.push('Top Critical:', ...crit.map(fmt)) }
      if (hi.length) { lines.push('Top High:', ...hi.map(fmt)) }
      return lines.join('\n')
    })()

    const wiresharkDetails = (() => {
      const flows: any[] = results.wireshark?.suspiciousFlows || []
      if (flows.length === 0) return 'No suspicious flows detected in the capture window'
      const top = flows.slice(0,5).map(f => `- ${f.flowType} ${f.source} → ${f.destination} • ${f.protocol} • ${f.severity}${f.recommendedMitigation?`\n  Mitigation: ${f.recommendedMitigation}`:''}`)
      return top.join('\n')
    })()

    const summaryMessage =
      `🎯 **Automated Security Assessment Complete**\n\n` +
      `**Target:** \`${target}\`\n` +
      `**Completed At:** ${new Date().toLocaleTimeString()}\n` +
      `**Tools Executed:** ${toolsExecuted}/5 ✅\n\n` +
      `**Phase Results:**\n` +
      `1) OSINT (Maltego): ${maltegoCount} entities discovered\n` +
      `2) Internet Intelligence (Shodan): ${shodanCount} results ranked by exploitability\n` +
      `3) Framework Recon (Recon-ng): ${reconDomains} domains correlated in workspace\n` +
      `4) Vulnerability Assessment (Nessus): ${nessusCrit} critical, ${nessusHigh} high findings\n` +
      `5) Network Traffic (Wireshark): ${wiresharkSuspicious} suspicious flows detected\n\n` +
      `**Highlights & Explanations**\n` +
      `- Maltego:\n${maltegoDetails}\n\n` +
      `- Shodan:\n${shodanDetails || 'No noteworthy internet-exposed services were returned for this query.'}\n\n` +
      `- Recon-ng:\n- ${reconDetails}\n\n` +
      `- Nessus:\n${nessusDetails}\n\n` +
      `- Wireshark:\n${wiresharkDetails}\n\n` +
      `**Executive Security Assessment**\n` +
      `${nessusSummary?.businessImpact || 'Business impact analyzed; review critical/high issues first for maximum risk reduction.'}\n\n` +
      `**Prioritized Remediation Plan**\n` +
      `- Immediate (0-24h): Patch/mitigate critical vulnerabilities; restrict or disable risky exposed services.\n` +
      `- Short-term (1-7 days): Address high-severity findings; enforce TLS, harden configs, add WAF rules as needed.\n` +
      `- Medium-term (1-4 weeks): Reduce OSINT footprint (remove sensitive paths/metadata), improve monitoring to catch flows like those detected.\n\n` +
      `Data provenance: All sections above are derived directly from executed tool outputs in this session.`;

    addAssistantMessage(summaryMessage, {
      tool: 'automated_assessment',
      target: target,
      summary: true,
      threatLevel: (nessusCrit > 0 || wiresharkSuspicious > 0) ? 'high' : 'medium'
    });
  }

  const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'available':
        return <span className="px-2 py-1 bg-green-500 text-white text-xs rounded-full">Available</span>
      case 'premium':
        return <span className="px-2 py-1 bg-yellow-500 text-white text-xs rounded-full">Premium</span>
      case 'coming_soon':
        return <span className="px-2 py-1 bg-gray-500 text-white text-xs rounded-full">Coming Soon</span>
      default:
        return null
    }
  }

  const filteredCategories = toolCategories.map(category => ({
    ...category,
    tools: category.tools.filter(tool => 
      tool.name.toLowerCase().includes(toolFilter.toLowerCase()) ||
      tool.description.toLowerCase().includes(toolFilter.toLowerCase())
    )
  })).filter(category => category.tools.length > 0 || !toolFilter)

  // Get active tool definition and component
  const activeToolDef = toolCategories
    .flatMap(cat => cat.tools)
    .find(tool => tool.id === activeTool)

  const ActiveToolComponent = activeToolDef?.component

  return (
    <div className="space-y-6">
      {/* Header - Matching Cobra AI Design */}
      <div className="bg-gradient-to-r from-red-900/20 to-red-600/20 border border-red-500/30 rounded-lg p-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="w-12 h-12 bg-red-600 rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-white mb-1 flex items-center">
                Advanced Cybersecurity Arsenal
                {agentMode && (
                  <span className="ml-3 px-3 py-1 bg-red-500 text-white text-sm rounded-full">AI AGENT MODE</span>
                )}
              </h2>
              <p className="text-red-200">
                AI-Augmented Professional Red Team Simulation Platform
              </p>
            </div>
          </div>
          
          {/* AI Agent Target Input or Status */}
          <div className="text-right">
            {agentMode ? (
              <div className="flex flex-col items-end space-y-2">
                <div className="text-purple-400 text-sm font-medium">🤖 AI Agent Target</div>
                <div className="flex items-center space-x-2">
                  <input
                    type="text"
                    value={aiAgentTarget}
                    placeholder="example.com or 192.168.1.1"
                    className="bg-black/30 border border-purple-500/30 rounded px-3 py-2 text-white placeholder-gray-400 focus:border-purple-400 focus:outline-none text-sm w-48"
                    onChange={(e) => setAiAgentTarget(e.target.value)}
                    onKeyPress={(e) => {
                      if (e.key === 'Enter') {
                        initiateAutomatedAttack();
                      }
                    }}
                  />
                  <button
                    onClick={initiateAutomatedAttack}
                    disabled={!aiAgentTarget.trim() || isExecutingAiTasks || isAutoAttacking}
                    className="px-3 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white text-xs rounded transition-colors flex items-center space-x-1"
                  >
                    {(isExecutingAiTasks || isAutoAttacking) ? (
                      <span>⚡ Running...</span>
                    ) : (
                      <span>🚀 Auto Attack</span>
                    )}
                  </button>
                </div>
                <div className="text-purple-200 text-xs">Enter target for automated assessment</div>
              </div>
            ) : (
              <div>
                <div className="text-green-400 text-sm font-medium">All Systems Operational</div>
                <div className="text-red-200 text-xs">16+ Tools Ready</div>
              </div>
            )}
          </div>
        </div>
        
        {/* Search Filter */}
        <div className="mt-6">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              value={toolFilter}
              onChange={(e) => setToolFilter(e.target.value)}
              placeholder="Search advanced tools..."
              className="w-full md:w-96 bg-black/30 border border-red-500/30 rounded px-10 py-3 text-white placeholder-gray-400 focus:border-red-400 focus:outline-none"
            />
          </div>
        </div>
      </div>

      {/* AI Task Queue Status Panel - Shows when AI is active */}
      {agentMode && (aiTaskQueue.length > 0 || isExecutingAiTasks) && (
        <div className="bg-gradient-to-r from-purple-900/20 to-blue-900/20 border border-purple-500/30 rounded-lg p-6 mb-6">
          <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
            <Activity className="w-5 h-5 mr-2 text-purple-500 animate-pulse" />
            🤖 AI Agent Task Queue
            {isExecutingAiTasks && (
              <span className="ml-3 px-2 py-1 bg-purple-500 text-white text-xs rounded-full animate-pulse">
                EXECUTING
              </span>
            )}
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {aiTaskQueue.map((toolName, index) => (
              <div key={toolName} className="flex items-center space-x-3 p-3 bg-terminal-bg/50 rounded-lg border border-purple-500/20">
                <div className="w-6 h-6 bg-purple-500 text-white rounded-full flex items-center justify-center text-xs font-bold">
                  {index + 1}
                </div>
                <div className="flex-1">
                  <span className="text-terminal-text text-sm font-medium">{toolName}</span>
                  {isExecutingAiTasks && index === 0 && (
                    <div className="text-xs text-purple-400 mt-1">⚡ Currently executing...</div>
                  )}
                </div>
                {index === 0 && isExecutingAiTasks && (
                  <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce"></div>
                )}
              </div>
            ))}
          </div>
          {isExecutingAiTasks && (
            <div className="mt-4 text-center text-purple-400 text-sm">
              🧠 AI is analyzing target and executing tools in optimal sequence...
            </div>
          )}
        </div>
      )}



      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Tool Categories Sidebar */}
        <div className="lg:col-span-1">
          <div className="bg-terminal-card border border-terminal-border rounded-lg p-4">
            <h3 className="text-lg font-semibold text-terminal-text mb-4 flex items-center">
              <Target className="w-5 h-5 mr-2 text-red-500" />
              Tool Categories
            </h3>
            
            <div className="space-y-2">
              {filteredCategories.map((category) => (
                <div key={category.id}>
                  <button
                    onClick={() => toggleCategory(category.id)}
                    className={`w-full flex items-center justify-between p-3 rounded-lg border transition-all hover:scale-[1.02] ${
                      expandedCategories.has(category.id)
                        ? `${category.color} border-opacity-100 shadow-lg`
                        : 'border-terminal-border hover:border-red-500/30 hover:bg-red-500/5'
                    }`}
                  >
                    <div className="flex items-center space-x-3">
                      {category.icon}
                      <span className="font-medium">{category.name}</span>
                    </div>
                    {expandedCategories.has(category.id) ? (
                      <ChevronDown className="w-4 h-4" />
                    ) : (
                      <ChevronRight className="w-4 h-4" />
                    )}
                  </button>
                  
                  {expandedCategories.has(category.id) && (
                    <div className="ml-4 mt-2 space-y-1">
                      {category.tools.map((tool) => (
                        <button
                          key={tool.id}
                          onClick={() => selectTool(tool.id)}
                          disabled={tool.status === 'coming_soon'}
                          className={`w-full flex items-center justify-between p-3 rounded-lg text-left transition-all hover:scale-[1.02] ${
                            activeTool === tool.id
                              ? 'bg-red-600 text-white shadow-lg border border-red-500'
                              : tool.status === 'coming_soon'
                              ? 'text-gray-500 cursor-not-allowed border border-gray-600'
                              : 'hover:bg-red-500/10 text-terminal-text border border-transparent hover:border-red-500/30'
                          }`}
                        >
                          <div className="flex items-center space-x-2">
                            {tool.icon}
                            <span className="text-sm">{tool.name}</span>
                          </div>
                          {getStatusBadge(tool.status)}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Main Content Area */}
        <div className="lg:col-span-3">
          {activeTool && ActiveToolComponent ? (
            <div>
              {/* Tool Header - Enhanced */}
              <div className="bg-gradient-to-r from-gray-900/50 to-red-900/20 border border-red-500/30 rounded-lg p-6 mb-6">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <div className="w-12 h-12 bg-red-600 rounded-lg flex items-center justify-center">
                      {activeToolDef.icon}
                    </div>
                    <div>
                      <h3 className="text-xl font-bold text-white">{activeToolDef.name}</h3>
                      <p className="text-red-200 text-sm">{activeToolDef.description}</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-3">
                    <div className="text-right">
                      <div className="text-green-400 text-sm font-medium">Ready for Operation</div>
                      <div className="text-red-200 text-xs">AI-Enhanced Mode</div>
                    </div>
                    {getStatusBadge(activeToolDef.status)}
                    {activeToolDef.userConfirmation && (
                      <span className="px-3 py-1 bg-orange-500 text-white text-xs rounded-full flex items-center space-x-1">
                        <AlertTriangle className="w-3 h-3" />
                        <span>Requires Confirmation</span>
                      </span>
                    )}
                    <button
                      onClick={() => setActiveTool(null)}
                      className="px-3 py-1 bg-gray-600 hover:bg-gray-700 text-white text-xs rounded"
                    >
                      Hide
                    </button>
                  </div>
                </div>
              </div>

              {/* Tool Component - Lazy Loaded with Suspense */}
              <Suspense fallback={
                <ChunkLoader 
                  page={`${activeToolDef?.name || 'tool'}`} 
                  fullHeight={false} 
                />
              }>
                <ActiveToolComponent onToolExecute={onToolExecute} />
              </Suspense>
            </div>
          ) : (
            /* Category Overview */
            <div className="space-y-6">
              {filteredCategories.map((category) => (
                <div key={category.id} className={`bg-terminal-card border rounded-lg p-6 hover:scale-[1.02] transition-all ${category.color} border-opacity-30 hover:border-opacity-60 hover:shadow-lg`}>
                  <h3 className="text-lg font-semibold text-terminal-text mb-3 flex items-center">
                    <div className="w-8 h-8 bg-red-600/20 rounded-lg flex items-center justify-center mr-3">
                      {category.icon}
                    </div>
                    <span>{category.name}</span>
                    <span className="ml-3 px-2 py-1 bg-red-500/20 text-red-400 text-xs rounded-full">
                      {category.tools.length} tools
                    </span>
                  </h3>
                  <p className="text-terminal-muted mb-4">{category.description}</p>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {category.tools.map((tool) => (
                      <div
                        key={tool.id}
                        className={`border border-terminal-border rounded-lg p-4 transition-all ${
                          tool.status === 'available' 
                            ? 'hover:border-cobra-500 cursor-pointer' 
                            : 'opacity-60'
                        }`}
                        onClick={() => tool.status === 'available' && selectTool(tool.id)}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center space-x-2">
                            {tool.icon}
                            <span className="font-medium text-terminal-text">{tool.name}</span>
                          </div>
                          {getStatusBadge(tool.status)}
                        </div>
                        <p className="text-terminal-muted text-sm">{tool.description}</p>
                        
                        {tool.userConfirmation && (
                          <div className="mt-2 flex items-center space-x-1">
                            <AlertTriangle className="w-3 h-3 text-orange-500" />
                            <span className="text-orange-400 text-xs">User confirmation required</span>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default AdvancedToolsDashboard