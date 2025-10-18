import React, { useState, useRef, useEffect, useMemo } from 'react'
import { Send, Target, Brain, Loader, ToggleLeft, ToggleRight, Settings, Key, LogOut, Shield, Paperclip, X } from 'lucide-react'
import RobotIcon from '../../components/icons/RobotIcon'
import { useChat } from '../../contexts/ChatContext'
import { useAuth } from '../../contexts/AuthContext'
import ReactMarkdown from 'react-markdown'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism'
import toast from 'react-hot-toast'
import ChatLayout from '../../components/ChatLayout'
import PentestPanel from '../../components/PentestPanel'
import AttackOptionsPanel from '../../components/AttackOptionsPanel'
import zypheronLogo from '../../ZypheronX.jpg'
import SEOOptimizer, { seoConfigs } from '../../components/SEOOptimizer'
import { shouldBypassAuth } from '../../utils/devMode'
import { getApiUrl, getCommonHeaders } from '../../config/api.config'

const Chat = () => {
  const [input, setInput] = useState('')
  const [showPentestPanel, setShowPentestPanel] = useState(false)
  const [analyzingPentest, setAnalyzingPentest] = useState(false)
  const [showAttackOptions, setShowAttackOptions] = useState(false)
  const [showCacheModal, setShowCacheModal] = useState(false)
  const [showTOSModal, setShowTOSModal] = useState(false)
  const [showTOUModal, setShowTOUModal] = useState(false)
  const [attachedImage, setAttachedImage] = useState<string | null>(null)
  const [agentMode, setAgentMode] = useState(false)
  // Pentest action states
  const [reasoningExpandedByMsg, setReasoningExpandedByMsg] = useState<Record<string, boolean>>({})
  const [reasoningByMsg, setReasoningByMsg] = useState<Record<string, string>>({})
  const [patchOpenForMsg, setPatchOpenForMsg] = useState<Record<string, boolean>>({})
  const [patchPlanByMsg, setPatchPlanByMsg] = useState<Record<string, any>>({})
  const [patchGeneratingFix, setPatchGeneratingFix] = useState<Record<string, boolean>>({})
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const agentTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  
  const {
    currentSession,
    createNewSession,
    sendMessage,
    addAssistantMessage,
    isLoading,
    currentModel,
    cachePentestResults,
    getCachedPentestResults,
    clearPentestCache
  } = useChat()
  
  const { signOut, session } = useAuth()

  // Get cached pentest results and force re-render when cache changes
  const [cacheVersion, setCacheVersion] = useState(0)
  
  // Use useMemo to make cache retrieval reactive to cacheVersion
  const { lastPentestResults, lastPentestTarget, cachedPentestResults } = useMemo(() => {
    const cache = getCachedPentestResults()
    return {
      cachedPentestResults: cache,
      lastPentestResults: cache?.results || null,
      lastPentestTarget: cache?.target || ''
    }
  }, [cacheVersion, currentSession?.id]) // Removed getCachedPentestResults to prevent infinite re-renders

  // Debug cache state (development only)
  useEffect(() => {
    if (import.meta.env.DEV) {
      console.log('Cache Debug:', {
        cachedPentestResults,
        lastPentestResults: !!lastPentestResults,
        lastPentestTarget,
        sessionId: currentSession?.id
      })
    }
  }, [cachedPentestResults, lastPentestResults, lastPentestTarget, currentSession?.id])

  // Force cache refresh when session changes
  useEffect(() => {
    setCacheVersion(prev => prev + 1)
  }, [currentSession?.id])

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [currentSession?.messages])

  useEffect(() => {
    if (!currentSession) {
      createNewSession()
    }
  }, [currentSession, createNewSession])

  // Cleanup timeout on unmount
  useEffect(() => {
    return () => {
      if (agentTimeoutRef.current) {
        clearTimeout(agentTimeoutRef.current)
      }
    }
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!input.trim() || isLoading) return

    const userInput = input
    await sendMessage(userInput, attachedImage)
    setInput('')
    setAttachedImage(null)
    
    // Reset textarea height
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto'
    }

    // If agent mode is active, automatically provide contextual recommendations
    if (agentMode) {
      // Clear any existing timeout
      if (agentTimeoutRef.current) {
        clearTimeout(agentTimeoutRef.current)
      }
      
      // Extract potential target from user input (simple heuristic)
      const targetMatch = userInput.match(/(?:scan|test|analyze|attack|target)\s+([^\s]+)/i)
      const target = targetMatch ? targetMatch[1] : 'unknown-target'
      
      // Use the user input as context for recommendations with proper cleanup
      agentTimeoutRef.current = setTimeout(async () => {
        try {
          await handleGetAgentRecommendations(target, userInput)
        } catch (error) {
          console.error('Agent recommendations failed:', error)
        }
        agentTimeoutRef.current = null
      }, 1000) // Small delay to let the main response start
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmit(e)
    }
  }

  const handleImageAttach = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0]
      const reader = new FileReader()
      reader.onloadend = () => {
        setAttachedImage(reader.result as string)
      }
      reader.readAsDataURL(file)
    }
  }

  const handleStartPentest = async (target: string, tests: string[], options?: any) => {
    try {
      // Check if user is authenticated (with dev mode bypass)
      if (!session?.access_token && !shouldBypassAuth()) {
        toast.error('Please log in to run penetration tests')
        return
      }
      
      // API URL now centralized - no local baseUrl needed
      
      // Prepare headers with authentication (handle dev mode)
      const headers: Record<string, string> = {
        'Content-Type': 'application/json'
      }
      
      // Add authorization header if we have a session or are in dev mode
      if (session?.access_token) {
        headers['Authorization'] = `Bearer ${session.access_token}`
      } else if (shouldBypassAuth()) {
        headers['X-Dev-Mode'] = 'true'
      }
      
      const response = await fetch(getApiUrl('/api/pentest/scan'), {
        method: 'POST',
        headers,
        body: JSON.stringify({ target, tests, options }),
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: 'Unknown error' }))
        console.error('Pentest API error:', errorData)
        throw new Error(errorData.message || `HTTP error! status: ${response.status}`)
      }

      const results = await response.json()
      
      // Format the results as a markdown message
      const formattedResults = formatPentestResults(results)
      
      // Send the initial request as user message
      const modeText = options?.useTor ? ' using TOR/OSINT mode' : ''
      await sendMessage(`Please run a penetration test on ${target}${modeText}`)
      
      // Store the results for AI analysis
      cachePentestResults(results, target)
      setCacheVersion(prev => prev + 1) // Force re-render to show new cache
      
      // Add the results as an assistant message
      addAssistantMessage(formattedResults, {
        threatLevel: results.summary?.risk_level || 'unknown',
        tool: 'penetration-test',
        command: `pentest ${target}${modeText}`,
        torMode: options?.useTor || false
      })
      
      toast.success(`Penetration test completed successfully${modeText}`)
      
      // Note: Stage 2 attack options can now be toggled manually via the toggle button
    } catch (error: any) {
      console.error('Pentest error:', error)
      const errorMessage = error.message || 'Failed to complete penetration test'
      
      // Check for common issues
      if (error.message.includes('Failed to fetch')) {
        toast.error('Cannot connect to backend server. Make sure the server is running on port 3001.')
      } else if (error.message.includes('CORS')) {
        toast.error('CORS error. Check backend CORS configuration.')
      } else {
        toast.error(`Pentest failed: ${errorMessage}`)
      }
      throw error
    }
  }

  const handleAnalyzePentest = async () => {
    if (!lastPentestResults) {
      toast.error('No penetration test results available to analyze')
      return
    }

    // Check if user is authenticated (with dev mode bypass)
    if (!session?.access_token && !shouldBypassAuth()) {
      toast.error('Please log in to analyze penetration test results')
      return
    }

    setAnalyzingPentest(true)
    try {
      // API URL now centralized - no local baseUrl needed
      
      // Prepare headers with authentication
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...(session?.access_token
          ? { 'Authorization': `Bearer ${session.access_token}` }
          : shouldBypassAuth()
            ? { 'Authorization': 'Bearer localhost-dev-token', 'x-dev-bypass': 'true' }
            : {})
      }
      
      const response = await fetch(getApiUrl('/api/chat/analyze-pentest'), {
        method: 'POST',
        headers,
        body: JSON.stringify({
          pentestResults: lastPentestResults,
          model: currentModel
        }),
      })

      if (!response.ok) {
        throw new Error('Failed to analyze penetration test results')
      }

      const analysis = await response.json()
      
      // Add user message asking for analysis
      await sendMessage('Please analyze the recent penetration test results and provide a comprehensive security assessment.')
      
      // Add the AI analysis as an assistant message
      addAssistantMessage(analysis.message, {
        threatLevel: 'high',
        tool: 'ai-pentest-analysis',
        command: 'analyze-pentest',
        analysisType: 'penetration_test_analysis'
      })
      
      toast.success('AI analysis completed successfully')
    } catch (error) {
      console.error('Pentest analysis error:', error)
      toast.error('Failed to analyze penetration test results')
    } finally {
      setAnalyzingPentest(false)
    }
  }

  // Note: API URLs now centralized in config/api.config.ts - no need for API_BASE variable

  const handleAnalyzeAssessmentFromMsg = async (_messageId: string, target: string) => {
    try {
      const url = getApiUrl('/api/agent/analyze-assessment')
      const resp = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(session?.access_token
            ? { 'Authorization': `Bearer ${session.access_token}` }
            : shouldBypassAuth()
              ? { 'Authorization': 'Bearer localhost-dev-token', 'x-dev-bypass': 'true' }
              : {})
        },
        credentials: 'include',
        body: JSON.stringify({ target, model: currentModel })
      })
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      const data = await resp.json()
      addAssistantMessage(data.message || 'AI analysis completed.', {
        tool: 'ai-pentest-analysis',
        analysisType: 'automated_assessment_analysis',
        threatLevel: data?.summary?.risk_level || 'unknown'
      })
    } catch (e: any) {
      toast.error(`Analyze with AI failed: ${e.message || e}`)
    }
  }

  const handleShowReasoningForMsg = async (messageId: string, target: string) => {
    const willOpen = !reasoningExpandedByMsg[messageId]
    setReasoningExpandedByMsg(prev => ({ ...prev, [messageId]: willOpen }))
    if (!willOpen || reasoningByMsg[messageId]) return
    try {
      const url = getApiUrl('/api/agent/reasoning')
      const resp = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(session?.access_token
            ? { 'Authorization': `Bearer ${session.access_token}` }
            : shouldBypassAuth()
              ? { 'Authorization': 'Bearer localhost-dev-token', 'x-dev-bypass': 'true' }
              : {})
        },
        credentials: 'include',
        body: JSON.stringify({ target, includeSteps: true, includeChainOfThought: true })
      })
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      const data = await resp.json()
      setReasoningByMsg(prev => ({ ...prev, [messageId]: data?.reasoning || 'No additional reasoning returned.' }))
    } catch (e: any) {
      setReasoningByMsg(prev => ({ ...prev, [messageId]: `Failed to load reasoning: ${e.message || e}` }))
    }
  }

  const handleTogglePatchForMsg = async (messageId: string, target: string) => {
    const willOpen = !patchOpenForMsg[messageId]
    setPatchOpenForMsg(prev => ({ ...prev, [messageId]: willOpen }))
    if (!willOpen) return
    if (patchPlanByMsg[messageId]) return
    try {
      const url = getApiUrl('/api/patch/plan')
      
      // Prepare headers with authentication (same as other API calls)
      const headers: Record<string, string> = {
        'Content-Type': 'application/json'
      }
      
      // Add authentication headers
      if (session?.access_token) {
        headers['Authorization'] = `Bearer ${session.access_token}`
      } else if (shouldBypassAuth()) {
        // For localhost development, bypass authentication
        headers['Authorization'] = `Bearer localhost-dev-token`
        headers['x-dev-bypass'] = 'true'
      }
      
      const resp = await fetch(url, {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({ target })
      })
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      const data = await resp.json()
      setPatchPlanByMsg(prev => ({ ...prev, [messageId]: data }))
    } catch (e: any) {
      toast.error(`Failed to load patch plan: ${e.message || e}`)
    }
  }

  const handleGenerateCustomFix = async (messageId: string, vulnId: string, target: string) => {
    const key = `${messageId}:${vulnId}`
    setPatchGeneratingFix(prev => ({ ...prev, [key]: true }))
    try {
      const url = getApiUrl('/api/patch/generate-fix')
      
      // Prepare headers with authentication (same as other API calls)
      const headers: Record<string, string> = {
        'Content-Type': 'application/json'
      }
      
      // Add authentication headers
      if (session?.access_token) {
        headers['Authorization'] = `Bearer ${session.access_token}`
      } else if (shouldBypassAuth()) {
        // For localhost development, bypass authentication
        headers['Authorization'] = `Bearer localhost-dev-token`
        headers['x-dev-bypass'] = 'true'
      }
      
      const resp = await fetch(url, {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({ target, vulnerabilityId: vulnId })
      })
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      const data = await resp.json()
      addAssistantMessage(`🛠️ **Custom Fix Generated for ${vulnId}**\n\n${data.fixMarkdown || 'See attached plan.'}`, {
        tool: 'patch-generation',
        command: 'generate-fix',
        vulnerabilityId: vulnId,
      })
    } catch (e: any) {
      toast.error(`Failed to generate fix: ${e.message || e}`)
    } finally {
      setPatchGeneratingFix(prev => ({ ...prev, [key]: false }))
    }
  }

  const handleGetAgentRecommendations = async (target: string, context: string) => {
    try {
      const url = getApiUrl('/api/agent/recommendations')
      
      // Prepare headers with authentication
      const headers: Record<string, string> = {
        'Content-Type': 'application/json'
      }
      
      // Add authentication headers
      if (session?.access_token) {
        headers['Authorization'] = `Bearer ${session.access_token}`
      } else if (shouldBypassAuth()) {
        headers['Authorization'] = `Bearer localhost-dev-token`
        headers['x-dev-bypass'] = 'true'
      }
      
      const resp = await fetch(url, {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({ target, context })
      })
      
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      const data = await resp.json()
      
      // Add agent recommendations as a message
      const recommendationsText = `🤖 **Agent Mode Recommendations for ${target}**

**Context:** ${context}

**Recommended Tools:**
${data.recommendations.tools.map((tool: any) => 
  `• **${tool.name}**: ${tool.description}\n  Usage: \`${tool.usage}\``
).join('\n')}

**Relevant Techniques:**
${data.recommendations.techniques.map((technique: any) => 
  `• **${technique.name}**: ${technique.description}\n  Steps: ${technique.steps.join(', ')}`
).join('\n')}

**Next Steps:**
${data.recommendations.nextSteps.map((step: string) => `• ${step}`).join('\n')}

${data.recommendations.contextualInfo ? `\n**Additional Context:**${data.recommendations.contextualInfo}` : ''}
`
      
      addAssistantMessage(recommendationsText, {
        tool: 'agent-recommendations',
        target,
        context,
        recommendations: data.recommendations
      })
      
      return data.recommendations
      
    } catch (e: any) {
      toast.error(`Failed to get agent recommendations: ${e.message || e}`)
      return null
    }
  }

  const handleGenerateAttackPayload = async (attackType: string, targetUrl: string, customDescription?: string) => {
    try {
      // API URL now centralized - no local baseUrl needed
      const requestBody = customDescription 
        ? { attackType, targetUrl, customDescription }
        : { attackType, targetUrl }
        
      // Prepare headers with authentication
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      }
      
      // Add authorization header if we have a session
      if (session?.access_token) {
        headers['Authorization'] = `Bearer ${session.access_token}`
      }
      
      const response = await fetch(getApiUrl('/api/attack/generate-payload'), {
        method: 'POST',
        headers,
        body: JSON.stringify(requestBody),
      })

      if (!response.ok) {
        throw new Error('Failed to generate attack payload')
      }

      const result = await response.json()
      
      // Format the attack payload as a markdown message
      const formattedPayload = formatAttackPayload(result.payload)
      
      // Send user message for the attack generation
      const userMessage = customDescription 
        ? `Generate a custom attack payload for "${customDescription}" targeting ${targetUrl}`
        : `Generate ${result.payload.name} payload for ${targetUrl}`
      await sendMessage(userMessage)
      
      // Add the payload as an assistant message
      addAssistantMessage(formattedPayload, {
        threatLevel: 'high',
        tool: 'attack-payload-generator',
        command: `generate-payload ${attackType}`,
        attackType: attackType
      })
      
    } catch (error) {
      console.error('Attack payload generation error:', error)
      throw error
    }
  }

  const formatAttackPayload = (payload: any): string => {
    let output = `# ⚔️ ${payload.name}\n\n`
    output += `**Description:** ${payload.description}\n\n`
    output += `**Target:** ${payload.payload.target}\n`
    output += `**Attack Type:** ${payload.payload.type}\n\n`

    // Attack Vectors
    output += `## 🎯 Attack Vectors\n\n`
    payload.payload.attack_vectors.forEach((vector: any, index: number) => {
      output += `### ${index + 1}. ${vector.name}\n\n`
      output += `**Description:** ${vector.description}\n\n`
      
      if (vector.script) {
        output += `**Bash Script:**\n\n\`\`\`bash\n${vector.script}\n\`\`\`\n\n`
      }
      
      if (vector.code) {
        output += `**Python Code:**\n\n\`\`\`python\n${vector.code}\n\`\`\`\n\n`
      }
      
      if (vector.payload) {
        output += `**Payload:**\n\n\`\`\`python\n${vector.payload}\n\`\`\`\n\n`
      }
      
      if (vector.wordlists) {
        output += `**Recommended Wordlists:**\n`
        vector.wordlists.forEach((wordlist: string) => {
          output += `- ${wordlist}\n`
        })
        output += `\n`
      }
    })

    // Detection Signatures
    if (payload.payload.detection_signatures?.length > 0) {
      output += `## 🔍 Detection Signatures\n\n`
      payload.payload.detection_signatures.forEach((signature: string) => {
        output += `- ${signature}\n`
      })
      output += `\n`
    }

    // Mitigation Strategies
    if (payload.payload.mitigation_strategies?.length > 0) {
      output += `## 🛡️ Mitigation Strategies\n\n`
      payload.payload.mitigation_strategies.forEach((strategy: string) => {
        output += `- ${strategy}\n`
      })
      output += `\n`
    }

    output += `---\n\n`
    output += `*⚠️ This payload is generated for authorized security testing purposes only.*\n`
    output += `*📋 Save these payloads for your penetration testing toolkit.*\n\n`
    output += `💡 **Next Steps:** Review the payload, customize as needed, and deploy in a controlled testing environment.`

    return output
  }

  const formatPentestResults = (results: any): string => {
    let output = `# 🎯 Penetration Test Results\n\n`
    output += `**Target:** ${results.target}\n`
    output += `**Timestamp:** ${new Date(results.timestamp).toLocaleString()}\n`
    output += `**Tests Performed:** ${results.tests_performed.join(', ')}\n`
    
    // Display active security options
    if (results.options) {
      const activeOptions = []
      if (results.options.useTor) activeOptions.push('🧅 TOR')
      if (results.options.useOsint) activeOptions.push('🔍 OSINT')
      if (results.options.firewallBypass) activeOptions.push('🔥 Firewall Bypass')
      
      if (activeOptions.length > 0) {
        output += `**Security Options:** ${activeOptions.join(' | ')}\n`
      }
    }
    
    // Display TOR status if enabled
    if (results.tor_status) {
      output += `\n## 🧅 TOR Status\n\n`
      output += `- **Status:** ${results.tor_status.tor_enabled ? 'Active' : 'Inactive'}\n`
      output += `- **Exit Node:** ${results.tor_status.exit_node}\n`
      output += `- **Circuit Hops:** ${results.tor_status.circuit_hops}\n`
      if (results.tor_status.bridge_type) {
        output += `- **Bridge Type:** ${results.tor_status.bridge_type}\n`
      }
      if (results.tor_status.expected_latency) {
        output += `- **Expected Latency:** ${results.tor_status.expected_latency}\n`
      }
      output += `- **Note:** ${results.tor_status.note}\n\n`
    }
    
    // Display active OSINT tools if used
    if (results.options?.useOsint && results.options.osintTools) {
      const activeTools = Object.entries(results.options.osintTools)
        .filter(([_, enabled]) => enabled)
        .map(([tool, _]) => tool)
      
      if (activeTools.length > 0) {
        output += `## 🔍 OSINT Configuration\n\n`
        output += `**Active Sources:** ${activeTools.map(t => t.charAt(0).toUpperCase() + t.slice(1)).join(', ')}\n\n`
      }
    }
    
    // Display firewall bypass techniques if used
    if (results.options?.firewallBypass && results.options.bypassTechniques) {
      const activeTechniques = Object.entries(results.options.bypassTechniques)
        .filter(([_, enabled]) => enabled)
        .map(([tech, _]) => {
          const techNames: Record<string, string> = {
            fragmentation: 'Packet Fragmentation',
            decoyIPs: 'Decoy IPs',
            timingEvasion: 'Timing Evasion',
            userAgentRotation: 'User-Agent Rotation'
          }
          return techNames[tech] || tech
        })
      
      if (activeTechniques.length > 0) {
        output += `## 🔥 Firewall Bypass Configuration\n\n`
        output += `**Active Techniques:** ${activeTechniques.join(', ')}\n\n`
      }
    }

    // Summary
    if (results.summary) {
      output += `## 📊 Summary\n\n`
      output += `- **Risk Level:** ${results.summary.risk_level.toUpperCase()}\n`
      output += `- **Total Issues:** ${results.summary.total_issues}\n`
      if (results.summary.security_score) {
        output += `- **Security Score:** ${results.summary.security_score}/100\n`
      }
      if (results.summary.osint_enhanced) {
        output += `- **OSINT Enhanced:** ✅ Yes\n`
      }
      output += `\n`

      if (results.summary.recommendations?.length > 0) {
        output += `### 🔧 Recommendations\n\n`
        results.summary.recommendations.forEach((rec: string, index: number) => {
          output += `${index + 1}. ${rec}\n`
        })
        output += `\n`
      }
    }

    // OSINT Intelligence (if available)
    if (results.results.osint) {
      output += `## 🔍 OSINT Intelligence Gathering\n\n`
      const osint = results.results.osint
      
      if (osint.sources_checked && Array.isArray(osint.sources_checked)) {
        output += `**Sources Checked:** ${osint.sources_checked.join(', ')}\n\n`
      }
      
      // Shodan data
      if (osint.data_found && osint.data_found.shodan) {
        const shodan = osint.data_found.shodan
        output += `### 🌐 Shodan Intelligence\n\n`
        if (shodan.open_ports && Array.isArray(shodan.open_ports)) {
          output += `- **Open Ports:** ${shodan.open_ports.join(', ')}\n`
        }
        if (shodan.services && Array.isArray(shodan.services)) {
          output += `- **Services:** ${shodan.services.join(', ')}\n`
        }
        if (shodan.vulnerabilities && Array.isArray(shodan.vulnerabilities)) {
          output += `- **Vulnerabilities:** ${shodan.vulnerabilities.join(', ')}\n`
        }
        if (shodan.note) {
          output += `- **Note:** ${shodan.note}\n\n`
        }
      }
      
      // Wayback Machine
      if (osint.data_found && osint.data_found.wayback) {
        const wayback = osint.data_found.wayback
        output += `### 📚 Wayback Machine\n\n`
        if (wayback.total_snapshots !== undefined) {
          output += `- **Snapshots:** ${wayback.total_snapshots}\n`
        }
        if (wayback.first_seen) {
          output += `- **First Seen:** ${wayback.first_seen}\n`
        }
        if (wayback.last_seen) {
          output += `- **Last Seen:** ${wayback.last_seen}\n`
        }
        if (wayback.interesting_paths && Array.isArray(wayback.interesting_paths)) {
          output += `- **Interesting Paths:** ${wayback.interesting_paths.join(', ')}\n\n`
        }
      }
      
      // DNS History
      if (osint.data_found && osint.data_found.dns_history) {
        const dns = osint.data_found.dns_history
        output += `### 🔄 DNS History\n\n`
        if (dns.a_records && Array.isArray(dns.a_records)) {
          const ips = dns.a_records.map((record: any) => record.ip || record).filter(Boolean)
          if (ips.length > 0) {
            output += `- **Historical IPs:** ${ips.join(', ')}\n`
          }
        }
        if (dns.nameserver_changes !== undefined) {
          output += `- **Nameserver Changes:** ${dns.nameserver_changes}\n`
        }
        if (dns.hosting_providers && Array.isArray(dns.hosting_providers)) {
          output += `- **Hosting Providers:** ${dns.hosting_providers.join(', ')}\n\n`
        }
      }
      
      // Special Intelligence (if available)
      if (osint.data_found && osint.data_found.special_intelligence) {
        const intel = osint.data_found.special_intelligence
        output += `### 🎯 Special Intelligence\n\n`
        output += `**Status:** ${intel.status}\n`
        output += `**Confidence:** ${intel.confidence}\n\n`
        
        if (intel.key_findings) {
          if (intel.key_findings.owner_info) {
            output += `**Owner Information:**\n`
            output += `- Name: ${intel.key_findings.owner_info.name}\n`
            output += `- Role: ${intel.key_findings.owner_info.role}\n`
            output += `- Company: ${intel.key_findings.owner_info.company}\n\n`
          }
          
          if (intel.key_findings.company_info) {
            output += `**Company Information:**\n`
            output += `- Name: ${intel.key_findings.company_info.name}\n`
            output += `- Type: ${intel.key_findings.company_info.type}\n`
            output += `- Founded: ${intel.key_findings.company_info.founded}\n\n`
          }
        }
      }
    }

    // Detailed Results
    output += `## 🔍 Detailed Results\n\n`

    // Basic Info with Enhanced Network Details
    if (results.results.basic_info) {
      const info = results.results.basic_info
      output += `### 🌐 Network Configuration Analysis\n\n`
      
      if (info.dns_error) {
        output += `❌ **DNS Error:** ${info.dns_error}\n\n`
      } else {
        // Primary connection info
        output += `**Target Domain:** ${info.domain}\n`
        output += `**Primary IP Address:** ${info.primary_ip || 'Unknown'}\n`
        output += `**IP Family:** ${info.ip_family || 'Unknown'}\n`
        output += `**Total IP Addresses:** ${info.total_ip_count || 1}\n\n`

        // All IP addresses (like ipconfig shows multiple interfaces)
        if (info.all_ips && info.all_ips.length > 0) {
          output += `**All Resolved IP Addresses:**\n`
          info.all_ips.forEach((ip: string, index: number) => {
            output += `- Interface ${index + 1}: ${ip}\n`
          })
          output += `\n`
        }

        // Network Information (ipconfig-style)
        if (info.network_info && !info.network_info.error) {
          const net = info.network_info
          
          output += `### 🔌 Network Interface Details\n\n`
          output += `**Connection Type:** ${net.network_config?.interface_type || 'Unknown'}\n`
          output += `**Connection Status:** ${net.network_config?.connection_status || 'Unknown'}\n`
          output += `**Network Type:** ${net.network_config?.network_type || 'Unknown'}\n`
          output += `**Accessibility:** ${net.network_config?.accessibility || 'Unknown'}\n\n`

          // IP Classification
          output += `### 📊 IP Address Classification\n\n`
          output += `**IP Type:** ${net.ip_type || 'Unknown'}\n`
          output += `**IP Class:** ${net.ip_class || 'Unknown'}\n`
          output += `**Private Network:** ${net.is_private ? 'Yes' : 'No'}\n\n`

          // Subnet Information (like ipconfig subnet details)
          if (net.subnet_info && !net.subnet_info.error) {
            output += `### 🌐 Subnet Configuration\n\n`
            output += `**Default Subnet Mask:** ${net.subnet_info.default_subnet_mask}\n`
            output += `**Network Address:** ${net.subnet_info.network_address}\n`
            output += `**Broadcast Address:** ${net.subnet_info.broadcast_address}\n`
            output += `**Host Bits:** ${net.subnet_info.host_bits}\n\n`
          }

          // Routing Information (like ipconfig gateway info)
          if (net.network_config?.routing_info) {
            output += `### 🛣️ Routing Information\n\n`
            output += `**Default Gateway:** ${net.network_config.routing_info.default_gateway}\n`
            output += `**DNS Servers:** ${net.network_config.routing_info.dns_servers}\n`
            output += `**DHCP Enabled:** ${net.network_config.routing_info.dhcp_enabled}\n`
            if (net.network_config.routing_info.note) {
              output += `\n*Note: ${net.network_config.routing_info.note}*\n`
            }
            output += `\n`
          }

          // Geographic Information
          if (net.geolocation) {
            output += `### 🌍 Geographic Information\n\n`
            if (net.geolocation.status === 'mock_data') {
              output += `**Status:** Service not configured\n`
              output += `**Note:** ${net.geolocation.note}\n\n`
            } else {
              output += `**Country:** ${net.geolocation.country || 'Unknown'}\n`
              output += `**Region:** ${net.geolocation.region || 'Unknown'}\n`
              output += `**City:** ${net.geolocation.city || 'Unknown'}\n`
              output += `**Timezone:** ${net.geolocation.timezone || 'Unknown'}\n\n`
            }
          }

          // Organization Information
          if (net.organization) {
            output += `### 🏢 Organization Information\n\n`
            if (net.organization.status === 'mock_data') {
              output += `**Status:** Service not configured\n`
              output += `**Note:** ${net.organization.note}\n\n`
            } else {
              output += `**Organization:** ${net.organization.organization || 'Unknown'}\n`
              output += `**ISP:** ${net.organization.isp || 'Unknown'}\n`
              output += `**ASN:** ${net.organization.asn || 'Unknown'}\n\n`
            }
          }
        } else if (info.network_info?.error) {
          output += `### ❌ Network Analysis Error\n\n`
          output += `**Error:** ${info.network_info.error}\n\n`
        }
      }
    }

    // Headers Check
    if (results.results.headers) {
      const headers = results.results.headers
      output += `### Security Headers Analysis\n\n`
      if (headers.error) {
        output += `❌ **Error:** ${headers.error}\n\n`
      } else {
        output += `- **Status Code:** ${headers.status_code}\n`
        output += `- **Server:** ${headers.server}\n`
        output += `- **Powered By:** ${headers.powered_by}\n`
        
        if (headers.security_score) {
          output += `- **Security Score:** ${headers.security_score.score}/100\n\n`
          
          if (headers.security_score.issues.length > 0) {
            output += `**Security Issues:**\n`
            headers.security_score.issues.forEach((issue: string) => {
              output += `- ⚠️ ${issue}\n`
            })
            output += `\n`
          }
        }

        output += `**Security Headers:**\n`
        Object.entries(headers.security_headers).forEach(([key, value]) => {
          const status = value ? '✅' : '❌'
          output += `- ${status} ${key}: ${value || 'Missing'}\n`
        })
        output += `\n`
      }
    }

    // SSL Check
    if (results.results.ssl) {
      const ssl = results.results.ssl
      output += `### SSL/TLS Analysis\n\n`
      if (ssl.error) {
        output += `❌ **Error:** ${ssl.error}\n`
        if (ssl.manual_check) {
          output += `🔗 **Manual Check:** ${ssl.manual_check}\n`
        }
      } else {
        output += `- **SSL Labs Grade:** ${ssl.ssl_labs_grade}\n`
        output += `- **Check URL:** [SSL Labs Report](${ssl.check_url})\n`
      }
      output += `\n`
    }

    // DNS Enumeration
    if (results.results.dns) {
      const dns = results.results.dns
      output += `### DNS Enumeration\n\n`
      if (dns.error) {
        output += `❌ **Error:** ${dns.error}\n\n`
      } else {
        if (dns.a_records?.length > 0) {
          output += `**A Records:**\n`
          dns.a_records.forEach((record: string) => {
            output += `- ${record}\n`
          })
          output += `\n`
        }

        if (dns.aaaa_records?.length > 0) {
          output += `**AAAA Records:**\n`
          dns.aaaa_records.forEach((record: string) => {
            output += `- ${record}\n`
          })
          output += `\n`
        }

        if (dns.mx_records?.length > 0) {
          output += `**MX Records:**\n`
          dns.mx_records.forEach((record: any) => {
            output += `- Priority ${record.priority}: ${record.exchange}\n`
          })
          output += `\n`
        }

        if (dns.txt_records?.length > 0) {
          output += `**TXT Records:**\n`
          dns.txt_records.forEach((record: string[]) => {
            output += `- ${record.join(' ')}\n`
          })
          output += `\n`
        }
      }
    }

    // Robots.txt Check
    if (results.results.robots) {
      const robots = results.results.robots
      output += `### Robots.txt Analysis\n\n`
      if (robots.error) {
        output += `❌ **Error:** ${robots.error}\n\n`
      } else if (robots.exists) {
        output += `✅ **Robots.txt found**\n`
        output += `- **URL:** ${robots.url}\n`
        
        if (robots.analysis) {
          const analysis = robots.analysis
          output += `- **Total Rules:** ${analysis.total_rules}\n`
          
          if (analysis.disallowed_paths?.length > 0) {
            output += `\n**Disallowed Paths:**\n`
            analysis.disallowed_paths.forEach((path: string) => {
              output += `- ${path}\n`
            })
          }

          if (analysis.sitemaps?.length > 0) {
            output += `\n**Sitemaps:**\n`
            analysis.sitemaps.forEach((sitemap: string) => {
              output += `- ${sitemap}\n`
            })
          }
        }
        output += `\n`
      } else {
        output += `❌ **Robots.txt not found**\n\n`
      }
    }

    // Port Scanning
    if (results.results.port_scan) {
      const ports = results.results.port_scan
      output += `### 🔌 Port Scanning\n\n`
      
      if (ports.osint_enhanced) {
        output += `**✨ OSINT Enhanced Scan**\n`
        output += `**Note:** ${ports.enhanced_scan_note || 'Enhanced with OSINT intelligence'}\n\n`
      }
      
      if (ports.error) {
        output += `❌ **Error:** ${ports.error}\n\n`
      } else {
        output += `**Domain:** ${ports.domain}\n`
        output += `**Scan Type:** ${ports.scan_type}\n`
        output += `**Total Scanned:** ${ports.total_scanned}\n`
        output += `**Open Ports:** ${ports.total_open}\n\n`
        
        if (ports.open_ports && ports.open_ports.length > 0) {
          output += `**🟢 Open Ports:**\n`
          ports.open_ports.forEach((port: any) => {
            output += `- **Port ${port.port}** - ${port.service} (${port.protocol || 'tcp'})\n`
          })
          output += `\n`
        }
        
        // OSINT Intelligence if available
        if (ports.osint_intelligence) {
          output += `**🔍 OSINT Intelligence:**\n\n`
          
          if (ports.osint_intelligence.shodan_data) {
            const shodan = ports.osint_intelligence.shodan_data
            output += `*Shodan Data:*\n`
            if (shodan.additional_ports) {
              output += `- Additional ports likely open: ${shodan.additional_ports.join(', ')}\n`
            }
            if (shodan.service_banners) {
              output += `- Service Banners:\n`
              Object.entries(shodan.service_banners).forEach(([port, banner]) => {
                output += `  - Port ${port}: ${banner}\n`
              })
            }
            output += `\n`
          }
          
          if (ports.osint_intelligence.censys_data) {
            const censys = ports.osint_intelligence.censys_data
            output += `*Censys Data:*\n`
            output += `- Certificates: ${censys.certificates.join(', ')}\n`
            output += `- Protocols: ${censys.protocols.join(', ')}\n\n`
          }
        }
        
        if (ports.scan_note) {
          output += `📝 **Note:** ${ports.scan_note}\n\n`
        }
      }
    }

    // Subdomain Enumeration
    if (results.results.subdomain_enum) {
      const subdomains = results.results.subdomain_enum
      output += `### 🌐 Subdomain Enumeration\n\n`
      
      if (subdomains.osint_enhanced) {
        output += `**✨ OSINT Enhanced Scan**\n`
        output += `**Sources:** ${subdomains.osint_sources?.join(', ') || 'Multiple'}\n\n`
      }
      
      if (subdomains.error) {
        output += `❌ **Error:** ${subdomains.error}\n\n`
      } else {
        output += `**Domain:** ${subdomains.domain}\n`
        output += `**Total Checked:** ${subdomains.total_checked}\n`
        output += `**Total Found:** ${subdomains.total_found}\n`
        
        if (subdomains.wildcard_dns) {
          output += `⚠️ **Warning:** Wildcard DNS detected - results may include false positives\n`
        }
        
        output += `\n`
        
        if (subdomains.found_subdomains && subdomains.found_subdomains.length > 0) {
          output += `**Active Subdomains:**\n`
          
          // Group by source if OSINT enhanced
          const standardSubdomains = subdomains.found_subdomains.filter((s: any) => !s.source || s.source !== 'OSINT')
          const osintSubdomains = subdomains.found_subdomains.filter((s: any) => s.source === 'OSINT')
          
          if (standardSubdomains.length > 0) {
            output += `\n*Standard Discovery:*\n`
            standardSubdomains.forEach((subdomain: any) => {
              output += `- **${subdomain.subdomain}** → ${subdomain.ip}\n`
            })
          }
          
          if (osintSubdomains.length > 0) {
            output += `\n*OSINT Intelligence:*\n`
            osintSubdomains.forEach((subdomain: any) => {
              output += `- **${subdomain.subdomain}** → ${subdomain.ip} (via OSINT)\n`
            })
          }
          
          output += `\n`
        } else {
          output += `*No subdomains found in this scan.*\n\n`
        }
        
        if (subdomains.note) {
          output += `📝 **Note:** ${subdomains.note}\n\n`
        }
      }
    }

    // Directory Enumeration
    if (results.results.directory_enum) {
      const dirs = results.results.directory_enum
      output += `### 📁 Directory Enumeration\n\n`
      
      if (dirs.osint_enhanced) {
        output += `**✨ OSINT Enhanced Scan**\n`
        output += `**Sources:** ${dirs.osint_sources?.join(', ') || 'Multiple'}\n\n`
      }
      
      if (dirs.error) {
        output += `❌ **Error:** ${dirs.error}\n\n`
      } else {
        output += `**Target:** ${dirs.target}\n`
        output += `**Total Checked:** ${dirs.total_checked}\n`
        output += `**Total Found:** ${dirs.total_found}\n\n`
        
        if (dirs.found_paths && dirs.found_paths.length > 0) {
          // Group by source if OSINT enhanced
          const standardPaths = dirs.found_paths.filter((p: any) => !p.source || p.source !== 'OSINT')
          const osintPaths = dirs.found_paths.filter((p: any) => p.source === 'OSINT')
          
          if (standardPaths.length > 0) {
            output += `**Found Paths (Standard):**\n`
            standardPaths.forEach((path: any) => {
              const statusIcon = path.status === 200 ? '✅' : path.status === 403 ? '🔒' : '↗️'
              output += `- ${statusIcon} **${path.path}** (${path.status})`
              if (path.title) output += ` - ${path.title}`
              output += `\n`
            })
            output += `\n`
          }
          
          if (osintPaths.length > 0) {
            output += `**Found Paths (OSINT Intelligence):**\n`
            osintPaths.forEach((path: any) => {
              const statusIcon = path.status === 200 ? '✅' : path.status === 403 ? '🔒' : '↗️'
              output += `- ${statusIcon} **${path.path}** (${path.status}) - via OSINT\n`
            })
            output += `\n`
          }
        }
        
        if (dirs.interesting_findings && dirs.interesting_findings.length > 0) {
          output += `**🚨 Security Findings:**\n`
          const highRisk = dirs.interesting_findings.filter((f: any) => f.risk === 'high')
          const mediumRisk = dirs.interesting_findings.filter((f: any) => f.risk === 'medium')
          const lowRisk = dirs.interesting_findings.filter((f: any) => f.risk === 'low')
          
          if (highRisk.length > 0) {
            output += `\n**❗ High Risk:**\n`
            highRisk.forEach((finding: any) => {
              output += `- **${finding.path}** - ${finding.description}\n`
            })
          }
          
          if (mediumRisk.length > 0) {
            output += `\n**⚠️ Medium Risk:**\n`
            mediumRisk.forEach((finding: any) => {
              output += `- **${finding.path}** - ${finding.description}\n`
            })
          }
          
          if (lowRisk.length > 0) {
            output += `\n**ℹ️ Low Risk:**\n`
            lowRisk.forEach((finding: any) => {
              output += `- **${finding.path}** - ${finding.description}\n`
            })
          }
          output += `\n`
        }
        
        if (dirs.note) {
          output += `📝 **Note:** ${dirs.note}\n\n`
        }
      }
    }

    output += `---\n\n`
    output += `*⚠️ This penetration test was performed for authorized security assessment purposes only.*\n\n`
    output += `💡 **Tip:** Use the "Analyze with AI" button above to get a detailed security assessment with attack vectors and remediation strategies.`

    return output
  }

  return (
    <>
      <SEOOptimizer {...seoConfigs.chat} />
      <ChatLayout>
      <div className="flex-1 flex flex-col bg-[#0d0d0d] h-full overflow-x-hidden w-full min-w-0">
        {/* Header */}
        <header className="bg-[#1a1a1a] border-b border-terminal-border px-6 py-4 flex items-center justify-between flex-shrink-0">
          <div className="flex items-center space-x-3">
            <h1 className="text-xl font-medium text-terminal-text lg:ml-0 ml-12">Chat</h1>
            {agentMode && (
              <span className="px-2 py-1 bg-zypheron-500 text-white text-xs rounded-full flex items-center">
                <RobotIcon size={12} className="mr-1" />
                AGENT MODE
              </span>
            )}
          </div>
          <div className="flex items-center space-x-4">
            <button
              onClick={() => setShowPentestPanel(true)}
              className="flex items-center space-x-2 px-3 py-2 bg-zypheron-500/10 hover:bg-zypheron-500/20 border border-zypheron-500/30 rounded-lg text-zypheron-400 hover:text-zypheron-300 transition-colors"
            >
              <Target className="w-4 h-4" />
              <span className="text-sm font-medium">Pen Test</span>
            </button>
            
            <button
              onClick={() => window.open('/red-team-ops', '_blank')}
              className="flex items-center space-x-2 px-3 py-2 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 rounded-lg text-red-400 hover:text-red-300 transition-colors"
            >
              <Shield className="w-4 h-4" />
              <span className="text-sm font-medium">Red Team Ops</span>
            </button>
            
            {lastPentestResults && (
              <button
                onClick={handleAnalyzePentest}
                disabled={analyzingPentest}
                className="flex items-center space-x-2 px-3 py-2 bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/30 rounded-lg text-purple-400 hover:text-purple-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {analyzingPentest ? (
                  <Loader className="w-4 h-4 animate-spin" />
                ) : (
                  <Brain className="w-4 h-4" />
                )}
                <span className="text-sm font-medium">
                  {analyzingPentest ? 'Analyzing...' : 'Analyze with AI'}
                </span>
              </button>
            )}
            
            {/* Cache Management Gear Icon */}
            <button
              onClick={() => setShowCacheModal(true)}
              className="flex items-center justify-center w-10 h-10 bg-terminal-surface hover:bg-terminal-border border border-terminal-border rounded-lg text-terminal-muted hover:text-terminal-text transition-colors"
              title="Cache Management"
            >
              <Settings className="w-4 h-4" />
            </button>
            
            <div className="flex items-center space-x-2 text-sm">
              <div className="w-2 h-2 bg-green-500 rounded-full"></div>
              <span className="text-green-500">Online</span>
            </div>
          </div>
        </header>

      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto p-8">
        <div className="max-w-4xl mx-auto">
          {!currentSession?.messages.length && (
            <div className="text-center py-16">
              {/* Large Zypheron Logo */}
              <div className="mb-8">
                <img 
                  src={zypheronLogo} 
                  alt="Zypheron" 
                  className="w-48 h-48 mx-auto object-contain"
                />
              </div>
              
              {/* Terminal Prompt Icon */}
              <div className="mb-8">
                <div className="inline-flex items-center justify-center w-16 h-16 bg-zypheron-500/10 rounded-lg">
                  <span className="text-zypheron-500 font-mono text-2xl font-bold">{'>'}_</span>
                </div>
              </div>

              {/* Welcome Message */}
              <h2 className="text-3xl font-bold text-white mb-6">Welcome to Zypheron</h2>
              <p className="text-terminal-muted text-lg max-w-2xl mx-auto leading-relaxed">
                Your AI-powered cybersecurity assistant. Ask about threat analysis, 
                security tools, or get help with penetration testing techniques.
              </p>
            </div>
          )}

          {currentSession?.messages.map((message) => (
            <div key={message.id} className="mb-6">
              {message.role === 'user' ? (
                <div className="flex justify-end">
                  <div className="bg-zypheron-500/10 border border-zypheron-500/30 rounded-lg p-4 max-w-[80%]">
                    <div className="text-zypheron-400 text-sm mb-2 font-medium">You</div>
                    <div className="text-terminal-text">{message.content}</div>
                    {message.attachment && (
                      <div className="mt-2">
                        <img src={message.attachment} alt="Attachment" className="rounded-lg max-w-xs" />
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="flex justify-start">
                  <div className="bg-[#1a1a1a] border border-terminal-border rounded-lg p-4 max-w-[80%]">
                    <div className="text-green-400 text-sm mb-2 font-medium">Zypheron</div>
                    <div className="prose prose-invert prose-sm max-w-none">
                      <ReactMarkdown
                        components={{
                          code({ className, children, ...props }: any) {
                            const match = /language-(\w+)/.exec(className || '')
                            const isInline = !className || !match
                            
                            return isInline ? (
                              <code className="bg-terminal-border px-1 py-0.5 rounded text-zypheron-400 text-sm" {...props}>
                                {children}
                              </code>
                            ) : (
                              <SyntaxHighlighter
                                style={oneDark as any}
                                language={match[1]}
                                PreTag="div"
                                {...props}
                              >
                                {String(children).replace(/\n$/, '')}
                              </SyntaxHighlighter>
                            )
                          }
                        }}
                      >
                        {message.content}
                      </ReactMarkdown>
                    </div>
                    {message.attachment && (
                      <div className="mt-2">
                        <img src={message.attachment} alt="Attachment" className="rounded-lg max-w-xs" />
                      </div>
                    )}
                    
                    {/* Action bar for pentest/assessment messages */}
                    {(message.metadata?.tool === 'penetration-test' || message.metadata?.tool === 'automated_assessment') && (
                      <div className="mt-4 pt-3 border-t border-terminal-border space-y-3">
                        <div className="flex flex-wrap gap-2">
                          <button
                            onClick={() => handleAnalyzeAssessmentFromMsg(message.id, message.metadata?.target || lastPentestTarget || '')}
                            className="px-3 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm"
                          >
                            Analyze with AI
                          </button>
                          <button
                            onClick={() => handleShowReasoningForMsg(message.id, message.metadata?.target || lastPentestTarget || '')}
                            className="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm"
                          >
                            {reasoningExpandedByMsg[message.id] ? 'Hide reasoning' : 'Show more'}
                          </button>
                          <button
                            onClick={() => handleTogglePatchForMsg(message.id, message.metadata?.target || lastPentestTarget || '')}
                            className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm flex items-center space-x-2"
                          >
                            <span>Patch</span>
                            <span className={`w-2 h-2 rounded-full ${patchOpenForMsg[message.id] ? 'bg-red-500' : 'bg-gray-500'}`} />
                          </button>
                          {lastPentestTarget && (
                            <button
                              onClick={() => setShowAttackOptions(!showAttackOptions)}
                              className="px-3 py-2 bg-red-600/20 hover:bg-red-600/30 text-red-300 border border-red-600/40 rounded-lg text-sm flex items-center space-x-2"
                            >
                              {showAttackOptions ? <ToggleRight className="w-4 h-4" /> : <ToggleLeft className="w-4 h-4" />}
                              <span>{showAttackOptions ? 'Hide' : 'Stage 2 Vectors'}</span>
                            </button>
                          )}
                        </div>

                        {reasoningExpandedByMsg[message.id] && (
                          <div className="bg-[#101010] border border-terminal-border rounded-lg p-3">
                            <div className="text-terminal-muted text-xs mb-2">AI Reasoning & Steps</div>
                            <div className="prose prose-invert prose-sm max-w-none">
                              <ReactMarkdown>{reasoningByMsg[message.id] || 'Loading...'}</ReactMarkdown>
                            </div>
                          </div>
                        )}

                        {patchOpenForMsg[message.id] && (
                          <div className="bg-blue-950/30 border border-blue-600/40 rounded-lg p-4">
                            <div className="flex items-center justify-between mb-3">
                              <div className="text-blue-300 font-semibold">Quick Patch Panel</div>
                              <div className={`w-2 h-2 rounded-full ${patchOpenForMsg[message.id] ? 'bg-red-500' : 'bg-gray-500'}`} />
                            </div>
                            {!patchPlanByMsg[message.id] && (
                              <div className="text-terminal-muted text-sm">Loading patch plan...</div>
                            )}
                            {patchPlanByMsg[message.id]?.vulnerabilities?.length > 0 ? (
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                {patchPlanByMsg[message.id].vulnerabilities.map((v: any) => {
                                  const key = `${message.id}:${v.id}`
                                  return (
                                    <div key={v.id} className="bg-[#0f0f14] border border-blue-600/30 rounded-lg p-3">
                                      <div className="flex items-center justify-between mb-1">
                                        <div className="font-medium text-terminal-text">{v.title || v.id}</div>
                                        <span className={`px-2 py-0.5 rounded text-xs ${
                                          v.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                                          v.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                                          v.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' : 'bg-green-500/20 text-green-400'
                                        }`}>{(v.severity || 'low').toUpperCase()}</span>
                                      </div>
                                      <div className="text-terminal-muted text-sm mb-2">{v.description || 'No description.'}</div>
                                      <div className="flex flex-wrap gap-2">
                                        <button
                                          onClick={() => handleGenerateCustomFix(message.id, v.id, message.metadata?.target || lastPentestTarget || '')}
                                          className="px-2 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs"
                                        >
                                          Generate custom fix
                                        </button>
                                        <details className="text-xs">
                                          <summary className="cursor-pointer select-none text-blue-300">Show more</summary>
                                          <div className="mt-1 text-terminal-muted">
                                            {(v.details && typeof v.details === 'string') ? v.details : JSON.stringify(v.details || v, null, 2)}
                                          </div>
                                        </details>
                                      </div>
                                      {patchGeneratingFix[key] && (
                                        <div className="text-xs text-blue-300 mt-2">Generating fix...</div>
                                      )}
                                    </div>
                                  )
                                })}
                              </div>
                            ) : patchPlanByMsg[message.id] ? (
                              <div className="text-terminal-muted text-sm">No vulnerabilities detected by patch planner.</div>
                            ) : null}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}

          {isLoading && (
            <div className="flex justify-start">
              <div className="bg-[#1a1a1a] border border-terminal-border rounded-lg p-4">
                <div className="text-green-400 text-sm mb-2 font-medium">Zypheron</div>
                <div className="flex items-center space-x-2">
                  <div className="flex space-x-1">
                    <div className="w-2 h-2 bg-zypheron-500 rounded-full animate-bounce"></div>
                    <div className="w-2 h-2 bg-zypheron-500 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }}></div>
                    <div className="w-2 h-2 bg-zypheron-500 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                  </div>
                  <span className="text-terminal-muted text-sm">Analyzing...</span>
                </div>
              </div>
            </div>
          )}

          {/* Show Attack Options Panel after pentest completion */}
          {showAttackOptions && lastPentestTarget && (
            <AttackOptionsPanel
              targetUrl={lastPentestTarget}
              pentestResults={lastPentestResults}
              onGeneratePayload={handleGenerateAttackPayload}
              onClose={() => setShowAttackOptions(false)}
            />
          )}

          <div ref={messagesEndRef} />
        </div>
      </div>

      {/* Input Area */}
      <div className="bg-[#1a1a1a] border-t border-terminal-border px-8 py-6 flex-shrink-0">
        <div className="max-w-4xl mx-auto">
          <form onSubmit={handleSubmit} className="flex items-end space-x-4">
            <div className="flex-1">
              {attachedImage && (
                <div className="relative mb-2 w-24 h-24">
                  <img src={attachedImage} alt="Attachment" className="rounded-lg object-cover w-full h-full" />
                  <button
                    type="button"
                    onClick={() => setAttachedImage(null)}
                    className="absolute -top-2 -right-2 bg-red-500 text-white rounded-full p-1"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              )}
              <div className="flex items-center bg-[#0d0d0d] border border-terminal-border rounded-lg px-4 py-3">
                <span className="text-zypheron-500 font-mono text-sm mr-3">{'>'}_</span>
                <textarea
                  ref={textareaRef}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder={agentMode ? "Agent Mode: I'll autonomously analyze cybersecurity threats..." : "Ask Zypheron about cybersecurity, threats, or penetration testing..."}
                  className="flex-1 bg-transparent text-terminal-text placeholder-terminal-muted font-mono text-sm resize-none outline-none min-h-[24px] max-h-32"
                  disabled={isLoading}
                  rows={1}
                  style={{
                    height: 'auto',
                    minHeight: '24px'
                  }}
                  onInput={(e) => {
                    const target = e.target as HTMLTextAreaElement
                    target.style.height = 'auto'
                    target.style.height = `${Math.min(target.scrollHeight, 128)}px`
                  }}
                />
                 <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleImageAttach}
                  className="hidden"
                  accept="image/*"
                />
                
                {/* Agent Mode Toggle Button */}
                <button
                  type="button"
                  onClick={() => setAgentMode(!agentMode)}
                  className={`flex items-center space-x-1 px-3 py-2 rounded-lg transition-all transform hover:scale-105 ml-2 ${
                    agentMode 
                      ? 'bg-zypheron-500 hover:bg-zypheron-600 text-white shadow-lg shadow-zypheron-500/25' 
                      : 'bg-gray-700 hover:bg-gray-600 text-gray-300'
                  }`}
                  title={agentMode ? 'Agent Mode: ON' : 'Agent Mode: OFF'}
                >
                  <RobotIcon size={16} color={agentMode ? "#ffffff" : "#DC2626"} />
                  <span className="text-xs font-medium">Agent</span>
                  {agentMode && (
                    <div className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse" />
                  )}
                </button>
                
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="text-terminal-muted hover:text-terminal-text transition-colors ml-2"
                >
                  <Paperclip className="w-5 h-5" />
                </button>
              </div>
            </div>
            
            <button
              type="submit"
              disabled={!input.trim() || isLoading}
              className="bg-zypheron-500 hover:bg-zypheron-600 disabled:opacity-50 disabled:cursor-not-allowed text-white p-3 rounded-lg transition-colors"
            >
              <Send className="w-5 h-5" />
            </button>
          </form>
        </div>
      </div>
      </div>

      {/* Cache Management Modal */}
      {showCacheModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-terminal-surface border border-terminal-border rounded-lg w-full max-w-md mx-4">
            <div className="p-4 border-b border-terminal-border">
              <h3 className="text-lg font-medium text-terminal-text">Cache Management</h3>
              <p className="text-sm text-terminal-muted mt-1">
                Debug and manage pentest result cache
              </p>
            </div>
            
            <div className="p-4 space-y-4">
              <div>
                <label className="text-sm text-terminal-muted block mb-2">Cache Status</label>
                <div className="bg-terminal-bg border border-terminal-border rounded p-3 text-sm">
                  <div className="space-y-1">
                    <div>Session ID: <span className="text-zypheron-400">{currentSession?.id || 'None'}</span></div>
                    <div>Has Cache: <span className={`${cachedPentestResults ? 'text-green-400' : 'text-red-400'}`}>
                      {cachedPentestResults ? 'Yes' : 'No'}
                    </span></div>
                    {cachedPentestResults && (
                      <>
                        <div>Target: <span className="text-zypheron-400">{cachedPentestResults.target}</span></div>
                        <div>Cached Session: <span className="text-zypheron-400">{cachedPentestResults.sessionId}</span></div>
                        <div>Timestamp: <span className="text-zypheron-400">{cachedPentestResults.timestamp.toLocaleString()}</span></div>
                      </>
                    )}
                  </div>
                </div>
              </div>
              
              <div className="space-y-2">
                <button
                  onClick={() => {
                    const cache = getCachedPentestResults()
                    if (cache) {
                      const info = `Target: ${cache.target}\nSession: ${cache.sessionId}\nTimestamp: ${cache.timestamp.toLocaleString()}\nData: ${JSON.stringify(cache.results, null, 2)}`
                      alert(info)
                    } else {
                      alert('No pentest cache found for current session')
                    }
                  }}
                  className="w-full flex items-center justify-center space-x-2 px-3 py-2 bg-terminal-bg border border-terminal-border text-terminal-text rounded hover:bg-terminal-surface transition-colors text-sm"
                >
                  <span>View Full Cache Data</span>
                </button>
                
                <button
                  onClick={() => {
                    clearPentestCache()
                    setCacheVersion(prev => prev + 1) // Force re-render
                    alert('Pentest cache cleared')
                  }}
                  className="w-full flex items-center justify-center space-x-2 px-3 py-2 bg-red-600/20 border border-red-600/30 text-red-400 rounded hover:bg-red-600/30 transition-colors text-sm"
                >
                  <span>Clear Cache</span>
                </button>
                
                <button
                  onClick={() => {
                    const localStorage = window.localStorage
                    const keys = Object.keys(localStorage).filter(key => key.startsWith('zypheron-'))
                    const info = keys.map(key => `${key}: ${localStorage[key]?.length || 0} chars`).join('\n')
                    alert(`LocalStorage Keys:\n${info}`)
                  }}
                  className="w-full flex items-center justify-center space-x-2 px-3 py-2 bg-terminal-bg border border-terminal-border text-terminal-text rounded hover:bg-terminal-surface transition-colors text-sm"
                >
                  <span>View localStorage</span>
                </button>
                
                <button
                  onClick={() => {
                    // Force cache refresh
                    setCacheVersion(prev => prev + 1)
                    alert('Cache refreshed')
                  }}
                  className="w-full flex items-center justify-center space-x-2 px-3 py-2 bg-blue-600/20 border border-blue-600/30 text-blue-400 rounded hover:bg-blue-600/30 transition-colors text-sm"
                >
                  <span>Refresh Cache</span>
                </button>
              </div>
              
              {/* Account Management Section */}
              <div className="border-t border-terminal-border pt-4">
                <label className="text-sm text-terminal-muted block mb-2">Account</label>
                <div className="space-y-2">
                  <button
                    onClick={async () => {
                      try {
                        await signOut()
                        toast.success('Successfully logged out')
                        setShowCacheModal(false)
                      } catch (error) {
                        toast.error('Failed to logout')
                      }
                    }}
                    className="w-full flex items-center justify-center space-x-2 px-3 py-2 bg-red-600/20 border border-red-600/30 text-red-400 rounded hover:bg-red-600/30 transition-colors text-sm"
                  >
                    <LogOut className="w-4 h-4" />
                    <span>Logout</span>
                  </button>
                </div>
              </div>
              
              {/* Legal Documents Section */}
              <div className="border-t border-terminal-border pt-4">
                <label className="text-sm text-terminal-muted block mb-2">Legal Documents</label>
                <div className="space-y-2">
                  <button
                    onClick={() => setShowTOSModal(true)}
                    className="w-full flex items-center justify-center space-x-2 px-3 py-2 bg-terminal-bg border border-terminal-border text-terminal-text rounded hover:bg-terminal-surface transition-colors text-sm"
                  >
                    <span>Terms of Service</span>
                  </button>
                  
                  <button
                    onClick={() => setShowTOUModal(true)}
                    className="w-full flex items-center justify-center space-x-2 px-3 py-2 bg-terminal-bg border border-terminal-border text-terminal-text rounded hover:bg-terminal-surface transition-colors text-sm"
                  >
                    <span>Terms of Use</span>
                  </button>
                </div>
              </div>
            </div>
            
            <div className="p-4 border-t border-terminal-border flex justify-end">
              <button
                onClick={() => setShowCacheModal(false)}
                className="px-4 py-2 bg-zypheron-500 text-white rounded hover:bg-zypheron-600 transition-colors text-sm"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Terms of Service Modal */}
      {showTOSModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-terminal-surface border border-terminal-border rounded-lg w-full max-w-4xl mx-4 max-h-[90vh] overflow-hidden">
            <div className="p-6 border-b border-terminal-border">
              <h3 className="text-xl font-medium text-terminal-text">Terms of Service</h3>
              <p className="text-sm text-terminal-muted mt-1">
                COBRA AI Legal Terms and Conditions
              </p>
            </div>
            
            <div className="p-6 overflow-y-auto max-h-[70vh] text-sm text-terminal-text leading-relaxed">
              <div className="prose prose-invert max-w-none">
                <h2 className="text-lg font-semibold text-white mb-4">1. ACCEPTANCE OF TERMS</h2>
                <p className="mb-4">
                  By accessing, downloading, installing, or using COBRA AI (the "Software"), you ("User," "you," or "your") agree to be bound by these Terms of Service ("Terms"). If you do not agree to these Terms, do not use the Software.
                </p>
                
                <h2 className="text-lg font-semibold text-white mb-4">2. DESCRIPTION OF SERVICE</h2>
                <p className="mb-4">
                  COBRA AI is a cybersecurity research and educational platform designed for:
                </p>
                <ul className="list-disc list-inside mb-4 space-y-1">
                  <li>Security assessment and penetration testing</li>
                  <li>Network reconnaissance and analysis</li>
                  <li>Threat intelligence gathering</li>
                  <li>Cybersecurity education and training</li>
                </ul>
                <p className="mb-4">
                  The Software operates primarily through self-hosted, local AI models including but not limited to DeepSeek and other downloadable language models.
                </p>
                
                <h2 className="text-lg font-semibold text-white mb-4">3. AUTHORIZED USE ONLY</h2>
                <div className="bg-red-900/20 border border-red-500 p-4 rounded-lg mb-4">
                  <h3 className="text-red-400 font-bold mb-2">⚠️ LEGAL AUTHORIZATION REQUIRED</h3>
                  <p className="text-red-200">
                    You may ONLY use COBRA AI on systems and networks that you:
                  </p>
                  <ul className="list-disc list-inside mt-2 space-y-1 text-red-200">
                    <li><strong>OWN</strong> outright, or</li>
                    <li>Have <strong>EXPLICIT, WRITTEN PERMISSION</strong> to test from the system owner, or</li>
                    <li>Are <strong>LEGALLY AUTHORIZED</strong> to assess through your professional role</li>
                  </ul>
                </div>
                
                <h3 className="text-md font-semibold text-white mb-2">3.2 Prohibited Uses</h3>
                <p className="mb-2">You are STRICTLY PROHIBITED from using COBRA AI to:</p>
                <ul className="list-disc list-inside mb-4 space-y-1">
                  <li>Access any system without explicit authorization</li>
                  <li>Perform any unauthorized network scanning or penetration testing</li>
                  <li>Violate any local, state, national, or international laws</li>
                  <li>Infringe upon the rights of others</li>
                  <li>Cause damage to any computer systems or networks</li>
                  <li>Violate terms of service of third-party platforms</li>
                  <li>Engage in any illegal, harmful, or malicious activities</li>
                </ul>
                
                <h2 className="text-lg font-semibold text-white mb-4">4. USER RESPONSIBILITIES</h2>
                <p className="mb-4">
                  You are solely responsible for ensuring your use complies with all applicable laws, obtaining necessary permissions before testing any systems, understanding and following the Computer Fraud and Abuse Act (CFAA) and similar laws in your jurisdiction.
                </p>
                
                <h2 className="text-lg font-semibold text-white mb-4">5. DISCLAIMERS AND LIMITATIONS</h2>
                <p className="mb-4">
                  COBRA AI is provided "AS IS" without any warranties, express or implied. You acknowledge that cybersecurity tools carry inherent risks and you use the Software entirely at your own risk.
                </p>
                
                <h2 className="text-lg font-semibold text-white mb-4">6. LIMITATION OF LIABILITY</h2>
                <p className="mb-4">
                  TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE COBRA AI DEVELOPERS SHALL NOT BE LIABLE FOR ANY DAMAGES ARISING FROM YOUR USE OF THE SOFTWARE. You agree to indemnify and hold harmless the COBRA AI developers from any claims arising from your use of the Software.
                </p>
                
                <div className="bg-yellow-900/20 border border-yellow-500 p-4 rounded-lg mt-6">
                  <h3 className="text-yellow-400 font-bold mb-2">🚨 FEDERAL CRIME WARNING</h3>
                  <p className="text-yellow-200 text-sm">
                    UNAUTHORIZED COMPUTER ACCESS IS A FEDERAL CRIME. Violation of the Computer Fraud and Abuse Act (18 U.S.C. § 1030) can result in up to 20 years in federal prison, fines up to $250,000, and permanent criminal record. ALWAYS OBTAIN EXPLICIT WRITTEN PERMISSION BEFORE TESTING.
                  </p>
                </div>
              </div>
            </div>
            
            <div className="p-4 border-t border-terminal-border flex justify-end">
              <button
                onClick={() => setShowTOSModal(false)}
                className="px-4 py-2 bg-zypheron-500 text-white rounded hover:bg-zypheron-600 transition-colors text-sm"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Terms of Use Modal */}
      {showTOUModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-terminal-surface border border-terminal-border rounded-lg w-full max-w-4xl mx-4 max-h-[90vh] overflow-hidden">
            <div className="p-6 border-b border-terminal-border">
              <h3 className="text-xl font-medium text-terminal-text">Terms of Use</h3>
              <p className="text-sm text-terminal-muted mt-1">
                COBRA AI Usage Guidelines and Requirements
              </p>
            </div>
            
            <div className="p-6 overflow-y-auto max-h-[70vh] text-sm text-terminal-text leading-relaxed">
              <div className="prose prose-invert max-w-none">
                <h2 className="text-lg font-semibold text-white mb-4">1. EDUCATIONAL PURPOSE</h2>
                <p className="mb-4">COBRA AI is designed primarily for:</p>
                <ul className="list-disc list-inside mb-4 space-y-1">
                  <li><strong>Cybersecurity education</strong> and learning</li>
                  <li><strong>Authorized security testing</strong> and research</li>
                  <li><strong>Professional penetration testing</strong> with proper authorization</li>
                  <li><strong>Academic research</strong> in controlled environments</li>
                </ul>
                
                <h2 className="text-lg font-semibold text-white mb-4">2. REQUIRED AUTHORIZATIONS</h2>
                <div className="bg-blue-900/20 border border-blue-500 p-4 rounded-lg mb-4">
                  <h3 className="text-blue-400 font-bold mb-2">📋 WRITTEN PERMISSION REQUIRED</h3>
                  <p className="text-blue-200 mb-2">Before using COBRA AI on any system, you MUST have:</p>
                  <ul className="list-disc list-inside space-y-1 text-blue-200">
                    <li>System owner's explicit consent</li>
                    <li>Scope of testing authorized</li>
                    <li>Time frame for testing</li>
                    <li>Contact information for responsible parties</li>
                    <li>Signature and date</li>
                  </ul>
                </div>
                
                <h2 className="text-lg font-semibold text-white mb-4">3. TECHNICAL SAFEGUARDS</h2>
                <p className="mb-2">You must implement:</p>
                <ul className="list-disc list-inside mb-4 space-y-1">
                  <li>Strong authentication mechanisms</li>
                  <li>Network segmentation and isolation</li>
                  <li>Regular security updates</li>
                  <li>Access logging and monitoring</li>
                  <li>Secure configuration management</li>
                </ul>
                
                <h2 className="text-lg font-semibold text-white mb-4">4. ETHICAL GUIDELINES</h2>
                <h3 className="text-md font-semibold text-white mb-2">Responsible Use:</h3>
                <ul className="list-disc list-inside mb-4 space-y-1">
                  <li>Test only what you're authorized to test</li>
                  <li>Minimize impact on production systems</li>
                  <li>Report vulnerabilities responsibly</li>
                  <li>Respect privacy and confidentiality</li>
                  <li>Follow principle of least privilege</li>
                </ul>
                
                <h3 className="text-md font-semibold text-white mb-2">Prohibited Activities:</h3>
                <ul className="list-disc list-inside mb-4 space-y-1">
                  <li>Unauthorized system access</li>
                  <li>Data theft or exfiltration</li>
                  <li>Service disruption attacks</li>
                  <li>Malware deployment</li>
                  <li>Social engineering without consent</li>
                </ul>
                
                <h2 className="text-lg font-semibold text-white mb-4">5. INCIDENT RESPONSE</h2>
                <p className="mb-2">If You Discover Vulnerabilities:</p>
                <ol className="list-decimal list-inside mb-4 space-y-1">
                  <li><strong>Document</strong> findings securely</li>
                  <li><strong>Notify</strong> system owner immediately</li>
                  <li><strong>Provide</strong> reasonable remediation time</li>
                  <li><strong>Follow</strong> coordinated disclosure practices</li>
                  <li><strong>Maintain</strong> confidentiality until patched</li>
                </ol>
                
                <h2 className="text-lg font-semibold text-white mb-4">6. COMPLIANCE REQUIREMENTS</h2>
                <p className="mb-2">You must comply with:</p>
                <ul className="list-disc list-inside mb-4 space-y-1">
                  <li>Computer Fraud and Abuse Act (CFAA)</li>
                  <li>Digital Millennium Copyright Act (DMCA)</li>
                  <li>General Data Protection Regulation (GDPR)</li>
                  <li>California Consumer Privacy Act (CCPA)</li>
                  <li>Industry-specific regulations</li>
                  <li>Local and international laws</li>
                </ul>
                
                <div className="bg-red-900/20 border border-red-500 p-4 rounded-lg mt-6">
                  <h3 className="text-red-400 font-bold mb-2">⚠️ INTERNATIONAL LAWS</h3>
                  <ul className="list-disc list-inside space-y-1 text-red-200">
                    <li><strong>UK:</strong> Computer Misuse Act 1990</li>
                    <li><strong>Canada:</strong> Criminal Code Section 342.1</li>
                    <li><strong>Australia:</strong> Criminal Code Act 1995</li>
                    <li><strong>EU:</strong> Various national implementations</li>
                    <li><strong>Asia-Pacific:</strong> Country-specific cyber laws</li>
                  </ul>
                </div>
              </div>
            </div>
            
            <div className="p-4 border-t border-terminal-border flex justify-end">
              <button
                onClick={() => setShowTOUModal(false)}
                className="px-4 py-2 bg-zypheron-500 text-white rounded hover:bg-zypheron-600 transition-colors text-sm"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Penetration Test Panel */}
      {showPentestPanel && (
        <PentestPanel
          onClose={() => setShowPentestPanel(false)}
          onStartPentest={handleStartPentest}
        />
      )}
    </ChatLayout>
    </>
  )
}

export default Chat 