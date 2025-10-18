// Ensure environment variables are loaded
import dotenv from 'dotenv'
dotenv.config({ path: '.env' })

import express from 'express'
import OpenAI from 'openai'
import { config, hasKey } from '../services/config'
import Joi from 'joi'
import { aiService } from '../services/ai'
import { xaiService } from '../services/xai'
import { getSecureApiKey } from '../services/encryption'
import { UsageService } from '../services/usage'
import { enhancedAuthMiddleware } from '../middleware/rbac'
import { knowledgeBase } from '../services/knowledgeBase'

const router = express.Router()

// Initialize OpenAI client with secure key management
const OPENAI_API_KEY = config.OPENAI_API_KEY || getSecureApiKey('OPENAI_API_KEY')
const openai = OPENAI_API_KEY ? new OpenAI({ apiKey: OPENAI_API_KEY }) : null

// Validation schemas
const messageSchema = Joi.object({
  messages: Joi.array().items(
    Joi.object({
      role: Joi.string().valid('user', 'assistant', 'system').required(),
      content: Joi.alternatives().try(Joi.string(), Joi.array()).required(),
      attachment: Joi.string().optional(),
    })
  ).min(1).required(),
  model: Joi.string().valid(
    'gpt-4',
    'gpt-3.5-turbo',
    'gpt-5',
    'claude-4-sonnet',
    'claude-4-opus',
    'gemini-2.5-flash',
    'gemini-2.5-pro',
    'grok-3',
    'grok-4',
    'moonshot-v1-128k'
  ).required(),
  pentestResults: Joi.object().optional()
})

const pentestAnalysisSchema = Joi.object({
  pentestResults: Joi.object().required(),
  model: Joi.string().valid(
    'gpt-4',
    'gpt-3.5-turbo',
    'gpt-5',
    'claude-4-sonnet',
    'claude-4-opus',
    'gemini-2.5-flash',
    'gemini-2.5-pro',
    'grok-3',
    'grok-4',
    'moonshot-v1-128k'
  ).required(),
})

const updateSessionSchema = Joi.object({
  sessionId: Joi.string().required(),
  title: Joi.string().min(1).max(100).required(),
})

// Simple token estimation function
function estimateTokens(text: string): number {
  // Rough estimation: ~1 token per 4 characters on average
  return Math.ceil(text.length / 4)
}

// System prompt for COBRA AI with knowledge base integration
const COBRA_SYSTEM_PROMPT = `You are COBRA AI, a specialized cybersecurity assistant with access to a comprehensive knowledge base of security tools, techniques, and vulnerabilities. Your responses should be:

1. **Security-focused**: Provide actionable cybersecurity insights, tool recommendations, and analysis
2. **Professional**: Maintain a professional, knowledgeable tone suitable for security professionals
3. **Practical**: Offer terminal-ready commands, payloads, and step-by-step procedures when appropriate
4. **Responsible**: Always emphasize authorized testing and legal compliance
5. **Current**: Reference modern tools, techniques, and vulnerabilities from your knowledge base
6. **Knowledge-enhanced**: Use your extensive database of cybersecurity information to provide detailed, accurate responses

Key capabilities:
- Threat analysis and IOC investigation
- Tool recommendations with detailed usage examples (Nmap, Burp Suite, Metasploit, etc.)
- Payload generation and command crafting
- Vulnerability assessment guidance with CVE references
- Network reconnaissance strategies with step-by-step procedures
- Web application security testing methodologies
- Social engineering awareness and mitigation strategies
- Incident response procedures following industry frameworks

Knowledge Base Access:
- 10+ essential penetration testing tools with usage examples
- 5+ attack techniques with detailed methodologies
- Critical vulnerabilities (CVEs) and exploitation methods
- Security best practices and frameworks
- Mitigation strategies and defensive measures

Always remind users to ensure they have proper authorization before conducting any security testing activities. When providing tool usage or attack techniques, include relevant knowledge base information for context and accuracy.`

// Specialized system prompt for pentest analysis
const PENTEST_ANALYSIS_PROMPT = `You are a world-class penetration testing analyst and are instructed to read the pen test results and elaborate on its weaknesses. 

Analyze the provided penetration test results and provide a comprehensive security assessment in exactly 3 paragraphs:

**Paragraph 1: Summary of Site Vulnerabilities**
- Provide a concise overview of all discovered vulnerabilities
- Rate the overall security posture and risk level
- Highlight the most critical findings that pose immediate threats

**Paragraph 2: Attack Vectors and Exploitation Methods**
- Detail specific ways an attacker could exploit the identified vulnerabilities
- Provide step-by-step attack scenarios for the most serious weaknesses
- Include potential tools and techniques that could be used
- Explain the potential impact and damage from successful exploitation

**Paragraph 3: Remediation and Prevention Strategies**
- Provide specific, actionable recommendations to fix each vulnerability
- Include both immediate patches and long-term security improvements
- Suggest security headers, configurations, and best practices
- Recommend monitoring and detection mechanisms

Base your analysis strictly on the provided penetration test data. Be thorough, technical, and provide actionable insights for both attackers (for authorized testing) and defenders (for remediation).`

// Helper function to detect cybersecurity content
function analyzeCyberSecurityContent(content: string) {
  const cyberKeywords = [
    'nmap', 'burp', 'metasploit', 'wireshark', 'sqlmap', 'gobuster', 'nikto',
    'vulnerability', 'exploit', 'payload', 'reconnaissance', 'enumeration',
    'injection', 'xss', 'csrf', 'rce', 'lfi', 'rfi', 'ssrf',
    'ctf', 'oscp', 'ceh', 'pentest', 'red team', 'blue team',
    'malware', 'trojan', 'ransomware', 'phishing', 'social engineering'
  ]
  
  const lowerContent = content.toLowerCase()
  const foundKeywords = cyberKeywords.filter(keyword => lowerContent.includes(keyword))
  
  return {
    isCyberSecurity: foundKeywords.length > 0,
    keywords: foundKeywords,
    threatLevel: foundKeywords.length > 3 ? 'high' : foundKeywords.length > 1 ? 'medium' : 'low'
  }
}

// Helper function to extract commands/tools from response
function extractToolsAndCommands(content: string) {
  const commandRegex = /```(?:bash|shell|cmd)?\n([^`]+)```/g
  const toolRegex = /(?:using|with|run|execute)\s+(\w+)/gi
  
  const commands: string[] = []
  const tools: string[] = []
  
  let match: RegExpExecArray | null
  while ((match = commandRegex.exec(content)) !== null) {
    if (match[1]) {
      commands.push(match[1].trim())
    }
  }
  
  while ((match = toolRegex.exec(content)) !== null) {
    if (match[1]) {
      tools.push(match[1])
    }
  }
  
  return { commands, tools }
}

// POST /api/chat/message - Send message to AI
router.post('/message', enhancedAuthMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    // Validate request
    const { error, value } = messageSchema.validate(req.body)
    if (error) {
      return res.status(400).json({
        error: 'Validation Error',
        message: error.details?.[0]?.message || 'Invalid request data'
      })
    }

    const { messages, model, pentestResults } = value

    // Get user from auth middleware (you may need to add auth middleware to this route)
    const userId = req.user?.id
    if (userId) {
      // Estimate tokens for the request
      const conversationText = messages.map((m: any) => m.content).join(' ')
      const estimatedTokens = estimateTokens(conversationText) + 500 // Add buffer for response
      
      // Validate plan/model/provider and limits according to plan
      const validation = await UsageService.validateModelAccess(userId, model, estimatedTokens)
      if (!validation.allowed) {
        return res.status(403).json({
          error: 'Access Denied',
          message: validation.reason || 'Your current plan does not allow this model or you reached a limit.',
          plan: validation.plan,
          provider: validation.provider
        })
      }
    }

    // Get contextual knowledge from knowledge base
    const userMessage = messages[messages.length - 1]?.content || ''
    const contextualKnowledge = knowledgeBase.getContextualKnowledge(userMessage)
    
    // Add system prompt - if pentest results are provided, use specialized prompt
    let systemPrompt = COBRA_SYSTEM_PROMPT
    if (pentestResults) {
      systemPrompt = `${COBRA_SYSTEM_PROMPT}\n\nADDITIONAL CONTEXT: You have access to recent penetration test results. When discussing security vulnerabilities, reference the specific findings from the pentest data provided.`
    }

    // Add knowledge base context if relevant information found
    if (contextualKnowledge) {
      systemPrompt += `\n\nKNOWLEDGE BASE CONTEXT:${contextualKnowledge}`
    }

    const fullMessages = [
      { role: 'system', content: systemPrompt },
      ...messages
    ]

    // If pentest results are provided, add them as context to the conversation
    if (pentestResults) {
      fullMessages.push({
        role: 'system',
        content: `PENETRATION TEST RESULTS:\n${JSON.stringify(pentestResults, null, 2)}`
      })
    }

    let response

    // Handle different models
    if (model === 'gpt-4' || model === 'gpt-3.5-turbo' || model === 'gpt-5') {
      if (!openai) {
        // Fall back to Gemini if OpenAI is not configured
        console.log('OpenAI not configured, falling back to Gemini')
        const conversationText = fullMessages.map((m: any) => `${m.role}: ${m.content}`).join('\n')
        const geminiResponse = await aiService.chat(conversationText, 'flash')
        response = geminiResponse
      } else {
        try {
          const gptMessages = JSON.parse(JSON.stringify(fullMessages));

          const lastMessage = messages[messages.length - 1];
          if (model === 'gpt-4' && lastMessage.attachment) {
            const lastGptMessage = gptMessages[gptMessages.length - 1];
            lastGptMessage.content = [
              { type: 'text', text: lastGptMessage.content },
              { type: 'image_url', image_url: { url: lastMessage.attachment } }
            ];
          }

          // Map legacy model ids to current OpenAI Chat Completions models
          const openAiModel =
            model === 'gpt-4' ? 'gpt-4o-mini' :
            model === 'gpt-3.5-turbo' ? 'gpt-4o-mini' :
            model

          const completion = await openai.chat.completions.create({
            model: openAiModel,
            messages: gptMessages as any,
            temperature: 0.7,
            max_tokens: 2000,
            presence_penalty: 0.1,
            frequency_penalty: 0.1,
          })

          response = completion.choices[0]?.message?.content || 'No response generated'
        } catch (openAiError: any) {
          console.error('OpenAI API error:', openAiError?.message || openAiError)
          // If OpenAI fails (e.g., invalid key), fall back to Gemini
          if (openAiError?.status === 401 || openAiError?.message?.includes('API key')) {
            console.log('OpenAI authentication failed, falling back to Gemini')
            const conversationText = fullMessages.map((m: any) => `${m.role}: ${m.content}`).join('\n')
            const geminiResponse = await aiService.chat(conversationText, 'flash')
            response = geminiResponse
          } else {
            throw openAiError
          }
        }
      }
    } else if (model === 'gemini-2.5-flash' || model === 'gemini-2.5-pro') {
      // Use real Google Gemini API
      try {
        const conversationHistory = fullMessages.map(msg => 
          `${msg.role === 'system' ? 'System' : msg.role === 'user' ? 'User' : 'Assistant'}: ${msg.content}`
        ).join('\n\n')
        
        const geminiModel = model === 'gemini-2.5-pro' ? 'pro' : 'flash'
        response = await aiService.chat(conversationHistory, geminiModel)
      } catch (geminiError: any) {
        console.error('Gemini API Error:', geminiError)
        const provider = 'Google'
        const modelName = model === 'gemini-2.5-pro' ? 'Gemini 2.5 Pro' : 'Gemini 2.5 Flash'
        const mock = `[MOCK RESPONSE from ${modelName}] This is a simulated response from ${modelName} by ${provider}. Configure GEMINI_API_KEY to enable real responses.`
        response = mock
      }
    } else if (model === 'grok-3' || model === 'grok-4') {
      // Use real xAI API for Grok 3
      try {
        response = await xaiService.chat(fullMessages)
      } catch (xaiError: any) {
        console.error('xAI API Error:', xaiError)
        const provider = 'xAI'
        const modelName = 'Grok 3'
        const mock = `[MOCK RESPONSE from ${modelName}] This is a simulated response from ${modelName} by ${provider}. Configure XAI_API_KEY to enable real responses.`
        response = mock
      }
    } else if (model === 'moonshot-v1-128k') {
      // Use Kimi (Moonshot) API
      try {
        const conversationHistory = fullMessages.map(msg => 
          `${msg.role === 'system' ? 'System' : msg.role === 'user' ? 'User' : 'Assistant'}: ${msg.content}`
        ).join('\n\n')
        
        response = await aiService.chat(conversationHistory, model)
      } catch (kimiError: any) {
        console.error('Kimi API Error:', kimiError)
        const provider = 'Moonshot'
        const modelName = 'Kimi K2'
        const mock = `[MOCK RESPONSE from ${modelName}] This is a simulated response from ${modelName} by ${provider}. Configure MOONSHOT_API_KEY to enable real responses.`
        response = mock
      }
    } else {
      // Mock responses for other models
      let modelName = model;
      let provider = 'Unknown';
      
      if (model === 'claude-4-sonnet' || model === 'claude-4-opus') {
        modelName = model === 'claude-4-opus' ? 'Claude-4 Opus' : 'Claude-4 Sonnet';
        provider = 'Anthropic';
      } else if (model === 'gemini-2.5-flash') {
        modelName = 'Gemini 2.5 Flash';
        provider = 'Google';
      } else if (model === 'gemini-2.5-pro') {
        modelName = 'Gemini 2.5 Pro';
        provider = 'Google';
      } else if (model === 'grok-3') {
        modelName = 'Grok 3';
        provider = 'xAI';
      }
      
      response = `[MOCK RESPONSE from ${modelName}] This is a simulated response from ${modelName} by ${provider}. In a production environment, this would connect to the actual ${modelName} API. 

For cybersecurity queries, I would provide:
- Advanced tool recommendations (Nmap, Burp Suite, Metasploit, Cobalt Strike)
- Comprehensive security analysis and vulnerability assessment
- Terminal-ready commands and sophisticated payloads
- Real-time threat intelligence insights
- Advanced penetration testing methodologies

Please configure the appropriate ${provider} API keys for full functionality.`
    }

    // Analyze the response for cybersecurity content
    const lastUserMessage = messages[messages.length - 1]?.content || ''
    const analysis = analyzeCyberSecurityContent(lastUserMessage + ' ' + response)
    const { commands, tools } = extractToolsAndCommands(response)

    const metadata = {
      threatLevel: analysis.threatLevel,
      keywords: analysis.keywords,
      tools: tools,
      commands: commands,
      isCyberSecurity: analysis.isCyberSecurity
    }

    // Track token usage after successful response
    if (userId) {
      const actualTokens = estimateTokens(lastUserMessage + response)
      const provider = UsageService.getProviderForModel(model)
      await UsageService.trackTokens(userId, actualTokens, model, undefined, { provider })
      await UsageService.trackUsage(userId, 'ai_requests', 1)
    }

    return res.json({
      message: response,
      model: model,
      metadata: metadata,
    })

  } catch (error) {
    console.error('Chat API Error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to process chat message'
    })
  }
})

// POST /api/chat/analyze-pentest - Analyze penetration test results
router.post('/analyze-pentest', enhancedAuthMiddleware, async (req: express.Request, res: express.Response) => {
  try {
    // Validate request
    const { error, value } = pentestAnalysisSchema.validate(req.body)
    if (error) {
      return res.status(400).json({
        error: 'Validation Error',
        message: error.details?.[0]?.message || 'Invalid request data'
      })
    }

    const { pentestResults, model } = value

    // Create analysis message with pentest data
    const analysisMessages = [
      { role: 'system', content: PENTEST_ANALYSIS_PROMPT },
      { 
        role: 'system', 
        content: `PENETRATION TEST RESULTS TO ANALYZE:\n${JSON.stringify(pentestResults, null, 2)}` 
      },
      { 
        role: 'user', 
        content: 'Please analyze these penetration test results and provide your expert assessment in exactly 3 paragraphs as specified.' 
      }
    ]

    let response

    // Handle different models
    if (model === 'gpt-4' || model === 'gpt-3.5-turbo') {
      if (!openai) {
        return res.status(500).json({
          error: 'Configuration Error',
          message: 'OpenAI API key not configured'
        })
      }

      const completion = await openai.chat.completions.create({
        model: model,
        messages: analysisMessages as any,
        temperature: 0.3, // Lower temperature for more focused analysis
        max_tokens: 3000,
        presence_penalty: 0.1,
        frequency_penalty: 0.1,
      })

      response = completion.choices[0]?.message?.content || 'No response generated'
    } else if (model === 'gemini-2.5-flash' || model === 'gemini-2.5-pro') {
      // Use real Google Gemini API for pentest analysis
      try {
        const geminiModel = model === 'gemini-2.5-pro' ? 'pro' : 'flash'
        response = await aiService.analyzePentestResults(pentestResults, geminiModel)
      } catch (geminiError: any) {
        console.error('Gemini API Error:', geminiError)
        return res.status(500).json({
          error: 'Gemini API Error',
          message: geminiError.message || 'Failed to analyze with Gemini'
        })
      }
    } else if (model === 'grok-3') {
      // Use real xAI API for Grok 3
      try {
        response = await xaiService.analyzePentestResults(pentestResults)
      } catch (xaiError: any) {
        console.error('xAI API Error:', xaiError)
        return res.status(500).json({
          error: 'xAI API Error',
          message: xaiError.message || 'Failed to analyze with Grok 3'
        })
      }
    } else if (model === 'moonshot-v1-128k') {
      // Use Kimi (Moonshot) API for pentest analysis
      try {
        response = await aiService.analyzePentestResults(pentestResults, model)
      } catch (kimiError: any) {
        console.error('Kimi API Error:', kimiError)
        return res.status(500).json({
          error: 'Kimi API Error',
          message: kimiError.message || 'Failed to analyze with Kimi'
        })
      }
    } else {
      // Mock responses for other models - more detailed for pentest analysis
      let modelName = model;
      let provider = 'Unknown';
      
      if (model === 'claude-4-sonnet') {
        modelName = 'Claude-4 Sonnet';
        provider = 'Anthropic';
      } else if (model === 'gemini-2.5-flash') {
        modelName = 'Gemini 2.5 Flash';
        provider = 'Google';
      } else if (model === 'gemini-2.5-pro') {
        modelName = 'Gemini 2.5 Pro';
        provider = 'Google';
      } else if (model === 'grok-3') {
        modelName = 'Grok 3';
        provider = 'xAI';
      }
      
      // Extract key info from pentest results for mock analysis
      const target = pentestResults.target || 'Unknown Target'
      const hasSecurityHeaders = pentestResults.results?.headers?.security_score?.score || 0
      const sslInfo = pentestResults.results?.ssl?.ssl_labs_grade || 'Unknown'
      const robotsExists = pentestResults.results?.robots?.exists || false

      response = `[MOCK PENTEST ANALYSIS from ${modelName}]

**Summary of Site Vulnerabilities**
The penetration test of ${target} reveals a concerning security posture with a security score of ${hasSecurityHeaders}/100. The primary vulnerabilities include missing critical security headers, insufficient SSL/TLS configuration (Grade: ${sslInfo}), and ${robotsExists ? 'exposed robots.txt file potentially revealing sensitive directories' : 'lack of proper robots.txt configuration'}. These findings indicate a medium to high-risk environment that requires immediate attention from the security team.

**Attack Vectors and Exploitation Methods**
An attacker could exploit the missing security headers to launch clickjacking attacks through iframe embedding, execute cross-site scripting (XSS) attacks due to absent Content Security Policy, and perform man-in-the-middle attacks leveraging the weak SSL configuration. The exposed directory structure could be enumerated to discover admin panels, backup files, and sensitive endpoints. Tools like Burp Suite, OWASP ZAP, and custom scripts could automate these attacks, potentially leading to data exfiltration, session hijacking, and complete site compromise.

**Remediation and Prevention Strategies**
Immediate remediation should include implementing all critical security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options), upgrading SSL/TLS configuration to achieve an A+ rating, and properly configuring robots.txt to prevent information disclosure. Long-term improvements should include regular security assessments, implementing a Web Application Firewall (WAF), establishing continuous security monitoring with tools like fail2ban, and conducting quarterly penetration tests to maintain security posture.

Note: This is a simulated analysis. Configure ${provider} API keys for full ${modelName} capabilities.`
    }

    // Extract metadata from the analysis
    const analysis = analyzeCyberSecurityContent(response)
    const { commands, tools } = extractToolsAndCommands(response)

    const metadata = {
      threatLevel: 'high', // Pentest analysis is always high priority
      keywords: analysis.keywords,
      tools: tools,
      commands: commands,
      isCyberSecurity: true,
      analysisType: 'penetration_test_analysis',
      target: pentestResults.target,
      timestamp: new Date().toISOString()
    }

    return res.json({
      message: response,
      model: model,
      metadata: metadata,
      pentestData: {
        target: pentestResults.target,
        testsPerformed: pentestResults.tests_performed,
        summary: pentestResults.summary
      }
    })

  } catch (error) {
    console.error('Pentest Analysis API Error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to analyze penetration test results'
    })
  }
})

// GET /api/chat/models - Get available models
router.get('/models', (req: express.Request, res: express.Response) => {
  const hasOpenAI = !!getSecureApiKey('OPENAI_API_KEY')
  const hasAnthropic = !!getSecureApiKey('ANTHROPIC_API_KEY')
  const hasGemini = !!getSecureApiKey('GEMINI_API_KEY')
  const hasXAI = !!getSecureApiKey('XAI_API_KEY')

  // If OpenAI is not available but Gemini is, OpenAI models will fall back to Gemini
  const openAIAvailable = hasOpenAI || hasGemini

  const models = [
    {
      id: 'gpt-4',
      name: 'GPT-4',
      provider: 'OpenAI',
      available: openAIAvailable,
      description: hasOpenAI ? 'Most capable model for complex cybersecurity analysis' : 'Will use Gemini as fallback'
    },
    {
      id: 'gpt-3.5-turbo',
      name: 'GPT-3.5 Turbo',
      provider: 'OpenAI',
      available: openAIAvailable,
      description: hasOpenAI ? 'Fast and reliable for general security queries' : 'Will use Gemini as fallback'
    },
    {
      id: 'gpt-5',
      name: 'GPT-5',
      provider: 'OpenAI',
      available: openAIAvailable,
      description: hasOpenAI ? 'Next-generation OpenAI model (placeholder)' : 'Will use Gemini as fallback'
    },
    {
      id: 'claude-4-sonnet',
      name: 'Claude-4 Sonnet',
      provider: 'Anthropic',
      available: hasAnthropic,
      description: 'Latest Claude model with advanced reasoning for security research'
    },
    {
      id: 'claude-4-opus',
      name: 'Claude-4 Opus',
      provider: 'Anthropic',
      available: hasAnthropic,
      description: 'Anthropic flagship model (placeholder)'
    },
    {
      id: 'gemini-2.5-flash',
      name: 'Gemini 2.5 Flash',
      provider: 'Google',
      available: hasGemini,
      description: 'Fast and efficient Google AI model for quick security analysis'
    },
    {
      id: 'gemini-2.5-pro',
      name: 'Gemini 2.5 Pro',
      provider: 'Google',
      available: hasGemini,
      description: 'Advanced Google AI model for complex cybersecurity tasks (may have quota limits)'
    },
    {
      id: 'grok-3',
      name: 'Grok 3',
      provider: 'xAI',
      available: hasXAI,
      description: 'Latest xAI model with cutting-edge capabilities for security research'
    },
    {
      id: 'grok-4',
      name: 'Grok 4',
      provider: 'xAI',
      available: hasXAI,
      description: 'Upcoming xAI model (placeholder)'
    },
    {
      id: 'moonshot-v1-128k',
      name: 'Kimi K2',
      provider: 'Moonshot',
      available: false,
      description: 'Latest Moonshot AI model with 128K context length - ideal for long documents'
    }
  ]

  return res.json({ models })
})

// GET /api/chat/knowledge - Get knowledge base information
router.get('/knowledge', (req: express.Request, res: express.Response) => {
  try {
    const { search, category, type } = req.query
    
    let results: any = {}
    
    if (search) {
      const searchQuery = search as string
      results.tools = knowledgeBase.searchTools(searchQuery, category as string)
      results.techniques = knowledgeBase.searchTechniques(searchQuery, category as string)
      results.knowledge = knowledgeBase.searchKnowledge(searchQuery, category as string)
    } else if (type) {
      switch (type) {
        case 'tools':
          results.tools = knowledgeBase.searchTools('', category as string)
          break
        case 'techniques':
          results.techniques = knowledgeBase.searchTechniques('', category as string)
          break
        case 'knowledge':
          results.knowledge = knowledgeBase.searchKnowledge('', category as string)
          break
        case 'stats':
          results.stats = knowledgeBase.getStats()
          break
        case 'categories':
          results.categories = knowledgeBase.getCategories()
          break
        default:
          results.stats = knowledgeBase.getStats()
          results.categories = knowledgeBase.getCategories()
      }
    } else {
      // Return overview
      results.stats = knowledgeBase.getStats()
      results.categories = knowledgeBase.getCategories()
      results.recentTools = knowledgeBase.searchTools('').slice(0, 5)
      results.recentTechniques = knowledgeBase.searchTechniques('').slice(0, 3)
    }
    
    return res.json({
      success: true,
      data: results,
      timestamp: new Date().toISOString()
    })
    
  } catch (error) {
    console.error('Knowledge base API error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to retrieve knowledge base information'
    })
  }
})

// GET /api/chat/knowledge/tool/:name - Get specific tool information
router.get('/knowledge/tool/:name', (req: express.Request, res: express.Response) => {
  try {
    const toolName = req.params.name
    const tool = knowledgeBase.getTool(toolName)
    
    if (!tool) {
      return res.status(404).json({
        error: 'Not Found',
        message: `Tool '${toolName}' not found in knowledge base`
      })
    }
    
    return res.json({
      success: true,
      data: tool,
      timestamp: new Date().toISOString()
    })
    
  } catch (error) {
    console.error('Tool lookup error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to retrieve tool information'
    })
  }
})

// GET /api/chat/knowledge/technique/:name - Get specific technique information
router.get('/knowledge/technique/:name', (req: express.Request, res: express.Response) => {
  try {
    const techniqueName = req.params.name.replace(/-/g, ' ')
    const technique = knowledgeBase.getTechnique(techniqueName)
    
    if (!technique) {
      return res.status(404).json({
        error: 'Not Found',
        message: `Technique '${techniqueName}' not found in knowledge base`
      })
    }
    
    return res.json({
      success: true,
      data: technique,
      timestamp: new Date().toISOString()
    })
    
  } catch (error) {
    console.error('Technique lookup error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to retrieve technique information'
    })
  }
})

// PUT /api/chat/session/title - Update session title
router.put('/session/title', (req: express.Request, res: express.Response) => {
  try {
    // Validate request
    const { error, value } = updateSessionSchema.validate(req.body)
    if (error) {
      return res.status(400).json({
        error: 'Validation Error',
        message: error.details?.[0]?.message || 'Invalid request data'
      })
    }

    const { sessionId, title } = value

    // In a real application, this would update the session in the database
    // For now, we'll just validate and return success
    const timestamp = new Date().toISOString()
    console.log(`[${timestamp}] COBRA AI - Updating session ${sessionId} with title: "${title}"`)

    // Log to demonstrate backend is working (in production, this would be saved to database)
    const updateLog = {
      timestamp,
      action: 'UPDATE_SESSION_TITLE',
      sessionId,
      title,
      success: true
    }
    
    console.log('Session Update Log:', JSON.stringify(updateLog, null, 2))

    return res.json({
      success: true,
      message: 'Session title updated successfully',
      sessionId: sessionId,
      title: title,
      updatedAt: timestamp
    })

  } catch (error) {
    console.error('Update Session Title Error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to update session title'
    })
  }
})

// GET /api/chat/sessions - Get all chat sessions (placeholder for future use)
router.get('/sessions', (req: express.Request, res: express.Response) => {
  // In a real application, this would fetch sessions from database
  // For now, return empty array since sessions are stored in frontend
  return res.json({
    sessions: [],
    message: 'Sessions are currently stored in the frontend. This endpoint is for future database integration.'
  })
})

// DELETE /api/chat/session/:sessionId - Delete a chat session (placeholder for future use)  
router.delete('/session/:sessionId', (req: express.Request, res: express.Response) => {
  try {
    const { sessionId } = req.params

    if (!sessionId) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Session ID is required'
      })
    }

    // In a real application, this would delete the session from database
    console.log(`Deleting session ${sessionId}`)

    return res.json({
      success: true,
      message: 'Session deleted successfully',
      sessionId: sessionId
    })

  } catch (error) {
    console.error('Delete Session Error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to delete session'
    })
  }
})

export default router 

