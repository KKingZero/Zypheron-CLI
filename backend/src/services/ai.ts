// Ensure environment variables are loaded
import dotenv from 'dotenv'
dotenv.config({ path: '.env' })

import { GoogleGenerativeAI } from '@google/generative-ai'
import { config } from './config'
import axios from 'axios'
import { getSecureApiKey } from './encryption'
import { kimiService, KIMI_MODELS } from './kimi'

// Initialize Google Gemini API with secure key management
const GEMINI_API_KEY = config.GEMINI_API_KEY || getSecureApiKey('GEMINI_API_KEY')
if (!GEMINI_API_KEY) {
  console.warn('GEMINI_API_KEY not found. Gemini services will be unavailable.')
}
const genAI = GEMINI_API_KEY ? new GoogleGenerativeAI(GEMINI_API_KEY) : null

// DeepSeek/Ollama configuration
const DEEPSEEK_API_URL = getSecureApiKey('DEEPSEEK_API_URL') || 'http://localhost:11434'

// Available models - Updated for Gemini 2.5 (2025)
export const GEMINI_MODELS = {
  'flash': 'gemini-2.5-flash',        // Hybrid reasoning model with adjustable thinking
  'pro': 'gemini-2.5-pro'             // Most intelligent Google model with advanced reasoning
}

export const LOCAL_MODELS = {
  'deepseek-r1-8b': 'deepseek-r1:8b',      // Latest open source reasoning model (recommended)
  'deepseek-r1-7b': 'deepseek-r1:7b',      // Alternative smaller model
  'deepseek-r1': 'deepseek-r1:latest',     // Latest available
  'deepseek-r1-1.5b': 'deepseek-r1:1.5b',  // Smallest model for limited resources
}

// Export Kimi models for easy access
export { KIMI_MODELS }

// AI Service for enhanced security analysis
export class AIService {
  private flashModel = genAI?.getGenerativeModel({ model: GEMINI_MODELS.flash }) || null
  private proModel = genAI?.getGenerativeModel({ model: GEMINI_MODELS.pro }) || null

  // DeepSeek-R1 local LLM chat
  async chatWithLocalModel(messages: string, model: string = 'deepseek-r1:8b') {
    try {
      console.log(`Using DeepSeek model: ${model} at ${DEEPSEEK_API_URL}`)
      
      const response = await axios.post(`${DEEPSEEK_API_URL}/api/generate`, {
        model: model,
        prompt: messages,
        stream: false,
        options: {
          temperature: 0.7,
          top_p: 0.9,
          max_tokens: 2048
        }
      }, {
        timeout: 30000 // 30 second timeout
      })
      
      return response.data.response
    } catch (error: any) {
      console.error('DeepSeek/Ollama API Error:', error)
      
      if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
        throw new Error(`DeepSeek is not running on ${DEEPSEEK_API_URL}. Start it with: start-deepseek.bat`)
      }
      
      if (error.response?.status === 404) {
        throw new Error(`Model '${model}' not found. Available models: ${Object.values(LOCAL_MODELS).join(', ')}`)
      }
      
      throw new Error('Failed to chat with local DeepSeek model: ' + (error.message || 'Unknown error'))
    }
  }

  // Check if local DeepSeek is available
  async checkLocalModelAvailability() {
    try {
      const response = await axios.get(`${DEEPSEEK_API_URL}/api/tags`, {
        timeout: 5000
      })
      
      const availableModels = response.data.models || []
      const deepseekModels = availableModels.filter((model: any) => 
        model.name.includes('deepseek-r1')
      )
      
      return {
        available: true,
        url: DEEPSEEK_API_URL,
        models: deepseekModels,
        recommended: deepseekModels.find((m: any) => m.name.includes('8b')) ? 'deepseek-r1:8b' : 
                    deepseekModels.find((m: any) => m.name.includes('7b')) ? 'deepseek-r1:7b' :
                    deepseekModels[0]?.name || 'deepseek-r1:8b'
      }
    } catch (error: any) {
      console.log(`DeepSeek not available at ${DEEPSEEK_API_URL}:`, error.message)
      return {
        available: false,
        url: DEEPSEEK_API_URL,
        models: [] as string[],
        error: error.code === 'ECONNREFUSED' ? 'Service not running' : error.message
      }
    }
  }

  // General chat - supports Gemini, local models, and Kimi
  async chat(messages: string, model: 'flash' | 'pro' | 'deepseek' | 'local' | string = 'flash') {
    // Route to Kimi models if specified
    if (model.startsWith('moonshot-v1') || model.startsWith('kimi-')) {
      if (!kimiService.isAvailable()) {
        throw new Error('Kimi API not available. Please configure MOONSHOT_API_KEY.')
      }
      
      // Convert string to message array for Kimi
      const messageArray = [
        {
          role: 'user',
          content: messages
        }
      ]
      
      return await kimiService.chat(messageArray, model.startsWith('kimi-') ? KIMI_MODELS[model.replace('kimi-', '') as keyof typeof KIMI_MODELS] : model)
    }

    // Route to local DeepSeek model if specified
    if (model === 'deepseek' || model === 'local' || model.startsWith('deepseek-r1')) {
      const selectedModel = model === 'deepseek' || model === 'local' ? 
        LOCAL_MODELS['deepseek-r1-8b'] : 
        LOCAL_MODELS[model as keyof typeof LOCAL_MODELS] || model
      
      return await this.chatWithLocalModel(messages, selectedModel)
    }

    let selectedModel = model === 'pro' ? this.proModel : this.flashModel
    
    if (!selectedModel) {
      throw new Error('Gemini API not available. Please configure GEMINI_API_KEY.')
    }
    
    try {
      const result = await selectedModel.generateContent(messages)
      const response = await result.response
      return response.text()
    } catch (error: any) {
      console.error('Gemini API Error:', error)
      
      // If Pro model hits quota limit, fallback to Flash
      if (model === 'pro' && error.message?.includes('quota')) {
        console.log('Pro model quota exceeded, falling back to Flash model...')
        if (!this.flashModel) {
          throw new Error('Flash model not available for fallback.')
        }
        
        try {
          const flashResult = await this.flashModel.generateContent(messages)
          const flashResponse = await flashResult.response
          return '**[Using Gemini Flash due to Pro quota limit]**\n\n' + flashResponse.text()
        } catch (flashError) {
          console.error('Flash model also failed:', flashError)
          throw new Error('Both Gemini models failed. The API key may have exceeded its quota.')
        }
      }
      
      // Check for specific error types
      if (error.message?.includes('API key')) {
        throw new Error('Invalid Gemini API key. Please check your configuration.')
      } else if (error.message?.includes('quota')) {
        throw new Error('Gemini API quota exceeded. Please try again later or use your own API key.')
      }
      
      throw new Error('Failed to chat with Gemini AI: ' + error.message)
    }
  }

  // Analyze penetration test results with AI (supports Gemini, local models, and Kimi)
  async analyzePentestResults(results: any, model: 'flash' | 'pro' | 'deepseek' | string = 'flash') {
    // Route to Kimi if specified
    if (model.startsWith('moonshot-v1') || model.startsWith('kimi-')) {
      return await kimiService.analyzePentestResults(results, model.startsWith('kimi-') ? KIMI_MODELS[model.replace('kimi-', '') as keyof typeof KIMI_MODELS] : model)
    }
    const prompt = `As a cybersecurity expert, analyze these penetration test results and provide:
1. A comprehensive security assessment
2. Identified vulnerabilities with severity ratings
3. Potential attack vectors
4. Detailed remediation recommendations
5. Priority action items

Penetration Test Results:
${JSON.stringify(results, null, 2)}

Format your response with clear sections and actionable insights.`

    return await this.chat(prompt, model)
  }

  // Generate attack payloads with AI
  async generateAttackPayload(attackType: string, target: string, customDescription?: string, model: 'flash' | 'deepseek' | string = 'flash') {
    // Route to Kimi if specified
    if (model.startsWith('moonshot-v1') || model.startsWith('kimi-')) {
      return await kimiService.generateAttackPayload(attackType, target, customDescription, model.startsWith('kimi-') ? KIMI_MODELS[model.replace('kimi-', '') as keyof typeof KIMI_MODELS] : model)
    }
    const prompt = `As a security researcher, generate a professional penetration testing payload for:
Attack Type: ${attackType}
Target: ${target}
${customDescription ? `Custom Requirements: ${customDescription}` : ''}

Include:
1. Detailed payload code/scripts
2. Step-by-step execution instructions
3. Expected outcomes
4. Detection evasion techniques
5. Safety considerations

Format as a structured security testing guide.`

    return await this.chat(prompt, model)
  }

  // Analyze network configurations with AI
  async analyzeNetworkConfig(networkInfo: any, model: 'flash' | 'deepseek' = 'flash') {
    const prompt = `Analyze this network configuration for security issues:
${JSON.stringify(networkInfo, null, 2)}

Provide:
1. Security vulnerabilities in the network setup
2. Misconfigurations
3. Best practices recommendations
4. Firewall rules suggestions`

    return await this.chat(prompt, model)
  }

  // Real-time threat intelligence with AI
  async getThreatIntelligence(domain: string, ips: string[], model: 'pro' | 'deepseek' = 'pro') {
    const prompt = `Provide threat intelligence for:
Domain: ${domain}
IP Addresses: ${ips.join(', ')}

Include:
1. Known vulnerabilities
2. Historical security incidents
3. Reputation analysis
4. Associated threat actors
5. Recommended security measures`

    return await this.chat(prompt, model)
  }

  // Enhanced OSINT analysis with AI
  async analyzeOSINTData(osintData: any, target: string, model: 'pro' | 'deepseek' = 'pro') {
    const prompt = `As an OSINT specialist, analyze this intelligence data for ${target}:
${JSON.stringify(osintData, null, 2)}

Provide:
1. Key security findings
2. Exposed attack surface
3. Data leak risks
4. Social engineering vectors
5. Actionable intelligence summary`

    return await this.chat(prompt, model)
  }
}

// Export singleton instance
export const aiService = new AIService() 