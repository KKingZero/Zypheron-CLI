// Ensure environment variables are loaded
import dotenv from 'dotenv'
dotenv.config({ path: '.env' })

import fetch from 'node-fetch'
import { getSecureApiKey } from './encryption'
import { config } from './config'

// Initialize xAI API with secure key management
const XAI_API_KEY = config.XAI_API_KEY || getSecureApiKey('XAI_API_KEY')
if (!XAI_API_KEY) {
  console.warn('XAI_API_KEY not found. xAI services will be unavailable.')
}
const XAI_API_URL = 'https://api.x.ai/v1'

// Available models
export const XAI_MODELS = {
  grok3: 'grok-beta' // Using grok-beta as the model name
}

// xAI Service for Grok 3
export class XAIService {
  // General chat with Grok
  async chat(messages: any[], model: string = 'grok-beta') {
    try {
      const response = await fetch(`${XAI_API_URL}/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${XAI_API_KEY}`
        },
        body: JSON.stringify({
          model: model,
          messages: messages,
          temperature: 0.7,
          max_tokens: 2048,
          stream: false
        })
      })

      if (!response.ok) {
        const error = await response.text()
        throw new Error(`xAI API Error: ${response.status} - ${error}`)
      }

      const data = await response.json() as any
      return data.choices[0].message.content
    } catch (error) {
      console.error('xAI API Error:', error)
      throw new Error('Failed to chat with Grok 3')
    }
  }

  // Analyze penetration test results with Grok
  async analyzePentestResults(results: any) {
    const prompt = `You are a world-class penetration testing analyst using Grok 3's advanced capabilities. Analyze the provided penetration test results and provide a comprehensive security assessment in exactly 3 paragraphs:

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

Penetration Test Results:
${JSON.stringify(results, null, 2)}`

    const messages = [
      {
        role: 'system',
        content: 'You are Grok 3, an advanced AI security analyst with cutting-edge capabilities in cybersecurity analysis.'
      },
      {
        role: 'user',
        content: prompt
      }
    ]

    return this.chat(messages)
  }

  // Generate attack payloads with Grok
  async generateAttackPayload(attackType: string, targetUrl: string, customDescription?: string) {
    const messages = [
      {
        role: 'system',
        content: 'You are Grok 3, an expert in generating security testing payloads for authorized penetration testing.'
      },
      {
        role: 'user',
        content: customDescription 
          ? `Generate a custom attack payload for "${customDescription}" targeting ${targetUrl}. Include detailed code, commands, and exploitation techniques.`
          : `Generate a ${attackType} attack payload for ${targetUrl}. Include specific code examples, terminal commands, and step-by-step exploitation instructions.`
      }
    ]

    const response = await this.chat(messages)
    
    return {
      name: customDescription || attackType,
      description: `Grok 3 generated ${attackType} payload`,
      payload: {
        type: attackType,
        target: targetUrl,
        attack_vectors: [{
          name: attackType,
          description: response,
          code: response
        }]
      }
    }
  }
}

// Export singleton instance
export const xaiService = new XAIService() 