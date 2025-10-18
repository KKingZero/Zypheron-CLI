// Ensure environment variables are loaded
import dotenv from 'dotenv'
dotenv.config({ path: '.env' })

import OpenAI from 'openai'
import { getSecureApiKey } from './encryption'

// Initialize Kimi (Moonshot) API with secure key management
const MOONSHOT_API_KEY = getSecureApiKey('MOONSHOT_API_KEY')
if (!MOONSHOT_API_KEY) {
  console.warn('MOONSHOT_API_KEY not found. Kimi services will be unavailable.')
}

// Kimi/Moonshot configuration
const MOONSHOT_BASE_URL = 'https://api.moonshot.cn/v1'

// Available Kimi models - Consolidated to K2 (128K context)
export const KIMI_MODELS = {
  'k2': 'moonshot-v1-128k'
}

export class KimiService {
  private client: OpenAI | null = null

  constructor() {
    if (MOONSHOT_API_KEY) {
      this.client = new OpenAI({
        apiKey: MOONSHOT_API_KEY,
        baseURL: MOONSHOT_BASE_URL,
      })
    }
  }

  // Check if Kimi API is available
  isAvailable(): boolean {
    return this.client !== null && MOONSHOT_API_KEY !== null
  }

  // Chat with Kimi models
  async chat(messages: any[], model: string = 'moonshot-v1-128k'): Promise<string> {
    if (!this.client) {
      throw new Error('Kimi API not available. Please configure MOONSHOT_API_KEY.')
    }

    try {
      const completion = await this.client.chat.completions.create({
        model: model,
        messages: messages,
        temperature: 0.3,
        max_tokens: 2000,
      })

      return completion.choices[0]?.message?.content || 'No response generated'
    } catch (error: any) {
      console.error('Kimi API Error:', error)
      
      if (error.status === 401) {
        throw new Error('Invalid Kimi API key. Please check your MOONSHOT_API_KEY configuration.')
      } else if (error.status === 429) {
        throw new Error('Kimi API rate limit exceeded. Please try again later.')
      } else if (error.status === 400) {
        throw new Error('Invalid request to Kimi API. Please check your message format.')
      }
      
      throw new Error(`Failed to chat with Kimi AI: ${error.message || 'Unknown error'}`)
    }
  }

  // Analyze penetration test results with Kimi
  async analyzePentestResults(results: any, model: string = 'moonshot-v1-128k'): Promise<string> {
    const messages = [
      {
        role: 'system',
        content: '你是一名网络安全专家，请用中文分析以下渗透测试结果，并提供专业的安全建议。'
      },
      {
        role: 'user',
        content: `请分析以下渗透测试结果并提供：
1. 全面的安全评估
2. 已识别的漏洞及其严重等级
3. 潜在的攻击向量
4. 详细的修复建议
5. 优先处理事项

渗透测试结果：
${JSON.stringify(results, null, 2)}`
      }
    ]

    return await this.chat(messages, model)
  }

  // Generate attack payloads with Kimi
  async generateAttackPayload(attackType: string, target: string, customDescription?: string, model: string = 'moonshot-v1-128k'): Promise<string> {
    const messages = [
      {
        role: 'system',
        content: '你是一名网络安全研究员，请协助生成用于安全测试的专业渗透测试载荷。请注意这仅用于合法的安全测试目的。'
      },
      {
        role: 'user',
        content: `请为以下安全测试场景生成专业的渗透测试载荷：
攻击类型：${attackType}
目标：${target}
${customDescription ? `自定义要求：${customDescription}` : ''}

请包含：
1. 详细的载荷代码/脚本
2. 逐步执行说明
3. 预期结果
4. 检测规避技术
5. 安全注意事项

请以结构化的安全测试指南格式输出。`
      }
    ]

    return await this.chat(messages, model)
  }
}

// Export singleton instance
export const kimiService = new KimiService() 