/**
 * ML-Based Similarity Engine
 * Uses embeddings instead of basic Levenshtein distance
 */

import axios from 'axios'
import * as crypto from 'crypto'

export interface SimilarityResult {
  similarity: number // 0-1 scale
  method: 'embedding' | 'levenshtein' | 'hybrid'
  confidence: number
  embeddingDimensions?: number
}

export interface TextEmbedding {
  text: string
  embedding: number[]
  model: string
  dimensions: number
  timestamp: Date
}

export class MLSimilarityEngine {
  private embeddingCache: Map<string, TextEmbedding> = new Map()
  private readonly cacheSize = 1000
  private openaiApiKey?: string
  private localEmbeddingEndpoint?: string

  constructor(config?: {
    openaiApiKey?: string
    localEmbeddingEndpoint?: string
  }) {
    this.openaiApiKey = config?.openaiApiKey || process.env.OPENAI_API_KEY
    this.localEmbeddingEndpoint = config?.localEmbeddingEndpoint || 'http://localhost:11434/api/embeddings'
    
    console.log('🧠 ML Similarity Engine initialized')
  }

  /**
   * Calculate similarity between two texts using ML embeddings
   */
  async calculateSimilarity(text1: string, text2: string): Promise<SimilarityResult> {
    try {
      // Try ML embeddings first
      if (this.openaiApiKey || this.localEmbeddingEndpoint) {
        const embedding1 = await this.getEmbedding(text1)
        const embedding2 = await this.getEmbedding(text2)

        const cosineSim = this.cosineSimilarity(embedding1.embedding, embedding2.embedding)

        return {
          similarity: cosineSim,
          method: 'embedding',
          confidence: 0.95,
          embeddingDimensions: embedding1.dimensions
        }
      }

      // Fallback to Levenshtein
      const levenshteinSim = this.levenshteinSimilarity(text1, text2)
      return {
        similarity: levenshteinSim,
        method: 'levenshtein',
        confidence: 0.6
      }
    } catch (error) {
      console.warn('ML embedding failed, using Levenshtein fallback:', error)
      
      const levenshteinSim = this.levenshteinSimilarity(text1, text2)
      return {
        similarity: levenshteinSim,
        method: 'levenshtein',
        confidence: 0.6
      }
    }
  }

  /**
   * Get embedding for text
   */
  private async getEmbedding(text: string): Promise<TextEmbedding> {
    // Check cache
    const cacheKey = this.getCacheKey(text)
    const cached = this.embeddingCache.get(cacheKey)
    if (cached) {
      return cached
    }

    // Try OpenAI embeddings first (best quality)
    if (this.openaiApiKey) {
      try {
        const embedding = await this.getOpenAIEmbedding(text)
        this.cacheEmbedding(cacheKey, embedding)
        return embedding
      } catch (error) {
        console.warn('OpenAI embedding failed:', error)
      }
    }

    // Fallback to local embeddings (Ollama)
    if (this.localEmbeddingEndpoint) {
      try {
        const embedding = await this.getLocalEmbedding(text)
        this.cacheEmbedding(cacheKey, embedding)
        return embedding
      } catch (error) {
        console.warn('Local embedding failed:', error)
      }
    }

    throw new Error('No embedding service available')
  }

  /**
   * Get OpenAI embedding
   */
  private async getOpenAIEmbedding(text: string): Promise<TextEmbedding> {
    const response = await axios.post(
      'https://api.openai.com/v1/embeddings',
      {
        input: text,
        model: 'text-embedding-3-small' // 1536 dimensions, cost-effective
      },
      {
        headers: {
          'Authorization': `Bearer ${this.openaiApiKey}`,
          'Content-Type': 'application/json'
        },
        timeout: 10000
      }
    )

    return {
      text,
      embedding: response.data.data[0].embedding,
      model: 'text-embedding-3-small',
      dimensions: response.data.data[0].embedding.length,
      timestamp: new Date()
    }
  }

  /**
   * Get local embedding (Ollama)
   */
  private async getLocalEmbedding(text: string): Promise<TextEmbedding> {
    const response = await axios.post(
      this.localEmbeddingEndpoint!,
      {
        model: 'nomic-embed-text', // Good open-source embedding model
        prompt: text
      },
      {
        timeout: 10000
      }
    )

    return {
      text,
      embedding: response.data.embedding,
      model: 'nomic-embed-text',
      dimensions: response.data.embedding.length,
      timestamp: new Date()
    }
  }

  /**
   * Calculate cosine similarity between embeddings
   */
  private cosineSimilarity(a: number[], b: number[]): number {
    if (a.length !== b.length) {
      throw new Error('Embeddings must have same dimensions')
    }

    let dotProduct = 0
    let normA = 0
    let normB = 0

    for (let i = 0; i < a.length; i++) {
      dotProduct += a[i] * b[i]
      normA += a[i] * a[i]
      normB += b[i] * b[i]
    }

    normA = Math.sqrt(normA)
    normB = Math.sqrt(normB)

    if (normA === 0 || normB === 0) {
      return 0
    }

    return dotProduct / (normA * normB)
  }

  /**
   * Fallback: Levenshtein similarity
   */
  private levenshteinSimilarity(str1: string, str2: string): number {
    const longer = str1.length > str2.length ? str1 : str2
    const shorter = str1.length > str2.length ? str2 : str1
    
    if (longer.length === 0) return 1.0
    
    const editDistance = this.levenshteinDistance(longer, shorter)
    return (longer.length - editDistance) / longer.length
  }

  /**
   * Levenshtein distance calculation
   */
  private levenshteinDistance(str1: string, str2: string): number {
    const matrix: number[][] = []
    
    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i]
    }
    
    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j
    }
    
    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1]
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          )
        }
      }
    }
    
    return matrix[str2.length][str1.length]
  }

  /**
   * Batch similarity calculation
   */
  async calculateBatchSimilarity(
    target: string,
    candidates: string[]
  ): Promise<Array<{ text: string; similarity: number }>> {
    const results: Array<{ text: string; similarity: number }> = []

    // Get target embedding once
    const targetEmbedding = await this.getEmbedding(target)

    // Calculate similarity with all candidates
    for (const candidate of candidates) {
      try {
        const candidateEmbedding = await this.getEmbedding(candidate)
        const similarity = this.cosineSimilarity(
          targetEmbedding.embedding,
          candidateEmbedding.embedding
        )

        results.push({ text: candidate, similarity })
      } catch (error) {
        // Skip failed embeddings
        console.warn(`Failed to calculate similarity for: ${candidate}`)
      }
    }

    // Sort by similarity (highest first)
    return results.sort((a, b) => b.similarity - a.similarity)
  }

  /**
   * Find most similar items
   */
  async findMostSimilar(
    target: string,
    candidates: string[],
    topN: number = 5,
    threshold: number = 0.7
  ): Promise<string[]> {
    const similarities = await this.calculateBatchSimilarity(target, candidates)
    
    return similarities
      .filter(item => item.similarity >= threshold)
      .slice(0, topN)
      .map(item => item.text)
  }

  /**
   * Cluster similar items
   */
  async clusterSimilarItems(
    items: string[],
    similarityThreshold: number = 0.8
  ): Promise<string[][]> {
    const clusters: string[][] = []
    const processed = new Set<string>()

    for (const item of items) {
      if (processed.has(item)) continue

      const cluster: string[] = [item]
      processed.add(item)

      // Find similar items
      for (const candidate of items) {
        if (processed.has(candidate)) continue

        const result = await this.calculateSimilarity(item, candidate)
        if (result.similarity >= similarityThreshold) {
          cluster.push(candidate)
          processed.add(candidate)
        }
      }

      clusters.push(cluster)
    }

    return clusters
  }

  /**
   * Cache management
   */
  private getCacheKey(text: string): string {
    return crypto.createHash('md5').update(text).digest('hex')
  }

  private cacheEmbedding(key: string, embedding: TextEmbedding): void {
    // Limit cache size
    if (this.embeddingCache.size >= this.cacheSize) {
      // Remove oldest entry
      const firstKey = this.embeddingCache.keys().next().value
      this.embeddingCache.delete(firstKey)
    }

    this.embeddingCache.set(key, embedding)
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.embeddingCache.clear()
  }

  /**
   * Get cache statistics
   */
  getCacheStats() {
    return {
      size: this.embeddingCache.size,
      maxSize: this.cacheSize,
      utilization: (this.embeddingCache.size / this.cacheSize) * 100
    }
  }
}

// Singleton instance
let similarityEngineInstance: MLSimilarityEngine | null = null

export function getMLSimilarityEngine(config?: {
  openaiApiKey?: string
  localEmbeddingEndpoint?: string
}): MLSimilarityEngine {
  if (!similarityEngineInstance) {
    similarityEngineInstance = new MLSimilarityEngine(config)
  }
  return similarityEngineInstance
}

