/**
 * ML-Enhanced Attack Chain Detector
 * Uses machine learning to identify sophisticated attack paths
 */

import { getMLSimilarityEngine } from './mlSimilarityEngine'

export interface AttackNode {
  id: string
  vulnerability: any
  type: 'entry' | 'escalation' | 'lateral' | 'exfiltration' | 'persistence'
  prerequisites: string[]
  enables: string[]
  confidence: number
}

export interface AttackChain {
  id: string
  name: string
  nodes: AttackNode[]
  totalRisk: number
  likelihood: number
  impact: string
  mitigations: string[]
  detectionDifficulty: 'trivial' | 'easy' | 'moderate' | 'hard' | 'very-hard'
  attackerSkillRequired: 'script-kiddie' | 'intermediate' | 'advanced' | 'expert'
}

export interface ChainPattern {
  name: string
  description: string
  sequence: string[]
  indicators: string[]
  realWorldExamples: string[]
}

export class MLAttackChainDetector {
  private knownPatterns: ChainPattern[] = []
  private mlSimilarity = getMLSimilarityEngine()

  constructor() {
    this.initializeKnownPatterns()
    console.log('🔗 ML Attack Chain Detector initialized')
  }

  /**
   * Initialize known attack chain patterns
   */
  private initializeKnownPatterns() {
    this.knownPatterns = [
      {
        name: 'Web Shell Upload Chain',
        description: 'File upload → RCE → privilege escalation',
        sequence: ['file-upload', 'rce', 'privilege-escalation'],
        indicators: ['CWE-434', 'CWE-78', 'CWE-269'],
        realWorldExamples: ['China Chopper', 'WebShell-Combo']
      },
      {
        name: 'SQL Injection to Lateral Movement',
        description: 'SQLi → credential theft → lateral movement',
        sequence: ['sql-injection', 'credential-access', 'lateral-movement'],
        indicators: ['CWE-89', 'credential-dumping', 'smb-relay'],
        realWorldExamples: ['APT29 TTP', 'FIN7 campaigns']
      },
      {
        name: 'Phishing to Ransomware',
        description: 'Phishing → initial access → ransomware deployment',
        sequence: ['phishing', 'initial-access', 'execution', 'ransomware'],
        indicators: ['social-engineering', 'macro-execution', 'file-encryption'],
        realWorldExamples: ['Conti', 'REvil', 'LockBit']
      },
      {
        name: 'API Exploitation Chain',
        description: 'API vuln → data exfiltration',
        sequence: ['api-vulnerability', 'authentication-bypass', 'data-exfiltration'],
        indicators: ['CWE-284', 'CWE-639', 'sensitive-data-exposure'],
        realWorldExamples: ['OWASP API Top 10 attacks']
      },
      {
        name: 'Container Escape to Host Compromise',
        description: 'Container vuln → escape → host takeover',
        sequence: ['container-vulnerability', 'escape', 'host-compromise'],
        indicators: ['privileged-container', 'kernel-exploit', 'docker-socket-access'],
        realWorldExamples: ['runc CVE-2019-5736', 'Docker breakout']
      }
    ]
  }

  /**
   * Detect attack chains from vulnerabilities
   */
  async detectAttackChains(vulnerabilities: any[]): Promise<AttackChain[]> {
    console.log(`🔍 Analyzing ${vulnerabilities.length} vulnerabilities for attack chains...`)

    const chains: AttackChain[] = []

    // Convert vulnerabilities to attack nodes
    const nodes = vulnerabilities.map(v => this.vulnerabilityToNode(v))

    // Method 1: Pattern-based detection
    const patternChains = await this.detectPatternBasedChains(nodes)
    chains.push(...patternChains)

    // Method 2: ML-based detection (semantic similarity)
    const mlChains = await this.detectMLBasedChains(nodes)
    chains.push(...mlChains)

    // Method 3: Graph-based detection (dependency analysis)
    const graphChains = this.detectGraphBasedChains(nodes)
    chains.push(...graphChains)

    // Deduplicate and rank
    const uniqueChains = this.deduplicateChains(chains)
    return uniqueChains.sort((a, b) => b.totalRisk - a.totalRisk)
  }

  /**
   * Convert vulnerability to attack node
   */
  private vulnerabilityToNode(vuln: any): AttackNode {
    const type = this.classifyNodeType(vuln)
    const prerequisites = this.identifyPrerequisites(vuln)
    const enables = this.identifyEnables(vuln)

    return {
      id: vuln.id || vuln.cve,
      vulnerability: vuln,
      type,
      prerequisites,
      enables,
      confidence: vuln.confidence || 0.5
    }
  }

  /**
   * Classify attack node type
   */
  private classifyNodeType(vuln: any): AttackNode['type'] {
    const description = (vuln.description || '').toLowerCase()
    const cwe = (vuln.cwe || []).map((c: string) => c.toLowerCase())

    // Entry points
    if (description.includes('remote') || description.includes('unauthenticated') ||
        cwe.includes('cwe-287') || cwe.includes('cwe-306')) {
      return 'entry'
    }

    // Privilege escalation
    if (description.includes('privilege') || description.includes('escalation') ||
        cwe.includes('cwe-269') || cwe.includes('cwe-250')) {
      return 'escalation'
    }

    // Lateral movement
    if (description.includes('lateral') || description.includes('network') ||
        description.includes('smb') || description.includes('rdp')) {
      return 'lateral'
    }

    // Data exfiltration
    if (description.includes('disclosure') || description.includes('information') ||
        cwe.includes('cwe-200') || cwe.includes('cwe-359')) {
      return 'exfiltration'
    }

    // Persistence
    if (description.includes('persistence') || description.includes('backdoor') ||
        description.includes('implant')) {
      return 'persistence'
    }

    return 'entry' // Default
  }

  /**
   * Identify prerequisites for exploiting vulnerability
   */
  private identifyPrerequisites(vuln: any): string[] {
    const prerequisites: string[] = []

    // Authentication required
    if (vuln.privilegesRequired && vuln.privilegesRequired !== 'NONE') {
      prerequisites.push('authenticated-access')
    }

    // User interaction required
    if (vuln.userInteraction === 'REQUIRED') {
      prerequisites.push('user-interaction')
    }

    // Network access
    if (vuln.attackVector === 'NETWORK') {
      prerequisites.push('network-access')
    }

    // Local access
    if (vuln.attackVector === 'LOCAL') {
      prerequisites.push('local-access')
    }

    return prerequisites
  }

  /**
   * Identify what this vulnerability enables
   */
  private identifyEnables(vuln: any): string[] {
    const enables: string[] = []

    // RCE enables many things
    if (vuln.cwe?.includes('CWE-78') || vuln.cwe?.includes('CWE-77')) {
      enables.push('code-execution', 'privilege-escalation', 'persistence')
    }

    // File upload
    if (vuln.cwe?.includes('CWE-434')) {
      enables.push('webshell', 'code-execution')
    }

    // SQLi
    if (vuln.cwe?.includes('CWE-89')) {
      enables.push('data-extraction', 'authentication-bypass')
    }

    // Authentication bypass
    if (vuln.cwe?.includes('CWE-287')) {
      enables.push('unauthorized-access', 'lateral-movement')
    }

    return enables
  }

  /**
   * Detect chains using known patterns
   */
  private async detectPatternBasedChains(nodes: AttackNode[]): Promise<AttackChain[]> {
    const chains: AttackChain[] = []

    for (const pattern of this.knownPatterns) {
      const matchingNodes = await this.findNodesMatchingPattern(nodes, pattern)
      
      if (matchingNodes.length >= 2) {
        const chain: AttackChain = {
          id: `pattern-${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
          name: pattern.name,
          nodes: matchingNodes,
          totalRisk: this.calculateChainRisk(matchingNodes),
          likelihood: this.calculateChainLikelihood(matchingNodes),
          impact: this.calculateChainImpact(matchingNodes),
          mitigations: this.generateChainMitigations(matchingNodes),
          detectionDifficulty: this.assessDetectionDifficulty(matchingNodes),
          attackerSkillRequired: this.assessAttackerSkill(matchingNodes)
        }

        chains.push(chain)
      }
    }

    return chains
  }

  /**
   * Find nodes matching pattern using ML similarity
   */
  private async findNodesMatchingPattern(
    nodes: AttackNode[],
    pattern: ChainPattern
  ): Promise<AttackNode[]> {
    const matchingNodes: AttackNode[] = []

    for (const node of nodes) {
      const nodeDescription = node.vulnerability.description || ''
      const nodeCWEs = node.vulnerability.cwe || []

      // Check CWE match
      const cweMatch = pattern.indicators.some(indicator => 
        nodeCWEs.some((cwe: string) => cwe.toLowerCase().includes(indicator.toLowerCase()))
      )

      if (cweMatch) {
        matchingNodes.push(node)
        continue
      }

      // Check semantic similarity with pattern description
      try {
        const similarity = await this.mlSimilarity.calculateSimilarity(
          nodeDescription,
          pattern.description
        )

        if (similarity.similarity > 0.6) {
          matchingNodes.push(node)
        }
      } catch (error) {
        // Skip if similarity calculation fails
      }
    }

    return matchingNodes
  }

  /**
   * Detect chains using ML (semantic clustering)
   */
  private async detectMLBasedChains(nodes: AttackNode[]): Promise<AttackChain[]> {
    const chains: AttackChain[] = []

    // Group nodes by semantic similarity
    try {
      const descriptions = nodes.map(n => n.vulnerability.description || n.vulnerability.title || '')
      const clusters = await this.mlSimilarity.clusterSimilarItems(descriptions, 0.7)

      for (const cluster of clusters) {
        if (cluster.length >= 2) {
          const clusterNodes = cluster.map(desc => 
            nodes.find(n => 
              (n.vulnerability.description || n.vulnerability.title) === desc
            )!
          ).filter(Boolean)

          if (clusterNodes.length >= 2) {
            const chain: AttackChain = {
              id: `ml-cluster-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
              name: `ML-Detected Attack Chain (${clusterNodes.length} steps)`,
              nodes: clusterNodes,
              totalRisk: this.calculateChainRisk(clusterNodes),
              likelihood: this.calculateChainLikelihood(clusterNodes),
              impact: this.calculateChainImpact(clusterNodes),
              mitigations: this.generateChainMitigations(clusterNodes),
              detectionDifficulty: this.assessDetectionDifficulty(clusterNodes),
              attackerSkillRequired: this.assessAttackerSkill(clusterNodes)
            }

            chains.push(chain)
          }
        }
      }
    } catch (error) {
      console.warn('ML clustering failed:', error)
    }

    return chains
  }

  /**
   * Detect chains using graph analysis
   */
  private detectGraphBasedChains(nodes: AttackNode[]): Promise<AttackChain[]> {
    const chains: AttackChain[] = []

    // Build dependency graph
    const graph = new Map<string, Set<string>>()

    for (const node of nodes) {
      const dependencies = new Set<string>()

      // Check if any node enables this one
      for (const otherNode of nodes) {
        if (otherNode.id === node.id) continue

        const enablesMatch = otherNode.enables.some(e => 
          node.prerequisites.includes(e)
        )

        if (enablesMatch) {
          dependencies.add(otherNode.id)
        }
      }

      graph.set(node.id, dependencies)
    }

    // Find paths through graph (simplified DFS)
    const visited = new Set<string>()
    const paths: AttackNode[][] = []

    for (const startNode of nodes.filter(n => n.type === 'entry')) {
      const path = this.findAttackPaths(startNode, nodes, graph, visited, [])
      if (path.length >= 2) {
        paths.push(path)
      }
    }

    // Convert paths to chains
    for (const path of paths) {
      const chain: AttackChain = {
        id: `graph-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        name: `Attack Path: ${path[0].type} → ${path[path.length - 1].type}`,
        nodes: path,
        totalRisk: this.calculateChainRisk(path),
        likelihood: this.calculateChainLikelihood(path),
        impact: this.calculateChainImpact(path),
        mitigations: this.generateChainMitigations(path),
        detectionDifficulty: this.assessDetectionDifficulty(path),
        attackerSkillRequired: this.assessAttackerSkill(path)
      }

      chains.push(chain)
    }

    return Promise.resolve(chains)
  }

  /**
   * Find attack paths through graph (DFS)
   */
  private findAttackPaths(
    current: AttackNode,
    allNodes: AttackNode[],
    graph: Map<string, Set<string>>,
    visited: Set<string>,
    path: AttackNode[]
  ): AttackNode[] {
    visited.add(current.id)
    path.push(current)

    // If we've found a significant path, return it
    if (path.length >= 3 || (path.length >= 2 && current.type === 'exfiltration')) {
      return path
    }

    // Explore dependencies
    const deps = graph.get(current.id) || new Set()
    for (const depId of deps) {
      if (!visited.has(depId)) {
        const depNode = allNodes.find(n => n.id === depId)
        if (depNode) {
          const result = this.findAttackPaths(depNode, allNodes, graph, visited, [...path])
          if (result.length > path.length) {
            return result
          }
        }
      }
    }

    return path
  }

  /**
   * Calculate chain risk
   */
  private calculateChainRisk(nodes: AttackNode[]): number {
    const avgCVSS = nodes.reduce((sum, n) => sum + (n.vulnerability.cvss || 5), 0) / nodes.length
    const chainLength = Math.min(nodes.length / 5, 1) // Longer chains = higher risk
    const confidenceMultiplier = nodes.reduce((sum, n) => sum + n.confidence, 0) / nodes.length

    return (avgCVSS * 10 * (1 + chainLength)) * confidenceMultiplier
  }

  /**
   * Calculate chain likelihood
   */
  private calculateChainLikelihood(nodes: AttackNode[]): number {
    // Product of individual likelihoods
    let likelihood = 1.0

    for (const node of nodes) {
      const nodeLikelihood = node.vulnerability.exploitAvailable ? 0.8 : 0.4
      likelihood *= nodeLikelihood
    }

    return likelihood
  }

  /**
   * Calculate chain impact
   */
  private calculateChainImpact(nodes: AttackNode[]): string {
    const hasCritical = nodes.some(n => n.vulnerability.severity === 'critical')
    const hasExfiltration = nodes.some(n => n.type === 'exfiltration')
    const hasEscalation = nodes.some(n => n.type === 'escalation')

    if (hasCritical || (hasExfiltration && hasEscalation)) {
      return 'Complete system compromise with data exfiltration'
    }

    if (hasExfiltration) {
      return 'Sensitive data exposure'
    }

    if (hasEscalation) {
      return 'Elevated privileges and system control'
    }

    return 'Limited unauthorized access'
  }

  /**
   * Generate mitigations for chain
   */
  private generateChainMitigations(nodes: AttackNode[]): string[] {
    const mitigations = new Set<string>()

    // Add specific mitigations
    mitigations.add('Break the attack chain by fixing any vulnerability in the sequence')
    mitigations.add('Implement defense in depth with multiple security layers')
    mitigations.add('Enable comprehensive logging and monitoring')

    // Node-specific mitigations
    for (const node of nodes) {
      if (node.vulnerability.remediation) {
        node.vulnerability.remediation.forEach((r: string) => mitigations.add(r))
      }
    }

    return Array.from(mitigations).slice(0, 10)
  }

  /**
   * Assess detection difficulty
   */
  private assessDetectionDifficulty(nodes: AttackNode[]): AttackChain['detectionDifficulty'] {
    const stealthyNodes = nodes.filter(n => 
      n.vulnerability.attackComplexity === 'HIGH' || 
      n.vulnerability.userInteraction === 'REQUIRED'
    ).length

    const ratio = stealthyNodes / nodes.length

    if (ratio > 0.7) return 'very-hard'
    if (ratio > 0.5) return 'hard'
    if (ratio > 0.3) return 'moderate'
    if (ratio > 0.1) return 'easy'
    return 'trivial'
  }

  /**
   * Assess attacker skill required
   */
  private assessAttackerSkill(nodes: AttackNode[]): AttackChain['attackerSkillRequired'] {
    const avgComplexity = nodes.filter(n => 
      n.vulnerability.attackComplexity === 'HIGH'
    ).length / nodes.length

    const hasExploits = nodes.every(n => n.vulnerability.exploitAvailable)

    if (avgComplexity > 0.7) return 'expert'
    if (avgComplexity > 0.4) return 'advanced'
    if (!hasExploits) return 'advanced'
    if (avgComplexity > 0.2) return 'intermediate'
    return 'script-kiddie'
  }

  /**
   * Deduplicate similar chains
   */
  private deduplicateChains(chains: AttackChain[]): AttackChain[] {
    const unique: AttackChain[] = []

    for (const chain of chains) {
      const isDuplicate = unique.some(existing => {
        // Check if nodes are mostly the same
        const commonNodes = chain.nodes.filter(n => 
          existing.nodes.some(en => en.id === n.id)
        )

        return commonNodes.length >= Math.min(chain.nodes.length, existing.nodes.length) * 0.7
      })

      if (!isDuplicate) {
        unique.push(chain)
      }
    }

    return unique
  }
}

// Singleton instance
let detectorInstance: MLAttackChainDetector | null = null

export function getMLAttackChainDetector(): MLAttackChainDetector {
  if (!detectorInstance) {
    detectorInstance = new MLAttackChainDetector()
  }
  return detectorInstance
}

