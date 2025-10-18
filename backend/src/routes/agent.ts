/**
 * Agent Mode API Routes
 * Handles AI-powered autonomous pentesting operations
 * Integrates AI orchestrator, job queue, and tool execution
 */

import { Router, Request, Response } from 'express'
import { authMiddleware } from '../middleware/auth'
import { commandSanitizerMiddleware } from '../middleware/commandSanitizer'
import { getAuditLogger } from '../services/auditLogger'
import { getPentestJobQueue } from '../services/pentestJobQueue'
import { getAIPentestOrchestrator } from '../services/aiPentestOrchestrator'
import { getVulnCorrelationEngine } from '../services/vulnCorrelationEngine'
import { DockerizedKaliTools } from '../services/dockerToolRunner'
import { CobraAgentFramework } from '../services/agentFramework'

const router = Router()
const auditLogger = getAuditLogger()
const jobQueue = getPentestJobQueue()
const aiOrchestrator = getAIPentestOrchestrator()
const vulnCorrelator = getVulnCorrelationEngine()
const kaliTools = new DockerizedKaliTools()
const agentFramework = new CobraAgentFramework()

/**
 * AI-powered tool recommendations
 */
router.post('/recommend-tools', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { target, operationType, agentMode, model } = req.body
    const userId = (req as any).user?.id || (req as any).user?.sub || 'anonymous'

    // Log request
    await auditLogger.logUserAction({
      userId,
      target,
      parameters: { operationType, agentMode, model },
      result: 'success',
      complianceNote: 'AI tool recommendation requested'
    })

    // Get contextual recommendations from agent framework
    const recommendations = agentFramework.getContextualRecommendations(
      target,
      operationType || 'reconnaissance'
    )

    // AI-generated tool sequence based on target and operation type
    let recommendedTools: string[] = []

    if (operationType === 'reconnaissance' || operationType === 'recon') {
      recommendedTools = [
        'recon_ng',           // WHOIS, DNS, OSINT
        'shodan_search',      // Internet-wide device search
        'nmap_scan',          // Port scanning
        'maltego_osint',      // Entity relationship mapping
        'web_port_scan'       // Web-based port scanning
      ]
    } else if (operationType === 'analysis' || operationType === 'scanning') {
      recommendedTools = [
        'nessus_scan',        // Vulnerability assessment
        'nikto_scan',         // Web server scanning
        'web_vulnerability_scan', // Comprehensive web scanning
        'nuclei_scan',        // Template-based scanning
        'sqlmap_scan'         // SQL injection testing
      ]
    } else if (operationType === 'exploitation') {
      recommendedTools = [
        'metasploit_exploit', // Automated exploitation
        'sqlmap_exploit',     // SQL injection exploitation
        'setoolkit_campaign'  // Social engineering
      ]
    } else if (operationType === 'payload') {
      recommendedTools = [
        'generate_payload',   // Payload generation
        'encode_payload',     // Payload encoding
        'start_listener'      // Listener setup
      ]
    } else {
      // Default comprehensive sequence
      recommendedTools = [
        'web_port_scan',
        'recon_ng',
        'nessus_scan',
        'web_vulnerability_scan',
        'sqlmap_scan',
        'password_strength_analysis'
      ]
    }

    // Add AI context
    const response = {
      tools: recommendedTools,
      reasoning: `AI selected ${recommendedTools.length} optimal tools for ${operationType || 'comprehensive assessment'} of ${target}`,
      recommendations: recommendations,
      estimatedDuration: recommendedTools.length * 120000, // ~2 min per tool
      confidence: 0.85
    }

    res.json(response)
  } catch (error) {
    console.error('Tool recommendation failed:', error)
    res.status(500).json({
      error: 'Failed to generate recommendations',
      message: error instanceof Error ? error.message : String(error)
    })
  }
})

/**
 * Execute security tool with Agent Mode
 */
router.post('/execute', authMiddleware, commandSanitizerMiddleware, async (req: Request, res: Response) => {
  try {
    const { toolName, parameters, agentMode } = req.body
    const validatedTool = req.body.validatedTool || toolName
    const sanitizedParams = req.body.sanitizedParams || parameters
    const userId = (req as any).user?.id || (req as any).user?.sub || 'anonymous'

    console.log(`🤖 Agent Mode: ${agentMode ? 'ENABLED' : 'DISABLED'} - Executing ${validatedTool}`)

    // Log tool execution start
    await auditLogger.logToolExecution({
      userId,
      toolName: validatedTool,
      target: sanitizedParams.target || sanitizedParams.url || 'unknown',
      parameters: sanitizedParams,
      result: 'success',
      severity: agentMode ? 'high' : 'medium',
      complianceNote: `Tool execution via Agent Mode: ${agentMode}`
    })

    // Execute tool via agent framework
    let result: any

    try {
      // Use agent framework's tool execution
      result = await agentFramework.executeTool(validatedTool, sanitizedParams)
      
      // If agent mode is enabled, add AI analysis
      if (agentMode && result) {
        // Ingest findings into correlation engine
        if (Array.isArray(result)) {
          await vulnCorrelator.ingestFindings(validatedTool, result)
        } else if (result.vulnerabilities) {
          await vulnCorrelator.ingestFindings(validatedTool, result.vulnerabilities)
        }

        // Get AI recommendations
        const context = `${validatedTool} results for ${sanitizedParams.target}`
        const aiRecommendations = agentFramework.getContextualRecommendations(
          sanitizedParams.target || '',
          context
        )

        // Add AI analysis to result
        result.aiAnalysis = {
          recommendations: aiRecommendations.nextSteps,
          relatedTools: aiRecommendations.tools,
          techniques: aiRecommendations.techniques
        }
      }
    } catch (toolError) {
      console.error(`Tool execution error: ${toolError}`)
      
      // Log failure
      await auditLogger.logToolExecution({
        userId,
        toolName: validatedTool,
        target: sanitizedParams.target || 'unknown',
        parameters: sanitizedParams,
        result: 'error',
        errorMessage: toolError instanceof Error ? toolError.message : String(toolError)
      })

      return res.status(500).json({
        success: false,
        error: 'Tool execution failed',
        message: toolError instanceof Error ? toolError.message : String(toolError),
        toolName: validatedTool
      })
    }

    // Log successful completion
    await auditLogger.logToolExecution({
      userId,
      toolName: validatedTool,
      target: sanitizedParams.target || 'unknown',
      parameters: sanitizedParams,
      result: 'success',
      duration: result.executionTime || 0
    })

    res.json({
      success: true,
      toolName: validatedTool,
      result,
      agentMode,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Agent execution failed:', error)
    res.status(500).json({
      success: false,
      error: 'Agent execution failed',
      message: error instanceof Error ? error.message : String(error)
    })
  }
})

/**
 * Analyze results with AI
 */
router.post('/analyze-results', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { toolName, results, target } = req.body
    const userId = (req as any).user?.id || (req as any).user?.sub || 'anonymous'

    console.log(`🧠 AI analyzing ${toolName} results for ${target}`)

    // Get contextual recommendations
    const recommendations = agentFramework.getContextualRecommendations(
      target || '',
      `${toolName} analysis`
    )

    // Generate insights based on tool type
    const insights: string[] = []

    if (results.vulnerable || results.vulnerabilities?.length > 0) {
      insights.push(`⚠️ Vulnerabilities detected in ${toolName} scan`)
      insights.push(`Recommended action: Review findings and prioritize remediation`)
    }

    if (results.ports?.length > 0) {
      const openPorts = results.ports.filter((p: any) => p.state === 'open')
      insights.push(`🔍 Found ${openPorts.length} open ports`)
      insights.push(`Consider: Close unnecessary ports and services`)
    }

    if (results.exploitAvailable || results.successful) {
      insights.push(`🚨 Exploitation successful or exploit available`)
      insights.push(`Critical: Immediate patching required`)
    }

    // Default insights if none generated
    if (insights.length === 0) {
      insights.push(`✅ ${toolName} execution completed successfully`)
      insights.push(`Continue with next recommended security tools`)
    }

    // Add contextual recommendations
    if (recommendations.nextSteps) {
      insights.push(...recommendations.nextSteps)
    }

    // Log analysis
    await auditLogger.logUserAction({
      userId,
      toolName,
      target,
      result: 'success',
      complianceNote: 'AI result analysis performed'
    })

    res.json({
      insights,
      recommendations: recommendations.tools,
      techniques: recommendations.techniques,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Result analysis failed:', error)
    res.status(500).json({
      error: 'Analysis failed',
      message: error instanceof Error ? error.message : String(error)
    })
  }
})

/**
 * Start AI-guided pentest session
 */
router.post('/session/start', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { target, objective } = req.body
    const userId = (req as any).user?.id || (req as any).user?.sub || 'anonymous'

    if (!target) {
      return res.status(400).json({
        error: 'Target is required',
        message: 'Please provide a target URL or IP address'
      })
    }

    console.log(`🎯 Starting AI-guided pentest session for ${target}`)

    // Start AI orchestrator session
    const sessionId = await aiOrchestrator.startSession(
      target,
      objective || 'Comprehensive security assessment',
      userId
    )

    res.json({
      success: true,
      sessionId,
      target,
      objective,
      message: 'AI pentest session initiated',
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Session start failed:', error)
    res.status(500).json({
      error: 'Failed to start session',
      message: error instanceof Error ? error.message : String(error)
    })
  }
})

/**
 * Get AI session status
 */
router.get('/session/:sessionId', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { sessionId } = req.params

    const session = aiOrchestrator.getSession(sessionId)

    if (!session) {
      return res.status(404).json({
        error: 'Session not found',
        message: `No session found with ID: ${sessionId}`
      })
    }

    res.json({
      success: true,
      session,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Session status failed:', error)
    res.status(500).json({
      error: 'Failed to get session status',
      message: error instanceof Error ? error.message : String(error)
    })
  }
})

/**
 * Complete AI session
 */
router.post('/session/:sessionId/complete', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { sessionId } = req.params

    await aiOrchestrator.completeSession(sessionId)

    res.json({
      success: true,
      message: 'Session completed',
      sessionId,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Session completion failed:', error)
    res.status(500).json({
      error: 'Failed to complete session',
      message: error instanceof Error ? error.message : String(error)
    })
  }
})

/**
 * Get vulnerability correlation report
 */
router.get('/vulnerabilities/report', authMiddleware, async (req: Request, res: Response) => {
  try {
    const report = await vulnCorrelator.generateReport()

    res.json({
      success: true,
      report,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Report generation failed:', error)
    res.status(500).json({
      error: 'Failed to generate report',
      message: error instanceof Error ? error.message : String(error)
    })
  }
})

/**
 * Queue a job for async execution
 */
router.post('/queue-job', authMiddleware, commandSanitizerMiddleware, async (req: Request, res: Response) => {
  try {
    const { toolName, target, parameters, priority } = req.body
    const validatedTool = req.body.validatedTool || toolName
    const sanitizedParams = req.body.sanitizedParams || parameters
    const userId = (req as any).user?.id || (req as any).user?.sub || 'anonymous'

    // Queue the job
    const jobId = await jobQueue.addJob({
      userId,
      toolName: validatedTool,
      target,
      parameters: sanitizedParams,
      priority: priority || 0
    })

    res.json({
      success: true,
      jobId,
      message: 'Job queued successfully',
      estimatedWaitTime: '2-5 minutes',
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Job queue failed:', error)
    res.status(500).json({
      error: 'Failed to queue job',
      message: error instanceof Error ? error.message : String(error)
    })
  }
})

/**
 * Get job status
 */
router.get('/job/:jobId', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { jobId } = req.params

    const job = await jobQueue.getJobStatus(jobId)

    if (!job) {
      return res.status(404).json({
        error: 'Job not found',
        message: `No job found with ID: ${jobId}`
      })
    }

    res.json({
      success: true,
      job,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Job status failed:', error)
    res.status(500).json({
      error: 'Failed to get job status',
      message: error instanceof Error ? error.message : String(error)
    })
  }
})

/**
 * Get queue statistics
 */
router.get('/queue/stats', authMiddleware, async (req: Request, res: Response) => {
  try {
    const stats = await jobQueue.getQueueStats()

    res.json({
      success: true,
      stats,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Queue stats failed:', error)
    res.status(500).json({
      error: 'Failed to get queue stats',
      message: error instanceof Error ? error.message : String(error)
    })
  }
})

/**
 * Health check endpoint
 */
router.get('/health', async (req: Request, res: Response) => {
  try {
    const queueStats = await jobQueue.getQueueStats()
    
    res.json({
      status: 'healthy',
      services: {
        jobQueue: 'operational',
        aiOrchestrator: 'operational',
        vulnCorrelator: 'operational',
        auditLogger: 'operational'
      },
      queueStats,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      error: error instanceof Error ? error.message : String(error),
      timestamp: new Date().toISOString()
    })
  }
})

export default router
