// Load environment variables FIRST before any other imports
import dotenv from 'dotenv'
dotenv.config({ path: '.env' })

import { spawn } from 'child_process'
import path from 'path'

import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import morgan from 'morgan'
import rateLimit from 'express-rate-limit'
import { createClient } from '@supabase/supabase-js'
import { createServer } from 'http'
import { WebSocketServer } from 'ws'
import { parse } from 'url'

// Import routes
import chatRoutes from './routes/chat'
import threatRoutes from './routes/threat'
import authRoutes from './routes/auth'
import pentestRoutes from './routes/pentest'
import attackRoutes from './routes/attack'
import bruteforceRoutes from './routes/bruteforce'
import billingRoutes from './routes/billing'
import adminRoutes from './routes/admin'
import userRoutes from './routes/user'
import authRbacRoutes from './routes/auth-rbac'
import redteamRoutes, { patchRouter } from './routes/redteam'
import agentRoutes from './routes/agent'
import toolsRoutes from './routes/tools'
import advancedPentestRoutes from './routes/advancedPentest'

// Import middleware
import { commandSanitizerMiddleware } from './middleware/commandSanitizer'

// Import and initialize services
import { getAuditLogger } from './services/auditLogger'
import { getPentestJobQueue } from './services/pentestJobQueue'
import { getAIPentestOrchestrator } from './services/aiPentestOrchestrator'
import { getVulnCorrelationEngine } from './services/vulnCorrelationEngine'
import { log } from './utils/logger'

// Initialize security services
log.security('Initializing security services...')
const auditLogger = getAuditLogger()
const jobQueue = getPentestJobQueue()
const aiOrchestrator = getAIPentestOrchestrator()
const vulnCorrelator = getVulnCorrelationEngine()
log.success('Security services initialized')

// Initialize Express app
const app = express()
const PORT = process.env.PORT || 3001

// Create HTTP server
const server = createServer(app)

// Initialize WebSocket server
const wss = new WebSocketServer({ server })

// WebSocket connection handler
wss.on('connection', (ws, req) => {
  const { query } = parse(req.url || '', true)
  const type = query.type as string || 'agent'

  log.http(`WebSocket client connected - Type: ${type}`)

  // Send initial connection confirmation
  ws.send(JSON.stringify({
    type: 'connection',
    message: `Connected to ${type} service`,
    timestamp: new Date().toISOString()
  }))

  // Handle different WebSocket types
  if (type === 'agent' || type === 'jobs') {
    // Agent Mode / Job Queue updates
    log.http('Agent Mode WebSocket connected')

    // Forward job queue events
    jobQueue.on('job-progress', (progress) => {
      if (ws.readyState === ws.OPEN) {
        ws.send(JSON.stringify({
          type: 'job-progress',
          data: progress,
          timestamp: new Date().toISOString()
        }))
      }
    })

    jobQueue.on('job-completed', (jobId, result) => {
      if (ws.readyState === ws.OPEN) {
        ws.send(JSON.stringify({
          type: 'job-completed',
          jobId,
          result,
          timestamp: new Date().toISOString()
        }))
      }
    })

    jobQueue.on('job-failed', (jobId, error) => {
      if (ws.readyState === ws.OPEN) {
        ws.send(JSON.stringify({
          type: 'job-failed',
          jobId,
          error: error.message,
          timestamp: new Date().toISOString()
        }))
      }
    })

    // Forward AI orchestrator events
    aiOrchestrator.on('stage-started', (session, stage) => {
      if (ws.readyState === ws.OPEN) {
        ws.send(JSON.stringify({
          type: 'stage-started',
          sessionId: session.id,
          stage: stage.name,
          timestamp: new Date().toISOString()
        }))
      }
    })

    aiOrchestrator.on('stage-completed', (session, stage) => {
      if (ws.readyState === ws.OPEN) {
        ws.send(JSON.stringify({
          type: 'stage-completed',
          sessionId: session.id,
          stage: stage.name,
          timestamp: new Date().toISOString()
        }))
      }
    })

    ws.on('close', () => {
      console.log('Agent Mode WebSocket client disconnected')
    })
  }

  // Handle errors
  ws.on('error', (error) => {
    console.error('WebSocket error:', error)
  })
})

// Supabase client initialization (optional for development)
const supabaseUrl = process.env.SUPABASE_URL
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY

export const supabase = (supabaseUrl && supabaseServiceKey && supabaseUrl !== 'your_supabase_project_url_here')
  ? createClient(supabaseUrl, supabaseServiceKey)
  : null

if (!supabase) {
  console.warn('⚠️  Supabase not configured - running in development mode without database features')
}

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.',
  },
})

// Middleware
app.use(helmet({
  contentSecurityPolicy: false, // Disable CSP for API
}))

// CORS allowlist using CORS_ORIGIN (comma-separated)
const corsEnvList = (process.env.CORS_ORIGIN || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean)

const devOrigins = ['http://localhost:5173', 'http://localhost:5174']
const allowedOrigins = process.env.NODE_ENV === 'production' ? corsEnvList : devOrigins

app.use(cors({
  origin: (origin, callback) => {
    // Allow non-browser clients or same-origin requests with no origin header
    if (!origin) return callback(null, true)
    if (allowedOrigins.includes(origin)) return callback(null, true)
    return callback(new Error('Not allowed by CORS'))
  },
  credentials: true,
  optionsSuccessStatus: 204,
}))
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'))

// Raw middleware for Stripe webhooks (must be before express.json())
app.use('/api/billing/webhook', express.raw({ type: 'application/json' }))

app.use(express.json({ limit: '10mb' }))
app.use(express.urlencoded({ extended: true }))
app.use('/api/', limiter)

// ============================================================================
// 🔒 COMMAND INJECTION PREVENTION MIDDLEWARE
// Protects tool execution endpoints from command injection attacks
// ============================================================================
app.use('/api/agent/execute', commandSanitizerMiddleware)
app.use('/api/agent/queue-job', commandSanitizerMiddleware)
app.use('/api/tools/', commandSanitizerMiddleware)

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    service: 'COBRA AI Backend',
    version: '1.0.0'
  })
})

// API Routes
app.use('/api/chat', chatRoutes)
app.use('/api/threat', threatRoutes)
app.use('/api/auth', authRoutes)
app.use('/api/auth', authRbacRoutes)  // RBAC authentication routes
app.use('/api/pentest', pentestRoutes)
app.use('/api/attack', attackRoutes)
app.use('/api/bruteforce', bruteforceRoutes)
app.use('/api/billing', billingRoutes)
app.use('/api/admin', adminRoutes)
app.use('/api/user', userRoutes)
app.use('/api/redteam', redteamRoutes)
app.use('/api/agent', agentRoutes)
app.use('/api/tools', toolsRoutes)
app.use('/api/advanced-pentest', advancedPentestRoutes)  // 🔥 Advanced Pentest Features
// Patch endpoints mounted under /api/patch
app.use('/api/patch', patchRouter)

// Global error handler
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Error:', err)
  
  // Don't leak error details in production
  const isDevelopment = process.env.NODE_ENV === 'development'
  
  res.status(err.status || 500).json({
    error: 'Internal Server Error',
    message: isDevelopment ? err.message : 'Something went wrong',
    ...(isDevelopment && { stack: err.stack })
  })
})

// Handle 404
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested resource was not found on this server.',
    path: req.originalUrl
  })
})

// Microservices startup function
const startMicroservices = () => {
  const servicesDir = path.join(__dirname, '..', 'services', 'simple-services')
  
  const services = [
    { name: 'OSINT', file: 'osint-service.js', port: 8001, icon: '🐍' },
    { name: 'Scanner', file: 'scanner-service.js', port: 8002, icon: '🔍' },
    { name: 'Packet', file: 'packet-service.js', port: 8003, icon: '📦' },
    { name: 'Crawler', file: 'crawler-service.js', port: 8004, icon: '🕷️' },
    { name: 'BruteForce', file: 'bruteforce-service.js', port: 8005, icon: '🔓' }
  ]

  services.forEach(service => {
    const servicePath = path.join(servicesDir, service.file)
    console.log(`${service.icon} [STARTUP] Starting ${service.name} service on port ${service.port}`)
    
    const childProcess = spawn('node', [servicePath], {
      stdio: 'pipe',
      cwd: path.join(__dirname, '..')
    })

    childProcess.stdout?.on('data', (data) => {
      const output = data.toString().trim()
      if (output) {
        console.log(`${service.icon} [${service.name.toUpperCase()}] ${output}`)
      }
    })

    childProcess.stderr?.on('data', (data) => {
      const error = data.toString().trim()
      if (error && !error.includes('DeprecationWarning')) {
        console.error(`❌ [${service.name.toUpperCase()}] ${error}`)
      }
    })

    childProcess.on('close', (code) => {
      if (code !== 0) {
        console.error(`❌ [${service.name.toUpperCase()}] Process exited with code ${code}`)
      }
    })

    childProcess.on('error', (error) => {
      console.error(`❌ [${service.name.toUpperCase()}] Failed to start: ${error.message}`)
    })
  })
}

// Start server
server.listen(PORT, async () => {
  console.log(`🐍 COBRA AI Backend running on port ${PORT}`)
  console.log(`📡 API URL: http://localhost:${PORT}`)
  console.log(`🔧 Environment: ${process.env.NODE_ENV || 'development'}`)
  console.log(`🌐 WebSocket server ready for agent mode`)
  
  // Start all microservices
  console.log(`\n🚀 [STARTUP] Initializing microservices...`)
  startMicroservices()
  
  // Wait a moment then check service health
  setTimeout(async () => {
    console.log(`\n🔍 [STARTUP] Checking microservice health...`)
    try {
      const { PolyglotServices } = await import('./services/polyglot')
      const polyglot = new PolyglotServices()
      // The polyglot constructor automatically checks services
    } catch (error) {
      console.log(`⚠️ [STARTUP] Service health check will run when polyglot is imported`)
    }
  }, 5000)
})

// Graceful shutdown
process.on('SIGTERM', async () => {
  log.info('SIGTERM received, shutting down gracefully...')
  
  server.close(() => {
    log.success('Server closed')
    process.exit(0)
  })
})

process.on('SIGINT', async () => {
  log.info('SIGINT received, shutting down gracefully...')
  
  server.close(() => {
    log.success('Server closed')
    process.exit(0)
  })
}) 