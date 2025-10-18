import express from 'express'
import axios from 'axios'
import Joi from 'joi'
import crypto from 'crypto'
import { AISecurityAnalyzer } from '../services/aiSecurityAnalyzer'
import { getSecureApiKey } from '../services/encryption'

const router = express.Router()
const aiAnalyzer = new AISecurityAnalyzer()

// Validation schemas
const iocSchema = Joi.object({
  value: Joi.string().required(),
  type: Joi.string().valid('ip', 'domain', 'url', 'hash').required(),
})

// Helper function to determine IOC type
function detectIOCType(value: string): string {
  // IP address regex
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/
  
  // Domain regex
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/
  
  // URL regex
  const urlRegex = /^https?:\/\//
  
  // Hash regex (MD5, SHA1, SHA256)
  const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/

  if (ipRegex.test(value)) return 'ip'
  if (urlRegex.test(value)) return 'url'
  if (hashRegex.test(value)) return 'hash'
  if (domainRegex.test(value)) return 'domain'
  
  return 'unknown'
}

// Mock data for when API keys are not available
function generateMockThreatData(value: string, type: string) {
  const threats = ['high', 'medium', 'low', 'unknown']
  const randomThreat = threats[Math.floor(Math.random() * threats.length)]
  
  return {
    ioc: value,
    type: type,
    threatLevel: randomThreat,
    reputation: Math.floor(Math.random() * 100),
    sources: ['Mock Data'],
    lastSeen: new Date().toISOString(),
    geolocation: type === 'ip' ? {
      country: 'Unknown',
      city: 'Unknown',
      asn: 'AS0000'
    } : null,
    malwareTypes: randomThreat === 'high' ? ['Trojan', 'Malware'] : [],
    confidence: Math.floor(Math.random() * 100),
    metadata: {
      mock: true,
      message: 'This is mock data. Configure VirusTotal and AbuseIPDB API keys for real threat intelligence.'
    }
  }
}

// AbuseIPDB API integration
async function checkAbuseIPDB(ip: string) {
  const apiKey = getSecureApiKey('ABUSEIPDB_API_KEY')
  if (!apiKey) {
    return null
  }

  try {
    const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      headers: {
        'Key': apiKey,
        'Accept': 'application/json'
      },
      params: {
        ipAddress: ip,
        maxAgeInDays: 90,
        verbose: ''
      }
    })

    const data = response.data.data
    return {
      abuseConfidenceScore: data.abuseConfidencePercentage,
      countryCode: data.countryCode,
      usageType: data.usageType,
      isp: data.isp,
      domain: data.domain,
      isWhitelisted: data.isWhitelisted,
      totalReports: data.totalReports,
      lastReportedAt: data.lastReportedAt
    }
  } catch (error) {
    console.error('AbuseIPDB API Error:', error)
    return null
  }
}

// VirusTotal API v3 integration
async function checkVirusTotal(value: string, type: string) {
  const apiKey = getSecureApiKey('VIRUSTOTAL_API_KEY')
  if (!apiKey) {
    return null
  }

  const vtApiUrl = 'https://www.virustotal.com/api/v3'
  let endpoint = ''

  switch (type) {
    case 'ip':
      endpoint = `${vtApiUrl}/ip_addresses/${value}`
      break
    case 'domain':
      endpoint = `${vtApiUrl}/domains/${value}`
      break
    case 'url':
      const urlId = crypto.createHash('sha256').update(value).digest('hex')
      endpoint = `${vtApiUrl}/urls/${urlId}`
      break
    case 'hash':
      endpoint = `${vtApiUrl}/files/${value}`
      break
    default:
      return null
  }

  try {
    const response = await axios.get(endpoint, {
      headers: {
        'x-apikey': apiKey
      }
    })

    const attributes = response.data.data.attributes
    const stats = attributes.last_analysis_stats
    return {
      stats: {
        harmless: stats.harmless,
        malicious: stats.malicious,
        suspicious: stats.suspicious,
        undetected: stats.undetected,
        timeout: stats.timeout,
      },
      reputation: attributes.reputation,
      lastAnalysisDate: new Date(attributes.last_analysis_date * 1000).toISOString(),
    }
  } catch (error: any) {
    if (error.response && error.response.status === 404) {
      // For URLs, we can try to submit for analysis if not found
      if (type === 'url') {
        return await submitUrlForAnalysis(value);
      }
      return { stats: null, reputation: 0, lastAnalysisDate: null, message: 'Not found in VirusTotal.' }
    }
    console.error('VirusTotal API Error:', error)
    return null
  }
}

async function submitUrlForAnalysis(url: string) {
    if (!process.env.VIRUSTOTAL_API_KEY) {
        return null;
    }

    try {
        await axios.post('https://www.virustotal.com/api/v3/urls', { url: url }, {
            headers: {
                'x-apikey': process.env.VIRUSTOTAL_API_KEY,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });
        return { stats: null as any, reputation: 0, lastAnalysisDate: null as any, message: 'URL submitted for analysis. Please check back later.' };
    } catch (error) {
        console.error('VirusTotal URL submission error:', error);
        return null;
    }
}


function calculateThreat(vtData: any, abuseData: any) {
    let threatLevel = 'unknown';
    let confidence = 0;
    const scores = [];

    if (vtData && vtData.stats) {
        const { malicious, suspicious } = vtData.stats;
        const total = Object.values(vtData.stats).reduce((acc: number, val: any) => acc + (val || 0), 0) as number;
        if (total > 0) {
            const vtScore = ((malicious * 2 + suspicious) / total) * 100;
            scores.push(vtScore);
        }
    }

    if (abuseData) {
        scores.push(abuseData.abuseConfidenceScore);
    }

    if (scores.length > 0) {
        confidence = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
    }

    if (confidence >= 75) {
        threatLevel = 'critical';
    } else if (confidence >= 50) {
        threatLevel = 'high';
    } else if (confidence >= 25) {
        threatLevel = 'medium';
    } else if (confidence > 0) {
        threatLevel = 'low';
    }

    return { threatLevel, confidence };
}


// POST /api/threat/analyze - Analyze IOC
router.post('/analyze', async (req: express.Request, res: express.Response) => {
  try {
    // Validate request
    const { error, value } = iocSchema.validate(req.body)
    if (error) {
      return res.status(400).json({
        error: 'Validation Error',
        message: error.details?.[0]?.message || 'Invalid request data'
      })
    }

    const { value: iocValue, type } = value

    // Auto-detect type if not provided or incorrect
    const detectedType = detectIOCType(iocValue)
    const finalType = detectedType !== 'unknown' ? detectedType : type

    let threatData: any = {
      ioc: iocValue,
      type: finalType,
      analyzedAt: new Date().toISOString(),
      sources: []
    }
    
    let abuseData = null;
    if (finalType === 'ip') {
      abuseData = await checkAbuseIPDB(iocValue)
      if (abuseData) {
        threatData.abuseipdb = abuseData
        threatData.sources.push('AbuseIPDB')
      }
    }

    const vtData = await checkVirusTotal(iocValue, finalType)
    if (vtData) {
      threatData.virustotal = vtData
      threatData.sources.push('VirusTotal')
    }

    if (threatData.sources.length === 0) {
      const mockData = generateMockThreatData(iocValue, finalType)
      threatData = { ...threatData, ...mockData }
    } else {
      const { threatLevel, confidence } = calculateThreat(vtData, abuseData);
      threatData.threatLevel = threatLevel;
      threatData.confidence = confidence;
    }

    // Add AI-powered threat intelligence analysis
    const hasOpenAI = !!getSecureApiKey('OPENAI_API_KEY')
    const hasGemini = !!getSecureApiKey('GEMINI_API_KEY')
    if (threatData.sources.length > 0 && threatData.threatLevel !== 'unknown' && (hasOpenAI || hasGemini)) {
      try {
        const aiAnalysis = await aiAnalyzer.analyzeThreatIntelligence(threatData)
        threatData.aiAnalysis = aiAnalysis
      } catch (error) {
        console.error('AI threat analysis error:', error)
        threatData.aiAnalysis = 'AI analysis could not be performed.'
      }
    }

    return res.json(threatData)

  } catch (error) {
    console.error('Threat Analysis Error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to analyze threat intelligence'
    })
  }
})

// GET /api/threat/sources - Get available threat intel sources
router.get('/sources', (req: express.Request, res: express.Response) => {
  const sources = [
    {
      name: 'VirusTotal',
      available: !!process.env.VIRUSTOTAL_API_KEY,
      types: ['ip', 'domain', 'url', 'hash'],
      description: 'Multi-engine malware scanner and threat intelligence platform'
    },
    {
      name: 'AbuseIPDB',
      available: !!process.env.ABUSEIPDB_API_KEY,
      types: ['ip'],
      description: 'Collaborative IP address blacklist and reporting platform'
    }
  ]

  return res.json({ sources })
})

// POST /api/threat/bulk-analyze - Analyze multiple IOCs
router.post('/bulk-analyze', async (req: express.Request, res: express.Response) => {
  try {
    const { iocs } = req.body

    if (!Array.isArray(iocs) || iocs.length === 0) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'IOCs array is required and must not be empty'
      })
    }

    if (iocs.length > 10) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Maximum 10 IOCs allowed per request'
      })
    }

    const results = []

    for (const ioc of iocs) {
      const detectedType = detectIOCType(ioc)
      const mockData = generateMockThreatData(ioc, detectedType)
      results.push(mockData)
    }

    return res.json({
      analyzed: results.length,
      results: results
    })

  } catch (error) {
    console.error('Bulk Analysis Error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to perform bulk analysis'
    })
  }
})

// POST /api/threat/security-scan - Perform security scan on a website
router.post('/security-scan', async (req: express.Request, res: express.Response) => {
  try {
    const { url } = req.body

    if (!url) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'URL is required'
      })
    }

    // Validate URL format
    let targetUrl: URL
    try {
      targetUrl = new URL(url)
      if (!['http:', 'https:'].includes(targetUrl.protocol)) {
        throw new Error('Invalid protocol')
      }
    } catch (error) {
      return res.status(400).json({
        error: 'Invalid URL',
        message: 'Please provide a valid HTTP or HTTPS URL'
      })
    }

    const metrics = {
      vulnerabilities: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      activeThreats: 0,
      suspiciousActivities: 0,
      securityScore: 100,
      ssl: {
        valid: false,
        grade: 'F'
      },
      headers: {
        score: 0,
        missing: [] as string[]
      }
    }

    const vulnerabilities: any[] = []
    const securityIssues: any[] = []
    let responseHeaders: any = null

    // 1. Check SSL/TLS Certificate
    if (targetUrl.protocol === 'https:') {
      try {
        const sslResponse = await axios.get(targetUrl.toString(), {
          timeout: 10000,
          validateStatus: () => true,
          maxRedirects: 5
        })
        
        metrics.ssl.valid = true
        metrics.ssl.grade = 'A' // Simplified - in production, check cert details
      } catch (error: any) {
        if (error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || 
            error.code === 'CERT_HAS_EXPIRED' ||
            error.code === 'ERR_TLS_CERT_ALTNAME_INVALID') {
          vulnerabilities.push({
            severity: 'high',
            title: 'Invalid SSL Certificate',
            cve: 'SSL-001',
            description: 'The SSL certificate is invalid, expired, or self-signed',
            recommendation: 'Install a valid SSL certificate from a trusted Certificate Authority'
          })
          metrics.vulnerabilities.high++
          metrics.securityScore -= 20
        }
      }
    } else {
      vulnerabilities.push({
        severity: 'medium',
        title: 'No HTTPS Encryption',
        cve: 'HTTPS-001',
        description: 'The website does not use HTTPS encryption',
        recommendation: 'Enable HTTPS with a valid SSL certificate'
      })
      metrics.vulnerabilities.medium++
      metrics.securityScore -= 15
    }

    // 2. Check Security Headers
    try {
      const response = await axios.get(targetUrl.toString(), {
        timeout: 10000,
        validateStatus: () => true,
        maxRedirects: 5
      })
      
      responseHeaders = response.headers
      const headers = response.headers
      const requiredHeaders = {
        'x-frame-options': { 
          name: 'X-Frame-Options',
          recommendation: 'Prevents clickjacking attacks'
        },
        'x-content-type-options': { 
          name: 'X-Content-Type-Options',
          recommendation: 'Prevents MIME type sniffing'
        },
        'strict-transport-security': { 
          name: 'Strict-Transport-Security',
          recommendation: 'Forces HTTPS connections'
        },
        'content-security-policy': { 
          name: 'Content-Security-Policy',
          recommendation: 'Prevents XSS and injection attacks'
        },
        'x-xss-protection': { 
          name: 'X-XSS-Protection',
          recommendation: 'Enables browser XSS protection'
        },
        'referrer-policy': { 
          name: 'Referrer-Policy',
          recommendation: 'Controls referrer information'
        }
      }

      Object.entries(requiredHeaders).forEach(([header, info]) => {
        if (!headers[header]) {
          metrics.headers.missing.push(info.name)
          vulnerabilities.push({
            severity: 'low',
            title: `Missing Security Header: ${info.name}`,
            cve: `HEADER-${header.toUpperCase()}`,
            description: `The ${info.name} header is not set`,
            recommendation: info.recommendation
          })
          metrics.vulnerabilities.low++
          metrics.securityScore -= 5
        }
      })

      metrics.headers.score = 100 - (metrics.headers.missing.length * 15)

    } catch (error) {
      console.error('Failed to check headers:', error)
    }

    // 3. Check for common vulnerabilities using domain/IP analysis
    const domain = targetUrl.hostname
    
    // Check if domain is in threat databases
    const domainCheck = await checkVirusTotal(domain, 'domain')
    if (domainCheck && 'stats' in domainCheck && domainCheck.stats && domainCheck.stats.malicious > 0) {
      metrics.activeThreats++
      vulnerabilities.push({
        severity: 'critical',
        title: 'Domain Flagged as Malicious',
        cve: 'THREAT-001',
        description: `Domain has ${domainCheck.stats.malicious} malicious detections`,
        recommendation: 'Investigate and clean any malware or malicious content'
      })
      metrics.vulnerabilities.critical++
      metrics.securityScore -= 30
    }

    // 4. Check for open directories and common vulnerabilities
    const commonPaths = [
      '/.git/',
      '/.env',
      '/wp-admin/',
      '/admin/',
      '/.htaccess',
      '/config.php',
      '/phpinfo.php',
      '/.DS_Store',
      '/robots.txt'
    ]

    for (const path of commonPaths) {
      try {
        const checkResponse = await axios.get(targetUrl.origin + path, {
          timeout: 5000,
          validateStatus: (status) => status < 500
        })
        
        if (checkResponse.status === 200) {
          if (['.git', '.env', '.htaccess', 'config.php', 'phpinfo.php'].some(sensitive => path.includes(sensitive))) {
            vulnerabilities.push({
              severity: 'high',
              title: `Exposed Sensitive File: ${path}`,
              cve: 'EXPOSURE-001',
              description: `Sensitive file or directory is publicly accessible at ${path}`,
              recommendation: 'Remove or restrict access to sensitive files'
            })
            metrics.vulnerabilities.high++
            metrics.securityScore -= 20
          }
        }
      } catch (error) {
        // Path not accessible, which is good
      }
    }

    // 5. AI-powered security analysis (if AI service is available)
    const hasOpenAIKey = !!getSecureApiKey('OPENAI_API_KEY')
    const hasGeminiKey = !!getSecureApiKey('GEMINI_API_KEY')
    if (hasOpenAIKey || hasGeminiKey) {
      try {
        const aiInsights = await aiAnalyzer.analyzeSecurityPosture({
          url,
          vulnerabilities,
          metrics,
          headers: responseHeaders
        })
        
        // Add AI insights to vulnerabilities
        aiInsights.forEach(insight => {
          vulnerabilities.push({
            severity: insight.severity,
            title: insight.finding,
            cve: `AI-${insight.category.replace(/\s+/g, '-').toUpperCase()}`,
            description: insight.finding,
            recommendation: insight.recommendation,
            confidence: insight.confidence,
            source: 'AI Analysis'
          })
          
          // Update metrics based on AI findings
          if (insight.severity in metrics.vulnerabilities) {
            metrics.vulnerabilities[insight.severity]++
          }
        })
        
        securityIssues.push({
          type: 'ai_analysis',
          message: `AI security analysis completed - found ${aiInsights.length} additional insights`
        })
      } catch (error) {
        console.error('AI analysis error:', error)
      }
    }

    // Calculate final security score
    metrics.securityScore = Math.max(0, metrics.securityScore)

    return res.json({
      url,
      scanTime: new Date().toISOString(),
      metrics,
      vulnerabilities,
      securityIssues,
      recommendations: generateRecommendations(metrics, vulnerabilities)
    })

  } catch (error) {
    console.error('Security Scan Error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to perform security scan'
    })
  }
})

// Helper function to generate recommendations
function generateRecommendations(metrics: any, vulnerabilities: any[]) {
  const recommendations = []
  
  if (!metrics.ssl.valid) {
    recommendations.push({
      priority: 'high',
      action: 'Implement HTTPS with a valid SSL certificate',
      impact: 'Protects data in transit and improves SEO'
    })
  }
  
  if (metrics.headers.missing.length > 0) {
    recommendations.push({
      priority: 'medium',
      action: `Add missing security headers: ${metrics.headers.missing.join(', ')}`,
      impact: 'Prevents common web vulnerabilities'
    })
  }
  
  if (metrics.vulnerabilities.critical > 0 || metrics.vulnerabilities.high > 0) {
    recommendations.push({
      priority: 'critical',
      action: 'Address critical and high severity vulnerabilities immediately',
      impact: 'Prevents potential security breaches'
    })
  }
  
  return recommendations
}

// POST /api/threat/anomalies - Check for anomalies
router.post('/anomalies', async (req: express.Request, res: express.Response) => {
  try {
    const { url } = req.body

    if (!url) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'URL is required'
      })
    }

    // Validate URL
    let targetUrl: URL
    try {
      targetUrl = new URL(url)
    } catch (error) {
      return res.status(400).json({
        error: 'Invalid URL',
        message: 'Please provide a valid URL'
      })
    }

    const anomalies = []
    
    // 1. Check for suspicious patterns in the URL itself
    const suspiciousPatterns = [
      { pattern: /[<>'"]/g, type: 'xss_attempt', description: 'Potential XSS characters in URL' },
      { pattern: /(\.\.|\/\/|\\\\)/g, type: 'path_traversal', description: 'Potential path traversal attempt' },
      { pattern: /(union|select|insert|update|delete|drop)\s/gi, type: 'sql_injection', description: 'Potential SQL injection keywords' },
      { pattern: /\.(php|asp|jsp|cgi)\?/i, type: 'script_probe', description: 'Direct script access attempt' }
    ]

    suspiciousPatterns.forEach(({ pattern, type, description }) => {
      if (pattern.test(targetUrl.toString())) {
        anomalies.push({
          type,
          description,
          severity: 'high',
          timestamp: new Date().toISOString(),
          source: targetUrl.hostname
        })
      }
    })

    // 2. Check DNS and domain reputation
    try {
      // Check if domain is newly registered (common for phishing)
      const domainAge = await checkDomainAge(targetUrl.hostname)
      if (domainAge && domainAge < 30) { // Less than 30 days old
        anomalies.push({
          type: 'new_domain',
          description: `Domain is only ${domainAge} days old - commonly used in phishing attacks`,
          severity: 'medium',
          timestamp: new Date().toISOString(),
          source: targetUrl.hostname
        })
      }
    } catch (error) {
      console.error('Domain check failed:', error)
    }

    // 3. Check for known malicious patterns
    const maliciousIndicators = [
      { indicator: 'phishing', check: /phish|p4yp4l|amaz0n|g00gle/i },
      { indicator: 'malware_distribution', check: /download.*\.(exe|scr|vbs|pif|cmd|bat|com)$/i },
      { indicator: 'crypto_mining', check: /coinhive|crypto-loot|coin-hive|miner/i }
    ]

    maliciousIndicators.forEach(({ indicator, check }) => {
      if (check.test(targetUrl.toString())) {
        anomalies.push({
          type: indicator,
          description: `URL contains ${indicator.replace('_', ' ')} indicators`,
          severity: 'critical',
          timestamp: new Date().toISOString(),
          source: targetUrl.hostname
        })
      }
    })

    // 4. Check response behavior
    try {
      const response = await axios.get(targetUrl.toString(), {
        timeout: 10000,
        maxRedirects: 10,
        validateStatus: () => true
      })

      // Check for suspicious redirects
      if (response.request._redirectable && response.request._redirectable._redirectCount > 3) {
        anomalies.push({
          type: 'excessive_redirects',
          description: `Excessive redirects detected (${response.request._redirectable._redirectCount})`,
          severity: 'medium',
          timestamp: new Date().toISOString(),
          source: targetUrl.hostname
        })
      }

      // Check for suspicious response sizes
      const contentLength = parseInt(response.headers['content-length'] || '0')
      if (contentLength > 10 * 1024 * 1024) { // Over 10MB
        anomalies.push({
          type: 'large_response',
          description: 'Unusually large response size detected',
          severity: 'low',
          timestamp: new Date().toISOString(),
          source: targetUrl.hostname
        })
      }

      // Check for suspicious headers
      if (response.headers['server'] && response.headers['server'].match(/nginx\/1\.[0-9]\.[0-9]/)) {
        // Old nginx versions might have vulnerabilities
        anomalies.push({
          type: 'outdated_server',
          description: 'Potentially outdated server software detected',
          severity: 'low',
          timestamp: new Date().toISOString(),
          source: targetUrl.hostname
        })
      }
    } catch (error: any) {
      if (error.code === 'ENOTFOUND') {
        anomalies.push({
          type: 'dns_failure',
          description: 'Domain does not resolve - possible typosquatting',
          severity: 'high',
          timestamp: new Date().toISOString(),
          source: targetUrl.hostname
        })
      }
    }

    // 5. AI-powered anomaly analysis
    const hasOpenAIForAnomaly = !!getSecureApiKey('OPENAI_API_KEY')
    const hasGeminiForAnomaly = !!getSecureApiKey('GEMINI_API_KEY')
    if (anomalies.length > 0 && (hasOpenAIForAnomaly || hasGeminiForAnomaly)) {
      // Add context about detected anomalies
      const aiContext = {
        url: targetUrl.toString(),
        anomalyCount: anomalies.length,
        severities: anomalies.map(a => a.severity),
        types: anomalies.map(a => a.type)
      }
      
      // In production, you would call AI here for deeper analysis
      console.log('AI analysis context:', aiContext)
    }

    return res.json({
      url,
      checkTime: new Date().toISOString(),
      anomalies,
      summary: {
        total: anomalies.length,
        critical: anomalies.filter(a => a.severity === 'critical').length,
        high: anomalies.filter(a => a.severity === 'high').length,
        medium: anomalies.filter(a => a.severity === 'medium').length,
        low: anomalies.filter(a => a.severity === 'low').length
      }
    })

  } catch (error) {
    console.error('Anomaly Check Error:', error)
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to check for anomalies'
    })
  }
})

// Helper function to check domain age (simplified)
async function checkDomainAge(domain: string): Promise<number | null> {
  // In production, you would use WHOIS API or similar
  // For now, return null to indicate unknown
  return null
}

export default router 