import React, { useState, useEffect } from 'react'
import { FileText, Download, Share2, Brain, Target, AlertTriangle, CheckCircle, Clock, Users, Database } from 'lucide-react'

interface VulnerabilityEntry {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  cvss: number
  cve?: string
  description: string
  evidence: string[]
  recommendation: string
  affectedHosts: string[]
  category: string
  status: 'open' | 'confirmed' | 'fixed' | 'false_positive'
  gptSummary?: string
}

interface ReportSection {
  id: string
  title: string
  content: string
  gptGenerated: boolean
  editable: boolean
  order: number
}

interface ExecutiveSummary {
  overallRisk: 'low' | 'medium' | 'high' | 'critical'
  keyFindings: string[]
  businessImpact: string
  recommendedActions: string[]
  timeline: string
  budgetEstimate?: string
}

interface TechnicalMetrics {
  hostsScanned: number
  vulnerabilitiesFound: number
  criticalVulns: number
  highVulns: number
  mediumVulns: number
  lowVulns: number
  remediated: number
  falsePositives: number
}

interface DradisReportPanelProps {
  onToolExecute: (toolName: string, params: any) => Promise<any>
}

const DradisReportPanel: React.FC<DradisReportPanelProps> = ({ onToolExecute }) => {
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityEntry[]>([])
  const [reportSections, setReportSections] = useState<ReportSection[]>([])
  const [executiveSummary, setExecutiveSummary] = useState<ExecutiveSummary | null>(null)
  const [metrics, setMetrics] = useState<TechnicalMetrics | null>(null)
  const [viewMode, setViewMode] = useState<'vulnerabilities' | 'report' | 'executive' | 'metrics'>('vulnerabilities')
  const [selectedVuln, setSelectedVuln] = useState<VulnerabilityEntry | null>(null)
  const [isGenerating, setIsGenerating] = useState(false)
  const [reportTitle, setReportTitle] = useState('Penetration Testing Report')
  const [clientName, setClientName] = useState('')
  const [testDate, setTestDate] = useState(new Date().toISOString().split('T')[0])

  const loadVulnerabilities = async () => {
    try {
      const result = await onToolExecute('dradis_load_data', {
        sources: ['nmap', 'nessus', 'burp', 'manual'],
        workspace: 'current'
      })

      if (result.vulnerabilities) {
        setVulnerabilities(result.vulnerabilities)
        calculateMetrics(result.vulnerabilities)
      }
    } catch (error) {
      console.error('Failed to load vulnerabilities:', error)
    }
  }

  const generateExecutiveSummary = async () => {
    setIsGenerating(true)
    try {
      const result = await onToolExecute('dradis_generate_executive', {
        vulnerabilities,
        clientName,
        testDate,
        includeBusinessImpact: true
      })

      if (result.summary) {
        setExecutiveSummary(result.summary)
      }
    } catch (error) {
      console.error('Executive summary generation failed:', error)
    } finally {
      setIsGenerating(false)
    }
  }

  const generateTechnicalReport = async () => {
    setIsGenerating(true)
    try {
      const result = await onToolExecute('dradis_generate_technical', {
        vulnerabilities,
        includeEvidence: true,
        includeRemediation: true,
        gptEnhanced: true
      })

      if (result.sections) {
        setReportSections(result.sections)
      }
    } catch (error) {
      console.error('Technical report generation failed:', error)
    } finally {
      setIsGenerating(false)
    }
  }

  const enhanceVulnWithGPT = async (vuln: VulnerabilityEntry) => {
    try {
      const result = await onToolExecute('dradis_gpt_enhance', {
        vulnerability: {
          title: vuln.title,
          description: vuln.description,
          severity: vuln.severity,
          category: vuln.category
        }
      })

      if (result.enhancement) {
        setVulnerabilities(prev => 
          prev.map(v => 
            v.id === vuln.id 
              ? { 
                  ...v, 
                  gptSummary: result.enhancement.summary,
                  recommendation: result.enhancement.recommendation || v.recommendation,
                  description: result.enhancement.description || v.description
                }
              : v
          )
        )
      }
    } catch (error) {
      console.error('GPT enhancement failed:', error)
    }
  }

  const calculateMetrics = (vulns: VulnerabilityEntry[]) => {
    const metrics: TechnicalMetrics = {
      hostsScanned: new Set(vulns.flatMap(v => v.affectedHosts)).size,
      vulnerabilitiesFound: vulns.length,
      criticalVulns: vulns.filter(v => v.severity === 'critical').length,
      highVulns: vulns.filter(v => v.severity === 'high').length,
      mediumVulns: vulns.filter(v => v.severity === 'medium').length,
      lowVulns: vulns.filter(v => v.severity === 'low').length,
      remediated: vulns.filter(v => v.status === 'fixed').length,
      falsePositives: vulns.filter(v => v.status === 'false_positive').length
    }
    setMetrics(metrics)
  }

  const exportReport = async (format: 'pdf' | 'docx' | 'html') => {
    try {
      const result = await onToolExecute('dradis_export', {
        format,
        includeExecutive: true,
        includeTechnical: true,
        includeMetrics: true,
        vulnerabilities,
        reportSections,
        executiveSummary,
        metadata: {
          title: reportTitle,
          client: clientName,
          date: testDate
        }
      })

      if (result.downloadUrl) {
        // Trigger download
        window.open(result.downloadUrl, '_blank')
      }
    } catch (error) {
      console.error('Export failed:', error)
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-600/20'
      case 'high': return 'text-red-500 bg-red-500/20'
      case 'medium': return 'text-yellow-500 bg-yellow-500/20'
      case 'low': return 'text-green-500 bg-green-500/20'
      case 'info': return 'text-blue-500 bg-blue-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'text-red-500 bg-red-500/20'
      case 'confirmed': return 'text-orange-500 bg-orange-500/20'
      case 'fixed': return 'text-green-500 bg-green-500/20'
      case 'false_positive': return 'text-gray-500 bg-gray-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'critical': return 'text-red-600 bg-red-600/20'
      case 'high': return 'text-red-500 bg-red-500/20'
      case 'medium': return 'text-yellow-500 bg-yellow-500/20'
      case 'low': return 'text-green-500 bg-green-500/20'
      default: return 'text-gray-500 bg-gray-500/20'
    }
  }

  useEffect(() => {
    // Initialize with demo data
    setVulnerabilities([
      {
        id: '1',
        title: 'SQL Injection in Login Form',
        severity: 'high',
        cvss: 8.2,
        cve: 'CVE-2023-12345',
        description: 'The login form is vulnerable to SQL injection attacks.',
        evidence: ['Parameter: username', 'Payload: \' OR 1=1--'],
        recommendation: 'Use parameterized queries and input validation.',
        affectedHosts: ['192.168.1.100', '192.168.1.101'],
        category: 'Web Application',
        status: 'open'
      },
      {
        id: '2',
        title: 'Outdated SSL/TLS Configuration',
        severity: 'medium',
        cvss: 5.3,
        description: 'Server supports weak SSL/TLS protocols.',
        evidence: ['SSLv3 enabled', 'Weak cipher suites'],
        recommendation: 'Disable SSLv3 and configure strong cipher suites.',
        affectedHosts: ['192.168.1.100'],
        category: 'Network',
        status: 'open'
      }
    ])

    setReportSections([
      {
        id: '1',
        title: 'Executive Summary',
        content: 'This report presents the findings of a comprehensive penetration test...',
        gptGenerated: true,
        editable: true,
        order: 1
      },
      {
        id: '2',
        title: 'Methodology',
        content: 'The testing methodology followed industry standards...',
        gptGenerated: false,
        editable: true,
        order: 2
      }
    ])

    calculateMetrics([
      {
        id: '1',
        title: 'SQL Injection in Login Form',
        severity: 'high',
        cvss: 8.2,
        cve: 'CVE-2023-12345',
        description: 'The login form is vulnerable to SQL injection attacks.',
        evidence: ['Parameter: username', 'Payload: \' OR 1=1--'],
        recommendation: 'Use parameterized queries and input validation.',
        affectedHosts: ['192.168.1.100', '192.168.1.101'],
        category: 'Web Application',
        status: 'open'
      }
    ])
  }, [])

  return (
    <div className="space-y-6">
      {/* Dradis Header */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
        <h3 className="text-xl font-bold text-terminal-text mb-4 flex items-center">
          <FileText className="w-6 h-6 mr-3 text-purple-500" />
          Dradis Report Generator
          <span className="ml-3 px-3 py-1 bg-purple-500 text-white text-sm rounded-full">AI-POWERED</span>
        </h3>
        <p className="text-terminal-muted">
          Professional penetration testing reports with GPT-enhanced content and automated formatting
        </p>

        {/* Report Configuration */}
        <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
          <input
            type="text"
            value={reportTitle}
            onChange={(e) => setReportTitle(e.target.value)}
            placeholder="Report Title"
            className="bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
          />
          <input
            type="text"
            value={clientName}
            onChange={(e) => setClientName(e.target.value)}
            placeholder="Client Name"
            className="bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
          />
          <input
            type="date"
            value={testDate}
            onChange={(e) => setTestDate(e.target.value)}
            className="bg-terminal-bg border border-terminal-border rounded px-3 py-2 text-terminal-text"
          />
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex space-x-2">
        <button
          onClick={() => setViewMode('vulnerabilities')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'vulnerabilities' 
              ? 'bg-purple-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <AlertTriangle className="w-4 h-4" />
          <span>Vulnerabilities ({vulnerabilities.length})</span>
        </button>
        <button
          onClick={() => setViewMode('executive')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'executive' 
              ? 'bg-purple-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Users className="w-4 h-4" />
          <span>Executive Summary</span>
        </button>
        <button
          onClick={() => setViewMode('report')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'report' 
              ? 'bg-purple-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <FileText className="w-4 h-4" />
          <span>Technical Report</span>
        </button>
        <button
          onClick={() => setViewMode('metrics')}
          className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
            viewMode === 'metrics' 
              ? 'bg-purple-600 text-white' 
              : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
          }`}
        >
          <Database className="w-4 h-4" />
          <span>Metrics</span>
        </button>
      </div>

      {/* Vulnerabilities Tab */}
      {viewMode === 'vulnerabilities' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h4 className="text-lg font-semibold text-terminal-text">Vulnerability Database</h4>
            <button
              onClick={loadVulnerabilities}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded"
            >
              Load from Tools
            </button>
          </div>

          <div className="space-y-3">
            {vulnerabilities.map((vuln) => (
              <div
                key={vuln.id}
                className={`border rounded-lg p-4 cursor-pointer transition-all ${
                  selectedVuln?.id === vuln.id 
                    ? 'border-purple-500 bg-purple-500/5' 
                    : 'border-terminal-border hover:border-purple-500/50'
                }`}
                onClick={() => setSelectedVuln(vuln)}
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-3">
                    <span className="font-medium text-terminal-text">{vuln.title}</span>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(vuln.severity)}`}>
                      {vuln.severity.toUpperCase()}
                    </span>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(vuln.status)}`}>
                      {vuln.status.replace('_', ' ').toUpperCase()}
                    </span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="text-terminal-muted text-sm">CVSS: {vuln.cvss}</span>
                    {vuln.cve && (
                      <span className="text-blue-400 text-sm">{vuln.cve}</span>
                    )}
                  </div>
                </div>

                <p className="text-terminal-muted text-sm mb-3">{vuln.description}</p>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                  <div>
                    <span className="text-terminal-muted">Category:</span>
                    <span className="ml-2 text-terminal-text">{vuln.category}</span>
                  </div>
                  <div>
                    <span className="text-terminal-muted">Affected Hosts:</span>
                    <span className="ml-2 text-terminal-text">{vuln.affectedHosts.length}</span>
                  </div>
                  <div>
                    <span className="text-terminal-muted">Evidence:</span>
                    <span className="ml-2 text-terminal-text">{vuln.evidence.length} items</span>
                  </div>
                </div>

                {vuln.gptSummary && (
                  <div className="mt-3 p-3 bg-terminal-bg border border-terminal-border rounded">
                    <span className="text-blue-400 font-medium">AI Summary: </span>
                    <span className="text-terminal-muted text-sm">{vuln.gptSummary}</span>
                  </div>
                )}

                <div className="mt-3 flex space-x-2">
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      enhanceVulnWithGPT(vuln)
                    }}
                    className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded"
                  >
                    <Brain className="w-3 h-3 inline mr-1" />
                    AI Enhance
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Executive Summary Tab */}
      {viewMode === 'executive' && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h4 className="text-lg font-semibold text-terminal-text">Executive Summary</h4>
            <button
              onClick={generateExecutiveSummary}
              disabled={isGenerating}
              className="px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 text-white rounded flex items-center space-x-2"
            >
              {isGenerating ? (
                <>
                  <Brain className="w-4 h-4 animate-spin" />
                  <span>Generating...</span>
                </>
              ) : (
                <>
                  <Brain className="w-4 h-4" />
                  <span>Generate with AI</span>
                </>
              )}
            </button>
          </div>

          {executiveSummary ? (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-terminal-bg border border-terminal-border rounded p-4">
                  <h5 className="font-medium text-terminal-text mb-2">Overall Risk Assessment</h5>
                  <div className="flex items-center space-x-3">
                    <div className={`text-2xl font-bold ${
                      executiveSummary.overallRisk === 'critical' ? 'text-red-600' :
                      executiveSummary.overallRisk === 'high' ? 'text-red-500' :
                      executiveSummary.overallRisk === 'medium' ? 'text-yellow-500' :
                      'text-green-500'
                    }`}>
                      {executiveSummary.overallRisk.toUpperCase()}
                    </div>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getRiskColor(executiveSummary.overallRisk)}`}>
                      RISK LEVEL
                    </span>
                  </div>
                </div>

                <div className="bg-terminal-bg border border-terminal-border rounded p-4">
                  <h5 className="font-medium text-terminal-text mb-2">Remediation Timeline</h5>
                  <div className="flex items-center space-x-2">
                    <Clock className="w-5 h-5 text-blue-500" />
                    <span className="text-terminal-text">{executiveSummary.timeline}</span>
                  </div>
                  {executiveSummary.budgetEstimate && (
                    <div className="text-terminal-muted text-sm mt-1">
                      Estimated budget: {executiveSummary.budgetEstimate}
                    </div>
                  )}
                </div>
              </div>

              <div>
                <h5 className="font-medium text-terminal-text mb-3">Business Impact</h5>
                <div className="bg-terminal-bg border border-terminal-border rounded p-4">
                  <p className="text-terminal-muted">{executiveSummary.businessImpact}</p>
                </div>
              </div>

              <div>
                <h5 className="font-medium text-terminal-text mb-3">Key Findings</h5>
                <ul className="space-y-2">
                  {executiveSummary.keyFindings.map((finding, index) => (
                    <li key={index} className="flex items-start space-x-2">
                      <AlertTriangle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
                      <span className="text-terminal-muted text-sm">{finding}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <h5 className="font-medium text-terminal-text mb-3">Recommended Actions</h5>
                <ul className="space-y-2">
                  {executiveSummary.recommendedActions.map((action, index) => (
                    <li key={index} className="flex items-start space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-500 mt-0.5 flex-shrink-0" />
                      <span className="text-terminal-muted text-sm">{action}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          ) : (
            <div className="text-center py-8">
              <Brain className="w-12 h-12 text-gray-500 mx-auto mb-4" />
              <p className="text-terminal-muted">No executive summary generated yet.</p>
              <p className="text-terminal-muted text-sm">Click "Generate with AI" to create a professional summary.</p>
            </div>
          )}
        </div>
      )}

      {/* Metrics Tab */}
      {viewMode === 'metrics' && metrics && (
        <div className="bg-terminal-card border border-terminal-border rounded-lg p-6">
          <h4 className="text-lg font-semibold text-terminal-text mb-4">Testing Metrics</h4>
          
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-terminal-bg border border-terminal-border rounded p-3 text-center">
              <div className="text-2xl font-bold text-terminal-text">{metrics.hostsScanned}</div>
              <div className="text-terminal-muted text-sm">Hosts Scanned</div>
            </div>
            <div className="bg-terminal-bg border border-terminal-border rounded p-3 text-center">
              <div className="text-2xl font-bold text-purple-500">{metrics.vulnerabilitiesFound}</div>
              <div className="text-terminal-muted text-sm">Total Vulnerabilities</div>
            </div>
            <div className="bg-terminal-bg border border-terminal-border rounded p-3 text-center">
              <div className="text-2xl font-bold text-green-500">{metrics.remediated}</div>
              <div className="text-terminal-muted text-sm">Remediated</div>
            </div>
            <div className="bg-terminal-bg border border-terminal-border rounded p-3 text-center">
              <div className="text-2xl font-bold text-gray-500">{metrics.falsePositives}</div>
              <div className="text-terminal-muted text-sm">False Positives</div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h5 className="font-medium text-terminal-text mb-3">Vulnerability Breakdown</h5>
              <div className="space-y-2">
                <div className="flex justify-between items-center p-2 bg-terminal-bg border border-terminal-border rounded">
                  <span className="text-red-600 font-medium">Critical</span>
                  <span className="text-terminal-text">{metrics.criticalVulns}</span>
                </div>
                <div className="flex justify-between items-center p-2 bg-terminal-bg border border-terminal-border rounded">
                  <span className="text-red-500 font-medium">High</span>
                  <span className="text-terminal-text">{metrics.highVulns}</span>
                </div>
                <div className="flex justify-between items-center p-2 bg-terminal-bg border border-terminal-border rounded">
                  <span className="text-yellow-500 font-medium">Medium</span>
                  <span className="text-terminal-text">{metrics.mediumVulns}</span>
                </div>
                <div className="flex justify-between items-center p-2 bg-terminal-bg border border-terminal-border rounded">
                  <span className="text-green-500 font-medium">Low</span>
                  <span className="text-terminal-text">{metrics.lowVulns}</span>
                </div>
              </div>
            </div>

            <div>
              <h5 className="font-medium text-terminal-text mb-3">Risk Distribution</h5>
              <div className="bg-terminal-bg border border-terminal-border rounded p-4">
                <p className="text-terminal-muted text-sm">
                  {metrics.criticalVulns + metrics.highVulns > 0 
                    ? 'High risk environment requiring immediate attention'
                    : metrics.mediumVulns > 0 
                    ? 'Medium risk environment with manageable issues'
                    : 'Low risk environment with minor findings'
                  }
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Export Options */}
      <div className="bg-terminal-card border border-terminal-border rounded-lg p-4">
        <div className="flex items-center justify-between">
          <span className="text-terminal-text font-medium">Export Report</span>
          <div className="flex space-x-2">
            <button 
              onClick={() => exportReport('pdf')}
              className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-sm rounded flex items-center space-x-1"
            >
              <Download className="w-3 h-3" />
              <span>PDF</span>
            </button>
            <button 
              onClick={() => exportReport('docx')}
              className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded flex items-center space-x-1"
            >
              <Download className="w-3 h-3" />
              <span>DOCX</span>
            </button>
            <button 
              onClick={() => exportReport('html')}
              className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded flex items-center space-x-1"
            >
              <Download className="w-3 h-3" />
              <span>HTML</span>
            </button>
            <button className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded flex items-center space-x-1">
              <Share2 className="w-3 h-3" />
              <span>Share</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export default DradisReportPanel