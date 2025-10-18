import React from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowLeft, Shield, AlertTriangle, Users, Lock, Target } from 'lucide-react'
import zypheronLogo from '../../../public/Zypheron1.jpg'
import SEOOptimizer from '../../components/SEOOptimizer'

const TermsOfUse: React.FC = () => {
  const navigate = useNavigate()

  const touConfig = {
    title: "Terms of Use - Cobra AI",
    description: "Terms of Use for Cobra AI - AI-powered cybersecurity platform. Review usage guidelines, restrictions, and best practices for security testing.",
    keywords: "terms of use, usage guidelines, cobra ai, cybersecurity, ethical hacking, penetration testing guidelines",
    canonicalUrl: "https://cobraai.dev/terms-of-use",
    ogType: "website",
    ogImage: "/Zypheron1.jpg"
  }

  return (
    <>
      <SEOOptimizer {...touConfig} />
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-800 text-white">
        {/* Header */}
        <div className="bg-gray-800 border-b border-gray-700 shadow-lg">
          <div className="max-w-6xl mx-auto px-6 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <button
                  onClick={() => navigate(-1)}
                  className="p-2 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors min-h-[44px] min-w-[44px] flex items-center justify-center"
                  aria-label="Go back"
                >
                  <ArrowLeft className="w-5 h-5" />
                </button>
                <div className="flex items-center space-x-3">
                  <img 
                    src={zypheronLogo} 
                    alt="Zypheron Logo" 
                    className="w-8 h-8 object-contain"
                    onError={(e) => {
                      e.currentTarget.src = "/ZypheronX.jpg";
                    }}
                  />
                  <div>
                    <h1 className="text-xl font-bold text-red-500 font-orbitron">Terms of Use</h1>
                    <p className="text-sm text-gray-400">Usage Guidelines</p>
                  </div>
                </div>
              </div>
              <div className="text-sm text-gray-400">
                Last Updated: {new Date().toLocaleDateString()}
              </div>
            </div>
          </div>
        </div>

        {/* Content */}
        <div className="max-w-4xl mx-auto px-6 py-8">
          {/* Important Notice */}
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 mb-8">
            <div className="flex items-start space-x-3">
              <AlertTriangle className="w-6 h-6 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <h2 className="text-lg font-semibold text-red-400 mb-2">Ethical Use Required</h2>
                <p className="text-red-200 text-sm">
                  Cobra AI's security tools are powerful and must be used ethically and legally. 
                  You are responsible for ensuring you have proper authorization before testing any systems.
                </p>
              </div>
            </div>
          </div>

          <div className="prose prose-invert max-w-none">
            {/* Section 1 */}
            <section className="mb-8">
              <div className="flex items-center space-x-3 mb-4">
                <Target className="w-6 h-6 text-red-400" />
                <h2 className="text-2xl font-bold text-white">1. Authorized Testing Only</h2>
              </div>
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <p className="text-gray-300 mb-4">
                  Cobra AI's security tools may only be used on systems where you have explicit authorization:
                </p>
                <ul className="list-disc list-inside text-gray-300 space-y-2 mb-4">
                  <li><strong>Your own systems:</strong> Systems you own, operate, or manage</li>
                  <li><strong>Contracted testing:</strong> Systems where you have a signed penetration testing agreement</li>
                  <li><strong>Bug bounty programs:</strong> Systems with published bug bounty programs that permit testing</li>
                  <li><strong>Educational environments:</strong> Dedicated lab environments designed for security testing</li>
                </ul>
                <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4">
                  <p className="text-amber-300 font-semibold">
                    ⚠️ NEVER use these tools against systems you do not own or lack explicit permission to test. 
                    This may constitute illegal activity under computer crime laws.
                  </p>
                </div>
              </div>
            </section>

            {/* Section 2 */}
            <section className="mb-8">
              <div className="flex items-center space-x-3 mb-4">
                <Shield className="w-6 h-6 text-red-400" />
                <h2 className="text-2xl font-bold text-white">2. Security Tool Guidelines</h2>
              </div>
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <h3 className="text-lg font-semibold text-white mb-3">Penetration Testing</h3>
                <ul className="list-disc list-inside text-gray-300 space-y-2 mb-4">
                  <li>Always obtain written authorization before conducting penetration tests</li>
                  <li>Define clear scope and limitations for testing activities</li>
                  <li>Avoid causing disruption or damage to target systems</li>
                  <li>Report findings responsibly to system owners</li>
                  <li>Do not access, modify, or exfiltrate sensitive data unnecessarily</li>
                </ul>

                <h3 className="text-lg font-semibold text-white mb-3">Vulnerability Scanning</h3>
                <ul className="list-disc list-inside text-gray-300 space-y-2 mb-4">
                  <li>Limit scan intensity to avoid system overload</li>
                  <li>Schedule scans during appropriate maintenance windows</li>
                  <li>Respect rate limits and system capacity</li>
                  <li>Document and report discovered vulnerabilities appropriately</li>
                </ul>

                <h3 className="text-lg font-semibold text-white mb-3">OSINT Gathering</h3>
                <ul className="list-disc list-inside text-gray-300 space-y-2">
                  <li>Use only publicly available information sources</li>
                  <li>Respect website terms of service and robots.txt</li>
                  <li>Avoid overwhelming servers with excessive requests</li>
                  <li>Protect personal privacy of individuals in gathered data</li>
                </ul>
              </div>
            </section>

            {/* Section 3 */}
            <section className="mb-8">
              <div className="flex items-center space-x-3 mb-4">
                <Lock className="w-6 h-6 text-red-400" />
                <h2 className="text-2xl font-bold text-white">3. Prohibited Activities</h2>
              </div>
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <p className="text-gray-300 mb-4">
                  The following activities are strictly prohibited when using Cobra AI:
                </p>
                <div className="grid md:grid-cols-2 gap-6">
                  <div>
                    <h4 className="text-lg font-semibold text-red-400 mb-3">Illegal Activities</h4>
                    <ul className="list-disc list-inside text-gray-300 space-y-1 text-sm">
                      <li>Unauthorized access to computer systems</li>
                      <li>Data theft or exfiltration</li>
                      <li>System disruption or denial of service</li>
                      <li>Malware distribution</li>
                      <li>Identity theft or fraud</li>
                      <li>Violation of computer crime laws</li>
                    </ul>
                  </div>
                  <div>
                    <h4 className="text-lg font-semibold text-red-400 mb-3">Unethical Activities</h4>
                    <ul className="list-disc list-inside text-gray-300 space-y-1 text-sm">
                      <li>Testing without proper authorization</li>
                      <li>Exceeding agreed-upon testing scope</li>
                      <li>Causing unnecessary system damage</li>
                      <li>Accessing personal or sensitive data</li>
                      <li>Selling or sharing discovered vulnerabilities</li>
                      <li>Using findings for competitive advantage</li>
                    </ul>
                  </div>
                </div>
              </div>
            </section>

            {/* Section 4 */}
            <section className="mb-8">
              <div className="flex items-center space-x-3 mb-4">
                <Users className="w-6 h-6 text-red-400" />
                <h2 className="text-2xl font-bold text-white">4. Professional Standards</h2>
              </div>
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <p className="text-gray-300 mb-4">
                  When using Cobra AI for professional security testing, adhere to industry standards:
                </p>
                <ul className="list-disc list-inside text-gray-300 space-y-2 mb-4">
                  <li><strong>Documentation:</strong> Maintain detailed records of testing activities and findings</li>
                  <li><strong>Communication:</strong> Keep stakeholders informed of testing progress and discoveries</li>
                  <li><strong>Confidentiality:</strong> Protect client information and testing results</li>
                  <li><strong>Remediation:</strong> Provide actionable recommendations for vulnerability fixes</li>
                  <li><strong>Follow-up:</strong> Verify that reported issues have been properly addressed</li>
                </ul>
                
                <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
                  <p className="text-blue-300">
                    <strong>Best Practice:</strong> Follow established frameworks like OWASP, NIST, or PTES 
                    for structured and comprehensive security assessments.
                  </p>
                </div>
              </div>
            </section>

            {/* Section 5 */}
            <section className="mb-8">
              <h2 className="text-2xl font-bold text-white mb-4">5. Legal Compliance</h2>
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <p className="text-gray-300 mb-4">
                  Users must comply with all applicable laws and regulations, including but not limited to:
                </p>
                <div className="grid md:grid-cols-2 gap-6">
                  <div>
                    <h4 className="text-lg font-semibold text-gray-200 mb-3">United States</h4>
                    <ul className="list-disc list-inside text-gray-300 space-y-1 text-sm">
                      <li>Computer Fraud and Abuse Act (CFAA)</li>
                      <li>Digital Millennium Copyright Act (DMCA)</li>
                      <li>State computer crime laws</li>
                      <li>Industry-specific regulations (HIPAA, SOX, etc.)</li>
                    </ul>
                  </div>
                  <div>
                    <h4 className="text-lg font-semibold text-gray-200 mb-3">International</h4>
                    <ul className="list-disc list-inside text-gray-300 space-y-1 text-sm">
                      <li>General Data Protection Regulation (GDPR)</li>
                      <li>Computer Misuse Act (UK)</li>
                      <li>Local cybercrime legislation</li>
                      <li>Cross-border data protection laws</li>
                    </ul>
                  </div>
                </div>
              </div>
            </section>

            {/* Section 6 */}
            <section className="mb-8">
              <h2 className="text-2xl font-bold text-white mb-4">6. Subscription Tiers and Usage Limits</h2>
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <p className="text-gray-300 mb-4">
                  Different subscription tiers have varying usage limits and capabilities:
                </p>
                <div className="space-y-4">
                  <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
                    <h4 className="text-lg font-semibold text-blue-400 mb-2">Light Tier</h4>
                    <ul className="list-disc list-inside text-gray-300 space-y-1 text-sm">
                      <li>100K total AI tokens per month</li>
                      <li>Basic security tools and scans</li>
                      <li>Standard rate limits apply</li>
                      <li>Community support</li>
                    </ul>
                  </div>
                  
                  <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                    <h4 className="text-lg font-semibold text-yellow-400 mb-2">Pro Tier</h4>
                    <ul className="list-disc list-inside text-gray-300 space-y-1 text-sm">
                      <li>1M total AI tokens per month</li>
                      <li>Advanced security tools and analysis</li>
                      <li>Higher rate limits</li>
                      <li>Priority support</li>
                      <li>Custom wordlists and configurations</li>
                    </ul>
                  </div>
                  
                  <div className="bg-purple-500/10 border border-purple-500/30 rounded-lg p-4">
                    <h4 className="text-lg font-semibold text-purple-400 mb-2">Enterprise Tier</h4>
                    <ul className="list-disc list-inside text-gray-300 space-y-1 text-sm">
                      <li>Unlimited AI tokens and usage</li>
                      <li>All security tools and features</li>
                      <li>No rate limits</li>
                      <li>Dedicated support</li>
                      <li>Custom integrations and on-premise options</li>
                    </ul>
                  </div>
                </div>
              </div>
            </section>

            {/* Section 7 */}
            <section className="mb-8">
              <h2 className="text-2xl font-bold text-white mb-4">7. Responsible Disclosure</h2>
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <p className="text-gray-300 mb-4">
                  When discovering vulnerabilities using Cobra AI tools, follow responsible disclosure practices:
                </p>
                <ol className="list-decimal list-inside text-gray-300 space-y-2">
                  <li>Report vulnerabilities directly to the affected organization</li>
                  <li>Provide reasonable time for remediation before public disclosure</li>
                  <li>Do not publicly disclose vulnerabilities without proper coordination</li>
                  <li>Avoid accessing or demonstrating impact on sensitive data</li>
                  <li>Work collaboratively with security teams to resolve issues</li>
                  <li>Respect bug bounty program rules and timelines</li>
                </ol>
              </div>
            </section>

            {/* Section 8 */}
            <section className="mb-8">
              <h2 className="text-2xl font-bold text-white mb-4">8. Educational Use</h2>
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <p className="text-gray-300 mb-4">
                  Cobra AI welcomes educational use for learning cybersecurity concepts:
                </p>
                <ul className="list-disc list-inside text-gray-300 space-y-2 mb-4">
                  <li>Use only on dedicated lab environments or your own systems</li>
                  <li>Respect institutional policies and guidelines</li>
                  <li>Focus on understanding security concepts and methodologies</li>
                  <li>Share knowledge responsibly within academic communities</li>
                </ul>
                <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                  <p className="text-green-300">
                    <strong>Students and Educators:</strong> Contact us for educational discounts and 
                    specialized training resources for cybersecurity education.
                  </p>
                </div>
              </div>
            </section>

            {/* Contact Information */}
            <section className="mb-8">
              <h2 className="text-2xl font-bold text-white mb-4">9. Questions and Support</h2>
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <p className="text-gray-300 mb-4">
                  If you have questions about appropriate use of Cobra AI tools:
                </p>
                <div className="bg-gray-900 rounded-lg p-4 border border-gray-600">
                  <p className="text-gray-300"><strong>Creator:</strong> Harrison McCall</p>
                  <p className="text-gray-300"><strong>Service:</strong> Cobra AI</p>
                  <p className="text-gray-300"><strong>Website:</strong> https://cobraai.dev</p>
                  <p className="text-gray-300"><strong>Support:</strong> Available through the platform</p>
                  <p className="text-gray-300"><strong>Last Updated:</strong> {new Date().toLocaleDateString()}</p>
                </div>
              </div>
            </section>
          </div>

          {/* Footer Actions */}
          <div className="mt-12 pt-8 border-t border-gray-700">
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <button
                onClick={() => navigate('/settings')}
                className="px-6 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors min-h-[44px]"
              >
                Back to Settings
              </button>
              <button
                onClick={() => navigate('/terms-of-service')}
                className="px-6 py-3 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors min-h-[44px]"
              >
                View Terms of Service
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  )
}

export default TermsOfUse 