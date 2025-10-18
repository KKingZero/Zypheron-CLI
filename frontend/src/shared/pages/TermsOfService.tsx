import React from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowLeft, Shield, AlertTriangle, Scale } from 'lucide-react'
import zypheronLogo from '../../../public/Zypheron1.jpg'
import SEOOptimizer from '../../components/SEOOptimizer'

const TermsOfService: React.FC = () => {
  const navigate = useNavigate()

  const tosConfig = {
    title: "Terms of Service - Cobra AI",
    description: "Terms of Service for Cobra AI - AI-powered cybersecurity platform. Review our legal terms, service conditions, and user obligations.",
    keywords: "terms of service, legal, cobra ai, cybersecurity, terms and conditions, user agreement",
    canonicalUrl: "https://cobraai.dev/terms-of-service",
    ogType: "website",
    ogImage: "/Zypheron1.jpg"
  }

  return (
    <>
      <SEOOptimizer {...tosConfig} />
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
                    <h1 className="text-xl font-bold text-red-500 font-orbitron">Terms of Service</h1>
                    <p className="text-sm text-gray-400">Legal Agreement</p>
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
          <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4 mb-8">
            <div className="flex items-start space-x-3">
              <AlertTriangle className="w-6 h-6 text-amber-400 flex-shrink-0 mt-0.5" />
              <div>
                <h2 className="text-lg font-semibold text-amber-400 mb-2">Important Legal Notice</h2>
                <p className="text-amber-200 text-sm">
                  Please read these Terms of Service carefully before using Cobra AI. By accessing or using our service, 
                  you agree to be bound by these terms and all applicable laws and regulations.
                </p>
              </div>
            </div>
          </div>

          <div className="prose prose-invert max-w-none">
            {/* Section 1 */}
            <section className="mb-8">
              <div className="flex items-center space-x-3 mb-4">
                <Scale className="w-6 h-6 text-red-400" />
                <h2 className="text-2xl font-bold text-white">1. Acceptance of Terms</h2>
              </div>
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <p className="text-gray-300 mb-4">
                  By accessing and using Cobra AI ("the Service"), you accept and agree to be bound by the terms 
                  and provision of this agreement. If you do not agree to abide by the above, please do not use this service.
                </p>
                <p className="text-gray-300">
                  These Terms of Service ("Terms") govern your use of our AI-powered cybersecurity platform, 
                  created by Harrison McCall, and all related services, features, and content.
                </p>
              </div>
            </section>

            {/* Section 2 */}
            <section className="mb-8">
              <div className="flex items-center space-x-3 mb-4">
                <Shield className="w-6 h-6 text-red-400" />
                <h2 className="text-2xl font-bold text-white">2. Service Description</h2>
              </div>
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <p className="text-gray-300 mb-4">
                  Cobra AI provides AI-powered cybersecurity tools including but not limited to:
                </p>
                <ul className="list-disc list-inside text-gray-300 space-y-2 mb-4">
                  <li>Automated penetration testing and vulnerability scanning</li>
                  <li>Network security analysis and threat detection</li>
                  <li>AI-driven security recommendations and reporting</li>
                  <li>OSINT (Open Source Intelligence) gathering tools</li>
                  <li>Blue team security monitoring capabilities</li>
                </ul>
                <p className="text-gray-300">
                  These tools are provided for legitimate security testing purposes only on systems you own or have explicit authorization to test.
                </p>
              </div>
            </section>

            {/* Section 3 */}
            <section className="mb-8">
              <h2 className="text-2xl font-bold text-white mb-4">3. Acceptable Use Policy</h2>
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <p className="text-gray-300 mb-4">You agree to use Cobra AI only for lawful purposes and in accordance with these Terms. You agree NOT to use the service:</p>
                <ul className="list-disc list-inside text-gray-300 space-y-2 mb-4">
                  <li>To conduct unauthorized penetration testing or security assessments</li>
                  <li>To access, modify, or damage systems without proper authorization</li>
                  <li>For any illegal, harmful, or malicious activities</li>
                  <li>To violate any applicable local, state, national, or international law</li>
                  <li>To infringe upon or violate others' rights</li>
                  <li>To distribute malware, viruses, or other harmful code</li>
                </ul>
                <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
                  <p className="text-red-300 font-semibold">
                    WARNING: Unauthorized use of these tools against systems you do not own or lack permission to test 
                    may violate local and federal laws. Users are solely responsible for ensuring compliance with all applicable laws.
                  </p>
                </div>
              </div>
            </section>

            {/* Section 4 */}
            <section className="mb-8">
              <h2 className="text-2xl font-bold text-white mb-4">4. User Accounts and Security</h2>
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <p className="text-gray-300 mb-4">
                  When you create an account with us, you must provide information that is accurate, complete, and current at all times.
                </p>
                <ul className="list-disc list-inside text-gray-300 space-y-2">
                  <li>You are responsible for safeguarding your account credentials</li>
                  <li>You must notify us immediately of any unauthorized use of your account</li>
                  <li>We reserve the right to terminate accounts that violate these terms</li>
                  <li>You are responsible for all activities that occur under your account</li>
                </ul>
              </div>
            </section>

            {/* Section 5 */}
            <section className="mb-8">
              <h2 className="text-2xl font-bold text-white mb-4">5. Subscription and Billing</h2>
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <p className="text-gray-300 mb-4">
                  Cobra AI offers various subscription tiers with different features and usage limits:
                </p>
                <ul className="list-disc list-inside text-gray-300 space-y-2 mb-4">
                  <li><strong>Light:</strong> Basic security tools with limited token usage</li>
                  <li><strong>Pro:</strong> Advanced features with increased limits</li>
                  <li><strong>Enterprise:</strong> Full feature access with unlimited usage</li>
                </ul>
                <p className="text-gray-300 mb-4">
                  Billing is processed through Stripe. Subscriptions auto-renew unless cancelled. 
                  Refunds may be available within 30 days of purchase at our discretion.
                </p>
              </div>
            </section>

            {/* Section 6 */}
            <section className="mb-8">
              <h2 className="text-2xl font-bold text-white mb-4">6. Privacy and Data Protection</h2>
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <p className="text-gray-300 mb-4">
                  We take your privacy seriously. Our data practices include:
                </p>
                <ul className="list-disc list-inside text-gray-300 space-y-2">
                  <li>Encryption of sensitive data in transit and at rest</li>
                  <li>Limited data collection necessary for service operation</li>
                  <li>No sharing of personal data with third parties without consent</li>
                  <li>Compliance with applicable data protection regulations</li>
                  <li>Secure storage and processing of security scan results</li>
                </ul>
              </div>
            </section>

            {/* Section 7 */}
            <section className="mb-8">
              <h2 className="text-2xl font-bold text-white mb-4">7. Limitation of Liability</h2>
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <p className="text-gray-300 mb-4">
                  TO THE MAXIMUM EXTENT PERMITTED BY LAW, COBRA AI AND ITS CREATORS SHALL NOT BE LIABLE FOR ANY INDIRECT, 
                  INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, OR ANY LOSS OF PROFITS OR REVENUES.
                </p>
                <p className="text-gray-300">
                  Our liability is limited to the amount paid for the service in the 12 months preceding the claim. 
                  The service is provided "as is" without warranties of any kind.
                </p>
              </div>
            </section>

            {/* Section 8 */}
            <section className="mb-8">
              <h2 className="text-2xl font-bold text-white mb-4">8. Termination</h2>
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <p className="text-gray-300 mb-4">
                  We may terminate or suspend your access immediately, without prior notice, for any reason, 
                  including breach of these Terms.
                </p>
                <p className="text-gray-300">
                  Upon termination, your right to use the service ceases immediately. 
                  Data may be retained for a limited period as required by law or for business purposes.
                </p>
              </div>
            </section>

            {/* Section 9 */}
            <section className="mb-8">
              <h2 className="text-2xl font-bold text-white mb-4">9. Changes to Terms</h2>
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <p className="text-gray-300">
                  We reserve the right to modify these Terms at any time. Changes will be effective immediately upon posting. 
                  Continued use of the service after changes constitutes acceptance of the new Terms.
                </p>
              </div>
            </section>

            {/* Contact Information */}
            <section className="mb-8">
              <h2 className="text-2xl font-bold text-white mb-4">10. Contact Information</h2>
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <p className="text-gray-300 mb-4">
                  If you have any questions about these Terms of Service, please contact us:
                </p>
                <div className="bg-gray-900 rounded-lg p-4 border border-gray-600">
                  <p className="text-gray-300"><strong>Creator:</strong> Harrison McCall</p>
                  <p className="text-gray-300"><strong>Service:</strong> Cobra AI</p>
                  <p className="text-gray-300"><strong>Website:</strong> https://cobraai.dev</p>
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
                onClick={() => navigate('/terms-of-use')}
                className="px-6 py-3 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors min-h-[44px]"
              >
                View Terms of Use
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  )
}

export default TermsOfService 