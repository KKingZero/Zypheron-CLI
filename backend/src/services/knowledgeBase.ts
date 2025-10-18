// COBRA AI Knowledge Base Service
// Comprehensive cybersecurity knowledge database for enhanced AI responses

export interface KnowledgeEntry {
  id: string
  category: string
  title: string
  description: string
  content: string
  tags: string[]
  difficulty: 'beginner' | 'intermediate' | 'advanced' | 'expert'
  lastUpdated: string
}

export interface ToolEntry {
  name: string
  category: string
  description: string
  usage: string
  examples: string[]
  installation: string
  platforms: string[]
  alternatives: string[]
}

export interface TechniqueEntry {
  name: string
  category: string
  description: string
  steps: string[]
  tools: string[]
  mitigations: string[]
  references: string[]
}

export class KnowledgeBaseService {
  private tools: ToolEntry[] = [
    {
      name: "Nmap",
      category: "Network Scanning",
      description: "Network discovery and security auditing tool",
      usage: "nmap [options] [target]",
      examples: [
        "nmap -sS -O -sV target.com",
        "nmap -sC -sV -p- 192.168.1.0/24",
        "nmap --script vuln target.com",
        "nmap -sU -p 53,67,68,161 target.com"
      ],
      installation: "apt-get install nmap (Linux) | brew install nmap (macOS) | Download from nmap.org (Windows)",
      platforms: ["Linux", "Windows", "macOS"],
      alternatives: ["Masscan", "Zmap", "Angry IP Scanner"]
    },
    {
      name: "Burp Suite",
      category: "Web Application Security",
      description: "Integrated platform for web application security testing",
      usage: "GUI-based proxy tool for intercepting and modifying HTTP requests",
      examples: [
        "Configure browser proxy to 127.0.0.1:8080",
        "Use Repeater to modify and resend requests",
        "Run active scanner on target endpoints",
        "Use Intruder for automated attacks"
      ],
      installation: "Download from portswigger.net",
      platforms: ["Linux", "Windows", "macOS"],
      alternatives: ["OWASP ZAP", "Caido", "Proxyman"]
    },
    {
      name: "Metasploit",
      category: "Exploitation Framework",
      description: "Penetration testing framework with extensive exploit database",
      usage: "msfconsole",
      examples: [
        "use exploit/windows/smb/ms17_010_eternalblue",
        "set RHOSTS 192.168.1.100",
        "set payload windows/x64/meterpreter/reverse_tcp",
        "exploit"
      ],
      installation: "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall",
      platforms: ["Linux", "Windows", "macOS"],
      alternatives: ["Cobalt Strike", "Empire", "Covenant"]
    },
    {
      name: "Wireshark",
      category: "Network Analysis",
      description: "Network protocol analyzer for packet capture and analysis",
      usage: "wireshark [options] [capture-file]",
      examples: [
        "wireshark -i eth0",
        "tshark -i eth0 -f 'tcp port 80'",
        "tshark -r capture.pcap -Y 'http.request.method == GET'",
        "wireshark -k -i eth0 -f 'host 192.168.1.100'"
      ],
      installation: "apt-get install wireshark (Linux) | Download from wireshark.org",
      platforms: ["Linux", "Windows", "macOS"],
      alternatives: ["tcpdump", "NetworkMiner", "Ettercap"]
    },
    {
      name: "SQLMap",
      category: "Web Application Security",
      description: "Automatic SQL injection and database takeover tool",
      usage: "sqlmap [options]",
      examples: [
        "sqlmap -u 'http://target.com/page.php?id=1' --dbs",
        "sqlmap -u 'http://target.com/login.php' --data 'user=admin&pass=admin' --dbs",
        "sqlmap -r request.txt --batch --dump",
        "sqlmap -u 'http://target.com/page.php?id=1' --os-shell"
      ],
      installation: "git clone https://github.com/sqlmapproject/sqlmap.git",
      platforms: ["Linux", "Windows", "macOS"],
      alternatives: ["jSQL Injection", "NoSQLMap", "Havij"]
    },
    {
      name: "Gobuster",
      category: "Web Application Security",
      description: "Directory/file & DNS busting tool written in Go",
      usage: "gobuster [mode] [options]",
      examples: [
        "gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt",
        "gobuster dns -d target.com -w /usr/share/wordlists/subdomains.txt",
        "gobuster vhost -u http://target.com -w /usr/share/wordlists/subdomains.txt",
        "gobuster dir -u http://target.com -w wordlist.txt -x php,html,js"
      ],
      installation: "apt-get install gobuster (Linux) | go install github.com/OJ/gobuster/v3@latest",
      platforms: ["Linux", "Windows", "macOS"],
      alternatives: ["Dirbuster", "Ffuf", "Feroxbuster"]
    },
    {
      name: "Nikto",
      category: "Web Application Security",
      description: "Web server scanner for vulnerabilities and misconfigurations",
      usage: "nikto [options]",
      examples: [
        "nikto -h http://target.com",
        "nikto -h http://target.com -p 80,443,8080",
        "nikto -h target.com -ssl",
        "nikto -h http://target.com -o report.html -Format htm"
      ],
      installation: "apt-get install nikto (Linux) | Download from cirt.net",
      platforms: ["Linux", "Windows", "macOS"],
      alternatives: ["Nuclei", "Skipfish", "W3af"]
    },
    {
      name: "John the Ripper",
      category: "Password Cracking",
      description: "Fast password cracker with support for many hash types",
      usage: "john [options] [password-files]",
      examples: [
        "john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt",
        "john --incremental hashes.txt",
        "john --show hashes.txt",
        "john --format=NT hashes.txt"
      ],
      installation: "apt-get install john (Linux) | Download from openwall.com",
      platforms: ["Linux", "Windows", "macOS"],
      alternatives: ["Hashcat", "Hydra", "Medusa"]
    },
    {
      name: "Hashcat",
      category: "Password Cracking",
      description: "Advanced password recovery tool supporting GPU acceleration",
      usage: "hashcat [options] hashfile [dictionary]",
      examples: [
        "hashcat -m 0 -a 0 hashes.txt rockyou.txt",
        "hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a",
        "hashcat -m 5600 -a 0 hashes.txt wordlist.txt",
        "hashcat -m 22000 -a 0 capture.hc22000 rockyou.txt"
      ],
      installation: "apt-get install hashcat (Linux) | Download from hashcat.net",
      platforms: ["Linux", "Windows", "macOS"],
      alternatives: ["John the Ripper", "oclHashcat", "MDXfind"]
    },
    {
      name: "Hydra",
      category: "Password Cracking",
      description: "Network logon cracker supporting many protocols",
      usage: "hydra [options] target service",
      examples: [
        "hydra -l admin -P passwords.txt ssh://192.168.1.100",
        "hydra -L users.txt -P passwords.txt ftp://target.com",
        "hydra -l admin -p password rdp://192.168.1.100",
        "hydra -L users.txt -P passwords.txt target.com http-post-form '/login:user=^USER^&pass=^PASS^:Invalid'"
      ],
      installation: "apt-get install hydra (Linux) | Download from github.com/vanhauser-thc/thc-hydra",
      platforms: ["Linux", "Windows", "macOS"],
      alternatives: ["Medusa", "Ncrack", "Patator"]
    }
  ]

  private techniques: TechniqueEntry[] = [
    {
      name: "SQL Injection",
      category: "Web Application Attacks",
      description: "Injection attack that exploits vulnerabilities in database queries",
      steps: [
        "Identify input parameters that interact with database",
        "Test for SQL injection using single quotes, double quotes",
        "Determine database type and structure",
        "Extract sensitive data using UNION queries",
        "Escalate to OS command execution if possible"
      ],
      tools: ["SQLMap", "Burp Suite", "OWASP ZAP"],
      mitigations: [
        "Use parameterized queries/prepared statements",
        "Input validation and sanitization",
        "Principle of least privilege for database accounts",
        "Web Application Firewall (WAF)",
        "Regular security testing"
      ],
      references: [
        "OWASP SQL Injection Prevention Cheat Sheet",
        "PortSwigger SQL Injection Guide",
        "NIST SP 800-53 Security Controls"
      ]
    },
    {
      name: "Cross-Site Scripting (XSS)",
      category: "Web Application Attacks",
      description: "Client-side code injection attack",
      steps: [
        "Identify input fields and parameters",
        "Test for reflected XSS with <script>alert(1)</script>",
        "Test for stored XSS in persistent data fields",
        "Test for DOM-based XSS in client-side JavaScript",
        "Craft payload to steal cookies or session tokens"
      ],
      tools: ["Burp Suite", "OWASP ZAP", "XSSHunter", "BeEF"],
      mitigations: [
        "Input validation and output encoding",
        "Content Security Policy (CSP)",
        "HttpOnly and Secure cookie flags",
        "Regular security code reviews",
        "Use modern frameworks with built-in XSS protection"
      ],
      references: [
        "OWASP XSS Prevention Cheat Sheet",
        "PortSwigger XSS Guide",
        "Mozilla CSP Documentation"
      ]
    },
    {
      name: "Network Reconnaissance",
      category: "Information Gathering",
      description: "Systematic discovery of network assets and services",
      steps: [
        "Passive information gathering (OSINT)",
        "DNS enumeration and subdomain discovery",
        "Port scanning and service identification",
        "OS fingerprinting and version detection",
        "Vulnerability scanning and assessment"
      ],
      tools: ["Nmap", "Masscan", "Amass", "Subfinder", "Shodan"],
      mitigations: [
        "Network segmentation and firewalls",
        "Intrusion Detection Systems (IDS)",
        "Rate limiting and monitoring",
        "Disable unnecessary services",
        "Regular security assessments"
      ],
      references: [
        "NIST Cybersecurity Framework",
        "OWASP Testing Guide",
        "SANS Penetration Testing Methodology"
      ]
    },
    {
      name: "Privilege Escalation",
      category: "Post-Exploitation",
      description: "Gaining higher-level permissions on a compromised system",
      steps: [
        "Enumerate current user privileges and group memberships",
        "Identify vulnerable services and applications",
        "Check for misconfigurations and weak permissions",
        "Exploit kernel vulnerabilities if present",
        "Maintain persistence with elevated access"
      ],
      tools: ["LinPEAS", "WinPEAS", "PowerUp", "GTFOBins", "LOLBAS"],
      mitigations: [
        "Principle of least privilege",
        "Regular patching and updates",
        "Application whitelisting",
        "User Account Control (UAC)",
        "Monitoring and logging"
      ],
      references: [
        "MITRE ATT&CK Framework",
        "Microsoft Security Baselines",
        "CIS Security Benchmarks"
      ]
    },
    {
      name: "Social Engineering",
      category: "Human Factor Attacks",
      description: "Psychological manipulation to gain unauthorized access",
      steps: [
        "Research target organization and employees",
        "Identify potential attack vectors (email, phone, physical)",
        "Craft convincing pretext and communication",
        "Execute attack (phishing, vishing, physical access)",
        "Exploit gained access for further compromise"
      ],
      tools: ["SET (Social Engineer Toolkit)", "Gophish", "King Phisher", "Evilginx"],
      mitigations: [
        "Security awareness training",
        "Multi-factor authentication",
        "Email security solutions",
        "Physical security controls",
        "Incident response procedures"
      ],
      references: [
        "NIST SP 800-50 Security Awareness Training",
        "SANS Social Engineering Framework",
        "Anti-Phishing Working Group Guidelines"
      ]
    }
  ]

  private vulnerabilities: KnowledgeEntry[] = [
    {
      id: "cve-2021-44228",
      category: "Critical Vulnerabilities",
      title: "Log4Shell (CVE-2021-44228)",
      description: "Remote code execution vulnerability in Apache Log4j",
      content: "Log4Shell is a critical vulnerability in the Apache Log4j logging library that allows remote code execution. The vulnerability occurs when Log4j processes untrusted input containing JNDI lookup strings, leading to arbitrary code execution.",
      tags: ["RCE", "Apache", "Log4j", "JNDI", "Critical"],
      difficulty: "intermediate",
      lastUpdated: "2024-01-15"
    },
    {
      id: "cve-2017-0144",
      category: "Critical Vulnerabilities",
      title: "EternalBlue (CVE-2017-0144)",
      description: "SMB vulnerability exploited by WannaCry ransomware",
      content: "EternalBlue exploits a vulnerability in Microsoft's Server Message Block (SMB) protocol. The vulnerability allows attackers to execute arbitrary code on target systems without authentication, making it extremely dangerous for network propagation.",
      tags: ["SMB", "Windows", "RCE", "Worm", "Critical"],
      difficulty: "advanced",
      lastUpdated: "2024-01-15"
    },
    {
      id: "owasp-top10-2021",
      category: "Web Security",
      title: "OWASP Top 10 2021",
      description: "Most critical web application security risks",
      content: "1. Broken Access Control\n2. Cryptographic Failures\n3. Injection\n4. Insecure Design\n5. Security Misconfiguration\n6. Vulnerable and Outdated Components\n7. Identification and Authentication Failures\n8. Software and Data Integrity Failures\n9. Security Logging and Monitoring Failures\n10. Server-Side Request Forgery (SSRF)",
      tags: ["OWASP", "Web Security", "Top 10", "Application Security"],
      difficulty: "beginner",
      lastUpdated: "2024-01-15"
    }
  ]

  private bestPractices: KnowledgeEntry[] = [
    {
      id: "secure-coding",
      category: "Development Security",
      title: "Secure Coding Practices",
      description: "Essential practices for writing secure code",
      content: "1. Input Validation: Validate all input data\n2. Output Encoding: Encode output to prevent injection\n3. Authentication: Implement strong authentication mechanisms\n4. Session Management: Secure session handling\n5. Access Control: Implement proper authorization\n6. Cryptographic Practices: Use strong encryption\n7. Error Handling: Secure error messages\n8. Data Protection: Protect sensitive data\n9. Communication Security: Use secure protocols\n10. System Configuration: Secure system settings",
      tags: ["Secure Coding", "Development", "Best Practices"],
      difficulty: "intermediate",
      lastUpdated: "2024-01-15"
    },
    {
      id: "incident-response",
      category: "Incident Response",
      title: "Incident Response Framework",
      description: "Structured approach to handling security incidents",
      content: "1. Preparation: Establish IR team and procedures\n2. Identification: Detect and analyze incidents\n3. Containment: Limit damage and prevent spread\n4. Eradication: Remove threats from environment\n5. Recovery: Restore systems to normal operation\n6. Lessons Learned: Document and improve processes",
      tags: ["Incident Response", "NIST", "Framework", "Security Operations"],
      difficulty: "advanced",
      lastUpdated: "2024-01-15"
    }
  ]

  // Search knowledge base
  searchKnowledge(query: string, category?: string): KnowledgeEntry[] {
    const allEntries = [...this.vulnerabilities, ...this.bestPractices]
    const searchTerms = query.toLowerCase().split(' ')
    
    return allEntries.filter(entry => {
      if (category && entry.category !== category) return false
      
      const searchableText = `${entry.title} ${entry.description} ${entry.content} ${entry.tags.join(' ')}`.toLowerCase()
      return searchTerms.some(term => searchableText.includes(term))
    })
  }

  // Get tool information
  getTool(toolName: string): ToolEntry | undefined {
    return this.tools.find(tool => 
      tool.name.toLowerCase() === toolName.toLowerCase()
    )
  }

  // Search tools
  searchTools(query: string, category?: string): ToolEntry[] {
    const searchTerms = query.toLowerCase().split(' ')
    
    return this.tools.filter(tool => {
      if (category && tool.category !== category) return false
      
      const searchableText = `${tool.name} ${tool.description} ${tool.category}`.toLowerCase()
      return searchTerms.some(term => searchableText.includes(term))
    })
  }

  // Get technique information
  getTechnique(techniqueName: string): TechniqueEntry | undefined {
    return this.techniques.find(technique => 
      technique.name.toLowerCase() === techniqueName.toLowerCase()
    )
  }

  // Search techniques
  searchTechniques(query: string, category?: string): TechniqueEntry[] {
    const searchTerms = query.toLowerCase().split(' ')
    
    return this.techniques.filter(technique => {
      if (category && technique.category !== category) return false
      
      const searchableText = `${technique.name} ${technique.description} ${technique.category}`.toLowerCase()
      return searchTerms.some(term => searchableText.includes(term))
    })
  }

  // Get contextual knowledge for AI responses
  getContextualKnowledge(userMessage: string): string {
    const message = userMessage.toLowerCase()
    let context = ""

    // Check for specific tools mentioned
    this.tools.forEach(tool => {
      if (message.includes(tool.name.toLowerCase())) {
        context += `\n\n**${tool.name} Knowledge:**\n${tool.description}\nUsage: ${tool.usage}\nExamples: ${tool.examples.slice(0, 2).join(', ')}`
      }
    })

    // Check for techniques mentioned
    this.techniques.forEach(technique => {
      if (message.includes(technique.name.toLowerCase().replace(/\s+/g, ''))) {
        context += `\n\n**${technique.name} Knowledge:**\n${technique.description}\nSteps: ${technique.steps.slice(0, 3).join(', ')}\nTools: ${technique.tools.join(', ')}`
      }
    })

    // Check for vulnerabilities mentioned
    this.vulnerabilities.forEach(vuln => {
      if (message.includes(vuln.title.toLowerCase()) || vuln.tags.some(tag => message.includes(tag.toLowerCase()))) {
        context += `\n\n**${vuln.title} Knowledge:**\n${vuln.description}\n${vuln.content.substring(0, 200)}...`
      }
    })

    return context
  }

  // Get all available categories
  getCategories(): string[] {
    const categories = new Set<string>()
    
    this.tools.forEach(tool => categories.add(tool.category))
    this.techniques.forEach(technique => categories.add(technique.category))
    this.vulnerabilities.forEach(vuln => categories.add(vuln.category))
    this.bestPractices.forEach(practice => categories.add(practice.category))
    
    return Array.from(categories).sort()
  }

  // Get statistics
  getStats() {
    return {
      tools: this.tools.length,
      techniques: this.techniques.length,
      vulnerabilities: this.vulnerabilities.length,
      bestPractices: this.bestPractices.length,
      categories: this.getCategories().length,
      totalEntries: this.tools.length + this.techniques.length + this.vulnerabilities.length + this.bestPractices.length
    }
  }
}

// Export singleton instance
export const knowledgeBase = new KnowledgeBaseService()
