import ToolRunner, { ExecutionMethod, RunResult } from './toolRunner'
import fs from 'fs'
import path from 'path'

export interface ToolInfo {
  id: string
  label: string
  command: string
  category: string
  tags?: string[]
  installed?: boolean
}

export class ToolRegistry {
  private runner: ToolRunner
  private tools: ToolInfo[]

  constructor(preferred?: ExecutionMethod) {
    this.runner = new ToolRunner(preferred)
    this.tools = this.buildDefaultList()
    this.loadExternalList()
  }

  list(): ToolInfo[] {
    return this.tools
  }

  private loadExternalList(): void {
    try {
      const configuredPath = process.env.TOOL_LIST_PATH
      const candidates = [
        configuredPath,
        path.join(process.cwd(), 'config', 'kali-tools.txt'),
        path.join(process.cwd(), 'backend', 'config', 'kali-tools.txt'),
        path.join(__dirname, '..', '..', 'config', 'kali-tools.txt'),
        path.join(__dirname, '..', 'config', 'kali-tools.txt'),
      ].filter(Boolean) as string[]

      const filePath = candidates.find(p => fs.existsSync(p))
      if (!filePath) return

      const raw = fs.readFileSync(filePath, 'utf8')
      const lines = raw.split(/\r?\n/)
      for (const line of lines) {
        const name = line.replace(/^\$/,'').trim()
        if (!name) continue
        const id = name
        if (!this.tools.find(t => t.id === id)) {
          this.tools.push({ id, label: name, command: name, category: 'misc', tags: [] })
        }
      }
    } catch {
      // ignore
    }
  }

  async detectInstalled(): Promise<ToolInfo[]> {
    const detected = await Promise.all(
      this.tools.map(async (t) => ({
        ...t,
        installed: this.runner.detectNative(t.command) || this.runner.detectWSLTool(t.command),
      }))
    )
    this.tools = detected
    return detected
  }

  async run(id: string, args: string[] = []): Promise<RunResult & { id: string }> {
    const tool = this.tools.find((t) => t.id === id)
    if (!tool) {
      return { id, ok: false, code: null, stdout: '', stderr: `Unknown tool: ${id}`, method: 'UNKNOWN' }
    }
    const res = await this.runner.run(tool.command, { args })
    return { id, ...res }
  }

  private buildDefaultList(): ToolInfo[] {
    const items: Array<[string, string, string, string, string[]?]> = [
      // Hydra suite
      ['hydra', 'Hydra', 'hydra', 'bruteforce'],
      ['dpl4hydra', 'dpl4hydra', 'dpl4hydra', 'bruteforce'],
      ['hydra-wizard', 'hydra-wizard', 'hydra-wizard', 'bruteforce'],
      ['pw-inspector', 'pw-inspector', 'pw-inspector', 'bruteforce'],

      // Nmap suite
      ['nmap', 'Nmap', 'nmap', 'scanner'],
      ['ncat', 'Ncat', 'ncat', 'network'],
      ['ndiff', 'Ndiff', 'ndiff', 'scanner'],
      ['nping', 'Nping', 'nping', 'network'],
      ['zenmap', 'Zenmap', 'zenmap', 'scanner'],

      // Metasploit
      ['msfconsole', 'Metasploit Console', 'msfconsole', 'exploitation'],
      ['msfvenom', 'msfvenom', 'msfvenom', 'exploitation'],
      ['msfupdate', 'msfupdate', 'msfupdate', 'exploitation'],
      ['msfdb', 'msfdb', 'msfdb', 'exploitation'],
      ['msfd', 'msfd', 'msfd', 'exploitation'],
      ['msfrpc', 'msfrpc', 'msfrpc', 'exploitation'],
      ['msfrpcd', 'msfrpcd', 'msfrpcd', 'exploitation'],
      ['msf-exe2vba', 'msf-exe2vba', 'msf-exe2vba', 'exploitation'],
      ['msf-exe2vbs', 'msf-exe2vbs', 'msf-exe2vbs', 'exploitation'],
      ['msf-egghunter', 'msf-egghunter', 'msf-egghunter', 'exploitation'],
      // ... many msf-* helpers omitted for brevity

      // Wireshark suite
      ['wireshark', 'Wireshark', 'wireshark', 'network'],
      ['tshark', 'tshark', 'tshark', 'network'],
      ['dumpcap', 'dumpcap', 'dumpcap', 'network'],
      ['editcap', 'editcap', 'editcap', 'network'],
      ['mergecap', 'mergecap', 'mergecap', 'network'],
      ['capinfos', 'capinfos', 'capinfos', 'network'],
      ['rawshark', 'rawshark', 'rawshark', 'network'],

      // Web/content discovery
      ['gobuster', 'gobuster', 'gobuster', 'web'],
      ['dirb', 'dirb', 'dirb', 'web'],
      ['dirbuster', 'dirbuster', 'dirbuster', 'web'],
      ['ffuf', 'ffuf', 'ffuf', 'web'],
      ['whatweb', 'whatweb', 'whatweb', 'web'],
      ['whatweb', 'whatweb', 'whatweb', 'web'],
      ['dirsearch', 'dirsearch', 'dirsearch', 'web'],

      // Wireless
      ['aircrack-ng', 'aircrack-ng', 'aircrack-ng', 'wireless'],
      ['airodump-ng', 'airodump-ng', 'airodump-ng', 'wireless'],
      ['aireplay-ng', 'aireplay-ng', 'aireplay-ng', 'wireless'],
      ['airmon-ng', 'airmon-ng', 'airmon-ng', 'wireless'],
      ['cowpatty', 'cowpatty', 'cowpatty', 'wireless'],
      ['wifite', 'wifite', 'wifite', 'wireless'],
      ['fern-wifi-cracker', 'fern-wifi-cracker', 'fern-wifi-cracker', 'wireless'],
      ['reaver', 'reaver', 'reaver', 'wireless'],
      ['wash', 'wash', 'wash', 'wireless'],

      // Hashing / cracking
      ['hashcat', 'hashcat', 'hashcat', 'cracking'],
      ['john', 'John the Ripper', 'john', 'cracking'],
      ['zip2john', 'zip2john', 'zip2john', 'cracking'],
      ['pdf2john', 'pdf2john', 'pdf2john', 'cracking'],
      ['rar2john', 'rar2john', 'rar2john', 'cracking'],

      // OSINT / recon
      ['theharvester', 'theHarvester', 'theharvester', 'osint'],
      ['amass', 'amass', 'amass', 'osint'],
      ['subfinder', 'subfinder', 'subfinder', 'osint'],
      ['sublist3r', 'sublist3r', 'sublist3r', 'osint'],
      ['whatweb', 'whatweb', 'whatweb', 'osint'],

      // Web vulns
      ['nikto', 'nikto', 'nikto', 'web'],
      ['sqlmap', 'sqlmap', 'sqlmap', 'web'],

      // Network utils
      ['netcat', 'netcat', 'nc', 'network'],
      ['ncat', 'ncat', 'ncat', 'network'],
      ['tcpdump', 'tcpdump', 'tcpdump', 'network'],
      ['masscan', 'masscan', 'masscan', 'scanner'],
      ['socat', 'socat', 'socat', 'network'],

      // Windows/AD
      ['evil-winrm', 'evil-winrm', 'evil-winrm', 'windows'],
      ['impacket-smbclient', 'impacket-smbclient', 'impacket-smbclient', 'windows'],
      ['impacket-ntlmrelayx', 'impacket-ntlmrelayx', 'impacket-ntlmrelayx', 'windows'],
      ['bloodhound', 'BloodHound', 'bloodhound', 'windows'],

      // Misc
      ['yara', 'yara', 'yara', 'forensics'],
      ['steghide', 'steghide', 'steghide', 'forensics'],
      ['testdisk', 'testdisk', 'testdisk', 'forensics'],
      ['foremost', 'foremost', 'foremost', 'forensics'],
      ['scapy', 'scapy', 'scapy', 'network'],
      ['mitmproxy', 'mitmproxy', 'mitmproxy', 'network'],
    ]

    const registry: ToolInfo[] = []
    for (const [id, label, command, category] of items) {
      // Avoid duplicates by id
      if (!registry.find((t) => t.id === id)) {
        registry.push({ id, label, command, category, tags: [] })
      }
    }
    return registry
  }
}

export default ToolRegistry


