/**
 * Kali Tools Manager
 * Auto-detect and manage Kali Linux security tools
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import chalk from 'chalk';
import { KaliTheme, StatusIndicators } from '../ui/themes/kali';

const execAsync = promisify(exec);

export interface KaliTool {
  name: string;
  command: string;
  aliases: string[];
  installed: boolean;
  version?: string;
  minVersion?: string; // Minimum required version
  requiredFor: string[];
  installCmd: string;
  category: ToolCategory;
  priority: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  compatible?: boolean; // Version compatibility flag
}

export enum ToolCategory {
  SCANNER = 'scanner',
  EXPLOIT = 'exploit',
  BRUTEFORCE = 'bruteforce',
  RECONNAISSANCE = 'reconnaissance',
  WEB = 'web',
  WIRELESS = 'wireless',
  FORENSICS = 'forensics',
  OSINT = 'osint',
  MISC = 'misc',
}

export interface ToolCompatibility {
  compatible: boolean;
  issues: string[];
  suggestions: string[];
}

export class KaliToolManager {
  private tools: Map<string, KaliTool>;
  private detectionCache: Map<string, boolean>;
  private readonly cacheTimeout = 5 * 60 * 1000; // 5 minutes

  constructor() {
    this.tools = new Map();
    this.detectionCache = new Map();
    this.initializeToolDefinitions();
  }

  /**
   * Initialize tool definitions
   */
  private initializeToolDefinitions(): void {
    const toolDefinitions: KaliTool[] = [
      // Network Scanners
      {
        name: 'nmap',
        command: 'nmap',
        aliases: ['zenmap'],
        installed: false,
        minVersion: '7.80',
        requiredFor: ['scan', 'recon'],
        installCmd: 'sudo apt install nmap',
        category: ToolCategory.SCANNER,
        priority: 'critical',
        description: 'Network exploration and security auditing',
      },
      {
        name: 'masscan',
        command: 'masscan',
        aliases: [],
        installed: false,
        minVersion: '1.3',
        requiredFor: ['scan'],
        installCmd: 'sudo apt install masscan',
        category: ToolCategory.SCANNER,
        priority: 'high',
        description: 'Fast TCP port scanner',
      },
      {
        name: 'nuclei',
        command: 'nuclei',
        aliases: [],
        installed: false,
        minVersion: '2.9',
        requiredFor: ['scan'],
        installCmd: 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
        category: ToolCategory.SCANNER,
        priority: 'high',
        description: 'Fast vulnerability scanner based on templates',
      },

      // Web Application Scanners
      {
        name: 'nikto',
        command: 'nikto',
        aliases: [],
        installed: false,
        requiredFor: ['scan', 'web'],
        installCmd: 'sudo apt install nikto',
        category: ToolCategory.WEB,
        priority: 'high',
        description: 'Web server scanner',
      },
      {
        name: 'sqlmap',
        command: 'sqlmap',
        aliases: [],
        installed: false,
        requiredFor: ['scan', 'exploit', 'web'],
        installCmd: 'sudo apt install sqlmap',
        category: ToolCategory.WEB,
        priority: 'high',
        description: 'Automatic SQL injection tool',
      },
      {
        name: 'gobuster',
        command: 'gobuster',
        aliases: [],
        installed: false,
        requiredFor: ['scan', 'recon', 'web'],
        installCmd: 'sudo apt install gobuster',
        category: ToolCategory.WEB,
        priority: 'high',
        description: 'Directory/file & DNS busting tool',
      },
      {
        name: 'ffuf',
        command: 'ffuf',
        aliases: [],
        installed: false,
        requiredFor: ['fuzz', 'web'],
        installCmd: 'sudo apt install ffuf',
        category: ToolCategory.WEB,
        priority: 'high',
        description: 'Fast web fuzzer',
      },
      {
        name: 'wfuzz',
        command: 'wfuzz',
        aliases: [],
        installed: false,
        requiredFor: ['fuzz', 'web'],
        installCmd: 'sudo apt install wfuzz',
        category: ToolCategory.WEB,
        priority: 'medium',
        description: 'Web application bruteforcer',
      },

      // Exploitation Frameworks
      {
        name: 'metasploit',
        command: 'msfconsole',
        aliases: ['msf', 'msfvenom'],
        installed: false,
        requiredFor: ['exploit'],
        installCmd: 'sudo apt install metasploit-framework',
        category: ToolCategory.EXPLOIT,
        priority: 'critical',
        description: 'Penetration testing framework',
      },

      // Bruteforce Tools
      {
        name: 'hydra',
        command: 'hydra',
        aliases: ['hydra-gtk'],
        installed: false,
        requiredFor: ['bruteforce'],
        installCmd: 'sudo apt install hydra',
        category: ToolCategory.BRUTEFORCE,
        priority: 'high',
        description: 'Network logon cracker',
      },
      {
        name: 'john',
        command: 'john',
        aliases: ['john-the-ripper'],
        installed: false,
        requiredFor: ['bruteforce'],
        installCmd: 'sudo apt install john',
        category: ToolCategory.BRUTEFORCE,
        priority: 'medium',
        description: 'Password cracker',
      },
      {
        name: 'hashcat',
        command: 'hashcat',
        aliases: [],
        installed: false,
        requiredFor: ['bruteforce'],
        installCmd: 'sudo apt install hashcat',
        category: ToolCategory.BRUTEFORCE,
        priority: 'high',
        description: 'Advanced password recovery',
      },

      // Reconnaissance Tools
      {
        name: 'subfinder',
        command: 'subfinder',
        aliases: [],
        installed: false,
        requiredFor: ['recon', 'osint'],
        installCmd: 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
        category: ToolCategory.RECONNAISSANCE,
        priority: 'medium',
        description: 'Subdomain discovery tool',
      },
      {
        name: 'amass',
        command: 'amass',
        aliases: [],
        installed: false,
        requiredFor: ['recon', 'osint'],
        installCmd: 'sudo apt install amass',
        category: ToolCategory.RECONNAISSANCE,
        priority: 'medium',
        description: 'In-depth DNS enumeration',
      },
      {
        name: 'theharvester',
        command: 'theHarvester',
        aliases: ['theharvester'],
        installed: false,
        requiredFor: ['osint'],
        installCmd: 'sudo apt install theharvester',
        category: ToolCategory.OSINT,
        priority: 'medium',
        description: 'E-mail, subdomain and people names harvester',
      },
      {
        name: 'recon-ng',
        command: 'recon-ng',
        aliases: [],
        installed: false,
        requiredFor: ['recon', 'osint'],
        installCmd: 'sudo apt install recon-ng',
        category: ToolCategory.OSINT,
        priority: 'low',
        description: 'Web reconnaissance framework',
      },

      // Wireless Tools
      {
        name: 'aircrack-ng',
        command: 'aircrack-ng',
        aliases: ['airodump-ng', 'aireplay-ng'],
        installed: false,
        requiredFor: ['wireless'],
        installCmd: 'sudo apt install aircrack-ng',
        category: ToolCategory.WIRELESS,
        priority: 'medium',
        description: 'WiFi security auditing tools',
      },

      // Network Analysis
      {
        name: 'wireshark',
        command: 'wireshark',
        aliases: ['tshark'],
        installed: false,
        requiredFor: ['capture', 'forensics'],
        installCmd: 'sudo apt install wireshark',
        category: ToolCategory.FORENSICS,
        priority: 'medium',
        description: 'Network protocol analyzer',
      },

      // Proxy Tools
      {
        name: 'burpsuite',
        command: 'burpsuite',
        aliases: ['burp'],
        installed: false,
        requiredFor: ['proxy', 'web'],
        installCmd: 'Download from https://portswigger.net/burp',
        category: ToolCategory.WEB,
        priority: 'medium',
        description: 'Web application security testing',
      },
      {
        name: 'zaproxy',
        command: 'zaproxy',
        aliases: ['zap', 'owasp-zap'],
        installed: false,
        requiredFor: ['proxy', 'web'],
        installCmd: 'sudo apt install zaproxy',
        category: ToolCategory.WEB,
        priority: 'medium',
        description: 'OWASP Zed Attack Proxy',
      },
    ];

    toolDefinitions.forEach(tool => {
      this.tools.set(tool.name, tool);
    });
  }

  /**
   * Detect all installed tools
   */
  async detectTools(): Promise<KaliTool[]> {
    console.log(chalk.hex(KaliTheme.info)(`${StatusIndicators.INFO} Detecting installed tools...`));
    
    const detectionPromises = Array.from(this.tools.values()).map(async tool => {
      const isInstalled = await this.checkToolInstalled(tool.command);
      tool.installed = isInstalled;
      
      if (isInstalled) {
        tool.version = await this.getToolVersion(tool.command, tool.name);
        tool.compatible = this.checkVersionCompatibility(tool);
      }
      
      return tool;
    });

    const results = await Promise.all(detectionPromises);
    
    // Cache results
    results.forEach(tool => {
      this.detectionCache.set(tool.name, tool.installed);
    });

    return results;
  }

  /**
   * Check if a specific tool is installed
   */
  private async checkToolInstalled(command: string): Promise<boolean> {
    try {
      await execAsync(`which ${command}`);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get tool version
   */
  private async getToolVersion(command: string, toolName: string): Promise<string | undefined> {
    try {
      const versionFlags = ['--version', '-V', '-v', 'version'];
      
      for (const flag of versionFlags) {
        try {
          const { stdout, stderr } = await execAsync(`${command} ${flag} 2>&1`, {
            timeout: 3000,
          });
          
          const output = stdout || stderr;
          const versionMatch = output.match(/\d+\.\d+(\.\d+)?/);
          
          if (versionMatch) {
            return versionMatch[0];
          }
        } catch {
          continue;
        }
      }
      
      return undefined;
    } catch {
      return undefined;
    }
  }

  /**
   * Compare two semantic versions
   * Returns: 1 if v1 > v2, -1 if v1 < v2, 0 if equal
   */
  private compareVersions(v1: string, v2: string): number {
    const parts1 = v1.split('.').map(Number);
    const parts2 = v2.split('.').map(Number);
    
    for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
      const part1 = parts1[i] || 0;
      const part2 = parts2[i] || 0;
      
      if (part1 > part2) return 1;
      if (part1 < part2) return -1;
    }
    
    return 0;
  }

  /**
   * Check if tool version meets minimum requirements
   */
  private checkVersionCompatibility(tool: KaliTool): boolean {
    if (!tool.minVersion || !tool.version) {
      return true; // No version requirement or version unknown
    }
    
    return this.compareVersions(tool.version, tool.minVersion) >= 0;
  }

  /**
   * Check if tool is available (with caching)
   */
  isAvailable(toolName: string): boolean {
    const cached = this.detectionCache.get(toolName);
    if (cached !== undefined) {
      return cached;
    }

    const tool = this.tools.get(toolName);
    return tool?.installed || false;
  }

  /**
   * Get tool by name
   */
  getTool(toolName: string): KaliTool | undefined {
    return this.tools.get(toolName);
  }

  /**
   * Get all tools
   */
  getAllTools(): KaliTool[] {
    return Array.from(this.tools.values());
  }

  /**
   * Get tools by category
   */
  getToolsByCategory(category: ToolCategory): KaliTool[] {
    return Array.from(this.tools.values()).filter(tool => tool.category === category);
  }

  /**
   * Get tools required for a command
   */
  getRequiredTools(command: string): KaliTool[] {
    return Array.from(this.tools.values()).filter(tool => 
      tool.requiredFor.includes(command)
    );
  }

  /**
   * Get installation instructions for a tool
   */
  getInstallInstructions(toolName: string): string {
    const tool = this.tools.get(toolName);
    if (!tool) {
      return `Tool '${toolName}' not found in registry`;
    }

    return tool.installCmd;
  }

  /**
   * Check tool compatibility
   */
  async checkCompatibility(toolName: string): Promise<ToolCompatibility> {
    const tool = this.tools.get(toolName);
    
    if (!tool) {
      return {
        compatible: false,
        issues: [`Tool '${toolName}' not found`],
        suggestions: [],
      };
    }

    const issues: string[] = [];
    const suggestions: string[] = [];

    if (!tool.installed) {
      issues.push(`${tool.name} is not installed`);
      suggestions.push(`Install with: ${tool.installCmd}`);
    }

    // Check if running on Kali Linux
    const isKali = await this.isKaliLinux();
    if (!isKali) {
      suggestions.push('For best compatibility, consider using Kali Linux or a Kali Docker container');
    }

    return {
      compatible: issues.length === 0,
      issues,
      suggestions,
    };
  }

  /**
   * Check if running on Kali Linux
   */
  private async isKaliLinux(): Promise<boolean> {
    try {
      const { stdout } = await execAsync('cat /etc/os-release');
      return stdout.toLowerCase().includes('kali');
    } catch {
      return false;
    }
  }

  /**
   * Get tool statistics
   */
  getStats(): {
    total: number;
    installed: number;
    missing: number;
    critical: number;
    high: number;
  } {
    const tools = Array.from(this.tools.values());
    
    return {
      total: tools.length,
      installed: tools.filter(t => t.installed).length,
      missing: tools.filter(t => !t.installed).length,
      critical: tools.filter(t => t.priority === 'critical' && !t.installed).length,
      high: tools.filter(t => t.priority === 'high' && !t.installed).length,
    };
  }

  /**
   * Suggest best tool for a task
   */
  suggestTool(task: string, category?: ToolCategory): KaliTool | null {
    let candidates = Array.from(this.tools.values());
    
    // Filter by category if provided
    if (category) {
      candidates = candidates.filter(t => t.category === category);
    }
    
    // Filter by task
    candidates = candidates.filter(t => t.requiredFor.includes(task));
    
    // Prefer installed AND compatible tools
    const installedCompatible = candidates.filter(t => t.installed && t.compatible !== false);
    if (installedCompatible.length > 0) {
      // Sort by priority
      installedCompatible.sort((a, b) => {
        const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        return priorityOrder[a.priority] - priorityOrder[b.priority];
      });
      return installedCompatible[0];
    }
    
    // If none installed and compatible, return highest priority
    candidates.sort((a, b) => {
      const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return priorityOrder[a.priority] - priorityOrder[b.priority];
    });
    
    return candidates[0] || null;
  }

  /**
   * Get alternative tools for a task if primary tool is unavailable
   */
  getAlternativeTools(primaryTool: string, task: string): KaliTool[] {
    const primary = this.tools.get(primaryTool);
    if (!primary) {
      return [];
    }

    // Get all tools for the same task and category
    const alternatives = Array.from(this.tools.values()).filter(tool => 
      tool.name !== primaryTool &&
      tool.category === primary.category &&
      tool.requiredFor.includes(task)
    );

    // Sort by: installed & compatible > installed > priority
    alternatives.sort((a, b) => {
      if (a.installed && a.compatible !== false && (!b.installed || b.compatible === false)) return -1;
      if (b.installed && b.compatible !== false && (!a.installed || a.compatible === false)) return 1;
      if (a.installed && !b.installed) return -1;
      if (b.installed && !a.installed) return 1;
      
      const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return priorityOrder[a.priority] - priorityOrder[b.priority];
    });

    return alternatives;
  }
}

// Singleton instance
let toolManagerInstance: KaliToolManager | null = null;

export function getToolManager(): KaliToolManager {
  if (!toolManagerInstance) {
    toolManagerInstance = new KaliToolManager();
  }
  return toolManagerInstance;
}

