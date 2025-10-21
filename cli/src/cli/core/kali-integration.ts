/**
 * Kali Linux Integration
 * Auto-detect Kali environment, metapackages, and optimize for WSL
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import { readFile, access } from 'fs/promises';
import chalk from 'chalk';
import ora from 'ora';
import { KaliTheme, StatusIndicators } from '../ui/themes/kali';

const execAsync = promisify(exec);

export interface KaliEnvironment {
  isKali: boolean;
  isWSL: boolean;
  version?: string;
  release?: string;
  wslVersion?: string;
  distribution?: string;
  metapackages: KaliMetapackage[];
  installedTools: string[];
  toolPaths: Record<string, string>;
}

export interface KaliMetapackage {
  name: string;
  installed: boolean;
  description: string;
  tools: string[];
  size?: string;
  category: 'core' | 'pentest' | 'wireless' | 'web' | 'forensics' | 'reverse' | 'social' | 'all';
}

export interface WSLOptimization {
  enabled: boolean;
  features: {
    interop: boolean;
    appendWindowsPath: boolean;
    mountFstab: boolean;
  };
  recommendations: string[];
}

// Kali Linux Metapackages
const KALI_METAPACKAGES: Omit<KaliMetapackage, 'installed' | 'tools'>[] = [
  {
    name: 'kali-linux-core',
    description: 'Core Kali Linux system',
    category: 'core',
  },
  {
    name: 'kali-linux-default',
    description: 'Default Kali Linux installation',
    category: 'core',
  },
  {
    name: 'kali-linux-everything',
    description: 'Every available Kali package',
    category: 'all',
  },
  {
    name: 'kali-linux-large',
    description: 'Large set of tools',
    category: 'all',
  },
  {
    name: 'kali-tools-top10',
    description: 'Top 10 Kali Linux tools',
    category: 'core',
  },
  {
    name: 'kali-tools-information-gathering',
    description: 'Information gathering tools',
    category: 'pentest',
  },
  {
    name: 'kali-tools-vulnerability',
    description: 'Vulnerability assessment tools',
    category: 'pentest',
  },
  {
    name: 'kali-tools-web',
    description: 'Web application analysis',
    category: 'web',
  },
  {
    name: 'kali-tools-database',
    description: 'Database assessment tools',
    category: 'web',
  },
  {
    name: 'kali-tools-passwords',
    description: 'Password attacks',
    category: 'pentest',
  },
  {
    name: 'kali-tools-wireless',
    description: 'Wireless attacks',
    category: 'wireless',
  },
  {
    name: 'kali-tools-reverse-engineering',
    description: 'Reverse engineering',
    category: 'reverse',
  },
  {
    name: 'kali-tools-exploitation',
    description: 'Exploitation tools',
    category: 'pentest',
  },
  {
    name: 'kali-tools-social-engineering',
    description: 'Social engineering',
    category: 'social',
  },
  {
    name: 'kali-tools-sniffing-spoofing',
    description: 'Sniffing and spoofing',
    category: 'pentest',
  },
  {
    name: 'kali-tools-post-exploitation',
    description: 'Post exploitation',
    category: 'pentest',
  },
  {
    name: 'kali-tools-forensics',
    description: 'Forensic tools',
    category: 'forensics',
  },
  {
    name: 'kali-tools-reporting',
    description: 'Reporting tools',
    category: 'pentest',
  },
];

export class KaliIntegration {
  private environment: KaliEnvironment | null = null;
  private wslOptimizations: WSLOptimization | null = null;

  /**
   * Detect complete Kali environment
   */
  async detectEnvironment(): Promise<KaliEnvironment> {
    if (this.environment) {
      return this.environment;
    }

    const spinner = ora({
      text: 'Detecting Kali Linux environment...',
      color: 'cyan',
    }).start();

    try {
      const [isKali, isWSL, version, metapackages, installedTools, toolPaths] = await Promise.all([
        this.isKaliLinux(),
        this.isWSL(),
        this.getKaliVersion(),
        this.detectMetapackages(),
        this.discoverInstalledTools(),
        this.mapToolPaths(),
      ]);

      const wslVersion = isWSL ? await this.getWSLVersion() : undefined;
      const distribution = isWSL ? await this.getWSLDistribution() : undefined;

      this.environment = {
        isKali,
        isWSL,
        version,
        release: version,
        wslVersion,
        distribution,
        metapackages,
        installedTools,
        toolPaths,
      };

      spinner.succeed(chalk.hex(KaliTheme.success)('Environment detected'));
      this.displayEnvironmentInfo();

      return this.environment;
    } catch (error: any) {
      spinner.fail(chalk.hex(KaliTheme.danger)('Environment detection failed'));
      throw error;
    }
  }

  /**
   * Check if running on Kali Linux
   */
  async isKaliLinux(): Promise<boolean> {
    try {
      // Check /etc/os-release
      const osRelease = await readFile('/etc/os-release', 'utf-8');
      if (osRelease.includes('Kali') || osRelease.includes('kali')) {
        return true;
      }

      // Check for Kali-specific files
      try {
        await access('/etc/apt/sources.list.d/kali.list');
        return true;
      } catch {}

      // Check dpkg for kali packages
      try {
        const { stdout } = await execAsync('dpkg -l | grep kali-linux');
        return stdout.trim().length > 0;
      } catch {}

      return false;
    } catch (error) {
      return false;
    }
  }

  /**
   * Check if running in WSL
   */
  async isWSL(): Promise<boolean> {
    try {
      // Check /proc/version for Microsoft
      const version = await readFile('/proc/version', 'utf-8');
      if (version.includes('Microsoft') || version.includes('WSL')) {
        return true;
      }

      // Check for WSL interop
      try {
        await access('/proc/sys/fs/binfmt_misc/WSLInterop');
        return true;
      } catch {}

      // Check environment variable
      if (process.env.WSL_DISTRO_NAME) {
        return true;
      }

      return false;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get Kali Linux version
   */
  async getKaliVersion(): Promise<string | undefined> {
    try {
      const osRelease = await readFile('/etc/os-release', 'utf-8');
      const versionMatch = osRelease.match(/VERSION="([^"]+)"/);
      if (versionMatch) {
        return versionMatch[1];
      }

      // Try lsb_release
      try {
        const { stdout } = await execAsync('lsb_release -d');
        const match = stdout.match(/Description:\s*(.+)/);
        if (match) {
          return match[1].trim();
        }
      } catch {}

      return undefined;
    } catch (error) {
      return undefined;
    }
  }

  /**
   * Get WSL version
   */
  async getWSLVersion(): Promise<string | undefined> {
    try {
      // Try to get WSL version from Windows host
      const { stdout } = await execAsync('wsl.exe --version 2>/dev/null || echo "WSL 1"');
      return stdout.trim();
    } catch (error) {
      return 'WSL 1'; // Default to WSL 1 if detection fails
    }
  }

  /**
   * Get WSL distribution name
   */
  async getWSLDistribution(): Promise<string | undefined> {
    return process.env.WSL_DISTRO_NAME || 'Unknown';
  }

  /**
   * Detect installed Kali metapackages
   */
  async detectMetapackages(): Promise<KaliMetapackage[]> {
    const metapackages: KaliMetapackage[] = [];

    for (const pkg of KALI_METAPACKAGES) {
      const installed = await this.isPackageInstalled(pkg.name);
      const tools = installed ? await this.getPackageTools(pkg.name) : [];
      
      metapackages.push({
        ...pkg,
        installed,
        tools,
      });
    }

    return metapackages;
  }

  /**
   * Check if package is installed
   */
  async isPackageInstalled(packageName: string): Promise<boolean> {
    try {
      const { stdout } = await execAsync(`dpkg -l | grep "^ii  ${packageName} "`);
      return stdout.trim().length > 0;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get tools from a metapackage
   */
  async getPackageTools(packageName: string): Promise<string[]> {
    try {
      const { stdout } = await execAsync(`apt-cache depends ${packageName} | grep Depends | awk '{print $2}'`);
      return stdout.trim().split('\n').filter(tool => tool && !tool.startsWith('lib'));
    } catch (error) {
      return [];
    }
  }

  /**
   * Discover installed pentesting tools
   */
  async discoverInstalledTools(): Promise<string[]> {
    const tools: string[] = [];
    const commonTools = [
      'nmap', 'masscan', 'nikto', 'nuclei', 'sqlmap', 'hydra',
      'metasploit-framework', 'msfconsole', 'john', 'hashcat',
      'aircrack-ng', 'wireshark', 'tcpdump', 'ettercap',
      'burpsuite', 'zaproxy', 'gobuster', 'dirbuster',
      'subfinder', 'amass', 'theharvester', 'recon-ng',
      'maltego', 'shodan', 'nessus', 'openvas',
    ];

    for (const tool of commonTools) {
      try {
        const { stdout } = await execAsync(`which ${tool}`);
        if (stdout.trim()) {
          tools.push(tool);
        }
      } catch {
        // Tool not found
      }
    }

    return tools;
  }

  /**
   * Map tool paths for quick access
   */
  async mapToolPaths(): Promise<Record<string, string>> {
    const paths: Record<string, string> = {};
    const tools = await this.discoverInstalledTools();

    for (const tool of tools) {
      try {
        const { stdout } = await execAsync(`which ${tool}`);
        paths[tool] = stdout.trim();
      } catch {
        // Skip
      }
    }

    return paths;
  }

  /**
   * Display environment information
   */
  private displayEnvironmentInfo(): void {
    if (!this.environment) return;

    console.log();
    console.log(chalk.hex(KaliTheme.primary).bold('╔═══ ENVIRONMENT DETECTED ═══════════════════════════╗'));
    
    if (this.environment.isKali) {
      console.log(chalk.hex(KaliTheme.success)(`║  ${StatusIndicators.SUCCESS} Kali Linux: ${this.environment.version || 'Unknown'}`.padEnd(55) + '║'));
    } else {
      console.log(chalk.hex(KaliTheme.warning)(`║  ${StatusIndicators.WARNING} Not running on Kali Linux`.padEnd(55) + '║'));
    }

    if (this.environment.isWSL) {
      console.log(chalk.hex(KaliTheme.info)(`║  ${StatusIndicators.INFO} WSL Environment: ${this.environment.distribution}`.padEnd(55) + '║'));
    }

    const installedMetapackages = this.environment.metapackages.filter(m => m.installed);
    console.log(chalk.hex(KaliTheme.accent)(`║  Metapackages: ${installedMetapackages.length}/${this.environment.metapackages.length}`.padEnd(55) + '║'));
    console.log(chalk.hex(KaliTheme.accent)(`║  Tools Found: ${this.environment.installedTools.length}`.padEnd(55) + '║'));
    
    console.log(chalk.hex(KaliTheme.primary).bold('╚════════════════════════════════════════════════════╝'));
    console.log();
  }

  /**
   * Get WSL optimizations
   */
  async getWSLOptimizations(): Promise<WSLOptimization> {
    if (this.wslOptimizations) {
      return this.wslOptimizations;
    }

    if (!this.environment?.isWSL) {
      return {
        enabled: false,
        features: {
          interop: false,
          appendWindowsPath: false,
          mountFstab: false,
        },
        recommendations: [],
      };
    }

    const recommendations: string[] = [];
    const features = {
      interop: false,
      appendWindowsPath: false,
      mountFstab: false,
    };

    try {
      // Check WSL config
      const wslConf = await readFile('/etc/wsl.conf', 'utf-8').catch(() => '');
      
      features.interop = wslConf.includes('enabled = true') || wslConf.includes('enabled=true');
      features.appendWindowsPath = !wslConf.includes('appendWindowsPath = false');
      features.mountFstab = wslConf.includes('mountFsTab = true');

      // Generate recommendations
      if (!features.interop) {
        recommendations.push('Enable WSL interop for Windows tool integration');
      }

      // Check for optimal mount options
      if (!wslConf.includes('[automount]')) {
        recommendations.push('Configure automount options for better performance');
      }

      // Check network configuration
      if (!wslConf.includes('[network]')) {
        recommendations.push('Configure network settings for pentesting tools');
      }

      // Check for systemd (WSL2)
      if (!wslConf.includes('systemd=true')) {
        recommendations.push('Enable systemd for better service management');
      }

    } catch (error) {
      recommendations.push('Create /etc/wsl.conf for WSL optimizations');
    }

    this.wslOptimizations = {
      enabled: true,
      features,
      recommendations,
    };

    return this.wslOptimizations;
  }

  /**
   * Apply WSL optimizations
   */
  async applyWSLOptimizations(): Promise<void> {
    if (!this.environment?.isWSL) {
      console.log(chalk.hex(KaliTheme.warning)('Not running in WSL - skipping optimizations'));
      return;
    }

    const spinner = ora({
      text: 'Applying WSL optimizations...',
      color: 'cyan',
    }).start();

    try {
      const wslConf = `
# Zypheron WSL Optimizations
[automount]
enabled = true
root = /mnt/
options = "metadata,umask=22,fmask=11"
mountFsTab = true

[network]
generateHosts = true
generateResolvConf = true

[interop]
enabled = true
appendWindowsPath = true

[boot]
systemd = true
`;

      // Note: This would require sudo permissions
      spinner.info(chalk.hex(KaliTheme.info)('WSL configuration suggested'));
      console.log();
      console.log(chalk.hex(KaliTheme.accent)('Add to /etc/wsl.conf:'));
      console.log(chalk.hex(KaliTheme.muted)(wslConf));
      console.log();
      console.log(chalk.hex(KaliTheme.warning)('⚠️  Restart WSL after applying: wsl --shutdown'));
      
      spinner.succeed(chalk.hex(KaliTheme.success)('Optimization recommendations displayed'));
    } catch (error: any) {
      spinner.fail(chalk.hex(KaliTheme.danger)('Failed to apply optimizations'));
      console.error(error.message);
    }
  }

  /**
   * Install Kali metapackage
   */
  async installMetapackage(packageName: string): Promise<boolean> {
    const spinner = ora({
      text: `Installing ${packageName}...`,
      color: 'cyan',
    }).start();

    try {
      const { stdout, stderr } = await execAsync(`sudo apt-get install -y ${packageName}`, {
        maxBuffer: 50 * 1024 * 1024, // 50MB buffer
      });

      spinner.succeed(chalk.hex(KaliTheme.success)(`Installed ${packageName}`));
      
      // Refresh environment
      this.environment = null;
      await this.detectEnvironment();
      
      return true;
    } catch (error: any) {
      spinner.fail(chalk.hex(KaliTheme.danger)(`Failed to install ${packageName}`));
      console.error(chalk.hex(KaliTheme.muted)(error.message));
      return false;
    }
  }

  /**
   * Get current environment
   */
  getEnvironment(): KaliEnvironment | null {
    return this.environment;
  }

  /**
   * Check if running on Kali (cached)
   */
  isKali(): boolean {
    return this.environment?.isKali || false;
  }

  /**
   * Check if running in WSL (cached)
   */
  isWSLEnvironment(): boolean {
    return this.environment?.isWSL || false;
  }
}

// Singleton instance
let kaliIntegrationInstance: KaliIntegration | null = null;

export function getKaliIntegration(): KaliIntegration {
  if (!kaliIntegrationInstance) {
    kaliIntegrationInstance = new KaliIntegration();
  }
  return kaliIntegrationInstance;
}

