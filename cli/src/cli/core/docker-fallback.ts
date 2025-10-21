/**
 * Docker Fallback
 * Use Docker containers when tools are not installed locally
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import chalk from 'chalk';
import ora from 'ora';
import { KaliTheme, StatusIndicators } from '../ui/themes/kali';

const execAsync = promisify(exec);

export interface DockerToolConfig {
  image: string;
  command: string;
  workdir?: string;
  volumes?: string[];
  env?: Record<string, string>;
}

// Docker images for common penetration testing tools
const DOCKER_TOOL_IMAGES: Record<string, DockerToolConfig> = {
  nmap: {
    image: 'instrumentisto/nmap:latest',
    command: 'nmap',
  },
  nikto: {
    image: 'securecodebox/scanner-nikto:latest',
    command: 'nikto.pl',
  },
  sqlmap: {
    image: 'paoloo/sqlmap:latest',
    command: 'sqlmap',
  },
  hydra: {
    image: 'ilyaglow/hydra:latest',
    command: 'hydra',
  },
  metasploit: {
    image: 'metasploitframework/metasploit-framework:latest',
    command: 'msfconsole',
  },
  masscan: {
    image: 'ilyaglow/masscan:latest',
    command: 'masscan',
  },
  nuclei: {
    image: 'projectdiscovery/nuclei:latest',
    command: 'nuclei',
  },
  subfinder: {
    image: 'projectdiscovery/subfinder:latest',
    command: 'subfinder',
  },
  amass: {
    image: 'caffix/amass:latest',
    command: 'amass',
  },
  theharvester: {
    image: 'hrbrmstr/theharvester:latest',
    command: 'theHarvester',
  },
  hashcat: {
    image: 'dizcza/docker-hashcat:latest',
    command: 'hashcat',
  },
  john: {
    image: 'ghcr.io/openwall/john:latest',
    command: 'john',
  },
};

export class DockerFallback {
  private dockerAvailable: boolean | null = null;

  /**
   * Check if Docker is available
   */
  async isDockerAvailable(): Promise<boolean> {
    if (this.dockerAvailable !== null) {
      return this.dockerAvailable;
    }

    try {
      await execAsync('docker --version');
      this.dockerAvailable = true;
      return true;
    } catch (error) {
      this.dockerAvailable = false;
      return false;
    }
  }

  /**
   * Check if tool has Docker image available
   */
  hasDockerImage(tool: string): boolean {
    return tool in DOCKER_TOOL_IMAGES;
  }

  /**
   * Get Docker config for tool
   */
  getDockerConfig(tool: string): DockerToolConfig | null {
    return DOCKER_TOOL_IMAGES[tool] || null;
  }

  /**
   * Check if Docker image is pulled
   */
  async isImagePulled(image: string): Promise<boolean> {
    try {
      const { stdout } = await execAsync(`docker images -q ${image}`);
      return stdout.trim().length > 0;
    } catch (error) {
      return false;
    }
  }

  /**
   * Pull Docker image
   */
  async pullImage(image: string): Promise<boolean> {
    const spinner = ora({
      text: `Pulling Docker image: ${image}`,
      color: 'cyan',
    }).start();

    try {
      await execAsync(`docker pull ${image}`);
      spinner.succeed(chalk.hex(KaliTheme.success)(`Image pulled: ${image}`));
      return true;
    } catch (error: any) {
      spinner.fail(chalk.hex(KaliTheme.danger)(`Failed to pull image: ${error.message}`));
      return false;
    }
  }

  /**
   * Run tool in Docker container
   */
  async runTool(
    tool: string,
    args: string[],
    options: {
      workdir?: string;
      volumes?: string[];
      env?: Record<string, string>;
      stream?: boolean;
    } = {}
  ): Promise<{ stdout: string; stderr: string; success: boolean }> {
    const dockerConfig = this.getDockerConfig(tool);
    if (!dockerConfig) {
      throw new Error(`No Docker image available for tool: ${tool}`);
    }

    // Check if Docker is available
    const dockerAvailable = await this.isDockerAvailable();
    if (!dockerAvailable) {
      throw new Error('Docker is not installed or not running');
    }

    // Check if image is pulled
    const imagePulled = await this.isImagePulled(dockerConfig.image);
    if (!imagePulled) {
      console.log(chalk.hex(KaliTheme.info)(`${StatusIndicators.INFO} Docker image not found, pulling...`));
      const pulled = await this.pullImage(dockerConfig.image);
      if (!pulled) {
        throw new Error('Failed to pull Docker image');
      }
    }

    // Build Docker command
    const dockerArgs = ['docker', 'run', '--rm'];

    // Add volumes
    if (options.volumes) {
      options.volumes.forEach(vol => {
        dockerArgs.push('-v', vol);
      });
    } else if (options.workdir) {
      dockerArgs.push('-v', `${options.workdir}:/workspace`);
      dockerArgs.push('-w', '/workspace');
    }

    // Add environment variables
    if (options.env) {
      Object.entries(options.env).forEach(([key, value]) => {
        dockerArgs.push('-e', `${key}=${value}`);
      });
    }

    // Add network (host for scanning tools)
    if (['nmap', 'masscan', 'nikto', 'hydra'].includes(tool)) {
      dockerArgs.push('--network', 'host');
    }

    // Add image and command
    dockerArgs.push(dockerConfig.image);
    dockerArgs.push(...args);

    console.log(chalk.hex(KaliTheme.muted)(`Running: ${dockerArgs.join(' ')}`));

    try {
      const { stdout, stderr } = await execAsync(dockerArgs.join(' '), {
        maxBuffer: 10 * 1024 * 1024, // 10MB buffer
      });

      return {
        stdout,
        stderr,
        success: true,
      };
    } catch (error: any) {
      return {
        stdout: error.stdout || '',
        stderr: error.stderr || error.message,
        success: false,
      };
    }
  }

  /**
   * Show Docker fallback suggestion
   */
  async suggestDockerFallback(tool: string): Promise<void> {
    const hasDocker = await this.isDockerAvailable();
    const hasImage = this.hasDockerImage(tool);

    if (!hasDocker) {
      console.log();
      console.log(chalk.hex(KaliTheme.info)('💡 Tip: Install Docker to run tools in containers'));
      console.log(chalk.hex(KaliTheme.muted)('   https://docs.docker.com/get-docker/'));
      return;
    }

    if (hasImage) {
      console.log();
      console.log(chalk.hex(KaliTheme.info)(`💡 Tip: Use Docker fallback with: ${chalk.hex(KaliTheme.accent)('--docker')}`));
      console.log(chalk.hex(KaliTheme.muted)(`   Docker image available: ${DOCKER_TOOL_IMAGES[tool].image}`));
    }
  }

  /**
   * List available Docker images
   */
  listAvailableImages(): void {
    console.log();
    console.log(chalk.hex(KaliTheme.primary).bold('Available Docker Images:'));
    console.log();

    Object.entries(DOCKER_TOOL_IMAGES).forEach(([tool, config]) => {
      console.log(
        `  ${chalk.hex(KaliTheme.accent)(tool.padEnd(15))} ${chalk.hex(KaliTheme.muted)(config.image)}`
      );
    });

    console.log();
  }

  /**
   * Pull all Docker images
   */
  async pullAllImages(): Promise<void> {
    console.log(chalk.hex(KaliTheme.primary).bold('Pulling all Docker images...'));
    console.log();

    for (const [tool, config] of Object.entries(DOCKER_TOOL_IMAGES)) {
      console.log(chalk.hex(KaliTheme.info)(`Pulling ${tool}...`));
      await this.pullImage(config.image);
    }

    console.log();
    console.log(chalk.hex(KaliTheme.success)('✓ All images pulled successfully'));
  }
}

// Singleton instance
let dockerFallbackInstance: DockerFallback | null = null;

export function getDockerFallback(): DockerFallback {
  if (!dockerFallbackInstance) {
    dockerFallbackInstance = new DockerFallback();
  }
  return dockerFallbackInstance;
}

