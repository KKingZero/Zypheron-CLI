/**
 * Tool Executor
 * Execute Kali tools with real-time output streaming
 */

import { spawn, ChildProcess } from 'child_process';
import chalk from 'chalk';
import ora, { Ora } from 'ora';
import { XMLParser } from 'fast-xml-parser';
import { KaliTheme, StatusIndicators } from '../ui/themes/kali';
import { getToolManager, KaliTool } from './kali-tools';
import { getDockerFallback } from './docker-fallback';

export interface ExecutionOptions {
  tool: string;
  args: string[];
  target?: string;
  format?: 'text' | 'json' | 'xml';
  stream?: boolean;
  aiAnalysis?: boolean;
  timeout?: number;
  env?: Record<string, string>;
}

export interface ToolResult {
  success: boolean;
  tool: string;
  output: string;
  error?: string;
  parsed?: any;
  aiInsights?: string;
  duration: number;
  exitCode: number;
}

export class ToolExecutor {
  private toolManager = getToolManager();
  private activeProcesses: Map<string, ChildProcess> = new Map();

  /**
   * Execute a tool with the given options
   */
  async execute(options: ExecutionOptions): Promise<ToolResult> {
    const startTime = Date.now();
    const tool = this.toolManager.getTool(options.tool);

    if (!tool) {
      return this.errorResult(options.tool, `Tool '${options.tool}' not found`, startTime);
    }

    if (!tool.installed) {
      return this.errorResult(
        options.tool,
        `Tool '${options.tool}' is not installed. Install with: ${tool.installCmd}`,
        startTime
      );
    }

    try {
      // Build command
      const command = this.buildCommand(tool, options);
      
      // Show execution info
      console.log(chalk.hex(KaliTheme.info)(`${StatusIndicators.INFO} Executing: ${chalk.bold(command)}`));

      // Execute with streaming
      const result = await this.executeCommand(command, options, tool);
      
      // Calculate duration
      result.duration = Date.now() - startTime;

      // Parse output if needed
      if (options.format && options.format !== 'text') {
        result.parsed = await this.parseOutput(result.output, options.format, tool);
      }

      // AI analysis (optional)
      if (options.aiAnalysis && result.success) {
        result.aiInsights = await this.getAIAnalysis(result, tool);
      }

      return result;
    } catch (error: any) {
      return this.errorResult(options.tool, error.message, startTime);
    }
  }

  /**
   * Build command string from options
   */
  private buildCommand(tool: KaliTool, options: ExecutionOptions): string {
    const parts = [tool.command];
    
    // Add arguments
    if (options.args && options.args.length > 0) {
      parts.push(...options.args);
    }

    // Add target (if not already in args)
    if (options.target && !options.args?.some(arg => arg === options.target)) {
      parts.push(options.target);
    }

    return parts.join(' ');
  }

  /**
   * Execute command with real-time streaming
   */
  private async executeCommand(
    command: string,
    options: ExecutionOptions,
    tool: KaliTool
  ): Promise<ToolResult> {
    return new Promise((resolve, reject) => {
      let stdout = '';
      let stderr = '';
      let spinner: Ora | null = null;

      // Create spinner if streaming is enabled
      if (options.stream) {
        spinner = ora({
          text: `Running ${tool.name}...`,
          color: 'cyan',
          spinner: 'dots',
        }).start();
      }

      // Spawn process
      const process = spawn(command, {
        shell: true,
        env: { ...process.env, ...options.env },
      });

      // Store process for potential cancellation
      const processId = `${tool.name}-${Date.now()}`;
      this.activeProcesses.set(processId, process);

      // Handle stdout
      process.stdout?.on('data', (data: Buffer) => {
        const output = data.toString();
        stdout += output;

        if (options.stream) {
          // Stream output in real-time
          this.streamOutput(output, spinner);
        }
      });

      // Handle stderr
      process.stderr?.on('data', (data: Buffer) => {
        const output = data.toString();
        stderr += output;

        if (options.stream) {
          this.streamError(output, spinner);
        }
      });

      // Handle process exit
      process.on('exit', (code) => {
        this.activeProcesses.delete(processId);

        if (spinner) {
          if (code === 0) {
            spinner.succeed(chalk.hex(KaliTheme.success)(`${tool.name} completed successfully`));
          } else {
            spinner.fail(chalk.hex(KaliTheme.danger)(`${tool.name} failed with code ${code}`));
          }
        }

        resolve({
          success: code === 0,
          tool: tool.name,
          output: stdout,
          error: stderr || undefined,
          exitCode: code || 1,
          duration: 0, // Set by caller
        });
      });

      // Handle errors
      process.on('error', (error) => {
        this.activeProcesses.delete(processId);
        
        if (spinner) {
          spinner.fail(chalk.hex(KaliTheme.danger)(`Error executing ${tool.name}`));
        }
        
        reject(error);
      });

      // Timeout handling
      if (options.timeout) {
        setTimeout(() => {
          if (this.activeProcesses.has(processId)) {
            process.kill('SIGTERM');
            if (spinner) {
              spinner.fail(chalk.hex(KaliTheme.warning)(`${tool.name} timed out`));
            }
            reject(new Error(`Execution timed out after ${options.timeout}ms`));
          }
        }, options.timeout);
      }
    });
  }

  /**
   * Stream output to terminal with formatting
   */
  private streamOutput(output: string, spinner: Ora | null): void {
    if (spinner) {
      spinner.stop();
    }

    const lines = output.split('\n');
    lines.forEach(line => {
      if (line.trim()) {
        // Color-code output based on content
        if (line.includes('open') || line.includes('found') || line.includes('success')) {
          console.log(chalk.hex(KaliTheme.success)('  ' + line));
        } else if (line.includes('error') || line.includes('failed')) {
          console.log(chalk.hex(KaliTheme.danger)('  ' + line));
        } else if (line.includes('warning')) {
          console.log(chalk.hex(KaliTheme.warning)('  ' + line));
        } else {
          console.log(chalk.hex(KaliTheme.foreground)('  ' + line));
        }
      }
    });

    if (spinner) {
      spinner.start();
    }
  }

  /**
   * Stream error output
   */
  private streamError(output: string, spinner: Ora | null): void {
    if (spinner) {
      spinner.stop();
    }

    const lines = output.split('\n');
    lines.forEach(line => {
      if (line.trim()) {
        console.log(chalk.hex(KaliTheme.danger)('  [!] ' + line));
      }
    });

    if (spinner) {
      spinner.start();
    }
  }

  /**
   * Parse tool output based on format
   */
  private async parseOutput(output: string, format: string, tool: KaliTool): Promise<any> {
    try {
      // Tool-specific parsers
      switch (tool.name) {
        case 'nmap':
          return this.parseNmapOutput(output, format);
        case 'nikto':
          return this.parseNiktoOutput(output, format);
        case 'nuclei':
          return this.parseNucleiOutput(output);
        default:
          // Generic parsing
          if (format === 'json') {
            return JSON.parse(output);
          } else if (format === 'xml') {
            return this.parseXML(output);
          }
          return output;
      }
    } catch (error) {
      console.warn(chalk.hex(KaliTheme.warning)(`${StatusIndicators.WARNING} Failed to parse ${format} output`));
      return output;
    }
  }

  /**
   * Parse nmap output (XML or plain text)
   */
  private parseNmapOutput(output: string, format: string): any {
    if (format === 'xml' || output.includes('<?xml')) {
      return this.parseNmapXML(output);
    }
    
    // Parse plain text output
    const hosts: any[] = [];
    const lines = output.split('\n');
    let currentHost: any = null;

    for (const line of lines) {
      // Match host line: Nmap scan report for example.com (93.184.216.34)
      const hostMatch = line.match(/Nmap scan report for ([\w\.\-]+)(\s+\(([\d\.]+)\))?/);
      if (hostMatch) {
        if (currentHost) hosts.push(currentHost);
        currentHost = {
          hostname: hostMatch[1],
          ip: hostMatch[3] || hostMatch[1],
          ports: [],
        };
        continue;
      }

      // Match port line: 80/tcp open http nginx
      const portMatch = line.match(/(\d+)\/(tcp|udp)\s+(open|closed|filtered)\s+([\w\-]+)?/);
      if (portMatch && currentHost) {
        currentHost.ports.push({
          port: portMatch[1],
          protocol: portMatch[2],
          state: portMatch[3],
          service: portMatch[4] || 'unknown',
        });
      }
    }

    if (currentHost) hosts.push(currentHost);
    return { hosts };
  }

  /**
   * Parse nmap XML output using fast-xml-parser
   */
  private parseNmapXML(xml: string): any {
    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
    });

    const result = parser.parse(xml);
    const nmaprun = result.nmaprun || {};
    const hosts: any[] = [];

    // Handle single or multiple hosts
    const hostData = Array.isArray(nmaprun.host) ? nmaprun.host : [nmaprun.host];

    for (const host of hostData.filter(Boolean)) {
      const addresses = Array.isArray(host.address) ? host.address : [host.address];
      const ipv4 = addresses.find((a: any) => a?.['@_addrtype'] === 'ipv4');
      
      const ports: any[] = [];
      if (host.ports?.port) {
        const portData = Array.isArray(host.ports.port) ? host.ports.port : [host.ports.port];
        
        for (const port of portData) {
          ports.push({
            port: port['@_portid'],
            protocol: port['@_protocol'],
            state: port.state?.['@_state'] || 'unknown',
            service: port.service?.['@_name'] || 'unknown',
            version: port.service?.['@_version'] || undefined,
          });
        }
      }

      hosts.push({
        ip: ipv4?.['@_addr'] || 'unknown',
        hostname: host.hostnames?.hostname?.['@_name'] || undefined,
        ports,
      });
    }

    return { hosts };
  }

  /**
   * Parse nikto output (JSON or text)
   */
  private parseNiktoOutput(output: string, format: string): any {
    if (format === 'json' || output.trim().startsWith('{')) {
      try {
        return JSON.parse(output);
      } catch {
        // Fall through to text parsing
      }
    }

    // Parse text output
    const findings: any[] = [];
    const lines = output.split('\n');
    let target = '';

    for (const line of lines) {
      // Extract target
      const targetMatch = line.match(/\+ Target IP:\s+([\d\.]+)/);
      if (targetMatch) {
        target = targetMatch[1];
        continue;
      }

      // Extract findings (lines starting with +)
      if (line.trim().startsWith('+') && !line.includes('Target IP')) {
        const finding = line.substring(line.indexOf('+') + 1).trim();
        
        // Try to extract OSVDB ID
        const osvdbMatch = finding.match(/OSVDB-(\d+)/);
        
        findings.push({
          description: finding,
          osvdb: osvdbMatch ? osvdbMatch[1] : undefined,
          severity: this.categorizeSeverity(finding),
        });
      }
    }

    return { target, findings };
  }

  /**
   * Parse nuclei JSON output
   */
  private parseNucleiOutput(output: string): any {
    // Nuclei outputs JSONL (one JSON object per line)
    const findings: any[] = [];
    const lines = output.split('\n').filter(line => line.trim());

    for (const line of lines) {
      try {
        const finding = JSON.parse(line);
        findings.push({
          template: finding['template-id'],
          name: finding.info?.name,
          severity: finding.info?.severity,
          host: finding.host,
          matchedAt: finding['matched-at'],
          extractedResults: finding['extracted-results'],
          type: finding.type,
        });
      } catch {
        // Skip non-JSON lines
      }
    }

    return { findings };
  }

  /**
   * Generic XML parser
   */
  private parseXML(xml: string): any {
    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
    });
    return parser.parse(xml);
  }

  /**
   * Categorize severity based on keywords
   */
  private categorizeSeverity(text: string): string {
    const lower = text.toLowerCase();
    if (lower.includes('critical') || lower.includes('exploit')) return 'critical';
    if (lower.includes('high') || lower.includes('vulnerable')) return 'high';
    if (lower.includes('medium') || lower.includes('warning')) return 'medium';
    if (lower.includes('low') || lower.includes('info')) return 'low';
    return 'info';
  }

  /**
   * Get AI analysis of results
   */
  private async getAIAnalysis(result: ToolResult, tool: KaliTool): Promise<string> {
    // This will integrate with the backend AI service
    // For now, return a placeholder
    return `AI analysis of ${tool.name} results would appear here`;
  }

  /**
   * Create error result
   */
  private errorResult(tool: string, message: string, startTime: number): ToolResult {
    return {
      success: false,
      tool,
      output: '',
      error: message,
      duration: Date.now() - startTime,
      exitCode: 1,
    };
  }

  /**
   * Cancel a running process
   */
  cancelAll(): void {
    this.activeProcesses.forEach(process => {
      process.kill('SIGTERM');
    });
    this.activeProcesses.clear();
  }

  /**
   * Get active process count
   */
  getActiveCount(): number {
    return this.activeProcesses.size;
  }
}

// Singleton instance
let executorInstance: ToolExecutor | null = null;

export function getToolExecutor(): ToolExecutor {
  if (!executorInstance) {
    executorInstance = new ToolExecutor();
  }
  return executorInstance;
}

