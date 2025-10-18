/**
 * Tool Executor
 * Execute Kali tools with real-time output streaming
 */

import { spawn, ChildProcess } from 'child_process';
import chalk from 'chalk';
import ora, { Ora } from 'ora';
import { KaliTheme, StatusIndicators } from '../ui/themes/kali';
import { getToolManager, KaliTool } from './kali-tools';

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
      switch (format) {
        case 'json':
          return JSON.parse(output);
        
        case 'xml':
          // For nmap XML output
          if (tool.name === 'nmap') {
            return this.parseNmapXML(output);
          }
          return output;
        
        default:
          return output;
      }
    } catch (error) {
      console.warn(chalk.hex(KaliTheme.warning)(`${StatusIndicators.WARNING} Failed to parse ${format} output`));
      return output;
    }
  }

  /**
   * Parse nmap XML output
   */
  private parseNmapXML(xml: string): any {
    // Simplified parser - in production, use fast-xml-parser
    const hosts: any[] = [];
    const hostRegex = /<host[^>]*>(.*?)<\/host>/gs;
    const matches = xml.matchAll(hostRegex);

    for (const match of matches) {
      const hostXML = match[1];
      
      // Extract IP
      const ipMatch = hostXML.match(/<address\s+addr="([^"]+)"/);
      const ip = ipMatch ? ipMatch[1] : 'unknown';

      // Extract ports
      const ports: any[] = [];
      const portRegex = /<port\s+protocol="([^"]+)"\s+portid="([^"]+)">(.*?)<\/port>/gs;
      const portMatches = hostXML.matchAll(portRegex);

      for (const portMatch of portMatches) {
        const protocol = portMatch[1];
        const portid = portMatch[2];
        const portData = portMatch[3];

        const stateMatch = portData.match(/<state\s+state="([^"]+)"/);
        const serviceMatch = portData.match(/<service\s+name="([^"]+)"/);

        ports.push({
          protocol,
          port: portid,
          state: stateMatch ? stateMatch[1] : 'unknown',
          service: serviceMatch ? serviceMatch[1] : 'unknown',
        });
      }

      hosts.push({ ip, ports });
    }

    return { hosts };
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

