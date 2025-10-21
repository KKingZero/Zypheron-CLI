/**
 * Scan Command - Network and Web Security Scanning
 * Integrates with nmap, nikto, nuclei, and other Kali tools
 */

import { Command } from 'commander';
import chalk from 'chalk';
import inquirer from 'inquirer';
import ora from 'ora';
import { KaliTheme, StatusIndicators } from '../ui/themes/kali';
import { showInfo, showSuccess, showError, showTarget } from '../ui/components/banner';
import { getToolManager } from '../core/kali-tools';
import { getToolExecutor, ToolResult } from '../core/tool-executor';
import { getApiClient } from '../core/api-client';
import { getSessionManager } from '../core/session-manager';
import { getWebSocketClient, disconnectWebSocket } from '../core/websocket-client';

export function scanCommand(program: Command): void {
  const scan = program
    .command('scan')
    .description('Security scanning with Kali tools (nmap, nikto, nuclei)')
    .argument('[target]', 'Target URL, IP, or hostname')
    .option('-t, --tool <tool>', 'Specific tool to use (nmap, nikto, nuclei, masscan)')
    .option('--tools <tools>', 'Comma-separated list of tools to use')
    .option('-p, --ports <ports>', 'Port range (e.g., 1-1000, 80,443)', '1-1000')
    .option('--web', 'Focus on web application scanning')
    .option('--full', 'Full pentest suite (all tools)')
    .option('--fast', 'Quick scan (masscan + basic checks)')
    .option('--ai-guided', 'AI-guided scanning with recommendations')
    .option('--ai-analysis', 'Include AI analysis of findings')
    .option('--backend', 'Use backend agent framework for execution')
    .option('--agent-mode', 'Enable agent mode (intelligent automation)')
    .option('-o, --output <file>', 'Output file for results')
    .option('--format <format>', 'Output format (text, json, xml)', 'text')
    .option('--nmap-args <args>', 'Additional nmap arguments')
    .option('--timeout <seconds>', 'Timeout in seconds', '300')
    .option('--stream', 'Stream output in real-time', true)
    .action(async (target, options) => {
      await runScan(target, options);
    });
}

async function runScan(target: string | undefined, options: any): Promise<void> {
  console.log(chalk.hex(KaliTheme.primary).bold('\n╔═══════════════════════════════════════╗'));
  console.log(chalk.hex(KaliTheme.primary).bold('║  ZYPHERON SECURITY SCANNER           ║'));
  console.log(chalk.hex(KaliTheme.primary).bold('╚═══════════════════════════════════════╝\n'));

  // Route to backend if requested
  if (options.backend || options.agentMode) {
    await runBackendScan(target, options);
    return;
  }

  const toolManager = getToolManager();
  const toolExecutor = getToolExecutor();

  // Interactive target selection if not provided
  if (!target) {
    const answer = await inquirer.prompt([
      {
        type: 'input',
        name: 'target',
        message: 'Enter target (URL, IP, or hostname):',
        validate: (input) => {
          if (!input || input.trim().length === 0) {
            return 'Target is required';
          }
          return true;
        },
      },
    ]);
    target = answer.target;
  }

  // Validate and normalize target
  const normalizedTarget = normalizeTarget(target!);
  showTarget({
    url: target!,
    ip: normalizedTarget.ip,
    type: normalizedTarget.type,
  });

  // Detect available tools
  showInfo('Detecting available security tools...');
  await toolManager.detectTools();
  
  const stats = toolManager.getStats();
  console.log(chalk.hex(KaliTheme.secondary)(
    `  Found ${stats.installed}/${stats.total} tools installed`
  ));

  if (stats.critical > 0) {
    showError(`${stats.critical} critical tools are missing!`);
  }

  // Determine which tools to use
  const toolsToUse = determineTools(options, toolManager);
  
  if (toolsToUse.length === 0) {
    showError('No suitable tools found for this scan');
    process.exit(1);
  }

  console.log(chalk.hex(KaliTheme.info)(`\n${StatusIndicators.INFO} Scan Configuration:`));
  console.log(chalk.hex(KaliTheme.muted)('─'.repeat(60)));
  console.log(`  Tools:    ${toolsToUse.map(t => chalk.hex(KaliTheme.accent)(t)).join(', ')}`);
  console.log(`  Ports:    ${chalk.hex(KaliTheme.accent)(options.ports)}`);
  console.log(`  Timeout:  ${chalk.hex(KaliTheme.accent)(options.timeout)}s`);
  console.log(`  AI Mode:  ${options.aiGuided ? chalk.hex(KaliTheme.success)('Enabled') : chalk.hex(KaliTheme.muted)('Disabled')}`);
  console.log(chalk.hex(KaliTheme.muted)('─'.repeat(60)));

  // Confirm scan
  if (!options.yes) {
    const { confirm } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'confirm',
        message: 'Start security scan?',
        default: true,
      },
    ]);

    if (!confirm) {
      showInfo('Scan cancelled');
      return;
    }
  }

  // Execute scans
  const results: ToolResult[] = [];

  for (const toolName of toolsToUse) {
    console.log(chalk.hex(KaliTheme.primary).bold(`\n┌─[${toolName.toUpperCase()}]${'─'.repeat(55 - toolName.length)}┐`));
    
    const executionOptions = buildExecutionOptions(toolName, normalizedTarget.target, options);
    const result = await toolExecutor.execute(executionOptions);
    
    results.push(result);

    if (result.success) {
      showSuccess(`${toolName} scan completed`);
      displayResults(result, toolName);
    } else {
      showError(`${toolName} scan failed: ${result.error}`);
    }

    console.log(chalk.hex(KaliTheme.primary).bold(`└${'─'.repeat(60)}┘`));
  }

  // Summary
  console.log(chalk.hex(KaliTheme.secondary).bold('\n╔═══════════════════════════════════════╗'));
  console.log(chalk.hex(KaliTheme.secondary).bold('║  SCAN SUMMARY                        ║'));
  console.log(chalk.hex(KaliTheme.secondary).bold('╚═══════════════════════════════════════╝\n'));

  const successful = results.filter(r => r.success).length;
  const failed = results.length - successful;
  const totalTime = results.reduce((sum, r) => sum + r.duration, 0);

  console.log(`  ${chalk.hex(KaliTheme.success)('✓')} Successful scans: ${chalk.bold(successful.toString())}`);
  console.log(`  ${chalk.hex(KaliTheme.danger)('✗')} Failed scans:     ${chalk.bold(failed.toString())}`);
  console.log(`  ${chalk.hex(KaliTheme.info)('⏱')}  Total time:       ${chalk.bold((totalTime / 1000).toFixed(2) + 's')}`);

  // AI Analysis Summary
  if (options.aiAnalysis || options.aiGuided) {
    console.log(chalk.hex(KaliTheme.claudeAccent).bold('\n🤖 AI Analysis:\n'));
    console.log(chalk.hex(KaliTheme.foreground)('  Analyzing findings and generating recommendations...'));
    // This would call the backend AI service
    console.log(chalk.hex(KaliTheme.muted)('  (AI integration with backend API)'));
  }

  // Export results
  if (options.output) {
    showInfo(`Exporting results to ${options.output}...`);
    await exportResults(results, options.output, options.format);
    showSuccess('Results exported successfully');
  }

  console.log();
}

function normalizeTarget(target: string): {
  target: string;
  ip?: string;
  type: 'ip' | 'hostname' | 'url';
} {
  // Remove protocol if present
  let normalized = target.replace(/^https?:\/\//, '');
  
  // Remove path
  normalized = normalized.split('/')[0];
  
  // Determine type
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const isIP = ipRegex.test(normalized);
  
  return {
    target: normalized,
    ip: isIP ? normalized : undefined,
    type: isIP ? 'ip' : (target.includes('://') ? 'url' : 'hostname'),
  };
}

function determineTools(options: any, toolManager: any): string[] {
  const tools: string[] = [];

  if (options.tool) {
    tools.push(options.tool);
  } else if (options.tools) {
    tools.push(...options.tools.split(',').map((t: string) => t.trim()));
  } else if (options.web) {
    // Web application focus
    const webTools = ['nikto', 'nuclei', 'gobuster', 'sqlmap'];
    webTools.forEach(tool => {
      if (toolManager.isAvailable(tool)) {
        tools.push(tool);
      }
    });
  } else if (options.full) {
    // Full pentest suite
    const allTools = ['nmap', 'nikto', 'nuclei', 'gobuster', 'sqlmap'];
    allTools.forEach(tool => {
      if (toolManager.isAvailable(tool)) {
        tools.push(tool);
      }
    });
  } else if (options.fast) {
    // Fast scan
    if (toolManager.isAvailable('masscan')) {
      tools.push('masscan');
    } else if (toolManager.isAvailable('nmap')) {
      tools.push('nmap');
    }
  } else {
    // Default: nmap
    if (toolManager.isAvailable('nmap')) {
      tools.push('nmap');
    }
  }

  return tools;
}

function buildExecutionOptions(toolName: string, target: string, options: any): any {
  const baseOptions = {
    tool: toolName,
    target,
    stream: options.stream,
    timeout: parseInt(options.timeout) * 1000,
    aiAnalysis: options.aiAnalysis,
  };

  switch (toolName) {
    case 'nmap':
      return {
        ...baseOptions,
        args: buildNmapArgs(options),
        format: 'xml',
      };
    
    case 'nikto':
      return {
        ...baseOptions,
        args: ['-h', target, '-Format', 'txt'],
      };
    
    case 'nuclei':
      return {
        ...baseOptions,
        args: ['-u', target, '-json'],
        format: 'json',
      };
    
    case 'masscan':
      return {
        ...baseOptions,
        args: [target, '-p', options.ports, '--rate', '1000'],
      };
    
    default:
      return baseOptions;
  }
}

function buildNmapArgs(options: any): string[] {
  const args: string[] = [];

  // Custom args take precedence
  if (options.nmapArgs) {
    return options.nmapArgs.split(' ');
  }

  // Service detection
  args.push('-sV');
  
  // Default scripts
  args.push('-sC');
  
  // Port range
  if (options.ports) {
    args.push('-p', options.ports);
  }

  // Fast mode
  if (options.fast) {
    args.push('-T4');
  }

  // XML output for parsing
  args.push('-oX', '-');

  return args;
}

function displayResults(result: ToolResult, toolName: string): void {
  console.log();
  
  if (toolName === 'nmap' && result.parsed) {
    displayNmapResults(result.parsed);
  } else {
    // Display raw output (first 500 chars)
    const output = result.output.substring(0, 500);
    console.log(chalk.hex(KaliTheme.foreground)(output));
    
    if (result.output.length > 500) {
      console.log(chalk.hex(KaliTheme.muted)(`\n  ... (${result.output.length - 500} more characters)`));
    }
  }
}

function displayNmapResults(parsed: any): void {
  if (!parsed.hosts || parsed.hosts.length === 0) {
    console.log(chalk.hex(KaliTheme.muted)('  No hosts found'));
    return;
  }

  parsed.hosts.forEach((host: any) => {
    console.log(chalk.hex(KaliTheme.accent)(`\n  Host: ${chalk.bold(host.ip)}`));
    
    if (host.ports && host.ports.length > 0) {
      console.log(chalk.hex(KaliTheme.info)('  Ports:'));
      
      host.ports.forEach((port: any) => {
        const stateColor = port.state === 'open' ? KaliTheme.success : KaliTheme.muted;
        console.log(
          `    ${chalk.hex(stateColor)(port.state.padEnd(8))} ` +
          `${chalk.bold(port.port.padEnd(6))}/${port.protocol} ` +
          `${chalk.hex(KaliTheme.foreground)(port.service)}`
        );
      });
    }
  });
}

async function exportResults(results: ToolResult[], outputFile: string, format: string): Promise<void> {
  const fs = await import('fs/promises');
  
  let content: string;
  
  switch (format) {
    case 'json':
      content = JSON.stringify(results, null, 2);
      break;
    
    case 'xml':
      content = resultsToXML(results);
      break;
    
    default:
      content = resultsToText(results);
  }
  
  await fs.writeFile(outputFile, content, 'utf-8');
}

function resultsToText(results: ToolResult[]): string {
  let text = 'ZYPHERON SCAN RESULTS\n';
  text += '='.repeat(80) + '\n\n';
  
  results.forEach(result => {
    text += `Tool: ${result.tool}\n`;
    text += `Success: ${result.success}\n`;
    text += `Duration: ${(result.duration / 1000).toFixed(2)}s\n`;
    text += `\nOutput:\n${result.output}\n`;
    text += '-'.repeat(80) + '\n\n';
  });
  
  return text;
}

function resultsToXML(results: ToolResult[]): string {
  let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
  xml += '<zypheron-scan>\n';
  
  results.forEach(result => {
    xml += '  <scan>\n';
    xml += `    <tool>${result.tool}</tool>\n`;
    xml += `    <success>${result.success}</success>\n`;
    xml += `    <duration>${result.duration}</duration>\n`;
    xml += `    <output><![CDATA[${result.output}]]></output>\n`;
    xml += '  </scan>\n';
  });
  
  xml += '</zypheron-scan>\n';
  return xml;
}

/**
 * Run scan using backend agent framework
 */
async function runBackendScan(target: string | undefined, options: any): Promise<void> {
  const apiClient = getApiClient();
  const sessionManager = await getSessionManager();

  // Interactive target selection if not provided
  if (!target) {
    const answer = await inquirer.prompt([
      {
        type: 'input',
        name: 'target',
        message: 'Enter target (URL, IP, or hostname):',
        validate: (input) => input && input.trim().length > 0 ? true : 'Target is required',
      },
    ]);
    target = answer.target;
  }

  console.log(chalk.hex(KaliTheme.accent).bold(`🌐 Target: ${chalk.hex(KaliTheme.success)(target!)}`));
  console.log(chalk.hex(KaliTheme.info)(`${StatusIndicators.INFO} Using backend agent framework\n`));

  const spinner = ora({
    text: 'Connecting to backend...',
    color: 'cyan',
  }).start();

  try {
    // Check backend health
    const health = await apiClient.checkAgentHealth();
    if (!health.success) {
      spinner.fail(chalk.hex(KaliTheme.danger)('Backend unavailable'));
      showError('Make sure the backend is running on the configured URL');
      return;
    }
    spinner.succeed(chalk.hex(KaliTheme.success)('Connected to backend'));

    // Get AI tool recommendations if agent mode
    if (options.agentMode || options.aiGuided) {
      spinner.start('AI analyzing target and recommending tools...');
      const recommendation = await apiClient.recommendTools(
        target!,
        options.web ? 'web-scan' : 'scan',
        true
      );

      if (recommendation.success && recommendation.data?.tools) {
        spinner.succeed(chalk.hex(KaliTheme.success)('AI recommendations received'));
        console.log(chalk.hex(KaliTheme.accent).bold('\nRecommended Tools:'));
        recommendation.data.tools.forEach((tool: string, index: number) => {
          console.log(`  ${index + 1}. ${chalk.hex(KaliTheme.success)(tool)}`);
        });
        console.log();
      } else {
        spinner.warn(chalk.hex(KaliTheme.warning)('Could not get AI recommendations'));
      }
    }

    // Execute scan via backend
    spinner.start(`Executing scan on ${target}...`);
    
    const scanResult = await apiClient.executeTool(
      options.tool || 'nmap_scan',
      {
        target: target!,
        ports: options.ports,
        web: options.web,
        full: options.full,
        timeout: parseInt(options.timeout),
      },
      options.agentMode || false
    );

    if (!scanResult.success) {
      spinner.fail(chalk.hex(KaliTheme.danger)('Scan failed'));
      showError(scanResult.error || 'Unknown error');
      return;
    }

    spinner.succeed(chalk.hex(KaliTheme.success)('Scan completed'));

    // Display results
    console.log();
    console.log(chalk.hex(KaliTheme.secondary).bold('╔═══════════════════════════════════════╗'));
    console.log(chalk.hex(KaliTheme.secondary).bold('║  SCAN RESULTS                        ║'));
    console.log(chalk.hex(KaliTheme.secondary).bold('╚═══════════════════════════════════════╝\n'));

    const data = scanResult.data;

    // Display parsed results
    if (data?.result) {
      console.log(chalk.hex(KaliTheme.foreground)(JSON.stringify(data.result, null, 2)));
    }

    // Display AI analysis if available
    if (data?.aiAnalysis) {
      console.log();
      console.log(chalk.hex(KaliTheme.accent).bold('🤖 AI Analysis:'));
      console.log(chalk.hex(KaliTheme.foreground)('─'.repeat(60)));
      
      if (data.aiAnalysis.recommendations) {
        console.log(chalk.hex(KaliTheme.info).bold('\nRecommendations:'));
        data.aiAnalysis.recommendations.forEach((rec: string, index: number) => {
          console.log(`  ${index + 1}. ${rec}`);
        });
      }

      if (data.aiAnalysis.relatedTools) {
        console.log(chalk.hex(KaliTheme.info).bold('\nRelated Tools:'));
        data.aiAnalysis.relatedTools.forEach((tool: string) => {
          console.log(`  • ${chalk.hex(KaliTheme.accent)(tool)}`);
        });
      }
    }

    // Save to session history
    await sessionManager.addScan({
      id: `scan-${Date.now()}`,
      tool: options.tool || 'backend-scan',
      target: target!,
      timestamp: Date.now(),
      success: true,
      result: data,
      duration: data?.executionTime,
      aiInsights: data?.aiAnalysis ? JSON.stringify(data.aiAnalysis) : undefined,
    });

    showSuccess(`\nScan saved to history. View with: ${chalk.hex(KaliTheme.accent)('zypheron config history')}`);
    console.log();

  } catch (error: any) {
    spinner.fail(chalk.hex(KaliTheme.danger)('Scan failed'));
    showError(error.message || 'Unknown error occurred');
  }
}

