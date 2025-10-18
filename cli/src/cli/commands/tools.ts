/**
 * Tools Command - Manage Kali Tools
 */

import { Command } from 'commander';
import chalk from 'chalk';
import Table from 'cli-table3';
import inquirer from 'inquirer';
import ora from 'ora';
import { exec } from 'child_process';
import { promisify } from 'util';
import { KaliTheme, Icons } from '../ui/themes/kali';
import { showInfo, showSuccess, showError, showWarning, showToolStatus } from '../ui/components/banner';
import { getToolManager, ToolCategory } from '../core/kali-tools';

const execAsync = promisify(exec);

export function toolsCommand(program: Command): void {
  const tools = program
    .command('tools')
    .description('Manage and check Kali security tools');

  tools
    .command('check')
    .description('Check installed tools')
    .option('-c, --category <category>', 'Filter by category')
    .action(async (options) => {
      await checkTools(options);
    });

  tools
    .command('list')
    .description('List all available tools')
    .option('-c, --category <category>', 'Filter by category')
    .option('--installed', 'Show only installed tools')
    .option('--missing', 'Show only missing tools')
    .action(async (options) => {
      await listTools(options);
    });

  tools
    .command('info <tool>')
    .description('Get information about a specific tool')
    .action(async (toolName) => {
      await toolInfo(toolName);
    });

  tools
    .command('suggest <task>')
    .description('Suggest best tool for a task')
    .action(async (task) => {
      await suggestTool(task);
    });

  tools
    .command('install <tool>')
    .description('Install a specific tool')
    .option('-y, --yes', 'Skip confirmation prompt')
    .action(async (toolName, options) => {
      await installTool(toolName, options);
    });

  tools
    .command('install-all')
    .description('Install all missing tools')
    .option('-y, --yes', 'Skip confirmation prompt')
    .option('--critical-only', 'Install only critical priority tools')
    .option('--high-priority', 'Install critical and high priority tools')
    .action(async (options) => {
      await installAllTools(options);
    });
}

async function checkTools(options: any): Promise<void> {
  showInfo('Checking installed security tools...\n');
  
  const toolManager = getToolManager();
  const allTools = await toolManager.detectTools();
  
  let tools = allTools;
  if (options.category) {
    tools = tools.filter(t => t.category === options.category);
  }
  
  showToolStatus(tools.map(t => ({
    name: t.name,
    installed: t.installed,
    version: t.version,
  })));

  const stats = toolManager.getStats();
  
  console.log(chalk.hex(KaliTheme.info)('\nStatistics:'));
  console.log(`  Total:    ${stats.total}`);
  console.log(`  Installed: ${chalk.hex(KaliTheme.success)(stats.installed.toString())}`);
  console.log(`  Missing:   ${chalk.hex(KaliTheme.danger)(stats.missing.toString())}`);
  
  if (stats.critical > 0) {
    console.log(`  Critical Missing: ${chalk.hex(KaliTheme.danger).bold(stats.critical.toString())}`);
  }
  if (stats.high > 0) {
    console.log(`  High Priority Missing: ${chalk.hex(KaliTheme.warning)(stats.high.toString())}`);
  }
  
  console.log();
}

async function listTools(options: any): Promise<void> {
  const toolManager = getToolManager();
  await toolManager.detectTools();
  
  let tools = toolManager.getAllTools();
  
  if (options.category) {
    tools = tools.filter(t => t.category === options.category);
  }
  
  if (options.installed) {
    tools = tools.filter(t => t.installed);
  } else if (options.missing) {
    tools = tools.filter(t => !t.installed);
  }

  const table = new Table({
    head: [
      chalk.hex(KaliTheme.primary)('Tool'),
      chalk.hex(KaliTheme.primary)('Category'),
      chalk.hex(KaliTheme.primary)('Status'),
      chalk.hex(KaliTheme.primary)('Priority'),
      chalk.hex(KaliTheme.primary)('Version'),
    ],
    style: {
      head: [],
      border: [chalk.hex(KaliTheme.border)],
    },
  });

  tools.forEach(tool => {
    const status = tool.installed
      ? chalk.hex(KaliTheme.success)(`${Icons.success} Installed`)
      : chalk.hex(KaliTheme.danger)(`${Icons.cross} Missing`);
    
    const priority = tool.priority === 'critical'
      ? chalk.hex(KaliTheme.critical)(tool.priority)
      : tool.priority === 'high'
      ? chalk.hex(KaliTheme.high)(tool.priority)
      : chalk.hex(KaliTheme.muted)(tool.priority);
    
    table.push([
      chalk.hex(KaliTheme.accent)(tool.name),
      tool.category,
      status,
      priority,
      tool.version || chalk.hex(KaliTheme.muted)('N/A'),
    ]);
  });

  console.log(table.toString());
  console.log();
}

async function toolInfo(toolName: string): Promise<void> {
  const toolManager = getToolManager();
  await toolManager.detectTools();
  
  const tool = toolManager.getTool(toolName);
  
  if (!tool) {
    console.log(chalk.hex(KaliTheme.danger)(`Tool '${toolName}' not found`));
    return;
  }

  console.log();
  console.log(chalk.hex(KaliTheme.primary).bold(`╔═══ ${tool.name.toUpperCase()} ${'═'.repeat(50 - tool.name.length)}╗`));
  console.log(chalk.hex(KaliTheme.primary).bold('╚' + '═'.repeat(58) + '╝'));
  console.log();
  
  console.log(chalk.hex(KaliTheme.accent)('Description:'));
  console.log(`  ${tool.description}`);
  console.log();
  
  console.log(chalk.hex(KaliTheme.accent)('Status:'));
  const status = tool.installed
    ? chalk.hex(KaliTheme.success)(`${Icons.success} Installed`)
    : chalk.hex(KaliTheme.danger)(`${Icons.cross} Not Installed`);
  console.log(`  ${status}`);
  
  if (tool.version) {
    console.log(chalk.hex(KaliTheme.accent)('Version:'));
    console.log(`  ${tool.version}`);
  }
  console.log();
  
  console.log(chalk.hex(KaliTheme.accent)('Category:'));
  console.log(`  ${tool.category}`);
  console.log();
  
  console.log(chalk.hex(KaliTheme.accent)('Priority:'));
  console.log(`  ${tool.priority}`);
  console.log();
  
  console.log(chalk.hex(KaliTheme.accent)('Required For:'));
  console.log(`  ${tool.requiredFor.join(', ')}`);
  console.log();
  
  if (!tool.installed) {
    console.log(chalk.hex(KaliTheme.accent)('Installation:'));
    console.log(`  ${tool.installCmd}`);
    console.log();
  }
  
  if (tool.aliases.length > 0) {
    console.log(chalk.hex(KaliTheme.accent)('Aliases:'));
    console.log(`  ${tool.aliases.join(', ')}`);
    console.log();
  }
}

async function suggestTool(task: string): Promise<void> {
  const toolManager = getToolManager();
  await toolManager.detectTools();
  
  const tool = toolManager.suggestTool(task);
  
  if (!tool) {
    console.log(chalk.hex(KaliTheme.warning)(`No tool found for task: ${task}`));
    console.log(chalk.hex(KaliTheme.info)('Available tasks: scan, exploit, bruteforce, recon, web, osint, wireless'));
    return;
  }

  console.log();
  console.log(chalk.hex(KaliTheme.primary)(`${Icons.robot} Best tool for '${task}':`));
  console.log();
  console.log(chalk.hex(KaliTheme.accent).bold(tool.name));
  console.log(chalk.hex(KaliTheme.foreground)(tool.description));
  console.log();
  
  if (tool.installed) {
    showSuccess(`${tool.name} is installed and ready to use`);
    console.log();
    console.log(chalk.hex(KaliTheme.info)(`Run: ${chalk.hex(KaliTheme.accent).bold(`zypheron ${task} --tool ${tool.name}`)}`));
  } else {
    console.log(chalk.hex(KaliTheme.warning)(`${tool.name} is not installed`));
    console.log(chalk.hex(KaliTheme.info)('Install with:'));
    console.log(`  ${chalk.hex(KaliTheme.accent)(tool.installCmd)}`));
  }
  console.log();
}

