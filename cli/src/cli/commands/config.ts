/**
 * Config Command - Configuration Management
 */

import { Command } from 'commander';
import chalk from 'chalk';
import Conf from 'conf';
import inquirer from 'inquirer';
import Table from 'cli-table3';
import { KaliTheme } from '../ui/themes/kali';
import { showSuccess, showError, showInfo } from '../ui/components/banner';
import { getSessionManager } from '../core/session-manager';

const config = new Conf({ projectName: 'zypheron-cli' });

export function configCommand(program: Command): void {
  const configCmd = program
    .command('config')
    .description('Manage Zypheron configuration');

  configCmd
    .command('set <key> <value>')
    .description('Set a configuration value')
    .action((key, value) => {
      config.set(key, value);
      showSuccess(`Set ${chalk.hex(KaliTheme.accent)(key)} = ${chalk.hex(KaliTheme.foreground)(value)}`);
    });

  configCmd
    .command('get [key]')
    .description('Get configuration value(s)')
    .action((key) => {
      if (key) {
        const value = config.get(key);
        console.log(chalk.hex(KaliTheme.accent)(key) + ': ' + chalk.hex(KaliTheme.foreground)(value || 'not set'));
      } else {
        const all = config.store;
        console.log(JSON.stringify(all, null, 2));
      }
    });

  configCmd
    .command('delete <key>')
    .description('Delete a configuration value')
    .action((key) => {
      config.delete(key);
      showSuccess(`Deleted ${chalk.hex(KaliTheme.accent)(key)}`);
    });

  configCmd
    .command('wizard')
    .description('Interactive configuration wizard')
    .action(async () => {
      await configWizard();
    });

  configCmd
    .command('path')
    .description('Show configuration file path')
    .action(() => {
      console.log(config.path);
    });

  configCmd
    .command('history')
    .description('Show scan history')
    .option('-l, --limit <number>', 'Limit number of results', '10')
    .option('-t, --tool <tool>', 'Filter by tool')
    .action(async (options) => {
      await showHistory(options);
    });

  configCmd
    .command('clear-history')
    .description('Clear scan history')
    .action(async () => {
      await clearHistory();
    });
}

async function configWizard(): Promise<void> {
  console.log(chalk.hex(KaliTheme.primary).bold('\n╔═══ CONFIGURATION WIZARD ═══════════════╗\n'));
  
  const answers = await inquirer.prompt([
    {
      type: 'input',
      name: 'apiUrl',
      message: 'Backend API URL:',
      default: config.get('api.url', 'http://localhost:3001'),
    },
    {
      type: 'input',
      name: 'openaiKey',
      message: 'OpenAI API Key:',
      default: config.get('ai.openai.apiKey'),
    },
    {
      type: 'list',
      name: 'defaultModel',
      message: 'Default AI Model:',
      choices: ['gpt-4', 'gpt-3.5-turbo', 'claude-3-opus', 'claude-3-sonnet'],
      default: config.get('ai.defaultModel', 'gpt-4'),
    },
    {
      type: 'confirm',
      name: 'colorOutput',
      message: 'Enable colored output?',
      default: config.get('output.colorize', true),
    },
  ]);

  config.set('api.url', answers.apiUrl);
  if (answers.openaiKey) {
    config.set('ai.openai.apiKey', answers.openaiKey);
  }
  config.set('ai.defaultModel', answers.defaultModel);
  config.set('output.colorize', answers.colorOutput);

  showSuccess('Configuration saved!');
  console.log(chalk.hex(KaliTheme.info)(`Config file: ${config.path}\n`));
}

async function showHistory(options: any): Promise<void> {
  const sessionManager = await getSessionManager();
  const limit = parseInt(options.limit);
  const history = sessionManager.getScanHistory(limit, options.tool);

  if (history.length === 0) {
    showInfo('No scan history found');
    return;
  }

  console.log();
  console.log(chalk.hex(KaliTheme.primary).bold('═══ SCAN HISTORY ═══'));
  console.log();

  const table = new Table({
    head: [
      chalk.hex(KaliTheme.primary)('ID'),
      chalk.hex(KaliTheme.primary)('Tool'),
      chalk.hex(KaliTheme.primary)('Target'),
      chalk.hex(KaliTheme.primary)('Status'),
      chalk.hex(KaliTheme.primary)('Date'),
      chalk.hex(KaliTheme.primary)('Duration'),
    ],
    style: {
      head: [],
      border: [],
    },
  });

  history.forEach(scan => {
    const status = scan.success
      ? chalk.hex(KaliTheme.success)('✓ Success')
      : chalk.hex(KaliTheme.danger)('✗ Failed');
    
    const date = new Date(scan.timestamp).toLocaleString();
    const duration = scan.duration ? `${(scan.duration / 1000).toFixed(1)}s` : 'N/A';

    table.push([
      chalk.hex(KaliTheme.muted)(scan.id.substring(0, 8)),
      chalk.hex(KaliTheme.accent)(scan.tool),
      scan.target,
      status,
      chalk.hex(KaliTheme.muted)(date),
      duration,
    ]);
  });

  console.log(table.toString());
  console.log();
}

async function clearHistory(): Promise<void> {
  const sessionManager = await getSessionManager();
  
  const { confirm } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'confirm',
      message: 'Clear all scan history?',
      default: false,
    },
  ]);

  if (confirm) {
    await sessionManager.clearScanHistory();
    showSuccess('Scan history cleared');
  } else {
    showInfo('Cancelled');
  }
}
