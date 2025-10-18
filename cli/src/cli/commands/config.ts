/**
 * Config Command - Configuration Management
 */

import { Command } from 'commander';
import chalk from 'chalk';
import Conf from 'conf';
import inquirer from 'inquirer';
import { KaliTheme } from '../ui/themes/kali';
import { showSuccess, showError, showInfo } from '../ui/components/banner';

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

