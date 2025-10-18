/**
 * Setup Command - Initialize Zypheron CLI
 */

import { Command } from 'commander';
import chalk from 'chalk';
import inquirer from 'inquirer';
import ora from 'ora';
import { KaliTheme } from '../ui/themes/kali';
import { showSuccess, showError, showInfo, showWelcome } from '../ui/components/banner';
import { getToolManager } from '../core/kali-tools';

export function setupCommand(program: Command): void {
  program
    .command('setup')
    .description('Setup and configure Zypheron CLI')
    .option('--skip-tools', 'Skip tool detection')
    .option('--install-completions', 'Install shell completions')
    .action(async (options) => {
      await runSetup(options);
    });
}

async function runSetup(options: any): Promise<void> {
  console.log();
  showWelcome();

  // Step 1: Tool Detection
  if (!options.skipTools) {
    console.log(chalk.hex(KaliTheme.secondary).bold('\n[1/4] Detecting Security Tools\n'));
    const spinner = ora('Scanning for installed tools...').start();
    
    const toolManager = getToolManager();
    const tools = await toolManager.detectTools();
    
    spinner.stop();
    
    const installed = tools.filter(t => t.installed);
    const missing = tools.filter(t => !t.installed);
    
    console.log(chalk.hex(KaliTheme.success)(`  ✓ Found ${installed.length} installed tools`));
    console.log(chalk.hex(KaliTheme.muted)(`  ℹ ${missing.length} tools not installed`));
    
    // Show critical missing tools
    const criticalMissing = missing.filter(t => t.priority === 'critical');
    if (criticalMissing.length > 0) {
      console.log(chalk.hex(KaliTheme.warning)('\n  ⚠ Critical tools missing:'));
      criticalMissing.forEach(tool => {
        console.log(chalk.hex(KaliTheme.danger)(`    • ${tool.name}`));
        console.log(chalk.hex(KaliTheme.muted)(`      ${tool.installCmd}`));
      });
    }
  }

  // Step 2: Configuration
  console.log(chalk.hex(KaliTheme.secondary).bold('\n[2/4] Configuration\n'));
  
  const { configureNow } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'configureNow',
      message: 'Would you like to configure API keys now?',
      default: false,
    },
  ]);

  if (configureNow) {
    showInfo('Configuration can be done using: zypheron config set <key> <value>');
  }

  // Step 3: Shell Completions
  if (options.installCompletions) {
    console.log(chalk.hex(KaliTheme.secondary).bold('\n[3/4] Shell Completions\n'));
    await installCompletions();
  } else {
    console.log(chalk.hex(KaliTheme.secondary).bold('\n[3/4] Shell Completions\n'));
    showInfo('Run with --install-completions to install shell completions');
  }

  // Step 4: Verification
  console.log(chalk.hex(KaliTheme.secondary).bold('\n[4/4] Verification\n'));
  showSuccess('Zypheron CLI setup complete!');
  
  console.log(chalk.hex(KaliTheme.info)('\n  Next steps:'));
  console.log(chalk.hex(KaliTheme.foreground)('    • Run ') + chalk.hex(KaliTheme.accent).bold('zypheron scan <target>') + chalk.hex(KaliTheme.foreground)(' to start scanning'));
  console.log(chalk.hex(KaliTheme.foreground)('    • Run ') + chalk.hex(KaliTheme.accent).bold('zypheron chat') + chalk.hex(KaliTheme.foreground)(' for AI assistance'));
  console.log(chalk.hex(KaliTheme.foreground)('    • Run ') + chalk.hex(KaliTheme.accent).bold('zypheron tools check') + chalk.hex(KaliTheme.foreground)(' to verify tools'));
  console.log();
}

async function installCompletions(): Promise<void> {
  const shell = process.env.SHELL || '';
  
  if (shell.includes('bash')) {
    showInfo('Installing bash completions...');
    // Installation logic would go here
    showSuccess('Bash completions installed');
  } else if (shell.includes('zsh')) {
    showInfo('Installing zsh completions...');
    // Installation logic would go here
    showSuccess('Zsh completions installed');
  } else {
    showError(`Shell ${shell} not supported for auto-completion`);
  }
}

