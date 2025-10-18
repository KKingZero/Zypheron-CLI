#!/usr/bin/env node

/**
 * Zypheron CLI - Main Entry Point
 * AI-Powered Penetration Testing with Kali Linux Integration
 */

import { Command } from 'commander';
import chalk from 'chalk';
import updateNotifier from 'update-notifier';
import { showBanner } from './cli/ui/components/banner';
import { KaliTheme } from './cli/ui/themes/kali';
import packageJson from '../package.json';

// Import commands
import { chatCommand } from './cli/commands/chat';
import { scanCommand } from './cli/commands/scan';
import { threatCommand } from './cli/commands/threat';
import { exploitCommand } from './cli/commands/exploit';
import { reconCommand } from './cli/commands/recon';
import { bruteforceCommand } from './cli/commands/bruteforce';
import { fuzzCommand } from './cli/commands/fuzz';
import { osintCommand } from './cli/commands/osint';
import { reportCommand } from './cli/commands/report';
import { dashboardCommand } from './cli/commands/dashboard';
import { toolsCommand } from './cli/commands/tools';
import { configCommand } from './cli/commands/config';
import { setupCommand } from './cli/commands/setup';

// Check for updates
const notifier = updateNotifier({ pkg: packageJson });
if (notifier.update) {
  notifier.notify({
    message: `Update available: ${chalk.green(notifier.update.latest)}\nRun ${chalk.cyan('npm install -g @zypheron/cli')} to update`
  });
}

// Create CLI program
const program = new Command();

program
  .name('zypheron')
  .description(chalk.hex(KaliTheme.primary)('🐍 Zypheron CLI - AI-Powered Penetration Testing Platform'))
  .version(packageJson.version, '-v, --version', 'Output the current version')
  .option('-d, --debug', 'Enable debug mode')
  .option('--no-color', 'Disable colored output')
  .option('--no-banner', 'Disable ASCII banner')
  .hook('preAction', (thisCommand) => {
    const opts = thisCommand.opts();
    
    // Show banner unless disabled
    if (opts.banner !== false && process.stdout.isTTY) {
      showBanner();
    }
    
    // Setup debug mode
    if (opts.debug) {
      process.env.DEBUG = 'zypheron:*';
    }
  });

// Register commands
chatCommand(program);
scanCommand(program);
threatCommand(program);
exploitCommand(program);
reconCommand(program);
bruteforceCommand(program);
fuzzCommand(program);
osintCommand(program);
reportCommand(program);
dashboardCommand(program);
toolsCommand(program);
configCommand(program);
setupCommand(program);

// Global error handler
process.on('uncaughtException', (error) => {
  console.error(chalk.red('[-]'), 'Uncaught Exception:', error.message);
  if (program.opts().debug) {
    console.error(error.stack);
  }
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error(chalk.red('[-]'), 'Unhandled Rejection:', reason);
  if (program.opts().debug) {
    console.error(promise);
  }
  process.exit(1);
});

// Handle Ctrl+C gracefully
process.on('SIGINT', () => {
  console.log(chalk.yellow('\n[!]'), 'Operation cancelled by user');
  process.exit(0);
});

// Parse command line arguments
program.parse(process.argv);

// Show help if no command provided
if (!process.argv.slice(2).length) {
  program.outputHelp();
}

