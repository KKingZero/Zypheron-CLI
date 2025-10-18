/**
 * Recon Command - Reconnaissance Operations
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { KaliTheme } from '../ui/themes/kali';
import { showInfo } from '../ui/components/banner';

export function reconCommand(program: Command): void {
  program
    .command('recon')
    .description('Reconnaissance operations (subfinder, amass)')
    .argument('[target]', 'Target domain')
    .option('--subdomain', 'Subdomain enumeration')
    .option('--deep', 'Deep reconnaissance')
    .action((target, options) => {
      console.log(chalk.hex(KaliTheme.primary)(`\nReconnaissance: ${target}\n`));
      showInfo('This would use subfinder, amass, and other recon tools');
    });
}

