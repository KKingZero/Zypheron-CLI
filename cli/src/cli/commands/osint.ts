/**
 * OSINT Command - Open Source Intelligence
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { KaliTheme } from '../ui/themes/kali';
import { showInfo } from '../ui/components/banner';

export function osintCommand(program: Command): void {
  program
    .command('osint')
    .description('OSINT operations (theHarvester, recon-ng)')
    .argument('[target]', 'Target to investigate')
    .option('--email', 'Email harvesting')
    .option('--username', 'Username search')
    .action((target, options) => {
      console.log(chalk.hex(KaliTheme.primary)(`\nOSINT: ${target}\n`));
      showInfo('This would use theHarvester and other OSINT tools');
    });
}

