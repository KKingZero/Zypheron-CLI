/**
 * Bruteforce Command - Credential Attacks
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { KaliTheme } from '../ui/themes/kali';
import { showInfo } from '../ui/components/banner';

export function bruteforceCommand(program: Command): void {
  program
    .command('bruteforce')
    .description('Credential attacks (hydra, john, hashcat)')
    .argument('[target]', 'Target to attack')
    .option('--type <type>', 'Attack type (ssh, http, hash)')
    .option('--users <file>', 'User list file')
    .option('--passwords <file>', 'Password list file')
    .action((target, options) => {
      console.log(chalk.hex(KaliTheme.primary)(`\nBruteforce: ${target}\n`));
      showInfo('This would integrate with hydra, john, and hashcat');
    });
}

