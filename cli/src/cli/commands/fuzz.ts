/**
 * Fuzz Command - Web Fuzzing
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { KaliTheme } from '../ui/themes/kali';
import { showInfo } from '../ui/components/banner';

export function fuzzCommand(program: Command): void {
  program
    .command('fuzz')
    .description('Web fuzzing (ffuf, wfuzz)')
    .argument('[url]', 'URL to fuzz')
    .option('-w, --wordlist <file>', 'Wordlist file')
    .action((url, options) => {
      console.log(chalk.hex(KaliTheme.primary)(`\nFuzzing: ${url}\n`));
      showInfo('This would use ffuf or wfuzz for fuzzing');
    });
}

