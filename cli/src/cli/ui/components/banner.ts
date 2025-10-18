/**
 * Banner Component - ASCII Art & Branding
 */

import chalk from 'chalk';
import boxen from 'boxen';
import { ASCIIArt, KaliTheme } from '../themes/kali';

export function showBanner(compact = false): void {
  const logo = compact ? ASCIIArt.logoCompact : ASCIIArt.logo;
  console.log(chalk.hex(KaliTheme.primary)(logo));
}

export function showWelcome(): void {
  const welcome = boxen(
    chalk.hex(KaliTheme.primary).bold('Welcome to Zypheron CLI\n\n') +
    chalk.hex(KaliTheme.secondary)('AI-Powered Penetration Testing Platform\n') +
    chalk.hex(KaliTheme.foreground)('Integrating with Kali Linux Tools\n\n') +
    chalk.hex(KaliTheme.muted)('Type ') +
    chalk.hex(KaliTheme.accent).bold('zypheron --help') +
    chalk.hex(KaliTheme.muted)(' for available commands'),
    {
      padding: 1,
      margin: 1,
      borderStyle: 'round',
      borderColor: KaliTheme.primary,
      backgroundColor: KaliTheme.background,
    }
  );
  console.log(welcome);
}

export function showToolStatus(tools: Array<{ name: string; installed: boolean; version?: string }>): void {
  console.log(chalk.hex(KaliTheme.secondary).bold('\n[*] Tool Detection:'));
  console.log(chalk.hex(KaliTheme.muted)('─'.repeat(60)));
  
  tools.forEach(tool => {
    const status = tool.installed
      ? chalk.hex(KaliTheme.success)('✓')
      : chalk.hex(KaliTheme.danger)('✗');
    
    const version = tool.version
      ? chalk.hex(KaliTheme.muted)(` v${tool.version}`)
      : '';
    
    const name = chalk.hex(KaliTheme.foreground)(tool.name.padEnd(15));
    
    console.log(`  ${status} ${name}${version}`);
  });
  
  console.log(chalk.hex(KaliTheme.muted)('─'.repeat(60)));
}

export function showTarget(target: { url: string; ip?: string; type: string }): void {
  const box = boxen(
    `${chalk.hex(KaliTheme.accent)('Target:')} ${chalk.bold(target.url)}\n` +
    (target.ip ? `${chalk.hex(KaliTheme.accent)('IP Address:')} ${target.ip}\n` : '') +
    `${chalk.hex(KaliTheme.accent)('Type:')} ${target.type}`,
    {
      padding: { left: 2, right: 2, top: 0, bottom: 0 },
      borderStyle: 'round',
      borderColor: KaliTheme.accent,
    }
  );
  console.log('\n' + box);
}

export function showSuccess(message: string): void {
  console.log(chalk.hex(KaliTheme.success)('[+]'), message);
}

export function showError(message: string): void {
  console.log(chalk.hex(KaliTheme.danger)('[-]'), message);
}

export function showWarning(message: string): void {
  console.log(chalk.hex(KaliTheme.warning)('[!]'), message);
}

export function showInfo(message: string): void {
  console.log(chalk.hex(KaliTheme.info)('[*]'), message);
}

export function showQuestion(message: string): void {
  console.log(chalk.hex(KaliTheme.accent)('[?]'), message);
}

