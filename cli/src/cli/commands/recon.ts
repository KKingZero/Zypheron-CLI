/**
 * Recon Command - Reconnaissance Operations
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import inquirer from 'inquirer';
import Table from 'cli-table3';
import { KaliTheme, StatusIndicators } from '../ui/themes/kali';
import { showInfo, showSuccess, showError } from '../ui/components/banner';
import { getApiClient } from '../core/api-client';
import { getToolManager } from '../core/kali-tools';
import { getToolExecutor } from '../core/tool-executor';
import { getSessionManager } from '../core/session-manager';

export function reconCommand(program: Command): void {
  const recon = program
    .command('recon')
    .description('Reconnaissance operations (subfinder, amass, theHarvester)')
    .argument('[target]', 'Target domain or IP');

  recon
    .command('subdomain <domain>')
    .description('Enumerate subdomains')
    .option('--tool <tool>', 'Tool to use (subfinder, amass)', 'subfinder')
    .option('--backend', 'Use backend for execution')
    .option('-o, --output <file>', 'Output file')
    .action(async (domain, options) => {
      await runSubdomainRecon(domain, options);
    });

  recon
    .command('osint <target>')
    .description('OSINT gathering (emails, users, etc.)')
    .option('--emails', 'Search for email addresses')
    .option('--users', 'Search for usernames')
    .option('--backend', 'Use backend for execution')
    .action(async (target, options) => {
      await runOSINT(target, options);
    });

  recon
    .command('dns <domain>')
    .description('DNS enumeration and analysis')
    .option('--backend', 'Use backend for execution')
    .action(async (domain, options) => {
      await runDNSRecon(domain, options);
    });

  recon
    .command('full <target>')
    .description('Full reconnaissance suite')
    .option('--backend', 'Use backend for execution')
    .option('--agent-mode', 'Enable agent mode')
    .action(async (target, options) => {
      await runFullRecon(target, options);
    });
}

async function runSubdomainRecon(domain: string, options: any): Promise<void> {
  console.log();
  console.log(chalk.hex(KaliTheme.primary).bold(`╔═══ SUBDOMAIN ENUMERATION ═══════════════════════════╗`));
  console.log(chalk.hex(KaliTheme.primary).bold(`║  Target: ${domain.padEnd(43)} ║`));
  console.log(chalk.hex(KaliTheme.primary).bold(`╚${'═'.repeat(54)}╝`));
  console.log();

  if (options.backend) {
    await runBackendRecon('subdomain_enum', domain, options);
    return;
  }

  // Local execution
  const toolManager = getToolManager();
  await toolManager.detectTools();
  
  const tool = toolManager.getTool(options.tool);
  if (!tool || !tool.installed) {
    showError(`${options.tool} is not installed`);
    console.log(chalk.hex(KaliTheme.info)(`Install with: ${chalk.hex(KaliTheme.accent)('zypheron tools install ' + options.tool)}`));
    return;
  }

  const spinner = ora({
    text: `Enumerating subdomains with ${options.tool}...`,
    color: 'cyan',
  }).start();

  try {
    const executor = getToolExecutor();
    const result = await executor.execute({
      tool: options.tool,
      args: ['-d', domain],
      target: domain,
      stream: true,
      timeout: 120000,
    });

    if (result.success) {
      spinner.succeed(chalk.hex(KaliTheme.success)('Enumeration complete'));
      
      // Parse and display subdomains
      const subdomains = result.output.split('\n').filter(line => line.trim());
      
      console.log();
      console.log(chalk.hex(KaliTheme.accent).bold(`Found ${subdomains.length} subdomains:`));
      
      const table = new Table({
        head: [chalk.hex(KaliTheme.primary)('#'), chalk.hex(KaliTheme.primary)('Subdomain')],
        style: { head: [], border: [] },
      });

      subdomains.slice(0, 20).forEach((subdomain, index) => {
        table.push([
          chalk.hex(KaliTheme.muted)((index + 1).toString()),
          chalk.hex(KaliTheme.accent)(subdomain),
        ]);
      });

      console.log(table.toString());
      
      if (subdomains.length > 20) {
        console.log(chalk.hex(KaliTheme.muted)(`\n... and ${subdomains.length - 20} more`));
      }
      
      // Save to session
      const sessionManager = await getSessionManager();
      await sessionManager.addScan({
        id: `recon-${Date.now()}`,
        tool: options.tool,
        target: domain,
        timestamp: Date.now(),
        success: true,
        result: { subdomains },
        duration: result.duration,
      });
      
      console.log();
    } else {
      spinner.fail(chalk.hex(KaliTheme.danger)('Enumeration failed'));
      showError(result.error || 'Unknown error');
    }
  } catch (error: any) {
    spinner.fail(chalk.hex(KaliTheme.danger)('Enumeration failed'));
    showError(error.message);
  }
}

async function runOSINT(target: string, options: any): Promise<void> {
  console.log();
  console.log(chalk.hex(KaliTheme.primary).bold(`╔═══ OSINT GATHERING ═════════════════════════════════╗`));
  console.log(chalk.hex(KaliTheme.primary).bold(`║  Target: ${target.padEnd(43)} ║`));
  console.log(chalk.hex(KaliTheme.primary).bold(`╚${'═'.repeat(54)}╝`));
  console.log();

  if (options.backend) {
    await runBackendRecon('osint_gather', target, options);
    return;
  }

  showInfo('Using theHarvester for OSINT gathering...');
  
  const toolManager = getToolManager();
  await toolManager.detectTools();
  
  const tool = toolManager.getTool('theharvester');
  if (!tool || !tool.installed) {
    showError('theHarvester is not installed');
    console.log(chalk.hex(KaliTheme.info)(`Install with: ${chalk.hex(KaliTheme.accent)('zypheron tools install theharvester')}`));
    return;
  }

  const spinner = ora({
    text: 'Gathering OSINT data...',
    color: 'cyan',
  }).start();

  try {
    const executor = getToolExecutor();
    const args = ['-d', target, '-b', 'all'];
    
    if (options.emails) args.push('-e');
    
    const result = await executor.execute({
      tool: 'theHarvester',
      args,
      target,
      stream: true,
      timeout: 180000,
    });

    if (result.success) {
      spinner.succeed(chalk.hex(KaliTheme.success)('OSINT gathering complete'));
      console.log();
      console.log(chalk.hex(KaliTheme.foreground)(result.output));
    } else {
      spinner.fail(chalk.hex(KaliTheme.danger)('OSINT gathering failed'));
      showError(result.error || 'Unknown error');
    }
  } catch (error: any) {
    spinner.fail(chalk.hex(KaliTheme.danger)('OSINT gathering failed'));
    showError(error.message);
  }
}

async function runDNSRecon(domain: string, options: any): Promise<void> {
  console.log();
  console.log(chalk.hex(KaliTheme.primary).bold(`╔═══ DNS ENUMERATION ═════════════════════════════════╗`));
  console.log(chalk.hex(KaliTheme.primary).bold(`║  Domain: ${domain.padEnd(43)} ║`));
  console.log(chalk.hex(KaliTheme.primary).bold(`╚${'═'.repeat(54)}╝`));
  console.log();

  if (options.backend) {
    await runBackendRecon('dns_enum', domain, options);
    return;
  }

  showInfo('Performing DNS enumeration...');
  
  // Use Node.js built-in DNS for basic enumeration
  const dns = require('dns').promises;
  const spinner = ora({
    text: 'Querying DNS records...',
    color: 'cyan',
  }).start();

  try {
    const results: any = {
      A: [],
      AAAA: [],
      MX: [],
      NS: [],
      TXT: [],
      CNAME: [],
    };

    // Query different record types
    try { results.A = await dns.resolve4(domain); } catch {}
    try { results.AAAA = await dns.resolve6(domain); } catch {}
    try { results.MX = await dns.resolveMx(domain); } catch {}
    try { results.NS = await dns.resolveNs(domain); } catch {}
    try { results.TXT = await dns.resolveTxt(domain); } catch {}
    try { results.CNAME = await dns.resolveCname(domain); } catch {}

    spinner.succeed(chalk.hex(KaliTheme.success)('DNS enumeration complete'));
    console.log();

    // Display results
    Object.entries(results).forEach(([type, records]: [string, any]) => {
      if (records && records.length > 0) {
        console.log(chalk.hex(KaliTheme.accent).bold(`${type} Records:`));
        if (type === 'MX') {
          records.forEach((mx: any) => {
            console.log(`  ${mx.priority} ${chalk.hex(KaliTheme.foreground)(mx.exchange)}`);
          });
        } else if (type === 'TXT') {
          records.forEach((txt: any) => {
            console.log(`  ${chalk.hex(KaliTheme.foreground)(txt.join(' '))}`);
          });
        } else {
          records.forEach((record: string) => {
            console.log(`  ${chalk.hex(KaliTheme.foreground)(record)}`);
          });
        }
        console.log();
      }
    });

    // Save to session
    const sessionManager = await getSessionManager();
    await sessionManager.addScan({
      id: `dns-${Date.now()}`,
      tool: 'dns-recon',
      target: domain,
      timestamp: Date.now(),
      success: true,
      result: results,
    });

  } catch (error: any) {
    spinner.fail(chalk.hex(KaliTheme.danger)('DNS enumeration failed'));
    showError(error.message);
  }
}

async function runFullRecon(target: string, options: any): Promise<void> {
  console.log();
  console.log(chalk.hex(KaliTheme.primary).bold(`╔═══ FULL RECONNAISSANCE ═════════════════════════════╗`));
  console.log(chalk.hex(KaliTheme.primary).bold(`║  Target: ${target.padEnd(43)} ║`));
  console.log(chalk.hex(KaliTheme.primary).bold(`╚${'═'.repeat(54)}╝`));
  console.log();

  if (options.backend || options.agentMode) {
    await runBackendRecon('full_recon', target, { ...options, agentMode: true });
    return;
  }

  showInfo('Running comprehensive reconnaissance...');
  console.log();

  // Run multiple recon phases
  await runDNSRecon(target, {});
  console.log();
  await runSubdomainRecon(target, { tool: 'subfinder' });
  console.log();
  await runOSINT(target, {});
  
  showSuccess('\nFull reconnaissance complete!');
}

async function runBackendRecon(operation: string, target: string, options: any): Promise<void> {
  const apiClient = getApiClient();
  const spinner = ora({
    text: 'Connecting to backend...',
    color: 'cyan',
  }).start();

  try {
    const health = await apiClient.checkAgentHealth();
    if (!health.success) {
      spinner.fail(chalk.hex(KaliTheme.danger)('Backend unavailable'));
      showError('Make sure the backend is running');
      return;
    }

    spinner.text = `Executing ${operation} via backend...`;
    
    const result = await apiClient.executeTool(operation, {
      target,
      ...options,
    }, options.agentMode || false);

    if (!result.success) {
      spinner.fail(chalk.hex(KaliTheme.danger)('Operation failed'));
      showError(result.error || 'Unknown error');
      return;
    }

    spinner.succeed(chalk.hex(KaliTheme.success)('Operation complete'));
    console.log();
    console.log(chalk.hex(KaliTheme.foreground)(JSON.stringify(result.data, null, 2)));
    console.log();

    // Save to session
    const sessionManager = await getSessionManager();
    await sessionManager.addScan({
      id: `recon-${Date.now()}`,
      tool: operation,
      target,
      timestamp: Date.now(),
      success: true,
      result: result.data,
    });

  } catch (error: any) {
    spinner.fail(chalk.hex(KaliTheme.danger)('Operation failed'));
    showError(error.message);
  }
}
