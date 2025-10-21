/**
 * Bruteforce Command - Credential Attacks
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import inquirer from 'inquirer';
import Table from 'cli-table3';
import { KaliTheme, StatusIndicators } from '../ui/themes/kali';
import { showInfo, showSuccess, showError, showWarning } from '../ui/components/banner';
import { getApiClient } from '../core/api-client';
import { getToolManager } from '../core/kali-tools';
import { getToolExecutor } from '../core/tool-executor';
import { getSessionManager } from '../core/session-manager';

export function bruteforceCommand(program: Command): void {
  const bruteforce = program
    .command('bruteforce')
    .description('Credential attacks (hydra, john, hashcat)');

  bruteforce
    .command('ssh <target>')
    .description('SSH brute force attack')
    .option('-u, --user <user>', 'Single username')
    .option('-U, --userlist <file>', 'User list file')
    .option('-p, --password <password>', 'Single password')
    .option('-P, --passlist <file>', 'Password list file')
    .option('--port <port>', 'SSH port', '22')
    .option('--backend', 'Use backend for execution')
    .action(async (target, options) => {
      await runSSHBruteforce(target, options);
    });

  bruteforce
    .command('ftp <target>')
    .description('FTP brute force attack')
    .option('-u, --user <user>', 'Single username')
    .option('-U, --userlist <file>', 'User list file')
    .option('-p, --password <password>', 'Single password')
    .option('-P, --passlist <file>', 'Password list file')
    .option('--port <port>', 'FTP port', '21')
    .option('--backend', 'Use backend for execution')
    .action(async (target, options) => {
      await runFTPBruteforce(target, options);
    });

  bruteforce
    .command('http <url>')
    .description('HTTP form brute force')
    .option('-u, --user <user>', 'Single username')
    .option('-U, --userlist <file>', 'User list file')
    .option('-p, --password <password>', 'Single password')
    .option('-P, --passlist <file>', 'Password list file')
    .option('--form <form>', 'Form parameters')
    .option('--backend', 'Use backend for execution')
    .action(async (url, options) => {
      await runHTTPBruteforce(url, options);
    });

  bruteforce
    .command('hash <hash>')
    .description('Hash cracking with hashcat/john')
    .option('-t, --type <type>', 'Hash type (md5, sha1, sha256, etc.)')
    .option('-w, --wordlist <file>', 'Wordlist file')
    .option('--tool <tool>', 'Tool to use (hashcat, john)', 'hashcat')
    .option('--backend', 'Use backend for execution')
    .action(async (hash, options) => {
      await runHashCrack(hash, options);
    });

  bruteforce
    .command('custom <protocol> <target>')
    .description('Custom protocol brute force')
    .option('-u, --user <user>', 'Single username')
    .option('-U, --userlist <file>', 'User list file')
    .option('-p, --password <password>', 'Single password')
    .option('-P, --passlist <file>', 'Password list file')
    .option('--port <port>', 'Target port')
    .option('--backend', 'Use backend for execution')
    .action(async (protocol, target, options) => {
      await runCustomBruteforce(protocol, target, options);
    });
}

async function runSSHBruteforce(target: string, options: any): Promise<void> {
  console.log();
  console.log(chalk.hex(KaliTheme.danger).bold(`╔═══ SSH BRUTEFORCE ATTACK ═══════════════════════════╗`));
  console.log(chalk.hex(KaliTheme.danger).bold(`║  Target: ${target.padEnd(43)} ║`));
  console.log(chalk.hex(KaliTheme.danger).bold(`║  Port: ${options.port.padEnd(45)} ║`));
  console.log(chalk.hex(KaliTheme.danger).bold(`╚${'═'.repeat(54)}╝`));
  console.log();

  // Legal warning
  showWarning('⚠️  LEGAL WARNING: Only attack systems you have explicit permission to test!');
  console.log();

  const { confirm } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'confirm',
      message: chalk.hex(KaliTheme.warning)('Do you have authorization to test this target?'),
      default: false,
    },
  ]);

  if (!confirm) {
    showError('Operation cancelled - authorization required');
    return;
  }

  if (options.backend) {
    await runBackendBruteforce('ssh', target, options);
    return;
  }

  // Validate inputs
  if (!options.user && !options.userlist) {
    showError('Provide either --user or --userlist');
    return;
  }

  if (!options.password && !options.passlist) {
    showError('Provide either --password or --passlist');
    return;
  }

  // Check for hydra
  const toolManager = getToolManager();
  await toolManager.detectTools();
  
  const hydra = toolManager.getTool('hydra');
  if (!hydra || !hydra.installed) {
    showError('hydra is not installed');
    console.log(chalk.hex(KaliTheme.info)(`Install with: ${chalk.hex(KaliTheme.accent)('zypheron tools install hydra')}`));
    return;
  }

  const spinner = ora({
    text: 'Running SSH brute force attack...',
    color: 'red',
  }).start();

  try {
    const executor = getToolExecutor();
    const args = [
      '-s', options.port,
      '-t', '4', // 4 parallel tasks
    ];

    if (options.user) {
      args.push('-l', options.user);
    } else {
      args.push('-L', options.userlist);
    }

    if (options.password) {
      args.push('-p', options.password);
    } else {
      args.push('-P', options.passlist);
    }

    args.push(target, 'ssh');

    const result = await executor.execute({
      tool: 'hydra',
      args,
      target,
      stream: true,
      timeout: 300000,
    });

    if (result.success) {
      spinner.succeed(chalk.hex(KaliTheme.success)('Attack completed'));
      
      // Parse results
      const lines = result.output.split('\n');
      const credentials = lines.filter(line => 
        line.includes('login:') && line.includes('password:')
      );

      if (credentials.length > 0) {
        console.log();
        console.log(chalk.hex(KaliTheme.success).bold('✓ Found valid credentials:'));
        console.log();

        const table = new Table({
          head: [chalk.hex(KaliTheme.primary)('Username'), chalk.hex(KaliTheme.primary)('Password')],
          style: { head: [], border: [] },
        });

        credentials.forEach(cred => {
          const loginMatch = cred.match(/login:\s*(\S+)/);
          const passMatch = cred.match(/password:\s*(\S+)/);
          if (loginMatch && passMatch) {
            table.push([
              chalk.hex(KaliTheme.success)(loginMatch[1]),
              chalk.hex(KaliTheme.success)(passMatch[1]),
            ]);
          }
        });

        console.log(table.toString());
        console.log();
      } else {
        showInfo('No valid credentials found');
      }

      // Save to session
      const sessionManager = await getSessionManager();
      await sessionManager.addScan({
        id: `bruteforce-${Date.now()}`,
        tool: 'hydra-ssh',
        target,
        timestamp: Date.now(),
        success: true,
        result: { credentials: credentials.length },
        duration: result.duration,
      });

    } else {
      spinner.fail(chalk.hex(KaliTheme.danger)('Attack failed'));
      showError(result.error || 'Unknown error');
    }
  } catch (error: any) {
    spinner.fail(chalk.hex(KaliTheme.danger)('Attack failed'));
    showError(error.message);
  }
}

async function runFTPBruteforce(target: string, options: any): Promise<void> {
  console.log();
  console.log(chalk.hex(KaliTheme.danger).bold(`╔═══ FTP BRUTEFORCE ATTACK ═══════════════════════════╗`));
  console.log(chalk.hex(KaliTheme.danger).bold(`║  Target: ${target.padEnd(43)} ║`));
  console.log(chalk.hex(KaliTheme.danger).bold(`╚${'═'.repeat(54)}╝`));
  console.log();

  showWarning('⚠️  Only attack authorized targets!');
  console.log();

  if (options.backend) {
    await runBackendBruteforce('ftp', target, options);
    return;
  }

  showInfo('FTP brute force - use similar logic to SSH');
  showInfo('Run with --backend for full implementation');
}

async function runHTTPBruteforce(url: string, options: any): Promise<void> {
  console.log();
  console.log(chalk.hex(KaliTheme.danger).bold(`╔═══ HTTP BRUTEFORCE ATTACK ══════════════════════════╗`));
  console.log(chalk.hex(KaliTheme.danger).bold(`║  URL: ${url.substring(0, 46).padEnd(46)} ║`));
  console.log(chalk.hex(KaliTheme.danger).bold(`╚${'═'.repeat(54)}╝`));
  console.log();

  showWarning('⚠️  Only attack authorized targets!');
  console.log();

  if (options.backend) {
    await runBackendBruteforce('http', url, options);
    return;
  }

  showInfo('HTTP form brute force - use hydra or custom implementation');
  showInfo('Run with --backend for full implementation');
}

async function runHashCrack(hash: string, options: any): Promise<void> {
  console.log();
  console.log(chalk.hex(KaliTheme.primary).bold(`╔═══ HASH CRACKING ═══════════════════════════════════╗`));
  console.log(chalk.hex(KaliTheme.primary).bold(`║  Hash: ${hash.substring(0, 43).padEnd(43)} ║`));
  console.log(chalk.hex(KaliTheme.primary).bold(`╚${'═'.repeat(54)}╝`));
  console.log();

  if (options.backend) {
    await runBackendBruteforce('hash', hash, options);
    return;
  }

  const toolManager = getToolManager();
  await toolManager.detectTools();
  
  const tool = toolManager.getTool(options.tool);
  if (!tool || !tool.installed) {
    showError(`${options.tool} is not installed`);
    console.log(chalk.hex(KaliTheme.info)(`Install with: ${chalk.hex(KaliTheme.accent)('zypheron tools install ' + options.tool)}`));
    return;
  }

  if (!options.wordlist) {
    showError('Wordlist required (--wordlist)');
    return;
  }

  const spinner = ora({
    text: `Cracking hash with ${options.tool}...`,
    color: 'cyan',
  }).start();

  try {
    const executor = getToolExecutor();
    let args: string[] = [];

    if (options.tool === 'hashcat') {
      // Hashcat mode
      const mode = getHashcatMode(options.type);
      args = ['-m', mode, '-a', '0', hash, options.wordlist];
    } else {
      // John the Ripper
      args = ['--wordlist=' + options.wordlist, hash];
      if (options.type) {
        args.unshift('--format=' + options.type);
      }
    }

    const result = await executor.execute({
      tool: options.tool,
      args,
      stream: true,
      timeout: 600000, // 10 minutes
    });

    if (result.success) {
      spinner.succeed(chalk.hex(KaliTheme.success)('Hash cracking complete'));
      
      // Check if hash was cracked
      if (result.output.includes(':') && !result.output.includes('Not found')) {
        console.log();
        console.log(chalk.hex(KaliTheme.success).bold('✓ Hash cracked!'));
        console.log(chalk.hex(KaliTheme.foreground)(result.output));
      } else {
        showInfo('Hash not cracked with provided wordlist');
      }
    } else {
      spinner.fail(chalk.hex(KaliTheme.danger)('Hash cracking failed'));
      showError(result.error || 'Unknown error');
    }
  } catch (error: any) {
    spinner.fail(chalk.hex(KaliTheme.danger)('Hash cracking failed'));
    showError(error.message);
  }
}

async function runCustomBruteforce(protocol: string, target: string, options: any): Promise<void> {
  console.log();
  console.log(chalk.hex(KaliTheme.danger).bold(`╔═══ CUSTOM BRUTEFORCE ═══════════════════════════════╗`));
  console.log(chalk.hex(KaliTheme.danger).bold(`║  Protocol: ${protocol.padEnd(41)} ║`));
  console.log(chalk.hex(KaliTheme.danger).bold(`║  Target: ${target.padEnd(43)} ║`));
  console.log(chalk.hex(KaliTheme.danger).bold(`╚${'═'.repeat(54)}╝`));
  console.log();

  showWarning('⚠️  Only attack authorized targets!');
  console.log();

  if (options.backend) {
    await runBackendBruteforce(protocol, target, options);
    return;
  }

  showInfo(`Custom protocol: ${protocol}`);
  showInfo('Run with --backend for full implementation');
}

async function runBackendBruteforce(protocol: string, target: string, options: any): Promise<void> {
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

    spinner.text = `Starting ${protocol} brute force attack...`;
    
    const result = await apiClient.startBruteforce(protocol, target, options);

    if (!result.success) {
      spinner.fail(chalk.hex(KaliTheme.danger)('Attack failed'));
      showError(result.error || 'Unknown error');
      return;
    }

    spinner.succeed(chalk.hex(KaliTheme.success)('Attack complete'));
    console.log();
    
    const data = result.data;
    if (data?.credentials && data.credentials.length > 0) {
      console.log(chalk.hex(KaliTheme.success).bold('✓ Found valid credentials:'));
      console.log();

      const table = new Table({
        head: [chalk.hex(KaliTheme.primary)('Username'), chalk.hex(KaliTheme.primary)('Password')],
        style: { head: [], border: [] },
      });

      data.credentials.forEach((cred: any) => {
        table.push([
          chalk.hex(KaliTheme.success)(cred.username),
          chalk.hex(KaliTheme.success)(cred.password),
        ]);
      });

      console.log(table.toString());
    } else {
      showInfo('No valid credentials found');
    }
    
    console.log();

  } catch (error: any) {
    spinner.fail(chalk.hex(KaliTheme.danger)('Attack failed'));
    showError(error.message);
  }
}

function getHashcatMode(type?: string): string {
  const modes: Record<string, string> = {
    'md5': '0',
    'sha1': '100',
    'sha256': '1400',
    'sha512': '1700',
    'ntlm': '1000',
  };
  
  return type && modes[type.toLowerCase()] ? modes[type.toLowerCase()] : '0';
}
