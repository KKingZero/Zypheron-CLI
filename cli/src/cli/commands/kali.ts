/**
 * Kali Command - Kali Linux Integration & Management
 */

import { Command } from 'commander';
import chalk from 'chalk';
import inquirer from 'inquirer';
import Table from 'cli-table3';
import { KaliTheme, StatusIndicators } from '../ui/themes/kali';
import { showInfo, showSuccess, showError, showWarning } from '../ui/components/banner';
import { getKaliIntegration } from '../core/kali-integration';

export function kaliCommand(program: Command): void {
  const kali = program
    .command('kali')
    .description('Kali Linux integration and management');

  kali
    .command('detect')
    .description('Detect Kali Linux environment')
    .action(async () => {
      await detectEnvironment();
    });

  kali
    .command('info')
    .description('Show detailed environment information')
    .action(async () => {
      await showEnvironmentInfo();
    });

  kali
    .command('metapackages')
    .description('List Kali metapackages')
    .option('--installed', 'Show only installed packages')
    .option('--available', 'Show only available packages')
    .option('--category <category>', 'Filter by category')
    .action(async (options) => {
      await listMetapackages(options);
    });

  kali
    .command('install <package>')
    .description('Install Kali metapackage')
    .action(async (packageName) => {
      await installMetapackage(packageName);
    });

  kali
    .command('wsl')
    .description('WSL environment information and optimizations')
    .option('--optimize', 'Show WSL optimization recommendations')
    .option('--apply', 'Apply WSL optimizations (requires sudo)')
    .action(async (options) => {
      await handleWSL(options);
    });

  kali
    .command('tools')
    .description('List natively discovered tools')
    .option('--category <category>', 'Filter by category')
    .action(async (options) => {
      await listDiscoveredTools(options);
    });

  kali
    .command('wizard')
    .description('Interactive Kali setup wizard')
    .action(async () => {
      await runSetupWizard();
    });
}

async function detectEnvironment(): Promise<void> {
  const integration = getKaliIntegration();
  const env = await integration.detectEnvironment();

  console.log();
  if (env.isKali) {
    showSuccess(`Running on Kali Linux ${env.version}`);
  } else {
    showWarning('Not running on Kali Linux');
  }

  if (env.isWSL) {
    showInfo(`WSL Environment: ${env.distribution}`);
  }

  console.log(chalk.hex(KaliTheme.info)(`Found ${env.installedTools.length} pentesting tools`));
  console.log(chalk.hex(KaliTheme.info)(`Installed metapackages: ${env.metapackages.filter(m => m.installed).length}`));
  console.log();
}

async function showEnvironmentInfo(): Promise<void> {
  const integration = getKaliIntegration();
  let env = integration.getEnvironment();
  
  if (!env) {
    env = await integration.detectEnvironment();
  }

  console.log();
  console.log(chalk.hex(KaliTheme.primary).bold('═══ KALI LINUX ENVIRONMENT ═══════════════════════════'));
  console.log();

  console.log(chalk.hex(KaliTheme.accent).bold('System Information:'));
  console.log(`  OS: ${env.isKali ? chalk.hex(KaliTheme.success)('Kali Linux ✓') : chalk.hex(KaliTheme.warning)('Other Linux')}`);
  if (env.version) {
    console.log(`  Version: ${chalk.hex(KaliTheme.foreground)(env.version)}`);
  }
  console.log(`  WSL: ${env.isWSL ? chalk.hex(KaliTheme.success)('Yes ✓') : 'No'}`);
  if (env.isWSL && env.distribution) {
    console.log(`  Distribution: ${chalk.hex(KaliTheme.foreground)(env.distribution)}`);
  }
  console.log();

  const installedMetapackages = env.metapackages.filter(m => m.installed);
  console.log(chalk.hex(KaliTheme.accent).bold('Metapackages:'));
  console.log(`  Installed: ${chalk.hex(KaliTheme.success)(installedMetapackages.length)} / ${env.metapackages.length}`);
  if (installedMetapackages.length > 0) {
    installedMetapackages.slice(0, 5).forEach(pkg => {
      console.log(`    ${chalk.hex(KaliTheme.success)('✓')} ${pkg.name}`);
    });
    if (installedMetapackages.length > 5) {
      console.log(`    ... and ${installedMetapackages.length - 5} more`);
    }
  }
  console.log();

  console.log(chalk.hex(KaliTheme.accent).bold('Discovered Tools:'));
  console.log(`  Total: ${chalk.hex(KaliTheme.success)(env.installedTools.length)}`);
  if (env.installedTools.length > 0) {
    const toolsPreview = env.installedTools.slice(0, 10).join(', ');
    console.log(`  ${chalk.hex(KaliTheme.muted)(toolsPreview)}`);
    if (env.installedTools.length > 10) {
      console.log(`  ${chalk.hex(KaliTheme.muted)(`... and ${env.installedTools.length - 10} more`)}`);
    }
  }
  console.log();
}

async function listMetapackages(options: any): Promise<void> {
  const integration = getKaliIntegration();
  let env = integration.getEnvironment();
  
  if (!env) {
    env = await integration.detectEnvironment();
  }

  let metapackages = env.metapackages;

  // Filter by installation status
  if (options.installed) {
    metapackages = metapackages.filter(m => m.installed);
  } else if (options.available) {
    metapackages = metapackages.filter(m => !m.installed);
  }

  // Filter by category
  if (options.category) {
    metapackages = metapackages.filter(m => m.category === options.category);
  }

  console.log();
  console.log(chalk.hex(KaliTheme.primary).bold(`═══ KALI METAPACKAGES (${metapackages.length}) ═══════════════════`));
  console.log();

  const table = new Table({
    head: [
      chalk.hex(KaliTheme.primary)('Package'),
      chalk.hex(KaliTheme.primary)('Category'),
      chalk.hex(KaliTheme.primary)('Status'),
      chalk.hex(KaliTheme.primary)('Description'),
    ],
    colWidths: [35, 12, 12, 40],
    style: { head: [], border: [] },
    wordWrap: true,
  });

  metapackages.forEach(pkg => {
    table.push([
      chalk.hex(KaliTheme.accent)(pkg.name),
      chalk.hex(KaliTheme.muted)(pkg.category),
      pkg.installed 
        ? chalk.hex(KaliTheme.success)('✓ Installed')
        : chalk.hex(KaliTheme.warning)('Available'),
      chalk.hex(KaliTheme.foreground)(pkg.description),
    ]);
  });

  console.log(table.toString());
  console.log();

  if (!options.installed && !options.available) {
    const installed = env.metapackages.filter(m => m.installed).length;
    const available = env.metapackages.filter(m => !m.installed).length;
    console.log(chalk.hex(KaliTheme.info)(`Installed: ${installed} | Available: ${available}`));
    console.log();
  }

  showInfo('Install a metapackage: zypheron kali install <package-name>');
  console.log();
}

async function installMetapackage(packageName: string): Promise<void> {
  const integration = getKaliIntegration();
  let env = integration.getEnvironment();
  
  if (!env) {
    env = await integration.detectEnvironment();
  }

  // Check if package exists
  const pkg = env.metapackages.find(m => m.name === packageName);
  if (!pkg) {
    showError(`Metapackage '${packageName}' not found`);
    console.log();
    showInfo('List available packages: zypheron kali metapackages');
    return;
  }

  if (pkg.installed) {
    showInfo(`${packageName} is already installed`);
    return;
  }

  // Confirm installation
  console.log();
  console.log(chalk.hex(KaliTheme.accent).bold(`Installing: ${packageName}`));
  console.log(chalk.hex(KaliTheme.foreground)(`Description: ${pkg.description}`));
  console.log(chalk.hex(KaliTheme.foreground)(`Category: ${pkg.category}`));
  console.log();

  const { confirm } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'confirm',
      message: chalk.hex(KaliTheme.warning)('This will install packages using apt. Continue?'),
      default: false,
    },
  ]);

  if (!confirm) {
    showWarning('Installation cancelled');
    return;
  }

  // Install
  const success = await integration.installMetapackage(packageName);
  
  if (success) {
    showSuccess(`${packageName} installed successfully!`);
    console.log();
    showInfo('Run "zypheron tools detect" to update tool list');
  }
}

async function handleWSL(options: any): Promise<void> {
  const integration = getKaliIntegration();
  let env = integration.getEnvironment();
  
  if (!env) {
    env = await integration.detectEnvironment();
  }

  if (!env.isWSL) {
    showWarning('Not running in WSL environment');
    return;
  }

  console.log();
  console.log(chalk.hex(KaliTheme.primary).bold('═══ WSL ENVIRONMENT ═══════════════════════════════════'));
  console.log();

  console.log(chalk.hex(KaliTheme.accent).bold('WSL Information:'));
  console.log(`  Distribution: ${chalk.hex(KaliTheme.foreground)(env.distribution || 'Unknown')}`);
  console.log(`  Version: ${chalk.hex(KaliTheme.foreground)(env.wslVersion || 'Unknown')}`);
  console.log();

  if (options.optimize || options.apply) {
    const optimizations = await integration.getWSLOptimizations();

    console.log(chalk.hex(KaliTheme.accent).bold('Features:'));
    console.log(`  Interop: ${optimizations.features.interop ? chalk.hex(KaliTheme.success)('✓') : chalk.hex(KaliTheme.warning)('✗')}`);
    console.log(`  Windows PATH: ${optimizations.features.appendWindowsPath ? chalk.hex(KaliTheme.success)('✓') : chalk.hex(KaliTheme.warning)('✗')}`);
    console.log(`  Mount fstab: ${optimizations.features.mountFstab ? chalk.hex(KaliTheme.success)('✓') : chalk.hex(KaliTheme.warning)('✗')}`);
    console.log();

    if (optimizations.recommendations.length > 0) {
      console.log(chalk.hex(KaliTheme.accent).bold('Recommendations:'));
      optimizations.recommendations.forEach((rec, index) => {
        console.log(`  ${index + 1}. ${chalk.hex(KaliTheme.foreground)(rec)}`);
      });
      console.log();
    }

    if (options.apply) {
      await integration.applyWSLOptimizations();
    }
  } else {
    showInfo('Use --optimize to see optimization recommendations');
    showInfo('Use --apply to apply recommended optimizations');
  }

  console.log();
}

async function listDiscoveredTools(options: any): Promise<void> {
  const integration = getKaliIntegration();
  let env = integration.getEnvironment();
  
  if (!env) {
    env = await integration.detectEnvironment();
  }

  console.log();
  console.log(chalk.hex(KaliTheme.primary).bold(`═══ DISCOVERED TOOLS (${env.installedTools.length}) ═══════════════════`));
  console.log();

  const table = new Table({
    head: [
      chalk.hex(KaliTheme.primary)('#'),
      chalk.hex(KaliTheme.primary)('Tool'),
      chalk.hex(KaliTheme.primary)('Path'),
    ],
    colWidths: [5, 25, 50],
    style: { head: [], border: [] },
  });

  env.installedTools.forEach((tool, index) => {
    const path = env.toolPaths[tool] || 'Unknown';
    table.push([
      chalk.hex(KaliTheme.muted)((index + 1).toString()),
      chalk.hex(KaliTheme.accent)(tool),
      chalk.hex(KaliTheme.foreground)(path),
    ]);
  });

  console.log(table.toString());
  console.log();
}

async function runSetupWizard(): Promise<void> {
  console.log();
  console.log(chalk.hex(KaliTheme.primary).bold('╔═══════════════════════════════════════════════════╗'));
  console.log(chalk.hex(KaliTheme.primary).bold('║     ZYPHERON KALI LINUX SETUP WIZARD             ║'));
  console.log(chalk.hex(KaliTheme.primary).bold('╚═══════════════════════════════════════════════════╝'));
  console.log();

  const integration = getKaliIntegration();
  const env = await integration.detectEnvironment();

  // Step 1: Environment check
  console.log(chalk.hex(KaliTheme.accent).bold('Step 1: Environment Check'));
  if (!env.isKali) {
    showWarning('Not running on Kali Linux - some features may be limited');
    console.log();
  }

  if (env.isWSL) {
    showInfo('Running in WSL - optimization recommendations available');
    console.log();
    
    const { optimizeWSL } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'optimizeWSL',
        message: 'Show WSL optimization recommendations?',
        default: true,
      },
    ]);

    if (optimizeWSL) {
      await integration.applyWSLOptimizations();
    }
  }

  // Step 2: Metapackage selection
  console.log();
  console.log(chalk.hex(KaliTheme.accent).bold('Step 2: Metapackage Installation'));
  
  const installedPackages = env.metapackages.filter(m => m.installed);
  if (installedPackages.length > 0) {
    console.log(chalk.hex(KaliTheme.success)(`You have ${installedPackages.length} metapackages installed`));
  } else {
    showWarning('No Kali metapackages installed');
  }

  const { installPackages } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'installPackages',
      message: 'Install recommended metapackages?',
      default: false,
    },
  ]);

  if (installPackages) {
    const { packages } = await inquirer.prompt([
      {
        type: 'checkbox',
        name: 'packages',
        message: 'Select metapackages to install:',
        choices: [
          { name: 'kali-tools-top10 - Top 10 Kali tools', value: 'kali-tools-top10', checked: true },
          { name: 'kali-tools-information-gathering', value: 'kali-tools-information-gathering' },
          { name: 'kali-tools-web - Web application analysis', value: 'kali-tools-web' },
          { name: 'kali-tools-vulnerability', value: 'kali-tools-vulnerability' },
          { name: 'kali-tools-passwords', value: 'kali-tools-passwords' },
        ],
      },
    ]);

    for (const pkg of packages) {
      await integration.installMetapackage(pkg);
    }
  }

  // Step 3: Docker setup
  console.log();
  console.log(chalk.hex(KaliTheme.accent).bold('Step 3: Docker Fallback'));
  
  const { setupDocker } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'setupDocker',
      message: 'Pull Docker images for tool fallback?',
      default: false,
    },
  ]);

  if (setupDocker) {
    showInfo('Run: zypheron tools docker-pull');
  }

  // Complete
  console.log();
  showSuccess('Setup wizard complete!');
  console.log();
  showInfo('Run "zypheron kali info" to see your environment');
  showInfo('Run "zypheron tools detect" to update tool list');
  console.log();
}

