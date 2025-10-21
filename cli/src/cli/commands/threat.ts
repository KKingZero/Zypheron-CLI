/**
 * Threat Command - Threat Intelligence Analysis
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import Table from 'cli-table3';
import { KaliTheme, StatusIndicators } from '../ui/themes/kali';
import { showInfo, showSuccess, showError } from '../ui/components/banner';
import { getApiClient } from '../core/api-client';

export function threatCommand(program: Command): void {
  const threat = program
    .command('threat')
    .description('Threat intelligence analysis');

  threat
    .command('ip <address>')
    .description('Analyze IP address with threat intelligence')
    .option('-v, --verbose', 'Show detailed information')
    .action(async (address, options) => {
      await analyzeIP(address, options);
    });

  threat
    .command('domain <domain>')
    .description('Analyze domain with threat intelligence')
    .option('-v, --verbose', 'Show detailed information')
    .action(async (domain, options) => {
      await analyzeDomain(domain, options);
    });

  threat
    .command('hash <hash>')
    .description('Analyze file hash against malware databases')
    .option('-v, --verbose', 'Show detailed information')
    .action(async (hash, options) => {
      await analyzeHash(hash, options);
    });

  threat
    .command('url <url>')
    .description('Analyze URL for malicious content')
    .option('-v, --verbose', 'Show detailed information')
    .action(async (url, options) => {
      await analyzeURL(url, options);
    });
}

async function analyzeIP(address: string, options: any): Promise<void> {
  console.log();
  console.log(chalk.hex(KaliTheme.primary).bold(`╔═══ IP THREAT ANALYSIS ═══════════════════════════════╗`));
  console.log(chalk.hex(KaliTheme.primary).bold(`║  Target: ${address.padEnd(43)} ║`));
  console.log(chalk.hex(KaliTheme.primary).bold(`╚${'═'.repeat(54)}╝`));
  console.log();

  const spinner = ora({
    text: 'Querying threat intelligence databases...',
    color: 'cyan',
  }).start();

  try {
    const apiClient = getApiClient();
    const response = await apiClient.scanThreat('ip', address);

    if (!response.success) {
      spinner.fail(chalk.hex(KaliTheme.danger)('Failed to analyze IP'));
      showError(response.error || 'Unknown error');
      return;
    }

    spinner.succeed(chalk.hex(KaliTheme.success)('Analysis complete'));
    console.log();

    const data = response.data;

    // Display reputation
    if (data.reputation) {
      const rep = data.reputation;
      const threatLevel = getThreatColor(rep.score);
      
      console.log(chalk.hex(KaliTheme.accent).bold('Reputation Score:'));
      console.log(`  ${threatLevel(rep.score.toString())}/100 - ${rep.verdict || 'Unknown'}`);
      console.log();
    }

    // Display geolocation
    if (data.location) {
      console.log(chalk.hex(KaliTheme.accent).bold('Geolocation:'));
      console.log(`  Country: ${data.location.country || 'Unknown'}`);
      console.log(`  City: ${data.location.city || 'Unknown'}`);
      console.log(`  ISP: ${data.location.isp || 'Unknown'}`);
      console.log();
    }

    // Display threats
    if (data.threats && data.threats.length > 0) {
      console.log(chalk.hex(KaliTheme.danger).bold('⚠ Detected Threats:'));
      data.threats.forEach((threat: any) => {
        console.log(`  ${chalk.hex(KaliTheme.danger)('•')} ${threat.type || threat}`);
      });
      console.log();
    } else {
      console.log(chalk.hex(KaliTheme.success)(`${StatusIndicators.SUCCESS} No threats detected`));
      console.log();
    }

    // Verbose mode: show additional details
    if (options.verbose && data.details) {
      console.log(chalk.hex(KaliTheme.accent).bold('Additional Details:'));
      console.log(JSON.stringify(data.details, null, 2));
      console.log();
    }

  } catch (error: any) {
    spinner.fail(chalk.hex(KaliTheme.danger)('Analysis failed'));
    showError(error.message);
  }
}

async function analyzeDomain(domain: string, options: any): Promise<void> {
  console.log();
  console.log(chalk.hex(KaliTheme.primary).bold(`╔═══ DOMAIN THREAT ANALYSIS ═══════════════════════════╗`));
  console.log(chalk.hex(KaliTheme.primary).bold(`║  Target: ${domain.padEnd(43)} ║`));
  console.log(chalk.hex(KaliTheme.primary).bold(`╚${'═'.repeat(54)}╝`));
  console.log();

  const spinner = ora({
    text: 'Analyzing domain...',
    color: 'cyan',
  }).start();

  try {
    const apiClient = getApiClient();
    const response = await apiClient.scanThreat('domain', domain);

    if (!response.success) {
      spinner.fail(chalk.hex(KaliTheme.danger)('Failed to analyze domain'));
      showError(response.error || 'Unknown error');
      return;
    }

    spinner.succeed(chalk.hex(KaliTheme.success)('Analysis complete'));
    console.log();

    const data = response.data;

    // Display DNS records
    if (data.dns) {
      console.log(chalk.hex(KaliTheme.accent).bold('DNS Records:'));
      if (data.dns.A) console.log(`  A: ${data.dns.A.join(', ')}`);
      if (data.dns.MX) console.log(`  MX: ${data.dns.MX.join(', ')}`);
      if (data.dns.NS) console.log(`  NS: ${data.dns.NS.join(', ')}`);
      console.log();
    }

    // Display threats
    if (data.threats && data.threats.length > 0) {
      console.log(chalk.hex(KaliTheme.danger).bold('⚠ Detected Threats:'));
      data.threats.forEach((threat: any) => {
        console.log(`  ${chalk.hex(KaliTheme.danger)('•')} ${threat}`);
      });
      console.log();
    } else {
      console.log(chalk.hex(KaliTheme.success)(`${StatusIndicators.SUCCESS} No threats detected`));
      console.log();
    }

    // Verbose mode
    if (options.verbose && data.details) {
      console.log(chalk.hex(KaliTheme.accent).bold('Additional Details:'));
      console.log(JSON.stringify(data.details, null, 2));
      console.log();
    }

  } catch (error: any) {
    spinner.fail(chalk.hex(KaliTheme.danger)('Analysis failed'));
    showError(error.message);
  }
}

async function analyzeHash(hash: string, options: any): Promise<void> {
  console.log();
  console.log(chalk.hex(KaliTheme.primary).bold(`╔═══ FILE HASH ANALYSIS ═══════════════════════════════╗`));
  console.log(chalk.hex(KaliTheme.primary).bold(`║  Hash: ${hash.substring(0, 40).padEnd(43)} ║`));
  console.log(chalk.hex(KaliTheme.primary).bold(`╚${'═'.repeat(54)}╝`));
  console.log();

  const spinner = ora({
    text: 'Checking malware databases...',
    color: 'cyan',
  }).start();

  try {
    const apiClient = getApiClient();
    const response = await apiClient.scanThreat('hash', hash);

    if (!response.success) {
      spinner.fail(chalk.hex(KaliTheme.danger)('Failed to analyze hash'));
      showError(response.error || 'Unknown error');
      return;
    }

    spinner.succeed(chalk.hex(KaliTheme.success)('Analysis complete'));
    console.log();

    const data = response.data;

    // Display verdict
    if (data.verdict) {
      const verdictColor = data.verdict === 'malicious' ? KaliTheme.danger : KaliTheme.success;
      console.log(chalk.hex(KaliTheme.accent).bold('Verdict:'));
      console.log(`  ${chalk.hex(verdictColor).bold(data.verdict.toUpperCase())}`);
      console.log();
    }

    // Display detections
    if (data.detections) {
      console.log(chalk.hex(KaliTheme.accent).bold('Detections:'));
      console.log(`  ${data.detections.positive}/${data.detections.total} engines flagged this file`);
      console.log();
    }

    // Display malware families
    if (data.families && data.families.length > 0) {
      console.log(chalk.hex(KaliTheme.danger).bold('Malware Families:'));
      data.families.forEach((family: string) => {
        console.log(`  ${chalk.hex(KaliTheme.danger)('•')} ${family}`);
      });
      console.log();
    }

    // Verbose mode
    if (options.verbose && data.details) {
      console.log(chalk.hex(KaliTheme.accent).bold('Additional Details:'));
      console.log(JSON.stringify(data.details, null, 2));
      console.log();
    }

  } catch (error: any) {
    spinner.fail(chalk.hex(KaliTheme.danger)('Analysis failed'));
    showError(error.message);
  }
}

async function analyzeURL(url: string, options: any): Promise<void> {
  console.log();
  console.log(chalk.hex(KaliTheme.primary).bold(`╔═══ URL THREAT ANALYSIS ═══════════════════════════════╗`));
  console.log(chalk.hex(KaliTheme.primary).bold(`║  URL: ${url.substring(0, 43).padEnd(43)} ║`));
  console.log(chalk.hex(KaliTheme.primary).bold(`╚${'═'.repeat(54)}╝`));
  console.log();

  const spinner = ora({
    text: 'Scanning URL for threats...',
    color: 'cyan',
  }).start();

  try {
    const apiClient = getApiClient();
    const response = await apiClient.scanThreat('url', url);

    if (!response.success) {
      spinner.fail(chalk.hex(KaliTheme.danger)('Failed to analyze URL'));
      showError(response.error || 'Unknown error');
      return;
    }

    spinner.succeed(chalk.hex(KaliTheme.success)('Analysis complete'));
    console.log();

    const data = response.data;

    // Display verdict
    if (data.verdict) {
      const verdictColor = data.verdict === 'malicious' ? KaliTheme.danger : KaliTheme.success;
      console.log(chalk.hex(KaliTheme.accent).bold('Verdict:'));
      console.log(`  ${chalk.hex(verdictColor).bold(data.verdict.toUpperCase())}`);
      console.log();
    }

    // Display threats
    if (data.threats && data.threats.length > 0) {
      console.log(chalk.hex(KaliTheme.danger).bold('⚠ Detected Threats:'));
      data.threats.forEach((threat: any) => {
        console.log(`  ${chalk.hex(KaliTheme.danger)('•')} ${threat}`);
      });
      console.log();
    } else {
      console.log(chalk.hex(KaliTheme.success)(`${StatusIndicators.SUCCESS} No threats detected`));
      console.log();
    }

    // Verbose mode
    if (options.verbose && data.details) {
      console.log(chalk.hex(KaliTheme.accent).bold('Additional Details:'));
      console.log(JSON.stringify(data.details, null, 2));
      console.log();
    }

  } catch (error: any) {
    spinner.fail(chalk.hex(KaliTheme.danger)('Analysis failed'));
    showError(error.message);
  }
}

function getThreatColor(score: number): (text: string) => string {
  if (score >= 75) return (text) => chalk.hex(KaliTheme.danger)(text);
  if (score >= 50) return (text) => chalk.hex(KaliTheme.warning)(text);
  if (score >= 25) return (text) => chalk.hex(KaliTheme.info)(text);
  return (text) => chalk.hex(KaliTheme.success)(text);
}
