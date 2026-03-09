#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { Scanner } from './scanner/index.js';
import { loadPolicy } from './policy/loader.js';
import type { McpConfig, Severity } from './types.js';

const program = new Command();

program
  .name('mcp-guardian')
  .description('Security scanner & runtime proxy for MCP servers')
  .version('1.0.0');

program
  .command('scan')
  .description('Scan an MCP server configuration for vulnerabilities')
  .argument('<config>', 'Path to MCP config file (JSON)')
  .option('-f, --format <format>', 'Output format (text, json)', 'text')
  .option('--min-severity <severity>', 'Minimum severity to report', 'low')
  .action(async (configPath: string, options: { format: string; minSeverity: string }) => {
    try {
      const fullPath = resolve(configPath);
      if (!existsSync(fullPath)) {
        console.error(chalk.red(`Error: Config file not found: ${fullPath}`));
        process.exit(1);
      }

      const configContent = readFileSync(fullPath, 'utf-8');
      const config: McpConfig = JSON.parse(configContent);

      const scanner = new Scanner();
      const result = scanner.scan(config);

      const severityOrder: Record<Severity, number> = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        info: 4,
      };

      const minLevel = severityOrder[options.minSeverity as Severity] ?? 3;
      const filtered = result.vulnerabilities.filter(
        (v) => severityOrder[v.severity] <= minLevel
      );

      if (options.format === 'json') {
        console.log(JSON.stringify({ ...result, vulnerabilities: filtered }, null, 2));
        return;
      }

      // Text output
      console.log(chalk.bold('\nmcp-guardian Security Scan Report'));
      console.log('='.repeat(50));
      console.log(`Servers scanned: ${result.serverCount}`);
      console.log(`Tools scanned:   ${result.toolCount}`);
      console.log(`Risk score:      ${colorScore(result.score)}/100`);
      console.log();

      if (filtered.length === 0) {
        console.log(chalk.green('No vulnerabilities found.'));
      } else {
        console.log(chalk.bold(`Found ${filtered.length} issue(s):\n`));
        for (const vuln of filtered) {
          const icon = severityIcon(vuln.severity);
          console.log(`  ${icon} [${vuln.severity.toUpperCase()}] ${vuln.title}`);
          console.log(`    ${chalk.dim(vuln.description)}`);
          console.log(`    Category: ${vuln.category}`);
          if (vuln.server) console.log(`    Server:   ${vuln.server}`);
          if (vuln.evidence) console.log(`    Evidence: ${chalk.yellow(vuln.evidence)}`);
          console.log(`    Fix:      ${chalk.cyan(vuln.remediation)}`);
          console.log();
        }
      }

      console.log('='.repeat(50));
      console.log(
        `Summary: ${chalk.red(String(result.summary.critical))} critical, ` +
        `${chalk.yellow(String(result.summary.high))} high, ` +
        `${chalk.blue(String(result.summary.medium))} medium, ` +
        `${result.summary.low} low`
      );

      if (result.summary.critical > 0 || result.summary.high > 0) {
        process.exit(1);
      }
    } catch (error) {
      console.error(chalk.red(`Scan failed: ${(error as Error).message}`));
      process.exit(1);
    }
  });

program
  .command('init')
  .description('Initialize a default mcp-guardian policy file')
  .option('-o, --output <path>', 'Output file path', 'mcp-policy.json')
  .action((options: { output: string }) => {
    const defaultPolicy = {
      version: '1.0',
      defaultPolicy: 'deny',
      servers: {},
      globalRules: {
        maxCallsPerMinute: 60,
        blockPatterns: ['rm -rf', 'eval(', '`'],
        allowedPathPrefixes: ['/workspace/', '/tmp/'],
      },
    };

    const outputPath = resolve(options.output);
    writeFileSync(outputPath, JSON.stringify(defaultPolicy, null, 2));
    console.log(chalk.green(`Policy file created: ${outputPath}`));
  });

program
  .command('check')
  .description('Check a config against a policy file')
  .argument('<config>', 'Path to MCP config file')
  .option('-p, --policy <path>', 'Path to policy file', 'mcp-policy.json')
  .action(async (configPath: string, options: { policy: string }) => {
    try {
      const config: McpConfig = JSON.parse(readFileSync(resolve(configPath), 'utf-8'));
      const policy = loadPolicy(resolve(options.policy));

      console.log(chalk.bold('\nPolicy Compliance Check'));
      console.log('='.repeat(40));

      let violations = 0;
      for (const [serverName, serverConfig] of Object.entries(config.mcpServers)) {
        const serverPolicy = policy.servers[serverName];
        if (!serverPolicy && policy.defaultPolicy === 'deny') {
          console.log(chalk.red(`  DENIED: Server "${serverName}" not in policy`));
          violations++;
          continue;
        }
        console.log(chalk.green(`  ALLOWED: Server "${serverName}"`));
      }

      console.log('\n' + '='.repeat(40));
      if (violations > 0) {
        console.log(chalk.red(`${violations} policy violation(s) found`));
        process.exit(1);
      } else {
        console.log(chalk.green('All servers comply with policy'));
      }
    } catch (error) {
      console.error(chalk.red(`Check failed: ${(error as Error).message}`));
      process.exit(1);
    }
  });

function severityIcon(severity: Severity): string {
  switch (severity) {
    case 'critical': return chalk.bgRed.white(' CRIT ');
    case 'high':     return chalk.red(' HIGH ');
    case 'medium':   return chalk.yellow(' MED  ');
    case 'low':      return chalk.blue(' LOW  ');
    case 'info':     return chalk.dim(' INFO ');
  }
}

function colorScore(score: number): string {
  if (score >= 80) return chalk.red(String(score));
  if (score >= 50) return chalk.yellow(String(score));
  if (score >= 20) return chalk.blue(String(score));
  return chalk.green(String(score));
}

program.parse();