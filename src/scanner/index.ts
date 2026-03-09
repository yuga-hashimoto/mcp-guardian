/**
 * Scanner orchestrator - runs all security rules against MCP configs
 */

import type { McpConfig, ScanResult, ScanRule, Vulnerability, ScanSummary, Severity } from '../types.js';
import { CommandInjectionRule } from './rules/command-injection.js';
import { PathTraversalRule } from './rules/path-traversal.js';
import { SSRFRule } from './rules/ssrf.js';
import { InsecureConfigRule } from './rules/insecure-config.js';
import { PermissionEscalationRule } from './rules/permission-escalation.js';

export class Scanner {
  private rules: ScanRule[];

  constructor(rules?: ScanRule[]) {
    this.rules = rules ?? [
      new CommandInjectionRule(),
      new PathTraversalRule(),
      new SSRFRule(),
      new InsecureConfigRule(),
      new PermissionEscalationRule(),
    ];
  }

  scan(config: McpConfig): ScanResult {
    const vulnerabilities: Vulnerability[] = [];

    for (const rule of this.rules) {
      const findings = rule.scan(config);
      vulnerabilities.push(...findings);
    }

    // Sort by severity
    const severityWeight: Record<Severity, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4,
    };
    vulnerabilities.sort((a, b) => severityWeight[a.severity] - severityWeight[b.severity]);

    const summary = this.buildSummary(vulnerabilities);
    const score = this.calculateScore(vulnerabilities);

    const serverCount = Object.keys(config.mcpServers).length;
    const toolCount = Object.values(config.mcpServers).reduce(
      (count, server) => count + (server.tools?.length ?? 0),
      0
    );

    return {
      vulnerabilities,
      score,
      scannedAt: new Date().toISOString(),
      serverCount,
      toolCount,
      summary,
    };
  }

  private buildSummary(vulnerabilities: Vulnerability[]): ScanSummary {
    const summary: ScanSummary = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      total: vulnerabilities.length,
    };

    for (const vuln of vulnerabilities) {
      summary[vuln.severity]++;
    }

    return summary;
  }

  private calculateScore(vulnerabilities: Vulnerability[]): number {
    if (vulnerabilities.length === 0) return 0;

    const weights: Record<Severity, number> = {
      critical: 25,
      high: 15,
      medium: 8,
      low: 3,
      info: 1,
    };

    const rawScore = vulnerabilities.reduce(
      (total, vuln) => total + weights[vuln.severity],
      0
    );

    return Math.min(100, rawScore);
  }
}