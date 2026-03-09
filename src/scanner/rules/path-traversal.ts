/**
 * Path Traversal detection rule
 * Detects ../traversal patterns and access to sensitive file paths
 */

import type { McpConfig, ScanRule, Vulnerability, VulnerabilityCategory } from '../../types.js';

const TRAVERSAL_PATTERNS = [
  /\.\.[\/\\]/,           // ../  or ..\
  /\.\.\.+/,              // Multiple dots
  /%2e%2e[\/\\%]/i,       // URL-encoded traversal
  /%252e%252e/i,           // Double-encoded
];

const SENSITIVE_PATHS = [
  '/etc/passwd',
  '/etc/shadow',
  '/etc/hosts',
  '/etc/ssh/',
  '/root/',
  '/proc/',
  '/sys/',
  'C:\\Windows\\System32',
  'C:\\Windows\\system.ini',
  '~/.ssh/',
  '~/.aws/',
  '~/.gnupg/',
  '.env',
  '.git/',
  'id_rsa',
  'id_ed25519',
  'authorized_keys',
  'known_hosts',
];

export class PathTraversalRule implements ScanRule {
  id = 'PATH-TRAV';
  name = 'Path Traversal';
  category: VulnerabilityCategory = 'path-traversal';

  scan(config: McpConfig): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (const [serverName, serverConfig] of Object.entries(config.mcpServers)) {
      const allValues = this.extractAllValues(serverConfig);

      for (const value of allValues) {
        // Check traversal patterns
        for (const pattern of TRAVERSAL_PATTERNS) {
          if (pattern.test(value)) {
            vulnerabilities.push({
              id: `${this.id}-001`,
              title: 'Path traversal pattern detected',
              description: `Server "${serverName}" contains path traversal patterns that could allow unauthorized file access`,
              severity: 'high',
              category: this.category,
              server: serverName,
              evidence: value,
              remediation: 'Normalize and validate all file paths. Use path.resolve() and verify paths are within allowed directories.',
            });
            break;
          }
        }

        // Check sensitive file access
        const valueLower = value.toLowerCase();
        for (const sensitivePath of SENSITIVE_PATHS) {
          if (valueLower.includes(sensitivePath.toLowerCase())) {
            vulnerabilities.push({
              id: `${this.id}-002`,
              title: `Access to sensitive path: ${sensitivePath}`,
              description: `Server "${serverName}" references sensitive system path "${sensitivePath}"`,
              severity: sensitivePath.includes('shadow') || sensitivePath.includes('id_rsa') ? 'critical' : 'high',
              category: this.category,
              server: serverName,
              evidence: value,
              remediation: `Avoid direct access to "${sensitivePath}". Use application-specific directories with proper access controls.`,
            });
          }
        }
      }
    }

    return vulnerabilities;
  }

  private extractAllValues(obj: unknown): string[] {
    const values: string[] = [];

    if (typeof obj === 'string') {
      values.push(obj);
    } else if (Array.isArray(obj)) {
      for (const item of obj) {
        values.push(...this.extractAllValues(item));
      }
    } else if (obj && typeof obj === 'object') {
      for (const value of Object.values(obj)) {
        values.push(...this.extractAllValues(value));
      }
    }

    return values;
  }
}