/**
 * Insecure Configuration detection rule
 * Detects hardcoded secrets, disabled TLS, and debug mode in production configs
 */

import type { McpConfig, ScanRule, Vulnerability, VulnerabilityCategory } from '../../types.js';

const SECRET_PATTERNS = [
  { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"][^'"]{8,}['"]/i, name: 'API key' },
  { pattern: /(?:secret|token|password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/i, name: 'Secret/Password' },
  { pattern: /(?:aws_access_key_id|aws_secret_access_key)\s*[:=]/i, name: 'AWS credentials' },
  { pattern: /(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{36,}/, name: 'GitHub token' },
  { pattern: /sk-[A-Za-z0-9]{20,}/, name: 'OpenAI API key' },
  { pattern: /sk_live_[A-Za-z0-9]{20,}/, name: 'Stripe secret key' },
  { pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/, name: 'Private key' },
  { pattern: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+/, name: 'JWT token' },
];

const INSECURE_ENV_KEYS = [
  { pattern: /^debug$/i, issue: 'Debug mode enabled' },
  { pattern: /^node_env$/i, checkValue: (v: string) => v === 'development', issue: 'Development mode' },
  { pattern: /^tls_reject_unauthorized$/i, checkValue: (v: string) => v === '0', issue: 'TLS verification disabled' },
  { pattern: /^node_tls_reject_unauthorized$/i, checkValue: (v: string) => v === '0', issue: 'TLS verification disabled' },
  { pattern: /^https?_proxy$/i, issue: 'HTTP proxy configured (may leak credentials)' },
];

export class InsecureConfigRule implements ScanRule {
  id = 'INSEC-CFG';
  name = 'Insecure Configuration';
  category: VulnerabilityCategory = 'insecure-config';

  scan(config: McpConfig): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (const [serverName, serverConfig] of Object.entries(config.mcpServers)) {
      // Check for hardcoded secrets in all string values
      const allValues = this.getAllStringValues(serverConfig);
      for (const value of allValues) {
        for (const secretDef of SECRET_PATTERNS) {
          if (secretDef.pattern.test(value)) {
            vulnerabilities.push({
              id: `${this.id}-001`,
              title: `Hardcoded ${secretDef.name} detected`,
              description: `Server "${serverName}" contains a hardcoded ${secretDef.name} in its configuration`,
              severity: secretDef.name.includes('Private key') ? 'critical' : 'high',
              category: this.category,
              server: serverName,
              evidence: this.maskSecret(value),
              remediation: `Use environment variables or a secrets manager instead of hardcoding ${secretDef.name}s.`,
            });
          }
        }
      }

      // Check environment variables
      if (serverConfig.env) {
        for (const [key, value] of Object.entries(serverConfig.env)) {
          // Check for insecure env settings
          for (const envCheck of INSECURE_ENV_KEYS) {
            if (envCheck.pattern.test(key)) {
              if (!envCheck.checkValue || envCheck.checkValue(value)) {
                vulnerabilities.push({
                  id: `${this.id}-002`,
                  title: envCheck.issue,
                  description: `Server "${serverName}" has ${envCheck.issue.toLowerCase()} via env var "${key}"`,
                  severity: key.toLowerCase().includes('tls') ? 'critical' : 'medium',
                  category: this.category,
                  server: serverName,
                  evidence: `${key}=${value}`,
                  remediation: `Review the "${key}" environment variable setting for production use.`,
                });
              }
            }
          }

          // Check for secrets in env values
          for (const secretDef of SECRET_PATTERNS) {
            if (secretDef.pattern.test(value)) {
              vulnerabilities.push({
                id: `${this.id}-003`,
                title: `${secretDef.name} in environment variable`,
                description: `Server "${serverName}" env var "${key}" contains a ${secretDef.name}`,
                severity: 'high',
                category: this.category,
                server: serverName,
                evidence: `${key}=${this.maskSecret(value)}`,
                remediation: 'Use a secrets manager or encrypted environment variables for sensitive values.',
              });
            }
          }
        }
      }

      // Check for HTTP (non-HTTPS) URLs
      if (serverConfig.url && serverConfig.url.startsWith('http://')) {
        vulnerabilities.push({
          id: `${this.id}-004`,
          title: 'Unencrypted HTTP connection',
          description: `Server "${serverName}" uses unencrypted HTTP instead of HTTPS`,
          severity: 'medium',
          category: this.category,
          server: serverName,
          evidence: serverConfig.url,
          remediation: 'Use HTTPS for all connections. Configure TLS certificates for the server.',
        });
      }
    }

    return vulnerabilities;
  }

  private getAllStringValues(obj: unknown): string[] {
    const values: string[] = [];
    if (typeof obj === 'string') {
      values.push(obj);
    } else if (Array.isArray(obj)) {
      for (const item of obj) {
        values.push(...this.getAllStringValues(item));
      }
    } else if (obj && typeof obj === 'object') {
      for (const value of Object.values(obj)) {
        values.push(...this.getAllStringValues(value));
      }
    }
    return values;
  }

  private maskSecret(value: string): string {
    if (value.length <= 8) return '***';
    return value.substring(0, 4) + '...' + value.substring(value.length - 4);
  }
}