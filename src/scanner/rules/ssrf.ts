/**
 * SSRF (Server-Side Request Forgery) detection rule
 * Detects internal IP ranges, localhost references, and cloud metadata endpoints
 */

import type { McpConfig, ScanRule, Vulnerability, VulnerabilityCategory } from '../../types.js';

const INTERNAL_IP_PATTERNS = [
  /127\.\d{1,3}\.\d{1,3}\.\d{1,3}/,     // Loopback
  /10\.\d{1,3}\.\d{1,3}\.\d{1,3}/,      // Private Class A
  /172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}/, // Private Class B
  /192\.168\.\d{1,3}\.\d{1,3}/,          // Private Class C
  /0\.0\.0\.0/,                            // All interfaces
  /\[::1\]/,                               // IPv6 loopback
  /\[fc[0-9a-f]{2}:/i,                     // IPv6 unique local
  /\[fe80:/i,                               // IPv6 link-local
];

const DANGEROUS_HOSTS = [
  'localhost',
  '169.254.169.254',     // AWS/GCP metadata
  '100.100.100.200',     // Alibaba metadata
  'metadata.google.internal',
  'metadata.internal',
  'instance-data',
];

const DANGEROUS_SCHEMES = [
  'file://',
  'gopher://',
  'dict://',
  'ftp://',
  'ldap://',
];

export class SSRFRule implements ScanRule {
  id = 'SSRF';
  name = 'Server-Side Request Forgery';
  category: VulnerabilityCategory = 'ssrf';

  scan(config: McpConfig): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (const [serverName, serverConfig] of Object.entries(config.mcpServers)) {
      // Check URL field
      if (serverConfig.url) {
        this.checkUrl(serverName, serverConfig.url, vulnerabilities);
      }

      // Check args for URLs
      if (serverConfig.args) {
        for (const arg of serverConfig.args) {
          if (arg.includes('://') || arg.includes('localhost') || arg.includes('169.254')) {
            this.checkUrl(serverName, arg, vulnerabilities);
          }
        }
      }

      // Check env vars for URLs
      if (serverConfig.env) {
        for (const [key, value] of Object.entries(serverConfig.env)) {
          if (value.includes('://') || value.includes('localhost') || value.includes('169.254')) {
            this.checkUrl(serverName, value, vulnerabilities, key);
          }
        }
      }
    }

    return vulnerabilities;
  }

  private checkUrl(
    serverName: string,
    url: string,
    vulnerabilities: Vulnerability[],
    envKey?: string
  ): void {
    const urlLower = url.toLowerCase();
    const context = envKey ? ` (env: ${envKey})` : '';

    // Check internal IPs
    for (const pattern of INTERNAL_IP_PATTERNS) {
      if (pattern.test(url)) {
        vulnerabilities.push({
          id: `${this.id}-001`,
          title: `Internal IP address detected${context}`,
          description: `Server "${serverName}" references an internal IP address, which could be used for SSRF attacks`,
          severity: 'high',
          category: this.category,
          server: serverName,
          evidence: url,
          remediation: 'Use external hostnames or configure allowlists for internal services. Block access to internal IP ranges.',
        });
        break;
      }
    }

    // Check dangerous hosts
    for (const host of DANGEROUS_HOSTS) {
      if (urlLower.includes(host.toLowerCase())) {
        const isMetadata = host.includes('169.254') || host.includes('metadata');
        vulnerabilities.push({
          id: `${this.id}-002`,
          title: `${isMetadata ? 'Cloud metadata endpoint' : 'Localhost reference'} detected${context}`,
          description: `Server "${serverName}" references ${isMetadata ? 'a cloud metadata endpoint' : 'localhost'} which could expose sensitive information`,
          severity: isMetadata ? 'critical' : 'high',
          category: this.category,
          server: serverName,
          evidence: url,
          remediation: isMetadata
            ? 'Block access to cloud metadata endpoints (169.254.169.254). Use IMDSv2 with hop limit.'
            : 'Avoid localhost references in production. Use proper service discovery.',
        });
      }
    }

    // Check dangerous schemes
    for (const scheme of DANGEROUS_SCHEMES) {
      if (urlLower.startsWith(scheme)) {
        vulnerabilities.push({
          id: `${this.id}-003`,
          title: `Dangerous URL scheme: ${scheme}${context}`,
          description: `Server "${serverName}" uses the "${scheme}" scheme which could be exploited for SSRF`,
          severity: 'high',
          category: this.category,
          server: serverName,
          evidence: url,
          remediation: `Block the "${scheme}" URL scheme. Only allow http:// and https:// schemes.`,
        });
      }
    }
  }
}