/**
 * Command Injection detection rule
 * Detects shell metacharacters and dangerous commands in MCP server configs
 */

import type { McpConfig, ScanRule, Vulnerability, VulnerabilityCategory } from '../../types.js';

const SHELL_METACHARACTERS = /[;|&`$(){}\[\]<>!\\]/;
const DANGEROUS_COMMANDS = [
  'eval', 'exec', 'spawn', 'execSync', 'spawnSync',
  'child_process', 'sh -c', 'bash -c', 'cmd /c',
  'powershell', 'pwsh',
];
const DANGEROUS_PATTERNS = [
  /\$\{.*\}/, // Template injection
  /\$\(.*\)/, // Command substitution
  /`[^`]+`/,  // Backtick execution
];

export class CommandInjectionRule implements ScanRule {
  id = 'CMD-INJ';
  name = 'Command Injection';
  category: VulnerabilityCategory = 'command-injection';

  scan(config: McpConfig): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (const [serverName, serverConfig] of Object.entries(config.mcpServers)) {
      // Check command field
      if (SHELL_METACHARACTERS.test(serverConfig.command)) {
        vulnerabilities.push({
          id: `${this.id}-001`,
          title: 'Shell metacharacters in server command',
          description: `Server "${serverName}" command contains shell metacharacters that could enable command injection`,
          severity: 'critical',
          category: this.category,
          server: serverName,
          evidence: serverConfig.command,
          remediation: 'Use an array of arguments instead of shell string. Avoid shell metacharacters in commands.',
        });
      }

      // Check for dangerous commands
      const commandLower = serverConfig.command.toLowerCase();
      for (const dangerous of DANGEROUS_COMMANDS) {
        if (commandLower.includes(dangerous.toLowerCase())) {
          vulnerabilities.push({
            id: `${this.id}-002`,
            title: `Dangerous command detected: ${dangerous}`,
            description: `Server "${serverName}" uses potentially dangerous command "${dangerous}"`,
            severity: 'high',
            category: this.category,
            server: serverName,
            evidence: serverConfig.command,
            remediation: `Avoid using "${dangerous}" directly. Use safer alternatives or sandboxed execution.`,
          });
        }
      }

      // Check args for injection patterns
      if (serverConfig.args) {
        for (const arg of serverConfig.args) {
          for (const pattern of DANGEROUS_PATTERNS) {
            if (pattern.test(arg)) {
              vulnerabilities.push({
                id: `${this.id}-003`,
                title: 'Potential command injection in arguments',
                description: `Server "${serverName}" has arguments containing command substitution patterns`,
                severity: 'critical',
                category: this.category,
                server: serverName,
                evidence: arg,
                remediation: 'Sanitize all arguments. Do not pass user-controlled values without validation.',
              });
            }
          }

          if (SHELL_METACHARACTERS.test(arg)) {
            vulnerabilities.push({
              id: `${this.id}-004`,
              title: 'Shell metacharacters in arguments',
              description: `Server "${serverName}" has arguments containing shell metacharacters`,
              severity: 'high',
              category: this.category,
              server: serverName,
              evidence: arg,
              remediation: 'Escape or remove shell metacharacters from arguments.',
            });
          }
        }
      }

      // Check env vars for injection
      if (serverConfig.env) {
        for (const [key, value] of Object.entries(serverConfig.env)) {
          for (const pattern of DANGEROUS_PATTERNS) {
            if (pattern.test(value)) {
              vulnerabilities.push({
                id: `${this.id}-005`,
                title: 'Command substitution in environment variable',
                description: `Server "${serverName}" env var "${key}" contains command substitution`,
                severity: 'high',
                category: this.category,
                server: serverName,
                evidence: `${key}=${value}`,
                remediation: 'Use static values for environment variables. Do not include command substitution patterns.',
              });
            }
          }
        }
      }
    }

    return vulnerabilities;
  }
}