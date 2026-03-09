/**
 * Permission Escalation detection rule
 * Detects sudo/privileged execution and dangerous tool patterns
 */

import type { McpConfig, ScanRule, Vulnerability, VulnerabilityCategory } from '../../types.js';

const PRIVILEGED_COMMANDS = [
  'sudo', 'su ', 'doas', 'pkexec',
  'runas', 'gsudo',
  'chmod 777', 'chmod +s', 'chown root',
];

const DANGEROUS_TOOLS = [
  { pattern: /execute[_-]?command/i, name: 'Command execution tool' },
  { pattern: /run[_-]?shell/i, name: 'Shell execution tool' },
  { pattern: /file[_-]?write/i, name: 'File write tool' },
  { pattern: /file[_-]?delete/i, name: 'File deletion tool' },
  { pattern: /system[_-]?exec/i, name: 'System execution tool' },
  { pattern: /admin/i, name: 'Admin tool' },
  { pattern: /root[_-]?access/i, name: 'Root access tool' },
  { pattern: /install[_-]?package/i, name: 'Package installation tool' },
  { pattern: /modify[_-]?config/i, name: 'Configuration modification tool' },
  { pattern: /network[_-]?scan/i, name: 'Network scanning tool' },
];

const PRIVILEGE_ESCALATION_ENV = [
  { key: /^user$/i, value: 'root', issue: 'Running as root user' },
  { key: /^uid$/i, value: '0', issue: 'Running with UID 0 (root)' },
  { key: /^euid$/i, value: '0', issue: 'Running with effective UID 0' },
];

export class PermissionEscalationRule implements ScanRule {
  id = 'PERM-ESC';
  name = 'Permission Escalation';
  category: VulnerabilityCategory = 'permission-escalation';

  scan(config: McpConfig): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (const [serverName, serverConfig] of Object.entries(config.mcpServers)) {
      // Check command for privileged execution
      const fullCommand = [serverConfig.command, ...(serverConfig.args ?? [])].join(' ');
      const commandLower = fullCommand.toLowerCase();

      for (const privCmd of PRIVILEGED_COMMANDS) {
        if (commandLower.includes(privCmd.toLowerCase())) {
          vulnerabilities.push({
            id: `${this.id}-001`,
            title: `Privileged command detected: ${privCmd.trim()}`,
            description: `Server "${serverName}" uses privileged command "${privCmd.trim()}" which could lead to permission escalation`,
            severity: 'high',
            category: this.category,
            server: serverName,
            evidence: fullCommand,
            remediation: 'Run MCP servers with minimum required privileges. Avoid sudo/root execution.',
          });
        }
      }

      // Check for --privileged or --cap-add flags (Docker)
      if (serverConfig.args) {
        for (const arg of serverConfig.args) {
          if (arg === '--privileged' || arg.startsWith('--cap-add')) {
            vulnerabilities.push({
              id: `${this.id}-002`,
              title: `Docker privilege escalation: ${arg}`,
              description: `Server "${serverName}" uses Docker flag "${arg}" which grants elevated container privileges`,
              severity: 'high',
              category: this.category,
              server: serverName,
              evidence: arg,
              remediation: 'Avoid --privileged flag. Use specific --cap-add only for required capabilities.',
            });
          }
        }
      }

      // Check tools for dangerous patterns
      if (serverConfig.tools) {
        for (const tool of serverConfig.tools) {
          for (const dangerousTool of DANGEROUS_TOOLS) {
            if (dangerousTool.pattern.test(tool.name)) {
              vulnerabilities.push({
                id: `${this.id}-003`,
                title: `${dangerousTool.name} exposed: ${tool.name}`,
                description: `Server "${serverName}" exposes a ${dangerousTool.name.toLowerCase()} "${tool.name}" which could be misused`,
                severity: 'high',
                category: this.category,
                server: serverName,
                tool: tool.name,
                evidence: `Tool: ${tool.name}${tool.description ? ' - ' + tool.description : ''}`,
                remediation: `Restrict access to "${tool.name}". Apply input validation and output filtering.`,
              });
            }
          }
        }
      }

      // Check env for privilege escalation
      if (serverConfig.env) {
        for (const [key, value] of Object.entries(serverConfig.env)) {
          for (const check of PRIVILEGE_ESCALATION_ENV) {
            if (check.key.test(key) && value === check.value) {
              vulnerabilities.push({
                id: `${this.id}-004`,
                title: check.issue,
                description: `Server "${serverName}" is configured with ${check.issue.toLowerCase()}`,
                severity: 'critical',
                category: this.category,
                server: serverName,
                evidence: `${key}=${value}`,
                remediation: 'Run MCP servers as non-root users with minimum required permissions.',
              });
            }
          }
        }
      }
    }

    return vulnerabilities;
  }
}