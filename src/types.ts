/**
 * Core type definitions for mcp-guardian
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Vulnerability {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: VulnerabilityCategory;
  server?: string;
  tool?: string;
  evidence: string;
  remediation: string;
}

export type VulnerabilityCategory =
  | 'command-injection'
  | 'path-traversal'
  | 'ssrf'
  | 'insecure-config'
  | 'permission-escalation';

export interface ScanResult {
  vulnerabilities: Vulnerability[];
  score: number;
  scannedAt: string;
  serverCount: number;
  toolCount: number;
  summary: ScanSummary;
}

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface McpServerConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  tools?: McpToolConfig[];
}

export interface McpToolConfig {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface McpConfig {
  mcpServers: Record<string, McpServerConfig>;
}

export interface ScanRule {
  id: string;
  name: string;
  category: VulnerabilityCategory;
  scan(config: McpConfig): Vulnerability[];
}