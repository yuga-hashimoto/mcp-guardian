/**
 * mcp-guardian - Security scanner & runtime proxy for MCP servers
 *
 * @module mcp-guardian
 */

export { Scanner } from './scanner/index.js';
export { ProxyServer } from './proxy/index.js';
export { loadPolicy, validatePolicy } from './policy/loader.js';

export type {
  Vulnerability,
  ScanResult,
  ScanSummary,
  ScanRule,
  Severity,
  VulnerabilityCategory,
  McpConfig,
  McpServerConfig,
  McpToolConfig,
} from './types.js';

export type {
  Policy,
  ServerPolicy,
  ToolPermission,
} from './policy/types.js';