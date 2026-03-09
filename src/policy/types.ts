/**
 * Policy type definitions for mcp-guardian
 */

export interface Policy {
  version: string;
  defaultPolicy: 'allow' | 'deny';
  servers: Record<string, ServerPolicy>;
  globalRules?: GlobalRules;
}

export interface ServerPolicy {
  tools?: Record<string, ToolPermission>;
  allowedCommands?: string[];
  blockedCommands?: string[];
  maxCallsPerMinute?: number;
  allowedPaths?: string[];
  blockedPaths?: string[];
}

export interface ToolPermission {
  permission: 'allow' | 'deny' | 'ask';
  constraints?: ToolConstraints;
  rateLimit?: number;
}

export interface ToolConstraints {
  pathPrefix?: string;
  allowedArgs?: string[];
  blockedArgs?: string[];
  maxInputLength?: number;
  regex?: string;
}

export interface GlobalRules {
  maxCallsPerMinute?: number;
  blockPatterns?: string[];
  allowedPathPrefixes?: string[];
  blockedPathPrefixes?: string[];
  requireHttps?: boolean;
  logAllCalls?: boolean;
}