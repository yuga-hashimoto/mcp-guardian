/**
 * Policy file loader & validator
 * Loads and validates mcp-guardian policy files
 */

import { readFileSync } from 'node:fs';
import type { Policy, ServerPolicy, ToolPermission } from './types.js';

export function loadPolicy(filePath: string): Policy {
  const content = readFileSync(filePath, 'utf-8');
  const raw = JSON.parse(content);
  return validatePolicy(raw);
}

export function validatePolicy(raw: unknown): Policy {
  if (!raw || typeof raw !== 'object') {
    throw new PolicyValidationError('Policy must be a JSON object');
  }

  const obj = raw as Record<string, unknown>;

  // Validate version
  if (typeof obj.version !== 'string') {
    throw new PolicyValidationError('Policy must have a "version" string field');
  }

  // Validate defaultPolicy
  if (obj.defaultPolicy !== 'allow' && obj.defaultPolicy !== 'deny') {
    throw new PolicyValidationError('Policy "defaultPolicy" must be "allow" or "deny"');
  }

  // Validate servers
  if (!obj.servers || typeof obj.servers !== 'object') {
    throw new PolicyValidationError('Policy must have a "servers" object');
  }

  const servers: Record<string, ServerPolicy> = {};
  for (const [name, serverRaw] of Object.entries(obj.servers as Record<string, unknown>)) {
    servers[name] = validateServerPolicy(name, serverRaw);
  }

  const policy: Policy = {
    version: obj.version,
    defaultPolicy: obj.defaultPolicy,
    servers,
  };

  // Validate optional globalRules
  if (obj.globalRules) {
    if (typeof obj.globalRules !== 'object') {
      throw new PolicyValidationError('"globalRules" must be an object');
    }
    policy.globalRules = obj.globalRules as Policy['globalRules'];
  }

  return policy;
}

function validateServerPolicy(name: string, raw: unknown): ServerPolicy {
  if (!raw || typeof raw !== 'object') {
    throw new PolicyValidationError(`Server policy for "${name}" must be an object`);
  }

  const obj = raw as Record<string, unknown>;
  const serverPolicy: ServerPolicy = {};

  if (obj.tools) {
    if (typeof obj.tools !== 'object') {
      throw new PolicyValidationError(`"tools" in server "${name}" must be an object`);
    }

    serverPolicy.tools = {};
    for (const [toolName, toolRaw] of Object.entries(obj.tools as Record<string, unknown>)) {
      serverPolicy.tools[toolName] = validateToolPermission(name, toolName, toolRaw);
    }
  }

  if (obj.allowedCommands) {
    if (!Array.isArray(obj.allowedCommands)) {
      throw new PolicyValidationError(`"allowedCommands" in server "${name}" must be an array`);
    }
    serverPolicy.allowedCommands = obj.allowedCommands as string[];
  }

  if (obj.blockedCommands) {
    if (!Array.isArray(obj.blockedCommands)) {
      throw new PolicyValidationError(`"blockedCommands" in server "${name}" must be an array`);
    }
    serverPolicy.blockedCommands = obj.blockedCommands as string[];
  }

  if (typeof obj.maxCallsPerMinute === 'number') {
    serverPolicy.maxCallsPerMinute = obj.maxCallsPerMinute;
  }

  return serverPolicy;
}

function validateToolPermission(
  serverName: string,
  toolName: string,
  raw: unknown
): ToolPermission {
  if (!raw || typeof raw !== 'object') {
    throw new PolicyValidationError(
      `Tool permission for "${toolName}" in server "${serverName}" must be an object`
    );
  }

  const obj = raw as Record<string, unknown>;

  if (obj.permission !== 'allow' && obj.permission !== 'deny' && obj.permission !== 'ask') {
    throw new PolicyValidationError(
      `Tool "${toolName}" in server "${serverName}" must have permission: "allow", "deny", or "ask"`
    );
  }

  const toolPermission: ToolPermission = {
    permission: obj.permission,
  };

  if (obj.constraints && typeof obj.constraints === 'object') {
    toolPermission.constraints = obj.constraints as ToolPermission['constraints'];
  }

  if (typeof obj.rateLimit === 'number') {
    toolPermission.rateLimit = obj.rateLimit;
  }

  return toolPermission;
}

export class PolicyValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PolicyValidationError';
  }
}