/**
 * Runtime Policy Enforcement Proxy
 * Transparent proxy that sits between LLM clients and MCP servers
 * to enforce security policies on tool calls
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { loadPolicy } from '../policy/loader.js';
import type { Policy } from '../policy/types.js';

export interface ProxyOptions {
  policyPath: string;
  target: string;
  port?: number;
  host?: string;
  onBlock?: (toolName: string, serverName: string, reason: string) => void;
  onAllow?: (toolName: string, serverName: string) => void;
}

export interface ProxyStats {
  totalRequests: number;
  blockedRequests: number;
  allowedRequests: number;
  startedAt: string;
}

export class ProxyServer {
  private policy: Policy;
  private target: string;
  private server: ReturnType<typeof createServer> | null = null;
  private stats: ProxyStats;
  private onBlock?: ProxyOptions['onBlock'];
  private onAllow?: ProxyOptions['onAllow'];

  constructor(options: ProxyOptions) {
    this.policy = loadPolicy(options.policyPath);
    this.target = options.target;
    this.onBlock = options.onBlock;
    this.onAllow = options.onAllow;
    this.stats = {
      totalRequests: 0,
      blockedRequests: 0,
      allowedRequests: 0,
      startedAt: new Date().toISOString(),
    };
  }

  async start(options?: { port?: number; host?: string }): Promise<void> {
    const port = options?.port ?? 8080;
    const host = options?.host ?? '127.0.0.1';

    this.server = createServer((req, res) => {
      this.handleRequest(req, res);
    });

    return new Promise((resolve, reject) => {
      this.server!.listen(port, host, () => {
        console.log(`mcp-guardian proxy listening on ${host}:${port}`);
        console.log(`Forwarding to: ${this.target}`);
        console.log(`Policy: ${this.policy.defaultPolicy} by default`);
        resolve();
      });
      this.server!.on('error', reject);
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  getStats(): ProxyStats {
    return { ...this.stats };
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    this.stats.totalRequests++;

    try {
      const body = await this.readBody(req);
      const parsed = JSON.parse(body);

      // Check if this is a tool call
      if (parsed.method === 'tools/call' && parsed.params) {
        const toolName = parsed.params.name;
        const serverName = parsed.params._server ?? 'default';

        const decision = this.evaluatePolicy(toolName, serverName);

        if (!decision.allowed) {
          this.stats.blockedRequests++;
          this.onBlock?.(toolName, serverName, decision.reason);

          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            jsonrpc: '2.0',
            error: {
              code: -32600,
              message: `Blocked by policy: ${decision.reason}`,
            },
            id: parsed.id,
          }));
          return;
        }

        this.stats.allowedRequests++;
        this.onAllow?.(toolName, serverName);
      }

      // Forward the request to target
      await this.forwardRequest(req, body, res);
    } catch (error) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        error: {
          code: -32603,
          message: 'Proxy internal error',
        },
      }));
    }
  }

  private evaluatePolicy(
    toolName: string,
    serverName: string
  ): { allowed: boolean; reason: string } {
    // Check server-specific policy
    const serverPolicy = this.policy.servers[serverName];
    if (serverPolicy) {
      const toolPolicy = serverPolicy.tools?.[toolName];
      if (toolPolicy) {
        return {
          allowed: toolPolicy.permission === 'allow',
          reason: toolPolicy.permission === 'deny'
            ? `Tool "${toolName}" is explicitly denied for server "${serverName}"`
            : 'Allowed by policy',
        };
      }
    }

    // Check global block patterns
    if (this.policy.globalRules?.blockPatterns) {
      for (const pattern of this.policy.globalRules.blockPatterns) {
        if (toolName.includes(pattern)) {
          return {
            allowed: false,
            reason: `Tool name matches blocked pattern: ${pattern}`,
          };
        }
      }
    }

    // Fall back to default policy
    return {
      allowed: this.policy.defaultPolicy === 'allow',
      reason: this.policy.defaultPolicy === 'deny'
        ? `Default policy is deny. Add explicit allow for "${toolName}".`
        : 'Allowed by default policy',
    };
  }

  private readBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => resolve(body));
      req.on('error', reject);
    });
  }

  private async forwardRequest(
    originalReq: IncomingMessage,
    body: string,
    res: ServerResponse
  ): Promise<void> {
    const targetUrl = new URL(originalReq.url ?? '/', this.target);

    const response = await fetch(targetUrl.toString(), {
      method: originalReq.method ?? 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...this.filterHeaders(originalReq.headers),
      },
      body: body || undefined,
    });

    res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
    const responseBody = await response.text();
    res.end(responseBody);
  }

  private filterHeaders(headers: IncomingMessage['headers']): Record<string, string> {
    const filtered: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      if (key.toLowerCase() !== 'host' && value) {
        filtered[key] = Array.isArray(value) ? value.join(', ') : value;
      }
    }
    return filtered;
  }
}