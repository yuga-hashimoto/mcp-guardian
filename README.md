# mcp-guardian

[![CI](https://github.com/yuga-hashimoto/mcp-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/yuga-hashimoto/mcp-guardian/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)

> Security scanner & runtime proxy for MCP (Model Context Protocol) servers. Detect vulnerabilities, enforce permissions, and sandbox tool calls.

## Overview

**mcp-guardian** helps you secure your MCP server deployments by:

1. **Scanning** MCP server configurations for known vulnerability patterns
2. **Enforcing** runtime policies on tool calls via a transparent proxy
3. **Detecting** command injection, path traversal, SSRF, insecure configs, and permission escalation

## Installation

```bash
npm install mcp-guardian
```

Or install globally for CLI usage:

```bash
npm install -g mcp-guardian
```

## Quick Start

### CLI Scanner

```bash
# Scan an MCP server config file
mcp-guardian scan ./mcp-config.json

# Initialize a default policy file
mcp-guardian init

# Check a config against a policy
mcp-guardian check ./mcp-config.json --policy ./mcp-policy.json
```

### Programmatic API

```typescript
import { Scanner } from 'mcp-guardian';

const scanner = new Scanner();
const results = await scanner.scan({
  mcpServers: {
    myServer: {
      command: 'node',
      args: ['server.js'],
      env: { API_KEY: 'hardcoded-secret' },
    },
  },
});

console.log(`Found ${results.vulnerabilities.length} issues`);
console.log(`Risk score: ${results.score}/100`);
```

## Features

### Vulnerability Scanner

Detects 5 categories of security issues:

| Category | Description | Severity |
|----------|-------------|----------|
| Command Injection | Shell metacharacters, dangerous commands (`eval`, `exec`) | Critical |
| Path Traversal | `../` sequences, access to sensitive files (`/etc/passwd`) | High |
| SSRF | Internal IP ranges, cloud metadata endpoints (`169.254.169.254`) | High |
| Insecure Config | Hardcoded secrets, disabled TLS, debug mode in production | Medium-Critical |
| Permission Escalation | `sudo`/privileged execution, dangerous tool patterns | High |

### Runtime Proxy

Transparent proxy that sits between LLM clients and MCP servers:

```typescript
import { ProxyServer } from 'mcp-guardian';

const proxy = new ProxyServer({
  policyPath: './mcp-policy.json',
  target: 'http://localhost:3000',
});

await proxy.start({ port: 8080 });
```

- **Tool call filtering** -- block or allow specific tool calls
- **Argument sanitization** -- strip dangerous patterns from arguments
- **Rate limiting** -- prevent abuse of tool calls
- **Audit logging** -- log all tool invocations for review

### Policy Engine

Define granular permissions per server and tool:

```json
{
  "version": "1.0",
  "defaultPolicy": "deny",
  "servers": {
    "myServer": {
      "tools": {
        "readFile": {
          "permission": "allow",
          "constraints": {
            "pathPrefix": "/safe/directory/"
          }
        },
        "executeCommand": {
          "permission": "deny"
        }
      }
    }
  }
}
```

## Architecture

```
src/
  index.ts            # Public API exports
  types.ts            # Core type definitions
  cli.ts              # CLI entry point
  scanner/
    index.ts          # Scanner orchestrator
    rules/
      command-injection.ts
      path-traversal.ts
      ssrf.ts
      insecure-config.ts
      permission-escalation.ts
  proxy/
    index.ts          # Runtime proxy server
  policy/
    types.ts          # Policy type definitions
    loader.ts         # Policy file loader & validator
  __tests__/
    scanner.test.ts   # Scanner test suite
```

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Watch mode
npm run dev
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see the [LICENSE](LICENSE) file for details.