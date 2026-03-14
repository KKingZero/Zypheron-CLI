# Zypheron MCP Integration Guide

This guide covers the current MCP flow for exposing Zypheron tooling to external AI clients.

## Overview

Zypheron's MCP integration allows compatible AI clients to call Zypheron through an MCP server instead of requiring direct manual CLI use for every step.

Typical use cases:

- connecting Claude Desktop to Zypheron
- exposing Zypheron workflows to Cursor or other MCP-aware clients
- letting an external AI client inspect available tools and invoke controlled workflows

## Prerequisites

- Zypheron CLI installed
- Python `3.9+`
- MCP dependencies installed
- an MCP-capable client

If you installed via the bootstrap script, most Python-side dependencies are already handled. If not:

```bash
zypheron install-deps --all
```

## Core Commands

```bash
zypheron mcp config
zypheron mcp start
zypheron mcp stop
zypheron mcp status
```

## Quick Start

### 1. Generate config

```bash
zypheron mcp config
```

This prints the MCP configuration you need for your client.

### 2. Start the MCP server

```bash
zypheron mcp start
```

### 3. Verify status

```bash
zypheron mcp status
```

## Client Configuration

The safest current pattern is:

1. run `zypheron mcp config`
2. copy the generated config into your MCP client
3. avoid hand-writing old hardcoded paths from archived docs

The exact JSON shape depends on the client, but the generated output from Zypheron should be treated as the current source of truth.

## Manual Path Notes

If you do need to reason about paths manually:

- the repo-local MCP server lives under `zypheron-ai/mcp_interface/`
- the actual runtime path depends on whether you are running from source or from an installed environment

That is why the generated `zypheron mcp config` output is preferred over older hardcoded examples.

## Example Workflow

Typical flow:

```bash
zypheron mcp config
zypheron mcp start
```

Then in your AI client, ask for something simple first, such as:

```text
List the Zypheron tools you can access.
```

After that, test a narrower workflow before attempting larger chained operations.

## Security Notes

MCP makes it easier for an external AI client to invoke Zypheron tooling, which means you should treat it as a privileged integration surface.

Recommended practices:

- run it only on systems you control
- review your client configuration carefully
- test with low-risk commands first
- keep your local toolchain and provider credentials under control

## Troubleshooting

Useful checks:

```bash
zypheron mcp status
zypheron ai status
zypheron doctor
```

Common causes of issues:

- Python dependencies missing
- AI engine not available when expected
- wrong path assumptions in manually written client config
- MCP client using stale config copied from older docs

If in doubt, regenerate config with:

```bash
zypheron mcp config
```
