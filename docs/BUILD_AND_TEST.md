# Zypheron Build and Test Guide

This guide covers the current build, install, and verification flow for the Go CLI, Python AI runtime, shared task system, MCP adapter, and autopent path.

For general setup, see [README.md](README.md), [docs/INSTALL.md](docs/INSTALL.md), and [docs/SETUP_AND_USE.md](docs/SETUP_AND_USE.md).

## Prerequisites

Required:

- Go `1.24+`
- Python `3.11+` for `zypheron-ai`
- Python `3.10+` for `zypheron-api`
- `make`

Recommended for runtime validation:

- working Python virtual environments under `zypheron-ai/.venv` and `zypheron-api/.venv`
- local model runtime such as Ollama, or hosted provider keys
- local security tools you intend to exercise, such as `nmap`, `httpx`, `sqlmap`, `nuclei`, `nikto`

## Build

### Go binary

```bash
cd zypheron-go
make build
./build/zypheron --version
```

This produces:

- `zypheron-go/build/zypheron`

### Python environments

Prepare the API test environment:

```bash
./scripts/setup_api_test_env.sh --allow-online
```

Prepare the AI runtime test environment:

```bash
./scripts/setup_ai_test_env.sh --allow-online
```

Both scripts prefer a local `wheelhouse/` when present. Without a wheelhouse,
online package resolution requires the explicit `--allow-online` flag.

## Global Install

User-local install:

```bash
cd zypheron-go
install -m 755 build/zypheron "$HOME/.local/bin/zypheron"
zypheron --version
```

System-wide install:

```bash
cd zypheron-go
sudo install -m 755 build/zypheron /usr/local/bin/zypheron
zypheron --version
```

## Verification

### Basic CLI checks

```bash
zypheron --version
zypheron --help
zypheron doctor
zypheron ai status
```

### Full release gate

```bash
./scripts/run_all_tests.sh --ci
```

This provisions missing Python test environments with locked dependencies,
runs API tests, AI runtime tests, Go tests, and integration checks. Go tests use
a workspace `GOTMPDIR` so noexec `/tmp` mounts do not break the test binary
execution step.

By default the API portion runs the OSS RC subset. To run the broader legacy
hosted/SaaS API suite:

```bash
API_TEST_SCOPE=full ./scripts/run_all_tests.sh --ci
```

The integration portion follows the same release posture. By default it runs
the OSS RC integration subset and excludes legacy hosted auth/license flows
whose contracts are not part of this RC. To run those legacy flows too:

```bash
INTEGRATION_TEST_SCOPE=full ./scripts/run_all_tests.sh --ci
```

### Python test suites

API:

```bash
cd zypheron-api
.venv/bin/python -m pytest tests/
```

AI runtime:

```bash
cd zypheron-ai
.venv/bin/python -m pytest tests/
```

### Go compile verification

Compile-oriented validation for the bridge, commands, and TUI packages:

```bash
cd zypheron-go
mkdir -p .gotmp
GOTMPDIR="$PWD/.gotmp" go test ./...
```

### Python compile check

```bash
cd zypheron-ai
.venv/bin/python -m compileall autopent mcp_interface tools/registry.py
```

## Dynamic Smoke Tests

### Runtime chat path

```bash
zypheron
```

Or:

```bash
zypheron tui
```

Then try a safe runtime-tool prompt such as:

```text
what configured providers do i have?
```

Expected behavior:

- TUI starts or connects to the Python AI engine
- the request is executed through the shared query engine
- runtime events appear in the console

### Autopent subprocess path

Direct Python runner:

```bash
cd zypheron-ai
venv/bin/python autopent/run_autopent.py \
  --target 127.0.0.1 \
  --objective "obtain admin" \
  --session-id smoke_autopent
```

What this validates:

- autopent runner startup
- attack graph discovery
- shared task emission
- approval-required state transitions
- shared-tool execution path for supported edges

### TUI approval widget

The TUI now includes a shared-runtime approval modal.

You can validate it by running an approval-gated runtime action or by observing a waiting task in the active runtime session.

Expected behavior:

- approval modal opens
- `Approve once`, `Allow for session`, and `Deny` submit correctly
- dismissal no longer immediately reopens the same prompt on the next poll cycle

## Current Runtime Notes

What is implemented now:

- chat routed through `zypheron-ai/core/query_engine.py`
- shared task and audit persistence in `zypheron-ai/tasks/store.py`
- runtime approvals over IPC through `task_approve`
- TUI runtime polling and approval widget
- autopent shared task/event integration
- partial MCP shared-tool routing

What is still partial:

- MCP is not fully migrated to the shared typed tool plane
- autopent still has workflow-specific orchestration outside the query engine
- context compaction and artifact summarization are not implemented yet
- streaming chat protocol support falls back to the standard chat path
- Enterprise Teams endpoints are deferred for the OSS RC and may return `501`
- full autonomous exploitation is deferred; autopent remains approval-gated

## Troubleshooting

Common issues:

- missing Python dependencies
- local model runtime not running
- missing local security tools
- keyring unavailable for hosted provider keys

Useful checks:

```bash
zypheron doctor
zypheron ai doctor
zypheron tools check
zypheron ai providers
```

If the Python runtime appears unhealthy:

```bash
zypheron ai stop
zypheron ai start
zypheron ai status
```
