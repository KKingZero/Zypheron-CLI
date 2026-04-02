# Zypheron Orchestration Status and Next Steps

This file records the current orchestration architecture and the remaining work. It is no longer a pure draft.

## Current State

Zypheron now has a shared runtime for part of the product:

- chat requests are routed through `zypheron-ai/core/query_engine.py`
- task state and audit events are persisted in `zypheron-ai/tasks/store.py`
- approvals are handled through the shared runtime policy path and `task_approve`
- the Go TUI can poll runtime tasks and render approval prompts
- autopent emits shared task and audit records and uses shared typed tools for supported edges
- MCP partially routes through the shared typed tool registry

## Effective Control Plane

```text
Go CLI / TUI
  -> input
  -> approval UX
  -> task/event rendering

AIBridge / IPC
  -> request/response transport

Python Runtime
  -> query engine
  -> policy
  -> typed tools
  -> task and audit store

Workflow Clients
  -> chat
  -> partial autopent integration
  -> partial MCP integration
```

## What Is Already Done

### Shared contracts

Implemented in:

- `zypheron-ai/contracts/runtime.py`

### Shared runtime tasks

Implemented in:

- `zypheron-ai/tasks/store.py`
- `zypheron-ai/core/server.py`

Exposed operations:

- `task_list`
- `task_get`
- `task_events`
- `task_approve`

### Query-engine orchestration

Implemented in:

- `zypheron-ai/core/query_engine.py`

Current use:

- chat turns
- typed tool execution for selected intents
- approval pause/resume
- per-session approval persistence

### TUI runtime approval flow

Implemented in:

- `zypheron-go/internal/aibridge/bridge.go`
- `zypheron-go/internal/tui/model.go`
- `zypheron-go/internal/tui/components/approvalprompt.go`

Validated behavior:

- waiting approvals surface in the TUI
- approval submission round-trips through the Python runtime
- prompt dismissal no longer immediately reopens on the next poll cycle

### Autopent shared-runtime participation

Implemented in:

- `zypheron-ai/autopent/autonomous_orchestrator.py`
- `zypheron-ai/autopent/tool_executor.py`
- `zypheron-ai/autopent/run_autopent.py`

Validated behavior:

- shared task emission
- approval-required task state
- external approval resolution through the task store
- correct `failed` terminal state after unrecovered step failure

## What Is Still Partial

### MCP

Current state:

- some tools use `execute_shared_tool()` first
- some tools still use legacy raw-command execution

Remaining work:

- finish migrating MCP tools to the shared typed tool registry
- remove or harden remaining raw-command MCP surfaces
- align MCP runtime policy posture with the main shared runtime

### Autopent

Current state:

- participates in shared tools, tasks, and approvals
- still owns workflow-specific orchestration and fallback behavior

Remaining work:

- remove remaining simulation fallback paths where real execution should be authoritative
- continue converging autopent approval and execution semantics onto the shared runtime model
- decide whether autopent should eventually become a direct query-engine workflow client

### Context compaction

Current state:

- not implemented

Remaining work:

- artifact references for large tool output
- summarization for long-lived sessions
- token-budget-aware history management

## Recommended Next Priorities

1. Finish MCP unification and eliminate remaining unsafe legacy paths.
2. Continue tightening autopent so shared tools and shared approvals are authoritative.
3. Add artifact storage and context compaction.
4. Move more command-specific AI behavior behind the query engine.

## Non-Goals for Now

Do not prioritize these before the shared runtime is fully hardened:

- Temporal orchestration
- multi-agent coordinator layers
- worktree/subagent complexity
- broad “always allow” approval semantics

## Reference Docs

- [docs/CLAUDE_CODE_ADOPTION_PLAN.md](docs/CLAUDE_CODE_ADOPTION_PLAN.md)
- [BUILD_AND_TEST.md](BUILD_AND_TEST.md)
- [docs/AI_GUIDE.md](docs/AI_GUIDE.md)
- [docs/MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md)
