# Claude Code Architecture and Adoption Plan for Zypheron

## Purpose

This document explains how Claude Code works at a systems level and lays out a concrete plan for applying the parts that fit to Zypheron at:

- `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production`

This is not a proposal to turn Zypheron into a clone of Claude Code. The goal is to reuse the durable architectural ideas:

- a single agent runtime
- a typed tool contract
- policy-aware tool execution
- resumable task orchestration
- context and memory management
- a cleaner boundary between UI, orchestration, and execution

## Sources Reviewed

Claude Code reference sources:

- `/home/zero/collection-claude-code-source-code/claude-code-source-code/src/main.tsx`
- `/home/zero/collection-claude-code-source-code/claude-code-source-code/src/query.ts`
- `/home/zero/collection-claude-code-source-code/claude-code-source-code/src/Tool.ts`
- `/home/zero/collection-claude-code-source-code/claude-code-source-code/src/tools.ts`
- `https://github.com/chauncygu/collection-claude-code-source-code`
- `https://ccunpacked.dev/`
- `https://github.com/zackautocracy/claude-code/tree/main`

Zypheron sources reviewed:

- `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/README.md`
- `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/PLAN_ORCHESTRATION.md`
- `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/docs/reports/CODE_ARCHITECTURE_REVIEW.md`
- `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-go/cmd/zypheron/main.go`
- `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-go/internal/aibridge/bridge.go`
- `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-go/internal/commands/chat.go`
- `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-go/internal/commands/autopent.go`
- `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-ai/core/server.py`
- `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-ai/providers/manager.py`
- `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-ai/core/memory.py`
- `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-ai/autopent/autonomous_orchestrator.py`
- `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-ai/autopent/approval_manager.py`
- `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-ai/mcp_interface/server.py`
- `/home/zero/Downloads/Zypheron project/Zypheron-CLI-Production/zypheron-mcp.json`

## How Claude Code Works

Claude Code is best understood as a layered agent runtime, not just a CLI with commands.

### 1. Bootstrap and environment assembly

The entrypoint in `src/main.tsx` does more than parse CLI args. It:

- initializes telemetry, config, auth, remote-managed settings, and feature flags
- loads commands and tool definitions
- prepares user context and system context
- starts the REPL or non-interactive execution path
- wires in plugins, MCP, skills, and state

The important idea is that Claude Code builds a runtime environment first, then runs the agent inside that environment.

### 2. One central query loop

The real core is `src/query.ts`.

This file implements an iterative loop that:

1. assembles prompt, history, system prompt, attachments, and runtime context
2. sends that state to the model
3. streams model output
4. detects tool invocations
5. executes approved tools
6. appends tool results back into history
7. repeats until the model reaches a terminal state

This matters because Claude Code does not let each command invent its own AI flow. The command surface feeds one execution engine.

### 3. Tools are typed runtime objects

`src/Tool.ts` defines the tool model and `src/tools.ts` builds the registry.

Each tool has:

- a stable name
- an input schema
- permission metadata
- execution logic
- context access
- progress and result reporting hooks

The agent runtime does not care whether the tool edits files, runs shell, calls MCP, searches the web, or spawns an agent. It treats them all through a common interface.

### 4. Permissions are first-class

Claude Code treats permissions as runtime policy, not ad hoc prompts.

The tool context carries:

- permission mode
- allow/deny/ask rules
- per-source policy
- additional working directory rules
- prompt suppression rules for background execution

The practical result is that safety and autonomy are tunable without rewriting tool code.

### 5. Context management is built into the loop

Claude Code expects long sessions. It includes:

- auto-compaction
- micro-compaction
- token budgeting
- prompt-too-long recovery
- transcript persistence
- memory attachment prefetch

This is important for Zypheron because offensive workflows produce long-lived sessions, large outputs, and multi-step operator decisions.

### 6. Tasks and multi-agent behavior sit above the same runtime

Claude Code adds:

- task objects
- background tasks
- subagents
- team/coordinator modes
- worktree isolation
- skill and plugin systems

These are not separate products. They are extensions on top of the same query and tool substrate.

## What the Zack Repository Adds

`zackautocracy/claude-code` is useful as a second confirmation point.

It presents the source snapshot as a larger, more direct `src/` mirror and highlights the same shape:

- entrypoint orchestration
- command registry
- tool registry
- query engine
- bridge, coordinator, plugins, skills, memdir, tasks

Its value for this plan is not unique code. Its value is corroboration that Claude Code is organized around:

- one agent engine
- many tools
- many UX surfaces
- one policy and state model

## Current Zypheron Architecture

Zypheron already has most of the raw ingredients needed to adopt this pattern.

### What Zypheron already has

Go CLI and UI:

- Cobra command surface in `zypheron-go/internal/commands/`
- root command bootstrap in `zypheron-go/cmd/zypheron/main.go`
- TUI support
- AI bridge bootstrap and auto-start behavior

Python runtime:

- IPC server in `zypheron-ai/core/server.py`
- provider orchestration in `zypheron-ai/providers/manager.py`
- memory persistence in `zypheron-ai/core/memory.py`
- autonomous orchestration in `zypheron-ai/autopent/autonomous_orchestrator.py`
- approvals in `zypheron-ai/autopent/approval_manager.py`

Integration plane:

- MCP server in `zypheron-ai/mcp_interface/server.py`
- MCP config in `zypheron-mcp.json`

### What Zypheron does not yet have

The missing piece was not more tools. It was a single control plane.

Today, Zypheron appears to have multiple separate AI execution styles:

- direct chat through the bridge
- command-specific AI behaviors
- autopent orchestration
- MCP tool exposure

Those were useful, but they were not unified behind one runtime contract when this plan began. Much of that unification now exists for chat, tasks, approvals, and part of the tool plane.

## Direct Mapping: Claude Code Concepts to Zypheron

### A. Query loop

Claude Code concept:

- one `query()` loop handles all turns, tools, context, and recovery

Zypheron fit:

- create a `ZypheronQueryEngine` in Python
- route `chat`, `autopent`, and future guided workflows through it
- preserve specialized modes, but make them configurations of one engine

Best initial placement:

- new module: `zypheron-ai/core/query_engine.py`

### B. Tool contract

Claude Code concept:

- tool definitions are typed objects with schema, policy, and executor

Zypheron fit:

- wrap scan, recon, exploit, reporting, search, loot, and MCP-backed operations under one tool interface
- stop treating these as only CLI subcommands or raw command invocations

Best initial placement:

- new package: `zypheron-ai/tools/`
- shared types: `zypheron-ai/tools/base.py`

### C. Permission context

Claude Code concept:

- permissions are a reusable runtime context

Zypheron fit:

- elevate `ApprovalManager` from autopent-only to runtime-wide policy
- unify interactive approval, session-wide approval, and always-deny rules
- attach risk labels to every tool, not only attack-path edges

Best initial placement:

- expand `zypheron-ai/autopent/approval_manager.py`
- or extract to `zypheron-ai/core/policy.py`

### D. Context and memory compaction

Claude Code concept:

- long-running sessions need managed context windows

Zypheron fit:

- use tiered memory and summarization for campaign sessions
- store compressed session summaries for long autopent or analyst sessions
- treat large tool outputs as artifacts with summaries, not raw prompt history

Best initial placement:

- expand `zypheron-ai/core/memory.py`
- add `zypheron-ai/core/compaction.py`

### E. Task orchestration

Claude Code concept:

- tasks are explicit units with progress, persistence, and optional background execution

Zypheron fit:

- turn scans, recon campaigns, report generation, and autopent runs into first-class task records
- let Go TUI observe and manage them rather than owning execution flow itself

Best initial placement:

- new package: `zypheron-ai/tasks/`
- Go side status client in `zypheron-go/internal/aibridge/`

### F. MCP and plugin interoperability

Claude Code concept:

- external capabilities are normalized through the same tool plane

Zypheron fit:

- do not keep MCP as a side interface only
- let the query engine invoke MCP tools using the same policy and event model as native tools

Best initial placement:

- new adapter layer inside `zypheron-ai/tools/mcp_adapter.py`

## Current Implementation Status

This document started as a migration plan. It is now partly a status document because much of the architecture has already been implemented.

### Implemented

- shared runtime contracts in `zypheron-ai/contracts/runtime.py`
- a Python-owned query engine in `zypheron-ai/core/query_engine.py`
- durable local task and audit storage in `zypheron-ai/tasks/store.py`
- shared runtime policy in `zypheron-ai/core/policy.py`
- typed tools and registry in `zypheron-ai/tools/base.py` and `zypheron-ai/tools/registry.py`
- chat routing through the query engine in `zypheron-ai/core/server.py`
- task inspection and approval IPC endpoints in `zypheron-ai/core/server.py`
- Go bridge support for task list, task events, and task approval in `zypheron-go/internal/aibridge/bridge.go`
- TUI runtime polling and approval widget in `zypheron-go/internal/tui/model.go` and `zypheron-go/internal/tui/components/approvalprompt.go`
- autopent task and audit emission in `zypheron-ai/autopent/autonomous_orchestrator.py`
- autopent shared-tool execution in `zypheron-ai/autopent/tool_executor.py`
- partial MCP-to-shared-tool routing in `zypheron-ai/mcp_interface/server.py` and `zypheron-ai/mcp_interface/tools.py`

### Smoke-tested

- dynamic autopent subprocess execution through `zypheron-ai/autopent/run_autopent.py`
- real approval gating and resume through the shared task store
- TUI runtime chat flow against the installed global binary
- TUI approval widget open, submit, and dismiss behavior

### Verified

- Python tests:
  - `zypheron-ai/tests/test_query_engine.py`
  - `zypheron-ai/tests/test_server.py`
  - `zypheron-ai/tests/test_mcp_shared_tools.py`
  - `zypheron-ai/tests/test_autopent_runtime.py`
- Go compile verification for:
  - `zypheron-go/internal/aibridge`
  - `zypheron-go/internal/commands`
  - `zypheron-go/internal/tui/...`

## Effective Architecture Today

The current control plane is no longer only a proposal. It is the effective runtime shape for chat and part of the workflow surface.

```text
Go CLI / TUI
  -> input, session UX, approval widget, task/event rendering

AIBridge / IPC
  -> transport and typed request/response plumbing

Python Query Engine
  -> chat turn execution
  -> tool planning for selected intents
  -> provider routing
  -> policy evaluation
  -> task persistence

Tool Layer
  -> typed native tools
  -> partial MCP shared-tool adapter
  -> autopent shared tool executor

Task / Audit Store
  -> SQLite-backed task records
  -> append-only audit events
  -> session approvals
```

## What Is Working Now

### 1. Shared contracts

Implemented in:

- `zypheron-ai/contracts/runtime.py`

Available concepts include:

- `TaskRecord`
- `TaskStatus`
- `ToolSpec`
- `ToolCall`
- `ToolResult`
- `ApprovalRequest`
- `AuditEvent`
- `QueryResponse`

This phase is complete enough to be considered the foundation for the rest of the runtime.

### 2. Query engine

Implemented in:

- `zypheron-ai/core/query_engine.py`

What it currently does:

- accepts chat turns from the IPC server
- persists task state
- plans a limited set of typed tool calls from natural-language prompts
- routes non-tool questions through provider chat
- pauses for approval where required
- resumes approved tool calls
- persists per-session approvals

Current typed tool usage includes:

- provider inspection
- memory store/search
- selected recon-oriented runtime tools such as `httpx_probe`

This is real and in use. It is not just a skeleton anymore.

### 3. Shared tool registry

Implemented in:

- `zypheron-ai/tools/base.py`
- `zypheron-ai/tools/registry.py`

What exists now:

- provider tools
- memory tools
- shared scan and recon tools
- typed risk metadata
- approval requirements
- structured execution context

Important detail:

- this is the authoritative execution path for the tools that have been migrated
- it is not yet the authoritative path for every MCP capability

### 4. Shared policy and approvals

Implemented in:

- `zypheron-ai/core/policy.py`
- `zypheron-ai/tasks/store.py`
- `zypheron-ai/core/server.py`

What exists now:

- runtime approval checks for shared tools
- per-session approval persistence
- audit events for approval required and approval decision
- runtime task approval endpoint through IPC

This is materially aligned with the Claude Code model.

### 5. Tasks and audit

Implemented in:

- `zypheron-ai/tasks/store.py`

Current task states in active use:

- `queued`
- `running`
- `waiting_approval`
- `completed`
- `failed`
- `aborted`

Exposed over IPC in:

- `task_list`
- `task_get`
- `task_events`
- `task_approve`

### 6. TUI integration

Implemented in:

- `zypheron-go/internal/aibridge/bridge.go`
- `zypheron-go/internal/tui/model.go`
- `zypheron-go/internal/tui/components/approvalprompt.go`

What exists now:

- runtime task polling
- runtime event rendering in the console
- approval modal for shared runtime tasks
- approval submission back to Python

Important note:

- the TUI now participates in the shared runtime instead of only launching separate AI flows

### 7. Autopent integration

Implemented in:

- `zypheron-ai/autopent/autonomous_orchestrator.py`
- `zypheron-ai/autopent/tool_executor.py`
- `zypheron-ai/autopent/run_autopent.py`

What exists now:

- autopent emits shared task and audit events
- autopent uses shared typed tools for supported attack edges
- autopent approvals can be resolved externally through the task store
- non-interactive autopent no longer reports false `completed` status after unrecovered failure

What was fixed during runtime validation:

- duplicate approval prompts on the same shared-tool step
- bad terminal status on failed autopent runs
- unbounded non-TTY waiting semantics
- missing `instructor` dependency causing hard runtime failure
- discovery stub producing no viable path for common demo objectives

## What Is Still Incomplete

### 1. MCP unification is partial

Status:

- partial

What is true now:

- several MCP tools call the shared registry first
- some recon and scan paths are already unified

What is not true yet:

- MCP is not fully normalized through the shared tool plane
- some MCP tools still execute through legacy raw-command paths
- MCP shared-tool execution still has policy-shape inconsistencies that should be cleaned up

### 2. Autopent is integrated but not fully converted

Status:

- partial

What is true now:

- autopent publishes into the shared task and audit model
- autopent can use shared typed tools

What is not true yet:

- autopent is not fully an engine client in the same sense as chat
- attack-graph logic still carries workflow-local control flow and fallback behavior
- simulation fallback still exists in some error paths

### 3. Context compaction is not implemented

Status:

- not implemented

Missing pieces:

- artifact summarization
- transcript compaction
- token-budget-aware pruning
- large-output reference model for long-running sessions

### 4. Full command migration is not finished

Status:

- partial

What is true now:

- runtime chat paths are real
- TUI approval/task participation is real

What is not true yet:

- not every AI-enabled command is just a request into the Python query engine
- some command-specific and legacy execution paths remain

## Revised Phase Status

### Phase 0: Shared contracts

Status:

- largely complete

### Phase 1: Python query engine

Status:

- implemented for chat/runtime turns

### Phase 2: Normalize tools

Status:

- implemented for an initial shared tool set

### Phase 3: Generalize policy and approvals

Status:

- implemented for the shared runtime path

### Phase 4: Convert autopent into an engine client

Status:

- partially complete

Autopent now participates in shared tools, tasks, and approvals, but still has workflow-local orchestration and incomplete unification.

### Phase 5: Context compaction and artifact summarization

Status:

- not started

### Phase 6: First-class tasks

Status:

- implemented

### Phase 7: Unify MCP with the main runtime

Status:

- partially complete

## Recommended Next Work

The plan should now focus on the remaining gaps instead of the original bootstrap work.

### Priority 1

- finish MCP migration to the shared typed tool plane
- remove or harden remaining legacy raw-command MCP paths
- align MCP policy handling with the main runtime instead of using a separate effective posture

### Priority 2

- remove remaining autopent simulation fallbacks where real execution should be authoritative
- finish migrating autopent control flow so shared tools and shared policy are the only approval/execution path

### Priority 3

- add artifact storage and compaction for long-running chat and campaign sessions
- move large tool outputs out of prompt replay and into summarized references

### Priority 4

- finish converting remaining command-specific AI flows into query-engine requests

## What Not to Copy from Claude Code

The original conclusion still stands.

Do not copy:

- product-specific telemetry behavior
- hidden feature-flag sprawl
- remote managed settings behavior
- worktree/team/subagent complexity before the security runtime is fully hardened

For Zypheron, the durable value remains:

- one runtime
- one tool model
- one policy model
- one task model
- one approval model

## Bottom Line

Claude Code’s main architectural lesson is still correct: one runtime and one tool plane scale better than many separate AI execution paths.

Zypheron has already crossed that line for chat, tasks, approvals, and part of the tool system. The document should no longer be read as “should we do this?” It should be read as “this is the architecture now, and these are the unfinished parts.”
