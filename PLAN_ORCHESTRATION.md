# Zypheron Orchestration Plan (Draft)

This plan aligns with a TUI-first, human-in-the-loop model and optional Temporal orchestration with a fallback in-process orchestrator.

## 1) Shared Contracts (Go + Python)
- Define shared JSON schemas for:
  - `ApprovalRequest` / `ApprovalDecision`
  - `ProgressEvent`
  - `ErrorTaxonomy` (transient vs permanent)
  - `AuditEvent`
- Store in a shared folder (e.g., `zypheron/contract/`) and load from both Go and Python.

## 2) Human-in-the-Loop Approvals (TUI-First)
- Add a queued approvals panel in the TUI:
  - Actions: `Yes`, `No`, `Allow for session`, `Allow always`, `Something different` (reprompt)
- Persist allow-always to `~/.zypheron/approvals.json`.
- Session allows remain in memory only.
- Enforce approvals for:
  - Exploits, privilege escalation, malicious/OPSEC-sensitive actions
  - Intense recon and other critical decisions
  - Tool executions as required per command

## 3) Optional Temporal Orchestration With Fallback
- If Temporal is available:
  - Use Temporal workflows for durability
  - Heartbeats for long-running tools
  - Retry transient errors by taxonomy
  - Pause before approval-gated actions
- If Temporal is not available:
  - Use current in-process orchestration
  - Persist minimal state to survive app restart

## 4) Explicit Agent Graph + Parallel Groups
- Centralize agent dependencies and parallelism in a single graph definition.
- Use the same graph in Temporal workflows and fallback orchestrator.

## 5) Pipeline-Level Retries
- Implement consistent retry policy in Go and Python using the shared error taxonomy.

## 6) Queue Validation Gates
- Validate vuln artifacts before exploit/report phases.
- If validation fails, route to approval panel for override or correction.

## 7) Router Mode (In-Process Fallback, Optional Go Policy Wrapper)
- Python AI manager uses provider priority list with timeouts, backoff, and failover.
- Optional Go policy wrapper to enforce per-session restrictions.

## 8) Append-Only Audit Logs
- Append-only JSONL logs in `~/.zypheron/audit/` with atomic write + flush.
- Default TUI shows summary; Ctrl+O reveals full raw stream.

---

## Open Questions (Needed to Finalize)
1. Do you want a global "ask me for everything" toggle, or only per-command policy?
2. For "Something different," should the user be able to edit parameters (target/flags), or only provide rationale?
3. Should approvals be scoped by target/domain or global only?
4. Should report export require approval, or always allowed?
5. Should fallback state be a single file or per-run directory?
