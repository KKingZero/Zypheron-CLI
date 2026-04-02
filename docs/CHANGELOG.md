# Changelog

## [2.0.0] - 2026-04-02

### Runtime and Orchestration

- unified the Python query engine, shared tool registry, task store, and policy layer
- added durable task and audit records for runtime actions
- migrated chat and related runtime flows to preserve the full task envelope

### TUI

- added a real approval widget for runtime tool approvals
- exposed task and event polling to the Go client
- improved prompt recovery and approval state handling

### Autopent

- kept the current subprocess UX while emitting shared task and approval events
- corrected denial and failure handling so denied actions do not fall into normal retry logic
- exercised the subprocess path and runtime approval behavior with dynamic smoke tests

### MCP and Tools

- moved shared recon tools toward the common typed registry
- tightened validation around shared recon tool execution
- reduced unsafe fallback behavior for shared tool paths

### Verification

- expanded Python coverage around query engine, server, MCP shared tools, and autopent runtime behavior
- verified Go bridge and TUI build surfaces against the updated runtime path
