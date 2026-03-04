# dbg-core

`dbg-core` defines the shared debugger domain model used by every other crate.

## Responsibilities

- Core error model (`DebugError`)
- Strongly typed IDs (`ProcessId`, `ThreadId`)
- Stop classification (`StopEvent`, `StopReason`)
- Register payload type (`RegisterValue`)
- Backend control contract (`DebugBackend`)
- Shutdown policy semantics (`ShutdownPolicy`)

## Why this crate exists

This crate keeps domain rules independent from OS-specific syscalls. The engine and CLI can rely on stable types while backends (`dbg-linux`) can be swapped without changing orchestration code.

## Invariants carried by this API

- At most one active inferior per backend instance
- APIs that require an inferior must return `MissingInferior` when none exists
- `launch`/`attach` must return `InferiorAlreadyActive` when already active
- `ShutdownPolicy::Detach` keeps the process alive; `Terminate` kills it

## Used by

- `dbg-engine` (state machine + metrics)
- `dbg-linux` (Linux ptrace backend)
- `dbg-regs-x64` (register alias mapping)
- `dbg-cli` (presentation and user input)
