# dbg-cli

`dbg-cli` is the user interface crate for Phase 2.

## Responsibilities

- One-shot command mode (`run`, `attach`, `continue`, `status`, `detach`, `kill`)
- Interactive REPL mode
- Register commands (`regs read`, `regs write`)
- Stop-path metric printing (`metrics`)

## Internal wiring

- Instantiates `LinuxBackend`
- Wraps it in `DebugEngine`
- Translates CLI/REPL commands into engine calls
- Prints state and stop events for users

## REPL commands

- `run <program> [args...]`
- `attach <pid>`
- `continue|c [count]`
- `status`
- `detach`
- `kill|terminate`
- `metrics`
- `regs read all|<name>`
- `regs write <name> <value>`
- `help`
- `quit|q|exit`
