# dbg-engine

`dbg-engine` is the orchestration layer above backends.

## Responsibilities

- Session state machine (`RunState`, `EngineState`)
- Lifecycle guards (`launch/attach/continue/detach/terminate`)
- Stop-path performance accounting (`StopPathMetrics`)
- Stable façade over `DebugBackend`

## Dataflow

1. Call backend operation (`launch`, `attach`, `resume`, `wait_for_stop`, ...)
2. Normalize resulting stop into `EngineState`
3. Record stop-path latency and ptrace delta for `continue -> stop`
4. Expose snapshots to callers (`state`, `stop_path_snapshot`)

## Why this crate exists

The engine isolates debugger control policy from syscall details. This keeps hot-path behavior testable via mock backends and avoids pushing lifecycle logic into platform crates.

## Key output

`StopPathSnapshot` reports:

- `samples`, `min/p50/p95/p99/max`, `mean` latency (`us`)
- `total_ptrace_calls`, `avg_ptrace_calls_per_stop`
