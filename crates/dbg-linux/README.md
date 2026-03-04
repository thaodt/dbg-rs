# dbg-linux

`dbg-linux` implements the `DebugBackend` trait using Linux `ptrace` + `waitpid`.

## Responsibilities

- Inferior launch (`fork` + child `ptrace(TRACEME)` + `execvp`)
- Attach to existing pid (`ptrace::attach`)
- Continue/wait control loop (`ptrace::cont`, `waitpid(__WALL)`)
- Register frame IO (`PTRACE_GETREGS` / `PTRACE_SETREGS`)
- Shutdown policy execution (`detach` vs `terminate`)
- Ptrace roundtrip accounting (`ptrace_call_count`)

## Ownership model

One `LinuxBackend` instance owns at most one inferior. Ownership is tracked as:

- `Launched`: backend created process
- `Attached`: backend attached to existing process

Drop-time fallback cleanup uses ownership:

- `Attached -> Detach`
- `Launched -> Terminate`

## Notes

- `waitpid(__WALL)` is used for ptrace-compatible status collection
- Initial stop is collected after `launch`/`attach` before normal continue loop
- Register alias semantics are delegated to `dbg-regs-x64`
