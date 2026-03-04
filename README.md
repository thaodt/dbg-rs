# debugger-rs

a Linux x86_64 debugger in Rust (`ptrace`):
- process lifecycle control (`launch`, `attach`, `continue`, `detach`, `terminate`)
- x86_64 register read/write with alias-aware semantics (`rax/eax/ax/al/ah`, etc.)
- stop-path latency + `ptrace` roundtrip metrics.
