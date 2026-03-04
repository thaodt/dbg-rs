//! Command-line interface and REPL for `dbg-rs` Phase 2.

use std::io::{self, Write};

use clap::{Parser, Subcommand};
use dbg_core::{DebugError, ProcessId, RegisterValue, StopEvent, StopReason};
use dbg_engine::{DebugEngine, EngineState};
use dbg_linux::LinuxBackend;
use tracing_subscriber::{EnvFilter, fmt};

/// Top-level CLI arguments.
#[derive(Parser, Debug)]
#[command(
    name = "dbg",
    version,
    about = "Phase 2 debugger CLI (process lifecycle + registers)",
    propagate_version = true
)]
struct Cli {
    /// Optional one-shot command. If omitted, interactive REPL starts.
    #[command(subcommand)]
    command: Option<Command>,
}

/// Supported one-shot commands.
#[derive(Subcommand, Debug)]
enum Command {
    /// Launch a new inferior and stop on the first debugger-visible event.
    Run {
        /// Program path to execute.
        program: String,
        /// Program arguments passed to inferior.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
        /// Number of `continue` cycles after initial launch stop.
        #[arg(short = 'c', long = "continue", default_value_t = 1)]
        continue_count: u32,
    },
    /// Attach to an existing pid and stop.
    Attach {
        /// Target pid.
        pid: i32,
        /// Number of `continue` cycles after initial attach stop.
        #[arg(short = 'c', long = "continue", default_value_t = 1)]
        continue_count: u32,
    },
    /// Continue the currently active inferior.
    Continue {
        /// Number of continue cycles.
        #[arg(default_value_t = 1)]
        count: u32,
    },
    /// Print in-memory engine state.
    Status,
    /// Detach from inferior and keep it running.
    Detach,
    /// Terminate inferior process.
    Kill,
}

/// Program entry point.
fn main() {
    init_tracing();
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

/// Initialize tracing subscriber from environment, defaulting to `info`.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(filter).with_target(false).try_init();
}

/// Execute one-shot command or start REPL.
fn run() -> Result<(), DebugError> {
    let cli = Cli::parse();
    let backend = LinuxBackend::new();
    let mut engine = DebugEngine::new(backend);

    match cli.command {
        Some(Command::Run {
            program,
            args,
            continue_count,
        }) => {
            let stop = engine.launch(&program, &args)?;
            print_stop_with_context(&mut engine, "launch", stop);
            continue_loop(&mut engine, continue_count)?;
        }
        Some(Command::Attach {
            pid,
            continue_count,
        }) => {
            let pid = ProcessId::new(pid)?;
            let stop = engine.attach(pid)?;
            print_stop_with_context(&mut engine, "attach", stop);
            continue_loop(&mut engine, continue_count)?;
        }
        Some(Command::Continue { count }) => {
            continue_loop(&mut engine, count)?;
        }
        Some(Command::Status) => {
            print_status(engine.state());
        }
        Some(Command::Detach) => {
            engine.detach()?;
            println!("detached");
        }
        Some(Command::Kill) => {
            engine.terminate()?;
            println!("terminated");
        }
        None => repl(&mut engine)?,
    }

    Ok(())
}

/// Interactive debugger REPL loop.
fn repl(engine: &mut DebugEngine<LinuxBackend>) -> Result<(), DebugError> {
    println!("dbg repl: run/attach/continue/status/detach/kill/metrics/regs/help/quit");

    let stdin = io::stdin();
    loop {
        print!("dbg> ");
        io::stdout().flush()?;

        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            safe_detach_on_exit(engine)?;
            println!();
            return Ok(());
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts = line.split_whitespace().collect::<Vec<_>>();
        match parts[0] {
            "run" => {
                if parts.len() < 2 {
                    println!("usage: run <program> [args...]");
                    continue;
                }
                let program = parts[1].to_string();
                let args = parts[2..]
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect::<Vec<_>>();
                match engine.launch(&program, &args) {
                    Ok(stop) => print_stop_with_context(engine, "launch", stop),
                    Err(err) => eprintln!("error: {err}"),
                }
            }
            "attach" => {
                if parts.len() != 2 {
                    println!("usage: attach <pid>");
                    continue;
                }
                let pid = match parse_i32(parts[1]) {
                    Ok(pid) => pid,
                    Err(err) => {
                        eprintln!("{err}");
                        continue;
                    }
                };

                match ProcessId::new(pid).and_then(|p| engine.attach(p)) {
                    Ok(stop) => print_stop_with_context(engine, "attach", stop),
                    Err(err) => eprintln!("error: {err}"),
                }
            }
            "continue" | "c" => {
                let count = if parts.len() >= 2 {
                    match parse_u32(parts[1]) {
                        Ok(v) => v,
                        Err(err) => {
                            eprintln!("{err}");
                            continue;
                        }
                    }
                } else {
                    1
                };

                if let Err(err) = continue_loop(engine, count) {
                    eprintln!("error: {err}");
                }
            }
            "status" => print_status(engine.state()),
            "detach" => match engine.detach() {
                Ok(()) => println!("detached"),
                Err(err) => eprintln!("error: {err}"),
            },
            "kill" | "terminate" => match engine.terminate() {
                Ok(()) => println!("terminated"),
                Err(err) => eprintln!("error: {err}"),
            },
            "metrics" => print_metrics(engine),
            "regs" => handle_regs_command(engine, &parts),
            "help" | "?" => print_help(),
            "quit" | "q" | "exit" => {
                safe_detach_on_exit(engine)?;
                return Ok(());
            }
            other => eprintln!("unknown command: {other}"),
        }
    }
}

/// Detach from active inferior when leaving REPL.
fn safe_detach_on_exit(engine: &mut DebugEngine<LinuxBackend>) -> Result<(), DebugError> {
    if engine.state().active_process.is_some() {
        engine.detach()?;
        println!("auto-detached inferior");
    }
    Ok(())
}

/// Perform `continue` loop and print stop context for each iteration.
fn continue_loop(
    engine: &mut DebugEngine<LinuxBackend>,
    continue_count: u32,
) -> Result<(), DebugError> {
    for idx in 0..continue_count {
        let stop = engine.continue_exec()?;
        print_stop_with_context(engine, &format!("continue[{idx}]"), stop);

        if matches!(
            stop.reason,
            StopReason::Exited { .. } | StopReason::Terminated { .. }
        ) {
            break;
        }
    }

    Ok(())
}

/// Print a stop event with current engine run-state.
fn print_stop_with_context(engine: &mut DebugEngine<LinuxBackend>, context: &str, stop: StopEvent) {
    println!(
        "{context}: tid={} reason={} run_state={:?}",
        stop.tid.get(),
        stop.reason,
        engine.state().run_state
    );
}

/// Print human-readable engine state.
fn print_status(state: EngineState) {
    println!("run_state: {:?}", state.run_state);
    println!(
        "active_process: {}",
        state
            .active_process
            .map(|pid| pid.get().to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    println!(
        "last_stop: {}",
        state
            .last_stop
            .map(|stop| format!("tid={} reason={}", stop.tid.get(), stop.reason))
            .unwrap_or_else(|| "none".to_string())
    );
}

/// Print stop-path metrics snapshot.
fn print_metrics(engine: &DebugEngine<LinuxBackend>) {
    let snap = engine.stop_path_snapshot();
    println!("stop_path_metrics:");
    println!("  samples={}", snap.samples);
    println!("  min_us={}", snap.min_us);
    println!("  p50_us={}", snap.p50_us);
    println!("  p95_us={}", snap.p95_us);
    println!("  p99_us={}", snap.p99_us);
    println!("  max_us={}", snap.max_us);
    println!("  mean_us={:.2}", snap.mean_us);
    println!("  total_ptrace_calls={}", snap.total_ptrace_calls);
    println!(
        "  avg_ptrace_calls_per_stop={:.2}",
        snap.avg_ptrace_calls_per_stop
    );
}

/// Handle REPL `regs` subcommands.
fn handle_regs_command(engine: &mut DebugEngine<LinuxBackend>, parts: &[&str]) {
    if parts.len() < 3 {
        println!("usage: regs read <name|all> | regs write <name> <value>");
        return;
    }

    match parts[1] {
        "read" => {
            let name = parts[2];
            if name == "all" {
                match engine.read_all_registers() {
                    Ok(values) => print_registers(&values),
                    Err(err) => eprintln!("error: {err}"),
                }
            } else {
                match engine.read_register(name) {
                    Ok(value) => println!("{value}"),
                    Err(err) => eprintln!("error: {err}"),
                }
            }
        }
        "write" => {
            if parts.len() < 4 {
                println!("usage: regs write <name> <value>");
                return;
            }

            let value = match parse_u64(parts[3]) {
                Ok(v) => v,
                Err(err) => {
                    eprintln!("{err}");
                    return;
                }
            };

            match engine.write_register(parts[2], value) {
                Ok(updated) => println!("{updated}"),
                Err(err) => eprintln!("error: {err}"),
            }
        }
        other => eprintln!("unknown regs command: {other}"),
    }
}

/// Print one register value per line.
fn print_registers(values: &[RegisterValue]) {
    if values.is_empty() {
        println!("no registers");
        return;
    }

    for value in values {
        println!("{value}");
    }
}

/// Parse `u64` supporting prefixes: `0x`, `0b`, and `0o`.
fn parse_u64(raw: &str) -> Result<u64, String> {
    if let Some(hex) = raw.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|e| format!("invalid hex value `{raw}`: {e}"))
    } else if let Some(bin) = raw.strip_prefix("0b") {
        u64::from_str_radix(bin, 2).map_err(|e| format!("invalid binary value `{raw}`: {e}"))
    } else if let Some(oct) = raw.strip_prefix("0o") {
        u64::from_str_radix(oct, 8).map_err(|e| format!("invalid octal value `{raw}`: {e}"))
    } else {
        raw.parse::<u64>()
            .map_err(|e| format!("invalid decimal value `{raw}`: {e}"))
    }
}

/// Parse `u32` using `parse_u64` and range-checking.
fn parse_u32(raw: &str) -> Result<u32, String> {
    let value = parse_u64(raw)?;
    u32::try_from(value).map_err(|_| format!("value out of range for u32: {value}"))
}

/// Parse signed 32-bit integer.
fn parse_i32(raw: &str) -> Result<i32, String> {
    raw.parse::<i32>()
        .map_err(|e| format!("invalid i32 value `{raw}`: {e}"))
}

/// Print REPL help text.
fn print_help() {
    println!("commands:");
    println!("  run <program> [args...]   launch and stop at first event");
    println!("  attach <pid>              attach to existing process");
    println!("  continue|c [count]        resume process count times");
    println!("  status                    print engine state");
    println!("  detach                    detach and keep process alive");
    println!("  kill                      terminate inferior process");
    println!("  metrics                   print stop-path latency + ptrace stats");
    println!("  regs read all|<name>      read registers");
    println!("  regs write <name> <val>   write register");
    println!("  help                      print this help");
    println!("  quit|q|exit               exit repl (auto-detach)");
}
