//! Debugger orchestration layer.
//!
//! The engine coordinates backend calls, enforces high-level lifecycle guards,
//! tracks run state, and records stop-path latency/ptrace metrics.

use std::time::{Duration, Instant};

use dbg_core::{
    DebugBackend, DebugError, ProcessId, RegisterValue, ShutdownPolicy, StopEvent, StopReason,
};
use hdrhistogram::Histogram;
use tracing::{debug, info};

/// Coarse runtime state of the debugger session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    /// No active inferior is owned.
    Idle,
    /// Inferior has been resumed and next stop is pending.
    Running,
    /// Inferior is currently stopped and inspectable.
    Stopped,
    /// Inferior has exited or was terminated.
    Exited,
}

/// In-memory state snapshot exposed to CLI and other callers.
#[derive(Debug, Clone, Copy)]
pub struct EngineState {
    /// Current run-state in the engine state machine.
    pub run_state: RunState,
    /// Active inferior process, if one is currently owned.
    pub active_process: Option<ProcessId>,
    /// Last observed stop event.
    pub last_stop: Option<StopEvent>,
}

impl Default for EngineState {
    fn default() -> Self {
        Self {
            run_state: RunState::Idle,
            active_process: None,
            last_stop: None,
        }
    }
}

/// Immutable metrics view for `continue -> stop` hot path.
#[derive(Debug, Clone, Copy)]
pub struct StopPathSnapshot {
    /// Number of recorded samples.
    pub samples: u64,
    /// Minimum stop latency in microseconds.
    pub min_us: u64,
    /// 50th percentile stop latency in microseconds.
    pub p50_us: u64,
    /// 95th percentile stop latency in microseconds.
    pub p95_us: u64,
    /// 99th percentile stop latency in microseconds.
    pub p99_us: u64,
    /// Maximum stop latency in microseconds.
    pub max_us: u64,
    /// Arithmetic mean stop latency in microseconds.
    pub mean_us: f64,
    /// Total ptrace calls consumed by all recorded stop transitions.
    pub total_ptrace_calls: u64,
    /// Average ptrace calls per stop sample.
    pub avg_ptrace_calls_per_stop: f64,
}

/// Mutable accumulator for stop-path latency and ptrace accounting.
pub struct StopPathMetrics {
    histogram_us: Histogram<u64>,
    samples: u64,
    total_ptrace_calls: u64,
}

impl Default for StopPathMetrics {
    fn default() -> Self {
        let histogram_us = Histogram::new_with_bounds(1, 60_000_000, 3)
            .expect("histogram bounds are compile-time valid");
        Self {
            histogram_us,
            samples: 0,
            total_ptrace_calls: 0,
        }
    }
}

impl StopPathMetrics {
    /// Record one stop transition latency and ptrace delta.
    pub fn record(&mut self, latency: Duration, ptrace_delta: u64) {
        let micros_raw = latency.as_micros().min(u128::from(u64::MAX)) as u64;
        let micros = micros_raw.max(1);

        if self.histogram_us.record(micros).is_ok() {
            self.samples += 1;
            self.total_ptrace_calls = self.total_ptrace_calls.saturating_add(ptrace_delta);
        }
    }

    /// Build an immutable snapshot suitable for printing/export.
    pub fn snapshot(&self) -> StopPathSnapshot {
        if self.samples == 0 {
            return StopPathSnapshot {
                samples: 0,
                min_us: 0,
                p50_us: 0,
                p95_us: 0,
                p99_us: 0,
                max_us: 0,
                mean_us: 0.0,
                total_ptrace_calls: 0,
                avg_ptrace_calls_per_stop: 0.0,
            };
        }

        StopPathSnapshot {
            samples: self.samples,
            min_us: self.histogram_us.min(),
            p50_us: self.histogram_us.value_at_quantile(0.50),
            p95_us: self.histogram_us.value_at_quantile(0.95),
            p99_us: self.histogram_us.value_at_quantile(0.99),
            max_us: self.histogram_us.max(),
            mean_us: self.histogram_us.mean(),
            total_ptrace_calls: self.total_ptrace_calls,
            avg_ptrace_calls_per_stop: self.total_ptrace_calls as f64 / self.samples as f64,
        }
    }
}

/// High-level debugger engine parameterized over a backend implementation.
pub struct DebugEngine<B: DebugBackend> {
    backend: B,
    state: EngineState,
    stop_path_metrics: StopPathMetrics,
}

impl<B: DebugBackend> DebugEngine<B> {
    /// Create a new engine from a backend.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            state: EngineState::default(),
            stop_path_metrics: StopPathMetrics::default(),
        }
    }

    /// Launch a new inferior process.
    ///
    /// Fails with [`DebugError::InferiorAlreadyActive`] if one is already active.
    pub fn launch(&mut self, program: &str, args: &[String]) -> Result<StopEvent, DebugError> {
        if self.state.active_process.is_some() {
            return Err(DebugError::InferiorAlreadyActive);
        }
        debug!(%program, arg_count = args.len(), "launch request");
        let event = self.backend.launch(program, args)?;
        self.on_stop(event);
        info!(
            pid = self.state.active_process.map(|pid| pid.get()),
            tid = event.tid.get(),
            reason = %event.reason,
            "inferior launched and stopped"
        );
        Ok(event)
    }

    /// Attach to an existing process.
    ///
    /// Fails with [`DebugError::InferiorAlreadyActive`] if one is already active.
    pub fn attach(&mut self, pid: ProcessId) -> Result<StopEvent, DebugError> {
        if self.state.active_process.is_some() {
            return Err(DebugError::InferiorAlreadyActive);
        }
        debug!(pid = pid.get(), "attach request");
        let event = self.backend.attach(pid)?;
        self.on_stop(event);
        info!(pid = pid.get(), tid = event.tid.get(), reason = %event.reason, "inferior attached");
        Ok(event)
    }

    /// Resume execution and wait for the next stop event.
    ///
    /// Records stop latency and ptrace roundtrip delta for diagnostics.
    pub fn continue_exec(&mut self) -> Result<StopEvent, DebugError> {
        if self.state.active_process.is_none() {
            return Err(DebugError::MissingInferior);
        }

        self.state.run_state = RunState::Running;

        let ptrace_before = self.backend.ptrace_call_count();
        let started = Instant::now();

        self.backend.resume()?;
        let event = self.backend.wait_for_stop()?;

        let latency = started.elapsed();
        let ptrace_after = self.backend.ptrace_call_count();
        let ptrace_delta = ptrace_after.saturating_sub(ptrace_before);
        self.stop_path_metrics.record(latency, ptrace_delta);

        self.on_stop(event);

        let latency_us = latency.as_micros().min(u128::from(u64::MAX)) as u64;
        info!(
            tid = event.tid.get(),
            reason = %event.reason,
            latency_us,
            ptrace_delta,
            "continue -> stop"
        );

        Ok(event)
    }

    /// Return a copy of the current engine state.
    pub fn state(&self) -> EngineState {
        self.state
    }

    /// Return a snapshot of stop-path latency/ptrace metrics.
    pub fn stop_path_snapshot(&self) -> StopPathSnapshot {
        self.stop_path_metrics.snapshot()
    }

    /// Shutdown the active inferior according to policy.
    pub fn shutdown(&mut self, policy: ShutdownPolicy) -> Result<(), DebugError> {
        if self.state.active_process.is_none() {
            return Err(DebugError::MissingInferior);
        }

        self.backend.shutdown(policy)?;
        self.state.active_process = None;
        self.state.run_state = RunState::Idle;
        Ok(())
    }

    /// Read one register from the active inferior.
    pub fn read_register(&mut self, name: &str) -> Result<RegisterValue, DebugError> {
        self.backend.read_register(name)
    }

    /// Write one register on the active inferior.
    pub fn write_register(&mut self, name: &str, value: u64) -> Result<RegisterValue, DebugError> {
        self.backend.write_register(name, value)
    }

    /// Read canonical register set from the active inferior.
    pub fn read_all_registers(&mut self) -> Result<Vec<RegisterValue>, DebugError> {
        self.backend.read_all_registers()
    }

    /// Convenience wrapper for `shutdown(Detach)`.
    pub fn detach(&mut self) -> Result<(), DebugError> {
        self.shutdown(ShutdownPolicy::Detach)
    }

    /// Convenience wrapper for `shutdown(Terminate)`.
    pub fn terminate(&mut self) -> Result<(), DebugError> {
        self.shutdown(ShutdownPolicy::Terminate)
    }

    /// Update engine state based on a newly observed stop event.
    fn on_stop(&mut self, event: StopEvent) {
        self.state.active_process = self.backend.active_process();
        self.state.last_stop = Some(event);
        self.state.run_state = match event.reason {
            StopReason::Exited { .. } | StopReason::Terminated { .. } => RunState::Exited,
            _ => RunState::Stopped,
        };
    }
}

#[cfg(test)]
mod tests {
    use dbg_core::{
        DebugBackend, DebugError, ProcessId, RegisterValue, ShutdownPolicy, StopEvent, StopReason,
        ThreadId,
    };

    use super::{DebugEngine, RunState};

    struct MockBackend {
        active: Option<ProcessId>,
        ptrace_calls: u64,
        next_stop: StopEvent,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                active: Some(ProcessId::new(1234).expect("valid test pid")),
                ptrace_calls: 0,
                next_stop: StopEvent {
                    tid: ThreadId::new(1234).expect("valid tid"),
                    reason: StopReason::Signal { signal: 5 },
                },
            }
        }
    }

    impl DebugBackend for MockBackend {
        fn launch(&mut self, _program: &str, _args: &[String]) -> Result<StopEvent, DebugError> {
            Ok(self.next_stop)
        }

        fn attach(&mut self, _pid: ProcessId) -> Result<StopEvent, DebugError> {
            Ok(self.next_stop)
        }

        fn resume(&mut self) -> Result<(), DebugError> {
            self.ptrace_calls += 1;
            Ok(())
        }

        fn wait_for_stop(&mut self) -> Result<StopEvent, DebugError> {
            Ok(self.next_stop)
        }

        fn read_register(&mut self, _name: &str) -> Result<RegisterValue, DebugError> {
            Ok(RegisterValue {
                name: "rax",
                bits: 64,
                value: 0xdead_beef,
            })
        }

        fn write_register(&mut self, _name: &str, value: u64) -> Result<RegisterValue, DebugError> {
            Ok(RegisterValue {
                name: "rax",
                bits: 64,
                value,
            })
        }

        fn read_all_registers(&mut self) -> Result<Vec<RegisterValue>, DebugError> {
            Ok(vec![RegisterValue {
                name: "rax",
                bits: 64,
                value: 1,
            }])
        }

        fn shutdown(&mut self, _policy: ShutdownPolicy) -> Result<(), DebugError> {
            self.active = None;
            Ok(())
        }

        fn active_process(&self) -> Option<ProcessId> {
            self.active
        }

        fn ptrace_call_count(&self) -> u64 {
            self.ptrace_calls
        }
    }

    #[test]
    fn continue_updates_state_and_metrics() {
        let mut engine = DebugEngine::new(MockBackend::new());

        let launch = engine
            .launch("/bin/true", &[])
            .expect("launch should provide initial stop event");
        assert_eq!(launch.reason, StopReason::Signal { signal: 5 });

        let stop = engine.continue_exec().expect("continue should stop again");
        assert_eq!(stop.reason, StopReason::Signal { signal: 5 });
        assert_eq!(engine.state().run_state, RunState::Stopped);

        let snap = engine.stop_path_snapshot();
        assert_eq!(snap.samples, 1);
        assert!(snap.mean_us >= 0.0);
    }

    #[test]
    fn continue_requires_active_inferior() {
        let mut backend = MockBackend::new();
        backend.active = None;
        let mut engine = DebugEngine::new(backend);

        let err = engine
            .continue_exec()
            .expect_err("continue should fail without inferior");
        assert!(matches!(err, DebugError::MissingInferior));
    }

    #[test]
    fn detach_transitions_to_idle() {
        let mut engine = DebugEngine::new(MockBackend::new());
        engine
            .launch("/bin/true", &[])
            .expect("launch should set active inferior");

        engine.detach().expect("detach should succeed");

        assert_eq!(engine.state().run_state, RunState::Idle);
        assert!(engine.state().active_process.is_none());
    }

    #[test]
    fn engine_register_passthrough_works() {
        let mut engine = DebugEngine::new(MockBackend::new());
        engine
            .launch("/bin/true", &[])
            .expect("launch should activate backend");

        let rax = engine.read_register("rax").expect("read should work");
        assert_eq!(rax.value, 0xdead_beef);

        let updated = engine
            .write_register("rax", 0x1234)
            .expect("write should work");
        assert_eq!(updated.value, 0x1234);

        let all = engine.read_all_registers().expect("read_all should work");
        assert_eq!(all.len(), 1);
    }
}
