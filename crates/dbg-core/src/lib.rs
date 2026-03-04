//! Core debugger domain model and backend contract.
//!
//! This crate is the stable "language" spoken by the engine, backend, and CLI:
//! process/thread identifiers, stop events, register values, lifecycle policies,
//! and the backend trait used by the orchestrator.

use std::fmt;
use std::num::NonZeroI32;

use thiserror::Error;

/// Domain-level debugger errors shared by all crates.
#[derive(Debug, Error)]
pub enum DebugError {
    /// A process/thread id was non-positive and therefore invalid on Linux.
    #[error("invalid pid: {0}")]
    InvalidPid(i32),
    /// Operation requires an active inferior, but none is currently owned.
    #[error("no active inferior process")]
    MissingInferior,
    /// `launch` or `attach` was requested while one inferior is already active.
    #[error("inferior process is already active")]
    InferiorAlreadyActive,
    /// Register name was not recognized by the target register map.
    #[error("unknown register: {0}")]
    UnknownRegister(String),
    /// A backend-specific error converted into a string boundary.
    #[error("backend error: {0}")]
    Backend(String),
    /// I/O error bubbled up from standard library operations.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl DebugError {
    /// Convert any displayable backend error into [`DebugError::Backend`].
    pub fn backend<E: fmt::Display>(err: E) -> Self {
        Self::Backend(err.to_string())
    }
}

/// Strongly-typed process id wrapper.
///
/// Uses `NonZeroI32` so invalid `0` cannot exist once constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessId(NonZeroI32);

impl ProcessId {
    /// Create a new process id from a raw Linux pid.
    pub fn new(raw: i32) -> Result<Self, DebugError> {
        if raw <= 0 {
            return Err(DebugError::InvalidPid(raw));
        }
        Ok(Self(
            NonZeroI32::new(raw).expect("positive integer is always non-zero"),
        ))
    }

    /// Return the raw integer pid value.
    pub fn get(self) -> i32 {
        self.0.get()
    }
}

/// Strongly-typed thread id wrapper.
///
/// Linux debugger wait events are often thread-scoped, so thread ids are
/// represented explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreadId(NonZeroI32);

impl ThreadId {
    /// Create a new thread id from a raw Linux tid.
    pub fn new(raw: i32) -> Result<Self, DebugError> {
        if raw <= 0 {
            return Err(DebugError::InvalidPid(raw));
        }
        Ok(Self(
            NonZeroI32::new(raw).expect("positive integer is always non-zero"),
        ))
    }

    /// Return the raw integer tid value.
    pub fn get(self) -> i32 {
        self.0.get()
    }
}

/// Why the inferior stopped according to `waitpid` / ptrace status decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// Stopped due to a signal delivery/trap.
    Signal { signal: i32 },
    /// Stopped due to a ptrace event code.
    PtraceEvent { event: i32, signal: i32 },
    /// Stopped at a syscall trap boundary.
    SyscallTrap,
    /// Process exited normally.
    Exited { code: i32 },
    /// Process terminated by signal, optionally with core dump.
    Terminated { signal: i32, core_dumped: bool },
    /// Status that does not currently map to a richer reason.
    Unknown,
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signal { signal } => write!(f, "signal-stop(sig={signal})"),
            Self::PtraceEvent { event, signal } => {
                write!(f, "ptrace-event(event={event}, sig={signal})")
            }
            Self::SyscallTrap => write!(f, "syscall-trap"),
            Self::Exited { code } => write!(f, "exited(code={code})"),
            Self::Terminated {
                signal,
                core_dumped,
            } => {
                write!(f, "terminated(sig={signal}, core_dumped={core_dumped})")
            }
            Self::Unknown => write!(f, "unknown-stop"),
        }
    }
}

/// A single debugger stop event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopEvent {
    /// Thread id reported by `waitpid`.
    pub tid: ThreadId,
    /// Classified reason for this stop.
    pub reason: StopReason,
}

/// Typed register payload returned by read/write operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterValue {
    /// Canonical register/alias name.
    pub name: &'static str,
    /// Bit width of the register view (for example 8/16/32/64).
    pub bits: u8,
    /// Value of the register view, already masked to `bits`.
    pub value: u64,
}

impl RegisterValue {
    /// Hex digit width required to print this value without truncation.
    pub fn hex_width(self) -> usize {
        (self.bits as usize).div_ceil(4)
    }
}

impl fmt::Display for RegisterValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let width = self.hex_width();
        write!(
            f,
            "{}: 0x{:0width$x} ({}) [{}-bit]",
            self.name,
            self.value,
            self.value,
            self.bits,
            width = width
        )
    }
}

/// Lifecycle action used when ending debugger ownership of the inferior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownPolicy {
    /// Detach tracer and keep target process alive.
    Detach,
    /// Force target process termination.
    Terminate,
}

/// Backend contract implemented by a concrete debugger backend (for now Linux ptrace).
pub trait DebugBackend {
    /// Launch a new inferior and return its initial stop event.
    fn launch(&mut self, program: &str, args: &[String]) -> Result<StopEvent, DebugError>;
    /// Attach to an existing process and return the first observed stop event.
    fn attach(&mut self, pid: ProcessId) -> Result<StopEvent, DebugError>;
    /// Resume the currently active inferior.
    fn resume(&mut self) -> Result<(), DebugError>;
    /// Block until the currently active inferior reports a stop event.
    fn wait_for_stop(&mut self) -> Result<StopEvent, DebugError>;
    /// Read a single register/alias by name.
    fn read_register(&mut self, name: &str) -> Result<RegisterValue, DebugError>;
    /// Write a single register/alias by name and return the normalized value.
    fn write_register(&mut self, name: &str, value: u64) -> Result<RegisterValue, DebugError>;
    /// Read a canonical register snapshot.
    fn read_all_registers(&mut self) -> Result<Vec<RegisterValue>, DebugError>;
    /// End debugger ownership according to the provided policy.
    fn shutdown(&mut self, policy: ShutdownPolicy) -> Result<(), DebugError>;
    /// Return the currently active process id, if any.
    fn active_process(&self) -> Option<ProcessId>;

    /// Count ptrace roundtrips performed by this backend.
    ///
    /// Backends that do not track this may keep the default `0`.
    fn ptrace_call_count(&self) -> u64 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::{ProcessId, RegisterValue, StopReason};

    #[test]
    fn process_id_rejects_zero() {
        assert!(ProcessId::new(0).is_err());
    }

    #[test]
    fn stop_reason_display_stable() {
        let msg = StopReason::Signal { signal: 5 }.to_string();
        assert_eq!(msg, "signal-stop(sig=5)");
    }

    #[test]
    fn register_display_width_matches_bits() {
        let v = RegisterValue {
            name: "eax",
            bits: 32,
            value: 0x12ab,
        };
        assert_eq!(v.to_string(), "eax: 0x000012ab (4779) [32-bit]");
    }
}
