//! Linux ptrace backend implementation.
//!
//! This crate owns the syscall-facing control plane:
//! `fork/exec`, `ptrace` attach/continue/register access, and `waitpid` status decoding.
//! It implements the backend contract from `dbg-core`.

use std::ffi::CString;

use dbg_core::{
    DebugBackend, DebugError, ProcessId, RegisterValue, ShutdownPolicy, StopEvent, StopReason,
    ThreadId,
};
use dbg_regs_x64::{
    read_all_gpr, read_register as read_register_alias, write_register as write_register_alias,
};
use nix::errno::Errno;
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::sys::ptrace;
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork, pipe, read, write};
use tracing::{debug, warn};

/// Records whether the debugger launched the inferior or attached to an existing one.
///
/// This ownership drives drop-time cleanup policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InferiorOwnership {
    /// Inferior process was created by `launch`.
    Launched,
    /// Inferior process existed already and was attached via `ptrace::attach`.
    Attached,
}

/// Linux `ptrace` backend.
///
/// Invariant: a backend instance owns at most one active inferior at a time.
#[derive(Debug, Default)]
pub struct LinuxBackend {
    /// Active traced process.
    inferior: Option<Pid>,
    /// How we acquired the active inferior.
    ownership: Option<InferiorOwnership>,
    /// Number of ptrace calls issued by this backend.
    ptrace_calls: u64,
}

impl LinuxBackend {
    /// Create a backend with no active inferior.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set active inferior and ownership mode.
    fn set_inferior(&mut self, pid: Pid, ownership: InferiorOwnership) {
        self.inferior = Some(pid);
        self.ownership = Some(ownership);
    }

    /// Clear active inferior ownership state.
    fn clear_inferior(&mut self) {
        self.inferior = None;
        self.ownership = None;
    }

    /// Resolve the currently active pid or return `MissingInferior`.
    fn current_pid(&self) -> Result<Pid, DebugError> {
        self.inferior.ok_or(DebugError::MissingInferior)
    }

    /// Build argv vector suitable for `execvp`.
    fn build_argv(program: &str, args: &[String]) -> Result<Vec<CString>, DebugError> {
        let mut argv = Vec::with_capacity(args.len() + 1);
        argv.push(CString::new(program).map_err(DebugError::backend)?);

        for arg in args {
            argv.push(CString::new(arg.as_str()).map_err(DebugError::backend)?);
        }

        Ok(argv)
    }

    /// Wait for any state change from the traced pid using `__WALL`.
    fn wait_blocking(pid: Pid) -> Result<WaitStatus, DebugError> {
        waitpid(pid, Some(WaitPidFlag::__WALL)).map_err(DebugError::backend)
    }

    /// Convert `waitpid` status into core-domain [`StopEvent`].
    fn next_stop_event(status: WaitStatus) -> Result<StopEvent, DebugError> {
        match status {
            WaitStatus::Stopped(pid, signal) => Ok(StopEvent {
                tid: ThreadId::new(pid.as_raw())?,
                reason: StopReason::Signal {
                    signal: signal as i32,
                },
            }),
            WaitStatus::PtraceEvent(pid, signal, event) => Ok(StopEvent {
                tid: ThreadId::new(pid.as_raw())?,
                reason: StopReason::PtraceEvent {
                    event,
                    signal: signal as i32,
                },
            }),
            WaitStatus::PtraceSyscall(pid) => Ok(StopEvent {
                tid: ThreadId::new(pid.as_raw())?,
                reason: StopReason::SyscallTrap,
            }),
            WaitStatus::Exited(pid, code) => Ok(StopEvent {
                tid: ThreadId::new(pid.as_raw())?,
                reason: StopReason::Exited { code },
            }),
            WaitStatus::Signaled(pid, signal, core_dumped) => Ok(StopEvent {
                tid: ThreadId::new(pid.as_raw())?,
                reason: StopReason::Terminated {
                    signal: signal as i32,
                    core_dumped,
                },
            }),
            WaitStatus::Continued(pid) => Ok(StopEvent {
                tid: ThreadId::new(pid.as_raw())?,
                reason: StopReason::Unknown,
            }),
            WaitStatus::StillAlive => Err(DebugError::backend("waitpid returned StillAlive")),
        }
    }

    /// Configure ptrace options after first successful stop.
    fn configure_ptrace_options(&mut self, pid: Pid) -> Result<(), DebugError> {
        ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD)
            .map_err(DebugError::backend)?;
        self.ptrace_calls = self.ptrace_calls.saturating_add(1);
        Ok(())
    }

    /// Fetch full register frame through `PTRACE_GETREGS`.
    fn getregs(&mut self, pid: Pid) -> Result<nix::libc::user_regs_struct, DebugError> {
        let regs = ptrace::getregs(pid).map_err(DebugError::backend)?;
        self.ptrace_calls = self.ptrace_calls.saturating_add(1);
        Ok(regs)
    }

    /// Write full register frame through `PTRACE_SETREGS`.
    fn setregs(&mut self, pid: Pid, regs: nix::libc::user_regs_struct) -> Result<(), DebugError> {
        ptrace::setregs(pid, regs).map_err(DebugError::backend)?;
        self.ptrace_calls = self.ptrace_calls.saturating_add(1);
        Ok(())
    }

    /// Resume inferior execution via `PTRACE_CONT`.
    fn ptrace_continue(&mut self, pid: Pid) -> Result<(), DebugError> {
        ptrace::cont(pid, None).map_err(DebugError::backend)?;
        self.ptrace_calls = self.ptrace_calls.saturating_add(1);
        Ok(())
    }
}

impl DebugBackend for LinuxBackend {
    /// Launch a new inferior via `fork + ptrace(TRACEME) + execvp`.
    fn launch(&mut self, program: &str, args: &[String]) -> Result<StopEvent, DebugError> {
        if self.inferior.is_some() {
            return Err(DebugError::InferiorAlreadyActive);
        }
        let argv = Self::build_argv(program, args)?;
        let (read_fd, write_fd) = pipe().map_err(DebugError::backend)?;

        fcntl(&read_fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(DebugError::backend)?;
        fcntl(&write_fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(DebugError::backend)?;

        // SAFETY: `fork` is the required POSIX primitive for debugger launch. We avoid
        // touching shared mutable Rust state in the child before `execvp`.
        match unsafe { fork() }.map_err(DebugError::backend)? {
            ForkResult::Parent { child } => {
                drop(write_fd);

                let mut err_buf = [0_u8; 512];
                let read_count = read(&read_fd, &mut err_buf).map_err(DebugError::backend)?;
                drop(read_fd);

                if read_count > 0 {
                    let msg = String::from_utf8_lossy(&err_buf[..read_count]).to_string();
                    return Err(DebugError::backend(format!(
                        "child failed before exec: {msg}"
                    )));
                }

                self.set_inferior(child, InferiorOwnership::Launched);
                let initial_status = Self::wait_blocking(child)?;
                let event = Self::next_stop_event(initial_status)?;

                if matches!(
                    event.reason,
                    StopReason::Exited { .. } | StopReason::Terminated { .. }
                ) {
                    self.clear_inferior();
                } else {
                    self.configure_ptrace_options(child)?;
                }

                debug!(pid = child.as_raw(), reason = %event.reason, "launch initial stop");
                Ok(event)
            }
            ForkResult::Child => {
                drop(read_fd);

                if let Err(err) = ptrace::traceme() {
                    let _ = write(
                        &write_fd,
                        format!("ptrace(TRACEME) failed: {err}").as_bytes(),
                    );
                    std::process::exit(1);
                }

                match nix::unistd::execvp(&argv[0], &argv) {
                    Ok(_) => unreachable!("execvp only returns on failure"),
                    Err(err) => {
                        let _ = write(&write_fd, format!("execvp failed: {err}").as_bytes());
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    /// Attach to an existing process and wait for its first debugger stop.
    fn attach(&mut self, pid: ProcessId) -> Result<StopEvent, DebugError> {
        if self.inferior.is_some() {
            return Err(DebugError::InferiorAlreadyActive);
        }

        let target = Pid::from_raw(pid.get());
        ptrace::attach(target).map_err(DebugError::backend)?;
        self.ptrace_calls = self.ptrace_calls.saturating_add(1);

        self.set_inferior(target, InferiorOwnership::Attached);
        let status = Self::wait_blocking(target)?;
        let event = Self::next_stop_event(status)?;

        if matches!(
            event.reason,
            StopReason::Exited { .. } | StopReason::Terminated { .. }
        ) {
            self.clear_inferior();
        } else {
            self.configure_ptrace_options(target)?;
        }

        debug!(pid = target.as_raw(), reason = %event.reason, "attach stop");
        Ok(event)
    }

    /// Continue currently active inferior.
    fn resume(&mut self) -> Result<(), DebugError> {
        let pid = self.current_pid()?;
        self.ptrace_continue(pid)
    }

    /// Wait until inferior reports a meaningful stop event.
    fn wait_for_stop(&mut self) -> Result<StopEvent, DebugError> {
        let pid = self.current_pid()?;

        loop {
            let status = Self::wait_blocking(pid)?;
            match status {
                WaitStatus::StillAlive | WaitStatus::Continued(_) => continue,
                other => {
                    let event = Self::next_stop_event(other)?;
                    if matches!(
                        event.reason,
                        StopReason::Exited { .. } | StopReason::Terminated { .. }
                    ) {
                        self.clear_inferior();
                    }
                    return Ok(event);
                }
            }
        }
    }

    /// Read one register alias from active inferior.
    fn read_register(&mut self, name: &str) -> Result<RegisterValue, DebugError> {
        let pid = self.current_pid()?;
        let regs = self.getregs(pid)?;
        read_register_alias(&regs, name)
    }

    /// Write one register alias on active inferior.
    fn write_register(&mut self, name: &str, value: u64) -> Result<RegisterValue, DebugError> {
        let pid = self.current_pid()?;
        let mut regs = self.getregs(pid)?;

        let updated = write_register_alias(&mut regs, name, value)?;
        self.setregs(pid, regs)?;
        Ok(updated)
    }

    /// Read canonical register set from active inferior.
    fn read_all_registers(&mut self) -> Result<Vec<RegisterValue>, DebugError> {
        let pid = self.current_pid()?;
        let regs = self.getregs(pid)?;
        Ok(read_all_gpr(&regs))
    }

    /// End debugger ownership according to `Detach` or `Terminate` policy.
    fn shutdown(&mut self, policy: ShutdownPolicy) -> Result<(), DebugError> {
        let pid = self.current_pid()?;

        match policy {
            ShutdownPolicy::Detach => {
                if let Err(err) = ptrace::detach(pid, None)
                    && err != Errno::ESRCH
                    && err != Errno::EINVAL
                {
                    return Err(DebugError::backend(err));
                }
                self.ptrace_calls = self.ptrace_calls.saturating_add(1);
            }
            ShutdownPolicy::Terminate => {
                if let Err(err) = kill(pid, Signal::SIGKILL)
                    && err != Errno::ESRCH
                {
                    return Err(DebugError::backend(err));
                }
                if let Err(err) = waitpid(pid, Some(WaitPidFlag::__WALL))
                    && err != Errno::ECHILD
                {
                    return Err(DebugError::backend(err));
                }
            }
        }

        self.clear_inferior();
        Ok(())
    }

    /// Return active inferior pid if one is currently tracked.
    fn active_process(&self) -> Option<ProcessId> {
        self.inferior
            .and_then(|pid| ProcessId::new(pid.as_raw()).ok())
    }

    /// Return accumulated ptrace call count.
    fn ptrace_call_count(&self) -> u64 {
        self.ptrace_calls
    }
}

impl Drop for LinuxBackend {
    /// Best-effort cleanup to avoid leaving orphan debugger state.
    fn drop(&mut self) {
        let Some(ownership) = self.ownership else {
            return;
        };

        let fallback_policy = match ownership {
            InferiorOwnership::Attached => ShutdownPolicy::Detach,
            InferiorOwnership::Launched => ShutdownPolicy::Terminate,
        };

        if let Err(err) = self.shutdown(fallback_policy) {
            warn!(%err, "drop cleanup failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::Command;

    use dbg_core::{DebugBackend, ProcessId, ShutdownPolicy, StopReason};
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    use super::LinuxBackend;

    #[test]
    fn launch_nonexistent_binary_fails() {
        let mut backend = LinuxBackend::new();
        let err = backend
            .launch("/definitely/not/a/real/binary", &[])
            .expect_err("launch should fail");
        let msg = err.to_string();
        assert!(msg.contains("execvp"));
    }

    #[test]
    fn launch_true_can_exit_after_continue() {
        let mut backend = LinuxBackend::new();
        let _initial = backend
            .launch("/bin/true", &[])
            .expect("launch should stop");
        backend.resume().expect("resume should work");
        let stop = backend.wait_for_stop().expect("wait should finish");
        assert!(matches!(stop.reason, StopReason::Exited { .. }));
    }

    #[test]
    fn shutdown_terminate_clears_active_process() {
        let mut backend = LinuxBackend::new();
        let args = vec!["30".to_string()];
        let _initial = backend
            .launch("/bin/sleep", &args)
            .expect("launch should stop");
        assert!(backend.active_process().is_some());

        backend
            .shutdown(ShutdownPolicy::Terminate)
            .expect("terminate should succeed");
        assert!(backend.active_process().is_none());
    }

    #[test]
    fn shutdown_detach_keeps_process_alive() {
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid_raw = child.id() as i32;
        let pid = ProcessId::new(pid_raw).expect("child pid must be positive");
        let mut backend = LinuxBackend::new();

        let _initial = backend.attach(pid).expect("attach should stop target");
        backend
            .shutdown(ShutdownPolicy::Detach)
            .expect("detach should succeed");
        assert!(backend.active_process().is_none());

        assert!(Path::new(&format!("/proc/{pid_raw}")).exists());

        let kill_res = kill(Pid::from_raw(pid_raw), Signal::SIGKILL);
        assert!(kill_res.is_ok());
        let wait_res = child.wait();
        assert!(wait_res.is_ok());
    }

    #[test]
    fn register_alias_read_write_works_on_live_inferior() {
        let mut backend = LinuxBackend::new();
        let args = vec!["30".to_string()];
        let _initial = backend
            .launch("/bin/sleep", &args)
            .expect("launch should stop");

        backend
            .write_register("rax", 0xFFFF_0000_1111_2222)
            .expect("write rax");
        backend
            .write_register("eax", 0xAABB_CCDD)
            .expect("write eax");
        let rax_after_eax = backend.read_register("rax").expect("read rax");
        assert_eq!(rax_after_eax.value, 0x0000_0000_AABB_CCDD);

        backend.write_register("ah", 0x12).expect("write ah");
        let rax_after_ah = backend.read_register("rax").expect("read rax");
        assert_eq!(rax_after_ah.value, 0x0000_0000_AABB_12DD);

        let all = backend.read_all_registers().expect("read all");
        assert!(all.iter().any(|reg| reg.name == "rip"));
        assert!(all.iter().any(|reg| reg.name == "rflags"));

        backend
            .shutdown(ShutdownPolicy::Terminate)
            .expect("terminate should succeed");
        assert!(backend.active_process().is_none());
    }
}
