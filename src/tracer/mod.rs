use crate::cli::RunArgs;
use crate::error::{Result, TracerError};
use crate::event::{PolicyAction, ProcessEvent, SyscallEvent, SyscallArgs, TraceEvent, TraceSummary};
use crate::output::OutputManager;
use crate::policy::Policy;
use crate::sandbox::{apply_child_sandbox, SandboxConfig};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub mod arch;
pub mod decoder;
pub mod memory;
pub mod state;
pub mod syscalls;

use arch::{Architecture, RawRegisters};
use state::{ProcessState, SyscallPhase};

pub struct Tracer {
    config: SandboxConfig,
    output: OutputManager,
    process_states: HashMap<Pid, ProcessState>,
    architecture: Box<dyn Architecture>,
    start_time: Instant,
    timeout: Duration,
    trace_only: bool,
    follow_forks: bool,
    stats: TraceStats,
    shutdown: Arc<AtomicBool>,
}

#[derive(Debug, Default)]
struct TraceStats {
    total_syscalls: u64,
    denied_count: u64,
    process_count: u64,
    unique_syscalls: std::collections::HashSet<String>,
    files_accessed: std::collections::HashSet<String>,
    network_attempts: std::collections::HashSet<String>,
    suspicious_activity: Vec<String>,
}

impl Tracer {
    pub fn new(
        args: &RunArgs,
        output: OutputManager,
        shutdown: Arc<AtomicBool>,
    ) -> Result<Self> {
        let config = SandboxConfig::from_args(args)?;
        let architecture = arch::detect_architecture()?;

        Ok(Self {
            config,
            output,
            process_states: HashMap::new(),
            architecture,
            start_time: Instant::now(),
            timeout: Duration::from_secs(args.timeout),
            trace_only: args.trace_only,
            follow_forks: args.follow_forks,
            stats: TraceStats::default(),
            shutdown,
        })
    }

    pub fn run(&mut self) -> Result<i32> {
        // Fork the child process
        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                // Child: apply sandbox and exec
                self.run_child()
            }
            Ok(ForkResult::Parent { child }) => {
                // Parent: trace the child
                self.run_tracer(child)
            }
            Err(e) => Err(crate::error::SandboxError::Fork(e).into()),
        }
    }

    fn run_child(&self) -> ! {
        // Apply sandbox layers
        if let Err(e) = apply_child_sandbox(&self.config) {
            eprintln!("Failed to apply sandbox: {}", e);
            std::process::exit(1);
        }

        // Execute the command
        let cmd = &self.config.command[0];
        let args: Vec<&str> = self.config.command[1..].iter().map(|s| s.as_str()).collect();

        let err = Command::new(cmd).args(&args).exec();
        eprintln!("Failed to execute {}: {}", cmd, err);
        std::process::exit(127);
    }

    fn run_tracer(&mut self, child: Pid) -> Result<i32> {
        // Wait for child to stop (SIGSTOP from traceme)
        let status = waitpid(child, None)
            .map_err(TracerError::Wait)?;

        match status {
            WaitStatus::Stopped(_, Signal::SIGSTOP) => {
                log::debug!("Child stopped with SIGSTOP, setting up ptrace options");
            }
            _ => {
                return Err(TracerError::Ptrace(nix::Error::EINVAL).into());
            }
        }

        // Set ptrace options
        let mut options = ptrace::Options::PTRACE_O_TRACESYSGOOD;
        if self.follow_forks {
            options |= ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_TRACEVFORK
                | ptrace::Options::PTRACE_O_TRACECLONE;
        }
        options |= ptrace::Options::PTRACE_O_TRACEEXEC;

        ptrace::setoptions(child, options).map_err(TracerError::Ptrace)?;

        // Start the child
        ptrace::syscall(child, None).map_err(TracerError::Ptrace)?;

        // Initialize first process state
        self.process_states.insert(child, ProcessState::new(child));
        self.stats.process_count = 1;

        // Main event loop
        let result = self.trace_loop();

        // Emit summary
        self.emit_summary(result.unwrap_or(-1));

        result.map_err(|e| e.into())
    }

    fn trace_loop(&mut self) -> Result<i32> {
        let mut last_exit_code = 0;

        loop {
            // Check for timeout
            if self.start_time.elapsed() > self.timeout {
                self.kill_all_tracees();
                return Err(TracerError::Timeout(self.timeout.as_secs()).into());
            }

            // Check for shutdown signal
            if self.shutdown.load(Ordering::Relaxed) {
                self.kill_all_tracees();
                return Ok(128 + 15); // SIGTERM exit code
            }

            // Wait for any tracee event
            let status = match waitpid(None::<Pid>, Some(WaitPidFlag::__WALL)) {
                Ok(s) => s,
                Err(nix::errno::Errno::ECHILD) => {
                    // No more children
                    break;
                }
                Err(e) => {
                    return Err(TracerError::Wait(e).into());
                }
            };

            match status {
                WaitStatus::PtraceSyscall(pid) => {
                    self.handle_syscall(pid)?;
                }
                WaitStatus::Stopped(pid, signal) => {
                    self.handle_signal(pid, signal)?;
                }
                WaitStatus::Exited(pid, code) => {
                    self.handle_exit(pid, code)?;
                    last_exit_code = code;
                    if self.process_states.is_empty() {
                        break;
                    }
                }
                WaitStatus::Signaled(pid, signal, _) => {
                    self.handle_signaled(pid, signal)?;
                    if self.process_states.is_empty() {
                        break;
                    }
                }
                WaitStatus::PtraceEvent(pid, _, event) => {
                    self.handle_ptrace_event(pid, event)?;
                }
                _ => {}
            }
        }

        Ok(last_exit_code)
    }

    fn handle_syscall(&mut self, pid: Pid) -> Result<()> {
        let state = self.process_states.get_mut(&pid)
            .ok_or_else(|| TracerError::ProcessNotFound(pid.as_raw()))?;

        match state.syscall_phase {
            SyscallPhase::Enter => {
                // Read registers to get syscall info
                let regs = arch::read_registers(pid)?;
                let syscall_nr = self.architecture.syscall_number(&regs);
                let args = self.architecture.syscall_args(&regs);

                let syscall_name = self.architecture.syscall_name(syscall_nr)
                    .unwrap_or("unknown")
                    .to_string();

                state.current_syscall = Some(syscalls::SyscallInfo {
                    number: syscall_nr,
                    name: syscall_name.clone(),
                    args,
                    start_time: Instant::now(),
                });

                // Determine action based on policy
                let action = if self.trace_only {
                    PolicyAction::Allow
                } else {
                    self.evaluate_syscall_policy(pid, syscall_nr, &syscall_name, &args)
                };

                state.pending_action = action;

                // If denying, modify registers to cause ENOSYS
                if action == PolicyAction::Deny {
                    let mut modified_regs = regs.clone();
                    self.architecture.set_syscall_number(&mut modified_regs, u64::MAX);
                    arch::write_registers(pid, &modified_regs)?;
                    self.stats.denied_count += 1;
                }

                state.syscall_phase = SyscallPhase::Exit;
            }
            SyscallPhase::Exit => {
                // Read return value
                let regs = arch::read_registers(pid)?;
                let return_value = self.architecture.return_value(&regs);

                if let Some(syscall_info) = &state.current_syscall {
                    // Decode syscall arguments
                    let decoded_args = decoder::decode_syscall_args(
                        pid,
                        &syscall_info.name,
                        &syscall_info.args,
                        &mut self.stats,
                    );

                    let event = SyscallEvent {
                        timestamp: chrono::Utc::now(),
                        pid: pid.as_raw(),
                        tgid: pid.as_raw(), // Simplified - could get from /proc
                        syscall: syscall_info.name.clone(),
                        syscall_nr: syscall_info.number,
                        args: SyscallArgs {
                            raw: syscall_info.args,
                            decoded: decoded_args,
                        },
                        return_value,
                        success: return_value >= 0,
                        duration_us: syscall_info.start_time.elapsed().as_micros() as u64,
                        action: state.pending_action,
                        category: syscalls::categorize_syscall(&syscall_info.name),
                    };

                    self.output.emit_event(TraceEvent::Syscall(event))?;

                    self.stats.total_syscalls += 1;
                    self.stats.unique_syscalls.insert(syscall_info.name.clone());
                }

                state.current_syscall = None;
                state.syscall_phase = SyscallPhase::Enter;
            }
        }

        // Continue the tracee
        ptrace::syscall(pid, None).map_err(TracerError::Ptrace)?;
        Ok(())
    }

    fn evaluate_syscall_policy(&self, pid: Pid, syscall_nr: u64, name: &str, args: &[u64; 6]) -> PolicyAction {
        // Check policy for this syscall
        self.config.policy.get_syscall_action(name)
    }

    fn handle_signal(&mut self, pid: Pid, signal: Signal) -> Result<()> {
        // Pass signal through to tracee
        ptrace::syscall(pid, Some(signal)).map_err(TracerError::Ptrace)?;
        Ok(())
    }

    fn handle_exit(&mut self, pid: Pid, code: i32) -> Result<()> {
        self.process_states.remove(&pid);

        let event = ProcessEvent::Exited {
            timestamp: chrono::Utc::now(),
            pid: pid.as_raw(),
            exit_code: code,
        };
        self.output.emit_event(TraceEvent::Process(event))?;

        Ok(())
    }

    fn handle_signaled(&mut self, pid: Pid, signal: Signal) -> Result<()> {
        self.process_states.remove(&pid);

        let event = ProcessEvent::Signaled {
            timestamp: chrono::Utc::now(),
            pid: pid.as_raw(),
            signal: format!("{:?}", signal),
        };
        self.output.emit_event(TraceEvent::Process(event))?;

        Ok(())
    }

    fn handle_ptrace_event(&mut self, pid: Pid, event: i32) -> Result<()> {
        use nix::sys::ptrace::*;

        const PTRACE_EVENT_FORK: i32 = 1;
        const PTRACE_EVENT_VFORK: i32 = 2;
        const PTRACE_EVENT_CLONE: i32 = 3;
        const PTRACE_EVENT_EXEC: i32 = 4;

        match event {
            PTRACE_EVENT_FORK | PTRACE_EVENT_VFORK | PTRACE_EVENT_CLONE => {
                // Get the new child's PID
                let new_pid = getevent(pid).map_err(TracerError::Ptrace)?;
                let child_pid = Pid::from_raw(new_pid as i32);

                self.process_states.insert(child_pid, ProcessState::new(child_pid));
                self.stats.process_count += 1;

                let proc_event = ProcessEvent::Spawned {
                    timestamp: chrono::Utc::now(),
                    parent_pid: pid.as_raw(),
                    child_pid: child_pid.as_raw(),
                };
                self.output.emit_event(TraceEvent::Process(proc_event))?;
            }
            PTRACE_EVENT_EXEC => {
                // Process exec'd a new binary
                // Could decode the path here if needed
            }
            _ => {}
        }

        ptrace::syscall(pid, None).map_err(TracerError::Ptrace)?;
        Ok(())
    }

    fn kill_all_tracees(&mut self) {
        for (pid, _) in &self.process_states {
            let _ = nix::sys::signal::kill(*pid, nix::sys::signal::SIGKILL);
        }
    }

    fn emit_summary(&mut self, exit_code: i32) {
        let summary = TraceSummary {
            timestamp: chrono::Utc::now(),
            total_syscalls: self.stats.total_syscalls,
            unique_syscalls: self.stats.unique_syscalls.len() as u64,
            denied_count: self.stats.denied_count,
            process_count: self.stats.process_count,
            duration_ms: self.start_time.elapsed().as_millis() as u64,
            exit_code,
            files_accessed: self.stats.files_accessed.drain().collect(),
            network_attempts: self.stats.network_attempts.drain().collect(),
            suspicious_activity: self.stats.suspicious_activity.clone(),
        };

        let _ = self.output.emit_event(TraceEvent::Summary(summary));
        let _ = self.output.flush();
    }
}
