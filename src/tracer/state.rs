use nix::unistd::Pid;
use std::time::Instant;

#[derive(Debug)]
pub struct ProcessState {
    pub pid: Pid,
    pub syscall_phase: SyscallPhase,
    pub current_syscall: Option<SyscallInfo>,
    pub pending_action: crate::event::PolicyAction,
    pub exec_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallPhase {
    Enter,
    Exit,
}

#[derive(Debug, Clone)]
pub struct SyscallInfo {
    pub number: u64,
    pub name: String,
    pub args: [u64; 6],
    pub start_time: Instant,
}

impl ProcessState {
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            syscall_phase: SyscallPhase::Enter,
            current_syscall: None,
            pending_action: crate::event::PolicyAction::Allow,
            exec_count: 0,
        }
    }
}
