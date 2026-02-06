use super::Architecture;
use crate::error::{Result, TracerError};
use crate::event::SyscallCategory;
use nix::unistd::Pid;

#[derive(Debug, Clone, Default)]
pub struct UserRegs {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

impl UserRegs {
    pub fn x(&self, n: usize) -> u64 {
        if n < 31 {
            self.regs[n]
        } else {
            0
        }
    }

    pub fn set_x(&mut self, n: usize, val: u64) {
        if n < 31 {
            self.regs[n] = val;
        }
    }
}

pub struct Aarch64Arch;

impl Aarch64Arch {
    pub fn new() -> Self {
        Self
    }
}

impl Architecture for Aarch64Arch {
    fn name(&self) -> &'static str {
        "aarch64"
    }

    fn syscall_number(&self, regs: &super::RawRegisters) -> u64 {
        match regs {
            super::RawRegisters::Aarch64(r) => r.x(8),
            _ => 0,
        }
    }

    fn syscall_args(&self, regs: &super::RawRegisters) -> [u64; 6] {
        match regs {
            super::RawRegisters::Aarch64(r) => {
                [r.x(0), r.x(1), r.x(2), r.x(3), r.x(4), r.x(5)]
            }
            _ => [0; 6],
        }
    }

    fn return_value(&self, regs: &super::RawRegisters) -> i64 {
        match regs {
            super::RawRegisters::Aarch64(r) => r.x(0) as i64,
            _ => 0,
        }
    }

    fn syscall_name(&self, nr: u64) -> Option<&'static str> {
        SYSCALL_TABLE.get(&nr).copied()
    }

    fn syscall_category(&self, nr: u64) -> SyscallCategory {
        let name = self.syscall_name(nr).unwrap_or("unknown");
        categorize_syscall(name)
    }

    fn set_syscall_number(&self, regs: &mut super::RawRegisters, nr: u64) {
        match regs {
            super::RawRegisters::Aarch64(r) => r.set_x(8, nr),
            _ => {}
        }
    }
}

pub fn read_registers(pid: Pid) -> Result<UserRegs> {
    use std::mem;

    // On aarch64, use PTRACE_GETREGSET with NT_PRSTATUS
    let mut regs: libc::user_pt_regs = unsafe { mem::zeroed() };
    
    let iov = libc::iovec {
        iov_base: &mut regs as *mut _ as *mut libc::c_void,
        iov_len: mem::size_of::<libc::user_pt_regs>(),
    };

    let res = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGSET,
            pid.as_raw(),
            libc::NT_PRSTATUS as *mut libc::c_void,
            &iov as *const _,
        )
    };

    if res < 0 {
        return Err(TracerError::Ptrace(nix::Error::last()).into());
    }

    let mut user_regs = UserRegs {
        regs: [0; 31],
        sp: regs.sp,
        pc: regs.pc,
        pstate: regs.pstate,
    };
    user_regs.regs.copy_from_slice(&regs.regs[..31]);

    Ok(user_regs)
}

pub fn write_registers(pid: Pid, regs: &UserRegs) -> Result<()> {
    let libc_regs = libc::user_pt_regs {
        regs: regs.regs,
        sp: regs.sp,
        pc: regs.pc,
        pstate: regs.pstate,
    };

    let iov = libc::iovec {
        iov_base: &libc_regs as *const _ as *mut libc::c_void,
        iov_len: std::mem::size_of::<libc::user_pt_regs>(),
    };

    let res = unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGSET,
            pid.as_raw(),
            libc::NT_PRSTATUS as *mut libc::c_void,
            &iov as *const _,
        )
    };

    if res < 0 {
        return Err(TracerError::Ptrace(nix::Error::last()).into());
    }

    Ok(())
}

fn categorize_syscall(name: &str) -> SyscallCategory {
    // Same categorization as x86_64
    match name {
        "read" | "pread64" | "readv" | "preadv" | "preadv2" | "openat" | "open" => {
            SyscallCategory::FileRead
        }
        "write" | "pwrite64" | "writev" | "pwritev" | "pwritev2" => SyscallCategory::FileWrite,
        "stat" | "fstat" | "lstat" | "newfstatat" | "statx" => SyscallCategory::FileMetadata,
        "mkdir" | "mkdirat" | "rmdir" | "getdents" | "getdents64" => SyscallCategory::Directory,
        "fork" | "vfork" | "clone" | "clone3" | "execve" | "execveat" | "exit" | "exit_group" => {
            SyscallCategory::Process
        }
        "socket" | "connect" | "accept" | "accept4" | "sendto" | "recvfrom" | "sendmsg"
        | "recvmsg" | "bind" | "listen" => SyscallCategory::Network,
        "mmap" | "munmap" | "mprotect" | "madvise" | "brk" => SyscallCategory::Memory,
        "kill" | "tkill" | "tgkill" | "sigaction" | "sigreturn" => SyscallCategory::Signal,
        "pipe" | "pipe2" | "shmget" | "shmat" => SyscallCategory::Ipc,
        "reboot" | "kexec_load" | "kexec_file_load" | "init_module" | "delete_module" => {
            SyscallCategory::System
        }
        _ => SyscallCategory::Other,
    }
}

use std::collections::HashMap;
use std::sync::LazyLock;

static SYSCALL_TABLE: LazyLock<HashMap<u64, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    // aarch64 syscall numbers are different from x86_64
    m.insert(29, "ioctl");
    m.insert(56, "openat");
    m.insert(57, "close");
    m.insert(63, "read");
    m.insert(64, "write");
    m.insert(78, "readlinkat");
    m.insert(79, "newfstatat");
    m.insert(80, "fstat");
    m.insert(93, "exit");
    m.insert(94, "exit_group");
    m.insert(96, "set_tid_address");
    m.insert(98, "futex");
    m.insert(99, "set_robust_list");
    m.insert(113, "clock_gettime");
    m.insert(115, "clock_nanosleep");
    m.insert(122, "sched_getaffinity");
    m.insert(123, "sched_setaffinity");
    m.insert(124, "sched_yield");
    m.insert(129, "kill");
    m.insert(130, "tkill");
    m.insert(131, "tgkill");
    m.insert(134, "rt_sigaction");
    m.insert(135, "rt_sigreturn");
    m.insert(136, "rt_sigprocmask");
    m.insert(137, "rt_sigpending");
    m.insert(138, "rt_sigtimedwait");
    m.insert(139, "rt_sigqueueinfo");
    m.insert(140, "rt_sigsuspend");
    m.insert(153, "getpid");
    m.insert(155, "getuid");
    m.insert(157, "getgid");
    m.insert(160, "getppid");
    m.insert(172, "getpgrp");
    m.insert(174, "getuid");
    m.insert(175, "geteuid");
    m.insert(176, "getgid");
    m.insert(177, "getegid");
    m.insert(198, "socket");
    m.insert(200, "bind");
    m.insert(201, "listen");
    m.insert(202, "accept");
    m.insert(203, "connect");
    m.insert(204, "getsockname");
    m.insert(205, "getpeername");
    m.insert(206, "sendto");
    m.insert(207, "recvfrom");
    m.insert(208, "setsockopt");
    m.insert(209, "getsockopt");
    m.insert(210, "shutdown");
    m.insert(211, "sendmsg");
    m.insert(212, "recvmsg");
    m.insert(214, "brk");
    m.insert(215, "munmap");
    m.insert(222, "mmap");
    m.insert(226, "mprotect");
    m.insert(233, "madvise");
    m.insert(220, "clone");
    m.insert(221, "execve");
    m.insert(249, "wait4");
    m.insert(260, "renameat");
    m.insert(263, "unlinkat");
    m.insert(269, "faccessat");
    m.insert(276, "splice");
    m.insert(277, "tee");
    m.insert(278, "sync_file_range");
    m.insert(280, "pipe2");
    m.insert(281, "quotactl");
    m.insert(282, "getdents64");
    m.insert(283, "lseek");
    m.insert(284, "creat");
    m.insert(285, "getrandom");
    m.insert(286, "memfd_create");
    m.insert(287, "bpf");
    m.insert(288, "execveat");
    m.insert(289, "userfaultfd");
    m.insert(290, "membarrier");
    m.insert(291, "mlock2");
    m.insert(292, "copy_file_range");
    m.insert(293, "preadv2");
    m.insert(294, "pwritev2");
    m.insert(295, "statx");
    m.insert(296, "io_pgetevents");
    m.insert(297, "rseq");
    m.insert(298, "kexec_file_load");
    m.insert(435, "clone3");
    m
});
