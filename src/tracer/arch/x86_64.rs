use super::Architecture;
use crate::error::{Result, TracerError};
use crate::event::SyscallCategory;
use nix::sys::ptrace;
use nix::unistd::Pid;

#[derive(Debug, Clone, Default)]
pub struct UserRegs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

pub struct X86_64Arch;

impl X86_64Arch {
    pub fn new() -> Self {
        Self
    }
}

impl Architecture for X86_64Arch {
    fn name(&self) -> &'static str {
        "x86_64"
    }

    fn syscall_number(&self, regs: &super::RawRegisters) -> u64 {
        match regs {
            super::RawRegisters::X86_64(r) => r.orig_rax,
            _ => 0,
        }
    }

    fn syscall_args(&self, regs: &super::RawRegisters) -> [u64; 6] {
        match regs {
            super::RawRegisters::X86_64(r) => [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9],
            _ => [0; 6],
        }
    }

    fn return_value(&self, regs: &super::RawRegisters) -> i64 {
        match regs {
            super::RawRegisters::X86_64(r) => r.rax as i64,
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
            super::RawRegisters::X86_64(r) => r.orig_rax = nr,
            _ => {}
        }
    }
}

pub fn read_registers(pid: Pid) -> Result<UserRegs> {
    use nix::sys::ptrace;
    use std::mem;

    // PTRACE_GETREGS on x86_64
    let mut regs: libc::user_regs_struct = unsafe { mem::zeroed() };
    
    // Use ptrace with PTRACE_GETREGS
    let res = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid.as_raw(),
            0,
            &mut regs as *mut _,
        )
    };

    if res < 0 {
        return Err(TracerError::Ptrace(nix::Error::last()).into());
    }

    Ok(UserRegs {
        r15: regs.r15 as u64,
        r14: regs.r14 as u64,
        r13: regs.r13 as u64,
        r12: regs.r12 as u64,
        rbp: regs.rbp as u64,
        rbx: regs.rbx as u64,
        r11: regs.r11 as u64,
        r10: regs.r10 as u64,
        r9: regs.r9 as u64,
        r8: regs.r8 as u64,
        rax: regs.rax as u64,
        rcx: regs.rcx as u64,
        rdx: regs.rdx as u64,
        rsi: regs.rsi as u64,
        rdi: regs.rdi as u64,
        orig_rax: regs.orig_rax as u64,
        rip: regs.rip as u64,
        cs: regs.cs as u64,
        eflags: regs.eflags as u64,
        rsp: regs.rsp as u64,
        ss: regs.ss as u64,
        fs_base: regs.fs_base as u64,
        gs_base: regs.gs_base as u64,
        ds: regs.ds as u64,
        es: regs.es as u64,
        fs: regs.fs as u64,
        gs: regs.gs as u64,
    })
}

pub fn write_registers(pid: Pid, regs: &UserRegs) -> Result<()> {
    let libc_regs = libc::user_regs_struct {
        r15: regs.r15 as libc::c_ulonglong,
        r14: regs.r14 as libc::c_ulonglong,
        r13: regs.r13 as libc::c_ulonglong,
        r12: regs.r12 as libc::c_ulonglong,
        rbp: regs.rbp as libc::c_ulonglong,
        rbx: regs.rbx as libc::c_ulonglong,
        r11: regs.r11 as libc::c_ulonglong,
        r10: regs.r10 as libc::c_ulonglong,
        r9: regs.r9 as libc::c_ulonglong,
        r8: regs.r8 as libc::c_ulonglong,
        rax: regs.rax as libc::c_ulonglong,
        rcx: regs.rcx as libc::c_ulonglong,
        rdx: regs.rdx as libc::c_ulonglong,
        rsi: regs.rsi as libc::c_ulonglong,
        rdi: regs.rdi as libc::c_ulonglong,
        orig_rax: regs.orig_rax as libc::c_ulonglong,
        rip: regs.rip as libc::c_ulonglong,
        cs: regs.cs as libc::c_ulonglong,
        eflags: regs.eflags as libc::c_ulonglong,
        rsp: regs.rsp as libc::c_ulonglong,
        ss: regs.ss as libc::c_ulonglong,
        fs_base: regs.fs_base as libc::c_ulonglong,
        gs_base: regs.gs_base as libc::c_ulonglong,
        ds: regs.ds as libc::c_ulonglong,
        es: regs.es as libc::c_ulonglong,
        fs: regs.fs as libc::c_ulonglong,
        gs: regs.gs as libc::c_ulonglong,
    };

    let res = unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGS,
            pid.as_raw(),
            0,
            &libc_regs as *const _,
        )
    };

    if res < 0 {
        return Err(TracerError::Ptrace(nix::Error::last()).into());
    }

    Ok(())
}

fn categorize_syscall(name: &str) -> SyscallCategory {
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

// x86_64 syscall numbers (selected common ones)
use std::collections::HashMap;
use std::sync::LazyLock;

static SYSCALL_TABLE: LazyLock<HashMap<u64, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert(0, "read");
    m.insert(1, "write");
    m.insert(2, "open");
    m.insert(3, "close");
    m.insert(4, "stat");
    m.insert(5, "fstat");
    m.insert(6, "lstat");
    m.insert(8, "lseek");
    m.insert(9, "mmap");
    m.insert(10, "mprotect");
    m.insert(11, "munmap");
    m.insert(12, "brk");
    m.insert(13, "rt_sigaction");
    m.insert(14, "rt_sigprocmask");
    m.insert(16, "ioctl");
    m.insert(17, "pread64");
    m.insert(18, "pwrite64");
    m.insert(19, "readv");
    m.insert(20, "writev");
    m.insert(21, "access");
    m.insert(22, "pipe");
    m.insert(23, "select");
    m.insert(24, "sched_yield");
    m.insert(25, "mremap");
    m.insert(26, "msync");
    m.insert(27, "mincore");
    m.insert(28, "madvise");
    m.insert(39, "getpid");
    m.insert(41, "socket");
    m.insert(42, "connect");
    m.insert(43, "accept");
    m.insert(44, "sendto");
    m.insert(45, "recvfrom");
    m.insert(46, "sendmsg");
    m.insert(47, "recvmsg");
    m.insert(49, "bind");
    m.insert(50, "listen");
    m.insert(56, "clone");
    m.insert(57, "fork");
    m.insert(58, "vfork");
    m.insert(59, "execve");
    m.insert(60, "exit");
    m.insert(61, "wait4");
    m.insert(62, "kill");
    m.insert(63, "uname");
    m.insert(72, "fcntl");
    m.insert(79, "getcwd");
    m.insert(80, "chdir");
    m.insert(82, "rename");
    m.insert(83, "mkdir");
    m.insert(84, "rmdir");
    m.insert(85, "creat");
    m.insert(86, "link");
    m.insert(87, "unlink");
    m.insert(88, "symlink");
    m.insert(89, "readlink");
    m.insert(90, "chmod");
    m.insert(91, "fchmod");
    m.insert(92, "chown");
    m.insert(93, "fchown");
    m.insert(94, "lchown");
    m.insert(95, "umask");
    m.insert(96, "gettimeofday");
    m.insert(102, "getuid");
    m.insert(104, "getgid");
    m.insert(105, "setuid");
    m.insert(106, "setgid");
    m.insert(107, "geteuid");
    m.insert(108, "getegid");
    m.insert(110, "getppid");
    m.insert(127, "rt_sigpending");
    m.insert(129, "rt_sigsuspend");
    m.insert(137, "statfs");
    m.insert(138, "fstatfs");
    m.insert(157, "prctl");
    m.insert(158, "arch_prctl");
    m.insert(165, "mount");
    m.insert(166, "umount2");
    m.insert(186, "gettid");
    m.insert(200, "tkill");
    m.insert(201, "time");
    m.insert(202, "futex");
    m.insert(217, "getdents64");
    m.insert(218, "set_tid_address");
    m.insert(228, "clock_gettime");
    m.insert(230, "clock_nanosleep");
    m.insert(231, "exit_group");
    m.insert(232, "epoll_wait");
    m.insert(233, "epoll_ctl");
    m.insert(234, "tgkill");
    m.insert(257, "openat");
    m.insert(258, "mkdirat");
    m.insert(259, "mknodat");
    m.insert(260, "fchownat");
    m.insert(261, "futimesat");
    m.insert(262, "newfstatat");
    m.insert(263, "unlinkat");
    m.insert(264, "renameat");
    m.insert(265, "linkat");
    m.insert(266, "symlinkat");
    m.insert(267, "readlinkat");
    m.insert(268, "fchmodat");
    m.insert(269, "faccessat");
    m.insert(270, "pselect6");
    m.insert(271, "ppoll");
    m.insert(273, "set_robust_list");
    m.insert(274, "get_robust_list");
    m.insert(281, "epoll_pwait");
    m.insert(288, "accept4");
    m.insert(289, "signalfd4");
    m.insert(290, "eventfd2");
    m.insert(291, "epoll_create1");
    m.insert(292, "dup3");
    m.insert(293, "pipe2");
    m.insert(294, "inotify_init1");
    m.insert(295, "preadv");
    m.insert(296, "pwritev");
    m.insert(297, "rt_tgsigqueueinfo");
    m.insert(298, "perf_event_open");
    m.insert(299, "recvmmsg");
    m.insert(302, "prlimit64");
    m.insert(303, "name_to_handle_at");
    m.insert(304, "open_by_handle_at");
    m.insert(307, "sendmmsg");
    m.insert(309, "getcpu");
    m.insert(315, "sched_getattr");
    m.insert(316, "renameat2");
    m.insert(318, "getrandom");
    m.insert(319, "memfd_create");
    m.insert(320, "kexec_file_load");
    m.insert(321, "bpf");
    m.insert(322, "execveat");
    m.insert(323, "userfaultfd");
    m.insert(324, "membarrier");
    m.insert(325, "mlock2");
    m.insert(326, "copy_file_range");
    m.insert(327, "preadv2");
    m.insert(328, "pwritev2");
    m.insert(329, "pkey_mprotect");
    m.insert(330, "pkey_alloc");
    m.insert(331, "pkey_free");
    m.insert(332, "statx");
    m.insert(333, "io_pgetevents");
    m.insert(334, "rseq");
    m.insert(435, "clone3");
    m
});
