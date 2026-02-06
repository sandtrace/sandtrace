use crate::event::SyscallCategory;

pub use super::arch::{Architecture, RawRegisters};

/// Information about a syscall being traced
#[derive(Debug, Clone)]
pub struct SyscallInfo {
    pub number: u64,
    pub name: String,
    pub args: [u64; 6],
    pub start_time: std::time::Instant,
}

/// Categorize a syscall by name
pub fn categorize_syscall(name: &str) -> SyscallCategory {
    match name {
        // File read operations
        "read" | "pread64" | "readv" | "preadv" | "preadv2" | "recvfrom" | "recvmsg"
        | "recvmmsg" => SyscallCategory::FileRead,

        // File write operations
        "write" | "pwrite64" | "writev" | "pwritev" | "pwritev2" | "sendto" | "sendmsg"
        | "sendmmsg" => SyscallCategory::FileWrite,

        // File open/stat operations
        "open" | "openat" | "creat" | "stat" | "fstat" | "lstat" | "newfstatat" | "statx"
        | "access" | "faccessat" => SyscallCategory::FileRead,

        // Metadata operations
        "chmod" | "fchmod" | "fchmodat" | "chown" | "fchown" | "lchown" | "fchownat"
        | "utime" | "utimes" | "futimesat" | "utimensat" | "futimens" | "statfs"
        | "fstatfs" => SyscallCategory::FileMetadata,

        // Directory operations
        "mkdir" | "mkdirat" | "rmdir" | "getdents" | "getdents64" | "chdir" | "fchdir"
        | "getcwd" => SyscallCategory::Directory,

        // Process operations
        "fork" | "vfork" | "clone" | "clone3" | "execve" | "execveat" | "exit"
        | "exit_group" | "wait4" | "waitid" | "waitpid" | "setuid" | "setgid"
        | "seteuid" | "setegid" | "setreuid" | "setregid" | "setgroups"
        | "setresuid" | "setresgid" | "setpgid" | "setsid" | "setrlimit"
        | "prlimit64" | "capset" | "capget" => SyscallCategory::Process,

        // Network operations
        "socket" | "socketpair" | "connect" | "accept" | "accept4" | "bind" | "listen"
        | "shutdown" | "getsockname" | "getpeername" | "getsockopt" | "setsockopt" => {
            SyscallCategory::Network
        }

        // Memory operations
        "mmap" | "munmap" | "mprotect" | "madvise" | "msync" | "mlock" | "munlock"
        | "mlockall" | "munlockall" | "mincore" | "remap_file_pages" | "mremap"
        | "brk" | "sbrk" => SyscallCategory::Memory,

        // Signal operations
        "kill" | "tkill" | "tgkill" | "sigaction" | "sigreturn" | "rt_sigreturn"
        | "rt_sigaction" | "rt_sigprocmask" | "rt_sigpending" | "rt_sigtimedwait"
        | "rt_sigqueueinfo" | "rt_sigsuspend" | "signal" | "sigsetmask" | "sigpending"
        | "sigprocmask" | "sigsuspend" | "sigaltstack" => SyscallCategory::Signal,

        // IPC operations
        "pipe" | "pipe2" | "dup" | "dup2" | "dup3" | "select" | "pselect6" | "poll"
        | "ppoll" | "epoll_create" | "epoll_create1" | "epoll_ctl" | "epoll_wait"
        | "epoll_pwait" | "eventfd" | "eventfd2" | "signalfd" | "signalfd4"
        | "timerfd_create" | "timerfd_settime" | "timerfd_gettime" | "inotify_init"
        | "inotify_init1" | "inotify_add_watch" | "inotify_rm_watch" | "fanotify_init"
        | "fanotify_mark" => SyscallCategory::Ipc,

        // System operations (usually dangerous)
        "reboot" | "kexec_load" | "kexec_file_load" | "init_module" | "finit_module"
        | "delete_module" | "acct" | "pivot_root" | "mount" | "umount2" | "swapon"
        | "swapoff" | "sethostname" | "setdomainname" | "iopl" | "ioperm" | "vm86"
        | "vm86old" | "create_module" | "get_kernel_syms" | "query_module"
        | "nfsservctl" | "getpmsg" | "putpmsg" | "afs_syscall" | "tuxcall"
        | "security" | "perf_event_open" | "bpf" | "userfaultfd" | "membarrier"
        | "pkey_alloc" | "pkey_free" | "pkey_mprotect" => SyscallCategory::System,

        // Other syscalls
        _ => SyscallCategory::Other,
    }
}

/// Check if a syscall name is valid/known
pub fn is_valid_syscall(name: &str) -> bool {
    // This is a simplified check - in a real implementation,
    // we would check against the complete syscall table
    !name.is_empty() && name != "unknown"
}

/// Get syscall number from name (architecture-specific)
pub fn syscall_number_from_name(_name: &str) -> Option<u64> {
    // This would require a reverse lookup in the syscall table
    // Implementation depends on the architecture module
    None
}
