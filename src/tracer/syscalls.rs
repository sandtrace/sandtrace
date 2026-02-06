use crate::event::SyscallCategory;

/// Categorize a syscall by name into a high-level category.
pub fn categorize_syscall(name: Option<&str>) -> SyscallCategory {
    let Some(name) = name else {
        return SyscallCategory::Other;
    };

    match name {
        // File read
        "read" | "pread64" | "readv" | "preadv" | "preadv2" | "open" | "openat" | "openat2"
        | "close" | "lseek" | "readlink" | "readlinkat" | "getdents" | "getdents64"
        | "sendfile" | "splice" | "tee" | "copy_file_range" => SyscallCategory::FileRead,

        // File write
        "write" | "pwrite64" | "writev" | "pwritev" | "pwritev2" | "creat" | "truncate"
        | "ftruncate" | "fallocate" => SyscallCategory::FileWrite,

        // File metadata
        "stat" | "fstat" | "lstat" | "newfstatat" | "statx" | "access" | "faccessat"
        | "faccessat2" | "chmod" | "fchmod" | "fchmodat" | "chown" | "fchown" | "lchown"
        | "fchownat" | "utimensat" | "utime" | "utimes" | "umask" | "statfs" | "fstatfs" => {
            SyscallCategory::FileMetadata
        }

        // Directory
        "mkdir" | "mkdirat" | "rmdir" | "rename" | "renameat" | "renameat2" | "link"
        | "linkat" | "unlink" | "unlinkat" | "symlink" | "symlinkat" | "chdir" | "fchdir"
        | "getcwd" | "mknodat" | "pivot_root" | "chroot" => SyscallCategory::Directory,

        // Process
        "fork" | "vfork" | "clone" | "clone3" | "execve" | "execveat" | "exit" | "exit_group"
        | "wait4" | "waitid" | "getpid" | "getppid" | "gettid" | "getpgrp" | "setsid"
        | "prctl" | "arch_prctl" | "set_tid_address" | "prlimit64" | "getrlimit"
        | "setrlimit" | "getrusage" | "times" | "sched_yield" | "sched_setattr"
        | "sched_getattr" | "unshare" => SyscallCategory::Process,

        // Network
        "socket" | "connect" | "accept" | "accept4" | "bind" | "listen" | "sendto"
        | "recvfrom" | "sendmsg" | "recvmsg" | "setsockopt" | "getsockopt" | "getsockname"
        | "getpeername" | "socketpair" | "shutdown" => SyscallCategory::Network,

        // Memory
        "brk" | "mmap" | "munmap" | "mprotect" | "mremap" | "madvise" | "mincore" | "msync"
        | "memfd_create" | "process_vm_readv" | "process_vm_writev" | "rseq" => {
            SyscallCategory::Memory
        }

        // Signal
        "kill" | "tkill" | "tgkill" | "rt_sigaction" | "rt_sigprocmask" | "rt_sigreturn"
        | "rt_sigsuspend" | "rt_tgsigqueueinfo" | "sigaltstack" | "pause" | "alarm" => {
            SyscallCategory::Signal
        }

        // IPC
        "pipe" | "pipe2" | "shmget" | "shmat" | "shmctl" | "eventfd" | "eventfd2"
        | "epoll_create1" | "epoll_ctl" | "epoll_wait" | "epoll_pwait" | "epoll_pwait2"
        | "select" | "pselect6" | "poll" | "ppoll" | "futex" | "set_robust_list"
        | "get_robust_list" => SyscallCategory::Ipc,

        // System
        "mount" | "umount2" | "swapon" | "swapoff" | "reboot" | "kexec_load"
        | "kexec_file_load" | "init_module" | "finit_module" | "delete_module" | "sysinfo"
        | "uname" | "gettimeofday" | "clock_gettime" | "clock_nanosleep" | "nanosleep"
        | "getrandom" | "setuid" | "setgid" | "setresuid" | "setresgid" | "getuid"
        | "geteuid" | "getgid" | "getegid" | "perf_event_open" | "dup" | "dup2" | "dup3"
        | "fcntl" | "flock" | "fsync" | "fdatasync" | "ioctl" | "setitimer" | "getitimer" => {
            SyscallCategory::System
        }

        _ => SyscallCategory::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_read_syscalls() {
        assert_eq!(categorize_syscall(Some("read")), SyscallCategory::FileRead);
        assert_eq!(categorize_syscall(Some("openat")), SyscallCategory::FileRead);
        assert_eq!(categorize_syscall(Some("pread64")), SyscallCategory::FileRead);
        assert_eq!(categorize_syscall(Some("getdents64")), SyscallCategory::FileRead);
        assert_eq!(categorize_syscall(Some("close")), SyscallCategory::FileRead);
    }

    #[test]
    fn file_write_syscalls() {
        assert_eq!(categorize_syscall(Some("write")), SyscallCategory::FileWrite);
        assert_eq!(categorize_syscall(Some("pwrite64")), SyscallCategory::FileWrite);
        assert_eq!(categorize_syscall(Some("truncate")), SyscallCategory::FileWrite);
    }

    #[test]
    fn file_metadata_syscalls() {
        assert_eq!(categorize_syscall(Some("stat")), SyscallCategory::FileMetadata);
        assert_eq!(categorize_syscall(Some("statx")), SyscallCategory::FileMetadata);
        assert_eq!(categorize_syscall(Some("access")), SyscallCategory::FileMetadata);
        assert_eq!(categorize_syscall(Some("chmod")), SyscallCategory::FileMetadata);
        assert_eq!(categorize_syscall(Some("faccessat2")), SyscallCategory::FileMetadata);
    }

    #[test]
    fn directory_syscalls() {
        assert_eq!(categorize_syscall(Some("mkdir")), SyscallCategory::Directory);
        assert_eq!(categorize_syscall(Some("rmdir")), SyscallCategory::Directory);
        assert_eq!(categorize_syscall(Some("unlink")), SyscallCategory::Directory);
        assert_eq!(categorize_syscall(Some("rename")), SyscallCategory::Directory);
        assert_eq!(categorize_syscall(Some("symlink")), SyscallCategory::Directory);
    }

    #[test]
    fn process_syscalls() {
        assert_eq!(categorize_syscall(Some("fork")), SyscallCategory::Process);
        assert_eq!(categorize_syscall(Some("clone")), SyscallCategory::Process);
        assert_eq!(categorize_syscall(Some("execve")), SyscallCategory::Process);
        assert_eq!(categorize_syscall(Some("exit_group")), SyscallCategory::Process);
        assert_eq!(categorize_syscall(Some("wait4")), SyscallCategory::Process);
    }

    #[test]
    fn network_syscalls() {
        assert_eq!(categorize_syscall(Some("socket")), SyscallCategory::Network);
        assert_eq!(categorize_syscall(Some("connect")), SyscallCategory::Network);
        assert_eq!(categorize_syscall(Some("bind")), SyscallCategory::Network);
        assert_eq!(categorize_syscall(Some("accept")), SyscallCategory::Network);
        assert_eq!(categorize_syscall(Some("sendto")), SyscallCategory::Network);
    }

    #[test]
    fn memory_syscalls() {
        assert_eq!(categorize_syscall(Some("mmap")), SyscallCategory::Memory);
        assert_eq!(categorize_syscall(Some("mprotect")), SyscallCategory::Memory);
        assert_eq!(categorize_syscall(Some("brk")), SyscallCategory::Memory);
        assert_eq!(categorize_syscall(Some("munmap")), SyscallCategory::Memory);
    }

    #[test]
    fn signal_syscalls() {
        assert_eq!(categorize_syscall(Some("kill")), SyscallCategory::Signal);
        assert_eq!(categorize_syscall(Some("tgkill")), SyscallCategory::Signal);
        assert_eq!(categorize_syscall(Some("rt_sigaction")), SyscallCategory::Signal);
    }

    #[test]
    fn system_syscalls() {
        assert_eq!(categorize_syscall(Some("mount")), SyscallCategory::System);
        assert_eq!(categorize_syscall(Some("reboot")), SyscallCategory::System);
        assert_eq!(categorize_syscall(Some("uname")), SyscallCategory::System);
        assert_eq!(categorize_syscall(Some("getrandom")), SyscallCategory::System);
    }

    #[test]
    fn unknown_syscall_is_other() {
        assert_eq!(categorize_syscall(Some("nonexistent_syscall")), SyscallCategory::Other);
        assert_eq!(categorize_syscall(None), SyscallCategory::Other);
    }

    #[test]
    fn ipc_syscalls() {
        assert_eq!(categorize_syscall(Some("pipe")), SyscallCategory::Ipc);
        assert_eq!(categorize_syscall(Some("pipe2")), SyscallCategory::Ipc);
        assert_eq!(categorize_syscall(Some("futex")), SyscallCategory::Ipc);
        assert_eq!(categorize_syscall(Some("epoll_create1")), SyscallCategory::Ipc);
    }
}
