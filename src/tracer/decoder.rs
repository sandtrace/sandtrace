use super::memory::{read_memory, read_string};
use crate::tracer::TraceStats;
use nix::unistd::Pid;
use serde_json::Value;
use std::collections::HashMap;

/// Decode syscall arguments based on syscall name
pub fn decode_syscall_args(
    pid: Pid,
    name: &str,
    args: &[u64; 6],
    stats: &mut TraceStats,
) -> Option<HashMap<String, Value>> {
    let mut decoded = HashMap::new();

    match name {
        "openat" | "open" => {
            if name == "openat" {
                decoded.insert("dirfd".to_string(), dirfd_to_string(args[0]));
                if let Ok(path) = read_string(pid, args[1], 4096) {
                    decoded.insert("path".to_string(), Value::String(path.clone()));
                    track_file_access(stats, &path);
                }
                decoded.insert("flags".to_string(), decode_open_flags(args[2]));
                decoded.insert("mode".to_string(), format!("0o{:o}", args[3]).into());
            } else {
                if let Ok(path) = read_string(pid, args[0], 4096) {
                    decoded.insert("path".to_string(), Value::String(path.clone()));
                    track_file_access(stats, &path);
                }
                decoded.insert("flags".to_string(), decode_open_flags(args[1]));
                decoded.insert("mode".to_string(), format!("0o{:o}", args[2]).into());
            }
        }
        "read" | "write" | "pread64" | "pwrite64" => {
            decoded.insert("fd".to_string(), (args[0] as i64).into());
            decoded.insert("count".to_string(), args[2].into());
        }
        "connect" => {
            decoded.insert("fd".to_string(), (args[0] as i64).into());
            if let Ok(addr) = decode_sockaddr(pid, args[1], args[2] as usize) {
                decoded.insert("addr".to_string(), Value::String(addr.clone()));
                stats.network_attempts.insert(addr);
            }
        }
        "socket" => {
            decoded.insert("domain".to_string(), decode_socket_domain(args[0]));
            decoded.insert("type".to_string(), decode_socket_type(args[1]));
            decoded.insert("protocol".to_string(), (args[2] as i64).into());
        }
        "bind" => {
            decoded.insert("fd".to_string(), (args[0] as i64).into());
            if let Ok(addr) = decode_sockaddr(pid, args[1], args[2] as usize) {
                decoded.insert("addr".to_string(), Value::String(addr));
            }
        }
        "execve" | "execveat" => {
            if let Ok(path) = read_string(pid, args[0], 4096) {
                decoded.insert("path".to_string(), Value::String(path));
            }
            // Could decode argv array here
        }
        "mmap" | "mprotect" => {
            decoded.insert("addr".to_string(), format!("0x{:x}", args[0]).into());
            decoded.insert("length".to_string(), args[1].into());
            if name == "mmap" {
                decoded.insert("prot".to_string(), decode_mmap_prot(args[2]));
                decoded.insert("flags".to_string(), decode_mmap_flags(args[3]));
            } else {
                decoded.insert("prot".to_string(), decode_mmap_prot(args[2]));
            }
        }
        "access" | "faccessat" => {
            if name == "faccessat" {
                decoded.insert("dirfd".to_string(), dirfd_to_string(args[0]));
                if let Ok(path) = read_string(pid, args[1], 4096) {
                    decoded.insert("path".to_string(), Value::String(path));
                }
                decoded.insert("mode".to_string(), decode_access_mode(args[2]));
            } else {
                if let Ok(path) = read_string(pid, args[0], 4096) {
                    decoded.insert("path".to_string(), Value::String(path));
                }
                decoded.insert("mode".to_string(), decode_access_mode(args[1]));
            }
        }
        "stat" | "lstat" | "newfstatat" | "statx" => {
            let path_idx = if name == "newfstatat" { 1 } else { 0 };
            if let Ok(path) = read_string(pid, args[path_idx], 4096) {
                decoded.insert("path".to_string(), Value::String(path));
            }
        }
        "unlink" | "unlinkat" | "rmdir" => {
            if name == "unlinkat" {
                decoded.insert("dirfd".to_string(), dirfd_to_string(args[0]));
                if let Ok(path) = read_string(pid, args[1], 4096) {
                    decoded.insert("path".to_string(), Value::String(path));
                }
                decoded.insert("flags".to_string(), (args[2] as i64).into());
            } else {
                if let Ok(path) = read_string(pid, args[0], 4096) {
                    decoded.insert("path".to_string(), Value::String(path));
                }
            }
        }
        "mkdir" | "mkdirat" => {
            if name == "mkdirat" {
                decoded.insert("dirfd".to_string(), dirfd_to_string(args[0]));
                if let Ok(path) = read_string(pid, args[1], 4096) {
                    decoded.insert("path".to_string(), Value::String(path));
                }
                decoded.insert("mode".to_string(), format!("0o{:o}", args[2]).into());
            } else {
                if let Ok(path) = read_string(pid, args[0], 4096) {
                    decoded.insert("path".to_string(), Value::String(path));
                }
                decoded.insert("mode".to_string(), format!("0o{:o}", args[1]).into());
            }
        }
        "rename" | "renameat" | "renameat2" => {
            let oldpath_idx = if name == "rename" { 0 } else { 1 };
            let newpath_idx = if name == "rename" { 1 } else { 3 };

            if name != "rename" {
                decoded.insert("olddirfd".to_string(), dirfd_to_string(args[0]));
            }
            if let Ok(path) = read_string(pid, args[oldpath_idx], 4096) {
                decoded.insert("oldpath".to_string(), Value::String(path));
            }

            if name != "rename" {
                decoded.insert("newdirfd".to_string(), dirfd_to_string(args[2]));
            }
            if let Ok(path) = read_string(pid, args[newpath_idx], 4096) {
                decoded.insert("newpath".to_string(), Value::String(path));
            }
        }
        "chown" | "fchown" | "lchown" | "fchownat" => {
            if name == "fchownat" {
                decoded.insert("dirfd".to_string(), dirfd_to_string(args[0]));
                if let Ok(path) = read_string(pid, args[1], 4096) {
                    decoded.insert("path".to_string(), Value::String(path));
                }
                decoded.insert("owner".to_string(), (args[2] as i64).into());
                decoded.insert("group".to_string(), (args[3] as i64).into());
            } else if name == "fchown" {
                decoded.insert("fd".to_string(), (args[0] as i64).into());
                decoded.insert("owner".to_string(), (args[1] as i64).into());
                decoded.insert("group".to_string(), (args[2] as i64).into());
            } else {
                if let Ok(path) = read_string(pid, args[0], 4096) {
                    decoded.insert("path".to_string(), Value::String(path));
                }
                decoded.insert("owner".to_string(), (args[1] as i64).into());
                decoded.insert("group".to_string(), (args[2] as i64).into());
            }
        }
        "chmod" | "fchmod" | "fchmodat" => {
            if name == "fchmodat" {
                decoded.insert("dirfd".to_string(), dirfd_to_string(args[0]));
                if let Ok(path) = read_string(pid, args[1], 4096) {
                    decoded.insert("path".to_string(), Value::String(path));
                }
                decoded.insert("mode".to_string(), format!("0o{:o}", args[2]).into());
            } else if name == "fchmod" {
                decoded.insert("fd".to_string(), (args[0] as i64).into());
                decoded.insert("mode".to_string(), format!("0o{:o}", args[1]).into());
            } else {
                if let Ok(path) = read_string(pid, args[0], 4096) {
                    decoded.insert("path".to_string(), Value::String(path));
                }
                decoded.insert("mode".to_string(), format!("0o{:o}", args[1]).into());
            }
        }
        _ => {
            // No specific decoder for this syscall
            return None;
        }
    }

    Some(decoded)
}

fn dirfd_to_string(dirfd: u64) -> Value {
    if dirfd as i64 == libc::AT_FDCWD as i64 {
        Value::String("AT_FDCWD".to_string())
    } else {
        (dirfd as i64).into()
    }
}

fn decode_open_flags(flags: u64) -> Value {
    let mut parts = Vec::new();

    let access_mode = flags & 0o3;
    match access_mode {
        0o0 => parts.push("O_RDONLY"),
        0o1 => parts.push("O_WRONLY"),
        0o2 => parts.push("O_RDWR"),
        _ => parts.push("O_ACCMODE"),
    }

    if flags & libc::O_CREAT as u64 != 0 {
        parts.push("O_CREAT");
    }
    if flags & libc::O_APPEND as u64 != 0 {
        parts.push("O_APPEND");
    }
    if flags & libc::O_TRUNC as u64 != 0 {
        parts.push("O_TRUNC");
    }
    if flags & libc::O_EXCL as u64 != 0 {
        parts.push("O_EXCL");
    }
    if flags & libc::O_CLOEXEC as u64 != 0 {
        parts.push("O_CLOEXEC");
    }
    if flags & libc::O_NONBLOCK as u64 != 0 {
        parts.push("O_NONBLOCK");
    }
    if flags & libc::O_DIRECTORY as u64 != 0 {
        parts.push("O_DIRECTORY");
    }
    if flags & libc::O_NOFOLLOW as u64 != 0 {
        parts.push("O_NOFOLLOW");
    }

    Value::String(parts.join(" | "))
}

fn decode_mmap_prot(prot: u64) -> Value {
    let mut parts = Vec::new();

    if prot == 0 {
        parts.push("PROT_NONE");
    } else {
        if prot & libc::PROT_READ as u64 != 0 {
            parts.push("PROT_READ");
        }
        if prot & libc::PROT_WRITE as u64 != 0 {
            parts.push("PROT_WRITE");
        }
        if prot & libc::PROT_EXEC as u64 != 0 {
            parts.push("PROT_EXEC");
        }
    }

    Value::String(parts.join(" | "))
}

fn decode_mmap_flags(flags: u64) -> Value {
    let mut parts = Vec::new();

    // Map type
    let map_type = flags & libc::MAP_TYPE as u64;
    match map_type {
        x if x == libc::MAP_SHARED as u64 => parts.push("MAP_SHARED"),
        x if x == libc::MAP_PRIVATE as u64 => parts.push("MAP_PRIVATE"),
        x if x == libc::MAP_SHARED_VALIDATE as u64 => parts.push("MAP_SHARED_VALIDATE"),
        _ => {}
    }

    if flags & libc::MAP_FIXED as u64 != 0 {
        parts.push("MAP_FIXED");
    }
    if flags & libc::MAP_ANONYMOUS as u64 != 0 {
        parts.push("MAP_ANONYMOUS");
    }
    if flags & libc::MAP_STACK as u64 != 0 {
        parts.push("MAP_STACK");
    }

    Value::String(parts.join(" | "))
}

fn decode_access_mode(mode: u64) -> Value {
    let mut parts = Vec::new();

    if mode & libc::R_OK as u64 != 0 {
        parts.push("R_OK");
    }
    if mode & libc::W_OK as u64 != 0 {
        parts.push("W_OK");
    }
    if mode & libc::X_OK as u64 != 0 {
        parts.push("X_OK");
    }
    if mode == libc::F_OK as u64 {
        parts.push("F_OK");
    }

    Value::String(parts.join(" | "))
}

fn decode_socket_domain(domain: u64) -> Value {
    match domain as i32 {
        libc::AF_UNIX => Value::String("AF_UNIX".to_string()),
        libc::AF_INET => Value::String("AF_INET".to_string()),
        libc::AF_INET6 => Value::String("AF_INET6".to_string()),
        libc::AF_NETLINK => Value::String("AF_NETLINK".to_string()),
        libc::AF_PACKET => Value::String("AF_PACKET".to_string()),
        _ => (domain as i64).into(),
    }
}

fn decode_socket_type(ty: u64) -> Value {
    let base = ty & 0xF;
    let mut parts = Vec::new();

    match base as i32 {
        libc::SOCK_STREAM => parts.push("SOCK_STREAM"),
        libc::SOCK_DGRAM => parts.push("SOCK_DGRAM"),
        libc::SOCK_SEQPACKET => parts.push("SOCK_SEQPACKET"),
        libc::SOCK_RAW => parts.push("SOCK_RAW"),
        libc::SOCK_RDM => parts.push("SOCK_RDM"),
        libc::SOCK_PACKET => parts.push("SOCK_PACKET"),
        _ => parts.push("UNKNOWN"),
    }

    if ty & libc::SOCK_NONBLOCK as u64 != 0 {
        parts.push("SOCK_NONBLOCK");
    }
    if ty & libc::SOCK_CLOEXEC as u64 != 0 {
        parts.push("SOCK_CLOEXEC");
    }

    Value::String(parts.join(" | "))
}

fn decode_sockaddr(pid: Pid, addr: u64, len: usize) -> Result<String, Box<dyn std::error::Error>> {
    if addr == 0 {
        return Ok("NULL".to_string());
    }

    let data = read_memory(pid, addr, len.min(128))?;
    if data.len() < 2 {
        return Ok("<invalid>".to_string());
    }

    let family = u16::from_le_bytes([data[0], data[1]]) as i32;

    match family {
        libc::AF_INET if data.len() >= 16 => {
            let port = u16::from_be_bytes([data[2], data[3]]);
            let ip = format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7]);
            Ok(format!("{}:{}", ip, port))
        }
        libc::AF_INET6 if data.len() >= 28 => {
            let port = u16::from_be_bytes([data[2], data[3]]);
            // Simplified IPv6 display
            Ok(format!("[IPv6]:{}", port))
        }
        libc::AF_UNIX => {
            if data.len() > 2 {
                let path = std::str::from_utf8(&data[2..])
                    .unwrap_or("<invalid>")
                    .trim_end_matches('\0');
                Ok(format!("unix:{}", path))
            } else {
                Ok("unix:<unnamed>".to_string())
            }
        }
        _ => Ok(format!("family:{}", family)),
    }
}

fn track_file_access(stats: &mut TraceStats, path: &str) {
    // Track sensitive file accesses
    let sensitive_paths = [".ssh", "/etc/shadow", "/etc/passwd", ".env", ".bashrc"];

    for sensitive in &sensitive_paths {
        if path.contains(sensitive) {
            let msg = format!("Attempted to access sensitive file: {}", path);
            if !stats.suspicious_activity.contains(&msg) {
                stats.suspicious_activity.push(msg);
            }
        }
    }

    stats.files_accessed.insert(path.to_string());
}
