use crate::error::{Result, TracerError};
use nix::unistd::Pid;

/// Read data from tracee's memory
/// Primary: process_vm_readv (fast)
/// Fallback: ptrace::read (slower, word by word)
pub fn read_memory(pid: Pid, addr: u64, len: usize) -> Result<Vec<u8>> {
    // Try process_vm_readv first
    match read_memory_process_vm(pid, addr, len) {
        Ok(data) => return Ok(data),
        Err(e) => {
            log::debug!("process_vm_readv failed, falling back to ptrace: {}", e);
        }
    }

    // Fallback to ptrace
    read_memory_ptrace(pid, addr, len)
}

fn read_memory_process_vm(pid: Pid, addr: u64, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];

    // Create local iovec using libc::iovec directly
    let local_iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: len,
    };
    let remote_iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };

    let res = unsafe {
        libc::process_vm_readv(
            pid.as_raw(),
            &local_iov,
            1,
            &remote_iov,
            1,
            0,
        )
    };

    if res < 0 {
        return Err(TracerError::MemoryRead {
            addr,
            source: Box::new(std::io::Error::last_os_error()),
        }.into());
    }

    buf.truncate(res as usize);
    Ok(buf)
}

fn read_memory_ptrace(pid: Pid, addr: u64, len: usize) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(len);
    let mut current_addr = addr;

    while buf.len() < len {
        match nix::sys::ptrace::read(pid, current_addr as *mut libc::c_void) {
            Ok(word) => {
                let bytes = word.to_le_bytes();
                let remaining = len - buf.len();
                let to_copy = std::cmp::min(remaining, 8);
                buf.extend_from_slice(&bytes[..to_copy]);
                current_addr += 8;
            }
            Err(e) => {
                // Partial read is okay if we got some data
                if buf.is_empty() {
                    return Err(TracerError::MemoryRead {
                        addr,
                        source: Box::new(std::io::Error::from(e)),
                    }.into());
                }
                break;
            }
        }
    }

    Ok(buf)
}

/// Read a null-terminated string from tracee memory
pub fn read_string(pid: Pid, addr: u64, max_len: usize) -> Result<String> {
    let mut result = Vec::new();
    let mut current_addr = addr;

    while result.len() < max_len {
        match nix::sys::ptrace::read(pid, current_addr as *mut libc::c_void) {
            Ok(word) => {
                let bytes = word.to_le_bytes();
                for byte in &bytes {
                    if *byte == 0 {
                        return String::from_utf8(result)
                            .map_err(|e| TracerError::MemoryRead {
                                addr,
                                source: Box::new(e),
                            }.into());
                    }
                    result.push(*byte);
                }
                current_addr += 8;
            }
            Err(e) => {
                return Err(TracerError::MemoryRead {
                    addr,
                    source: Box::new(std::io::Error::from(e)),
                }.into());
            }
        }
    }

    // Truncated string
    String::from_utf8(result).map_err(|e| TracerError::MemoryRead {
        addr,
        source: Box::new(e),
    }.into())
}

/// Read a struct from tracee memory
pub fn read_struct<T: Sized>(pid: Pid, addr: u64) -> Result<T> {
    let size = std::mem::size_of::<T>();
    let bytes = read_memory(pid, addr, size)?;

    if bytes.len() < size {
        return Err(TracerError::MemoryRead {
            addr,
            source: Box::new(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Incomplete struct read",
            )),
        }.into());
    }

    unsafe {
        let ptr = bytes.as_ptr() as *const T;
        Ok(std::ptr::read(ptr))
    }
}
