use crate::error::{Result, TracerError};
use nix::sys::uio::{process_vm_readv, RemoteIoVec};
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

    let local_iov = [nix::sys::uio::IoVec::from_mut_slice(&mut buf)];
    let remote_iov = [RemoteIoVec {
        base: addr as usize,
        len,
    }];

    match process_vm_readv(pid, &local_iov, &remote_iov) {
        Ok(n) => {
            buf.truncate(n);
            Ok(buf)
        }
        Err(e) => Err(TracerError::MemoryRead {
            addr,
            source: Box::new(std::io::Error::from(e)),
        }.into()),
    }
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
