use crate::error::{Result, TracerError};
use crate::event::SyscallCategory;
use nix::unistd::Pid;

pub mod x86_64;
pub mod aarch64;

pub trait Architecture: Send + Sync {
    fn name(&self) -> &'static str;
    fn syscall_number(&self, regs: &RawRegisters) -> u64;
    fn syscall_args(&self, regs: &RawRegisters) -> [u64; 6];
    fn return_value(&self, regs: &RawRegisters) -> i64;
    fn syscall_name(&self, nr: u64) -> Option<&'static str>;
    fn syscall_category(&self, nr: u64) -> SyscallCategory;
    fn set_syscall_number(&self, regs: &mut RawRegisters, nr: u64);
}

#[derive(Debug, Clone)]
pub enum RawRegisters {
    X86_64(x86_64::UserRegs),
    Aarch64(aarch64::UserRegs),
}

pub fn detect_architecture() -> Result<Box<dyn Architecture>> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(Box::new(x86_64::X86_64Arch::new()))
    }

    #[cfg(target_arch = "aarch64")]
    {
        Ok(Box::new(aarch64::Aarch64Arch::new()))
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err(TracerError::UnsupportedArch(std::env::consts::ARCH.to_string()).into())
    }
}

pub fn read_registers(pid: Pid) -> Result<RawRegisters> {
    // Try PTRACE_GET_SYSCALL_INFO first (Linux 5.3+)
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::read_registers(pid).map(RawRegisters::X86_64)
    }

    #[cfg(target_arch = "aarch64")]
    {
        aarch64::read_registers(pid).map(RawRegisters::Aarch64)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err(TracerError::UnsupportedArch(std::env::consts::ARCH.to_string()).into())
    }
}

pub fn write_registers(pid: Pid, regs: &RawRegisters) -> Result<()> {
    match regs {
        RawRegisters::X86_64(r) => x86_64::write_registers(pid, r),
        RawRegisters::Aarch64(r) => aarch64::write_registers(pid, r),
    }
}
