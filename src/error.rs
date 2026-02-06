use thiserror::Error;

#[derive(Error, Debug)]
pub enum SandtraceError {
    #[error("Sandbox error: {0}")]
    Sandbox(#[from] SandboxError),

    #[error("Tracer error: {0}")]
    Tracer(#[from] TracerError),

    #[error("Policy error: {0}")]
    Policy(#[from] PolicyError),

    #[error("Output error: {0}")]
    Output(#[from] OutputError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
}

#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("Namespace creation failed: {0}")]
    NamespaceCreation(#[source] nix::Error),

    #[error("Landlock setup failed: {0}")]
    LandlockSetup(String),

    #[error("Seccomp installation failed: {0}")]
    SeccompInstall(String),

    #[error("Capability drop failed: {0}")]
    CapabilityDrop(String),

    #[error("Fork failed: {0}")]
    Fork(#[source] nix::Error),

    #[error("Exec failed: path={path}, source={source}")]
    Exec {
        path: String,
        #[source]
        source: nix::Error,
    },

    #[error("Failed to set PR_SET_NO_NEW_PRIVS: {0}")]
    NoNewPrivs(#[source] nix::Error),

    #[error("Ptrace error: {0}")]
    Ptrace(#[source] nix::Error),
}

#[derive(Error, Debug)]
pub enum TracerError {
    #[error("Ptrace error: {0}")]
    Ptrace(#[source] nix::Error),

    #[error("Memory read failed at {addr:#x}: {source}")]
    MemoryRead {
        addr: u64,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Wait failed: {0}")]
    Wait(#[source] nix::Error),

    #[error("Unknown syscall {number} on {arch}")]
    UnknownSyscall { number: u64, arch: String },

    #[error("Timeout after {0} seconds")]
    Timeout(u64),

    #[error("Architecture not supported: {0}")]
    UnsupportedArch(String),

    #[error("Process {pid} not found in state map")]
    ProcessNotFound(i32),
}

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Failed to read policy file {path}: {source}")]
    FileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse policy TOML: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("Invalid rule: {0}")]
    InvalidRule(String),

    #[error("Invalid glob pattern '{pattern}': {source}")]
    GlobPattern {
        pattern: String,
        #[source]
        source: glob::PatternError,
    },
}

#[derive(Error, Debug)]
pub enum OutputError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Serialize(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, SandtraceError>;
