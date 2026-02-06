# Sandtrace

A Rust-based malware sandbox tool that combines syscall tracing, filesystem restriction, and network control for safely analyzing untrusted binaries on Linux.

## Overview

Sandtrace provides full-stack isolation using:
- **Linux namespaces** (user, mount, PID, network)
- **Landlock** LSM for filesystem access control
- **seccomp-bpf** for syscall filtering
- **ptrace** for syscall tracing and logging

## Features

- 🔒 **8-layer sandbox** defense-in-depth architecture
- 📊 **Structured JSONL output** for machine parsing
- 🎨 **Colored terminal output** with verbosity levels
- 📜 **TOML policy files** for configurable rules
- 🔍 **Real-time syscall tracing** with argument decoding
- 👶 **Child process tracking** via fork/clone following
- 🚫 **Filesystem restriction** with glob-based rules
- 🌐 **Network control** (allow/deny)

## Building

Requires:
- Rust 1.75+
- Linux 5.13+ (for Landlock v1)
- Linux 5.3+ (for PTRACE_GET_SYSCALL_INFO)

```bash
cargo build --release
```

## Usage

### Basic trace (trace-only mode)
```bash
sandtrace run --trace-only -vv /bin/ls /tmp
```

### Strict sandbox (default policy)
```bash
sandtrace run --allow-path ./project --output trace.jsonl npm install
```

### Custom policy file
```bash
sandtrace run --policy policies/strict.toml ./untrusted_binary
```

### Allow network access
```bash
sandtrace run --allow-net curl https://example.com
```

## Policy File Format (TOML)

```toml
[filesystem]
allow_read = ["/usr", "/lib", "/etc/ld.so.cache"]
allow_write = ["./output"]
deny = ["/home/*/.ssh", "/etc/shadow"]

[network]
allow = false

[syscalls]
deny = ["mount", "ptrace", "reboot"]

[limits]
timeout = 30
```

## Architecture

```
sandtrace/
├── Cargo.toml
├── src/
│   ├── main.rs              # CLI entry point
│   ├── cli.rs               # clap derive structs
│   ├── error.rs             # thiserror error hierarchy
│   ├── event.rs             # Event structs (SyscallEvent, ProcessEvent)
│   ├── policy/              # Policy engine
│   ├── sandbox/             # Sandbox layers
│   │   ├── namespaces.rs    # Linux namespaces
│   │   ├── landlock.rs      # Landlock LSM
│   │   ├── seccomp.rs       # seccomp-bpf
│   │   └── capabilities.rs  # Capability dropping
│   ├── tracer/              # Ptrace tracer
│   │   ├── mod.rs           # Main event loop
│   │   ├── arch/            # Architecture abstraction
│   │   ├── decoder.rs       # Syscall argument decoding
│   │   ├── memory.rs        # Tracee memory access
│   │   └── state.rs         # Per-PID state tracking
│   └── output/              # Output formats
│       ├── jsonl.rs         # JSONL writer
│       └── terminal.rs      # Colored terminal output
```

## Security Note

This is a prototype implementation. In production environments:
- Ensure unprivileged user namespaces are enabled (`kernel.unprivileged_userns_clone=1`)
- Run with appropriate YAMA ptrace scope (`kernel.yama.ptrace_scope <= 1`)
- Test thoroughly in your environment before production use

## License

MIT OR Apache-2.0
