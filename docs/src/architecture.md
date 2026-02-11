# Architecture

## Source tree

```
sandtrace/
├── Cargo.toml
├── rules/                        # Built-in YAML detection rules
│   ├── credential-access.yml     # 14 credential file monitoring rules
│   ├── supply-chain.yml          # 4 supply-chain attack detection rules
│   └── exfiltration.yml          # Data exfiltration detection rules
├── examples/                     # Example policy and config files
│   ├── config.toml               # Annotated global config
│   ├── strict.toml               # Strict sandbox policy
│   ├── permissive.toml           # Permissive sandbox policy
│   └── *_audit.toml              # Package manager audit policies
├── src/
│   ├── main.rs                   # CLI entry point + dispatch
│   ├── cli.rs                    # clap derive structs + validation
│   ├── config.rs                 # Global config (~/.sandtrace/config.toml)
│   ├── error.rs                  # thiserror error hierarchy
│   ├── event.rs                  # SyscallEvent, AuditFinding, Severity
│   ├── init.rs                   # `init` subcommand
│   ├── scan.rs                   # `scan` subcommand (rayon parallel sweep)
│   ├── process.rs                # Process tree tracking via /proc
│   ├── rules/
│   │   ├── mod.rs                # RuleRegistry, rule loading
│   │   ├── matcher.rs            # File access + process matching
│   │   ├── schema.rs             # YAML schema definitions
│   │   └── builtin.rs            # Built-in rule definitions
│   ├── audit/
│   │   ├── mod.rs                # Audit orchestrator (parallel via rayon)
│   │   ├── scanner.rs            # Credential + supply-chain patterns
│   │   └── obfuscation.rs        # Steganography + obfuscation detection
│   ├── watch/
│   │   ├── mod.rs                # Watch orchestrator (tokio async)
│   │   ├── monitor.rs            # inotify file monitoring
│   │   └── handler.rs            # Event handler + rule matching
│   ├── alert/
│   │   ├── mod.rs                # AlertRouter + AlertDispatcher trait
│   │   ├── stdout.rs             # Console alerts
│   │   ├── desktop.rs            # Desktop notifications (notify-rust)
│   │   ├── webhook.rs            # HTTP webhook (reqwest)
│   │   └── syslog.rs             # Syslog alerts
│   ├── policy/
│   │   ├── mod.rs                # Policy struct, path/syscall evaluation
│   │   ├── parser.rs             # TOML policy parsing
│   │   └── rules.rs              # PolicyEvaluator
│   ├── sandbox/
│   │   ├── mod.rs                # SandboxConfig, apply_child_sandbox()
│   │   ├── namespaces.rs         # User, mount, PID, network namespaces
│   │   ├── landlock.rs           # Landlock LSM filesystem control
│   │   ├── seccomp.rs            # seccomp-bpf syscall filtering
│   │   └── capabilities.rs       # Capability dropping, NO_NEW_PRIVS
│   ├── tracer/
│   │   ├── mod.rs                # Main ptrace event loop
│   │   ├── decoder.rs            # Syscall argument decoding
│   │   ├── memory.rs             # Tracee memory access
│   │   ├── state.rs              # Per-PID state tracking
│   │   ├── syscalls.rs           # Syscall categorization
│   │   └── arch/
│   │       ├── mod.rs            # Architecture trait
│   │       ├── x86_64.rs         # x86_64 syscall table
│   │       └── aarch64.rs        # ARM64 syscall table
│   └── output/
│       ├── mod.rs                # OutputManager + OutputSink trait
│       ├── jsonl.rs              # JSONL writer
│       └── terminal.rs           # Colored terminal output
└── tests/
    ├── integration.rs            # Integration tests
    └── fixtures/binaries/        # Test binaries (fork, mount, read, connect)
```

## Module overview

### CLI layer (`main.rs`, `cli.rs`)

Entry point using `clap` derive macros. Parses arguments, loads config, and dispatches to the appropriate subcommand.

### Config (`config.rs`)

Loads and validates `~/.sandtrace/config.toml`. Provides defaults for all optional fields.

### Audit (`audit/`)

Parallel codebase scanner using `rayon`. The `scanner.rs` module handles credential and supply-chain pattern matching via regex. The `obfuscation.rs` module handles whitespace obfuscation, zero-width unicode, and homoglyph detection.

### Scan (`scan.rs`)

Standalone parallel filesystem sweep using `rayon` and ignore-aware directory walking. Focused specifically on detecting consecutive whitespace runs.

### Watch (`watch/`)

Async file monitoring using `tokio` and `inotify`. The `monitor.rs` module manages inotify watches, and `handler.rs` matches events against YAML rules.

### Rules (`rules/`)

YAML rule loading, parsing, and matching. The `RuleRegistry` merges rules from all configured directories. The `matcher.rs` module handles file path globbing and process name matching.

### Alert (`alert/`)

Pluggable alert dispatch using the `AlertDispatcher` trait. Implementations for stdout, desktop notifications (via `notify-rust`), HTTP webhooks (via `reqwest`), and syslog.

### Policy (`policy/`)

TOML policy parsing and evaluation. The `PolicyEvaluator` determines whether a given filesystem access or syscall should be allowed, denied, or logged.

### Sandbox (`sandbox/`)

Linux namespace and security module setup. Applied in order: user namespace, mount namespace, PID namespace, network namespace, `NO_NEW_PRIVS`, Landlock, seccomp-bpf, ptrace.

### Tracer (`tracer/`)

ptrace-based syscall tracing. The main event loop handles `PTRACE_SYSCALL` stops, decodes arguments via architecture-specific tables (`x86_64`, `aarch64`), and applies policy decisions.

### Output (`output/`)

Pluggable output using the `OutputSink` trait. JSONL writer for machine-readable traces and colored terminal output for human consumption.
