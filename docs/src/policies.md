# Policies

TOML policy files configure the sandbox for `sandtrace run`. They define filesystem access, network permissions, syscall filters, and resource limits.

## Policy format

```toml
[filesystem]
allow_read = ["/usr", "/lib", "/lib64", "/etc/ld.so.cache", "/dev/null", "/proc/self"]
allow_write = ["./output"]
allow_exec = []
deny = ["/home/*/.ssh", "/etc/shadow", "**/.env"]

[network]
allow = false

[syscalls]
deny = ["mount", "ptrace", "reboot"]
log_only = ["mprotect", "mmap"]

[limits]
timeout = 30
```

## Sections

### [filesystem]

| Field | Description |
|-------|-------------|
| `allow_read` | Paths the sandboxed process can read |
| `allow_write` | Paths the sandboxed process can write to |
| `allow_exec` | Paths from which the sandboxed process can execute binaries |
| `deny` | Paths that are always blocked, even if matched by an allow rule |

Path patterns support globs (`*`, `**`). Deny rules take precedence over allow rules.

### [network]

| Field | Description |
|-------|-------------|
| `allow` | Whether to allow network access (`true`/`false`) |

When `false`, the sandbox creates an isolated network namespace with no external connectivity.

### [syscalls]

| Field | Description |
|-------|-------------|
| `deny` | Syscalls to block (returns EPERM) |
| `log_only` | Syscalls to log but allow |

Note: The [always-blocked syscalls](./commands/run.md#always-blocked-syscalls) are blocked regardless of policy configuration.

### [limits]

| Field | Description |
|-------|-------------|
| `timeout` | Kill the process after N seconds |

## Example policies

Example policies are included in the [`examples/`](https://github.com/sandtrace/sandtrace/tree/main/examples) directory:

| File | Description |
|------|-------------|
| `strict.toml` | Minimal filesystem access, no network, blocked dangerous syscalls |
| `permissive.toml` | Broad read access, trace-focused |
| `npm_audit.toml` | Tuned for `npm install` sandboxing |
| `pnpm_audit.toml` | Tuned for `pnpm install` sandboxing |
| `composer_audit.toml` | Tuned for `composer install` sandboxing |

## Usage

```bash
sandtrace run --policy examples/strict.toml ./untrusted-binary
sandtrace run --policy examples/npm_audit.toml npm install
```

Policy flags can be combined with CLI flags. CLI flags (`--allow-path`, `--allow-net`, etc.) are merged with policy file settings, with CLI flags taking precedence.

## Writing your own policies

Start from one of the example policies and customize:

1. **Start strict** — begin with `strict.toml` and add only what the binary needs.
2. **Use trace-only first** — run with `--trace-only` to see what the binary accesses, then write a policy based on the trace.
3. **Deny sensitive paths** — always deny `~/.ssh`, `~/.aws`, `~/.gnupg`, and `.env` files.
4. **Log before blocking** — use `log_only` for syscalls you're unsure about before adding them to `deny`.
