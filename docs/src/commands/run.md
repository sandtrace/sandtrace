# sandtrace run

Executes untrusted binaries inside an 8-layer isolation sandbox with ptrace-based syscall tracing.

## Usage

```bash
sandtrace run --trace-only -vv /bin/ls /tmp                   # Trace only (no enforcement)
sandtrace run --allow-path ./project --output trace.jsonl npm install  # With filesystem restriction
sandtrace run --policy policies/strict.toml ./untrusted        # Custom policy
sandtrace run --allow-net curl https://example.com             # Allow network
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--policy` | — | TOML policy file |
| `--allow-path` | — | Allow filesystem access to path (repeatable) |
| `--allow-net` | `false` | Allow network access |
| `--allow-exec` | `false` | Allow child process execution |
| `-o, --output` | — | JSONL output file |
| `--timeout` | `30` | Kill process after N seconds |
| `--trace-only` | `false` | Disable enforcement (no Landlock/seccomp) |
| `--follow-forks` | `true` | Trace child processes |
| `--no-color` | `false` | Disable colored output |
| `-v` / `-vv` / `-vvv` | — | Verbosity level |

## Sandbox layers

Applied in order after `fork()`:

| Layer | Mechanism | What it does |
|-------|-----------|--------------|
| 1 | User namespace | Gain capabilities without privilege escalation |
| 2 | Mount namespace | Restrict filesystem view |
| 3 | PID namespace | Hide host processes |
| 4 | Network namespace | Isolate network (unless `--allow-net`) |
| 5 | `PR_SET_NO_NEW_PRIVS` | Prevent privilege escalation via setuid |
| 6 | Landlock LSM | Kernel-level filesystem access control |
| 7 | seccomp-bpf | Block dangerous syscalls at kernel level |
| 8 | ptrace `TRACEME` | Signal readiness to tracer, raise SIGSTOP |

Layers 6-7 are skipped when `--trace-only` is set.

### Always-blocked syscalls

The following syscalls are always blocked by the seccomp-bpf filter, regardless of policy:

`kexec_load`, `kexec_file_load`, `reboot`, `swapon`, `swapoff`, `init_module`, `finit_module`, `delete_module`, `acct`, `pivot_root`

## JSONL output format

When using `--output`, each line is a self-contained JSON object:

### Syscall event

```json
{
  "event_type": "syscall",
  "timestamp": "2025-01-01T12:00:00Z",
  "pid": 1234,
  "syscall": "openat",
  "syscall_nr": 257,
  "args": {"raw": [0, 140234567, 0, 0, 0, 0]},
  "return_value": 3,
  "success": true,
  "duration_us": 42,
  "action": "allow",
  "category": "file_read"
}
```

### Process lifecycle

```json
{"event_type": "process", "action": "exec", "pid": 1234, "comm": "npm"}
{"event_type": "process", "action": "exited", "pid": 1234, "exit_code": 0}
```

### Trace summary

```json
{"event_type": "summary", "total_syscalls": 4521, "unique_syscalls": 23, "duration_ms": 1200}
```

## Examples

### Trace a command without enforcement

```bash
sandtrace run --trace-only -vv /bin/ls /tmp
```

Useful for understanding what syscalls a binary makes before writing a policy.

### Sandbox npm install

```bash
sandtrace run --allow-path ./my-project --output npm-trace.jsonl npm install
```

Restricts filesystem access to the project directory, traces all syscalls, and writes results to a JSONL file for analysis.

### Use a policy file

```bash
sandtrace run --policy examples/strict.toml ./untrusted-binary
```

See [Policies](../policies.md) for the TOML policy format and example policies.
