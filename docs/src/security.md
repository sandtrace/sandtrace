# Security

## Important notes

sandtrace is a prototype security tool. Review these notes before using it in production environments.

## Kernel requirements

### sandtrace run (sandbox)

| Requirement | Kernel setting | Minimum version |
|-------------|---------------|-----------------|
| Unprivileged user namespaces | `kernel.unprivileged_userns_clone=1` | Linux 3.8+ |
| Landlock LSM | Built-in or module loaded | Linux 5.13+ (Landlock v1) |
| PTRACE_GET_SYSCALL_INFO | — | Linux 5.3+ |
| YAMA ptrace scope | `kernel.yama.ptrace_scope <= 1` | — |

Check your kernel settings:

```bash
sysctl kernel.unprivileged_userns_clone
sysctl kernel.yama.ptrace_scope
cat /sys/kernel/security/lsm  # Should include "landlock"
```

### sandtrace watch

Requires `inotify` support (available in all modern Linux kernels).

### sandtrace audit / sandtrace scan

No special kernel requirements. Works on any Linux system with Rust 1.75+.

## Limitations

- **The sandbox is defense-in-depth, not a security boundary guarantee.** A determined attacker with kernel exploits could escape the sandbox. Use sandtrace as one layer in a defense-in-depth strategy, not as your sole isolation mechanism.
- **ptrace-based tracing has overhead.** Sandboxed processes will run slower than native execution due to syscall interception. This is acceptable for auditing untrusted packages but not suitable for production workloads.
- **seccomp-bpf filters are process-wide.** Once applied, they cannot be relaxed — only made more restrictive. This is by design.
- **Landlock restrictions are cumulative.** Like seccomp, Landlock rules can only be made more restrictive after initial application.

## Security model

sandtrace's sandbox applies multiple independent isolation layers. Each layer provides protection even if other layers are bypassed:

1. **Namespace isolation** prevents the sandboxed process from seeing or affecting the host.
2. **Landlock** provides kernel-enforced filesystem access control.
3. **seccomp-bpf** blocks dangerous syscalls at the kernel level.
4. **ptrace tracing** provides visibility into all syscall activity.

The combination means an attacker would need to bypass multiple independent kernel security mechanisms to escape.

## Responsible use

- Test sandtrace thoroughly in your environment before production use.
- Keep your kernel updated for the latest security patches.
- Review sandbox traces to understand what untrusted code is doing before allowing it in production.
- Use strict policies by default and only relax restrictions when you understand why they're needed.
