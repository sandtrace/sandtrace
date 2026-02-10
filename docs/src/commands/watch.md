# sandtrace watch

Monitors sensitive files via inotify and matches access events against YAML rules. Alerts through multiple channels when unexpected processes access credential files.

## Usage

```bash
sandtrace watch                                    # stdout alerts
sandtrace watch --alert desktop                    # Desktop notifications
sandtrace watch --alert webhook:https://hooks.slack.com/services/T00/B00/XXX
sandtrace watch --alert stdout --alert desktop     # Multiple channels
sandtrace watch --paths /opt/secrets/              # Watch additional paths
sandtrace watch --daemon --pid-file /tmp/st.pid    # Run as daemon
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--rules` | `~/.sandtrace/rules/` | YAML rules directory |
| `--paths` | — | Additional paths to monitor (repeatable) |
| `--alert` | `stdout` | Alert channel (repeatable) |
| `--daemon` | `false` | Fork to background |
| `--pid-file` | — | PID file for daemon mode |
| `--no-color` | `false` | Disable colored output |
| `-v` / `-vv` | — | Increase verbosity |

## Alert channels

| Channel | Format | Description |
|---------|--------|-------------|
| `stdout` | `--alert stdout` | Print to console |
| `desktop` | `--alert desktop` | Desktop notification (notify-rust) |
| `webhook` | `--alert webhook:<url>` | HTTP POST to webhook URL |
| `syslog` | `--alert syslog` | System log |

Multiple alert channels can be combined by repeating the `--alert` flag.

## How it works

1. On startup, sandtrace reads all YAML rules from the rules directory.
2. It registers inotify watches on all file paths defined in the rules.
3. When a file access event fires, it checks the accessing process against the rule's `excluded_processes` list.
4. If the process is not in the allowlist, an alert is dispatched to all configured channels.

## Examples

### Desktop + webhook alerts

```bash
sandtrace watch --alert desktop --alert webhook:https://hooks.slack.com/services/T00/B00/XXX
```

### Daemon mode

```bash
sandtrace watch --daemon --pid-file /tmp/sandtrace-watch.pid --alert syslog
```

Runs in the background and logs to syslog. Use the PID file to stop the daemon:

```bash
kill $(cat /tmp/sandtrace-watch.pid)
```

### Monitor additional paths

```bash
sandtrace watch --paths /opt/vault/creds/ --paths /etc/ssl/private/
```

## Built-in watch rules

See [Watch Rules](../rules/watch-rules.md) for the full list of 19 built-in rules that monitor credential files, supply-chain directories, and exfiltration attempts.
