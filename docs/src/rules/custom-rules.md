# Custom Rules

Write custom YAML detection rules for `sandtrace watch` to monitor additional files and processes.

## YAML rule format

```yaml
rules:
  - id: cred-access-custom-vault
    name: Custom Vault File Access
    severity: high
    description: Unexpected process accessed vault credentials
    detection:
      file_paths:
        - "/opt/vault/creds/*"
      excluded_processes:
        - vault
        - consul
      access_types: [read, write]
    alert:
      channels: [stdout, desktop]
      message: "{process_name} (PID: {pid}) accessed {path}"
    tags: [credential, vault]
    enabled: true
```

## Rule fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique rule identifier |
| `name` | Yes | Human-readable name |
| `severity` | Yes | `critical`, `high`, `medium`, `low`, or `info` |
| `description` | Yes | What the rule detects |
| `detection.file_paths` | Yes | Glob patterns for files to monitor |
| `detection.excluded_processes` | Yes | Process names that are allowed (the allowlist) |
| `detection.access_types` | Yes | Array of `read`, `write`, or both |
| `alert.channels` | No | Override alert channels for this rule |
| `alert.message` | No | Custom alert message template |
| `tags` | No | Tags for filtering and categorization |
| `enabled` | No | Set to `false` to disable (default: `true`) |

## Template variables

Use these variables in the `alert.message` field:

| Variable | Description |
|----------|-------------|
| `{process_name}` | Name of the process that triggered the alert |
| `{pid}` | Process ID |
| `{path}` | File path that was accessed |

## Where to place custom rules

Custom rules can be placed in:

1. **`~/.sandtrace/rules/`** — the default rules directory
2. **Any directory listed in `additional_rules`** in your `config.toml`

```toml
# config.toml
additional_rules = [
  "~/.sandtrace/community-rules",
  "/opt/team-rules/sandtrace",
]
```

All rules from all directories are merged at startup.

## Examples

### Monitor a custom secrets directory

```yaml
rules:
  - id: cred-access-app-secrets
    name: Application Secrets Access
    severity: critical
    description: Unexpected process accessed application secrets
    detection:
      file_paths:
        - "/opt/app/secrets/*"
        - "/opt/app/.env"
      excluded_processes:
        - myapp
        - supervisor
      access_types: [read, write]
    alert:
      channels: [stdout, webhook]
      message: "ALERT: {process_name} (PID: {pid}) accessed {path}"
    tags: [credential, application]
    enabled: true
```

### Monitor database config files

```yaml
rules:
  - id: cred-access-mysql
    name: MySQL Config Access
    severity: high
    description: Unexpected process accessed MySQL credentials
    detection:
      file_paths:
        - "~/.my.cnf"
        - "/etc/mysql/debian.cnf"
      excluded_processes:
        - mysql
        - mysqld
        - mysqldump
        - mysqlsh
      access_types: [read]
    alert:
      channels: [stdout]
      message: "{process_name} read MySQL config at {path}"
    tags: [credential, database]
    enabled: true
```
