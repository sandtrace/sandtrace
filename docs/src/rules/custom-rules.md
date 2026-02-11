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

## IOC Rules

The `custom_patterns` configuration in `config.toml` supports three match types that make it easy to add indicators of compromise (IOCs) without writing regex.

### Match types

| Type | Description | Use case |
|------|-------------|----------|
| `regex` | Regular expression matched against file content (default) | Custom credential formats |
| `literal` | Exact string match against file content (case-insensitive) | IOC domains, IPs, hashes |
| `filename` | Match against file names/paths (case-insensitive) | Known malicious filenames |

### C2 domains

```toml
[[custom_patterns]]
id = "ioc-c2-domain-1"
description = "Known C2 domain: evil-payload.example.com"
severity = "critical"
match_type = "literal"
pattern = "evil-payload.example.com"
tags = ["ioc", "c2"]

[[custom_patterns]]
id = "ioc-c2-domain-2"
description = "Known C2 domain: data-exfil.example.net"
severity = "critical"
match_type = "literal"
pattern = "data-exfil.example.net"
tags = ["ioc", "c2"]
```

### Malicious file hashes

```toml
# SHA256 hash
[[custom_patterns]]
id = "ioc-malware-sha256-1"
description = "Known malware SHA256: Trojan.GenericKD"
severity = "critical"
match_type = "literal"
pattern = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
tags = ["ioc", "malware", "sha256"]

# MD5 hash
[[custom_patterns]]
id = "ioc-malware-md5-1"
description = "Known malware MD5: Backdoor.Agent"
severity = "critical"
match_type = "literal"
pattern = "d41d8cd98f00b204e9800998ecf8427e"
tags = ["ioc", "malware", "md5"]
```

### Suspicious IP addresses

```toml
[[custom_patterns]]
id = "ioc-c2-ip-1"
description = "Known C2 IP address"
severity = "critical"
match_type = "literal"
pattern = "198.51.100.42"
tags = ["ioc", "c2", "ip"]
```

### Known malicious filenames

```toml
[[custom_patterns]]
id = "ioc-tool-mimikatz"
description = "Mimikatz credential dumping tool"
severity = "high"
match_type = "filename"
pattern = "mimikatz"
file_extensions = ["exe", "dll", "ps1"]
tags = ["ioc", "tool", "credential-theft"]

[[custom_patterns]]
id = "ioc-webshell"
description = "Common webshell filename"
severity = "critical"
match_type = "filename"
pattern = "c99shell"
file_extensions = ["php", "asp", "jsp"]
tags = ["ioc", "webshell"]
```

### Bulk IOC import

For large IOC lists, generate `config.toml` entries programmatically. Example with a domains list:

```bash
# Convert a plain-text IOC list to TOML config entries
while IFS= read -r domain; do
  id=$(echo "$domain" | tr '.' '-' | tr -cd 'a-z0-9-')
  cat <<EOF

[[custom_patterns]]
id = "ioc-domain-${id}"
description = "IOC domain: ${domain}"
severity = "critical"
match_type = "literal"
pattern = "${domain}"
tags = ["ioc", "c2"]
EOF
done < domains.txt >> ~/.sandtrace/config.toml
```

## Automated IOC feeds

sandtrace can automatically ingest indicators of compromise from external threat feeds. The `pattern_files` config option lets you load auto-generated pattern files without cluttering your main `config.toml`.

### npm malware feed (OpenSSF / OSV)

The `scripts/update-npm-iocs.sh` script downloads the [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) dataset (published in OSV format) and generates a TOML file of `[[custom_patterns]]` entries for every known-malicious npm package.

**Requirements:** `curl`, `unzip`, `jq`

**Usage:**

```bash
# Download and generate (default output: ~/.sandtrace/npm-malware.toml)
./scripts/update-npm-iocs.sh

# Custom output path
./scripts/update-npm-iocs.sh /path/to/output.toml
```

Then add the generated file to your `config.toml`:

```toml
pattern_files = ["~/.sandtrace/npm-malware.toml"]
```

**Run on a schedule with cron:**

```bash
# Update npm malware patterns daily at 3 AM
0 3 * * * /path/to/sandtrace/scripts/update-npm-iocs.sh
```

The generated file contains one `[[custom_patterns]]` entry per malicious package, with `match_type = "literal"` and `file_extensions = ["json"]` so it only scans `package.json`, `package-lock.json`, and similar files.

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
