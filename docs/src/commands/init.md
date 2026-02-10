# sandtrace init

Initializes the `~/.sandtrace/` directory with default configuration and rule files.

## Usage

```bash
sandtrace init            # Create config and rules (skip if exists)
sandtrace init --force    # Overwrite existing files
```

## What it creates

```
~/.sandtrace/
├── config.toml                  # Global settings
└── rules/
    ├── credential-access.yml    # 14 credential file monitoring rules
    ├── supply-chain.yml         # 4 supply-chain attack detection rules
    └── exfiltration.yml         # Data exfiltration detection rules
```

### config.toml

The global configuration file. Controls:

- Rules directory paths
- Default alert channels for watch mode
- Shai-Hulud scanner thresholds
- Custom credential patterns
- Redaction markers for false positive suppression

See [Configuration](../configuration.md) for the full reference.

### rules/credential-access.yml

14 rules that define which credential files to monitor and which processes are allowed to access them. Used by `sandtrace watch`.

See [Watch Rules](../rules/watch-rules.md) for the full rule list.

### rules/supply-chain.yml

4 rules that detect suspicious writes to dependency directories (node_modules, pip config, cargo registry) from unexpected processes.

### rules/exfiltration.yml

Rules that detect potential data exfiltration patterns, such as unexpected curl/wget outbound requests during build or install operations.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--force` | `false` | Overwrite existing files |

## When to re-initialize

Run `sandtrace init --force` after upgrading sandtrace to get the latest default rules and configuration. Your custom rules in additional directories will not be affected.
