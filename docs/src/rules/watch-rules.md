# Watch Rules

`sandtrace watch` uses YAML rules to monitor credential files and detect suspicious access patterns. Built-in rules cover 19 detection scenarios across three categories.

## Credential access rules (14 rules)

These rules alert when processes outside the expected allowlist access sensitive files:

| Rule ID | Files Monitored | Allowed Processes |
|---------|----------------|-------------------|
| `cred-access-aws` | `~/.aws/credentials`, `~/.aws/config` | aws, terraform, pulumi, cdktf |
| `cred-access-ssh` | `~/.ssh/id_*`, `~/.ssh/config` | ssh, scp, sftp, ssh-agent, git |
| `cred-access-gpg` | `~/.gnupg/*` | gpg, gpg2, gpg-agent, git |
| `cred-access-npm` | `~/.npmrc`, `~/.config/npm/*` | npm, npx, pnpm, yarn, node |
| `cred-access-docker` | `~/.docker/config.json` | docker, dockerd, containerd |
| `cred-access-kube` | `~/.kube/config` | kubectl, helm, k9s, kubectx |
| `cred-access-gcloud` | `~/.config/gcloud/*` | gcloud, terraform, pulumi |
| `cred-access-azure` | `~/.azure/*` | az, terraform, pulumi |
| `cred-access-pgpass` | `~/.pgpass` | psql, pg_dump, pg_restore, pgcli |
| `cred-access-volta` | `~/.volta/*` | volta, node, npm, npx |
| `cred-access-triton` | `~/.triton/*` | triton, node |
| `cred-access-netrc` | `~/.netrc` | curl, wget, git, ftp |
| `cred-access-git-credentials` | `~/.git-credentials` | git, git-credential-store |
| `cred-access-cpln` | `~/.config/cpln/*` | cpln, node |

## Supply-chain rules (4 rules)

These rules detect writes to dependency directories from processes outside the expected package managers:

| Rule ID | What it detects |
|---------|----------------|
| `supply-chain-node-modules` | Direct write to `node_modules` outside npm/yarn/pnpm |
| `supply-chain-npmrc-write` | Unexpected modification of `.npmrc` |
| `supply-chain-pip-conf` | Unexpected modification of pip configuration |
| `supply-chain-cargo-registry` | Direct modification of Cargo registry cache |

## Exfiltration rules (1 rule)

| Rule ID | What it detects |
|---------|----------------|
| `exfil-curl-unknown` | curl/wget outbound requests during build/install |

## How rules work

Each watch rule defines:

1. **File paths** to monitor via inotify
2. **Excluded processes** (the allowlist) that are expected to access those files
3. **Access types** to watch for (read, write, or both)
4. **Alert channels** and message templates

When a file access event occurs, sandtrace checks the accessing process name against the rule's excluded processes list. If the process is not in the allowlist, an alert fires.

## Adding custom watch rules

See [Custom Rules](./custom-rules.md) for the YAML format to write your own watch rules.
