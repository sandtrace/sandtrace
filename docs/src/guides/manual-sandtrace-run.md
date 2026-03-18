# Manual `sandtrace run` Workflow

When the shared GitHub workflow runs on hosted runners it only executes `audit` and `sbom`. The `run` command requires a privileged host that allows `ptrace`/namespace creation. Follow these steps once, then reuse them as needed.

## 1. Provision a privileged host

- Use a VM, dedicated container, or self-hosted GitHub runner that you control.
- Ensure the kernel allows `CAP_SYS_PTRACE` and the command below exits without errors:

```bash
docker run --rm --privileged --cap-add=SYS_PTRACE ubuntu:24.04 sh -c 'software-properties-common >/dev/null'
```

- On that host install `sandtrace` (v0.3.0) or copy `/usr/local/bin/sandtrace` from this repo.

## 2. Run a command through the sandbox

```bash
sandtrace run --allow-exec --timeout 60 --trace-only=false -- echo hi
```

- `--allow-exec` lets the traced process spawn children.
- `--timeout` avoids hanging forever.
- `--trace-only` should stay `false` so enforcement runs, matching your CI needs.

If the run succeeds, `sandtrace` prints JSONL to stdout. Save it (e.g. `run.jsonl`).

## 3. Upload to Sandtrace Cloud

```bash
curl -X POST https://ingest.sandtrace.cloud/v1/ingest/runs \
  -H "Authorization: Bearer st_sandtrace_cdf0c509739d482dae44bcc4670b414c" \
  -H "Content-Type: application/json" \
  -d @run.jsonl
```

- Use the org-scoped API key created via the ingest admin API.
- If the request succeeds, the response contains `run_id`; the “cloud” dashboard shows the new run under the corresponding project.

## 4. Document the process

Add a short note to your repo’s README or internal wiki describing:

1. Which host/runners can execute `sandtrace run`.
2. The command above plus any extra flags (e.g., `--allow-net`).
3. That audit+sbom stay on GitHub-hosted runners while runs go to the privileged host.

When a new teammate needs `sandtrace run`, point them at this guide.
