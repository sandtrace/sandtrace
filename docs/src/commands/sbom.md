# sandtrace sbom

Generate a CycloneDX SBOM for a project or monorepo by discovering common package manifests and lockfiles.

## Usage

```bash
sandtrace sbom ./my-project
sandtrace sbom ./my-project --output bom.json
sandtrace sbom ./workspace --no-pretty
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `TARGET` | *(required)* | Directory to inspect |
| `--format cyclonedx-json` | `cyclonedx-json` | Output format |
| `-o, --output FILE` | stdout | Write JSON to a file |
| `--no-pretty` | `false` | Emit compact JSON |

## What It Detects

Current SBOM generation supports:

- `npm-shrinkwrap.json`, `package-lock.json`, `package-lock.yaml`, and `package.json` for npm projects
- `pnpm-lock.yaml` for pnpm projects
- `yarn.lock` for Yarn projects
- `Cargo.lock` and `Cargo.toml` for Rust projects
- `requirements.txt`, `poetry.lock`, `uv.lock`, `pylock.toml`, `pyproject.toml`, `Pipfile.lock`, and `Pipfile` for Python projects
- `conda-lock.yml`, `conda-lock.yaml`, `explicit.txt`, `explicit-*.txt`, `*-explicit.txt`, `environment.yml`, and `environment.yaml` for Conda environments
- `composer.lock` and `composer.json` for Composer projects
- `Gemfile.lock`, `Gemfile`, and `.gemspec` for Ruby projects
- `go.sum` and `go.mod` for Go projects
- `mix.lock` and `mix.exs` for Elixir projects
- `bun.lock` for Bun projects, with `bun.lockb` falling back to `package.json`
- `deno.json`, `deno.jsonc`, and `deno.lock` for Deno projects, including `npm:`, `jsr:`, and remote URL imports
- `pom.xml`, `gradle.lockfile`, and Gradle build files for Java projects
- `packages.lock.json` and `.csproj` for .NET projects
- `Package.resolved` and `Package.swift` for Swift projects

When a text lockfile is present, `sandtrace sbom` prefers resolved package versions. When only a manifest is available, it emits the dependency with a `sandtrace:version_spec` property when the version is a range or other unresolved specifier.

## Output

The command emits CycloneDX 1.5 JSON with:

- metadata about the scanned application
- discovered library components
- a root dependency list for direct dependencies when they can be inferred

Example:

```bash
sandtrace sbom . --output bom.json
jq '.bomFormat, .metadata.component.name, (.components | length)' bom.json
```

## Notes

- Hidden and generated directories such as `node_modules`, `target`, `vendor`, `.git`, and common cache folders are skipped during discovery.
- The current implementation focuses on inventory generation, not vulnerability matching. Use `sandtrace audit` and `sandtrace run` for behavioral and static detection.
