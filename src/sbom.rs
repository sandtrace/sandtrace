use crate::cli::{SbomArgs, SbomFormat};
use crate::cloud;
use anyhow::{Context, Result};
use chrono::Utc;
use ignore::WalkBuilder;
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub fn run_sbom(args: SbomArgs) -> Result<()> {
    args.validate()?;

    let target = args.target.canonicalize().unwrap_or(args.target.clone());
    let built = build_sbom(&target)?;
    let output = match args.format {
        SbomFormat::CyclonedxJson if args.no_pretty => serde_json::to_string(&built.bom)?,
        SbomFormat::CyclonedxJson => serde_json::to_string_pretty(&built.bom)?,
    };

    if let Some(path) = &args.output {
        std::fs::write(path, &output)
            .with_context(|| format!("failed to write SBOM output to {}", path.display()))?;
    } else {
        println!("{output}");
    }

    if let Some(cloud_config) = cloud::CloudConfig::from_env() {
        let bom_json = serde_json::to_value(&built.bom)?;
        if let Err(error) = cloud::upload_sbom(
            &cloud_config,
            &args,
            &target,
            &bom_json,
            &built.manifest_sources,
        ) {
            eprintln!("Warning: failed to upload SBOM to Sandtrace Cloud: {error}");
        }
    }

    Ok(())
}

struct BuiltSbom {
    bom: Bom,
    manifest_sources: Vec<String>,
}

impl Deref for BuiltSbom {
    type Target = Bom;

    fn deref(&self) -> &Self::Target {
        &self.bom
    }
}

fn build_sbom(target: &Path) -> Result<BuiltSbom> {
    let discovered = discover_manifests(target)?;
    let root_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("project")
        .to_string();

    let mut builder = SbomBuilder::new(root_name);
    for group in discovered.values() {
        if let Some(lock_path) = &group.npm_shrinkwrap_json {
            ingest_npm_lock(lock_path, group.package_json.as_deref(), &mut builder)?;
        } else if let Some(lock_path) = &group.package_lock_json {
            ingest_npm_lock(lock_path, group.package_json.as_deref(), &mut builder)?;
        } else if let Some(lock_path) = &group.package_lock_yaml {
            ingest_npm_lock_yaml(lock_path, group.package_json.as_deref(), &mut builder)?;
        } else if let Some(lock_path) = &group.pnpm_lock_yaml {
            ingest_pnpm_lock(lock_path, group.package_json.as_deref(), &mut builder)?;
        } else if let Some(lock_path) = &group.yarn_lock {
            ingest_yarn_lock(lock_path, group.package_json.as_deref(), &mut builder)?;
        } else if let Some(lock_path) = &group.bun_lock {
            ingest_bun_lock(lock_path, group.package_json.as_deref(), &mut builder)?;
        } else if group.bun_lockb.is_some() || package_manager_is_bun(group.package_json.as_deref())
        {
            if let Some(package_json) = &group.package_json {
                ingest_package_json_manifest(package_json, &mut builder)?;
            }
        } else if let Some(package_json) = &group.package_json {
            ingest_package_json_manifest(package_json, &mut builder)?;
        }

        if let Some(composer_lock) = &group.composer_lock {
            ingest_composer_lock(composer_lock, group.composer_json.as_deref(), &mut builder)?;
        } else if let Some(composer_json) = &group.composer_json {
            ingest_composer_manifest(composer_json, &mut builder)?;
        }

        if let Some(gemfile_lock) = &group.gemfile_lock {
            ingest_gemfile_lock(
                gemfile_lock,
                group.gemfile.as_deref(),
                &group.gemspecs,
                &mut builder,
            )?;
        } else if let Some(gemfile) = &group.gemfile {
            ingest_gemfile(gemfile, &mut builder)?;
        } else {
            for gemspec in &group.gemspecs {
                ingest_gemspec(gemspec, &mut builder)?;
            }
        }

        if let Some(poetry_lock) = &group.poetry_lock {
            ingest_poetry_lock(poetry_lock, group.pyproject_toml.as_deref(), &mut builder)?;
        } else if let Some(uv_lock) = &group.uv_lock {
            ingest_uv_lock(uv_lock, group.pyproject_toml.as_deref(), &mut builder)?;
        } else if let Some(pipfile_lock) = &group.pipfile_lock {
            ingest_pipfile_lock(pipfile_lock, group.pipfile.as_deref(), &mut builder)?;
        } else if let Some(pylock_toml) = &group.pylock_toml {
            ingest_pylock_toml(pylock_toml, group.pyproject_toml.as_deref(), &mut builder)?;
        } else if let Some(conda_explicit) = &group.conda_explicit {
            ingest_conda_explicit(
                conda_explicit,
                group.conda_environment.as_deref(),
                &mut builder,
            )?;
        } else if let Some(conda_lock) = &group.conda_lock {
            ingest_conda_lock(conda_lock, group.conda_environment.as_deref(), &mut builder)?;
        } else if let Some(pyproject_toml) = &group.pyproject_toml {
            ingest_pyproject_toml(pyproject_toml, &mut builder)?;
        } else if let Some(pipfile) = &group.pipfile {
            ingest_pipfile(pipfile, &mut builder)?;
        } else if let Some(conda_environment) = &group.conda_environment {
            ingest_conda_environment(conda_environment, &mut builder)?;
        }

        if let Some(go_sum) = &group.go_sum {
            ingest_go_sum(go_sum, group.go_mod.as_deref(), &mut builder)?;
        } else if let Some(go_mod) = &group.go_mod {
            ingest_go_mod(go_mod, &mut builder)?;
        }

        if let Some(mix_lock) = &group.mix_lock {
            ingest_mix_lock(mix_lock, group.mix_exs.as_deref(), &mut builder)?;
        } else if let Some(mix_exs) = &group.mix_exs {
            ingest_mix_exs(mix_exs, &mut builder)?;
        }

        if let Some(packages_lock_json) = &group.packages_lock_json {
            ingest_packages_lock_json(
                packages_lock_json,
                group.csproj.first().map(PathBuf::as_path),
                &mut builder,
            )?;
        } else {
            for csproj in &group.csproj {
                ingest_csproj(csproj, &mut builder)?;
            }
        }

        if let Some(pom_xml) = &group.pom_xml {
            ingest_pom_xml(pom_xml, &mut builder)?;
        }
        if !group.gradle_lockfiles.is_empty() {
            ingest_gradle_lockfiles(
                &group.gradle_lockfiles,
                group
                    .gradle_build
                    .as_deref()
                    .or(group.gradle_build_kts.as_deref()),
                &mut builder,
            )?;
        } else if let Some(build_gradle) = &group.gradle_build {
            ingest_gradle_manifest(build_gradle, &mut builder)?;
        } else if let Some(build_gradle_kts) = &group.gradle_build_kts {
            ingest_gradle_manifest(build_gradle_kts, &mut builder)?;
        }

        if let Some(package_resolved) = &group.package_resolved {
            ingest_package_resolved(
                package_resolved,
                group.package_swift.as_deref(),
                &mut builder,
            )?;
        } else if let Some(package_swift) = &group.package_swift {
            ingest_package_swift(package_swift, &mut builder)?;
        }

        if let Some(cargo_lock) = &group.cargo_lock {
            ingest_cargo_lock(cargo_lock, group.cargo_toml.as_deref(), &mut builder)?;
        } else if let Some(cargo_toml) = &group.cargo_toml {
            ingest_cargo_toml_manifest(cargo_toml, &mut builder)?;
        }

        for requirements in &group.requirements {
            ingest_requirements(requirements, &mut builder)?;
        }

        if let Some(deno_json) = &group.deno_json {
            ingest_deno_manifest(deno_json, group.deno_lock.as_deref(), &mut builder)?;
        } else if let Some(deno_jsonc) = &group.deno_jsonc {
            ingest_deno_manifest(deno_jsonc, group.deno_lock.as_deref(), &mut builder)?;
        }
    }

    Ok(BuiltSbom {
        bom: builder.finish(),
        manifest_sources: collect_manifest_sources(&discovered),
    })
}

#[derive(Default)]
struct ManifestGroup {
    package_json: Option<PathBuf>,
    npm_shrinkwrap_json: Option<PathBuf>,
    package_lock_json: Option<PathBuf>,
    package_lock_yaml: Option<PathBuf>,
    pnpm_lock_yaml: Option<PathBuf>,
    yarn_lock: Option<PathBuf>,
    composer_json: Option<PathBuf>,
    composer_lock: Option<PathBuf>,
    gemfile: Option<PathBuf>,
    gemfile_lock: Option<PathBuf>,
    gemspecs: Vec<PathBuf>,
    pyproject_toml: Option<PathBuf>,
    poetry_lock: Option<PathBuf>,
    uv_lock: Option<PathBuf>,
    pylock_toml: Option<PathBuf>,
    conda_environment: Option<PathBuf>,
    conda_explicit: Option<PathBuf>,
    conda_lock: Option<PathBuf>,
    pipfile: Option<PathBuf>,
    pipfile_lock: Option<PathBuf>,
    bun_lock: Option<PathBuf>,
    bun_lockb: Option<PathBuf>,
    go_mod: Option<PathBuf>,
    go_sum: Option<PathBuf>,
    mix_exs: Option<PathBuf>,
    mix_lock: Option<PathBuf>,
    csproj: Vec<PathBuf>,
    packages_lock_json: Option<PathBuf>,
    pom_xml: Option<PathBuf>,
    gradle_build: Option<PathBuf>,
    gradle_build_kts: Option<PathBuf>,
    gradle_lockfiles: Vec<PathBuf>,
    package_swift: Option<PathBuf>,
    package_resolved: Option<PathBuf>,
    cargo_toml: Option<PathBuf>,
    cargo_lock: Option<PathBuf>,
    requirements: Vec<PathBuf>,
    deno_json: Option<PathBuf>,
    deno_jsonc: Option<PathBuf>,
    deno_lock: Option<PathBuf>,
}

fn discover_manifests(target: &Path) -> Result<BTreeMap<PathBuf, ManifestGroup>> {
    let mut builder = WalkBuilder::new(target);
    builder
        .hidden(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .max_depth(Some(12))
        .filter_entry(|entry| {
            let name = entry.file_name().to_string_lossy();
            if name.starts_with('.') && entry.file_type().is_some_and(|ft| ft.is_dir()) {
                return false;
            }
            !matches!(
                name.as_ref(),
                "node_modules"
                    | "target"
                    | "vendor"
                    | ".git"
                    | "__pycache__"
                    | "dist"
                    | "build"
                    | ".pnpm"
                    | ".venv"
                    | "venv"
                    | ".tox"
                    | "coverage"
                    | ".cache"
                    | "logs"
                    | "storage"
            )
        });

    let mut groups = BTreeMap::<PathBuf, ManifestGroup>::new();
    for entry in builder.build() {
        let Ok(entry) = entry else {
            continue;
        };
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }

        let file_name = entry.file_name().to_string_lossy();
        let Some(parent) = entry.path().parent() else {
            continue;
        };
        let group = groups.entry(parent.to_path_buf()).or_default();
        match file_name.as_ref() {
            "package.json" => group.package_json = Some(entry.path().to_path_buf()),
            "npm-shrinkwrap.json" => group.npm_shrinkwrap_json = Some(entry.path().to_path_buf()),
            "package-lock.json" => group.package_lock_json = Some(entry.path().to_path_buf()),
            "package-lock.yaml" => group.package_lock_yaml = Some(entry.path().to_path_buf()),
            "pnpm-lock.yaml" => group.pnpm_lock_yaml = Some(entry.path().to_path_buf()),
            "yarn.lock" => group.yarn_lock = Some(entry.path().to_path_buf()),
            "composer.json" => group.composer_json = Some(entry.path().to_path_buf()),
            "composer.lock" => group.composer_lock = Some(entry.path().to_path_buf()),
            "Gemfile" => group.gemfile = Some(entry.path().to_path_buf()),
            "Gemfile.lock" => group.gemfile_lock = Some(entry.path().to_path_buf()),
            "pyproject.toml" => group.pyproject_toml = Some(entry.path().to_path_buf()),
            "poetry.lock" => group.poetry_lock = Some(entry.path().to_path_buf()),
            "uv.lock" => group.uv_lock = Some(entry.path().to_path_buf()),
            "pylock.toml" => group.pylock_toml = Some(entry.path().to_path_buf()),
            "environment.yml" | "environment.yaml" => {
                group.conda_environment = Some(entry.path().to_path_buf())
            }
            "conda-lock.yml" | "conda-lock.yaml" => {
                group.conda_lock = Some(entry.path().to_path_buf())
            }
            "explicit.txt" => group.conda_explicit = Some(entry.path().to_path_buf()),
            "Pipfile" => group.pipfile = Some(entry.path().to_path_buf()),
            "Pipfile.lock" => group.pipfile_lock = Some(entry.path().to_path_buf()),
            "bun.lock" => group.bun_lock = Some(entry.path().to_path_buf()),
            "bun.lockb" => group.bun_lockb = Some(entry.path().to_path_buf()),
            "go.mod" => group.go_mod = Some(entry.path().to_path_buf()),
            "go.sum" => group.go_sum = Some(entry.path().to_path_buf()),
            "mix.exs" => group.mix_exs = Some(entry.path().to_path_buf()),
            "mix.lock" => group.mix_lock = Some(entry.path().to_path_buf()),
            "packages.lock.json" => group.packages_lock_json = Some(entry.path().to_path_buf()),
            "pom.xml" => group.pom_xml = Some(entry.path().to_path_buf()),
            "build.gradle" => group.gradle_build = Some(entry.path().to_path_buf()),
            "build.gradle.kts" => group.gradle_build_kts = Some(entry.path().to_path_buf()),
            "gradle.lockfile" | "buildscript-gradle.lockfile" => {
                group.gradle_lockfiles.push(entry.path().to_path_buf())
            }
            "Package.swift" => group.package_swift = Some(entry.path().to_path_buf()),
            "Package.resolved" => group.package_resolved = Some(entry.path().to_path_buf()),
            "Cargo.toml" => group.cargo_toml = Some(entry.path().to_path_buf()),
            "Cargo.lock" => group.cargo_lock = Some(entry.path().to_path_buf()),
            "requirements.txt" => group.requirements.push(entry.path().to_path_buf()),
            "deno.json" => group.deno_json = Some(entry.path().to_path_buf()),
            "deno.jsonc" => group.deno_jsonc = Some(entry.path().to_path_buf()),
            "deno.lock" => group.deno_lock = Some(entry.path().to_path_buf()),
            _ => {
                if file_name.ends_with(".gemspec") {
                    group.gemspecs.push(entry.path().to_path_buf());
                } else if file_name.ends_with(".csproj") {
                    group.csproj.push(entry.path().to_path_buf());
                } else if file_name.ends_with(".txt")
                    && (file_name.starts_with("explicit-") || file_name.ends_with("-explicit.txt"))
                {
                    group.conda_explicit = Some(entry.path().to_path_buf());
                }
            }
        }
    }

    Ok(groups)
}

fn collect_manifest_sources(discovered: &BTreeMap<PathBuf, ManifestGroup>) -> Vec<String> {
    let mut sources = BTreeSet::new();
    for group in discovered.values() {
        for source in [
            group.package_json.as_deref(),
            group.npm_shrinkwrap_json.as_deref(),
            group.package_lock_json.as_deref(),
            group.package_lock_yaml.as_deref(),
            group.pnpm_lock_yaml.as_deref(),
            group.yarn_lock.as_deref(),
            group.composer_json.as_deref(),
            group.composer_lock.as_deref(),
            group.gemfile.as_deref(),
            group.gemfile_lock.as_deref(),
            group.pyproject_toml.as_deref(),
            group.poetry_lock.as_deref(),
            group.uv_lock.as_deref(),
            group.pylock_toml.as_deref(),
            group.conda_environment.as_deref(),
            group.conda_explicit.as_deref(),
            group.conda_lock.as_deref(),
            group.pipfile.as_deref(),
            group.pipfile_lock.as_deref(),
            group.bun_lock.as_deref(),
            group.bun_lockb.as_deref(),
            group.go_mod.as_deref(),
            group.go_sum.as_deref(),
            group.mix_exs.as_deref(),
            group.mix_lock.as_deref(),
            group.packages_lock_json.as_deref(),
            group.pom_xml.as_deref(),
            group.gradle_build.as_deref(),
            group.gradle_build_kts.as_deref(),
            group.package_swift.as_deref(),
            group.package_resolved.as_deref(),
            group.cargo_toml.as_deref(),
            group.cargo_lock.as_deref(),
            group.deno_json.as_deref(),
            group.deno_jsonc.as_deref(),
            group.deno_lock.as_deref(),
        ] {
            if let Some(source) = source
                .and_then(|path| path.file_name())
                .and_then(|name| name.to_str())
            {
                sources.insert(source.to_string());
            }
        }
        for path in &group.gemspecs {
            if let Some(source) = path.file_name().and_then(|name| name.to_str()) {
                sources.insert(source.to_string());
            }
        }
        for path in &group.csproj {
            if let Some(source) = path.file_name().and_then(|name| name.to_str()) {
                sources.insert(source.to_string());
            }
        }
        for path in &group.gradle_lockfiles {
            if let Some(source) = path.file_name().and_then(|name| name.to_str()) {
                sources.insert(source.to_string());
            }
        }
        for path in &group.requirements {
            if let Some(source) = path.file_name().and_then(|name| name.to_str()) {
                sources.insert(source.to_string());
            }
        }
    }

    sources.into_iter().collect()
}

fn ingest_npm_lock(
    lock_path: &Path,
    package_json: Option<&Path>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    let lock = parse_json_file(lock_path)?;
    ingest_npm_lock_value(lock, package_json, builder)
}

fn ingest_npm_lock_yaml(
    lock_path: &Path,
    package_json: Option<&Path>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    let lock = parse_yaml_as_json(lock_path)?;
    ingest_npm_lock_value(lock, package_json, builder)
}

fn ingest_npm_lock_value(
    lock: Value,
    package_json: Option<&Path>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    if let Some(manifest) = package_json {
        maybe_set_project_from_package_json(manifest, builder)?;
    } else if let Some(root_pkg) = lock.pointer("/packages/").and_then(Value::as_object) {
        let name = root_pkg.get("name").and_then(Value::as_str);
        let version = root_pkg.get("version").and_then(Value::as_str);
        builder.set_project_if_missing(name, version);
    }

    let mut refs_by_name: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let mut refs_by_path: HashMap<String, String> = HashMap::new();
    if let Some(packages) = lock.get("packages").and_then(Value::as_object) {
        for (package_path, package) in packages {
            if package_path.is_empty() {
                continue;
            }
            let Some(version) = package.get("version").and_then(Value::as_str) else {
                continue;
            };
            let name = package
                .get("name")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .or_else(|| infer_npm_name_from_path(package_path))
                .unwrap_or_else(|| package_path.to_string());
            let purl = npm_purl(&name, Some(version));
            builder.add_component(ComponentBuilder::new(
                purl.clone(),
                name.clone(),
                Some(version.to_string()),
            ));
            refs_by_path.insert(package_path.clone(), purl.clone());
            refs_by_name
                .entry(name)
                .or_default()
                .push((purl, package_path.clone()));
        }

        let direct_deps = lock
            .pointer("/packages//dependencies")
            .and_then(Value::as_object)
            .map(|deps| deps.keys().cloned().collect::<Vec<_>>())
            .or_else(|| {
                package_json.and_then(|manifest| {
                    direct_dependency_names_from_package_json(manifest)
                        .ok()
                        .filter(|deps| !deps.is_empty())
                })
            })
            .unwrap_or_default();

        for dep_name in direct_deps {
            if let Some(dep_ref) = pick_best_npm_ref(&refs_by_name, &dep_name) {
                builder.add_root_dependency(dep_ref);
            }
        }

        add_npm_package_lock_edges(packages, &refs_by_path, &refs_by_name, builder);

        return Ok(());
    }

    if let Some(dependencies) = lock.get("dependencies").and_then(Value::as_object) {
        let mut direct_refs = Vec::new();
        ingest_legacy_npm_dependencies(dependencies, &mut direct_refs, builder)?;
        for dep_ref in direct_refs {
            builder.add_root_dependency(dep_ref);
        }
    }

    Ok(())
}

fn ingest_pnpm_lock(
    lock_path: &Path,
    package_json: Option<&Path>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    let lock = parse_yaml_as_json(lock_path)?;
    if let Some(manifest) = package_json {
        maybe_set_project_from_package_json(manifest, builder)?;
    }

    let mut refs_by_name: HashMap<String, Vec<String>> = HashMap::new();
    let mut refs_by_name_version: HashMap<(String, String), String> = HashMap::new();
    if let Some(packages) = lock.get("packages").and_then(Value::as_object) {
        for key in packages.keys() {
            let Some((name, version)) = parse_pnpm_package_key(key) else {
                continue;
            };
            let purl = npm_purl(&name, Some(&version));
            builder.add_component(ComponentBuilder::new(
                purl.clone(),
                name.clone(),
                Some(version),
            ));
            refs_by_name_version.insert(
                (name.clone(), purl_version(&purl).unwrap_or_default()),
                purl.clone(),
            );
            refs_by_name.entry(name).or_default().push(purl);
        }
    }

    if refs_by_name.is_empty() {
        if let Some(snapshots) = lock.get("snapshots").and_then(Value::as_object) {
            for key in snapshots.keys() {
                let Some((name, version)) = parse_pnpm_package_key(key) else {
                    continue;
                };
                let purl = npm_purl(&name, Some(&version));
                builder.add_component(ComponentBuilder::new(
                    purl.clone(),
                    name.clone(),
                    Some(version),
                ));
                refs_by_name_version.insert(
                    (name.clone(), purl_version(&purl).unwrap_or_default()),
                    purl.clone(),
                );
                refs_by_name.entry(name).or_default().push(purl);
            }
        }
    }

    if let Some(packages) = lock.get("packages").and_then(Value::as_object) {
        add_pnpm_dependency_edges(packages, &refs_by_name, &refs_by_name_version, builder);
    } else if let Some(snapshots) = lock.get("snapshots").and_then(Value::as_object) {
        add_pnpm_dependency_edges(snapshots, &refs_by_name, &refs_by_name_version, builder);
    }

    if let Some(importers) = lock.get("importers").and_then(Value::as_object) {
        if let Some(root_importer) = importers.get(".").and_then(Value::as_object) {
            for section in ["dependencies", "optionalDependencies", "devDependencies"] {
                if let Some(deps) = root_importer.get(section).and_then(Value::as_object) {
                    for (name, value) in deps {
                        let resolved = pnpm_importer_version(value);
                        let purl = npm_purl(name, resolved.as_deref());
                        if !refs_by_name.contains_key(name) {
                            builder.add_component(ComponentBuilder::new(
                                purl.clone(),
                                name.clone(),
                                resolved.clone(),
                            ));
                        }
                        builder.add_root_dependency(
                            refs_by_name
                                .get(name)
                                .and_then(|refs| refs.first())
                                .cloned()
                                .unwrap_or(purl),
                        );
                    }
                }
            }
        }
    } else if let Some(package_json) = package_json {
        for dep_name in direct_dependency_names_from_package_json(package_json)? {
            if let Some(dep_ref) = refs_by_name
                .get(&dep_name)
                .and_then(|refs| refs.first())
                .cloned()
            {
                builder.add_root_dependency(dep_ref);
            }
        }
    }

    Ok(())
}

fn ingest_yarn_lock(
    lock_path: &Path,
    package_json: Option<&Path>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    let content = std::fs::read_to_string(lock_path)
        .with_context(|| format!("failed to read {}", lock_path.display()))?;
    if let Some(manifest) = package_json {
        maybe_set_project_from_package_json(manifest, builder)?;
    }

    let mut refs_by_name: HashMap<String, String> = HashMap::new();
    for (selectors, fields) in parse_yarn_lock_blocks(&content) {
        let Some(version) = fields.get("version").cloned() else {
            continue;
        };
        for selector in selectors {
            let Some(name) = parse_yarn_selector_name(&selector) else {
                continue;
            };
            let purl = npm_purl(&name, Some(&version));
            builder.add_component(ComponentBuilder::new(
                purl.clone(),
                name.clone(),
                Some(version.clone()),
            ));
            refs_by_name.entry(name).or_insert(purl);
        }
    }

    if let Some(package_json) = package_json {
        for dep_name in direct_dependency_names_from_package_json(package_json)? {
            if let Some(dep_ref) = refs_by_name.get(&dep_name).cloned() {
                builder.add_root_dependency(dep_ref);
            }
        }
    }

    Ok(())
}

fn ingest_bun_lock(
    lock_path: &Path,
    package_json: Option<&Path>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    let lock = parse_jsonc_file(lock_path)?;
    if let Some(manifest) = package_json {
        maybe_set_project_from_package_json(manifest, builder)?;
    } else {
        maybe_set_project_from_bun_workspace(&lock, builder);
    }

    let mut refs_by_name: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(packages) = lock.get("packages").and_then(Value::as_object) {
        for (key, value) in packages {
            let Some((name, version)) = parse_bun_package_entry(key, value) else {
                continue;
            };
            let purl = npm_purl(&name, Some(&version));
            builder.add_component(ComponentBuilder::new(
                purl.clone(),
                name.clone(),
                Some(version),
            ));
            refs_by_name.entry(name).or_default().push(purl);
        }
    }

    if let Some(root_workspace) = root_bun_workspace(&lock) {
        for section in ["dependencies", "optionalDependencies", "devDependencies"] {
            if let Some(deps) = root_workspace.get(section).and_then(Value::as_object) {
                for (name, value) in deps {
                    let resolved = bun_workspace_version(value);
                    let purl = npm_purl(name, resolved.as_deref());
                    if !refs_by_name.contains_key(name) {
                        builder.add_component(ComponentBuilder::new(
                            purl.clone(),
                            name.clone(),
                            resolved.clone(),
                        ));
                    }
                    builder.add_root_dependency(
                        refs_by_name
                            .get(name)
                            .and_then(|refs| refs.first())
                            .cloned()
                            .unwrap_or(purl),
                    );
                }
            }
        }
    } else if let Some(package_json) = package_json {
        for dep_name in direct_dependency_names_from_package_json(package_json)? {
            if let Some(dep_ref) = refs_by_name
                .get(&dep_name)
                .and_then(|refs| refs.first())
                .cloned()
            {
                builder.add_root_dependency(dep_ref);
            }
        }
    }

    Ok(())
}

fn ingest_composer_lock(
    lock_path: &Path,
    composer_json: Option<&Path>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    let lock = parse_json_file(lock_path)?;
    if let Some(manifest) = composer_json {
        maybe_set_project_from_composer_json(manifest, builder)?;
    }

    let mut refs_by_name: HashMap<String, String> = HashMap::new();
    for section in ["packages", "packages-dev"] {
        if let Some(packages) = lock.get(section).and_then(Value::as_array) {
            for package in packages {
                let Some(name) = package.get("name").and_then(Value::as_str) else {
                    continue;
                };
                if !is_composer_package_name(name) {
                    continue;
                }
                let version = package
                    .get("version")
                    .and_then(Value::as_str)
                    .map(normalize_composer_version)
                    .filter(|value| !value.is_empty());
                let purl = composer_purl(name, version.as_deref());
                builder.add_component(ComponentBuilder::new(
                    purl.clone(),
                    name.to_string(),
                    version.clone(),
                ));
                refs_by_name.entry(name.to_string()).or_insert(purl);
            }
        }
    }

    for section in ["packages", "packages-dev"] {
        if let Some(packages) = lock.get(section).and_then(Value::as_array) {
            for package in packages {
                let Some(name) = package.get("name").and_then(Value::as_str) else {
                    continue;
                };
                if !is_composer_package_name(name) {
                    continue;
                }
                let Some(parent_ref) = refs_by_name.get(name).cloned() else {
                    continue;
                };

                for dependency_section in ["require", "require-dev"] {
                    let Some(dependencies) =
                        package.get(dependency_section).and_then(Value::as_object)
                    else {
                        continue;
                    };

                    for dep_name in dependencies.keys() {
                        if !is_composer_package_name(dep_name) {
                            continue;
                        }
                        if let Some(child_ref) = refs_by_name.get(dep_name).cloned() {
                            builder.add_dependency(parent_ref.clone(), child_ref);
                        }
                    }
                }
            }
        }
    }

    if let Some(composer_json) = composer_json {
        for dep_name in direct_dependency_names_from_composer_json(composer_json)? {
            if let Some(dep_ref) = refs_by_name.get(&dep_name).cloned() {
                builder.add_root_dependency(dep_ref);
            }
        }
    }

    Ok(())
}

fn ingest_composer_manifest(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    let composer_json = parse_json_file(path)?;
    builder.set_project_if_missing(
        composer_json.get("name").and_then(Value::as_str),
        composer_json.get("version").and_then(Value::as_str),
    );
    for section in ["require", "require-dev"] {
        if let Some(deps) = composer_json.get(section).and_then(Value::as_object) {
            for (name, spec) in deps {
                if !is_composer_package_name(name) {
                    continue;
                }
                let spec = spec.as_str().unwrap_or_default();
                let (version, properties) = spec_to_version_and_properties(spec);
                let purl = composer_purl(name, version.as_deref());
                builder.add_component(
                    ComponentBuilder::new(purl.clone(), name.clone(), version)
                        .with_properties(properties),
                );
                builder.add_root_dependency(purl);
            }
        }
    }
    Ok(())
}

fn ingest_deno_manifest(
    manifest_path: &Path,
    deno_lock: Option<&Path>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    let manifest = parse_jsonc_file(manifest_path)?;
    builder.set_project_if_missing(
        manifest.get("name").and_then(Value::as_str),
        manifest.get("version").and_then(Value::as_str),
    );

    let lock_info = deno_lock
        .map(parse_deno_lock)
        .transpose()?
        .unwrap_or_default();
    for package in lock_info.packages {
        let purl = match package.ecosystem.as_str() {
            "npm" => npm_purl(&package.name, Some(&package.version)),
            "jsr" => jsr_purl(&package.name, Some(&package.version)),
            _ => continue,
        };
        builder.add_component(ComponentBuilder::new(
            purl,
            package.name,
            Some(package.version),
        ));
    }

    for spec in deno_import_specs(&manifest) {
        if let Some(package) = parse_deno_package_spec(&spec) {
            let version = lock_info
                .resolved_specifiers
                .get(&spec)
                .cloned()
                .or(package.version);
            let purl = match package.ecosystem.as_str() {
                "npm" => npm_purl(&package.name, version.as_deref()),
                "jsr" => jsr_purl(&package.name, version.as_deref()),
                _ => continue,
            };
            let mut properties = Vec::new();
            if version.is_none() {
                properties.push(Property::new("sandtrace:version_spec", package.specifier));
            }
            builder.add_component(
                ComponentBuilder::new(purl.clone(), package.name, version)
                    .with_properties(properties),
            );
            builder.add_root_dependency(purl);
            continue;
        }

        if let Some(remote) = parse_deno_remote_import(&spec) {
            let bom_ref = remote.url.clone();
            builder.add_component(
                ComponentBuilder::new(bom_ref.clone(), remote.name, None).with_properties(vec![
                    Property::new("sandtrace:source", "url"),
                    Property::new("sandtrace:url", remote.url),
                ]),
            );
            builder.add_root_dependency(bom_ref);
        }
    }

    Ok(())
}

fn ingest_legacy_npm_dependencies(
    dependencies: &serde_json::Map<String, Value>,
    direct_refs: &mut Vec<String>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    for (name, value) in dependencies {
        direct_refs.push(ingest_legacy_npm_dependency(name, value, builder)?);
    }
    Ok(())
}

fn ingest_legacy_npm_dependency(
    name: &str,
    value: &Value,
    builder: &mut SbomBuilder,
) -> Result<String> {
    let version = value.get("version").and_then(Value::as_str);
    let purl = npm_purl(name, version);
    builder.add_component(ComponentBuilder::new(
        purl.clone(),
        name.to_string(),
        version.map(ToOwned::to_owned),
    ));

    if let Some(children) = value.get("dependencies").and_then(Value::as_object) {
        for child_ref in ingest_nested_npm_dependencies(children, builder)? {
            builder.add_dependency(purl.clone(), child_ref);
        }
    }

    Ok(purl)
}

fn ingest_nested_npm_dependencies(
    dependencies: &serde_json::Map<String, Value>,
    builder: &mut SbomBuilder,
) -> Result<Vec<String>> {
    let mut refs = Vec::new();
    for (name, value) in dependencies {
        refs.push(ingest_legacy_npm_dependency(name, value, builder)?);
    }
    Ok(refs)
}

fn ingest_package_json_manifest(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    let package_json: Value = serde_json::from_str(
        &std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?,
    )
    .with_context(|| format!("failed to parse {}", path.display()))?;

    builder.set_project_if_missing(
        package_json.get("name").and_then(Value::as_str),
        package_json.get("version").and_then(Value::as_str),
    );

    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(deps) = package_json.get(section).and_then(Value::as_object) {
            for (name, spec) in deps {
                let spec = spec.as_str().unwrap_or_default();
                let (version, properties) = spec_to_version_and_properties(spec);
                let purl = npm_purl(name, version.as_deref());
                builder.add_component(
                    ComponentBuilder::new(purl.clone(), name.clone(), version)
                        .with_properties(properties),
                );
                builder.add_root_dependency(purl);
            }
        }
    }

    Ok(())
}

fn maybe_set_project_from_package_json(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    let package_json: Value = serde_json::from_str(
        &std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?,
    )
    .with_context(|| format!("failed to parse {}", path.display()))?;

    builder.set_project_if_missing(
        package_json.get("name").and_then(Value::as_str),
        package_json.get("version").and_then(Value::as_str),
    );
    Ok(())
}

fn direct_dependency_names_from_package_json(path: &Path) -> Result<Vec<String>> {
    let package_json: Value = serde_json::from_str(
        &std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?,
    )
    .with_context(|| format!("failed to parse {}", path.display()))?;

    let mut names = Vec::new();
    for section in ["dependencies", "optionalDependencies"] {
        if let Some(deps) = package_json.get(section).and_then(Value::as_object) {
            names.extend(deps.keys().cloned());
        }
    }
    Ok(names)
}

fn maybe_set_project_from_composer_json(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    let composer_json = parse_json_file(path)?;
    builder.set_project_if_missing(
        composer_json.get("name").and_then(Value::as_str),
        composer_json.get("version").and_then(Value::as_str),
    );
    Ok(())
}

fn direct_dependency_names_from_composer_json(path: &Path) -> Result<Vec<String>> {
    let composer_json = parse_json_file(path)?;
    let mut names = Vec::new();
    for section in ["require", "require-dev"] {
        if let Some(deps) = composer_json.get(section).and_then(Value::as_object) {
            names.extend(
                deps.keys()
                    .filter(|name| is_composer_package_name(name))
                    .cloned(),
            );
        }
    }
    Ok(names)
}

fn maybe_set_project_from_bun_workspace(lock: &Value, builder: &mut SbomBuilder) {
    let Some(root_workspace) = root_bun_workspace(lock) else {
        return;
    };
    builder.set_project_if_missing(
        root_workspace.get("name").and_then(Value::as_str),
        root_workspace.get("version").and_then(Value::as_str),
    );
}

fn root_bun_workspace(lock: &Value) -> Option<&serde_json::Map<String, Value>> {
    lock.get("workspaces")
        .and_then(Value::as_object)
        .and_then(|workspaces| workspaces.get(""))
        .and_then(Value::as_object)
}

fn package_manager_is_bun(package_json: Option<&Path>) -> bool {
    package_json
        .and_then(|path| parse_json_file(path).ok())
        .and_then(|json| {
            json.get("packageManager")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .is_some_and(|package_manager| package_manager.starts_with("bun@"))
}

fn parse_bun_package_entry(key: &str, value: &Value) -> Option<(String, String)> {
    if let Some(array) = value.as_array() {
        if let Some(identifier) = array.first().and_then(Value::as_str) {
            return parse_bun_package_identifier(identifier).or_else(|| {
                parse_bun_package_identifier(key).map(|(_, version)| (key.to_string(), version))
            });
        }
    }

    if let Some(object) = value.as_object() {
        if let (Some(name), Some(version)) = (
            object.get("name").and_then(Value::as_str),
            object.get("version").and_then(Value::as_str),
        ) {
            return Some((name.to_string(), version.to_string()));
        }
    }

    parse_bun_package_identifier(key)
}

fn parse_bun_package_identifier(identifier: &str) -> Option<(String, String)> {
    let identifier = identifier.strip_prefix("npm:").unwrap_or(identifier);
    let identifier = identifier.split_whitespace().next().unwrap_or(identifier);
    let (name, version) = parse_scoped_name_and_version(identifier)?;
    if version.is_empty() {
        return None;
    }
    Some((name, version.to_string()))
}

fn bun_workspace_version(value: &Value) -> Option<String> {
    match value {
        Value::String(version) => {
            let version = version.trim();
            if is_manifest_only_version(version) || !is_resolved_version(version) {
                None
            } else {
                Some(version.to_string())
            }
        }
        Value::Object(map) => map
            .get("version")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|version| !is_manifest_only_version(version) && is_resolved_version(version))
            .map(ToOwned::to_owned),
        _ => None,
    }
}

fn parse_json_file(path: &Path) -> Result<Value> {
    serde_json::from_str(
        &std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?,
    )
    .with_context(|| format!("failed to parse {}", path.display()))
}

fn parse_jsonc_file(path: &Path) -> Result<Value> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    json5::from_str(&content).with_context(|| format!("failed to parse {}", path.display()))
}

fn parse_toml_file(path: &Path) -> Result<toml::Value> {
    toml::from_str(
        &std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?,
    )
    .with_context(|| format!("failed to parse {}", path.display()))
}

fn parse_yaml_as_json(path: &Path) -> Result<Value> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let yaml: serde_yml::Value = serde_yml::from_str(&content)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    serde_json::to_value(yaml).with_context(|| format!("failed to normalize {}", path.display()))
}

fn parse_pnpm_package_key(key: &str) -> Option<(String, String)> {
    let key = key.trim_start_matches('/');
    let key = key.strip_prefix("npm:").unwrap_or(key);
    let (name, version) = key.rsplit_once('@')?;
    let version = strip_peer_suffix(version);
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

fn pnpm_importer_version(value: &Value) -> Option<String> {
    match value {
        Value::String(version) => {
            let version = strip_peer_suffix(version);
            if is_manifest_only_version(version) {
                None
            } else {
                Some(version.to_string())
            }
        }
        Value::Object(map) => map
            .get("version")
            .and_then(Value::as_str)
            .map(strip_peer_suffix)
            .filter(|version| !is_manifest_only_version(version))
            .map(ToOwned::to_owned),
        _ => None,
    }
}

fn strip_peer_suffix(version: &str) -> &str {
    version.split(['(', '_']).next().unwrap_or(version).trim()
}

fn purl_version(purl: &str) -> Option<String> {
    let version = purl.rsplit_once('@')?.1;
    Some(version.to_string())
}

fn add_pnpm_dependency_edges(
    packages: &serde_json::Map<String, Value>,
    refs_by_name: &HashMap<String, Vec<String>>,
    refs_by_name_version: &HashMap<(String, String), String>,
    builder: &mut SbomBuilder,
) {
    for (key, package) in packages {
        let Some((name, version)) = parse_pnpm_package_key(key) else {
            continue;
        };
        let Some(parent_ref) = refs_by_name_version
            .get(&(name.clone(), version.clone()))
            .cloned()
        else {
            continue;
        };

        for section in ["dependencies", "optionalDependencies"] {
            let Some(dependencies) = package.get(section).and_then(Value::as_object) else {
                continue;
            };

            for (dep_name, dep_value) in dependencies {
                if let Some(child_ref) = resolve_pnpm_dependency_ref(
                    dep_name,
                    dep_value,
                    refs_by_name,
                    refs_by_name_version,
                ) {
                    builder.add_dependency(parent_ref.clone(), child_ref);
                }
            }
        }
    }
}

fn resolve_pnpm_dependency_ref(
    dep_name: &str,
    dep_value: &Value,
    refs_by_name: &HashMap<String, Vec<String>>,
    refs_by_name_version: &HashMap<(String, String), String>,
) -> Option<String> {
    let exact_version = match dep_value {
        Value::String(version) => Some(strip_peer_suffix(version).to_string()),
        Value::Object(map) => map
            .get("version")
            .and_then(Value::as_str)
            .map(strip_peer_suffix)
            .map(ToOwned::to_owned),
        _ => None,
    };

    exact_version
        .as_ref()
        .and_then(|version| {
            refs_by_name_version
                .get(&(dep_name.to_string(), version.clone()))
                .cloned()
        })
        .or_else(|| {
            refs_by_name
                .get(dep_name)
                .and_then(|refs| refs.first())
                .cloned()
        })
}

fn is_manifest_only_version(version: &str) -> bool {
    version.is_empty()
        || version.starts_with("link:")
        || version.starts_with("file:")
        || version.starts_with("workspace:")
}

fn parse_yarn_lock_blocks(input: &str) -> Vec<(Vec<String>, HashMap<String, String>)> {
    let mut blocks = Vec::new();
    let mut selectors: Option<Vec<String>> = None;
    let mut fields = HashMap::new();

    for line in input.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if !line.starts_with(' ') && !line.starts_with('\t') && line.ends_with(':') {
            if let Some(existing_selectors) = selectors.take() {
                blocks.push((existing_selectors, fields));
                fields = HashMap::new();
            }
            selectors = Some(
                line.trim_end_matches(':')
                    .split(',')
                    .map(|selector| {
                        selector
                            .trim()
                            .trim_matches('"')
                            .trim_matches('\'')
                            .to_string()
                    })
                    .collect(),
            );
            continue;
        }

        if selectors.is_none() {
            continue;
        }

        let trimmed = line.trim_start();
        if line.len() - trimmed.len() > 2 {
            continue;
        }

        if let Some((key, rest)) = trimmed.split_once(' ') {
            fields.insert(
                key.to_string(),
                rest.trim().trim_matches('"').trim_matches('\'').to_string(),
            );
        }
    }

    if let Some(existing_selectors) = selectors {
        blocks.push((existing_selectors, fields));
    }

    blocks
}

fn parse_yarn_selector_name(selector: &str) -> Option<String> {
    let selector = selector.trim().trim_matches('"').trim_matches('\'');
    let selector = selector.strip_prefix("npm:").unwrap_or(selector);
    if selector.starts_with('@') {
        let slash = selector.find('/')?;
        let tail = &selector[slash + 1..];
        let at = tail.find('@')? + slash + 1;
        Some(selector[..at].to_string())
    } else {
        let at = selector.find('@')?;
        Some(selector[..at].to_string())
    }
}

fn is_composer_package_name(name: &str) -> bool {
    name.contains('/')
        && !name.starts_with("ext-")
        && !name.starts_with("lib-")
        && !name.starts_with("php")
        && !name.starts_with("composer-")
}

fn normalize_composer_version(version: &str) -> String {
    version.trim_start_matches('v').to_string()
}

struct DenoPackageSpec {
    ecosystem: String,
    name: String,
    version: Option<String>,
    specifier: String,
}

struct DenoRemoteImport {
    name: String,
    url: String,
}

#[derive(Default)]
struct DenoLockInfo {
    resolved_specifiers: HashMap<String, String>,
    packages: Vec<DenoResolvedPackage>,
}

struct DenoResolvedPackage {
    ecosystem: String,
    name: String,
    version: String,
}

fn deno_import_specs(manifest: &Value) -> Vec<String> {
    let mut specs = Vec::new();
    if let Some(imports) = manifest.get("imports").and_then(Value::as_object) {
        for value in imports.values() {
            if let Some(spec) = value.as_str() {
                specs.push(spec.to_string());
            }
        }
    }
    if let Some(scopes) = manifest.get("scopes").and_then(Value::as_object) {
        for scope in scopes.values() {
            if let Some(imports) = scope.as_object() {
                for value in imports.values() {
                    if let Some(spec) = value.as_str() {
                        specs.push(spec.to_string());
                    }
                }
            }
        }
    }
    specs
}

fn parse_deno_package_spec(spec: &str) -> Option<DenoPackageSpec> {
    if let Some(rest) = spec.strip_prefix("npm:") {
        let (name, version) = parse_scoped_name_and_version(rest)?;
        return Some(DenoPackageSpec {
            ecosystem: "npm".to_string(),
            name,
            version: exact_version(version).map(ToOwned::to_owned),
            specifier: version.to_string(),
        });
    }
    if let Some(rest) = spec.strip_prefix("jsr:") {
        let (name, version) = parse_scoped_name_and_version(rest)?;
        return Some(DenoPackageSpec {
            ecosystem: "jsr".to_string(),
            name,
            version: exact_version(version).map(ToOwned::to_owned),
            specifier: version.to_string(),
        });
    }
    None
}

fn parse_deno_remote_import(spec: &str) -> Option<DenoRemoteImport> {
    if !(spec.starts_with("https://") || spec.starts_with("http://")) {
        return None;
    }

    let path = spec.split('?').next().unwrap_or(spec);
    let name = path
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
        .unwrap_or("remote-import");

    Some(DenoRemoteImport {
        name: name.to_string(),
        url: spec.to_string(),
    })
}

fn parse_scoped_name_and_version(input: &str) -> Option<(String, &str)> {
    if input.starts_with('@') {
        let slash = input.find('/')?;
        let tail = &input[slash + 1..];
        let at = tail.rfind('@')? + slash + 1;
        Some((input[..at].to_string(), &input[at + 1..]))
    } else {
        let (name, version) = input.rsplit_once('@')?;
        Some((name.to_string(), version))
    }
}

fn exact_version(specifier: &str) -> Option<&str> {
    if is_resolved_version(specifier) {
        Some(specifier)
    } else {
        None
    }
}

fn parse_deno_lock(path: &Path) -> Result<DenoLockInfo> {
    let lock = parse_json_file(path)?;
    let mut resolved = HashMap::new();
    if let Some(specifiers) = lock
        .pointer("/packages/specifiers")
        .and_then(Value::as_object)
    {
        for (specifier, value) in specifiers {
            if let Some(resolved_version) = value.as_str() {
                resolved.insert(
                    specifier.to_string(),
                    strip_peer_suffix(resolved_version).to_string(),
                );
            }
        }
    }
    if let Some(specifiers) = lock.get("specifiers").and_then(Value::as_object) {
        for (specifier, value) in specifiers {
            if let Some(resolved_version) = value.as_str() {
                resolved.insert(
                    specifier.to_string(),
                    strip_peer_suffix(resolved_version).to_string(),
                );
            }
        }
    }
    let mut packages = Vec::new();
    collect_deno_lock_packages(lock.pointer("/packages/npm"), "npm", &mut packages);
    collect_deno_lock_packages(lock.pointer("/packages/jsr"), "jsr", &mut packages);
    collect_deno_lock_packages(lock.get("npm"), "npm", &mut packages);
    collect_deno_lock_packages(lock.get("jsr"), "jsr", &mut packages);

    Ok(DenoLockInfo {
        resolved_specifiers: resolved,
        packages,
    })
}

fn collect_deno_lock_packages(
    node: Option<&Value>,
    ecosystem: &str,
    packages: &mut Vec<DenoResolvedPackage>,
) {
    let Some(entries) = node.and_then(Value::as_object) else {
        return;
    };

    for key in entries.keys() {
        let Some((name, version)) = parse_scoped_name_and_version(key) else {
            continue;
        };
        if version.is_empty() {
            continue;
        }
        packages.push(DenoResolvedPackage {
            ecosystem: ecosystem.to_string(),
            name,
            version: version.to_string(),
        });
    }
}

fn ingest_go_sum(go_sum: &Path, go_mod: Option<&Path>, builder: &mut SbomBuilder) -> Result<()> {
    let content = std::fs::read_to_string(go_sum)
        .with_context(|| format!("failed to read {}", go_sum.display()))?;
    let go_mod_info = go_mod.map(parse_go_mod).transpose()?;
    if let Some(info) = &go_mod_info {
        builder.set_project_if_missing(info.module_path.as_deref(), None);
    }

    let mut refs_by_name: HashMap<String, Vec<String>> = HashMap::new();
    for line in content.lines() {
        let Some((module, version)) = parse_go_sum_line(line) else {
            continue;
        };
        let purl = golang_purl(&module, Some(&version));
        builder.add_component(ComponentBuilder::new(
            purl.clone(),
            module.clone(),
            Some(version),
        ));
        refs_by_name.entry(module).or_default().push(purl);
    }

    if let Some(info) = go_mod_info {
        for dependency in info.direct_dependencies {
            if let Some(dep_ref) = refs_by_name
                .get(&dependency.module)
                .and_then(|refs| refs.first())
                .cloned()
            {
                builder.add_root_dependency(dep_ref);
            } else {
                let purl = golang_purl(&dependency.module, dependency.version.as_deref());
                builder.add_component(
                    ComponentBuilder::new(
                        purl.clone(),
                        dependency.module,
                        dependency.version.clone(),
                    )
                    .with_properties(dependency.properties),
                );
                builder.add_root_dependency(purl);
            }
        }
    }

    Ok(())
}

fn ingest_go_mod(go_mod: &Path, builder: &mut SbomBuilder) -> Result<()> {
    let info = parse_go_mod(go_mod)?;
    builder.set_project_if_missing(info.module_path.as_deref(), None);
    for dependency in info.direct_dependencies {
        let purl = golang_purl(&dependency.module, dependency.version.as_deref());
        builder.add_component(
            ComponentBuilder::new(purl.clone(), dependency.module, dependency.version)
                .with_properties(dependency.properties),
        );
        builder.add_root_dependency(purl);
    }
    Ok(())
}

struct GoModInfo {
    module_path: Option<String>,
    direct_dependencies: Vec<GoDependency>,
}

struct GoDependency {
    module: String,
    version: Option<String>,
    properties: Vec<Property>,
}

fn parse_go_mod(path: &Path) -> Result<GoModInfo> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let mut module_path = None;
    let mut direct_dependencies = Vec::new();
    let mut in_require_block = false;

    for raw_line in content.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("module ") {
            let rest = rest.split("//").next().unwrap_or("").trim();
            module_path = Some(rest.to_string());
            continue;
        }

        if trimmed == "require (" {
            in_require_block = true;
            continue;
        }
        if in_require_block && trimmed == ")" {
            in_require_block = false;
            continue;
        }

        let requirement = if in_require_block {
            parse_go_mod_requirement(trimmed)
        } else if let Some(rest) = trimmed.strip_prefix("require ") {
            parse_go_mod_requirement(rest.trim())
        } else {
            None
        };

        if let Some(dependency) = requirement {
            direct_dependencies.push(dependency);
        }
    }

    Ok(GoModInfo {
        module_path,
        direct_dependencies,
    })
}

fn parse_go_mod_requirement(line: &str) -> Option<GoDependency> {
    let is_indirect = line.contains("// indirect");
    let line = line.split("//").next().unwrap_or("").trim();
    let mut parts = line.split_whitespace();
    let module = parts.next()?.trim();
    let version = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if module.is_empty() || is_indirect {
        return None;
    }

    let mut properties = Vec::new();
    let version = version.and_then(|value| {
        let (resolved, props) = spec_to_version_and_properties(value);
        properties.extend(props);
        resolved
    });

    Some(GoDependency {
        module: module.to_string(),
        version,
        properties,
    })
}

fn parse_go_sum_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    let mut parts = line.split_whitespace();
    let module = parts.next()?;
    let version = parts.next()?;
    if version.ends_with("/go.mod") {
        return None;
    }

    Some((module.to_string(), version.to_string()))
}

fn ingest_mix_lock(
    lock_path: &Path,
    mix_exs: Option<&Path>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    if let Some(mix_exs) = mix_exs {
        maybe_set_project_from_mix_exs(mix_exs, builder)?;
    }
    let content = std::fs::read_to_string(lock_path)
        .with_context(|| format!("failed to read {}", lock_path.display()))?;
    let lock_regex =
        Regex::new(r#""([^"]+)"\s*(?::|=>)\s*\{:[^,]+,\s*:?[a-zA-Z0-9_]+\s*,\s*"([^"]+)""#)
            .context("invalid mix.lock regex")?;
    let mut refs_by_name = HashMap::new();
    for captures in lock_regex.captures_iter(&content) {
        let Some(name) = captures.get(1).map(|value| value.as_str().to_string()) else {
            continue;
        };
        let Some(version) = captures.get(2).map(|value| value.as_str().to_string()) else {
            continue;
        };
        let purl = hex_purl(&name, Some(&version));
        builder.add_component(ComponentBuilder::new(
            purl.clone(),
            name.clone(),
            Some(version),
        ));
        refs_by_name.entry(name).or_insert(purl);
    }

    if let Some(mix_exs) = mix_exs {
        for dependency in parse_mix_exs_dependencies(mix_exs)? {
            if let Some(dep_ref) = refs_by_name.get(&dependency.name).cloned() {
                builder.add_root_dependency(dep_ref);
            } else {
                let purl = hex_purl(&dependency.name, dependency.version.as_deref());
                builder.add_component(
                    ComponentBuilder::new(purl.clone(), dependency.name, dependency.version)
                        .with_properties(dependency.properties),
                );
                builder.add_root_dependency(purl);
            }
        }
    }

    Ok(())
}

fn ingest_mix_exs(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    maybe_set_project_from_mix_exs(path, builder)?;
    for dependency in parse_mix_exs_dependencies(path)? {
        let purl = hex_purl(&dependency.name, dependency.version.as_deref());
        builder.add_component(
            ComponentBuilder::new(purl.clone(), dependency.name, dependency.version)
                .with_properties(dependency.properties),
        );
        builder.add_root_dependency(purl);
    }
    Ok(())
}

struct ElixirDependency {
    name: String,
    version: Option<String>,
    properties: Vec<Property>,
}

fn maybe_set_project_from_mix_exs(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let app_regex = Regex::new(r#"app:\s*:([a-zA-Z0-9_]+)"#).context("invalid mix app regex")?;
    let version_regex =
        Regex::new(r#"version:\s*"([^"]+)""#).context("invalid mix version regex")?;
    let name = app_regex
        .captures(&content)
        .and_then(|captures| captures.get(1).map(|value| value.as_str()));
    let version = version_regex
        .captures(&content)
        .and_then(|captures| captures.get(1).map(|value| value.as_str()));
    builder.set_project_if_missing(name, version);
    Ok(())
}

fn parse_mix_exs_dependencies(path: &Path) -> Result<Vec<ElixirDependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let dep_regex = Regex::new(r#"\{\s*:([a-zA-Z0-9_]+)\s*,\s*"([^"]+)""#)
        .context("invalid mix dependency regex")?;
    let mut dependencies = Vec::new();
    for captures in dep_regex.captures_iter(&content) {
        let Some(name) = captures.get(1).map(|value| value.as_str().to_string()) else {
            continue;
        };
        let spec = captures.get(2).map(|value| value.as_str()).unwrap_or("");
        let (version, properties) = spec_to_version_and_properties(spec);
        dependencies.push(ElixirDependency {
            name,
            version,
            properties,
        });
    }
    Ok(dependencies)
}

fn ingest_packages_lock_json(
    lock_path: &Path,
    csproj: Option<&Path>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    let lock = parse_json_file(lock_path)?;
    let csproj_info = csproj.map(parse_csproj).transpose()?;
    if let Some(info) = &csproj_info {
        builder.set_project_if_missing(
            info.project_name.as_deref(),
            info.project_version.as_deref(),
        );
    }

    let mut refs_by_name = HashMap::new();
    if let Some(frameworks) = lock.get("dependencies").and_then(Value::as_object) {
        for packages in frameworks.values().filter_map(Value::as_object) {
            for (name, value) in packages {
                let version = value
                    .get("resolved")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .or_else(|| {
                        value
                            .get("requested")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                    });
                let purl = nuget_purl(name, version.as_deref());
                let mut properties = Vec::new();
                if let Some(kind) = value.get("type").and_then(Value::as_str) {
                    properties.push(Property::new("sandtrace:type", kind));
                }
                builder.add_component(
                    ComponentBuilder::new(purl.clone(), name.clone(), version.clone())
                        .with_properties(properties.clone()),
                );
                refs_by_name.entry(name.clone()).or_insert(purl.clone());
                if value
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| {
                        kind.eq_ignore_ascii_case("Direct")
                            || kind.eq_ignore_ascii_case("DirectDevelopment")
                    })
                {
                    builder.add_root_dependency(purl);
                }
            }
        }
    }

    if let Some(info) = csproj_info {
        for dependency in info.dependencies {
            if let Some(dep_ref) = refs_by_name.get(&dependency.name).cloned() {
                builder.add_root_dependency(dep_ref);
            } else {
                let purl = nuget_purl(&dependency.name, dependency.version.as_deref());
                builder.add_component(
                    ComponentBuilder::new(purl.clone(), dependency.name, dependency.version)
                        .with_properties(dependency.properties),
                );
                builder.add_root_dependency(purl);
            }
        }
    }

    Ok(())
}

fn ingest_csproj(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    let info = parse_csproj(path)?;
    builder.set_project_if_missing(
        info.project_name.as_deref(),
        info.project_version.as_deref(),
    );
    for dependency in info.dependencies {
        let purl = nuget_purl(&dependency.name, dependency.version.as_deref());
        builder.add_component(
            ComponentBuilder::new(purl.clone(), dependency.name, dependency.version)
                .with_properties(dependency.properties),
        );
        builder.add_root_dependency(purl);
    }
    Ok(())
}

fn ingest_gemfile_lock(
    lock_path: &Path,
    gemfile: Option<&Path>,
    gemspecs: &[PathBuf],
    builder: &mut SbomBuilder,
) -> Result<()> {
    let content = std::fs::read_to_string(lock_path)
        .with_context(|| format!("failed to read {}", lock_path.display()))?;
    if let Some(gemfile) = gemfile {
        maybe_set_project_from_gemfile(gemfile, builder)?;
    } else if let Some(gemspec) = gemspecs.first() {
        maybe_set_project_from_gemspec(gemspec, builder)?;
    }

    let mut refs_by_name = HashMap::new();
    let mut section = "";
    for line in content.lines() {
        if line == "GEM" || line == "PATH" || line == "GIT" || line == "PLATFORMS" {
            section = "";
            continue;
        }
        if line == "DEPENDENCIES" {
            section = "dependencies";
            continue;
        }
        if line.trim() == "specs:" {
            section = "specs";
            continue;
        }

        if section == "specs" && line.starts_with("    ") && !line.starts_with("      ") {
            if let Some((name, version)) = parse_gem_lock_spec_line(line.trim()) {
                let purl = gem_purl(&name, Some(&version));
                builder.add_component(ComponentBuilder::new(
                    purl.clone(),
                    name.clone(),
                    Some(version),
                ));
                refs_by_name.entry(name).or_insert(purl);
            }
        }
    }

    section = "";
    for line in content.lines() {
        if line == "DEPENDENCIES" {
            section = "dependencies";
            continue;
        }
        if section == "dependencies" {
            if line.trim().is_empty() || !line.starts_with("  ") {
                continue;
            }
            let Some(name) = parse_gem_dependency_name(line.trim()) else {
                continue;
            };
            if let Some(dep_ref) = refs_by_name.get(&name).cloned() {
                builder.add_root_dependency(dep_ref);
            } else {
                let purl = gem_purl(&name, None);
                builder.add_component(ComponentBuilder::new(purl.clone(), name, None));
                builder.add_root_dependency(purl);
            }
        }
    }

    Ok(())
}

fn ingest_gemfile(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    maybe_set_project_from_gemfile(path, builder)?;
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let regex = Regex::new(r#"^\s*gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?"#)
        .context("invalid Gemfile dependency regex")?;
    for captures in regex.captures_iter(&content) {
        let Some(name) = captures.get(1).map(|value| value.as_str()) else {
            continue;
        };
        let spec = captures.get(2).map(|value| value.as_str()).unwrap_or("");
        let (version, properties) = spec_to_version_and_properties(spec);
        let purl = gem_purl(name, version.as_deref());
        builder.add_component(
            ComponentBuilder::new(purl.clone(), name.to_string(), version)
                .with_properties(properties),
        );
        builder.add_root_dependency(purl);
    }
    Ok(())
}

fn ingest_gemspec(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    let info = parse_gemspec(path)?;
    builder.set_project_if_missing(
        info.project_name.as_deref(),
        info.project_version.as_deref(),
    );
    for dependency in info.dependencies {
        let purl = gem_purl(&dependency.name, dependency.version.as_deref());
        builder.add_component(
            ComponentBuilder::new(purl.clone(), dependency.name, dependency.version)
                .with_properties(dependency.properties),
        );
        builder.add_root_dependency(purl);
    }
    Ok(())
}

struct GemspecInfo {
    project_name: Option<String>,
    project_version: Option<String>,
    dependencies: Vec<RubyDependency>,
}

struct RubyDependency {
    name: String,
    version: Option<String>,
    properties: Vec<Property>,
}

fn maybe_set_project_from_gemfile(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let source_regex = Regex::new(r#"gemspec(?:\s+name:\s*["']([^"']+)["'])?"#)
        .context("invalid gemspec regex")?;
    if let Some(captures) = source_regex.captures(&content) {
        if let Some(name) = captures.get(1).map(|value| value.as_str()) {
            builder.set_project_if_missing(Some(name), None);
        }
    }
    Ok(())
}

fn maybe_set_project_from_gemspec(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    let info = parse_gemspec(path)?;
    builder.set_project_if_missing(
        info.project_name.as_deref(),
        info.project_version.as_deref(),
    );
    Ok(())
}

fn parse_gemspec(path: &Path) -> Result<GemspecInfo> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let name_regex =
        Regex::new(r#"(?m)\.name\s*=\s*["']([^"']+)["']"#).context("invalid gemspec name regex")?;
    let version_regex = Regex::new(r#"(?m)\.version\s*=\s*["']([^"']+)["']"#)
        .context("invalid gemspec version regex")?;
    let dep_regex = Regex::new(
        r#"(?m)\.(?:add_dependency|add_runtime_dependency|add_development_dependency)\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?"#,
    )
    .context("invalid gemspec dependency regex")?;

    let mut dependencies = Vec::new();
    for captures in dep_regex.captures_iter(&content) {
        let Some(name) = captures.get(1).map(|value| value.as_str().to_string()) else {
            continue;
        };
        let spec = captures.get(2).map(|value| value.as_str()).unwrap_or("");
        let (version, properties) = spec_to_version_and_properties(spec);
        dependencies.push(RubyDependency {
            name,
            version,
            properties,
        });
    }

    Ok(GemspecInfo {
        project_name: name_regex
            .captures(&content)
            .and_then(|captures| captures.get(1).map(|value| value.as_str().to_string())),
        project_version: version_regex
            .captures(&content)
            .and_then(|captures| captures.get(1).map(|value| value.as_str().to_string())),
        dependencies,
    })
}

fn parse_gem_lock_spec_line(line: &str) -> Option<(String, String)> {
    let (name, rest) = line.split_once(" (")?;
    let version = rest.strip_suffix(')')?;
    Some((name.to_string(), version.to_string()))
}

fn parse_gem_dependency_name(line: &str) -> Option<String> {
    let name = line
        .split_whitespace()
        .next()?
        .trim_end_matches('!')
        .trim()
        .to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn ingest_poetry_lock(
    lock_path: &Path,
    pyproject_toml: Option<&Path>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    let content = std::fs::read_to_string(lock_path)
        .with_context(|| format!("failed to read {}", lock_path.display()))?;
    let lock: toml::Value = toml::from_str(&content)
        .with_context(|| format!("failed to parse {}", lock_path.display()))?;

    let pyproject = pyproject_toml.map(parse_pyproject_toml).transpose()?;
    if let Some(info) = &pyproject {
        builder.set_project_if_missing(
            info.project_name.as_deref(),
            info.project_version.as_deref(),
        );
    }

    let mut refs_by_name: HashMap<String, String> = HashMap::new();
    for package in lock
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(name) = package.get("name").and_then(toml::Value::as_str) else {
            continue;
        };
        let Some(version) = package.get("version").and_then(toml::Value::as_str) else {
            continue;
        };
        let normalized = normalize_python_package_token(name);
        let purl = pypi_purl(&normalized, Some(version));
        builder.add_component(ComponentBuilder::new(
            purl.clone(),
            normalized.clone(),
            Some(version.to_string()),
        ));
        refs_by_name.entry(normalized).or_insert(purl);
    }

    if let Some(info) = pyproject {
        for dependency in info.dependencies {
            if let Some(dep_ref) = refs_by_name.get(&dependency.name).cloned() {
                builder.add_root_dependency(dep_ref);
            } else {
                let purl = pypi_purl(&dependency.name, dependency.version.as_deref());
                builder.add_component(
                    ComponentBuilder::new(purl.clone(), dependency.name, dependency.version)
                        .with_properties(dependency.properties),
                );
                builder.add_root_dependency(purl);
            }
        }
    }

    Ok(())
}

fn ingest_uv_lock(
    lock_path: &Path,
    pyproject_toml: Option<&Path>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    let lock = parse_toml_file(lock_path)?;
    let pyproject = pyproject_toml.map(parse_pyproject_toml).transpose()?;

    if let Some(info) = &pyproject {
        builder.set_project_if_missing(
            info.project_name.as_deref(),
            info.project_version.as_deref(),
        );
    }

    let mut refs_by_name: HashMap<String, String> = HashMap::new();
    for package in lock
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(name) = package.get("name").and_then(toml::Value::as_str) else {
            continue;
        };
        let Some(version) = package.get("version").and_then(toml::Value::as_str) else {
            continue;
        };
        let normalized = normalize_python_package_token(name);
        let purl = pypi_purl(&normalized, Some(version));
        let mut properties = Vec::new();
        if let Some(source_kind) = package
            .get("source")
            .and_then(toml::Value::as_table)
            .and_then(|source| source.get("type"))
            .and_then(toml::Value::as_str)
        {
            properties.push(Property::new("sandtrace:source", source_kind));
        }
        builder.add_component(
            ComponentBuilder::new(purl.clone(), normalized.clone(), Some(version.to_string()))
                .with_properties(properties),
        );
        refs_by_name.entry(normalized).or_insert(purl);
    }

    if let Some(info) = pyproject {
        for dependency in info.dependencies {
            if let Some(dep_ref) = refs_by_name.get(&dependency.name).cloned() {
                builder.add_root_dependency(dep_ref);
            } else {
                let purl = pypi_purl(&dependency.name, dependency.version.as_deref());
                builder.add_component(
                    ComponentBuilder::new(purl.clone(), dependency.name, dependency.version)
                        .with_properties(dependency.properties),
                );
                builder.add_root_dependency(purl);
            }
        }
    }

    Ok(())
}

fn ingest_pyproject_toml(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    let info = parse_pyproject_toml(path)?;
    builder.set_project_if_missing(
        info.project_name.as_deref(),
        info.project_version.as_deref(),
    );
    for dependency in info.dependencies {
        let purl = pypi_purl(&dependency.name, dependency.version.as_deref());
        builder.add_component(
            ComponentBuilder::new(purl.clone(), dependency.name, dependency.version)
                .with_properties(dependency.properties),
        );
        builder.add_root_dependency(purl);
    }
    Ok(())
}

fn ingest_pipfile_lock(
    lock_path: &Path,
    pipfile: Option<&Path>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    let lock = parse_json_file(lock_path)?;
    let pipfile_info = pipfile.map(parse_pipfile).transpose()?;

    let mut refs_by_name: HashMap<String, String> = HashMap::new();
    for section in ["default", "develop"] {
        if let Some(packages) = lock.get(section).and_then(Value::as_object) {
            for (name, value) in packages {
                let normalized = normalize_python_package_token(name);
                let version = pipfile_lock_version(value);
                let purl = pypi_purl(&normalized, version.as_deref());
                let mut properties = Vec::new();
                if version.is_none() {
                    properties.push(Property::new("sandtrace:source", "pipfile-lock"));
                }
                builder.add_component(
                    ComponentBuilder::new(purl.clone(), normalized.clone(), version)
                        .with_properties(properties),
                );
                refs_by_name.entry(normalized).or_insert(purl);
            }
        }
    }

    if let Some(info) = pipfile_info {
        for dependency in info.dependencies {
            if let Some(dep_ref) = refs_by_name.get(&dependency.name).cloned() {
                builder.add_root_dependency(dep_ref);
            } else {
                let purl = pypi_purl(&dependency.name, dependency.version.as_deref());
                builder.add_component(
                    ComponentBuilder::new(purl.clone(), dependency.name, dependency.version)
                        .with_properties(dependency.properties),
                );
                builder.add_root_dependency(purl);
            }
        }
    }

    Ok(())
}

fn ingest_pylock_toml(
    lock_path: &Path,
    pyproject_toml: Option<&Path>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    let lock = parse_toml_file(lock_path)?;
    let pyproject = pyproject_toml.map(parse_pyproject_toml).transpose()?;

    if let Some(info) = &pyproject {
        builder.set_project_if_missing(
            info.project_name.as_deref(),
            info.project_version.as_deref(),
        );
    }

    let mut refs_by_name: HashMap<String, String> = HashMap::new();
    for package in lock
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            lock.get("packages")
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten(),
        )
    {
        let Some(name) = package.get("name").and_then(toml::Value::as_str) else {
            continue;
        };
        let Some(version) = package.get("version").and_then(toml::Value::as_str) else {
            continue;
        };
        let normalized = normalize_python_package_token(name);
        let purl = pypi_purl(&normalized, Some(version));
        builder.add_component(ComponentBuilder::new(
            purl.clone(),
            normalized.clone(),
            Some(version.to_string()),
        ));
        refs_by_name.entry(normalized).or_insert(purl);
    }

    if let Some(info) = pyproject {
        for dependency in info.dependencies {
            if let Some(dep_ref) = refs_by_name.get(&dependency.name).cloned() {
                builder.add_root_dependency(dep_ref);
            } else {
                let purl = pypi_purl(&dependency.name, dependency.version.as_deref());
                builder.add_component(
                    ComponentBuilder::new(purl.clone(), dependency.name, dependency.version)
                        .with_properties(dependency.properties),
                );
                builder.add_root_dependency(purl);
            }
        }
    }

    Ok(())
}

fn ingest_conda_lock(
    lock_path: &Path,
    environment_path: Option<&Path>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    let lock = parse_yaml_as_json(lock_path)?;
    let environment = environment_path.map(parse_conda_environment).transpose()?;

    if let Some(info) = &environment {
        builder.set_project_if_missing(info.project_name.as_deref(), None);
    }

    let mut refs_by_name: HashMap<String, String> = HashMap::new();
    for package in lock
        .get("package")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(name) = package.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(version) = package.get("version").and_then(Value::as_str) else {
            continue;
        };
        let manager = package
            .get("manager")
            .and_then(Value::as_str)
            .unwrap_or("conda");
        let normalized = normalize_python_package_token(name);
        let purl = if manager == "pip" {
            pypi_purl(&normalized, Some(version))
        } else {
            conda_purl(name, Some(version))
        };
        let mut properties = Vec::new();
        if let Some(platform) = package.get("platform").and_then(Value::as_str) {
            properties.push(Property::new("sandtrace:platform", platform));
        }
        if let Some(url) = package.get("url").and_then(Value::as_str) {
            properties.push(Property::new("sandtrace:url", url));
        }
        if let Some(category) = package.get("category").and_then(Value::as_str) {
            properties.push(Property::new("sandtrace:category", category));
        }
        if manager != "conda" {
            properties.push(Property::new("sandtrace:source", manager));
        }
        builder.add_component(
            ComponentBuilder::new(
                purl.clone(),
                if manager == "pip" {
                    normalized.clone()
                } else {
                    name.to_string()
                },
                Some(version.to_string()),
            )
            .with_properties(properties),
        );
        refs_by_name
            .entry(if manager == "pip" {
                normalized
            } else {
                name.to_string()
            })
            .or_insert(purl);
    }

    if let Some(info) = environment {
        for dependency in info.dependencies {
            if let Some(dep_ref) = refs_by_name.get(&dependency.name).cloned() {
                builder.add_root_dependency(dep_ref);
            } else {
                builder.add_component(
                    ComponentBuilder::new(
                        dependency.purl.clone(),
                        dependency.name,
                        dependency.version,
                    )
                    .with_properties(dependency.properties),
                );
                builder.add_root_dependency(dependency.purl);
            }
        }
    }

    Ok(())
}

fn ingest_conda_explicit(
    path: &Path,
    environment_path: Option<&Path>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    let packages = parse_conda_explicit(path)?;
    let environment = environment_path.map(parse_conda_environment).transpose()?;

    if let Some(info) = &environment {
        builder.set_project_if_missing(info.project_name.as_deref(), None);
    }

    let mut refs_by_name: HashMap<String, String> = HashMap::new();
    for package in packages {
        let purl = conda_purl(&package.name, Some(&package.version));
        let mut properties = package.properties;
        properties.push(Property::new("sandtrace:source", "conda-explicit"));
        builder.add_component(
            ComponentBuilder::new(purl.clone(), package.name.clone(), Some(package.version))
                .with_properties(properties),
        );
        refs_by_name.entry(package.name).or_insert(purl);
    }

    if let Some(info) = environment {
        for dependency in info.dependencies {
            if let Some(dep_ref) = refs_by_name.get(&dependency.name).cloned() {
                builder.add_root_dependency(dep_ref);
            } else {
                builder.add_component(
                    ComponentBuilder::new(
                        dependency.purl.clone(),
                        dependency.name,
                        dependency.version,
                    )
                    .with_properties(dependency.properties),
                );
                builder.add_root_dependency(dependency.purl);
            }
        }
    } else {
        for dep_ref in refs_by_name.into_values() {
            builder.add_root_dependency(dep_ref);
        }
    }

    Ok(())
}

fn ingest_conda_environment(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    let info = parse_conda_environment(path)?;
    builder.set_project_if_missing(info.project_name.as_deref(), None);
    for dependency in info.dependencies {
        builder.add_component(
            ComponentBuilder::new(dependency.purl.clone(), dependency.name, dependency.version)
                .with_properties(dependency.properties),
        );
        builder.add_root_dependency(dependency.purl);
    }
    Ok(())
}

fn ingest_pipfile(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    let info = parse_pipfile(path)?;
    for dependency in info.dependencies {
        let purl = pypi_purl(&dependency.name, dependency.version.as_deref());
        builder.add_component(
            ComponentBuilder::new(purl.clone(), dependency.name, dependency.version)
                .with_properties(dependency.properties),
        );
        builder.add_root_dependency(purl);
    }
    Ok(())
}

struct PythonManifestInfo {
    project_name: Option<String>,
    project_version: Option<String>,
    dependencies: Vec<PythonDependency>,
}

struct PythonDependency {
    name: String,
    version: Option<String>,
    properties: Vec<Property>,
}

fn parse_pyproject_toml(path: &Path) -> Result<PythonManifestInfo> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let pyproject: toml::Value =
        toml::from_str(&content).with_context(|| format!("failed to parse {}", path.display()))?;

    let project = pyproject.get("project").and_then(toml::Value::as_table);
    let poetry = pyproject
        .get("tool")
        .and_then(toml::Value::as_table)
        .and_then(|tool| tool.get("poetry"))
        .and_then(toml::Value::as_table);

    let mut info = PythonManifestInfo {
        project_name: project
            .and_then(|table| table.get("name"))
            .and_then(toml::Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| {
                poetry
                    .and_then(|table| table.get("name"))
                    .and_then(toml::Value::as_str)
                    .map(ToOwned::to_owned)
            }),
        project_version: project
            .and_then(|table| table.get("version"))
            .and_then(toml::Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| {
                poetry
                    .and_then(|table| table.get("version"))
                    .and_then(toml::Value::as_str)
                    .map(ToOwned::to_owned)
            }),
        dependencies: Vec::new(),
    };

    if let Some(project) = project {
        if let Some(deps) = project.get("dependencies").and_then(toml::Value::as_array) {
            for dep in deps {
                if let Some(dep) = dep.as_str().and_then(parse_python_dependency_string) {
                    info.dependencies.push(dep);
                }
            }
        }
        if let Some(optional) = project
            .get("optional-dependencies")
            .and_then(toml::Value::as_table)
        {
            for deps in optional.values() {
                if let Some(deps) = deps.as_array() {
                    for dep in deps {
                        if let Some(dep) = dep.as_str().and_then(parse_python_dependency_string) {
                            info.dependencies.push(dep);
                        }
                    }
                }
            }
        }
    }

    if let Some(poetry) = poetry {
        if let Some(deps) = poetry.get("dependencies").and_then(toml::Value::as_table) {
            collect_poetry_dependencies(deps, &mut info.dependencies);
        }
        if let Some(dev_deps) = poetry
            .get("dev-dependencies")
            .and_then(toml::Value::as_table)
        {
            collect_poetry_dependencies(dev_deps, &mut info.dependencies);
        }
        if let Some(group) = poetry.get("group").and_then(toml::Value::as_table) {
            for table in group.values() {
                if let Some(deps) = table
                    .as_table()
                    .and_then(|value| value.get("dependencies"))
                    .and_then(toml::Value::as_table)
                {
                    collect_poetry_dependencies(deps, &mut info.dependencies);
                }
            }
        }
    }

    Ok(info)
}

fn collect_poetry_dependencies(
    table: &toml::map::Map<String, toml::Value>,
    output: &mut Vec<PythonDependency>,
) {
    for (name, value) in table {
        if name == "python" {
            continue;
        }
        if let Some(dep) = parse_poetry_dependency(name, value) {
            output.push(dep);
        }
    }
}

fn parse_poetry_dependency(name: &str, value: &toml::Value) -> Option<PythonDependency> {
    let normalized = normalize_python_package_token(name);
    match value {
        toml::Value::String(spec) => {
            let (version, properties) = spec_to_version_and_properties(spec);
            Some(PythonDependency {
                name: normalized,
                version,
                properties,
            })
        }
        toml::Value::Table(table) => {
            let spec = table
                .get("version")
                .and_then(toml::Value::as_str)
                .unwrap_or("");
            let (version, mut properties) = spec_to_version_and_properties(spec);
            for key in ["path", "git", "url"] {
                if table.get(key).and_then(toml::Value::as_str).is_some() {
                    properties.push(Property::new("sandtrace:source", key));
                }
            }
            Some(PythonDependency {
                name: normalized,
                version,
                properties,
            })
        }
        _ => None,
    }
}

fn parse_pipfile(path: &Path) -> Result<PythonManifestInfo> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let pipfile: toml::Value =
        toml::from_str(&content).with_context(|| format!("failed to parse {}", path.display()))?;
    let mut info = PythonManifestInfo {
        project_name: None,
        project_version: None,
        dependencies: Vec::new(),
    };

    for section in ["packages", "dev-packages"] {
        if let Some(deps) = pipfile.get(section).and_then(toml::Value::as_table) {
            for (name, value) in deps {
                if let Some(dep) = parse_poetry_dependency(name, value) {
                    info.dependencies.push(dep);
                }
            }
        }
    }

    Ok(info)
}

fn parse_python_dependency_string(spec: &str) -> Option<PythonDependency> {
    let requirement = parse_requirement_line(spec)?;
    Some(PythonDependency {
        name: requirement.name,
        version: requirement.version,
        properties: requirement.properties,
    })
}

fn pipfile_lock_version(value: &Value) -> Option<String> {
    match value {
        Value::String(version) => version.strip_prefix("==").map(ToOwned::to_owned),
        Value::Object(map) => map
            .get("version")
            .and_then(Value::as_str)
            .and_then(|version| version.strip_prefix("==").map(ToOwned::to_owned)),
        _ => None,
    }
}

struct DotnetDependency {
    name: String,
    version: Option<String>,
    properties: Vec<Property>,
}

struct CondaDependency {
    name: String,
    version: Option<String>,
    properties: Vec<Property>,
    purl: String,
}

struct CondaEnvironmentInfo {
    project_name: Option<String>,
    dependencies: Vec<CondaDependency>,
}

struct CondaExplicitPackage {
    name: String,
    version: String,
    properties: Vec<Property>,
}

fn parse_conda_explicit(path: &Path) -> Result<Vec<CondaExplicitPackage>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let mut platform = None;
    let mut packages = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(value) = line.strip_prefix("# platform:") {
            platform = Some(value.trim().to_string());
            continue;
        }
        if line.starts_with('#') || line == "@EXPLICIT" {
            continue;
        }
        let Some(package) = parse_conda_explicit_url(line, platform.as_deref()) else {
            continue;
        };
        packages.push(package);
    }

    Ok(packages)
}

fn parse_conda_environment(path: &Path) -> Result<CondaEnvironmentInfo> {
    let environment = parse_yaml_as_json(path)?;
    let project_name = environment
        .get("name")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let mut dependencies = Vec::new();

    for dependency in environment
        .get("dependencies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        match dependency {
            Value::String(spec) => {
                if let Some(dep) = parse_conda_spec(spec, false) {
                    dependencies.push(dep);
                }
            }
            Value::Object(map) => {
                if let Some(pip_deps) = map.get("pip").and_then(Value::as_array) {
                    for spec in pip_deps.iter().filter_map(Value::as_str) {
                        if let Some(requirement) = parse_requirement_line(spec) {
                            let purl = pypi_purl(&requirement.name, requirement.version.as_deref());
                            dependencies.push(CondaDependency {
                                name: requirement.name,
                                version: requirement.version,
                                properties: requirement.properties,
                                purl,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok(CondaEnvironmentInfo {
        project_name,
        dependencies,
    })
}

fn parse_conda_spec(spec: &str, exact_only: bool) -> Option<CondaDependency> {
    let spec = spec.trim();
    if spec.is_empty() || spec.starts_with('#') {
        return None;
    }

    let (source_channel, body) = spec
        .split_once("::")
        .map(|(channel, rest)| (Some(channel.trim()), rest.trim()))
        .unwrap_or((None, spec));

    let name_end = body
        .find(|ch: char| ch.is_whitespace() || matches!(ch, '=' | '<' | '>' | '!' | '~'))
        .unwrap_or(body.len());
    let name = body[..name_end].trim();
    if name.is_empty() {
        return None;
    }

    let remainder = body[name_end..].trim();
    let (version, mut properties) = if exact_only {
        (
            (!remainder.is_empty()).then(|| remainder.trim_start_matches('=').trim().to_string()),
            Vec::new(),
        )
    } else {
        parse_conda_version_spec(remainder)
    };

    if let Some(channel) = source_channel.filter(|channel| !channel.is_empty()) {
        properties.push(Property::new("sandtrace:channel", channel));
    }

    let purl = conda_purl(name, version.as_deref());
    Some(CondaDependency {
        name: name.to_string(),
        version,
        properties,
        purl,
    })
}

fn parse_conda_explicit_url(line: &str, platform: Option<&str>) -> Option<CondaExplicitPackage> {
    let path_part = line.split('#').next().unwrap_or(line).trim();
    let file_name = path_part.rsplit('/').next()?;
    let base = file_name
        .strip_suffix(".tar.bz2")
        .or_else(|| file_name.strip_suffix(".conda"))
        .unwrap_or(file_name);
    let mut parts = base.rsplitn(3, '-');
    let build = parts.next()?;
    let version = parts.next()?;
    let name = parts.next()?;
    if name.is_empty() || version.is_empty() || build.is_empty() {
        return None;
    }

    let mut properties = vec![
        Property::new("sandtrace:url", line),
        Property::new("sandtrace:build", build),
    ];
    if let Some(platform) = platform {
        properties.push(Property::new("sandtrace:platform", platform));
    }

    Some(CondaExplicitPackage {
        name: name.to_string(),
        version: version.to_string(),
        properties,
    })
}

fn parse_conda_version_spec(spec: &str) -> (Option<String>, Vec<Property>) {
    let spec = spec.trim();
    if spec.is_empty() {
        return (None, Vec::new());
    }

    let exact_candidate = spec.trim_start_matches('=').trim();
    if !exact_candidate.is_empty()
        && !exact_candidate.contains([',', '*'])
        && !spec.starts_with(">=")
        && !spec.starts_with("<=")
        && !spec.starts_with(">")
        && !spec.starts_with("<")
        && !spec.starts_with("~")
        && !spec.starts_with("!")
    {
        return (Some(exact_candidate.to_string()), Vec::new());
    }

    (
        None,
        vec![Property::new("sandtrace:version_spec", spec.to_string())],
    )
}

struct CsprojInfo {
    project_name: Option<String>,
    project_version: Option<String>,
    dependencies: Vec<DotnetDependency>,
}

fn parse_csproj(path: &Path) -> Result<CsprojInfo> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let doc = roxmltree::Document::parse(&content)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let project = doc
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "Project")
        .context("missing <Project> root")?;

    let mut project_name = None;
    let mut project_version = None;
    for property_group in project
        .children()
        .filter(|node| node.is_element() && node.tag_name().name() == "PropertyGroup")
    {
        if project_name.is_none() {
            project_name = child_text(property_group, "AssemblyName")
                .or_else(|| child_text(property_group, "PackageId"))
                .or_else(|| child_text(property_group, "RootNamespace"));
        }
        if project_version.is_none() {
            project_version = child_text(property_group, "Version")
                .or_else(|| child_text(property_group, "PackageVersion"));
        }
    }
    if project_name.is_none() {
        project_name = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(ToOwned::to_owned);
    }

    let mut dependencies = Vec::new();
    for package_ref in project
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "PackageReference")
    {
        let Some(name) = package_ref
            .attribute("Include")
            .or_else(|| package_ref.attribute("Update"))
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        let version = package_ref
            .attribute("Version")
            .map(ToOwned::to_owned)
            .or_else(|| child_text(package_ref, "Version"));
        let mut properties = Vec::new();
        if let Some(private_assets) = child_text(package_ref, "PrivateAssets") {
            properties.push(Property::new("sandtrace:private_assets", private_assets));
        }
        dependencies.push(DotnetDependency {
            name,
            version,
            properties,
        });
    }

    Ok(CsprojInfo {
        project_name,
        project_version,
        dependencies,
    })
}

fn ingest_package_resolved(
    path: &Path,
    package_swift: Option<&Path>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    if let Some(package_swift) = package_swift {
        maybe_set_project_from_package_swift(package_swift, builder)?;
    }
    let resolved = parse_json_file(path)?;
    let pins = resolved
        .pointer("/object/pins")
        .and_then(Value::as_array)
        .or_else(|| resolved.get("pins").and_then(Value::as_array))
        .cloned()
        .unwrap_or_default();

    let mut refs_by_name = HashMap::new();
    for pin in pins {
        let name = pin
            .get("identity")
            .and_then(Value::as_str)
            .or_else(|| pin.get("package").and_then(Value::as_str))
            .or_else(|| {
                pin.get("location")
                    .and_then(Value::as_str)
                    .and_then(swift_package_name_from_url)
            })
            .map(ToOwned::to_owned);
        let version = pin
            .pointer("/state/version")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let location = pin
            .get("location")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| {
                pin.pointer("/repositoryURL")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            });
        let Some(name) = name else {
            continue;
        };
        let purl = swift_purl(&name, version.as_deref());
        let mut properties = Vec::new();
        if let Some(location) = location {
            properties.push(Property::new("sandtrace:url", location));
        }
        builder.add_component(
            ComponentBuilder::new(purl.clone(), name.clone(), version).with_properties(properties),
        );
        refs_by_name.entry(name).or_insert(purl);
    }

    if let Some(package_swift) = package_swift {
        for dependency in parse_package_swift_dependencies(package_swift)? {
            if let Some(dep_ref) = refs_by_name.get(&dependency.name).cloned() {
                builder.add_root_dependency(dep_ref);
            } else {
                let purl = swift_purl(&dependency.name, dependency.version.as_deref());
                builder.add_component(
                    ComponentBuilder::new(purl.clone(), dependency.name, dependency.version)
                        .with_properties(dependency.properties),
                );
                builder.add_root_dependency(purl);
            }
        }
    }

    Ok(())
}

fn ingest_package_swift(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    maybe_set_project_from_package_swift(path, builder)?;
    for dependency in parse_package_swift_dependencies(path)? {
        let purl = swift_purl(&dependency.name, dependency.version.as_deref());
        builder.add_component(
            ComponentBuilder::new(purl.clone(), dependency.name, dependency.version)
                .with_properties(dependency.properties),
        );
        builder.add_root_dependency(purl);
    }
    Ok(())
}

struct SwiftDependency {
    name: String,
    version: Option<String>,
    properties: Vec<Property>,
}

fn maybe_set_project_from_package_swift(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let package_name_regex = Regex::new(r#"let\s+package\s*=\s*Package\(\s*name:\s*"([^"]+)""#)
        .context("invalid Package.swift name regex")?;
    let name = package_name_regex
        .captures(&content)
        .and_then(|captures| captures.get(1).map(|value| value.as_str()));
    builder.set_project_if_missing(name, None);
    Ok(())
}

fn parse_package_swift_dependencies(path: &Path) -> Result<Vec<SwiftDependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let regex =
        Regex::new(r#"\.package\s*\(\s*url:\s*"([^"]+)"\s*,\s*(?:from|exact):\s*"([^"]+)""#)
            .context("invalid Package.swift dependency regex")?;
    let mut dependencies = Vec::new();
    for captures in regex.captures_iter(&content) {
        let Some(url) = captures.get(1).map(|value| value.as_str()) else {
            continue;
        };
        let name = swift_package_name_from_url(url)
            .unwrap_or("package")
            .to_string();
        let spec = captures.get(2).map(|value| value.as_str()).unwrap_or("");
        let mut properties = Vec::new();
        if !spec.is_empty() {
            properties.push(Property::new("sandtrace:version_spec", spec));
        }
        properties.push(Property::new("sandtrace:url", url));
        dependencies.push(SwiftDependency {
            name,
            version: None,
            properties,
        });
    }
    Ok(dependencies)
}

fn swift_package_name_from_url(url: &str) -> Option<&str> {
    let path = url.trim_end_matches('/').split('?').next().unwrap_or(url);
    let name = path
        .rsplit('/')
        .next()?
        .strip_suffix(".git")
        .unwrap_or_else(|| path.rsplit('/').next().unwrap());
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn ingest_pom_xml(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    let info = parse_pom_xml(path)?;
    builder.set_project_if_missing(
        info.project_name.as_deref(),
        info.project_version.as_deref(),
    );
    for dependency in info.dependencies {
        let purl = maven_purl(
            &dependency.group_id,
            &dependency.artifact_id,
            dependency.version.as_deref(),
        );
        builder.add_component(
            ComponentBuilder::new(
                purl.clone(),
                format!("{}:{}", dependency.group_id, dependency.artifact_id),
                dependency.version,
            )
            .with_properties(dependency.properties),
        );
        builder.add_root_dependency(purl);
    }
    Ok(())
}

fn ingest_gradle_lockfiles(
    lockfiles: &[PathBuf],
    build_file: Option<&Path>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    let direct = build_file
        .map(parse_gradle_manifest_dependencies)
        .transpose()?
        .unwrap_or_default();
    let mut refs_by_ga: HashMap<String, String> = HashMap::new();

    for lockfile in lockfiles {
        let content = std::fs::read_to_string(lockfile)
            .with_context(|| format!("failed to read {}", lockfile.display()))?;
        for line in content.lines() {
            let Some((group, artifact, version)) = parse_gradle_lock_line(line) else {
                continue;
            };
            let purl = maven_purl(&group, &artifact, Some(&version));
            builder.add_component(ComponentBuilder::new(
                purl.clone(),
                format!("{group}:{artifact}"),
                Some(version),
            ));
            refs_by_ga
                .entry(format!("{group}:{artifact}"))
                .or_insert(purl);
        }
    }

    for dependency in direct {
        let ga = format!("{}:{}", dependency.group_id, dependency.artifact_id);
        if let Some(dep_ref) = refs_by_ga.get(&ga).cloned() {
            builder.add_root_dependency(dep_ref);
        } else {
            let purl = maven_purl(
                &dependency.group_id,
                &dependency.artifact_id,
                dependency.version.as_deref(),
            );
            builder.add_component(
                ComponentBuilder::new(
                    purl.clone(),
                    format!("{}:{}", dependency.group_id, dependency.artifact_id),
                    dependency.version,
                )
                .with_properties(dependency.properties),
            );
            builder.add_root_dependency(purl);
        }
    }

    Ok(())
}

fn ingest_gradle_manifest(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    for dependency in parse_gradle_manifest_dependencies(path)? {
        let purl = maven_purl(
            &dependency.group_id,
            &dependency.artifact_id,
            dependency.version.as_deref(),
        );
        builder.add_component(
            ComponentBuilder::new(
                purl.clone(),
                format!("{}:{}", dependency.group_id, dependency.artifact_id),
                dependency.version,
            )
            .with_properties(dependency.properties),
        );
        builder.add_root_dependency(purl);
    }
    Ok(())
}

struct JavaDependency {
    group_id: String,
    artifact_id: String,
    version: Option<String>,
    properties: Vec<Property>,
}

struct PomInfo {
    project_name: Option<String>,
    project_version: Option<String>,
    dependencies: Vec<JavaDependency>,
}

fn parse_pom_xml(path: &Path) -> Result<PomInfo> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let doc = roxmltree::Document::parse(&content)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let project = doc
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "project")
        .context("missing <project> root")?;

    let mut properties = HashMap::new();
    if let Some(props) = child_element(project, "properties") {
        for child in props.children().filter(|node| node.is_element()) {
            if let Some(text) = child
                .text()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                properties.insert(child.tag_name().name().to_string(), text.to_string());
            }
        }
    }

    let group_id = child_text(project, "groupId").or_else(|| {
        child_element(project, "parent").and_then(|parent| child_text(parent, "groupId"))
    });
    let artifact_id = child_text(project, "artifactId");
    let version = child_text(project, "version").or_else(|| {
        child_element(project, "parent").and_then(|parent| child_text(parent, "version"))
    });
    if let Some(version) = version.clone() {
        properties.insert("project.version".to_string(), version.clone());
        properties.insert("pom.version".to_string(), version);
    }
    if let Some(group_id) = group_id.clone() {
        properties.insert("project.groupId".to_string(), group_id);
    }
    if let Some(artifact_id) = artifact_id.clone() {
        properties.insert("project.artifactId".to_string(), artifact_id);
    }

    let mut dependencies = Vec::new();
    for deps in project
        .children()
        .filter(|node| node.is_element() && node.tag_name().name() == "dependencies")
    {
        for dependency in deps
            .children()
            .filter(|node| node.is_element() && node.tag_name().name() == "dependency")
        {
            let Some(group_id) = child_text(dependency, "groupId") else {
                continue;
            };
            let Some(artifact_id) = child_text(dependency, "artifactId") else {
                continue;
            };
            let version = child_text(dependency, "version")
                .map(|value| resolve_maven_property(&value, &properties));
            let mut extra = Vec::new();
            if let Some(scope) = child_text(dependency, "scope") {
                extra.push(Property::new("sandtrace:scope", scope));
            }
            if child_text(dependency, "optional").as_deref() == Some("true") {
                extra.push(Property::new("sandtrace:optional", "true"));
            }
            dependencies.push(JavaDependency {
                group_id,
                artifact_id,
                version,
                properties: extra,
            });
        }
    }

    Ok(PomInfo {
        project_name: artifact_id.or_else(|| child_text(project, "name")),
        project_version: version,
        dependencies,
    })
}

fn child_element<'a, 'input>(
    node: roxmltree::Node<'a, 'input>,
    name: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == name)
}

fn child_text(node: roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    child_element(node, name)
        .and_then(|child| child.text())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn resolve_maven_property(value: &str, properties: &HashMap<String, String>) -> String {
    if let Some(name) = value
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
    {
        return properties
            .get(name)
            .cloned()
            .unwrap_or_else(|| value.to_string());
    }
    value.to_string()
}

fn parse_gradle_manifest_dependencies(path: &Path) -> Result<Vec<JavaDependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let regex = Regex::new(r#"['"]([^:'"\s]+):([^:'"\s]+):([^'"\s)]+)['"]"#)
        .context("invalid Gradle dependency regex")?;
    let mut dependencies = Vec::new();

    for captures in regex.captures_iter(&content) {
        let Some(group_id) = captures.get(1).map(|value| value.as_str().to_string()) else {
            continue;
        };
        let Some(artifact_id) = captures.get(2).map(|value| value.as_str().to_string()) else {
            continue;
        };
        let version_spec = captures.get(3).map(|value| value.as_str()).unwrap_or("");
        let (version, properties) = spec_to_version_and_properties(version_spec);
        dependencies.push(JavaDependency {
            group_id,
            artifact_id,
            version,
            properties,
        });
    }

    Ok(dependencies)
}

fn parse_gradle_lock_line(line: &str) -> Option<(String, String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with("empty=") {
        return None;
    }

    let coords = line.split('=').next()?.trim();
    let mut parts = coords.splitn(3, ':');
    let group = parts.next()?.trim();
    let artifact = parts.next()?.trim();
    let version = parts.next()?.trim();
    if group.is_empty() || artifact.is_empty() || version.is_empty() {
        return None;
    }

    Some((group.to_string(), artifact.to_string(), version.to_string()))
}

fn ingest_cargo_lock(
    lock_path: &Path,
    cargo_toml: Option<&Path>,
    builder: &mut SbomBuilder,
) -> Result<()> {
    let content = std::fs::read_to_string(lock_path)
        .with_context(|| format!("failed to read {}", lock_path.display()))?;
    let cargo_lock: toml::Value = toml::from_str(&content)
        .with_context(|| format!("failed to parse {}", lock_path.display()))?;

    let mut direct_deps = Vec::new();
    let mut root_name = None;
    let mut root_version = None;
    if let Some(cargo_toml) = cargo_toml {
        let manifest = parse_cargo_toml_manifest(cargo_toml)?;
        builder.set_project_if_missing(
            manifest.package_name.as_deref(),
            manifest.package_version.as_deref(),
        );
        root_name = manifest.package_name;
        root_version = manifest.package_version;
        direct_deps = manifest.direct_dependencies;
    }

    let packages = cargo_lock
        .get("package")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut refs_by_name: HashMap<String, Vec<String>> = HashMap::new();
    let mut refs_by_name_version: HashMap<(String, String), String> = HashMap::new();
    let mut package_dependencies: Vec<(String, Vec<String>)> = Vec::new();
    for package in packages {
        let Some(name) = package.get("name").and_then(toml::Value::as_str) else {
            continue;
        };
        let Some(version) = package.get("version").and_then(toml::Value::as_str) else {
            continue;
        };
        if root_name.as_deref() == Some(name) && root_version.as_deref() == Some(version) {
            continue;
        }
        let purl = cargo_purl(name, Some(version));
        builder.add_component(ComponentBuilder::new(
            purl.clone(),
            name.to_string(),
            Some(version.to_string()),
        ));
        refs_by_name_version.insert((name.to_string(), version.to_string()), purl.clone());
        refs_by_name.entry(name.to_string()).or_default().push(purl);

        let dependencies = package
            .get("dependencies")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        package_dependencies.push((format!("{name}@{version}"), dependencies));
    }

    for dep_name in direct_deps {
        if let Some(dep_ref) = refs_by_name
            .get(&dep_name)
            .and_then(|refs| refs.first())
            .cloned()
        {
            builder.add_root_dependency(dep_ref);
        }
    }

    for (package_key, dependencies) in package_dependencies {
        let Some((name, version)) = package_key.rsplit_once('@') else {
            continue;
        };
        let Some(parent_ref) = refs_by_name_version
            .get(&(name.to_string(), version.to_string()))
            .cloned()
        else {
            continue;
        };

        for dependency in dependencies {
            let Some((dep_name, dep_version)) = parse_cargo_lock_dependency(&dependency) else {
                continue;
            };
            let child_ref = dep_version
                .as_ref()
                .and_then(|resolved| {
                    refs_by_name_version
                        .get(&(dep_name.clone(), resolved.clone()))
                        .cloned()
                })
                .or_else(|| {
                    refs_by_name
                        .get(&dep_name)
                        .and_then(|refs| refs.first())
                        .cloned()
                });

            if let Some(child_ref) = child_ref {
                builder.add_dependency(parent_ref.clone(), child_ref);
            }
        }
    }

    Ok(())
}

fn parse_cargo_lock_dependency(input: &str) -> Option<(String, Option<String>)> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let package_part = trimmed
        .split_once('(')
        .map(|(value, _)| value)
        .unwrap_or(trimmed)
        .trim();
    let mut parts = package_part.split_whitespace();
    let name = parts.next()?.to_string();
    let version = parts.next().map(ToOwned::to_owned);
    Some((name, version))
}

fn ingest_cargo_toml_manifest(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    let manifest = parse_cargo_toml_manifest(path)?;
    builder.set_project_if_missing(
        manifest.package_name.as_deref(),
        manifest.package_version.as_deref(),
    );

    for dependency in manifest.dependencies {
        let purl = cargo_purl(&dependency.name, dependency.version.as_deref());
        builder.add_component(
            ComponentBuilder::new(purl.clone(), dependency.name, dependency.version)
                .with_properties(dependency.properties),
        );
        builder.add_root_dependency(purl);
    }

    Ok(())
}

#[derive(Default)]
struct CargoManifestInfo {
    package_name: Option<String>,
    package_version: Option<String>,
    direct_dependencies: Vec<String>,
    dependencies: Vec<ManifestDependency>,
}

#[derive(Default)]
struct ManifestDependency {
    name: String,
    version: Option<String>,
    properties: Vec<Property>,
}

fn parse_cargo_toml_manifest(path: &Path) -> Result<CargoManifestInfo> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let cargo_toml: toml::Value =
        toml::from_str(&content).with_context(|| format!("failed to parse {}", path.display()))?;

    let mut info = CargoManifestInfo::default();
    if let Some(package) = cargo_toml.get("package").and_then(toml::Value::as_table) {
        info.package_name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .map(ToOwned::to_owned);
        info.package_version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .map(ToOwned::to_owned);
    }

    for section in ["dependencies", "workspace.dependencies"] {
        let Some(table) = get_toml_table(&cargo_toml, section) else {
            continue;
        };
        for (name, value) in table {
            let dependency = parse_cargo_manifest_dependency(name, value);
            info.direct_dependencies.push(name.to_string());
            info.dependencies.push(dependency);
        }
    }

    Ok(info)
}

fn get_toml_table<'a>(
    root: &'a toml::Value,
    dotted_key: &str,
) -> Option<&'a toml::map::Map<String, toml::Value>> {
    let mut current = root;
    for segment in dotted_key.split('.') {
        current = current.get(segment)?;
    }
    current.as_table()
}

fn parse_cargo_manifest_dependency(name: &str, value: &toml::Value) -> ManifestDependency {
    match value {
        toml::Value::String(version) => {
            let (resolved, properties) = spec_to_version_and_properties(version);
            ManifestDependency {
                name: name.to_string(),
                version: resolved,
                properties,
            }
        }
        toml::Value::Table(table) => {
            let version_spec = table
                .get("version")
                .and_then(toml::Value::as_str)
                .unwrap_or("");
            let (resolved, mut properties) = spec_to_version_and_properties(version_spec);
            if table.get("path").and_then(toml::Value::as_str).is_some() {
                properties.push(Property::new("sandtrace:source", "path"));
            }
            if table.get("git").and_then(toml::Value::as_str).is_some() {
                properties.push(Property::new("sandtrace:source", "git"));
            }
            ManifestDependency {
                name: name.to_string(),
                version: resolved,
                properties,
            }
        }
        _ => ManifestDependency {
            name: name.to_string(),
            version: None,
            properties: Vec::new(),
        },
    }
}

fn ingest_requirements(path: &Path, builder: &mut SbomBuilder) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    for line in content.lines() {
        let Some(requirement) = parse_requirement_line(line) else {
            continue;
        };
        let purl = pypi_purl(&requirement.name, requirement.version.as_deref());
        builder.add_component(
            ComponentBuilder::new(purl.clone(), requirement.name, requirement.version)
                .with_properties(requirement.properties),
        );
        builder.add_root_dependency(purl);
    }
    Ok(())
}

struct RequirementSpec {
    name: String,
    version: Option<String>,
    properties: Vec<Property>,
}

fn parse_requirement_line(line: &str) -> Option<RequirementSpec> {
    let line = line.split('#').next()?.trim();
    if line.is_empty()
        || line.starts_with('-')
        || line.starts_with("--")
        || line.starts_with("git+")
        || line.starts_with("http://")
        || line.starts_with("https://")
    {
        return None;
    }

    for operator in ["==", ">=", "<=", "~=", "!=", ">", "<"] {
        if let Some((name, spec)) = line.split_once(operator) {
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            let spec = spec.trim();
            let (version, properties) = if operator == "==" {
                (Some(spec.to_string()), Vec::new())
            } else {
                (
                    None,
                    vec![Property::new(
                        "sandtrace:version_spec",
                        format!("{operator}{spec}"),
                    )],
                )
            };
            return Some(RequirementSpec {
                name: normalize_python_package_token(name),
                version,
                properties,
            });
        }
    }

    Some(RequirementSpec {
        name: normalize_python_package_token(line),
        version: None,
        properties: Vec::new(),
    })
}

#[derive(Serialize)]
struct Bom {
    #[serde(rename = "bomFormat")]
    bom_format: &'static str,
    #[serde(rename = "specVersion")]
    spec_version: &'static str,
    #[serde(rename = "serialNumber")]
    serial_number: String,
    version: u32,
    metadata: Metadata,
    components: Vec<Component>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    dependencies: Vec<Dependency>,
}

#[derive(Serialize)]
struct Metadata {
    timestamp: String,
    tools: Vec<Tool>,
    component: Component,
}

#[derive(Serialize)]
struct Tool {
    vendor: &'static str,
    name: &'static str,
    version: &'static str,
}

#[derive(Clone, Serialize)]
struct Component {
    #[serde(rename = "type")]
    component_type: &'static str,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    properties: Vec<Property>,
}

#[derive(Clone, Serialize)]
struct Property {
    name: String,
    value: String,
}

impl Property {
    fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

#[derive(Serialize)]
struct Dependency {
    #[serde(rename = "ref")]
    ref_: String,
    #[serde(rename = "dependsOn")]
    depends_on: Vec<String>,
}

struct ComponentBuilder {
    bom_ref: String,
    name: String,
    version: Option<String>,
    properties: Vec<Property>,
}

impl ComponentBuilder {
    fn new(bom_ref: String, name: String, version: Option<String>) -> Self {
        Self {
            bom_ref,
            name,
            version,
            properties: Vec::new(),
        }
    }

    fn with_properties(mut self, properties: Vec<Property>) -> Self {
        self.properties = properties;
        self
    }

    fn build(self) -> Component {
        let purl = self
            .bom_ref
            .strip_prefix("pkg:")
            .map(|_| self.bom_ref.clone());
        Component {
            component_type: "library",
            bom_ref: self.bom_ref,
            name: self.name,
            version: self.version,
            purl,
            properties: self.properties,
        }
    }
}

struct SbomBuilder {
    root_name: String,
    root_version: Option<String>,
    root_bom_ref: String,
    components: BTreeMap<String, Component>,
    dependency_edges: BTreeMap<String, BTreeSet<String>>,
}

impl SbomBuilder {
    fn new(root_name: String) -> Self {
        let root_bom_ref = format!("urn:uuid:{}", Uuid::new_v4());
        Self {
            root_name,
            root_version: None,
            root_bom_ref,
            components: BTreeMap::new(),
            dependency_edges: BTreeMap::new(),
        }
    }

    fn set_project_if_missing(&mut self, name: Option<&str>, version: Option<&str>) {
        if self.root_version.is_some() {
            return;
        }
        if let Some(name) = name.filter(|name| !name.trim().is_empty()) {
            self.root_name = name.to_string();
        }
        self.root_version = version
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
    }

    fn add_component(&mut self, component: ComponentBuilder) {
        let component = component.build();
        self.components
            .entry(component.bom_ref.clone())
            .and_modify(|existing| merge_component(existing, &component))
            .or_insert(component);
    }

    fn add_root_dependency(&mut self, bom_ref: String) {
        self.add_dependency(self.root_bom_ref.clone(), bom_ref);
    }

    fn add_dependency(&mut self, parent_ref: String, child_ref: String) {
        if parent_ref == child_ref {
            return;
        }

        self.dependency_edges
            .entry(parent_ref)
            .or_default()
            .insert(child_ref);
    }

    fn finish(self) -> Bom {
        let metadata_component = Component {
            component_type: "application",
            bom_ref: self.root_bom_ref.clone(),
            name: self.root_name,
            version: self.root_version,
            purl: None,
            properties: Vec::new(),
        };

        let components = self.components.into_values().collect::<Vec<_>>();
        let dependencies = self
            .dependency_edges
            .into_iter()
            .filter_map(|(ref_, depends_on)| {
                if depends_on.is_empty() {
                    None
                } else {
                    Some(Dependency {
                        ref_,
                        depends_on: depends_on.into_iter().collect(),
                    })
                }
            })
            .collect::<Vec<_>>();

        Bom {
            bom_format: "CycloneDX",
            spec_version: "1.5",
            serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
            version: 1,
            metadata: Metadata {
                timestamp: Utc::now().to_rfc3339(),
                tools: vec![Tool {
                    vendor: "Sandtrace",
                    name: "sandtrace",
                    version: env!("CARGO_PKG_VERSION"),
                }],
                component: metadata_component,
            },
            components,
            dependencies,
        }
    }
}

fn merge_component(existing: &mut Component, incoming: &Component) {
    if existing.version.is_none() {
        existing.version = incoming.version.clone();
    }
    let mut seen = existing
        .properties
        .iter()
        .map(|property| (property.name.clone(), property.value.clone()))
        .collect::<BTreeSet<_>>();
    for property in &incoming.properties {
        if seen.insert((property.name.clone(), property.value.clone())) {
            existing.properties.push(property.clone());
        }
    }
}

fn infer_npm_name_from_path(package_path: &str) -> Option<String> {
    let trimmed = package_path.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let segments = trimmed.split('/').collect::<Vec<_>>();
    let idx = segments
        .iter()
        .rposition(|segment| *segment == "node_modules")?;
    let first = *segments.get(idx + 1)?;
    if first.starts_with('@') {
        Some(format!("{}/{}", first, segments.get(idx + 2)?))
    } else {
        Some(first.to_string())
    }
}

fn pick_best_npm_ref(
    refs_by_name: &HashMap<String, Vec<(String, String)>>,
    dep_name: &str,
) -> Option<String> {
    let refs = refs_by_name.get(dep_name)?;
    refs.iter()
        .find(|(_, path)| {
            path == &format!("node_modules/{dep_name}")
                || path == &format!("node_modules/{}", dep_name.replace('/', "/node_modules/"))
        })
        .map(|(bom_ref, _)| bom_ref.clone())
        .or_else(|| refs.first().map(|(bom_ref, _)| bom_ref.clone()))
}

fn add_npm_package_lock_edges(
    packages: &serde_json::Map<String, Value>,
    refs_by_path: &HashMap<String, String>,
    refs_by_name: &HashMap<String, Vec<(String, String)>>,
    builder: &mut SbomBuilder,
) {
    for (package_path, package) in packages {
        let Some(parent_ref) = refs_by_path.get(package_path).cloned() else {
            continue;
        };

        for section in ["dependencies", "optionalDependencies", "peerDependencies"] {
            let Some(dependencies) = package.get(section).and_then(Value::as_object) else {
                continue;
            };

            for dep_name in dependencies.keys() {
                let child_ref = npm_dependency_ref_for_parent(
                    package_path,
                    dep_name,
                    refs_by_path,
                    refs_by_name,
                );
                if let Some(child_ref) = child_ref {
                    builder.add_dependency(parent_ref.clone(), child_ref);
                }
            }
        }
    }
}

fn npm_dependency_ref_for_parent(
    parent_path: &str,
    dep_name: &str,
    refs_by_path: &HashMap<String, String>,
    refs_by_name: &HashMap<String, Vec<(String, String)>>,
) -> Option<String> {
    let nested_path = if parent_path.is_empty() {
        format!("node_modules/{dep_name}")
    } else {
        format!("{parent_path}/node_modules/{dep_name}")
    };

    refs_by_path
        .get(&nested_path)
        .cloned()
        .or_else(|| pick_best_npm_ref(refs_by_name, dep_name))
}

fn spec_to_version_and_properties(spec: &str) -> (Option<String>, Vec<Property>) {
    let spec = spec.trim();
    if spec.is_empty() {
        return (None, Vec::new());
    }
    if is_resolved_version(spec) {
        return (Some(spec.to_string()), Vec::new());
    }
    (
        None,
        vec![Property::new("sandtrace:version_spec", spec.to_string())],
    )
}

fn is_resolved_version(spec: &str) -> bool {
    !spec.contains(['^', '~', '>', '<', '=', '*'])
        && !spec.starts_with("workspace:")
        && !spec.starts_with("file:")
        && !spec.starts_with("link:")
        && !spec.starts_with("git")
        && !spec.starts_with("http://")
        && !spec.starts_with("https://")
}

fn npm_purl(name: &str, version: Option<&str>) -> String {
    let name = name.replacen('@', "%40", 1);
    match version {
        Some(version) if !version.is_empty() => format!("pkg:npm/{name}@{version}"),
        _ => format!("pkg:npm/{name}"),
    }
}

fn cargo_purl(name: &str, version: Option<&str>) -> String {
    match version {
        Some(version) if !version.is_empty() => format!("pkg:cargo/{name}@{version}"),
        _ => format!("pkg:cargo/{name}"),
    }
}

fn composer_purl(name: &str, version: Option<&str>) -> String {
    match version {
        Some(version) if !version.is_empty() => format!("pkg:composer/{name}@{version}"),
        _ => format!("pkg:composer/{name}"),
    }
}

fn jsr_purl(name: &str, version: Option<&str>) -> String {
    match version {
        Some(version) if !version.is_empty() => format!("pkg:jsr/{name}@{version}"),
        _ => format!("pkg:jsr/{name}"),
    }
}

fn golang_purl(name: &str, version: Option<&str>) -> String {
    match version {
        Some(version) if !version.is_empty() => format!("pkg:golang/{name}@{version}"),
        _ => format!("pkg:golang/{name}"),
    }
}

fn maven_purl(group: &str, artifact: &str, version: Option<&str>) -> String {
    match version {
        Some(version) if !version.is_empty() => format!("pkg:maven/{group}/{artifact}@{version}"),
        _ => format!("pkg:maven/{group}/{artifact}"),
    }
}

fn gem_purl(name: &str, version: Option<&str>) -> String {
    match version {
        Some(version) if !version.is_empty() => format!("pkg:gem/{name}@{version}"),
        _ => format!("pkg:gem/{name}"),
    }
}

fn nuget_purl(name: &str, version: Option<&str>) -> String {
    match version {
        Some(version) if !version.is_empty() => format!("pkg:nuget/{name}@{version}"),
        _ => format!("pkg:nuget/{name}"),
    }
}

fn hex_purl(name: &str, version: Option<&str>) -> String {
    match version {
        Some(version) if !version.is_empty() => format!("pkg:hex/{name}@{version}"),
        _ => format!("pkg:hex/{name}"),
    }
}

fn swift_purl(name: &str, version: Option<&str>) -> String {
    match version {
        Some(version) if !version.is_empty() => format!("pkg:swift/{name}@{version}"),
        _ => format!("pkg:swift/{name}"),
    }
}

fn pypi_purl(name: &str, version: Option<&str>) -> String {
    match version {
        Some(version) if !version.is_empty() => format!("pkg:pypi/{name}@{version}"),
        _ => format!("pkg:pypi/{name}"),
    }
}

fn conda_purl(name: &str, version: Option<&str>) -> String {
    match version {
        Some(version) if !version.is_empty() => format!("pkg:conda/{name}@{version}"),
        _ => format!("pkg:conda/{name}"),
    }
}

fn normalize_pypi_name(name: &str) -> String {
    name.trim().replace('_', "-").to_lowercase()
}

fn normalize_python_package_token(name: &str) -> String {
    let name = name.split(';').next().unwrap_or(name).trim();
    let name = name.split_whitespace().next().unwrap_or(name);
    let name = name.split('[').next().unwrap_or(name);
    normalize_pypi_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parses_requirements_lines() {
        let pinned = parse_requirement_line("Requests==2.32.3").unwrap();
        assert_eq!(pinned.name, "requests");
        assert_eq!(pinned.version.as_deref(), Some("2.32.3"));

        let ranged = parse_requirement_line("urllib3>=2.2,<3").unwrap();
        assert_eq!(ranged.name, "urllib3");
        assert!(ranged.version.is_none());
        assert_eq!(ranged.properties[0].name, "sandtrace:version_spec");
    }

    #[test]
    fn parses_package_lock_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            serde_json::json!({
                "name": "demo",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "name": "demo",
                        "version": "1.0.0",
                        "dependencies": {
                            "left-pad": "^1.3.0"
                        }
                    },
                    "node_modules/left-pad": {
                        "version": "1.3.0"
                    }
                }
            })
            .to_string(),
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert_eq!(bom.metadata.component.name, "demo");
        assert_eq!(bom.components.len(), 1);
        assert_eq!(bom.components[0].name, "left-pad");
        assert_eq!(bom.components[0].version.as_deref(), Some("1.3.0"));
        assert_eq!(bom.dependencies[0].depends_on.len(), 1);
    }

    #[test]
    fn package_lock_emits_transitive_dependency_edges() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            serde_json::json!({
                "name": "demo",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "name": "demo",
                        "version": "1.0.0",
                        "dependencies": {
                            "left-pad": "^1.3.0"
                        }
                    },
                    "node_modules/left-pad": {
                        "version": "1.3.0",
                        "dependencies": {
                            "repeat-string": "^1.6.1"
                        }
                    },
                    "node_modules/repeat-string": {
                        "version": "1.6.1"
                    }
                }
            })
            .to_string(),
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:npm/repeat-string@1.6.1"));
        assert!(bom.dependencies.iter().any(|dependency| {
            dependency.ref_ == "pkg:npm/left-pad@1.3.0"
                && dependency.depends_on == vec!["pkg:npm/repeat-string@1.6.1"]
        }));
    }

    #[test]
    fn parses_npm_shrinkwrap_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("npm-shrinkwrap.json"),
            serde_json::json!({
                "name": "demo",
                "version": "1.0.0",
                "packages": {
                    "": {
                        "name": "demo",
                        "version": "1.0.0",
                        "dependencies": {
                            "chalk": "^5.4.1"
                        }
                    },
                    "node_modules/chalk": {
                        "version": "5.4.1"
                    }
                }
            })
            .to_string(),
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert_eq!(bom.metadata.component.name, "demo");
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:npm/chalk@5.4.1"));
        assert_eq!(bom.dependencies[0].depends_on, vec!["pkg:npm/chalk@5.4.1"]);
    }

    #[test]
    fn parses_package_lock_yaml_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("package-lock.yaml"),
            r#"
name: demo
version: 1.0.0
packages:
  "":
    name: demo
    version: 1.0.0
    dependencies:
      left-pad: ^1.3.0
  node_modules/left-pad:
    version: 1.3.0
"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:npm/left-pad@1.3.0"));
    }

    #[test]
    fn parses_cargo_lock_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            r#"
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            serde = "1.0"
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("Cargo.lock"),
            r#"
            version = 3

            [[package]]
            name = "demo"
            version = "0.1.0"

            [[package]]
            name = "serde"
            version = "1.0.217"
            "#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert_eq!(bom.metadata.component.name, "demo");
        assert_eq!(bom.components.len(), 1);
        assert_eq!(bom.components[0].bom_ref, "pkg:cargo/serde@1.0.217");
        assert_eq!(bom.dependencies[0].depends_on[0], "pkg:cargo/serde@1.0.217");
    }

    #[test]
    fn cargo_lock_emits_transitive_dependency_edges() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            r#"
            [package]
            name = "demo"
            version = "0.1.0"

            [dependencies]
            serde = "1.0"
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("Cargo.lock"),
            r#"
            version = 3

            [[package]]
            name = "demo"
            version = "0.1.0"
            dependencies = [
                "serde 1.0.217",
            ]

            [[package]]
            name = "serde"
            version = "1.0.217"
            dependencies = [
                "serde_derive 1.0.217",
            ]

            [[package]]
            name = "serde_derive"
            version = "1.0.217"
            "#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert!(bom.dependencies.iter().any(|dependency| {
            dependency.ref_ == "pkg:cargo/serde@1.0.217"
                && dependency.depends_on == vec!["pkg:cargo/serde_derive@1.0.217"]
        }));
    }

    #[test]
    fn parses_requirements_sbom() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("requirements.txt"),
            "requests==2.32.3\nurllib3>=2.2\n",
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert_eq!(bom.components.len(), 2);
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:pypi/requests@2.32.3"));
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:pypi/urllib3"));
    }

    #[test]
    fn parses_pnpm_lock_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            serde_json::json!({
                "name": "demo",
                "version": "1.0.0",
                "dependencies": { "react": "^18.3.1" }
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("pnpm-lock.yaml"),
            r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: ^18.3.1
        version: 18.3.1
packages:
  react@18.3.1:
    resolution: {integrity: sha512-demo}
"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:npm/react@18.3.1"));
        assert_eq!(bom.dependencies[0].depends_on, vec!["pkg:npm/react@18.3.1"]);
    }

    #[test]
    fn parses_yarn_lock_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            serde_json::json!({
                "name": "demo",
                "version": "1.0.0",
                "dependencies": { "left-pad": "^1.3.0" }
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("yarn.lock"),
            r#"
"left-pad@^1.3.0":
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz"
  integrity sha512-demo
"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:npm/left-pad@1.3.0"));
    }

    #[test]
    fn parses_composer_lock_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("composer.json"),
            serde_json::json!({
                "name": "acme/demo",
                "require": { "monolog/monolog": "^3.0" }
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("composer.lock"),
            serde_json::json!({
                "packages": [
                    { "name": "monolog/monolog", "version": "3.6.0" }
                ],
                "packages-dev": []
            })
            .to_string(),
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:composer/monolog/monolog@3.6.0"));
    }

    #[test]
    fn composer_lock_emits_transitive_dependency_edges() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("composer.json"),
            serde_json::json!({
                "name": "acme/demo",
                "require": { "laravel/framework": "^12.0" }
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("composer.lock"),
            serde_json::json!({
                "packages": [
                    {
                        "name": "laravel/framework",
                        "version": "12.52.0",
                        "require": {
                            "symfony/http-foundation": "^7.3"
                        }
                    },
                    {
                        "name": "symfony/http-foundation",
                        "version": "7.3.0"
                    }
                ],
                "packages-dev": []
            })
            .to_string(),
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        let root_ref = bom.metadata.component.bom_ref.clone();

        let root_deps = bom
            .dependencies
            .iter()
            .find(|dependency| dependency.ref_ == root_ref)
            .map(|dependency| dependency.depends_on.clone())
            .unwrap_or_default();
        assert!(root_deps.contains(&"pkg:composer/laravel/framework@12.52.0".to_string()));

        let package_deps = bom
            .dependencies
            .iter()
            .find(|dependency| dependency.ref_ == "pkg:composer/laravel/framework@12.52.0")
            .map(|dependency| dependency.depends_on.clone())
            .unwrap_or_default();
        assert!(package_deps.contains(&"pkg:composer/symfony/http-foundation@7.3.0".to_string()));
    }

    #[test]
    fn parses_deno_imports() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("deno.json"),
            serde_json::json!({
                "name": "demo",
                "imports": {
                    "@std/assert": "jsr:@std/assert@1.0.8",
                    "chalk": "npm:chalk@5.3.0"
                }
            })
            .to_string(),
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:jsr/@std/assert@1.0.8"));
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:npm/chalk@5.3.0"));
    }

    #[test]
    fn parses_deno_jsonc_and_lock_packages() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("deno.jsonc"),
            r#"
{
  // comment
  name: "demo",
  imports: {
    "@std/assert": "jsr:@std/assert@^1.0.8",
    "chalk": "npm:chalk@^5.3.0",
  },
}
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("deno.lock"),
            serde_json::json!({
                "version": "4",
                "specifiers": {
                    "jsr:@std/assert@^1.0.8": "1.0.8",
                    "npm:chalk@^5.3.0": "5.3.0"
                },
                "jsr": {
                    "@std/assert@1.0.8": {}
                },
                "npm": {
                    "chalk@5.3.0": {}
                }
            })
            .to_string(),
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:jsr/@std/assert@1.0.8"));
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:npm/chalk@5.3.0"));
    }

    #[test]
    fn parses_deno_remote_url_imports() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("deno.json"),
            serde_json::json!({
                "name": "demo",
                "imports": {
                    "oak": "https://deno.land/x/oak@v17.1.3/mod.ts"
                }
            })
            .to_string(),
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert!(bom.components.iter().any(|component| {
            component.bom_ref == "https://deno.land/x/oak@v17.1.3/mod.ts"
                && component.name == "mod.ts"
                && component.purl.is_none()
        }));
        assert_eq!(
            bom.dependencies[0].depends_on,
            vec!["https://deno.land/x/oak@v17.1.3/mod.ts"]
        );
    }

    #[test]
    fn parses_poetry_lock_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            r#"
[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests>=2.32.0"]
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("poetry.lock"),
            r#"
[[package]]
name = "requests"
version = "2.32.3"

[[package]]
name = "urllib3"
version = "2.2.3"
"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:pypi/requests@2.32.3"));
        assert_eq!(
            bom.dependencies[0].depends_on,
            vec!["pkg:pypi/requests@2.32.3"]
        );
    }

    #[test]
    fn parses_uv_lock_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            r#"
[project]
name = "demo"
version = "0.1.0"
dependencies = ["httpx>=0.27.0"]
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("uv.lock"),
            r#"
version = 1
revision = 1
requires-python = ">=3.12"

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }
dependencies = [
  { name = "httpx" },
]

[[package]]
name = "httpx"
version = "0.27.2"
source = { registry = "https://pypi.org/simple" }
"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert_eq!(bom.metadata.component.name, "demo");
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:pypi/httpx@0.27.2"));
        assert_eq!(
            bom.dependencies[0].depends_on,
            vec!["pkg:pypi/httpx@0.27.2"]
        );
    }

    #[test]
    fn parses_pylock_toml_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            r#"
[project]
name = "demo"
version = "0.1.0"
dependencies = ["click>=8.1.0"]
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("pylock.toml"),
            r#"
lock-version = "1.0"

[[package]]
name = "click"
version = "8.1.8"
"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert_eq!(bom.metadata.component.name, "demo");
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:pypi/click@8.1.8"));
        assert_eq!(bom.dependencies[0].depends_on, vec!["pkg:pypi/click@8.1.8"]);
    }

    #[test]
    fn parses_conda_lock_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("environment.yml"),
            r#"
name: demo
dependencies:
  - python=3.12
  - numpy>=1.26
  - pip:
      - httpx>=0.27
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("conda-lock.yml"),
            r#"
package:
  - name: python
    version: 3.12.8
    manager: conda
    platform: linux-64
  - name: numpy
    version: 2.1.3
    manager: conda
    platform: linux-64
  - name: httpx
    version: 0.27.2
    manager: pip
    platform: linux-64
"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert_eq!(bom.metadata.component.name, "demo");
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:conda/python@3.12.8"));
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:conda/numpy@2.1.3"));
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:pypi/httpx@0.27.2"));
        assert_eq!(
            bom.dependencies[0].depends_on,
            vec![
                "pkg:conda/numpy@2.1.3",
                "pkg:conda/python@3.12.8",
                "pkg:pypi/httpx@0.27.2"
            ]
        );
    }

    #[test]
    fn parses_conda_explicit_export_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("environment.yml"),
            r#"
name: demo
dependencies:
  - python=3.12
  - numpy>=1.26
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("explicit-linux-64.txt"),
            r#"
# platform: linux-64
@EXPLICIT
https://repo.anaconda.com/pkgs/main/linux-64/python-3.12.8-h1234567_0.conda#abc
https://repo.anaconda.com/pkgs/main/linux-64/numpy-2.1.3-py312h1234567_0.conda#def
"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert_eq!(bom.metadata.component.name, "demo");
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:conda/python@3.12.8"));
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:conda/numpy@2.1.3"));
        assert_eq!(
            bom.dependencies[0].depends_on,
            vec!["pkg:conda/numpy@2.1.3", "pkg:conda/python@3.12.8"]
        );
    }

    #[test]
    fn parses_conda_environment_without_lock() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("environment.yaml"),
            r#"
name: demo
dependencies:
  - conda-forge::python=3.12
  - pandas>=2.2
  - pip:
      - fastapi==0.115.0
"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert_eq!(bom.metadata.component.name, "demo");
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:conda/python@3.12"));
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:conda/pandas"));
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:pypi/fastapi@0.115.0"));
    }

    #[test]
    fn parses_pipfile_lock_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("Pipfile"),
            r#"
[packages]
flask = "==3.0.3"
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("Pipfile.lock"),
            serde_json::json!({
                "default": {
                    "flask": { "version": "==3.0.3" }
                }
            })
            .to_string(),
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:pypi/flask@3.0.3"));
    }

    #[test]
    fn parses_gemfile_lock_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("Gemfile"),
            r#"
source "https://rubygems.org"
gemspec name: "demo"
gem "rake", "~> 13.0"
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("Gemfile.lock"),
            r#"
GEM
  remote: https://rubygems.org/
  specs:
    rake (13.2.1)

DEPENDENCIES
  rake (~> 13.0)
"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert_eq!(bom.metadata.component.name, "demo");
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:gem/rake@13.2.1"));
        assert_eq!(bom.dependencies[0].depends_on, vec!["pkg:gem/rake@13.2.1"]);
    }

    #[test]
    fn parses_gemspec_without_lock() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("demo.gemspec"),
            r#"
Gem::Specification.new do |spec|
  spec.name = "demo"
  spec.version = "0.1.0"
  spec.add_dependency "thor", "~> 1.3"
end
"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert_eq!(bom.metadata.component.name, "demo");
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:gem/thor"));
    }

    #[test]
    fn parses_go_sum_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("go.mod"),
            r#"
module example.com/demo

go 1.24.0

require (
    github.com/google/uuid v1.6.0
    golang.org/x/text v0.22.0 // indirect
)
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("go.sum"),
            r#"
github.com/google/uuid v1.6.0 h1:demo
github.com/google/uuid v1.6.0/go.mod h1:demo
golang.org/x/text v0.22.0 h1:demo
"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert_eq!(bom.metadata.component.name, "example.com/demo");
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:golang/github.com/google/uuid@v1.6.0"));
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:golang/golang.org/x/text@v0.22.0"));
        assert_eq!(
            bom.dependencies[0].depends_on,
            vec!["pkg:golang/github.com/google/uuid@v1.6.0"]
        );
    }

    #[test]
    fn parses_go_mod_without_sum() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("go.mod"),
            r#"
module example.com/demo

require github.com/spf13/cobra v1.8.1
"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:golang/github.com/spf13/cobra@v1.8.1"));
    }

    #[test]
    fn parses_mix_lock_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("mix.exs"),
            r#"
defmodule Demo.MixProject do
  use Mix.Project
  def project do
    [
      app: :demo,
      version: "0.1.0"
    ]
  end
  defp deps do
    [
      {:plug, "~> 1.15"}
    ]
  end
end
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("mix.lock"),
            r#"%{
  "plug": {:hex, :plug, "1.15.3", "checksum", [:mix], [], "hexpm", "checksum"}
}"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert_eq!(bom.metadata.component.name, "demo");
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:hex/plug@1.15.3"));
        assert_eq!(bom.dependencies[0].depends_on, vec!["pkg:hex/plug@1.15.3"]);
    }

    #[test]
    fn parses_mix_exs_without_lock() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("mix.exs"),
            r#"
defmodule Demo.MixProject do
  use Mix.Project
  def project do
    [
      app: :demo
    ]
  end
  defp deps do
    [
      {:ecto, "~> 3.12"}
    ]
  end
end
"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:hex/ecto"));
    }

    #[test]
    fn parses_pom_xml_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("pom.xml"),
            r#"
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <properties>
    <junit.version>5.10.2</junit.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>${junit.version}</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert_eq!(bom.metadata.component.name, "demo");
        assert!(bom.components.iter().any(|component| {
            component.bom_ref == "pkg:maven/org.junit.jupiter/junit-jupiter@5.10.2"
        }));
    }

    #[test]
    fn parses_gradle_lockfile_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("build.gradle"),
            r#"
dependencies {
  implementation "org.slf4j:slf4j-api:2.0.16"
}
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("gradle.lockfile"),
            "org.slf4j:slf4j-api:2.0.16=compileClasspath\n",
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:maven/org.slf4j/slf4j-api@2.0.16"));
        assert_eq!(
            bom.dependencies[0].depends_on,
            vec!["pkg:maven/org.slf4j/slf4j-api@2.0.16"]
        );
    }

    #[test]
    fn parses_packages_lock_json_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("Demo.csproj"),
            r#"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <AssemblyName>Demo</AssemblyName>
    <Version>1.0.0</Version>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("packages.lock.json"),
            serde_json::json!({
                "version": 1,
                "dependencies": {
                    "net8.0": {
                        "Newtonsoft.Json": {
                            "type": "Direct",
                            "requested": "[13.0.3, )",
                            "resolved": "13.0.3"
                        }
                    }
                }
            })
            .to_string(),
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert_eq!(bom.metadata.component.name, "Demo");
        assert!(bom
            .components
            .iter()
            .any(|component| { component.bom_ref == "pkg:nuget/Newtonsoft.Json@13.0.3" }));
    }

    #[test]
    fn parses_csproj_without_lock() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("Demo.csproj"),
            r#"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <AssemblyName>Demo</AssemblyName>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Serilog">
      <Version>4.0.1</Version>
      <PrivateAssets>all</PrivateAssets>
    </PackageReference>
  </ItemGroup>
</Project>
"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:nuget/Serilog@4.0.1"));
    }

    #[test]
    fn parses_package_resolved_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("Package.swift"),
            r#"
// swift-tools-version: 5.10
import PackageDescription
let package = Package(
    name: "Demo",
    dependencies: [
        .package(url: "https://github.com/apple/swift-collections.git", from: "1.1.0")
    ]
)
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("Package.resolved"),
            serde_json::json!({
                "version": 2,
                "pins": [
                    {
                        "identity": "swift-collections",
                        "location": "https://github.com/apple/swift-collections.git",
                        "state": { "revision": "deadbeef", "version": "1.1.0" }
                    }
                ]
            })
            .to_string(),
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert_eq!(bom.metadata.component.name, "Demo");
        assert!(bom
            .components
            .iter()
            .any(|component| { component.bom_ref == "pkg:swift/swift-collections@1.1.0" }));
    }

    #[test]
    fn parses_package_swift_without_resolved() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("Package.swift"),
            r#"
import PackageDescription
let package = Package(
    name: "Demo",
    dependencies: [
        .package(url: "https://github.com/pointfreeco/swift-parsing.git", from: "0.13.0")
    ]
)
"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:swift/swift-parsing"));
    }

    #[test]
    fn parses_bun_lock_components() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            serde_json::json!({
                "name": "demo",
                "version": "1.0.0",
                "packageManager": "bun@1.2.0",
                "dependencies": { "elysia": "^1.1.11" }
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("bun.lock"),
            r#"
{
  lockfileVersion: 1,
  workspaces: {
    "": {
      name: "demo",
      version: "1.0.0",
      dependencies: {
        elysia: "1.1.11",
      },
    },
  },
  packages: {
    elysia: [
      "elysia@1.1.11",
      "",
      {},
      "sha512-demo",
    ],
  },
}
"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:npm/elysia@1.1.11"));
        assert_eq!(
            bom.dependencies[0].depends_on,
            vec!["pkg:npm/elysia@1.1.11"]
        );
    }

    #[test]
    fn bun_lockb_projects_fall_back_to_package_json_dependencies() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            serde_json::json!({
                "name": "demo",
                "version": "1.0.0",
                "packageManager": "bun@1.2.0",
                "dependencies": { "elysia": "^1.1.11" }
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(dir.path().join("bun.lockb"), "binary-placeholder").unwrap();

        let bom = build_sbom(dir.path()).unwrap();
        assert!(bom
            .components
            .iter()
            .any(|component| component.bom_ref == "pkg:npm/elysia"));
    }

    #[test]
    fn pnpm_lock_emits_transitive_dependency_edges() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            serde_json::json!({
                "name": "pnpm-transitive-test",
                "version": "1.0.0",
                "dependencies": {
                    "express": "4.21.0"
                }
            })
            .to_string(),
        )
        .unwrap();
        // pnpm v9 lockfile: packages has resolution metadata,
        // snapshots has the actual dependency graph.
        // When packages has no dependency keys, the code falls back to snapshots.
        // Use a v6-style lockfile where packages contains dependency info directly.
        std::fs::write(
            dir.path().join("pnpm-lock.yaml"),
            r#"lockfileVersion: '6.0'

importers:
  .:
    dependencies:
      express:
        specifier: 4.21.0
        version: 4.21.0

packages:
  /accepts@1.3.8:
    resolution: {integrity: sha512-test}

  /body-parser@1.20.3:
    resolution: {integrity: sha512-test}
    dependencies:
      qs: 6.13.0

  /express@4.21.0:
    resolution: {integrity: sha512-test}
    dependencies:
      accepts: 1.3.8
      body-parser: 1.20.3

  /qs@6.13.0:
    resolution: {integrity: sha512-test}
"#,
        )
        .unwrap();

        let bom = build_sbom(dir.path()).unwrap();

        // express should be a root dependency
        let root = bom
            .dependencies
            .iter()
            .find(|dep| dep.ref_ == bom.metadata.component.bom_ref)
            .expect("root dependency node");
        assert!(
            root.depends_on
                .iter()
                .any(|dep| dep == "pkg:npm/express@4.21.0"),
            "express should be a root dependency"
        );

        // express should depend on accepts and body-parser (transitive edges)
        let express_dep = bom
            .dependencies
            .iter()
            .find(|dep| dep.ref_ == "pkg:npm/express@4.21.0")
            .expect("express dependency node");
        assert!(
            express_dep
                .depends_on
                .iter()
                .any(|dep| dep == "pkg:npm/accepts@1.3.8"),
            "express should depend on accepts"
        );
        assert!(
            express_dep
                .depends_on
                .iter()
                .any(|dep| dep == "pkg:npm/body-parser@1.20.3"),
            "express should depend on body-parser"
        );

        // body-parser should depend on qs (second-level transitive)
        let body_parser_dep = bom
            .dependencies
            .iter()
            .find(|dep| dep.ref_ == "pkg:npm/body-parser@1.20.3")
            .expect("body-parser dependency node");
        assert!(
            body_parser_dep
                .depends_on
                .iter()
                .any(|dep| dep == "pkg:npm/qs@6.13.0"),
            "body-parser should depend on qs"
        );
    }
}
