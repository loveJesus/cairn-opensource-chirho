// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The single home of the app-source bounded-read / path-confinement law: the byte bounds, the
//! bounded reader, and the read-only-against-the-ROOT prepared-input preflight whose byte set the write phase
//! consumes (#6077-1/#6085/#6090 — the preflight→write TOCTOU is structurally closed for flows
//! that use it; a symlink or app-root escape refuses before any mutation).
//!
//! Workflow: `spec-chirho/workflows-chirho/reversible-postgres-effect-chirho/credits-demo-localphaseb-smoke-chirho.md`.

use super::require_app_source_manifest_v1_chirho;
use anyhow::{bail, Context, Result};
use cairn_model_app_chirho::{
    resolve_app_source_path_chirho, AppSourceAssetSourceChirho, AppSourceNodeSourceChirho,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

pub(super) const MAX_APP_SOURCE_MANIFEST_BYTES_CHIRHO: u64 = 1024 * 1024;
pub(super) const MAX_APP_SOURCE_NODE_ARTIFACT_BYTES_CHIRHO: u64 = 64 * 1024 * 1024;
pub(super) const MAX_APP_SOURCE_STATIC_ASSET_BYTES_CHIRHO: u64 = 1024 * 1024;

pub(super) fn read_bounded_bytes_chirho(
    path_chirho: &Path,
    label_chirho: &str,
    max_bytes_chirho: u64,
) -> Result<Vec<u8>> {
    // The READ ITSELF is bounded (#6109): a metadata-then-unbounded-read pair would let a file
    // that grows or is swapped between the two calls bypass the byte bound and allocate
    // arbitrarily. `take(max+1)` caps both allocation and bytes; more than `max` read = refuse.
    use std::io::Read;
    let limit_chirho = max_bytes_chirho
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("{label_chirho} byte bound overflow"))?;
    let file_chirho = std::fs::File::open(path_chirho)
        .with_context(|| format!("open {label_chirho} {}", path_chirho.display()))?;
    let mut bytes_chirho = Vec::new();
    file_chirho
        .take(limit_chirho)
        .read_to_end(&mut bytes_chirho)
        .with_context(|| format!("read {label_chirho} {}", path_chirho.display()))?;
    let read_len_chirho = u64::try_from(bytes_chirho.len())
        .map_err(|_error_chirho| anyhow::anyhow!("{label_chirho} read length overflow"))?;
    if read_len_chirho > max_bytes_chirho {
        bail!(
            "{label_chirho} {} exceeds the {} byte limit",
            path_chirho.display(),
            max_bytes_chirho
        );
    }
    Ok(bytes_chirho)
}

/// The PREPARED byte set for one app-source manifest's path-backed inputs (#6085/#6090): every
/// referenced filesystem input read ONCE at read-only preflight — typed-parsed manifest, each
/// path resolved and REQUIRED to canonicalize inside the canonical app root with no symlink at
/// the final component, the SAME byte bounds as the write path — so the write phase can consume
/// THESE bytes and never touch the filesystem for them again (the preflight→write TOCTOU is
/// structurally closed for flows that use it). Fields are PRIVATE;
/// [`preflight_app_source_manifest_inputs_chirho`] is the sole producer.
pub struct AppSourcePreparedInputsChirho {
    inputs_chirho: BTreeMap<PathBuf, Vec<u8>>,
    /// The EXACT manifest bytes + canonical base this set was prepared for (#6102): the prepared
    /// build verifies BOTH before any root write, so prepared-A/build-B or a substituted base
    /// refuses by construction.
    raw_manifest_digest_chirho: blake3::Hash,
    canonical_base_chirho: PathBuf,
}

/// One node artifact captured by a caller that built and tested it before the app-source write
/// phase. The digest makes the byte identity explicit at this API boundary; preflight verifies it
/// before admitting the bytes into the prepared set.
pub struct AppSourceCapturedNodeArtifactChirho {
    pub artifact_path_chirho: PathBuf,
    pub artifact_blake3_chirho: String,
    pub bytes_chirho: Vec<u8>,
}

impl AppSourcePreparedInputsChirho {
    pub(super) fn get_chirho(&self, resolved_chirho: &Path) -> Option<&[u8]> {
        self.inputs_chirho
            .get(resolved_chirho)
            .map(|bytes_chirho| bytes_chirho.as_slice())
    }

    /// Refuse unless this prepared set was built for EXACTLY these manifest bytes and base.
    pub(super) fn verify_binding_chirho(
        &self,
        manifest_bytes_chirho: &[u8],
        base_chirho: &Path,
    ) -> Result<()> {
        if blake3::hash(manifest_bytes_chirho) != self.raw_manifest_digest_chirho {
            bail!("prepared input set was built for different manifest bytes");
        }
        let canonical_chirho = base_chirho
            .canonicalize()
            .with_context(|| format!("canonicalize app root {}", base_chirho.display()))?;
        if canonical_chirho != self.canonical_base_chirho {
            bail!("prepared input set was built for a different app root");
        }
        Ok(())
    }
}

/// READ-ONLY preflight of an app-source manifest's path-backed inputs (#6077-1/#6085): the SAME
/// typed parse the candidate build uses, canonical non-symlink app-root containment per referenced
/// file, and the SAME bounded reads as the write path — with ZERO authoritative/root writes (no
/// cas_add; the cargo-example build runs PRE-mutation into its build directory and the exact
/// artifact bytes are captured). Cargo-example nodes validate their SOURCE coordinates (and
/// `examples/<name>.rs`) since cargo-example artifacts are PREBUILT here and the write phase consumes their exact bytes. Returns the
/// prepared byte set the write phase consumes.
pub fn preflight_app_source_manifest_inputs_chirho(
    base_chirho: &Path,
    manifest_bytes_chirho: &[u8],
) -> Result<AppSourcePreparedInputsChirho> {
    preflight_app_source_manifest_inputs_inner_chirho(base_chirho, manifest_bytes_chirho, None)
}

/// Prepare an app-source manifest from node artifacts already built and fixture-tested by a
/// stronger caller. Every path/cargo node in the manifest must have exactly one matching captured
/// artifact path, every supplied digest must match its bytes, and foreign captures are refused.
/// The resulting write phase consumes these bytes without rebuilding or rereading node artifacts.
pub fn preflight_app_source_manifest_inputs_with_captured_node_artifacts_chirho(
    base_chirho: &Path,
    manifest_bytes_chirho: &[u8],
    captured_artifacts_chirho: &[AppSourceCapturedNodeArtifactChirho],
) -> Result<AppSourcePreparedInputsChirho> {
    let mut captured_by_path_chirho = BTreeMap::new();
    for artifact_chirho in captured_artifacts_chirho {
        validate_relative_artifact_path_chirho(&artifact_chirho.artifact_path_chirho)?;
        if artifact_chirho.bytes_chirho.len() as u64 > MAX_APP_SOURCE_NODE_ARTIFACT_BYTES_CHIRHO {
            bail!(
                "captured node artifact '{}' exceeds the {} byte limit",
                artifact_chirho.artifact_path_chirho.display(),
                MAX_APP_SOURCE_NODE_ARTIFACT_BYTES_CHIRHO
            );
        }
        let actual_digest_chirho = blake3::hash(&artifact_chirho.bytes_chirho)
            .to_hex()
            .to_string();
        if actual_digest_chirho != artifact_chirho.artifact_blake3_chirho {
            bail!(
                "captured node artifact '{}' bytes do not match its supplied BLAKE3 digest",
                artifact_chirho.artifact_path_chirho.display()
            );
        }
        if captured_by_path_chirho
            .insert(
                artifact_chirho.artifact_path_chirho.clone(),
                artifact_chirho,
            )
            .is_some()
        {
            bail!(
                "duplicate captured node artifact path '{}'",
                artifact_chirho.artifact_path_chirho.display()
            );
        }
    }
    preflight_app_source_manifest_inputs_inner_chirho(
        base_chirho,
        manifest_bytes_chirho,
        Some(&captured_by_path_chirho),
    )
}

fn preflight_app_source_manifest_inputs_inner_chirho(
    base_chirho: &Path,
    manifest_bytes_chirho: &[u8],
    captured_by_path_chirho: Option<&BTreeMap<PathBuf, &AppSourceCapturedNodeArtifactChirho>>,
) -> Result<AppSourcePreparedInputsChirho> {
    let manifest_text_chirho = std::str::from_utf8(manifest_bytes_chirho)
        .context("app source manifest bytes were not valid UTF-8")?;
    let manifest_chirho =
        require_app_source_manifest_v1_chirho(serde_json::from_str(manifest_text_chirho)?)?;
    // The app root ITSELF is a path-backed input (#6098): a symlink root refuses before any
    // canonicalization-based containment could be laundered through it.
    let root_metadata_chirho = std::fs::symlink_metadata(base_chirho)
        .with_context(|| format!("app root {} is missing", base_chirho.display()))?;
    if root_metadata_chirho.file_type().is_symlink() {
        bail!("app root {} is a symlink (refused)", base_chirho.display());
    }
    if !root_metadata_chirho.is_dir() {
        bail!("app root {} is not a directory", base_chirho.display());
    }
    let canonical_base_chirho = base_chirho
        .canonicalize()
        .with_context(|| format!("canonicalize app root {}", base_chirho.display()))?;
    let mut inputs_chirho: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
    let mut consumed_captures_chirho = BTreeSet::new();
    for asset_chirho in &manifest_chirho.assets_chirho {
        if let AppSourceAssetSourceChirho::PathChirho { path_chirho } = &asset_chirho.source_chirho
        {
            preflight_bounded_input_chirho(
                &canonical_base_chirho,
                base_chirho,
                path_chirho,
                MAX_APP_SOURCE_STATIC_ASSET_BYTES_CHIRHO,
                "app static asset",
                &mut inputs_chirho,
            )?;
        }
    }
    for node_chirho in &manifest_chirho.nodes_chirho {
        match &node_chirho.source_chirho {
            AppSourceNodeSourceChirho::PathChirho { path_chirho } => {
                validate_relative_artifact_path_chirho(path_chirho)?;
                let (resolved_chirho, canonical_chirho) = preflight_input_path_chirho(
                    &canonical_base_chirho,
                    base_chirho,
                    path_chirho,
                    "node artifact",
                )?;
                let bytes_chirho = match captured_by_path_chirho {
                    Some(captured_chirho) => {
                        let artifact_chirho =
                            captured_chirho.get(path_chirho).ok_or_else(|| {
                                anyhow::anyhow!(
                                    "node artifact '{}' is missing from the captured artifact set",
                                    path_chirho.display()
                                )
                            })?;
                        consumed_captures_chirho.insert(path_chirho.clone());
                        artifact_chirho.bytes_chirho.clone()
                    }
                    None => read_bounded_bytes_chirho(
                        &canonical_chirho,
                        "node artifact",
                        MAX_APP_SOURCE_NODE_ARTIFACT_BYTES_CHIRHO,
                    )?,
                };
                inputs_chirho.insert(resolved_chirho, bytes_chirho);
            }
            AppSourceNodeSourceChirho::CargoExampleChirho {
                package_chirho,
                example_chirho,
                features_chirho,
                manifest_path_chirho,
                target_chirho,
                artifact_path_chirho,
            } => {
                validate_relative_artifact_path_chirho(artifact_path_chirho)?;
                let cargo_manifest_chirho = manifest_path_chirho
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("Cargo.toml"));
                preflight_bounded_input_chirho(
                    &canonical_base_chirho,
                    base_chirho,
                    &cargo_manifest_chirho,
                    MAX_APP_SOURCE_MANIFEST_BYTES_CHIRHO,
                    "cargo manifest",
                    &mut inputs_chirho,
                )?;
                let example_source_chirho =
                    PathBuf::from("examples").join(format!("{example_chirho}.rs"));
                preflight_bounded_input_chirho(
                    &canonical_base_chirho,
                    base_chirho,
                    &example_source_chirho,
                    MAX_APP_SOURCE_NODE_ARTIFACT_BYTES_CHIRHO,
                    "cargo example source",
                    &mut inputs_chirho,
                )?;
                let artifact_bytes_chirho = match captured_by_path_chirho {
                    Some(captured_chirho) => {
                        let artifact_chirho =
                            captured_chirho.get(artifact_path_chirho).ok_or_else(|| {
                                anyhow::anyhow!(
                                    "cargo example artifact '{}' is missing from the captured \
                                     artifact set",
                                    artifact_path_chirho.display()
                                )
                            })?;
                        consumed_captures_chirho.insert(artifact_path_chirho.clone());
                        artifact_chirho.bytes_chirho.clone()
                    }
                    None => {
                        // #6098-1: PREBUILD the cargo example BEFORE any mutation and capture the
                        // exact artifact bytes. The prepared map keys those bytes by the manifest's
                        // declared path, independent of the isolated target directory used to
                        // produce them.
                        let artifact_built_chirho = run_cargo_example_build_chirho(
                            base_chirho,
                            package_chirho,
                            example_chirho,
                            features_chirho,
                            manifest_path_chirho.as_deref(),
                            target_chirho.as_deref().unwrap_or("wasm32-unknown-unknown"),
                            artifact_path_chirho,
                        )?;
                        read_bounded_bytes_chirho(
                            &artifact_built_chirho,
                            "cargo example artifact",
                            MAX_APP_SOURCE_NODE_ARTIFACT_BYTES_CHIRHO,
                        )?
                    }
                };
                inputs_chirho.insert(
                    resolve_app_source_path_chirho(base_chirho, artifact_path_chirho),
                    artifact_bytes_chirho,
                );
            }
            _ => {}
        }
    }
    if let Some(captured_chirho) = captured_by_path_chirho {
        let foreign_chirho: Vec<String> = captured_chirho
            .keys()
            .filter(|path_chirho| !consumed_captures_chirho.contains(*path_chirho))
            .map(|path_chirho| path_chirho.display().to_string())
            .collect();
        if !foreign_chirho.is_empty() {
            bail!(
                "captured artifact set contains path(s) not emitted by the manifest: {}",
                foreign_chirho.join(", ")
            );
        }
    }
    Ok(AppSourcePreparedInputsChirho {
        inputs_chirho,
        raw_manifest_digest_chirho: blake3::hash(manifest_bytes_chirho),
        canonical_base_chirho,
    })
}

/// One prepared input: resolve exactly as the write path does, refuse a symlink final component,
/// require canonical containment in the app root, and perform the SAME bounded read ONCE.
fn preflight_bounded_input_chirho(
    canonical_base_chirho: &Path,
    base_chirho: &Path,
    path_chirho: &Path,
    max_bytes_chirho: u64,
    label_chirho: &str,
    inputs_chirho: &mut BTreeMap<PathBuf, Vec<u8>>,
) -> Result<()> {
    let (resolved_chirho, canonical_chirho) = preflight_input_path_chirho(
        canonical_base_chirho,
        base_chirho,
        path_chirho,
        label_chirho,
    )?;
    // Read via the VALIDATED canonical pathname (#6109). Honest scope: File::open still follows
    // whatever that pathname holds at open time, so this narrows (not eliminates) the
    // check-to-open window; the invariant actually closed here is bounded allocation plus the
    // preflight→write TOCTOU (the write phase consumes THESE captured bytes).
    let bytes_chirho =
        read_bounded_bytes_chirho(&canonical_chirho, label_chirho, max_bytes_chirho)?;
    inputs_chirho.insert(resolved_chirho, bytes_chirho);
    Ok(())
}

fn preflight_input_path_chirho(
    canonical_base_chirho: &Path,
    base_chirho: &Path,
    path_chirho: &Path,
    label_chirho: &str,
) -> Result<(PathBuf, PathBuf)> {
    let resolved_chirho = resolve_app_source_path_chirho(base_chirho, path_chirho);
    let link_metadata_chirho = std::fs::symlink_metadata(&resolved_chirho).with_context(|| {
        format!(
            "{label_chirho} '{}' is missing under the app root",
            path_chirho.display()
        )
    })?;
    if link_metadata_chirho.file_type().is_symlink() {
        bail!(
            "{label_chirho} '{}' is a symlink (refused: checked-in app inputs only)",
            path_chirho.display()
        );
    }
    if !link_metadata_chirho.is_file() {
        bail!(
            "{label_chirho} '{}' is not a regular file",
            path_chirho.display()
        );
    }
    let canonical_chirho = resolved_chirho
        .canonicalize()
        .with_context(|| format!("canonicalize {label_chirho} '{}'", path_chirho.display()))?;
    if !canonical_chirho.starts_with(canonical_base_chirho) {
        bail!(
            "{label_chirho} '{}' escapes the canonical app root (refused)",
            path_chirho.display()
        );
    }
    Ok((resolved_chirho, canonical_chirho))
}

fn validate_relative_artifact_path_chirho(path_chirho: &Path) -> Result<()> {
    if path_chirho.as_os_str().is_empty() || path_chirho.is_absolute() {
        bail!(
            "node artifact path '{}' must be a nonempty relative path",
            path_chirho.display()
        );
    }
    if path_chirho
        .components()
        .any(|component_chirho| !matches!(component_chirho, Component::Normal(_)))
    {
        bail!(
            "node artifact path '{}' contains an escaping or non-normal component",
            path_chirho.display()
        );
    }
    Ok(())
}

pub(super) fn run_cargo_example_build_chirho(
    base_chirho: &Path,
    package_chirho: &str,
    example_chirho: &str,
    features_chirho: &[String],
    manifest_path_chirho: Option<&Path>,
    target_chirho: &str,
    declared_artifact_path_chirho: &Path,
) -> Result<PathBuf> {
    let cargo_target_dir_chirho = std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from);
    let mut command_chirho = cargo_example_build_command_chirho(
        base_chirho,
        package_chirho,
        example_chirho,
        features_chirho,
        manifest_path_chirho,
        target_chirho,
        cargo_target_dir_chirho.as_deref(),
    );
    let output_chirho = command_chirho
        .output()
        .with_context(|| "failed to run cargo for app source node")?;
    if !output_chirho.status.success() {
        bail!(
            "cargo build failed for example '{}': {}",
            example_chirho,
            String::from_utf8_lossy(&output_chirho.stderr)
        );
    }
    cargo_example_artifact_path_chirho(
        base_chirho,
        declared_artifact_path_chirho,
        target_chirho,
        cargo_target_dir_chirho.as_deref(),
    )
}

pub(super) fn cargo_example_build_command_chirho(
    base_chirho: &Path,
    package_chirho: &str,
    example_chirho: &str,
    features_chirho: &[String],
    manifest_path_chirho: Option<&Path>,
    target_chirho: &str,
    cargo_target_dir_chirho: Option<&Path>,
) -> Command {
    let mut command_chirho = Command::new("cargo");
    command_chirho
        .arg("build")
        .arg("--locked")
        .arg("-p")
        .arg(package_chirho)
        .arg("--example")
        .arg(example_chirho)
        .arg("--target")
        .arg(target_chirho);
    if let Some(cargo_target_dir_chirho) = cargo_target_dir_chirho {
        command_chirho
            .arg("--target-dir")
            .arg(cargo_target_dir_chirho);
    }
    if !features_chirho.is_empty() {
        command_chirho
            .arg("--features")
            .arg(features_chirho.join(","));
    }
    if let Some(manifest_path_chirho) = manifest_path_chirho {
        command_chirho
            .arg("--manifest-path")
            .arg(resolve_app_source_path_chirho(
                base_chirho,
                manifest_path_chirho,
            ));
    }
    command_chirho
}

pub(super) fn cargo_example_artifact_path_chirho(
    base_chirho: &Path,
    declared_artifact_path_chirho: &Path,
    target_chirho: &str,
    cargo_target_dir_chirho: Option<&Path>,
) -> Result<PathBuf> {
    let Some(cargo_target_dir_chirho) = cargo_target_dir_chirho else {
        return Ok(resolve_app_source_path_chirho(
            base_chirho,
            declared_artifact_path_chirho,
        ));
    };
    let artifact_name_chirho = declared_artifact_path_chirho
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("cargo example artifact path has no file name"))?;
    Ok(cargo_target_dir_chirho
        .join(target_chirho)
        .join("debug")
        .join("examples")
        .join(artifact_name_chirho))
}
