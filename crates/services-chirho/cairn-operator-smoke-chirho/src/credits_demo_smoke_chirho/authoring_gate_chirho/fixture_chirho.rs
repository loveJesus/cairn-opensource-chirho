// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Captures emitted node artifacts once and executes complete fixtures against those exact bytes.

use super::super::types_chirho::AuthoringGateArtifactDispositionChirho;
use anyhow::{bail, Context, Result};
use cairn_chirho::{
    app_model_chirho::{
        AppSourceManifestChirho, AppSourceNodeSourceChirho, APP_SOURCE_MANIFEST_SCHEMA_CHIRHO,
    },
    app_source_manifest_chirho::AppSourceCapturedNodeArtifactChirho,
    cas_chirho,
    runner_chirho::run_node_bytes_with_limits_chirho,
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const NODE_FIXTURE_SCHEMA_CHIRHO: &str = "tree-build-node-fixture-v1-chirho";
const MAX_FIXTURE_SPEC_BYTES_CHIRHO: u64 = 64 * 1024;
const MAX_FIXTURE_INPUT_BYTES_CHIRHO: u64 = 1024 * 1024;
const MAX_NODE_ARTIFACT_BYTES_CHIRHO: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct CapturedNodeArtifactChirho {
    pub node_id_chirho: String,
    pub node_identities_chirho: BTreeSet<String>,
    pub entry_chirho: String,
    pub artifact_path_chirho: PathBuf,
    pub artifact_blake3_chirho: String,
    pub bytes_chirho: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct ExactFixtureReportChirho {
    pub fixture_count_chirho: usize,
    pub pure_node_count_chirho: usize,
    pub dispositions_chirho: Vec<AuthoringGateArtifactDispositionChirho>,
}

pub(super) fn parse_emitted_manifest_chirho(
    emit_bytes_chirho: &[u8],
) -> Result<AppSourceManifestChirho> {
    let manifest_chirho: AppSourceManifestChirho =
        serde_json::from_slice(emit_bytes_chirho).context("parse emitted app-source manifest")?;
    if manifest_chirho.schema_chirho != APP_SOURCE_MANIFEST_SCHEMA_CHIRHO {
        bail!(
            "emitted app-source manifest used unsupported schema '{}'",
            manifest_chirho.schema_chirho
        );
    }
    Ok(manifest_chirho)
}

pub(super) fn capture_emitted_node_artifacts_chirho(
    app_root_chirho: &Path,
    target_dir_chirho: &Path,
    manifest_chirho: &AppSourceManifestChirho,
) -> Result<Vec<CapturedNodeArtifactChirho>> {
    let mut artifacts_chirho = Vec::new();
    let mut artifact_paths_chirho = BTreeSet::new();
    for node_chirho in &manifest_chirho.nodes_chirho {
        let pure_chirho = node_chirho.capabilities_chirho.is_empty();
        let node_identities_chirho = if pure_chirho {
            emitted_node_identities_chirho(
                manifest_chirho,
                &node_chirho.id_chirho,
                &node_chirho.name_chirho,
            )?
        } else {
            BTreeSet::new()
        };
        let (artifact_path_chirho, actual_path_chirho) = match &node_chirho.source_chirho {
            AppSourceNodeSourceChirho::PathChirho { path_chirho } => {
                validate_relative_fixture_path_chirho(path_chirho, "emitted node artifact")?;
                let actual_chirho = confined_regular_file_chirho(
                    app_root_chirho,
                    path_chirho,
                    "emitted node artifact",
                )?;
                (path_chirho.clone(), actual_chirho)
            }
            AppSourceNodeSourceChirho::CargoExampleChirho {
                artifact_path_chirho,
                target_chirho,
                ..
            } => {
                validate_relative_fixture_path_chirho(
                    artifact_path_chirho,
                    "emitted cargo artifact",
                )?;
                let target_chirho = target_chirho.as_deref().unwrap_or("wasm32-unknown-unknown");
                let artifact_name_chirho = artifact_path_chirho.file_name().ok_or_else(|| {
                    anyhow::anyhow!(
                        "emitted cargo artifact '{}' has no file name",
                        artifact_path_chirho.display()
                    )
                })?;
                (
                    artifact_path_chirho.clone(),
                    target_dir_chirho
                        .join(target_chirho)
                        .join("debug")
                        .join("examples")
                        .join(artifact_name_chirho),
                )
            }
            _ if pure_chirho => {
                bail!(
                    "emitted pure node '{}' has no fixture-testable path or cargo artifact",
                    node_chirho.id_chirho
                )
            }
            _ => continue,
        };
        if !artifact_paths_chirho.insert(artifact_path_chirho.clone()) {
            bail!(
                "emitted nodes repeat artifact path '{}'; one artifact path must identify one \
                 promoted byte vector",
                artifact_path_chirho.display()
            );
        }
        let metadata_chirho =
            std::fs::symlink_metadata(&actual_path_chirho).with_context(|| {
                format!(
                    "inspect emitted artifact output {}",
                    actual_path_chirho.display()
                )
            })?;
        if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_file() {
            bail!(
                "emitted artifact output {} is not a regular non-symlink file",
                actual_path_chirho.display()
            );
        }
        let bytes_chirho = read_bounded_chirho(
            &actual_path_chirho,
            "emitted node artifact",
            MAX_NODE_ARTIFACT_BYTES_CHIRHO,
        )?;
        let entry_chirho = node_chirho
            .entry_chirho
            .clone()
            .unwrap_or_else(|| node_chirho.name_chirho.clone());
        artifacts_chirho.push(CapturedNodeArtifactChirho {
            node_id_chirho: node_chirho.id_chirho.clone(),
            node_identities_chirho,
            entry_chirho,
            artifact_path_chirho,
            artifact_blake3_chirho: hash_bytes_chirho(&bytes_chirho),
            bytes_chirho,
        });
    }
    if artifacts_chirho
        .iter()
        .filter(|artifact_chirho| !artifact_chirho.node_identities_chirho.is_empty())
        .count()
        == 0
    {
        bail!("emitted manifest contains no fixture-testable pure node artifacts");
    }
    Ok(artifacts_chirho)
}

pub(super) fn prepared_artifacts_chirho(
    artifacts_chirho: &[CapturedNodeArtifactChirho],
) -> Vec<AppSourceCapturedNodeArtifactChirho> {
    artifacts_chirho
        .iter()
        .map(|artifact_chirho| AppSourceCapturedNodeArtifactChirho {
            artifact_path_chirho: artifact_chirho.artifact_path_chirho.clone(),
            artifact_blake3_chirho: artifact_chirho.artifact_blake3_chirho.clone(),
            bytes_chirho: artifact_chirho.bytes_chirho.clone(),
        })
        .collect()
}

pub(super) fn run_exact_node_fixtures_chirho(
    app_root_chirho: &Path,
    artifacts_chirho: &[CapturedNodeArtifactChirho],
) -> Result<ExactFixtureReportChirho> {
    let fixture_paths_chirho = find_fixture_paths_chirho(app_root_chirho)?;
    if fixture_paths_chirho.is_empty() {
        bail!("credits-demo node fixtures were empty");
    }
    let mut artifact_indexes_chirho: BTreeMap<PathBuf, usize> = BTreeMap::new();
    for (index_chirho, artifact_chirho) in artifacts_chirho.iter().enumerate() {
        artifact_indexes_chirho.insert(artifact_chirho.artifact_path_chirho.clone(), index_chirho);
    }
    let mut execution_counts_chirho = vec![0_usize; artifacts_chirho.len()];
    for fixture_path_chirho in &fixture_paths_chirho {
        let fixture_bytes_chirho = read_bounded_chirho(
            fixture_path_chirho,
            "node fixture",
            MAX_FIXTURE_SPEC_BYTES_CHIRHO,
        )?;
        let fixture_text_chirho = std::str::from_utf8(&fixture_bytes_chirho)
            .with_context(|| format!("fixture {} is not UTF-8", fixture_path_chirho.display()))?;
        let fixture_chirho: NodeFixtureSpecChirho = toml::from_str(fixture_text_chirho)
            .with_context(|| format!("parse node fixture {}", fixture_path_chirho.display()))?;
        if fixture_chirho.schema_chirho != NODE_FIXTURE_SCHEMA_CHIRHO {
            bail!(
                "fixture '{}' used schema '{}', expected '{}'",
                fixture_chirho.fixture_chirho,
                fixture_chirho.schema_chirho,
                NODE_FIXTURE_SCHEMA_CHIRHO
            );
        }
        validate_relative_fixture_path_chirho(&fixture_chirho.wasm_chirho, "fixture WASM")?;
        let artifact_index_chirho = artifact_indexes_chirho
            .get(&fixture_chirho.wasm_chirho)
            .copied()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "fixture '{}' references foreign WASM path '{}'",
                    fixture_chirho.fixture_chirho,
                    fixture_chirho.wasm_chirho.display()
                )
            })?;
        let artifact_chirho = &artifacts_chirho[artifact_index_chirho];
        if artifact_chirho.node_identities_chirho.is_empty() {
            bail!(
                "fixture '{}' targets capability-bearing node artifact '{}'",
                fixture_chirho.fixture_chirho,
                fixture_chirho.wasm_chirho.display()
            );
        }
        if !artifact_chirho
            .node_identities_chirho
            .contains(&fixture_chirho.node_chirho)
        {
            bail!(
                "fixture '{}' declares foreign node identity '{}' for emitted node '{}'",
                fixture_chirho.fixture_chirho,
                fixture_chirho.node_chirho,
                artifact_chirho.node_id_chirho
            );
        }
        if fixture_chirho.entry_chirho != artifact_chirho.entry_chirho {
            bail!(
                "fixture '{}' entry '{}' does not match emitted entry '{}'",
                fixture_chirho.fixture_chirho,
                fixture_chirho.entry_chirho,
                artifact_chirho.entry_chirho
            );
        }
        if !is_hex_hash_chirho(&fixture_chirho.expected_output_blake3_chirho) {
            bail!(
                "fixture '{}' expected_output_blake3_chirho is not a 64-hex digest",
                fixture_chirho.fixture_chirho
            );
        }
        let input_path_chirho = confined_regular_file_chirho(
            app_root_chirho,
            &fixture_chirho.input_chirho,
            "fixture input",
        )?;
        let expected_path_chirho = confined_regular_file_chirho(
            app_root_chirho,
            &fixture_chirho.expected_output_chirho,
            "fixture expected output",
        )?;
        let input_bytes_chirho = read_bounded_chirho(
            &input_path_chirho,
            "fixture input",
            MAX_FIXTURE_INPUT_BYTES_CHIRHO,
        )?;
        let expected_bytes_chirho = read_bounded_chirho(
            &expected_path_chirho,
            "fixture expected output",
            fixture_chirho.max_output_bytes_chirho as u64,
        )?;
        if hash_bytes_chirho(&expected_bytes_chirho) != fixture_chirho.expected_output_blake3_chirho
        {
            bail!(
                "fixture '{}' expected output bytes do not match its declared digest",
                fixture_chirho.fixture_chirho
            );
        }
        let outcome_chirho = run_node_bytes_with_limits_chirho(
            &artifact_chirho.bytes_chirho,
            &fixture_chirho.entry_chirho,
            &input_bytes_chirho,
            fixture_chirho.fuel_limit_chirho,
            fixture_chirho.max_output_bytes_chirho,
            fixture_chirho.max_memory_bytes_chirho,
        )
        .with_context(|| {
            format!(
                "run fixture '{}' against captured artifact {}",
                fixture_chirho.fixture_chirho, artifact_chirho.artifact_blake3_chirho
            )
        })?;
        let actual_chirho = hash_bytes_chirho(&outcome_chirho.output_chirho);
        if actual_chirho != fixture_chirho.expected_output_blake3_chirho {
            bail!(
                "fixture '{}' output digest mismatch: expected {}, actual {}",
                fixture_chirho.fixture_chirho,
                fixture_chirho.expected_output_blake3_chirho,
                actual_chirho
            );
        }
        execution_counts_chirho[artifact_index_chirho] += 1;
    }

    let mut dispositions_chirho = Vec::new();
    for (index_chirho, artifact_chirho) in artifacts_chirho.iter().enumerate() {
        if artifact_chirho.node_identities_chirho.is_empty() {
            continue;
        }
        let fixture_count_chirho = execution_counts_chirho[index_chirho];
        if fixture_count_chirho == 0 {
            bail!(
                "emitted pure node '{}' artifact '{}' has no fixture disposition",
                artifact_chirho.node_id_chirho,
                artifact_chirho.artifact_path_chirho.display()
            );
        }
        let node_identity_chirho = artifact_chirho
            .node_identities_chirho
            .iter()
            .next()
            .expect("pure artifacts carry at least one identity")
            .clone();
        dispositions_chirho.push(AuthoringGateArtifactDispositionChirho {
            node_id_chirho: artifact_chirho.node_id_chirho.clone(),
            node_identity_chirho,
            artifact_path_chirho: path_text_chirho(&artifact_chirho.artifact_path_chirho),
            artifact_blake3_chirho: artifact_chirho.artifact_blake3_chirho.clone(),
            artifact_bytes_chirho: artifact_chirho.bytes_chirho.len(),
            fixture_count_chirho,
            disposition_chirho: "fixture-executed-exact-bytes-chirho",
        });
    }
    dispositions_chirho.sort_by(|left_chirho, right_chirho| {
        left_chirho.node_id_chirho.cmp(&right_chirho.node_id_chirho)
    });
    Ok(ExactFixtureReportChirho {
        fixture_count_chirho: fixture_paths_chirho.len(),
        pure_node_count_chirho: dispositions_chirho.len(),
        dispositions_chirho,
    })
}

fn emitted_node_identities_chirho(
    manifest_chirho: &AppSourceManifestChirho,
    node_id_chirho: &str,
    node_name_chirho: &str,
) -> Result<BTreeSet<String>> {
    let mut identities_chirho = BTreeSet::new();
    for module_chirho in &manifest_chirho.modules_chirho {
        let dag_chirho = manifest_chirho
            .dags_chirho
            .iter()
            .find(|dag_chirho| dag_chirho.id_chirho == module_chirho.dag_chirho)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "emitted module '{}' references missing DAG '{}'",
                    module_chirho.id_chirho,
                    module_chirho.dag_chirho
                )
            })?;
        if dag_chirho
            .nodes_chirho
            .iter()
            .any(|member_chirho| member_chirho == node_id_chirho)
        {
            identities_chirho.insert(format!(
                "{}/{}",
                module_chirho.name_chirho, node_name_chirho
            ));
        }
    }
    if identities_chirho.is_empty() {
        bail!(
            "emitted pure node '{node_id_chirho}' is not reachable from an emitted module identity"
        );
    }
    Ok(identities_chirho)
}

#[derive(Deserialize)]
struct NodeFixtureSpecChirho {
    schema_chirho: String,
    fixture_chirho: String,
    node_chirho: String,
    wasm_chirho: PathBuf,
    entry_chirho: String,
    input_chirho: PathBuf,
    expected_output_chirho: PathBuf,
    expected_output_blake3_chirho: String,
    fuel_limit_chirho: u64,
    max_output_bytes_chirho: usize,
    max_memory_bytes_chirho: usize,
}

fn find_fixture_paths_chirho(app_root_chirho: &Path) -> Result<Vec<PathBuf>> {
    let fixture_root_chirho = app_root_chirho.join("fixtures_chirho/node-tests-chirho");
    let metadata_chirho = std::fs::symlink_metadata(&fixture_root_chirho).with_context(|| {
        format!(
            "inspect node fixture directory {}",
            fixture_root_chirho.display()
        )
    })?;
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_dir() {
        bail!("node fixture root is not a regular directory");
    }
    let mut fixtures_chirho = Vec::new();
    collect_fixture_paths_chirho(&fixture_root_chirho, &mut fixtures_chirho)?;
    fixtures_chirho.sort();
    Ok(fixtures_chirho)
}

fn collect_fixture_paths_chirho(
    directory_chirho: &Path,
    fixtures_chirho: &mut Vec<PathBuf>,
) -> Result<()> {
    let mut entries_chirho = std::fs::read_dir(directory_chirho)
        .with_context(|| format!("read fixture directory {}", directory_chirho.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("collect fixture directory {}", directory_chirho.display()))?;
    entries_chirho.sort_by_key(|entry_chirho| entry_chirho.file_name());
    for entry_chirho in entries_chirho {
        let path_chirho = entry_chirho.path();
        let metadata_chirho = std::fs::symlink_metadata(&path_chirho)
            .with_context(|| format!("inspect fixture entry {}", path_chirho.display()))?;
        if metadata_chirho.file_type().is_symlink() {
            bail!("fixture tree contains symlink {}", path_chirho.display());
        }
        if metadata_chirho.is_dir() {
            collect_fixture_paths_chirho(&path_chirho, fixtures_chirho)?;
        } else if metadata_chirho.is_file()
            && path_chirho
                .extension()
                .and_then(|extension_chirho| extension_chirho.to_str())
                == Some("toml")
        {
            fixtures_chirho.push(path_chirho);
        }
    }
    Ok(())
}

fn confined_regular_file_chirho(
    app_root_chirho: &Path,
    relative_chirho: &Path,
    label_chirho: &str,
) -> Result<PathBuf> {
    validate_relative_fixture_path_chirho(relative_chirho, label_chirho)?;
    let app_root_canonical_chirho = app_root_chirho
        .canonicalize()
        .with_context(|| format!("canonicalize app root {}", app_root_chirho.display()))?;
    let path_chirho = app_root_chirho.join(relative_chirho);
    let metadata_chirho = std::fs::symlink_metadata(&path_chirho)
        .with_context(|| format!("inspect {label_chirho} {}", relative_chirho.display()))?;
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_file() {
        bail!(
            "{label_chirho} '{}' is not a regular non-symlink file",
            relative_chirho.display()
        );
    }
    let canonical_chirho = path_chirho
        .canonicalize()
        .with_context(|| format!("canonicalize {label_chirho} {}", relative_chirho.display()))?;
    if !canonical_chirho.starts_with(&app_root_canonical_chirho) {
        bail!(
            "{label_chirho} '{}' escapes the immutable app root",
            relative_chirho.display()
        );
    }
    Ok(canonical_chirho)
}

fn validate_relative_fixture_path_chirho(path_chirho: &Path, label_chirho: &str) -> Result<()> {
    if path_chirho.as_os_str().is_empty() || path_chirho.is_absolute() {
        bail!(
            "{label_chirho} '{}' must be a nonempty relative path",
            path_chirho.display()
        );
    }
    if path_chirho
        .components()
        .any(|component_chirho| !matches!(component_chirho, Component::Normal(_)))
    {
        bail!(
            "{label_chirho} '{}' contains an escaping or non-normal component",
            path_chirho.display()
        );
    }
    Ok(())
}

fn read_bounded_chirho(path_chirho: &Path, label_chirho: &str, max_chirho: u64) -> Result<Vec<u8>> {
    let file_chirho = std::fs::File::open(path_chirho)
        .with_context(|| format!("open {label_chirho} {}", path_chirho.display()))?;
    let mut bytes_chirho = Vec::new();
    file_chirho
        .take(max_chirho.saturating_add(1))
        .read_to_end(&mut bytes_chirho)
        .with_context(|| format!("read {label_chirho} {}", path_chirho.display()))?;
    if bytes_chirho.len() as u64 > max_chirho {
        bail!(
            "{label_chirho} {} exceeds the {} byte limit",
            path_chirho.display(),
            max_chirho
        );
    }
    Ok(bytes_chirho)
}

fn hash_bytes_chirho(bytes_chirho: &[u8]) -> String {
    cas_chirho::hash_chirho(bytes_chirho).0
}

fn is_hex_hash_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit())
}

fn path_text_chirho(path_chirho: &Path) -> String {
    path_chirho.to_string_lossy().replace('\\', "/")
}
