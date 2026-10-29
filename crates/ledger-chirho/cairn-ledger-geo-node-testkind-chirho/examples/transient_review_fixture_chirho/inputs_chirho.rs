// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Captures bounded prebuilt node bytes before fixture birth, with no cargo or network preparation.

use anyhow::{ensure, Result};
use cairn_chirho::app_source_manifest_chirho::{
    preflight_app_source_manifest_inputs_with_captured_node_artifacts_chirho,
    AppSourceCapturedNodeArtifactChirho, AppSourcePreparedInputsChirho,
};
use cairn_model_app_chirho::{
    AppSourceAssetSourceChirho, AppSourceManifestChirho, AppSourceNodeSourceChirho,
};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

pub(super) struct InputsChirho {
    pub(super) bytes_chirho: Vec<u8>,
    pub(super) base_chirho: PathBuf,
    pub(super) prepared_chirho: AppSourcePreparedInputsChirho,
    pub(super) manifest_digest_chirho: String,
    pub(super) artifact_digest_chirho: String,
}

impl InputsChirho {
    pub(super) fn read_chirho(path_chirho: &Path) -> Result<Self> {
        let bytes_chirho = cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
            path_chirho,
            1024 * 1024,
        )?;
        let manifest_chirho: AppSourceManifestChirho = serde_json::from_slice(&bytes_chirho)?;
        ensure!(
            manifest_chirho.nodes_chirho.len() <= 256 && manifest_chirho.assets_chirho.len() <= 64,
            "fixture manifest bound"
        );
        let base_chirho = path_chirho
            .parent()
            .ok_or_else(|| anyhow::anyhow!("manifest parent"))?
            .canonicalize()?;
        let mut captures_chirho = BTreeMap::new();
        let mut total_chirho = 0;
        for node_chirho in &manifest_chirho.nodes_chirho {
            match &node_chirho.source_chirho {
                AppSourceNodeSourceChirho::PathChirho { path_chirho } => {
                    ensure!(
                        !path_chirho.is_absolute()
                            && path_chirho
                                .components()
                                .all(|part_chirho| matches!(part_chirho, Component::Normal(_))),
                        "fixture artifact path"
                    );
                    if captures_chirho.contains_key(path_chirho) {
                        continue;
                    }
                    let resolved_chirho = base_chirho.join(path_chirho);
                    ensure!(
                        resolved_chirho.canonicalize()?.starts_with(&base_chirho),
                        "fixture artifact escape"
                    );
                    let artifact_chirho =
                        cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
                            &resolved_chirho,
                            16 * 1024 * 1024,
                        )?;
                    total_chirho += artifact_chirho.len();
                    ensure!(
                        total_chirho <= 128 * 1024 * 1024,
                        "fixture artifact aggregate bound"
                    );
                    captures_chirho.insert(
                        path_chirho.clone(),
                        AppSourceCapturedNodeArtifactChirho {
                            artifact_path_chirho: path_chirho.clone(),
                            artifact_blake3_chirho: blake3::hash(&artifact_chirho)
                                .to_hex()
                                .to_string(),
                            bytes_chirho: artifact_chirho,
                        },
                    );
                }
                AppSourceNodeSourceChirho::BuiltinNodeTemplateChirho { .. }
                | AppSourceNodeSourceChirho::BuiltinPhiChirho { .. } => {}
                AppSourceNodeSourceChirho::CargoExampleChirho { .. }
                | AppSourceNodeSourceChirho::StoredNodeChirho { .. } => {
                    anyhow::bail!("fixture requires staged prebuilt inputs")
                }
            }
        }
        ensure!(
            manifest_chirho
                .assets_chirho
                .iter()
                .all(|asset_chirho| matches!(
                    asset_chirho.source_chirho,
                    AppSourceAssetSourceChirho::PathChirho { .. }
                )),
            "fixture assets must be staged"
        );
        let mut artifact_hash_chirho =
            blake3::Hasher::new_derive_key("transient-review-artifacts-v1-chirho");
        for (path_chirho, captured_chirho) in &captures_chirho {
            let path_bytes_chirho = path_chirho
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("artifact encoding"))?
                .as_bytes();
            artifact_hash_chirho.update(&(path_bytes_chirho.len() as u64).to_le_bytes());
            artifact_hash_chirho.update(path_bytes_chirho);
            artifact_hash_chirho.update(blake3::hash(&captured_chirho.bytes_chirho).as_bytes());
        }
        let captures_chirho: Vec<_> = captures_chirho.into_values().collect();
        let prepared_chirho =
            preflight_app_source_manifest_inputs_with_captured_node_artifacts_chirho(
                &base_chirho,
                &bytes_chirho,
                &captures_chirho,
            )?;
        Ok(Self {
            manifest_digest_chirho: blake3::hash(&bytes_chirho).to_hex().to_string(),
            artifact_digest_chirho: artifact_hash_chirho.finalize().to_hex().to_string(),
            bytes_chirho,
            base_chirho,
            prepared_chirho,
        })
    }
}
