// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Value-redacted custody posture for the six runtime ledger signer coordinates.

use crate::signer_chirho::HostLedgerSignerSecretRefsChirho;
use anyhow::Result;
use cairn_secret_chirho::secret_chirho::{list_secrets_chirho, SecretInfoChirho, SecretRefChirho};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::path::Path;

pub const HOST_LEDGER_SIGNER_CUSTODY_SCHEMA_V1_CHIRHO: &str =
    "host-ledger-signer-custody-v1-chirho";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostLedgerConfigCustodyRefusalChirho {
    SelectedRootUnavailableChirho,
    ConfigUnavailableChirho,
    ConfigNotRegularChirho,
    ConfigSymlinkChirho,
    ConfigModeTooBroadChirho,
    ConfigOwnerMismatchChirho,
}

impl fmt::Display for HostLedgerConfigCustodyRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::SelectedRootUnavailableChirho => "selected ledger host root is unavailable",
            Self::ConfigUnavailableChirho => "ledger host config is unavailable",
            Self::ConfigNotRegularChirho => "ledger host config is not a regular file",
            Self::ConfigSymlinkChirho => "ledger host config must not be a symlink",
            Self::ConfigModeTooBroadChirho => "ledger host config permissions are too broad",
            Self::ConfigOwnerMismatchChirho => {
                "ledger host config owner does not match the selected root owner"
            }
        })
    }
}

impl Error for HostLedgerConfigCustodyRefusalChirho {}

/// Verify the root-owned host block's file boundary without reading or writing its contents.
/// Parsing and root binding remain the config/CLI boundary's responsibility; this check owns only
/// regular-file, symlink, private-mode, and same-owner custody.
pub fn verify_host_ledger_config_custody_chirho(
    selected_root_chirho: &Path,
    config_path_chirho: &Path,
) -> Result<()> {
    let root_metadata_chirho =
        std::fs::symlink_metadata(selected_root_chirho).map_err(|_error_chirho| {
            HostLedgerConfigCustodyRefusalChirho::SelectedRootUnavailableChirho
        })?;
    let config_metadata_chirho = std::fs::symlink_metadata(config_path_chirho)
        .map_err(|_error_chirho| HostLedgerConfigCustodyRefusalChirho::ConfigUnavailableChirho)?;
    if config_metadata_chirho.file_type().is_symlink() {
        return Err(HostLedgerConfigCustodyRefusalChirho::ConfigSymlinkChirho.into());
    }
    if !config_metadata_chirho.is_file() {
        return Err(HostLedgerConfigCustodyRefusalChirho::ConfigNotRegularChirho.into());
    }
    if !private_config_mode_chirho(&config_metadata_chirho) {
        return Err(HostLedgerConfigCustodyRefusalChirho::ConfigModeTooBroadChirho.into());
    }
    if !same_owner_chirho(&root_metadata_chirho, &config_metadata_chirho) {
        return Err(HostLedgerConfigCustodyRefusalChirho::ConfigOwnerMismatchChirho.into());
    }
    Ok(())
}

#[cfg(unix)]
fn private_config_mode_chirho(metadata_chirho: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata_chirho.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn private_config_mode_chirho(_metadata_chirho: &std::fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn same_owner_chirho(left_chirho: &std::fs::Metadata, right_chirho: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left_chirho.uid() == right_chirho.uid()
}

#[cfg(not(unix))]
fn same_owner_chirho(_left_chirho: &std::fs::Metadata, _right_chirho: &std::fs::Metadata) -> bool {
    true
}

/// One redacted secret coordinate. No key bytes or public-key bytes are representable here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerSignerSecretPostureChirho {
    pub scope_chirho: String,
    pub secret_name_chirho: String,
    pub present_chirho: bool,
    pub exact_32_bytes_chirho: bool,
    pub value_redacted_chirho: bool,
    pub required_when_composed_chirho: bool,
}

/// The complete runtime signer custody view consumed by the root inventory in H2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostLedgerSignerCustodyInventoryChirho {
    pub schema_chirho: &'static str,
    pub journal_chirho: LedgerSignerSecretPostureChirho,
    pub config_chirho: LedgerSignerSecretPostureChirho,
    pub feeder_chirho: LedgerSignerSecretPostureChirho,
    pub kind_root_chirho: LedgerSignerSecretPostureChirho,
    pub effect_intent_chirho: LedgerSignerSecretPostureChirho,
    pub effect_terminal_chirho: LedgerSignerSecretPostureChirho,
    pub values_redacted_chirho: bool,
}

/// Inspect presence/size only. The function never resolves secret values.
///
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf6-regenesis-boundary-chirho.md`.
pub fn inspect_host_ledger_signer_custody_chirho(
    root_chirho: &Path,
    refs_chirho: &HostLedgerSignerSecretRefsChirho,
) -> Result<HostLedgerSignerCustodyInventoryChirho> {
    let entries_chirho = list_secrets_chirho(root_chirho)?;
    Ok(HostLedgerSignerCustodyInventoryChirho {
        schema_chirho: HOST_LEDGER_SIGNER_CUSTODY_SCHEMA_V1_CHIRHO,
        journal_chirho: posture_chirho(
            "ledger-journal-signer-secret-redacted-chirho",
            &refs_chirho.journal_chirho,
            &entries_chirho,
        ),
        config_chirho: posture_chirho(
            "ledger-config-signer-secret-redacted-chirho",
            &refs_chirho.config_chirho,
            &entries_chirho,
        ),
        feeder_chirho: posture_chirho(
            "ledger-feeder-signer-secret-redacted-chirho",
            &refs_chirho.feeder_chirho,
            &entries_chirho,
        ),
        kind_root_chirho: posture_chirho(
            "ledger-kind-root-signer-secret-redacted-chirho",
            &refs_chirho.kind_root_chirho,
            &entries_chirho,
        ),
        effect_intent_chirho: posture_chirho(
            "effect-intent-signer-secret-redacted-chirho",
            &refs_chirho.effect_intent_chirho,
            &entries_chirho,
        ),
        effect_terminal_chirho: posture_chirho(
            "effect-terminal-signer-secret-redacted-chirho",
            &refs_chirho.effect_terminal_chirho,
            &entries_chirho,
        ),
        values_redacted_chirho: true,
    })
}

fn posture_chirho(
    scope_chirho: &str,
    secret_ref_chirho: &SecretRefChirho,
    entries_chirho: &[SecretInfoChirho],
) -> LedgerSignerSecretPostureChirho {
    let entry_chirho = entries_chirho
        .iter()
        .find(|entry_chirho| entry_chirho.name_chirho == secret_ref_chirho.name_chirho);
    LedgerSignerSecretPostureChirho {
        scope_chirho: scope_chirho.to_string(),
        secret_name_chirho: secret_ref_chirho.name_chirho.clone(),
        present_chirho: entry_chirho.is_some(),
        exact_32_bytes_chirho: entry_chirho
            .is_some_and(|entry_chirho| entry_chirho.bytes_chirho == 32),
        value_redacted_chirho: true,
        required_when_composed_chirho: true,
    }
}
