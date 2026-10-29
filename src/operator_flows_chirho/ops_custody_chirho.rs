// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Operations custody — path-redacted file-mode evidence for hosted keys, secrets, and config.

use crate::effect_chirho::postgres_reversible_chirho::ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO;
use crate::{config_chirho, operator_evidence_chirho, secret_chirho, tenant_chirho};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const OPS_CUSTODY_INVENTORY_REPORT_SCHEMA_CHIRHO: &str =
    "ops-custody-inventory-report-v1-chirho";
const SIGNING_KEY_SCOPE_CHIRHO: &str = "instance-signing-key-redacted-chirho";
const PRIVATE_BLOB_KEYS_SCOPE_CHIRHO: &str = "private-blob-keys-dir-redacted-chirho";
const IDENTITY_KEYS_SCOPE_CHIRHO: &str = "identity-keys-dir-redacted-chirho";
const PRIVATE_SECRETS_SCOPE_CHIRHO: &str = "private-secrets-dir-redacted-chirho";
const CONFIG_FILE_SCOPE_CHIRHO: &str = "config-file-redacted-chirho";
const SELECTED_ROOT_SCOPE_CHIRHO: &str = "selected-runtime-root-redacted-chirho";
const CONFIG_EFFECTIVE_ROOT_SCOPE_CHIRHO: &str = "config-effective-root-redacted-chirho";
const ENV_FILE_SCOPE_CHIRHO: &str = "env-file-redacted-chirho";
const DESCRIPTOR_D_EVIDENCE_KEY_SCOPE_CHIRHO: &str =
    "descriptor-d-adapter-evidence-key-redacted-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsCustodyFilePostureChirho {
    pub scope_chirho: String,
    pub checked_chirho: bool,
    pub present_chirho: bool,
    pub regular_file_chirho: bool,
    pub private_mode_chirho: bool,
    pub symlink_chirho: bool,
    pub special_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsCustodyDirectoryPostureChirho {
    pub scope_chirho: String,
    pub present_chirho: bool,
    pub directory_chirho: bool,
    pub private_dir_mode_chirho: bool,
    pub files_chirho: usize,
    pub private_files_chirho: usize,
    pub broad_files_chirho: usize,
    pub child_directories_chirho: usize,
    pub broad_child_directories_chirho: usize,
    pub symlink_entries_chirho: usize,
    pub special_entries_chirho: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsCustodyConfigPostureChirho {
    pub file_chirho: OpsCustodyFilePostureChirho,
    pub root_binding_chirho: OpsCustodyConfigRootBindingChirho,
    pub ownership_checked_chirho: bool,
    pub owner_matches_selected_root_chirho: bool,
    pub publish_token_configured_chirho: bool,
    pub registration_token_configured_chirho: bool,
    pub ledger_host_configured_chirho: bool,
    pub token_values_redacted_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsCustodyConfigRootBindingChirho {
    pub checked_chirho: bool,
    pub selected_root_scope_chirho: String,
    pub config_effective_root_scope_chirho: String,
    pub config_tenant_configured_chirho: bool,
    pub effective_root_matches_selected_root_chirho: bool,
    pub values_redacted_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsCustodyEnvPostureChirho {
    pub file_chirho: OpsCustodyFilePostureChirho,
    pub nonempty_assignments_chirho: usize,
    pub values_redacted_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsCustodySecretCoordinatePostureChirho {
    pub scope_chirho: String,
    pub present_chirho: bool,
    pub expected_size_chirho: bool,
    pub value_redacted_chirho: bool,
    pub required_when_composed_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsCustodyInventoryReportChirho {
    pub schema_chirho: &'static str,
    pub root_scope_chirho: String,
    pub signing_key_chirho: OpsCustodyFilePostureChirho,
    pub private_blob_keys_chirho: OpsCustodyDirectoryPostureChirho,
    pub identity_keys_chirho: OpsCustodyDirectoryPostureChirho,
    pub private_secret_refs_chirho: OpsCustodyDirectoryPostureChirho,
    pub descriptor_d_evidence_key_chirho: OpsCustodySecretCoordinatePostureChirho,
    pub ledger_host_signers_chirho: Vec<OpsCustodySecretCoordinatePostureChirho>,
    pub config_file_chirho: OpsCustodyConfigPostureChirho,
    pub env_file_chirho: OpsCustodyEnvPostureChirho,
    pub findings_chirho: usize,
    pub custody_ready_chirho: bool,
    pub hosted_ops_blocker_closed_chirho: bool,
    pub honest_scope_chirho: Vec<String>,
}

pub fn run_ops_custody_inventory_chirho(
    root_chirho: &Path,
    config_path_chirho: Option<&Path>,
    env_file_path_chirho: Option<&Path>,
) -> Result<OpsCustodyInventoryReportChirho> {
    let signing_key_chirho = file_posture_chirho(
        &root_chirho.join("signing-key-chirho.bin"),
        SIGNING_KEY_SCOPE_CHIRHO,
    )?;
    let private_blob_keys_chirho = directory_posture_chirho(
        &root_chirho.join("privacy-keys-chirho"),
        PRIVATE_BLOB_KEYS_SCOPE_CHIRHO,
    )?;
    let identity_keys_chirho = directory_posture_chirho(
        &root_chirho.join("identity-keys-chirho"),
        IDENTITY_KEYS_SCOPE_CHIRHO,
    )?;
    let private_secret_refs_chirho = directory_posture_chirho(
        &root_chirho.join("private-secrets-chirho"),
        PRIVATE_SECRETS_SCOPE_CHIRHO,
    )?;
    let descriptor_d_evidence_key_chirho = descriptor_d_evidence_key_posture_chirho(root_chirho)?;
    let config_inspection_chirho = config_posture_chirho(root_chirho, config_path_chirho)?;
    let config_file_chirho = config_inspection_chirho.posture_chirho;
    let ledger_host_signers_chirho = config_inspection_chirho.ledger_host_signers_chirho;
    let env_file_chirho = env_posture_chirho(env_file_path_chirho)?;

    let findings_chirho = file_findings_chirho(&signing_key_chirho, false)
        + directory_findings_chirho(&private_blob_keys_chirho)
        + directory_findings_chirho(&identity_keys_chirho)
        + directory_findings_chirho(&private_secret_refs_chirho)
        + usize::from(
            descriptor_d_evidence_key_chirho.present_chirho
                && !descriptor_d_evidence_key_chirho.expected_size_chirho,
        )
        + ledger_host_signers_chirho
            .iter()
            .map(|posture_chirho| {
                usize::from(!posture_chirho.present_chirho)
                    + usize::from(!posture_chirho.expected_size_chirho)
            })
            .sum::<usize>()
        + config_findings_chirho(&config_file_chirho)
        + env_findings_chirho(&env_file_chirho);
    let custody_ready_chirho = findings_chirho == 0;

    Ok(OpsCustodyInventoryReportChirho {
        schema_chirho: OPS_CUSTODY_INVENTORY_REPORT_SCHEMA_CHIRHO,
        root_scope_chirho: operator_evidence_chirho::redacted_local_root_scope_chirho(root_chirho),
        signing_key_chirho,
        private_blob_keys_chirho,
        identity_keys_chirho,
        private_secret_refs_chirho,
        descriptor_d_evidence_key_chirho,
        ledger_host_signers_chirho,
        config_file_chirho,
        env_file_chirho,
        findings_chirho,
        custody_ready_chirho,
        hosted_ops_blocker_closed_chirho: false,
        honest_scope_chirho: vec![
            "local/host file-mode custody evidence only; no key rotation, SSH, DNS, TLS, provider, Stripe, or user-traffic action was performed".to_string(),
            "filesystem paths, token values, env values, key material, private payloads, and secret names are redacted from the report".to_string(),
            "the Descriptor-D adapter evidence-key row reports only presence and exact-size posture; absence is allowed until that optional local/host composition is selected, while the composition itself refuses before intent".to_string(),
            "when the optional ledger-host block is present, all six runtime signer rows, plus a control-plane signer row when its block names a signer, report fixed role labels plus presence/exact-size posture only; secret names, private values, and issuer verifying-key bytes are absent".to_string(),
            "present sensitive root files must be regular files with no group/other permissions; present sensitive directories and children must not be group/other accessible".to_string(),
            "when a hosted config is supplied, its root_chirho plus tenant_chirho must resolve to the same selected runtime root being inventoried; both root values are path-redacted".to_string(),
            "the hosted ops blocker remains open until this inventory plus restore, token custody, TLS/DNS monitoring, and hosted verifier evidence are captured on the hosted root".to_string(),
        ],
    })
}

fn descriptor_d_evidence_key_posture_chirho(
    root_chirho: &Path,
) -> Result<OpsCustodySecretCoordinatePostureChirho> {
    let entry_chirho = secret_chirho::list_secrets_chirho(root_chirho)?
        .into_iter()
        .find(|entry_chirho| entry_chirho.name_chirho == ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO);
    Ok(OpsCustodySecretCoordinatePostureChirho {
        scope_chirho: DESCRIPTOR_D_EVIDENCE_KEY_SCOPE_CHIRHO.to_owned(),
        present_chirho: entry_chirho.is_some(),
        expected_size_chirho: entry_chirho
            .as_ref()
            .is_some_and(|entry_chirho| entry_chirho.bytes_chirho == 32),
        value_redacted_chirho: true,
        required_when_composed_chirho: true,
    })
}

pub fn ensure_ops_custody_ready_chirho(
    report_chirho: &OpsCustodyInventoryReportChirho,
) -> Result<()> {
    if report_chirho.custody_ready_chirho {
        Ok(())
    } else {
        bail!(
            "ops custody inventory has {} custody finding(s); hosted_ops_blocker_closed={}",
            report_chirho.findings_chirho,
            report_chirho.hosted_ops_blocker_closed_chirho
        )
    }
}

struct OpsCustodyConfigInspectionChirho {
    posture_chirho: OpsCustodyConfigPostureChirho,
    ledger_host_signers_chirho: Vec<OpsCustodySecretCoordinatePostureChirho>,
}

fn config_posture_chirho(
    selected_root_chirho: &Path,
    config_path_chirho: Option<&Path>,
) -> Result<OpsCustodyConfigInspectionChirho> {
    let file_chirho = match config_path_chirho {
        Some(path_chirho) => file_posture_chirho(path_chirho, CONFIG_FILE_SCOPE_CHIRHO)?,
        None => unchecked_file_posture_chirho(CONFIG_FILE_SCOPE_CHIRHO),
    };
    let mut publish_token_configured_chirho = false;
    let mut registration_token_configured_chirho = false;
    let mut ledger_host_configured_chirho = false;
    let mut ledger_host_signers_chirho = Vec::new();
    let mut root_binding_chirho = unchecked_config_root_binding_chirho();
    let mut ownership_checked_chirho = false;
    let mut owner_matches_selected_root_chirho = false;
    if let Some(path_chirho) = config_path_chirho {
        if file_chirho.present_chirho && file_chirho.regular_file_chirho {
            (ownership_checked_chirho, owner_matches_selected_root_chirho) =
                config_owner_posture_chirho(selected_root_chirho, path_chirho)?;
            let config_chirho = config_chirho::load_config_chirho(path_chirho)
                .with_context(|| "load redacted ops custody config file")?;
            publish_token_configured_chirho = !config_chirho.publish_token_chirho.trim().is_empty();
            registration_token_configured_chirho =
                !config_chirho.registration_token_chirho.trim().is_empty();
            if let Some(ledger_host_chirho) = &config_chirho.ledger_host_chirho {
                ledger_host_configured_chirho = true;
                ledger_host_signers_chirho =
                    ledger_host_signer_postures_chirho(selected_root_chirho, ledger_host_chirho)?;
            }
            root_binding_chirho = config_root_binding_chirho(selected_root_chirho, &config_chirho)?;
        }
    }
    Ok(OpsCustodyConfigInspectionChirho {
        posture_chirho: OpsCustodyConfigPostureChirho {
            file_chirho,
            root_binding_chirho,
            ownership_checked_chirho,
            owner_matches_selected_root_chirho,
            publish_token_configured_chirho,
            registration_token_configured_chirho,
            ledger_host_configured_chirho,
            token_values_redacted_chirho: config_path_chirho.is_some(),
        },
        ledger_host_signers_chirho,
    })
}

#[cfg(unix)]
fn config_owner_posture_chirho(
    selected_root_chirho: &Path,
    config_path_chirho: &Path,
) -> Result<(bool, bool)> {
    use std::os::unix::fs::MetadataExt;

    let selected_root_metadata_chirho = std::fs::symlink_metadata(selected_root_chirho)
        .with_context(|| "inspect redacted selected-root ownership")?;
    let config_metadata_chirho = std::fs::symlink_metadata(config_path_chirho)
        .with_context(|| "inspect redacted config ownership")?;
    Ok((
        true,
        selected_root_metadata_chirho.uid() == config_metadata_chirho.uid(),
    ))
}

#[cfg(not(unix))]
fn config_owner_posture_chirho(
    _selected_root_chirho: &Path,
    _config_path_chirho: &Path,
) -> Result<(bool, bool)> {
    Ok((false, false))
}

fn ledger_host_signer_postures_chirho(
    root_chirho: &Path,
    ledger_host_chirho: &config_chirho::LedgerHostConfigChirho,
) -> Result<Vec<OpsCustodySecretCoordinatePostureChirho>> {
    let entries_chirho = secret_chirho::list_secrets_chirho(root_chirho)?;
    let refs_chirho = &ledger_host_chirho.signer_secrets_chirho;
    let mut coordinates_chirho = vec![
        (
            "ledger-journal-signer-secret-redacted-chirho",
            refs_chirho.journal_chirho.as_str(),
        ),
        (
            "ledger-config-signer-secret-redacted-chirho",
            refs_chirho.config_chirho.as_str(),
        ),
        (
            "ledger-feeder-signer-secret-redacted-chirho",
            refs_chirho.feeder_chirho.as_str(),
        ),
        (
            "ledger-kind-root-signer-secret-redacted-chirho",
            refs_chirho.kind_root_chirho.as_str(),
        ),
        (
            "effect-intent-signer-secret-redacted-chirho",
            refs_chirho.effect_intent_chirho.as_str(),
        ),
        (
            "effect-terminal-signer-secret-redacted-chirho",
            refs_chirho.effect_terminal_chirho.as_str(),
        ),
    ];
    // C2.1 1a-iii: a control-plane block that names a signer makes this node a control-plane voter,
    // so its role secret is a seventh runtime coordinate with the same custody posture.
    if let Some(control_plane_secret_chirho) = ledger_host_chirho
        .control_plane_chirho
        .as_ref()
        .and_then(|control_plane_chirho| control_plane_chirho.signer_secret_chirho.as_deref())
    {
        coordinates_chirho.push((
            "control-plane-signer-secret-redacted-chirho",
            control_plane_secret_chirho,
        ));
    }
    Ok(coordinates_chirho
        .into_iter()
        .map(|(scope_chirho, secret_name_chirho)| {
            let entry_chirho = entries_chirho
                .iter()
                .find(|entry_chirho| entry_chirho.name_chirho == *secret_name_chirho);
            OpsCustodySecretCoordinatePostureChirho {
                scope_chirho: scope_chirho.to_owned(),
                present_chirho: entry_chirho.is_some(),
                expected_size_chirho: entry_chirho
                    .is_some_and(|entry_chirho| entry_chirho.bytes_chirho == 32),
                value_redacted_chirho: true,
                required_when_composed_chirho: true,
            }
        })
        .collect())
}

fn unchecked_config_root_binding_chirho() -> OpsCustodyConfigRootBindingChirho {
    OpsCustodyConfigRootBindingChirho {
        checked_chirho: false,
        selected_root_scope_chirho: SELECTED_ROOT_SCOPE_CHIRHO.to_string(),
        config_effective_root_scope_chirho: CONFIG_EFFECTIVE_ROOT_SCOPE_CHIRHO.to_string(),
        config_tenant_configured_chirho: false,
        effective_root_matches_selected_root_chirho: false,
        values_redacted_chirho: false,
    }
}

fn config_root_binding_chirho(
    selected_root_chirho: &Path,
    config_chirho: &config_chirho::ConfigChirho,
) -> Result<OpsCustodyConfigRootBindingChirho> {
    let tenant_chirho = config_chirho
        .tenant_chirho
        .as_deref()
        .filter(|tenant_chirho| !tenant_chirho.trim().is_empty());
    let config_root_chirho = PathBuf::from(&config_chirho.root_chirho);
    let config_effective_root_chirho = match tenant_chirho {
        Some(tenant_chirho) => {
            tenant_chirho::tenant_root_chirho(&config_root_chirho, tenant_chirho)
                .with_context(|| "derive redacted config effective root")?
        }
        None => config_root_chirho,
    };
    Ok(OpsCustodyConfigRootBindingChirho {
        checked_chirho: true,
        selected_root_scope_chirho: SELECTED_ROOT_SCOPE_CHIRHO.to_string(),
        config_effective_root_scope_chirho: CONFIG_EFFECTIVE_ROOT_SCOPE_CHIRHO.to_string(),
        config_tenant_configured_chirho: tenant_chirho.is_some(),
        effective_root_matches_selected_root_chirho: path_binding_equivalent_chirho(
            selected_root_chirho,
            &config_effective_root_chirho,
        )?,
        values_redacted_chirho: true,
    })
}

fn path_binding_equivalent_chirho(left_chirho: &Path, right_chirho: &Path) -> Result<bool> {
    Ok(normalized_binding_path_chirho(left_chirho)?
        == normalized_binding_path_chirho(right_chirho)?)
}

fn normalized_binding_path_chirho(path_chirho: &Path) -> Result<PathBuf> {
    let absolute_chirho = if path_chirho.is_absolute() {
        path_chirho.to_path_buf()
    } else {
        std::env::current_dir()
            .with_context(|| "resolve current directory for redacted custody root binding")?
            .join(path_chirho)
    };
    Ok(absolute_chirho.canonicalize().unwrap_or(absolute_chirho))
}

fn env_posture_chirho(env_file_path_chirho: Option<&Path>) -> Result<OpsCustodyEnvPostureChirho> {
    let file_chirho = match env_file_path_chirho {
        Some(path_chirho) => file_posture_chirho(path_chirho, ENV_FILE_SCOPE_CHIRHO)?,
        None => unchecked_file_posture_chirho(ENV_FILE_SCOPE_CHIRHO),
    };
    let mut nonempty_assignments_chirho = 0usize;
    if let Some(path_chirho) = env_file_path_chirho {
        if file_chirho.present_chirho && file_chirho.regular_file_chirho {
            let text_chirho = std::fs::read_to_string(path_chirho)
                .with_context(|| "read redacted ops custody env file")?;
            nonempty_assignments_chirho = text_chirho
                .lines()
                .filter_map(env_assignment_value_chirho)
                .filter(|value_chirho| !value_chirho.trim().is_empty())
                .count();
        }
    }
    Ok(OpsCustodyEnvPostureChirho {
        file_chirho,
        nonempty_assignments_chirho,
        values_redacted_chirho: env_file_path_chirho.is_some(),
    })
}

fn env_assignment_value_chirho(line_chirho: &str) -> Option<&str> {
    let line_chirho = line_chirho.trim();
    if line_chirho.is_empty() || line_chirho.starts_with('#') {
        return None;
    }
    let (_key_chirho, value_chirho) = line_chirho.split_once('=')?;
    Some(value_chirho)
}

fn unchecked_file_posture_chirho(scope_chirho: &str) -> OpsCustodyFilePostureChirho {
    OpsCustodyFilePostureChirho {
        scope_chirho: scope_chirho.to_string(),
        checked_chirho: false,
        present_chirho: false,
        regular_file_chirho: false,
        private_mode_chirho: false,
        symlink_chirho: false,
        special_chirho: false,
    }
}

fn file_posture_chirho(
    path_chirho: &Path,
    scope_chirho: &str,
) -> Result<OpsCustodyFilePostureChirho> {
    let metadata_chirho = match std::fs::symlink_metadata(path_chirho) {
        Ok(metadata_chirho) => metadata_chirho,
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {
            return Ok(OpsCustodyFilePostureChirho {
                scope_chirho: scope_chirho.to_string(),
                checked_chirho: true,
                present_chirho: false,
                regular_file_chirho: false,
                private_mode_chirho: false,
                symlink_chirho: false,
                special_chirho: false,
            });
        }
        Err(error_chirho) => {
            return Err(error_chirho).with_context(|| "inspect redacted custody file")
        }
    };
    let file_type_chirho = metadata_chirho.file_type();
    let regular_file_chirho = metadata_chirho.is_file();
    let symlink_chirho = file_type_chirho.is_symlink();
    Ok(OpsCustodyFilePostureChirho {
        scope_chirho: scope_chirho.to_string(),
        checked_chirho: true,
        present_chirho: true,
        regular_file_chirho,
        private_mode_chirho: regular_file_chirho && private_mode_chirho(&metadata_chirho),
        symlink_chirho,
        special_chirho: !regular_file_chirho && !symlink_chirho,
    })
}

fn directory_posture_chirho(
    path_chirho: &Path,
    scope_chirho: &str,
) -> Result<OpsCustodyDirectoryPostureChirho> {
    let metadata_chirho = match std::fs::symlink_metadata(path_chirho) {
        Ok(metadata_chirho) => metadata_chirho,
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {
            return Ok(OpsCustodyDirectoryPostureChirho {
                scope_chirho: scope_chirho.to_string(),
                present_chirho: false,
                directory_chirho: false,
                private_dir_mode_chirho: false,
                files_chirho: 0,
                private_files_chirho: 0,
                broad_files_chirho: 0,
                child_directories_chirho: 0,
                broad_child_directories_chirho: 0,
                symlink_entries_chirho: 0,
                special_entries_chirho: 0,
            });
        }
        Err(error_chirho) => {
            return Err(error_chirho).with_context(|| "inspect redacted custody directory");
        }
    };
    let mut posture_chirho = OpsCustodyDirectoryPostureChirho {
        scope_chirho: scope_chirho.to_string(),
        present_chirho: true,
        directory_chirho: metadata_chirho.is_dir(),
        private_dir_mode_chirho: metadata_chirho.is_dir() && private_mode_chirho(&metadata_chirho),
        files_chirho: 0,
        private_files_chirho: 0,
        broad_files_chirho: 0,
        child_directories_chirho: 0,
        broad_child_directories_chirho: 0,
        symlink_entries_chirho: if metadata_chirho.file_type().is_symlink() {
            1
        } else {
            0
        },
        special_entries_chirho: if !metadata_chirho.is_dir()
            && !metadata_chirho.file_type().is_symlink()
        {
            1
        } else {
            0
        },
    };
    if posture_chirho.directory_chirho {
        inspect_directory_children_chirho(path_chirho, &mut posture_chirho)?;
    }
    Ok(posture_chirho)
}

fn inspect_directory_children_chirho(
    path_chirho: &Path,
    posture_chirho: &mut OpsCustodyDirectoryPostureChirho,
) -> Result<()> {
    for entry_chirho in
        std::fs::read_dir(path_chirho).with_context(|| "read redacted custody directory")?
    {
        let entry_chirho = entry_chirho?;
        let child_chirho = entry_chirho.path();
        let metadata_chirho = std::fs::symlink_metadata(&child_chirho)
            .with_context(|| "inspect redacted custody directory entry")?;
        let file_type_chirho = metadata_chirho.file_type();
        if file_type_chirho.is_symlink() {
            posture_chirho.symlink_entries_chirho += 1;
            continue;
        }
        if metadata_chirho.is_file() {
            posture_chirho.files_chirho += 1;
            if private_mode_chirho(&metadata_chirho) {
                posture_chirho.private_files_chirho += 1;
            } else {
                posture_chirho.broad_files_chirho += 1;
            }
            continue;
        }
        if metadata_chirho.is_dir() {
            posture_chirho.child_directories_chirho += 1;
            if !private_mode_chirho(&metadata_chirho) {
                posture_chirho.broad_child_directories_chirho += 1;
            }
            inspect_directory_children_chirho(&child_chirho, posture_chirho)?;
            continue;
        }
        posture_chirho.special_entries_chirho += 1;
    }
    Ok(())
}

fn config_findings_chirho(posture_chirho: &OpsCustodyConfigPostureChirho) -> usize {
    file_findings_chirho(
        &posture_chirho.file_chirho,
        posture_chirho.file_chirho.checked_chirho,
    ) + usize::from(
        posture_chirho.root_binding_chirho.checked_chirho
            && !posture_chirho
                .root_binding_chirho
                .effective_root_matches_selected_root_chirho,
    ) + usize::from(
        posture_chirho.ownership_checked_chirho
            && !posture_chirho.owner_matches_selected_root_chirho,
    )
}

fn env_findings_chirho(posture_chirho: &OpsCustodyEnvPostureChirho) -> usize {
    file_findings_chirho(
        &posture_chirho.file_chirho,
        posture_chirho.file_chirho.checked_chirho,
    )
}

fn file_findings_chirho(
    posture_chirho: &OpsCustodyFilePostureChirho,
    required_chirho: bool,
) -> usize {
    if !posture_chirho.checked_chirho {
        return 0;
    }
    if !posture_chirho.present_chirho {
        return usize::from(required_chirho);
    }
    usize::from(!posture_chirho.regular_file_chirho)
        + usize::from(!posture_chirho.private_mode_chirho)
        + usize::from(posture_chirho.symlink_chirho)
        + usize::from(posture_chirho.special_chirho)
}

fn directory_findings_chirho(posture_chirho: &OpsCustodyDirectoryPostureChirho) -> usize {
    if !posture_chirho.present_chirho {
        return 0;
    }
    usize::from(!posture_chirho.directory_chirho)
        + usize::from(!posture_chirho.private_dir_mode_chirho)
        + posture_chirho.broad_files_chirho
        + posture_chirho.broad_child_directories_chirho
        + posture_chirho.symlink_entries_chirho
        + posture_chirho.special_entries_chirho
}

#[cfg(unix)]
fn private_mode_chirho(metadata_chirho: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata_chirho.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn private_mode_chirho(_metadata_chirho: &std::fs::Metadata) -> bool {
    true
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::{identity_chirho, privacy_chirho, secret_chirho, tenant_chirho};
    use cairn_signer_chirho::signer_chirho;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_root_chirho(label_chirho: &str) -> std::path::PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!("cairn-{label_chirho}-{nanos_chirho}-{n_chirho}"))
    }

    fn write_private_file_chirho(path_chirho: &Path, bytes_chirho: &[u8]) {
        std::fs::write(path_chirho, bytes_chirho).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn toml_string_chirho(value_chirho: &str) -> String {
        serde_json::to_string(value_chirho).unwrap()
    }

    #[test]
    fn ops_custody_inventory_reports_private_redacted_surfaces_chirho() {
        let root_chirho = tmp_root_chirho("ops-custody-clean");
        std::fs::create_dir_all(&root_chirho).unwrap();
        let private_payload_chirho = b"m204-private-payload-secret@example.com";
        let host_secret_chirho = b"m204-host-secret-value";
        signer_chirho::sign_message_chirho(&root_chirho, b"m204 custody").unwrap();
        privacy_chirho::store_private_blob_chirho(
            &root_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/m204",
            ),
            "user/m204",
            private_payload_chirho,
        )
        .unwrap();
        identity_chirho::register_identity_with_credential_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::UserChirho,
            "m204-credential-secret@example.com",
        )
        .unwrap();
        secret_chirho::set_secret_chirho(&root_chirho, "openrouter-chirho", host_secret_chirho)
            .unwrap();
        secret_chirho::set_secret_chirho(
            &root_chirho,
            ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
            &[7_u8; 32],
        )
        .unwrap();
        let config_chirho = root_chirho.join("cairn-chirho.toml");
        let env_chirho = root_chirho.join("cairn-chirho.env");
        let publish_token_chirho = "m204-publish-token-secret@example.com";
        let registration_token_chirho = "";
        let stripe_secret_chirho = "sk_test_m204_secret";
        write_private_file_chirho(
            &config_chirho,
            format!(
                "root_chirho = {}\npublish_token_chirho = \"{publish_token_chirho}\"\nregistration_token_chirho = \"{registration_token_chirho}\"\n",
                toml_string_chirho(root_chirho.to_string_lossy().as_ref())
            )
            .as_bytes(),
        );
        write_private_file_chirho(
            &env_chirho,
            format!("STRIPE_SECRET_KEY_CHIRHO={stripe_secret_chirho}\n").as_bytes(),
        );

        let report_chirho =
            run_ops_custody_inventory_chirho(&root_chirho, Some(&config_chirho), Some(&env_chirho))
                .unwrap();
        assert!(report_chirho.custody_ready_chirho);
        assert!(!report_chirho.hosted_ops_blocker_closed_chirho);
        assert!(report_chirho.signing_key_chirho.private_mode_chirho);
        assert_eq!(report_chirho.private_blob_keys_chirho.files_chirho, 1);
        assert_eq!(report_chirho.private_blob_keys_chirho.broad_files_chirho, 0);
        assert_eq!(report_chirho.identity_keys_chirho.broad_files_chirho, 0);
        assert_eq!(
            report_chirho.private_secret_refs_chirho.broad_files_chirho,
            0
        );
        assert!(
            report_chirho
                .descriptor_d_evidence_key_chirho
                .present_chirho
        );
        assert!(
            report_chirho
                .descriptor_d_evidence_key_chirho
                .expected_size_chirho
        );
        assert!(
            report_chirho
                .descriptor_d_evidence_key_chirho
                .value_redacted_chirho
        );
        assert!(
            report_chirho
                .config_file_chirho
                .publish_token_configured_chirho
        );
        assert!(
            !report_chirho
                .config_file_chirho
                .registration_token_configured_chirho
        );
        assert!(
            report_chirho
                .config_file_chirho
                .root_binding_chirho
                .checked_chirho
        );
        assert!(
            report_chirho
                .config_file_chirho
                .root_binding_chirho
                .effective_root_matches_selected_root_chirho
        );
        assert_eq!(report_chirho.env_file_chirho.nonempty_assignments_chirho, 1);

        let json_chirho = serde_json::to_string_pretty(&report_chirho).unwrap();
        for needle_chirho in [
            root_chirho.to_string_lossy().as_ref(),
            config_chirho.to_string_lossy().as_ref(),
            env_chirho.to_string_lossy().as_ref(),
            std::env::temp_dir().to_string_lossy().as_ref(),
            std::str::from_utf8(private_payload_chirho).unwrap(),
            std::str::from_utf8(host_secret_chirho).unwrap(),
            publish_token_chirho,
            stripe_secret_chirho,
            "m204-credential-secret@example.com",
            "openrouter-chirho",
            ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
        ] {
            assert!(
                !json_chirho.contains(needle_chirho),
                "custody report leaked {needle_chirho}"
            );
        }
    }

    #[test]
    fn ops_custody_inventory_binds_config_effective_root_without_path_leak_chirho() {
        let platform_root_chirho = tmp_root_chirho("ops-custody-platform");
        let tenant_id_chirho = "production-chirho";
        let selected_root_chirho =
            tenant_chirho::prepare_tenant_root_chirho(&platform_root_chirho, tenant_id_chirho)
                .unwrap();
        let config_chirho = platform_root_chirho.join("hosted-cairn-chirho.toml");
        write_private_file_chirho(
            &config_chirho,
            format!(
                "root_chirho = {}\ntenant_chirho = {}\n",
                toml_string_chirho(platform_root_chirho.to_string_lossy().as_ref()),
                toml_string_chirho(tenant_id_chirho)
            )
            .as_bytes(),
        );

        let report_chirho =
            run_ops_custody_inventory_chirho(&selected_root_chirho, Some(&config_chirho), None)
                .unwrap();
        assert!(report_chirho.custody_ready_chirho);
        assert!(
            report_chirho
                .config_file_chirho
                .root_binding_chirho
                .checked_chirho
        );
        assert!(
            report_chirho
                .config_file_chirho
                .root_binding_chirho
                .config_tenant_configured_chirho
        );
        assert!(
            report_chirho
                .config_file_chirho
                .root_binding_chirho
                .effective_root_matches_selected_root_chirho
        );

        let wrong_platform_root_chirho = tmp_root_chirho("ops-custody-wrong-platform");
        std::fs::create_dir_all(&wrong_platform_root_chirho).unwrap();
        write_private_file_chirho(
            &config_chirho,
            format!(
                "root_chirho = {}\ntenant_chirho = {}\n",
                toml_string_chirho(wrong_platform_root_chirho.to_string_lossy().as_ref()),
                toml_string_chirho(tenant_id_chirho)
            )
            .as_bytes(),
        );

        let mismatch_chirho =
            run_ops_custody_inventory_chirho(&selected_root_chirho, Some(&config_chirho), None)
                .unwrap();
        assert!(!mismatch_chirho.custody_ready_chirho);
        assert_eq!(mismatch_chirho.findings_chirho, 1);
        assert!(
            !mismatch_chirho
                .config_file_chirho
                .root_binding_chirho
                .effective_root_matches_selected_root_chirho
        );
        let error_chirho = ensure_ops_custody_ready_chirho(&mismatch_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("custody finding"));

        let json_chirho = serde_json::to_string_pretty(&mismatch_chirho).unwrap();
        for needle_chirho in [
            platform_root_chirho.to_string_lossy().as_ref(),
            selected_root_chirho.to_string_lossy().as_ref(),
            wrong_platform_root_chirho.to_string_lossy().as_ref(),
            config_chirho.to_string_lossy().as_ref(),
            std::env::temp_dir().to_string_lossy().as_ref(),
            tenant_id_chirho,
        ] {
            assert!(
                !json_chirho.contains(needle_chirho),
                "custody root binding report leaked {needle_chirho}"
            );
        }
        let _ = std::fs::remove_dir_all(&platform_root_chirho);
        let _ = std::fs::remove_dir_all(&wrong_platform_root_chirho);
    }

    #[test]
    fn descriptor_d_evidence_key_wrong_size_is_a_custody_finding_chirho() {
        let root_chirho = tmp_root_chirho("ops-custody-descriptor-d-size");
        secret_chirho::set_secret_chirho(
            &root_chirho,
            ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
            b"too-short-chirho",
        )
        .unwrap();

        let report_chirho = run_ops_custody_inventory_chirho(&root_chirho, None, None).unwrap();
        assert!(
            report_chirho
                .descriptor_d_evidence_key_chirho
                .present_chirho
        );
        assert!(
            !report_chirho
                .descriptor_d_evidence_key_chirho
                .expected_size_chirho
        );
        assert!(!report_chirho.custody_ready_chirho);
        assert_eq!(report_chirho.findings_chirho, 1);
        let json_chirho = serde_json::to_string(&report_chirho).unwrap();
        assert!(!json_chirho.contains(ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO));
        assert!(!json_chirho.contains("too-short-chirho"));
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn ledger_host_custody_reports_six_fixed_redacted_signer_coordinates_chirho() {
        let root_chirho = tmp_root_chirho("ops-custody-ledger-host");
        let config_path_chirho = root_chirho.join("cairn-chirho.toml");
        let signer_names_chirho = [
            "ledger-journal-key-chirho",
            "ledger-config-key-chirho",
            "ledger-feeder-key-chirho",
            "ledger-kind-root-key-chirho",
            "effect-intent-key-chirho",
            "effect-terminal-key-chirho",
        ];
        for (index_chirho, name_chirho) in signer_names_chirho.iter().enumerate() {
            let size_chirho = if index_chirho == 5 { 7 } else { 32 };
            secret_chirho::set_secret_chirho(
                &root_chirho,
                name_chirho,
                &vec![(index_chirho + 1) as u8; size_chirho],
            )
            .unwrap();
        }
        write_private_file_chirho(
            &config_path_chirho,
            format!(
                r#"root_chirho = {}
[ledger_host_chirho]
schema_chirho = "ledger-host-config-v1-chirho"
storage_namespace_chirho = "ledger-host-chirho"
monitor_evidence_namespace_chirho = "ledger-monitor-ops-chirho"
monitor_evidence_path_chirho = "cycles/conservation-chirho.jsonl"
money_group_id_chirho = "credits-money-group-chirho"
cluster_id_chirho = "credits-cluster-chirho"
journal_path_chirho = "journals/credits-chirho.jsonl"
local_epoch_chirho = 0
kind_registry_path_chirho = "registries/kinds-chirho.jsonl"
kind_registry_id_chirho = "credits-kinds-chirho"
projection_registry_path_chirho = "registries/projections-chirho.jsonl"
projection_registry_id_chirho = "credits-projections-chirho"
source_registry_path_chirho = "registries/sources-chirho.jsonl"
source_registry_id_chirho = "credits-sources-chirho"
monitor_cadence_ms_chirho = 5000
[[ledger_host_chirho.members_chirho]]
owner_chirho = "credits-user-chirho"
kind_id_chirho = "credits-chirho"
[ledger_host_chirho.kind_issuer_chirho]
principal_chirho = "platform-issuer-chirho"
verifying_key_hex_chirho = "{}"
[[ledger_host_chirho.projection_routes_chirho]]
projection_name_chirho = "credits-balances-chirho"
head_path_chirho = "projections/credits-balances-chirho"
[ledger_host_chirho.signer_secrets_chirho]
journal_chirho = "{}"
config_chirho = "{}"
feeder_chirho = "{}"
kind_root_chirho = "{}"
effect_intent_chirho = "{}"
effect_terminal_chirho = "{}"
"#,
                toml_string_chirho(root_chirho.to_string_lossy().as_ref()),
                "11".repeat(32),
                signer_names_chirho[0],
                signer_names_chirho[1],
                signer_names_chirho[2],
                signer_names_chirho[3],
                signer_names_chirho[4],
                signer_names_chirho[5],
            )
            .as_bytes(),
        );

        let short_chirho =
            run_ops_custody_inventory_chirho(&root_chirho, Some(&config_path_chirho), None)
                .unwrap();
        assert!(
            short_chirho
                .config_file_chirho
                .ledger_host_configured_chirho
        );
        assert!(short_chirho.config_file_chirho.ownership_checked_chirho);
        assert!(
            short_chirho
                .config_file_chirho
                .owner_matches_selected_root_chirho
        );
        assert_eq!(short_chirho.ledger_host_signers_chirho.len(), 6);
        assert_eq!(short_chirho.findings_chirho, 1);
        assert!(!short_chirho.custody_ready_chirho);

        secret_chirho::set_secret_chirho(&root_chirho, signer_names_chirho[5], &[6_u8; 32])
            .unwrap();
        let ready_chirho =
            run_ops_custody_inventory_chirho(&root_chirho, Some(&config_path_chirho), None)
                .unwrap();
        assert!(ready_chirho.custody_ready_chirho);
        assert!(ready_chirho.ledger_host_signers_chirho.iter().all(
            |posture_chirho| posture_chirho.present_chirho
                && posture_chirho.expected_size_chirho
                && posture_chirho.value_redacted_chirho
                && posture_chirho.required_when_composed_chirho
        ));
        let json_chirho = serde_json::to_string(&ready_chirho).unwrap();
        for secret_name_chirho in signer_names_chirho {
            assert!(!json_chirho.contains(secret_name_chirho));
        }
    }

    #[cfg(unix)]
    #[test]
    fn ledger_host_custody_adds_a_control_plane_signer_row_when_the_block_names_one_chirho() {
        let platform_root_chirho = tmp_root_chirho("ops-custody-control-plane");
        let tenant_root_chirho = platform_root_chirho
            .join("tenants-chirho")
            .join("geo-tenant-chirho");
        std::fs::create_dir_all(&tenant_root_chirho).unwrap();
        let config_path_chirho = tenant_root_chirho.join("cairn-chirho.toml");
        let control_plane_secret_chirho = "control-plane-key-chirho";
        for name_chirho in [
            "ledger-journal-key-chirho",
            "ledger-config-key-chirho",
            "ledger-feeder-key-chirho",
            "ledger-kind-root-key-chirho",
            "effect-intent-key-chirho",
            "effect-terminal-key-chirho",
        ] {
            secret_chirho::set_secret_chirho(&tenant_root_chirho, name_chirho, &[9_u8; 32])
                .unwrap();
        }
        write_private_file_chirho(
            &config_path_chirho,
            format!(
                r#"root_chirho = {}
tenant_chirho = "geo-tenant-chirho"
[ledger_host_chirho]
schema_chirho = "ledger-host-config-v4-chirho"
storage_namespace_chirho = "ledger-host-chirho"
monitor_evidence_namespace_chirho = "ledger-monitor-ops-chirho"
monitor_evidence_path_chirho = "cycles/conservation-chirho.jsonl"
money_group_id_chirho = "credits-money-group-chirho"
cluster_id_chirho = "credits-cluster-chirho"
journal_path_chirho = "journals/credits-chirho.jsonl"
local_epoch_chirho = 0
kind_registry_path_chirho = "registries/kinds-chirho.jsonl"
kind_registry_id_chirho = "credits-kinds-chirho"
projection_registry_path_chirho = "registries/projections-chirho.jsonl"
projection_registry_id_chirho = "credits-projections-chirho"
source_registry_path_chirho = "registries/sources-chirho.jsonl"
source_registry_id_chirho = "credits-sources-chirho"
monitor_cadence_ms_chirho = 5000
[[ledger_host_chirho.members_chirho]]
owner_chirho = "credits-user-chirho"
kind_id_chirho = "credits-chirho"
[ledger_host_chirho.kind_issuer_chirho]
principal_chirho = "platform-issuer-chirho"
verifying_key_hex_chirho = "{}"
[[ledger_host_chirho.projection_routes_chirho]]
projection_name_chirho = "credits-balances-chirho"
head_path_chirho = "projections/credits-balances-chirho"
[ledger_host_chirho.held_verifier_pins_chirho]
journal_verifying_key_hex_chirho = "{}"
effect_intent_verifying_key_hex_chirho = "{}"
effect_terminal_verifying_key_hex_chirho = "{}"
[ledger_host_chirho.signer_secrets_chirho]
journal_chirho = "ledger-journal-key-chirho"
config_chirho = "ledger-config-key-chirho"
feeder_chirho = "ledger-feeder-key-chirho"
kind_root_chirho = "ledger-kind-root-key-chirho"
effect_intent_chirho = "effect-intent-key-chirho"
effect_terminal_chirho = "effect-terminal-key-chirho"
[ledger_host_chirho.control_plane_chirho]
verifying_key_hex_chirho = "{}"
tenant_id_chirho = "geo-tenant-chirho"
genesis_instance_id_chirho = "{}"
signer_secret_chirho = "{control_plane_secret_chirho}"
"#,
                toml_string_chirho(platform_root_chirho.to_string_lossy().as_ref()),
                "11".repeat(32),
                "33".repeat(32),
                "44".repeat(32),
                "55".repeat(32),
                "77".repeat(32),
                "88".repeat(32),
            )
            .as_bytes(),
        );

        let missing_chirho =
            run_ops_custody_inventory_chirho(&tenant_root_chirho, Some(&config_path_chirho), None)
                .unwrap();
        assert_eq!(missing_chirho.ledger_host_signers_chirho.len(), 7);
        let missing_row_chirho = missing_chirho.ledger_host_signers_chirho.last().unwrap();
        assert_eq!(
            missing_row_chirho.scope_chirho,
            "control-plane-signer-secret-redacted-chirho"
        );
        assert!(!missing_row_chirho.present_chirho);
        assert!(missing_row_chirho.required_when_composed_chirho);

        secret_chirho::set_secret_chirho(
            &tenant_root_chirho,
            control_plane_secret_chirho,
            &[7_u8; 32],
        )
        .unwrap();
        let present_chirho =
            run_ops_custody_inventory_chirho(&tenant_root_chirho, Some(&config_path_chirho), None)
                .unwrap();
        let present_row_chirho = present_chirho.ledger_host_signers_chirho.last().unwrap();
        assert!(present_row_chirho.present_chirho && present_row_chirho.expected_size_chirho);
        assert!(present_row_chirho.value_redacted_chirho);
        // The absent row was two findings (absent, and so not the exact size); installing it clears both.
        assert_eq!(
            missing_chirho.findings_chirho,
            present_chirho.findings_chirho + 2
        );
        let json_chirho = serde_json::to_string(&present_chirho).unwrap();
        assert!(!json_chirho.contains(control_plane_secret_chirho));
    }

    #[test]
    fn ops_custody_inventory_fails_on_broad_sensitive_modes_chirho() {
        use std::os::unix::fs::PermissionsExt;
        let root_chirho = tmp_root_chirho("ops-custody-broad");
        std::fs::create_dir_all(&root_chirho).unwrap();
        let blob_chirho = privacy_chirho::store_private_blob_chirho(
            &root_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/m204",
            ),
            "user/m204",
            b"private",
        )
        .unwrap();
        let key_path_chirho = root_chirho
            .join("privacy-keys-chirho")
            .join(format!("{}.json", blob_chirho.key_id_chirho));
        std::fs::set_permissions(&key_path_chirho, std::fs::Permissions::from_mode(0o644)).unwrap();

        let report_chirho = run_ops_custody_inventory_chirho(&root_chirho, None, None).unwrap();
        assert!(!report_chirho.custody_ready_chirho);
        assert_eq!(report_chirho.private_blob_keys_chirho.broad_files_chirho, 1);
        let err_chirho = ensure_ops_custody_ready_chirho(&report_chirho).unwrap_err();
        assert!(err_chirho.to_string().contains("custody finding"));
    }

    #[cfg(unix)]
    #[test]
    fn ops_custody_inventory_counts_symlink_sensitive_entries_chirho() {
        let root_chirho = tmp_root_chirho("ops-custody-symlink");
        let secrets_dir_chirho = root_chirho.join("private-secrets-chirho");
        std::fs::create_dir_all(&secrets_dir_chirho).unwrap();
        let target_chirho = root_chirho.join("target-secret-chirho");
        std::fs::write(&target_chirho, b"target").unwrap();
        std::os::unix::fs::symlink(
            &target_chirho,
            secrets_dir_chirho.join("linked-secret.secret-chirho"),
        )
        .unwrap();

        let report_chirho = run_ops_custody_inventory_chirho(&root_chirho, None, None).unwrap();
        assert!(!report_chirho.custody_ready_chirho);
        assert_eq!(
            report_chirho
                .private_secret_refs_chirho
                .symlink_entries_chirho,
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn ops_custody_inventory_redacts_broad_config_tokens_chirho() {
        use std::os::unix::fs::PermissionsExt;
        let root_chirho = tmp_root_chirho("ops-custody-config");
        std::fs::create_dir_all(&root_chirho).unwrap();
        let config_chirho = root_chirho.join("cairn-chirho.toml");
        let publish_token_chirho = "m204-broad-publish-token-secret@example.com";
        std::fs::write(
            &config_chirho,
            format!("publish_token_chirho = \"{publish_token_chirho}\"\n").as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(&config_chirho, std::fs::Permissions::from_mode(0o644)).unwrap();

        let report_chirho =
            run_ops_custody_inventory_chirho(&root_chirho, Some(&config_chirho), None).unwrap();
        assert!(!report_chirho.custody_ready_chirho);
        assert!(
            report_chirho
                .config_file_chirho
                .publish_token_configured_chirho
        );
        assert!(
            !report_chirho
                .config_file_chirho
                .file_chirho
                .private_mode_chirho
        );
        let json_chirho = serde_json::to_string_pretty(&report_chirho).unwrap();
        assert!(!json_chirho.contains(publish_token_chirho));
        assert!(!json_chirho.contains(config_chirho.to_string_lossy().as_ref()));
    }
}
