// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Current-substrate Class-A evidence for geo-latched app Deploy.

use super::{
    app_branch_ref_name_chirho, app_head_transition_chirho, app_record_message_chirho,
    app_records_path_chirho, ensure_owner_principal_chirho, now_ms_chirho,
    verified_app_owner_chirho, verified_app_records_chirho, AppActionChirho, AppRecordChirho,
    DagChirho, HashChirho, APP_RECORD_V2_SCHEMA_CHIRHO,
};
use crate::model_chirho::{CapabilityChirho, NodeDefChirho};
use crate::{blessed_chirho, cas_chirho, native_worker_chirho, refs_chirho, store_chirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_durable_chirho::cas_lifecycle_chirho::{
    CasLifecycleRootChirho, CasLifecycleSnapshotChirho,
};
use cairn_head_removal_chirho::head_removal_transition_chirho as removal_transition_chirho;
use cairn_seqlog_chirho::seqlog_chirho;
use cairn_signer_chirho::signer_chirho;
use cairn_undo_plan_chirho::canonical_chirho::contract_set_digest_chirho;
use cairn_undo_plan_chirho::contract_chirho::canonical_authoring_reversion_contract_set_chirho;
use cairn_writer_head_chirho::{
    head_transition_authority_chirho::HeadTransitionCommitScopeChirho,
    head_transition_chirho::{
        self as head_transition_chirho, PreparedFenceHeadTransitionIdentityInputChirho,
        PreparedHeadTransitionChirho,
    },
    writer_head_chirho::{
        consistency_group_for_root_chirho, observe_prepared_fence_lower_bound_chirho,
    },
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::File;
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const APP_RECORDS_LOG_CHIRHO: &str = "app-records-chirho.jsonl";
const APP_HEAD_REASON_CHIRHO: &str = "app-deploy";
const MAX_APP_DEPLOY_TAIL_LINE_BYTES_CHIRHO: usize = 1024 * 1024;

pub(super) enum PreparedElectedAppDeployChirho {
    AlreadyAppliedChirho {
        record_chirho: AppRecordChirho,
        mutable_state_chirho: AppDeployMutableStateChirho,
    },
    MutationChirho {
        record_chirho: AppRecordChirho,
        prepared_head_chirho: PreparedHeadTransitionChirho,
        expected_key_id_chirho: String,
        mutable_state_chirho: Box<AppDeployMutableStateChirho>,
        lifecycle_root_chirho: CasLifecycleRootChirho,
        lifecycle_snapshot_chirho: CasLifecycleSnapshotChirho,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AppDeployMutableStateChirho {
    app_records_chirho: FileStateChirho,
    identities_chirho: FileStateChirho,
    refs_chirho: FileStateChirho,
    reflog_chirho: FileStateChirho,
    removals_chirho: FileStateChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum FileStateChirho {
    MissingChirho,
    PresentChirho {
        device_chirho: u64,
        inode_chirho: u64,
        length_chirho: u64,
        modified_seconds_chirho: i64,
        modified_nanoseconds_chirho: i64,
        last_line_length_chirho: Option<u64>,
        last_line_blake3_chirho: Option<String>,
    },
}

#[derive(Clone, Copy)]
enum MutableFileEvidenceKindChirho {
    ReplaceUpdatedChirho,
    TailConfinedLogChirho,
}

pub(super) fn prepare_elected_app_deploy_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    dag_chirho: HashChirho,
    action_chirho: AppActionChirho,
) -> Result<PreparedElectedAppDeployChirho> {
    let lifecycle_root_chirho = CasLifecycleRootChirho::open_chirho(root_chirho)
        .map_err(anyhow::Error::new)
        .context("AppDeployCasLifecycleUnavailableChirho")?;
    let lifecycle_snapshot_chirho = lifecycle_root_chirho
        .snapshot_chirho()
        .map_err(anyhow::Error::new)
        .context("AppDeployCasLifecycleSnapshotRefusedChirho")?;
    let before_chirho = capture_mutable_state_chirho(root_chirho)?;

    ensure_owner_principal_chirho(root_chirho, owner_principal_chirho)?;
    if let Some(existing_owner_chirho) = verified_app_owner_chirho(root_chirho, app_chirho)? {
        if existing_owner_chirho != owner_principal_chirho {
            bail!(
                "app '{app_chirho}' is owned by '{existing_owner_chirho}', not '{owner_principal_chirho}'"
            );
        }
    }
    refuse_existing_app_removal_chirho(root_chirho, app_chirho)?;
    let verified_records_chirho = verified_app_records_chirho(root_chirho)?;
    refuse_pending_app_transition_chirho(root_chirho, app_chirho, &verified_records_chirho)?;
    let previous_chirho = app_head_transition_chirho::app_ref_head_chirho(root_chirho, app_chirho)?;
    if let Some(previous_chirho) = &previous_chirho {
        if !cairn_model_app_chirho::app_head_transition_chirho::app_previous_is_verified_chirho(
            &verified_records_chirho,
            app_chirho,
            owner_principal_chirho,
            previous_chirho,
        ) {
            bail!("AppDeployPreviousHeadUnverifiedChirho");
        }
    }

    validate_exact_dag_closure_chirho(root_chirho, &dag_chirho)?;
    if previous_chirho.as_ref() == Some(&dag_chirho) {
        let selected_chirho =
            cairn_model_app_chirho::app_head_transition_chirho::selected_app_record_from_verified_history_chirho(
                &verified_records_chirho,
                app_chirho,
                &dag_chirho,
            )?;
        app_head_transition_chirho::require_applied_app_record_chirho(
            root_chirho,
            selected_chirho,
        )?;
        let after_chirho = capture_mutable_state_chirho(root_chirho)?;
        require_stable_prepare_state_chirho(&before_chirho, &after_chirho)?;
        return Ok(PreparedElectedAppDeployChirho::AlreadyAppliedChirho {
            record_chirho: selected_chirho.clone(),
            mutable_state_chirho: after_chirho,
        });
    }

    let group_chirho = consistency_group_for_root_chirho(root_chirho)?;
    let prepared_fence_chirho =
        observe_prepared_fence_lower_bound_chirho(root_chirho, &group_chirho)?;
    let seq_chirho = u64::try_from(verified_records_chirho.len())
        .context("app record sequence does not fit u64")?;
    let mut record_chirho = AppRecordChirho {
        seq_chirho,
        schema_chirho: APP_RECORD_V2_SCHEMA_CHIRHO.to_string(),
        app_chirho: app_chirho.to_string(),
        owner_principal_chirho: owner_principal_chirho.to_string(),
        dag_chirho: Some(dag_chirho),
        action_chirho,
        at_ms_chirho: now_ms_chirho(),
        previous_chirho,
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: Some(prepared_fence_chirho.epoch_chirho()),
        sig_chirho: String::new(),
    };
    let operation_bytes_chirho =
        cairn_model_app_chirho::app_head_transition_chirho::app_head_transition_operation_bytes_chirho(
            &record_chirho,
        )?;
    let branch_chirho = app_branch_ref_name_chirho(app_chirho);
    let next_chirho = record_chirho
        .dag_chirho
        .as_ref()
        .ok_or_else(|| anyhow!("AppDeployPreparedDagMissingChirho"))?;
    let identity_chirho = PreparedFenceHeadTransitionIdentityInputChirho {
        family_log_chirho: APP_RECORDS_LOG_CHIRHO,
        family_seq_chirho: record_chirho.seq_chirho,
        branch_chirho: &branch_chirho,
        previous_chirho: &record_chirho.previous_chirho,
        next_chirho,
        reason_chirho: APP_HEAD_REASON_CHIRHO,
        operation_bytes_chirho: &operation_bytes_chirho,
        prepared_fence_chirho: &prepared_fence_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    };
    record_chirho.transition_id_chirho =
        head_transition_chirho::derive_head_transition_id_from_prepared_fence_chirho(
            &identity_chirho,
        )?;
    let message_chirho = app_record_message_chirho(&record_chirho)?;
    let possession_chirho =
        signer_chirho::sign_with_existing_key_possession_chirho(root_chirho, &message_chirho)?;
    let expected_key_id_chirho = possession_chirho.key_id_chirho().to_string();
    record_chirho.sig_chirho = possession_chirho.into_signature_hex_chirho();
    let operation_bytes_chirho =
        cairn_model_app_chirho::app_head_transition_chirho::app_head_transition_operation_bytes_chirho(
            &record_chirho,
        )?;
    let next_chirho = record_chirho
        .dag_chirho
        .as_ref()
        .ok_or_else(|| anyhow!("AppDeployPreparedDagMissingChirho"))?;
    let identity_chirho = PreparedFenceHeadTransitionIdentityInputChirho {
        family_log_chirho: APP_RECORDS_LOG_CHIRHO,
        family_seq_chirho: record_chirho.seq_chirho,
        branch_chirho: &branch_chirho,
        previous_chirho: &record_chirho.previous_chirho,
        next_chirho,
        reason_chirho: APP_HEAD_REASON_CHIRHO,
        operation_bytes_chirho: &operation_bytes_chirho,
        prepared_fence_chirho: &prepared_fence_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    };
    let prepared_head_chirho =
        head_transition_chirho::bind_caller_verified_head_transition_from_prepared_fence_chirho(
            &identity_chirho,
            &record_chirho.transition_id_chirho,
            &serde_json::to_vec(&record_chirho)?,
        )?;
    let after_chirho = capture_mutable_state_chirho(root_chirho)?;
    require_stable_prepare_state_chirho(&before_chirho, &after_chirho)?;
    Ok(PreparedElectedAppDeployChirho::MutationChirho {
        record_chirho,
        prepared_head_chirho,
        expected_key_id_chirho,
        mutable_state_chirho: Box::new(after_chirho),
        lifecycle_root_chirho,
        lifecycle_snapshot_chirho,
    })
}

pub(super) fn commit_elected_app_deploy_chirho(
    root_chirho: &Path,
    prepared_chirho: PreparedElectedAppDeployChirho,
    scope_chirho: HeadTransitionCommitScopeChirho<'_>,
) -> Result<AppRecordChirho> {
    match prepared_chirho {
        PreparedElectedAppDeployChirho::AlreadyAppliedChirho {
            record_chirho,
            mutable_state_chirho,
        } => {
            require_current_prepare_state_chirho(root_chirho, &mutable_state_chirho)?;
            app_head_transition_chirho::require_applied_app_record_chirho(
                root_chirho,
                &record_chirho,
            )?;
            Ok(record_chirho)
        }
        PreparedElectedAppDeployChirho::MutationChirho {
            record_chirho,
            prepared_head_chirho,
            expected_key_id_chirho,
            mutable_state_chirho,
            lifecycle_root_chirho,
            lifecycle_snapshot_chirho,
        } => {
            scope_chirho.preflight_head_transition_chirho(root_chirho, &prepared_head_chirho)?;
            require_current_prepare_state_chirho(root_chirho, &mutable_state_chirho)?;
            let current_key_id_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
            if current_key_id_chirho != expected_key_id_chirho {
                bail!("AppDeployPreparedSigningKeyChangedChirho");
            }
            let lifecycle_guard_chirho = lifecycle_root_chirho
                .promote_chirho(lifecycle_snapshot_chirho)
                .map_err(anyhow::Error::new)
                .context("AppDeployCasLifecyclePromotionRefusedChirho")?;
            seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
                &app_records_path_chirho(root_chirho),
                record_chirho.seq_chirho,
                &record_chirho,
            )?;
            scope_chirho.complete_head_transition_chirho(root_chirho, &prepared_head_chirho)?;
            drop(lifecycle_guard_chirho);
            Ok(record_chirho)
        }
    }
}

fn refuse_existing_app_removal_chirho(root_chirho: &Path, app_chirho: &str) -> Result<()> {
    let branch_chirho = app_branch_ref_name_chirho(app_chirho);
    let prepared_chirho =
        removal_transition_chirho::root_signed_prepared_head_removal_records_chirho(root_chirho)?;
    if prepared_chirho
        .iter()
        .any(|record_chirho| record_chirho.branch_chirho == branch_chirho)
    {
        bail!("AppDeployHeadRemovalSettlementRequiredChirho");
    }
    let values_chirho =
        removal_transition_chirho::load_head_removal_evidence_values_chirho(root_chirho)?;
    if values_chirho.iter().any(|value_chirho| {
        value_chirho
            .get("branch_chirho")
            .and_then(serde_json::Value::as_str)
            == Some(branch_chirho.as_str())
    }) {
        bail!("AppDeployHeadRemovalSettlementRequiredChirho");
    }
    Ok(())
}

fn refuse_pending_app_transition_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    records_chirho: &[AppRecordChirho],
) -> Result<()> {
    for record_chirho in records_chirho.iter().filter(|record_chirho| {
        record_chirho.app_chirho == app_chirho
            && record_chirho.schema_chirho == APP_RECORD_V2_SCHEMA_CHIRHO
    }) {
        let prepared_chirho = app_head_transition_chirho::prepared_from_verified_app_record_chirho(
            root_chirho,
            record_chirho,
        )?;
        if !head_transition_chirho::verified_head_transition_receipt_chirho(
            root_chirho,
            &prepared_chirho,
        )? {
            bail!("AppDeployPendingHeadTransitionChirho");
        }
    }
    Ok(())
}

fn capture_mutable_state_chirho(root_chirho: &Path) -> Result<AppDeployMutableStateChirho> {
    Ok(AppDeployMutableStateChirho {
        app_records_chirho: capture_file_state_chirho(
            &app_records_path_chirho(root_chirho),
            MutableFileEvidenceKindChirho::TailConfinedLogChirho,
        )?,
        identities_chirho: capture_file_state_chirho(
            &root_chirho.join("identities-chirho.jsonl"),
            MutableFileEvidenceKindChirho::TailConfinedLogChirho,
        )?,
        refs_chirho: capture_file_state_chirho(
            &root_chirho.join("refs-chirho.json"),
            MutableFileEvidenceKindChirho::ReplaceUpdatedChirho,
        )?,
        reflog_chirho: capture_file_state_chirho(
            &refs_chirho::reflog_path_chirho(root_chirho),
            MutableFileEvidenceKindChirho::TailConfinedLogChirho,
        )?,
        removals_chirho: capture_file_state_chirho(
            &root_chirho.join("head-removals-chirho.jsonl"),
            MutableFileEvidenceKindChirho::TailConfinedLogChirho,
        )?,
    })
}

fn capture_file_state_chirho(
    path_chirho: &Path,
    evidence_kind_chirho: MutableFileEvidenceKindChirho,
) -> Result<FileStateChirho> {
    match std::fs::symlink_metadata(path_chirho) {
        Ok(path_metadata_chirho) => {
            if !path_metadata_chirho.file_type().is_file() {
                bail!(
                    "AppDeployMutableInputNotRegularChirho: {}",
                    path_chirho.display()
                );
            }
            let mut file_chirho = File::open(path_chirho)
                .with_context(|| format!("open mutable input {}", path_chirho.display()))?;
            let opened_metadata_chirho = file_chirho
                .metadata()
                .with_context(|| format!("stat mutable input {}", path_chirho.display()))?;
            if !same_file_snapshot_chirho(&path_metadata_chirho, &opened_metadata_chirho) {
                bail!(
                    "AppDeployMutableInputReboundChirho: {}",
                    path_chirho.display()
                );
            }
            let (last_line_length_chirho, last_line_blake3_chirho) = match evidence_kind_chirho {
                MutableFileEvidenceKindChirho::ReplaceUpdatedChirho => (None, None),
                MutableFileEvidenceKindChirho::TailConfinedLogChirho => {
                    let (length_chirho, blake3_chirho) =
                        capture_terminal_line_chirho(&mut file_chirho, path_chirho)?;
                    (Some(length_chirho), Some(blake3_chirho))
                }
            };
            let final_opened_metadata_chirho = file_chirho
                .metadata()
                .with_context(|| format!("restat mutable input {}", path_chirho.display()))?;
            let final_path_metadata_chirho = std::fs::symlink_metadata(path_chirho)
                .with_context(|| format!("restat mutable path {}", path_chirho.display()))?;
            if !final_path_metadata_chirho.file_type().is_file()
                || !same_file_snapshot_chirho(
                    &opened_metadata_chirho,
                    &final_opened_metadata_chirho,
                )
                || !same_file_snapshot_chirho(
                    &final_opened_metadata_chirho,
                    &final_path_metadata_chirho,
                )
            {
                bail!(
                    "AppDeployMutableInputChangedDuringReadChirho: {}",
                    path_chirho.display()
                );
            }
            Ok(FileStateChirho::PresentChirho {
                device_chirho: final_opened_metadata_chirho.dev(),
                inode_chirho: final_opened_metadata_chirho.ino(),
                length_chirho: final_opened_metadata_chirho.len(),
                modified_seconds_chirho: final_opened_metadata_chirho.mtime(),
                modified_nanoseconds_chirho: final_opened_metadata_chirho.mtime_nsec(),
                last_line_length_chirho,
                last_line_blake3_chirho,
            })
        }
        Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => {
            Ok(FileStateChirho::MissingChirho)
        }
        Err(error_chirho) => Err(error_chirho)
            .with_context(|| format!("inspect mutable input {}", path_chirho.display())),
    }
}

fn same_file_snapshot_chirho(
    left_chirho: &std::fs::Metadata,
    right_chirho: &std::fs::Metadata,
) -> bool {
    left_chirho.file_type().is_file()
        && right_chirho.file_type().is_file()
        && left_chirho.dev() == right_chirho.dev()
        && left_chirho.ino() == right_chirho.ino()
        && left_chirho.len() == right_chirho.len()
        && left_chirho.mtime() == right_chirho.mtime()
        && left_chirho.mtime_nsec() == right_chirho.mtime_nsec()
}

/// Hashes only the final physical line. Tail-confinement makes that bounded suffix the mutation
/// witness for append/truncate logs; replace-updated files use inode identity instead.
fn capture_terminal_line_chirho(
    file_chirho: &mut File,
    path_chirho: &Path,
) -> Result<(u64, String)> {
    let byte_length_chirho = file_chirho
        .metadata()
        .with_context(|| format!("stat mutable log {}", path_chirho.display()))?
        .len();
    if byte_length_chirho == 0 {
        return Ok((0, blake3::hash(b"").to_hex().to_string()));
    }
    let max_tail_plus_boundary_chirho = u64::try_from(MAX_APP_DEPLOY_TAIL_LINE_BYTES_CHIRHO + 1)
        .context("app deploy tail cap does not fit u64")?;
    let suffix_length_chirho = byte_length_chirho.min(max_tail_plus_boundary_chirho);
    let suffix_start_chirho = byte_length_chirho - suffix_length_chirho;
    file_chirho
        .seek(SeekFrom::Start(suffix_start_chirho))
        .with_context(|| format!("seek mutable log tail {}", path_chirho.display()))?;
    let suffix_capacity_chirho =
        usize::try_from(suffix_length_chirho).context("mutable log tail does not fit usize")?;
    let mut suffix_chirho = vec![0u8; suffix_capacity_chirho];
    file_chirho
        .read_exact(&mut suffix_chirho)
        .with_context(|| format!("read mutable log tail {}", path_chirho.display()))?;

    let search_end_chirho = if suffix_chirho.last() == Some(&b'\n') {
        suffix_chirho.len() - 1
    } else {
        suffix_chirho.len()
    };
    let line_start_chirho = suffix_chirho[..search_end_chirho]
        .iter()
        .rposition(|byte_chirho| *byte_chirho == b'\n')
        .map_or(0, |newline_chirho| newline_chirho + 1);
    if line_start_chirho == 0 && suffix_start_chirho != 0 {
        bail!(
            "AppDeployMutableInputTailTooLargeChirho: {}",
            path_chirho.display()
        );
    }
    let line_chirho = &suffix_chirho[line_start_chirho..];
    if line_chirho.len() > MAX_APP_DEPLOY_TAIL_LINE_BYTES_CHIRHO {
        bail!(
            "AppDeployMutableInputTailTooLargeChirho: {}",
            path_chirho.display()
        );
    }
    Ok((
        u64::try_from(line_chirho.len()).context("mutable log tail length does not fit u64")?,
        blake3::hash(line_chirho).to_hex().to_string(),
    ))
}

fn require_stable_prepare_state_chirho(
    before_chirho: &AppDeployMutableStateChirho,
    after_chirho: &AppDeployMutableStateChirho,
) -> Result<()> {
    if before_chirho != after_chirho {
        bail!("AppDeployPrepareStateChangedChirho");
    }
    Ok(())
}

fn require_current_prepare_state_chirho(
    root_chirho: &Path,
    expected_chirho: &AppDeployMutableStateChirho,
) -> Result<()> {
    if &capture_mutable_state_chirho(root_chirho)? != expected_chirho {
        bail!("AppDeployPreparedStateChangedChirho");
    }
    Ok(())
}

pub(super) fn validate_exact_dag_closure_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
) -> Result<()> {
    let dag_chirho: DagChirho = store_chirho::get_object_chirho(root_chirho, dag_hash_chirho)
        .with_context(|| format!("AppDeployDagMissingChirho: {}", dag_hash_chirho.0))?;
    let dag_nodes_chirho = dag_chirho
        .nodes_chirho
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if dag_nodes_chirho.len() != dag_chirho.nodes_chirho.len() {
        bail!("AppDeployDagDuplicateNodeChirho");
    }
    if dag_nodes_chirho.is_empty() {
        bail!("AppDeployDagEmptyChirho");
    }

    let contract_set_chirho = canonical_authoring_reversion_contract_set_chirho();
    let contract_digest_chirho = contract_set_digest_chirho(&contract_set_chirho)?;
    let registry_chirho =
        blessed_chirho::registry_v2_message_from_contract_set_chirho(&contract_set_chirho)?;
    let mut definitions_chirho = BTreeMap::new();
    let mut visiting_chirho = BTreeSet::new();
    let mut verified_chirho = BTreeSet::new();
    for node_hash_chirho in &dag_chirho.nodes_chirho {
        validate_node_closure_chirho(
            root_chirho,
            node_hash_chirho,
            &contract_set_chirho,
            &contract_digest_chirho,
            &registry_chirho,
            &mut visiting_chirho,
            &mut verified_chirho,
            &mut definitions_chirho,
        )?;
    }
    validate_dag_edges_chirho(&dag_chirho, &dag_nodes_chirho, &definitions_chirho)?;
    validate_dag_acyclic_chirho(&dag_chirho, &dag_nodes_chirho)
}

#[allow(clippy::too_many_arguments)]
fn validate_node_closure_chirho(
    root_chirho: &Path,
    node_hash_chirho: &HashChirho,
    contract_set_chirho: &cairn_undo_plan_chirho::contract_chirho::BlessedReversionContractSetChirho,
    contract_digest_chirho: &HashChirho,
    registry_chirho: &blessed_chirho::BlessedRegistryV2MessageChirho,
    visiting_chirho: &mut BTreeSet<HashChirho>,
    verified_chirho: &mut BTreeSet<HashChirho>,
    definitions_chirho: &mut BTreeMap<HashChirho, NodeDefChirho>,
) -> Result<()> {
    if verified_chirho.contains(node_hash_chirho) {
        return Ok(());
    }
    if !visiting_chirho.insert(node_hash_chirho.clone()) {
        bail!("AppDeployInvokeCycleChirho");
    }
    let node_chirho: NodeDefChirho = store_chirho::get_object_chirho(root_chirho, node_hash_chirho)
        .with_context(|| format!("AppDeployNodeMissingChirho: {}", node_hash_chirho.0))?;
    validate_node_ports_chirho(root_chirho, &node_chirho)?;
    if let Some(spec_chirho) =
        native_worker_chirho::native_node_spec_from_impl_chirho(&node_chirho.impl_wasm_chirho)
    {
        native_worker_chirho::validate_native_node_def_chirho(
            root_chirho,
            &node_chirho,
            &spec_chirho,
        )?;
        native_worker_chirho::verify_native_program_chirho(root_chirho, &spec_chirho)?;
    } else if !node_chirho.is_builtin_phi_chirho() {
        cas_chirho::get_chirho(root_chirho, &node_chirho.impl_wasm_chirho).with_context(|| {
            format!(
                "AppDeployImplementationMissingChirho: {}",
                node_chirho.impl_wasm_chirho.0
            )
        })?;
    }
    if node_chirho.capabilities_chirho.is_empty() {
        if node_chirho.effect_contract_set_chirho.is_some() {
            bail!("AppDeployPureNodeNamesEffectContractChirho");
        }
    } else {
        if node_chirho.effect_contract_set_chirho.as_ref() != Some(contract_digest_chirho) {
            bail!("AppDeployEffectContractMismatchChirho");
        }
        blessed_chirho::validate_registry_v2_node_effects_chirho(
            registry_chirho,
            contract_set_chirho,
            &node_chirho,
        )?;
    }
    for invoked_chirho in node_chirho
        .capabilities_chirho
        .iter()
        .filter_map(|capability_chirho| match capability_chirho {
            CapabilityChirho::InvokeChirho { node_chirho } => Some(node_chirho),
            _ => None,
        })
    {
        validate_node_closure_chirho(
            root_chirho,
            invoked_chirho,
            contract_set_chirho,
            contract_digest_chirho,
            registry_chirho,
            visiting_chirho,
            verified_chirho,
            definitions_chirho,
        )?;
    }
    visiting_chirho.remove(node_hash_chirho);
    verified_chirho.insert(node_hash_chirho.clone());
    definitions_chirho.insert(node_hash_chirho.clone(), node_chirho);
    Ok(())
}

fn validate_node_ports_chirho(root_chirho: &Path, node_chirho: &NodeDefChirho) -> Result<()> {
    for ports_chirho in [&node_chirho.inputs_chirho, &node_chirho.outputs_chirho] {
        let mut names_chirho = BTreeSet::new();
        for port_chirho in ports_chirho {
            if port_chirho.name_chirho.trim().is_empty()
                || !names_chirho.insert(port_chirho.name_chirho.as_str())
            {
                bail!("AppDeployNodePortInvalidChirho");
            }
            cas_chirho::get_chirho(root_chirho, &port_chirho.schema_chirho).with_context(|| {
                format!(
                    "AppDeployPortSchemaMissingChirho: {}",
                    port_chirho.schema_chirho.0
                )
            })?;
        }
    }
    Ok(())
}

fn validate_dag_edges_chirho(
    dag_chirho: &DagChirho,
    dag_nodes_chirho: &BTreeSet<HashChirho>,
    definitions_chirho: &BTreeMap<HashChirho, NodeDefChirho>,
) -> Result<()> {
    let mut target_ports_chirho = BTreeSet::new();
    for edge_chirho in &dag_chirho.edges_chirho {
        if !dag_nodes_chirho.contains(&edge_chirho.from_node_chirho)
            || !dag_nodes_chirho.contains(&edge_chirho.to_node_chirho)
        {
            bail!("AppDeployDanglingEdgeChirho");
        }
        if !target_ports_chirho.insert((
            edge_chirho.to_node_chirho.clone(),
            edge_chirho.to_port_chirho.clone(),
        )) {
            bail!("AppDeployDuplicateTargetEdgeChirho");
        }
        let from_chirho = definitions_chirho
            .get(&edge_chirho.from_node_chirho)
            .and_then(|node_chirho| {
                node_chirho
                    .outputs_chirho
                    .iter()
                    .find(|port_chirho| port_chirho.name_chirho == edge_chirho.from_port_chirho)
            })
            .ok_or_else(|| anyhow!("AppDeployEdgeSourcePortMissingChirho"))?;
        let to_chirho = definitions_chirho
            .get(&edge_chirho.to_node_chirho)
            .and_then(|node_chirho| {
                node_chirho
                    .inputs_chirho
                    .iter()
                    .find(|port_chirho| port_chirho.name_chirho == edge_chirho.to_port_chirho)
            })
            .ok_or_else(|| anyhow!("AppDeployEdgeTargetPortMissingChirho"))?;
        if from_chirho.schema_chirho != to_chirho.schema_chirho {
            bail!("AppDeployEdgeSchemaMismatchChirho");
        }
    }
    Ok(())
}

fn validate_dag_acyclic_chirho(
    dag_chirho: &DagChirho,
    dag_nodes_chirho: &BTreeSet<HashChirho>,
) -> Result<()> {
    let mut indegree_chirho = dag_nodes_chirho
        .iter()
        .cloned()
        .map(|node_chirho| (node_chirho, 0_usize))
        .collect::<BTreeMap<_, _>>();
    for edge_chirho in &dag_chirho.edges_chirho {
        *indegree_chirho
            .get_mut(&edge_chirho.to_node_chirho)
            .ok_or_else(|| anyhow!("AppDeployDanglingEdgeChirho"))? += 1;
    }
    let mut ready_chirho = indegree_chirho
        .iter()
        .filter_map(|(node_chirho, count_chirho)| {
            (*count_chirho == 0).then_some(node_chirho.clone())
        })
        .collect::<VecDeque<_>>();
    let mut visited_chirho = 0_usize;
    while let Some(node_chirho) = ready_chirho.pop_front() {
        visited_chirho += 1;
        for edge_chirho in dag_chirho
            .edges_chirho
            .iter()
            .filter(|edge_chirho| edge_chirho.from_node_chirho == node_chirho)
        {
            let count_chirho = indegree_chirho
                .get_mut(&edge_chirho.to_node_chirho)
                .ok_or_else(|| anyhow!("AppDeployDanglingEdgeChirho"))?;
            *count_chirho -= 1;
            if *count_chirho == 0 {
                ready_chirho.push_back(edge_chirho.to_node_chirho.clone());
            }
        }
    }
    if visited_chirho != dag_nodes_chirho.len() {
        bail!("AppDeployDagCycleChirho");
    }
    Ok(())
}
