// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Current-substrate Class-A evidence for geo-latched app-route Deploy.
//!
//! Workflow and temporary-cost rulings:
//! - `spec-chirho/workflows-chirho/distributed-ha-chirho/f2-chirho/elected-door-primitives-chirho/class-a-witness-chirho.md`
//! - `spec-chirho/workflows-chirho/distributed-ha-chirho/f2-chirho/elected-door-primitives-chirho/prepared-fence-lower-bound-ruling-chirho.md`
//! - `spec-chirho/workflows-chirho/distributed-ha-chirho/f2-chirho/elected-door-primitives-chirho/demo-era-door-commit-loan-ruling-chirho.md`
//!
//! # RECORDED LOAN — duplicated prepare-state evidence
//!
//! `FileStateChirho`, `MutableFileEvidenceKindChirho`, and the capture/compare helpers below are
//! deliberately private copies of the same machinery in:
//!
//! - `src/app_runtime_chirho/app_chirho/app_deploy_evidence_chirho.rs` (S1, the original)
//! - `src/app_runtime_chirho/effect_pricing_chirho/price_book_evidence_chirho.rs` (S3)
//!
//! Extracting a shared home while S2 and S3 were both in flight would have serialized the demo
//! behind a cross-door refactor. Claude2_chirho therefore ruled this temporary loan on 2026-07-28:
//! three independently-drifting copies of a safety mechanism is worse than one copy plus a
//! scheduled extraction. Immediately after the demo lands in the S4 host run, gpt_chirho owns a
//! separate brick that places one shared evidence home and deletes all three copies, before any
//! fourth consumer exists. Until that repayment, this duplication is an exception, not a pattern.

use super::{
    app_route_branch_ref_name_chirho, app_route_records_path_chirho, app_route_ref_head_chirho,
    now_ms_chirho, prepared_from_verified_app_route_record_chirho,
    require_applied_app_route_record_chirho, store_app_route_authority_state_chirho,
    AppRouteAuthorityPortChirho, APP_ROUTE_HEAD_REASON_CHIRHO, APP_ROUTE_RECORDS_LOG_CHIRHO,
};
use anyhow::{bail, Context, Result};
use cairn_core_chirho::{refs_chirho, store_chirho};
use cairn_durable_chirho::cas_lifecycle_chirho::{
    CasLifecycleRootChirho, CasLifecycleSnapshotChirho,
};
use cairn_head_removal_chirho::head_removal_transition_chirho as removal_transition_chirho;
use cairn_model_app_chirho::{
    app_route_head_transition_chirho as route_model_chirho, AppRouteActionChirho,
    AppRouteAuthorityStateChirho, AppRouteRecordChirho, APP_ROUTE_RECORD_V2_SCHEMA_CHIRHO,
};
use cairn_seqlog_chirho::seqlog_chirho;
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
use std::fs::File;
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const MAX_APP_ROUTE_DEPLOY_TAIL_LINE_BYTES_CHIRHO: usize = 1024 * 1024;

pub(super) enum PreparedElectedAppRouteDeployChirho {
    AlreadyAppliedChirho {
        record_chirho: AppRouteRecordChirho,
        mutable_state_chirho: AppRouteDeployMutableStateChirho,
    },
    MutationChirho {
        record_chirho: AppRouteRecordChirho,
        prepared_head_chirho: PreparedHeadTransitionChirho,
        expected_key_id_chirho: String,
        mutable_state_chirho: Box<AppRouteDeployMutableStateChirho>,
        lifecycle_root_chirho: CasLifecycleRootChirho,
        lifecycle_snapshot_chirho: CasLifecycleSnapshotChirho,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AppRouteDeployMutableStateChirho {
    app_route_records_chirho: FileStateChirho,
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

pub(super) fn prepare_elected_app_route_deploy_chirho<P: AppRouteAuthorityPortChirho>(
    port_chirho: &P,
    root_chirho: &Path,
    state_chirho: AppRouteAuthorityStateChirho,
) -> Result<PreparedElectedAppRouteDeployChirho> {
    let lifecycle_root_chirho = CasLifecycleRootChirho::open_chirho(root_chirho)
        .map_err(anyhow::Error::new)
        .context("AppRouteDeployCasLifecycleUnavailableChirho")?;
    let lifecycle_snapshot_chirho = lifecycle_root_chirho
        .snapshot_chirho()
        .map_err(anyhow::Error::new)
        .context("AppRouteDeployCasLifecycleSnapshotRefusedChirho")?;
    let before_chirho = capture_mutable_state_chirho(root_chirho)?;

    port_chirho.validate_app_route_deploy_evidence_chirho(root_chirho, &state_chirho)?;
    let verified_records_chirho = port_chirho.verified_app_route_records_chirho(root_chirho)?;
    refuse_existing_app_route_removal_chirho(root_chirho, &state_chirho, &verified_records_chirho)?;
    refuse_pending_app_route_transition_chirho(
        root_chirho,
        &state_chirho,
        &verified_records_chirho,
    )?;
    let previous_chirho = app_route_ref_head_chirho(
        root_chirho,
        &state_chirho.app_chirho,
        &state_chirho.route_chirho,
    )?;
    if let Some(previous_chirho) = &previous_chirho {
        if !route_model_chirho::app_route_previous_is_verified_chirho(
            &verified_records_chirho,
            &state_chirho.app_chirho,
            &state_chirho.route_chirho,
            &state_chirho.owner_principal_chirho,
            previous_chirho,
        )? {
            bail!("AppRouteDeployPreviousHeadUnverifiedChirho");
        }
    }

    let state_hash_chirho = store_app_route_authority_state_chirho(root_chirho, &state_chirho)?;
    let stored_state_chirho: AppRouteAuthorityStateChirho =
        store_chirho::get_object_chirho(root_chirho, &state_hash_chirho).with_context(|| {
            format!(
                "AppRouteDeployAuthorityStateMissingChirho: {}",
                state_hash_chirho.0
            )
        })?;
    if stored_state_chirho != state_chirho {
        bail!("AppRouteDeployAuthorityStateChangedChirho");
    }
    if previous_chirho.as_ref() == Some(&state_hash_chirho) {
        let selected_chirho =
            route_model_chirho::selected_app_route_record_from_verified_history_chirho(
                &verified_records_chirho,
                &state_chirho.app_chirho,
                &state_chirho.route_chirho,
                &state_chirho.owner_principal_chirho,
                &state_hash_chirho,
            )?;
        require_applied_app_route_record_chirho(root_chirho, selected_chirho)?;
        let after_chirho = capture_mutable_state_chirho(root_chirho)?;
        require_stable_prepare_state_chirho(&before_chirho, &after_chirho)?;
        return Ok(PreparedElectedAppRouteDeployChirho::AlreadyAppliedChirho {
            record_chirho: selected_chirho.clone(),
            mutable_state_chirho: after_chirho,
        });
    }

    let group_chirho = consistency_group_for_root_chirho(root_chirho)?;
    let prepared_fence_chirho =
        observe_prepared_fence_lower_bound_chirho(root_chirho, &group_chirho)?;
    let seq_chirho = u64::try_from(verified_records_chirho.len())
        .context("app-route record sequence does not fit u64")?;
    let mut record_chirho = AppRouteRecordChirho {
        seq_chirho,
        schema_chirho: APP_ROUTE_RECORD_V2_SCHEMA_CHIRHO.to_string(),
        app_chirho: state_chirho.app_chirho.clone(),
        route_chirho: state_chirho.route_chirho.clone(),
        owner_principal_chirho: state_chirho.owner_principal_chirho.clone(),
        dag_chirho: Some(state_chirho.dag_chirho.clone()),
        action_chirho: state_chirho.action_chirho.clone(),
        request_body_policy_chirho: state_chirho.request_body_policy_chirho.clone(),
        at_ms_chirho: now_ms_chirho(),
        previous_chirho,
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: Some(prepared_fence_chirho.epoch_chirho()),
        sig_chirho: String::new(),
    };
    let branch_chirho =
        app_route_branch_ref_name_chirho(&record_chirho.app_chirho, &record_chirho.route_chirho);
    let operation_bytes_chirho =
        route_model_chirho::app_route_head_transition_operation_bytes_chirho(
            &record_chirho,
            &state_hash_chirho,
        )?;
    let identity_chirho = PreparedFenceHeadTransitionIdentityInputChirho {
        family_log_chirho: APP_ROUTE_RECORDS_LOG_CHIRHO,
        family_seq_chirho: record_chirho.seq_chirho,
        branch_chirho: &branch_chirho,
        previous_chirho: &record_chirho.previous_chirho,
        next_chirho: &state_hash_chirho,
        reason_chirho: APP_ROUTE_HEAD_REASON_CHIRHO,
        operation_bytes_chirho: &operation_bytes_chirho,
        prepared_fence_chirho: &prepared_fence_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    };
    record_chirho.transition_id_chirho =
        head_transition_chirho::derive_head_transition_id_from_prepared_fence_chirho(
            &identity_chirho,
        )?;
    let (expected_key_id_chirho, signature_chirho) = port_chirho
        .sign_app_route_record_with_key_possession_chirho(root_chirho, &record_chirho)?;
    record_chirho.sig_chirho = signature_chirho;
    let operation_bytes_chirho =
        route_model_chirho::app_route_head_transition_operation_bytes_chirho(
            &record_chirho,
            &state_hash_chirho,
        )?;
    let identity_chirho = PreparedFenceHeadTransitionIdentityInputChirho {
        family_log_chirho: APP_ROUTE_RECORDS_LOG_CHIRHO,
        family_seq_chirho: record_chirho.seq_chirho,
        branch_chirho: &branch_chirho,
        previous_chirho: &record_chirho.previous_chirho,
        next_chirho: &state_hash_chirho,
        reason_chirho: APP_ROUTE_HEAD_REASON_CHIRHO,
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
    Ok(PreparedElectedAppRouteDeployChirho::MutationChirho {
        record_chirho,
        prepared_head_chirho,
        expected_key_id_chirho,
        mutable_state_chirho: Box::new(after_chirho),
        lifecycle_root_chirho,
        lifecycle_snapshot_chirho,
    })
}

pub(super) fn commit_elected_app_route_deploy_chirho<P: AppRouteAuthorityPortChirho>(
    port_chirho: &P,
    root_chirho: &Path,
    prepared_chirho: PreparedElectedAppRouteDeployChirho,
    scope_chirho: HeadTransitionCommitScopeChirho<'_>,
) -> Result<AppRouteRecordChirho> {
    match prepared_chirho {
        PreparedElectedAppRouteDeployChirho::AlreadyAppliedChirho {
            record_chirho,
            mutable_state_chirho,
        } => {
            require_current_prepare_state_chirho(root_chirho, &mutable_state_chirho)?;
            require_applied_app_route_record_chirho(root_chirho, &record_chirho)?;
            Ok(record_chirho)
        }
        PreparedElectedAppRouteDeployChirho::MutationChirho {
            record_chirho,
            prepared_head_chirho,
            expected_key_id_chirho,
            mutable_state_chirho,
            lifecycle_root_chirho,
            lifecycle_snapshot_chirho,
        } => {
            scope_chirho.preflight_head_transition_chirho(root_chirho, &prepared_head_chirho)?;
            require_current_prepare_state_chirho(root_chirho, &mutable_state_chirho)?;
            let current_key_id_chirho =
                port_chirho.current_root_signing_key_id_chirho(root_chirho)?;
            if current_key_id_chirho != expected_key_id_chirho {
                bail!("AppRouteDeployPreparedSigningKeyChangedChirho");
            }
            let lifecycle_guard_chirho = lifecycle_root_chirho
                .promote_chirho(lifecycle_snapshot_chirho)
                .map_err(anyhow::Error::new)
                .context("AppRouteDeployCasLifecyclePromotionRefusedChirho")?;
            seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
                &app_route_records_path_chirho(root_chirho),
                record_chirho.seq_chirho,
                &record_chirho,
            )?;
            scope_chirho.complete_head_transition_chirho(root_chirho, &prepared_head_chirho)?;
            drop(lifecycle_guard_chirho);
            Ok(record_chirho)
        }
    }
}

fn refuse_existing_app_route_removal_chirho(
    root_chirho: &Path,
    state_chirho: &AppRouteAuthorityStateChirho,
    records_chirho: &[AppRouteRecordChirho],
) -> Result<()> {
    if records_chirho.iter().any(|record_chirho| {
        record_chirho.app_chirho == state_chirho.app_chirho
            && record_chirho.route_chirho == state_chirho.route_chirho
            && record_chirho.action_chirho == AppRouteActionChirho::UndeployRouteChirho
    }) {
        bail!("AppRouteDeployHeadRemovalSettlementRequiredChirho");
    }
    let branch_chirho =
        app_route_branch_ref_name_chirho(&state_chirho.app_chirho, &state_chirho.route_chirho);
    let prepared_chirho =
        removal_transition_chirho::root_signed_prepared_head_removal_records_chirho(root_chirho)?;
    if prepared_chirho
        .iter()
        .any(|record_chirho| record_chirho.branch_chirho == branch_chirho)
    {
        bail!("AppRouteDeployHeadRemovalSettlementRequiredChirho");
    }
    let values_chirho =
        removal_transition_chirho::load_head_removal_evidence_values_chirho(root_chirho)?;
    if values_chirho.iter().any(|value_chirho| {
        value_chirho
            .get("branch_chirho")
            .and_then(serde_json::Value::as_str)
            == Some(branch_chirho.as_str())
    }) {
        bail!("AppRouteDeployHeadRemovalSettlementRequiredChirho");
    }
    Ok(())
}

fn refuse_pending_app_route_transition_chirho(
    root_chirho: &Path,
    state_chirho: &AppRouteAuthorityStateChirho,
    records_chirho: &[AppRouteRecordChirho],
) -> Result<()> {
    for record_chirho in records_chirho.iter().filter(|record_chirho| {
        record_chirho.app_chirho == state_chirho.app_chirho
            && record_chirho.route_chirho == state_chirho.route_chirho
            && record_chirho.schema_chirho == APP_ROUTE_RECORD_V2_SCHEMA_CHIRHO
    }) {
        let prepared_chirho =
            prepared_from_verified_app_route_record_chirho(root_chirho, record_chirho)?;
        if !head_transition_chirho::verified_head_transition_receipt_chirho(
            root_chirho,
            &prepared_chirho,
        )? {
            bail!("AppRouteDeployPendingHeadTransitionChirho");
        }
    }
    Ok(())
}

fn capture_mutable_state_chirho(root_chirho: &Path) -> Result<AppRouteDeployMutableStateChirho> {
    Ok(AppRouteDeployMutableStateChirho {
        app_route_records_chirho: capture_file_state_chirho(
            &app_route_records_path_chirho(root_chirho),
            MutableFileEvidenceKindChirho::TailConfinedLogChirho,
        )?,
        app_records_chirho: capture_file_state_chirho(
            &root_chirho.join("app-records-chirho.jsonl"),
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
                    "AppRouteDeployMutableInputNotRegularChirho: {}",
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
                    "AppRouteDeployMutableInputReboundChirho: {}",
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
                    "AppRouteDeployMutableInputChangedDuringReadChirho: {}",
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
    let max_tail_plus_boundary_chirho =
        u64::try_from(MAX_APP_ROUTE_DEPLOY_TAIL_LINE_BYTES_CHIRHO + 1)
            .context("app-route deploy tail cap does not fit u64")?;
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
            "AppRouteDeployMutableInputTailTooLargeChirho: {}",
            path_chirho.display()
        );
    }
    let line_chirho = &suffix_chirho[line_start_chirho..];
    if line_chirho.len() > MAX_APP_ROUTE_DEPLOY_TAIL_LINE_BYTES_CHIRHO {
        bail!(
            "AppRouteDeployMutableInputTailTooLargeChirho: {}",
            path_chirho.display()
        );
    }
    Ok((
        u64::try_from(line_chirho.len())
            .context("mutable app-route log tail length does not fit u64")?,
        blake3::hash(line_chirho).to_hex().to_string(),
    ))
}

fn require_stable_prepare_state_chirho(
    before_chirho: &AppRouteDeployMutableStateChirho,
    after_chirho: &AppRouteDeployMutableStateChirho,
) -> Result<()> {
    if before_chirho != after_chirho {
        bail!("AppRouteDeployPrepareStateChangedChirho");
    }
    Ok(())
}

fn require_current_prepare_state_chirho(
    root_chirho: &Path,
    expected_chirho: &AppRouteDeployMutableStateChirho,
) -> Result<()> {
    if &capture_mutable_state_chirho(root_chirho)? != expected_chirho {
        bail!("AppRouteDeployPreparedStateChangedChirho");
    }
    Ok(())
}
