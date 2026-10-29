// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Reviewed H3 activation capsule: one exact signed intent becomes one internally derived mint
//! through the elected resident. No permit, append request, postings, path, or elector is returned
//! to the caller. Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/cf6-regenesis-boundary-chirho.md`.

use super::{
    journal_ports_chirho, ResidentLedgerAppendPermitChirho, ResidentLedgerAuthorityChirho,
    ResidentLedgerAuthorityRefusalChirho, ResidentLedgerBirthPermitChirho,
    ResidentLedgerLocalPortsChirho,
};
use crate::authority_chirho::PinnedLedgerActivationVerifierChirho;
use crate::resident_ledger_identity_chirho::logical_storage_namespace_digest_chirho;
use crate::storage_chirho::{FsLedgerStorageChirho, StableLedgerNamespaceSnapshotChirho};
use cairn_config_chirho::config_chirho::validate_ledger_account_owner_chirho;
use cairn_ledger_log_chirho::journal_chirho::{
    AppendLegRequestChirho, AppendRequestChirho, LedgerJournalChirho,
};
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerOpChirho, LegDeltaChirho};
use cairn_writer_elector_chirho::LocalAppendAuthorityHandleChirho;
use cairn_writer_head_chirho::resident_writer_chirho::canonical_filesystem_path_digest_chirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, consistency_group_for_root_chirho, ConsistencyGroupIdChirho,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const RESIDENT_LEDGER_ACTIVATION_STATEMENT_SCHEMA_V1_CHIRHO: &str =
    "resident-ledger-activation-statement-v1-chirho";
const ACTIVATION_AUTHORIZATION_DIGEST_PREFIX_CHIRHO: &str =
    "resident-ledger-activation-authorization-blake3-v1-chirho:";
const ACTIVATION_REQUEST_DIGEST_PREFIX_CHIRHO: &str =
    "resident-ledger-activation-request-blake3-v1-chirho:";
const ACTIVATION_ROSTER_DIGEST_PREFIX_CHIRHO: &str =
    "resident-ledger-activation-roster-blake3-v1-chirho:";
const MAX_ACTIVATION_LABEL_BYTES_CHIRHO: usize = 256;
pub const MAX_RESIDENT_LEDGER_ACTIVATION_AUTHORIZATION_BYTES_CHIRHO: usize = 16 * 1024;

/// Exact plan-derived money intent. The capsule converts this to one credit-only mint request;
/// callers cannot supply generic legs or an `AppendRequestChirho`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidentLedgerMintIntentChirho {
    pub plan_digest_chirho: String,
    pub activation_principal_chirho: String,
    pub initial_owner_chirho: String,
    pub kind_id_chirho: AssetKindIdChirho,
    pub kind_policy_ref_chirho: AssetKindRefChirho,
    pub amount_chirho: u64,
    pub idempotency_key_chirho: String,
}

/// Canonical bytes independently signed by the offline activation authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidentLedgerActivationStatementChirho {
    pub schema_chirho: String,
    pub intent_chirho: ResidentLedgerMintIntentChirho,
    pub canonical_root_digest_chirho: String,
    pub authority_root_device_chirho: u64,
    pub authority_root_inode_chirho: u64,
    pub consistency_group_digest_chirho: String,
    pub final_storage_digest_chirho: String,
    pub cluster_id_chirho: ClusterIdChirho,
    pub journal_storage_key_chirho: String,
    pub opening_epoch_chirho: u64,
    pub append_physical_ms_chirho: u64,
    pub elected_node_id_chirho: String,
    pub election_roster_digest_chirho: String,
    pub request_digest_chirho: String,
}

/// Every coordinate needed for an offline authority to approve the exact H3 mint before the
/// non-live staging namespace exists. The later resident identity separately binds the actual
/// created storage inode to this final logical namespace.
pub struct ResidentLedgerActivationStatementInputChirho<'input_chirho> {
    pub root_chirho: &'input_chirho Path,
    pub identity_storage_namespace_chirho: &'input_chirho Path,
    pub journal_path_chirho: &'input_chirho StoragePathChirho,
    pub cluster_id_chirho: &'input_chirho ClusterIdChirho,
    pub opening_epoch_chirho: u64,
    pub append_physical_ms_chirho: u64,
    pub elected_node_chirho: &'input_chirho str,
    pub consistency_group_chirho: &'input_chirho ConsistencyGroupIdChirho,
    pub intent_chirho: ResidentLedgerMintIntentChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidentLedgerActivationAuthorizationChirho {
    pub principal_chirho: String,
    pub statement_chirho: ResidentLedgerActivationStatementChirho,
    pub signature_hex_chirho: String,
}

/// Path-free evidence from the exact signed activation and elected append.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidentLedgerActivationReceiptChirho {
    pub authorization_digest_chirho: String,
    pub plan_digest_chirho: String,
    pub resident_identity_digest_chirho: String,
    pub append_seq_chirho: u64,
    pub append_record_digest_chirho: DigestChirho,
    pub append_hlc_physical_ms_chirho: u64,
    pub append_hlc_logical_chirho: u32,
    pub process_generation_chirho: u64,
    pub durable_term_chirho: u64,
    pub fence_epoch_chirho: u64,
    pub fence_group_digest_chirho: String,
}

pub struct ResidentLedgerActivationInputChirho<'ports_chirho> {
    pub root_chirho: &'ports_chirho Path,
    pub identity_storage_namespace_chirho: &'ports_chirho Path,
    pub ports_chirho: ResidentLedgerLocalPortsChirho<'ports_chirho>,
    pub journal_path_chirho: StoragePathChirho,
    pub cluster_id_chirho: ClusterIdChirho,
    pub opening_epoch_chirho: u64,
    pub append_physical_ms_chirho: u64,
    pub local_authority_chirho: LocalAppendAuthorityHandleChirho,
    pub verifier_chirho: &'ports_chirho PinnedLedgerActivationVerifierChirho,
    pub intent_chirho: ResidentLedgerMintIntentChirho,
    pub authorization_chirho: ResidentLedgerActivationAuthorizationChirho,
}

struct PreparedResidentLedgerActivationStatementChirho {
    statement_chirho: ResidentLedgerActivationStatementChirho,
    canonical_root_chirho: PathBuf,
    authority_root_snapshot_chirho: StableLedgerNamespaceSnapshotChirho,
}

#[cfg(test)]
std::thread_local! {
    static RESIDENT_ACTIVATION_POST_AUTHORIZATION_TEST_HOOK_CHIRHO:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    static RESIDENT_ACTIVATION_POST_APPEND_TEST_HOOK_CHIRHO:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
}

#[cfg(test)]
impl ResidentLedgerActivationInputChirho<'_> {
    pub(crate) fn install_post_authorization_test_hook_chirho(
        hook_chirho: impl FnOnce() + 'static,
    ) {
        RESIDENT_ACTIVATION_POST_AUTHORIZATION_TEST_HOOK_CHIRHO.with(|slot_chirho| {
            assert!(
                slot_chirho.borrow().is_none(),
                "resident activation post-authorization test hook must be installed at most once"
            );
            *slot_chirho.borrow_mut() = Some(Box::new(hook_chirho));
        });
    }

    pub(crate) fn install_post_append_test_hook_chirho(hook_chirho: impl FnOnce() + 'static) {
        RESIDENT_ACTIVATION_POST_APPEND_TEST_HOOK_CHIRHO.with(|slot_chirho| {
            assert!(
                slot_chirho.borrow().is_none(),
                "resident activation post-append test hook must be installed at most once"
            );
            *slot_chirho.borrow_mut() = Some(Box::new(hook_chirho));
        });
    }
}

#[cfg(test)]
fn run_resident_activation_post_authorization_test_hook_chirho() {
    let hook_chirho = RESIDENT_ACTIVATION_POST_AUTHORIZATION_TEST_HOOK_CHIRHO
        .with(|slot_chirho| slot_chirho.borrow_mut().take());
    if let Some(hook_chirho) = hook_chirho {
        hook_chirho();
    }
}

#[cfg(test)]
fn run_resident_activation_post_append_test_hook_chirho() {
    let hook_chirho = RESIDENT_ACTIVATION_POST_APPEND_TEST_HOOK_CHIRHO
        .with(|slot_chirho| slot_chirho.borrow_mut().take());
    if let Some(hook_chirho) = hook_chirho {
        hook_chirho();
    }
}

/// Construct the exact bytes an offline activation authority must sign. This performs no mutation.
pub fn resident_ledger_activation_statement_chirho(
    input_chirho: ResidentLedgerActivationStatementInputChirho<'_>,
) -> Result<ResidentLedgerActivationStatementChirho, ResidentLedgerAuthorityRefusalChirho> {
    Ok(prepare_resident_ledger_activation_statement_chirho(input_chirho)?.statement_chirho)
}

fn prepare_resident_ledger_activation_statement_chirho(
    input_chirho: ResidentLedgerActivationStatementInputChirho<'_>,
) -> Result<PreparedResidentLedgerActivationStatementChirho, ResidentLedgerAuthorityRefusalChirho> {
    validate_mint_intent_chirho(&input_chirho.intent_chirho)?;
    if input_chirho.append_physical_ms_chirho == 0
        || !is_lower_hex_chirho(input_chirho.elected_node_chirho, 64)
    {
        return Err(ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho);
    }
    let canonical_root_chirho = input_chirho
        .root_chirho
        .canonicalize()
        .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho)?;
    let group_chirho = consistency_group_for_root_chirho(&canonical_root_chirho)
        .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho)?;
    if input_chirho.consistency_group_chirho != &group_chirho {
        return Err(ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho);
    }
    let authority_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&canonical_root_chirho)
            .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho)?;
    let authority_snapshot_chirho = authority_storage_chirho
        .stable_namespace_snapshot_chirho()
        .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho)?;
    authority_snapshot_chirho
        .verify_current_path_chirho(&canonical_root_chirho)
        .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho)?;
    let authority_identity_chirho = authority_snapshot_chirho
        .identity_chirho()
        .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho)?;
    let request_chirho = mint_request_from_intent_chirho(&input_chirho.intent_chirho);
    let request_bytes_chirho = serde_json::to_vec(&request_chirho)
        .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho)?;
    let roster_bytes_chirho =
        serde_json::to_vec(&(group_chirho.clone(), input_chirho.elected_node_chirho))
            .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho)?;
    let statement_chirho = ResidentLedgerActivationStatementChirho {
        schema_chirho: RESIDENT_LEDGER_ACTIVATION_STATEMENT_SCHEMA_V1_CHIRHO.to_owned(),
        intent_chirho: input_chirho.intent_chirho,
        canonical_root_digest_chirho: canonical_filesystem_path_digest_chirho(
            &canonical_root_chirho,
        )
        .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho)?,
        authority_root_device_chirho: authority_identity_chirho.device_chirho,
        authority_root_inode_chirho: authority_identity_chirho.inode_chirho,
        consistency_group_digest_chirho: consistency_group_digest_chirho(&group_chirho)
            .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho)?,
        final_storage_digest_chirho: logical_storage_namespace_digest_chirho(
            &canonical_root_chirho,
            input_chirho.identity_storage_namespace_chirho,
        )
        .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho)?,
        cluster_id_chirho: input_chirho.cluster_id_chirho.clone(),
        journal_storage_key_chirho: input_chirho.journal_path_chirho.key_chirho().to_owned(),
        opening_epoch_chirho: input_chirho.opening_epoch_chirho,
        append_physical_ms_chirho: input_chirho.append_physical_ms_chirho,
        elected_node_id_chirho: input_chirho.elected_node_chirho.to_owned(),
        election_roster_digest_chirho: format!(
            "{ACTIVATION_ROSTER_DIGEST_PREFIX_CHIRHO}{}",
            blake3::hash(&roster_bytes_chirho).to_hex()
        ),
        request_digest_chirho: format!(
            "{ACTIVATION_REQUEST_DIGEST_PREFIX_CHIRHO}{}",
            blake3::hash(&request_bytes_chirho).to_hex()
        ),
    };
    verify_activation_root_binding_chirho(
        &canonical_root_chirho,
        &authority_snapshot_chirho,
        &statement_chirho,
    )?;
    Ok(PreparedResidentLedgerActivationStatementChirho {
        statement_chirho,
        canonical_root_chirho,
        authority_root_snapshot_chirho: authority_snapshot_chirho,
    })
}

pub fn canonical_resident_ledger_activation_statement_chirho(
    statement_chirho: &ResidentLedgerActivationStatementChirho,
) -> Result<Vec<u8>, ResidentLedgerAuthorityRefusalChirho> {
    if statement_chirho.schema_chirho != RESIDENT_LEDGER_ACTIVATION_STATEMENT_SCHEMA_V1_CHIRHO {
        return Err(ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho);
    }
    validate_mint_intent_chirho(&statement_chirho.intent_chirho)?;
    serde_json::to_vec(statement_chirho)
        .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho)
}

pub fn canonical_resident_ledger_activation_authorization_chirho(
    authorization_chirho: &ResidentLedgerActivationAuthorizationChirho,
) -> Result<Vec<u8>, ResidentLedgerAuthorityRefusalChirho> {
    canonical_resident_ledger_activation_statement_chirho(&authorization_chirho.statement_chirho)?;
    if authorization_chirho.principal_chirho
        != authorization_chirho
            .statement_chirho
            .intent_chirho
            .activation_principal_chirho
        || !is_lower_hex_chirho(&authorization_chirho.signature_hex_chirho, 128)
    {
        return Err(ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho);
    }
    let bytes_chirho = serde_json::to_vec(authorization_chirho)
        .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho)?;
    if bytes_chirho.len() > MAX_RESIDENT_LEDGER_ACTIVATION_AUTHORIZATION_BYTES_CHIRHO {
        return Err(ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho);
    }
    Ok(bytes_chirho)
}

pub fn parse_canonical_resident_ledger_activation_authorization_chirho(
    bytes_chirho: &[u8],
) -> Result<ResidentLedgerActivationAuthorizationChirho, ResidentLedgerAuthorityRefusalChirho> {
    if bytes_chirho.is_empty()
        || bytes_chirho.len() > MAX_RESIDENT_LEDGER_ACTIVATION_AUTHORIZATION_BYTES_CHIRHO
    {
        return Err(ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho);
    }
    let authorization_chirho: ResidentLedgerActivationAuthorizationChirho =
        serde_json::from_slice(bytes_chirho)
            .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho)?;
    if canonical_resident_ledger_activation_authorization_chirho(&authorization_chirho)?
        != bytes_chirho
    {
        return Err(ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho);
    }
    Ok(authorization_chirho)
}

pub fn resident_ledger_activation_authorization_digest_chirho(bytes_chirho: &[u8]) -> String {
    format!(
        "{ACTIVATION_AUTHORIZATION_DIGEST_PREFIX_CHIRHO}{}",
        blake3::hash(bytes_chirho).to_hex()
    )
}

pub fn verify_resident_ledger_activation_authorization_chirho(
    verifier_chirho: &PinnedLedgerActivationVerifierChirho,
    expected_statement_chirho: &ResidentLedgerActivationStatementChirho,
    authorization_chirho: &ResidentLedgerActivationAuthorizationChirho,
) -> Result<String, ResidentLedgerAuthorityRefusalChirho> {
    if authorization_chirho.principal_chirho
        != expected_statement_chirho
            .intent_chirho
            .activation_principal_chirho
        || authorization_chirho.statement_chirho != *expected_statement_chirho
    {
        return Err(ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho);
    }
    let canonical_statement_chirho =
        canonical_resident_ledger_activation_statement_chirho(expected_statement_chirho)?;
    if !verifier_chirho.verify_canonical_statement_chirho(
        &authorization_chirho.principal_chirho,
        &canonical_statement_chirho,
        &authorization_chirho.signature_hex_chirho,
    ) {
        return Err(ResidentLedgerAuthorityRefusalChirho::ActivationSignatureRefusedChirho);
    }
    let canonical_authorization_chirho =
        canonical_resident_ledger_activation_authorization_chirho(authorization_chirho)?;
    Ok(resident_ledger_activation_authorization_digest_chirho(
        &canonical_authorization_chirho,
    ))
}

/// Verify and consume one signed H3 activation. The mint request is derived only after exact
/// statement reconstruction and signature verification.
pub fn activate_reviewed_h3_chirho(
    input_chirho: ResidentLedgerActivationInputChirho<'_>,
) -> Result<ResidentLedgerActivationReceiptChirho, ResidentLedgerAuthorityRefusalChirho> {
    let prepared_statement_chirho = prepare_resident_ledger_activation_statement_chirho(
        ResidentLedgerActivationStatementInputChirho {
            root_chirho: input_chirho.root_chirho,
            identity_storage_namespace_chirho: input_chirho.identity_storage_namespace_chirho,
            journal_path_chirho: &input_chirho.journal_path_chirho,
            cluster_id_chirho: &input_chirho.cluster_id_chirho,
            opening_epoch_chirho: input_chirho.opening_epoch_chirho,
            append_physical_ms_chirho: input_chirho.append_physical_ms_chirho,
            elected_node_chirho: &input_chirho.local_authority_chirho.node_id_chirho().0,
            consistency_group_chirho: input_chirho
                .local_authority_chirho
                .consistency_group_chirho(),
            intent_chirho: input_chirho.intent_chirho.clone(),
        },
    )?;
    let authorization_digest_chirho = verify_resident_ledger_activation_authorization_chirho(
        input_chirho.verifier_chirho,
        &prepared_statement_chirho.statement_chirho,
        &input_chirho.authorization_chirho,
    )?;
    #[cfg(test)]
    run_resident_activation_post_authorization_test_hook_chirho();
    verify_activation_root_binding_chirho(
        &prepared_statement_chirho.canonical_root_chirho,
        &prepared_statement_chirho.authority_root_snapshot_chirho,
        &prepared_statement_chirho.statement_chirho,
    )?;
    if !input_chirho
        .ports_chirho
        .clock_chirho
        .set_reviewed_chirho(input_chirho.append_physical_ms_chirho)
    {
        return Err(ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho);
    }
    let birth_permit_chirho = ResidentLedgerBirthPermitChirho::for_reviewed_activation_chirho(
        prepared_statement_chirho.canonical_root_chirho.clone(),
        input_chirho.identity_storage_namespace_chirho.to_path_buf(),
        input_chirho.journal_path_chirho,
        input_chirho.cluster_id_chirho,
        input_chirho.opening_epoch_chirho,
    );
    let mut resident_chirho = ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
        birth_permit_chirho,
        input_chirho.ports_chirho,
        input_chirho.local_authority_chirho,
    )?;
    verify_activation_root_binding_chirho(
        &prepared_statement_chirho.canonical_root_chirho,
        &prepared_statement_chirho.authority_root_snapshot_chirho,
        &prepared_statement_chirho.statement_chirho,
    )?;
    verify_activation_root_binding_chirho(
        &resident_chirho.canonical_root_chirho,
        &resident_chirho.authority_root_snapshot_chirho,
        &prepared_statement_chirho.statement_chirho,
    )?;
    let append_chirho = resident_chirho.append_preactivation_chirho(
        &ResidentLedgerAppendPermitChirho { _sealed_chirho: () },
        mint_request_from_intent_chirho(&input_chirho.intent_chirho),
    )?;
    #[cfg(test)]
    run_resident_activation_post_append_test_hook_chirho();
    let persisted_journal_chirho = LedgerJournalChirho::open_read_only_chirho(
        journal_ports_chirho(resident_chirho.ports_chirho),
        resident_chirho.journal_path_chirho.clone(),
        &resident_chirho.cluster_id_chirho,
    )
    .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationReceiptRefusedChirho)?;
    if persisted_journal_chirho.tail_seq_chirho() != append_chirho.append_chirho.seq_chirho
        || persisted_journal_chirho.tail_line_digest_chirho()
            != &append_chirho.append_chirho.record_digest_chirho
    {
        return Err(ResidentLedgerAuthorityRefusalChirho::ActivationReceiptRefusedChirho);
    }
    let readiness_chirho = resident_chirho.probe_chirho()?;
    if readiness_chirho.journal_tail_seq_chirho != append_chirho.append_chirho.seq_chirho
        || readiness_chirho.journal_tail_digest_chirho
            != append_chirho.append_chirho.record_digest_chirho
        || readiness_chirho.journal_tail_seq_chirho != persisted_journal_chirho.tail_seq_chirho()
        || &readiness_chirho.journal_tail_digest_chirho
            != persisted_journal_chirho.tail_line_digest_chirho()
    {
        return Err(ResidentLedgerAuthorityRefusalChirho::ActivationReceiptRefusedChirho);
    }
    Ok(ResidentLedgerActivationReceiptChirho {
        authorization_digest_chirho,
        plan_digest_chirho: input_chirho.intent_chirho.plan_digest_chirho,
        resident_identity_digest_chirho: readiness_chirho.resident_identity_digest_chirho,
        append_seq_chirho: append_chirho.append_chirho.seq_chirho,
        append_record_digest_chirho: append_chirho.append_chirho.record_digest_chirho,
        append_hlc_physical_ms_chirho: append_chirho.append_chirho.hlc_chirho.physical_ms_chirho,
        append_hlc_logical_chirho: append_chirho.append_chirho.hlc_chirho.logical_chirho,
        process_generation_chirho: append_chirho.process_generation_chirho,
        durable_term_chirho: append_chirho.published_raft_term_chirho,
        fence_epoch_chirho: append_chirho.fence_chirho.epoch_chirho,
        fence_group_digest_chirho: consistency_group_digest_chirho(
            &append_chirho.fence_chirho.group_chirho,
        )
        .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationReceiptRefusedChirho)?,
    })
}

fn verify_activation_root_binding_chirho(
    canonical_root_chirho: &Path,
    authority_root_snapshot_chirho: &StableLedgerNamespaceSnapshotChirho,
    statement_chirho: &ResidentLedgerActivationStatementChirho,
) -> Result<(), ResidentLedgerAuthorityRefusalChirho> {
    authority_root_snapshot_chirho
        .verify_current_path_chirho(canonical_root_chirho)
        .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho)?;
    let observed_root_digest_chirho =
        canonical_filesystem_path_digest_chirho(canonical_root_chirho)
            .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho)?;
    authority_root_snapshot_chirho
        .verify_current_path_chirho(canonical_root_chirho)
        .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho)?;
    let observed_identity_chirho = authority_root_snapshot_chirho
        .identity_chirho()
        .map_err(|_| ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho)?;
    if observed_root_digest_chirho != statement_chirho.canonical_root_digest_chirho
        || observed_identity_chirho.device_chirho != statement_chirho.authority_root_device_chirho
        || observed_identity_chirho.inode_chirho != statement_chirho.authority_root_inode_chirho
    {
        return Err(ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho);
    }
    Ok(())
}

fn validate_mint_intent_chirho(
    intent_chirho: &ResidentLedgerMintIntentChirho,
) -> Result<(), ResidentLedgerAuthorityRefusalChirho> {
    if !is_lower_hex_chirho(&intent_chirho.plan_digest_chirho, 64)
        || intent_chirho.amount_chirho == 0
        || intent_chirho.activation_principal_chirho.is_empty()
        || intent_chirho.activation_principal_chirho.len() > MAX_ACTIVATION_LABEL_BYTES_CHIRHO
        || intent_chirho.kind_id_chirho.0.is_empty()
        || intent_chirho.kind_id_chirho.0.len() > MAX_ACTIVATION_LABEL_BYTES_CHIRHO
        || !is_lower_hex_chirho(&(intent_chirho.kind_policy_ref_chirho.0).0, 64)
        || intent_chirho.idempotency_key_chirho
            != format!(
                "regenesis-initial-mint-{}-chirho",
                &intent_chirho.plan_digest_chirho[..24]
            )
        || validate_ledger_account_owner_chirho(&intent_chirho.initial_owner_chirho).is_err()
    {
        return Err(ResidentLedgerAuthorityRefusalChirho::ActivationIntentRefusedChirho);
    }
    Ok(())
}

fn mint_request_from_intent_chirho(
    intent_chirho: &ResidentLedgerMintIntentChirho,
) -> AppendRequestChirho {
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::MintChirho {
            authority_evidence_chirho: (intent_chirho.kind_policy_ref_chirho.0).clone(),
        },
        legs_chirho: vec![AppendLegRequestChirho {
            account_chirho: AccountIdChirho {
                owner_chirho: intent_chirho.initial_owner_chirho.clone(),
                kind_id_chirho: intent_chirho.kind_id_chirho.clone(),
            },
            kind_policy_ref_chirho: intent_chirho.kind_policy_ref_chirho.clone(),
            delta_chirho: LegDeltaChirho::CreditChirho,
            amount_chirho: intent_chirho.amount_chirho,
            counterpart_chirho: None,
        }],
        idempotency_key_chirho: intent_chirho.idempotency_key_chirho.clone(),
        provenance_chirho: Some(DigestChirho(intent_chirho.plan_digest_chirho.clone())),
        attribution_chirho: AttributionChirho::PlatformChirho,
    }
}

fn is_lower_hex_chirho(value_chirho: &str, len_chirho: usize) -> bool {
    value_chirho.len() == len_chirho
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}
