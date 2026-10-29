// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::family_chirho::LedgerMirrorRecordChirho;
use crate::recovery_chirho::{
    prefix_refusal_identity_in_detail_chirho, LedgerMirrorOrdinaryTermAcceptanceRequestChirho,
    LedgerMirrorRecoveryHeadReceiptChirho, LedgerMirrorRecoveryHeadRefusalChirho,
    LedgerMirrorRecoveryHeadRequestChirho, LedgerMirrorVerifiedPrefixManifestChirho,
    LedgerMirrorVerifiedPrefixPageChirho,
};
use crate::store_chirho::{
    LedgerMirrorBootstrapCommitPreparationChirho, LedgerMirrorBootstrapHeadChirho,
    LedgerMirrorFollowerStoreChirho, LedgerMirrorHighWaterChirho, LedgerMirrorHighWaterInputChirho,
};
use crate::{
    LEDGER_MIRROR_FINALIZE_PATH_CHIRHO, LEDGER_MIRROR_ORDINARY_TERM_ACCEPTANCE_PATH_CHIRHO,
    LEDGER_MIRROR_PREFIX_BEGIN_PATH_CHIRHO, LEDGER_MIRROR_PREFIX_PAGE_PATH_CHIRHO,
    LEDGER_MIRROR_PREFIX_SEAL_PATH_CHIRHO, LEDGER_MIRROR_PREPARE_PATH_CHIRHO,
    LEDGER_MIRROR_RECOVERY_HEAD_PATH_CHIRHO,
};
use anyhow::{bail, Result};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use cairn_ledger_log_chirho::recovery_mirror_chirho::{
    LedgerMirrorOrdinaryTermAcceptanceReceiptChirho,
    LedgerMirrorOrdinaryTermAcceptanceReceiptInputChirho,
};
use cairn_mirror_chirho::{
    decode_and_authenticate_mirror_prepare_chirho, decode_and_verify_mirror_finalize_chirho,
    join_mirror_view_chirho, verify_mirror_finalize_authority_chirho,
    verify_mirror_prepare_authority_chirho, verify_mirror_receiver_elected_leader_chirho,
    MirrorContractErrorChirho, MirrorDurableCommitClassChirho, MirrorLeadershipViewChirho,
    MirrorReceiptInputChirho, MirrorReceiptStageChirho, MirrorRefusalIdentityChirho,
    MirrorResidencyPolicyChirho, PreparedMirrorReceiptChirho, VerifiedMirrorFinalizeChirho,
    VerifiedMirrorPrepareChirho,
};
use cairn_tenant_placement_authority_chirho::VerifiedTenantPlacementChirho;
use cairn_writer_elector_chirho::monotonic_clock_chirho::{
    MonotonicClockChirho, SystemMonotonicClockChirho, DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO,
};
use std::path::PathBuf;
use std::sync::Arc;

const LEDGER_MIRROR_F1_REQUEST_MAX_BYTES_CHIRHO: usize = 768 * 1024;

#[derive(Clone)]
pub(crate) struct LedgerMirrorServerStateChirho {
    local_node_id_chirho: String,
    sign_root_chirho: Arc<PathBuf>,
    placement_chirho: Arc<VerifiedTenantPlacementChirho>,
    election_view_chirho: Arc<dyn MirrorLeadershipViewChirho>,
    residency_chirho: MirrorResidencyPolicyChirho,
    store_chirho: Arc<LedgerMirrorFollowerStoreChirho>,
    clock_chirho: Arc<dyn MonotonicClockChirho>,
    #[cfg(test)]
    receipt_refusal_stage_chirho: Option<MirrorReceiptStageChirho>,
}

impl LedgerMirrorServerStateChirho {
    pub(crate) fn new_chirho(
        local_node_id_chirho: String,
        sign_root_chirho: PathBuf,
        placement_chirho: Arc<VerifiedTenantPlacementChirho>,
        election_view_chirho: Arc<dyn MirrorLeadershipViewChirho>,
        residency_chirho: MirrorResidencyPolicyChirho,
        store_chirho: Arc<LedgerMirrorFollowerStoreChirho>,
    ) -> Result<Self> {
        if cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho(
            &sign_root_chirho,
        )? != local_node_id_chirho
        {
            bail!("LedgerMirrorServerSignerIdentityRefusedChirho");
        }
        Ok(Self {
            local_node_id_chirho,
            sign_root_chirho: Arc::new(sign_root_chirho),
            placement_chirho,
            election_view_chirho,
            residency_chirho,
            store_chirho,
            clock_chirho: Arc::new(SystemMonotonicClockChirho::new_chirho()),
            #[cfg(test)]
            receipt_refusal_stage_chirho: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_receipt_refusal_stage_chirho(
        mut self,
        stage_chirho: MirrorReceiptStageChirho,
    ) -> Self {
        self.receipt_refusal_stage_chirho = Some(stage_chirho);
        self
    }
}

#[derive(Clone, Copy)]
enum LedgerMirrorRequestStageChirho {
    PrepareChirho,
    FinalizeChirho,
}

impl LedgerMirrorRequestStageChirho {
    const fn refusal_log_prefix_chirho(self) -> &'static str {
        match self {
            Self::PrepareChirho => "LedgerMirrorPrepareRefusalChirho",
            Self::FinalizeChirho => "LedgerMirrorFinalizeRefusalChirho",
        }
    }
}

pub(crate) fn ledger_mirror_router_chirho(state_chirho: LedgerMirrorServerStateChirho) -> Router {
    Router::new()
        .route(
            LEDGER_MIRROR_PREPARE_PATH_CHIRHO,
            post(prepare_handler_chirho),
        )
        .route(
            LEDGER_MIRROR_FINALIZE_PATH_CHIRHO,
            post(finalize_handler_chirho),
        )
        .route(
            LEDGER_MIRROR_RECOVERY_HEAD_PATH_CHIRHO,
            post(recovery_head_handler_chirho),
        )
        .route(
            LEDGER_MIRROR_ORDINARY_TERM_ACCEPTANCE_PATH_CHIRHO,
            post(ordinary_term_acceptance_handler_chirho),
        )
        .route(
            LEDGER_MIRROR_PREFIX_BEGIN_PATH_CHIRHO,
            post(prefix_begin_handler_chirho),
        )
        .route(
            LEDGER_MIRROR_PREFIX_PAGE_PATH_CHIRHO,
            post(prefix_page_handler_chirho),
        )
        .route(
            LEDGER_MIRROR_PREFIX_SEAL_PATH_CHIRHO,
            post(prefix_seal_handler_chirho),
        )
        .layer(DefaultBodyLimit::max(
            LEDGER_MIRROR_F1_REQUEST_MAX_BYTES_CHIRHO,
        ))
        .with_state(state_chirho)
}

/// Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.
async fn recovery_head_handler_chirho(
    State(state_chirho): State<LedgerMirrorServerStateChirho>,
    body_chirho: Bytes,
) -> Response {
    match recovery_head_chirho(&state_chirho, &body_chirho) {
        Ok(bytes_chirho) => (
            [(header::CONTENT_TYPE, "application/octet-stream")],
            bytes_chirho,
        )
            .into_response(),
        Err(refusal_chirho) => {
            eprintln!("{}", refusal_chirho.as_str_chirho());
            (StatusCode::CONFLICT, refusal_chirho.as_str_chirho()).into_response()
        }
    }
}

fn recovery_head_chirho(
    state_chirho: &LedgerMirrorServerStateChirho,
    body_chirho: &[u8],
) -> std::result::Result<Vec<u8>, LedgerMirrorRecoveryHeadRefusalChirho> {
    let request_chirho =
        LedgerMirrorRecoveryHeadRequestChirho::decode_and_verify_chirho(body_chirho)
            .map_err(|_| LedgerMirrorRecoveryHeadRefusalChirho::REQUEST_REFUSED_CHIRHO)?;
    let joined_chirho = join_mirror_view_chirho(
        &state_chirho.placement_chirho,
        state_chirho.election_view_chirho.as_ref(),
    )
    .map_err(|refusal_chirho| {
        LedgerMirrorRecoveryHeadRefusalChirho::from_join_refusal_chirho(&refusal_chirho)
    })?;
    if request_chirho.target_node_id_chirho() != state_chirho.local_node_id_chirho {
        return Err(LedgerMirrorRecoveryHeadRefusalChirho::TARGET_NODE_MISMATCH_CHIRHO);
    }
    if request_chirho.consistency_group_digest_chirho()
        != joined_chirho
            .view_chirho()
            .consistency_group_digest_chirho()
    {
        return Err(LedgerMirrorRecoveryHeadRefusalChirho::CONSISTENCY_GROUP_MISMATCH_CHIRHO);
    }
    if request_chirho.assignment_digest_chirho()
        != state_chirho.placement_chirho.assignment_digest_chirho()
    {
        return Err(LedgerMirrorRecoveryHeadRefusalChirho::ASSIGNMENT_MISMATCH_CHIRHO);
    }
    if request_chirho.expected_term_chirho() != joined_chirho.term_chirho() {
        return Err(LedgerMirrorRecoveryHeadRefusalChirho::TERM_MISMATCH_CHIRHO);
    }
    if request_chirho.membership_view_digest_chirho()
        != joined_chirho.view_chirho().view_digest_chirho()
    {
        return Err(LedgerMirrorRecoveryHeadRefusalChirho::MEMBERSHIP_VIEW_MISMATCH_CHIRHO);
    }
    verify_mirror_receiver_elected_leader_chirho(
        &joined_chirho,
        request_chirho.requester_node_id_chirho(),
        request_chirho.expected_term_chirho(),
    )
    .map_err(|_| LedgerMirrorRecoveryHeadRefusalChirho::REQUESTER_AUTHORITY_REFUSED_CHIRHO)?;
    verify_holder_selection_chirho(
        state_chirho,
        &joined_chirho,
        request_chirho.requester_node_id_chirho(),
    )
    .map_err(|_| LedgerMirrorRecoveryHeadRefusalChirho::HOLDER_SELECTION_REFUSED_CHIRHO)?;
    let source_head_chirho = state_chirho
        .store_chirho
        .load_recovery_source_head_chirho()
        .map_err(|_| LedgerMirrorRecoveryHeadRefusalChirho::SOURCE_READ_REFUSED_CHIRHO)?
        .ok_or(LedgerMirrorRecoveryHeadRefusalChirho::UNAVAILABLE_CHIRHO)?;
    LedgerMirrorRecoveryHeadReceiptChirho::sign_from_source_head_chirho(
        &source_head_chirho,
        &state_chirho.sign_root_chirho,
    )
    .map_err(|_| LedgerMirrorRecoveryHeadRefusalChirho::RECEIPT_SIGNING_REFUSED_CHIRHO)?
    .to_wire_bytes_chirho()
    .map_err(|_| LedgerMirrorRecoveryHeadRefusalChirho::RECEIPT_ENCODING_REFUSED_CHIRHO)
}

async fn ordinary_term_acceptance_handler_chirho(
    State(state_chirho): State<LedgerMirrorServerStateChirho>,
    body_chirho: Bytes,
) -> Response {
    ordinary_term_result_response_chirho(ordinary_term_acceptance_chirho(
        &state_chirho,
        &body_chirho,
    ))
}

/// Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.
fn ordinary_term_acceptance_chirho(
    state_chirho: &LedgerMirrorServerStateChirho,
    body_chirho: &[u8],
) -> Result<Vec<u8>> {
    let request_chirho =
        LedgerMirrorOrdinaryTermAcceptanceRequestChirho::decode_and_verify_chirho(body_chirho)?;
    let joined_chirho = join_mirror_view_chirho(
        &state_chirho.placement_chirho,
        state_chirho.election_view_chirho.as_ref(),
    )?;
    let current_assigned_node_ids_chirho: [String; 3] = state_chirho
        .placement_chirho
        .assigned_nodes_chirho()
        .iter()
        .map(|node_chirho| node_chirho.node_id_chirho.clone())
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| anyhow::anyhow!("LedgerMirrorAssignedNodePopulationRefusedChirho"))?;
    if request_chirho.target_node_id_chirho() != state_chirho.local_node_id_chirho
        || request_chirho.consistency_group_digest_chirho()
            != joined_chirho
                .view_chirho()
                .consistency_group_digest_chirho()
        || request_chirho.assignment_digest_chirho()
            != state_chirho.placement_chirho.assignment_digest_chirho()
        || request_chirho.assigned_node_ids_chirho() != &current_assigned_node_ids_chirho
        || request_chirho.expected_term_chirho() != joined_chirho.term_chirho()
        || request_chirho.membership_view_digest_chirho()
            != joined_chirho.view_chirho().view_digest_chirho()
    {
        bail!("LedgerMirrorOrdinaryTermRequestAuthorityRefusedChirho");
    }
    verify_mirror_receiver_elected_leader_chirho(
        &joined_chirho,
        request_chirho.requester_node_id_chirho(),
        request_chirho.expected_term_chirho(),
    )
    .map_err(|_| anyhow::anyhow!("LedgerMirrorOrdinaryTermRequestAuthorityRefusedChirho"))?;
    verify_holder_selection_chirho(
        state_chirho,
        &joined_chirho,
        request_chirho.requester_node_id_chirho(),
    )?;

    let high_water_chirho = state_chirho
        .store_chirho
        .load_high_water_chirho()?
        .ok_or_else(|| anyhow::anyhow!("LedgerMirrorOrdinaryTermLiveHighWaterUnavailableChirho"))?;
    let record_chirho = high_water_chirho.record_chirho();
    if high_water_chirho.consistency_group_digest_chirho()
        != request_chirho.consistency_group_digest_chirho()
        || high_water_chirho.assignment_digest_chirho() != request_chirho.assignment_digest_chirho()
        || high_water_chirho.assigned_node_ids_chirho() != request_chirho.assigned_node_ids_chirho()
        || high_water_chirho.origin_leader_node_id_chirho()
            != request_chirho.requester_node_id_chirho()
        || high_water_chirho.holder_node_id_chirho() != state_chirho.local_node_id_chirho
        || high_water_chirho.membership_view_digest_chirho()
            != request_chirho.membership_view_digest_chirho()
        || high_water_chirho.historical_term_chirho() != request_chirho.expected_term_chirho()
        || record_chirho.cluster_id_chirho != request_chirho.cluster_id_chirho()
        || record_chirho.journal_genesis_digest_chirho
            != request_chirho.journal_genesis_digest_chirho()
        || record_chirho.record_seq_chirho != request_chirho.tail_seq_chirho()
        || record_chirho.record_digest_chirho != request_chirho.tail_record_digest_chirho()
        || record_chirho.record_epoch_chirho != request_chirho.tail_epoch_chirho()
        || record_chirho.record_hlc_physical_ms_chirho
            != request_chirho.tail_hlc_physical_ms_chirho()
        || record_chirho.record_hlc_logical_chirho != request_chirho.tail_hlc_logical_chirho()
    {
        bail!("LedgerMirrorOrdinaryTermLiveHighWaterBindingRefusedChirho");
    }
    let joined_after_chirho = join_mirror_view_chirho(
        &state_chirho.placement_chirho,
        state_chirho.election_view_chirho.as_ref(),
    )?;
    if joined_after_chirho.term_chirho() != joined_chirho.term_chirho()
        || joined_after_chirho.view_chirho().view_digest_chirho()
            != joined_chirho.view_chirho().view_digest_chirho()
    {
        bail!("LedgerMirrorOrdinaryTermAuthorityChangedAfterHighWaterReadChirho");
    }
    verify_mirror_receiver_elected_leader_chirho(
        &joined_after_chirho,
        request_chirho.requester_node_id_chirho(),
        request_chirho.expected_term_chirho(),
    )
    .map_err(|_| {
        anyhow::anyhow!("LedgerMirrorOrdinaryTermAuthorityChangedAfterHighWaterReadChirho")
    })?;

    LedgerMirrorOrdinaryTermAcceptanceReceiptChirho::sign_chirho(
        LedgerMirrorOrdinaryTermAcceptanceReceiptInputChirho {
            challenge_nonce_hex_chirho: request_chirho.challenge_nonce_hex_chirho().to_owned(),
            current_consistency_group_digest_chirho: joined_after_chirho
                .view_chirho()
                .consistency_group_digest_chirho()
                .to_owned(),
            current_assignment_digest_chirho: state_chirho
                .placement_chirho
                .assignment_digest_chirho()
                .to_owned(),
            current_assigned_node_ids_chirho,
            current_leader_node_id_chirho: request_chirho.requester_node_id_chirho().to_owned(),
            current_membership_view_digest_chirho: joined_after_chirho
                .view_chirho()
                .view_digest_chirho(),
            current_term_chirho: joined_after_chirho.term_chirho(),
            acknowledged_consistency_group_digest_chirho: high_water_chirho
                .consistency_group_digest_chirho()
                .to_owned(),
            acknowledged_assignment_digest_chirho: high_water_chirho
                .assignment_digest_chirho()
                .to_owned(),
            acknowledged_assigned_node_ids_chirho: high_water_chirho
                .assigned_node_ids_chirho()
                .clone(),
            acknowledged_leader_node_id_chirho: high_water_chirho
                .origin_leader_node_id_chirho()
                .to_owned(),
            acknowledged_membership_view_digest_chirho: high_water_chirho
                .membership_view_digest_chirho()
                .to_owned(),
            acknowledged_term_chirho: high_water_chirho.historical_term_chirho(),
            holder_node_id_chirho: high_water_chirho.holder_node_id_chirho().to_owned(),
            cluster_id_chirho: record_chirho.cluster_id_chirho.clone(),
            journal_genesis_digest_chirho: record_chirho.journal_genesis_digest_chirho.clone(),
            tail_seq_chirho: record_chirho.record_seq_chirho,
            tail_record_digest_chirho: record_chirho.record_digest_chirho.clone(),
            tail_epoch_chirho: record_chirho.record_epoch_chirho,
            tail_hlc_physical_ms_chirho: record_chirho.record_hlc_physical_ms_chirho,
            tail_hlc_logical_chirho: record_chirho.record_hlc_logical_chirho,
        },
        &state_chirho.sign_root_chirho,
    )?
    .to_wire_bytes_chirho()
    .map_err(Into::into)
}

async fn prefix_begin_handler_chirho(
    State(state_chirho): State<LedgerMirrorServerStateChirho>,
    body_chirho: Bytes,
) -> Response {
    recovery_result_response_chirho(prefix_begin_chirho(&state_chirho, &body_chirho))
}

fn prefix_begin_chirho(
    state_chirho: &LedgerMirrorServerStateChirho,
    body_chirho: &[u8],
) -> Result<Vec<u8>> {
    let manifest_chirho =
        LedgerMirrorVerifiedPrefixManifestChirho::decode_and_verify_chirho(body_chirho)?;
    verify_prefix_manifest_authority_chirho(state_chirho, &manifest_chirho)?;
    let previous_assignment_digest_chirho = state_chirho
        .placement_chirho
        .intent_chirho()
        .previous_assignment_digest_chirho
        .as_deref();
    let already_committed_chirho = state_chirho
        .store_chirho
        .begin_verified_prefix_chirho(manifest_chirho, previous_assignment_digest_chirho)?;
    Ok(vec![u8::from(already_committed_chirho)])
}

async fn prefix_page_handler_chirho(
    State(state_chirho): State<LedgerMirrorServerStateChirho>,
    body_chirho: Bytes,
) -> Response {
    recovery_result_response_chirho(prefix_page_chirho(&state_chirho, &body_chirho))
}

fn prefix_page_chirho(
    state_chirho: &LedgerMirrorServerStateChirho,
    body_chirho: &[u8],
) -> Result<Vec<u8>> {
    let page_chirho = LedgerMirrorVerifiedPrefixPageChirho::decode_chirho(body_chirho)?;
    state_chirho
        .store_chirho
        .store_verified_prefix_page_chirho(page_chirho)?;
    Ok(Vec::new())
}

async fn prefix_seal_handler_chirho(
    State(state_chirho): State<LedgerMirrorServerStateChirho>,
    body_chirho: Bytes,
) -> Response {
    recovery_result_response_chirho(prefix_seal_chirho(&state_chirho, &body_chirho))
}

fn prefix_seal_chirho(
    state_chirho: &LedgerMirrorServerStateChirho,
    body_chirho: &[u8],
) -> Result<Vec<u8>> {
    let manifest_chirho =
        LedgerMirrorVerifiedPrefixManifestChirho::decode_and_verify_chirho(body_chirho)?;
    verify_prefix_manifest_authority_chirho(state_chirho, &manifest_chirho)?;
    match state_chirho
        .store_chirho
        .prepare_bootstrap_commit_chirho(manifest_chirho.manifest_digest_chirho())?
    {
        LedgerMirrorBootstrapCommitPreparationChirho::AlreadyCommittedChirho => {}
        LedgerMirrorBootstrapCommitPreparationChirho::SignChirho(input_chirho) => {
            let signed_head_chirho = LedgerMirrorBootstrapHeadChirho::sign_chirho(
                *input_chirho,
                &state_chirho.sign_root_chirho,
            )?;
            state_chirho
                .store_chirho
                .commit_bootstrap_chirho(signed_head_chirho)?;
        }
    }
    Ok(Vec::new())
}

fn verify_prefix_manifest_authority_chirho(
    state_chirho: &LedgerMirrorServerStateChirho,
    manifest_chirho: &LedgerMirrorVerifiedPrefixManifestChirho,
) -> Result<()> {
    let joined_chirho = join_mirror_view_chirho(
        &state_chirho.placement_chirho,
        state_chirho.election_view_chirho.as_ref(),
    )
    .map_err(|_| anyhow::anyhow!("LedgerMirrorPrefixManifestAuthorityRefusedChirho"))?;
    let assigned_node_ids_chirho = state_chirho
        .placement_chirho
        .assigned_nodes_chirho()
        .iter()
        .map(|node_chirho| node_chirho.node_id_chirho.clone())
        .collect::<Vec<_>>();
    if manifest_chirho.consistency_group_digest_chirho()
        != joined_chirho
            .view_chirho()
            .consistency_group_digest_chirho()
        || manifest_chirho.assignment_digest_chirho()
            != state_chirho.placement_chirho.assignment_digest_chirho()
        || manifest_chirho.assigned_node_ids_chirho().as_slice()
            != assigned_node_ids_chirho.as_slice()
        || manifest_chirho.expected_term_chirho() != joined_chirho.term_chirho()
        || manifest_chirho.membership_view_digest_chirho()
            != joined_chirho.view_chirho().view_digest_chirho()
    {
        bail!("LedgerMirrorPrefixManifestAuthorityRefusedChirho");
    }
    verify_mirror_receiver_elected_leader_chirho(
        &joined_chirho,
        manifest_chirho.origin_leader_node_id_chirho(),
        manifest_chirho.expected_term_chirho(),
    )
    .map_err(|_| anyhow::anyhow!("LedgerMirrorPrefixManifestAuthorityRefusedChirho"))?;
    verify_holder_selection_chirho(
        state_chirho,
        &joined_chirho,
        manifest_chirho.origin_leader_node_id_chirho(),
    )
    .map_err(|_| anyhow::anyhow!("LedgerMirrorPrefixManifestAuthorityRefusedChirho"))
}

async fn prepare_handler_chirho(
    State(state_chirho): State<LedgerMirrorServerStateChirho>,
    body_chirho: Bytes,
) -> Response {
    let result_chirho = prepare_chirho(&state_chirho, &body_chirho);
    result_response_chirho(LedgerMirrorRequestStageChirho::PrepareChirho, result_chirho)
}

fn prepare_chirho(
    state_chirho: &LedgerMirrorServerStateChirho,
    body_chirho: &[u8],
) -> std::result::Result<Vec<u8>, MirrorContractErrorChirho> {
    let joined_chirho = join_mirror_view_chirho(
        &state_chirho.placement_chirho,
        state_chirho.election_view_chirho.as_ref(),
    )?;
    let roster_chirho = joined_chirho.view_chirho().relay_roster_chirho()?;
    let authenticated_chirho =
        decode_and_authenticate_mirror_prepare_chirho(body_chirho, &roster_chirho)?;
    let verified_chirho = authenticated_chirho.bind_destination_chirho(
        joined_chirho
            .view_chirho()
            .consistency_group_digest_chirho(),
        &state_chirho.local_node_id_chirho,
        &roster_chirho,
    )?;
    verify_mirror_prepare_authority_chirho(
        &verified_chirho,
        &joined_chirho,
        &state_chirho.local_node_id_chirho,
        state_chirho.clock_chirho.as_ref(),
        DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO,
    )?;
    verify_holder_selection_chirho(
        state_chirho,
        &joined_chirho,
        verified_chirho.origin_node_id_chirho(),
    )?;
    verify_f1_prepare_chirho(&verified_chirho)?;
    let record_chirho =
        LedgerMirrorRecordChirho::from_manifest_chirho(verified_chirho.manifest_chirho())
            .map_err(|_| MirrorContractErrorChirho::closure_unverified_chirho())?;
    state_chirho
        .store_chirho
        .verify_record_chirho(&record_chirho)
        .map_err(|_| MirrorContractErrorChirho::closure_unverified_chirho())?;
    state_chirho
        .store_chirho
        .prepare_chirho(verified_chirho.frame_chirho().clone(), record_chirho)
        // A single catch-all here previously reported EVERY store refusal as in-doubt. That was
        // wrong twice over: it stamped provably pre-durable continuity refusals as
        // may-have-executed, and it erased the only string naming WHY the holder refused, so a
        // deterministic cause left the process indistinguishable from a genuine ambiguity.
        // Three cases now, and the split is deliberately asymmetric. A recognized pre-durable
        // refusal reports its own identity and keeps the definitely-not-executed default; a
        // poisoned lock or unreadable store is NOT in that family, because a panic mid-write cannot
        // prove nothing landed; and anything unrecognized falls to the conservative in-doubt
        // identity. Resolving to `None` therefore always lands on the safe side, so a future store
        // refusal that nobody classified cannot be quietly downgraded.
        .map_err(|error_chirho| {
            match crate::store_chirho::prepare_pre_durable_identity_chirho(&error_chirho) {
                Some(identity_chirho) => MirrorContractErrorChirho::new_chirho(
                    identity_chirho,
                    "the holder refused the prepare before any prepared slot was written",
                ),
                None => MirrorContractErrorChirho::new_chirho(
                    MirrorRefusalIdentityChirho::MirrorPrepareStoreOutcomeAmbiguousChirho,
                    "the holder could not prove whether the prepared slot reached durable storage",
                )
                .after_prepare_may_be_durable_chirho(),
            }
        })?;
    signed_receipt_chirho(
        state_chirho,
        LedgerMirrorReceiptBindingChirho {
            prepare_frame_digest_chirho: verified_chirho.prepare_frame_digest_chirho(),
            caller_idempotency_key_digest_chirho: verified_chirho
                .caller_idempotency_key_digest_chirho(),
            consistency_group_digest_chirho: verified_chirho.consistency_group_digest_chirho(),
            mirror_closure_id_chirho: verified_chirho.mirror_closure_id_chirho(),
            actual_term_chirho: joined_chirho.term_chirho(),
            stage_chirho: MirrorReceiptStageChirho::PreparedChirho,
        },
    )
    .map_err(|_| {
        MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorPrepareReceiptEvidencePendingChirho,
            "the prepared slot is durable but its signed receipt could not be returned",
        )
        .after_prepare_may_be_durable_chirho()
    })
}

async fn finalize_handler_chirho(
    State(state_chirho): State<LedgerMirrorServerStateChirho>,
    body_chirho: Bytes,
) -> Response {
    let result_chirho = finalize_chirho(&state_chirho, &body_chirho);
    result_response_chirho(
        LedgerMirrorRequestStageChirho::FinalizeChirho,
        result_chirho,
    )
}

fn finalize_chirho(
    state_chirho: &LedgerMirrorServerStateChirho,
    body_chirho: &[u8],
) -> std::result::Result<Vec<u8>, MirrorContractErrorChirho> {
    let joined_chirho = join_mirror_view_chirho(
        &state_chirho.placement_chirho,
        state_chirho.election_view_chirho.as_ref(),
    )?;
    let roster_chirho = joined_chirho.view_chirho().relay_roster_chirho()?;
    let finalize_chirho = decode_and_verify_mirror_finalize_chirho(
        body_chirho,
        joined_chirho
            .view_chirho()
            .consistency_group_digest_chirho(),
        &state_chirho.local_node_id_chirho,
        &roster_chirho,
    )?;
    verify_mirror_finalize_authority_chirho(
        &finalize_chirho,
        &joined_chirho,
        &state_chirho.local_node_id_chirho,
        state_chirho.clock_chirho.as_ref(),
        DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO,
    )?;
    verify_holder_selection_chirho(
        state_chirho,
        &joined_chirho,
        finalize_chirho.origin_node_id_chirho(),
    )?;

    if let Some(slot_chirho) = state_chirho
        .store_chirho
        .load_prepared_chirho()
        .map_err(|_| {
            MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorPreparedSlotUnreadableChirho,
                "the prepared slot exists or may exist but cannot be read safely",
            )
            .after_prepare_may_be_durable_chirho()
        })?
    {
        let prepared_slot_verification_refusal_chirho = || {
            MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorPreparedSlotVerificationRefusedChirho,
                "the durable prepared slot does not re-verify as the request originally stored",
            )
            .after_prepare_may_be_durable_chirho()
        };
        let prepared_wire_chirho = slot_chirho
            .prepare_chirho
            .to_wire_bytes_chirho()
            .map_err(|_| prepared_slot_verification_refusal_chirho())?;
        let prepared_authenticated_chirho =
            decode_and_authenticate_mirror_prepare_chirho(&prepared_wire_chirho, &roster_chirho)
                .map_err(|_| prepared_slot_verification_refusal_chirho())?;
        let prepared_verified_chirho = prepared_authenticated_chirho
            .bind_destination_chirho(
                joined_chirho
                    .view_chirho()
                    .consistency_group_digest_chirho(),
                &state_chirho.local_node_id_chirho,
                &roster_chirho,
            )
            .map_err(|_| prepared_slot_verification_refusal_chirho())?;
        // Keep lease/term/view refusals distinct. They are runtime authority facts, even though the
        // frame being checked came from the durable slot rather than the current request.
        verify_mirror_prepare_authority_chirho(
            &prepared_verified_chirho,
            &joined_chirho,
            &state_chirho.local_node_id_chirho,
            state_chirho.clock_chirho.as_ref(),
            DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO,
        )?;
        verify_f1_prepare_chirho(&prepared_verified_chirho)
            .map_err(|_| prepared_slot_verification_refusal_chirho())?;
        state_chirho
            .store_chirho
            .verify_record_chirho(&slot_chirho.record_chirho)
            .map_err(|_| prepared_slot_verification_refusal_chirho())?;
        verify_finalize_binds_prepare_chirho(
            &finalize_chirho,
            &prepared_verified_chirho,
            &slot_chirho.record_chirho,
        )?;
        let high_water_chirho = LedgerMirrorHighWaterChirho::sign_chirho(
            LedgerMirrorHighWaterInputChirho {
                consistency_group_digest_chirho: finalize_chirho
                    .consistency_group_digest_chirho()
                    .to_string(),
                origin_leader_node_id_chirho: finalize_chirho.origin_node_id_chirho().to_string(),
                holder_node_id_chirho: state_chirho.local_node_id_chirho.clone(),
                assignment_digest_chirho: state_chirho
                    .placement_chirho
                    .assignment_digest_chirho()
                    .to_string(),
                assigned_node_ids_chirho: state_chirho
                    .placement_chirho
                    .assigned_nodes_chirho()
                    .iter()
                    .map(|node_chirho| node_chirho.node_id_chirho.clone())
                    .collect::<Vec<_>>()
                    .try_into()
                    .map_err(|_| {
                        MirrorContractErrorChirho::new_chirho(
                            MirrorRefusalIdentityChirho::MirrorAssignedNodePopulationRefusedChirho,
                            "the verified placement does not contain exactly three assigned voters",
                        )
                        .after_prepare_may_be_durable_chirho()
                    })?,
                membership_view_digest_chirho: finalize_chirho
                    .membership_view_digest_chirho()
                    .to_string(),
                historical_term_chirho: finalize_chirho.expected_term_chirho(),
                mirror_closure_id_chirho: finalize_chirho.mirror_closure_id_chirho().to_string(),
                prepare_frame_digest_chirho: finalize_chirho
                    .prepare_frame_digest_chirho()
                    .to_string(),
                caller_idempotency_key_digest_chirho: finalize_chirho
                    .caller_idempotency_key_digest_chirho()
                    .to_string(),
                record_chirho: slot_chirho.record_chirho.clone(),
            },
            &state_chirho.sign_root_chirho,
        )
        .map_err(|_| {
            MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorFinalizeEvidenceConstructionRefusedChirho,
                "the holder could not construct the signed finalized high-water evidence",
            )
            .after_prepare_may_be_durable_chirho()
        })?;
        state_chirho
            .store_chirho
            .finalize_chirho(
                finalize_chirho.prepare_frame_digest_chirho(),
                &slot_chirho.record_chirho,
                &high_water_chirho,
            )
            .map_err(|_| {
                MirrorContractErrorChirho::new_chirho(
                    MirrorRefusalIdentityChirho::MirrorFinalizeStoreOutcomeAmbiguousChirho,
                    "the holder could not prove whether finalization reached durable storage",
                )
                .after_prepare_may_be_durable_chirho()
            })?;
    } else {
        let high_water_chirho = state_chirho
            .store_chirho
            .load_high_water_chirho()
            .map_err(|_| {
                MirrorContractErrorChirho::new_chirho(
                    MirrorRefusalIdentityChirho::MirrorFinalizedHighWaterUnreadableChirho,
                    "the finalized high-water exists or may exist but cannot be read safely",
                )
                .after_prepare_may_be_durable_chirho()
            })?
            .ok_or_else(|| {
                MirrorContractErrorChirho::new_chirho(
                    MirrorRefusalIdentityChirho::MirrorPreparedSlotUnavailableChirho,
                    "neither a prepared slot nor a finalized high-water can answer this finalize",
                )
                .after_prepare_may_be_durable_chirho()
            })?;
        if !high_water_chirho.matches_finalize_replay_chirho(&finalize_chirho) {
            return Err(MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorFinalizedReplayBindingRefusedChirho,
                "the finalize replay does not bind the holder's durable finalized high-water",
            )
            .after_prepare_may_be_durable_chirho());
        }
    }

    signed_receipt_chirho(
        state_chirho,
        LedgerMirrorReceiptBindingChirho {
            prepare_frame_digest_chirho: finalize_chirho.prepare_frame_digest_chirho(),
            caller_idempotency_key_digest_chirho: finalize_chirho
                .caller_idempotency_key_digest_chirho(),
            consistency_group_digest_chirho: finalize_chirho.consistency_group_digest_chirho(),
            mirror_closure_id_chirho: finalize_chirho.mirror_closure_id_chirho(),
            actual_term_chirho: joined_chirho.term_chirho(),
            stage_chirho: MirrorReceiptStageChirho::FinalizedChirho,
        },
    )
    .map_err(|_| {
        MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorFinalizeCommittedEvidencePendingChirho,
            "finalization is durable but its signed receipt could not be returned",
        )
        .after_prepare_may_be_durable_chirho()
    })
}

#[cfg(test)]
pub(crate) fn finalize_result_for_test_chirho(
    state_chirho: &LedgerMirrorServerStateChirho,
    body_chirho: &[u8],
) -> std::result::Result<Vec<u8>, MirrorContractErrorChirho> {
    finalize_chirho(state_chirho, body_chirho)
}

fn verify_f1_prepare_chirho(
    verified_chirho: &VerifiedMirrorPrepareChirho,
) -> std::result::Result<(), MirrorContractErrorChirho> {
    let payloads_chirho = verified_chirho.verify_inline_payloads_against_manifest_chirho()?;
    if !payloads_chirho.is_empty() {
        return Err(MirrorContractErrorChirho::closure_unverified_chirho());
    }
    LedgerMirrorRecordChirho::from_manifest_chirho(verified_chirho.manifest_chirho())
        .map_err(|_| MirrorContractErrorChirho::closure_unverified_chirho())?;
    Ok(())
}

fn verify_holder_selection_chirho(
    state_chirho: &LedgerMirrorServerStateChirho,
    joined_chirho: &cairn_mirror_chirho::JoinedMirrorViewChirho,
    leader_node_id_chirho: &str,
) -> std::result::Result<(), MirrorContractErrorChirho> {
    let holder_set_chirho = cairn_mirror_chirho::MirrorHolderSetChirho::select_chirho(
        joined_chirho.view_chirho(),
        leader_node_id_chirho,
        &state_chirho.residency_chirho,
    )?;
    if !holder_set_chirho
        .mirror_holders_chirho()
        .iter()
        .any(|holder_chirho| holder_chirho.node_id_chirho() == state_chirho.local_node_id_chirho)
    {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorRecipientMismatchChirho,
            "the request reached a rostered receiver outside the exact selected holder set",
        ));
    }
    Ok(())
}

fn verify_finalize_binds_prepare_chirho(
    finalize_chirho: &VerifiedMirrorFinalizeChirho,
    prepare_chirho: &VerifiedMirrorPrepareChirho,
    record_chirho: &LedgerMirrorRecordChirho,
) -> std::result::Result<(), MirrorContractErrorChirho> {
    if finalize_chirho.prepare_frame_digest_chirho() != prepare_chirho.prepare_frame_digest_chirho()
        || finalize_chirho.mirror_closure_id_chirho() != prepare_chirho.mirror_closure_id_chirho()
        || finalize_chirho.caller_idempotency_key_digest_chirho()
            != prepare_chirho.caller_idempotency_key_digest_chirho()
        || finalize_chirho.origin_node_id_chirho() != prepare_chirho.origin_node_id_chirho()
        || finalize_chirho.local_commit_binding_chirho() != record_chirho.record_digest_chirho
    {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorFinalizePreparedBindingRefusedChirho,
            "the finalize request does not bind the exact durable prepared frame and record",
        )
        .after_prepare_may_be_durable_chirho());
    }
    Ok(())
}

struct LedgerMirrorReceiptBindingChirho<'binding_chirho> {
    prepare_frame_digest_chirho: &'binding_chirho str,
    caller_idempotency_key_digest_chirho: &'binding_chirho str,
    consistency_group_digest_chirho: &'binding_chirho str,
    mirror_closure_id_chirho: &'binding_chirho str,
    actual_term_chirho: u64,
    stage_chirho: MirrorReceiptStageChirho,
}

fn signed_receipt_chirho(
    state_chirho: &LedgerMirrorServerStateChirho,
    binding_chirho: LedgerMirrorReceiptBindingChirho<'_>,
) -> Result<Vec<u8>> {
    #[cfg(test)]
    if state_chirho.receipt_refusal_stage_chirho == Some(binding_chirho.stage_chirho) {
        bail!("LedgerMirrorTestReceiptRefusalChirho");
    }
    let prepared_chirho = PreparedMirrorReceiptChirho::new_chirho(MirrorReceiptInputChirho {
        prepare_frame_digest_chirho: binding_chirho.prepare_frame_digest_chirho.to_string(),
        caller_idempotency_key_digest_chirho: binding_chirho
            .caller_idempotency_key_digest_chirho
            .to_string(),
        responder_node_id_chirho: state_chirho.local_node_id_chirho.clone(),
        consistency_group_digest_chirho: binding_chirho.consistency_group_digest_chirho.to_string(),
        mirror_closure_id_chirho: binding_chirho.mirror_closure_id_chirho.to_string(),
        actual_term_chirho: binding_chirho.actual_term_chirho,
        stage_chirho: binding_chirho.stage_chirho,
        durable_commit_class_chirho:
            MirrorDurableCommitClassChirho::SignedLedgerRecordNativeDurableChirho,
    })?;
    let possession_chirho =
        cairn_signer_chirho::signer_chirho::sign_with_existing_key_possession_chirho(
            &state_chirho.sign_root_chirho,
            &prepared_chirho.signing_digest_chirho(),
        )?;
    if possession_chirho.key_id_chirho() != state_chirho.local_node_id_chirho {
        bail!("LedgerMirrorReceiptSignerIdentityRefusedChirho");
    }
    Ok(prepared_chirho
        .into_signed_chirho(possession_chirho.into_signature_hex_chirho())?
        .to_wire_bytes_chirho()?)
}

fn result_response_chirho(
    stage_chirho: LedgerMirrorRequestStageChirho,
    result_chirho: std::result::Result<Vec<u8>, MirrorContractErrorChirho>,
) -> Response {
    match result_chirho {
        Ok(bytes_chirho) => (
            [(header::CONTENT_TYPE, "application/octet-stream")],
            bytes_chirho,
        )
            .into_response(),
        Err(error_chirho) => {
            let identity_chirho = error_chirho.identity_chirho().as_str_chirho();
            eprintln!(
                "{}:{}",
                stage_chirho.refusal_log_prefix_chirho(),
                identity_chirho
            );
            (StatusCode::CONFLICT, identity_chirho).into_response()
        }
    }
}

fn recovery_result_response_chirho(result_chirho: Result<Vec<u8>>) -> Response {
    match result_chirho {
        Ok(bytes_chirho) => (
            [(header::CONTENT_TYPE, "application/octet-stream")],
            bytes_chirho,
        )
            .into_response(),
        Err(error_chirho) => {
            let detail_chirho = error_chirho.to_string();
            match prefix_refusal_identity_in_detail_chirho(&detail_chirho) {
                Some(identity_chirho) => {
                    (StatusCode::CONFLICT, identity_chirho.to_string()).into_response()
                }
                None => StatusCode::CONFLICT.into_response(),
            }
        }
    }
}

fn ordinary_term_result_response_chirho(result_chirho: Result<Vec<u8>>) -> Response {
    match result_chirho {
        Ok(bytes_chirho) => (
            [(header::CONTENT_TYPE, "application/octet-stream")],
            bytes_chirho,
        )
            .into_response(),
        Err(error_chirho) => {
            let detail_chirho = error_chirho.to_string();
            let identity_chirho = [
                "LedgerMirrorOrdinaryTermRequestAuthorityRefusedChirho",
                "LedgerMirrorReceiverHolderSelectionRefusedChirho",
                "LedgerMirrorOrdinaryTermLiveHighWaterUnavailableChirho",
                "LedgerMirrorOrdinaryTermLiveHighWaterBindingRefusedChirho",
                "LedgerMirrorOrdinaryTermAuthorityChangedAfterHighWaterReadChirho",
            ]
            .into_iter()
            .find(|identity_chirho| detail_chirho.contains(identity_chirho));
            match identity_chirho {
                Some(identity_chirho) => {
                    (StatusCode::CONFLICT, identity_chirho.to_owned()).into_response()
                }
                None => StatusCode::CONFLICT.into_response(),
            }
        }
    }
}
