// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Private, roster-authenticated GD7 winner-view transfer on the election listener.
//!
//! Each request performs one bounded operation through the existing resident actor. A response is
//! a canonical signed header followed by at most one raw canonical bundle page. No caller supplies
//! a storage path, object family, page size, cursor, adoption target, compensation, ref movement,
//! effect append, or write-enablement input.

use anyhow::{anyhow, bail, Context, Result};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Extension, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use cairn_ledger_host_chirho::reconciliation_chirho::{
    gd7_winner_handoff_attempt_digest_chirho,
    parse_canonical_gd7_winner_current_view_challenge_chirho, ExistingNodeGd7SignerChirho,
    Gd7HeldViewTransferCheckpointChirho, Gd7HeldViewTransferIdentityChirho,
    Gd7ReconciliationCheckpointChirho, Gd7ReconciliationSignerPortChirho,
    Gd7ReconciliationVerifierPortChirho, Gd7WinnerCurrentViewInspectionChirho,
    Gd7WinnerCurrentViewRefusalChirho, Gd7WinnerEvidenceManifestChirho,
    Gd7WinnerEvidencePageGrantChirho, Gd7WinnerHandoffAttemptIdentityChirho,
    Gd7WinnerHandoffPhaseChirho, Gd7WinnerViewPageGrantChirho, PinnedNodeGd7VerifierChirho,
    MAX_GD7_HELD_VIEW_TRANSFER_CHECKPOINT_BYTES_CHIRHO,
    MAX_GD7_RECONCILIATION_CHECKPOINT_BYTES_CHIRHO,
    MAX_GD7_WINNER_CURRENT_VIEW_CHALLENGE_BYTES_CHIRHO,
    MAX_GD7_WINNER_EVIDENCE_MANIFEST_BYTES_CHIRHO, MAX_GD7_WINNER_EVIDENCE_PAGE_GRANT_BYTES_CHIRHO,
    MAX_GD7_WINNER_HISTORY_PAGE_BYTES_CHIRHO, MAX_GD7_WINNER_VIEW_PAGE_GRANT_BYTES_CHIRHO,
};
use cairn_ledger_host_chirho::{
    ResidentGd7WinnerAdoptionEvidenceHandleChirho,
    ResidentGd7WinnerAdoptionEvidenceInspectionChirho,
    ResidentGd7WinnerAdoptionEvidenceRefusalChirho, ResidentGd7WinnerEvidenceHandleChirho,
    ResidentGd7WinnerEvidenceRefusalChirho, ResidentGd7WinnerHandoffHandleChirho,
    ResidentGd7WinnerHandoffRefusalChirho, ResidentGd7WinnerHandoffStatusChirho,
    ResidentGd7WinnerViewSealChirho, ResidentGd7WinnerViewStageInspectionChirho,
};
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_chirho::LocalAppendAuthorityRefusalChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use url::{Host, Url};

#[path = "winner_view_transfer_chirho/client_chirho.rs"]
mod client_chirho;
pub(crate) use client_chirho::call_winner_view_transfer_chirho;

pub(crate) const GD7_WINNER_VIEW_TRANSFER_PATH_CHIRHO: &str = "/gd7-winner-view-transfer-chirho";
const GD7_WINNER_VIEW_TRANSFER_REQUEST_SCHEMA_V1_CHIRHO: &str =
    "gd7-winner-view-transfer-request-v1-chirho";
const GD7_WINNER_VIEW_TRANSFER_RESPONSE_SCHEMA_V1_CHIRHO: &str =
    "gd7-winner-view-transfer-response-v1-chirho";
const MAX_GD7_WINNER_VIEW_TRANSFER_REQUEST_BYTES_CHIRHO: usize =
    MAX_GD7_HELD_VIEW_TRANSFER_CHECKPOINT_BYTES_CHIRHO
        + MAX_GD7_RECONCILIATION_CHECKPOINT_BYTES_CHIRHO
        + 32 * 1024;
const MAX_GD7_WINNER_VIEW_TRANSFER_HEADER_BYTES_CHIRHO: usize = 64 * 1024;
const MAX_GD7_WINNER_VIEW_TRANSFER_PAGE_BYTES_CHIRHO: usize =
    MAX_GD7_WINNER_HISTORY_PAGE_BYTES_CHIRHO;
const MAX_GD7_WINNER_VIEW_TRANSFER_RESPONSE_BYTES_CHIRHO: usize = 4
    + MAX_GD7_WINNER_VIEW_TRANSFER_HEADER_BYTES_CHIRHO
    + MAX_GD7_WINNER_VIEW_TRANSFER_PAGE_BYTES_CHIRHO;
const MAX_GD7_WINNER_VIEW_TRANSFER_INFLIGHT_CHIRHO: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation_chirho", content = "input_chirho")]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub(crate) enum Gd7WinnerViewTransferOperationChirho {
    StageOnePageChirho {
        expected_stage_index_chirho: u64,
    },
    SealCurrentViewChirho {
        canonical_challenge_chirho: String,
    },
    FetchGrantedPageChirho {
        grant_chirho: Box<Gd7WinnerViewPageGrantChirho>,
    },
    BeginHandoffChirho {
        held_transfer_identity_chirho: Box<Gd7HeldViewTransferIdentityChirho>,
        reconciliation_checkpoint_chirho: Box<Gd7ReconciliationCheckpointChirho>,
        held_transfer_checkpoint_ref_chirho: String,
        held_transfer_checkpoint_chirho: Box<Gd7HeldViewTransferCheckpointChirho>,
        expected_bundle_root_object_digest_chirho: String,
        canonical_challenge_chirho: String,
    },
    HandoffStatusChirho {
        attempt_digest_chirho: String,
    },
    AbortHandoffChirho {
        attempt_digest_chirho: String,
    },
    PrepareAdoptionEvidenceChirho,
    FetchAdoptionEvidencePageChirho {
        grant_chirho: Box<Gd7WinnerEvidencePageGrantChirho>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gd7WinnerViewTransferRequestChirho {
    schema_chirho: String,
    consistency_group_digest_chirho: String,
    sender_node_chirho: String,
    recipient_node_chirho: String,
    transfer_identity_digest_chirho: String,
    expected_raft_term_chirho: u64,
    nonce_chirho: String,
    operation_chirho: Gd7WinnerViewTransferOperationChirho,
    key_id_chirho: String,
    sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result_chirho", content = "output_chirho")]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub(crate) enum Gd7WinnerViewTransferResultChirho {
    StageAdvancedChirho,
    StageReadyChirho {
        bundle_root_object_digest_chirho: String,
        page_count_chirho: u64,
        row_count_chirho: u64,
    },
    ViewSealedChirho {
        inspection_chirho: Gd7WinnerCurrentViewInspectionChirho,
        first_page_grant_chirho: Option<Gd7WinnerViewPageGrantChirho>,
    },
    PageFetchedChirho {
        grant_chirho: Gd7WinnerViewPageGrantChirho,
        next_grant_chirho: Option<Gd7WinnerViewPageGrantChirho>,
    },
    HandoffStatusChirho {
        status_chirho: Box<ResidentGd7WinnerHandoffStatusChirho>,
    },
    AdoptionEvidenceStageAdvancedChirho,
    AdoptionEvidenceReadyChirho {
        manifest_chirho: Box<Gd7WinnerEvidenceManifestChirho>,
    },
    AdoptionEvidencePageFetchedChirho {
        grant_chirho: Gd7WinnerEvidencePageGrantChirho,
        next_grant_chirho: Option<Gd7WinnerEvidencePageGrantChirho>,
    },
    RefusedChirho {
        code_chirho: Gd7WinnerViewTransferRefusalCodeChirho,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub(crate) enum Gd7WinnerViewTransferRefusalCodeChirho {
    InvalidRequestChirho,
    UnauthenticatedPeerChirho,
    LeadershipChangedChirho,
    ActorBusyChirho,
    ActorUnavailableChirho,
    ActorStateChangedChirho,
    ActorRefusedChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gd7WinnerViewTransferResponseHeaderChirho {
    schema_chirho: String,
    consistency_group_digest_chirho: String,
    request_digest_chirho: String,
    winner_node_chirho: String,
    raft_term_chirho: u64,
    result_chirho: Gd7WinnerViewTransferResultChirho,
    payload_length_chirho: u64,
    payload_digest_chirho: String,
    key_id_chirho: String,
    sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Gd7WinnerViewTransferReplyChirho {
    pub result_chirho: Gd7WinnerViewTransferResultChirho,
    pub canonical_page_bytes_chirho: Vec<u8>,
}

pub(crate) struct Gd7WinnerViewTransferCallContextChirho<'a> {
    pub agent_chirho: &'a ureq::Agent,
    pub base_url_chirho: &'a str,
    pub consistency_group_digest_chirho: &'a str,
    pub sender_signer_chirho: &'a ExistingNodeGd7SignerChirho,
    pub winner_node_chirho: &'a NodeIdChirho,
    pub transfer_identity_digest_chirho: &'a str,
    pub expected_raft_term_chirho: u64,
    pub request_nonce_chirho: &'a str,
}

struct Gd7WinnerViewTransferStateChirho {
    consistency_group_digest_chirho: String,
    local_node_chirho: NodeIdChirho,
    held_node_chirho: NodeIdChirho,
    held_raft_id_chirho: u64,
    elector_chirho: Arc<RaftWriterElectorChirho>,
    signer_chirho: ExistingNodeGd7SignerChirho,
    session_chirho: Mutex<Gd7WinnerViewTransferSessionChirho>,
    inflight_chirho: AtomicUsize,
}

#[derive(Clone)]
struct Gd7WinnerViewTransferHandlesChirho {
    evidence_chirho: ResidentGd7WinnerEvidenceHandleChirho,
    handoff_chirho: ResidentGd7WinnerHandoffHandleChirho,
    adoption_evidence_chirho: ResidentGd7WinnerAdoptionEvidenceHandleChirho,
}

struct Gd7WinnerViewTransferSessionChirho {
    winner_handles_chirho: Option<Gd7WinnerViewTransferHandlesChirho>,
    active_transfer_identity_digest_chirho: Option<String>,
}

struct Gd7WinnerViewTransferAdmissionChirho {
    state_chirho: Arc<Gd7WinnerViewTransferStateChirho>,
}

impl Drop for Gd7WinnerViewTransferAdmissionChirho {
    fn drop(&mut self) {
        self.state_chirho
            .inflight_chirho
            .fetch_sub(1, Ordering::AcqRel);
    }
}

/// One install-once transfer surface sharing the election node's exact elector and resident actor.
#[derive(Clone)]
pub(crate) struct Gd7WinnerViewTransferServiceChirho {
    state_chirho: Arc<Gd7WinnerViewTransferStateChirho>,
}

impl Gd7WinnerViewTransferServiceChirho {
    pub(crate) fn open_chirho(
        node_sign_root_chirho: &Path,
        group_chirho: &ConsistencyGroupIdChirho,
        local_node_chirho: NodeIdChirho,
        held_node_chirho: NodeIdChirho,
        elector_chirho: Arc<RaftWriterElectorChirho>,
    ) -> Result<Self> {
        let authenticated_local_count_chirho = elector_chirho
            .authenticated_members_chirho()
            .iter()
            .filter(|(_raft_id_chirho, node_chirho)| node_chirho == &local_node_chirho)
            .count();
        if authenticated_local_count_chirho != 1 {
            bail!("winner-view transfer local node is not uniquely authenticated");
        }
        if held_node_chirho == local_node_chirho {
            bail!("winner-view transfer held recipient cannot equal the local winner");
        }
        let held_raft_ids_chirho = elector_chirho
            .authenticated_members_chirho()
            .iter()
            .filter(|(_raft_id_chirho, node_chirho)| node_chirho == &held_node_chirho)
            .map(|(raft_id_chirho, _node_chirho)| *raft_id_chirho)
            .collect::<Vec<_>>();
        let [held_raft_id_chirho] = held_raft_ids_chirho.as_slice() else {
            bail!("winner-view transfer held recipient is not uniquely authenticated");
        };
        let (voters_chirho, learners_chirho) = elector_chirho
            .membership_snapshot_chirho()
            .context("read winner-view transfer membership")?;
        if voters_chirho.contains(held_raft_id_chirho)
            || learners_chirho.as_slice() != [*held_raft_id_chirho]
        {
            bail!("winner-view transfer requires one exact authenticated held learner");
        }
        let signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
            node_sign_root_chirho,
            &local_node_chirho,
        )
        .context("open existing winner-view transfer signer")?;
        Ok(Self {
            state_chirho: Arc::new(Gd7WinnerViewTransferStateChirho {
                consistency_group_digest_chirho: consistency_group_digest_chirho(group_chirho)?,
                local_node_chirho,
                held_node_chirho,
                held_raft_id_chirho: *held_raft_id_chirho,
                elector_chirho,
                signer_chirho,
                session_chirho: Mutex::new(Gd7WinnerViewTransferSessionChirho {
                    winner_handles_chirho: None,
                    active_transfer_identity_digest_chirho: None,
                }),
                inflight_chirho: AtomicUsize::new(0),
            }),
        })
    }

    pub(crate) fn install_winner_handles_chirho(
        &self,
        evidence_chirho: ResidentGd7WinnerEvidenceHandleChirho,
        handoff_chirho: ResidentGd7WinnerHandoffHandleChirho,
        adoption_evidence_chirho: ResidentGd7WinnerAdoptionEvidenceHandleChirho,
    ) -> Result<()> {
        let mut session_chirho = self
            .state_chirho
            .session_chirho
            .lock()
            .map_err(|_poison_chirho| anyhow!("winner-view transfer session lock is poisoned"))?;
        if session_chirho.winner_handles_chirho.is_some() {
            bail!("winner-view transfer actor handles are already installed");
        }
        let restored_status_chirho = handoff_chirho
            .current_chirho()
            .context("restore winner-view transfer binding from durable actor state")?;
        if let Some(status_chirho) = restored_status_chirho.as_ref() {
            let identity_chirho = &status_chirho
                .attempt_identity_chirho
                .held_transfer_identity_chirho;
            if identity_chirho.consistency_group_digest_chirho
                != self.state_chirho.consistency_group_digest_chirho
                || identity_chirho.winner_node_chirho != self.state_chirho.local_node_chirho.0
                || identity_chirho.held_node_chirho != self.state_chirho.held_node_chirho.0
            {
                bail!("durable winner handoff differs from the transfer service identity");
            }
        }
        session_chirho.active_transfer_identity_digest_chirho =
            match restored_status_chirho.as_ref() {
                Some(status_chirho)
                    if status_chirho.phase_chirho != Gd7WinnerHandoffPhaseChirho::AbortedChirho =>
                {
                    Some(transfer_identity_digest_from_status_chirho(status_chirho)?)
                }
                Some(_) | None => None,
            };
        session_chirho.winner_handles_chirho = Some(Gd7WinnerViewTransferHandlesChirho {
            evidence_chirho,
            handoff_chirho,
            adoption_evidence_chirho,
        });
        Ok(())
    }

    pub(crate) fn router_chirho(&self) -> Router {
        let admission_state_chirho = self.clone();
        Router::new()
            .route(
                GD7_WINNER_VIEW_TRANSFER_PATH_CHIRHO,
                post(post_winner_view_transfer_chirho),
            )
            .layer(DefaultBodyLimit::max(
                MAX_GD7_WINNER_VIEW_TRANSFER_REQUEST_BYTES_CHIRHO,
            ))
            .route_layer(middleware::from_fn_with_state(
                admission_state_chirho,
                admit_winner_view_transfer_chirho,
            ))
            .with_state(self.clone())
    }

    fn try_admit_chirho(&self) -> Option<Arc<Gd7WinnerViewTransferAdmissionChirho>> {
        self.state_chirho
            .inflight_chirho
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |inflight_chirho| {
                (inflight_chirho < MAX_GD7_WINNER_VIEW_TRANSFER_INFLIGHT_CHIRHO)
                    .then_some(inflight_chirho + 1)
            })
            .ok()
            .map(|_prior_chirho| {
                Arc::new(Gd7WinnerViewTransferAdmissionChirho {
                    state_chirho: Arc::clone(&self.state_chirho),
                })
            })
    }

    fn handle_chirho(&self, request_bytes_chirho: &[u8]) -> Result<Vec<u8>> {
        let request_digest_chirho = digest_bytes_chirho(request_bytes_chirho);
        let parsed_chirho = parse_canonical_bounded_chirho::<Gd7WinnerViewTransferRequestChirho>(
            request_bytes_chirho,
            MAX_GD7_WINNER_VIEW_TRANSFER_REQUEST_BYTES_CHIRHO,
        );
        let request_chirho = match parsed_chirho {
            Ok(request_chirho) => request_chirho,
            Err(_error_chirho) => {
                return self.signed_response_chirho(
                    &request_digest_chirho,
                    self.state_chirho
                        .elector_chirho
                        .current_leadership_chirho()
                        .term_chirho,
                    Gd7WinnerViewTransferResultChirho::RefusedChirho {
                        code_chirho: Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho,
                    },
                    &[],
                );
            }
        };
        let leadership_chirho = match self.verify_request_chirho(&request_chirho) {
            Ok(leadership_chirho) => leadership_chirho,
            Err(code_chirho) => {
                return self.signed_response_chirho(
                    &request_digest_chirho,
                    self.state_chirho
                        .elector_chirho
                        .current_leadership_chirho()
                        .term_chirho,
                    Gd7WinnerViewTransferResultChirho::RefusedChirho { code_chirho },
                    &[],
                );
            }
        };
        let stage_zero_chirho = matches!(
            &request_chirho.operation_chirho,
            Gd7WinnerViewTransferOperationChirho::StageOnePageChirho {
                expected_stage_index_chirho: 0
            }
        );
        let handoff_operation_chirho =
            is_handoff_operation_chirho(&request_chirho.operation_chirho);
        let requested_transfer_identity_digest_chirho =
            request_chirho.transfer_identity_digest_chirho.clone();
        // The session lock spans binding verification, actor execution, and the binding update.
        // This makes Stage-0 admission and durable handoff recovery one serialized transition.
        let mut session_chirho = self
            .state_chirho
            .session_chirho
            .lock()
            .map_err(|_poison_chirho| anyhow!("winner-view transfer session lock is poisoned"))?;
        let Some(winner_handles_chirho) = session_chirho.winner_handles_chirho.clone() else {
            return self.signed_response_chirho(
                &request_digest_chirho,
                leadership_chirho.term_chirho,
                Gd7WinnerViewTransferResultChirho::RefusedChirho {
                    code_chirho: Gd7WinnerViewTransferRefusalCodeChirho::ActorUnavailableChirho,
                },
                &[],
            );
        };
        if handoff_operation_chirho {
            if let Err(code_chirho) = self.verify_handoff_operation_binding_chirho(
                &request_chirho,
                &winner_handles_chirho.handoff_chirho,
                session_chirho
                    .active_transfer_identity_digest_chirho
                    .as_deref(),
            ) {
                return self.signed_response_chirho(
                    &request_digest_chirho,
                    leadership_chirho.term_chirho,
                    Gd7WinnerViewTransferResultChirho::RefusedChirho { code_chirho },
                    &[],
                );
            }
        } else if let Err(code_chirho) = verify_staging_operation_binding_chirho(
            &request_chirho,
            session_chirho
                .active_transfer_identity_digest_chirho
                .as_deref(),
        ) {
            return self.signed_response_chirho(
                &request_digest_chirho,
                leadership_chirho.term_chirho,
                Gd7WinnerViewTransferResultChirho::RefusedChirho { code_chirho },
                &[],
            );
        }
        let sender_node_chirho = NodeIdChirho(request_chirho.sender_node_chirho.clone());
        let mut operation_result_chirho: std::result::Result<
            (Gd7WinnerViewTransferResultChirho, Vec<u8>),
            Gd7WinnerViewTransferRefusalCodeChirho,
        > = match request_chirho.operation_chirho {
            Gd7WinnerViewTransferOperationChirho::StageOnePageChirho {
                expected_stage_index_chirho,
            } => winner_handles_chirho
                .evidence_chirho
                .stage_view_page_at_chirho(expected_stage_index_chirho)
                .map_err(map_actor_refusal_code_chirho)
                .map(map_stage_inspection_chirho)
                .map(|result_chirho| (result_chirho, Vec::new())),
            Gd7WinnerViewTransferOperationChirho::SealCurrentViewChirho {
                canonical_challenge_chirho,
            } => parse_canonical_gd7_winner_current_view_challenge_chirho(
                canonical_challenge_chirho.as_bytes(),
            )
            .map_err(|_error_chirho| Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho)
            .and_then(|challenge_chirho| {
                winner_handles_chirho
                    .evidence_chirho
                    .seal_current_view_for_held_chirho(challenge_chirho, sender_node_chirho)
                    .map_err(map_actor_refusal_code_chirho)
            })
            .map(map_sealed_view_chirho)
            .map(|result_chirho| (result_chirho, Vec::new())),
            Gd7WinnerViewTransferOperationChirho::FetchGrantedPageChirho { grant_chirho } => {
                winner_handles_chirho
                    .evidence_chirho
                    .fetch_granted_page_chirho(sender_node_chirho, *grant_chirho)
                    .map_err(map_actor_refusal_code_chirho)
                    .map(|page_transfer_chirho| {
                        (
                            Gd7WinnerViewTransferResultChirho::PageFetchedChirho {
                                grant_chirho: page_transfer_chirho.grant_chirho,
                                next_grant_chirho: page_transfer_chirho.next_grant_chirho,
                            },
                            page_transfer_chirho.canonical_page_bytes_chirho,
                        )
                    })
            }
            Gd7WinnerViewTransferOperationChirho::BeginHandoffChirho {
                held_transfer_identity_chirho,
                reconciliation_checkpoint_chirho,
                held_transfer_checkpoint_ref_chirho,
                held_transfer_checkpoint_chirho,
                expected_bundle_root_object_digest_chirho,
                canonical_challenge_chirho,
            } => parse_canonical_gd7_winner_current_view_challenge_chirho(
                canonical_challenge_chirho.as_bytes(),
            )
            .map_err(|_error_chirho| Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho)
            .and_then(|challenge_chirho| {
                winner_handles_chirho
                    .handoff_chirho
                    .begin_chirho(
                        *held_transfer_identity_chirho,
                        reconciliation_checkpoint_chirho,
                        held_transfer_checkpoint_ref_chirho,
                        held_transfer_checkpoint_chirho,
                        expected_bundle_root_object_digest_chirho,
                        challenge_chirho,
                    )
                    .map_err(map_handoff_refusal_code_chirho)
            })
            .map(map_handoff_status_chirho)
            .map(|result_chirho| (result_chirho, Vec::new())),
            Gd7WinnerViewTransferOperationChirho::HandoffStatusChirho {
                attempt_digest_chirho,
            } => winner_handles_chirho
                .handoff_chirho
                .status_chirho(attempt_digest_chirho)
                .map_err(map_handoff_refusal_code_chirho)
                .map(map_handoff_status_chirho)
                .map(|result_chirho| (result_chirho, Vec::new())),
            Gd7WinnerViewTransferOperationChirho::AbortHandoffChirho {
                attempt_digest_chirho,
            } => winner_handles_chirho
                .handoff_chirho
                .abort_chirho(attempt_digest_chirho)
                .map_err(map_handoff_refusal_code_chirho)
                .map(map_handoff_status_chirho)
                .map(|result_chirho| (result_chirho, Vec::new())),
            Gd7WinnerViewTransferOperationChirho::PrepareAdoptionEvidenceChirho => {
                winner_handles_chirho
                    .adoption_evidence_chirho
                    .prepare_next_chirho()
                    .map_err(map_adoption_evidence_refusal_code_chirho)
                    .map(|inspection_chirho| match inspection_chirho {
                        ResidentGd7WinnerAdoptionEvidenceInspectionChirho::AdvancedWinnerHistoryPageChirho => (
                            Gd7WinnerViewTransferResultChirho::AdoptionEvidenceStageAdvancedChirho,
                            Vec::new(),
                        ),
                        ResidentGd7WinnerAdoptionEvidenceInspectionChirho::ReadyChirho(
                            manifest_chirho,
                        ) => (
                            Gd7WinnerViewTransferResultChirho::AdoptionEvidenceReadyChirho {
                                manifest_chirho,
                            },
                            Vec::new(),
                        ),
                    })
            }
            Gd7WinnerViewTransferOperationChirho::FetchAdoptionEvidencePageChirho {
                grant_chirho,
            } => winner_handles_chirho
                .adoption_evidence_chirho
                .fetch_page_chirho(sender_node_chirho, *grant_chirho)
                .map_err(map_adoption_evidence_refusal_code_chirho)
                .map(|evidence_page_transfer_chirho| {
                    (
                        Gd7WinnerViewTransferResultChirho::AdoptionEvidencePageFetchedChirho {
                            grant_chirho: evidence_page_transfer_chirho.grant_chirho,
                            next_grant_chirho: evidence_page_transfer_chirho.next_grant_chirho,
                        },
                        evidence_page_transfer_chirho.canonical_page_bytes_chirho,
                    )
                }),
        };
        let binding_update_chirho: std::result::Result<
            Option<Option<String>>,
            Gd7WinnerViewTransferRefusalCodeChirho,
        > = match operation_result_chirho.as_ref() {
            Ok((Gd7WinnerViewTransferResultChirho::HandoffStatusChirho { status_chirho }, _)) => {
                if status_chirho.phase_chirho == Gd7WinnerHandoffPhaseChirho::AbortedChirho {
                    Ok(Some(None))
                } else {
                    transfer_identity_digest_from_status_chirho(status_chirho)
                        .map(Some)
                        .map(Some)
                        .map_err(|_error_chirho| {
                            Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho
                        })
                }
            }
            Ok((_result_chirho, _payload_chirho)) if stage_zero_chirho => Ok(Some(Some(
                requested_transfer_identity_digest_chirho.clone(),
            ))),
            Ok(_) | Err(_) => Ok(None),
        };
        match binding_update_chirho {
            Ok(Some(next_binding_chirho)) => {
                session_chirho.active_transfer_identity_digest_chirho = next_binding_chirho;
            }
            Ok(None) => {}
            Err(code_chirho) => operation_result_chirho = Err(code_chirho),
        }
        let (result_chirho, payload_chirho) =
            operation_result_chirho.unwrap_or_else(|code_chirho| {
                (
                    Gd7WinnerViewTransferResultChirho::RefusedChirho { code_chirho },
                    Vec::new(),
                )
            });
        drop(session_chirho);
        self.signed_response_chirho(
            &request_digest_chirho,
            leadership_chirho.term_chirho,
            result_chirho,
            &payload_chirho,
        )
    }

    fn verify_request_chirho(
        &self,
        request_chirho: &Gd7WinnerViewTransferRequestChirho,
    ) -> std::result::Result<
        cairn_writer_elector_chirho::elector_port_chirho::LeadershipChirho,
        Gd7WinnerViewTransferRefusalCodeChirho,
    > {
        if request_chirho.schema_chirho != GD7_WINNER_VIEW_TRANSFER_REQUEST_SCHEMA_V1_CHIRHO
            || request_chirho.consistency_group_digest_chirho
                != self.state_chirho.consistency_group_digest_chirho
            || request_chirho.recipient_node_chirho != self.state_chirho.local_node_chirho.0
            || request_chirho.key_id_chirho != request_chirho.sender_node_chirho
            || !is_lower_hex_64_chirho(&request_chirho.sender_node_chirho)
            || !is_lower_hex_64_chirho(&request_chirho.transfer_identity_digest_chirho)
            || !is_lower_hex_64_chirho(&request_chirho.nonce_chirho)
            || request_chirho.sender_node_chirho == request_chirho.recipient_node_chirho
        {
            return Err(Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho);
        }
        if request_chirho.sender_node_chirho != self.state_chirho.held_node_chirho.0 {
            return Err(Gd7WinnerViewTransferRefusalCodeChirho::UnauthenticatedPeerChirho);
        }
        let sender_node_chirho = NodeIdChirho(request_chirho.sender_node_chirho.clone());
        let authenticated_sender_count_chirho = self
            .state_chirho
            .elector_chirho
            .authenticated_members_chirho()
            .iter()
            .filter(|(_raft_id_chirho, node_chirho)| node_chirho == &sender_node_chirho)
            .count();
        if authenticated_sender_count_chirho != 1 {
            return Err(Gd7WinnerViewTransferRefusalCodeChirho::UnauthenticatedPeerChirho);
        }
        self.verify_held_membership_chirho()?;
        let verifier_chirho = PinnedNodeGd7VerifierChirho::new_chirho(sender_node_chirho)
            .map_err(|_| Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho)?;
        let mut unsigned_chirho = request_chirho.clone();
        let signature_chirho = std::mem::take(&mut unsigned_chirho.sig_chirho);
        let unsigned_bytes_chirho = canonical_json_chirho(&unsigned_chirho)
            .map_err(|_| Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho)?;
        let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
            .map_err(|_| Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho)?;
        if !verifier_chirho.verify_chirho(unsigned_line_chirho, &signature_chirho) {
            return Err(Gd7WinnerViewTransferRefusalCodeChirho::UnauthenticatedPeerChirho);
        }
        validate_operation_shape_chirho(&request_chirho.operation_chirho)?;
        validate_operation_binding_chirho(
            &request_chirho.operation_chirho,
            &request_chirho.consistency_group_digest_chirho,
            &request_chirho.sender_node_chirho,
            &request_chirho.recipient_node_chirho,
            &request_chirho.transfer_identity_digest_chirho,
            request_chirho.expected_raft_term_chirho,
        )?;
        let leadership_chirho = self.state_chirho.elector_chirho.current_leadership_chirho();
        if !leadership_chirho.is_leader_chirho
            || !leadership_chirho.lease_valid_chirho
            || leadership_chirho.leader_id_chirho.as_ref()
                != Some(&self.state_chirho.local_node_chirho)
            || leadership_chirho.term_chirho != request_chirho.expected_raft_term_chirho
        {
            return Err(Gd7WinnerViewTransferRefusalCodeChirho::LeadershipChangedChirho);
        }
        Ok(leadership_chirho)
    }

    fn verify_held_membership_chirho(
        &self,
    ) -> std::result::Result<(), Gd7WinnerViewTransferRefusalCodeChirho> {
        let (voters_chirho, learners_chirho) = self
            .state_chirho
            .elector_chirho
            .membership_snapshot_chirho()
            .map_err(|_| Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho)?;
        if voters_chirho.contains(&self.state_chirho.held_raft_id_chirho)
            || learners_chirho.as_slice() != [self.state_chirho.held_raft_id_chirho]
        {
            return Err(Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho);
        }
        Ok(())
    }

    fn verify_handoff_operation_binding_chirho(
        &self,
        request_chirho: &Gd7WinnerViewTransferRequestChirho,
        handoff_chirho: &ResidentGd7WinnerHandoffHandleChirho,
        active_transfer_chirho: Option<&str>,
    ) -> std::result::Result<(), Gd7WinnerViewTransferRefusalCodeChirho> {
        if active_transfer_chirho.is_some_and(|active_chirho| {
            active_chirho != request_chirho.transfer_identity_digest_chirho
        }) {
            return Err(Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho);
        }

        match &request_chirho.operation_chirho {
            Gd7WinnerViewTransferOperationChirho::BeginHandoffChirho {
                held_transfer_identity_chirho,
                held_transfer_checkpoint_ref_chirho,
                expected_bundle_root_object_digest_chirho,
                canonical_challenge_chirho,
                ..
            } => {
                let challenge_chirho = parse_canonical_gd7_winner_current_view_challenge_chirho(
                    canonical_challenge_chirho.as_bytes(),
                )
                .map_err(|_error_chirho| {
                    Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho
                })?;
                let attempt_identity_chirho = Gd7WinnerHandoffAttemptIdentityChirho {
                    held_transfer_identity_chirho: held_transfer_identity_chirho.as_ref().clone(),
                    held_transfer_checkpoint_ref_chirho: held_transfer_checkpoint_ref_chirho
                        .clone(),
                    expected_bundle_root_object_digest_chirho:
                        expected_bundle_root_object_digest_chirho.clone(),
                    challenge_digest_chirho: challenge_chirho.digest_chirho().map_err(
                        |_error_chirho| {
                            Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho
                        },
                    )?,
                };
                verify_handoff_attempt_request_binding_chirho(
                    request_chirho,
                    &attempt_identity_chirho,
                )?;
                if active_transfer_chirho.is_none() {
                    let attempt_digest_chirho =
                        gd7_winner_handoff_attempt_digest_chirho(&attempt_identity_chirho)
                            .map_err(|_error_chirho| {
                                Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho
                            })?;
                    let status_chirho = handoff_chirho
                        .status_chirho(attempt_digest_chirho)
                        .map_err(map_handoff_refusal_code_chirho)?;
                    verify_handoff_status_request_binding_chirho(request_chirho, &status_chirho)?;
                    if status_chirho.attempt_identity_chirho != attempt_identity_chirho {
                        return Err(
                            Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho,
                        );
                    }
                }
                Ok(())
            }
            Gd7WinnerViewTransferOperationChirho::HandoffStatusChirho {
                attempt_digest_chirho,
            }
            | Gd7WinnerViewTransferOperationChirho::AbortHandoffChirho {
                attempt_digest_chirho,
            } => {
                let status_chirho = handoff_chirho
                    .status_chirho(attempt_digest_chirho.clone())
                    .map_err(map_handoff_refusal_code_chirho)?;
                verify_handoff_status_request_binding_chirho(request_chirho, &status_chirho)
            }
            _ => Err(Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho),
        }
    }

    fn signed_response_chirho(
        &self,
        request_digest_chirho: &str,
        raft_term_chirho: u64,
        result_chirho: Gd7WinnerViewTransferResultChirho,
        payload_chirho: &[u8],
    ) -> Result<Vec<u8>> {
        if payload_chirho.len() > MAX_GD7_WINNER_VIEW_TRANSFER_PAGE_BYTES_CHIRHO {
            bail!("winner-view transfer payload exceeds its fixed page bound");
        }
        let payload_length_chirho = u64::try_from(payload_chirho.len())
            .map_err(|_| anyhow!("winner-view transfer payload length cannot fit u64"))?;
        let mut header_chirho = Gd7WinnerViewTransferResponseHeaderChirho {
            schema_chirho: GD7_WINNER_VIEW_TRANSFER_RESPONSE_SCHEMA_V1_CHIRHO.to_owned(),
            consistency_group_digest_chirho: self
                .state_chirho
                .consistency_group_digest_chirho
                .clone(),
            request_digest_chirho: request_digest_chirho.to_owned(),
            winner_node_chirho: self.state_chirho.local_node_chirho.0.clone(),
            raft_term_chirho,
            result_chirho,
            payload_length_chirho,
            payload_digest_chirho: digest_bytes_chirho(payload_chirho),
            key_id_chirho: self.state_chirho.signer_chirho.key_id_chirho(),
            sig_chirho: String::new(),
        };
        let unsigned_bytes_chirho = canonical_json_chirho(&header_chirho)?;
        let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
            .map_err(|_| anyhow!("winner-view transfer response is not UTF-8"))?;
        header_chirho.sig_chirho = self
            .state_chirho
            .signer_chirho
            .sign_chirho(unsigned_line_chirho)?;
        encode_frame_chirho(&header_chirho, payload_chirho)
    }
}

fn verify_staging_operation_binding_chirho(
    request_chirho: &Gd7WinnerViewTransferRequestChirho,
    active_transfer_chirho: Option<&str>,
) -> std::result::Result<(), Gd7WinnerViewTransferRefusalCodeChirho> {
    match active_transfer_chirho {
        Some(active_digest_chirho)
            if active_digest_chirho == request_chirho.transfer_identity_digest_chirho =>
        {
            Ok(())
        }
        Some(_other_chirho) => Err(Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho),
        None if matches!(
            &request_chirho.operation_chirho,
            Gd7WinnerViewTransferOperationChirho::StageOnePageChirho {
                expected_stage_index_chirho: 0
            }
        ) =>
        {
            Ok(())
        }
        // A restarted winner cannot resume an in-memory staging coordinate. Only Stage-0 may
        // establish a binding, and it does so after the actor operation succeeds.
        None => Err(Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho),
    }
}

fn transfer_identity_digest_from_status_chirho(
    status_chirho: &ResidentGd7WinnerHandoffStatusChirho,
) -> Result<String> {
    canonical_json_chirho(
        &status_chirho
            .attempt_identity_chirho
            .held_transfer_identity_chirho,
    )
    .map(|bytes_chirho| digest_bytes_chirho(&bytes_chirho))
}

async fn admit_winner_view_transfer_chirho(
    State(service_chirho): State<Gd7WinnerViewTransferServiceChirho>,
    mut request_chirho: Request,
    next_chirho: Next,
) -> Response {
    let Some(admission_chirho) = service_chirho.try_admit_chirho() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    request_chirho.extensions_mut().insert(admission_chirho);
    next_chirho.run(request_chirho).await
}

async fn post_winner_view_transfer_chirho(
    State(service_chirho): State<Gd7WinnerViewTransferServiceChirho>,
    Extension(admission_chirho): Extension<Arc<Gd7WinnerViewTransferAdmissionChirho>>,
    body_chirho: Bytes,
) -> Response {
    match tokio::task::spawn_blocking(move || {
        let _admission_chirho = admission_chirho;
        service_chirho.handle_chirho(&body_chirho)
    })
    .await
    {
        Ok(Ok(response_bytes_chirho)) => {
            (StatusCode::OK, Bytes::from(response_bytes_chirho)).into_response()
        }
        Ok(Err(_error_chirho)) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Err(_error_chirho) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn validate_operation_shape_chirho(
    operation_chirho: &Gd7WinnerViewTransferOperationChirho,
) -> std::result::Result<(), Gd7WinnerViewTransferRefusalCodeChirho> {
    match operation_chirho {
        Gd7WinnerViewTransferOperationChirho::StageOnePageChirho { .. } => Ok(()),
        Gd7WinnerViewTransferOperationChirho::SealCurrentViewChirho {
            canonical_challenge_chirho,
        } => {
            if canonical_challenge_chirho.len() > MAX_GD7_WINNER_CURRENT_VIEW_CHALLENGE_BYTES_CHIRHO
                || parse_canonical_gd7_winner_current_view_challenge_chirho(
                    canonical_challenge_chirho.as_bytes(),
                )
                .is_err()
            {
                return Err(Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho);
            }
            Ok(())
        }
        Gd7WinnerViewTransferOperationChirho::FetchGrantedPageChirho { grant_chirho } => {
            if grant_chirho.canonical_bytes_chirho().is_err()
                || grant_chirho
                    .canonical_bytes_chirho()
                    .is_ok_and(|bytes_chirho| {
                        bytes_chirho.len() > MAX_GD7_WINNER_VIEW_PAGE_GRANT_BYTES_CHIRHO
                    })
            {
                return Err(Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho);
            }
            Ok(())
        }
        Gd7WinnerViewTransferOperationChirho::BeginHandoffChirho {
            held_transfer_identity_chirho,
            reconciliation_checkpoint_chirho,
            held_transfer_checkpoint_ref_chirho,
            held_transfer_checkpoint_chirho,
            expected_bundle_root_object_digest_chirho,
            canonical_challenge_chirho,
        } => {
            if canonical_challenge_chirho.len() > MAX_GD7_WINNER_CURRENT_VIEW_CHALLENGE_BYTES_CHIRHO
                || parse_canonical_gd7_winner_current_view_challenge_chirho(
                    canonical_challenge_chirho.as_bytes(),
                )
                .is_err()
                || !is_lower_hex_64_chirho(held_transfer_checkpoint_ref_chirho)
                || !is_lower_hex_64_chirho(expected_bundle_root_object_digest_chirho)
                || !is_lower_hex_64_chirho(
                    &held_transfer_identity_chirho.reconciliation_checkpoint_ref_chirho,
                )
                || !is_lower_hex_64_chirho(&held_transfer_identity_chirho.winner_node_chirho)
                || !is_lower_hex_64_chirho(&held_transfer_identity_chirho.held_node_chirho)
                || held_transfer_checkpoint_chirho.identity_chirho
                    != **held_transfer_identity_chirho
                || canonical_json_chirho(held_transfer_checkpoint_chirho.as_ref()).is_err()
                || canonical_json_chirho(held_transfer_checkpoint_chirho.as_ref()).is_ok_and(
                    |bytes_chirho| {
                        bytes_chirho.len() > MAX_GD7_HELD_VIEW_TRANSFER_CHECKPOINT_BYTES_CHIRHO
                    },
                )
                || canonical_json_chirho(reconciliation_checkpoint_chirho.as_ref()).is_err()
                || canonical_json_chirho(reconciliation_checkpoint_chirho.as_ref()).is_ok_and(
                    |bytes_chirho| {
                        bytes_chirho.len() > MAX_GD7_RECONCILIATION_CHECKPOINT_BYTES_CHIRHO
                    },
                )
                || held_transfer_identity_chirho.winner_term_chirho == 0
            {
                return Err(Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho);
            }
            Ok(())
        }
        Gd7WinnerViewTransferOperationChirho::HandoffStatusChirho {
            attempt_digest_chirho,
        }
        | Gd7WinnerViewTransferOperationChirho::AbortHandoffChirho {
            attempt_digest_chirho,
        } => {
            if !is_lower_hex_64_chirho(attempt_digest_chirho) {
                return Err(Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho);
            }
            Ok(())
        }
        Gd7WinnerViewTransferOperationChirho::PrepareAdoptionEvidenceChirho => Ok(()),
        Gd7WinnerViewTransferOperationChirho::FetchAdoptionEvidencePageChirho { grant_chirho } => {
            let bytes_chirho = canonical_json_chirho(grant_chirho.as_ref())
                .map_err(|_| Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho)?;
            if bytes_chirho.len() > MAX_GD7_WINNER_EVIDENCE_PAGE_GRANT_BYTES_CHIRHO {
                return Err(Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho);
            }
            Ok(())
        }
    }
}

fn validate_operation_binding_chirho(
    operation_chirho: &Gd7WinnerViewTransferOperationChirho,
    consistency_group_digest_chirho: &str,
    held_node_chirho: &str,
    winner_node_chirho: &str,
    transfer_identity_digest_chirho: &str,
    expected_raft_term_chirho: u64,
) -> std::result::Result<(), Gd7WinnerViewTransferRefusalCodeChirho> {
    match operation_chirho {
        Gd7WinnerViewTransferOperationChirho::StageOnePageChirho { .. } => Ok(()),
        Gd7WinnerViewTransferOperationChirho::SealCurrentViewChirho {
            canonical_challenge_chirho,
        } => {
            let challenge_chirho = parse_canonical_gd7_winner_current_view_challenge_chirho(
                canonical_challenge_chirho.as_bytes(),
            )
            .map_err(|_| Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho)?;
            if challenge_chirho.held_node_chirho() != held_node_chirho
                || challenge_chirho.transfer_identity_digest_chirho()
                    != transfer_identity_digest_chirho
            {
                return Err(Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho);
            }
            Ok(())
        }
        Gd7WinnerViewTransferOperationChirho::FetchGrantedPageChirho { grant_chirho } => {
            if grant_chirho.held_node_chirho != held_node_chirho {
                return Err(Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho);
            }
            Ok(())
        }
        Gd7WinnerViewTransferOperationChirho::BeginHandoffChirho {
            held_transfer_identity_chirho,
            canonical_challenge_chirho,
            ..
        } => {
            let challenge_chirho = parse_canonical_gd7_winner_current_view_challenge_chirho(
                canonical_challenge_chirho.as_bytes(),
            )
            .map_err(|_| Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho)?;
            let identity_digest_chirho = digest_bytes_chirho(
                &canonical_json_chirho(held_transfer_identity_chirho.as_ref())
                    .map_err(|_| Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho)?,
            );
            if identity_digest_chirho != transfer_identity_digest_chirho
                || held_transfer_identity_chirho.consistency_group_digest_chirho
                    != consistency_group_digest_chirho
                || held_transfer_identity_chirho.winner_node_chirho != winner_node_chirho
                || held_transfer_identity_chirho.held_node_chirho != held_node_chirho
                || held_transfer_identity_chirho.winner_term_chirho != expected_raft_term_chirho
                || challenge_chirho.consistency_group_digest_chirho()
                    != consistency_group_digest_chirho
                || challenge_chirho.expected_winner_node_chirho() != winner_node_chirho
                || challenge_chirho.held_node_chirho() != held_node_chirho
                || challenge_chirho.transfer_identity_digest_chirho()
                    != transfer_identity_digest_chirho
                || challenge_chirho.raft_term_chirho() != expected_raft_term_chirho
            {
                return Err(Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho);
            }
            Ok(())
        }
        Gd7WinnerViewTransferOperationChirho::HandoffStatusChirho { .. }
        | Gd7WinnerViewTransferOperationChirho::AbortHandoffChirho { .. }
        | Gd7WinnerViewTransferOperationChirho::PrepareAdoptionEvidenceChirho
        | Gd7WinnerViewTransferOperationChirho::FetchAdoptionEvidencePageChirho { .. } => Ok(()),
    }
}

fn is_handoff_operation_chirho(operation_chirho: &Gd7WinnerViewTransferOperationChirho) -> bool {
    matches!(
        operation_chirho,
        Gd7WinnerViewTransferOperationChirho::BeginHandoffChirho { .. }
            | Gd7WinnerViewTransferOperationChirho::HandoffStatusChirho { .. }
            | Gd7WinnerViewTransferOperationChirho::AbortHandoffChirho { .. }
    )
}

fn map_adoption_evidence_refusal_code_chirho(
    error_chirho: ResidentGd7WinnerAdoptionEvidenceRefusalChirho,
) -> Gd7WinnerViewTransferRefusalCodeChirho {
    match error_chirho {
        ResidentGd7WinnerAdoptionEvidenceRefusalChirho::MailboxFullChirho => {
            Gd7WinnerViewTransferRefusalCodeChirho::ActorBusyChirho
        }
        ResidentGd7WinnerAdoptionEvidenceRefusalChirho::ActorUnavailableChirho => {
            Gd7WinnerViewTransferRefusalCodeChirho::ActorUnavailableChirho
        }
        ResidentGd7WinnerAdoptionEvidenceRefusalChirho::AcceptedBarrierMissingChirho => {
            Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho
        }
        ResidentGd7WinnerAdoptionEvidenceRefusalChirho::InvalidRequestChirho
        | ResidentGd7WinnerAdoptionEvidenceRefusalChirho::StoreChirho(_) => {
            Gd7WinnerViewTransferRefusalCodeChirho::ActorRefusedChirho
        }
    }
}

fn verify_handoff_attempt_request_binding_chirho(
    request_chirho: &Gd7WinnerViewTransferRequestChirho,
    attempt_identity_chirho: &Gd7WinnerHandoffAttemptIdentityChirho,
) -> std::result::Result<(), Gd7WinnerViewTransferRefusalCodeChirho> {
    let held_transfer_identity_chirho = &attempt_identity_chirho.held_transfer_identity_chirho;
    let transfer_digest_chirho = digest_bytes_chirho(
        &canonical_json_chirho(held_transfer_identity_chirho)
            .map_err(|_| Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho)?,
    );
    let begin_chirho = matches!(
        &request_chirho.operation_chirho,
        Gd7WinnerViewTransferOperationChirho::BeginHandoffChirho { .. }
    );
    if transfer_digest_chirho != request_chirho.transfer_identity_digest_chirho
        || held_transfer_identity_chirho.consistency_group_digest_chirho
            != request_chirho.consistency_group_digest_chirho
        || held_transfer_identity_chirho.winner_node_chirho != request_chirho.recipient_node_chirho
        || held_transfer_identity_chirho.held_node_chirho != request_chirho.sender_node_chirho
        || (begin_chirho
            && held_transfer_identity_chirho.winner_term_chirho
                != request_chirho.expected_raft_term_chirho)
        || !is_lower_hex_64_chirho(&attempt_identity_chirho.held_transfer_checkpoint_ref_chirho)
        || !is_lower_hex_64_chirho(
            &attempt_identity_chirho.expected_bundle_root_object_digest_chirho,
        )
        || !is_lower_hex_64_chirho(&attempt_identity_chirho.challenge_digest_chirho)
    {
        return Err(Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho);
    }
    Ok(())
}

fn verify_handoff_status_request_binding_chirho(
    request_chirho: &Gd7WinnerViewTransferRequestChirho,
    status_chirho: &ResidentGd7WinnerHandoffStatusChirho,
) -> std::result::Result<(), Gd7WinnerViewTransferRefusalCodeChirho> {
    verify_handoff_attempt_request_binding_chirho(
        request_chirho,
        &status_chirho.attempt_identity_chirho,
    )?;
    let expected_attempt_digest_chirho =
        gd7_winner_handoff_attempt_digest_chirho(&status_chirho.attempt_identity_chirho)
            .map_err(|_| Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho)?;
    if status_chirho.attempt_digest_chirho != expected_attempt_digest_chirho {
        return Err(Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho);
    }
    match &request_chirho.operation_chirho {
        Gd7WinnerViewTransferOperationChirho::HandoffStatusChirho {
            attempt_digest_chirho,
        }
        | Gd7WinnerViewTransferOperationChirho::AbortHandoffChirho {
            attempt_digest_chirho,
        } if attempt_digest_chirho != &status_chirho.attempt_digest_chirho => {
            Err(Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho)
        }
        _ => Ok(()),
    }
}

fn map_stage_inspection_chirho(
    inspection_chirho: ResidentGd7WinnerViewStageInspectionChirho,
) -> Gd7WinnerViewTransferResultChirho {
    match inspection_chirho {
        ResidentGd7WinnerViewStageInspectionChirho::AdvancedOnePageChirho => {
            Gd7WinnerViewTransferResultChirho::StageAdvancedChirho
        }
        ResidentGd7WinnerViewStageInspectionChirho::ReadyChirho {
            bundle_root_object_digest_chirho,
            page_count_chirho,
            row_count_chirho,
        } => Gd7WinnerViewTransferResultChirho::StageReadyChirho {
            bundle_root_object_digest_chirho,
            page_count_chirho,
            row_count_chirho,
        },
    }
}

fn map_handoff_status_chirho(
    status_chirho: ResidentGd7WinnerHandoffStatusChirho,
) -> Gd7WinnerViewTransferResultChirho {
    Gd7WinnerViewTransferResultChirho::HandoffStatusChirho {
        status_chirho: Box::new(status_chirho),
    }
}

fn map_handoff_refusal_code_chirho(
    refusal_chirho: ResidentGd7WinnerHandoffRefusalChirho,
) -> Gd7WinnerViewTransferRefusalCodeChirho {
    match refusal_chirho {
        ResidentGd7WinnerHandoffRefusalChirho::MailboxFullChirho => {
            Gd7WinnerViewTransferRefusalCodeChirho::ActorBusyChirho
        }
        ResidentGd7WinnerHandoffRefusalChirho::ActorUnavailableChirho => {
            Gd7WinnerViewTransferRefusalCodeChirho::ActorUnavailableChirho
        }
        ResidentGd7WinnerHandoffRefusalChirho::NoAttemptChirho => {
            Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho
        }
        ResidentGd7WinnerHandoffRefusalChirho::InvalidRequestChirho => {
            Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho
        }
        ResidentGd7WinnerHandoffRefusalChirho::DurableHeadChangedChirho
        | ResidentGd7WinnerHandoffRefusalChirho::MigrationSourceFenceActiveChirho => {
            Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho
        }
        ResidentGd7WinnerHandoffRefusalChirho::HeldCheckpointChirho(_) => {
            Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho
        }
        ResidentGd7WinnerHandoffRefusalChirho::ReconciliationCheckpointChirho(_) => {
            Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho
        }
        ResidentGd7WinnerHandoffRefusalChirho::DurabilityUnconfirmedChirho => {
            Gd7WinnerViewTransferRefusalCodeChirho::ActorBusyChirho
        }
        ResidentGd7WinnerHandoffRefusalChirho::WinnerStateChangedChirho => {
            Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho
        }
        ResidentGd7WinnerHandoffRefusalChirho::LocalAuthorityChirho(
            LocalAppendAuthorityRefusalChirho::TransitionPendingChirho
            | LocalAppendAuthorityRefusalChirho::GuardBusyChirho,
        ) => Gd7WinnerViewTransferRefusalCodeChirho::ActorBusyChirho,
        ResidentGd7WinnerHandoffRefusalChirho::LocalAuthorityChirho(
            LocalAppendAuthorityRefusalChirho::NotLocalLeaderChirho
            | LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho
            | LocalAppendAuthorityRefusalChirho::NotPromotableVoterChirho
            | LocalAppendAuthorityRefusalChirho::LeadershipTransferInProgressChirho,
        ) => Gd7WinnerViewTransferRefusalCodeChirho::LeadershipChangedChirho,
        ResidentGd7WinnerHandoffRefusalChirho::CurrentViewChirho(
            Gd7WinnerCurrentViewRefusalChirho::LeadershipUnavailableChirho
            | Gd7WinnerCurrentViewRefusalChirho::LeadershipChangedChirho,
        ) => Gd7WinnerViewTransferRefusalCodeChirho::LeadershipChangedChirho,
        // THE FOUR HISTORICAL-CUT CAUSES COARSEN BACK TOGETHER HERE, DELIBERATELY. Until the
        // refusal discrimination landed, all four of these were one `WinnerStateChangedChirho`,
        // which mapped to `ActorStateChangedChirho`. Splitting them was for LOCAL arms that must
        // tell the digest check from the snapshot floors from the guard from the probe; it was
        // never a request to widen the WIRE vocabulary. Mapping all four to the code they already
        // produced keeps remote behaviour byte-identical, so the split carries no transport
        // consequence a caller could observe.
        //
        // The alternative was considered and REJECTED as out of scope: the extension refusal is
        // arguably a hard refusal rather than a retryable state change, and a remote caller told
        // `ActorStateChangedChirho` may retry a request that can never succeed. Changing that is a
        // money-authority transport semantics change and belongs to whoever reviews the wire, not
        // to a compile fix. Recorded here rather than left for the next reader to re-derive.
        ResidentGd7WinnerHandoffRefusalChirho::HistoricalCutAttemptMismatchChirho
        | ResidentGd7WinnerHandoffRefusalChirho::HistoricalCutProbeFailedChirho
        | ResidentGd7WinnerHandoffRefusalChirho::HistoricalCutSnapshotRefusedChirho
        | ResidentGd7WinnerHandoffRefusalChirho::HistoricalCutExtensionRefusedChirho { .. } => {
            Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho
        }
        ResidentGd7WinnerHandoffRefusalChirho::LocalAuthorityChirho(_)
        | ResidentGd7WinnerHandoffRefusalChirho::CurrentViewChirho(_)
        | ResidentGd7WinnerHandoffRefusalChirho::StoreChirho(_) => {
            Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho
        }
    }
}

fn map_sealed_view_chirho(
    sealed_chirho: ResidentGd7WinnerViewSealChirho,
) -> Gd7WinnerViewTransferResultChirho {
    Gd7WinnerViewTransferResultChirho::ViewSealedChirho {
        inspection_chirho: sealed_chirho.inspection_chirho,
        first_page_grant_chirho: sealed_chirho.first_page_grant_chirho,
    }
}

fn map_actor_refusal_code_chirho(
    refusal_chirho: ResidentGd7WinnerEvidenceRefusalChirho,
) -> Gd7WinnerViewTransferRefusalCodeChirho {
    match refusal_chirho {
        ResidentGd7WinnerEvidenceRefusalChirho::MailboxFullChirho => {
            Gd7WinnerViewTransferRefusalCodeChirho::ActorBusyChirho
        }
        ResidentGd7WinnerEvidenceRefusalChirho::ActorUnavailableChirho => {
            Gd7WinnerViewTransferRefusalCodeChirho::ActorUnavailableChirho
        }
        ResidentGd7WinnerEvidenceRefusalChirho::OperationChirho(operation_chirho) => {
            match operation_chirho {
                Gd7WinnerCurrentViewRefusalChirho::LeadershipUnavailableChirho
                | Gd7WinnerCurrentViewRefusalChirho::LeadershipChangedChirho => {
                    Gd7WinnerViewTransferRefusalCodeChirho::LeadershipChangedChirho
                }
                Gd7WinnerCurrentViewRefusalChirho::LocalAuthorityChirho(
                    LocalAppendAuthorityRefusalChirho::TransitionPendingChirho
                    | LocalAppendAuthorityRefusalChirho::GuardBusyChirho,
                ) => Gd7WinnerViewTransferRefusalCodeChirho::ActorBusyChirho,
                Gd7WinnerCurrentViewRefusalChirho::LocalAuthorityChirho(
                    LocalAppendAuthorityRefusalChirho::NotLocalLeaderChirho
                    | LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho
                    | LocalAppendAuthorityRefusalChirho::NotPromotableVoterChirho
                    | LocalAppendAuthorityRefusalChirho::LeadershipTransferInProgressChirho,
                ) => Gd7WinnerViewTransferRefusalCodeChirho::LeadershipChangedChirho,
                Gd7WinnerCurrentViewRefusalChirho::ResidentEvidenceChangedChirho
                | Gd7WinnerCurrentViewRefusalChirho::LocalAuthorityChirho(
                    LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho
                    | LocalAppendAuthorityRefusalChirho::ElectorDroppedChirho
                    | LocalAppendAuthorityRefusalChirho::AuthorityUnavailableChirho
                    | LocalAppendAuthorityRefusalChirho::PublishedRaftTermOutOfRangeChirho,
                )
                | Gd7WinnerCurrentViewRefusalChirho::StageIndexMismatchChirho
                | Gd7WinnerCurrentViewRefusalChirho::BundleRootMismatchChirho
                | Gd7WinnerCurrentViewRefusalChirho::JournalCutMismatchChirho
                | Gd7WinnerCurrentViewRefusalChirho::MissingEvidenceChirho
                | Gd7WinnerCurrentViewRefusalChirho::MissingBundleRootChirho
                | Gd7WinnerCurrentViewRefusalChirho::MissingBundlePageChirho
                | Gd7WinnerCurrentViewRefusalChirho::ObjectDigestMismatchChirho => {
                    Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho
                }
                _ => Gd7WinnerViewTransferRefusalCodeChirho::ActorRefusedChirho,
            }
        }
    }
}

fn encode_frame_chirho(
    header_chirho: &Gd7WinnerViewTransferResponseHeaderChirho,
    payload_chirho: &[u8],
) -> Result<Vec<u8>> {
    let header_bytes_chirho = canonical_json_chirho(header_chirho)?;
    if header_bytes_chirho.len() > MAX_GD7_WINNER_VIEW_TRANSFER_HEADER_BYTES_CHIRHO {
        bail!("winner-view transfer response header exceeds its fixed bound");
    }
    let header_length_chirho = u32::try_from(header_bytes_chirho.len())
        .map_err(|_| anyhow!("winner-view transfer response header cannot fit u32"))?;
    let capacity_chirho = 4_usize
        .checked_add(header_bytes_chirho.len())
        .and_then(|length_chirho| length_chirho.checked_add(payload_chirho.len()))
        .ok_or_else(|| anyhow!("winner-view transfer response length overflow"))?;
    if capacity_chirho > MAX_GD7_WINNER_VIEW_TRANSFER_RESPONSE_BYTES_CHIRHO {
        bail!("winner-view transfer response exceeds its fixed bound");
    }
    let mut frame_chirho = Vec::with_capacity(capacity_chirho);
    frame_chirho.extend_from_slice(&header_length_chirho.to_be_bytes());
    frame_chirho.extend_from_slice(&header_bytes_chirho);
    frame_chirho.extend_from_slice(payload_chirho);
    Ok(frame_chirho)
}

fn decode_frame_chirho(
    frame_chirho: &[u8],
) -> Result<(Gd7WinnerViewTransferResponseHeaderChirho, &[u8])> {
    let header_length_bytes_chirho: [u8; 4] = frame_chirho
        .get(..4)
        .ok_or_else(|| anyhow!("winner-view transfer response omits its header length"))?
        .try_into()
        .map_err(|_| anyhow!("winner-view transfer response header length is invalid"))?;
    let header_length_chirho = usize::try_from(u32::from_be_bytes(header_length_bytes_chirho))
        .map_err(|_| anyhow!("winner-view transfer response header length cannot fit usize"))?;
    if header_length_chirho > MAX_GD7_WINNER_VIEW_TRANSFER_HEADER_BYTES_CHIRHO {
        bail!("winner-view transfer response header exceeds its fixed bound");
    }
    let payload_offset_chirho = 4_usize
        .checked_add(header_length_chirho)
        .ok_or_else(|| anyhow!("winner-view transfer response offset overflow"))?;
    let header_bytes_chirho = frame_chirho
        .get(4..payload_offset_chirho)
        .ok_or_else(|| anyhow!("winner-view transfer response header is truncated"))?;
    let payload_chirho = frame_chirho
        .get(payload_offset_chirho..)
        .ok_or_else(|| anyhow!("winner-view transfer response payload offset is invalid"))?;
    let header_chirho = parse_canonical_bounded_chirho::<Gd7WinnerViewTransferResponseHeaderChirho>(
        header_bytes_chirho,
        MAX_GD7_WINNER_VIEW_TRANSFER_HEADER_BYTES_CHIRHO,
    )?;
    Ok((header_chirho, payload_chirho))
}

#[allow(
    clippy::too_many_arguments,
    reason = "verification binds the exact signed request-response coordinate without ambient state"
)]
fn verify_response_chirho(
    header_chirho: &Gd7WinnerViewTransferResponseHeaderChirho,
    payload_chirho: &[u8],
    expected_group_digest_chirho: &str,
    expected_request_digest_chirho: &str,
    expected_winner_node_chirho: &NodeIdChirho,
    expected_raft_term_chirho: u64,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<()> {
    let term_coordinate_valid_chirho = match &header_chirho.result_chirho {
        Gd7WinnerViewTransferResultChirho::RefusedChirho {
            code_chirho: Gd7WinnerViewTransferRefusalCodeChirho::LeadershipChangedChirho,
        } => header_chirho.raft_term_chirho >= expected_raft_term_chirho,
        _ => header_chirho.raft_term_chirho == expected_raft_term_chirho,
    };
    if header_chirho.schema_chirho != GD7_WINNER_VIEW_TRANSFER_RESPONSE_SCHEMA_V1_CHIRHO
        || header_chirho.consistency_group_digest_chirho != expected_group_digest_chirho
        || header_chirho.request_digest_chirho != expected_request_digest_chirho
        || header_chirho.winner_node_chirho != expected_winner_node_chirho.0
        || !term_coordinate_valid_chirho
        || header_chirho.key_id_chirho != expected_winner_node_chirho.0
        || usize::try_from(header_chirho.payload_length_chirho).ok() != Some(payload_chirho.len())
        || header_chirho.payload_digest_chirho != digest_bytes_chirho(payload_chirho)
    {
        bail!("winner-view transfer response coordinate is invalid");
    }
    let mut unsigned_chirho = header_chirho.clone();
    let signature_chirho = std::mem::take(&mut unsigned_chirho.sig_chirho);
    let unsigned_bytes_chirho = canonical_json_chirho(&unsigned_chirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| anyhow!("winner-view transfer response is not UTF-8"))?;
    if !verifier_chirho.verify_chirho(unsigned_line_chirho, &signature_chirho) {
        bail!("winner-view transfer response signature is invalid");
    }
    match &header_chirho.result_chirho {
        Gd7WinnerViewTransferResultChirho::PageFetchedChirho { .. }
        | Gd7WinnerViewTransferResultChirho::AdoptionEvidencePageFetchedChirho { .. } => {
            if payload_chirho.is_empty()
                || payload_chirho.len() > MAX_GD7_WINNER_VIEW_TRANSFER_PAGE_BYTES_CHIRHO
            {
                bail!("winner-view page response payload is invalid");
            }
        }
        Gd7WinnerViewTransferResultChirho::AdoptionEvidenceReadyChirho { manifest_chirho }
            if canonical_json_chirho(manifest_chirho.as_ref()).is_ok_and(|bytes_chirho| {
                bytes_chirho.len() > MAX_GD7_WINNER_EVIDENCE_MANIFEST_BYTES_CHIRHO
            }) =>
        {
            bail!("winner adoption-evidence manifest exceeds its fixed bound");
        }
        _ if !payload_chirho.is_empty() => {
            bail!("winner-view control response unexpectedly carries a payload");
        }
        _ => {}
    }
    Ok(())
}

fn parse_canonical_bounded_chirho<ValueChirho: DeserializeOwned + Serialize>(
    bytes_chirho: &[u8],
    maximum_bytes_chirho: usize,
) -> Result<ValueChirho> {
    if bytes_chirho.len() > maximum_bytes_chirho {
        bail!("canonical value exceeds its fixed bound");
    }
    let value_chirho: ValueChirho = serde_json::from_slice(bytes_chirho)?;
    if canonical_json_chirho(&value_chirho)?.as_slice() != bytes_chirho {
        bail!("value is not canonical JSON");
    }
    Ok(value_chirho)
}

fn canonical_json_chirho<ValueChirho: Serialize>(value_chirho: &ValueChirho) -> Result<Vec<u8>> {
    serde_json::to_vec(value_chirho).context("serialize canonical winner-view transfer JSON")
}

fn digest_bytes_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}

fn is_lower_hex_64_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

pub(crate) fn validate_winner_view_transfer_base_url_chirho(base_url_chirho: &str) -> Result<()> {
    let parsed_chirho =
        Url::parse(base_url_chirho).context("parse winner-view transfer peer URL")?;
    if !parsed_chirho.username().is_empty()
        || parsed_chirho.password().is_some()
        || parsed_chirho.query().is_some()
        || parsed_chirho.fragment().is_some()
        || parsed_chirho.path() != "/"
    {
        bail!("winner-view transfer peer URL must be an origin without credentials or suffixes");
    }
    let loopback_chirho = match parsed_chirho.host() {
        Some(Host::Ipv4(address_chirho)) => address_chirho.is_loopback(),
        Some(Host::Ipv6(address_chirho)) => address_chirho.is_loopback(),
        Some(Host::Domain(domain_chirho)) => domain_chirho.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    match parsed_chirho.scheme() {
        "https" => Ok(()),
        "http" if loopback_chirho => Ok(()),
        _ => bail!("winner-view transfer requires HTTPS outside a loopback test endpoint"),
    }
}

#[cfg(test)]
#[path = "winner_view_transfer_tests_chirho.rs"]
mod tests_chirho;

#[cfg(test)]
#[path = "winner_view_transfer_chirho/test_stub_chirho.rs"]
pub(super) mod test_stub_chirho;
