// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Private, roster-authenticated GD7 winner-fork observation on the election listener.
//!
//! The held learner supplies only its frozen losing journal coordinate. The resident winner actor
//! derives the winner term-first record, fork anchor, and reconciliation identity. A successful
//! response carries the two canonical signed evidence objects needed by the held coordinator; it
//! cannot select storage paths, append effects, adopt a winner, move refs, or enable writes.

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
    ExistingNodeGd7SignerChirho, Gd7JournalTailCoordinateChirho, Gd7ReconciliationSignerPortChirho,
    Gd7ReconciliationVerifierPortChirho, Gd7WinnerFirstRecordIndexChirho,
    Gd7WinnerForkWitnessChirho, PinnedNodeGd7VerifierChirho,
    MAX_GD7_WINNER_FIRST_RECORD_INDEX_BYTES_CHIRHO, MAX_GD7_WINNER_FORK_WITNESS_BYTES_CHIRHO,
};
use cairn_ledger_host_chirho::{
    ResidentGd7HeldObservationImportChirho, ResidentGd7WinnerEvidenceHandleChirho,
    ResidentGd7WinnerForkObservationChirho, ResidentGd7WinnerForkObservationRefusalChirho,
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
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub(crate) const GD7_WINNER_FORK_OBSERVATION_PATH_CHIRHO: &str =
    "/gd7-winner-fork-observation-chirho";
const GD7_WINNER_FORK_OBSERVATION_REQUEST_SCHEMA_V1_CHIRHO: &str =
    "gd7-winner-fork-observation-request-v1-chirho";
const GD7_WINNER_FORK_OBSERVATION_RESPONSE_SCHEMA_V1_CHIRHO: &str =
    "gd7-winner-fork-observation-response-v1-chirho";
const MAX_GD7_WINNER_FORK_OBSERVATION_REQUEST_BYTES_CHIRHO: usize = 16 * 1024;
const MAX_GD7_WINNER_FORK_OBSERVATION_HEADER_BYTES_CHIRHO: usize = 64 * 1024;
const MAX_GD7_WINNER_FORK_OBSERVATION_PAYLOAD_BYTES_CHIRHO: usize =
    4 + MAX_GD7_WINNER_FIRST_RECORD_INDEX_BYTES_CHIRHO + MAX_GD7_WINNER_FORK_WITNESS_BYTES_CHIRHO;
const MAX_GD7_WINNER_FORK_OBSERVATION_RESPONSE_BYTES_CHIRHO: usize = 4
    + MAX_GD7_WINNER_FORK_OBSERVATION_HEADER_BYTES_CHIRHO
    + MAX_GD7_WINNER_FORK_OBSERVATION_PAYLOAD_BYTES_CHIRHO;
const MAX_GD7_WINNER_FORK_OBSERVATION_INFLIGHT_CHIRHO: usize = 8;
const MAX_GD7_WINNER_FORK_OBSERVATION_REQUEST_DURATION_CHIRHO: Duration = Duration::from_secs(5);
const CONSISTENCY_GROUP_DIGEST_PREFIX_CHIRHO: &str = "writer-fence-group-blake3-chirho:";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gd7WinnerForkObservationRequestChirho {
    schema_chirho: String,
    consistency_group_digest_chirho: String,
    sender_node_chirho: String,
    recipient_node_chirho: String,
    expected_winner_term_chirho: u64,
    losing_journal_genesis_digest_chirho: String,
    losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho,
    nonce_chirho: String,
    key_id_chirho: String,
    sig_chirho: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub(crate) enum Gd7WinnerForkObservationRefusalCodeChirho {
    InvalidRequestChirho,
    UnauthenticatedPeerChirho,
    LeadershipChangedChirho,
    ActorBusyChirho,
    ActorUnavailableChirho,
    ActorStateChangedChirho,
    ActorRefusedChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result_chirho", content = "output_chirho")]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
enum Gd7WinnerForkObservationResultChirho {
    ObservedChirho,
    RefusedChirho {
        code_chirho: Gd7WinnerForkObservationRefusalCodeChirho,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gd7WinnerForkObservationResponseHeaderChirho {
    schema_chirho: String,
    consistency_group_digest_chirho: String,
    request_digest_chirho: String,
    winner_node_chirho: String,
    winner_term_chirho: u64,
    result_chirho: Gd7WinnerForkObservationResultChirho,
    payload_length_chirho: u64,
    payload_digest_chirho: String,
    key_id_chirho: String,
    sig_chirho: String,
}

/// Exact caller-owned coordinates for one bounded observation request.
///
/// `agent_chirho` is supplied by the held startup path with its two-second request timeout.
pub(crate) struct Gd7WinnerForkObservationCallContextChirho<'a> {
    pub agent_chirho: &'a ureq::Agent,
    pub base_url_chirho: &'a str,
    pub consistency_group_digest_chirho: &'a str,
    pub held_signer_chirho: &'a ExistingNodeGd7SignerChirho,
    pub winner_node_chirho: &'a NodeIdChirho,
    pub expected_winner_term_chirho: u64,
    pub losing_journal_genesis_digest_chirho: &'a str,
    pub losing_journal_tail_chirho: &'a Gd7JournalTailCoordinateChirho,
    pub request_nonce_chirho: &'a str,
}

struct Gd7WinnerForkObservationStateChirho {
    consistency_group_digest_chirho: String,
    local_node_chirho: NodeIdChirho,
    held_node_chirho: NodeIdChirho,
    held_raft_id_chirho: u64,
    elector_chirho: Arc<RaftWriterElectorChirho>,
    signer_chirho: ExistingNodeGd7SignerChirho,
    winner_handle_chirho: RwLock<Option<ResidentGd7WinnerEvidenceHandleChirho>>,
    inflight_chirho: AtomicUsize,
}

struct Gd7WinnerForkObservationAdmissionChirho {
    state_chirho: Arc<Gd7WinnerForkObservationStateChirho>,
}

impl Drop for Gd7WinnerForkObservationAdmissionChirho {
    fn drop(&mut self) {
        self.state_chirho
            .inflight_chirho
            .fetch_sub(1, Ordering::AcqRel);
    }
}

/// Install-once fork-observation surface sharing the election node's elector and resident actor.
#[derive(Clone)]
pub(crate) struct Gd7WinnerForkObservationServiceChirho {
    state_chirho: Arc<Gd7WinnerForkObservationStateChirho>,
}

impl Gd7WinnerForkObservationServiceChirho {
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
            bail!("winner-fork observation local node is not uniquely authenticated");
        }
        if held_node_chirho == local_node_chirho {
            bail!("winner-fork observation held sender cannot equal the local winner");
        }
        let held_raft_ids_chirho = elector_chirho
            .authenticated_members_chirho()
            .iter()
            .filter(|(_raft_id_chirho, node_chirho)| node_chirho == &held_node_chirho)
            .map(|(raft_id_chirho, _node_chirho)| *raft_id_chirho)
            .collect::<Vec<_>>();
        let [held_raft_id_chirho] = held_raft_ids_chirho.as_slice() else {
            bail!("winner-fork observation held sender is not uniquely authenticated");
        };
        let authenticated_members_chirho = elector_chirho.authenticated_members_chirho();
        let (voters_chirho, learners_chirho) = elector_chirho
            .membership_snapshot_chirho()
            .context("read winner-fork observation membership")?;
        if !held_member_pair_is_exact_chirho(
            &authenticated_members_chirho,
            &voters_chirho,
            &learners_chirho,
            *held_raft_id_chirho,
            &held_node_chirho,
        ) {
            bail!("winner-fork observation requires one exact authenticated held learner");
        }
        let signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
            node_sign_root_chirho,
            &local_node_chirho,
        )
        .context("open existing winner-fork observation signer")?;
        Ok(Self {
            state_chirho: Arc::new(Gd7WinnerForkObservationStateChirho {
                consistency_group_digest_chirho: consistency_group_digest_chirho(group_chirho)?,
                local_node_chirho,
                held_node_chirho,
                held_raft_id_chirho: *held_raft_id_chirho,
                elector_chirho,
                signer_chirho,
                winner_handle_chirho: RwLock::new(None),
                inflight_chirho: AtomicUsize::new(0),
            }),
        })
    }

    pub(crate) fn install_winner_handle_chirho(
        &self,
        winner_handle_chirho: ResidentGd7WinnerEvidenceHandleChirho,
    ) -> Result<()> {
        let mut installed_chirho = self
            .state_chirho
            .winner_handle_chirho
            .write()
            .map_err(|_poison_chirho| anyhow!("winner-fork observation handle lock is poisoned"))?;
        if installed_chirho.is_some() {
            bail!("winner-fork observation actor handle is already installed");
        }
        *installed_chirho = Some(winner_handle_chirho);
        Ok(())
    }

    pub(crate) fn router_chirho(&self) -> Router {
        let admission_state_chirho = self.clone();
        Router::new()
            .route(
                GD7_WINNER_FORK_OBSERVATION_PATH_CHIRHO,
                post(post_winner_fork_observation_chirho),
            )
            .route_layer(middleware::from_fn_with_state(
                admission_state_chirho,
                admit_winner_fork_observation_chirho,
            ))
            .layer(DefaultBodyLimit::max(
                MAX_GD7_WINNER_FORK_OBSERVATION_REQUEST_BYTES_CHIRHO,
            ))
            .with_state(self.clone())
    }

    fn try_admit_chirho(&self) -> Option<Arc<Gd7WinnerForkObservationAdmissionChirho>> {
        self.state_chirho
            .inflight_chirho
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |inflight_chirho| {
                (inflight_chirho < MAX_GD7_WINNER_FORK_OBSERVATION_INFLIGHT_CHIRHO)
                    .then_some(inflight_chirho + 1)
            })
            .ok()
            .map(|_prior_chirho| {
                Arc::new(Gd7WinnerForkObservationAdmissionChirho {
                    state_chirho: Arc::clone(&self.state_chirho),
                })
            })
    }

    fn handle_chirho(&self, request_bytes_chirho: &[u8]) -> Result<Vec<u8>> {
        let request_digest_chirho = digest_bytes_chirho(request_bytes_chirho);
        let request_chirho =
            match parse_canonical_bounded_chirho::<Gd7WinnerForkObservationRequestChirho>(
                request_bytes_chirho,
                MAX_GD7_WINNER_FORK_OBSERVATION_REQUEST_BYTES_CHIRHO,
            ) {
                Ok(request_chirho) => request_chirho,
                Err(_error_chirho) => {
                    return self.signed_response_chirho(
                        &request_digest_chirho,
                        self.state_chirho
                            .elector_chirho
                            .current_leadership_chirho()
                            .term_chirho,
                        Gd7WinnerForkObservationResultChirho::RefusedChirho {
                            code_chirho:
                                Gd7WinnerForkObservationRefusalCodeChirho::InvalidRequestChirho,
                        },
                        &[],
                    );
                }
            };
        let winner_term_chirho = match self.verify_request_chirho(&request_chirho) {
            Ok(winner_term_chirho) => winner_term_chirho,
            Err(code_chirho) => {
                return self.signed_response_chirho(
                    &request_digest_chirho,
                    self.state_chirho
                        .elector_chirho
                        .current_leadership_chirho()
                        .term_chirho,
                    Gd7WinnerForkObservationResultChirho::RefusedChirho { code_chirho },
                    &[],
                );
            }
        };
        let winner_handle_chirho = self
            .state_chirho
            .winner_handle_chirho
            .read()
            .map_err(|_poison_chirho| anyhow!("winner-fork observation handle lock is poisoned"))?
            .clone();
        let Some(winner_handle_chirho) = winner_handle_chirho else {
            return self.signed_response_chirho(
                &request_digest_chirho,
                winner_term_chirho,
                Gd7WinnerForkObservationResultChirho::RefusedChirho {
                    code_chirho: Gd7WinnerForkObservationRefusalCodeChirho::ActorUnavailableChirho,
                },
                &[],
            );
        };
        let observation_chirho = winner_handle_chirho.observe_deposed_fork_chirho(
            request_chirho.expected_winner_term_chirho,
            NodeIdChirho(request_chirho.sender_node_chirho.clone()),
            request_chirho.losing_journal_genesis_digest_chirho.clone(),
            request_chirho.losing_journal_tail_chirho.clone(),
        );
        let observation_chirho = match observation_chirho {
            Ok(observation_chirho) => observation_chirho,
            Err(refusal_chirho) => {
                return self.signed_response_chirho(
                    &request_digest_chirho,
                    winner_term_chirho,
                    Gd7WinnerForkObservationResultChirho::RefusedChirho {
                        code_chirho: map_actor_refusal_code_chirho(refusal_chirho),
                    },
                    &[],
                );
            }
        };
        let post_observation_coordinate_chirho =
            self.verify_held_membership_chirho().and_then(|()| {
                self.verify_local_warm_leadership_chirho(request_chirho.expected_winner_term_chirho)
            });
        if let Err(code_chirho) = post_observation_coordinate_chirho {
            return self.signed_response_chirho(
                &request_digest_chirho,
                self.state_chirho
                    .elector_chirho
                    .current_leadership_chirho()
                    .term_chirho,
                Gd7WinnerForkObservationResultChirho::RefusedChirho { code_chirho },
                &[],
            );
        }
        if validate_observation_binding_chirho(
            &observation_chirho,
            &request_chirho.consistency_group_digest_chirho,
            &self.state_chirho.local_node_chirho,
            &NodeIdChirho(request_chirho.sender_node_chirho.clone()),
            request_chirho.expected_winner_term_chirho,
            &request_chirho.losing_journal_genesis_digest_chirho,
            &request_chirho.losing_journal_tail_chirho,
        )
        .is_err()
        {
            return self.signed_response_chirho(
                &request_digest_chirho,
                winner_term_chirho,
                Gd7WinnerForkObservationResultChirho::RefusedChirho {
                    code_chirho: Gd7WinnerForkObservationRefusalCodeChirho::ActorStateChangedChirho,
                },
                &[],
            );
        }
        let payload_chirho = canonical_json_chirho(
            &observation_chirho.winner_first_record_index_chirho,
        )
        .and_then(|index_bytes_chirho| {
            canonical_json_chirho(&observation_chirho.winner_fork_witness_chirho).and_then(
                |witness_bytes_chirho| {
                    encode_observation_payload_chirho(&index_bytes_chirho, &witness_bytes_chirho)
                },
            )
        });
        let payload_chirho = match payload_chirho {
            Ok(payload_chirho) => payload_chirho,
            Err(_error_chirho) => {
                return self.signed_response_chirho(
                    &request_digest_chirho,
                    winner_term_chirho,
                    Gd7WinnerForkObservationResultChirho::RefusedChirho {
                        code_chirho: Gd7WinnerForkObservationRefusalCodeChirho::ActorRefusedChirho,
                    },
                    &[],
                );
            }
        };
        self.signed_response_chirho(
            &request_digest_chirho,
            winner_term_chirho,
            Gd7WinnerForkObservationResultChirho::ObservedChirho,
            &payload_chirho,
        )
    }

    fn verify_request_chirho(
        &self,
        request_chirho: &Gd7WinnerForkObservationRequestChirho,
    ) -> std::result::Result<u64, Gd7WinnerForkObservationRefusalCodeChirho> {
        if request_chirho.schema_chirho != GD7_WINNER_FORK_OBSERVATION_REQUEST_SCHEMA_V1_CHIRHO
            || request_chirho.consistency_group_digest_chirho
                != self.state_chirho.consistency_group_digest_chirho
            || request_chirho.recipient_node_chirho != self.state_chirho.local_node_chirho.0
            || request_chirho.key_id_chirho != request_chirho.sender_node_chirho
            || request_chirho.expected_winner_term_chirho == 0
            || !is_consistency_group_digest_chirho(&request_chirho.consistency_group_digest_chirho)
            || !is_lower_hex_64_chirho(&request_chirho.sender_node_chirho)
            || !is_lower_hex_64_chirho(&request_chirho.recipient_node_chirho)
            || !is_lower_hex_64_chirho(&request_chirho.losing_journal_genesis_digest_chirho)
            || !is_lower_hex_64_chirho(
                &request_chirho
                    .losing_journal_tail_chirho
                    .record_digest_chirho,
            )
            || !is_lower_hex_64_chirho(&request_chirho.nonce_chirho)
            || request_chirho.sender_node_chirho == request_chirho.recipient_node_chirho
        {
            return Err(Gd7WinnerForkObservationRefusalCodeChirho::InvalidRequestChirho);
        }
        if request_chirho.sender_node_chirho != self.state_chirho.held_node_chirho.0 {
            return Err(Gd7WinnerForkObservationRefusalCodeChirho::UnauthenticatedPeerChirho);
        }
        let sender_node_chirho = NodeIdChirho(request_chirho.sender_node_chirho.clone());
        self.verify_held_membership_chirho()?;
        let verifier_chirho = PinnedNodeGd7VerifierChirho::new_chirho(sender_node_chirho)
            .map_err(|_| Gd7WinnerForkObservationRefusalCodeChirho::InvalidRequestChirho)?;
        let mut unsigned_chirho = request_chirho.clone();
        let signature_chirho = std::mem::take(&mut unsigned_chirho.sig_chirho);
        let unsigned_bytes_chirho = canonical_json_chirho(&unsigned_chirho)
            .map_err(|_| Gd7WinnerForkObservationRefusalCodeChirho::InvalidRequestChirho)?;
        let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
            .map_err(|_| Gd7WinnerForkObservationRefusalCodeChirho::InvalidRequestChirho)?;
        if !verifier_chirho.verify_chirho(unsigned_line_chirho, &signature_chirho) {
            return Err(Gd7WinnerForkObservationRefusalCodeChirho::UnauthenticatedPeerChirho);
        }
        self.verify_local_warm_leadership_chirho(request_chirho.expected_winner_term_chirho)
    }

    fn verify_held_membership_chirho(
        &self,
    ) -> std::result::Result<(), Gd7WinnerForkObservationRefusalCodeChirho> {
        let (voters_chirho, learners_chirho) = self
            .state_chirho
            .elector_chirho
            .membership_snapshot_chirho()
            .map_err(|_| Gd7WinnerForkObservationRefusalCodeChirho::ActorStateChangedChirho)?;
        if !held_member_pair_is_exact_chirho(
            &self
                .state_chirho
                .elector_chirho
                .authenticated_members_chirho(),
            &voters_chirho,
            &learners_chirho,
            self.state_chirho.held_raft_id_chirho,
            &self.state_chirho.held_node_chirho,
        ) {
            return Err(Gd7WinnerForkObservationRefusalCodeChirho::ActorStateChangedChirho);
        }
        Ok(())
    }

    fn verify_local_warm_leadership_chirho(
        &self,
        expected_winner_term_chirho: u64,
    ) -> std::result::Result<u64, Gd7WinnerForkObservationRefusalCodeChirho> {
        let before_chirho = self.state_chirho.elector_chirho.current_leadership_chirho();
        if !leadership_matches_chirho(
            &before_chirho,
            &self.state_chirho.local_node_chirho,
            expected_winner_term_chirho,
        ) {
            return Err(Gd7WinnerForkObservationRefusalCodeChirho::LeadershipChangedChirho);
        }
        let authority_handle_chirho = self
            .state_chirho
            .elector_chirho
            .local_append_authority_handle_chirho();
        let authority_guard_chirho = authority_handle_chirho
            .try_acquire_chirho()
            .map_err(map_local_authority_refusal_code_chirho)?;
        if authority_guard_chirho.published_raft_term_chirho() != expected_winner_term_chirho {
            return Err(Gd7WinnerForkObservationRefusalCodeChirho::LeadershipChangedChirho);
        }
        drop(authority_guard_chirho);
        let after_chirho = self.state_chirho.elector_chirho.current_leadership_chirho();
        if !leadership_matches_chirho(
            &after_chirho,
            &self.state_chirho.local_node_chirho,
            expected_winner_term_chirho,
        ) {
            return Err(Gd7WinnerForkObservationRefusalCodeChirho::LeadershipChangedChirho);
        }
        Ok(expected_winner_term_chirho)
    }

    fn signed_response_chirho(
        &self,
        request_digest_chirho: &str,
        winner_term_chirho: u64,
        result_chirho: Gd7WinnerForkObservationResultChirho,
        payload_chirho: &[u8],
    ) -> Result<Vec<u8>> {
        if payload_chirho.len() > MAX_GD7_WINNER_FORK_OBSERVATION_PAYLOAD_BYTES_CHIRHO {
            bail!("winner-fork observation payload exceeds its fixed bound");
        }
        let payload_length_chirho = u64::try_from(payload_chirho.len())
            .map_err(|_| anyhow!("winner-fork observation payload length cannot fit u64"))?;
        let mut header_chirho = Gd7WinnerForkObservationResponseHeaderChirho {
            schema_chirho: GD7_WINNER_FORK_OBSERVATION_RESPONSE_SCHEMA_V1_CHIRHO.to_owned(),
            consistency_group_digest_chirho: self
                .state_chirho
                .consistency_group_digest_chirho
                .clone(),
            request_digest_chirho: request_digest_chirho.to_owned(),
            winner_node_chirho: self.state_chirho.local_node_chirho.0.clone(),
            winner_term_chirho,
            result_chirho,
            payload_length_chirho,
            payload_digest_chirho: digest_bytes_chirho(payload_chirho),
            key_id_chirho: self.state_chirho.signer_chirho.key_id_chirho(),
            sig_chirho: String::new(),
        };
        let unsigned_bytes_chirho = canonical_json_chirho(&header_chirho)?;
        let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
            .map_err(|_| anyhow!("winner-fork observation response is not UTF-8"))?;
        header_chirho.sig_chirho = self
            .state_chirho
            .signer_chirho
            .sign_chirho(unsigned_line_chirho)?;
        encode_response_frame_chirho(&header_chirho, payload_chirho)
    }
}

async fn admit_winner_fork_observation_chirho(
    State(service_chirho): State<Gd7WinnerForkObservationServiceChirho>,
    mut request_chirho: Request,
    next_chirho: Next,
) -> Response {
    let Some(admission_chirho) = service_chirho.try_admit_chirho() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    request_chirho.extensions_mut().insert(admission_chirho);
    match tokio::time::timeout(
        MAX_GD7_WINNER_FORK_OBSERVATION_REQUEST_DURATION_CHIRHO,
        next_chirho.run(request_chirho),
    )
    .await
    {
        Ok(response_chirho) => response_chirho,
        Err(_elapsed_chirho) => StatusCode::REQUEST_TIMEOUT.into_response(),
    }
}

async fn post_winner_fork_observation_chirho(
    State(service_chirho): State<Gd7WinnerForkObservationServiceChirho>,
    Extension(admission_chirho): Extension<Arc<Gd7WinnerForkObservationAdmissionChirho>>,
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

pub(crate) fn call_winner_fork_observation_chirho(
    context_chirho: Gd7WinnerForkObservationCallContextChirho<'_>,
) -> Result<ResidentGd7HeldObservationImportChirho> {
    let Gd7WinnerForkObservationCallContextChirho {
        agent_chirho,
        base_url_chirho,
        consistency_group_digest_chirho,
        held_signer_chirho,
        winner_node_chirho,
        expected_winner_term_chirho,
        losing_journal_genesis_digest_chirho,
        losing_journal_tail_chirho,
        request_nonce_chirho,
    } = context_chirho;
    crate::winner_view_transfer_chirho::validate_winner_view_transfer_base_url_chirho(
        base_url_chirho,
    )?;
    if expected_winner_term_chirho == 0
        || !is_consistency_group_digest_chirho(consistency_group_digest_chirho)
        || !is_lower_hex_64_chirho(losing_journal_genesis_digest_chirho)
        || !is_lower_hex_64_chirho(&losing_journal_tail_chirho.record_digest_chirho)
        || !is_lower_hex_64_chirho(request_nonce_chirho)
        || held_signer_chirho.node_id_chirho() == winner_node_chirho
    {
        bail!("winner-fork observation request coordinate is invalid");
    }
    let mut request_chirho = Gd7WinnerForkObservationRequestChirho {
        schema_chirho: GD7_WINNER_FORK_OBSERVATION_REQUEST_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: consistency_group_digest_chirho.to_owned(),
        sender_node_chirho: held_signer_chirho.node_id_chirho().0.clone(),
        recipient_node_chirho: winner_node_chirho.0.clone(),
        expected_winner_term_chirho,
        losing_journal_genesis_digest_chirho: losing_journal_genesis_digest_chirho.to_owned(),
        losing_journal_tail_chirho: losing_journal_tail_chirho.clone(),
        nonce_chirho: request_nonce_chirho.to_owned(),
        key_id_chirho: held_signer_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    let unsigned_bytes_chirho = canonical_json_chirho(&request_chirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| anyhow!("winner-fork observation request is not UTF-8"))?;
    request_chirho.sig_chirho = held_signer_chirho.sign_chirho(unsigned_line_chirho)?;
    let request_bytes_chirho = canonical_json_chirho(&request_chirho)?;
    if request_bytes_chirho.len() > MAX_GD7_WINNER_FORK_OBSERVATION_REQUEST_BYTES_CHIRHO {
        bail!("winner-fork observation request exceeds its fixed bound");
    }
    let request_digest_chirho = digest_bytes_chirho(&request_bytes_chirho);
    let url_chirho = format!(
        "{}{}",
        base_url_chirho.trim_end_matches('/'),
        GD7_WINNER_FORK_OBSERVATION_PATH_CHIRHO
    );
    let response_chirho = agent_chirho
        .post(&url_chirho)
        .set("content-type", "application/json")
        .send_bytes(&request_bytes_chirho)
        .with_context(|| format!("post winner-fork observation request to {url_chirho}"))?;
    if response_chirho.status() != 200 {
        bail!(
            "winner-fork observation endpoint returned HTTP {}",
            response_chirho.status()
        );
    }
    let mut response_bytes_chirho = Vec::new();
    response_chirho
        .into_reader()
        .take(
            u64::try_from(MAX_GD7_WINNER_FORK_OBSERVATION_RESPONSE_BYTES_CHIRHO)
                .expect("response cap fits u64")
                + 1,
        )
        .read_to_end(&mut response_bytes_chirho)
        .context("read bounded winner-fork observation response")?;
    if response_bytes_chirho.len() > MAX_GD7_WINNER_FORK_OBSERVATION_RESPONSE_BYTES_CHIRHO {
        bail!("winner-fork observation response exceeds its fixed bound");
    }
    let (header_chirho, payload_chirho) = decode_response_frame_chirho(&response_bytes_chirho)?;
    let winner_verifier_chirho =
        PinnedNodeGd7VerifierChirho::new_chirho(winner_node_chirho.clone())?;
    verify_response_chirho(
        &header_chirho,
        payload_chirho,
        consistency_group_digest_chirho,
        &request_digest_chirho,
        winner_node_chirho,
        expected_winner_term_chirho,
        &winner_verifier_chirho,
    )?;
    match header_chirho.result_chirho {
        Gd7WinnerForkObservationResultChirho::RefusedChirho { code_chirho } => {
            bail!("winner-fork observation was refused: {code_chirho:?}");
        }
        Gd7WinnerForkObservationResultChirho::ObservedChirho => {}
    }
    let (index_bytes_chirho, witness_bytes_chirho) =
        decode_observation_payload_chirho(payload_chirho)?;
    let index_chirho = parse_canonical_bounded_chirho::<Gd7WinnerFirstRecordIndexChirho>(
        index_bytes_chirho,
        MAX_GD7_WINNER_FIRST_RECORD_INDEX_BYTES_CHIRHO,
    )?;
    let witness_chirho = parse_canonical_bounded_chirho::<Gd7WinnerForkWitnessChirho>(
        witness_bytes_chirho,
        MAX_GD7_WINNER_FORK_WITNESS_BYTES_CHIRHO,
    )?;
    let observation_chirho = ResidentGd7WinnerForkObservationChirho {
        identity_chirho: witness_chirho.identity_chirho.clone(),
        winner_first_record_index_chirho: index_chirho,
        winner_fork_witness_chirho: witness_chirho,
    };
    validate_observation_binding_chirho(
        &observation_chirho,
        consistency_group_digest_chirho,
        winner_node_chirho,
        held_signer_chirho.node_id_chirho(),
        expected_winner_term_chirho,
        losing_journal_genesis_digest_chirho,
        losing_journal_tail_chirho,
    )?;
    Ok(ResidentGd7HeldObservationImportChirho {
        identity_chirho: observation_chirho.identity_chirho,
        winner_first_record_index_bytes_chirho: index_bytes_chirho.to_vec(),
        winner_fork_witness_bytes_chirho: witness_bytes_chirho.to_vec(),
    })
}

fn leadership_matches_chirho(
    leadership_chirho: &cairn_writer_elector_chirho::elector_port_chirho::LeadershipChirho,
    local_node_chirho: &NodeIdChirho,
    expected_winner_term_chirho: u64,
) -> bool {
    leadership_chirho.is_leader_chirho
        && leadership_chirho.lease_valid_chirho
        && leadership_chirho.leader_id_chirho.as_ref() == Some(local_node_chirho)
        && leadership_chirho.term_chirho == expected_winner_term_chirho
}

fn map_local_authority_refusal_code_chirho(
    refusal_chirho: LocalAppendAuthorityRefusalChirho,
) -> Gd7WinnerForkObservationRefusalCodeChirho {
    match refusal_chirho {
        LocalAppendAuthorityRefusalChirho::TransitionPendingChirho
        | LocalAppendAuthorityRefusalChirho::GuardBusyChirho => {
            Gd7WinnerForkObservationRefusalCodeChirho::ActorBusyChirho
        }
        LocalAppendAuthorityRefusalChirho::NotLocalLeaderChirho
        | LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho
        | LocalAppendAuthorityRefusalChirho::NotPromotableVoterChirho
        | LocalAppendAuthorityRefusalChirho::LeadershipTransferInProgressChirho => {
            Gd7WinnerForkObservationRefusalCodeChirho::LeadershipChangedChirho
        }
        // This mapper receives only `try_acquire_chirho` refusals; that path never allocates a
        // handoff generation. Keep the unreachable case explicit so enum growth remains visible.
        LocalAppendAuthorityRefusalChirho::HandoffGenerationExhaustedChirho => {
            Gd7WinnerForkObservationRefusalCodeChirho::ActorStateChangedChirho
        }
        LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho
        | LocalAppendAuthorityRefusalChirho::ElectorDroppedChirho
        | LocalAppendAuthorityRefusalChirho::AuthorityUnavailableChirho
        | LocalAppendAuthorityRefusalChirho::HandoffActiveChirho
        | LocalAppendAuthorityRefusalChirho::HandoffIdentityMismatchChirho
        | LocalAppendAuthorityRefusalChirho::InvalidHandoffIdentityChirho
        | LocalAppendAuthorityRefusalChirho::PublishedRaftTermOutOfRangeChirho => {
            Gd7WinnerForkObservationRefusalCodeChirho::ActorStateChangedChirho
        }
    }
}

fn map_actor_refusal_code_chirho(
    refusal_chirho: ResidentGd7WinnerForkObservationRefusalChirho,
) -> Gd7WinnerForkObservationRefusalCodeChirho {
    match refusal_chirho {
        ResidentGd7WinnerForkObservationRefusalChirho::ActorBusyChirho => {
            Gd7WinnerForkObservationRefusalCodeChirho::ActorBusyChirho
        }
        ResidentGd7WinnerForkObservationRefusalChirho::ActorReplyTimedOutChirho => {
            Gd7WinnerForkObservationRefusalCodeChirho::ActorBusyChirho
        }
        ResidentGd7WinnerForkObservationRefusalChirho::ActorUnavailableChirho => {
            Gd7WinnerForkObservationRefusalCodeChirho::ActorUnavailableChirho
        }
        ResidentGd7WinnerForkObservationRefusalChirho::WinnerStateChangedChirho => {
            Gd7WinnerForkObservationRefusalCodeChirho::ActorStateChangedChirho
        }
        ResidentGd7WinnerForkObservationRefusalChirho::TenantMigrationSourceFenceActiveChirho => {
            Gd7WinnerForkObservationRefusalCodeChirho::ActorStateChangedChirho
        }
        ResidentGd7WinnerForkObservationRefusalChirho::InvalidHeldCoordinateChirho => {
            Gd7WinnerForkObservationRefusalCodeChirho::InvalidRequestChirho
        }
        ResidentGd7WinnerForkObservationRefusalChirho::MissingWinnerIndexChirho
        | ResidentGd7WinnerForkObservationRefusalChirho::WitnessChirho(_) => {
            Gd7WinnerForkObservationRefusalCodeChirho::ActorRefusedChirho
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the exact request and winner-derived observation coordinate must be compared directly"
)]
fn validate_observation_binding_chirho(
    observation_chirho: &ResidentGd7WinnerForkObservationChirho,
    expected_group_digest_chirho: &str,
    expected_winner_node_chirho: &NodeIdChirho,
    expected_held_node_chirho: &NodeIdChirho,
    expected_winner_term_chirho: u64,
    expected_losing_genesis_chirho: &str,
    expected_losing_tail_chirho: &Gd7JournalTailCoordinateChirho,
) -> Result<()> {
    let identity_chirho = &observation_chirho.identity_chirho;
    let index_chirho = &observation_chirho.winner_first_record_index_chirho;
    let witness_chirho = &observation_chirho.winner_fork_witness_chirho;
    if identity_chirho.consistency_group_digest_chirho != expected_group_digest_chirho
        || identity_chirho.winner_node_chirho != expected_winner_node_chirho.0
        || identity_chirho.held_node_chirho != expected_held_node_chirho.0
        || identity_chirho.winner_term_chirho != expected_winner_term_chirho
        || identity_chirho.losing_journal_genesis_digest_chirho != expected_losing_genesis_chirho
        || &identity_chirho.losing_journal_tail_chirho != expected_losing_tail_chirho
        || witness_chirho.identity_chirho != *identity_chirho
        || index_chirho.consistency_group_digest_chirho != expected_group_digest_chirho
        || index_chirho.winner_node_chirho != expected_winner_node_chirho.0
        || index_chirho.winner_term_chirho != expected_winner_term_chirho
        || index_chirho.winner_journal_genesis_digest_chirho
            != identity_chirho.winner_journal_genesis_digest_chirho
    {
        bail!("winner-fork observation evidence does not bind the exact request coordinate");
    }
    Ok(())
}

fn encode_observation_payload_chirho(
    index_bytes_chirho: &[u8],
    witness_bytes_chirho: &[u8],
) -> Result<Vec<u8>> {
    if index_bytes_chirho.is_empty()
        || index_bytes_chirho.len() > MAX_GD7_WINNER_FIRST_RECORD_INDEX_BYTES_CHIRHO
        || witness_bytes_chirho.is_empty()
        || witness_bytes_chirho.len() > MAX_GD7_WINNER_FORK_WITNESS_BYTES_CHIRHO
    {
        bail!("winner-fork observation evidence exceeds its fixed object bounds");
    }
    let index_length_chirho = u32::try_from(index_bytes_chirho.len())
        .map_err(|_| anyhow!("winner-fork observation index length cannot fit u32"))?;
    let capacity_chirho = 4_usize
        .checked_add(index_bytes_chirho.len())
        .and_then(|length_chirho| length_chirho.checked_add(witness_bytes_chirho.len()))
        .ok_or_else(|| anyhow!("winner-fork observation payload length overflow"))?;
    if capacity_chirho > MAX_GD7_WINNER_FORK_OBSERVATION_PAYLOAD_BYTES_CHIRHO {
        bail!("winner-fork observation payload exceeds its fixed bound");
    }
    let mut payload_chirho = Vec::with_capacity(capacity_chirho);
    payload_chirho.extend_from_slice(&index_length_chirho.to_be_bytes());
    payload_chirho.extend_from_slice(index_bytes_chirho);
    payload_chirho.extend_from_slice(witness_bytes_chirho);
    Ok(payload_chirho)
}

fn decode_observation_payload_chirho(payload_chirho: &[u8]) -> Result<(&[u8], &[u8])> {
    if payload_chirho.len() > MAX_GD7_WINNER_FORK_OBSERVATION_PAYLOAD_BYTES_CHIRHO {
        bail!("winner-fork observation payload exceeds its fixed bound");
    }
    let index_length_bytes_chirho: [u8; 4] = payload_chirho
        .get(..4)
        .ok_or_else(|| anyhow!("winner-fork observation payload omits its index length"))?
        .try_into()
        .map_err(|_| anyhow!("winner-fork observation index length is invalid"))?;
    let index_length_chirho = usize::try_from(u32::from_be_bytes(index_length_bytes_chirho))
        .map_err(|_| anyhow!("winner-fork observation index length cannot fit usize"))?;
    if index_length_chirho == 0
        || index_length_chirho > MAX_GD7_WINNER_FIRST_RECORD_INDEX_BYTES_CHIRHO
    {
        bail!("winner-fork observation index length exceeds its fixed bound");
    }
    let witness_offset_chirho = 4_usize
        .checked_add(index_length_chirho)
        .ok_or_else(|| anyhow!("winner-fork observation witness offset overflow"))?;
    let index_bytes_chirho = payload_chirho
        .get(4..witness_offset_chirho)
        .ok_or_else(|| anyhow!("winner-fork observation index is truncated"))?;
    let witness_bytes_chirho = payload_chirho
        .get(witness_offset_chirho..)
        .ok_or_else(|| anyhow!("winner-fork observation witness offset is invalid"))?;
    if witness_bytes_chirho.is_empty()
        || witness_bytes_chirho.len() > MAX_GD7_WINNER_FORK_WITNESS_BYTES_CHIRHO
    {
        bail!("winner-fork observation witness length exceeds its fixed bound");
    }
    Ok((index_bytes_chirho, witness_bytes_chirho))
}

fn encode_response_frame_chirho(
    header_chirho: &Gd7WinnerForkObservationResponseHeaderChirho,
    payload_chirho: &[u8],
) -> Result<Vec<u8>> {
    let header_bytes_chirho = canonical_json_chirho(header_chirho)?;
    if header_bytes_chirho.len() > MAX_GD7_WINNER_FORK_OBSERVATION_HEADER_BYTES_CHIRHO {
        bail!("winner-fork observation response header exceeds its fixed bound");
    }
    let header_length_chirho = u32::try_from(header_bytes_chirho.len())
        .map_err(|_| anyhow!("winner-fork observation response header cannot fit u32"))?;
    let capacity_chirho = 4_usize
        .checked_add(header_bytes_chirho.len())
        .and_then(|length_chirho| length_chirho.checked_add(payload_chirho.len()))
        .ok_or_else(|| anyhow!("winner-fork observation response length overflow"))?;
    if capacity_chirho > MAX_GD7_WINNER_FORK_OBSERVATION_RESPONSE_BYTES_CHIRHO {
        bail!("winner-fork observation response exceeds its fixed bound");
    }
    let mut frame_chirho = Vec::with_capacity(capacity_chirho);
    frame_chirho.extend_from_slice(&header_length_chirho.to_be_bytes());
    frame_chirho.extend_from_slice(&header_bytes_chirho);
    frame_chirho.extend_from_slice(payload_chirho);
    Ok(frame_chirho)
}

fn decode_response_frame_chirho(
    frame_chirho: &[u8],
) -> Result<(Gd7WinnerForkObservationResponseHeaderChirho, &[u8])> {
    if frame_chirho.len() > MAX_GD7_WINNER_FORK_OBSERVATION_RESPONSE_BYTES_CHIRHO {
        bail!("winner-fork observation response exceeds its fixed bound");
    }
    let header_length_bytes_chirho: [u8; 4] = frame_chirho
        .get(..4)
        .ok_or_else(|| anyhow!("winner-fork observation response omits its header length"))?
        .try_into()
        .map_err(|_| anyhow!("winner-fork observation response header length is invalid"))?;
    let header_length_chirho = usize::try_from(u32::from_be_bytes(header_length_bytes_chirho))
        .map_err(|_| anyhow!("winner-fork observation header length cannot fit usize"))?;
    if header_length_chirho > MAX_GD7_WINNER_FORK_OBSERVATION_HEADER_BYTES_CHIRHO {
        bail!("winner-fork observation response header exceeds its fixed bound");
    }
    let payload_offset_chirho = 4_usize
        .checked_add(header_length_chirho)
        .ok_or_else(|| anyhow!("winner-fork observation response offset overflow"))?;
    let header_bytes_chirho = frame_chirho
        .get(4..payload_offset_chirho)
        .ok_or_else(|| anyhow!("winner-fork observation response header is truncated"))?;
    let payload_chirho = frame_chirho
        .get(payload_offset_chirho..)
        .ok_or_else(|| anyhow!("winner-fork observation response payload offset is invalid"))?;
    let header_chirho =
        parse_canonical_bounded_chirho::<Gd7WinnerForkObservationResponseHeaderChirho>(
            header_bytes_chirho,
            MAX_GD7_WINNER_FORK_OBSERVATION_HEADER_BYTES_CHIRHO,
        )?;
    Ok((header_chirho, payload_chirho))
}

#[allow(
    clippy::too_many_arguments,
    reason = "verification binds the exact signed request-response coordinate without ambient state"
)]
fn verify_response_chirho(
    header_chirho: &Gd7WinnerForkObservationResponseHeaderChirho,
    payload_chirho: &[u8],
    expected_group_digest_chirho: &str,
    expected_request_digest_chirho: &str,
    expected_winner_node_chirho: &NodeIdChirho,
    expected_winner_term_chirho: u64,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<()> {
    let term_coordinate_valid_chirho = match &header_chirho.result_chirho {
        Gd7WinnerForkObservationResultChirho::RefusedChirho {
            code_chirho: Gd7WinnerForkObservationRefusalCodeChirho::LeadershipChangedChirho,
        } => header_chirho.winner_term_chirho >= expected_winner_term_chirho,
        _ => header_chirho.winner_term_chirho == expected_winner_term_chirho,
    };
    if header_chirho.schema_chirho != GD7_WINNER_FORK_OBSERVATION_RESPONSE_SCHEMA_V1_CHIRHO
        || header_chirho.consistency_group_digest_chirho != expected_group_digest_chirho
        || header_chirho.request_digest_chirho != expected_request_digest_chirho
        || header_chirho.winner_node_chirho != expected_winner_node_chirho.0
        || !term_coordinate_valid_chirho
        || header_chirho.key_id_chirho != expected_winner_node_chirho.0
        || usize::try_from(header_chirho.payload_length_chirho).ok() != Some(payload_chirho.len())
        || header_chirho.payload_digest_chirho != digest_bytes_chirho(payload_chirho)
    {
        bail!("winner-fork observation response coordinate is invalid");
    }
    let mut unsigned_chirho = header_chirho.clone();
    let signature_chirho = std::mem::take(&mut unsigned_chirho.sig_chirho);
    let unsigned_bytes_chirho = canonical_json_chirho(&unsigned_chirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| anyhow!("winner-fork observation response is not UTF-8"))?;
    if !verifier_chirho.verify_chirho(unsigned_line_chirho, &signature_chirho) {
        bail!("winner-fork observation response signature is invalid");
    }
    match &header_chirho.result_chirho {
        Gd7WinnerForkObservationResultChirho::ObservedChirho => {
            if payload_chirho.is_empty()
                || payload_chirho.len() > MAX_GD7_WINNER_FORK_OBSERVATION_PAYLOAD_BYTES_CHIRHO
            {
                bail!("winner-fork observation success payload is invalid");
            }
        }
        Gd7WinnerForkObservationResultChirho::RefusedChirho { .. }
            if !payload_chirho.is_empty() =>
        {
            bail!("winner-fork observation refusal unexpectedly carries a payload");
        }
        Gd7WinnerForkObservationResultChirho::RefusedChirho { .. } => {}
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
    serde_json::to_vec(value_chirho).context("serialize canonical winner-fork observation JSON")
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

fn is_consistency_group_digest_chirho(value_chirho: &str) -> bool {
    value_chirho
        .strip_prefix(CONSISTENCY_GROUP_DIGEST_PREFIX_CHIRHO)
        .is_some_and(is_lower_hex_64_chirho)
}

fn held_member_pair_is_exact_chirho(
    authenticated_members_chirho: &[(u64, NodeIdChirho)],
    voters_chirho: &[u64],
    learners_chirho: &[u64],
    held_raft_id_chirho: u64,
    held_node_chirho: &NodeIdChirho,
) -> bool {
    !voters_chirho.contains(&held_raft_id_chirho)
        && learners_chirho == [held_raft_id_chirho]
        && authenticated_members_chirho
            .iter()
            .filter(|(raft_id_chirho, node_chirho)| {
                *raft_id_chirho == held_raft_id_chirho && node_chirho == held_node_chirho
            })
            .count()
            == 1
        && authenticated_members_chirho
            .iter()
            .filter(|(_raft_id_chirho, node_chirho)| node_chirho == held_node_chirho)
            .count()
            == 1
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CanonicalProbeChirho {
        value_chirho: u64,
    }

    #[test]
    fn observation_payload_round_trips_exact_object_bytes_chirho() {
        let index_bytes_chirho = br#"{"index_chirho":"one"}"#;
        let witness_bytes_chirho = br#"{"witness_chirho":"two"}"#;
        let payload_chirho =
            encode_observation_payload_chirho(index_bytes_chirho, witness_bytes_chirho)
                .expect("encode bounded observation payload");
        let (decoded_index_chirho, decoded_witness_chirho) =
            decode_observation_payload_chirho(&payload_chirho)
                .expect("decode bounded observation payload");
        assert_eq!(decoded_index_chirho, index_bytes_chirho);
        assert_eq!(decoded_witness_chirho, witness_bytes_chirho);
    }

    #[test]
    fn observation_payload_rejects_truncation_and_object_overflow_chirho() {
        let truncated_chirho = [0_u8, 0, 0, 5, b'x'];
        assert!(decode_observation_payload_chirho(&truncated_chirho).is_err());
        assert!(encode_observation_payload_chirho(
            &vec![b'x'; MAX_GD7_WINNER_FIRST_RECORD_INDEX_BYTES_CHIRHO + 1],
            b"{}",
        )
        .is_err());
        assert!(encode_observation_payload_chirho(
            b"{}",
            &vec![b'x'; MAX_GD7_WINNER_FORK_WITNESS_BYTES_CHIRHO + 1],
        )
        .is_err());
    }

    #[test]
    fn canonical_parser_rejects_equivalent_noncanonical_json_chirho() {
        let canonical_chirho = br#"{"value_chirho":7}"#;
        let parsed_chirho = parse_canonical_bounded_chirho::<CanonicalProbeChirho>(
            canonical_chirho,
            canonical_chirho.len(),
        )
        .expect("parse canonical JSON");
        assert_eq!(parsed_chirho.value_chirho, 7);
        let noncanonical_chirho = br#"{ "value_chirho": 7 }"#;
        assert!(parse_canonical_bounded_chirho::<CanonicalProbeChirho>(
            noncanonical_chirho,
            noncanonical_chirho.len(),
        )
        .unwrap_err()
        .to_string()
        .contains("not canonical"));
    }

    #[test]
    fn actor_transport_and_state_refusals_remain_distinct_chirho() {
        assert_eq!(
            map_actor_refusal_code_chirho(
                ResidentGd7WinnerForkObservationRefusalChirho::ActorBusyChirho,
            ),
            Gd7WinnerForkObservationRefusalCodeChirho::ActorBusyChirho
        );
        assert_eq!(
            map_actor_refusal_code_chirho(
                ResidentGd7WinnerForkObservationRefusalChirho::ActorUnavailableChirho,
            ),
            Gd7WinnerForkObservationRefusalCodeChirho::ActorUnavailableChirho
        );
        assert_eq!(
            map_actor_refusal_code_chirho(
                ResidentGd7WinnerForkObservationRefusalChirho::WinnerStateChangedChirho,
            ),
            Gd7WinnerForkObservationRefusalCodeChirho::ActorStateChangedChirho
        );
    }

    #[test]
    fn response_frame_round_trips_header_and_payload_chirho() {
        let payload_chirho =
            encode_observation_payload_chirho(b"{}", b"{}").expect("encode payload");
        let header_chirho = Gd7WinnerForkObservationResponseHeaderChirho {
            schema_chirho: GD7_WINNER_FORK_OBSERVATION_RESPONSE_SCHEMA_V1_CHIRHO.to_owned(),
            consistency_group_digest_chirho: "a".repeat(64),
            request_digest_chirho: "b".repeat(64),
            winner_node_chirho: "c".repeat(64),
            winner_term_chirho: 7,
            result_chirho: Gd7WinnerForkObservationResultChirho::ObservedChirho,
            payload_length_chirho: u64::try_from(payload_chirho.len())
                .expect("payload length fits u64"),
            payload_digest_chirho: digest_bytes_chirho(&payload_chirho),
            key_id_chirho: "c".repeat(64),
            sig_chirho: "d".repeat(128),
        };
        let frame_chirho = encode_response_frame_chirho(&header_chirho, &payload_chirho)
            .expect("encode response frame");
        let (decoded_header_chirho, decoded_payload_chirho) =
            decode_response_frame_chirho(&frame_chirho).expect("decode response frame");
        assert_eq!(decoded_header_chirho, header_chirho);
        assert_eq!(decoded_payload_chirho, payload_chirho);
    }

    #[test]
    fn runtime_consistency_group_digest_is_wire_valid_chirho() {
        let group_chirho = ConsistencyGroupIdChirho::TenantChirho {
            tenant_id_chirho: "tenant-one-chirho".to_owned(),
        };
        let digest_chirho =
            consistency_group_digest_chirho(&group_chirho).expect("derive runtime group digest");
        assert!(is_consistency_group_digest_chirho(&digest_chirho));
        assert!(!is_consistency_group_digest_chirho(
            digest_chirho
                .strip_prefix(CONSISTENCY_GROUP_DIGEST_PREFIX_CHIRHO)
                .expect("runtime digest carries its type prefix"),
        ));
    }

    #[test]
    fn held_member_pair_requires_exact_authenticated_learner_mapping_chirho() {
        let held_node_chirho = NodeIdChirho("a".repeat(64));
        let other_node_chirho = NodeIdChirho("b".repeat(64));
        assert!(held_member_pair_is_exact_chirho(
            &[
                (7, other_node_chirho.clone()),
                (9, held_node_chirho.clone())
            ],
            &[7],
            &[9],
            9,
            &held_node_chirho,
        ));
        assert!(!held_member_pair_is_exact_chirho(
            &[
                (7, held_node_chirho.clone()),
                (9, other_node_chirho.clone())
            ],
            &[7],
            &[9],
            9,
            &held_node_chirho,
        ));
        assert!(!held_member_pair_is_exact_chirho(
            &[(7, held_node_chirho.clone()), (9, held_node_chirho.clone())],
            &[7],
            &[9],
            9,
            &held_node_chirho,
        ));
    }
}
