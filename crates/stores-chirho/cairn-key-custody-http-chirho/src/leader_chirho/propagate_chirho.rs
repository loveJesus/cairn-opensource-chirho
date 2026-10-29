// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Erasure propagation after the lock: for one bound requirement, chosen by seq or found again by an attempt's identity, send each holder whose share is still open one freshly signed frame, keep its receipt only through B1's answer check, and report the attempt the store then holds.
//!
//! C5 B3-a3-ii (item 14 D3 and D4; design GOs gpt #30156, agy #30163), and B3-a4-i's retry by identity
//! (item 17; design GOs gpt #30296, agy #30332). It runs after every root lock is
//! released and holds none across a send. Authority is read afresh before EVERY attempt, and each attempt signs a
//! fresh frame, because a frame carries the leader's remaining lease measured at signing: a resent frame would
//! overstate it. Re-signing never refreshes leadership; an attempt is sent only under a lease observation that is
//! valid when it is read, and the lease the frame carries is what remains of that observation when the frame is
//! built, so time spent preparing is charged to it. One call budget bounds the whole call: it is read before the
//! authority read, again before signing and once more at the delivery boundary, so no signing or delivery STARTS
//! once it is spent, and each network timeout and backoff is cut to what remains of it (gpt #30241). The clock
//! cannot interrupt synchronous work already started: the in-process admission, the
//! store's own reads (each verifies every stored receipt of the requirement, up to 64 holders x 64 receipts), a lock
//! wait or an fsync can each run past the budget, so a call returns after the budget plus that work (gpt #30205).
//! That overrun is a named residual, not a promise to return by 30 seconds. The attempt returned is read back from
//! the STORE after the sends, by the requirement's identity, never from what the engine saw in memory.
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/key-custody-chirho/erasure-propagation-workflow-chirho.md`, section 2.

use super::refusal_chirho::{LeaderRefusalChirho, LeaderRefusalIdentityChirho};
use super::store_chirho::{
    requirement_for_identity_chirho, ErasureAttemptChirho, ErasureAttemptIdentityChirho,
    ErasurePropagationStoreChirho, RequirementStandingChirho,
};
use crate::client_chirho::{KeyCustodyClientChirho, KeyCustodyClientErrorChirho};
use crate::holder_chirho::KeyCustodyHolderChirho;
use crate::refusal_chirho::HolderRefusalIdentityChirho;
use cairn_key_custody_chirho::{
    decode_and_verify_erasure_receipt_chirho, verify_erasure_receipt_answers_frame_chirho,
    ErasureFrameInputChirho, ErasureFrameV1Chirho, ErasureStatusChirho,
    KeyCustodyRefusalIdentityChirho, PreparedErasureFrameChirho,
    VerifiedErasurePropagationRequirementChirho, VerifiedErasureReceiptChirho,
};
use cairn_mirror_chirho::{
    join_mirror_view_chirho, JoinedMirrorViewChirho, MirrorLeadershipViewChirho,
    MirrorRefusalIdentityChirho,
};
use cairn_tenant_placement_authority_chirho::VerifiedTenantPlacementChirho;
use cairn_writer_elector_chirho::monotonic_clock_chirho::MonotonicClockChirho;
use std::collections::BTreeMap;
use std::time::Duration;

/// The most attempts one holder gets in one call.
pub const ERASURE_PROPAGATION_ATTEMPTS_PER_HOLDER_CHIRHO: u32 = 3;
/// The pause after a first unanswered attempt; it doubles after each further one.
pub const ERASURE_PROPAGATION_FIRST_BACKOFF_CHIRHO: Duration = Duration::from_millis(200);
/// The most one request waits for its answer, before the call budget cuts it shorter.
pub const ERASURE_PROPAGATION_REQUEST_TIMEOUT_CHIRHO: Duration = Duration::from_secs(5);
/// The one budget for a whole call.
pub const ERASURE_PROPAGATION_CALL_BUDGET_CHIRHO: Duration = Duration::from_secs(30);
/// The least time reserved for signing one frame. It comes off the lease the frame carries, so the receiver's
/// transit allowance is left for transit, and a frame whose signing took longer is never sent (gpt #30243).
pub const ERASURE_PROPAGATION_SIGNING_RESERVE_CHIRHO: Duration = Duration::from_millis(100);

/// How hard one call tries. The defaults are the design's limits: a caller may lower the attempts, the request
/// timeout and the call budget, and may raise the signing reserve, never the other way (gpt #30244). The backoff
/// is cut to the remaining budget, so it needs no limit of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErasurePropagationPolicyChirho {
    pub attempts_per_holder_chirho: u32,
    pub first_backoff_chirho: Duration,
    pub request_timeout_chirho: Duration,
    pub call_budget_chirho: Duration,
    pub signing_reserve_chirho: Duration,
}

impl Default for ErasurePropagationPolicyChirho {
    fn default() -> Self {
        Self {
            attempts_per_holder_chirho: ERASURE_PROPAGATION_ATTEMPTS_PER_HOLDER_CHIRHO,
            first_backoff_chirho: ERASURE_PROPAGATION_FIRST_BACKOFF_CHIRHO,
            request_timeout_chirho: ERASURE_PROPAGATION_REQUEST_TIMEOUT_CHIRHO,
            call_budget_chirho: ERASURE_PROPAGATION_CALL_BUDGET_CHIRHO,
            signing_reserve_chirho: ERASURE_PROPAGATION_SIGNING_RESERVE_CHIRHO,
        }
    }
}

impl ErasurePropagationPolicyChirho {
    /// Whether this policy stays inside the design's limits: at least one and at most the default attempts, a
    /// request timeout and a call budget above zero and at most the defaults, and at least the default reserve.
    pub fn within_limits_chirho(&self) -> bool {
        (1..=ERASURE_PROPAGATION_ATTEMPTS_PER_HOLDER_CHIRHO)
            .contains(&self.attempts_per_holder_chirho)
            && !self.request_timeout_chirho.is_zero()
            && self.request_timeout_chirho <= ERASURE_PROPAGATION_REQUEST_TIMEOUT_CHIRHO
            && !self.call_budget_chirho.is_zero()
            && self.call_budget_chirho <= ERASURE_PROPAGATION_CALL_BUDGET_CHIRHO
            && self.signing_reserve_chirho >= ERASURE_PROPAGATION_SIGNING_RESERVE_CHIRHO
    }
}

/// The policy, and the clock and sleep it is measured and paced by. Both are injected, so arms can move time.
pub struct ErasurePropagationPacingChirho<'pacing_chirho> {
    pub policy_chirho: ErasurePropagationPolicyChirho,
    pub clock_chirho: &'pacing_chirho dyn MonotonicClockChirho,
    pub sleep_chirho: &'pacing_chirho dyn Fn(Duration),
}

/// What one delivery attempt to one holder came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErasureDeliveryErrorChirho {
    /// There is no route to this holder; it stays pending.
    NoRouteChirho,
    /// No answer arrived in time, so the holder may or may not have acted; a later attempt signs a fresh frame.
    TransportChirho,
    /// The holder says this node is not its leader, its term is stale, or its lease has expired: stop the call.
    AuthorityRefusedChirho,
    /// Any other refusal; this holder stays pending.
    RefusedChirho,
    /// The answer is not a verifying receipt for exactly this frame.
    ReceiptRejectedChirho,
}

/// How a frame reaches a holder. `holder_chirho` only routes; whether the receipt answers is judged from the
/// frame itself.
pub trait ErasureHolderSeamChirho {
    fn deliver_erasure_chirho(
        &self,
        holder_chirho: &str,
        frame_chirho: &ErasureFrameV1Chirho,
        timeout_chirho: Duration,
    ) -> Result<VerifiedErasureReceiptChirho, ErasureDeliveryErrorChirho>;
}

/// The one seam: this node's own holder in process, every other holder over its private-mesh origin. The peer
/// map is built at composition from the ledger mirror's peer endpoints, never a second config (Q4).
pub struct ErasureHoldersChirho<'holder_chirho> {
    local_node_id_chirho: String,
    local_holder_chirho: Option<&'holder_chirho KeyCustodyHolderChirho>,
    peers_chirho: BTreeMap<String, KeyCustodyClientChirho>,
}

impl<'holder_chirho> ErasureHoldersChirho<'holder_chirho> {
    pub fn new_chirho(
        local_node_id_chirho: impl Into<String>,
        local_holder_chirho: Option<&'holder_chirho KeyCustodyHolderChirho>,
        peer_origins_chirho: BTreeMap<String, String>,
    ) -> Self {
        Self {
            local_node_id_chirho: local_node_id_chirho.into(),
            local_holder_chirho,
            peers_chirho: peer_origins_chirho
                .into_iter()
                .map(|(node_chirho, origin_chirho)| {
                    (
                        node_chirho,
                        KeyCustodyClientChirho::new_chirho(
                            origin_chirho,
                            ERASURE_PROPAGATION_REQUEST_TIMEOUT_CHIRHO,
                        ),
                    )
                })
                .collect(),
        }
    }
}

impl ErasureHolderSeamChirho for ErasureHoldersChirho<'_> {
    fn deliver_erasure_chirho(
        &self,
        holder_chirho: &str,
        frame_chirho: &ErasureFrameV1Chirho,
        timeout_chirho: Duration,
    ) -> Result<VerifiedErasureReceiptChirho, ErasureDeliveryErrorChirho> {
        if holder_chirho == self.local_node_id_chirho {
            // The local road passes the signed WIRE bytes through the holder's whole admission; it never builds an
            // authorized frame or a receipt itself (gpt #30156). It cannot be interrupted, so it ignores the timeout.
            let local_chirho = self
                .local_holder_chirho
                .ok_or(ErasureDeliveryErrorChirho::NoRouteChirho)?;
            let wire_chirho = frame_chirho
                .to_wire_bytes_chirho()
                .map_err(|_| ErasureDeliveryErrorChirho::RefusedChirho)?;
            let answer_chirho =
                local_chirho
                    .admit_erasure_chirho(&wire_chirho)
                    .map_err(|refusal_chirho| {
                        classify_refusal_chirho(&refusal_chirho.wire_identity_chirho())
                    })?;
            let receipt_chirho = decode_and_verify_erasure_receipt_chirho(&answer_chirho)
                .map_err(|_| ErasureDeliveryErrorChirho::ReceiptRejectedChirho)?;
            verify_erasure_receipt_answers_frame_chirho(frame_chirho, &receipt_chirho)
                .map_err(|_| ErasureDeliveryErrorChirho::ReceiptRejectedChirho)?;
            return Ok(receipt_chirho);
        }
        let client_chirho = self
            .peers_chirho
            .get(holder_chirho)
            .ok_or(ErasureDeliveryErrorChirho::NoRouteChirho)?;
        client_chirho
            .send_erasure_chirho(frame_chirho, timeout_chirho)
            .map_err(|error_chirho| match error_chirho {
                KeyCustodyClientErrorChirho::TransportChirho => {
                    ErasureDeliveryErrorChirho::TransportChirho
                }
                KeyCustodyClientErrorChirho::RefusedChirho {
                    identity_chirho, ..
                } => classify_refusal_chirho(&identity_chirho),
                KeyCustodyClientErrorChirho::ReceiptRejectedChirho => {
                    ErasureDeliveryErrorChirho::ReceiptRejectedChirho
                }
                KeyCustodyClientErrorChirho::FrameNotEncodableChirho => {
                    ErasureDeliveryErrorChirho::RefusedChirho
                }
            })
    }
}

/// A holder's refusal, by the one fixed wire name both roads carry. Not-the-leader, a stale term or an expired
/// lease stops the whole call; an interrupted admission is retried; anything else leaves that holder pending.
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/key-custody-chirho/erasure-propagation-workflow-chirho.md`.
pub(crate) fn classify_refusal_chirho(identity_chirho: &str) -> ErasureDeliveryErrorChirho {
    let authority_chirho = |reason_chirho: MirrorRefusalIdentityChirho| {
        format!(
            "{:?}:{}",
            KeyCustodyRefusalIdentityChirho::CustodyAuthorityRefusedChirho,
            reason_chirho.as_str_chirho()
        )
    };
    let deposed_chirho = identity_chirho
        == HolderRefusalIdentityChirho::HolderStaleTermChirho.as_str_chirho()
        || [
            MirrorRefusalIdentityChirho::MirrorSenderNotLeaderChirho,
            MirrorRefusalIdentityChirho::MirrorTermInvalidChirho,
            MirrorRefusalIdentityChirho::MirrorLeaseExpiredChirho,
        ]
        .into_iter()
        .any(|reason_chirho| identity_chirho == authority_chirho(reason_chirho));
    if deposed_chirho {
        ErasureDeliveryErrorChirho::AuthorityRefusedChirho
    } else if identity_chirho
        == HolderRefusalIdentityChirho::HolderAdmissionInterruptedChirho.as_str_chirho()
    {
        ErasureDeliveryErrorChirho::TransportChirho
    } else {
        ErasureDeliveryErrorChirho::RefusedChirho
    }
}

/// Where this node's authority to send comes from: the verified placement and the one election adapter the
/// composition holds. The engine joins them itself, through the mirror's one join, and never implements an
/// election view of its own.
pub struct ErasureLeaderAuthorityChirho<'authority_chirho> {
    pub placement_chirho: &'authority_chirho VerifiedTenantPlacementChirho,
    pub election_view_chirho: &'authority_chirho dyn MirrorLeadershipViewChirho,
}

/// Why a call stopped before reaching every pending holder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErasurePropagationStopChirho {
    /// This node's own read of authority no longer showed it the elected leader with a live lease.
    NotLeaderChirho,
    /// A holder refused this node as its leader, or its term or lease.
    DeposedChirho,
    /// The call budget was spent.
    BudgetSpentChirho,
    /// Signing a frame took longer than the reserve taken off its lease, so it was not sent.
    SigningOverranChirho,
}

/// What became of one holder in one call. These stay internal; R3 gets the attempt (a4-i).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErasureHolderOutcomeChirho {
    /// Its stored receipts already closed its share, so it got no frame.
    AlreadyClosedChirho,
    /// A receipt was delivered, passed the answer check and is stored.
    ClosedChirho,
    /// A receipt was delivered but the store refused it, so it does not count.
    StoreRefusedChirho,
    /// No answer arrived in this many attempts.
    UnansweredChirho { attempts_chirho: u32 },
    /// The holder refused the frame, or answered with something that is not its receipt.
    RefusedChirho(ErasureDeliveryErrorChirho),
    /// The call stopped before this holder was tried.
    NotReachedChirho,
}

/// One call's result: the attempt the store holds afterwards, why the call stopped early if it did, and what
/// became of each holder that was pending when it began.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasurePropagationReportChirho {
    /// Read back from the store after the sends, by the requirement's identity.
    pub attempt_chirho: ErasureAttemptChirho,
    pub stopped_chirho: Option<ErasurePropagationStopChirho>,
    pub holders_chirho: BTreeMap<String, ErasureHolderOutcomeChirho>,
}

/// Which requirement one call carries: the bound one at a seq, or the one an attempt's identity names.
#[derive(Clone, Copy)]
enum RequirementSelectorChirho<'select_chirho> {
    SeqChirho {
        subject_digest_chirho: &'select_chirho str,
        erasure_seq_chirho: u64,
    },
    IdentityChirho(&'select_chirho ErasureAttemptIdentityChirho),
}

/// Propagate the BOUND requirement at (subject, seq) once. It refuses before sending anything when the
/// requirement is not bound, when this node is not the elected leader with a live lease, or when the current view
/// is another group. Otherwise each holder whose stored receipts do not yet close its share gets up to the
/// policy's attempts, each a fresh frame under a fresh authority read. Call it after every root lock is released.
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/key-custody-chirho/erasure-propagation-workflow-chirho.md`.
pub fn propagate_erasure_requirement_chirho(
    store_chirho: &ErasurePropagationStoreChirho,
    subject_digest_chirho: &str,
    erasure_seq_chirho: u64,
    authority_chirho: &ErasureLeaderAuthorityChirho<'_>,
    seam_chirho: &dyn ErasureHolderSeamChirho,
    pacing_chirho: &ErasurePropagationPacingChirho<'_>,
) -> Result<ErasurePropagationReportChirho, LeaderRefusalChirho> {
    propagate_selected_chirho(
        store_chirho,
        RequirementSelectorChirho::SeqChirho {
            subject_digest_chirho,
            erasure_seq_chirho,
        },
        authority_chirho,
        seam_chirho,
        pacing_chirho,
    )
}

/// Propagate again the requirement an attempt's identity names, and return that attempt read afresh (C5 B3-a4-i,
/// design item 17). It takes the identity, never a status, and trusts none of it. Before anything is read it
/// refuses an identity for another group, tenant or genesis instance; then it finds the requirement by its digest
/// in the subject's verified view, never by a seq, and refuses one that is unknown, carried by a successor,
/// unbound, or bound to another erasure record. Those refusals of the identity itself come before any
/// authority read, frame or write, so they change nothing. It then runs the same engine as the first call, with
/// the same policy limits, authority reads and budget, on the STORED holders. It never calls the root's erasure,
/// appends no erasure record, and never widens the cut: the key ids come only from the stored requirement.
/// An error after that, such as the final read finding the requirement replaced, can follow sent frames and
/// stored receipts (gpt #30365). It means the attempt is unresolved and its holders pending, never that the
/// root's erasure may be repeated.
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/key-custody-chirho/erasure-propagation-workflow-chirho.md`.
pub fn retry_erasure_propagation_chirho(
    store_chirho: &ErasurePropagationStoreChirho,
    identity_chirho: &ErasureAttemptIdentityChirho,
    authority_chirho: &ErasureLeaderAuthorityChirho<'_>,
    seam_chirho: &dyn ErasureHolderSeamChirho,
    pacing_chirho: &ErasurePropagationPacingChirho<'_>,
) -> Result<ErasureAttemptChirho, LeaderRefusalChirho> {
    store_chirho.check_attempt_context_chirho(identity_chirho)?;
    Ok(propagate_selected_chirho(
        store_chirho,
        RequirementSelectorChirho::IdentityChirho(identity_chirho),
        authority_chirho,
        seam_chirho,
        pacing_chirho,
    )?
    .attempt_chirho)
}

/// The one engine behind both entries: select the requirement, then carry it to every open holder.
fn propagate_selected_chirho(
    store_chirho: &ErasurePropagationStoreChirho,
    selector_chirho: RequirementSelectorChirho<'_>,
    authority_chirho: &ErasureLeaderAuthorityChirho<'_>,
    seam_chirho: &dyn ErasureHolderSeamChirho,
    pacing_chirho: &ErasurePropagationPacingChirho<'_>,
) -> Result<ErasurePropagationReportChirho, LeaderRefusalChirho> {
    let policy_chirho = &pacing_chirho.policy_chirho;
    if !policy_chirho.within_limits_chirho() {
        return Err(LeaderRefusalIdentityChirho::ErasurePropagationPolicyOutOfLimitsChirho.into());
    }
    let clock_chirho = pacing_chirho.clock_chirho;
    let started_millis_chirho = clock_chirho.now_millis_chirho();
    let subject_digest_chirho = match selector_chirho {
        RequirementSelectorChirho::SeqChirho {
            subject_digest_chirho,
            ..
        } => subject_digest_chirho,
        RequirementSelectorChirho::IdentityChirho(identity_chirho) => {
            identity_chirho.subject_digest_chirho.as_str()
        }
    };
    let view_chirho = store_chirho.subject_view_chirho(subject_digest_chirho)?;
    let (requirement_chirho, identity_chirho) = match selector_chirho {
        RequirementSelectorChirho::SeqChirho {
            erasure_seq_chirho, ..
        } => {
            let (requirement_chirho, standing_chirho) = view_chirho
                .entries_chirho()
                .iter()
                .find(|(requirement_chirho, _)| {
                    requirement_chirho.erasure_seq_chirho() == erasure_seq_chirho
                })
                .ok_or(LeaderRefusalIdentityChirho::ErasureRequirementMissingChirho)?;
            let RequirementStandingChirho::BoundChirho(binding_chirho) = standing_chirho else {
                return Err(
                    LeaderRefusalIdentityChirho::ErasurePropagationRequirementUnboundChirho.into(),
                );
            };
            (
                requirement_chirho,
                store_chirho.attempt_identity_chirho(requirement_chirho, binding_chirho),
            )
        }
        RequirementSelectorChirho::IdentityChirho(identity_chirho) => (
            requirement_for_identity_chirho(&view_chirho, identity_chirho)?.0,
            identity_chirho.clone(),
        ),
    };
    let erasure_seq_chirho = requirement_chirho.erasure_seq_chirho();
    let joined_chirho = read_authority_chirho(store_chirho, authority_chirho)
        .ok_or(LeaderRefusalIdentityChirho::ErasurePropagationNotLeaderChirho)?;
    if joined_chirho
        .view_chirho()
        .consistency_group_digest_chirho()
        != store_chirho.group_digest_chirho()
    {
        return Err(LeaderRefusalIdentityChirho::ErasurePropagationViewGroupMismatchChirho.into());
    }
    let pending_chirho = match store_chirho.requirement_erasure_status_chirho(
        subject_digest_chirho,
        erasure_seq_chirho,
        joined_chirho.view_chirho(),
    )? {
        ErasureStatusChirho::ErasurePropagationPendingChirho {
            pending_holders_chirho,
        } => pending_holders_chirho,
        _ => Default::default(),
    };
    let mut holders_chirho = requirement_chirho
        .holders_chirho()
        .iter()
        .filter(|holder_chirho| !pending_chirho.contains(*holder_chirho))
        .map(|holder_chirho| {
            (
                holder_chirho.clone(),
                ErasureHolderOutcomeChirho::AlreadyClosedChirho,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut stopped_chirho = None;
    'holders_chirho: for holder_chirho in &pending_chirho {
        if stopped_chirho.is_some() {
            holders_chirho.insert(
                holder_chirho.clone(),
                ErasureHolderOutcomeChirho::NotReachedChirho,
            );
            continue;
        }
        let mut outcome_chirho = ErasureHolderOutcomeChirho::NotReachedChirho;
        for attempt_chirho in 0..policy_chirho.attempts_per_holder_chirho {
            let (frame_chirho, timeout_chirho) = match prepare_attempt_chirho(
                store_chirho,
                authority_chirho,
                pacing_chirho,
                started_millis_chirho,
                subject_digest_chirho,
                requirement_chirho,
                holder_chirho,
            )? {
                PreparedAttemptChirho::SendChirho(frame_chirho, timeout_chirho) => {
                    (frame_chirho, timeout_chirho)
                }
                PreparedAttemptChirho::StopChirho(stop_chirho) => {
                    stopped_chirho = Some(stop_chirho);
                    holders_chirho.insert(holder_chirho.clone(), outcome_chirho);
                    continue 'holders_chirho;
                }
            };
            match seam_chirho.deliver_erasure_chirho(holder_chirho, &frame_chirho, timeout_chirho) {
                Ok(receipt_chirho) => {
                    outcome_chirho = match store_chirho.record_erasure_receipt_chirho(
                        subject_digest_chirho,
                        erasure_seq_chirho,
                        &receipt_chirho,
                    ) {
                        Ok(_) => ErasureHolderOutcomeChirho::ClosedChirho,
                        Err(_) => ErasureHolderOutcomeChirho::StoreRefusedChirho,
                    };
                    break;
                }
                Err(ErasureDeliveryErrorChirho::TransportChirho) => {
                    outcome_chirho = ErasureHolderOutcomeChirho::UnansweredChirho {
                        attempts_chirho: attempt_chirho + 1,
                    };
                    if attempt_chirho + 1 < policy_chirho.attempts_per_holder_chirho {
                        let backoff_chirho = policy_chirho
                            .first_backoff_chirho
                            .saturating_mul(1_u32 << attempt_chirho.min(16))
                            .min(remaining_budget_chirho(
                                pacing_chirho,
                                started_millis_chirho,
                            ));
                        (pacing_chirho.sleep_chirho)(backoff_chirho);
                    }
                }
                Err(ErasureDeliveryErrorChirho::AuthorityRefusedChirho) => {
                    stopped_chirho = Some(ErasurePropagationStopChirho::DeposedChirho);
                    outcome_chirho = ErasureHolderOutcomeChirho::RefusedChirho(
                        ErasureDeliveryErrorChirho::AuthorityRefusedChirho,
                    );
                    break;
                }
                Err(other_chirho) => {
                    outcome_chirho = ErasureHolderOutcomeChirho::RefusedChirho(other_chirho);
                    break;
                }
            }
        }
        holders_chirho.insert(holder_chirho.clone(), outcome_chirho);
    }
    let attempt_chirho =
        store_chirho.attempt_for_identity_chirho(&identity_chirho, joined_chirho.view_chirho())?;
    Ok(ErasurePropagationReportChirho {
        attempt_chirho,
        stopped_chirho,
        holders_chirho,
    })
}

/// What preparing one attempt yields: a signed frame and how long its delivery may wait, or why the call stops.
enum PreparedAttemptChirho {
    SendChirho(Box<ErasureFrameV1Chirho>, Duration),
    StopChirho(ErasurePropagationStopChirho),
}

/// The call budget left now: the policy's budget less the time since the call began, never below zero.
fn remaining_budget_chirho(
    pacing_chirho: &ErasurePropagationPacingChirho<'_>,
    started_millis_chirho: u64,
) -> Duration {
    remaining_budget_at_chirho(
        pacing_chirho,
        started_millis_chirho,
        pacing_chirho.clock_chirho.now_millis_chirho(),
    )
}

/// The call budget left at the clock reading `now_millis_chirho`, never below zero.
fn remaining_budget_at_chirho(
    pacing_chirho: &ErasurePropagationPacingChirho<'_>,
    started_millis_chirho: u64,
    now_millis_chirho: u64,
) -> Duration {
    let elapsed_chirho =
        Duration::from_millis(now_millis_chirho.saturating_sub(started_millis_chirho));
    pacing_chirho
        .policy_chirho
        .call_budget_chirho
        .saturating_sub(elapsed_chirho)
}

/// Prepare one attempt, or say why the call stops instead (gpt #30241, #30243, #30253 and #30255).
/// - Each boundary takes ONE clock reading, and every decision at that boundary uses it, so no authority read,
///   signature or delivery starts once its own reading finds the budget spent:
///   - before the authority read, `read_at` decides the budget and starts the lease's deadline;
///   - before signing, `built_at` decides the budget and the lease the frame carries;
///   - before delivery, `sent_at` decides the signing reserve, the delivery budget and the timeout.
/// - The view reports the lease as a duration at the read. Its deadline is `read_at` plus that duration, which errs
///   early, since the observation comes after `read_at`. The frame carries what remains at `built_at`, less the
///   signing reserve. A lease that leaves nothing stops the call as lost leadership.
/// - Signing loads the existing key from disk, so it is timed. A frame is sent only if `sent_at` is within the
///   reserve of `built_at`, so the lease it carries is never more than remains at `sent_at`. Otherwise the call
///   stops by name. Nothing after `sent_at` is guarded against preemption: that interval is transit.
fn prepare_attempt_chirho(
    store_chirho: &ErasurePropagationStoreChirho,
    authority_chirho: &ErasureLeaderAuthorityChirho<'_>,
    pacing_chirho: &ErasurePropagationPacingChirho<'_>,
    started_millis_chirho: u64,
    subject_digest_chirho: &str,
    requirement_chirho: &VerifiedErasurePropagationRequirementChirho,
    holder_chirho: &str,
) -> Result<PreparedAttemptChirho, LeaderRefusalChirho> {
    let clock_chirho = pacing_chirho.clock_chirho;
    let reserve_millis_chirho = u64::try_from(
        pacing_chirho
            .policy_chirho
            .signing_reserve_chirho
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    let budget_spent_at_chirho = |now_millis_chirho: u64| {
        remaining_budget_at_chirho(pacing_chirho, started_millis_chirho, now_millis_chirho)
            .is_zero()
    };
    // Before the authority read. Authority is read afresh before every attempt; re-signing never refreshes it.
    let read_at_chirho = clock_chirho.now_millis_chirho();
    if budget_spent_at_chirho(read_at_chirho) {
        return Ok(PreparedAttemptChirho::StopChirho(
            ErasurePropagationStopChirho::BudgetSpentChirho,
        ));
    }
    let Some(attempt_view_chirho) = read_authority_chirho(store_chirho, authority_chirho) else {
        return Ok(PreparedAttemptChirho::StopChirho(
            ErasurePropagationStopChirho::NotLeaderChirho,
        ));
    };
    // Before signing.
    let built_at_chirho = clock_chirho.now_millis_chirho();
    if budget_spent_at_chirho(built_at_chirho) {
        return Ok(PreparedAttemptChirho::StopChirho(
            ErasurePropagationStopChirho::BudgetSpentChirho,
        ));
    }
    let lease_left_chirho = attempt_view_chirho
        .leader_lease_remaining_millis_chirho()
        .map(|lease_chirho| {
            read_at_chirho
                .saturating_add(lease_chirho)
                .saturating_sub(built_at_chirho)
                .saturating_sub(reserve_millis_chirho)
        })
        .filter(|left_chirho| *left_chirho > 0);
    let Some(lease_left_chirho) = lease_left_chirho else {
        return Ok(PreparedAttemptChirho::StopChirho(
            ErasurePropagationStopChirho::NotLeaderChirho,
        ));
    };
    let frame_chirho = store_chirho.sign_erasure_frame_chirho(
        PreparedErasureFrameChirho::new_chirho(ErasureFrameInputChirho {
            consistency_group_digest_chirho: attempt_view_chirho
                .view_chirho()
                .consistency_group_digest_chirho()
                .to_string(),
            membership_view_digest_chirho: attempt_view_chirho.view_chirho().view_digest_chirho(),
            elected_term_chirho: attempt_view_chirho.term_chirho(),
            origin_node_id_chirho: store_chirho.issuer_node_id_chirho().to_string(),
            holder_node_id_chirho: holder_chirho.to_string(),
            leader_lease_remaining_millis_chirho: Some(lease_left_chirho),
            subject_digest_chirho: subject_digest_chirho.to_string(),
            erased_below_blob_seq_chirho: requirement_chirho.erased_below_blob_seq_chirho(),
            key_ids_chirho: requirement_chirho
                .key_ids_chirho()
                .iter()
                .cloned()
                .collect(),
        })?,
    )?;
    // Before delivery.
    let sent_at_chirho = clock_chirho.now_millis_chirho();
    if sent_at_chirho.saturating_sub(built_at_chirho) > reserve_millis_chirho {
        return Ok(PreparedAttemptChirho::StopChirho(
            ErasurePropagationStopChirho::SigningOverranChirho,
        ));
    }
    let remaining_at_send_chirho =
        remaining_budget_at_chirho(pacing_chirho, started_millis_chirho, sent_at_chirho);
    if remaining_at_send_chirho.is_zero() {
        return Ok(PreparedAttemptChirho::StopChirho(
            ErasurePropagationStopChirho::BudgetSpentChirho,
        ));
    }
    Ok(PreparedAttemptChirho::SendChirho(
        Box::new(frame_chirho),
        pacing_chirho
            .policy_chirho
            .request_timeout_chirho
            .min(remaining_at_send_chirho),
    ))
}

/// This node's joined view, only when it may send as that view's elected leader: the issuer of the store is the
/// elected leader with a live lease (the shared sender predicate, D3). Anything else, including a failed join,
/// is no authority.
fn read_authority_chirho(
    store_chirho: &ErasurePropagationStoreChirho,
    authority_chirho: &ErasureLeaderAuthorityChirho<'_>,
) -> Option<JoinedMirrorViewChirho> {
    let joined_chirho = join_mirror_view_chirho(
        authority_chirho.placement_chirho,
        authority_chirho.election_view_chirho,
    )
    .ok()?;
    joined_chirho
        .local_sender_is_elected_leader_chirho(store_chirho.issuer_node_id_chirho())
        .then_some(joined_chirho)
}
