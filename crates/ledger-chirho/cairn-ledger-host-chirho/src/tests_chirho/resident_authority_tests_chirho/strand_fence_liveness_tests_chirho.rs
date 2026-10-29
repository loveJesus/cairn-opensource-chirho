// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Executable pin for RULING 5: a compensation append must never advance the fence it is checked
//! against.
//!
//! The sink cell is written at resident birth and advanced only from the birth-recovery path, so a
//! term bump during a live resident's life leaves the cell behind. When a resident has no configured
//! ordinary-term acceptance inputs, the unchanged lower sink fence still returns
//! `UnseenWinnerTermChirho`, but the resident relabels that fact as inputs unavailable; the pure
//! sink-fence suite separately pins the underlying identity. Before this module the no-self-advance
//! prohibition lived only in prose, so a future brick "fixing" the strand by advancing the cell from
//! inside the append would have made the suite greener rather than redder.
//!
//! MIGRATION PATH, stated here because whoever meets this red will not have this context:
//! - If `mid_life_term_bump_refuses_compensation_by_name_without_moving_the_cell_chirho` starts
//!   COMPLETING instead of refusing, either source absence stopped failing closed or some path now
//!   advances the cell mid-life. If that path is the append itself, RULING 5 is violated and the
//!   append is self-authorizing — that is the defect this arm exists to catch.
//! - If it fails on the CELL-MOVED assertion, read that as the stronger signal: something wrote the
//!   cell during a refused append, which is the self-authorizing shape even if the refusal held.
//!
//! # THE FULL-CHAIN ARM RUNS BELOW THE MAILBOX
//!
//! `the_full_chain_unstrands_a_bumped_compensation_through_advance_and_release_chirho` drives the
//! RESIDENT directly — `accept_new_winner_term_chirho`, `release_converged_gd7_hold_chirho`, and
//! `record_effect_compensation_hold_chirho` — not the actor mailbox. So it proves the barriers, the
//! advance, the release, and the unstranded append at the resident tier, and it proves NOTHING about
//! the mailbox hop, command dispatch, or actor startup. That gap is HARNESS-1's, and its wire tier
//! now exists (2026-08-05): the capstone arms in `cairn-ledger-regenesis-chirho`
//! (`harness1_compensated_terminal_arms_chirho`) drive advance, release, and the fenced append
//! through the REAL mailbox on a real fork world — where the append COMMITS and the post-commit
//! winner-first-record evidence refuses, because the post-adoption resume step is unbuilt. So a
//! "live completed compensation path" claim now needs THAT design decision, not this arm and not
//! merely more harness.

use super::super::provision_signers_chirho;
use super::{
    warm_single_node_elector_chirho, with_bound_resident_fixture_chirho,
    with_unbound_resident_fixture_chirho,
};
use crate::reconciliation_chirho::sink_term_fence_chirho::{
    advance_accepted_winner_term_chirho, read_sink_term_fence_chirho, SinkTermFenceRefusalChirho,
    SinkTermFenceStateChirho,
};
use crate::HostLedgerSignersChirho;
use crate::ResidentLedgerBirthPermitChirho;
use crate::{ResidentLedgerAuthorityChirho, ResidentLedgerAuthorityRefusalChirho};
use cairn_effect_commit_chirho::compensation_chirho::{
    authorize_effect_compensation_chirho, CompensationAuthorizationFactsChirho,
    CompensationAuthorizationViewChirho, CompensationAuthorizationViewErrorChirho,
    CompensationBreakerVerdictChirho, EffectCompensationAuthorizationOutcomeChirho,
    VerifiedEffectCompensationChirho,
};
use cairn_effect_commit_chirho::intent_chirho::{
    canonical_effect_intent_line_chirho, sign_effect_intent_chirho, EffectIntentChirho,
    EffectIntentSignerPortChirho, VerifiedEffectIntentChirho, EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::AttributionChirho;
use cairn_seqlog_chirho::seqlog_chirho::named_lock_storage_key_chirho;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, ConsistencyGroupIdChirho, WRITER_FENCE_LOCK_CHIRHO,
};

/// Must parse as a real effect-intent coordinate; a free-form string is refused upstream of the
/// fence, which would make this fixture prove nothing about the fence.
const ORIGINAL_EFFECT_KEY_CHIRHO: &str = concat!(
    "cf3-intent-v1-chirho:",
    "7f",
    "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"
);

/// Permits every candidate, so the ONLY thing that can refuse the append under test is the sink
/// fence. A fixture that could be refused by two mechanisms proves neither.
struct PermittingCompensationViewChirho;

impl CompensationAuthorizationViewChirho for PermittingCompensationViewChirho {
    fn derive_chirho(
        &self,
        _candidate_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<CompensationAuthorizationFactsChirho, CompensationAuthorizationViewErrorChirho>
    {
        Ok(CompensationAuthorizationFactsChirho::new_chirho(
            ORIGINAL_EFFECT_KEY_CHIRHO.to_owned(),
            ORIGINAL_EFFECT_KEY_CHIRHO.to_owned(),
            1,
            4,
            CompensationBreakerVerdictChirho::PermittedChirho,
        ))
    }
}

fn digest_chirho(seed_chirho: &str) -> DigestChirho {
    DigestChirho(seed_chirho.repeat(32))
}

fn signed_compensation_intent_line_chirho(
    journal_chirho: &LedgerJournalChirho<'_>,
    signer_chirho: &dyn EffectIntentSignerPortChirho,
) -> String {
    let intent_chirho = EffectIntentChirho {
        schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
        journal_cut_chirho: journal_chirho.effect_intent_cut_chirho(),
        contract_set_digest_chirho: digest_chirho("a1"),
        door_chirho: serde_json::from_value(serde_json::json!({
            "effect_node_chirho": "b2".repeat(32),
            "capability_fingerprint_chirho": "c3".repeat(32),
        }))
        .unwrap(),
        reversion_contract_digest_chirho: digest_chirho("d4"),
        request_ref_chirho: digest_chirho("e5"),
        request_context_ref_chirho: digest_chirho("f6"),
        evidence_refs_chirho: vec![digest_chirho("a1")],
        resolved_price_chirho: AssetOpChirho {
            amount_chirho: 10,
            kind_id_chirho: AssetKindIdChirho("credits-chirho".to_owned()),
            kind_policy_ref_chirho: AssetKindRefChirho(digest_chirho("11")),
            rounding_chirho: RoundingChirho::ExactChirho,
        },
        payer_account_chirho: AccountIdChirho {
            owner_chirho: "resident-authority-user-chirho".to_owned(),
            kind_id_chirho: AssetKindIdChirho("credits-chirho".to_owned()),
        },
        effect_step_chirho: 7,
        attribution_chirho: AttributionChirho::CauserChirho {
            principal_chirho: "resident-authority-user-chirho".to_owned(),
        },
        original_effect_key_chirho: Some(ORIGINAL_EFFECT_KEY_CHIRHO.to_owned()),
        sig_chirho: String::new(),
        key_id_chirho: String::new(),
    };
    let signed_chirho = sign_effect_intent_chirho(intent_chirho, signer_chirho).unwrap();
    canonical_effect_intent_line_chirho(&signed_chirho).unwrap()
}

fn authorized_compensation_chirho(
    line_chirho: &str,
    signer_chirho: &dyn EffectIntentSignerPortChirho,
) -> VerifiedEffectCompensationChirho {
    match authorize_effect_compensation_chirho(
        line_chirho,
        signer_chirho,
        &PermittingCompensationViewChirho,
    )
    .unwrap()
    {
        EffectCompensationAuthorizationOutcomeChirho::AuthorizedChirho(token_chirho) => {
            token_chirho
        }
        EffectCompensationAuthorizationOutcomeChirho::PendingManualChirho(pending_chirho) => {
            panic!("permitting view returned pending/manual: {pending_chirho:?}")
        }
    }
}

/// Reads the durable cell through the same production reader the append uses. Local copy of the
/// lifecycle suite's lock helper rather than widening that module's visibility for a test.
fn read_cell_chirho(
    root_chirho: &std::path::Path,
    group_chirho: &ConsistencyGroupIdChirho,
) -> Option<SinkTermFenceStateChirho> {
    let storage_chirho = crate::FsLedgerStorageChirho::open_existing_chirho(root_chirho).unwrap();
    let path_chirho =
        StoragePathChirho::new_chirho(named_lock_storage_key_chirho(WRITER_FENCE_LOCK_CHIRHO));
    let mut handle_chirho = storage_chirho
        .provision_exclusive_lock_handle_chirho(&path_chirho)
        .unwrap();
    let guard_chirho = handle_chirho.try_acquire_chirho().unwrap();
    read_sink_term_fence_chirho(
        &guard_chirho,
        &consistency_group_digest_chirho(group_chirho).unwrap(),
    )
    .unwrap()
}

fn advance_cell_for_classification_arm_chirho(
    root_chirho: &std::path::Path,
    group_chirho: &ConsistencyGroupIdChirho,
    accepted_term_chirho: u64,
) -> SinkTermFenceStateChirho {
    let storage_chirho = crate::FsLedgerStorageChirho::open_existing_chirho(root_chirho).unwrap();
    let path_chirho =
        StoragePathChirho::new_chirho(named_lock_storage_key_chirho(WRITER_FENCE_LOCK_CHIRHO));
    let mut handle_chirho = storage_chirho
        .provision_exclusive_lock_handle_chirho(&path_chirho)
        .unwrap();
    let guard_chirho = handle_chirho.try_acquire_chirho().unwrap();
    advance_accepted_winner_term_chirho(
        &guard_chirho,
        &consistency_group_digest_chirho(group_chirho).unwrap(),
        accepted_term_chirho,
    )
    .unwrap()
}

/// A three-voter in-process elector mesh. ROUTE (b), ruled after MEASURE-1 disproved route (a):
/// `local_append_authority_handle_chirho` is deliberately invalidated (`ElectorDroppedChirho`) when
/// its elector instance drops, so a handle can never silently outlive its elector into a new term —
/// the design already fails closed at exactly the seam this arm worried about. The bump must
/// therefore arrive IN PLACE, through real raft traffic, on the instance the resident still holds.
pub(crate) struct ElectorMeshChirho {
    nodes_chirho: Vec<RaftWriterElectorChirho>,
}

impl ElectorMeshChirho {
    pub(crate) fn new_chirho(
        group_chirho: &ConsistencyGroupIdChirho,
        local_node_chirho: &NodeIdChirho,
    ) -> Self {
        let voters_chirho = vec![
            (1u64, local_node_chirho.clone()),
            (2u64, NodeIdChirho(format!("{}-peer2", local_node_chirho.0))),
            (3u64, NodeIdChirho(format!("{}-peer3", local_node_chirho.0))),
        ];
        let nodes_chirho = (1u64..=3)
            .map(|raft_id_chirho| {
                RaftWriterElectorChirho::new_cluster_node_chirho(
                    group_chirho.clone(),
                    raft_id_chirho,
                    voters_chirho.clone(),
                )
                .unwrap()
                .with_leadership_warmup_lease_chirho()
            })
            .collect();
        Self { nodes_chirho }
    }

    pub(crate) fn node_chirho(&self, raft_id_chirho: u64) -> &RaftWriterElectorChirho {
        self.nodes_chirho
            .iter()
            .find(|node_chirho| node_chirho.local_raft_id_chirho() == raft_id_chirho)
            .expect("mesh node")
    }

    /// Drives `raft_id_chirho` to leadership and returns the term it won, asserting by VALUE.
    /// The message pump is a closure so the raft message type stays INFERRED — `raft` is a
    /// dependency of the elector crate, not of this one, and the A6 pump this mirrors never names
    /// it either.
    /// Reconnects every node to the current leader so a previously-fenced node LEARNS the new term
    /// and steps down. Without this the old leader still believes it leads at the old term and its
    /// next campaign is rejected as stale — correct raft, wrong fixture.
    fn rejoin_chirho(&self, leader_raft_id_chirho: u64) {
        let leader_chirho = self.node_chirho(leader_raft_id_chirho);
        for _round_chirho in 0..40 {
            let mut messages_chirho = leader_chirho.tick_chirho();
            for _drain_chirho in 0..100 {
                if messages_chirho.is_empty() {
                    break;
                }
                let mut next_chirho = Vec::new();
                for message_chirho in messages_chirho.drain(..) {
                    next_chirho.extend(
                        self.node_chirho(message_chirho.to)
                            .step_chirho(message_chirho)
                            .expect("step"),
                    );
                }
                messages_chirho = next_chirho;
            }
        }
    }

    /// `silent_raft_id_chirho` is the incumbent leader, left un-ticked so its followers' election
    /// timers actually expire. Without this the incumbent's heartbeats keep refreshing the quorum
    /// and no peer can ever win — the leader-lease behaviour working, not a fixture bug.
    fn elect_once_chirho(
        &self,
        raft_id_chirho: u64,
        silent_raft_id_chirho: Option<u64>,
    ) -> Option<u64> {
        if let Some(silent_chirho) = silent_raft_id_chirho {
            // Use the elector's existing real leadership-transfer primitive. It sends authenticated
            // raft traffic, advances the term, and lets the target become leader without forging a
            // term or adding a test-only timeout control. The bounded outer retry handles a transfer
            // that does not complete in one pump.
            let mut encoded_messages_chirho = self
                .node_chirho(silent_chirho)
                .transfer_leadership_to_chirho(raft_id_chirho)
                .ok()?;
            for _drain_round_chirho in 0..1000 {
                if encoded_messages_chirho.is_empty() {
                    break;
                }
                let mut next_encoded_messages_chirho = Vec::new();
                for (target_raft_id_chirho, message_bytes_chirho) in
                    encoded_messages_chirho.drain(..)
                {
                    next_encoded_messages_chirho.extend(
                        self.node_chirho(target_raft_id_chirho)
                            .step_encoded_chirho(&message_bytes_chirho)
                            .ok()?,
                    );
                }
                encoded_messages_chirho = next_encoded_messages_chirho;
            }
            self.rejoin_chirho(raft_id_chirho);
            let target_leadership_chirho =
                self.node_chirho(raft_id_chirho).current_leadership_chirho();
            return target_leadership_chirho
                .is_leader_chirho
                .then_some(target_leadership_chirho.term_chirho);
        }
        let node_chirho = self.node_chirho(raft_id_chirho);
        // One drain loop seeded from `campaign_chirho`, so the raft message type stays INFERRED:
        // `raft` is a dependency of the elector crate, not of this one, and the A6 pump this mirrors
        // never names it either. Ticks feed the same loop once the campaign traffic quiesces.
        let mut messages_chirho = match node_chirho.campaign_chirho() {
            Ok(messages_chirho) => messages_chirho,
            Err(campaign_refusal_chirho) => {
                println!(
                    "target election campaign refused: target=n{raft_id_chirho}, reason={campaign_refusal_chirho}"
                );
                return None;
            }
        };
        let mut warm_ticks_chirho = 0usize;
        for _round_chirho in 0..10_000 {
            if messages_chirho.is_empty() {
                if warm_ticks_chirho >= 10 {
                    break;
                }
                warm_ticks_chirho += 1;
                messages_chirho = node_chirho.tick_chirho();
                continue;
            }
            let mut next_chirho = Vec::new();
            for message_chirho in messages_chirho.drain(..) {
                next_chirho.extend(
                    self.node_chirho(message_chirho.to)
                        .step_chirho(message_chirho)
                        .expect("step"),
                );
            }
            messages_chirho = next_chirho;
        }
        let leadership_chirho = node_chirho.current_leadership_chirho();
        let states_chirho: Vec<String> = self
            .nodes_chirho
            .iter()
            .map(|node_chirho| {
                let view_chirho = node_chirho.current_leadership_chirho();
                format!(
                    "n{}(term={},leader={})",
                    node_chirho.local_raft_id_chirho(),
                    view_chirho.term_chirho,
                    view_chirho.is_leader_chirho
                )
            })
            .collect();
        if leadership_chirho.is_leader_chirho {
            Some(leadership_chirho.term_chirho)
        } else {
            println!(
                "target election attempt lost: target=n{raft_id_chirho}, mesh={}",
                states_chirho.join(" ")
            );
            None
        }
    }

    /// Retry a real target election after rejoining the observed leader. The bound makes a fixture
    /// failure finite while every term still comes from raft campaign traffic and is asserted by
    /// the target node's observed leadership value.
    pub(crate) fn elect_chirho(
        &self,
        raft_id_chirho: u64,
        silent_raft_id_chirho: Option<u64>,
    ) -> u64 {
        for attempt_chirho in 0..8 {
            if let Some(term_chirho) = self.elect_once_chirho(raft_id_chirho, silent_raft_id_chirho)
            {
                println!(
                    "target election won: target=n{raft_id_chirho}, attempt={attempt_chirho}, term={term_chirho}"
                );
                return term_chirho;
            }
            let observed_leader_chirho = self
                .nodes_chirho
                .iter()
                .map(|node_chirho| {
                    (
                        node_chirho.local_raft_id_chirho(),
                        node_chirho.current_leadership_chirho(),
                    )
                })
                .find(|(_raft_id_chirho, leadership_chirho)| leadership_chirho.is_leader_chirho)
                .map(|(raft_id_chirho, _leadership_chirho)| raft_id_chirho)
                .expect("a failed target election must leave an observed leader to rejoin");
            self.rejoin_chirho(observed_leader_chirho);
        }
        panic!("target n{raft_id_chirho} did not win within bounded real-election retries");
    }
}

#[test]
fn mid_life_term_bump_refuses_compensation_by_name_without_moving_the_cell_chirho() {
    with_unbound_resident_fixture_chirho(
        "strand-fence-liveness-bump",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            // Birth AND append both run on the same mesh instance, so the cell's birth term and the
            // append's published term share one authority — no cross-fixture term mismatch.
            let mesh_chirho = ElectorMeshChirho::new_chirho(group_chirho, local_node_chirho);
            let term_at_open_chirho = mesh_chirho.elect_chirho(1, None);

            let birth_permit_chirho = ResidentLedgerBirthPermitChirho::for_test_chirho(
                root_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
            );
            drop(
                ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                    birth_permit_chirho,
                    ports_chirho,
                    mesh_chirho
                        .node_chirho(1)
                        .local_append_authority_handle_chirho(),
                )
                .expect("bound resident is born on the mesh leader"),
            );

            let mut resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    mesh_chirho
                        .node_chirho(1)
                        .local_append_authority_handle_chirho(),
                )
                .expect("bound resident opens at its birth term");

            let cell_before_chirho =
                read_cell_chirho(root_chirho, group_chirho).expect("cell exists after birth");

            // THE BUMP, IN PLACE: a peer wins an election, then node 1 wins it back at a strictly
            // higher term — a real same-winner rollover over real raft messages. The resident keeps
            // the SAME handle throughout; nothing touches the cell.
            mesh_chirho.elect_chirho(2, Some(1));
            mesh_chirho.rejoin_chirho(2);
            let bumped_term_chirho = mesh_chirho.elect_chirho(1, Some(2));
            assert!(
                bumped_term_chirho > term_at_open_chirho,
                "the arm requires a REAL term bump: {term_at_open_chirho} -> {bumped_term_chirho}"
            );

            let refs_chirho = provision_signers_chirho(root_chirho);
            let signers_chirho =
                HostLedgerSignersChirho::load_existing_chirho(root_chirho, &refs_chirho).unwrap();
            let journal_chirho = LedgerJournalChirho::open_read_only_chirho(
                JournalPortsChirho {
                    storage_chirho: ports_chirho.storage_chirho,
                    signer_chirho: ports_chirho.signer_chirho,
                    clock_chirho: ports_chirho.clock_chirho,
                    membership_chirho: ports_chirho.membership_chirho,
                    kind_registry_chirho: ports_chirho.kind_registry_chirho,
                    authority_chirho: ports_chirho.authority_chirho,
                },
                journal_path_chirho.clone(),
                cluster_id_chirho,
            )
            .unwrap();
            let line_chirho = signed_compensation_intent_line_chirho(
                &journal_chirho,
                &signers_chirho.effect_intent_chirho,
            );
            let token_chirho =
                authorized_compensation_chirho(&line_chirho, &signers_chirho.effect_intent_chirho);

            let refusal_chirho = resident_chirho
                .record_effect_compensation_hold_chirho(
                    &line_chirho,
                    &signers_chirho.effect_intent_chirho,
                    &token_chirho,
                )
                .expect_err("a compensation at a term the sink has not accepted must refuse");

            // ASSERT THE REASON, and assert the negative: this fixture deliberately carries no
            // ordinary-term receipt source, so it must not masquerade as a lower sink-fence red.
            match &refusal_chirho {
                ResidentLedgerAuthorityRefusalChirho::OrdinaryElectionSinkTermAcceptanceInputsUnavailableChirho => {}
                other_chirho => panic!(
                    "expected the source-missing ordinary-term identity, got {other_chirho:?}; \
                     UnseenWinnerTerm would conceal that acceptance was never attempted"
                ),
            }

            // RULING 5: the append must not advance the fence it is checked against.
            let cell_after_chirho = read_cell_chirho(root_chirho, group_chirho)
                .expect("cell survives a refused append");
            assert_eq!(
                cell_after_chirho, cell_before_chirho,
                "the refused compensation append MOVED the sink cell — ruling 5 violated: an append \
                 that advances its own fence authorizes itself"
            );
            assert!(
                cell_after_chirho.highest_accepted_winner_term_chirho < bumped_term_chirho,
                "the cell must still trail the bumped term; if it caught up, something advanced it \
                 mid-life"
            );
        },
    );
}

#[test]
fn missing_acceptance_inputs_do_not_relabel_a_stale_sink_term_chirho() {
    with_bound_resident_fixture_chirho(
        "strand-fence-stale-neighbour",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(local_node_chirho, group_chirho);
            let mut resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    elector_chirho.local_append_authority_handle_chirho(),
                )
                .expect("bound resident opens at its birth term");
            let cell_at_open_chirho =
                read_cell_chirho(root_chirho, group_chirho).expect("cell exists after birth");
            let supplied_term_chirho = cell_at_open_chirho.highest_accepted_winner_term_chirho;
            let advanced_cell_chirho = advance_cell_for_classification_arm_chirho(
                root_chirho,
                group_chirho,
                supplied_term_chirho + 1,
            );
            assert_eq!(
                advanced_cell_chirho.highest_accepted_winner_term_chirho,
                supplied_term_chirho + 1,
                "the arm requires the durable cell strictly ahead of the actor's supplied term"
            );

            let refs_chirho = provision_signers_chirho(root_chirho);
            let signers_chirho =
                HostLedgerSignersChirho::load_existing_chirho(root_chirho, &refs_chirho).unwrap();
            let journal_chirho = LedgerJournalChirho::open_read_only_chirho(
                JournalPortsChirho {
                    storage_chirho: ports_chirho.storage_chirho,
                    signer_chirho: ports_chirho.signer_chirho,
                    clock_chirho: ports_chirho.clock_chirho,
                    membership_chirho: ports_chirho.membership_chirho,
                    kind_registry_chirho: ports_chirho.kind_registry_chirho,
                    authority_chirho: ports_chirho.authority_chirho,
                },
                journal_path_chirho.clone(),
                cluster_id_chirho,
            )
            .unwrap();
            let line_chirho = signed_compensation_intent_line_chirho(
                &journal_chirho,
                &signers_chirho.effect_intent_chirho,
            );
            let token_chirho =
                authorized_compensation_chirho(&line_chirho, &signers_chirho.effect_intent_chirho);

            let refusal_chirho = resident_chirho
                .record_effect_compensation_hold_chirho(
                    &line_chirho,
                    &signers_chirho.effect_intent_chirho,
                    &token_chirho,
                )
                .expect_err("a supplied term below the durable sink cell must refuse as stale");
            match refusal_chirho {
                ResidentLedgerAuthorityRefusalChirho::CompensationFenceRefusedChirho {
                    reason_chirho:
                        SinkTermFenceRefusalChirho::StaleWinnerTermChirho {
                            supplied_term_chirho: observed_supplied_term_chirho,
                            highest_accepted_term_chirho,
                        },
                } => {
                    assert_eq!(observed_supplied_term_chirho, supplied_term_chirho);
                    assert_eq!(
                        highest_accepted_term_chirho,
                        advanced_cell_chirho.highest_accepted_winner_term_chirho
                    );
                }
                ResidentLedgerAuthorityRefusalChirho::OrdinaryElectionSinkTermAcceptanceInputsUnavailableChirho => {
                    panic!(
                        "missing inputs must relabel only UnseenWinnerTerm, never a stale actor"
                    );
                }
                other_chirho => panic!(
                    "expected the exact stale sink-term refusal, got {other_chirho:?}"
                ),
            }
            assert_eq!(
                read_cell_chirho(root_chirho, group_chirho),
                Some(advanced_cell_chirho),
                "classification must not move the durable sink cell"
            );
        },
    );
}

#[test]
fn without_the_bump_the_same_setup_passes_the_fence_chirho() {
    // POSITIVE CONTROL. Identical to the arm minus the campaign, so a green arm cannot be explained
    // by the fixture simply being unable to reach the fence. This asserts the fence is PASSED, not
    // that the whole append completes: completion needs a journal-admissible compensation against a
    // real prior effect, which is more machinery than this arm should build. So the control asserts
    // the negative that matters — whatever happens, it is NOT the fence refusing.
    with_bound_resident_fixture_chirho(
        "strand-fence-liveness-control",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(local_node_chirho, group_chirho);
            let mut resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    elector_chirho.local_append_authority_handle_chirho(),
                )
                .expect("bound resident opens at its birth term");

            let cell_before_chirho =
                read_cell_chirho(root_chirho, group_chirho).expect("cell exists after birth");

            let refs_chirho = provision_signers_chirho(root_chirho);
            let signers_chirho =
                HostLedgerSignersChirho::load_existing_chirho(root_chirho, &refs_chirho).unwrap();
            let journal_chirho = LedgerJournalChirho::open_read_only_chirho(
                JournalPortsChirho {
                    storage_chirho: ports_chirho.storage_chirho,
                    signer_chirho: ports_chirho.signer_chirho,
                    clock_chirho: ports_chirho.clock_chirho,
                    membership_chirho: ports_chirho.membership_chirho,
                    kind_registry_chirho: ports_chirho.kind_registry_chirho,
                    authority_chirho: ports_chirho.authority_chirho,
                },
                journal_path_chirho.clone(),
                cluster_id_chirho,
            )
            .unwrap();
            let line_chirho = signed_compensation_intent_line_chirho(
                &journal_chirho,
                &signers_chirho.effect_intent_chirho,
            );
            let token_chirho =
                authorized_compensation_chirho(&line_chirho, &signers_chirho.effect_intent_chirho);

            let outcome_chirho = resident_chirho.record_effect_compensation_hold_chirho(
                &line_chirho,
                &signers_chirho.effect_intent_chirho,
                &token_chirho,
            );

            if let Err(ResidentLedgerAuthorityRefusalChirho::CompensationFenceRefusedChirho {
                reason_chirho,
            }) = &outcome_chirho
            {
                panic!(
                    "WITHOUT a term bump the fence must not refuse, but it returned \
                     {reason_chirho:?}; the arm above would then be green for the wrong reason"
                );
            }

            let cell_after_chirho =
                read_cell_chirho(root_chirho, group_chirho).expect("cell survives the control");
            assert_eq!(
                cell_after_chirho, cell_before_chirho,
                "no append may move the sink cell, refused or not"
            );
        },
    );
}

/// Install a genuine AdoptedHeld cut in the RESIDENT'S OWN ROOT, bound to `observation_chirho`.
///
/// Same shape as B3a's sink-revoke helper, but pointed at the live resident's storage and group so
/// the advance, the release, and the fenced append all read one namespace.
pub(super) fn install_adopted_cut_in_resident_root_chirho(
    storage_chirho: &crate::FsLedgerStorageChirho,
    signer_chirho: &super::super::reconciliation_witness_tests_chirho::FakeGd7ControlSignerChirho,
    observation_chirho: &crate::reconciliation_chirho::AuthenticatedGd7DeposedForkObservationChirho,
) -> String {
    use crate::reconciliation_chirho::{
        Gd7ReconciliationCheckpointStateChirho, Gd7ReconciliationPhaseChirho,
        Gd7ReconciliationStoreChirho,
    };
    let hex_chirho =
        |nibble_chirho: char| -> String { std::iter::repeat_n(nibble_chirho, 64).collect() };
    let store_chirho = Gd7ReconciliationStoreChirho::new_authenticated_chirho(
        storage_chirho,
        signer_chirho,
        observation_chirho.identity_chirho().clone(),
        observation_chirho
            .winner_fork_witness_chirho()
            .object_digest_chirho()
            .to_owned(),
    )
    .expect("signer key id equals the identity's held node");
    let state_chirho = |phase_chirho, seq_chirho, previous_chirho: Option<String>| {
        Gd7ReconciliationCheckpointStateChirho {
            phase_chirho,
            transition_seq_chirho: seq_chirho,
            previous_checkpoint_ref_chirho: previous_chirho,
            manifest_head_ref_chirho: (seq_chirho > 0).then(|| hex_chirho('7')),
            manifest_page_count_chirho: u64::from(seq_chirho > 0),
            manifest_record_count_chirho: if seq_chirho > 0 { 3 } else { 0 },
            plan_head_ref_chirho: (seq_chirho >= 2).then(|| hex_chirho('8')),
            plan_page_count_chirho: u64::from(seq_chirho >= 2),
            sealed_plan_ref_chirho: (seq_chirho >= 2).then(|| hex_chirho('8')),
            effect_obligation_count_chirho: if seq_chirho >= 2 { 2 } else { 0 },
            cursor_object_ref_chirho: None,
            adoption_binding_chirho: None,
        }
    };
    let observed_chirho = store_chirho
        .commit_checkpoint_chirho(
            None,
            state_chirho(Gd7ReconciliationPhaseChirho::ObservedHeldChirho, 0, None),
        )
        .expect("commit observed-held");
    let manifesting_chirho = store_chirho
        .commit_checkpoint_chirho(
            Some(&observed_chirho.checkpoint_ref_chirho),
            state_chirho(
                Gd7ReconciliationPhaseChirho::ManifestingChirho,
                1,
                Some(observed_chirho.checkpoint_ref_chirho.clone()),
            ),
        )
        .expect("commit manifesting");
    let sealed_chirho = store_chirho
        .commit_checkpoint_chirho(
            Some(&manifesting_chirho.checkpoint_ref_chirho),
            state_chirho(
                Gd7ReconciliationPhaseChirho::PlanSealedChirho,
                2,
                Some(manifesting_chirho.checkpoint_ref_chirho.clone()),
            ),
        )
        .expect("commit plan-sealed");
    store_chirho
        .commit_adopted_held_checkpoint_chirho(
            &sealed_chirho.checkpoint_ref_chirho,
            super::super::resident_adoption_tests_chirho::adoption_binding_chirho(
                &sealed_chirho.checkpoint_ref_chirho,
            ),
        )
        .expect("commit adopted-held")
        .checkpoint_ref_chirho
}

#[test]
fn the_full_chain_unstrands_a_bumped_compensation_through_advance_and_release_chirho() {
    // THE ARM THE WHOLE SEAM HAS POINTED AT SINCE FINDING 0.
    //
    // TWO BARRIERS STAND BETWEEN A BUMPED RESIDENT AND ITS COMPENSATION, and they are distinct
    // objects refused in a fixed order by `append_with_current_fence_chirho`: the GD7 hold
    // (checked first, at the group active-head) and the SINK-TERM FENCE (checked later, against
    // the cell). Each link below asserts BY VALUE, and the two refusals are asserted by their own
    // names, so a chain that merely ended green could not be mistaken for a chain that ran.
    use super::super::reconciliation_witness_tests_chirho::{
        empty_verified_losing_tail_chirho, held_winner_import_fixture_for_group_and_term_chirho,
        FakeGd7ControlSignerChirho, FakeWinnerLedgerSignerChirho,
    };
    use crate::reconciliation_chirho::{
        gd7_reconciliation_group_has_any_active_hold_chirho,
        signed_converged_read_replica_for_release_test_chirho, Gd7WinnerWitnessReaderChirho,
    };

    with_unbound_resident_fixture_chirho(
        "full-chain-unstrand",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            // A CF3-COMPLIANT REGISTRY, built locally rather than by editing the shared fixture.
            //
            // `policy_chirho()` in the shared test registry leaves `idempotency_window_chirho` at
            // `None`, which the journal reads as RetainIndefinitely and refuses for any CF3 effect
            // intent — so NO compensation append can complete anywhere in that fixture family, and
            // the existing fence control says exactly that. This is not "inventing a finite default
            // for an absent policy" (which the admission layer forbids a caller from doing at
            // resolution time); it is declaring a kind that HAS a bounded window, which is what a
            // real CF3 kind carries. The window only has to be wide enough that the intent minted
            // moments ago is not stale.
            let mut cf3_kinds_chirho = ports_chirho.kind_registry_chirho.kinds_chirho.clone();
            for projection_chirho in cf3_kinds_chirho.values_mut() {
                projection_chirho
                    .current_policy_chirho
                    .idempotency_window_chirho = Some(
                    cairn_kind_registry_chirho::record_chirho::IdempotencyWindowPolicyChirho {
                        idempotency_horizon_ms_chirho: 3_600_000,
                        retry_finality_horizon_ms_chirho: 7_200_000,
                    },
                );
            }
            let cf3_registry_chirho =
                cairn_kind_registry_chirho::chain_chirho::VerifiedRegistryChirho {
                    records_chirho: Vec::new(),
                    tail_digest_chirho: ports_chirho
                        .kind_registry_chirho
                        .tail_digest_chirho
                        .clone(),
                    kinds_chirho: cf3_kinds_chirho,
                };
            let ports_chirho = crate::ResidentLedgerLocalPortsChirho {
                kind_registry_chirho: &cf3_registry_chirho,
                ..ports_chirho
            };

            let mesh_chirho = ElectorMeshChirho::new_chirho(group_chirho, local_node_chirho);
            let term_at_open_chirho = mesh_chirho.elect_chirho(1, None);
            let birth_permit_chirho = ResidentLedgerBirthPermitChirho::for_test_chirho(
                root_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
            );
            drop(
                ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                    birth_permit_chirho,
                    ports_chirho,
                    mesh_chirho
                        .node_chirho(1)
                        .local_append_authority_handle_chirho(),
                )
                .expect("bound resident is born on the mesh leader"),
            );
            let mut resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    mesh_chirho
                        .node_chirho(1)
                        .local_append_authority_handle_chirho(),
                )
                .expect("bound resident opens at its birth term");

            // FUND THE PAYER, before the bump and before any hold, so the compensation's spendable
            // floor is satisfied by real minted balance rather than by weakening admission. Mints
            // are NOT sink-fenced (only EffectCompensationHoldChirho is), so this is admissible now
            // and would be refused later — which is itself the ordering the chain depends on.
            resident_chirho
                .append_preactivation_chirho(
                    &crate::ResidentLedgerAppendPermitChirho::for_test_chirho(),
                    super::resident_mint_request_chirho(1_000, "full-chain-funding-chirho"),
                )
                .expect("fund the compensation payer before the bump");

            // LINK 0 — the real term bump, in place, over real raft traffic.
            mesh_chirho.elect_chirho(2, Some(1));
            mesh_chirho.rejoin_chirho(2);
            let bumped_term_chirho = mesh_chirho.elect_chirho(1, Some(2));
            assert!(
                bumped_term_chirho > term_at_open_chirho,
                "the chain requires a REAL bump: {term_at_open_chirho} -> {bumped_term_chirho}"
            );
            assert_eq!(
                read_cell_chirho(root_chirho, group_chirho)
                    .expect("cell exists after birth")
                    .highest_accepted_winner_term_chirho,
                term_at_open_chirho,
                "the cell is still at its BIRTH term — this is the strand, by value"
            );

            let refs_chirho = provision_signers_chirho(root_chirho);
            let signers_chirho =
                HostLedgerSignersChirho::load_existing_chirho(root_chirho, &refs_chirho).unwrap();
            let journal_chirho = LedgerJournalChirho::open_read_only_chirho(
                JournalPortsChirho {
                    storage_chirho: ports_chirho.storage_chirho,
                    signer_chirho: ports_chirho.signer_chirho,
                    clock_chirho: ports_chirho.clock_chirho,
                    membership_chirho: ports_chirho.membership_chirho,
                    kind_registry_chirho: ports_chirho.kind_registry_chirho,
                    authority_chirho: ports_chirho.authority_chirho,
                },
                journal_path_chirho.clone(),
                cluster_id_chirho,
            )
            .unwrap();
            let line_chirho = signed_compensation_intent_line_chirho(
                &journal_chirho,
                &signers_chirho.effect_intent_chirho,
            );
            let token_chirho =
                authorized_compensation_chirho(&line_chirho, &signers_chirho.effect_intent_chirho);

            // LINK 1 — the source-less ordinary-election strand, proven BEFORE any hold exists.
            // The lower sink fence would also refuse, but reaching it here would conceal that the
            // required two-holder acceptance was never attempted.
            match resident_chirho
                .record_effect_compensation_hold_chirho(
                    &line_chirho,
                    &signers_chirho.effect_intent_chirho,
                    &token_chirho,
                )
                .expect_err("a bumped resident's compensation must refuse")
            {
                ResidentLedgerAuthorityRefusalChirho::OrdinaryElectionSinkTermAcceptanceInputsUnavailableChirho => {}
                other_chirho => {
                    panic!(
                        "expected the source-missing refusal with no hold installed, got \
                         {other_chirho:?}"
                    )
                }
            }

            // LINK 2 — a genuine witness AT THE BUMPED TERM, for THIS resident's group, imported
            // into THIS root. The fixture that made this possible is the whole reason the chain
            // was previously unreachable.
            let storage_chirho = crate::FsLedgerStorageChirho::open_existing_chirho(root_chirho)
                .expect("open the resident root");
            let control_signer_chirho =
                FakeGd7ControlSignerChirho::new_chirho("a".repeat(64), 0x31);
            let ledger_signer_chirho = FakeWinnerLedgerSignerChirho::new_chirho(0x32);
            let losing_tail_chirho = empty_verified_losing_tail_chirho(
                &storage_chirho,
                &ledger_signer_chirho,
                "full-chain-chirho",
            );
            let fixture_chirho = held_winner_import_fixture_for_group_and_term_chirho(
                &storage_chirho,
                &control_signer_chirho,
                &ledger_signer_chirho,
                &losing_tail_chirho,
                group_chirho,
                bumped_term_chirho,
            );
            assert_eq!(
                fixture_chirho.identity_chirho.winner_term_chirho, bumped_term_chirho,
                "the witness must name the BUMPED term by value, or the advance's freshness \
                 equality could never hold"
            );
            let observation_chirho = Gd7WinnerWitnessReaderChirho::new_chirho(
                &storage_chirho,
                &control_signer_chirho,
                &ledger_signer_chirho,
            )
            .import_authenticated_deposed_fork_observation_chirho(
                &fixture_chirho.identity_chirho,
                &fixture_chirho.index_bytes_chirho,
                &fixture_chirho.witness_bytes_chirho,
                &losing_tail_chirho,
            )
            .expect("import the genuine authenticated observation into the resident root");

            let held_signer_chirho = FakeGd7ControlSignerChirho::new_chirho(
                observation_chirho
                    .identity_chirho()
                    .held_node_chirho
                    .clone(),
                0x41,
            );
            let adopted_ref_chirho = install_adopted_cut_in_resident_root_chirho(
                &storage_chirho,
                &held_signer_chirho,
                &observation_chirho,
            );

            // LINK 3 — THE SECOND BARRIER APPEARS. The cut that authorizes the advance is itself
            // the hold, and it is checked BEFORE the fence, so the refusal name changes here.
            let group_digest_chirho = consistency_group_digest_chirho(group_chirho).unwrap();
            assert!(
                gd7_reconciliation_group_has_any_active_hold_chirho(
                    &storage_chirho,
                    &group_digest_chirho
                )
                .expect("probe the hold"),
                "adoption must raise the hold — finding 0"
            );
            assert!(
                matches!(
                    resident_chirho.record_effect_compensation_hold_chirho(
                        &line_chirho,
                        &signers_chirho.effect_intent_chirho,
                        &token_chirho,
                    ),
                    Err(ResidentLedgerAuthorityRefusalChirho::Gd7ReconciliationHoldActiveChirho)
                ),
                "with the cut installed the HOLD refuses first, ahead of the fence"
            );

            // LINK 4 — THE LAWFUL ADVANCE. The accepted term is the WITNESS's, by value.
            let accepted_term_chirho = resident_chirho
                .accept_new_winner_term_chirho(
                    &observation_chirho,
                    &adopted_ref_chirho,
                    &held_signer_chirho,
                )
                .expect("a real cut bound to a real bumped-term witness must advance the cell");
            assert_eq!(
                accepted_term_chirho, bumped_term_chirho,
                "the advance accepts the WITNESS's term by value"
            );
            assert_eq!(
                read_cell_chirho(root_chirho, group_chirho)
                    .expect("cell exists")
                    .highest_accepted_winner_term_chirho,
                bumped_term_chirho,
                "the DURABLE cell caught up to the bumped term"
            );

            // LINK 5 — THE RELEASE. The fence is satisfied now, but the hold still stands, so this
            // proves the release is genuinely load-bearing rather than incidental.
            assert!(
                matches!(
                    resident_chirho.record_effect_compensation_hold_chirho(
                        &line_chirho,
                        &signers_chirho.effect_intent_chirho,
                        &token_chirho,
                    ),
                    Err(ResidentLedgerAuthorityRefusalChirho::Gd7ReconciliationHoldActiveChirho)
                ),
                "advancing the cell alone must NOT unstrand: the hold is a separate barrier"
            );
            resident_chirho
                .release_converged_gd7_hold_chirho(
                    &adopted_ref_chirho,
                    &signed_converged_read_replica_for_release_test_chirho(
                        adopted_ref_chirho.clone(),
                        &held_signer_chirho,
                    ),
                    &held_signer_chirho,
                )
                .expect("release the converged hold");
            assert!(
                !gd7_reconciliation_group_has_any_active_hold_chirho(
                    &storage_chirho,
                    &group_digest_chirho
                )
                .expect("probe the hold after release"),
                "the release supersedes the head"
            );

            // LINK 6 — THE FENCED APPEND SUCCEEDS. First time in this repo's history that a
            // compensation append completes after a mid-life term bump.
            let receipt_chirho = resident_chirho
                .record_effect_compensation_hold_chirho(
                    &line_chirho,
                    &signers_chirho.effect_intent_chirho,
                    &token_chirho,
                )
                .expect("with the cell advanced AND the hold released, the append must succeed");
            assert_eq!(
                receipt_chirho.published_raft_term_chirho, bumped_term_chirho,
                "the append committed at the bumped term, by value"
            );
            assert!(
                !receipt_chirho
                    .append_chirho
                    .record_digest_chirho
                    .0
                    .is_empty(),
                "the receipt carries the content-addressed record digest the completed leg binds"
            );

            // LINK 7 — RECEIPT -> COMPLETED, driven by the REAL append's record digest through the
            // production state machine the B3a leg calls. Before this chain existed, nothing could
            // reach CompletedChirho in production: the append that yields the receipt was fenced.
            use crate::reconciliation_chirho::{
                create_or_load_gd7_obligation_processing_state_chirho,
                mark_gd7_obligation_completed_chirho, record_gd7_journal_receipt_chirho,
                record_gd7_provider_intent_chirho, record_gd7_provider_observation_chirho,
                Gd7ObligationTerminalProgressChirho,
            };
            let obligation_storage_chirho =
                resident_chirho.gd7_obligation_processing_storage_chirho();
            let obligation_chirho = create_or_load_gd7_obligation_processing_state_chirho(
                obligation_storage_chirho,
                &"0f".repeat(32),
                "full-chain-obligation-receipt-chirho",
                &"1e".repeat(32),
                "full-chain-inverse-chirho",
                "full-chain-action-chirho",
            )
            .expect("create the obligation processing state");
            let intent_state_chirho = record_gd7_provider_intent_chirho(
                obligation_storage_chirho,
                &obligation_chirho,
                "full-chain-provider-key-chirho",
                &"1e".repeat(32),
            )
            .expect("persist the provider intent");
            let observed_chirho = record_gd7_provider_observation_chirho(
                obligation_storage_chirho,
                &intent_state_chirho,
                "full-chain-observation-chirho",
                "full-chain-provider-effect-chirho",
            )
            .expect("record the observed provider outcome");

            let receipt_ref_chirho = receipt_chirho.append_chirho.record_digest_chirho.0.clone();
            let journalled_chirho = record_gd7_journal_receipt_chirho(
                obligation_storage_chirho,
                &observed_chirho,
                &receipt_ref_chirho,
            )
            .expect("bind the REAL append receipt");
            assert_eq!(
                journalled_chirho.journal_receipt_ref_chirho(),
                Some(receipt_ref_chirho.as_str()),
                "the bound receipt is the exact record digest the unstranded append returned, by value"
            );
            assert_eq!(
                mark_gd7_obligation_completed_chirho(obligation_storage_chirho, &journalled_chirho)
                    .expect("complete the obligation")
                    .terminal_progress_chirho(),
                Gd7ObligationTerminalProgressChirho::CompletedChirho,
                "CompletedChirho — the terminal state D1's classifier requires, reached here for the \
                 first time from a real fenced append that a mid-life term bump had stranded"
            );
        },
    );
}
