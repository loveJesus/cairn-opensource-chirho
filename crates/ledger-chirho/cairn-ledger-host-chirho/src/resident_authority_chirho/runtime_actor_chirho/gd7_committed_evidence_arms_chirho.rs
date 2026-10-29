// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Item 6.2 cut 4, NARROWED — the committed coordinate, the optimistic planner, and the actor's
//! retained refusal. **This arm is NOT the full composition proof; see the scope limit below.**
//!
//! # THE PROPERTY CUT 4 SERVES
//!
//! `complete_gd7_compensation_command_chirho` composes two independent things
//! (`command_dispatch_chirho.rs:486-516`):
//!
//! 1. an OPTIMISTIC planner — at `ProviderObservedChirho` it plans `AppendThenFinishChirho`, and it
//!    is pure, so it has no idea whether a previous attempt's append already committed; and
//! 2. a journal port that, once the record IS committed but the authority evidence is not, refuses
//!    with `CommittedEvidencePendingChirho` carrying the committed receipt, which the actor RETAINS
//!    so its own retry reports that coordinate instead of appending again.
//!
//! Neither is safe alone. The planner on its own would re-append; the refusal on its own would be a
//! bare error. Safety is the pair.
//!
//! # SCOPE LIMIT — WHICH HALF RUNS THROUGH PRODUCTION, AND WHICH DOES NOT
//!
//! Stated because the first version of this arm claimed more than it drove (money-class review,
//! 2026-08-08). Two of the three assertions run through real machinery; ONE does not.
//!
//! - REAL: the committed coordinate. A genuine `LedgerJournalChirho` append over `SimStorageChirho`
//!   produces it, and the arm reads it back from RESTORED durable bytes rather than trusting the
//!   value the append returned.
//! - REAL: the planner. `plan_gd7_compensation_completion_chirho` is the production function.
//! - **HELPER-SCOPED, NOT THE COMPOSITION: the refusal.** This arm calls
//!   `sticky_committed_refusal_chirho` DIRECTLY. That helper both writes `sticky_refusal_chirho` and
//!   returns `CommittedEvidencePendingChirho`, so what is pinned is the helper's MAPPING and
//!   RETENTION — that a committed coordinate handed in survives into both the refusal and the
//!   retained state. It is NOT proof that the real append -> canary-failure -> dispatch path REACHES
//!   that helper after a committed append. A test can assemble the right-looking pieces while
//!   bypassing the production function under review; this arm does exactly that on this one half,
//!   and says so rather than letting the shape imply otherwise.
//!
//! # WHY THE FULL COMPOSITION IS OWED TO 6.4 RATHER THAN BUILT HERE
//!
//! Measured, not assumed. The fault cannot be injected on the real path at 6.2's scale:
//! `ResidentLedgerLocalPortsChirho.storage_chirho` is `&FsLedgerStorageChirho` — CONCRETE by design
//! (`resident_authority_chirho.rs:214`, GAP 3's primary guarantee, which must NOT be widened to
//! `&dyn` to make a test easier) — so SimStorage reaches a standalone journal but never the resident
//! authority that dispatch drives. `ShadowCanaryEvidenceStoreChirho` is likewise not port-injected;
//! it writes through a `PathBuf`. Driving the real refusal therefore needs the whole resident-actor
//! world plus a filesystem-level canary fault — a fuller harness than this arm, which is 6.4's item.
//!
//! `harness1_compensated_terminal_arms_chirho` (regenesis crate) ALREADY drives that real path to
//! `CommittedEvidencePendingChirho` after a real committed append, and already pins the money
//! property this cut exists for: the retry refuses WITHOUT writing a second record. What it does not
//! yet assert is the carried coordinate's VALUE — and note that at
//! `command_dispatch_chirho.rs:509` the error is stringified (`format!("{error_chirho:?}")`), so on
//! the real path that coordinate is observable only as Debug TEXT, never as a value. 6.4 inherits
//! that assertion in its achievable form, not the structural one.
//!
//! # MIGRATION PATH
//!
//! If the refusal assertion here ever fails, it means the helper's mapping or retention changed —
//! retarget at whatever now carries the coordinate into the retry, and re-check
//! `ensure_canary_ready_chirho:1454-1459`, which is that field's consumer. If 6.4 lands the real
//! path, this arm's refusal third becomes redundant and should be DELETED rather than kept as a
//! weaker twin; the coordinate and planner assertions stay.
//!
//! The pending/sticky state is IN-MEMORY, so nothing here claims it survives a process crash.

use super::*;
use crate::reconciliation_chirho::{
    create_or_load_gd7_obligation_processing_state_chirho, record_gd7_provider_intent_chirho,
    record_gd7_provider_observation_chirho,
};
use crate::tests_chirho::reconciliation_witness_tests_chirho::{
    digest_chirho, FakeWinnerLedgerSignerChirho, ObservedTailAuthorityChirho,
    ObservedTailKindRegistryChirho, ObservedTailMembershipChirho,
};
use crate::tests_chirho::with_bound_resident_fixture_chirho;
use crate::SystemLedgerClockChirho;
use cairn_ledger_log_chirho::journal_chirho::{
    AppendLegRequestChirho, AppendRequestChirho, JournalPortsChirho, LedgerJournalChirho,
};
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::{AssetKindRefChirho, ClusterIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::{
    AttributionChirho, HlcChirho, LedgerOpChirho, LegDeltaChirho,
};
use cairn_ledger_model_chirho::LogIdChirho;
use cairn_ledger_sim_chirho::fault_chirho::FaultPlanChirho;
use cairn_ledger_sim_chirho::storage_chirho::SimStorageChirho;
use cairn_writer_elector_chirho::shadow_canary_chirho::{
    ShadowCanaryAppendCutChirho, ShadowCanaryEvidenceStoreChirho, SHADOW_CANARY_SCHEMA_CHIRHO,
};
use cairn_writer_head_chirho::writer_head_chirho::WriterFenceTokenChirho;

use super::gd7_completed_leg_chirho::{
    plan_gd7_compensation_completion_chirho, Gd7CompensationCompletionPlanChirho,
};

const MINT_DIGEST_CHIRHO: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OBLIGATION_DIGEST_CHIRHO: &str =
    "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";

/// CUT 4, NARROWED — a real committed coordinate, an optimistic planner, and the actor's RETAINED
/// refusal carrying that coordinate.
///
/// The name says "retained refusal" rather than "a committed append refuses" because the refusal
/// third is driven by calling the helper directly, not by the production append/canary path. A name
/// asserting the production path would hand every later reader a guarantee this arm does not hold.
#[test]
fn the_retained_refusal_carries_the_committed_coordinate_while_the_planner_stays_optimistic_chirho()
{
    // ---- 1. A REAL committed append, over a real journal ----
    let journal_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let ledger_signer_chirho = FakeWinnerLedgerSignerChirho::new_chirho(0x61);
    let clock_chirho = SystemLedgerClockChirho;
    let membership_chirho = ObservedTailMembershipChirho;
    let kind_registry_chirho = ObservedTailKindRegistryChirho;
    let authority_chirho = ObservedTailAuthorityChirho;
    let journal_ports_chirho = || JournalPortsChirho {
        storage_chirho: &journal_storage_chirho,
        signer_chirho: &ledger_signer_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &kind_registry_chirho,
        authority_chirho: &authority_chirho,
    };
    let journal_path_chirho =
        StoragePathChirho::new_chirho("journals-chirho/gd7-cut4-chirho.jsonl");
    let cluster_chirho = ClusterIdChirho("gd7-cut4-cluster-chirho".to_owned());
    let mut journal_chirho = LedgerJournalChirho::create_chirho(
        journal_ports_chirho(),
        journal_path_chirho.clone(),
        cluster_chirho.clone(),
        0,
    )
    .expect("create the compensation journal");
    let tail_before_chirho = journal_chirho.tail_seq_chirho();

    let append_receipt_chirho = journal_chirho
        .append_chirho(AppendRequestChirho {
            op_chirho: LedgerOpChirho::MintChirho {
                authority_evidence_chirho: DigestChirho(digest_chirho('7')),
            },
            legs_chirho: vec![AppendLegRequestChirho {
                account_chirho: LogIdChirho::new_chirho(
                    "gd7-cut4-owner-chirho",
                    "gd7-observed-kind-chirho",
                ),
                kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(digest_chirho('8'))),
                delta_chirho: LegDeltaChirho::CreditChirho,
                amount_chirho: 10,
                counterpart_chirho: None,
            }],
            idempotency_key_chirho: "gd7-cut4-compensation-chirho".to_owned(),
            provenance_chirho: None,
            attribution_chirho: AttributionChirho::PlatformChirho,
        })
        .expect("the compensation append must COMMIT — this cut is the post-commit window");
    assert_eq!(
        journal_chirho.tail_seq_chirho(),
        tail_before_chirho + 1,
        "exactly one record committed; a tail that did not move means there is no committed \
         coordinate for the refusal to carry and this arm is measuring nothing"
    );

    // The coordinate is DURABLE, not merely returned: reopen over the surviving bytes and confirm
    // the journal agrees with the receipt the append handed out.
    let durable_chirho = SimStorageChirho::restore_chirho(
        journal_storage_chirho.snapshot_chirho(),
        FaultPlanChirho::none_chirho(),
    );
    let reopened_ports_chirho = JournalPortsChirho {
        storage_chirho: &durable_chirho,
        signer_chirho: &ledger_signer_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &kind_registry_chirho,
        authority_chirho: &authority_chirho,
    };
    let reopened_chirho = LedgerJournalChirho::open_chirho(
        reopened_ports_chirho,
        journal_path_chirho,
        &cluster_chirho,
    )
    .expect("the committed record survives and the journal reopens over it");
    assert_eq!(
        reopened_chirho.tail_seq_chirho(),
        append_receipt_chirho.seq_chirho,
        "the DURABLE tail must be the appended seq — the coordinate this arm calls committed is a \
         fact about persisted bytes, not about the value the append returned"
    );

    // ---- 2. (c) THE PLANNER IS STILL OPTIMISTIC ----
    // The obligation is at ProviderObserved and knows nothing about the append that committed, so
    // a replay WOULD try to append again. That is precisely why the refusal below must carry the
    // committed coordinate rather than merely saying no.
    let obligation_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let state_chirho = create_or_load_gd7_obligation_processing_state_chirho(
        &obligation_storage_chirho,
        MINT_DIGEST_CHIRHO,
        "receipt-cut4-chirho",
        OBLIGATION_DIGEST_CHIRHO,
        "inverse-cut4-chirho",
        "action-cut4-chirho",
    )
    .expect("create the obligation processing state");
    let intent_chirho = record_gd7_provider_intent_chirho(
        &obligation_storage_chirho,
        &state_chirho,
        "provider-key-cut4-chirho",
        OBLIGATION_DIGEST_CHIRHO,
    )
    .expect("persist the provider intent");
    let observed_chirho = record_gd7_provider_observation_chirho(
        &obligation_storage_chirho,
        &intent_chirho,
        "observation-cut4-chirho",
        "provider-effect-cut4-chirho",
    )
    .expect("record the observed provider outcome");
    assert_eq!(
        plan_gd7_compensation_completion_chirho(&observed_chirho),
        Ok(Gd7CompensationCompletionPlanChirho::AppendThenFinishChirho),
        "the planner must STILL plan an append at ProviderObserved. If this ever returns \
         FinishWithoutAppend, the composition changed shape: the safety of this window depends on \
         an optimistic planner paired with a refusal that carries the committed coordinate, and a \
         conservative planner would need a different proof, not this one"
    );

    // ---- 3. (a)+(b) THE RETAINED REFUSAL CARRIES THE COMMITTED COORDINATE ----
    //
    // HELPER-SCOPED, AND THE LIMIT BELONGS AT THIS LINE, not only in the module header: the call
    // below invokes `sticky_committed_refusal_chirho` DIRECTLY. `effect_receipt_chirho` and that
    // helper are both production functions, and the coordinate fed to them is a real committed one —
    // so what follows genuinely pins the MAPPING and the RETENTION. It does NOT pin that the
    // production append/canary/dispatch path reaches this helper after a committed append. That
    // composition is harness1's on the real path today, and 6.4's to assert by value.
    let resident_receipt_chirho = ResidentLedgerAppendReceiptChirho {
        append_chirho: append_receipt_chirho.clone(),
        fence_chirho: WriterFenceTokenChirho {
            group_chirho: ConsistencyGroupIdChirho::TenantChirho {
                tenant_id_chirho: "gd7-cut4-tenant-chirho".to_owned(),
            },
            epoch_chirho: 1,
            issued_at_ms_chirho: 1,
        },
        process_generation_chirho: 1,
        published_raft_term_chirho: 1,
    };
    let carried_receipt_chirho = effect_receipt_chirho(&resident_receipt_chirho);

    let mut canary_state_chirho = ResidentCanaryStateChirho {
        latest_ledger_cut_chirho: ShadowCanaryLedgerCutChirho::new_chirho(
            1,
            digest_chirho('0'),
            1,
            0,
            1,
            &resident_receipt_chirho.fence_chirho.group_chirho,
        )
        .expect("construct valid committed-refusal fixture cut"),
        pending_chirho: None,
        sticky_refusal_chirho: None,
    };
    let refusal_chirho: ResidentEffectJournalResultChirho<()> = sticky_committed_refusal_chirho(
        &mut canary_state_chirho,
        carried_receipt_chirho,
        EffectCommitJournalCommittedEvidenceIdentityChirho::CanaryLeaseAuthorityEvidencePendingChirho,
        "canary recorded that the committed append lacked elected lease authority",
    );

    // (a) THE BRANCH, by name.
    let Err(EffectCommitJournalPortErrorChirho::CommittedEvidencePendingChirho {
        receipt_chirho,
        identity_chirho,
        ..
    }) = refusal_chirho
    else {
        panic!(
            "the retention helper must return CommittedEvidencePending — any other refusal loses \
             the fact that a durable record already exists, and the actor's own retry would append \
             a second compensation record. (Scope: this is the HELPER's return, not the production \
             append/canary path reaching it — see the module header.)"
        );
    };
    assert_eq!(
        identity_chirho,
        EffectCommitJournalCommittedEvidenceIdentityChirho::CanaryLeaseAuthorityEvidencePendingChirho,
        "the retained refusal must carry the fixed origin identity, not derive a new identity from private detail"
    );

    // (b) THE PAYLOAD: every coordinate field is the COMMITTED record's, not a synthesized label.
    assert_eq!(
        receipt_chirho.seq_chirho, append_receipt_chirho.seq_chirho,
        "the carried seq must be the committed record's"
    );
    assert_eq!(
        receipt_chirho.record_digest_chirho, append_receipt_chirho.record_digest_chirho,
        "the carried record digest must be the committed record's. NOTE the two paths are \
         different and must not be conflated: on SUCCESS, dispatch binds the obligation's receipt \
         ref from the append receipt (`command_dispatch_chirho.rs:513`); on THIS refusal path the \
         coordinate is retained inside the actor for its own retry and is stringified at the \
         dispatch boundary (`:509`), so no caller receives it as a value. A wrong digest here would \
         make the actor's retry report a record that is not the compensation that happened"
    );
    assert_eq!(
        receipt_chirho.hlc_chirho, append_receipt_chirho.hlc_chirho,
        "and the carried HLC must be the committed record's"
    );
    assert_eq!(
        receipt_chirho.seq_chirho,
        reopened_chirho.tail_seq_chirho(),
        "closing the loop against DURABLE bytes: the coordinate the refusal carries is the one the \
         reopened journal reports as its tail"
    );

    // The sticky field now holds that same coordinate — the mechanism that makes a retry report
    // the committed record instead of appending another (`ensure_canary_ready_chirho:1454-1459`).
    let sticky_chirho = canary_state_chirho
        .sticky_refusal_chirho
        .as_ref()
        .expect("the committed-but-pending refusal must be STICKY, or a retry would re-append");
    assert_eq!(
        sticky_chirho.receipt_chirho.record_digest_chirho,
        append_receipt_chirho.record_digest_chirho,
        "the retained receipt must be the committed coordinate; a retry that read a different one \
         would hand the obligation a second compensation identity"
    );
    assert_eq!(
        sticky_chirho.origin_identity_chirho,
        EffectCommitJournalCommittedEvidenceIdentityChirho::CanaryLeaseAuthorityEvidencePendingChirho,
        "the sticky retry state must retain the first post-append origin identity"
    );
}

#[test]
fn pending_canary_retry_retains_the_first_committed_evidence_origin_chirho() {
    with_bound_resident_fixture_chirho(
        "committed-evidence-origin-retry",
        |root_chirho,
         group_chirho,
         node_chirho,
         _ports_chirho,
         _journal_path_chirho,
         _cluster_id_chirho| {
            let canary_root_chirho = root_chirho.join("committed-evidence-origin-canary-chirho");
            let _generation_zero_chirho = ShadowCanaryEvidenceStoreChirho::open_chirho(
                &canary_root_chirho,
                root_chirho,
                group_chirho.clone(),
                node_chirho.clone(),
            )
            .expect("create the retry canary evidence store");
            let canary_store_chirho = ShadowCanaryGenerationStoreChirho::open_existing_chirho(
                &canary_root_chirho,
                root_chirho,
                group_chirho.clone(),
                node_chirho.clone(),
            )
            .expect("open the retry canary generation store");
            let receipt_chirho = EffectCommitJournalReceiptChirho {
                seq_chirho: 1,
                record_digest_chirho: DigestChirho(digest_chirho('9')),
                hlc_chirho: HlcChirho {
                    physical_ms_chirho: 17,
                    logical_chirho: 0,
                },
            };
            let observation_chirho = ShadowCanaryChirho {
                schema_chirho: SHADOW_CANARY_SCHEMA_CHIRHO.to_owned(),
                group_chirho: group_chirho.clone(),
                minter_node_id_chirho: node_chirho.clone(),
                append_cut_chirho: ShadowCanaryAppendCutChirho {
                    append_seq_chirho: receipt_chirho.seq_chirho,
                    append_record_digest_chirho: receipt_chirho.record_digest_chirho.0.clone(),
                    append_hlc_physical_ms_chirho: receipt_chirho.hlc_chirho.physical_ms_chirho,
                    append_hlc_logical_chirho: receipt_chirho.hlc_chirho.logical_chirho,
                    process_generation_chirho: 1,
                    durable_term_chirho: 1,
                    fence_epoch_chirho: 1,
                    fence_group_digest_chirho: consistency_group_digest_chirho(group_chirho)
                        .expect("digest the retry canary group"),
                },
                raft_leader_id_chirho: Some(node_chirho.clone()),
                raft_term_chirho: 1,
                raft_lease_valid_chirho: false,
                cutover_would_permit_chirho: false,
                at_ms_chirho: 17,
            };
            let origin_identity_chirho =
                EffectCommitJournalCommittedEvidenceIdentityChirho::CanaryPersistenceEvidencePendingChirho;
            let mut canary_state_chirho = ResidentCanaryStateChirho {
                latest_ledger_cut_chirho: ShadowCanaryLedgerCutChirho::new_chirho(
                    1,
                    digest_chirho('0'),
                    1,
                    0,
                    1,
                    group_chirho,
                )
                .expect("construct the pre-retry canary cut"),
                pending_chirho: Some(PendingCanaryObservationChirho {
                    receipt_chirho: receipt_chirho.clone(),
                    origin_identity_chirho,
                    observation_chirho,
                }),
                sticky_refusal_chirho: None,
            };

            let refusal_chirho = ensure_canary_ready_chirho(
                &canary_store_chirho,
                &mut canary_state_chirho,
                group_chirho,
            );
            let Err(EffectCommitJournalPortErrorChirho::CommittedEvidencePendingChirho {
                receipt_chirho: retried_receipt_chirho,
                identity_chirho: retried_identity_chirho,
                ..
            }) = refusal_chirho
            else {
                panic!("the pending canary retry must remain a committed-evidence refusal");
            };
            assert_eq!(retried_receipt_chirho, receipt_chirho);
            assert_eq!(
                retried_identity_chirho, origin_identity_chirho,
                "a later lease refusal must not overwrite the first canary-persistence origin"
            );
            assert_ne!(
                retried_identity_chirho,
                EffectCommitJournalCommittedEvidenceIdentityChirho::CanaryLeaseAuthorityEvidencePendingChirho,
                "the retry reached the lease neighbour only after the original persistence failure"
            );
            assert_eq!(
                canary_state_chirho
                    .sticky_refusal_chirho
                    .as_ref()
                    .expect("the retry refusal becomes sticky")
                    .origin_identity_chirho,
                origin_identity_chirho,
            );
        },
    );
}

/// Census the diagnostic identity assigned beside every existing post-append branch marker.
///
/// This is deliberately a source census, not proof that every branch is behaviorally reachable in
/// this fixture. Production construction would be stronger, but changing production structure only
/// to arm a diagnostic is outside this test-only successor. A coordinated edit that moves an
/// identity together with its marker can pass this census; the accepted protection is against the
/// likelier plain misassignment that would make a hosted refusal name the wrong branch.
#[test]
fn every_committed_evidence_origin_stays_paired_with_its_branch_marker_chirho() {
    const COMMAND_DISPATCH_SOURCE_CHIRHO: &str = include_str!("command_dispatch_chirho.rs");
    const JOURNAL_REFUSAL_SOURCE_CHIRHO: &str = include_str!("journal_port_refusal_chirho.rs");
    const MUTATION_ENVELOPE_SOURCE_CHIRHO: &str =
        include_str!("../resident_mutation_chirho/envelope_chirho.rs");

    let pairings_chirho = [
        (
            EffectCommitJournalCommittedEvidenceIdentityChirho::MirrorAppendEvidencePendingChirho,
            JOURNAL_REFUSAL_SOURCE_CHIRHO,
            "ResidentLedgerAuthorityRefusalChirho::MirrorCommittedEvidencePendingChirho",
            false,
            512,
        ),
        (
            EffectCommitJournalCommittedEvidenceIdentityChirho::WinnerTermIndexEvidencePendingChirho,
            MUTATION_ENVELOPE_SOURCE_CHIRHO,
            "GD7 winner term-first index is pending after commit",
            true,
            384,
        ),
        (
            EffectCommitJournalCommittedEvidenceIdentityChirho::JournalPostAppendReprobeEvidencePendingChirho,
            MUTATION_ENVELOPE_SOURCE_CHIRHO,
            "resident journal reprobe failed after commit",
            true,
            384,
        ),
        (
            EffectCommitJournalCommittedEvidenceIdentityChirho::JournalPostAppendAuthorityChangedEvidencePendingChirho,
            MUTATION_ENVELOPE_SOURCE_CHIRHO,
            "resident post-append authority changed before durable reprobe",
            true,
            384,
        ),
        (
            EffectCommitJournalCommittedEvidenceIdentityChirho::JournalReplayBeyondTailEvidencePendingChirho,
            MUTATION_ENVELOPE_SOURCE_CHIRHO,
            "journal replay returned a receipt beyond an unchanged tail",
            true,
            384,
        ),
        (
            EffectCommitJournalCommittedEvidenceIdentityChirho::JournalSequenceExhaustedEvidencePendingChirho,
            MUTATION_ENVELOPE_SOURCE_CHIRHO,
            "resident journal sequence exhausted after a committed tail transition",
            true,
            384,
        ),
        (
            EffectCommitJournalCommittedEvidenceIdentityChirho::JournalDenseTailTransitionEvidencePendingChirho,
            MUTATION_ENVELOPE_SOURCE_CHIRHO,
            "resident append did not produce one exact dense tail transition",
            true,
            384,
        ),
        (
            EffectCommitJournalCommittedEvidenceIdentityChirho::CanaryCutConstructionEvidencePendingChirho,
            MUTATION_ENVELOPE_SOURCE_CHIRHO,
            "receipt-bound canary cut construction failed",
            true,
            384,
        ),
        (
            EffectCommitJournalCommittedEvidenceIdentityChirho::CanaryCutDomainEvidencePendingChirho,
            MUTATION_ENVELOPE_SOURCE_CHIRHO,
            "committed canary cut domain refused",
            true,
            384,
        ),
        (
            EffectCommitJournalCommittedEvidenceIdentityChirho::CanaryLeaseAuthorityEvidencePendingChirho,
            MUTATION_ENVELOPE_SOURCE_CHIRHO,
            "canary recorded that the committed append lacked elected lease authority",
            true,
            384,
        ),
        (
            EffectCommitJournalCommittedEvidenceIdentityChirho::CanaryPersistenceEvidencePendingChirho,
            MUTATION_ENVELOPE_SOURCE_CHIRHO,
            "receipt-bound canary append failed",
            true,
            2_048,
        ),
        (
            EffectCommitJournalCommittedEvidenceIdentityChirho::TestkindDeposedSinkAdmissionEvidencePendingChirho,
            COMMAND_DISPATCH_SOURCE_CHIRHO,
            "deposed test-kind resident reached a committed final-sink outcome",
            true,
            384,
        ),
    ];

    for identity_chirho in EffectCommitJournalCommittedEvidenceIdentityChirho::ALL_CHIRHO {
        assert_eq!(
            pairings_chirho
                .iter()
                .filter(|(paired_identity_chirho, ..)| paired_identity_chirho == identity_chirho)
                .count(),
            1,
            "committed-evidence source pairing is missing or duplicated for {}",
            identity_chirho.as_str_chirho(),
        );
    }
    for (
        identity_chirho,
        source_chirho,
        branch_marker_chirho,
        marker_follows_identity_chirho,
        maximum_distance_chirho,
    ) in pairings_chirho
    {
        assert!(
            EffectCommitJournalCommittedEvidenceIdentityChirho::ALL_CHIRHO
                .contains(&identity_chirho),
            "source pairing names an identity absent from the macro population: {}",
            identity_chirho.as_str_chirho(),
        );
        let identity_anchor_chirho = format!(
            "EffectCommitJournalCommittedEvidenceIdentityChirho::{}",
            identity_chirho.as_str_chirho()
        );
        assert_eq!(
            source_chirho.matches(&identity_anchor_chirho).count(),
            1,
            "expected one production assignment for {}",
            identity_chirho.as_str_chirho(),
        );
        let identity_offset_chirho = source_chirho
            .find(&identity_anchor_chirho)
            .expect("the counted identity assignment exists");
        let distance_chirho = if marker_follows_identity_chirho {
            source_chirho[identity_offset_chirho + identity_anchor_chirho.len()..]
                .find(branch_marker_chirho)
                .unwrap_or_else(|| {
                    panic!(
                        "branch marker is no longer after {}: {branch_marker_chirho}",
                        identity_chirho.as_str_chirho()
                    )
                })
        } else {
            let marker_offset_chirho = source_chirho[..identity_offset_chirho]
                .rfind(branch_marker_chirho)
                .unwrap_or_else(|| {
                    panic!(
                        "branch marker is no longer before {}: {branch_marker_chirho}",
                        identity_chirho.as_str_chirho()
                    )
                });
            identity_offset_chirho - marker_offset_chirho - branch_marker_chirho.len()
        };
        assert!(
            distance_chirho <= maximum_distance_chirho,
            "branch marker moved away from {}: expected at most {maximum_distance_chirho} bytes, got {distance_chirho}",
            identity_chirho.as_str_chirho(),
        );
    }
}
