// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! ROUTE (a), measured to its true frontier: the capstone's NAMED wall is closed — a REAL minted
//! obligation reaches `ProviderObservedChirho` through the real mailbox via a completing provider —
//! and the ONE remaining gap past it is pinned by exact refusal, not papered over.
//!
//! # WHAT THE FIRST ARM PROVES
//!
//! The PRD's item-5 capstone named its wall precisely: *"the obligation can never reach
//! `ProviderObservedChirho` because cairn has no completing compensation provider anywhere in the
//! repository."* The first arm closes exactly that: a completing provider (test-scope, REPORTS
//! settlement, moves no money) supplied through the capstone's one door —
//! `open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho` — carries a REAL
//! minted obligation, on a really-adopted two-root world, through the real mailbox to
//! `ProviderObservedChirho`, with the provider executed exactly once against the persisted,
//! idempotency-keyed intent. Production's spawn default remains
//! `RefusingGd7CompensationProviderChirho` at every pre-existing opener; the route (b) tail pins
//! that posture and stays green beside this arm.
//!
//! SCOPE (item 6.5-a, 2026-08-09): the PRD wall's phrase "no completing compensation provider
//! anywhere in the repository" is now scoped to the PRODUCTION/shipping binaries. Two test-scope
//! reporting-only providers exist — this crate's `SettlementReportingProviderChirho` and
//! `cairn-ledger-geo-node-testkind-chirho`'s `TestkindSettlementReportingProviderChirho` — and NO
//! shipping binary can reach a compensation-provider door, proved by the source guard
//! `gd7_compensation_provider_door_has_no_shipping_binary_caller_chirho`.
//!
//! # WHAT THE SECOND ARM PROVES — the deposed side cannot lift the hold
//!
//! Past `ProviderObservedChirho`, the completion needs the FENCED APPEND. On the DEPOSED ROOT that
//! append never happens, and after ruled (a) never will: the compensation lands on the live
//! winner's journal, so the held root is deliberately given no way to carry it. The sink-term strand
//! IS lifted lawfully by the REAL witness observation through `advance_gd7_sink_term_chirho` (that
//! wire command's FIRST traversal) — but the reconciliation HOLD is a separate barrier the deposed
//! root cannot lift. Since the guarded-release brick the release door verifies the convergence
//! certificate's signature, and the deposed root cannot produce a real held-signed certificate (its
//! own converger refuses `UnconvergedObligationChirho` while the obligation is open). So a fabricated
//! certificate no longer releases the hold, and the completion refuses at the active-hold barrier
//! BEFORE any record is appended. (Before the guarded-release brick this arm lifted the hold with a
//! caller-built certificate and pinned the post-commit winner-first-record refusal; that depended on
//! the hole the brick closed, and the arm was retargeted per its own migration path. The forgery
//! property is now pinned by the host-tier arm
//! `a_fabricated_or_tampered_convergence_certificate_cannot_release_the_hold_chirho`.)
//!
//! The MEASURED conclusion, recorded so nobody re-derives it: after a real handoff + adoption,
//! neither root can lawfully carry the compensation append today —
//!
//! - the WINNER (the correct sink: its cell is current, a non-first append in its own term needs
//!   no first-record evidence) refuses at actor startup, frozen by its own ACCEPTED handoff — and
//!   an accepted handoff cannot be aborted into resumption BY CONSTRUCTION, twice over:
//!   `abort_chirho` (production, `winner_handoff_chirho.rs`) refuses `AcceptedChirho` with
//!   `InvalidTransitionChirho` before acquiring any authority, and the store's
//!   `commit_aborted_chirho` independently refuses any phase but `PreparingChirho`. (Corrected at
//!   review: an earlier version said `commit_aborted_chirho` had only test callers — it has a
//!   production caller, and the two phase gates are the true, stronger reason. That aborting a
//!   successful adoption would assert a failure that never happened is now the second reason, not
//!   the only one.)
//! - the HELD node's append under the winner's term correctly loses the first-record coordinate
//!   to the winner, and a later term of its own has no lawful cell mover (the only production
//!   writer of the sink cell is the witness-bounded lawful advance).
//!
//! So route (a)'s full chain — append, receipt, `CompletedChirho` — waited on ONE design decision:
//! the post-adoption RESUME step, either a lawful "handoff resolved by adoption" transition on
//! the winner or a later-election cell advance for the held node.
//!
//! # THE RESUME STEP LANDED — ruled (a) by L.J., 2026-08-05 — AND THE HELD-SIDE ARM IS A CONTROL
//!
//! L.J. ruled (a): compensations land on the LIVE WINNER's journal under the winner's own term. The
//! winner-side exemption is built, and the held-side arm above is the NEGATIVE CONTROL. Ruled (a)
//! deliberately did NOT give the deposed root a way to carry the compensation, so a held-side
//! success — a lifted hold or a committed append — would mean the exemption leaked to the wrong
//! node. (The guarded-release brick retargeted this arm from the post-commit frontier to the
//! active-hold barrier; see the second-arm section above.)
//!
//! # WHAT THE WINNER-SIDE ARMS PROVE, now that the wall is closed
//!
//! `route_a_winner_reaches_completed_after_the_winner_own_term_cell_advance_chirho` drives the
//! winner and proves five things that were all impossible before this brick: the winner's actor
//! OPENS under its own accepted handoff, composition runs there, the actor's freeze precheck admits
//! the compensation lane, the seam's four gates admit the append — and the append now CLEARS the
//! sink-term fence and completes.
//!
//! **That last step is new.** This arm was `route_a_winner_frontier_pins_the_winner_own_term_cell_
//! gap_chirho` and asserted a REFUSAL at the fence, because the winner's own sink winner-term cell
//! sat at its birth term while the winner published the term it won. The winner-own-term cell
//! advance has since been ruled and built, so the arm was retargeted per its own migration path into
//! the success arm it promised to become — `CompletedChirho`, the receipt bound to the winner's new
//! tail record digest, and an exact replay owing no second append. Its fixture is unchanged, so the
//! new green is a statement about the code. Read that arm's header for what each future failure
//! means.
//!
//! Three further arms fix the exemption's SHAPE, so the reviewer can attack a population rather
//! than an assertion — the exemption admits exactly one mutation kind
//! (`winner_freeze_still_refuses_a_non_compensation_append_chirho`), it requires durable signed
//! evidence and not merely the in-memory freeze marker
//! (`winner_compensation_lane_refuses_without_the_durable_accepted_head_chirho`), and it requires
//! that evidence to be ACCEPTED (`winner_compensation_lane_refuses_a_preparing_phase_head_chirho`,
//! whose fixture is winner-SIGNED precisely so the signature check cannot be what refuses).
//!
//! The cell advance has landed, so route (a)'s compensated terminal now completes — but the phrase
//! "live completed compensation path" still belongs to nobody, and the reason is SCOPE rather than
//! a missing step. This is LOCAL PROOF on a fixture world: `super::fixture_chirho()` twice, an
//! in-test provider, and two roots on this machine. It says nothing about a hosted deployment, and
//! nothing here has run against one.
//!
//! # MIGRATION PATH
//!
//! - If the FIRST arm refuses `ProviderNotConfiguredChirho`, the capstone door stopped threading
//!   its provider into the actor — the seam regressed; fix the opener, not this arm.
//! - The HELD-side control arm should stay red-if-it-passes: the deposed root must not lift the hold
//!   or commit the compensation append, so a released hold or a `CompletedChirho` there would mean
//!   the winner-side exemption became reachable from the deposed root. Do not retarget it into a
//!   success arm.
//! - If the held-side arm's refusal changes, read the new name before loosening anything: it refuses
//!   first at the certificate-verification barrier (the fabricated certificate) and then at the
//!   active-hold barrier (the completion), the two barriers a deposed root must never pass.

use super::harness1_success_ladder_tests_chirho::{
    drive_ladder_through_adoption_returning_world_chirho, AdoptedLadderStateChirho,
};
use cairn_effect_commit_chirho::compensation_chirho::{
    authorize_effect_compensation_chirho, CompensationAuthorizationFactsChirho,
    CompensationAuthorizationViewChirho, CompensationAuthorizationViewErrorChirho,
    CompensationBreakerVerdictChirho, EffectCompensationAuthorizationOutcomeChirho,
    VerifiedEffectCompensationChirho,
};
use cairn_effect_commit_chirho::coordinator_chirho::EffectCommitJournalViewPortChirho;
use cairn_effect_commit_chirho::intent_chirho::{
    canonical_effect_intent_line_chirho, sign_effect_intent_chirho, EffectIntentChirho,
    VerifiedEffectIntentChirho, EFFECT_INTENT_KEY_PREFIX_CHIRHO, EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_host_chirho::reconciliation_chirho::{
    gd7_reconciliation_identity_digest_chirho, gd7_winner_handoff_attempt_digest_chirho,
    gd7_winner_handoff_checkpoint_path_chirho, gd7_winner_handoff_head_path_chirho,
    load_gd7_obligation_processing_state_chirho, ConvergedReadReplicaChirho,
    ExistingNodeGd7SignerChirho, Gd7HeldManualClassificationChirho,
    Gd7LosingEffectObligationSelectorChirho, Gd7ObligationTerminalProgressChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
    Gd7WinnerHandoffCheckpointChirho, Gd7WinnerHandoffHeadChirho, Gd7WinnerHandoffPhaseChirho,
    Gd7WinnerWitnessReaderChirho, PinnedNodeGd7VerifierChirho,
};
use cairn_ledger_host_chirho::{
    host_ledger_signer_refs_from_config_chirho,
    open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho,
    open_resident_effect_journal_handle_with_shared_elector_and_gd7_compensation_provider_chirho,
    open_resident_gd7_held_coordinator_chirho, FsLedgerStorageChirho,
    Gd7CompensationCompletionRefusalChirho, Gd7CompensationProviderAdapterChirho,
    Gd7CompensationProviderObservationChirho, Gd7CompensationProviderRefusalChirho,
    HostLedgerSignersChirho, ResidentActorServiceCompositionChirho,
    ResidentEffectJournalHandleChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::AttributionChirho;
use cairn_ledger_model_chirho::LogIdChirho;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

type KeyedProviderCallsChirho = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// Bounded, non-identifying composition coordinates — labels for a compensation ACTION, not
/// content, exactly as the route (b) tail's constants are.
pub(super) const ROUTE_A_INVERSE_AUTHORITY_REF_CHIRHO: &str =
    "gd7-route-a-inverse-authority-ref-chirho";
pub(super) const ROUTE_A_ACTION_IDEMPOTENCY_KEY_CHIRHO: &str =
    "gd7-route-a-action-idempotency-key-chirho";
const ROUTE_A_BOUNDED_PAYLOAD_CHIRHO: &[u8] = b"gd7-route-a-bounded-compensation-payload-chirho";
const ROUTE_A_OBSERVATION_REF_CHIRHO: &str = "gd7-route-a-settlement-observation-ref-chirho";
const ROUTE_A_PROVIDER_EFFECT_ID_CHIRHO: &str = "gd7-route-a-provider-effect-id-chirho";
const ROUTE_A_IN_DOUBT_EVIDENCE_CHIRHO: &str = "gd7-route-a-in-doubt-evidence-chirho";

/// The capstone's layer-2 provider: it REPORTS a settlement and performs nothing.
///
/// The counters live behind `Arc` because the provider itself is MOVED into the actor thread by
/// the opener; without shared handles the arm could inject the provider or observe it, never both
/// — and an unobserved provider would make "executed exactly once" an unmeasured claim.
struct SettlementReportingProviderChirho {
    executions_chirho: Arc<AtomicU8>,
    keyed_calls_chirho: KeyedProviderCallsChirho,
}

impl Gd7CompensationProviderAdapterChirho for SettlementReportingProviderChirho {
    fn dedup_retention_duration_chirho(&self) -> std::time::Duration {
        std::time::Duration::from_secs(3600)
    }

    fn execute_gd7_compensation_provider_chirho(
        &self,
        provider_idempotency_key_chirho: &str,
        bounded_payload_chirho: &[u8],
    ) -> Result<Gd7CompensationProviderObservationChirho, Gd7CompensationProviderRefusalChirho>
    {
        self.executions_chirho.fetch_add(1, Ordering::SeqCst);
        assert!(
            !provider_idempotency_key_chirho.is_empty(),
            "the composition must never dispatch an empty provider idempotency key"
        );
        self.keyed_calls_chirho
            .lock()
            .expect("the provider call log is never poisoned")
            .push((
                provider_idempotency_key_chirho.to_owned(),
                bounded_payload_chirho.to_vec(),
            ));
        Ok(Gd7CompensationProviderObservationChirho::ObservedChirho {
            observation_ref_chirho: ROUTE_A_OBSERVATION_REF_CHIRHO.to_owned(),
            provider_effect_id_chirho: ROUTE_A_PROVIDER_EFFECT_ID_CHIRHO.to_owned(),
        })
    }
}

/// The reviewer-chosen arm's provider (F3): it reports IN-DOUBT — the external side may have
/// moved and cairn does not know — which must land as an operator hold, never as an observation.
struct InDoubtReportingProviderChirho {
    executions_chirho: Arc<AtomicU8>,
}

impl Gd7CompensationProviderAdapterChirho for InDoubtReportingProviderChirho {
    fn dedup_retention_duration_chirho(&self) -> std::time::Duration {
        std::time::Duration::from_secs(3600)
    }

    fn execute_gd7_compensation_provider_chirho(
        &self,
        provider_idempotency_key_chirho: &str,
        _bounded_payload_chirho: &[u8],
    ) -> Result<Gd7CompensationProviderObservationChirho, Gd7CompensationProviderRefusalChirho>
    {
        self.executions_chirho.fetch_add(1, Ordering::SeqCst);
        assert!(
            !provider_idempotency_key_chirho.is_empty(),
            "the composition must never dispatch an empty provider idempotency key"
        );
        Ok(Gd7CompensationProviderObservationChirho::InDoubtChirho {
            evidence_chirho: ROUTE_A_IN_DOUBT_EVIDENCE_CHIRHO.to_owned(),
        })
    }
}

/// Everything the frontier arm needs after the shared drive: the observed obligation's
/// coordinates, the live actor with its provider counters, and the world's own identities.
struct ObservedObligationWorldChirho {
    state_chirho: AdoptedLadderStateChirho,
    world_chirho: super::harness1_gd7_world_chirho::ObservedGd7WorldChirho,
    actor_chirho: ResidentEffectJournalHandleChirho,
    executions_chirho: Arc<AtomicU8>,
    mint_identity_digest_chirho: String,
    receipt_ref_chirho: String,
    canonical_obligation_digest_chirho: String,
    original_effect_key_chirho: String,
    tail_seq_before_chirho: u64,
    plan_kind_id_chirho: String,
    plan_initial_owner_chirho: String,
}

/// The coordinates a REAL minted obligation exposes, before any provider touches it.
///
/// Split out of the observed drive so the reviewer-chosen in-doubt arm can stand on the SAME
/// world and mint while supplying a DIFFERENT provider outcome.
pub(super) struct MintedObligationWorldChirho {
    // WIDENED to `pub(super)` for item 6.4's convergence arm (test-only). It carries the ADOPTED
    // reconciliation coordinates the honest converger needs — `adopted_checkpoint_ref_chirho`,
    // `canonical_root_chirho`, `ledger_config_chirho`, `sealed_plan_ref_chirho`,
    // `effect_obligation_count_chirho` — all reached through this one field.
    pub(super) state_chirho: AdoptedLadderStateChirho,
    pub(super) world_chirho: super::harness1_gd7_world_chirho::ObservedGd7WorldChirho,
    pub(super) mint_identity_digest_chirho: String,
    pub(super) receipt_ref_chirho: String,
    pub(super) canonical_obligation_digest_chirho: String,
    original_effect_key_chirho: String,
    plan_kind_id_chirho: String,
    plan_initial_owner_chirho: String,
}

/// Adoption -> non-vacuity -> the REAL mint by the actor that owns it -> lineage coordinates.
fn drive_to_minted_obligation_chirho(
    fixture_chirho: &mut super::RegenesisFixtureChirho,
    winner_fixture_chirho: &mut super::RegenesisFixtureChirho,
) -> MintedObligationWorldChirho {
    let (state_chirho, world_chirho) =
        drive_ladder_through_adoption_returning_world_chirho(fixture_chirho, winner_fixture_chirho);

    // NON-VACUITY FIRST, same reason as the route (b) tail: a zero-obligation plan would let every
    // assertion below fire honestly while measuring nothing.
    assert!(
        state_chirho.effect_obligation_count_chirho > 0,
        "the sealed plan carries NO effect obligations, so this capstone arm has no subject"
    );

    // ---- THE REAL MINT, by the actor that owns it (identical shape to the route (b) tail) ----
    let minted_chirho = {
        let mut coordinator_chirho = open_resident_gd7_held_coordinator_chirho(
            &state_chirho.canonical_root_chirho,
            &fixture_chirho.config_path_chirho,
            &state_chirho.ledger_config_chirho,
            std::sync::Arc::clone(&state_chirho.held_elector_chirho),
        )
        .expect("the held coordinator reopens on the adopted world");
        let minted_chirho = coordinator_chirho
            .mint_losing_effect_obligation_chirho(
                Gd7LosingEffectObligationSelectorChirho::new_chirho(
                    state_chirho.sealed_plan_ref_chirho.clone(),
                    0,
                )
                .expect("a lower-hex plan page ref and a zero index are a well-formed selector"),
            )
            .expect("the adopted held coordinator mints the exact selected obligation");
        // The coordinator holds the writer lock; the effect-journal actor cannot open beside it.
        coordinator_chirho.close_chirho().unwrap();
        minted_chirho
    };
    let mint_identity_digest_chirho = minted_chirho.mint_identity_digest_chirho().to_owned();
    let canonical_obligation_digest_chirho = minted_chirho
        .canonical_obligation_digest_chirho()
        .to_owned();
    let receipt_ref_chirho = minted_chirho.receipt_ref_chirho().to_owned();
    // The REAL lineage. The plan obligation names the losing effect by its INTENT REF, and
    // production derives the CF3 effect key from that ref exactly this way
    // (`journal_effect_chirho.rs`: `EFFECT_INTENT_KEY_PREFIX_CHIRHO + intent_ref`), so the CF3
    // authorization downstream is bound to the same losing effect the obligation compensates —
    // through the system's own derivation, never an invented coordinate.
    let original_effect_key_chirho = format!(
        "{EFFECT_INTENT_KEY_PREFIX_CHIRHO}{}",
        minted_chirho.obligation_chirho().intent_ref_chirho.0
    );
    // MEASURED, not assumed: the binding's own `original_effect_key_chirho` records the losing
    // effect's OWN compensation lineage — None here because the world's losing effect is
    // FIRST-ORDER. A Some would mean the fixture's obligation is itself a compensation and the
    // lineage facts downstream would be about the wrong effect.
    assert!(
        minted_chirho.original_effect_key_chirho().is_none(),
        "this world's losing effect must be first-order; its obligation carried a compensation \
         lineage key, so the arm's subject is not the effect it thinks it is"
    );
    drop(minted_chirho);

    MintedObligationWorldChirho {
        plan_kind_id_chirho: fixture_chirho.plan_chirho.kind_id_chirho.clone(),
        plan_initial_owner_chirho: fixture_chirho.plan_chirho.initial_owner_chirho.clone(),
        state_chirho,
        world_chirho,
        mint_identity_digest_chirho,
        receipt_ref_chirho,
        canonical_obligation_digest_chirho,
        original_effect_key_chirho,
    }
}

/// THE SHARED DRIVE: adoption -> real mint -> compose through the one door -> PROVIDER-OBSERVED.
///
/// Every assertion here is the FIRST arm's claim; the frontier arm stands on it unchanged so its
/// own claims start exactly where the closed wall ends.
fn drive_to_provider_observed_chirho(
    fixture_chirho: &mut super::RegenesisFixtureChirho,
    winner_fixture_chirho: &mut super::RegenesisFixtureChirho,
) -> ObservedObligationWorldChirho {
    let MintedObligationWorldChirho {
        state_chirho,
        world_chirho,
        mint_identity_digest_chirho,
        receipt_ref_chirho,
        canonical_obligation_digest_chirho,
        original_effect_key_chirho,
        plan_kind_id_chirho,
        plan_initial_owner_chirho,
    } = drive_to_minted_obligation_chirho(fixture_chirho, winner_fixture_chirho);

    // ---- THE CAPSTONE'S ONE DOOR: the held root's actor reopens WITH a completing provider ----
    let executions_chirho = Arc::new(AtomicU8::new(0));
    let keyed_calls_chirho = Arc::new(Mutex::new(Vec::new()));
    let actor_chirho = open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho(
        &state_chirho.canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &state_chirho.ledger_config_chirho,
        None,
        Box::new(SettlementReportingProviderChirho {
            executions_chirho: Arc::clone(&executions_chirho),
            keyed_calls_chirho: Arc::clone(&keyed_calls_chirho),
        }),
    )
    .expect("the capstone door runs the same custody checks as the base opener and admits");

    // POSITIVE CONTROL that the actor is alive BEFORE the wire calls, exactly as the mailbox
    // refusal arms do — a dead actor would refuse everything below for the wrong reason.
    let cut_before_chirho = actor_chirho
        .effect_intent_cut_chirho()
        .expect("the live actor answers a verified-view command before any wire command");

    // ---- COMPOSE, once: the provider observes and the obligation is PROVIDER-OBSERVED ----
    let observed_chirho = actor_chirho
        .compose_gd7_compensation_chirho(
            &mint_identity_digest_chirho,
            &receipt_ref_chirho,
            &canonical_obligation_digest_chirho,
            ROUTE_A_INVERSE_AUTHORITY_REF_CHIRHO,
            ROUTE_A_ACTION_IDEMPOTENCY_KEY_CHIRHO,
            ROUTE_A_BOUNDED_PAYLOAD_CHIRHO,
        )
        .expect(
            "with a completing provider the composition must SUCCEED; a ProviderNotConfigured \
             refusal here means the capstone door stopped threading its provider into the actor",
        );
    assert_eq!(
        observed_chirho.terminal_progress_chirho(),
        Gd7ObligationTerminalProgressChirho::ProviderObservedChirho,
        "the composed obligation must be PROVIDER-OBSERVED — the exact state the whole GD7 chain \
         could never reach before a completing provider existed"
    );
    assert_eq!(
        observed_chirho.provider_observation_ref_chirho(),
        Some(ROUTE_A_OBSERVATION_REF_CHIRHO),
        "the recorded observation must be the provider's own claim, verbatim"
    );
    assert_eq!(
        executions_chirho.load(Ordering::SeqCst),
        1,
        "one composition dispatches the provider exactly once"
    );
    {
        let calls_chirho = keyed_calls_chirho
            .lock()
            .expect("the provider call log is never poisoned");
        assert_eq!(calls_chirho.len(), 1);
        assert_eq!(
            calls_chirho[0].1, ROUTE_A_BOUNDED_PAYLOAD_CHIRHO,
            "the provider must receive the exact bounded payload the caller composed"
        );
    }
    assert_eq!(
        cut_before_chirho.tail_seq_chirho,
        actor_chirho
            .effect_intent_cut_chirho()
            .expect("the actor keeps serving after composition")
            .tail_seq_chirho,
        "composition records obligation state, never a journal append — the tail must not move"
    );

    ObservedObligationWorldChirho {
        plan_kind_id_chirho,
        plan_initial_owner_chirho,
        state_chirho,
        world_chirho,
        actor_chirho,
        executions_chirho,
        mint_identity_digest_chirho,
        receipt_ref_chirho,
        canonical_obligation_digest_chirho,
        original_effect_key_chirho,
        tail_seq_before_chirho: cut_before_chirho.tail_seq_chirho,
    }
}

/// Permits exactly one lineage — the REAL original effect key the minted obligation compensates.
struct RouteAPermittingViewChirho {
    original_effect_key_chirho: String,
}

impl CompensationAuthorizationViewChirho for RouteAPermittingViewChirho {
    fn derive_chirho(
        &self,
        _candidate_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<CompensationAuthorizationFactsChirho, CompensationAuthorizationViewErrorChirho>
    {
        Ok(CompensationAuthorizationFactsChirho::new_chirho(
            self.original_effect_key_chirho.clone(),
            self.original_effect_key_chirho.clone(),
            1,
            4,
            CompensationBreakerVerdictChirho::PermittedChirho,
        ))
    }
}

/// THE CAPSTONE'S CLOSED WALL: a real minted obligation reaches `ProviderObservedChirho` through
/// the real mailbox, and the terminal is durable in the root's own storage.
#[test]
fn route_a_reaches_provider_observed_through_the_one_door_chirho() {
    let mut fixture_chirho = super::fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let driven_chirho =
        drive_to_provider_observed_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);

    // DURABILITY: the observed state survives independent storage, not just the reply channel.
    drop(driven_chirho.actor_chirho);
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(
        &driven_chirho.state_chirho.canonical_root_chirho,
    )
    .expect("the held root's own storage opens");
    let durable_chirho = load_gd7_obligation_processing_state_chirho(
        &storage_chirho,
        &driven_chirho.mint_identity_digest_chirho,
    )
    .expect("the observed row is durable");
    assert_eq!(
        durable_chirho.terminal_progress_chirho(),
        Gd7ObligationTerminalProgressChirho::ProviderObservedChirho,
        "PROVIDER-OBSERVED must be durable state — this is the capstone's named wall, closed"
    );
    assert_eq!(
        durable_chirho.provider_observation_ref_chirho(),
        Some(ROUTE_A_OBSERVATION_REF_CHIRHO)
    );
    assert_eq!(
        driven_chirho.executions_chirho.load(Ordering::SeqCst),
        1,
        "the provider's single execution belongs to the composition; nothing else may re-run it"
    );
}

/// THE NEGATIVE CONTROL: the deposed root cannot lift the hold, so its completion refuses at the
/// hold barrier.
///
/// RETARGETED by the guarded-release brick, and the retarget is the point. When this arm was written
/// it was the frontier: it lifted the hold with a caller-built certificate and pinned the post-commit
/// winner-first-record refusal. That worked only because the release door did not verify the
/// certificate — the hole the guarded-release brick closed — and this block's own former migration
/// path predicted it ("if this release starts refusing on certificate custody or signature, the D3
/// hardening landed ... treat the refusal as the intended strengthening"). So the arm now proves the
/// deposed-side truth it was always a control for, one barrier earlier: the deposed root cannot
/// produce a real held-signed certificate (its own converger refuses `UnconvergedObligationChirho`
/// while the obligation is open), a fabricated certificate no longer lifts the hold, and its
/// completion therefore refuses at the FIRST barrier — the active hold — before any record is
/// appended.
///
/// What it controls FOR is unchanged: the winner-side exemption must not be reachable from the
/// deposed root. The held elector carries no handoff marker, so the compensation lane is never
/// consulted here; a `CompletedChirho` — or now any lifted hold or committed append — would mean the
/// exemption leaked to the wrong node. The forgery property (a fabricated certificate refuses) is
/// pinned directly by the host-tier arm
/// `a_fabricated_or_tampered_convergence_certificate_cannot_release_the_hold_chirho`; this arm keeps
/// the deposed-refuses invariant at the mailbox tier, through the full completion path.
///
/// (Former name: `route_a_completion_frontier_pins_the_post_adoption_resume_gap_chirho`.)
#[test]
fn route_a_deposed_side_completion_refuses_at_the_hold_barrier_chirho() {
    let mut fixture_chirho = super::fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let driven_chirho =
        drive_to_provider_observed_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);
    let actor_chirho = &driven_chirho.actor_chirho;
    let state_chirho = &driven_chirho.state_chirho;
    let world_chirho = &driven_chirho.world_chirho;

    // ---- the CF3 authorization, bound to the minted obligation's own original effect ----
    let signer_refs_chirho = host_ledger_signer_refs_from_config_chirho(
        &state_chirho.ledger_config_chirho.signer_secrets_chirho,
    )
    .expect("the adopted world's config names its signer secrets");
    let signers_chirho = HostLedgerSignersChirho::load_existing_chirho(
        &state_chirho.canonical_root_chirho,
        &signer_refs_chirho,
    )
    .expect("the adopted world carries all six runtime signers");
    let kind_id_chirho = AssetKindIdChirho(driven_chirho.plan_kind_id_chirho.clone());
    let continuation_chirho = actor_chirho
        .current_continuation_chirho(&kind_id_chirho)
        .expect("the resident answers its kind continuation")
        .expect("the published kind has a verified continuation");
    let digest_chirho =
        |character_chirho: char| DigestChirho(character_chirho.to_string().repeat(64));
    let intent_chirho = sign_effect_intent_chirho(
        EffectIntentChirho {
            schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
            journal_cut_chirho: actor_chirho
                .effect_intent_cut_chirho()
                .expect("the compensation intent binds the actor's live journal cut"),
            contract_set_digest_chirho: digest_chirho('a'),
            door_chirho: serde_json::from_value(serde_json::json!({
                "effect_node_chirho": "b".repeat(64),
                "capability_fingerprint_chirho": "c".repeat(64)
            }))
            .expect("the fixture door parses"),
            reversion_contract_digest_chirho: digest_chirho('d'),
            request_ref_chirho: digest_chirho('e'),
            request_context_ref_chirho: digest_chirho('f'),
            evidence_refs_chirho: vec![digest_chirho('9')],
            resolved_price_chirho: AssetOpChirho {
                amount_chirho: 1,
                kind_id_chirho: kind_id_chirho.clone(),
                kind_policy_ref_chirho: continuation_chirho.kind_policy_ref_chirho,
                rounding_chirho: RoundingChirho::ExactChirho,
            },
            payer_account_chirho: LogIdChirho::new_chirho(
                driven_chirho.plan_initial_owner_chirho.clone(),
                kind_id_chirho,
            ),
            effect_step_chirho: 1,
            attribution_chirho: AttributionChirho::CauserChirho {
                principal_chirho: driven_chirho.plan_initial_owner_chirho.clone(),
            },
            original_effect_key_chirho: Some(driven_chirho.original_effect_key_chirho.clone()),
            sig_chirho: String::new(),
            key_id_chirho: String::new(),
        },
        signers_chirho.effect_intent_signer_chirho(),
    )
    .expect("the compensation intent signs");
    let intent_line_chirho =
        canonical_effect_intent_line_chirho(&intent_chirho).expect("the intent line is canonical");
    let authorization_chirho = match authorize_effect_compensation_chirho(
        &intent_line_chirho,
        signers_chirho.effect_intent_signer_chirho(),
        &RouteAPermittingViewChirho {
            original_effect_key_chirho: driven_chirho.original_effect_key_chirho.clone(),
        },
    )
    .expect("the compensation authorization completes")
    {
        EffectCompensationAuthorizationOutcomeChirho::AuthorizedChirho(authorized_chirho) => {
            authorized_chirho
        }
        other_chirho => panic!(
            "this arm must yield an AUTHORIZED capability, or it stops before the mailbox and \
             proves nothing about the completion frontier: {other_chirho:?}"
        ),
    };

    // ---- THE LAWFUL D2 ADVANCE: lift the sink-term fence to the witness's term (B3c LINK 4) ----
    //
    // Measured: without this, the fenced append refuses
    // `UnseenWinnerTermChirho { supplied_term: 2, highest_accepted_term: 1 }` — the strand, by
    // value. The lawful lift reads the accepted term OUT OF THE SIGNED OBSERVATION (never a
    // caller argument), authenticated by the same public witness reader the held coordinator used
    // at install time. This is the THIRD wire command's first traversal — before this arm,
    // `advance_gd7_sink_term_chirho` had never been driven through the real mailbox.
    let authority_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&state_chirho.canonical_root_chirho)
            .expect("the held root's own storage opens for the witness reader");
    let winner_verifier_chirho =
        PinnedNodeGd7VerifierChirho::new_chirho(world_chirho.winner_node_chirho.clone())
            .expect("the held side pins the winner by node id, holding no winner signing power");
    let provider_fixture_chirho = super::harness1_conservation_provider_tests_chirho::
        RegenesisGd7ConservationProviderChirho::from_fixture_chirho(&fixture_chirho);
    let verified_losing_tail_chirho = provider_fixture_chirho
        .verified_losing_tail_chirho()
        .expect("the public losing-journal reader verifies the exact current tail");
    let observation_chirho = Gd7WinnerWitnessReaderChirho::new_chirho(
        &authority_storage_chirho,
        &winner_verifier_chirho,
        signers_chirho.journal_signer_chirho(),
    )
    .load_authenticated_deposed_fork_observation_chirho(
        &world_chirho.identity_chirho,
        &verified_losing_tail_chirho,
    )
    .expect("the public observation loader re-verifies the installed signed witness objects");
    let accepted_term_chirho = actor_chirho
        .advance_gd7_sink_term_chirho(
            &observation_chirho,
            &state_chirho.adopted_checkpoint_ref_chirho,
        )
        .expect("the lawful advance accepts the witness's deposing term");
    assert_eq!(
        accepted_term_chirho, world_chirho.winner_term_chirho,
        "the accepted term is the WITNESS's term, read out of the signed observation by value — a \
         different term would mean the advance took a caller's word for it"
    );

    // ---- THE RELEASE NOW REFUSES: the deposed side cannot lawfully lift the hold ----
    //
    // RETARGET (guarded-release brick). This arm used to lift the hold here with a caller-built
    // certificate and then pin the post-commit winner-first-record frontier. That depended on the
    // release door NOT verifying the certificate — the exact hole the guarded-release brick closed,
    // as this block's own former migration path predicted. So the fabricated certificate below no
    // longer lifts the hold: it refuses at the certificate-verification barrier. That is honest here,
    // because the deposed root genuinely cannot obtain a real held-signed certificate — its own
    // converger (`converge_and_certify_gd7_chirho`) refuses `UnconvergedObligationChirho` while this
    // obligation is open. The forgery property is pinned directly by the host-tier arm
    // `a_fabricated_or_tampered_convergence_certificate_cannot_release_the_hold_chirho`.
    //
    // Every field below that the world can supply is the world's TRUE value; only the certificate key
    // id and signature are caller-built, which is exactly what the release door now rejects.
    //
    // MIGRATION PATH: if this release now SUCCEEDS, the certificate signature binding regressed and a
    // fabricated certificate lifted the hold on the deposed root — a money-authority defect.
    let fabricated_certificate_chirho: ConvergedReadReplicaChirho =
        serde_json::from_value(serde_json::json!({
            "schema_chirho": "gd7-converged-read-replica-v2-chirho",
            "reconciliation_identity_digest_chirho":
                gd7_reconciliation_identity_digest_chirho(&world_chirho.identity_chirho)
                    .expect("the world's reconciliation identity digests"),
            "checkpoint_ref_chirho": state_chirho.adopted_checkpoint_ref_chirho.clone(),
            "sealed_plan_ref_chirho": state_chirho.sealed_plan_ref_chirho.clone(),
            "winner_fork_witness_object_digest_chirho": "3".repeat(64),
            "winner_term_chirho": world_chirho.winner_term_chirho,
            "adopted_checkpoint_ref_chirho": state_chirho.adopted_checkpoint_ref_chirho.clone(),
            "losing_population_identity_chirho": "route-a-losing-population-chirho",
            "losing_population_digest_chirho": "4".repeat(64),
            "terminal_outcome_identity_chirho": "route-a-terminal-outcome-chirho",
            "terminal_outcome_digest_chirho": "5".repeat(64),
            "conservation_snapshot_digest_chirho": "6".repeat(64),
            "retained_refs_chirho": [],
            "population_count_chirho": state_chirho.effect_obligation_count_chirho,
            "completed_count_chirho": 0,
            "disposed_count_chirho": 0,
            "certificate_key_id_chirho": "route-a-caller-built-not-custody-chirho",
            "certificate_sig_chirho": "7".repeat(128),
        }))
        .expect("the fabricated certificate deserializes through the public type");
    let release_refusal_chirho = actor_chirho
        .release_converged_gd7_hold_chirho(
            &state_chirho.adopted_checkpoint_ref_chirho,
            &fabricated_certificate_chirho,
        )
        .expect_err(
            "the deposed side must not lift the hold with a fabricated certificate; a success here \
             means the certificate signature binding regressed and a forged certificate released \
             the hold",
        );
    assert!(
        format!("{release_refusal_chirho:?}").contains("ConvergenceCertificateUnverifiedChirho"),
        "the release must refuse at the certificate-verification barrier: {release_refusal_chirho:?}"
    );

    // ---- COMPLETE with the hold still active: it refuses at the FIRST barrier, no append ----
    //
    // The hold was never lifted, so the fenced append never commits: the completion refuses at the
    // active-hold barrier, BEFORE any record is written. This is the deposed-refuses invariant,
    // measured at the mailbox tier through the full `complete_gd7_compensation_chirho` path (the
    // host-tier strand-fence arms prove the same barrier on `record_effect_compensation_hold_chirho`,
    // the resident-direct surface). Nothing between actor-open and here appends to the effect journal
    // — the CF3 authorization signs an intent and the sink-term advance writes a reconciliation cell,
    // not the journal — so the tail must still stand at `tail_seq_before_chirho`.
    let refusal_chirho = actor_chirho
        .complete_gd7_compensation_chirho(
            &driven_chirho.mint_identity_digest_chirho,
            &driven_chirho.receipt_ref_chirho,
            &driven_chirho.canonical_obligation_digest_chirho,
            ROUTE_A_INVERSE_AUTHORITY_REF_CHIRHO,
            ROUTE_A_ACTION_IDEMPOTENCY_KEY_CHIRHO,
            &intent_line_chirho,
            &authorization_chirho,
        )
        .expect_err(
            "with the hold still active the completion must refuse at the hold barrier; a success \
             would mean the deposed side completed a compensation it may not",
        );
    let refusal_text_chirho = format!("{refusal_chirho:?}");
    // ASSERT THE REFUSAL'S IDENTITY: the append family (JournalAppendRefused), naming the ACTIVE
    // HOLD — the first barrier, which has no exemption and fires before any append commits.
    assert!(
        matches!(
            &refusal_chirho,
            Gd7CompensationCompletionRefusalChirho::JournalAppendRefusedChirho { .. }
        ),
        "the refusal must be the append family, nothing upstream.\nrefusal: {refusal_text_chirho}"
    );
    assert!(
        refusal_text_chirho.contains("held by active GD7 reconciliation"),
        "the barrier must be the ACTIVE HOLD — the first barrier, which has no exemption and fires \
         before any append commits. That refusal's message is the Display of \
         `Gd7ReconciliationHoldActiveChirho`; if it changed, read the new name before loosening \
         anything.\nrefusal: {refusal_text_chirho}"
    );

    // NO RECORD WAS WRITTEN: the hold barrier refuses before the append, so the journal tail must
    // NOT move — the opposite of the old frontier arm, where the append committed before its
    // evidence step refused.
    assert_eq!(
        actor_chirho
            .effect_intent_cut_chirho()
            .expect("the actor keeps serving its verified views after the refusal")
            .tail_seq_chirho,
        driven_chirho.tail_seq_before_chirho,
        "a completion refused at the hold barrier must not append a record"
    );

    // THE OBLIGATION DID NOT ADVANCE: no receipt was bound, so the state machine still says
    // PROVIDER-OBSERVED.
    let durable_chirho = load_gd7_obligation_processing_state_chirho(
        &authority_storage_chirho,
        &driven_chirho.mint_identity_digest_chirho,
    )
    .expect("the observed row is durable");
    assert_eq!(
        durable_chirho.terminal_progress_chirho(),
        Gd7ObligationTerminalProgressChirho::ProviderObservedChirho,
        "the obligation must remain PROVIDER-OBSERVED after the hold-barrier refusal"
    );
    assert!(
        durable_chirho.journal_receipt_ref_chirho().is_none(),
        "no receipt may be bound by a completion that refused at the hold barrier"
    );

    // The provider's one execution still belongs to the composition alone.
    assert_eq!(
        driven_chirho.executions_chirho.load(Ordering::SeqCst),
        1,
        "the refused completion may not re-execute the provider"
    );
}

/// Everything the winner-side arms need: the minted obligation, the WINNER's live actor opened on
/// the shared elector that carries its accepted handoff marker, and the world's own identities.
pub(super) struct WinnerCompensationWorldChirho {
    pub(super) minted_chirho: MintedObligationWorldChirho,
    pub(super) winner_actor_chirho: ResidentEffectJournalHandleChirho,
    pub(super) executions_chirho: Arc<AtomicU8>,
    pub(super) tail_seq_before_chirho: u64,
}

/// Adoption -> real mint (held side) -> open the WINNER's actor UNDER ITS OWN ACCEPTED FREEZE.
///
/// The open is itself the first thing this brick proves. Before the resume step, this exact call
/// refused at startup: `open_bound_preactivation_chirho`'s generation bracket used the ordinary
/// acquisition, which refuses `HandoffActiveChirho` before validating anything, so the winner — the
/// node ruled (a) puts the compensation on — could not even be opened.
pub(super) fn drive_to_open_winner_under_freeze_chirho(
    fixture_chirho: &mut super::RegenesisFixtureChirho,
    winner_fixture_chirho: &mut super::RegenesisFixtureChirho,
) -> WinnerCompensationWorldChirho {
    let minted_chirho = drive_to_minted_obligation_chirho(fixture_chirho, winner_fixture_chirho);
    let executions_chirho = Arc::new(AtomicU8::new(0));
    let winner_actor_chirho =
        open_resident_effect_journal_handle_with_shared_elector_and_gd7_compensation_provider_chirho(
            &minted_chirho.world_chirho.winner_source_root_chirho,
            &minted_chirho.world_chirho.winner_config_path_chirho,
            &minted_chirho.world_chirho.winner_ledger_config_chirho,
            &minted_chirho.world_chirho.nodes_chirho[0],
            ResidentActorServiceCompositionChirho::with_gd7_compensation_provider_chirho(
                None,
                None,
                None,
                Box::new(SettlementReportingProviderChirho {
                    executions_chirho: Arc::clone(&executions_chirho),
                    keyed_calls_chirho: Arc::new(Mutex::new(Vec::new())),
                }),
            ),
        )
        .expect(
            "the winner's actor must OPEN while its own handoff is accepted — a refusal here means \
             the startup acquisition stopped being handoff-aware, which is the resume step \
             regressing, not a fixture problem",
        );
    let cut_before_chirho = winner_actor_chirho
        .effect_intent_cut_chirho()
        .expect("the live winner actor answers a verified-view command before any wire command");
    WinnerCompensationWorldChirho {
        minted_chirho,
        winner_actor_chirho,
        executions_chirho,
        tail_seq_before_chirho: cut_before_chirho.tail_seq_chirho,
    }
}

/// Build the CF3 compensation authorization against the WINNER's own journal cut and signers.
///
/// The cut, the kind continuation, and the signing key all come from the winner, because ruled (a)
/// puts the append on the winner's journal: an intent bound to the held root's cut would be refused
/// by the winner for the honest reason that it names another journal, and the arm would then be
/// measuring the wrong refusal.
pub(super) fn winner_compensation_authorization_chirho(
    driven_chirho: &WinnerCompensationWorldChirho,
) -> (String, VerifiedEffectCompensationChirho) {
    let winner_signers_chirho = &driven_chirho
        .minted_chirho
        .world_chirho
        .winner_signers_chirho;
    let kind_id_chirho = AssetKindIdChirho(driven_chirho.minted_chirho.plan_kind_id_chirho.clone());
    let continuation_chirho = driven_chirho
        .winner_actor_chirho
        .current_continuation_chirho(&kind_id_chirho)
        .expect("the winner resident answers its kind continuation")
        .expect("the published kind has a verified continuation on the winner root");
    let digest_chirho =
        |character_chirho: char| DigestChirho(character_chirho.to_string().repeat(64));
    let intent_chirho = sign_effect_intent_chirho(
        EffectIntentChirho {
            schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
            journal_cut_chirho: driven_chirho
                .winner_actor_chirho
                .effect_intent_cut_chirho()
                .expect("the compensation intent binds the WINNER's live journal cut"),
            contract_set_digest_chirho: digest_chirho('a'),
            door_chirho: serde_json::from_value(serde_json::json!({
                "effect_node_chirho": "b".repeat(64),
                "capability_fingerprint_chirho": "c".repeat(64)
            }))
            .expect("the fixture door parses"),
            reversion_contract_digest_chirho: digest_chirho('d'),
            request_ref_chirho: digest_chirho('e'),
            request_context_ref_chirho: digest_chirho('f'),
            evidence_refs_chirho: vec![digest_chirho('9')],
            resolved_price_chirho: AssetOpChirho {
                amount_chirho: 1,
                kind_id_chirho: kind_id_chirho.clone(),
                kind_policy_ref_chirho: continuation_chirho.kind_policy_ref_chirho,
                rounding_chirho: RoundingChirho::ExactChirho,
            },
            payer_account_chirho: LogIdChirho::new_chirho(
                driven_chirho
                    .minted_chirho
                    .plan_initial_owner_chirho
                    .clone(),
                kind_id_chirho,
            ),
            effect_step_chirho: 1,
            attribution_chirho: AttributionChirho::CauserChirho {
                principal_chirho: driven_chirho
                    .minted_chirho
                    .plan_initial_owner_chirho
                    .clone(),
            },
            original_effect_key_chirho: Some(
                driven_chirho
                    .minted_chirho
                    .original_effect_key_chirho
                    .clone(),
            ),
            sig_chirho: String::new(),
            key_id_chirho: String::new(),
        },
        winner_signers_chirho.effect_intent_signer_chirho(),
    )
    .expect("the compensation intent signs in the winner's own custody");
    let intent_line_chirho =
        canonical_effect_intent_line_chirho(&intent_chirho).expect("the intent line is canonical");
    let authorization_chirho = match authorize_effect_compensation_chirho(
        &intent_line_chirho,
        winner_signers_chirho.effect_intent_signer_chirho(),
        &RouteAPermittingViewChirho {
            original_effect_key_chirho: driven_chirho
                .minted_chirho
                .original_effect_key_chirho
                .clone(),
        },
    )
    .expect("the compensation authorization completes")
    {
        EffectCompensationAuthorizationOutcomeChirho::AuthorizedChirho(authorized_chirho) => {
            authorized_chirho
        }
        other_chirho => panic!(
            "this arm must yield an AUTHORIZED capability, or it stops before the mailbox and \
             proves nothing about the winner-side completion: {other_chirho:?}"
        ),
    };
    (intent_line_chirho, authorization_chirho)
}

/// Compose the observation on the WINNER, so the obligation this node completes is the one it owns.
pub(super) fn compose_on_the_winner_chirho(driven_chirho: &WinnerCompensationWorldChirho) {
    let observed_chirho = driven_chirho
        .winner_actor_chirho
        .compose_gd7_compensation_chirho(
            &driven_chirho.minted_chirho.mint_identity_digest_chirho,
            &driven_chirho.minted_chirho.receipt_ref_chirho,
            &driven_chirho
                .minted_chirho
                .canonical_obligation_digest_chirho,
            ROUTE_A_INVERSE_AUTHORITY_REF_CHIRHO,
            ROUTE_A_ACTION_IDEMPOTENCY_KEY_CHIRHO,
            ROUTE_A_BOUNDED_PAYLOAD_CHIRHO,
        )
        .expect(
            "composition must succeed on the frozen winner: it records obligation state and \
             appends nothing, so the handoff freeze has no bearing on it",
        );
    assert_eq!(
        observed_chirho.terminal_progress_chirho(),
        Gd7ObligationTerminalProgressChirho::ProviderObservedChirho,
        "the winner's own obligation row must reach PROVIDER-OBSERVED before any append is owed"
    );
    assert_eq!(
        driven_chirho
            .winner_actor_chirho
            .effect_intent_cut_chirho()
            .expect("the winner keeps serving after composition")
            .tail_seq_chirho,
        driven_chirho.tail_seq_before_chirho,
        "composition records obligation state, never a journal append — the tail must not move"
    );
}

/// THE WALL IS CLOSED — route (a)'s compensated terminal reaches `CompletedChirho` on the winner.
///
/// # THIS ARM WAS RETARGETED, AND WHAT IT USED TO SAY IS THE POINT
///
/// It was `route_a_winner_frontier_pins_the_winner_own_term_cell_gap_chirho`, and it asserted a
/// REFUSAL: the winner's own sink winner-term cell sat at its BIRTH term while the winner published
/// the term it won, so the fence refused `UnseenWinnerTermChirho { supplied_term: 2,
/// highest_accepted_term: 1 }`. Its own migration path said that a SUCCESS there would mean the
/// winner-side cell advance had landed, and that the arm should then become the success arm
/// asserting three things — `CompletedChirho`, the bound receipt equal to the winner's new tail
/// record digest, and an exact replay owing no second append. **That is exactly what happened, and
/// this is exactly those three assertions.** The fixture is untouched: the driver, the composition,
/// and the authorization are byte-for-byte what the refusal arm used, so this green is a statement
/// about the CODE and not about a rebuilt fixture.
///
/// What ruled (a) bought, all of it still traversed on the way here: the winner's actor OPENS under
/// its own accepted handoff, composition runs on the winner, the actor's freeze precheck admits the
/// compensation lane, and the seam's four gates admit the append. What the cell advance added is the
/// last step — the append now clears the SINK-TERM FENCE instead of stopping at it.
///
/// # MIGRATION PATH — what each future failure MEANS
///
/// - A refusal naming `UnseenWinnerTermChirho` means the winner-own-term cell advance REGRESSED and
///   the wall is back. That is the defect this arm now exists to catch; do not retarget it back into
///   a refusal arm without a ruling that says the advance was withdrawn.
/// - A refusal naming `frozen by an active GD7 winner handoff` means the exemption stopped reaching
///   the seam — the lane regressed to pre-resume-step behaviour.
/// - A refusal naming `refused the GD7 winner-side compensation append lane` means the lane's own
///   evidence gate declined; read its detail, that is a regression in this brick.
/// - A refusal naming `winner term-first index` means the append ran on the HELD root; this arm
///   stopped being about the winner.
/// - If the RECEIPT/TAIL equality fails while `CompletedChirho` holds, the completion bound a
///   receipt that is not the record it wrote — worse than a refusal, because it presents a
///   compensation as landed against the wrong coordinate.
/// - If the REPLAY assertions fail, completion stopped being idempotent and a retry can append a
///   second compensation record. That is a money defect, not a test defect.
#[test]
fn route_a_winner_reaches_completed_after_the_winner_own_term_cell_advance_chirho() {
    let mut fixture_chirho = super::fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let driven_chirho =
        drive_to_open_winner_under_freeze_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);
    compose_on_the_winner_chirho(&driven_chirho);
    let (intent_line_chirho, authorization_chirho) =
        winner_compensation_authorization_chirho(&driven_chirho);

    let completed_chirho = driven_chirho
        .winner_actor_chirho
        .complete_gd7_compensation_chirho(
            &driven_chirho.minted_chirho.mint_identity_digest_chirho,
            &driven_chirho.minted_chirho.receipt_ref_chirho,
            &driven_chirho.minted_chirho.canonical_obligation_digest_chirho,
            ROUTE_A_INVERSE_AUTHORITY_REF_CHIRHO,
            ROUTE_A_ACTION_IDEMPOTENCY_KEY_CHIRHO,
            &intent_line_chirho,
            &authorization_chirho,
        )
        .expect(
            "the winner-side completion must now COMPLETE; a refusal here means the winner-own-term \
             cell advance regressed — read the refusal's name against this arm's migration path \
             before touching the fixture",
        );

    // (1) COMPLETED — the terminal state route (a) exists to reach.
    assert_eq!(
        completed_chirho.terminal_progress_chirho(),
        Gd7ObligationTerminalProgressChirho::CompletedChirho,
        "route (a)'s compensated terminal must reach CompletedChirho"
    );

    // (2) THE RECEIPT BINDS THE RECORD THE APPEND ACTUALLY WROTE. The tail must have MOVED (the
    // refusal arm asserted it must not), and the bound receipt must equal the NEW tail digest —
    // a completion bound to any other coordinate presents a compensation against the wrong record.
    let cut_after_chirho = driven_chirho
        .winner_actor_chirho
        .effect_intent_cut_chirho()
        .expect("the winner keeps serving its verified views after the completion");
    assert!(
        cut_after_chirho.tail_seq_chirho > driven_chirho.tail_seq_before_chirho,
        "the completion must APPEND: tail {} did not advance past {}",
        cut_after_chirho.tail_seq_chirho,
        driven_chirho.tail_seq_before_chirho
    );
    assert_eq!(
        completed_chirho.journal_receipt_ref_chirho(),
        Some(cut_after_chirho.tail_record_digest_chirho.0.as_str()),
        "the bound receipt must be the winner's NEW tail record digest, by value"
    );

    // The durable row on the WINNER's own root agrees with what the call returned — a completion
    // visible only in the returned value would not survive the process that wrote it.
    let winner_storage_chirho = FsLedgerStorageChirho::open_existing_chirho(
        &driven_chirho
            .minted_chirho
            .world_chirho
            .winner_source_root_chirho,
    )
    .expect("the winner root's own storage opens");
    let durable_chirho = load_gd7_obligation_processing_state_chirho(
        &winner_storage_chirho,
        &driven_chirho.minted_chirho.mint_identity_digest_chirho,
    )
    .expect("the winner's obligation row is durable");
    assert_eq!(
        durable_chirho.terminal_progress_chirho(),
        Gd7ObligationTerminalProgressChirho::CompletedChirho,
        "the DURABLE row on the winner root must be CompletedChirho, not merely the return value"
    );
    assert_eq!(
        durable_chirho.journal_receipt_ref_chirho(),
        completed_chirho.journal_receipt_ref_chirho(),
        "the durable receipt and the returned receipt must be one value"
    );

    // (3) EXACT REPLAY OWES NO SECOND APPEND. Same arguments, same authorization — the money
    // property is that a retry cannot mint a second compensation record.
    let replayed_chirho = driven_chirho
        .winner_actor_chirho
        .complete_gd7_compensation_chirho(
            &driven_chirho.minted_chirho.mint_identity_digest_chirho,
            &driven_chirho.minted_chirho.receipt_ref_chirho,
            &driven_chirho
                .minted_chirho
                .canonical_obligation_digest_chirho,
            ROUTE_A_INVERSE_AUTHORITY_REF_CHIRHO,
            ROUTE_A_ACTION_IDEMPOTENCY_KEY_CHIRHO,
            &intent_line_chirho,
            &authorization_chirho,
        )
        .expect("an exact replay of a completed compensation must not refuse");
    assert_eq!(
        replayed_chirho.journal_receipt_ref_chirho(),
        completed_chirho.journal_receipt_ref_chirho(),
        "the replay must return the ORIGINAL receipt, not a new one"
    );
    assert_eq!(
        driven_chirho
            .winner_actor_chirho
            .effect_intent_cut_chirho()
            .expect("the winner keeps serving after the replay")
            .tail_seq_chirho,
        cut_after_chirho.tail_seq_chirho,
        "the replay must append NOTHING — a moved tail means a second compensation record"
    );
    assert_eq!(
        driven_chirho.executions_chirho.load(Ordering::SeqCst),
        1,
        "the provider's one execution belongs to the composition alone; neither the completion nor \
         its replay may execute the provider again"
    );
}

/// ITEM 6.5-a ARM 3 — the shipped test-kind geo-node surface reaches `CompletedChirho`.
///
/// This stands exactly where `route_a_winner_reaches_completed_after_the_winner_own_term_cell_
/// advance_chirho` stands, but the winner's actor is opened through
/// `cairn-ledger-geo-node-testkind-chirho`'s PUBLIC E-B opener with that crate's
/// `TestkindSettlementReportingProviderChirho`, instead of calling the host-crate door directly. So
/// it proves the exact opener + provider a hosted item-6 drill will run carries a synthetic
/// obligation to the compensated terminal — receipt bound to the winner's new tail digest, an exact
/// replay owing no second append, and the reporting-only provider executed exactly once and moving
/// no money. The fixture is the same two-root adopted world the winner arm uses (reuse, not mirror).
///
/// MIGRATION PATH — what each future failure MEANS:
/// - A refusal at OPEN means the testkind opener stopped threading its provider through E-B; fix the
///   testkind wiring, not this arm.
/// - A refusal naming `UnseenWinnerTermChirho` / `frozen by an active GD7 winner handoff` / the
///   winner-side lane means the underlying host-layer route (a) regressed; fix it there.
/// - A `CompletedChirho` with a mismatched receipt/tail, or a replay that APPENDS, is a money defect
///   in the testkind path — worse than a refusal.
#[test]
fn route_a_testkind_geo_node_reaches_completed_through_the_provider_door_chirho() {
    let mut fixture_chirho = super::fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let minted_chirho =
        drive_to_minted_obligation_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);

    // Open the WINNER through the testkind crate's public E-B opener + its reporting-only provider,
    // on the exact shared elector that carries the winner's accepted handoff marker.
    let executions_chirho = Arc::new(AtomicU8::new(0));
    let winner_actor_chirho =
        cairn_ledger_geo_node_testkind_chirho::open_testkind_winner_resident_with_reporting_provider_chirho(
            &minted_chirho.world_chirho.winner_source_root_chirho,
            &minted_chirho.world_chirho.winner_config_path_chirho,
            &minted_chirho.world_chirho.winner_ledger_config_chirho,
            &minted_chirho.world_chirho.nodes_chirho[0],
            None,
            None,
            Box::new(
                cairn_ledger_geo_node_testkind_chirho::TestkindSettlementReportingProviderChirho::with_observers_chirho(
                    Arc::clone(&executions_chirho),
                    Arc::new(Mutex::new(Vec::new())),
                ),
            ),
        )
        .expect(
            "the testkind opener must open the winner under its own accepted handoff freeze — a \
             refusal here means the testkind E-B wiring regressed, not the fixture",
        );
    let cut_before_chirho = winner_actor_chirho.effect_intent_cut_chirho().expect(
        "the live testkind winner actor answers a verified-view command before any wire command",
    );
    let driven_chirho = WinnerCompensationWorldChirho {
        minted_chirho,
        winner_actor_chirho,
        executions_chirho,
        tail_seq_before_chirho: cut_before_chirho.tail_seq_chirho,
    };

    compose_on_the_winner_chirho(&driven_chirho);
    let (intent_line_chirho, authorization_chirho) =
        winner_compensation_authorization_chirho(&driven_chirho);

    let completed_chirho = driven_chirho
        .winner_actor_chirho
        .complete_gd7_compensation_chirho(
            &driven_chirho.minted_chirho.mint_identity_digest_chirho,
            &driven_chirho.minted_chirho.receipt_ref_chirho,
            &driven_chirho.minted_chirho.canonical_obligation_digest_chirho,
            ROUTE_A_INVERSE_AUTHORITY_REF_CHIRHO,
            ROUTE_A_ACTION_IDEMPOTENCY_KEY_CHIRHO,
            &intent_line_chirho,
            &authorization_chirho,
        )
        .expect(
            "the testkind winner-side completion must reach CompletedChirho; a refusal means route \
             (a)'s terminal regressed under the testkind opener",
        );

    // (1) COMPLETED — the terminal the test-kind path must reach.
    assert_eq!(
        completed_chirho.terminal_progress_chirho(),
        Gd7ObligationTerminalProgressChirho::CompletedChirho,
        "the testkind geo-node path must reach route (a)'s compensated terminal"
    );

    // (2) The receipt binds the record the append actually wrote — the tail MOVED and the bound
    // receipt equals the NEW tail digest, by value.
    let cut_after_chirho = driven_chirho
        .winner_actor_chirho
        .effect_intent_cut_chirho()
        .expect("the winner keeps serving its verified views after the completion");
    assert!(
        cut_after_chirho.tail_seq_chirho > driven_chirho.tail_seq_before_chirho,
        "the completion must APPEND on the winner's journal: tail {} did not advance past {}",
        cut_after_chirho.tail_seq_chirho,
        driven_chirho.tail_seq_before_chirho
    );
    assert_eq!(
        completed_chirho.journal_receipt_ref_chirho(),
        Some(cut_after_chirho.tail_record_digest_chirho.0.as_str()),
        "the bound receipt must be the winner's NEW tail record digest, by value"
    );

    // (3) Exact replay owes no second append — a retry cannot mint a second compensation record.
    let replayed_chirho = driven_chirho
        .winner_actor_chirho
        .complete_gd7_compensation_chirho(
            &driven_chirho.minted_chirho.mint_identity_digest_chirho,
            &driven_chirho.minted_chirho.receipt_ref_chirho,
            &driven_chirho
                .minted_chirho
                .canonical_obligation_digest_chirho,
            ROUTE_A_INVERSE_AUTHORITY_REF_CHIRHO,
            ROUTE_A_ACTION_IDEMPOTENCY_KEY_CHIRHO,
            &intent_line_chirho,
            &authorization_chirho,
        )
        .expect("an exact replay of a completed compensation must not refuse");
    assert_eq!(
        replayed_chirho.journal_receipt_ref_chirho(),
        completed_chirho.journal_receipt_ref_chirho(),
        "the replay must return the ORIGINAL receipt, not a new one"
    );
    assert_eq!(
        driven_chirho
            .winner_actor_chirho
            .effect_intent_cut_chirho()
            .expect("the winner keeps serving after the replay")
            .tail_seq_chirho,
        cut_after_chirho.tail_seq_chirho,
        "the replay must append NOTHING — a moved tail means a second compensation record"
    );

    // (4) The provider is reporting-only: executed exactly once (composition), moved no money.
    assert_eq!(
        driven_chirho.executions_chirho.load(Ordering::SeqCst),
        1,
        "the reporting-only provider executed exactly once and neither completion nor replay ran it \
         again"
    );
}

/// THE EXEMPTION IS EXACTLY ONE KIND — proven by an arm, not by prose.
///
/// The same frozen winner that carries a compensation must still refuse an ORDINARY effect intent.
/// If this arm ever passes, the exemption stopped being kind-scoped and became a hole in the
/// handoff freeze.
#[test]
fn winner_freeze_still_refuses_a_non_compensation_append_chirho() {
    use cairn_effect_commit_chirho::coordinator_chirho::EffectCommitJournalPortChirho;

    let mut fixture_chirho = super::fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let mut driven_chirho =
        drive_to_open_winner_under_freeze_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);
    // An ordinary intent line is enough: the freeze must refuse BEFORE any line parsing, so a
    // well-formed line is not required to measure the refusal — but a refusal about the LINE would
    // be the wrong refusal, so the assertion below names the freeze specifically.
    let refusal_chirho = driven_chirho
        .winner_actor_chirho
        .append_hold_chirho("{\"schema_chirho\":\"not-reached-chirho\"}")
        .expect_err(
            "an ordinary effect intent must stay frozen on a winner with an accepted handoff",
        );
    let refusal_text_chirho = format!("{refusal_chirho:?}");
    assert!(
        refusal_text_chirho.contains("frozen by an active GD7 winner handoff"),
        "the ordinary append must refuse FOR THE FREEZE. Any other refusal would leave this arm \
         green while the freeze itself was gone.\nrefusal: {refusal_text_chirho}"
    );
    assert_eq!(
        driven_chirho
            .winner_actor_chirho
            .effect_intent_cut_chirho()
            .expect("the winner keeps serving after the frozen refusal")
            .tail_seq_chirho,
        driven_chirho.tail_seq_before_chirho,
        "a refused ordinary append must leave the winner's tail exactly where it was"
    );
}

/// THE LANE NEEDS DURABLE SIGNED EVIDENCE, not merely the in-memory marker.
///
/// The elector's marker is still armed here — the freeze is real — but the winner's durable handoff
/// head is gone. The lane must refuse rather than fall back to the marker alone, because the marker
/// says only THAT a handoff is active; the head is what says which attempt and in what phase.
#[test]
fn winner_compensation_lane_refuses_without_the_durable_accepted_head_chirho() {
    let mut fixture_chirho = super::fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let driven_chirho =
        drive_to_open_winner_under_freeze_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);
    compose_on_the_winner_chirho(&driven_chirho);
    let (intent_line_chirho, authorization_chirho) =
        winner_compensation_authorization_chirho(&driven_chirho);

    let head_file_chirho = winner_handoff_head_file_chirho(&driven_chirho);
    assert!(
        head_file_chirho.is_file(),
        "the winner must really own a durable handoff head before this arm removes it, or the arm \
         proves nothing about removing it"
    );
    std::fs::remove_file(&head_file_chirho).expect("remove the winner's durable handoff head");

    let refusal_chirho = driven_chirho
        .winner_actor_chirho
        .complete_gd7_compensation_chirho(
            &driven_chirho.minted_chirho.mint_identity_digest_chirho,
            &driven_chirho.minted_chirho.receipt_ref_chirho,
            &driven_chirho
                .minted_chirho
                .canonical_obligation_digest_chirho,
            ROUTE_A_INVERSE_AUTHORITY_REF_CHIRHO,
            ROUTE_A_ACTION_IDEMPOTENCY_KEY_CHIRHO,
            &intent_line_chirho,
            &authorization_chirho,
        )
        .expect_err("with no durable head the compensation lane must not open");
    let refusal_text_chirho = format!("{refusal_chirho:?}");
    assert!(
        refusal_text_chirho.contains("refused the GD7 winner-side compensation append lane"),
        "the refusal must be the LANE's own evidence gate, not some upstream failure — otherwise \
         this arm is green without measuring the gate.\nrefusal: {refusal_text_chirho}"
    );
    assert!(
        refusal_text_chirho.contains("owns no durable GD7 winner handoff head"),
        "the lane must name the missing head specifically.\nrefusal: {refusal_text_chirho}"
    );
    assert_eq!(
        driven_chirho
            .winner_actor_chirho
            .effect_intent_cut_chirho()
            .expect("the winner keeps serving after the lane refusal")
            .tail_seq_chirho,
        driven_chirho.tail_seq_before_chirho,
        "a refused lane must append nothing"
    );
}

/// THE PHASE GATE: a `Preparing` handoff keeps the freeze WHOLE.
///
/// The head installed here is signed by the winner's OWN key through the same canonical encoding
/// production uses, so the signature check passes and the ONLY thing that can refuse this append is
/// the phase branch. That isolation is the point: a tampered-but-unsigned head would refuse on the
/// signature and leave the phase gate unmeasured while the arm looked green.
#[test]
fn winner_compensation_lane_refuses_a_preparing_phase_head_chirho() {
    let mut fixture_chirho = super::fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let driven_chirho =
        drive_to_open_winner_under_freeze_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);
    compose_on_the_winner_chirho(&driven_chirho);
    let (intent_line_chirho, authorization_chirho) =
        winner_compensation_authorization_chirho(&driven_chirho);

    install_winner_signed_preparing_head_chirho(&driven_chirho);

    let refusal_chirho = driven_chirho
        .winner_actor_chirho
        .complete_gd7_compensation_chirho(
            &driven_chirho.minted_chirho.mint_identity_digest_chirho,
            &driven_chirho.minted_chirho.receipt_ref_chirho,
            &driven_chirho
                .minted_chirho
                .canonical_obligation_digest_chirho,
            ROUTE_A_INVERSE_AUTHORITY_REF_CHIRHO,
            ROUTE_A_ACTION_IDEMPOTENCY_KEY_CHIRHO,
            &intent_line_chirho,
            &authorization_chirho,
        )
        .expect_err("a Preparing handoff must keep the compensation lane closed");
    let refusal_text_chirho = format!("{refusal_chirho:?}");
    assert!(
        refusal_text_chirho.contains("refused the GD7 winner-side compensation append lane"),
        "the refusal must be the lane's own gate.\nrefusal: {refusal_text_chirho}"
    );
    assert!(
        refusal_text_chirho.contains("not accepted"),
        "the lane must refuse for the PHASE specifically. A signature or malformed-head refusal \
         here would mean the re-signed fixture did not reproduce production's canonical encoding, \
         so the phase branch was never reached.\nrefusal: {refusal_text_chirho}"
    );
    assert!(
        !refusal_text_chirho.contains("Signature"),
        "a signature refusal means this arm stopped isolating the phase gate.\nrefusal: \
         {refusal_text_chirho}"
    );
    assert_eq!(
        driven_chirho
            .winner_actor_chirho
            .effect_intent_cut_chirho()
            .expect("the winner keeps serving after the phase refusal")
            .tail_seq_chirho,
        driven_chirho.tail_seq_before_chirho,
        "a Preparing-phase refusal must append nothing"
    );
}

/// The winner's own durable handoff head file, at production's own derived path.
fn winner_handoff_head_file_chirho(
    driven_chirho: &WinnerCompensationWorldChirho,
) -> std::path::PathBuf {
    let head_path_chirho = gd7_winner_handoff_head_path_chirho(
        &driven_chirho.minted_chirho.world_chirho.group_digest_chirho,
        &driven_chirho
            .minted_chirho
            .world_chirho
            .winner_node_chirho
            .0,
    )
    .expect("derive the fixed winner-handoff head path");
    driven_chirho
        .minted_chirho
        .world_chirho
        .winner_source_root_chirho
        .join(head_path_chirho.key_chirho())
}

/// Replace the winner's durable Accepted head with a genuinely winner-signed `Preparing` one.
///
/// Built through the production types, the production canonical encoding (`serde_json::to_vec` over
/// the same structs), the production path derivation, and the WINNER'S OWN signing key opened from
/// its own root custody. It is a NEGATIVE control — an object designed to be refused — so building
/// it with real authority is what makes the refusal attributable to the phase branch rather than to
/// a broken signature.
fn install_winner_signed_preparing_head_chirho(driven_chirho: &WinnerCompensationWorldChirho) {
    let winner_root_chirho = &driven_chirho
        .minted_chirho
        .world_chirho
        .winner_source_root_chirho;
    let signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
        winner_root_chirho,
        &driven_chirho.minted_chirho.world_chirho.winner_node_chirho,
    )
    .expect("the winner root carries its own GD7 signing custody");
    let sign_canonical_chirho = |unsigned_chirho: &str| {
        signer_chirho
            .sign_chirho(unsigned_chirho)
            .expect("the winner signs its own handoff objects")
    };

    let head_file_chirho = winner_handoff_head_file_chirho(driven_chirho);
    let accepted_head_chirho: Gd7WinnerHandoffHeadChirho = serde_json::from_slice(
        &std::fs::read(&head_file_chirho).expect("read the winner's durable accepted head"),
    )
    .expect("the durable head parses through the public type");
    let checkpoint_file_chirho = winner_root_chirho.join(
        gd7_winner_handoff_checkpoint_path_chirho(
            &accepted_head_chirho.active_checkpoint_ref_chirho,
        )
        .expect("derive the accepted checkpoint path")
        .key_chirho(),
    );
    let mut preparing_checkpoint_chirho: Gd7WinnerHandoffCheckpointChirho = serde_json::from_slice(
        &std::fs::read(&checkpoint_file_chirho).expect("read the durable accepted checkpoint"),
    )
    .expect("the durable checkpoint parses through the public type");
    assert_eq!(
        preparing_checkpoint_chirho.phase_chirho,
        Gd7WinnerHandoffPhaseChirho::AcceptedChirho,
        "this helper must start from a genuinely ACCEPTED checkpoint, or the arm it serves proves \
         nothing about moving away from accepted"
    );

    // Only the phase moves. Every other field stays the winner's own, so the object differs from
    // the durable one in exactly the dimension under test.
    preparing_checkpoint_chirho.phase_chirho = Gd7WinnerHandoffPhaseChirho::PreparingChirho;
    preparing_checkpoint_chirho.accepting_process_generation_chirho = None;
    preparing_checkpoint_chirho.sig_chirho = String::new();
    preparing_checkpoint_chirho.key_id_chirho = signer_chirho.key_id_chirho();
    let unsigned_checkpoint_chirho = serde_json::to_string(&preparing_checkpoint_chirho)
        .expect("the unsigned checkpoint encodes canonically");
    preparing_checkpoint_chirho.sig_chirho = sign_canonical_chirho(&unsigned_checkpoint_chirho);
    let checkpoint_bytes_chirho = serde_json::to_vec(&preparing_checkpoint_chirho)
        .expect("the signed checkpoint encodes canonically");
    let checkpoint_ref_chirho = blake3::hash(&checkpoint_bytes_chirho).to_hex().to_string();
    let preparing_checkpoint_file_chirho = winner_root_chirho.join(
        gd7_winner_handoff_checkpoint_path_chirho(&checkpoint_ref_chirho)
            .expect("derive the preparing checkpoint path")
            .key_chirho(),
    );
    std::fs::create_dir_all(
        preparing_checkpoint_file_chirho
            .parent()
            .expect("checkpoint paths are nested"),
    )
    .expect("create the preparing checkpoint directory");
    std::fs::write(&preparing_checkpoint_file_chirho, &checkpoint_bytes_chirho)
        .expect("write the winner-signed preparing checkpoint");

    let mut preparing_head_chirho = accepted_head_chirho;
    preparing_head_chirho.active_checkpoint_ref_chirho = checkpoint_ref_chirho;
    preparing_head_chirho.phase_chirho = Gd7WinnerHandoffPhaseChirho::PreparingChirho;
    preparing_head_chirho.sig_chirho = String::new();
    preparing_head_chirho.key_id_chirho = signer_chirho.key_id_chirho();
    let unsigned_head_chirho = serde_json::to_string(&preparing_head_chirho)
        .expect("the unsigned head encodes canonically");
    preparing_head_chirho.sig_chirho = sign_canonical_chirho(&unsigned_head_chirho);
    std::fs::write(
        &head_file_chirho,
        serde_json::to_vec(&preparing_head_chirho).expect("the signed head encodes canonically"),
    )
    .expect("install the winner-signed preparing head");
}

/// THE REVIEWER-CHOSEN ARM (claude_chirho, review of `a4f37992`/`69cf02ea`): this brick's `pub`
/// widening made `InDoubtChirho` constructible by a supplied provider for the FIRST time, and the
/// branch consuming it had never executed anywhere in the tree. In-doubt is the dangerous
/// settlement outcome — the external side may have moved and cairn does not know — so the ONLY
/// lawful landing is the operator hold: never an observation, never a receipt.
#[test]
fn route_a_in_doubt_provider_lands_held_manual_never_observed_chirho() {
    let mut fixture_chirho = super::fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let minted_chirho =
        drive_to_minted_obligation_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);

    let executions_chirho = Arc::new(AtomicU8::new(0));
    let actor_chirho = open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho(
        &minted_chirho.state_chirho.canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &minted_chirho.state_chirho.ledger_config_chirho,
        None,
        Box::new(InDoubtReportingProviderChirho {
            executions_chirho: Arc::clone(&executions_chirho),
        }),
    )
    .expect("the capstone door admits the in-doubt provider through the same custody checks");
    let cut_before_chirho = actor_chirho
        .effect_intent_cut_chirho()
        .expect("the live actor answers a verified-view command before the wire command");

    let held_chirho = actor_chirho
        .compose_gd7_compensation_chirho(
            &minted_chirho.mint_identity_digest_chirho,
            &minted_chirho.receipt_ref_chirho,
            &minted_chirho.canonical_obligation_digest_chirho,
            ROUTE_A_INVERSE_AUTHORITY_REF_CHIRHO,
            ROUTE_A_ACTION_IDEMPOTENCY_KEY_CHIRHO,
            ROUTE_A_BOUNDED_PAYLOAD_CHIRHO,
        )
        .expect(
            "an in-doubt observation is a lawful composition OUTCOME — the machine records the \
             operator hold rather than refusing the wire call",
        );
    assert_eq!(
        held_chirho.terminal_progress_chirho(),
        Gd7ObligationTerminalProgressChirho::HeldManualChirho,
        "an in-doubt settlement must land HELD-MANUAL — stop trying, and hold it for an operator \
         whose authority is roster-checked at read time"
    );
    assert_ne!(
        held_chirho.terminal_progress_chirho(),
        Gd7ObligationTerminalProgressChirho::ProviderObservedChirho,
        "in-doubt must NEVER present as observed — that would assert an outcome nobody observed"
    );
    assert_eq!(
        held_chirho.provider_observation_ref_chirho(),
        None,
        "no observation may be recorded from an in-doubt outcome"
    );
    assert_eq!(
        held_chirho.journal_receipt_ref_chirho(),
        None,
        "no receipt may ever bind to an obligation whose external settlement is unknown"
    );
    assert_eq!(
        executions_chirho.load(Ordering::SeqCst),
        1,
        "the provider executed exactly once against the persisted idempotency-keyed intent"
    );
    assert_eq!(
        actor_chirho
            .effect_intent_cut_chirho()
            .expect("the actor keeps serving after the in-doubt composition")
            .tail_seq_chirho,
        cut_before_chirho.tail_seq_chirho,
        "an in-doubt composition writes obligation state, never a journal record"
    );

    // DURABILITY, from the root's own storage rather than the reply channel.
    drop(actor_chirho);
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(
        &minted_chirho.state_chirho.canonical_root_chirho,
    )
    .expect("the held root's own storage opens");
    let durable_chirho = load_gd7_obligation_processing_state_chirho(
        &storage_chirho,
        &minted_chirho.mint_identity_digest_chirho,
    )
    .expect("the held row is durable");
    assert_eq!(
        durable_chirho.terminal_progress_chirho(),
        Gd7ObligationTerminalProgressChirho::HeldManualChirho,
        "the operator hold must be durable state, not a reply-channel artifact"
    );
    assert_eq!(
        durable_chirho.held_manual_classification_chirho(),
        Some(Gd7HeldManualClassificationChirho::HeldManualOpenChirho),
        "held-but-undisposed is OPEN — an operator decision is still owed"
    );
}

/// Replace the winner's durable Accepted head with a winner-signed Accepted head for a DIVERGENT
/// attempt.
///
/// The forged pair is everything the store checks FOR: parsed through the production types, signed
/// by the winner's own key through the production canonical encoding, internally consistent (the
/// head's attempt digest is recomputed from the divergent checkpoint through production's own
/// derivation, the checkpoint ref is the checkpoint bytes' real blake3, phase and transition seq
/// agree), and phase ACCEPTED. It differs from the live attempt in exactly ONE dimension: the
/// attempt identity, moved by replacing `challenge_digest_chirho`. Group, winner node, held
/// transfer refs, and every other coordinate stay the winner's own. What its first run measured:
/// even this much consistency is NOT enough to reach the elector — the checkpoint's canonical
/// challenge object still binds the original attempt, and the store refuses the divergence there.
fn install_winner_signed_divergent_accepted_head_chirho(
    driven_chirho: &WinnerCompensationWorldChirho,
) {
    let winner_root_chirho = &driven_chirho
        .minted_chirho
        .world_chirho
        .winner_source_root_chirho;
    let signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
        winner_root_chirho,
        &driven_chirho.minted_chirho.world_chirho.winner_node_chirho,
    )
    .expect("the winner root carries its own GD7 signing custody");
    let sign_canonical_chirho = |unsigned_chirho: &str| {
        signer_chirho
            .sign_chirho(unsigned_chirho)
            .expect("the winner signs its own handoff objects")
    };

    let head_file_chirho = winner_handoff_head_file_chirho(driven_chirho);
    let accepted_head_chirho: Gd7WinnerHandoffHeadChirho = serde_json::from_slice(
        &std::fs::read(&head_file_chirho).expect("read the winner's durable accepted head"),
    )
    .expect("the durable head parses through the public type");
    let checkpoint_file_chirho = winner_root_chirho.join(
        gd7_winner_handoff_checkpoint_path_chirho(
            &accepted_head_chirho.active_checkpoint_ref_chirho,
        )
        .expect("derive the accepted checkpoint path")
        .key_chirho(),
    );
    let mut divergent_checkpoint_chirho: Gd7WinnerHandoffCheckpointChirho = serde_json::from_slice(
        &std::fs::read(&checkpoint_file_chirho).expect("read the durable accepted checkpoint"),
    )
    .expect("the durable checkpoint parses through the public type");
    assert_eq!(
        divergent_checkpoint_chirho.phase_chirho,
        Gd7WinnerHandoffPhaseChirho::AcceptedChirho,
        "this helper must start from a genuinely ACCEPTED checkpoint, or the arm it serves proves \
         nothing about a divergent-but-accepted head"
    );

    // Only the attempt identity moves, and inside it only the challenge digest — the one field
    // whose change makes this a DIFFERENT attempt without touching any other coordinate.
    let divergent_challenge_chirho = blake3::hash(b"claude2-divergent-attempt-challenge-chirho")
        .to_hex()
        .to_string();
    assert_ne!(
        divergent_checkpoint_chirho
            .attempt_identity_chirho
            .challenge_digest_chirho,
        divergent_challenge_chirho,
        "the divergent challenge must actually differ, or nothing was forged"
    );
    divergent_checkpoint_chirho
        .attempt_identity_chirho
        .challenge_digest_chirho = divergent_challenge_chirho;
    let divergent_attempt_digest_chirho = gd7_winner_handoff_attempt_digest_chirho(
        &divergent_checkpoint_chirho.attempt_identity_chirho,
    )
    .expect("production's own derivation digests the divergent attempt identity");
    assert_ne!(
        divergent_attempt_digest_chirho, accepted_head_chirho.attempt_digest_chirho,
        "the divergent attempt digest must differ from the live attempt's, or the arm would drive \
         the elector with the digest it already holds and measure nothing"
    );
    divergent_checkpoint_chirho.sig_chirho = String::new();
    divergent_checkpoint_chirho.key_id_chirho = signer_chirho.key_id_chirho();
    let unsigned_checkpoint_chirho = serde_json::to_string(&divergent_checkpoint_chirho)
        .expect("the unsigned checkpoint encodes canonically");
    divergent_checkpoint_chirho.sig_chirho = sign_canonical_chirho(&unsigned_checkpoint_chirho);
    let checkpoint_bytes_chirho = serde_json::to_vec(&divergent_checkpoint_chirho)
        .expect("the signed checkpoint encodes canonically");
    let checkpoint_ref_chirho = blake3::hash(&checkpoint_bytes_chirho).to_hex().to_string();
    let divergent_checkpoint_file_chirho = winner_root_chirho.join(
        gd7_winner_handoff_checkpoint_path_chirho(&checkpoint_ref_chirho)
            .expect("derive the divergent checkpoint path")
            .key_chirho(),
    );
    std::fs::create_dir_all(
        divergent_checkpoint_file_chirho
            .parent()
            .expect("checkpoint paths are nested"),
    )
    .expect("create the divergent checkpoint directory");
    std::fs::write(&divergent_checkpoint_file_chirho, &checkpoint_bytes_chirho)
        .expect("write the winner-signed divergent checkpoint");

    let mut divergent_head_chirho = accepted_head_chirho;
    divergent_head_chirho.attempt_digest_chirho = divergent_attempt_digest_chirho;
    divergent_head_chirho.active_checkpoint_ref_chirho = checkpoint_ref_chirho;
    divergent_head_chirho.sig_chirho = String::new();
    divergent_head_chirho.key_id_chirho = signer_chirho.key_id_chirho();
    let unsigned_head_chirho = serde_json::to_string(&divergent_head_chirho)
        .expect("the unsigned head encodes canonically");
    divergent_head_chirho.sig_chirho = sign_canonical_chirho(&unsigned_head_chirho);
    std::fs::write(
        &head_file_chirho,
        serde_json::to_vec(&divergent_head_chirho).expect("the signed head encodes canonically"),
    )
    .expect("install the winner-signed divergent accepted head");
}

/// THE REVIEWER-CHOSEN ARM (claude2_chirho, review of `604a98ce`): tamper the ATTEMPT IDENTITY of
/// a winner-signed, head-consistent, genuinely ACCEPTED handoff. The no-head arm proves the lane
/// needs durable evidence; the Preparing arm proves the phase branch; this arm was aimed at the
/// elector's exact-attempt gate — and what it MEASURED is one gate earlier and one binding deeper.
///
/// WHAT THIS ARM MEASURED, corrected against its first run rather than against its intent: the
/// tampered head never REACHES the elector. The store's load validates the attempt identity's
/// challenge digest against the checkpoint's own canonical challenge object — which is itself
/// cross-bound to the transfer identity and to the winner-signed inspection — so a mutated
/// `challenge_digest_chirho` refuses at the STORE with "GD7 winner-handoff challenge is invalid",
/// surfaced as the lane's own refusal. The four-gate enumeration in the seam's comment therefore
/// under-counts in the safe direction: the "store that would not open" clause is a whole bound
/// chain (head sig -> checkpoint sig -> challenge digest -> transfer identity -> winner-signed
/// inspection), and a divergent attempt cannot be forged without re-deriving all of it under the
/// winner's key. This arm pins that binding — the gate no other arm measures.
///
/// Gate 3 itself — the elector's exact-attempt marker comparison — is measured directly at its own
/// layer by `handoff_fence_tests_chirho::active_handoff_append_lane_admits_only_the_exact_active_
/// attempt_chirho` (reviewer-authored, same review), because a world-level divergent head that
/// PASSES the store's challenge chain would require re-deriving that entire chain in a fixture —
/// re-implementing production's construction — which this file deliberately refuses to do.
///
/// MUTATION-PROVEN at review (claude2_chirho): dropping the store's challenge-digest comparison
/// made this tampered head pass the store — and the ELECTOR then refused it ("attempt differs from
/// the active attempt"), turning this arm red at its lane-gate assertion. One mutation, two facts:
/// this arm really pins the challenge binding, and gate 3 backstops it exactly as the
/// defense-in-depth story claims.
#[test]
fn winner_compensation_lane_refuses_a_tampered_attempt_identity_head_chirho() {
    let mut fixture_chirho = super::fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let driven_chirho =
        drive_to_open_winner_under_freeze_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);
    compose_on_the_winner_chirho(&driven_chirho);
    let (intent_line_chirho, authorization_chirho) =
        winner_compensation_authorization_chirho(&driven_chirho);

    install_winner_signed_divergent_accepted_head_chirho(&driven_chirho);

    let refusal_chirho = driven_chirho
        .winner_actor_chirho
        .complete_gd7_compensation_chirho(
            &driven_chirho.minted_chirho.mint_identity_digest_chirho,
            &driven_chirho.minted_chirho.receipt_ref_chirho,
            &driven_chirho
                .minted_chirho
                .canonical_obligation_digest_chirho,
            ROUTE_A_INVERSE_AUTHORITY_REF_CHIRHO,
            ROUTE_A_ACTION_IDEMPOTENCY_KEY_CHIRHO,
            &intent_line_chirho,
            &authorization_chirho,
        )
        .expect_err(
            "a tampered attempt identity must not open the compensation lane; an Ok here means an \
             append ran under handoff evidence whose challenge binding never verified",
        );
    let refusal_text_chirho = format!("{refusal_chirho:?}");
    assert!(
        matches!(
            &refusal_chirho,
            Gd7CompensationCompletionRefusalChirho::JournalAppendRefusedChirho { .. }
        ),
        "the tampered-head refusal must be the append family.\nrefusal: {refusal_text_chirho}"
    );
    // The refusal must be the LANE's own evidence gate, and specifically the CHALLENGE BINDING —
    // the store caught the tamper before any later gate could.
    assert!(
        refusal_text_chirho.contains("refused the GD7 winner-side compensation append lane"),
        "the refusal must surface as the lane's own evidence gate.\nrefusal: {refusal_text_chirho}"
    );
    assert!(
        refusal_text_chirho.contains("challenge is invalid"),
        "the store's challenge binding must be what refuses a tampered attempt identity; the \
         elector's mismatch here instead would mean the store stopped validating the challenge \
         chain and gate 3 became the only defense.\nrefusal: {refusal_text_chirho}"
    );
    assert!(
        !refusal_text_chirho.contains("UnseenWinnerTermChirho"),
        "the append must never reach the sink-term fence under tampered evidence.\nrefusal: \
         {refusal_text_chirho}"
    );
    assert!(
        !refusal_text_chirho.contains("frozen by an active GD7 winner handoff"),
        "a freeze refusal here means the compensation lane never reached the seam — the arm \
         stopped measuring the evidence chain.\nrefusal: {refusal_text_chirho}"
    );

    assert_eq!(
        driven_chirho
            .winner_actor_chirho
            .effect_intent_cut_chirho()
            .expect("the winner keeps serving after the mismatch refusal")
            .tail_seq_chirho,
        driven_chirho.tail_seq_before_chirho,
        "a challenge-binding refusal must append nothing"
    );
    let winner_storage_chirho = FsLedgerStorageChirho::open_existing_chirho(
        &driven_chirho
            .minted_chirho
            .world_chirho
            .winner_source_root_chirho,
    )
    .expect("the winner root's own storage opens");
    let durable_chirho = load_gd7_obligation_processing_state_chirho(
        &winner_storage_chirho,
        &driven_chirho.minted_chirho.mint_identity_digest_chirho,
    )
    .expect("the winner's obligation row is durable");
    assert_eq!(
        durable_chirho.terminal_progress_chirho(),
        Gd7ObligationTerminalProgressChirho::ProviderObservedChirho,
        "the obligation must remain PROVIDER-OBSERVED — a divergent head must not move terminal \
         state"
    );
    assert!(
        durable_chirho.journal_receipt_ref_chirho().is_none(),
        "no receipt may bind when no record was written"
    );
    assert_eq!(
        driven_chirho.executions_chirho.load(Ordering::SeqCst),
        1,
        "the provider's one execution belongs to the composition alone"
    );
}
