// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Item 6.4's local full-chain drill: the real two-root world carried past the compensated terminal.
//!
//! # WHAT THIS MODULE IS FOR
//!
//! Item 5 proved the compensated TERMINAL (route (a) reaches `CompletedChirho`, the receipt binds
//! the winner's new tail, replay owes no second append). It DEFERRED two things to 6.4: convergence
//! over the REAL compensated row, and crash/restart after the committed append. This module does
//! that deferred work, on top of item 5's path rather than beside it.
//!
//! # REUSE IS THE ANTI-REASSEMBLY MOVE HERE, NOT A SHORTCUT
//!
//! Every world-building call below comes from `harness1_compensated_terminal_arms_chirho` and
//! `harness1_gd7_world_chirho`. Rebuilding that path locally would produce a chain that LOOKS like
//! production's and proves the test's composition instead — the trap item 6.2's cut 4 fell into and
//! this brick is explicitly forbidden to repeat. So: real opener, real actor, real completing
//! provider, real wire methods.
//!
//! # THE COMPOSED CHAIN LIVES HERE ONCE; THE PROPERTIES STAND ON IT (item 6.4, recon:245-249)
//!
//! `route_a_release_lifts_the_hold_only_on_a_verified_convergence_certificate_chirho` IS the "one
//! local drill" recon:248 asks for: real two-root world -> completing provider -> `CompletedChirho`
//! receipt -> convergence over the REAL compensated row -> RELEASE. The Brick-D arms below do NOT
//! rebuild that chain; they reuse its two composition helpers
//! (`drive_to_open_winner_under_freeze_chirho`, `drive_to_imported_convergence_certificate_chirho`)
//! and assert the recon:249 properties ON it:
//!
//!   - `route_a_after_release_former_owner_stays_held_and_losing_evidence_stays_reachable_chirho`
//!     proves the two recon:249 outcomes past the release — the deposed FORMER OWNER remains unable
//!     to write, and the LOSING FORK EVIDENCE stays immutable and reachable.
//!   - `route_a_release_admits_only_its_exact_subject_cut_chirho` is cut-1(ii)'s exact-subject arm:
//!     the release barrier admits ONLY the exact adopted cut its certificate certifies.
//!
//! # THE CRASH MATRIX IS INHERITED, CITED BY NAME, NOT REDRIVEN (ruling 3, no-reassembly)
//!
//! The six item-6 durable cuts (recon:154-160) are proven at unit scale by arms already on main;
//! re-driving them here as regenesis fixtures would prove this test's composition, not the property.
//! So they are CITED, not rebuilt:
//!
//!   - cut 1 (losing effect durable + ACK, before disconnect): NO WINDOW — one atomic append, the
//!     ACK is the return value, not a second write (durability-bridge matrix, `store_chirho`).
//!   - cut 2 (adoption checkpoint written, head not moved):
//!     `reconciliation_store_durability_arms_chirho::
//!     a_crash_between_the_checkpoint_object_and_the_head_resumes_idempotently_chirho`.
//!   - cut 3 (provider observation durable, before the append):
//!     `gd7_completed_leg_chirho::a_crash_before_the_observation_write_resumes_forward_chirho`.
//!   - cut 4 (append committed, receipt/Completed not yet bound):
//!     `gd7_completed_leg_chirho::replay_owes_no_second_append_and_cannot_rebind_the_receipt_chirho`,
//!     and on the winner side the exact-replay assertions in
//!     `harness1_compensated_terminal_arms_chirho::
//!     route_a_winner_reaches_completed_after_the_winner_own_term_cell_advance_chirho`.
//!   - cut 5 (`CompletedChirho` durable, before convergence):
//!     `gd7_completed_leg_chirho::a_completed_row_replays_idempotently_and_adds_no_durable_write_chirho`,
//!     with the whole observed -> Completed sweep in
//!     `gd7_completed_leg_chirho::every_durable_boundary_of_the_completion_drive_recovers_to_one_receipt_chirho`.
//!   - cut 6 (convergence certificate durable, before hold release): the NET-NEW Brick-R arm in this
//!     file, `route_a_release_survives_a_crash_before_and_after_the_head_removal_chirho`, plus the
//!     narrow remove-idempotency arms in `gd7_completed_leg_chirho`.

use super::harness1_compensated_terminal_arms_chirho::{
    compose_on_the_winner_chirho, drive_to_open_winner_under_freeze_chirho,
    winner_compensation_authorization_chirho, WinnerCompensationWorldChirho,
    ROUTE_A_ACTION_IDEMPOTENCY_KEY_CHIRHO, ROUTE_A_INVERSE_AUTHORITY_REF_CHIRHO,
};
use cairn_effect_commit_chirho::coordinator_chirho::{
    EffectCommitJournalPortChirho, EffectCommitJournalViewPortChirho,
};
use cairn_effect_commit_chirho::intent_chirho::{
    canonical_effect_intent_line_chirho, sign_effect_intent_chirho, EffectIntentChirho,
    EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_host_chirho::reconciliation_chirho::{
    gd7_reconciliation_checkpoint_path_chirho, gd7_reconciliation_group_has_any_active_hold_chirho,
    gd7_reconciliation_group_head_path_chirho,
    gd7_reconciliation_group_ordinary_writes_withheld_chirho,
    load_gd7_obligation_processing_state_chirho, ConvergedReadReplicaChirho,
    Gd7ConvergenceBindingInputChirho, Gd7ConvergenceUnmeasuredPredicatesChirho,
    Gd7ObligationProcessingRefusalChirho, Gd7ObligationTerminalProgressChirho,
    Gd7PlanRefusalChirho, Gd7WinnerWitnessReaderChirho, PinnedNodeGd7VerifierChirho,
};
use cairn_ledger_host_chirho::{
    host_ledger_signer_refs_from_config_chirho, open_resident_effect_journal_handle_chirho,
    FsLedgerStorageChirho, HostLedgerSignersChirho,
};
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::AttributionChirho;
use cairn_ledger_model_chirho::wire_chirho::stored_line_digest_chirho;
use cairn_ledger_model_chirho::LogIdChirho;
use std::sync::Arc;

/// STAND-UP CHECK: the reused item-5 path really does deliver a compensated row to this module.
///
/// This asserts nothing new about the engine — item 5 already proved the terminal, and re-proving it
/// here would be duplication. What it pins is that the REUSE works from a sibling module: if the
/// widened `pub(super)` surface or the world builders drift, this fails first and cheaply, before
/// the convergence and crash/restart arms that depend on standing this row up.
#[test]
fn the_reused_item5_path_delivers_a_real_compensated_row_chirho() {
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
            "the reused item-5 winner-side path must reach the compensated terminal; a refusal here \
             is a REUSE failure (widened surface or world builder drift), not a 6.4 finding — read \
             the refusal name against item 5's arms before treating it as this brick's problem",
        );

    assert_eq!(
        completed_chirho.terminal_progress_chirho(),
        Gd7ObligationTerminalProgressChirho::CompletedChirho,
        "the row this module's later arms converge over must actually be COMPLETED; anything else \
         means the arms would be measuring a state item 5 did not produce"
    );
    assert!(
        completed_chirho.journal_receipt_ref_chirho().is_some(),
        "a compensated terminal carries its journal receipt — convergence classifies on the durable \
         row, so a receipt-less row would make the convergence arm measure the wrong thing"
    );
    assert_eq!(
        driven_chirho
            .executions_chirho
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "exactly one provider execution stood this row up; a second would mean the reused path \
         double-executed and every count this module later asserts would inherit that error"
    );
}

/// Item 6.4's convergence arm, COMPLETED (Shape A'): the honest held converger now CERTIFIES over the
/// REAL compensated row, once the winner's own signed compensation receipt is imported into the held
/// root through the production write-side caller.
///
/// # THE PATH — refuse before, certify after
///
/// Item 5's compensated terminal lands, by ruled (a), on the LIVE WINNER's own root: after the
/// foundation drives the row to `CompletedChirho`, the durable obligation-processing row is on the
/// WINNER root (asserted below) and ABSENT from the held root. The held converger reads only held
/// storage, so BEFORE any import it classifies the obligation OPEN and refuses
/// `UnconvergedObligationChirho(<the real mint identity>)` — the non-vacuity control, and the same
/// refusal this arm used to pin as its cross-root frontier.
///
/// Shape A' closes the gap without giving the held converger live winner-journal access. The winner's
/// compensation record is a REAL line EXTRACTED from the winner journal — the exact record the durable
/// row's receipt ref names, found by content digest, never a fabricated one. The production write-side
/// caller `import_converged_compensation_receipt_gd7_chirho` re-verifies that transferred line with the
/// held node's OWN authority (the config-pinned journal verifier the winner fork witness also uses — no
/// winner key) and persists a held-signed converged-import row. AFTER that import the SAME held
/// converger certifies over the SAME single obligation: `completed_count == population`,
/// `disposed_count == 0`.
///
/// # MIGRATION PATH — what each future change MEANS
///
///   - If the AFTER-import call stops CERTIFYING, the write-side caller or the classify consult path
///     regressed — read the new refusal; a fabricated/empty-population certificate must NOT satisfy it.
///   - If the BEFORE-import call stops refusing `UnconvergedObligationChirho` naming the real mint
///     identity, either the A -> S coordinate resolution regressed or an import row leaked in before
///     the caller ran; read the new outcome before loosening anything.
///   - If the imported receipt digest stops equaling the winner row's `journal_receipt_ref`, the
///     extraction picked the wrong winner record or the mover bound the wrong digest.
#[test]
fn route_a_compensated_row_convergence_certifies_over_the_imported_winner_receipt_chirho() {
    // ---- FOUNDATION: the reused item-5 winner-side path to a REAL compensated terminal ----
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
            "the reused item-5 winner-side path must reach the compensated terminal; a refusal here \
             is a REUSE failure (widened surface or world-builder drift), not a 6.4 finding",
        );
    assert_eq!(
        completed_chirho.terminal_progress_chirho(),
        Gd7ObligationTerminalProgressChirho::CompletedChirho,
        "convergence's subject must be a real COMPLETED compensation, not any earlier state"
    );

    let state_chirho = &driven_chirho.minted_chirho.state_chirho;
    let world_chirho = &driven_chirho.minted_chirho.world_chirho;
    let mint_identity_chirho = &driven_chirho.minted_chirho.mint_identity_digest_chirho;

    // ---- THE SPLIT, MEASURED: the compensated row is on the WINNER root, ABSENT on the HELD root ----
    //
    // This is the whole reason the honest converger below refuses. It is asserted, not narrated, so
    // that a future change which co-locates the row (the fix) fails this arm loudly at THIS line.
    let held_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&state_chirho.canonical_root_chirho)
            .expect("the held root's own storage opens");
    let winner_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&world_chirho.winner_source_root_chirho)
            .expect("the winner root's own storage opens");
    let winner_row_chirho =
        load_gd7_obligation_processing_state_chirho(&winner_storage_chirho, mint_identity_chirho)
            .expect("the winner root carries the durable compensated row");
    assert_eq!(
        winner_row_chirho.terminal_progress_chirho(),
        Gd7ObligationTerminalProgressChirho::CompletedChirho,
        "ruled (a) lands the compensated terminal on the WINNER root; without it there this arm has \
         no subject and the certification below would be green by emptiness"
    );
    assert!(
        matches!(
            load_gd7_obligation_processing_state_chirho(&held_storage_chirho, mint_identity_chirho),
            Err(Gd7ObligationProcessingRefusalChirho::MissingStateChirho)
        ),
        "the HELD root must carry NO processing row for this obligation — that exact absence is why \
         the held-side convergence classifier below reports it OPEN before the import"
    );

    // ---- THE REAL OBSERVATION, from the held root (verbatim reuse of the frontier arm's path) ----
    //
    // `load_` (never `import_`): this re-reads the signed witness objects REAL ADOPTION already
    // installed, rather than reassembling them from raw bytes.
    let signer_refs_chirho = host_ledger_signer_refs_from_config_chirho(
        &state_chirho.ledger_config_chirho.signer_secrets_chirho,
    )
    .expect("the adopted world's config names its signer secrets");
    let signers_chirho = HostLedgerSignersChirho::load_existing_chirho(
        &state_chirho.canonical_root_chirho,
        &signer_refs_chirho,
    )
    .expect("the adopted world carries all six runtime signers");
    let winner_verifier_chirho =
        PinnedNodeGd7VerifierChirho::new_chirho(world_chirho.winner_node_chirho.clone())
            .expect("the held side pins the winner by node id, holding no winner signing power");
    let provider_fixture_chirho = super::harness1_conservation_provider_tests_chirho::
        RegenesisGd7ConservationProviderChirho::from_fixture_chirho(&fixture_chirho);
    let verified_losing_tail_chirho = provider_fixture_chirho
        .verified_losing_tail_chirho()
        .expect("the public losing-journal reader verifies the exact current tail");
    let observation_chirho = Gd7WinnerWitnessReaderChirho::new_chirho(
        &held_storage_chirho,
        &winner_verifier_chirho,
        signers_chirho.journal_signer_chirho(),
    )
    .load_authenticated_deposed_fork_observation_chirho(
        &world_chirho.identity_chirho,
        &verified_losing_tail_chirho,
    )
    .expect("the public observation loader re-verifies the installed signed witness objects");

    // The binding now carries ONLY the state-verified `adopted_checkpoint_ref_chirho` (the world's
    // REAL adopted checkpoint). The losing-population digests and retained refs are no longer caller
    // inputs at all — the converger MEASURES the population and BINDS the retained refs from its own
    // verified proof, so the certificate's closed-population digest is measured, not asserted here.
    let binding_chirho = || Gd7ConvergenceBindingInputChirho {
        adopted_checkpoint_ref_chirho: state_chirho.adopted_checkpoint_ref_chirho.clone(),
    };

    // ---- EXTRACT the REAL winner compensation record line from the WINNER journal ----
    //
    // The compensated obligation's durable row names its receipt by the winner journal record's
    // stored-line digest. That record is a real line in the winner journal (the compensation
    // EscrowHold the winner appended at its own tail). Take the exact line whose digest is that
    // receipt ref: a self-verifying extraction — a wrong line could not match — and the held mover
    // RE-VERIFIES the line's winner signature, deterministic coordinate, and winner term before it
    // trusts it. This is the transferred object, not a live winner-journal read by the converger.
    let winner_receipt_ref_chirho = winner_row_chirho
        .journal_receipt_ref_chirho()
        .expect("a compensated terminal binds its winner journal receipt")
        .to_owned();
    let winner_config_chirho = &world_chirho.winner_ledger_config_chirho;
    let winner_journal_file_chirho = world_chirho
        .winner_source_root_chirho
        .join(&winner_config_chirho.storage_namespace_chirho)
        .join(&winner_config_chirho.journal_path_chirho);
    let winner_journal_text_chirho = std::fs::read_to_string(&winner_journal_file_chirho)
        .expect("the winner journal file opens on the winner root");
    let winner_compensation_line_chirho = winner_journal_text_chirho
        .lines()
        .find(|line_chirho| {
            !line_chirho.trim().is_empty()
                && stored_line_digest_chirho(line_chirho).0 == winner_receipt_ref_chirho
        })
        .expect(
            "the winner journal contains the exact compensation record the durable row's receipt \
             ref names — a REAL extracted line, not a fabricated one",
        )
        .to_owned();

    // ---- The held actor: the reconciliation's own root, reopened WITH a conservation provider ----
    let conservation_provider_chirho = super::harness1_conservation_provider_tests_chirho::
        RegenesisGd7ConservationProviderChirho::from_fixture_chirho(&fixture_chirho);
    let held_actor_chirho = open_resident_effect_journal_handle_chirho(
        &state_chirho.canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &state_chirho.ledger_config_chirho,
        Some(Arc::new(conservation_provider_chirho)),
    )
    .expect("the held root reopens one resident actor with the injected conservation provider");

    // ---- BEFORE IMPORT (non-vacuity): the honest converger refuses, naming THIS obligation ----
    //
    // The held root carries NO row for the compensated obligation, so the classifier calls it OPEN.
    // The refusal must name the EXACT real mint identity (a wrong A -> S coordinate would derive a
    // different digest), which also proves the certificate below is not green by emptiness.
    let before_refusal_chirho = held_actor_chirho
        .converge_and_certify_gd7_chirho(
            &observation_chirho,
            &state_chirho.adopted_checkpoint_ref_chirho,
            binding_chirho(),
            Gd7ConvergenceUnmeasuredPredicatesChirho {
                winner_view_matches_chirho: true,
            },
        )
        .expect_err(
            "before the import the compensated obligation has no held-root evidence and is OPEN",
        );
    assert_eq!(
        before_refusal_chirho,
        Gd7PlanRefusalChirho::UnconvergedObligationChirho(mint_identity_chirho.clone()),
        "before import the converger must call open THIS obligation, by the digest it was minted \
         under; a different digest is a coordinate bug, a different variant a frontier change"
    );

    // ---- IMPORT the transferred winner receipt through the PRODUCTION write-side caller ----
    //
    // The held node re-verifies the transferred line with its own authority and persists a
    // held-signed converged-import row. The returned digest is DIGEST-EXACT: it must equal the
    // winner row's own receipt ref.
    let imported_receipt_digest_chirho = held_actor_chirho
        .import_converged_compensation_receipt_gd7_chirho(
            &observation_chirho,
            &state_chirho.adopted_checkpoint_ref_chirho,
            &winner_compensation_line_chirho,
        )
        .expect(
            "the transferred winner compensation receipt re-verifies and the held row persists",
        );
    assert_eq!(
        imported_receipt_digest_chirho, winner_receipt_ref_chirho,
        "the held-signed row must bind the winner record's exact stored-line digest — the same \
         receipt the winner's own durable row names"
    );

    // ---- AFTER IMPORT: the honest converger CERTIFIES over the same single obligation ----
    let certificate_chirho = held_actor_chirho
        .converge_and_certify_gd7_chirho(
            &observation_chirho,
            &state_chirho.adopted_checkpoint_ref_chirho,
            binding_chirho(),
            Gd7ConvergenceUnmeasuredPredicatesChirho {
                winner_view_matches_chirho: true,
            },
        )
        .expect("after importing the verified compensation receipt the honest converger certifies");
    assert_eq!(
        certificate_chirho.population_count_chirho(),
        1,
        "the certificate covers exactly the one obligation the arm converges over"
    );
    assert_eq!(
        certificate_chirho
            .verified_v2_counts_chirho()
            .expect("a signed v2 certificate"),
        (1, 0),
        "the imported obligation certifies as compensated: completed_count == population, \
         disposed == 0"
    );
}

/// Drive the reused item-5 winner path to a compensated terminal, import the winner's receipt into
/// the held root through the production write-side caller, and return the HONEST held-signed
/// convergence certificate the converger certifies over that imported row.
///
/// This is the exact path the convergence arm above walks to produce a real certificate; the release
/// arms below reuse it rather than rebuild the world. The held actor it opens is DROPPED before
/// returning, so the held root's writer lock is free for the release arm to reopen its own actor —
/// which also models the release running in a later process than the convergence.
fn drive_to_imported_convergence_certificate_chirho(
    driven_chirho: &WinnerCompensationWorldChirho,
    fixture_chirho: &super::RegenesisFixtureChirho,
) -> ConvergedReadReplicaChirho {
    compose_on_the_winner_chirho(driven_chirho);
    let (intent_line_chirho, authorization_chirho) =
        winner_compensation_authorization_chirho(driven_chirho);
    let completed_chirho = driven_chirho
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
        .expect("the reused item-5 winner-side path must reach the compensated terminal");
    assert_eq!(
        completed_chirho.terminal_progress_chirho(),
        Gd7ObligationTerminalProgressChirho::CompletedChirho,
        "the release arms' subject must be a real COMPLETED compensation"
    );

    let state_chirho = &driven_chirho.minted_chirho.state_chirho;
    let world_chirho = &driven_chirho.minted_chirho.world_chirho;
    let mint_identity_chirho = &driven_chirho.minted_chirho.mint_identity_digest_chirho;

    let winner_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&world_chirho.winner_source_root_chirho)
            .expect("the winner root's own storage opens");
    let winner_row_chirho =
        load_gd7_obligation_processing_state_chirho(&winner_storage_chirho, mint_identity_chirho)
            .expect("the winner root carries the durable compensated row");

    let held_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&state_chirho.canonical_root_chirho)
            .expect("the held root's own storage opens");
    let signer_refs_chirho = host_ledger_signer_refs_from_config_chirho(
        &state_chirho.ledger_config_chirho.signer_secrets_chirho,
    )
    .expect("the adopted world's config names its signer secrets");
    let signers_chirho = HostLedgerSignersChirho::load_existing_chirho(
        &state_chirho.canonical_root_chirho,
        &signer_refs_chirho,
    )
    .expect("the adopted world carries all six runtime signers");
    let winner_verifier_chirho =
        PinnedNodeGd7VerifierChirho::new_chirho(world_chirho.winner_node_chirho.clone())
            .expect("the held side pins the winner by node id");
    let provider_fixture_chirho = super::harness1_conservation_provider_tests_chirho::
        RegenesisGd7ConservationProviderChirho::from_fixture_chirho(fixture_chirho);
    let verified_losing_tail_chirho = provider_fixture_chirho
        .verified_losing_tail_chirho()
        .expect("the public losing-journal reader verifies the exact current tail");
    let observation_chirho = Gd7WinnerWitnessReaderChirho::new_chirho(
        &held_storage_chirho,
        &winner_verifier_chirho,
        signers_chirho.journal_signer_chirho(),
    )
    .load_authenticated_deposed_fork_observation_chirho(
        &world_chirho.identity_chirho,
        &verified_losing_tail_chirho,
    )
    .expect("the public observation loader re-verifies the installed signed witness objects");

    let winner_receipt_ref_chirho = winner_row_chirho
        .journal_receipt_ref_chirho()
        .expect("a compensated terminal binds its winner journal receipt")
        .to_owned();
    let winner_config_chirho = &world_chirho.winner_ledger_config_chirho;
    let winner_journal_file_chirho = world_chirho
        .winner_source_root_chirho
        .join(&winner_config_chirho.storage_namespace_chirho)
        .join(&winner_config_chirho.journal_path_chirho);
    let winner_journal_text_chirho = std::fs::read_to_string(&winner_journal_file_chirho)
        .expect("the winner journal file opens on the winner root");
    let winner_compensation_line_chirho = winner_journal_text_chirho
        .lines()
        .find(|line_chirho| {
            !line_chirho.trim().is_empty()
                && stored_line_digest_chirho(line_chirho).0 == winner_receipt_ref_chirho
        })
        .expect("the winner journal contains the exact compensation record the receipt ref names")
        .to_owned();

    let conservation_provider_chirho = super::harness1_conservation_provider_tests_chirho::
        RegenesisGd7ConservationProviderChirho::from_fixture_chirho(fixture_chirho);
    let held_actor_chirho = open_resident_effect_journal_handle_chirho(
        &state_chirho.canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &state_chirho.ledger_config_chirho,
        Some(Arc::new(conservation_provider_chirho)),
    )
    .expect("the held root reopens one resident actor with the injected conservation provider");
    let imported_receipt_digest_chirho = held_actor_chirho
        .import_converged_compensation_receipt_gd7_chirho(
            &observation_chirho,
            &state_chirho.adopted_checkpoint_ref_chirho,
            &winner_compensation_line_chirho,
        )
        .expect(
            "the transferred winner compensation receipt re-verifies and the held row persists",
        );
    assert_eq!(
        imported_receipt_digest_chirho, winner_receipt_ref_chirho,
        "the held-signed row binds the winner record's exact stored-line digest"
    );
    held_actor_chirho
        .converge_and_certify_gd7_chirho(
            &observation_chirho,
            &state_chirho.adopted_checkpoint_ref_chirho,
            Gd7ConvergenceBindingInputChirho {
                adopted_checkpoint_ref_chirho: state_chirho.adopted_checkpoint_ref_chirho.clone(),
            },
            Gd7ConvergenceUnmeasuredPredicatesChirho {
                winner_view_matches_chirho: true,
            },
        )
        .expect("after importing the verified compensation receipt the honest converger certifies")
    // held_actor_chirho drops here, freeing the held root's writer lock for the release arm.
}

/// RELEASE REQUIRES A VERIFIED CONVERGENCE CERTIFICATE — the money-authority acceptance arm.
///
/// Reuses the real imported-certificate path, then drives the hardened release door on the held root
/// three ways: a fabricated certificate cannot lift the hold (also the "no early / no unverified
/// release" property — before convergence certifies, no verifiable certificate exists), a tampered
/// honest certificate cannot, and only the real held-signed certificate does — superseding the active
/// head while RETAINING the adopted checkpoint object byte-for-byte (supersede, not erase).
///
/// MIGRATION PATH: if the fabricated or tampered release SUCCEEDS, the certificate signature binding
/// regressed and a forged certificate lifted the hold. If the honest release REFUSES, either the
/// convergence certificate stopped verifying against the held root's own verifier or the adopted-head
/// chain drifted; read the refusal.
#[test]
fn route_a_release_lifts_the_hold_only_on_a_verified_convergence_certificate_chirho() {
    let mut fixture_chirho = super::fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let driven_chirho =
        drive_to_open_winner_under_freeze_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);
    let certificate_chirho =
        drive_to_imported_convergence_certificate_chirho(&driven_chirho, &fixture_chirho);

    let state_chirho = &driven_chirho.minted_chirho.state_chirho;
    let world_chirho = &driven_chirho.minted_chirho.world_chirho;
    let group_digest_chirho = &world_chirho.identity_chirho.consistency_group_digest_chirho;
    let adopted_ref_chirho = &state_chirho.adopted_checkpoint_ref_chirho;
    let held_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&state_chirho.canonical_root_chirho)
            .expect("the held root's own storage opens");

    assert!(
        gd7_reconciliation_group_has_any_active_hold_chirho(
            &held_storage_chirho,
            group_digest_chirho
        )
        .expect("probe the hold before release"),
        "the adopted cut leaves the held group active-headed; without it every refusal below \
         measures an empty world"
    );
    let checkpoint_path_chirho = gd7_reconciliation_checkpoint_path_chirho(adopted_ref_chirho)
        .expect("derive the retained checkpoint path");
    let checkpoint_before_chirho = held_storage_chirho
        .read_all_chirho(&checkpoint_path_chirho)
        .expect("read the retained checkpoint before release")
        .expect("the retained checkpoint exists before release");
    let head_path_chirho = gd7_reconciliation_group_head_path_chirho(group_digest_chirho)
        .expect("derive the active head path");
    let head_before_chirho = held_storage_chirho
        .read_all_chirho(&head_path_chirho)
        .expect("read the active head before release")
        .expect("the active head exists before release");

    // A fabricated certificate: v2 shape, `checkpoint_ref` bound to the real adopted cut so the
    // cheap field-equality check passes, but a non-custody key id and a placeholder signature.
    let fabricated_certificate_chirho: ConvergedReadReplicaChirho =
        serde_json::from_value(serde_json::json!({
            "schema_chirho": "gd7-converged-read-replica-v2-chirho",
            "reconciliation_identity_digest_chirho":
                certificate_chirho.reconciliation_identity_digest_chirho(),
            "checkpoint_ref_chirho": adopted_ref_chirho,
            "sealed_plan_ref_chirho": "2".repeat(64),
            "winner_fork_witness_object_digest_chirho": "3".repeat(64),
            "winner_term_chirho": certificate_chirho.winner_term_chirho(),
            "adopted_checkpoint_ref_chirho": adopted_ref_chirho,
            "losing_population_identity_chirho": "3".repeat(64),
            "losing_population_digest_chirho": "4".repeat(64),
            "terminal_outcome_identity_chirho": "1".repeat(64),
            "terminal_outcome_digest_chirho": "5".repeat(64),
            "conservation_snapshot_digest_chirho": "6".repeat(64),
            "retained_refs_chirho": [],
            "population_count_chirho": 1,
            "completed_count_chirho": 1,
            "disposed_count_chirho": 0,
            "certificate_key_id_chirho": "drill-caller-built-not-custody-chirho",
            "certificate_sig_chirho": "7".repeat(128),
        }))
        .expect("the fabricated certificate deserializes through the public type");

    // A tampered HONEST certificate: one signed field flipped, so the held root's own signature no
    // longer covers the bytes even though the key id is genuinely the held root's.
    let mut tampered_value_chirho =
        serde_json::to_value(&certificate_chirho).expect("the honest certificate serializes");
    tampered_value_chirho["winner_term_chirho"] =
        serde_json::json!(certificate_chirho.winner_term_chirho() + 7);
    let tampered_certificate_chirho: ConvergedReadReplicaChirho =
        serde_json::from_value(tampered_value_chirho)
            .expect("the tampered certificate still deserializes");

    for (label_chirho, unverifiable_chirho) in [
        ("a fabricated certificate", &fabricated_certificate_chirho),
        (
            "a tampered honest certificate",
            &tampered_certificate_chirho,
        ),
    ] {
        let held_actor_chirho = open_resident_effect_journal_handle_chirho(
            &state_chirho.canonical_root_chirho,
            &fixture_chirho.config_path_chirho,
            &state_chirho.ledger_config_chirho,
            None,
        )
        .expect("the held root reopens a resident actor for the refused release");
        let refusal_chirho = held_actor_chirho
            .release_converged_gd7_hold_chirho(adopted_ref_chirho, unverifiable_chirho)
            .expect_err(&format!(
                "release must REFUSE {label_chirho}; a success means the certificate signature \
                 binding regressed and an unverifiable certificate lifted the hold"
            ));
        assert!(
            format!("{refusal_chirho:?}").contains("ConvergenceCertificateUnverifiedChirho"),
            "the refusal must name the certificate-verification barrier ({label_chirho}): \
             {refusal_chirho:?}"
        );
        drop(held_actor_chirho);
        assert!(
            gd7_reconciliation_group_has_any_active_hold_chirho(
                &held_storage_chirho,
                group_digest_chirho
            )
            .expect("probe the hold after a refused release"),
            "a refused release must leave the hold ACTIVE ({label_chirho})"
        );
        assert_eq!(
            held_storage_chirho
                .read_all_chirho(&head_path_chirho)
                .expect("read the active head after a refused release")
                .as_deref(),
            Some(head_before_chirho.as_slice()),
            "a refused release must leave the active head present and byte-unchanged \
             ({label_chirho})"
        );
    }

    // THE REAL RELEASE: the honest held-signed certificate supersedes the head.
    let releasing_actor_chirho = open_resident_effect_journal_handle_chirho(
        &state_chirho.canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &state_chirho.ledger_config_chirho,
        None,
    )
    .expect("the held root reopens a resident actor for the real release");
    releasing_actor_chirho
        .release_converged_gd7_hold_chirho(adopted_ref_chirho, &certificate_chirho)
        .expect("the honest held-signed convergence certificate releases the reconciliation hold");
    drop(releasing_actor_chirho);
    assert!(
        !gd7_reconciliation_group_has_any_active_hold_chirho(
            &held_storage_chirho,
            group_digest_chirho
        )
        .expect("probe the hold after the real release"),
        "the honest certificate supersedes the active head"
    );
    assert_eq!(
        held_storage_chirho
            .read_all_chirho(&checkpoint_path_chirho)
            .expect("read the retained checkpoint after release")
            .as_deref(),
        Some(checkpoint_before_chirho.as_slice()),
        "release supersedes the ref but RETAINS the immutable adopted checkpoint byte-for-byte"
    );
}

/// CUT-6 — the release survives a crash BEFORE and AFTER the head removal, on the real FS.
///
/// SimStorage cannot reach the real release fn (its writer-lock guard is the concrete
/// `FsLedgerStorageChirho` by design), so this is the STRONGER proof: real fn, real guard, real FS,
/// real drop/reopen across a process boundary. Two windows, and the SAFETY OUTCOME is asserted rather
/// than any refusal variant name (per ruling 5, the already-released case maps to a tracked-misnomer
/// variant, so the arm does not name it):
///   - crash BEFORE remove: the hold is active, the held actor is dropped before it releases, a fresh
///     actor reopens and releases — the head is removed once.
///   - crash AFTER remove: drop, reopen, release again — idempotent; the head stays absent and the
///     retained checkpoint stays byte-identical. EXACTLY ONE removal across crash and retry.
///
/// MIGRATION PATH: if the reopened release cannot remove the head, the release stopped being
/// crash-safe across a process boundary. If the retry re-removes or corrupts the retained checkpoint,
/// the idempotent / supersede-not-erase property regressed — a money defect.
#[test]
fn route_a_release_survives_a_crash_before_and_after_the_head_removal_chirho() {
    let mut fixture_chirho = super::fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let driven_chirho =
        drive_to_open_winner_under_freeze_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);
    let certificate_chirho =
        drive_to_imported_convergence_certificate_chirho(&driven_chirho, &fixture_chirho);

    let state_chirho = &driven_chirho.minted_chirho.state_chirho;
    let world_chirho = &driven_chirho.minted_chirho.world_chirho;
    let group_digest_chirho = &world_chirho.identity_chirho.consistency_group_digest_chirho;
    let adopted_ref_chirho = &state_chirho.adopted_checkpoint_ref_chirho;
    let held_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&state_chirho.canonical_root_chirho)
            .expect("the held root's own storage opens");
    let checkpoint_path_chirho = gd7_reconciliation_checkpoint_path_chirho(adopted_ref_chirho)
        .expect("derive the retained checkpoint path");
    let checkpoint_before_chirho = held_storage_chirho
        .read_all_chirho(&checkpoint_path_chirho)
        .expect("read the retained checkpoint before release")
        .expect("the retained checkpoint exists before release");

    let reopen_held_actor_chirho = || {
        open_resident_effect_journal_handle_chirho(
            &state_chirho.canonical_root_chirho,
            &fixture_chirho.config_path_chirho,
            &state_chirho.ledger_config_chirho,
            None,
        )
        .expect("the held root reopens a resident actor after a simulated crash")
    };

    // ---- CRASH BEFORE REMOVE ----
    assert!(
        gd7_reconciliation_group_has_any_active_hold_chirho(
            &held_storage_chirho,
            group_digest_chirho
        )
        .expect("probe the hold before the crash"),
        "the hold must be active before the crash-before-remove window"
    );
    let crashed_before_chirho = reopen_held_actor_chirho();
    drop(crashed_before_chirho); // crash: the process holding the hold dies before releasing
    assert!(
        gd7_reconciliation_group_has_any_active_hold_chirho(
            &held_storage_chirho,
            group_digest_chirho
        )
        .expect("probe the hold after the crash-before-remove"),
        "a crash before the release must leave the hold ACTIVE — nothing was removed yet"
    );

    // REOPEN and release: the head is removed exactly once.
    let recovering_actor_chirho = reopen_held_actor_chirho();
    recovering_actor_chirho
        .release_converged_gd7_hold_chirho(adopted_ref_chirho, &certificate_chirho)
        .expect("the reopened actor releases the hold on the honest certificate after the crash");
    drop(recovering_actor_chirho);
    assert!(
        !gd7_reconciliation_group_has_any_active_hold_chirho(
            &held_storage_chirho,
            group_digest_chirho
        )
        .expect("probe the hold after the recovering release"),
        "the reopened release supersedes the head"
    );
    assert_eq!(
        held_storage_chirho
            .read_all_chirho(&checkpoint_path_chirho)
            .expect("read the retained checkpoint after the recovering release")
            .as_deref(),
        Some(checkpoint_before_chirho.as_slice()),
        "the recovering release retains the immutable adopted checkpoint byte-for-byte"
    );

    // ---- CRASH AFTER REMOVE, then RETRY: idempotent, no second removal ----
    let crashed_after_chirho = reopen_held_actor_chirho();
    drop(crashed_after_chirho); // crash after the head was already removed
    let retry_actor_chirho = reopen_held_actor_chirho();
    // The head is already absent, so the retry does not release again. The SAFETY OUTCOME is what is
    // asserted — the retry must not re-remove or corrupt anything — never the (tracked-misnomer)
    // refusal variant of the already-released case.
    let _retry_chirho = retry_actor_chirho
        .release_converged_gd7_hold_chirho(adopted_ref_chirho, &certificate_chirho);
    drop(retry_actor_chirho);
    assert!(
        !gd7_reconciliation_group_has_any_active_hold_chirho(
            &held_storage_chirho,
            group_digest_chirho
        )
        .expect("probe the hold after the idempotent retry"),
        "the head stays absent after the retry — exactly one removal across crash and retry"
    );
    assert_eq!(
        held_storage_chirho
            .read_all_chirho(&checkpoint_path_chirho)
            .expect("read the retained checkpoint after the idempotent retry")
            .as_deref(),
        Some(checkpoint_before_chirho.as_slice()),
        "the retry must not re-remove or corrupt the retained checkpoint — supersede-not-erase holds \
         across the crash and the retry"
    );
}

/// Drive one ORDINARY effect append on the former owner's OWN root and return the refusal text.
///
/// The former owner (the deposed/held node, `canonical_root_chirho`) self-elects a single-node
/// writer through the plain opener — the SAME composition the deposed-side completion arm reaches
/// the append funnel through — so a refusal here is the funnel's own barrier, not a missing lease.
/// The intent is a well-formed ordinary spend signed by the former owner's OWN effect-intent signer
/// against the live actor's own cut, so it PARSES and reaches the funnel; a garbage line would refuse
/// at parsing, upstream of the reconciliation barrier under test. Its fields mirror the world
/// builder's `try_append_resident_record_chirho` exactly, with `original_effect_key_chirho: None`
/// (this is ordinary work, not a compensation), so the ONE thing that can withhold it is the
/// ordinary-write barrier.
fn former_owner_ordinary_append_refusal_text_chirho(
    driven_chirho: &WinnerCompensationWorldChirho,
    fixture_chirho: &super::RegenesisFixtureChirho,
) -> String {
    let state_chirho = &driven_chirho.minted_chirho.state_chirho;
    let mut actor_chirho = open_resident_effect_journal_handle_chirho(
        &state_chirho.canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &state_chirho.ledger_config_chirho,
        None,
    )
    .expect("the former owner's own root reopens a single-node resident actor");
    let signer_refs_chirho = host_ledger_signer_refs_from_config_chirho(
        &state_chirho.ledger_config_chirho.signer_secrets_chirho,
    )
    .expect("the former owner's config names its signer secrets");
    let signers_chirho = HostLedgerSignersChirho::load_existing_chirho(
        &state_chirho.canonical_root_chirho,
        &signer_refs_chirho,
    )
    .expect("the former owner root carries its own runtime signers");
    let kind_id_chirho = AssetKindIdChirho(fixture_chirho.plan_chirho.kind_id_chirho.clone());
    let pre_append_cut_chirho = actor_chirho
        .effect_intent_cut_chirho()
        .expect("the former owner's live actor reports its authenticated cut");
    let continuation_chirho = actor_chirho
        .current_continuation_chirho(&kind_id_chirho)
        .expect("the former owner answers its continuation view")
        .expect("the former owner published the kind this world spends");
    let digest_chirho =
        |character_chirho: char| DigestChirho(character_chirho.to_string().repeat(64));
    let intent_chirho = sign_effect_intent_chirho(
        EffectIntentChirho {
            schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
            journal_cut_chirho: pre_append_cut_chirho,
            contract_set_digest_chirho: digest_chirho('a'),
            door_chirho: serde_json::from_value(serde_json::json!({
                "effect_node_chirho": "b".repeat(64),
                "capability_fingerprint_chirho": "c".repeat(64)
            }))
            .expect("the fixture door parses"),
            reversion_contract_digest_chirho: digest_chirho('d'),
            request_ref_chirho: digest_chirho('7'),
            request_context_ref_chirho: digest_chirho('f'),
            evidence_refs_chirho: vec![digest_chirho('9')],
            resolved_price_chirho: AssetOpChirho {
                amount_chirho: 10,
                kind_id_chirho: kind_id_chirho.clone(),
                kind_policy_ref_chirho: continuation_chirho.kind_policy_ref_chirho,
                rounding_chirho: RoundingChirho::ExactChirho,
            },
            payer_account_chirho: LogIdChirho::new_chirho(
                fixture_chirho.plan_chirho.initial_owner_chirho.clone(),
                kind_id_chirho,
            ),
            effect_step_chirho: 1,
            attribution_chirho: AttributionChirho::CauserChirho {
                principal_chirho: fixture_chirho.plan_chirho.initial_owner_chirho.clone(),
            },
            original_effect_key_chirho: None,
            sig_chirho: String::new(),
            key_id_chirho: String::new(),
        },
        signers_chirho.effect_intent_signer_chirho(),
    )
    .expect("the former owner's own effect-intent signer signs an ordinary spend");
    let intent_line_chirho =
        canonical_effect_intent_line_chirho(&intent_chirho).expect("the intent canonicalizes");
    actor_chirho
        .append_hold_chirho(&intent_line_chirho)
        .expect_err(
            "a deposed former owner must not resume ordinary writes; an Ok here means the release \
             re-admitted ordinary writes with no D4 restoration",
        )
        .to_string()
}

/// RECON:249 — after the winner-side completion + release, the FORMER OWNER stays held and the
/// LOSING FORK EVIDENCE stays reachable. The Brick-D property arm, standing on the composed chain.
///
/// # THE TWO BARRIERS, AND WHY RELEASE MOVES THE REFUSAL RATHER THAN REMOVING IT
///
/// Adoption plants TWO per-group barriers on the former owner's root: the reconciliation HEAD (the
/// active hold) and the ordinary-write HOLD. The D3 release supersedes the head ONLY — it removes no
/// ordinary-write hold, by design (`store_chirho.rs`: sibling-then-head ordering exists precisely so
/// a release can never re-admit ordinary writes without D4's signed confirmation). So after the real
/// release the former owner's ordinary write is still withheld — the refusal has MOVED from the
/// active-hold barrier (`Gd7ReconciliationHoldActiveChirho`, the deposed-side arm's barrier) to the
/// ordinary-write barrier (`Gd7OrdinaryWritesWithheldChirho`), which only D4 restoration lifts and
/// D4 is out of this drill's scope.
///
/// The losing-fork evidence is the former owner's own divergent journal tail — the record it
/// committed at the losing term that the winner never replicated. The winner-side completion writes
/// on the WINNER root; the import and release touch only reconciliation objects on the held root,
/// never the journal's losing records. So the verified losing tail must read back BYTE-IDENTICAL and
/// still verify: retain-not-erase, the immutable losing suffix reachable through its frozen reader.
///
/// # MIGRATION PATH
///
/// - If the post-release ordinary append SUCCEEDS, or refuses at `Gd7ReconciliationHoldActiveChirho`
///   instead of `Gd7OrdinaryWritesWithheldChirho`, the release stopped leaving the ordinary-write
///   hold standing — a deposed node could resume writes with no D4 confirmation, a money-authority
///   defect.
/// - If the losing tail stops verifying or differs after the chain, the winner-side completion or
///   the release reached across and mutated the former owner's immutable losing suffix — retain-not-
///   erase regressed.
#[test]
fn route_a_after_release_former_owner_stays_held_and_losing_evidence_stays_reachable_chirho() {
    let mut fixture_chirho = super::fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let driven_chirho =
        drive_to_open_winner_under_freeze_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);

    let state_chirho = &driven_chirho.minted_chirho.state_chirho;
    let world_chirho = &driven_chirho.minted_chirho.world_chirho;
    let group_digest_chirho = &world_chirho.identity_chirho.consistency_group_digest_chirho;
    let adopted_ref_chirho = &state_chirho.adopted_checkpoint_ref_chirho;
    let held_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&state_chirho.canonical_root_chirho)
            .expect("the held root's own storage opens");

    // ---- LOSING-EVIDENCE BASELINE, before the winner completes anything ----
    let provider_fixture_chirho = super::harness1_conservation_provider_tests_chirho::
        RegenesisGd7ConservationProviderChirho::from_fixture_chirho(&fixture_chirho);
    let losing_tail_before_chirho = provider_fixture_chirho
        .verified_losing_tail_chirho()
        .expect(
            "the losing-journal reader verifies the former owner's divergent tail before the run",
        );

    // ---- BOTH BARRIERS UP on the former owner's root before release ----
    assert!(
        gd7_reconciliation_group_has_any_active_hold_chirho(
            &held_storage_chirho,
            group_digest_chirho
        )
        .expect("probe the active hold before release"),
        "adoption leaves the former owner's group active-headed; without it the release below \
         supersedes an empty world"
    );
    assert!(
        gd7_reconciliation_group_ordinary_writes_withheld_chirho(
            &held_storage_chirho,
            group_digest_chirho
        )
        .expect("probe the ordinary-write hold before release"),
        "adoption also plants the ordinary-write hold; without it the post-release assertion below \
         would be vacuous — there would be no second barrier left to catch the former owner"
    );

    // ---- STARTING POINT: before release the ordinary append refuses at the ACTIVE-HOLD barrier ----
    //
    // The funnel checks the active hold BEFORE the ordinary-write hold, so with both barriers up the
    // refusal is the FIRST one. Pinning it here makes the post-release assertion below a CONTRAST: the
    // release moves this exact append's refusal from barrier one to barrier two, rather than the append
    // having refused at barrier two all along.
    let before_refusal_text_chirho =
        former_owner_ordinary_append_refusal_text_chirho(&driven_chirho, &fixture_chirho);
    assert!(
        before_refusal_text_chirho.contains("held by active GD7 reconciliation"),
        "before release the former owner's ordinary append must refuse at the ACTIVE-HOLD barrier, \
         checked ahead of the ordinary-write barrier.\nrefusal: {before_refusal_text_chirho}"
    );

    // ---- COMPOSE THROUGH RELEASE (reused, not rebuilt): winner completes, held imports/converges ----
    let certificate_chirho =
        drive_to_imported_convergence_certificate_chirho(&driven_chirho, &fixture_chirho);
    let releasing_actor_chirho = open_resident_effect_journal_handle_chirho(
        &state_chirho.canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &state_chirho.ledger_config_chirho,
        None,
    )
    .expect("the held root reopens a resident actor for the real release");
    releasing_actor_chirho
        .release_converged_gd7_hold_chirho(adopted_ref_chirho, &certificate_chirho)
        .expect("the honest held-signed convergence certificate releases the reconciliation hold");
    drop(releasing_actor_chirho);

    // ---- PROPERTY (recon:249) — the former owner REMAINS HELD ----
    //
    // Release lifted the FIRST barrier (the head is gone) but left the SECOND standing.
    assert!(
        !gd7_reconciliation_group_has_any_active_hold_chirho(
            &held_storage_chirho,
            group_digest_chirho
        )
        .expect("probe the active hold after release"),
        "the honest release must supersede the reconciliation head"
    );
    assert!(
        gd7_reconciliation_group_ordinary_writes_withheld_chirho(
            &held_storage_chirho,
            group_digest_chirho
        )
        .expect("probe the ordinary-write hold after release"),
        "the D3 release must leave the ordinary-write hold STANDING — only D4 restoration lifts it, \
         and D4 is out of this drill's scope"
    );
    let refusal_text_chirho =
        former_owner_ordinary_append_refusal_text_chirho(&driven_chirho, &fixture_chirho);
    assert!(
        refusal_text_chirho.contains("ordinary writes are withheld"),
        "after release the former owner's ordinary write must refuse at the ORDINARY-WRITE barrier — \
         the refusal moved here from the active-hold barrier the deposed-side arm pins.\nrefusal: \
         {refusal_text_chirho}"
    );
    assert!(
        !refusal_text_chirho.contains("held by active GD7 reconciliation"),
        "the refusal must NOT be the active-hold barrier: release lifted that one, so a refusal here \
         would mean the head was not actually superseded.\nrefusal: {refusal_text_chirho}"
    );

    // ---- PROPERTY (recon:249) — the LOSING FORK EVIDENCE remains reachable ----
    let losing_tail_after_chirho = provider_fixture_chirho
        .verified_losing_tail_chirho()
        .expect(
        "the losing-journal reader must still verify the former owner's divergent tail after the \
             winner-side completion and release — a failure here is retain-not-erase regressing",
    );
    assert_eq!(
        losing_tail_after_chirho, losing_tail_before_chirho,
        "the verified losing tail must read back byte-identical after the whole chain (its coordinate \
         carries the record's content digest) — the winner-side completion and release must not reach \
         across and mutate the former owner's own divergent journal tail"
    );
}

/// CUT-1(ii), EXACT SUBJECT — the release barrier admits ONLY the exact adopted cut its certificate
/// certifies; a neighboring cut cannot satisfy it even carried by the genuine certificate.
///
/// # WHAT THIS IS AND WHERE ITS SIBLINGS LIVE
///
/// recon:270's "barrier disabled control — the effect completes normally, proving the test kind and
/// provider are live" is already the winner-side completion arm
/// `harness1_compensated_terminal_arms_chirho::
/// route_a_winner_reaches_completed_after_the_winner_own_term_cell_advance_chirho`: with no
/// reconciliation hold on the winner root the compensation completes to `CompletedChirho` and the
/// provider executes once. This arm is recon:276's exact-subject half, re-scoped from the 6.1
/// transport controller (whose own exact-subject arms are
/// `cairn_drill_barrier_chirho ... disconnecting_one_node_leaves_its_neighbour_connected_chirho` and
/// `an_unknown_node_label_refuses_chirho`) to the 6.4 flow's blessed effect barrier, the
/// reconciliation hold.
///
/// # THE SUBJECT IS THE ADOPTED CUT, AND THE CERTIFICATE CARRIES A NEIGHBORING ONE
///
/// A genuine convergence certificate carries TWO refs: `checkpoint_ref_chirho` names the PlanSealed
/// plan cut, and `adopted_checkpoint_ref_chirho` names the AdoptedHeld cut the release supersedes.
/// After a real adoption these are DIFFERENT (asserted below for non-vacuity). The release door binds
/// the certificate to the cut being superseded by `adopted_checkpoint_ref_chirho`; presenting the
/// genuine certificate but asking to release the NEIGHBORING plan cut refuses at the identity
/// binding, BEFORE the signature check — so the refusal is purely about the subject, and the
/// positive control below proves the SAME certificate releases its exact subject.
///
/// # MIGRATION PATH
///
/// - If the neighboring-cut release SUCCEEDS, the door stopped binding the certificate to its exact
///   adopted cut and a certificate could be redirected to supersede a cut it never certified.
/// - If it refuses at `ConvergenceCertificateUnverified` instead of the identity mismatch, the
///   subject binding stopped running before the signature check and this arm no longer isolates it.
/// - If the exact-subject positive control REFUSES, the certificate or the adopted head drifted; read
///   that refusal before touching this arm.
#[test]
fn route_a_release_admits_only_its_exact_subject_cut_chirho() {
    let mut fixture_chirho = super::fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let driven_chirho =
        drive_to_open_winner_under_freeze_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);
    let certificate_chirho =
        drive_to_imported_convergence_certificate_chirho(&driven_chirho, &fixture_chirho);

    let state_chirho = &driven_chirho.minted_chirho.state_chirho;
    let world_chirho = &driven_chirho.minted_chirho.world_chirho;
    let group_digest_chirho = &world_chirho.identity_chirho.consistency_group_digest_chirho;
    let adopted_ref_chirho = &state_chirho.adopted_checkpoint_ref_chirho;
    let held_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&state_chirho.canonical_root_chirho)
            .expect("the held root's own storage opens");

    // NON-VACUITY: the neighboring plan cut must genuinely differ from the adopted cut, or "wrong
    // subject" would be the same subject and the refusal below would prove nothing.
    let neighboring_cut_ref_chirho = certificate_chirho.checkpoint_ref_chirho().to_owned();
    assert_ne!(
        neighboring_cut_ref_chirho.as_str(),
        certificate_chirho.adopted_checkpoint_ref_chirho(),
        "after a real adoption the plan cut and the adopted cut differ; without that this arm's \
         'neighboring subject' is the exact subject and proves nothing"
    );
    assert_eq!(
        certificate_chirho.adopted_checkpoint_ref_chirho(),
        adopted_ref_chirho.as_str(),
        "the certificate must certify the world's REAL adopted cut, or the positive control below is \
         not releasing the subject the hold actually names"
    );

    let held_actor_chirho = open_resident_effect_journal_handle_chirho(
        &state_chirho.canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &state_chirho.ledger_config_chirho,
        None,
    )
    .expect("the held root reopens a resident actor for the exact-subject probe");

    // ---- WRONG SUBJECT: the genuine certificate, asked to release the NEIGHBORING plan cut ----
    let wrong_subject_refusal_chirho = held_actor_chirho
        .release_converged_gd7_hold_chirho(&neighboring_cut_ref_chirho, &certificate_chirho)
        .expect_err(
            "the release barrier must admit only its exact adopted cut; a success here means a \
             genuine certificate was redirected to supersede a cut it never certified",
        );
    let wrong_subject_text_chirho = format!("{wrong_subject_refusal_chirho:?}");
    assert!(
        wrong_subject_text_chirho.contains("AdoptedCutIdentityMismatch"),
        "the refusal must be the adopted-cut identity binding: {wrong_subject_text_chirho}"
    );
    assert!(
        !wrong_subject_text_chirho.contains("ConvergenceCertificateUnverified"),
        "the subject binding must refuse BEFORE the signature check, so this arm isolates the \
         subject and not the certificate: {wrong_subject_text_chirho}"
    );
    assert!(
        gd7_reconciliation_group_has_any_active_hold_chirho(
            &held_storage_chirho,
            group_digest_chirho
        )
        .expect("probe the hold after the wrong-subject refusal"),
        "a release refused for the wrong subject must leave the hold ACTIVE"
    );

    // ---- POSITIVE CONTROL: the SAME certificate releases its EXACT subject ----
    held_actor_chirho
        .release_converged_gd7_hold_chirho(adopted_ref_chirho, &certificate_chirho)
        .expect("the same genuine certificate releases the exact adopted cut it certifies");
    drop(held_actor_chirho);
    assert!(
        !gd7_reconciliation_group_has_any_active_hold_chirho(
            &held_storage_chirho,
            group_digest_chirho
        )
        .expect("probe the hold after the exact-subject release"),
        "the exact-subject release must supersede the head — the ONLY difference from the refused \
         attempt was the subject cut"
    );
}
