// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! THE TAIL — one minted GD7 obligation driven to a LAWFUL TERMINAL OUTCOME.
//!
//! # THE CHAIN, and why each step is production's own
//!
//! ```text
//!   mint  ->  compose  ->  compose  ->  roster  ->  dispose
//!             (intent)     (held)       (custody)   (signed)
//! ```
//!
//! **Compose twice is not a retry loop; it is the system's designed answer.** Every resident
//! opener wires `RefusingGd7CompensationProviderChirho` — that IS production's spawn default — and
//! its dedup retention is `Duration::ZERO`. So the first composition persists the provider INTENT
//! and refuses `ProviderNotConfiguredChirho`; the second finds the resume window already elapsed,
//! refuses `ResumeWindowExpiredChirho`, and marks the obligation `HeldManualChirho` ON ITS WAY OUT.
//! Nothing here simulates a failing provider: the refusal is the shipped adapter's own answer, and
//! `HeldManual` is where a compensation with no provider is SUPPOSED to land — stop trying, and
//! hold it for an operator whose authority is checked against the signed roster at read time.
//!
//! # THE OPERATOR IS A DISTINCT PRINCIPAL, and that is the point of the roster
//!
//! The disposition is authored and signed in the WINNER root's own key custody, and verified on the
//! held side by a verifier pinned to that key id and nothing else. The held root never holds the
//! operator's signing power, and the operator never holds the held root's. This is the production
//! CLI shape exactly (`handle_gd7_obligation_processing_dispose_chirho`): operator-authored JSON,
//! deserialized, verified by pinned key id — no ambient signing anywhere on the held side.
//!
//! # WHAT THIS IS NOT — the boundary, stated where a reader meets it
//!
//! A disposed obligation is a TERMINAL outcome, not a COMPLETED one. Nothing here observes a
//! provider effect, records a journal receipt, or reaches `CompletedChirho`. The compensated
//! terminal — the full adopt -> advance -> release -> fenced append -> complete chain carrying a
//! journal receipt — belongs to the capstone's own test and must never be satisfied by disposal.

use super::harness1_success_ladder_tests_chirho::drive_ladder_through_adoption_chirho;
use cairn_ledger_host_chirho::reconciliation_chirho::{
    dispose_gd7_obligation_held_manual_chirho, load_gd7_obligation_processing_state_chirho,
    write_gd7_operator_roster_chirho, ExistingNodeGd7SignerChirho,
    Gd7HeldManualClassificationChirho, Gd7HeldManualDispositionChirho,
    Gd7LosingEffectObligationSelectorChirho, Gd7ObligationProcessingRefusalChirho,
    Gd7ObligationTerminalProgressChirho, Gd7OperatorRosterChirho, Gd7OperatorRosterMemberChirho,
    Gd7OperatorRosterRoleChirho, Gd7ReconciliationSignerPortChirho, PinnedNodeGd7VerifierChirho,
    GD7_OPERATOR_ROSTER_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_host_chirho::{
    open_resident_effect_journal_handle_chirho, open_resident_gd7_held_coordinator_chirho,
    FsLedgerStorageChirho, Gd7CompensationCompositionRefusalChirho,
    Gd7CompensationProviderRefusalChirho, ResidentEffectJournalHandleChirho,
};
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;

/// Bounded, non-identifying composition coordinates. They are labels for a compensation ACTION, not
/// content: nothing here carries a payer, an amount, or any free text.
const TAIL_INVERSE_AUTHORITY_REF_CHIRHO: &str = "gd7-tail-inverse-authority-ref-chirho";
const TAIL_ACTION_IDEMPOTENCY_KEY_CHIRHO: &str = "gd7-tail-action-idempotency-key-chirho";
const TAIL_BOUNDED_PAYLOAD_CHIRHO: &[u8] = b"gd7-tail-bounded-compensation-payload-chirho";
const TAIL_COMPENSATING_EFFECT_REF_CHIRHO: &str = "gd7-tail-compensating-effect-ref-chirho";

/// What a disposed obligation exposes to a caller that must then converge over it.
pub(super) struct DisposedObligationChirho {
    pub(super) mint_identity_digest_chirho: String,
    pub(super) operator_key_id_chirho: String,
}

/// Author ONE operator disposition exactly as production's CLI receives it.
///
/// The held side reconstructs the signing payload by clearing `sig_chirho` and re-serialising the
/// struct, so the operator must sign THOSE bytes. Round-tripping the unsigned value through the
/// type's own `Serialize` is how an operator obtains them without the crate-private canonical
/// helper — and it is why this cannot silently drift from the verifier: both sides derive the bytes
/// from the same impl.
pub(super) fn author_signed_disposition_chirho(
    mint_identity_digest_chirho: &str,
    operator_key_id_chirho: &str,
    operator_signer_chirho: &ExistingNodeGd7SignerChirho,
) -> Gd7HeldManualDispositionChirho {
    let unsigned_chirho: Gd7HeldManualDispositionChirho =
        serde_json::from_value(serde_json::json!({
            "mint_identity_digest_chirho": mint_identity_digest_chirho,
            "operator_key_id_chirho": operator_key_id_chirho,
            "disposed_at_unix_seconds_chirho": 7u64,
            "compensating_effect_ref_chirho": TAIL_COMPENSATING_EFFECT_REF_CHIRHO,
            "no_action_reason_chirho": serde_json::Value::Null,
            "sig_chirho": "",
        }))
        .expect("an operator-authored disposition deserializes through the public type");
    let canonical_unsigned_chirho =
        serde_json::to_vec(&unsigned_chirho).expect("the unsigned disposition re-serializes");
    let signature_chirho = operator_signer_chirho
        .sign_chirho(
            std::str::from_utf8(&canonical_unsigned_chirho)
                .expect("the canonical unsigned line is utf-8"),
        )
        .expect("the operator signs in its OWN key custody, never the held root's");
    let mut signed_value_chirho =
        serde_json::to_value(&unsigned_chirho).expect("the unsigned disposition re-serializes");
    signed_value_chirho["sig_chirho"] = serde_json::Value::String(signature_chirho);
    serde_json::from_value(signed_value_chirho)
        .expect("the signed operator JSON deserializes through the public type")
}

/// Publish the signed operator roster that names WHICH principal may dispose.
///
/// Signed by the HELD root's own custody — the roster is the held side's statement of who it will
/// accept — while the member it names is the operator's key. Those being different keys is the
/// custody separation this anchor exists for.
pub(super) fn write_disposition_roster_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    group_digest_chirho: &str,
    roster_signer_chirho: &ExistingNodeGd7SignerChirho,
    roster_signer_key_id_chirho: &str,
    roster_epoch_chirho: u64,
    operator_key_id_chirho: &str,
) {
    write_gd7_operator_roster_chirho(
        storage_chirho,
        group_digest_chirho,
        roster_signer_chirho,
        Gd7OperatorRosterChirho {
            schema_chirho: GD7_OPERATOR_ROSTER_SCHEMA_V1_CHIRHO.to_owned(),
            consistency_group_digest_chirho: group_digest_chirho.to_owned(),
            roster_epoch_chirho,
            signer_key_id_chirho: roster_signer_key_id_chirho.to_owned(),
            members_chirho: vec![Gd7OperatorRosterMemberChirho {
                operator_key_id_chirho: operator_key_id_chirho.to_owned(),
                role_chirho: Gd7OperatorRosterRoleChirho::Gd7DispositionChirho,
            }],
            sig_chirho: String::new(),
        },
    )
    .expect("the held root signs its own operator roster");
}

/// Drive ONE minted obligation from its receipt to a signed operator disposal.
///
/// `minted_chirho` is taken BY VALUE because the receipt is affine: it is moved in, its three
/// coordinates are read once, and it dies here. Nothing clones it, so no second consumer of the
/// same mint can exist — which is the property that makes "one selector, one obligation" hold at
/// the type level rather than by convention.
#[allow(clippy::too_many_arguments)]
pub(super) fn drive_minted_obligation_to_disposal_chirho(
    actor_chirho: &ResidentEffectJournalHandleChirho,
    storage_chirho: &dyn LedgerStoragePortChirho,
    minted_chirho: cairn_ledger_host_chirho::reconciliation_chirho::MintedGd7LosingEffectObligationChirho,
    group_digest_chirho: &str,
    roster_signer_chirho: &ExistingNodeGd7SignerChirho,
    roster_signer_key_id_chirho: &str,
    operator_signer_chirho: &ExistingNodeGd7SignerChirho,
    operator_key_id_chirho: &str,
) -> DisposedObligationChirho {
    let mint_identity_digest_chirho = minted_chirho.mint_identity_digest_chirho().to_owned();
    let canonical_obligation_digest_chirho = minted_chirho
        .canonical_obligation_digest_chirho()
        .to_owned();
    let receipt_ref_chirho = minted_chirho.receipt_ref_chirho().to_owned();
    drop(minted_chirho);

    // ---- COMPOSE, call 1: the provider INTENT is persisted, then the default provider refuses ----
    assert_eq!(
        actor_chirho
            .compose_gd7_compensation_chirho(
                &mint_identity_digest_chirho,
                &receipt_ref_chirho,
                &canonical_obligation_digest_chirho,
                TAIL_INVERSE_AUTHORITY_REF_CHIRHO,
                TAIL_ACTION_IDEMPOTENCY_KEY_CHIRHO,
                TAIL_BOUNDED_PAYLOAD_CHIRHO,
            )
            .expect_err("production's spawn-default compensation provider must refuse"),
        Gd7CompensationCompositionRefusalChirho::ProviderChirho(
            Gd7CompensationProviderRefusalChirho::ProviderNotConfiguredChirho
        ),
        "the first composition must refuse for the PROVIDER reason. Any other refusal means the \
         row was never created or the intent never persisted, and the second call would then \
         re-enter the create path instead of the resume path this tail depends on"
    );
    assert_eq!(
        load_gd7_obligation_processing_state_chirho(storage_chirho, &mint_identity_digest_chirho)
            .expect("the first composition created the durable processing row")
            .terminal_progress_chirho(),
        Gd7ObligationTerminalProgressChirho::ProviderIntentPersistedChirho,
        "the refusal must still have PERSISTED the intent -- that durability is what makes the \
         second call a resume rather than a fresh attempt"
    );

    // ---- COMPOSE, call 2: zero retention -> the resume window is already gone -> HeldManual ----
    assert_eq!(
        actor_chirho
            .compose_gd7_compensation_chirho(
                &mint_identity_digest_chirho,
                &receipt_ref_chirho,
                &canonical_obligation_digest_chirho,
                TAIL_INVERSE_AUTHORITY_REF_CHIRHO,
                TAIL_ACTION_IDEMPOTENCY_KEY_CHIRHO,
                TAIL_BOUNDED_PAYLOAD_CHIRHO,
            )
            .expect_err("a resume against a zero-retention adapter must refuse"),
        Gd7CompensationCompositionRefusalChirho::ProcessingChirho(
            Gd7ObligationProcessingRefusalChirho::ResumeWindowExpiredChirho
        ),
        "the second composition must refuse by the RESUME-WINDOW reason specifically. \
         ResumeAttemptsExceeded would also mark HeldManual, so a test satisfied by either would \
         not distinguish 'the window closed' from 'we tried too often'"
    );
    let held_chirho =
        load_gd7_obligation_processing_state_chirho(storage_chirho, &mint_identity_digest_chirho)
            .expect("the held row is durable");
    assert_eq!(
        held_chirho.terminal_progress_chirho(),
        Gd7ObligationTerminalProgressChirho::HeldManualChirho,
        "the refusing composition must have marked the obligation HeldManual ON ITS WAY OUT -- \
         this is production's own hand-off to an operator, not a step this test performs"
    );
    assert_eq!(
        held_chirho.held_manual_classification_chirho(),
        Some(Gd7HeldManualClassificationChirho::HeldManualOpenChirho),
        "a held-but-undisposed obligation is OPEN, never a satisfying terminal outcome"
    );

    // ---- ROSTER: the held root names WHICH operator principal may dispose ----
    write_disposition_roster_chirho(
        storage_chirho,
        group_digest_chirho,
        roster_signer_chirho,
        roster_signer_key_id_chirho,
        1,
        operator_key_id_chirho,
    );

    // ---- THE AUTHORITY ARM: a well-formed disposition SIGNED BY THE WRONG CUSTODY ----
    //
    // This is the arm that makes the disposal path's authority claim mean something. The JSON names
    // the authorized operator, the verifier is pinned to that same operator, and the signature is a
    // REAL signature — made by the held root's own custody instead of the operator's. Everything a
    // name-comparison could check passes; only the cryptographic check can refuse it.
    //
    // Without this, "the operator signed it" would be indistinguishable from "someone wrote the
    // operator's key id at the top" — which is precisely the forgery this roster exists to stop.
    let forged_custody_disposition_chirho = author_signed_disposition_chirho(
        &mint_identity_digest_chirho,
        operator_key_id_chirho,
        roster_signer_chirho,
    );
    assert_eq!(
        dispose_gd7_obligation_held_manual_chirho(
            storage_chirho,
            &held_chirho,
            forged_custody_disposition_chirho,
            &PinnedNodeGd7VerifierChirho::new_from_key_id_chirho(operator_key_id_chirho.to_owned())
                .expect("the operator verifier opens"),
        )
        .expect_err("a disposition signed by the wrong custody must refuse"),
        Gd7ObligationProcessingRefusalChirho::InvalidStateChirho,
        "a wrong-custody signature must refuse BY INVALID STATE. A StateCollision here would mean \
         the row had already been disposed and this arm never reached the signature check at all"
    );
    assert_eq!(
        load_gd7_obligation_processing_state_chirho(storage_chirho, &mint_identity_digest_chirho)
            .expect("the held row survives a refused disposal")
            .held_manual_classification_chirho(),
        Some(Gd7HeldManualClassificationChirho::HeldManualOpenChirho),
        "a REFUSED disposal must leave the row OPEN. If a rejected disposition could half-close a \
         row, the refusal would be worse than useless -- it would strand the obligation"
    );

    // ---- DISPOSE: the operator's own signed JSON, through the real public disposal path ----
    let disposition_chirho = author_signed_disposition_chirho(
        &mint_identity_digest_chirho,
        operator_key_id_chirho,
        operator_signer_chirho,
    );
    let operator_verifier_chirho =
        PinnedNodeGd7VerifierChirho::new_from_key_id_chirho(operator_key_id_chirho.to_owned())
            .expect("the held side pins the operator by key id, holding no operator signing power");
    let disposed_chirho = dispose_gd7_obligation_held_manual_chirho(
        storage_chirho,
        &held_chirho,
        disposition_chirho,
        &operator_verifier_chirho,
    )
    .expect("the real signed disposal path accepts the operator's own authored JSON");
    assert_eq!(
        disposed_chirho.held_manual_classification_chirho(),
        Some(Gd7HeldManualClassificationChirho::HeldManualDisposedChirho),
        "the disposed row must classify as DISPOSED -- the classification is what a convergence \
         read consults, so a row that disposed without reclassifying would still be unconverged"
    );

    DisposedObligationChirho {
        mint_identity_digest_chirho,
        operator_key_id_chirho: operator_key_id_chirho.to_owned(),
    }
}

/// THE TAIL, END TO END, on a world driven through a real adoption.
///
/// # MIGRATION PATH
///
/// If this fails at the obligation-count assertion, the WORLD stopped carrying an obligation and
/// the whole module is vacuous — fix that first. If it fails at either composition's refusal, read
/// WHICH variant came back: a `ProviderChirho` refusal on the SECOND call means the row was
/// recreated rather than resumed, and a `Processing` refusal on the FIRST means the row already
/// existed when this test began. If it fails at the disposal, the operator-JSON shape and the
/// verifier's reconstruction have drifted apart.
#[test]
fn the_tail_composes_holds_and_disposes_one_minted_obligation_chirho() {
    let mut fixture_chirho = super::fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let state_chirho =
        drive_ladder_through_adoption_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);

    // NON-VACUITY FIRST, for the same reason the mint arms assert it: on a zero-obligation plan
    // there is nothing to mint, and every refusal below would fire honestly while measuring nothing.
    assert!(
        state_chirho.effect_obligation_count_chirho > 0,
        "the sealed plan carries NO effect obligations, so this tail has no subject and every \
         assertion in it is vacuous"
    );

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

    let storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&state_chirho.canonical_root_chirho)
            .expect("the held root's own storage opens");
    let actor_chirho = open_resident_effect_journal_handle_chirho(
        &state_chirho.canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &state_chirho.ledger_config_chirho,
        None,
    )
    .expect("the production-shaped opener accepts an explicitly absent conservation provider");
    let roster_signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
        &state_chirho.canonical_root_chirho,
        &state_chirho.held_node_chirho,
    )
    .expect("the held root's own key custody opens");
    // THE OPERATOR IS THE WINNER ROOT'S PRINCIPAL, opened on the WINNER's own root. The held root
    // cannot produce this signature, which is what makes the roster check meaningful rather than a
    // node signing its own permission slip.
    let operator_signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
        &state_chirho.winner_source_root_chirho,
        &state_chirho.winner_node_chirho,
    )
    .expect("the winner root's own key custody opens as the operator principal");
    assert_ne!(
        state_chirho.held_node_chirho.0, state_chirho.winner_node_chirho.0,
        "the operator and the held root must be DISTINCT principals, or the custody separation \
         this roster anchors is not being exercised at all"
    );

    let disposed_chirho = drive_minted_obligation_to_disposal_chirho(
        &actor_chirho,
        &storage_chirho,
        minted_chirho,
        &state_chirho.group_digest_chirho,
        &roster_signer_chirho,
        &state_chirho.held_node_chirho.0,
        &operator_signer_chirho,
        &state_chirho.winner_node_chirho.0,
    );

    // RE-DISPOSE REFUSES BY STATE COLLISION, and the distinction matters to a retrying operator:
    // "already disposed, stop" is a different instruction from "your disposition does not bind".
    let disposed_state_chirho = load_gd7_obligation_processing_state_chirho(
        &storage_chirho,
        &disposed_chirho.mint_identity_digest_chirho,
    )
    .expect("the disposed row is durable");
    let second_disposition_chirho = author_signed_disposition_chirho(
        &disposed_chirho.mint_identity_digest_chirho,
        &disposed_chirho.operator_key_id_chirho,
        &operator_signer_chirho,
    );
    assert_eq!(
        dispose_gd7_obligation_held_manual_chirho(
            &storage_chirho,
            &disposed_state_chirho,
            second_disposition_chirho,
            &PinnedNodeGd7VerifierChirho::new_from_key_id_chirho(
                disposed_chirho.operator_key_id_chirho.clone()
            )
            .unwrap(),
        )
        .expect_err("a second disposal of the same row must refuse"),
        Gd7ObligationProcessingRefusalChirho::StateCollisionChirho,
        "re-disposal must refuse by STATE COLLISION specifically. An InvalidState refusal here \
         would mean the row stopped presenting as HeldManual, which is a different defect"
    );

    drop(actor_chirho);
}
