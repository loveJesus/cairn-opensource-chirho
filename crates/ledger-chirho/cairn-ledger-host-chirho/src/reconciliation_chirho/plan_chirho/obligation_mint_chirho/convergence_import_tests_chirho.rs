// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! D1 convergence acceptance over an imported winner compensation receipt (Shape A').
//!
//! Split from `convergence_tests_chirho` to keep both test modules under the file-size cap. The
//! shared convergence runners (`run_convergence_chirho`, the binding/predicate/proof fixtures) live
//! in the sibling and are reused here; this file holds only the converged-import arm and the winner
//! compensation record it fabricates. The record is fabricated rather than extracted from a live
//! winner journal — that two-root extraction is the regenesis drill's job; here the point is that
//! the held mover RE-VERIFIES the record before the classifier will trust it.

use super::super::authority_chirho::{
    enumerate_gd7_sealed_plan_obligations_chirho, measure_gd7_losing_population_chirho,
};
use super::super::tests_chirho::digest_chirho;
use super::convergence_tests_chirho::{
    alternate_convergence_proof_chirho, alternate_population_mint_identity_chirho,
    convergence_binding_chirho, create_convergence_row_chirho, drive_row_to_completed_chirho,
    run_convergence_chirho, satisfied_predicates_chirho,
};
use super::gd7_mint_identity_for_verified_obligation_chirho;
use super::tests_chirho::obligation_mint_fixture_chirho;
use super::verified_gd7_sealed_plan_obligation_for_test_chirho;
use crate::reconciliation_chirho::Gd7PlanRefusalChirho;
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;

/// The UNSIGNED winner compensation Hold record for `original_effect_key` under `winner_term`, built
/// as the winner journal would store it (key id and signature left empty for the caller to set). Two
/// callers sign it differently: `fabricated_winner_compensation_line_chirho` with the self-contained
/// winner fake, and `journal_signed_winner_compensation_line_chirho` with the fixture's journal
/// verifier — the latter is what the over-population mover needs, since production wires ONE journal
/// verifier for both the manifest enumeration and the winner-record check.
fn winner_compensation_record_chirho(
    original_effect_key_chirho: &str,
    winner_term_chirho: u64,
) -> cairn_ledger_model_chirho::record_chirho::LedgerRecordChirho {
    use cairn_ledger_model_chirho::record_chirho::{
        AttributionChirho, EscrowControlChirho, HlcChirho, LedgerLegChirho, LedgerOpChirho,
        LedgerRecordChirho, LegDeltaChirho, LegPostStateChirho,
    };
    let compensation_key_chirho =
        cairn_effect_commit_chirho::intent_chirho::effect_compensation_key_chirho(
            original_effect_key_chirho,
        )
        .expect("valid original effect key");
    let saga_id_chirho =
        cairn_effect_commit_chirho::intent_chirho::parse_effect_compensation_key_chirho(
            &compensation_key_chirho,
        )
        .expect("compensation key parses");
    let epoch_chirho = cairn_writer_head_chirho::writer_head_chirho::compose_writer_epoch_chirho(
        winner_term_chirho,
        0,
    )
    .expect("winner term composes an epoch");
    LedgerRecordChirho {
        schema_chirho: cairn_ledger_model_chirho::wire_chirho::LEDGER_RECORD_SCHEMA_V1_CHIRHO
            .to_owned(),
        format_version_chirho: 1,
        seq_chirho: 9,
        prev_chirho: DigestChirho("bb".repeat(32)),
        epoch_chirho,
        hlc_chirho: HlcChirho {
            physical_ms_chirho: 4321,
            logical_chirho: 0,
        },
        legs_chirho: vec![LedgerLegChirho {
            account_chirho: cairn_ledger_model_chirho::LogIdChirho::new_chirho(
                "payer-chirho",
                "money-chirho",
            ),
            kind_policy_ref_chirho: cairn_ledger_model_chirho::ids_chirho::AssetKindRefChirho(
                DigestChirho("policy-digest-chirho".into()),
            ),
            delta_chirho: LegDeltaChirho::HoldChirho,
            amount_chirho: 1,
            post_chirho: LegPostStateChirho {
                credits_total_chirho: 0,
                debits_total_chirho: 0,
                held_chirho: 1,
            },
            counterpart_chirho: None,
        }],
        op_chirho: LedgerOpChirho::EscrowHoldChirho {
            control_chirho: EscrowControlChirho {
                saga_id_chirho,
                step_chirho: 1,
            },
        },
        idempotency_key_chirho: "gd7-import-compensation-idem-chirho".to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::CauserChirho {
            principal_chirho: "payer-chirho".to_owned(),
        },
        anchor_chirho: None,
        sig_chirho: String::new(),
        key_id_chirho: String::new(),
    }
}

/// A winner-signed compensation line, signed with the self-contained winner ledger fake. Fabricated
/// rather than extracted from a live winner journal — that two-root extraction is the drill's job;
/// here the point is that the held mover RE-VERIFIES authenticity (canonical bytes, winner ledger
/// signature, deterministic-K coordinate, winner term) before the classifier will trust it.
fn fabricated_winner_compensation_line_chirho(
    winner_ledger_key_id_chirho: &str,
    original_effect_key_chirho: &str,
    winner_term_chirho: u64,
) -> String {
    let mut record_chirho =
        winner_compensation_record_chirho(original_effect_key_chirho, winner_term_chirho);
    record_chirho.key_id_chirho = winner_ledger_key_id_chirho.to_owned();
    let signed_content_chirho =
        cairn_ledger_model_chirho::wire_chirho::ledger_record_signed_content_line_chirho(
            &record_chirho,
        )
        .expect("signed content encodes");
    record_chirho.sig_chirho = format!(
        "winner-ledger-sig-{}",
        blake3::hash(signed_content_chirho.as_bytes()).to_hex()
    );
    cairn_ledger_model_chirho::wire_chirho::canonical_ledger_record_line_chirho(&record_chirho)
        .expect("canonical record line")
}

/// A winner compensation line signed with the FIXTURE's journal verifier — the trust root the
/// over-population mover uses for BOTH the manifest enumeration and the winner-record check, exactly
/// as production wires `losing_record_verifier` == the config-pinned winner-journal verifier.
fn journal_signed_winner_compensation_line_chirho(
    fixture_chirho: &super::tests_chirho::ObligationMintFixtureChirho,
    original_effect_key_chirho: &str,
    winner_term_chirho: u64,
) -> String {
    let record_chirho =
        winner_compensation_record_chirho(original_effect_key_chirho, winner_term_chirho);
    let signed_chirho = fixture_chirho
        .losing_record_verifier_chirho
        .sign_record_chirho(record_chirho);
    cairn_ledger_model_chirho::wire_chirho::canonical_ledger_record_line_chirho(&signed_chirho)
        .expect("canonical record line")
}

/// Re-canonicalize a genuine winner compensation line with a TAMPERED signature. The bytes stay
/// canonical (so the mover's canonical check passes) but the ledger signature no longer verifies —
/// the mover must fail closed at the signature, before the compensation coordinate.
fn forge_record_signature_chirho(genuine_line_chirho: &str) -> String {
    let mut record_chirho: cairn_ledger_model_chirho::record_chirho::LedgerRecordChirho =
        serde_json::from_str(genuine_line_chirho).expect("the genuine line parses");
    record_chirho.sig_chirho = "forged-signature-chirho".to_owned();
    cairn_ledger_model_chirho::wire_chirho::canonical_ledger_record_line_chirho(&record_chirho)
        .expect("canonical forged line")
}

struct FakeWinnerLedgerVerifierChirho {
    key_id_chirho: String,
}

impl crate::reconciliation_chirho::Gd7LedgerRecordVerifierPortChirho
    for FakeWinnerLedgerVerifierChirho
{
    fn key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }
    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho
            == format!(
                "winner-ledger-sig-{}",
                blake3::hash(signed_content_line_chirho.as_bytes()).to_hex()
            )
    }
}

/// End-to-end acceptance: with NO native completed row, importing the winner's own verified signed
/// compensation receipt lets the REAL converger CERTIFY over the compensated terminal (Shape A').
#[test]
fn convergence_certifies_over_an_imported_winner_compensation_receipt_chirho() {
    let fixture_chirho = obligation_mint_fixture_chirho("convergence-imported-compensation");
    let effect_ports_chirho = fixture_chirho.effect_ports_chirho();
    let population_chirho = enumerate_gd7_sealed_plan_obligations_chirho(
        &fixture_chirho.storage_chirho,
        &fixture_chirho.held_signer_chirho,
        &fixture_chirho.losing_record_verifier_chirho,
        &effect_ports_chirho,
        &fixture_chirho.alternate_checkpoint_chirho,
    )
    .expect("walk the complete two-page manifest chain");
    assert_eq!(population_chirho.len(), 1);
    let intent_ref_chirho = population_chirho[0]
        .obligation_chirho()
        .intent_ref_chirho
        .0
        .clone();
    let (mint_identity_digest_chirho, canonical_obligation_digest_chirho) =
        gd7_mint_identity_for_verified_obligation_chirho(
            &digest_chirho('e').0,
            &fixture_chirho.alternate_checkpoint_ref_chirho,
            &fixture_chirho.alternate_obligation_plan_ref_chirho,
            &fixture_chirho.identity_digest_chirho,
            fixture_chirho.identity_chirho.winner_term_chirho,
            &population_chirho[0],
        )
        .expect("derive the population obligation's mint identity");
    let proof_chirho = alternate_convergence_proof_chirho(&fixture_chirho, 1);
    let winner_term_chirho = proof_chirho.winner_term_chirho();

    // No native row AND no import row: the obligation is OPEN, exactly as before this brick.
    assert_eq!(
        run_convergence_chirho(
            &fixture_chirho,
            &proof_chirho,
            convergence_binding_chirho(),
            satisfied_predicates_chirho(),
        ),
        Err(Gd7PlanRefusalChirho::UnconvergedObligationChirho(
            mint_identity_digest_chirho.clone()
        )),
        "with neither a native completed row nor an import row the obligation blocks convergence"
    );

    // Import a verified winner compensation receipt for THIS obligation — no native row is created.
    let original_effect_key_chirho = format!(
        "{}{intent_ref_chirho}",
        cairn_effect_commit_chirho::intent_chirho::EFFECT_INTENT_KEY_PREFIX_CHIRHO
    );
    let winner_ledger_chirho = FakeWinnerLedgerVerifierChirho {
        key_id_chirho: "winner-journal-key-chirho".to_owned(),
    };
    let record_line_chirho = fabricated_winner_compensation_line_chirho(
        &winner_ledger_chirho.key_id_chirho,
        &original_effect_key_chirho,
        winner_term_chirho,
    );
    let expected_receipt_digest_chirho =
        cairn_ledger_model_chirho::wire_chirho::stored_line_digest_chirho(&record_line_chirho).0;
    let row_chirho =
        super::super::converged_import_chirho::import_verified_gd7_compensation_receipt_chirho(
            &fixture_chirho.storage_chirho,
            &fixture_chirho.held_signer_chirho,
            &winner_ledger_chirho,
            &mint_identity_digest_chirho,
            &canonical_obligation_digest_chirho,
            &original_effect_key_chirho,
            winner_term_chirho,
            &record_line_chirho,
        )
        .expect("the winner compensation receipt verifies and imports");
    assert_eq!(
        row_chirho.verified_receipt_digest_chirho(),
        expected_receipt_digest_chirho,
        "the held-signed row binds the winner record's exact stored-line digest"
    );

    // NOW the honest converger CERTIFIES over the imported compensated terminal, with no native row.
    let certificate_chirho = run_convergence_chirho(
        &fixture_chirho,
        &proof_chirho,
        convergence_binding_chirho(),
        satisfied_predicates_chirho(),
    )
    .expect("an imported, verified compensated receipt certifies convergence");
    assert_eq!(certificate_chirho.population_count_chirho(), 1);
    assert_eq!(
        certificate_chirho
            .verified_v2_counts_chirho()
            .expect("v2 certificate"),
        (1, 0),
        "the imported obligation counts as compensated: completed_count == population, disposed == 0"
    );
}

#[test]
fn convergence_certificate_binds_measured_losing_population_not_a_caller_literal_chirho() {
    // The certificate's losing-population digests are MEASURED from the enumerated population, and
    // `losing_population_digest_chirho` is exactly what flows into the signed D4 confirmation as
    // `closed_population_digest_chirho`. This proves they are measured, not the caller literals every
    // pre-brick binding supplied: the signed values equal an independent measurement over the same
    // walk; they are NOT the "1"/"f" repeats; a different-size population measures differently (count
    // discriminator); and perturbing ONE member's position moves the digest (member discriminator).
    // A fold that ignored the population — returning a constant — fails both discriminators.
    let fixture_chirho = obligation_mint_fixture_chirho("convergence-measured-population");
    let (mint_identity_digest_chirho, canonical_obligation_digest_chirho) =
        alternate_population_mint_identity_chirho(&fixture_chirho);
    let state_chirho = create_convergence_row_chirho(
        &fixture_chirho,
        &mint_identity_digest_chirho,
        &canonical_obligation_digest_chirho,
    );
    drive_row_to_completed_chirho(&fixture_chirho, &state_chirho);
    let proof_chirho = alternate_convergence_proof_chirho(&fixture_chirho, 1);

    let certificate_chirho = run_convergence_chirho(
        &fixture_chirho,
        &proof_chirho,
        convergence_binding_chirho(),
        satisfied_predicates_chirho(),
    )
    .expect("a completed population certifies");

    // Independent measurement over the SAME enumerated population the converger walked.
    let effect_ports_chirho = fixture_chirho.effect_ports_chirho();
    let population_chirho = enumerate_gd7_sealed_plan_obligations_chirho(
        &fixture_chirho.storage_chirho,
        &fixture_chirho.held_signer_chirho,
        &fixture_chirho.losing_record_verifier_chirho,
        &effect_ports_chirho,
        &fixture_chirho.alternate_checkpoint_chirho,
    )
    .expect("walk the complete two-page manifest chain");
    let measured_chirho =
        measure_gd7_losing_population_chirho(&population_chirho).expect("measure the population");

    assert_eq!(
        certificate_chirho.losing_population_digest_chirho(),
        measured_chirho.losing_population_digest_chirho,
        "the signed closed-population digest must be the MEASURED value, not a caller literal"
    );
    assert_eq!(
        certificate_chirho.losing_population_identity_chirho(),
        measured_chirho.losing_population_identity_chirho
    );

    // Not the pre-brick caller literals.
    assert_ne!(
        certificate_chirho.losing_population_digest_chirho(),
        "1".repeat(64).as_str()
    );
    assert_ne!(
        certificate_chirho.losing_population_identity_chirho(),
        "f".repeat(64).as_str()
    );

    // Count discriminator: an empty population measures differently, so the fold is not a constant.
    let empty_measured_chirho =
        measure_gd7_losing_population_chirho(&[]).expect("measure an empty population");
    assert_ne!(
        measured_chirho.losing_population_digest_chirho,
        empty_measured_chirho.losing_population_digest_chirho
    );
    assert_ne!(
        measured_chirho.losing_population_identity_chirho,
        empty_measured_chirho.losing_population_identity_chirho
    );

    // Member discriminator: perturbing one member's plan-page position moves the measured digest.
    let perturbed_member_chirho = verified_gd7_sealed_plan_obligation_for_test_chirho(
        digest_chirho('a').0,
        population_chirho[0].plan_page_index_chirho() + 1,
        population_chirho[0].obligation_index_chirho(),
        population_chirho[0].obligation_chirho().clone(),
    );
    let perturbed_measured_chirho =
        measure_gd7_losing_population_chirho(std::slice::from_ref(&perturbed_member_chirho))
            .expect("measure the perturbed population");
    assert_ne!(
        measured_chirho.losing_population_digest_chirho,
        perturbed_measured_chirho.losing_population_digest_chirho,
        "perturbing one member's position must move the measured digest"
    );

    // retained_refs are BOUND from the verified proof, not the "2".repeat(64) caller literal.
    let retained_chirho = certificate_chirho.retained_refs_chirho();
    assert!(
        retained_chirho.contains(&fixture_chirho.alternate_checkpoint_ref_chirho),
        "the verified plan checkpoint is a retained ref"
    );
    assert!(
        retained_chirho.contains(&fixture_chirho.alternate_obligation_plan_ref_chirho),
        "the verified sealed-plan root is a retained ref"
    );
    assert!(
        !retained_chirho.contains(&"2".repeat(64)),
        "the pre-brick retained-refs caller literal is gone"
    );
    fixture_chirho.assert_source_objects_unchanged_chirho();
}

/// The COMPLETION-1 reviewer's direct-caller arm, driving the PRODUCTION SEAM the drill does not
/// isolate: `import_converged_compensation_receipt_over_population_chirho` — enumerate + coordinate
/// derivation + per-obligation match — rather than the low-level single-obligation import the
/// end-to-end acceptance above exercises. A FORGED receipt (tampered signature) fails closed; a
/// GENUINE receipt for a DIFFERENT obligation refuses (resolve-not-match); only the genuine receipt
/// for THIS obligation persists a held-signed row and lets the converger certify. Both refusals leave
/// the obligation OPEN, since the fail-closed mover persists nothing.
///
/// Non-vacuity (mutation-proven): disabling the mover's winner-signature check turns the FORGED arm
/// green-to-red (the forged receipt would then persist a row); disabling the classifier's import
/// consult turns the GENUINE arm red (the persisted row would no longer certify).
///
/// ONE journal verifier serves both the manifest enumeration AND the winner-record check, exactly as
/// production wires it — so the winner compensation record is signed with the fixture's journal
/// verifier, not the self-contained winner fake used above.
#[test]
fn reviewer_over_population_forged_and_sibling_refuse_only_genuine_certifies_chirho() {
    let fixture_chirho = obligation_mint_fixture_chirho("over-population-direct-caller");
    let effect_ports_chirho = fixture_chirho.effect_ports_chirho();
    let population_chirho = enumerate_gd7_sealed_plan_obligations_chirho(
        &fixture_chirho.storage_chirho,
        &fixture_chirho.held_signer_chirho,
        &fixture_chirho.losing_record_verifier_chirho,
        &effect_ports_chirho,
        &fixture_chirho.alternate_checkpoint_chirho,
    )
    .expect("walk the complete two-page manifest chain");
    assert_eq!(population_chirho.len(), 1);
    let intent_ref_chirho = population_chirho[0]
        .obligation_chirho()
        .intent_ref_chirho
        .0
        .clone();
    let (mint_identity_digest_chirho, _canonical_obligation_digest_chirho) =
        gd7_mint_identity_for_verified_obligation_chirho(
            &digest_chirho('e').0,
            &fixture_chirho.alternate_checkpoint_ref_chirho,
            &fixture_chirho.alternate_obligation_plan_ref_chirho,
            &fixture_chirho.identity_digest_chirho,
            fixture_chirho.identity_chirho.winner_term_chirho,
            &population_chirho[0],
        )
        .expect("derive the population obligation's mint identity");
    let proof_chirho = alternate_convergence_proof_chirho(&fixture_chirho, 1);
    let winner_term_chirho = proof_chirho.winner_term_chirho();
    // The adopted coordinate the classifier uses for this fixture; the mover must be handed the same
    // one so its persisted row's mint identity is the one the classifier looks up.
    let adopted_ref_chirho = digest_chirho('e').0;
    let original_effect_key_chirho = format!(
        "{}{intent_ref_chirho}",
        cairn_effect_commit_chirho::intent_chirho::EFFECT_INTENT_KEY_PREFIX_CHIRHO
    );

    let run_mover_chirho = |record_line_chirho: &str| {
        super::super::converged_import_chirho::import_converged_compensation_receipt_over_population_chirho(
            &fixture_chirho.storage_chirho,
            &fixture_chirho.held_signer_chirho,
            &fixture_chirho.losing_record_verifier_chirho,
            &fixture_chirho.effect_ports_chirho(),
            &fixture_chirho.alternate_checkpoint_chirho,
            &proof_chirho,
            &adopted_ref_chirho,
            record_line_chirho,
        )
    };
    let obligation_open_chirho = || {
        run_convergence_chirho(
            &fixture_chirho,
            &proof_chirho,
            convergence_binding_chirho(),
            satisfied_predicates_chirho(),
        )
    };

    // (1) FORGED receipt: a genuine line for THIS obligation with a tampered signature. The mover
    //     checks the winner signature FIRST, so it fails closed and persists nothing.
    let genuine_line_chirho = journal_signed_winner_compensation_line_chirho(
        &fixture_chirho,
        &original_effect_key_chirho,
        winner_term_chirho,
    );
    let forged_line_chirho = forge_record_signature_chirho(&genuine_line_chirho);
    assert_eq!(
        run_mover_chirho(&forged_line_chirho),
        Err(Gd7PlanRefusalChirho::InvalidTerminalEvidenceChirho),
        "a forged winner-receipt signature must fail closed at the mover"
    );
    assert_eq!(
        obligation_open_chirho(),
        Err(Gd7PlanRefusalChirho::UnconvergedObligationChirho(
            mint_identity_digest_chirho.clone()
        )),
        "a forged receipt persists nothing, so the obligation stays OPEN"
    );

    // (2) SIBLING receipt: a genuinely-signed receipt for a DIFFERENT obligation's effect key. Its
    //     deterministic compensation coordinate matches no enumerated obligation, so the mover
    //     resolves-not-matches and persists nothing.
    // A different, well-formed original effect key (a lower-hex digest tail, as the format requires),
    // so the sibling record is genuinely signed and only its compensation coordinate differs.
    let sibling_effect_key_chirho = format!(
        "{}{}",
        cairn_effect_commit_chirho::intent_chirho::EFFECT_INTENT_KEY_PREFIX_CHIRHO,
        digest_chirho('9').0
    );
    assert_ne!(sibling_effect_key_chirho, original_effect_key_chirho);
    let sibling_line_chirho = journal_signed_winner_compensation_line_chirho(
        &fixture_chirho,
        &sibling_effect_key_chirho,
        winner_term_chirho,
    );
    assert_eq!(
        run_mover_chirho(&sibling_line_chirho),
        Err(Gd7PlanRefusalChirho::InvalidTerminalEvidenceChirho),
        "a genuine receipt for a DIFFERENT obligation must not satisfy this one (resolve-not-match)"
    );
    assert_eq!(
        obligation_open_chirho(),
        Err(Gd7PlanRefusalChirho::UnconvergedObligationChirho(
            mint_identity_digest_chirho.clone()
        )),
        "a sibling receipt persists nothing, so the obligation stays OPEN"
    );

    // (3) GENUINE receipt for THIS obligation: the mover persists a held-signed row and the converger
    //     certifies over the compensated terminal — population == 1, verified_v2_counts == (1, 0).
    let receipt_digest_chirho = run_mover_chirho(&genuine_line_chirho)
        .expect("the genuine winner receipt verifies and imports over the population");
    assert_eq!(receipt_digest_chirho.len(), 64);
    let certificate_chirho = obligation_open_chirho()
        .expect("the imported compensated receipt certifies convergence over the population");
    assert_eq!(certificate_chirho.population_count_chirho(), 1);
    assert_eq!(
        certificate_chirho
            .verified_v2_counts_chirho()
            .expect("v2 certificate"),
        (1, 0),
        "the imported obligation counts as compensated: completed == population, disposed == 0"
    );
}
