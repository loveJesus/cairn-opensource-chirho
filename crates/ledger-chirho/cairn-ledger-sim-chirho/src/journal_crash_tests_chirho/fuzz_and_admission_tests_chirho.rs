// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Seeded crash-fuzz and arithmetic-admission regressions for the real journal harness.

use super::*;

#[test]
fn seeded_crash_fuzz_recovers_to_a_valid_prefix_chirho() {
    // Deterministic seeded fuzz (no wall-clock, no rng) — every seed is reproducible, and any
    // failing seed is PRESERVED in the assertion message as a named regression (CF1 clause 1).
    let failing_seeds_chirho: Vec<u64> = (0..2_000u64)
        .filter(|seed_chirho| !crash_fuzz_seed_holds_chirho(*seed_chirho))
        .collect();
    assert!(
        failing_seeds_chirho.is_empty(),
        "crash-fuzz seeds violated the recovery law (reproduce with these exact seeds): {failing_seeds_chirho:?}"
    );
}

/// Self-audit finding #1: an uncapped-kind mint that would overflow the durable Σ-supply aggregate
/// is REFUSED AT ADMISSION (the sim `MoneyRegistry` is `PlatformPolicy{None}` — uncapped — and the
/// authority verifies any mint, exactly the auditor's exploit shape). Before the fix the second
/// mint was durably appended and then errored in `apply_supply`, bricking reopen; now it never
/// reaches storage and the journal stays openable.
#[test]
fn uncapped_mint_supply_overflow_refused_at_admission_chirho() {
    let views_chirho = ViewsChirho::new_chirho();
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        views_chirho.ports_chirho(&storage_chirho),
        path_chirho(),
        cluster_chirho(),
        1,
    )
    .unwrap();
    let half_chirho = 1_u64 << 63;
    // First mint to issuer: supply = 2^63.
    views_chirho.clock_chirho.tick_chirho();
    engine_chirho
        .append_chirho(mint_chirho(half_chirho, "idem-mint-a"))
        .unwrap();
    // Second mint to a DIFFERENT account of the SAME uncapped kind: supply would be 2^64 -> overflow.
    let mint_bob_chirho = AppendRequestChirho {
        op_chirho: LedgerOpChirho::MintChirho {
            authority_evidence_chirho: DigestChirho(MINT_EVIDENCE_CHIRHO.into()),
        },
        legs_chirho: vec![leg_chirho(
            "bob-chirho",
            LegDeltaChirho::CreditChirho,
            half_chirho,
        )],
        idempotency_key_chirho: "idem-mint-b".to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
    };
    views_chirho.clock_chirho.tick_chirho();
    let reject_chirho = engine_chirho.append_chirho(mint_bob_chirho).unwrap_err();
    assert!(
        matches!(
            reject_chirho,
            JournalErrorChirho::AdmissionChirho {
                reject_chirho: cairn_ledger_log_chirho::admission_chirho::AdmissionRejectChirho::ArithmeticChirho
            }
        ),
        "the overflowing mint must be refused AT ADMISSION, not after a durable append: {reject_chirho:?}"
    );
    // The refused mint left NO durable trace: the journal is genesis + the one good mint, and it
    // reopens cleanly (never bricked by an un-replayable committed record).
    assert_eq!(engine_chirho.tail_chirho().0, 1);
    assert_eq!(
        engine_chirho.supply_chirho(&MONEY_KIND_CHIRHO.into()),
        half_chirho
    );
    drop(engine_chirho);
    let reopened_chirho = LedgerJournalChirho::open_chirho(
        views_chirho.ports_chirho(&storage_chirho),
        path_chirho(),
        &cluster_chirho(),
    )
    .unwrap();
    assert_eq!(reopened_chirho.tail_chirho().0, 1);
    assert_eq!(
        reopened_chirho.supply_chirho(&MONEY_KIND_CHIRHO.into()),
        half_chirho
    );
}
