// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! An under-count must be impossible: truncation moves the digest, a broken chain refuses everything,
//! and an empty log refuses by name rather than reporting a confident zero.

use super::*;
use crate::tests_chirho::{fixture_chirho, FixtureChirho};
use crate::{
    tenant_placement_intent_digest_chirho,
    unsigned_tenant_placement_held_observer_readiness_message_chirho,
    unsigned_tenant_placement_readiness_message_chirho,
    unsigned_tenant_placement_record_message_chirho,
};
use cairn_signer_chirho::signer_chirho::sign_message_chirho;
use tempfile::TempDir;

/// Author the next revision for the fixture's tenant, re-signing every receipt.
///
/// Every readiness receipt binds the intent digest, so a new revision cannot reuse the old
/// signatures — which is exactly why the chain is worth checking rather than assuming.
pub(crate) fn successor_chirho(
    fixture_chirho: &FixtureChirho,
    base_chirho: &TenantPlacementRecordChirho,
    revision_chirho: u64,
    previous_assignment_digest_chirho: Option<String>,
) -> TenantPlacementRecordChirho {
    let mut intent_chirho = base_chirho.intent_chirho.clone();
    intent_chirho.revision_chirho = revision_chirho;
    intent_chirho.previous_assignment_digest_chirho = previous_assignment_digest_chirho;
    let intent_digest_chirho = tenant_placement_intent_digest_chirho(&intent_chirho).unwrap();

    let serving_chirho = base_chirho
        .serving_readiness_receipts_chirho
        .iter()
        .zip(&fixture_chirho.serving_node_roots_chirho)
        .map(|(receipt_chirho, root_chirho)| {
            let mut receipt_chirho = receipt_chirho.clone();
            receipt_chirho.intent_digest_chirho = intent_digest_chirho.clone();
            receipt_chirho.sig_chirho = String::new();
            let unsigned_chirho =
                unsigned_tenant_placement_readiness_message_chirho(&receipt_chirho).unwrap();
            receipt_chirho.sig_chirho = sign_message_chirho(root_chirho, &unsigned_chirho).unwrap();
            receipt_chirho
        })
        .collect::<Vec<_>>();

    let mut held_chirho = base_chirho.held_observer_readiness_receipt_chirho.clone();
    held_chirho.intent_digest_chirho = intent_digest_chirho.clone();
    held_chirho.sig_chirho = String::new();
    let unsigned_chirho =
        unsigned_tenant_placement_held_observer_readiness_message_chirho(&held_chirho).unwrap();
    held_chirho.sig_chirho =
        sign_message_chirho(&fixture_chirho.held_observer_root_chirho, &unsigned_chirho).unwrap();

    let mut record_chirho = base_chirho.clone();
    record_chirho.intent_chirho = intent_chirho;
    record_chirho.intent_digest_chirho = intent_digest_chirho;
    record_chirho.serving_readiness_receipts_chirho = serving_chirho;
    record_chirho.held_observer_readiness_receipt_chirho = held_chirho;
    record_chirho.sig_chirho = String::new();
    let unsigned_chirho = unsigned_tenant_placement_record_message_chirho(&record_chirho).unwrap();
    record_chirho.sig_chirho =
        sign_message_chirho(&fixture_chirho.placement_root_chirho, &unsigned_chirho).unwrap();
    record_chirho
}

fn append_chirho(
    root_chirho: &std::path::Path,
    fixture_chirho: &FixtureChirho,
    record_chirho: TenantPlacementRecordChirho,
) -> Result<VerifiedTenantPlacementChirho, PlacementRecordStoreRefusalChirho> {
    append_verified_placement_record_chirho(
        root_chirho,
        record_chirho,
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
}

fn load_chirho(
    root_chirho: &std::path::Path,
    fixture_chirho: &FixtureChirho,
    expected_chirho: &str,
) -> Result<VerifiedPlacementPopulationChirho, PlacementRecordStoreRefusalChirho> {
    load_verified_placement_population_chirho(
        root_chirho,
        expected_chirho,
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
}

/// EXACT-CURRENT LOAD — the positive control. Every other arm here could pass on a broken fixture.
#[test]
fn the_current_placement_is_the_head_of_the_verified_chain_chirho() {
    let temp_chirho = TempDir::new().unwrap();
    let root_chirho = temp_chirho.path();
    let fixture_chirho = fixture_chirho();

    let base_chirho = append_chirho(
        root_chirho,
        &fixture_chirho,
        fixture_chirho.record_chirho.clone(),
    )
    .expect("revision 0 appends");
    let rev0_digest_chirho = base_chirho.assignment_digest_chirho().to_string();

    let rev1_chirho = successor_chirho(
        &fixture_chirho,
        &fixture_chirho.record_chirho,
        1,
        Some(rev0_digest_chirho),
    );
    let rev1_verified_chirho =
        append_chirho(root_chirho, &fixture_chirho, rev1_chirho).expect("revision 1 appends");
    let expected_chirho = tenant_placement_population_digest_chirho(&[rev1_verified_chirho
        .assignment_digest_chirho()
        .to_string()]);

    let population_chirho =
        load_chirho(root_chirho, &fixture_chirho, &expected_chirho).expect("the chain loads");
    assert_eq!(population_chirho.current_chirho().len(), 1, "one tenant");
    assert_eq!(
        population_chirho.current_chirho()[0]
            .intent_chirho()
            .revision_chirho,
        1,
        "the CURRENT record is the head, not the first"
    );
    assert_eq!(
        population_chirho.population_digest_chirho(),
        expected_chirho
    );
}

/// ZERO — a named refusal, never an empty success.
#[test]
fn an_empty_log_refuses_by_name_rather_than_reporting_no_placements_chirho() {
    let temp_chirho = TempDir::new().unwrap();
    let fixture_chirho = fixture_chirho();
    let refusal_chirho = load_chirho(temp_chirho.path(), &fixture_chirho, &"0".repeat(64))
        .expect_err("an empty population must refuse");
    assert_eq!(
        refusal_chirho,
        PlacementRecordStoreRefusalChirho::NoCurrentPlacementsChirho,
        "a confident empty here becomes a confident zero reservation one layer up"
    );
}

/// TRUNCATION / OMISSION — removing the head moves the digest, so it cannot silently undercount.
#[test]
fn a_truncated_log_refuses_because_the_population_digest_moves_chirho() {
    let temp_chirho = TempDir::new().unwrap();
    let root_chirho = temp_chirho.path();
    let fixture_chirho = fixture_chirho();

    let rev0_chirho = append_chirho(
        root_chirho,
        &fixture_chirho,
        fixture_chirho.record_chirho.clone(),
    )
    .expect("revision 0 appends");
    let rev1_chirho = successor_chirho(
        &fixture_chirho,
        &fixture_chirho.record_chirho,
        1,
        Some(rev0_chirho.assignment_digest_chirho().to_string()),
    );
    let rev1_verified_chirho =
        append_chirho(root_chirho, &fixture_chirho, rev1_chirho).expect("revision 1 appends");
    let pinned_chirho = tenant_placement_population_digest_chirho(&[rev1_verified_chirho
        .assignment_digest_chirho()
        .to_string()]);
    load_chirho(root_chirho, &fixture_chirho, &pinned_chirho).expect("control: it loads first");

    // Truncate the head line, exactly as a deletion or a partial write would.
    let log_chirho = root_chirho.join(TENANT_PLACEMENT_RECORD_LOG_CHIRHO);
    let text_chirho = std::fs::read_to_string(&log_chirho).unwrap();
    let kept_chirho: Vec<&str> = text_chirho.lines().take(1).collect();
    std::fs::write(&log_chirho, format!("{}\n", kept_chirho.join("\n"))).unwrap();

    let refusal_chirho = load_chirho(root_chirho, &fixture_chirho, &pinned_chirho)
        .expect_err("a truncated log must refuse");
    assert!(
        matches!(
            refusal_chirho,
            PlacementRecordStoreRefusalChirho::PopulationDigestMismatchChirho { .. }
        ),
        "truncation must be a digest mismatch, not a smaller world: {refusal_chirho:?}"
    );
}

/// CHAIN BREAK — a revision whose declared predecessor is not its actual one.
#[test]
fn a_broken_predecessor_refuses_the_whole_population_chirho() {
    let temp_chirho = TempDir::new().unwrap();
    let root_chirho = temp_chirho.path();
    let fixture_chirho = fixture_chirho();

    append_chirho(
        root_chirho,
        &fixture_chirho,
        fixture_chirho.record_chirho.clone(),
    )
    .expect("revision 0 appends");
    // A well-formed but WRONG predecessor: valid lower-hex, not the actual revision-0 digest.
    let forged_chirho = successor_chirho(
        &fixture_chirho,
        &fixture_chirho.record_chirho,
        1,
        Some("a".repeat(64)),
    );
    append_chirho(root_chirho, &fixture_chirho, forged_chirho)
        .expect("it appends; the CHAIN is what refuses");

    let refusal_chirho = load_chirho(root_chirho, &fixture_chirho, &"0".repeat(64))
        .expect_err("a broken chain must refuse");
    assert!(
        matches!(
            refusal_chirho,
            PlacementRecordStoreRefusalChirho::BrokenPredecessorChirho { .. }
        ),
        "must refuse by the CHAIN identity, not by the digest mismatch that would also be true: {refusal_chirho:?}"
    );
}

/// SKIPPED REVISION — a hole in the chain is not a smaller chain.
#[test]
fn a_skipped_revision_refuses_the_whole_population_chirho() {
    let temp_chirho = TempDir::new().unwrap();
    let root_chirho = temp_chirho.path();
    let fixture_chirho = fixture_chirho();

    let rev0_chirho = append_chirho(
        root_chirho,
        &fixture_chirho,
        fixture_chirho.record_chirho.clone(),
    )
    .expect("revision 0 appends");
    let rev2_chirho = successor_chirho(
        &fixture_chirho,
        &fixture_chirho.record_chirho,
        2,
        Some(rev0_chirho.assignment_digest_chirho().to_string()),
    );
    append_chirho(root_chirho, &fixture_chirho, rev2_chirho).expect("it appends");

    let refusal_chirho = load_chirho(root_chirho, &fixture_chirho, &"0".repeat(64))
        .expect_err("a skipped revision must refuse");
    assert!(
        matches!(
            refusal_chirho,
            PlacementRecordStoreRefusalChirho::SkippedRevisionChirho { .. }
        ),
        "got {refusal_chirho:?}"
    );
}

/// IDEMPOTENCY is exact-bytes only, and a conflicting replay at the same revision refuses.
#[test]
fn an_exact_duplicate_is_idempotent_but_a_conflicting_replay_refuses_chirho() {
    let temp_chirho = TempDir::new().unwrap();
    let root_chirho = temp_chirho.path();
    let fixture_chirho = fixture_chirho();

    append_chirho(
        root_chirho,
        &fixture_chirho,
        fixture_chirho.record_chirho.clone(),
    )
    .expect("revision 0 appends");
    append_chirho(
        root_chirho,
        &fixture_chirho,
        fixture_chirho.record_chirho.clone(),
    )
    .expect("an EXACT duplicate is idempotent");
    let log_chirho = root_chirho.join(TENANT_PLACEMENT_RECORD_LOG_CHIRHO);
    assert_eq!(
        std::fs::read_to_string(&log_chirho)
            .unwrap()
            .lines()
            .count(),
        1,
        "the duplicate appended nothing"
    );

    // A conflicting ref at the SAME revision, forged directly into the log.
    //
    // Deliberately not built by re-signing: ed25519 signing here is deterministic, so re-authoring
    // revision 0 yields byte-identical bytes and would take the idempotent path instead — the arm
    // would pass while testing the opposite branch.
    let log_chirho = root_chirho.join(TENANT_PLACEMENT_RECORD_LOG_CHIRHO);
    let forged_chirho = TenantPlacementRecordRefChirho {
        schema_chirho: TENANT_PLACEMENT_RECORD_REF_SCHEMA_V1_CHIRHO.to_string(),
        tenant_id_chirho: fixture_chirho
            .record_chirho
            .intent_chirho
            .tenant_id_chirho
            .clone(),
        revision_chirho: 0,
        assignment_digest_chirho: "b".repeat(64),
    };
    let mut line_chirho = serde_json::to_vec(&forged_chirho).unwrap();
    line_chirho.push(b'\n');
    use std::io::Write;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&log_chirho)
        .unwrap()
        .write_all(&line_chirho)
        .unwrap();

    let refusal_chirho = load_chirho(root_chirho, &fixture_chirho, &"0".repeat(64))
        .expect_err("a conflicting replay must refuse");
    assert!(
        matches!(
            refusal_chirho,
            PlacementRecordStoreRefusalChirho::ForkedRevisionChirho { .. }
        ),
        "got {refusal_chirho:?}"
    );
}

/// Append a raw ref line, bypassing the append path — the direct-write adversary the log's own
/// identity checks already assume exists.
fn forge_ref_line_chirho(
    root_chirho: &std::path::Path,
    ref_chirho: &TenantPlacementRecordRefChirho,
) {
    use std::io::Write;
    let mut line_chirho = serde_json::to_vec(ref_chirho).unwrap();
    line_chirho.push(b'\n');
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root_chirho.join(TENANT_PLACEMENT_RECORD_LOG_CHIRHO))
        .unwrap()
        .write_all(&line_chirho)
        .unwrap();
}

/// A ref naming bytes that were never stored refuses as UNRESOLVED, and does not read as an
/// absent tenant.
#[test]
fn a_ref_naming_an_unstored_record_refuses_as_absent_chirho() {
    let temp_chirho = TempDir::new().unwrap();
    let root_chirho = temp_chirho.path();
    let fixture_chirho = fixture_chirho();
    append_chirho(
        root_chirho,
        &fixture_chirho,
        fixture_chirho.record_chirho.clone(),
    )
    .expect("revision 0 appends");

    forge_ref_line_chirho(
        root_chirho,
        &TenantPlacementRecordRefChirho {
            schema_chirho: TENANT_PLACEMENT_RECORD_REF_SCHEMA_V1_CHIRHO.to_string(),
            tenant_id_chirho: "zzz-absent-tenant-chirho".to_string(),
            revision_chirho: 0,
            assignment_digest_chirho: "c".repeat(64),
        },
    );

    let refusal_chirho = load_chirho(root_chirho, &fixture_chirho, &"0".repeat(64))
        .expect_err("an unresolvable ref must refuse");
    assert!(
        matches!(
            refusal_chirho,
            PlacementRecordStoreRefusalChirho::RecordAbsentChirho { .. }
        ),
        "a ref pointing nowhere must refuse the population, not shrink it: {refusal_chirho:?}"
    );
}

/// CAS bytes edited after the fact resolve fine and must not be trusted for that.
///
/// `get_object_chirho` does not re-hash, so this is the arm that proves the loader's own re-derivation
/// is what catches an edited object — not the store layer beneath it.
#[test]
fn tampered_cas_bytes_refuse_as_tampered_chirho() {
    let temp_chirho = TempDir::new().unwrap();
    let root_chirho = temp_chirho.path();
    let fixture_chirho = fixture_chirho();
    let verified_chirho = append_chirho(
        root_chirho,
        &fixture_chirho,
        fixture_chirho.record_chirho.clone(),
    )
    .expect("revision 0 appends");
    let digest_chirho = verified_chirho.assignment_digest_chirho().to_string();

    // Objects live at <root>/objects-chirho/ab/cdef… — overwrite in place with different VALID bytes.
    let object_chirho = root_chirho
        .join("objects-chirho")
        .join(&digest_chirho[0..2])
        .join(&digest_chirho[2..]);
    assert!(object_chirho.exists(), "control: the object was stored");
    let mut edited_chirho = fixture_chirho.record_chirho.clone();
    edited_chirho.intent_chirho.revision_chirho = 99;
    std::fs::write(&object_chirho, serde_json::to_vec(&edited_chirho).unwrap()).unwrap();

    let refusal_chirho = load_chirho(root_chirho, &fixture_chirho, &"0".repeat(64))
        .expect_err("edited CAS bytes must refuse");
    assert!(
        matches!(
            refusal_chirho,
            PlacementRecordStoreRefusalChirho::RecordTamperedChirho { .. }
        ),
        "present-but-edited must refuse as TAMPERED, never as absent: {refusal_chirho:?}"
    );
}

/// A record that does not verify against the supplied authority refuses, and refuses as UNVERIFIABLE
/// rather than as absent or malformed.
#[test]
fn a_record_checked_against_the_wrong_authority_refuses_as_unverifiable_chirho() {
    let temp_chirho = TempDir::new().unwrap();
    let root_chirho = temp_chirho.path();
    let fixture_chirho = fixture_chirho();
    append_chirho(
        root_chirho,
        &fixture_chirho,
        fixture_chirho.record_chirho.clone(),
    )
    .expect("revision 0 appends");

    // The roster key is a real public key and the WRONG one for this role.
    let refusal_chirho = load_verified_placement_population_chirho(
        root_chirho,
        &"0".repeat(64),
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .expect_err("the wrong placement authority must refuse");
    assert!(
        matches!(
            refusal_chirho,
            PlacementRecordStoreRefusalChirho::RecordUnverifiableChirho { .. }
        ),
        "got {refusal_chirho:?}"
    );
}

/// A ref carrying an unknown schema refuses at the line, before anything is resolved.
#[test]
fn a_ref_with_an_unknown_schema_refuses_at_its_line_chirho() {
    let temp_chirho = TempDir::new().unwrap();
    let root_chirho = temp_chirho.path();
    let fixture_chirho = fixture_chirho();
    forge_ref_line_chirho(
        root_chirho,
        &TenantPlacementRecordRefChirho {
            schema_chirho: "tenant-placement-record-ref-v0-chirho".to_string(),
            tenant_id_chirho: "tenant-chirho".to_string(),
            revision_chirho: 0,
            assignment_digest_chirho: "d".repeat(64),
        },
    );
    let refusal_chirho = load_chirho(root_chirho, &fixture_chirho, &"0".repeat(64))
        .expect_err("an unknown ref schema must refuse");
    assert!(
        matches!(
            refusal_chirho,
            PlacementRecordStoreRefusalChirho::RefSchemaChirho { line_chirho: 1 }
        ),
        "got {refusal_chirho:?}"
    );
}

/// PRESENT BUT UNREADABLE is a third thing, and a planted directory forces it deterministically.
///
/// The two-case fix — absent or tampered — reads as complete and leaves this one to fall through
/// whichever arm the implementation happened to write first. That is why the CAS layer offers four
/// variants and why this store handles them exhaustively.
#[test]
fn an_unreadable_object_refuses_as_unreadable_not_as_absent_chirho() {
    let temp_chirho = TempDir::new().unwrap();
    let root_chirho = temp_chirho.path();
    let fixture_chirho = fixture_chirho();
    let verified_chirho = append_chirho(
        root_chirho,
        &fixture_chirho,
        fixture_chirho.record_chirho.clone(),
    )
    .expect("revision 0 appends");
    let digest_chirho = verified_chirho.assignment_digest_chirho().to_string();

    let object_chirho = root_chirho
        .join("objects-chirho")
        .join(&digest_chirho[0..2])
        .join(&digest_chirho[2..]);
    std::fs::remove_file(&object_chirho).unwrap();
    std::fs::create_dir(&object_chirho).unwrap();

    let refusal_chirho = load_chirho(root_chirho, &fixture_chirho, &"0".repeat(64))
        .expect_err("an unreadable object must refuse");
    assert!(
        matches!(
            refusal_chirho,
            PlacementRecordStoreRefusalChirho::RecordUnreadableChirho { .. }
        ),
        "present-but-unreadable is NOT absence — absence is the only outcome for which looking \
         elsewhere would be legitimate: {refusal_chirho:?}"
    );
}

/// A pin taken BEFORE a new revision lands is stale afterward, and refuses.
///
/// This is the placement half of the identity-drift property, proven at the store layer where it
/// lives rather than at the migration layer that consumes it. The composition brick will assert the
/// same drift end to end; this pins the mechanism it will rely on, so a failure there can be
/// localised to the composition rather than to the digest.
///
/// **The refusal is on CORRECT input and that is the point.** Appending a legitimate revision SHOULD
/// invalidate an operator's pin until they review and reauthor it — that is what makes the pin an
/// external review rather than a rolling read. A later reader who meets this refusal and "fixes" it by
/// recomputing the expectation beside the log has turned the check into one that cannot fail.
#[test]
fn a_pin_taken_before_a_new_revision_is_stale_afterward_chirho() {
    let temp_chirho = TempDir::new().unwrap();
    let root_chirho = temp_chirho.path();
    let fixture_chirho = fixture_chirho();

    let rev0_chirho = append_chirho(
        root_chirho,
        &fixture_chirho,
        fixture_chirho.record_chirho.clone(),
    )
    .expect("revision 0 appends");
    let before_chirho = report_placement_population_for_review_chirho(
        root_chirho,
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .expect("the candidate reports")
    .population_digest_chirho()
    .to_string();
    load_chirho(root_chirho, &fixture_chirho, &before_chirho)
        .expect("control: the pin is good before the drift");

    let rev1_chirho = successor_chirho(
        &fixture_chirho,
        &fixture_chirho.record_chirho,
        1,
        Some(rev0_chirho.assignment_digest_chirho().to_string()),
    );
    append_chirho(root_chirho, &fixture_chirho, rev1_chirho).expect("revision 1 appends");

    let after_chirho = report_placement_population_for_review_chirho(
        root_chirho,
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .expect("the candidate reports again")
    .population_digest_chirho()
    .to_string();
    assert_ne!(
        before_chirho, after_chirho,
        "a new current revision MUST move the population digest, or no pin could detect one"
    );

    let refusal_chirho = load_chirho(root_chirho, &fixture_chirho, &before_chirho)
        .expect_err("the stale pin must refuse");
    assert!(
        matches!(
            refusal_chirho,
            PlacementRecordStoreRefusalChirho::PopulationDigestMismatchChirho { .. }
        ),
        "and by the mismatch identity, not by a chain or vacuity refusal: {refusal_chirho:?}"
    );
    load_chirho(root_chirho, &fixture_chirho, &after_chirho)
        .expect("and the REAUTHORED pin admits again — the refusal is a review prompt, not a wall");
}

/// A ref that lies about WHICH REVISION its record is refuses — a rollback wearing an advance.
///
/// This is the sharpest thing a direct-write adversary can do to this log without breaking any
/// signature. The forged ref names a REAL record that resolves from CAS, re-serialises to its own
/// digest, and verifies against every authority — it simply claims that record is revision 1 when the
/// record itself says revision 0. Nothing cryptographic is violated.
///
/// It matters because the ref's revision, not the record's, is what the chain logic and current-head
/// selection read. Left unchecked, an old placement could be presented as the newest one, which is a
/// rollback that arrives looking like progress — and the population digest computed over it would be
/// a confident wrong answer rather than a refusal.
///
/// Measured 2026-08-21: this identity had no arm. Asserting the EXACT refusal matters here more than
/// usual, because a forged revision also sits near `SkippedRevisionChirho` and `ForkedRevisionChirho`
/// — the disagreement is caught during per-ref resolution, before any chain check, and an arm that
/// accepted any of the three would not pin that ordering.
#[test]
fn a_ref_that_lies_about_its_records_revision_refuses_chirho() {
    let temp_chirho = TempDir::new().unwrap();
    let root_chirho = temp_chirho.path();
    let fixture_chirho = fixture_chirho();

    let revision_zero_chirho = append_chirho(
        root_chirho,
        &fixture_chirho,
        fixture_chirho.record_chirho.clone(),
    )
    .expect("revision 0 appends");
    let revision_zero_digest_chirho = revision_zero_chirho.assignment_digest_chirho().to_string();

    // POSITIVE CONTROL: the log reports cleanly before the forgery.
    report_placement_population_for_review_chirho(
        root_chirho,
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .expect("the honest single-revision log reports");

    forge_ref_line_chirho(
        root_chirho,
        &TenantPlacementRecordRefChirho {
            schema_chirho: TENANT_PLACEMENT_RECORD_REF_SCHEMA_V1_CHIRHO.to_string(),
            tenant_id_chirho: fixture_chirho
                .record_chirho
                .intent_chirho
                .tenant_id_chirho
                .clone(),
            revision_chirho: 1,
            assignment_digest_chirho: revision_zero_digest_chirho.clone(),
        },
    );

    let refusal_chirho = report_placement_population_for_review_chirho(
        root_chirho,
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .expect_err("a ref disagreeing with its own record must refuse");
    assert_eq!(
        refusal_chirho,
        PlacementRecordStoreRefusalChirho::RefRecordDisagreementChirho {
            assignment_digest_chirho: revision_zero_digest_chirho,
        },
        "and by the DISAGREEMENT identity — not by a chain refusal, which would mean the lie was \
         caught only after being admitted into the chain: {refusal_chirho:?}"
    );
}
