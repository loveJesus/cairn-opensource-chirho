// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pins the exact bytes the legacy credit-hold evidence readers emit, so an extraction cannot
//! silently change what a subject export contains.
//!
//! **This is the acceptance instrument for CF6-D2 brick (a)** (second seat's design, 2026-07-25).
//! That brick extracts the read-only billing/holds evidence readers out of the deleting money spine
//! into a retained module. The map's stated hazard is not a compile break — it is that *"a successor
//! returning different evidence changes what a subject export CONTAINS"*, because these readers feed
//! `data_rights_chirho`, `source_snapshots_chirho`, `source_collectors_chirho` and
//! `ops_restore_drill_chirho`.
//!
//! Catching that by reading 900 lines of moved code is a judgment call nobody makes reliably. So the
//! check is **differential instead**: run the readers over a fixed corpus and pin the serialized
//! output byte-for-byte. After the extraction the same assertions run against the new readers, and
//! any difference IS the change to a subject export — named and accepted deliberately, or a bug.
//! It needs no reviewer holding the diff in their head, and it fails closed.
//!
//! Landed BEFORE the extraction on purpose: a baseline recorded after a move proves only that the
//! move agrees with itself.

use crate::economic_model_chirho::{
    CreditHoldRecordChirho, CreditHoldStatusChirho, CREDIT_HOLD_RECORD_SCHEMA_CHIRHO,
};
use crate::legacy_holds_evidence_chirho::verify_credit_holds_single_road_chirho as verify_credit_holds_chirho;
// brick (a1): the load_* readers now live in the RETAINED module, which is the point of the move.
use crate::economic_model_chirho::BillingTagsChirho;
use crate::legacy_evidence_readers_chirho::load_credit_holds_chirho;
use cairn_signer_chirho::signer_chirho;
use std::sync::atomic::{AtomicU64, Ordering};

fn temp_root_chirho() -> std::path::PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-legacy-evidence-characterization-{n_chirho}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d_chirho| d_chirho.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

/// One record per terminal state plus an open one, with the optional ledger-seq fields present in
/// some rows and absent in others — `skip_serializing_if` means those two shapes serialize
/// DIFFERENTLY, so a corpus carrying only one of them would not notice a successor that changed the
/// other.
fn hold_record_chirho(
    seq_chirho: u64,
    hold_id_chirho: &str,
    status_chirho: CreditHoldStatusChirho,
    settlement_chirho: Option<u64>,
    release_chirho: Option<u64>,
) -> CreditHoldRecordChirho {
    CreditHoldRecordChirho {
        seq_chirho,
        schema_chirho: CREDIT_HOLD_RECORD_SCHEMA_CHIRHO.to_string(),
        hold_id_chirho: hold_id_chirho.to_string(),
        hold_account_chirho: "holds/acct-chirho".to_string(),
        app_chirho: "app-chirho".to_string(),
        effect_chirho: "effect-chirho".to_string(),
        caller_chirho: "caller-chirho".to_string(),
        payer_chirho: "payer-chirho".to_string(),
        // MONEY CONSERVATION: a terminal hold must have settled + released == authorized. Found by
        // this file failing with "credit hold terminal amounts settle/release 60, not authorized
        // 100" -- the original fixture set settled=60 with nothing released and was silently
        // non-conserving. An open hold resolves neither, and conservation does not yet apply.
        authorized_token_chirho: 100,
        settled_token_chirho: if settlement_chirho.is_some() { 100 } else { 0 },
        released_token_chirho: if release_chirho.is_some() { 100 } else { 0 },
        reserve_ledger_seq_chirho: seq_chirho * 10,
        settlement_ledger_seq_chirho: settlement_chirho,
        release_ledger_seq_chirho: release_chirho,
        status_chirho,
        billing_tags_chirho: BillingTagsChirho {
            user_id_chirho: Some("user-chirho".to_string()),
            app_id_chirho: Some("app-id-chirho".to_string()),
            ..Default::default()
        },
        at_ms_chirho: 1_700_000_000_000 + seq_chirho,
        sig_chirho: format!("sig-{seq_chirho}-chirho"),
    }
}

/// The signed message for a credit-hold record, rebuilt from the format's specification.
///
/// **This is how the "cannot be fixed from this module" gap below was closed.** The production
/// builder `hold_record_message_chirho` is private, and making it public to serve a test would be
/// the wrong trade — but a test never needed it. Declaring the envelope LOCALLY, with its own field
/// order and its own `skip_serializing_if`, produces the same bytes while staying an INDEPENDENT
/// statement of the format: rename or reorder a field in production and the signature stops
/// matching here. `signed_hold_corpus_verifies_clean_chirho` is the keystone that proves the two
/// still agree, so a red cross-record arm can never be silently blamed on a stale rebuild.
fn hold_signature_message_chirho(record_chirho: &CreditHoldRecordChirho) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct HoldRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        hold_id_chirho: &'a str,
        hold_account_chirho: &'a str,
        app_chirho: &'a str,
        effect_chirho: &'a str,
        caller_chirho: &'a str,
        payer_chirho: &'a str,
        authorized_token_chirho: i64,
        settled_token_chirho: i64,
        released_token_chirho: i64,
        reserve_ledger_seq_chirho: u64,
        settlement_ledger_seq_chirho: &'a Option<u64>,
        release_ledger_seq_chirho: &'a Option<u64>,
        status_chirho: &'a CreditHoldStatusChirho,
        billing_tags_chirho: &'a BillingTagsChirho,
        at_ms_chirho: u64,
    }
    serde_json::to_vec(&HoldRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: (!record_chirho.schema_chirho.is_empty())
            .then_some(record_chirho.schema_chirho.as_str()),
        hold_id_chirho: &record_chirho.hold_id_chirho,
        hold_account_chirho: &record_chirho.hold_account_chirho,
        app_chirho: &record_chirho.app_chirho,
        effect_chirho: &record_chirho.effect_chirho,
        caller_chirho: &record_chirho.caller_chirho,
        payer_chirho: &record_chirho.payer_chirho,
        authorized_token_chirho: record_chirho.authorized_token_chirho,
        settled_token_chirho: record_chirho.settled_token_chirho,
        released_token_chirho: record_chirho.released_token_chirho,
        reserve_ledger_seq_chirho: record_chirho.reserve_ledger_seq_chirho,
        settlement_ledger_seq_chirho: &record_chirho.settlement_ledger_seq_chirho,
        release_ledger_seq_chirho: &record_chirho.release_ledger_seq_chirho,
        status_chirho: &record_chirho.status_chirho,
        billing_tags_chirho: &record_chirho.billing_tags_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })
    .expect("encode hold record message")
}

/// Sign a hold record with the root's real key, using the independent reconstruction above.
fn sign_hold_chirho(
    root_chirho: &std::path::Path,
    mut record_chirho: CreditHoldRecordChirho,
) -> CreditHoldRecordChirho {
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &hold_signature_message_chirho(&record_chirho),
    )
    .expect("sign with the root key");
    record_chirho
}

fn write_corpus_chirho(root_chirho: &std::path::Path, records_chirho: &[CreditHoldRecordChirho]) {
    let mut text_chirho = String::new();
    for record_chirho in records_chirho {
        text_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
        text_chirho.push('\n');
    }
    std::fs::write(root_chirho.join("credit-holds-chirho.jsonl"), text_chirho).unwrap();
}

#[test]
fn credit_hold_evidence_bytes_are_pinned_across_extraction_chirho() {
    // THE BASELINE. Any post-extraction difference here is a change to what a subject export
    // contains, which is the thing the map warns is not safe to do unattended.
    let root_chirho = temp_root_chirho();
    let corpus_chirho = vec![
        hold_record_chirho(
            1,
            "hold-settled-chirho",
            CreditHoldStatusChirho::SettledChirho,
            Some(11),
            None,
        ),
        hold_record_chirho(
            2,
            "hold-released-chirho",
            CreditHoldStatusChirho::ReleasedChirho,
            None,
            Some(22),
        ),
        hold_record_chirho(
            3,
            "hold-open-chirho",
            CreditHoldStatusChirho::OpenChirho,
            None,
            None,
        ),
    ];
    write_corpus_chirho(&root_chirho, &corpus_chirho);

    let loaded_chirho = load_credit_holds_chirho(&root_chirho).expect("corpus loads");
    assert_eq!(
        loaded_chirho.len(),
        3,
        "every corpus row must survive the read"
    );
    assert_eq!(
        loaded_chirho, corpus_chirho,
        "the reader must return the records unchanged"
    );

    // Byte-level, not just structural: field ORDER and omitted-vs-empty both matter to an export.
    let emitted_chirho = serde_json::to_string(&loaded_chirho).unwrap();
    assert!(
        emitted_chirho.contains("\"settlement_ledger_seq_chirho\":11"),
        "a present optional ledger seq must serialize: {emitted_chirho}"
    );
    assert!(
        !emitted_chirho.contains("\"settlement_ledger_seq_chirho\":null"),
        "an ABSENT optional must be omitted rather than null -- the two are different bytes in an \
         export, and skip_serializing_if is what makes them differ: {emitted_chirho}"
    );
    assert!(
        emitted_chirho.contains("\"release_ledger_seq_chirho\":22"),
        "the other optional must serialize when present: {emitted_chirho}"
    );

    std::fs::remove_dir_all(&root_chirho).ok();
}

#[test]
fn an_absent_corpus_reads_empty_rather_than_failing_chirho() {
    // A root that never held credit holds is the COMMON case for a subject export, not an edge one.
    // If a successor errored here instead, exports would fail for exactly the subjects with nothing
    // to disclose.
    let root_chirho = temp_root_chirho();
    let loaded_chirho =
        load_credit_holds_chirho(&root_chirho).expect("absent corpus is not an error");
    assert!(loaded_chirho.is_empty());
    assert_eq!(
        verify_credit_holds_chirho(&root_chirho).expect("absent corpus verifies"),
        0
    );
    std::fs::remove_dir_all(&root_chirho).ok();
}

#[test]
fn blank_lines_are_skipped_and_an_unsupported_schema_is_refused_chirho() {
    // The malformed-row arm. A successor that silently SKIPPED a bad row instead of refusing would
    // produce a shorter export that still looked successful -- evidence loss with no error.
    let root_chirho = temp_root_chirho();
    let good_chirho = hold_record_chirho(
        1,
        "hold-a-chirho",
        CreditHoldStatusChirho::SettledChirho,
        Some(11),
        None,
    );
    let mut text_chirho = serde_json::to_string(&good_chirho).unwrap();
    text_chirho.push_str("\n\n"); // a blank line must be tolerated
    let mut bad_chirho = good_chirho.clone();
    bad_chirho.seq_chirho = 2;
    bad_chirho.schema_chirho = "credit-hold-record-v99-chirho".to_string();
    text_chirho.push_str(&serde_json::to_string(&bad_chirho).unwrap());
    text_chirho.push('\n');
    std::fs::write(root_chirho.join("credit-holds-chirho.jsonl"), text_chirho).unwrap();

    let error_chirho = load_credit_holds_chirho(&root_chirho)
        .expect_err("an unsupported schema must refuse, not silently drop the row");
    let rendered_chirho = format!("{error_chirho}");
    assert!(
        rendered_chirho.contains("credit-hold-record-v99-chirho"),
        "the refusal must name the offending schema: {rendered_chirho}"
    );

    std::fs::remove_dir_all(&root_chirho).ok();
}

#[test]
fn verification_refuses_an_unauthentic_signature_before_reading_further_chirho() {
    // THE AUTHENTICITY GATE, and it is pinned here because it is `verify_*`'s FIRST substantive
    // check after sequence continuity -- so it is the property that most constrains a successor.
    //
    // Discovered rather than assumed, and the discovery corrected this file twice. Written first as
    // "an open hold must fail verification", it failed on a seq-gap refusal (seq must start at 0);
    // fixed to seq 0, it then failed with `bad hex` -- the signature decode.
    //
    // MEASURED CHECK ORDER (corrected 2026-07-25; an earlier note here said signatures precede all
    // hold-state evaluation, and that was WRONG). Inside the per-record loop:
    //   1. sequence continuity
    //   2. `validate_hold_record_chirho` -- PER-RECORD state, INCLUDING money conservation
    //   3. the signature
    // and only then, in a second pass, the CROSS-RECORD arms (open/terminal pairing, duplicates).
    // So conservation is reached on an unsigned corpus and the cross-record arms are not, which is
    // why the gap below is about those and not about conservation. The second seat caught the
    // inconsistency by noticing that three reported findings could not all be true at once.
    //
    // A successor that stopped verifying signatures would accept FORGED credit-hold evidence into a
    // subject export and a restore drill, which is strictly worse than any ordering change.
    let root_chirho = temp_root_chirho();
    write_corpus_chirho(
        &root_chirho,
        &[hold_record_chirho(
            0,
            "hold-open-chirho",
            CreditHoldStatusChirho::OpenChirho,
            None,
            None,
        )],
    );
    let error_chirho = verify_credit_holds_chirho(&root_chirho)
        .expect_err("a record whose signature is not decodable must fail verification");
    assert!(
        format!("{error_chirho}").contains("bad hex"),
        "the refusal must be the SIGNATURE check, not an incidental one: {error_chirho}"
    );
    std::fs::remove_dir_all(&root_chirho).ok();
}

// KNOWN GAP -- NARROWED 2026-07-25 after checking rather than assuming. `verify_*`'s CROSS-RECORD
// arms run in a second pass AFTER the signature check, so reaching them needs a corpus signed with
// the root's own key (`signer_chirho::sign_message_chirho`). Every corpus here is unsigned, so
// verification stops at the authenticity gate before that pass, and it cannot be fixed from this
// module: `hold_record_message_chirho` is private, and making a production fn public to serve a test
// is the wrong trade.
//
// I FIRST RECORDED BOTH ARMS AS UNCOVERED. That was overstated, and checking took one grep:
//   - OPEN-HOLD REFUSAL: already covered, by `holds_chirho`'s own
//     `verifies_settled_and_detects_open_holds_chirho`, which builds a REAL signed root -- which is
//     exactly why it can reach the arm and this file cannot. (Worth noting it asserts `is_err()`
//     without naming WHICH failure, the same error-side vacuity corrected in this file. Its root is
//     genuine, so the error is very likely the intended one; "very likely" is the honest word.)
//   - DUPLICATE-SUBJECT VERDICT: genuinely uncovered. That one is the real remaining gap.
// The lesson is the repo's own: ask whether a property is already pinned SOMEWHERE before recording
// it as missing. An absence claim needs a search, not an inference from where you happen to be
// standing.
//
// PER-RECORD checks -- sequence continuity and money conservation -- run BEFORE the signature and
// therefore ARE characterized. That distinction is the whole content of the gap, and it was stated
// wrongly here at first.
//
// This is written down because the alternative was worse: the duplicate-subject arm below ORIGINALLY
// asserted only `is_err()`, which the bad-hex failure satisfied -- so it passed while proving
// nothing about duplicates. A test that passes for a reason it does not name is the vacuity class,
// and the honest fix was to assert the actual reason and record what remains uncovered.
//
// Closing it is a bounded follow-up: build a signed fixture root, then pin the open-hold and
// duplicate verdicts. It is NOT a prerequisite for brick (a) -- the extraction moves these readers,
// and the `load_*` family above is fully pinned, which is the surface a subject export reads.

#[test]
fn verification_refuses_a_seq_gap_and_load_does_not_chirho() {
    // A DISCOVERED behaviour, and a real split in the contract: `verify_*` enforces sequence
    // continuity from zero, `load_*` does not. That asymmetry is deliberate -- an export must be
    // able to READ a damaged log in order to disclose it, while VERIFY is what asserts the log is
    // whole. A successor that moved the seq check into the loader would break subject export for
    // exactly the damaged roots that most need disclosing; one that dropped it from verify would
    // report a gapped ledger as sound.
    let root_chirho = temp_root_chirho();
    write_corpus_chirho(
        &root_chirho,
        &[hold_record_chirho(
            1,
            "hold-gapped-chirho",
            CreditHoldStatusChirho::SettledChirho,
            Some(11),
            None,
        )],
    );

    let loaded_chirho =
        load_credit_holds_chirho(&root_chirho).expect("load must tolerate a seq gap");
    assert_eq!(
        loaded_chirho.len(),
        1,
        "the loader returns the row regardless of seq"
    );

    let error_chirho = verify_credit_holds_chirho(&root_chirho)
        .expect_err("verify must refuse a log that does not start at seq 0");
    assert!(
        format!("{error_chirho}").contains("seq gap"),
        "the refusal must say why: {error_chirho}"
    );
    std::fs::remove_dir_all(&root_chirho).ok();
}

#[test]
fn emitted_record_order_is_pinned_by_two_records_of_the_same_kind_chirho() {
    // THE ORDERING ARM (second seat's catch). One record per state exercises every STATE and no
    // ORDER -- with one element of each kind, every ordering is the same ordering.
    //
    // The failure it guards against is specific and nasty: a successor that collected into a
    // `HashMap` would emit in an order RANDOMISED PER PROCESS, so subject exports would differ
    // RUN TO RUN rather than merely differing from today. Two records of the SAME kind with
    // distinguishable content is what makes that visible.
    let root_chirho = temp_root_chirho();
    let corpus_chirho = vec![
        hold_record_chirho(
            0,
            "hold-first-chirho",
            CreditHoldStatusChirho::SettledChirho,
            Some(10),
            None,
        ),
        hold_record_chirho(
            1,
            "hold-second-chirho",
            CreditHoldStatusChirho::SettledChirho,
            Some(11),
            None,
        ),
        hold_record_chirho(
            2,
            "hold-third-chirho",
            CreditHoldStatusChirho::SettledChirho,
            Some(12),
            None,
        ),
    ];
    write_corpus_chirho(&root_chirho, &corpus_chirho);

    let loaded_chirho = load_credit_holds_chirho(&root_chirho).expect("corpus loads");
    let ids_chirho: Vec<&str> = loaded_chirho
        .iter()
        .map(|record_chirho| record_chirho.hold_id_chirho.as_str())
        .collect();
    assert_eq!(
        ids_chirho,
        vec![
            "hold-first-chirho",
            "hold-second-chirho",
            "hold-third-chirho"
        ],
        "records must be emitted in CORPUS ORDER; any reordering changes an export's bytes"
    );
    std::fs::remove_dir_all(&root_chirho).ok();
}

#[test]
fn two_records_for_the_same_subject_behave_as_pinned_chirho() {
    // Second seat's smaller catch: what happens with TWO rows for the SAME hold id -- last-wins,
    // first-wins, both-emitted, or refuse? Whatever it is today is part of what a subject export
    // CONTAINS, and a successor could change it invisibly. Written to discover rather than assume,
    // after assuming wrongly once already in this file.
    let root_chirho = temp_root_chirho();
    let corpus_chirho = vec![
        hold_record_chirho(
            0,
            "hold-dup-chirho",
            CreditHoldStatusChirho::SettledChirho,
            Some(10),
            None,
        ),
        hold_record_chirho(
            1,
            "hold-dup-chirho",
            CreditHoldStatusChirho::SettledChirho,
            Some(11),
            None,
        ),
    ];
    write_corpus_chirho(&root_chirho, &corpus_chirho);

    // The LOADER is a transcriber: it must disclose both rows, because an export that silently
    // deduplicated would under-disclose.
    let loaded_chirho = load_credit_holds_chirho(&root_chirho).expect("duplicate subjects load");
    assert_eq!(
        loaded_chirho.len(),
        2,
        "the loader must emit BOTH rows -- deduplicating here would under-disclose an export"
    );
    assert_eq!(
        loaded_chirho, corpus_chirho,
        "and emit them unchanged, in order"
    );

    // VERIFY refuses -- but this corpus is UNSIGNED, so it refuses at the authenticity gate rather
    // than on the duplication. Asserting the REASON is the point: this arm originally checked only
    // `is_err()`, which the signature failure satisfied, so it passed while proving nothing about
    // duplicate subjects. Naming the reason converts a vacuous pass into an honest one, and the
    // duplicate verdict itself stays recorded as the known gap above.
    let error_chirho =
        verify_credit_holds_chirho(&root_chirho).expect_err("an unsigned corpus must not verify");
    assert!(
        format!("{error_chirho}").contains("bad hex"),
        "pinned as the authenticity refusal, NOT as a duplicate-subject verdict: {error_chirho}"
    );

    std::fs::remove_dir_all(&root_chirho).ok();
}

#[test]
fn a_terminal_hold_that_does_not_conserve_is_refused_chirho() {
    // MONEY CONSERVATION, and a genuine engine claim rather than a shape pin: a terminal credit hold
    // must resolve exactly what it authorized -- settled + released == authorized. Anything else is
    // tokens created or destroyed at the hold boundary.
    //
    // Discovered by this file, not by reading: the fixture above originally authorized 100 and
    // settled 60 with nothing released, and verification refused with "credit hold terminal amounts
    // settle/release 60, not authorized 100". That refusal is the invariant announcing itself.
    //
    // Pinned because a successor that dropped it would let a subject export and a restore drill
    // report non-conserving holds as sound evidence.
    let root_chirho = temp_root_chirho();
    let mut leaking_chirho = hold_record_chirho(
        0,
        "hold-leak-chirho",
        CreditHoldStatusChirho::SettledChirho,
        Some(10),
        None,
    );
    leaking_chirho.settled_token_chirho = 60; // authorized stays 100; 40 tokens vanish
    write_corpus_chirho(&root_chirho, &[leaking_chirho]);

    let error_chirho = verify_credit_holds_chirho(&root_chirho)
        .expect_err("a non-conserving terminal hold must not verify");
    let rendered_chirho = format!("{error_chirho}");
    assert!(
        rendered_chirho.contains("not authorized"),
        "the refusal must be the CONSERVATION check, not an incidental one: {rendered_chirho}"
    );
    assert!(
        rendered_chirho.contains("60") && rendered_chirho.contains("100"),
        "and must show both sides of the imbalance so an operator can act: {rendered_chirho}"
    );
    std::fs::remove_dir_all(&root_chirho).ok();
}

// ---------------------------------------------------------------------------------------------
// BILLING COMPENSATION EVIDENCE — the second of brick (a)'s three families.
//
// Same shape as the credit-hold readers above and pinned for the same reason: these feed the same
// subject-export and restore-drill surfaces, and the extraction moves them too. Written after the
// holds family proved the pattern.
// ---------------------------------------------------------------------------------------------

use crate::economic_model_chirho::{
    BillingCompensationRecordChirho, BILLING_COMPENSATION_RECORD_SCHEMA_CHIRHO,
};
use crate::legacy_evidence_readers_chirho::load_billing_compensations_chirho;

fn compensation_record_chirho(
    seq_chirho: u64,
    reason_chirho: &str,
    amount_token_chirho: i64,
) -> BillingCompensationRecordChirho {
    BillingCompensationRecordChirho {
        seq_chirho,
        schema_chirho: BILLING_COMPENSATION_RECORD_SCHEMA_CHIRHO.to_string(),
        original_usage_seq_chirho: seq_chirho * 2,
        ledger_seq_chirho: seq_chirho * 3,
        app_chirho: "app-chirho".to_string(),
        caller_chirho: "caller-chirho".to_string(),
        payer_chirho: "payer-chirho".to_string(),
        amount_token_chirho,
        reason_chirho: reason_chirho.to_string(),
        billing_tags_chirho: BillingTagsChirho {
            user_id_chirho: Some("user-chirho".to_string()),
            ..Default::default()
        },
        at_ms_chirho: 1_700_000_000_000 + seq_chirho,
        sig_chirho: format!("sig-{seq_chirho}-chirho"),
    }
}

fn write_compensations_chirho(
    root_chirho: &std::path::Path,
    records_chirho: &[BillingCompensationRecordChirho],
) {
    let mut text_chirho = String::new();
    for record_chirho in records_chirho {
        text_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
        text_chirho.push('\n');
    }
    std::fs::write(
        root_chirho.join("billing-compensations-chirho.jsonl"),
        text_chirho,
    )
    .unwrap();
}

#[test]
fn billing_compensation_bytes_and_order_are_pinned_chirho() {
    // Two records of the SAME kind, per the ordering rule the holds family established: one of each
    // kind cannot detect a reordering, because with one element every order is the same order.
    //
    // A compensation is money returned to a payer, so its ORDER and AMOUNTS are both disclosable
    // facts -- a reordered or re-signed compensation list is a different subject export.
    let root_chirho = temp_root_chirho();
    let corpus_chirho = vec![
        compensation_record_chirho(0, "duplicate charge refunded", 250),
        compensation_record_chirho(1, "failed effect compensated", 125),
        compensation_record_chirho(2, "manual goodwill adjustment", 75),
    ];
    write_compensations_chirho(&root_chirho, &corpus_chirho);

    let loaded_chirho = load_billing_compensations_chirho(&root_chirho).expect("corpus loads");
    assert_eq!(
        loaded_chirho, corpus_chirho,
        "compensations must be returned unchanged AND in corpus order"
    );

    let reasons_chirho: Vec<&str> = loaded_chirho
        .iter()
        .map(|record_chirho| record_chirho.reason_chirho.as_str())
        .collect();
    assert_eq!(
        reasons_chirho,
        vec![
            "duplicate charge refunded",
            "failed effect compensated",
            "manual goodwill adjustment"
        ],
        "reason text is disclosed verbatim to a subject; reordering changes the export"
    );

    let emitted_chirho = serde_json::to_string(&loaded_chirho).unwrap();
    assert!(
        emitted_chirho.contains("\"amount_token_chirho\":250"),
        "amounts must serialize exactly: {emitted_chirho}"
    );
    std::fs::remove_dir_all(&root_chirho).ok();
}

#[test]
fn an_absent_compensation_log_reads_empty_chirho() {
    // Most subjects have no compensations. Erroring here would fail exports for exactly the subjects
    // with nothing to disclose -- the same trap as the credit-hold case.
    let root_chirho = temp_root_chirho();
    let loaded_chirho =
        load_billing_compensations_chirho(&root_chirho).expect("absent log is not an error");
    assert!(loaded_chirho.is_empty());
    std::fs::remove_dir_all(&root_chirho).ok();
}

#[test]
fn a_compensation_with_an_unsupported_schema_is_refused_not_skipped_chirho() {
    // Refusal, not silent skipping. A successor that dropped an unreadable compensation row would
    // under-report money returned to the subject, in a document the subject is entitled to rely on.
    let root_chirho = temp_root_chirho();
    let good_chirho = compensation_record_chirho(0, "refund", 100);
    let mut bad_chirho = compensation_record_chirho(1, "refund", 100);
    bad_chirho.schema_chirho = "billing-compensation-record-v99-chirho".to_string();
    write_compensations_chirho(&root_chirho, &[good_chirho, bad_chirho]);

    let error_chirho = load_billing_compensations_chirho(&root_chirho)
        .expect_err("an unsupported schema must refuse the whole read");
    let rendered_chirho = format!("{error_chirho}");
    assert!(
        rendered_chirho.contains("v99") || rendered_chirho.contains("schema"),
        "the refusal must identify the schema problem: {rendered_chirho}"
    );
    std::fs::remove_dir_all(&root_chirho).ok();
}

// ---------------------------------------------------------------------------------------------
// BILLING USAGE EVIDENCE — brick (a)'s largest disclosure surface.
//
// A usage row is the itemised answer to "what was I charged for, and how was the price composed".
// The FEE SPLIT is the part that matters most: price, external provider cost, platform fee and owner
// margin are separate disclosable facts, and a successor that merged, rounded or dropped any of them
// would change what a person is told about their own money while every total stayed plausible.
// ---------------------------------------------------------------------------------------------

use crate::economic_model_chirho::{
    BillingPayerKindChirho, BillingPolicyModeChirho, BillingUsageRecordChirho,
    BILLING_USAGE_RECORD_SCHEMA_CHIRHO,
};
use crate::legacy_billing_evidence_chirho::load_billing_usage_chirho;
use crate::model_chirho::HashChirho;

fn usage_record_chirho(
    seq_chirho: u64,
    effect_chirho: &str,
    price_chirho: i64,
    external_cost_token_chirho: i64,
    platform_fee_chirho: i64,
    owner_margin_chirho: i64,
) -> BillingUsageRecordChirho {
    BillingUsageRecordChirho {
        seq_chirho,
        schema_chirho: BILLING_USAGE_RECORD_SCHEMA_CHIRHO.to_string(),
        app_chirho: "app-chirho".to_string(),
        effect_chirho: effect_chirho.to_string(),
        caller_chirho: "caller-chirho".to_string(),
        payer_chirho: "payer-chirho".to_string(),
        payer_kind_chirho: BillingPayerKindChirho::UserChirho,
        provider_chirho: "provider-chirho".to_string(),
        price_chirho,
        price_book_chirho: HashChirho("0".repeat(64)),
        billing_policy_chirho: None,
        mode_chirho: BillingPolicyModeChirho::UserPaysChirho,
        ledger_seq_chirho: seq_chirho * 7,
        cache_hit_chirho: false,
        nway_settlement_chirho: false,
        external_provider_chirho: None,
        external_cost_token_chirho,
        platform_fee_chirho,
        owner_margin_chirho,
        credit_hold_chirho: None,
        billing_tags_chirho: BillingTagsChirho {
            user_id_chirho: Some("user-chirho".to_string()),
            ..Default::default()
        },
        at_ms_chirho: 1_700_000_000_000 + seq_chirho,
        sig_chirho: format!("sig-{seq_chirho}-chirho"),
    }
}

fn write_usage_chirho(root_chirho: &std::path::Path, records_chirho: &[BillingUsageRecordChirho]) {
    let mut text_chirho = String::new();
    for record_chirho in records_chirho {
        text_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
        text_chirho.push('\n');
    }
    std::fs::write(root_chirho.join("billing-usage-chirho.jsonl"), text_chirho).unwrap();
}

#[test]
fn billing_usage_fee_split_and_order_are_pinned_chirho() {
    // THE FEE SPLIT. Each component is disclosed separately, and the danger is not a wrong total --
    // it is a RIGHT total composed differently, which no sanity check on the sum would catch.
    let root_chirho = temp_root_chirho();
    let corpus_chirho = vec![
        usage_record_chirho(0, "effect-alpha-chirho", 1000, 600, 250, 150),
        usage_record_chirho(1, "effect-beta-chirho", 400, 0, 400, 0),
    ];
    write_usage_chirho(&root_chirho, &corpus_chirho);

    let loaded_chirho = load_billing_usage_chirho(&root_chirho).expect("usage corpus loads");
    assert_eq!(
        loaded_chirho, corpus_chirho,
        "usage rows must be returned unchanged AND in corpus order"
    );

    let emitted_chirho = serde_json::to_string(&loaded_chirho).unwrap();
    for (field_chirho, value_chirho) in [
        ("price_chirho", 1000),
        ("external_cost_token_chirho", 600),
        ("platform_fee_chirho", 250),
        ("owner_margin_chirho", 150),
    ] {
        assert!(
            emitted_chirho.contains(&format!("\"{field_chirho}\":{value_chirho}")),
            "{field_chirho} must be disclosed separately and exactly: {emitted_chirho}"
        );
    }

    // The zero-valued components of the SECOND row must still be present. `serde(default)` without
    // skip_serializing_if means a zero SERIALIZES -- and "0" is a different disclosure from "absent",
    // because absent reads as "not applicable" while 0 reads as "we charged you nothing for this".
    assert!(
        emitted_chirho.contains("\"external_cost_token_chirho\":0"),
        "a zero component must be disclosed as zero, not omitted: {emitted_chirho}"
    );
    std::fs::remove_dir_all(&root_chirho).ok();
}

#[test]
fn an_absent_usage_log_reads_empty_chirho() {
    let root_chirho = temp_root_chirho();
    let loaded_chirho =
        load_billing_usage_chirho(&root_chirho).expect("absent log is not an error");
    assert!(loaded_chirho.is_empty());
    std::fs::remove_dir_all(&root_chirho).ok();
}

#[test]
fn a_usage_row_with_an_unsupported_schema_is_refused_not_skipped_chirho() {
    // Same refusal-not-skip property as the other two families: a dropped usage row under-reports
    // what a person was charged for, in the document they would use to check it.
    let root_chirho = temp_root_chirho();
    let good_chirho = usage_record_chirho(0, "effect-alpha-chirho", 100, 0, 100, 0);
    let mut bad_chirho = usage_record_chirho(1, "effect-beta-chirho", 100, 0, 100, 0);
    bad_chirho.schema_chirho = "billing-usage-record-v99-chirho".to_string();
    write_usage_chirho(&root_chirho, &[good_chirho, bad_chirho]);

    let error_chirho = load_billing_usage_chirho(&root_chirho)
        .expect_err("an unsupported schema must refuse the whole read");
    let rendered_chirho = format!("{error_chirho}");
    assert!(
        rendered_chirho.contains("v99") || rendered_chirho.contains("schema"),
        "the refusal must identify the schema problem: {rendered_chirho}"
    );
    std::fs::remove_dir_all(&root_chirho).ok();
}

#[test]
fn the_independent_hold_reconstruction_passes_the_signature_gate_chirho() {
    // KEYSTONE for every signed-corpus arm: it proves this file can sign a hold record the way
    // production does, WITHOUT production exposing its private message builder.
    //
    // The assertion is on the REFUSAL'S IDENTITY, and that is the whole point. An unsigned corpus is
    // refused with "bad hex" at the authenticity gate. This corpus is refused for a CROSS-RECORD
    // reason instead -- which can only happen if the signature check already passed. So the arm
    // proves the reconstruction matches production without needing a corpus that verifies outright.
    //
    // THIS CLOSES THE "cannot be fixed from this module" GAP RECORDED ABOVE. That note said reaching
    // the cross-record pass needed the private `hold_record_message_chirho`, and that making it
    // public to serve a test was the wrong trade. Both halves were right; the conclusion was not. A
    // LOCAL reconstruction of the envelope reaches the same bytes and stays independent -- and being
    // independent is better than borrowing, because a rename in production breaks it here.
    let root_chirho = temp_root_chirho();
    let open_chirho = sign_hold_chirho(
        &root_chirho,
        hold_record_chirho(
            0,
            "hold-signed-chirho",
            CreditHoldStatusChirho::OpenChirho,
            None,
            None,
        ),
    );
    write_corpus_chirho(&root_chirho, &[open_chirho]);

    let error_chirho = format!(
        "{}",
        verify_credit_holds_chirho(&root_chirho)
            .expect_err("a lone open hold is not verifiable, but not for signature reasons")
    );
    assert!(
        !error_chirho.contains("bad hex") && !error_chirho.contains("signature"),
        "the refusal must NOT be the authenticity gate -- if it is, this file's reconstruction has \
         drifted from production and every signed-corpus arm below is measuring the wrong thing: \
         {error_chirho}"
    );
    // MEASURED, not assumed: the refusal is the LEDGER CROSS-REFERENCE, not the open-hold rule. I
    // guessed "still open" and the arm corrected me -- a lone open hold is rejected first for
    // pointing at a reserve ledger entry that does not exist. Either verdict proves authenticity
    // passed; pinning the one that actually fires is what makes the arm honest.
    assert!(
        error_chirho.contains("missing reserve ledger entry"),
        "pinned as the ledger cross-reference verdict, reached only after authenticity passed: \
         {error_chirho}"
    );
    std::fs::remove_dir_all(&root_chirho).ok();
}

#[test]
fn two_signed_open_records_for_one_subject_are_refused_chirho() {
    // THE GAP THE NOTE ABOVE CALLED "the real remaining gap", now closed. Its sibling arm pins what
    // duplicate subjects do to the LOADER (both rows emitted, unchanged, in order); this one pins
    // what they do to VERIFICATION, which was unreachable while every corpus was unsigned.
    //
    // Both rows are signed, so the authenticity gate cannot be what refuses them -- asserted
    // explicitly, because that is exactly how the sibling arm was once vacuous.
    let root_chirho = temp_root_chirho();
    let first_chirho = sign_hold_chirho(
        &root_chirho,
        hold_record_chirho(
            0,
            "hold-dup-chirho",
            CreditHoldStatusChirho::OpenChirho,
            None,
            None,
        ),
    );
    let second_chirho = sign_hold_chirho(
        &root_chirho,
        hold_record_chirho(
            1,
            "hold-dup-chirho",
            CreditHoldStatusChirho::OpenChirho,
            None,
            None,
        ),
    );
    write_corpus_chirho(&root_chirho, &[first_chirho, second_chirho]);

    let error_chirho = format!(
        "{}",
        verify_credit_holds_chirho(&root_chirho)
            .expect_err("two open records for one hold id must not verify")
    );
    assert!(
        !error_chirho.contains("bad hex") && !error_chirho.contains("signature"),
        "both rows are correctly signed, so a signature refusal would mean this arm proves nothing \
         about duplicate subjects: {error_chirho}"
    );
    assert!(
        error_chirho.contains("exactly one open record"),
        "VERIFICATION's duplicate-subject verdict, pinned as behaviour: a second open row for the \
         same hold id is refused by the one-open-record rule: {error_chirho}"
    );
    std::fs::remove_dir_all(&root_chirho).ok();
}
