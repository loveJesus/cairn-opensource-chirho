// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::*;

const PRICEBOOK_CHIRHO: &str = "src/app_runtime_chirho/effect_pricing_chirho.rs";
const PRICEBOOK_MODEL_CHIRHO: &str =
    "crates/domain-chirho/cairn-model-economic-chirho/src/pricebook_chirho.rs";

fn production_pricebook_chirho() -> String {
    production_text_chirho(
        &std::fs::read_to_string(workspace_root_chirho().join(PRICEBOOK_CHIRHO)).unwrap(),
    )
    .into_owned()
}

fn between_markers_chirho<'a>(
    text_chirho: &'a str,
    start_chirho: &str,
    end_chirho: &str,
) -> &'a str {
    let start_chirho = text_chirho.find(start_chirho).unwrap();
    let end_chirho = text_chirho[start_chirho..]
        .find(end_chirho)
        .map(|offset_chirho| start_chirho + offset_chirho)
        .unwrap();
    &text_chirho[start_chirho..end_chirho]
}

/// **TWO-ERA GUARD, local half.** Scoped to the LOCAL body by S3, where the original ordering
/// remains true verbatim: a never-latched root still recovers a verified pending transition before
/// reading previous and appending the next signed row.
///
/// The ELECTED half is deliberately NOT here, because it is a behavioural claim rather than a
/// source-order one: on a geo-latched root a pending unreceipted transition must REFUSE
/// (`PriceBookPendingHeadTransitionChirho`) and run no recovery mutation. That twin lives with the
/// runtime arms, where it can assert the refusal identity and unchanged row/head counts — a source
/// scan cannot see either.
///
/// MIGRATION PATH: if this fails because the local body no longer recovers first, the LOCAL
/// contract broke — stop, that is not an S3 consequence. If it fails because the markers moved,
/// retarget the span; do not weaken the ordering into a recover-or-refuse predicate, which would
/// pass on a path that does neither.
#[test]
fn pricebook_local_body_recovers_before_reading_previous_or_appending_chirho() {
    let text_chirho = production_pricebook_chirho();
    let local_chirho = between_markers_chirho(
        &text_chirho,
        "fn set_price_book_local_unlocked_chirho(",
        "pub fn recover_price_book_head_chirho(",
    );
    let recover_chirho = local_chirho
        .find("recover_price_book_head_unlocked_chirho(")
        .unwrap();
    let previous_chirho = local_chirho
        .find("current_price_book_hash_chirho(")
        .unwrap();
    let append_chirho = local_chirho
        .find("append_price_record_unlocked_chirho(")
        .unwrap();
    assert!(
        recover_chirho < previous_chirho && previous_chirho < append_chirho,
        "the never-latched pricebook body must recover a verified pending transition before reading previous and appending the next signed row"
    );

    // The scope acquisition moved to the dispatcher in S3. Assert it is still acquired, and that the
    // door reaches it through the era dispatcher rather than a bare local scope of its own.
    let dispatch_chirho = between_markers_chirho(
        &text_chirho,
        "fn set_price_book_with_authority_chirho(",
        "fn set_price_book_local_unlocked_chirho(",
    );
    assert!(
        dispatch_chirho.contains("dispatch_head_transition_chirho("),
        "the price door must reach its local scope through the era dispatcher"
    );
}

#[test]
fn pricebook_recovery_verifies_before_lowering_prepared_rows_chirho() {
    let text_chirho = production_pricebook_chirho();
    let recovery_chirho = between_markers_chirho(
        &text_chirho,
        "fn recover_price_book_head_unlocked_chirho(",
        "fn prepared_from_verified_price_book_record_chirho(",
    );
    let verify_chirho = recovery_chirho
        .find("verified_price_book_records_chirho(")
        .unwrap();
    let lower_chirho = recovery_chirho
        .find("prepared_from_verified_price_book_record_chirho(")
        .unwrap();
    assert!(
        verify_chirho < lower_chirho,
        "verified pricebook records must be established before any row becomes Prepared"
    );
    assert!(
        !recovery_chirho.contains("load_price_book_records_chirho("),
        "raw pricebook records must never mint Prepared transition authority"
    );
    let set_chirho = between_markers_chirho(
        &text_chirho,
        "pub fn set_price_book_chirho(",
        "pub fn recover_price_book_head_chirho(",
    );
    assert!(
        set_chirho.find("verified_price_book_records_chirho(").unwrap()
            < set_chirho
                .find("prepared_from_verified_price_book_record_chirho(")
                .unwrap(),
        "a newly appended row must be reloaded through the exact verified-vector boundary before binding"
    );
}

#[test]
fn pricebook_current_reads_require_verified_history_and_v2_receipt_chirho() {
    let text_chirho = production_pricebook_chirho();
    let selected_chirho = between_markers_chirho(
        &text_chirho,
        "fn selected_verified_price_book_record_chirho(",
        "pub fn current_price_book_hash_chirho(",
    );
    let verified_chirho = selected_chirho
        .find("verified_price_book_records_chirho(")
        .unwrap();
    let raw_head_chirho = selected_chirho.find("price_book_ref_head_chirho(").unwrap();
    let lower_chirho = selected_chirho
        .find("prepared_from_verified_price_book_record_chirho(")
        .unwrap();
    let receipt_chirho = selected_chirho
        .find("verified_head_transition_receipt_chirho(")
        .unwrap();
    assert!(
        verified_chirho < raw_head_chirho
            && raw_head_chirho < lower_chirho
            && lower_chirho < receipt_chirho,
        "pricebook selected authority must verify signed history before reading the ref and must lower the exact selected v2 row before checking its Applied receipt"
    );
    let current_chirho = between_markers_chirho(
        &text_chirho,
        "pub fn current_price_book_hash_chirho(",
        "pub fn current_price_book_chirho(",
    );
    assert!(
        current_chirho.contains("selected_verified_price_book_record_chirho(")
            && !current_chirho.contains("price_book_ref_head_chirho("),
        "public pricebook current reads must not consume the raw mutable ref directly"
    );
    // The whole-file raw-head occurrence count freeze (==3) was demoted to the advisory structure
    // report; the verify-before-read + no-raw-ref-consumption engine claims stay RED above.
}

#[test]
fn pricebook_v2_is_additive_and_legacy_rows_cannot_recover_chirho() {
    let model_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(PRICEBOOK_MODEL_CHIRHO)).unwrap();
    for required_chirho in [
        "PRICE_BOOK_RECORD_SCHEMA_CHIRHO: &str = \"price-book-record-v1-chirho\"",
        "PRICE_BOOK_RECORD_V2_SCHEMA_CHIRHO: &str = \"price-book-record-v2-chirho\"",
        "skip_serializing_if = \"String::is_empty\"",
        "pub transition_id_chirho: String",
        "skip_serializing_if = \"Option::is_none\"",
        "pub prepared_writer_fence_epoch_chirho: Option<u64>",
    ] {
        assert!(
            model_chirho.contains(required_chirho),
            "pricebook v2 additive field/legacy contract missing: {required_chirho}"
        );
    }
    let pricebook_chirho = production_pricebook_chirho();
    assert!(
        pricebook_chirho
            .contains("record_chirho.schema_chirho == PRICE_BOOK_RECORD_V2_SCHEMA_CHIRHO")
            && pricebook_chirho
                .contains("only verified price book v2 rows can become prepared head transitions"),
        "only explicit v2 rows may enter pricebook recovery"
    );
}

#[test]
fn pricebook_v2_signature_and_transition_binding_stay_load_bearing_chirho() {
    let text_chirho = production_pricebook_chirho();
    let message_start_chirho = text_chirho.find("fn price_record_message_chirho(").unwrap();
    let message_chirho = &text_chirho[message_start_chirho..];
    for required_chirho in [
        "transition_id_chirho: Option<&'a str>",
        "prepared_writer_fence_epoch_chirho: Option<u64>",
        "transition_id_chirho: nonempty_schema_chirho(&record_chirho.transition_id_chirho)",
        "prepared_writer_fence_epoch_chirho: record_chirho",
    ] {
        assert!(
            message_chirho.contains(required_chirho),
            "pricebook v2 signed message must bind {required_chirho}"
        );
    }
    for required_chirho in [
        "derive_head_transition_id_chirho(",
        "bind_caller_verified_head_transition_chirho(",
        "serde_json::to_vec(record_chirho)?",
    ] {
        assert!(
            text_chirho.contains(required_chirho),
            "pricebook transition identity/canonical-line binding missing {required_chirho}"
        );
    }
}

#[test]
fn pricebook_cannot_bypass_the_reviewed_transition_boundary_chirho() {
    let text_chirho = production_pricebook_chirho();
    for forbidden_chirho in [
        "refs_chirho::commit_head_chirho(",
        "commit_head_with_transition_receipt_chirho(",
        "with_head_commit_chirho(",
        "refs_chirho::save_refs_chirho(",
        "refs_chirho::set_branch_chirho(",
        "refs_chirho::rollback_chirho(",
    ] {
        assert!(
            !text_chirho.contains(forbidden_chirho),
            "pricebook production path bypasses the reviewed positive-head protocol via {forbidden_chirho}"
        );
    }
    for required_chirho in [
        "pending_head_transition_index_unlocked_chirho(",
        "complete_head_transition_unlocked_chirho(",
    ] {
        assert!(
            text_chirho.contains(required_chirho),
            "pricebook production path must retain reviewed transition call {required_chirho}"
        );
    }
}

const PRICEBOOK_EVIDENCE_CHIRHO: &str =
    "src/app_runtime_chirho/effect_pricing_chirho/price_book_evidence_chirho.rs";

/// **THE ELECTED COMMIT ORDERING, PINNED.** Was correct and UNGUARDED until gpt's S3 review moved
/// the CAS put before F4 promotion and deleted the stored-address divergence check — both in
/// silence, because the existing pricebook guard reads only `effect_pricing_chirho.rs` and never
/// opened the evidence module.
///
/// The required order, and why each step is where it is:
/// 1. `promote_chirho` — F4 promotion precedes the FIRST durable write, and for this door the first
///    durable write is the operation-created book, not the row.
/// 2. `put_object_chirho` — the book lands only under a promoted lifecycle.
/// 3. the stored-address divergence check — PREPARE bound an address it did not write; if the
///    stored address ever differs, the signed row points at an object that is not there.
/// 4. `append_recovered_jsonl_unlocked_chirho` — the signed row, after its object exists.
/// 5. `complete_head_transition_chirho` — ref and receipt last, consuming the affine scope.
///
/// MIGRATION PATH: if this fails, read WHICH pair inverted before touching it. A put before promote
/// is an F4 violation; a missing divergence check means a row can be signed for an absent object.
/// Neither is a test problem.
#[test]
fn pricebook_elected_commit_promotes_before_storing_and_checks_the_address_chirho() {
    let text_chirho = production_text_chirho(
        &std::fs::read_to_string(workspace_root_chirho().join(PRICEBOOK_EVIDENCE_CHIRHO)).unwrap(),
    )
    .into_owned();
    let commit_chirho = between_markers_chirho(
        &text_chirho,
        "pub(super) fn commit_elected_price_book_chirho(",
        "fn refuse_pending_price_transition_chirho(",
    );
    let promote_chirho = commit_chirho
        .find(".promote_chirho(")
        .expect("elected COMMIT must promote the CAS lifecycle");
    let put_chirho = commit_chirho
        .find("store_chirho::put_object_chirho(")
        .expect("elected COMMIT must store the operation-created price book");
    let divergence_chirho = commit_chirho
        .find("PriceBookStoredAddressDivergedFromPreparedChirho")
        .expect("elected COMMIT must compare the stored address against the prepared one");
    let append_chirho = commit_chirho
        .find("append_recovered_jsonl_unlocked_chirho(")
        .expect("elected COMMIT must append the signed row");
    let complete_chirho = commit_chirho
        .find("complete_head_transition_chirho(")
        .expect("elected COMMIT must complete the head transition");

    assert!(
        promote_chirho < put_chirho,
        "F4 promotion must precede the CAS put: the book is this door's FIRST durable write"
    );
    assert!(
        put_chirho < divergence_chirho,
        "the stored address must be compared after the put that produced it"
    );
    assert!(
        divergence_chirho < append_chirho,
        "the divergence check must precede the signed row, or a row can be signed for an absent object"
    );
    assert!(
        append_chirho < complete_chirho,
        "the row must exist before the ref and receipt point at it"
    );
}
