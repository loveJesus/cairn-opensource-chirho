// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pins the money-integrity behaviour of the credit-hold read/verify core, so extracting it cannot
//! silently change which holds verify clean or what a subject export discloses about them.
//!
//! **This is the acceptance instrument for CF6-D2 brick (a2-2).** Landed BEFORE the move, because a
//! baseline recorded after a move proves only that the move agrees with itself.
//!
//! # The scope boundary this file assumes (agreed with the second seat at pre-review)
//!
//! `verified_credit_hold_states_from_records_chirho` takes records AND ledger entries as parameters
//! — it is road-agnostic, and it is what moves. `verified_credit_hold_states_chirho` and
//! `verify_credit_holds_chirho` are the two-road dispatcher, the identical shape to
//! `verified_entries_chirho`, and they **stay** with the spine. Brick (a2-0) made the same cut for
//! the ledger, so this is one rule applied twice rather than a new judgment.
//!
//! # Why the corpus is real rather than synthetic
//!
//! Every arm here drives a root carrying REAL signed ledger entries at the reserve and settlement
//! seqs, because the hold verifier's whole job is binding a record to its ledger effect. A corpus
//! whose holds point at absent entries can only ever exercise the "missing entry" refusal, which is
//! the one path that says nothing about whether the binding is sound. This corpus was named as the
//! remaining instrument gap at pre-review; it is built once here so arms can be written on top of
//! it without each rebuilding a ledger.
//!
//! # The reconstruction is INDEPENDENT and deliberately duplicated
//!
//! `hold_signature_message_chirho` below rebuilds the signed byte-stream from its specification
//! rather than calling production's private builder. A pin that asks the code under test to
//! describe itself agrees with itself by construction; this one disagrees if the production format
//! moves. The ledger-side reconstruction is duplicated from brick (a2-0)'s pin on purpose: sharing
//! it would make this file inherit that file's drift, and (a2-0)'s instrument has already been
//! independently reviewed — borrowing from it would also silently widen the surface that review
//! covered.

use crate::economic_model_chirho::{
    AssetChirho, BillingTagsChirho, CreditHoldRecordChirho, CreditHoldStatusChirho,
    LedgerEntryChirho, PostingChirho, CREDIT_HOLD_RECORD_SCHEMA_CHIRHO, LEDGER_ENTRY_SCHEMA_CHIRHO,
};
use crate::legacy_holds_evidence_chirho::verify_credit_holds_single_road_chirho as verify_credit_holds_chirho;
use cairn_signer_chirho::signer_chirho;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const AUTHORIZED_CHIRHO: i64 = 100;
const PAYER_CHIRHO: &str = "payer-chirho";
const HOLD_ACCOUNT_CHIRHO: &str = "holds/acct-chirho";
const REVENUE_CHIRHO: &str = "revenue-chirho";
const HOLD_ID_CHIRHO: &str = "hold-chirho";

const RESERVE_SEQ_CHIRHO: u64 = 0;
const SETTLEMENT_SEQ_CHIRHO: u64 = 1;

fn temp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-legacy-holds-characterization-{n_chirho}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d_chirho| d_chirho.as_nanos())
            .unwrap_or(0)
    ))
}

/// The on-disk hold-evidence path, reconstructed independently of the production helper.
///
/// A pin in its own right: an extraction that changed this filename would relocate the hold
/// evidence every subject export reads, and nothing else in the suite would notice.
fn holds_evidence_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("credit-holds-chirho.jsonl")
}

fn ledger_evidence_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("ledger-chirho.jsonl")
}

/// The inner legacy ledger string: `seq|at_ms|memo` then one `|account:Asset:amount` per posting.
fn v1_legacy_string_chirho(entry_chirho: &LedgerEntryChirho) -> String {
    let mut message_chirho = format!(
        "{}|{}|{}",
        entry_chirho.seq_chirho, entry_chirho.at_ms_chirho, entry_chirho.memo_chirho
    );
    for posting_chirho in &entry_chirho.postings_chirho {
        message_chirho.push_str(&format!(
            "|{}:{:?}:{}",
            posting_chirho.account_chirho,
            posting_chirho.asset_chirho,
            posting_chirho.amount_chirho
        ));
    }
    message_chirho
}

/// The v1 ledger signature message: the legacy string, wrapped by whichever envelope the entry's
/// populated fields select.
///
/// **The four branches are load-bearing, and the keystone arm proved it.** A first version of this
/// helper emitted only the schema envelope, because that is the branch brick (a2-0)'s corpus
/// exercises. This corpus carries billing tags — the binding compares them — so it takes the
/// schema-tagged branch, and every arm in the file failed on `entry 0 signature invalid` until all
/// four were present. That is the instrument working: a reconstruction that covers only the shape
/// you happened to test is a reconstruction that agrees with itself.
fn v1_signature_message_chirho(entry_chirho: &LedgerEntryChirho) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct SchemaEnvelopeChirho<'a> {
        legacy_message_chirho: String,
        schema_chirho: &'a str,
    }
    #[derive(serde::Serialize)]
    struct SchemaTaggedEnvelopeChirho<'a> {
        legacy_message_chirho: String,
        schema_chirho: &'a str,
        billing_tags_chirho: &'a BillingTagsChirho,
    }
    #[derive(serde::Serialize)]
    struct TaggedEnvelopeChirho<'a> {
        legacy_message_chirho: String,
        billing_tags_chirho: &'a BillingTagsChirho,
    }
    assert!(
        entry_chirho.op_binding_chirho.is_none(),
        "this reconstruction covers v1 only; no arm here signs a v2 row"
    );
    let legacy_chirho = v1_legacy_string_chirho(entry_chirho);
    match (
        entry_chirho.billing_tags_chirho.is_empty_chirho(),
        entry_chirho.schema_chirho.is_empty(),
    ) {
        (true, true) => legacy_chirho.into_bytes(),
        (true, false) => serde_json::to_vec(&SchemaEnvelopeChirho {
            legacy_message_chirho: legacy_chirho,
            schema_chirho: &entry_chirho.schema_chirho,
        })
        .expect("encode schema envelope"),
        (false, false) => serde_json::to_vec(&SchemaTaggedEnvelopeChirho {
            legacy_message_chirho: legacy_chirho,
            schema_chirho: &entry_chirho.schema_chirho,
            billing_tags_chirho: &entry_chirho.billing_tags_chirho,
        })
        .expect("encode schema-tagged envelope"),
        (false, true) => serde_json::to_vec(&TaggedEnvelopeChirho {
            legacy_message_chirho: legacy_chirho,
            billing_tags_chirho: &entry_chirho.billing_tags_chirho,
        })
        .expect("encode tagged envelope"),
    }
}

/// The hold-record signature message, rebuilt from its specification.
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

fn resign_entry_chirho(
    root_chirho: &Path,
    mut entry_chirho: LedgerEntryChirho,
) -> LedgerEntryChirho {
    entry_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &v1_signature_message_chirho(&entry_chirho),
    )
    .expect("sign ledger entry with the root key");
    entry_chirho
}

fn resign_hold_chirho(
    root_chirho: &Path,
    mut record_chirho: CreditHoldRecordChirho,
) -> CreditHoldRecordChirho {
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &hold_signature_message_chirho(&record_chirho),
    )
    .expect("sign hold record with the root key");
    record_chirho
}

/// The tags carried identically by every record and every ledger entry in the corpus.
///
/// They must match: the verifier compares record tags to entry tags at each of the three bindings,
/// so a corpus with default tags on one side would pass that check vacuously.
fn corpus_tags_chirho() -> BillingTagsChirho {
    BillingTagsChirho {
        user_id_chirho: Some("user-chirho".to_string()),
        app_id_chirho: Some("app-id-chirho".to_string()),
        ..Default::default()
    }
}

fn posting_chirho(account_chirho: &str, amount_chirho: i64) -> PostingChirho {
    PostingChirho {
        account_chirho: account_chirho.to_string(),
        asset_chirho: AssetChirho::TokenChirho,
        amount_chirho,
    }
}

fn entry_chirho(
    seq_chirho: u64,
    memo_chirho: &str,
    postings_chirho: Vec<PostingChirho>,
) -> LedgerEntryChirho {
    LedgerEntryChirho {
        seq_chirho,
        schema_chirho: LEDGER_ENTRY_SCHEMA_CHIRHO.to_string(),
        memo_chirho: memo_chirho.to_string(),
        postings_chirho,
        billing_tags_chirho: corpus_tags_chirho(),
        at_ms_chirho: 1_700_000_000_000 + seq_chirho,
        sig_chirho: String::new(),
        op_binding_chirho: None,
    }
}

/// The reserve entry the corpus's hold points at: the payer is debited, the hold account credited.
fn reserve_entry_chirho() -> LedgerEntryChirho {
    entry_chirho(
        RESERVE_SEQ_CHIRHO,
        "reserve",
        vec![
            posting_chirho(PAYER_CHIRHO, -AUTHORIZED_CHIRHO),
            posting_chirho(HOLD_ACCOUNT_CHIRHO, AUTHORIZED_CHIRHO),
        ],
    )
}

/// The settlement entry: the hold account is drained and revenue recognised.
fn settlement_entry_chirho() -> LedgerEntryChirho {
    entry_chirho(
        SETTLEMENT_SEQ_CHIRHO,
        "settle",
        vec![
            posting_chirho(HOLD_ACCOUNT_CHIRHO, -AUTHORIZED_CHIRHO),
            posting_chirho(REVENUE_CHIRHO, AUTHORIZED_CHIRHO),
        ],
    )
}

fn hold_record_chirho(
    seq_chirho: u64,
    status_chirho: CreditHoldStatusChirho,
    settled_token_chirho: i64,
    released_token_chirho: i64,
    settlement_ledger_seq_chirho: Option<u64>,
) -> CreditHoldRecordChirho {
    CreditHoldRecordChirho {
        seq_chirho,
        schema_chirho: CREDIT_HOLD_RECORD_SCHEMA_CHIRHO.to_string(),
        hold_id_chirho: HOLD_ID_CHIRHO.to_string(),
        hold_account_chirho: HOLD_ACCOUNT_CHIRHO.to_string(),
        app_chirho: "app-chirho".to_string(),
        effect_chirho: "effect-chirho".to_string(),
        caller_chirho: "caller-chirho".to_string(),
        payer_chirho: PAYER_CHIRHO.to_string(),
        authorized_token_chirho: AUTHORIZED_CHIRHO,
        settled_token_chirho,
        released_token_chirho,
        reserve_ledger_seq_chirho: RESERVE_SEQ_CHIRHO,
        settlement_ledger_seq_chirho,
        release_ledger_seq_chirho: None,
        status_chirho,
        billing_tags_chirho: corpus_tags_chirho(),
        at_ms_chirho: 1_700_000_000_000 + seq_chirho,
        sig_chirho: String::new(),
    }
}

fn write_entries_chirho(root_chirho: &Path, entries_chirho: &[LedgerEntryChirho]) {
    let mut text_chirho = String::new();
    for entry_chirho in entries_chirho {
        text_chirho.push_str(&serde_json::to_string(entry_chirho).expect("encode entry"));
        text_chirho.push('\n');
    }
    std::fs::write(ledger_evidence_path_chirho(root_chirho), text_chirho).expect("write ledger");
}

fn write_holds_chirho(root_chirho: &Path, records_chirho: &[CreditHoldRecordChirho]) {
    let mut text_chirho = String::new();
    for record_chirho in records_chirho {
        text_chirho.push_str(&serde_json::to_string(record_chirho).expect("encode record"));
        text_chirho.push('\n');
    }
    std::fs::write(holds_evidence_path_chirho(root_chirho), text_chirho).expect("write holds");
}

/// THE CORPUS: one hold, opened then settled, bound to two real signed ledger entries.
///
/// Built by hand rather than through the production reserve/settle doors for the same reason brick
/// (a2-0)'s corpus was: R6e retired the unchecked ledger door and requires zero production caller
/// edges, and the checked door refuses a debit against an empty account, so neither can seed a
/// first entry. The keystone arms below recover what the write path would have shown — production's
/// verifier ACCEPTS records and entries this file signed independently, which is exactly the format
/// equivalence a write-side fixture would have demonstrated.
///
/// `ledger_override_chirho` replaces the settlement entry, so an arm can vary the ledger effect
/// while leaving the signed hold records untouched. That is the axis the binding is meant to
/// constrain, and it is the one the pre-review candidate finding wants.
fn corpus_root_chirho(ledger_override_chirho: Option<LedgerEntryChirho>) -> PathBuf {
    let root_chirho = temp_root_chirho();
    std::fs::create_dir_all(&root_chirho).expect("create root");

    let settlement_chirho = ledger_override_chirho.unwrap_or_else(settlement_entry_chirho);
    let entries_chirho = vec![
        resign_entry_chirho(&root_chirho, reserve_entry_chirho()),
        resign_entry_chirho(&root_chirho, settlement_chirho),
    ];
    write_entries_chirho(&root_chirho, &entries_chirho);

    let records_chirho = vec![
        resign_hold_chirho(
            &root_chirho,
            hold_record_chirho(0, CreditHoldStatusChirho::OpenChirho, 0, 0, None),
        ),
        resign_hold_chirho(
            &root_chirho,
            hold_record_chirho(
                1,
                CreditHoldStatusChirho::SettledChirho,
                AUTHORIZED_CHIRHO,
                0,
                Some(SETTLEMENT_SEQ_CHIRHO),
            ),
        ),
    ];
    write_holds_chirho(&root_chirho, &records_chirho);
    root_chirho
}

#[test]
fn the_independent_hold_reconstruction_agrees_with_the_production_signature_chirho() {
    // THE KEYSTONE. Production recomputes its own `hold_record_message_chirho` and checks the
    // signature against it, so ACCEPTING records this file signed proves the two byte-streams are
    // identical. If the formats ever diverge, every other arm here starts failing on "signature
    // invalid" instead of on the property it names -- so read this arm FIRST when the suite is red.
    let root_chirho = corpus_root_chirho(None);
    assert_eq!(
        verify_credit_holds_chirho(&root_chirho).unwrap(),
        2,
        "production must accept hold records signed from the independent reconstruction"
    );
}

#[test]
fn a_settled_hold_bound_to_real_ledger_entries_verifies_clean_chirho() {
    // THE BASELINE the whole corpus exists for. Every refusal arm is only meaningful against a
    // corpus that is otherwise clean -- a fixture that refuses for some unrelated reason would make
    // every negative arm pass while measuring nothing.
    let root_chirho = corpus_root_chirho(None);
    assert_eq!(verify_credit_holds_chirho(&root_chirho).unwrap(), 2);
}

#[test]
fn the_hold_evidence_path_is_pinned_chirho() {
    // Observed THROUGH production: the corpus writes to the independently-reconstructed path, and
    // production finds it. Asserting the PathBuf alone would compare this file to itself.
    //
    // THE COUNT IS LOAD-BEARING, AND `is_ok()` HERE WAS VACUOUS (second seat, at review). The first
    // version asserted `is_ok()`. Under a WRONG path reconstruction every line still passed:
    // `write_holds_chirho` writes THROUGH the same reconstruction, so the wrong file exists; then
    // production reads its REAL path, finds nothing, and returns Ok(0) -- which `is_ok()` accepts.
    // The arm went green while proving nothing about the binding it names. `== 2` is what forces
    // production to have read THIS file. General shape worth remembering: `is_ok()` is where vacuity
    // hides, because it passes in the EMPTY case by construction, and the empty case is exactly what
    // a broken fixture produces.
    //
    // MIGRATION PATH: if this fails after a deliberate rename, retarget the constant in
    // `holds_evidence_path_chirho`. If it fails without one, production stopped reading the file
    // every historical subject export lives in.
    let root_chirho = corpus_root_chirho(None);
    assert!(holds_evidence_path_chirho(&root_chirho).exists());
    assert_eq!(
        verify_credit_holds_chirho(&root_chirho).unwrap(),
        2,
        "production must read the hold evidence at the reconstructed path, not merely succeed"
    );

    std::fs::remove_file(holds_evidence_path_chirho(&root_chirho)).expect("remove holds evidence");
    assert_eq!(
        verify_credit_holds_chirho(&root_chirho).unwrap(),
        0,
        "an absent hold log reads as zero holds, not as an error"
    );
}

#[test]
fn a_terminal_hold_whose_amounts_do_not_conserve_is_refused_chirho() {
    // MONEY CONSERVATION: settled + released must equal authorized. The record is re-signed, so the
    // signature check cannot be what refuses -- only the property under test can fire.
    let root_chirho = corpus_root_chirho(None);
    let broken_chirho = resign_hold_chirho(
        &root_chirho,
        hold_record_chirho(
            1,
            CreditHoldStatusChirho::SettledChirho,
            AUTHORIZED_CHIRHO - 40,
            0,
            Some(SETTLEMENT_SEQ_CHIRHO),
        ),
    );
    let open_chirho = resign_hold_chirho(
        &root_chirho,
        hold_record_chirho(0, CreditHoldStatusChirho::OpenChirho, 0, 0, None),
    );
    write_holds_chirho(&root_chirho, &[open_chirho, broken_chirho]);

    let err_chirho = verify_credit_holds_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        err_chirho.contains("authorized"),
        "must refuse on conservation, got: {err_chirho}"
    );
    assert!(
        !err_chirho.contains("signature"),
        "the conservation arm must not be passing because of a signature failure: {err_chirho}"
    );
}

#[test]
fn a_tampered_hold_record_fails_authentication_chirho() {
    // The signature gate itself: mutate a signed record WITHOUT re-signing.
    let root_chirho = corpus_root_chirho(None);
    let open_chirho = resign_hold_chirho(
        &root_chirho,
        hold_record_chirho(0, CreditHoldStatusChirho::OpenChirho, 0, 0, None),
    );
    let mut terminal_chirho = resign_hold_chirho(
        &root_chirho,
        hold_record_chirho(
            1,
            CreditHoldStatusChirho::SettledChirho,
            AUTHORIZED_CHIRHO,
            0,
            Some(SETTLEMENT_SEQ_CHIRHO),
        ),
    );
    terminal_chirho.payer_chirho = "attacker-chirho".to_string();
    write_holds_chirho(&root_chirho, &[open_chirho, terminal_chirho]);

    let err_chirho = verify_credit_holds_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        err_chirho.contains("signature"),
        "a mutated unsigned record must fail authentication, got: {err_chirho}"
    );
}

#[test]
fn a_hold_seq_gap_is_refused_chirho() {
    // Sequence continuity is asserted at VERIFY time and deliberately not in the loader, so that an
    // export can still disclose a damaged log. This pins the verify half of that asymmetry.
    let root_chirho = corpus_root_chirho(None);
    let stranded_chirho = resign_hold_chirho(
        &root_chirho,
        hold_record_chirho(
            7,
            CreditHoldStatusChirho::SettledChirho,
            AUTHORIZED_CHIRHO,
            0,
            Some(SETTLEMENT_SEQ_CHIRHO),
        ),
    );
    write_holds_chirho(&root_chirho, &[stranded_chirho]);

    let err_chirho = verify_credit_holds_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        err_chirho.contains("seq gap"),
        "must refuse on the seq gap, got: {err_chirho}"
    );
}

#[test]
fn a_hold_pointing_at_a_missing_settlement_entry_is_refused_chirho() {
    // The binding's cheapest half: the entry must EXIST at the named seq. The corpus is what makes
    // this meaningful -- against a ledger-less root, this refusal is the only one reachable, which
    // is precisely why a real corpus was the gap worth closing.
    let root_chirho = corpus_root_chirho(None);
    write_entries_chirho(
        &root_chirho,
        &[resign_entry_chirho(&root_chirho, reserve_entry_chirho())],
    );

    let err_chirho = verify_credit_holds_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        err_chirho.contains("missing settlement ledger entry"),
        "must refuse on the absent settlement entry, got: {err_chirho}"
    );
}

#[test]
fn a_settlement_entry_whose_tags_disagree_with_the_record_is_refused_chirho() {
    // The tag binding, exercised with a REAL alternative entry rather than an absent one. Re-signed,
    // so only the tag mismatch can fire.
    let mut mismatched_chirho = settlement_entry_chirho();
    mismatched_chirho.billing_tags_chirho = BillingTagsChirho::default();
    let root_chirho = corpus_root_chirho(Some(mismatched_chirho));

    let err_chirho = verify_credit_holds_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        err_chirho.contains("tags mismatch"),
        "must refuse on the tag mismatch, got: {err_chirho}"
    );
    assert!(
        !err_chirho.contains("signature"),
        "the tag arm must not be passing because of a signature failure: {err_chirho}"
    );
}

#[test]
fn a_settlement_entry_that_never_drains_the_hold_account_is_refused_chirho() {
    // The binding's ABSENCE half: the settlement entry must CONTAIN a posting that debits the hold
    // account by the authorized amount. Here it credits revenue from the payer instead, so the drain
    // posting is missing entirely -- balanced, signed, and wrong.
    //
    // WHAT THIS ARM DOES NOT PROVE, stated because the comment first claimed it did: that the amount
    // actually LEAVES the hold account. `require_posting_chirho` matches a posting COMPONENT with
    // `.any()`; it never computes the account's net in the entry, and `assert_balanced_chirho` keys
    // conservation on ASSET ONLY, so two postings for one account are legal. A drain that is present
    // but cancelled by a compensating credit is therefore a different axis, and it is pinned
    // separately -- by the second seat, from their own independent read, on this corpus.
    let mut wrong_chirho = settlement_entry_chirho();
    wrong_chirho.postings_chirho = vec![
        posting_chirho(PAYER_CHIRHO, -AUTHORIZED_CHIRHO),
        posting_chirho(REVENUE_CHIRHO, AUTHORIZED_CHIRHO),
    ];
    let root_chirho = corpus_root_chirho(Some(wrong_chirho));

    let err_chirho = verify_credit_holds_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        err_chirho.contains("missing token posting"),
        "must refuse when the hold account is never drained, got: {err_chirho}"
    );
}

#[test]
fn a_still_open_hold_is_refused_by_the_public_verifier_chirho() {
    // `verify_credit_holds_chirho` is stricter than the state builder it wraps: every hold must have
    // reached a terminal state. This is the arm that would notice if that strictness were lost in
    // the move, since the state builder itself would keep returning the same states.
    let root_chirho = corpus_root_chirho(None);
    let open_chirho = resign_hold_chirho(
        &root_chirho,
        hold_record_chirho(0, CreditHoldStatusChirho::OpenChirho, 0, 0, None),
    );
    write_holds_chirho(&root_chirho, &[open_chirho]);

    let err_chirho = verify_credit_holds_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        err_chirho.contains("still open"),
        "must refuse a hold that never reached a terminal state, got: {err_chirho}"
    );
}

#[test]
fn a_settlement_entry_that_cancels_its_own_drain_is_refused_chirho() {
    // SECOND-SEAT ARM (claude_chirho), selected from an independent read of the holds path BEFORE
    // this corpus existed, and pinned here as the completion of the arm above.
    //
    // RETARGETED at 6701d5fa, FIXTURE UNTOUCHED -- so this arm's new green is a statement about the
    // production code, not about the test. It was written expecting ACCEPTED and it got ACCEPTED:
    // the history below is what this arm FOUND, kept as the evidence that the hardening was real.
    //
    // `a_settlement_entry_that_never_drains_the_hold_account_is_refused_chirho` DELETES the drain
    // posting, so `require_posting_chirho` refuses on ABSENCE. This arm keeps the drain posting and
    // NEUTRALISES it with a compensating credit to the same account. The entry balances, it is
    // re-signed, and it CONTAINS (hold account, -authorized) -- so a matcher that looks for A
    // POSTING rather than for the account's NET has nothing to object to, while the hold account's
    // net movement in this entry is ZERO.
    //
    // Legal by construction: `assert_balanced_chirho` keys conservation by ASSET ONLY, so two
    // postings for one account in one entry are conservation-legal.
    //
    // What the accepted history then asserts: the hold is SETTLED, the payer was refunded in full,
    // the platform paid out, and the reserved amount is still sitting in the hold account -- money
    // no later step will release, because the hold is terminal. On four structurally different
    // searches (the prefix constant, the literal account string, the `hold_account` identifier
    // outside the holds module, and prefix-scans on account names) there is no net-based
    // hold-account reconciliation anywhere. Four routes is not exhaustive and this does not claim it.
    //
    // BOUND, so the arm cannot be read as bigger than it is: this needs a root-SIGNED corpus, so it
    // is robustness parity rather than privilege escalation. The same `.any()` shape exists
    // independently at `require_token_posting_chirho` in cairn-model-economic-chirho, whose only
    // production caller dies with this spine; the successor's `admission_chirho` derived path has
    // the shape too but CLOSES it with a leg-count precondition that no number of compensating pairs
    // can satisfy.
    //
    // WHAT CLOSED IT (6701d5fa): not a change to `require_posting_chirho`, which still matches a
    // component. A rule ABOVE it -- a TERMINAL hold's account must reconcile to zero over the whole
    // ledger. That catches a compensating pair on the reserve side too, which a per-entry net
    // assertion at settlement would have missed, and it states the invariant about MONEY rather than
    // about encoding. The hold account is `platform/credit-hold/<hold_id>`, per-hold and never
    // shared, and the exactly-one-open-record rule enforces that at VERIFY time -- which is what
    // makes "nets to zero" well-defined against a signed corpus rather than merely by convention.
    //
    // MIGRATION PATH, FORWARD FROM HERE -- what each way this can stop passing MEANS:
    //   * it ACCEPTS again -> the reconcile-to-zero rule was LOST. That is the regression this arm
    //     now exists to catch, and the finding above describes exactly what becomes possible again.
    //   * it refuses on a DIFFERENT phrase -> the rule changed shape. Read the new refusal before
    //     retargeting; if it is "missing token posting" the absence arm is firing instead and this
    //     arm has stopped measuring its own axis.
    //   * it refuses on "signature" or "unbalanced" -> the FIXTURE rotted, not the ledger. The
    //     compensating entry is re-signed and balanced on purpose so only the rule can fire.
    let mut compensating_chirho = settlement_entry_chirho();
    compensating_chirho.postings_chirho = vec![
        posting_chirho(HOLD_ACCOUNT_CHIRHO, -AUTHORIZED_CHIRHO),
        posting_chirho(HOLD_ACCOUNT_CHIRHO, AUTHORIZED_CHIRHO),
        posting_chirho(PAYER_CHIRHO, AUTHORIZED_CHIRHO),
        posting_chirho(REVENUE_CHIRHO, -AUTHORIZED_CHIRHO),
    ];
    let root_chirho = corpus_root_chirho(Some(compensating_chirho));

    let err_chirho = verify_credit_holds_chirho(&root_chirho)
        .expect_err(
            "the compensated drain must be REFUSED -- if this returned a count, the \
             reconcile-to-zero rule was lost and the finding above is live again",
        )
        .to_string();
    assert!(
        err_chirho.contains("does not reconcile to zero"),
        "must refuse because the hold account still holds the reserved amount, got: {err_chirho}"
    );
    // The two negatives are the point: without them the ABSENCE arm's refusal would satisfy this
    // assertion and the retarget would pass while measuring the wrong refusal entirely.
    assert!(
        !err_chirho.contains("signature") && !err_chirho.contains("missing token posting"),
        "the refusal must be the reconcile rule, not a signature failure or the absence match: \
         {err_chirho}"
    );
}
