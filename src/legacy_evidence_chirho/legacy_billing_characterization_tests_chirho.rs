// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pins how a billing usage record must agree with the ledger entry it charges against, so
//! extracting that check cannot silently change what is billable or what a subject export discloses.
//!
//! **Acceptance instrument for CF6-D2 brick (a2-3).** Landed BEFORE the move, because a baseline
//! recorded afterwards proves only that the move agrees with itself.
//!
//! # What actually moves, measured rather than assumed
//!
//! `append_verified_billing_usage_states_from_records_chirho` takes records AND ledger entries as
//! parameters — it is road-agnostic, and it is the 101-line core that moves. The `verified_*`
//! helpers above it dispatch on the Gate-1 authority stream and stay with the spine. Every arm here
//! drives that core through `verify_billing_usage_chirho`, which is one of the five entry points
//! being rebased onto the probe.
//!
//! Two instrument errors produced the first, wrong cut of this brick, and both are worth keeping:
//! a body-only scan calls a three-line wrapper road-free when its callee dispatches, and a census
//! keyed on the name `verified_*` cannot see `selected_current_billing_policy_record_chirho` — a
//! dispatcher nobody named like one, whose caller sat in the MOVE set.
//!
//! # Why the corpus carries a REAL signed ledger
//!
//! Usage verification binds each record to `ledger_entries[record.ledger_seq]` and checks that the
//! entry actually debits the payer and credits the provider **by the record's own price**. A corpus
//! whose records point at absent entries can only ever reach the "missing ledger entry" refusal —
//! the one path that says nothing about whether the binding is sound. The first draft of this file
//! was exactly that corpus, and three of its five arms were measuring the wrong refusal.
//!
//! # Every negative arm keeps the ledger BALANCED
//!
//! `assert_balanced_chirho` runs inside the old-road entry verifier, so an arm that simply deletes
//! the payer posting is refused by the LEDGER for being unbalanced and never reaches the billing
//! check it claims to pin. The fixtures below therefore violate the binding while conserving:
//! money moves to or from the WRONG account, or moves in the WRONG amount on both sides. A tamper
//! fixture must violate the property it pins rather than merely differ from the original.
//!
//! # Why this file does NOT reconstruct the usage message independently
//!
//! Bricks (a2-0) and (a2-2) rebuilt the signed byte-stream from its specification, because there
//! the builder was PRIVATE and INSIDE the moving code, so a pin that called it would agree with
//! itself by construction. `usage_record_message_chirho` is `pub` in `cairn-model-economic-chirho`,
//! a crate OUTSIDE this brick's move set. **The trade is stated rather than hidden:** if that crate's
//! record types later move, this file stops being able to detect format drift and the
//! reconstruction argument returns. The LEDGER-side reconstruction below is independent, because
//! the ledger entry format is what brick (a2-1) just relocated.

use crate::app_model_chirho::{
    app_record_signed_message_chirho, AppActionChirho, AppRecordChirho, APP_RECORD_SCHEMA_CHIRHO,
};
use crate::economic_model_chirho::billing_contract_chirho::{
    compensation_record_message_chirho, policy_record_message_chirho, usage_record_message_chirho,
};
use crate::economic_model_chirho::billing_postings_chirho::compensation_postings_for_usage_chirho;
use crate::economic_model_chirho::{
    AppBillingPolicyChirho, AssetChirho, BillingCompensationRecordChirho, BillingPayerKindChirho,
    BillingPolicyModeChirho, BillingPolicyRecordChirho, BillingTagsChirho,
    BillingUsageRecordChirho, LedgerEntryChirho, PostingChirho,
    BILLING_COMPENSATION_RECORD_SCHEMA_CHIRHO, BILLING_POLICY_RECORD_SCHEMA_CHIRHO,
    BILLING_POLICY_RECORD_V2_SCHEMA_CHIRHO, BILLING_USAGE_RECORD_SCHEMA_CHIRHO,
    LEDGER_ENTRY_SCHEMA_CHIRHO,
};
use crate::identity_model_chirho::{IdentityRecordChirho, PrincipalKindChirho};
use crate::legacy_billing_evidence_chirho::{
    current_billing_policy_hash_single_road_chirho as current_billing_policy_hash_chirho,
    current_billing_policy_single_road_chirho as current_billing_policy_chirho,
    verify_billing_compensations_single_road_chirho as verify_billing_compensations_chirho,
    verify_billing_policies_single_road_chirho as verify_billing_policies_chirho,
    verify_billing_usage_single_road_chirho as verify_billing_usage_chirho,
};
use crate::model_chirho::HashChirho;
use cairn_signer_chirho::signer_chirho;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const PRICE_CHIRHO: i64 = 17;
const APP_CHIRHO: &str = "app-chirho";
const EFFECT_CHIRHO: &str = "effect-chirho";
const CALLER_CHIRHO: &str = "caller-chirho";
const PAYER_CHIRHO: &str = "payer-chirho";
const PROVIDER_CHIRHO: &str = "provider-chirho";
const CORPUS_RECORDS_CHIRHO: u64 = 2;

fn temp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-legacy-billing-characterization-{n_chirho}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d_chirho| d_chirho.as_nanos())
            .unwrap_or(0)
    ))
}

/// The usage-evidence path, reconstructed independently of the production helper.
///
/// A pin in its own right: `load_billing_usage_chirho` is in the move set, and a relocated evidence
/// file would make a subject export read an empty log and report nothing rather than fail.
fn usage_evidence_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("billing-usage-chirho.jsonl")
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

/// The v1 ledger signature message, rebuilt from its specification.
///
/// Deliberately duplicated from brick (a2-2)'s pin rather than shared: borrowing it would make this
/// file inherit that file's drift and would silently widen the surface that file's review covered.
/// **All four branches are load-bearing** — that pin's keystone arm proved it when a version
/// carrying only the schema envelope failed every arm on `entry 0 signature invalid`. This corpus
/// carries billing tags, so it takes the schema-tagged branch.
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

fn resign_usage_chirho(
    root_chirho: &Path,
    mut record_chirho: BillingUsageRecordChirho,
) -> BillingUsageRecordChirho {
    let message_chirho = usage_record_message_chirho(&record_chirho).expect("encode usage message");
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(root_chirho, &message_chirho)
        .expect("sign with the root key");
    record_chirho
}

/// The tags carried identically by every usage record and every ledger entry in the corpus.
///
/// Non-empty on purpose, and all three ids populated. The verifier compares record tags to entry
/// tags, so a corpus with default tags on both sides would pass that check vacuously; and the
/// contract requires `user_id` to equal the caller, `app_id` the app, and `effect_id` the effect,
/// so these values are the only ones that clear validation.
fn corpus_tags_chirho() -> BillingTagsChirho {
    BillingTagsChirho {
        user_id_chirho: Some(CALLER_CHIRHO.to_string()),
        app_id_chirho: Some(APP_CHIRHO.to_string()),
        effect_id_chirho: Some(EFFECT_CHIRHO.to_string()),
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

/// The same leg in the OTHER asset.
///
/// It exists because the helper above hardcoded `TokenChirho`, which made the asset conjunct of
/// both posting matches unpinnable by construction — every posting in every arm was a Token posting,
/// so deleting the asset comparison from production left the whole suite green. Found by the second
/// seat (claude_chirho, #7674) reading the predicates rather than the arms; the mover's own helper
/// could not express the axis, so the mover's own arms could never test it.
fn cash_posting_chirho(account_chirho: &str, amount_chirho: i64) -> PostingChirho {
    PostingChirho {
        account_chirho: account_chirho.to_string(),
        asset_chirho: AssetChirho::CashChirho,
        amount_chirho,
    }
}

fn entry_chirho(seq_chirho: u64, postings_chirho: Vec<PostingChirho>) -> LedgerEntryChirho {
    LedgerEntryChirho {
        seq_chirho,
        schema_chirho: LEDGER_ENTRY_SCHEMA_CHIRHO.to_string(),
        memo_chirho: "metered".to_string(),
        postings_chirho,
        billing_tags_chirho: corpus_tags_chirho(),
        at_ms_chirho: 1_700_000_000_000 + seq_chirho,
        sig_chirho: String::new(),
        op_binding_chirho: None,
    }
}

/// The charge the corpus's usage record points at: the payer is debited, the provider credited.
fn charge_entry_chirho(seq_chirho: u64) -> LedgerEntryChirho {
    entry_chirho(
        seq_chirho,
        vec![
            posting_chirho(PAYER_CHIRHO, -PRICE_CHIRHO),
            posting_chirho(PROVIDER_CHIRHO, PRICE_CHIRHO),
        ],
    )
}

fn usage_record_chirho(
    seq_chirho: u64,
    price_book_chirho: &HashChirho,
) -> BillingUsageRecordChirho {
    BillingUsageRecordChirho {
        seq_chirho,
        schema_chirho: BILLING_USAGE_RECORD_SCHEMA_CHIRHO.to_string(),
        app_chirho: APP_CHIRHO.to_string(),
        effect_chirho: EFFECT_CHIRHO.to_string(),
        caller_chirho: CALLER_CHIRHO.to_string(),
        payer_chirho: PAYER_CHIRHO.to_string(),
        payer_kind_chirho: BillingPayerKindChirho::UserChirho,
        provider_chirho: PROVIDER_CHIRHO.to_string(),
        price_chirho: PRICE_CHIRHO,
        price_book_chirho: price_book_chirho.clone(),
        billing_policy_chirho: None,
        mode_chirho: BillingPolicyModeChirho::UserPaysChirho,
        ledger_seq_chirho: seq_chirho,
        cache_hit_chirho: false,
        nway_settlement_chirho: false,
        external_provider_chirho: None,
        external_cost_token_chirho: 0,
        platform_fee_chirho: 0,
        owner_margin_chirho: 0,
        credit_hold_chirho: None,
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

fn write_usage_chirho(root_chirho: &Path, records_chirho: &[BillingUsageRecordChirho]) {
    let mut text_chirho = String::new();
    for record_chirho in records_chirho {
        text_chirho.push_str(&serde_json::to_string(record_chirho).expect("encode record"));
        text_chirho.push('\n');
    }
    std::fs::write(usage_evidence_path_chirho(root_chirho), text_chirho).expect("write usage log");
}

/// A price book stored in CAS, because usage verification resolves the record's `price_book_chirho`
/// through the object store and refuses the record if the object is not there.
fn store_price_book_chirho(root_chirho: &Path) -> HashChirho {
    crate::store_chirho::put_object_chirho(
        root_chirho,
        &crate::effect_pricing_chirho::PriceBookChirho {
            app_chirho: APP_CHIRHO.to_string(),
            owner_principal_chirho: "owner-chirho".to_string(),
            price_per_request_chirho: Some(PRICE_CHIRHO),
            effect_prices_chirho: Default::default(),
            external_markup_bps_chirho: 0,
            previous_chirho: None,
            at_ms_chirho: 1_700_000_000_000,
        },
    )
    .expect("store the corpus price book")
}

/// THE CORPUS: two metered charges, each bound to a real signed ledger entry that conserves.
///
/// Returns the price-book hash alongside the root so an arm can rebuild records without re-storing
/// it. Built by hand rather than through the production billing door for the same reason bricks
/// (a2-0) and (a2-2) built theirs by hand: R6e retired the unchecked ledger door and requires zero
/// production caller edges, and the checked door refuses a debit against an empty account, so
/// neither can seed a first entry. The keystone arm recovers what a write-side fixture would have
/// shown — production ACCEPTS records and entries this file signed independently.
fn corpus_root_chirho() -> (PathBuf, HashChirho) {
    let root_chirho = temp_root_chirho();
    std::fs::create_dir_all(&root_chirho).expect("create root");
    let price_book_chirho = store_price_book_chirho(&root_chirho);

    let entries_chirho: Vec<_> = (0..CORPUS_RECORDS_CHIRHO)
        .map(|seq_chirho| resign_entry_chirho(&root_chirho, charge_entry_chirho(seq_chirho)))
        .collect();
    write_entries_chirho(&root_chirho, &entries_chirho);

    let records_chirho: Vec<_> = (0..CORPUS_RECORDS_CHIRHO)
        .map(|seq_chirho| {
            resign_usage_chirho(
                &root_chirho,
                usage_record_chirho(seq_chirho, &price_book_chirho),
            )
        })
        .collect();
    write_usage_chirho(&root_chirho, &records_chirho);

    (root_chirho, price_book_chirho)
}

#[test]
fn the_usage_verifier_counts_the_signed_records_it_authenticated_chirho() {
    // THE KEYSTONE, and the baseline every negative arm below depends on. Production recomputes the
    // signed message, re-resolves the price book, and re-checks the ledger postings, so ACCEPTING
    // this corpus proves the fixture is a real instrument rather than a decoration.
    //
    // READ THIS ARM FIRST when the suite goes red: if it fails, every arm below is failing for the
    // same reason and not for the property it names.
    let (root_chirho, _price_book_chirho) = corpus_root_chirho();
    assert_eq!(
        verify_billing_usage_chirho(&root_chirho).unwrap(),
        CORPUS_RECORDS_CHIRHO as usize,
        "the verifier must report the records it authenticated against the ledger"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn an_absent_billing_log_verifies_as_zero_rather_than_failing_chirho() {
    // The property a subject export depends on: a root that never billed anything is not an ERROR.
    // Asserting the COUNT rather than `is_ok`, because `is_ok` cannot tell "no records" from "read
    // nothing due to a wrong path" — and a wrong path is exactly what an extraction can cause.
    let root_chirho = temp_root_chirho();
    std::fs::create_dir_all(&root_chirho).expect("create root");
    assert_eq!(verify_billing_policies_chirho(&root_chirho).unwrap(), 0);
    assert_eq!(verify_billing_usage_chirho(&root_chirho).unwrap(), 0);
    assert_eq!(
        verify_billing_compensations_chirho(&root_chirho).unwrap(),
        0
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn the_usage_evidence_path_is_pinned_chirho() {
    // Observed THROUGH production: the fixture writes to the independently-reconstructed path and
    // production finds it. THE COUNT IS LOAD-BEARING — an `is_ok()` here would pass at ZERO records,
    // which is precisely what a wrong path produces, and that is how an arm in the holds pin went
    // vacuous earlier in this brick series.
    //
    // MIGRATION PATH: if this fails after a deliberate rename, retarget `usage_evidence_path_chirho`.
    // If it fails without one, production stopped reading the file every historical subject export
    // lives in.
    let (root_chirho, _price_book_chirho) = corpus_root_chirho();
    assert!(usage_evidence_path_chirho(&root_chirho).exists());
    assert_eq!(
        verify_billing_usage_chirho(&root_chirho).unwrap(),
        CORPUS_RECORDS_CHIRHO as usize,
        "production must read the usage evidence at the reconstructed path, not merely succeed"
    );

    std::fs::remove_file(usage_evidence_path_chirho(&root_chirho)).expect("remove usage log");
    assert_eq!(
        verify_billing_usage_chirho(&root_chirho).unwrap(),
        0,
        "an absent usage log reads as zero, not as an error"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_usage_seq_gap_is_refused_chirho() {
    // Sequence continuity is a VERIFY-time property. Re-signed, so only the gap can fire.
    let (root_chirho, price_book_chirho) = corpus_root_chirho();
    let stranded_chirho =
        resign_usage_chirho(&root_chirho, usage_record_chirho(7, &price_book_chirho));
    write_usage_chirho(&root_chirho, &[stranded_chirho]);

    let error_chirho = verify_billing_usage_chirho(&root_chirho)
        .expect_err("a usage log whose first record is not seq 0 must be refused")
        .to_string();
    assert!(
        error_chirho.contains("seq gap"),
        "the refusal must be the sequence check: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn the_usage_verifier_refuses_a_tampered_record_chirho() {
    // `at_ms_chirho` is the right field to tamper, and the choice is load-bearing: it is IN the
    // signed message but is read by nothing earlier in the chain. Tampering `price_chirho` instead
    // — the obvious choice, and this file's first draft — reaches the LEDGER-POSTING check first,
    // so the arm would refuse for the binding rather than for authentication and would still be
    // green with the signature check deleted.
    let (root_chirho, price_book_chirho) = corpus_root_chirho();
    let mut records_chirho: Vec<_> = (0..CORPUS_RECORDS_CHIRHO)
        .map(|seq_chirho| {
            resign_usage_chirho(
                &root_chirho,
                usage_record_chirho(seq_chirho, &price_book_chirho),
            )
        })
        .collect();
    records_chirho[1].at_ms_chirho += 1;
    write_usage_chirho(&root_chirho, &records_chirho);

    let error_chirho = verify_billing_usage_chirho(&root_chirho)
        .expect_err("a tampered usage record must not authenticate")
        .to_string();
    assert!(
        error_chirho.contains("signature"),
        "the refusal must be authentication, not an incidental failure: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_charge_debited_to_someone_other_than_the_payer_is_refused_chirho() {
    // MONEY, and the entry still CONSERVES: the same 17 tokens move, just out of the wrong account.
    // A fixture that merely deleted the payer posting would be refused by the ledger's own
    // `assert_balanced_chirho` and would never reach the check this arm names.
    //
    // What it pins: the record claims the payer was charged; the ledger charged someone else.
    let (root_chirho, _price_book_chirho) = corpus_root_chirho();
    let tampered_chirho = resign_entry_chirho(
        &root_chirho,
        entry_chirho(
            0,
            vec![
                posting_chirho("someone-else-chirho", -PRICE_CHIRHO),
                posting_chirho(PROVIDER_CHIRHO, PRICE_CHIRHO),
            ],
        ),
    );
    let clean_chirho = resign_entry_chirho(&root_chirho, charge_entry_chirho(1));
    write_entries_chirho(&root_chirho, &[tampered_chirho, clean_chirho]);

    let error_chirho = verify_billing_usage_chirho(&root_chirho)
        .expect_err("a charge that never debited the payer must be refused")
        .to_string();
    assert!(
        error_chirho.contains("missing payer debit"),
        "the refusal must be the payer binding: {error_chirho}"
    );
    assert!(
        !error_chirho.contains("unbalanced"),
        "the fixture must reach the billing check, not trip the ledger's conservation check: \
         {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_charge_credited_to_someone_other_than_the_provider_is_refused_chirho() {
    // MONEY, conserving for the same reason as the arm above. The payer is correctly debited, so
    // the debit check passes and only the provider binding can fire — which is what makes this arm
    // distinguishable from its sibling rather than a second copy of it.
    let (root_chirho, _price_book_chirho) = corpus_root_chirho();
    let tampered_chirho = resign_entry_chirho(
        &root_chirho,
        entry_chirho(
            0,
            vec![
                posting_chirho(PAYER_CHIRHO, -PRICE_CHIRHO),
                posting_chirho("someone-else-chirho", PRICE_CHIRHO),
            ],
        ),
    );
    let clean_chirho = resign_entry_chirho(&root_chirho, charge_entry_chirho(1));
    write_entries_chirho(&root_chirho, &[tampered_chirho, clean_chirho]);

    let error_chirho = verify_billing_usage_chirho(&root_chirho)
        .expect_err("a charge that never credited the provider must be refused")
        .to_string();
    assert!(
        error_chirho.contains("does not match ledger entry"),
        "the refusal must be the provider binding: {error_chirho}"
    );
    assert!(
        !error_chirho.contains("unbalanced"),
        "the fixture must reach the billing check, not trip the ledger's conservation check: \
         {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_charge_whose_ledger_amount_is_not_the_billed_price_is_refused_chirho() {
    // MONEY, and the arm the two above cannot replace. Right accounts, right direction, WRONG
    // AMOUNT — the record bills 17 while the books moved 5, and the entry conserves so the ledger
    // has no complaint. This is the arm that dies if the amount comparison is ever dropped from the
    // posting match: the sibling arms above would stay green, because their accounts differ.
    let (root_chirho, _price_book_chirho) = corpus_root_chirho();
    let understated_chirho = resign_entry_chirho(
        &root_chirho,
        entry_chirho(
            0,
            vec![
                posting_chirho(PAYER_CHIRHO, -(PRICE_CHIRHO - 12)),
                posting_chirho(PROVIDER_CHIRHO, PRICE_CHIRHO - 12),
            ],
        ),
    );
    let clean_chirho = resign_entry_chirho(&root_chirho, charge_entry_chirho(1));
    write_entries_chirho(&root_chirho, &[understated_chirho, clean_chirho]);

    let error_chirho = verify_billing_usage_chirho(&root_chirho)
        .expect_err("a charge whose ledger amount understates the billed price must be refused")
        .to_string();
    assert!(
        error_chirho.contains("missing payer debit"),
        "the refusal must be the posting binding: {error_chirho}"
    );
    assert!(
        !error_chirho.contains("unbalanced") && !error_chirho.contains("signature"),
        "the fixture must reach the amount binding, not an incidental failure: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_charge_whose_payer_was_debited_in_the_wrong_asset_is_refused_chirho() {
    // MONEY, on the axis this file's own helper could not reach. **Selected by the second seat**
    // (claude_chirho, #7674) — both posting matches are THREE conjuncts (account, ASSET, amount),
    // and the mover's three money arms move only account and amount. Delete the asset comparison
    // from both predicates and all eleven of them stay green.
    //
    // The record still bills 17 TOKENS; the ledger moved 17 CASH. `assert_balanced_chirho` sums per
    // asset, so a Cash pair conserves exactly like a Token pair and the entry passes the ledger
    // clean — which is what lets the fixture reach the billing check at all.
    let (root_chirho, _price_book_chirho) = corpus_root_chirho();
    let wrong_asset_chirho = resign_entry_chirho(
        &root_chirho,
        entry_chirho(
            0,
            vec![
                cash_posting_chirho(PAYER_CHIRHO, -PRICE_CHIRHO),
                cash_posting_chirho(PROVIDER_CHIRHO, PRICE_CHIRHO),
            ],
        ),
    );
    let clean_chirho = resign_entry_chirho(&root_chirho, charge_entry_chirho(1));
    write_entries_chirho(&root_chirho, &[wrong_asset_chirho, clean_chirho]);

    let error_chirho = verify_billing_usage_chirho(&root_chirho)
        .expect_err("a charge billed in tokens but settled in cash must be refused")
        .to_string();
    assert!(
        error_chirho.contains("missing payer debit"),
        "the refusal must be the payer binding: {error_chirho}"
    );
    assert!(
        !error_chirho.contains("unbalanced") && !error_chirho.contains("signature"),
        "the fixture must reach the asset binding, not an incidental failure: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_charge_whose_provider_was_credited_in_the_wrong_asset_is_refused_chirho() {
    // The credit-side half of the arm above, and it needs its own fixture because the debit check
    // short-circuits: if the payer leg does not match, the provider leg is never reached. So the
    // payer IS correctly debited in tokens here, and only the provider is paid in the wrong asset.
    //
    // Postings net to zero in BOTH assets, so the ledger has no complaint. The second seat measured
    // that the old-road verifier applies no account allowlist and no posting-count limit, so the
    // suspense accounts pass clean.
    //
    // THE TOKEN SUSPENSE LEG IS SPLIT 10 + 7 ON PURPOSE, and mutation testing is what asked for it.
    // A single `(suspense, Token, +17)` leg — the obvious way to balance — made this arm die under
    // the mutation that drops the PROVIDER ACCOUNT comparison as well as the one that drops the
    // asset comparison: with the account conjunct gone, `Token && +17` matched the suspense leg and
    // the check passed. Splitting the balance across two postings means no single Token posting
    // equals the price, so the only conjunct whose removal this arm can survive is the one it
    // exists to pin.
    let (root_chirho, _price_book_chirho) = corpus_root_chirho();
    let postings_chirho = vec![
        posting_chirho(PAYER_CHIRHO, -PRICE_CHIRHO),
        cash_posting_chirho(PROVIDER_CHIRHO, PRICE_CHIRHO),
        posting_chirho("suspense-one-chirho", PRICE_CHIRHO - 7),
        posting_chirho("suspense-two-chirho", 7),
        cash_posting_chirho("suspense-one-chirho", -PRICE_CHIRHO),
    ];
    // THE EXCLUSIVITY INVARIANT, ASSERTED RATHER THAN COMMENTED (second seat, #7682). The split is
    // written in terms of `PRICE_CHIRHO`, so it is tied to a constant nobody would think of as
    // load-bearing: at 17 it is 10 + 7 and correct, but at `PRICE_CHIRHO = 7` it becomes 0 + 7, the
    // second leg equals the price, and this arm silently loses exclusivity to the account-drop
    // mutation — the exact regression the split exists to prevent, arriving through an edit
    // somewhere else. This fails loudly at the moment the constant changes rather than quietly at
    // the next mutation run.
    assert!(
        !postings_chirho.iter().any(|posting_chirho| {
            posting_chirho.asset_chirho == AssetChirho::TokenChirho
                && posting_chirho.amount_chirho == PRICE_CHIRHO
        }),
        "no single Token posting may equal the price, or this arm stops being an exclusive asset pin"
    );
    let wrong_asset_chirho = resign_entry_chirho(&root_chirho, entry_chirho(0, postings_chirho));
    let clean_chirho = resign_entry_chirho(&root_chirho, charge_entry_chirho(1));
    write_entries_chirho(&root_chirho, &[wrong_asset_chirho, clean_chirho]);

    let error_chirho = verify_billing_usage_chirho(&root_chirho)
        .expect_err("a provider paid in the wrong asset must be refused")
        .to_string();
    assert!(
        error_chirho.contains("does not match ledger entry"),
        "the refusal must be the provider binding: {error_chirho}"
    );
    assert!(
        !error_chirho.contains("missing payer debit") && !error_chirho.contains("signature"),
        "the payer leg must MATCH here, or this arm is a second copy of its sibling: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_charge_whose_tags_disagree_with_its_ledger_entry_is_refused_chirho() {
    // The attribution binding: a usage record and the entry it charges must agree on WHO the spend
    // belongs to. Both sides are re-signed, so neither signature check can be what refuses.
    let (root_chirho, _price_book_chirho) = corpus_root_chirho();
    let mut retagged_chirho = charge_entry_chirho(0);
    retagged_chirho.billing_tags_chirho.user_id_chirho =
        Some("a-different-user-chirho".to_string());
    let retagged_chirho = resign_entry_chirho(&root_chirho, retagged_chirho);
    let clean_chirho = resign_entry_chirho(&root_chirho, charge_entry_chirho(1));
    write_entries_chirho(&root_chirho, &[retagged_chirho, clean_chirho]);

    let error_chirho = verify_billing_usage_chirho(&root_chirho)
        .expect_err("a charge whose ledger tags disagree with the record must be refused")
        .to_string();
    assert!(
        error_chirho.contains("tags do not match"),
        "the refusal must be the tag binding: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_charge_whose_price_book_is_not_in_the_store_is_refused_chirho() {
    // The record's price book must RESOLVE. A subject export that reported a charge whose price
    // book had been collected would be disclosing a number nothing can justify.
    let (root_chirho, _price_book_chirho) = corpus_root_chirho();
    let absent_chirho = HashChirho("1".repeat(64));
    let records_chirho: Vec<_> = (0..CORPUS_RECORDS_CHIRHO)
        .map(|seq_chirho| {
            resign_usage_chirho(
                &root_chirho,
                usage_record_chirho(seq_chirho, &absent_chirho),
            )
        })
        .collect();
    write_usage_chirho(&root_chirho, &records_chirho);

    let error_chirho = verify_billing_usage_chirho(&root_chirho)
        .expect_err("a charge pointing at an absent price book must be refused")
        .to_string();
    assert!(
        !error_chirho.contains("signature"),
        "the refusal must be the price-book resolution, not authentication: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_charge_pointing_past_the_end_of_the_ledger_is_refused_chirho() {
    // The weakest of the binding refusals, pinned anyway because it is the one an unbound record
    // reaches — and because a corpus that could ONLY reach this refusal is what made the first
    // draft of this file measure nothing.
    let (root_chirho, price_book_chirho) = corpus_root_chirho();
    let mut records_chirho: Vec<_> = (0..CORPUS_RECORDS_CHIRHO)
        .map(|seq_chirho| usage_record_chirho(seq_chirho, &price_book_chirho))
        .collect();
    records_chirho[1].ledger_seq_chirho = 9;
    let records_chirho: Vec<_> = records_chirho
        .into_iter()
        .map(|record_chirho| resign_usage_chirho(&root_chirho, record_chirho))
        .collect();
    write_usage_chirho(&root_chirho, &records_chirho);

    let error_chirho = verify_billing_usage_chirho(&root_chirho)
        .expect_err("a charge pointing past the ledger must be refused")
        .to_string();
    assert!(
        error_chirho.contains("missing ledger entry"),
        "the refusal must be the range check: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

fn compensation_evidence_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("billing-compensations-chirho.jsonl")
}

/// A corpus whose usage record at seq 0 is reversed by a compensation at seq 0.
///
/// The reversing ledger entry's postings are taken from the production helper rather than
/// hand-written: the verifier compares the entry's postings for EXACT equality against
/// `compensation_postings_for_usage_chirho`, so any hand-built approximation would refuse for the
/// wrong reason and the arm would prove nothing.
fn corpus_with_compensation_chirho() -> PathBuf {
    let (root_chirho, price_book_chirho) = corpus_root_chirho();
    let usage_chirho = usage_record_chirho(0, &price_book_chirho);

    let mut reversal_chirho =
        entry_chirho(2, compensation_postings_for_usage_chirho(&usage_chirho));
    reversal_chirho.memo_chirho = "refund".to_string();
    let entries_chirho: Vec<_> = (0..CORPUS_RECORDS_CHIRHO)
        .map(charge_entry_chirho)
        .chain(std::iter::once(reversal_chirho))
        .map(|entry_chirho| resign_entry_chirho(&root_chirho, entry_chirho))
        .collect();
    write_entries_chirho(&root_chirho, &entries_chirho);

    let mut compensation_chirho = BillingCompensationRecordChirho {
        seq_chirho: 0,
        schema_chirho: BILLING_COMPENSATION_RECORD_SCHEMA_CHIRHO.to_string(),
        original_usage_seq_chirho: 0,
        ledger_seq_chirho: 2,
        app_chirho: APP_CHIRHO.to_string(),
        caller_chirho: CALLER_CHIRHO.to_string(),
        payer_chirho: PAYER_CHIRHO.to_string(),
        amount_token_chirho: PRICE_CHIRHO,
        reason_chirho: "refund-chirho".to_string(),
        billing_tags_chirho: corpus_tags_chirho(),
        at_ms_chirho: 1_700_000_100_000,
        sig_chirho: String::new(),
    };
    compensation_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        &root_chirho,
        &compensation_record_message_chirho(&compensation_chirho).expect("encode compensation"),
    )
    .expect("sign with the root key");
    std::fs::write(
        compensation_evidence_path_chirho(&root_chirho),
        format!(
            "{}\n",
            serde_json::to_string(&compensation_chirho).expect("encode compensation record")
        ),
    )
    .expect("write compensation log");
    root_chirho
}

#[test]
fn a_compensation_verifies_against_the_usage_it_reverses_chirho() {
    // THE ARM THAT WAS MISSING, and its absence cost a money-path defect. Compensation verification
    // resolves `original_usage_seq_chirho` against the USAGE states that must be appended FIRST, so
    // the reader's two appends are ordered and the order is load-bearing. The (a2-3) rebase dropped
    // the usage append while writing the single-road entry point, and SEVEN of the spine's own tests
    // caught it -- this suite did not, because its only compensation coverage drove an EMPTY root,
    // where zero is the right answer whether or not the ordering survives.
    //
    // A pin whose only case is the empty one cannot see an ordering bug. Same family as `is_ok()`
    // passing vacuously on zero records.
    //
    // MIGRATION PATH: if this fails with "points at missing usage", the usage append was dropped
    // again. If it fails on "postings do not compensate", the production posting helper changed
    // shape and the fixture should be re-derived from it rather than patched.
    let root_chirho = corpus_with_compensation_chirho();
    assert_eq!(
        verify_billing_compensations_chirho(&root_chirho).unwrap(),
        1,
        "a compensation bound to a real usage record and a real reversing entry must verify"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The baseline for a policy read: an app that was never given a policy.
///
/// The three arms this was written beside — the v1 happy path, the v2 no-Applied-receipt refusal
/// (the money-authority one), and the ref-names-no-verified-record refusal — are NOT here yet, and
/// the reason is a corpus requirement the pin discovered rather than an omission.
///
/// **A policy record's verification requires APP-OWNERSHIP EVIDENCE.** `ensure_app_owner_chirho`
/// demands a registered identity for the owner principal AND a signed app-owner record mapping the
/// app to it, so a policy-read corpus is materially larger than the usage-read corpus this file
/// already builds: two more signed log formats, hand-built for the same R6e reason the ledger and
/// hold corpora are hand-built. Scoped as its own piece rather than rushed into a money-path
/// fixture. Recorded in the (a2-3) tasklist with the three witness shapes claude_chirho specified.
#[test]
fn an_app_with_no_billing_policy_reads_as_none_rather_than_failing_chirho() {
    // Asserting None rather than is_ok, for the same reason the count matters elsewhere -- is_ok
    // cannot tell "no policy" from "read the wrong place". This one needs no ownership evidence
    // because it never reaches record verification: there are no records.
    let (root_chirho, _price_book_chirho) = corpus_root_chirho();
    assert_eq!(
        current_billing_policy_hash_chirho(&root_chirho, APP_CHIRHO).unwrap(),
        None
    );
    assert!(current_billing_policy_chirho(&root_chirho, APP_CHIRHO)
        .unwrap()
        .is_none());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

const OWNER_PRINCIPAL_CHIRHO: &str = "owner/chirho";

fn policy_records_evidence_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("billing-policy-records-chirho.jsonl")
}

fn write_jsonl_line_chirho<T: serde::Serialize>(path_chirho: PathBuf, value_chirho: &T) {
    std::fs::write(
        path_chirho,
        format!(
            "{}\n",
            serde_json::to_string(value_chirho).expect("encode record")
        ),
    )
    .expect("write jsonl fixture");
}

/// Seed the APP-OWNERSHIP evidence a policy read requires: an OWNER-kind identity row and an
/// app-owner row naming it.
///
/// **This is the corpus requirement that re-cut shape 2**, and it is two gates reading two different
/// logs (measured by claude_chirho, #7701): `ensure_owner_principal_chirho` wants the principal in
/// the verified identity map with kind `OwnerChirho`, and `ensure_app_owned_by_chirho` wants the
/// verified app-owner map to map this exact app to that exact principal. Miss either and the policy
/// read refuses long before it reaches the property under test.
///
/// The identity message is reconstructed independently (clone, clear the signature, serialize) since
/// production's builder is private; the app-record message uses the `pub` builder from the model
/// crate, the same trade this file's header records for the usage message.
fn seed_app_ownership_chirho(root_chirho: &Path) {
    let mut identity_chirho = IdentityRecordChirho {
        seq_chirho: 0,
        schema_chirho: "identity-record-v1-chirho".to_string(),
        principal_chirho: OWNER_PRINCIPAL_CHIRHO.to_string(),
        kind_chirho: PrincipalKindChirho::OwnerChirho,
        wallet_chirho: OWNER_PRINCIPAL_CHIRHO.to_string(),
        pubkey_chirho: signer_chirho::pubkey_hex_chirho(root_chirho).expect("root pubkey"),
        at_ms_chirho: 1_700_000_000_000,
        sig_chirho: String::new(),
    };
    let message_chirho = serde_json::to_vec(&identity_chirho).expect("encode identity message");
    identity_chirho.sig_chirho =
        signer_chirho::sign_message_chirho(root_chirho, &message_chirho).expect("sign identity");
    write_jsonl_line_chirho(
        root_chirho.join("identities-chirho.jsonl"),
        &identity_chirho,
    );

    let mut app_record_chirho = AppRecordChirho {
        seq_chirho: 0,
        schema_chirho: APP_RECORD_SCHEMA_CHIRHO.to_string(),
        app_chirho: APP_CHIRHO.to_string(),
        owner_principal_chirho: OWNER_PRINCIPAL_CHIRHO.to_string(),
        dag_chirho: None,
        action_chirho: AppActionChirho::DeployChirho,
        at_ms_chirho: 1_700_000_000_000,
        previous_chirho: None,
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: None,
        sig_chirho: String::new(),
    };
    app_record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &app_record_signed_message_chirho(&app_record_chirho).expect("encode app record message"),
    )
    .expect("sign app record");
    write_jsonl_line_chirho(
        root_chirho.join("app-records-chirho.jsonl"),
        &app_record_chirho,
    );
}

fn policy_record_chirho(
    seq_chirho: u64,
    schema_chirho: &str,
    hash_chirho: &HashChirho,
) -> BillingPolicyRecordChirho {
    BillingPolicyRecordChirho {
        seq_chirho,
        schema_chirho: schema_chirho.to_string(),
        app_chirho: APP_CHIRHO.to_string(),
        owner_principal_chirho: OWNER_PRINCIPAL_CHIRHO.to_string(),
        billing_policy_chirho: hash_chirho.clone(),
        previous_chirho: None,
        at_ms_chirho: 1_700_000_000_000 + seq_chirho,
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: None,
        sig_chirho: String::new(),
    }
}

fn resign_policy_chirho(
    root_chirho: &Path,
    mut record_chirho: BillingPolicyRecordChirho,
) -> BillingPolicyRecordChirho {
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &policy_record_message_chirho(&record_chirho).expect("encode policy record"),
    )
    .expect("sign policy record");
    record_chirho
}

fn store_policy_object_chirho(root_chirho: &Path, at_ms_chirho: u64) -> HashChirho {
    crate::store_chirho::put_object_chirho(
        root_chirho,
        &AppBillingPolicyChirho {
            app_chirho: APP_CHIRHO.to_string(),
            owner_principal_chirho: OWNER_PRINCIPAL_CHIRHO.to_string(),
            default_chirho: BillingPolicyModeChirho::UserPaysChirho,
            effect_overrides_chirho: Default::default(),
            spend_caps_chirho: Default::default(),
            previous_chirho: None,
            at_ms_chirho,
        },
    )
    .expect("store policy object")
}

/// The canonical head-transition id for a billing policy v2 row, derived independently.
///
/// **A v2 row faces THREE gates, and this clears the second so an arm can reach the third.** The
/// transition-shape check wants a prefixed id and a nonzero epoch; THIS one wants the id to equal a
/// hash of the unsigned operation tuple, so an arbitrary prefixed string refuses with "does not
/// match the canonical unsigned operation tuple"; only then is the applied-receipt gate reached.
///
/// The operation tuple is reconstructed from its specification rather than by calling production's
/// private builder -- three fields and a schema string -- so a format change surfaces here as a
/// refusal instead of being inherited silently.
fn canonical_transition_id_chirho(
    root_chirho: &Path,
    record_chirho: &BillingPolicyRecordChirho,
) -> String {
    #[derive(serde::Serialize)]
    struct OperationChirho<'a> {
        schema_chirho: &'static str,
        app_chirho: &'a str,
        owner_principal_chirho: &'a str,
    }
    let operation_bytes_chirho = serde_json::to_vec(&OperationChirho {
        schema_chirho: "billing-policy-transition-operation-v1-chirho",
        app_chirho: &record_chirho.app_chirho,
        owner_principal_chirho: &record_chirho.owner_principal_chirho,
    })
    .expect("encode the operation tuple");
    let fence_chirho = cairn_writer_head_chirho::writer_head_chirho::WriterFenceTokenChirho {
        group_chirho:
            cairn_writer_head_chirho::writer_head_chirho::consistency_group_for_root_chirho(
                root_chirho,
            )
            .expect("consistency group"),
        epoch_chirho: record_chirho
            .prepared_writer_fence_epoch_chirho
            .expect("the fixture sets a prepared epoch"),
        issued_at_ms_chirho: 0,
    };
    let branch_chirho = format!("billing/{}", record_chirho.app_chirho);
    cairn_writer_head_chirho::head_transition_chirho::derive_head_transition_id_chirho(
        &cairn_writer_head_chirho::head_transition_chirho::HeadTransitionIdentityInputChirho {
            family_log_chirho: "billing-policy-records-chirho.jsonl",
            family_seq_chirho: record_chirho.seq_chirho,
            branch_chirho: &branch_chirho,
            previous_chirho: &record_chirho.previous_chirho,
            next_chirho: &record_chirho.billing_policy_chirho,
            reason_chirho: "billing-policy",
            operation_bytes_chirho: &operation_bytes_chirho,
            prepared_fence_chirho: &fence_chirho,
            at_ms_chirho: record_chirho.at_ms_chirho,
        },
    )
    .expect("derive the canonical transition id")
}

fn point_billing_ref_at_chirho(root_chirho: &Path, hash_chirho: &HashChirho) {
    let mut refs_chirho = crate::refs_chirho::load_refs_chirho(root_chirho).expect("load refs");
    refs_chirho
        .branches_chirho
        .insert(format!("billing/{APP_CHIRHO}"), hash_chirho.clone());
    std::fs::write(
        root_chirho.join("refs-chirho.json"),
        serde_json::to_vec_pretty(&refs_chirho).expect("encode refs"),
    )
    .expect("write refs fixture");
}

#[test]
fn a_v1_policy_selected_by_the_ref_head_is_returned_as_current_chirho() {
    // THE HAPPY PATH, and the baseline the three refusal arms below are only meaningful against. A
    // fixture that refused for some unrelated reason would make every negative arm pass while
    // measuring nothing -- which is exactly what happened on the first attempt at these, before the
    // app-ownership evidence was seeded.
    let (root_chirho, _price_book_chirho) = corpus_root_chirho();
    seed_app_ownership_chirho(&root_chirho);
    let hash_chirho = store_policy_object_chirho(&root_chirho, 1_700_000_000_000);
    let record_chirho = resign_policy_chirho(
        &root_chirho,
        policy_record_chirho(0, BILLING_POLICY_RECORD_SCHEMA_CHIRHO, &hash_chirho),
    );
    write_jsonl_line_chirho(
        policy_records_evidence_path_chirho(&root_chirho),
        &record_chirho,
    );
    point_billing_ref_at_chirho(&root_chirho, &hash_chirho);

    assert_eq!(
        current_billing_policy_hash_chirho(&root_chirho, APP_CHIRHO).unwrap(),
        Some(hash_chirho.clone())
    );
    let (returned_chirho, policy_chirho) = current_billing_policy_chirho(&root_chirho, APP_CHIRHO)
        .unwrap()
        .expect("a selected policy must resolve to its object");
    assert_eq!(returned_chirho, hash_chirho);
    assert_eq!(policy_chirho.app_chirho, APP_CHIRHO);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_tampered_policy_row_the_ref_does_not_select_still_refuses_chirho() {
    // **W1 — VERIFY-BEFORE-SELECT.** The read verifies the WHOLE policy history and then the ref
    // picks from it. Under the opposite order -- select one row, verify only that one -- this corpus
    // would return the clean selected row instead of refusing, so the arm distinguishes the two
    // orders rather than merely failing.
    //
    // THE TRAP THIS AVOIDS, and it is why the arm tampers row 0 rather than row 1: tampering the
    // SELECTED row proves nothing, because BOTH orders refuse it. Same family as the empty-root
    // compensation arm that missed a real ordering defect earlier in this brick. (claude_chirho,
    // #7699.)
    let (root_chirho, _price_book_chirho) = corpus_root_chirho();
    seed_app_ownership_chirho(&root_chirho);
    let old_chirho = store_policy_object_chirho(&root_chirho, 1_700_000_000_000);
    let selected_chirho = store_policy_object_chirho(&root_chirho, 1_700_000_500_000);

    // Row 0 is signed and then MUTATED, so only whole-history verification can see it.
    let mut tampered_chirho = resign_policy_chirho(
        &root_chirho,
        policy_record_chirho(0, BILLING_POLICY_RECORD_SCHEMA_CHIRHO, &old_chirho),
    );
    tampered_chirho.at_ms_chirho += 1;
    let clean_chirho = resign_policy_chirho(
        &root_chirho,
        policy_record_chirho(1, BILLING_POLICY_RECORD_SCHEMA_CHIRHO, &selected_chirho),
    );
    std::fs::write(
        policy_records_evidence_path_chirho(&root_chirho),
        format!(
            "{}\n{}\n",
            serde_json::to_string(&tampered_chirho).expect("encode row 0"),
            serde_json::to_string(&clean_chirho).expect("encode row 1")
        ),
    )
    .expect("write policy records");
    // The ref selects the CLEAN row, so a select-then-verify reader would answer happily.
    point_billing_ref_at_chirho(&root_chirho, &selected_chirho);

    let error_chirho = current_billing_policy_hash_chirho(&root_chirho, APP_CHIRHO)
        .expect_err("a tampered row elsewhere in the history must still refuse the read")
        .to_string();
    assert!(
        error_chirho.contains("signature"),
        "the refusal must be the whole-history verification: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_billing_ref_naming_no_verified_record_is_refused_chirho() {
    // **W2 — THE REF SELECTS FROM VERIFIED HISTORY, it does not INVENT.** Never pinned by the text
    // ordering guard this replaces, so it is coverage the behavioural rewrite gains rather than
    // preserves. The ref points at a real stored policy object that no signed record names -- the
    // shape a forged or stale ref takes.
    let (root_chirho, _price_book_chirho) = corpus_root_chirho();
    seed_app_ownership_chirho(&root_chirho);
    let named_chirho = store_policy_object_chirho(&root_chirho, 1_700_000_000_000);
    let unnamed_chirho = store_policy_object_chirho(&root_chirho, 1_700_000_777_000);
    assert_ne!(
        named_chirho, unnamed_chirho,
        "the fixture must vary the hash"
    );
    let record_chirho = resign_policy_chirho(
        &root_chirho,
        policy_record_chirho(0, BILLING_POLICY_RECORD_SCHEMA_CHIRHO, &named_chirho),
    );
    write_jsonl_line_chirho(
        policy_records_evidence_path_chirho(&root_chirho),
        &record_chirho,
    );
    point_billing_ref_at_chirho(&root_chirho, &unnamed_chirho);

    let error_chirho = current_billing_policy_hash_chirho(&root_chirho, APP_CHIRHO)
        .expect_err("a ref naming no signed record must not select a policy")
        .to_string();
    assert!(
        error_chirho.contains("does not select verified signed history"),
        "the refusal must be the signed-history binding: {error_chirho}"
    );
    assert!(
        !error_chirho.contains("signature"),
        "the history itself is clean here; a signature failure means the fixture drifted: \
         {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_v2_policy_without_an_applied_receipt_is_not_returned_as_current_chirho() {
    // **W3 — THE APPLIED-RECEIPT GATE, and this is the money-authority arm.** A v2 billing policy
    // row is effective only once a valid Applied receipt exists for its head transition. Billing
    // policy decides what an app CHARGES, so a written-but-never-applied policy becoming current is
    // a money-authority regression -- the outcome that made deferring this brick unacceptable.
    //
    // Behavioural beats the text guard outright here: `.find("require_applied_...(")` proves only
    // that the call is WRITTEN, and passes with it inside `if false`, after an early return, or
    // applied to a value that is never the selected row. The same hole as an `allow(dead_code)`
    // asserting deadness.
    //
    // The transition fields are POPULATED on purpose. A v2 row faces TWO gates: the transition-shape
    // check rejects incomplete evidence at VERIFY time, before the receipt gate is ever reached, so
    // a row with empty fields refuses for the wrong reason and the arm would be decoration.
    //
    // MIGRATION PATH: if this ever RETURNS a policy, the receipt gate stopped running on the path
    // that reaches it -- that is the regression, not a stale test. If it fails on "incomplete head
    // transition evidence", the fixture stopped reaching the gate and needs re-deriving.
    let (root_chirho, _price_book_chirho) = corpus_root_chirho();
    seed_app_ownership_chirho(&root_chirho);
    let hash_chirho = store_policy_object_chirho(&root_chirho, 1_700_000_000_000);
    let mut v2_chirho =
        policy_record_chirho(0, BILLING_POLICY_RECORD_V2_SCHEMA_CHIRHO, &hash_chirho);
    v2_chirho.prepared_writer_fence_epoch_chirho = Some(1);
    v2_chirho.transition_id_chirho = canonical_transition_id_chirho(&root_chirho, &v2_chirho);
    let v2_chirho = resign_policy_chirho(&root_chirho, v2_chirho);
    write_jsonl_line_chirho(
        policy_records_evidence_path_chirho(&root_chirho),
        &v2_chirho,
    );
    point_billing_ref_at_chirho(&root_chirho, &hash_chirho);

    let error_chirho = current_billing_policy_hash_chirho(&root_chirho, APP_CHIRHO)
        .expect_err("a v2 policy with no Applied receipt must not become the current policy")
        .to_string();
    assert!(
        error_chirho.contains("Applied receipt"),
        "the refusal must be the applied-receipt gate: {error_chirho}"
    );
    assert!(
        !error_chirho.contains("incomplete head transition evidence"),
        "the fixture must REACH the receipt gate, not trip the shape check before it: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}
