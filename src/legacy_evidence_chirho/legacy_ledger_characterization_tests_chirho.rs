// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pins the money-integrity behaviour of the legacy ledger read/verify core, so extracting it
//! cannot silently change what verification accepts or what evidence a reader emits.
//!
//! **This is the acceptance instrument for CF6-D2 brick (a2-0)** — the 272-line shared core that
//! `verify_ledger_chirho`, `verify_credit_holds_chirho` and the three `verify_billing_*` entry
//! points all depend on. It is where money conservation, signature authentication, and the J0a
//! authority-inert gate actually live, so it is the seam that hides risk. Landed BEFORE the move,
//! because a baseline recorded after a move proves only that the move agrees with itself.
//!
//! **Why this file exists at all, rather than the pins already in the ledger's own test module:**
//! those pins live in `src/economic_flows_chirho/ledger_chirho/tests_chirho.rs`, which is INSIDE
//! CF6-D2's delete scope. They protect the move and then die with the spine. Every property below
//! is one that must outlive `src/economic_flows_chirho`, so it is pinned here, in a file that
//! survives — the same reasoning that put brick (a1)'s pins in a retained module.
//!
//! **The v1 signature message is reconstructed INDEPENDENTLY here** (`v1_signature_message_chirho`
//! below) rather than by calling the production builder. A pin that asks the code under test to
//! describe itself agrees with itself by construction; this one disagrees if the production format
//! moves, which is the only way it can catch a format change during an extraction.

use crate::economic_model_chirho::{
    AssetChirho, LedgerEntryChirho, PostingChirho, LEDGER_ENTRY_SCHEMA_CHIRHO,
    LEDGER_ENTRY_SCHEMA_V2_CHIRHO,
};
use crate::legacy_ledger_evidence_chirho::{
    balances_chirho, gas_balance_chirho, load_entries_chirho, verified_balances_chirho,
    verified_gas_balance_chirho, verify_ledger_chirho,
};
use cairn_signer_chirho::signer_chirho;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn temp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-legacy-ledger-characterization-{n_chirho}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d_chirho| d_chirho.as_nanos())
            .unwrap_or(0)
    ))
}

/// The on-disk evidence path, reconstructed independently of the production helper.
///
/// This is a pin in its own right: an extraction that changed the filename would relocate every
/// historical ledger a subject export reads, and nothing else in the suite would notice.
fn ledger_evidence_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("ledger-chirho.jsonl")
}

/// The inner legacy string: `seq|at_ms|memo` then one `|account:Asset:amount` group per posting,
/// where `Asset` is the enum's Debug spelling.
fn legacy_message_chirho(entry_chirho: &LedgerEntryChirho) -> String {
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

/// The v1 signed message, rebuilt from the format's specification rather than from its code.
///
/// Deliberately NOT a call to `entry_signature_message_chirho`. The envelope structs are declared
/// LOCALLY, with their own field order, so a rename or reorder in production changes the signed
/// bytes here too — which is the whole point of an independent reconstruction. A first version of
/// this helper emitted only the bare legacy string; the keystone arm caught it immediately, which
/// is the behaviour an instrument is supposed to have.
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
        billing_tags_chirho: &'a crate::economic_model_chirho::BillingTagsChirho,
    }
    #[derive(serde::Serialize)]
    struct TaggedEnvelopeChirho<'a> {
        legacy_message_chirho: String,
        billing_tags_chirho: &'a crate::economic_model_chirho::BillingTagsChirho,
    }
    assert!(
        entry_chirho.op_binding_chirho.is_none(),
        "this reconstruction covers v1 only; a v2 row takes the typed-JSON path and no arm here \
         signs one"
    );
    let legacy_chirho = legacy_message_chirho(entry_chirho);
    let tags_empty_chirho = entry_chirho.billing_tags_chirho.is_empty_chirho();
    let schema_empty_chirho = entry_chirho.schema_chirho.is_empty();
    match (tags_empty_chirho, schema_empty_chirho) {
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

/// Re-sign a v1 entry with the root's real key, using the INDEPENDENT message reconstruction.
///
/// Load-bearing in every conservation/gate arm below: without it those arms would refuse on
/// "signature invalid" and prove nothing about the property they name.
fn resign_v1_chirho(root_chirho: &Path, mut entry_chirho: LedgerEntryChirho) -> LedgerEntryChirho {
    entry_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &v1_signature_message_chirho(&entry_chirho),
    )
    .expect("sign with the root key");
    entry_chirho
}

fn write_entries_chirho(root_chirho: &Path, entries_chirho: &[LedgerEntryChirho]) {
    let mut text_chirho = String::new();
    for entry_chirho in entries_chirho {
        text_chirho.push_str(&serde_json::to_string(entry_chirho).expect("serialize entry"));
        text_chirho.push('\n');
    }
    std::fs::write(ledger_evidence_path_chirho(root_chirho), text_chirho).expect("write ledger");
}

fn postings_chirho(payer_amount_chirho: i64, payee_amount_chirho: i64) -> Vec<PostingChirho> {
    vec![
        PostingChirho {
            account_chirho: "payer-chirho".to_string(),
            asset_chirho: AssetChirho::TokenChirho,
            amount_chirho: payer_amount_chirho,
        },
        PostingChirho {
            account_chirho: "payee-chirho".to_string(),
            asset_chirho: AssetChirho::TokenChirho,
            amount_chirho: payee_amount_chirho,
        },
    ]
}

/// A root with exactly one balanced v1 entry, signed with the root's real key.
///
/// **Deliberately built by hand rather than through a production transfer.** R6e retired the
/// unchecked `transfer_chirho` door and its guard requires ZERO production caller edges; the checked
/// door refuses a debit against an empty account, so it cannot seed a first entry either. Building
/// the row here costs nothing the instrument needed: the keystone arm below proves the signature
/// format from the READ side, by showing production's verifier ACCEPTS bytes this file signed
/// independently — which is the same equivalence the write side would have shown.
fn root_with_one_entry_chirho() -> PathBuf {
    let root_chirho = temp_root_chirho();
    std::fs::create_dir_all(&root_chirho).expect("create root");
    let entry_chirho = resign_v1_chirho(
        &root_chirho,
        LedgerEntryChirho {
            seq_chirho: 0,
            schema_chirho: LEDGER_ENTRY_SCHEMA_CHIRHO.to_string(),
            memo_chirho: "grant".to_string(),
            postings_chirho: postings_chirho(-100, 100),
            billing_tags_chirho: Default::default(),
            at_ms_chirho: 1_700_000_000_000,
            sig_chirho: String::new(),
            op_binding_chirho: None,
        },
    );
    write_entries_chirho(&root_chirho, &[entry_chirho]);
    root_chirho
}

#[test]
fn the_independent_v1_reconstruction_agrees_with_the_production_signature_chirho() {
    // The keystone arm: it proves the reconstruction above is a REAL instrument. Production's
    // verifier recomputes `entry_signature_message_chirho` and checks the signature against it, so
    // ACCEPTING an entry this file signed proves the two byte-streams are identical. If the formats
    // ever diverge, every other arm that re-signs would start failing on "signature invalid"
    // instead of on the property it names -- so read this arm first when the suite goes red.
    let root_chirho = root_with_one_entry_chirho();
    assert_eq!(
        verify_ledger_chirho(&root_chirho).unwrap(),
        1,
        "production's verifier must accept an entry signed with this file's spec-derived v1 \
         message; a refusal means the instrument is stale, not that the ledger is broken"
    );
    let entries_chirho = load_entries_chirho(&root_chirho).unwrap();
    assert_eq!(entries_chirho.len(), 1);
    assert_eq!(entries_chirho[0].schema_chirho, LEDGER_ENTRY_SCHEMA_CHIRHO);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn the_ledger_evidence_path_is_pinned_chirho() {
    // A relocated evidence file is a silent subject-export break: exports would read an EMPTY ledger
    // and report nothing rather than fail. So the assertion has to be that PRODUCTION resolves the
    // pinned filename -- not merely that this file wrote one.
    //
    // THIS ARM WAS VACUOUS ONCE AND THE MUTATION HARNESS CAUGHT IT. It originally asserted
    // `<root>/ledger-chirho.jsonl` EXISTS after the fixture ran. That was a real check only while the
    // fixture seeded through a production transfer; once the fixture was changed to hand-build its
    // entry (to stop calling R6e's retired write door), the test wrote the path through its OWN
    // reconstruction and the arm could no longer see production's helper at all. It passed either
    // way. Reading production's loader is what makes the pin bite: relocate `ledger_path_chirho` and
    // `load_entries_chirho` finds nothing.
    let root_chirho = root_with_one_entry_chirho();
    assert!(
        root_chirho.join("ledger-chirho.jsonl").exists(),
        "the fixture must have written the pinned filename"
    );
    assert_eq!(
        load_entries_chirho(&root_chirho).unwrap().len(),
        1,
        "production's reader must resolve <root>/ledger-chirho.jsonl; reading zero entries here \
         means the evidence path moved and every subject export silently went empty"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn conservation_refuses_a_correctly_signed_unbalanced_entry_chirho() {
    // MONEY CONSERVATION on a CORRECTLY SIGNED entry. The re-sign is what makes this a conservation
    // pin rather than a signature pin -- see the AGENTS.md rule that a tamper fixture must VIOLATE
    // the property it pins, not merely differ from the original.
    let root_chirho = root_with_one_entry_chirho();
    let mut entries_chirho = load_entries_chirho(&root_chirho).unwrap();
    entries_chirho[0].postings_chirho[1].amount_chirho = 50; // -100 against +50: fifty vanish.
    entries_chirho[0] = resign_v1_chirho(&root_chirho, entries_chirho[0].clone());
    write_entries_chirho(&root_chirho, &entries_chirho);

    let error_chirho = verify_ledger_chirho(&root_chirho).unwrap_err().to_string();
    assert!(
        error_chirho.contains("unbalanced entry"),
        "must refuse on CONSERVATION: {error_chirho}"
    );
    assert!(
        !error_chirho.contains("signature"),
        "a signature refusal would mean this arm proves nothing about conservation: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn authenticity_refuses_a_balanced_but_unsigned_edit_chirho() {
    // The complement: an edit that KEEPS conservation (-10_000/+10_000 still sums to zero) and is
    // NOT re-signed. Only the signature check can refuse it, so it pins authentication.
    let root_chirho = root_with_one_entry_chirho();
    let mut entries_chirho = load_entries_chirho(&root_chirho).unwrap();
    entries_chirho[0].postings_chirho = postings_chirho(-10_000, 10_000);
    write_entries_chirho(&root_chirho, &entries_chirho);

    let error_chirho = verify_ledger_chirho(&root_chirho).unwrap_err().to_string();
    assert!(
        error_chirho.contains("signature"),
        "a balanced but unsigned edit must be refused on AUTHENTICITY: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_seq_gap_is_refused_by_verification_chirho() {
    let root_chirho = root_with_one_entry_chirho();
    let mut entries_chirho = load_entries_chirho(&root_chirho).unwrap();
    entries_chirho[0].seq_chirho = 7;
    entries_chirho[0] = resign_v1_chirho(&root_chirho, entries_chirho[0].clone());
    write_entries_chirho(&root_chirho, &entries_chirho);

    let error_chirho = verify_ledger_chirho(&root_chirho).unwrap_err().to_string();
    assert!(
        error_chirho.contains("seq gap"),
        "a correctly signed entry at the wrong sequence position must still be refused: \
         {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn an_absent_ledger_verifies_as_zero_entries_chirho() {
    // Reading absence as empty (not as an error) is what lets a fresh root be audited at all.
    let root_chirho = temp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    assert_eq!(load_entries_chirho(&root_chirho).unwrap().len(), 0);
    assert_eq!(verify_ledger_chirho(&root_chirho).unwrap(), 0);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn an_unsupported_schema_is_refused_at_load_chirho() {
    let root_chirho = root_with_one_entry_chirho();
    let mut entries_chirho = load_entries_chirho(&root_chirho).unwrap();
    entries_chirho[0].schema_chirho = "ledger-entry-v99-chirho".to_string();
    write_entries_chirho(&root_chirho, &entries_chirho);

    let error_chirho = load_entries_chirho(&root_chirho).unwrap_err().to_string();
    assert!(
        error_chirho.contains("unsupported ledger entry schema"),
        "an unknown schema must be refused at LOAD, before anything reads the row: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn the_schema_v2_biconditional_is_enforced_in_both_directions_chirho() {
    // schema-v2 <=> op_binding present. Pinned BOTH ways, because a one-way check would let a v2
    // row arrive wearing a v1 label and take the legacy signing path.
    let root_chirho = root_with_one_entry_chirho();
    let mut entries_chirho = load_entries_chirho(&root_chirho).unwrap();
    entries_chirho[0].schema_chirho = LEDGER_ENTRY_SCHEMA_V2_CHIRHO.to_string();
    // op_binding stays None -> v2 label without a binding.
    write_entries_chirho(&root_chirho, &entries_chirho);

    let error_chirho = load_entries_chirho(&root_chirho).unwrap_err().to_string();
    assert!(
        error_chirho.contains("biconditional"),
        "a schema-v2 label with no op_binding must be refused: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn degenerate_balance_is_accepted_and_that_is_pinned_as_behaviour_chirho() {
    // PINNED AS BEHAVIOUR, NOT BLESSED AS CORRECT. A signed entry whose postings are all zero
    // satisfies conservation arithmetically while moving nothing, and occupies a sequence position.
    // Whether that is benign is a RULING about what consumes seq numbers -- recorded open, and
    // deliberately unresolved here. The pin's value is independent of which answer is right: it
    // stops a mover changing this silently in EITHER direction.
    //
    // The arm was selected by the second seat, not by the mover, which is the point of it: pins
    // chosen by the mover cannot reveal a property the mover did not think of.
    let root_chirho = root_with_one_entry_chirho();
    let mut entries_chirho = load_entries_chirho(&root_chirho).unwrap();
    entries_chirho[0].postings_chirho = postings_chirho(0, 0);
    entries_chirho[0] = resign_v1_chirho(&root_chirho, entries_chirho[0].clone());
    write_entries_chirho(&root_chirho, &entries_chirho);

    assert_eq!(
        verify_ledger_chirho(&root_chirho).unwrap(),
        1,
        "a signed all-zero entry currently verifies clean; if this arm goes red the behaviour \
         changed and it needs a deliberate ruling, not a fixture edit"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn an_entry_with_no_postings_at_all_is_refused_chirho() {
    // The neighbouring degenerate case, which is refused rather than accepted. Pinning both sides
    // is what makes the pair informative: vacuous-empty is caught, vacuous-zero is not.
    let root_chirho = root_with_one_entry_chirho();
    let mut entries_chirho = load_entries_chirho(&root_chirho).unwrap();
    entries_chirho[0].postings_chirho = Vec::new();
    entries_chirho[0] = resign_v1_chirho(&root_chirho, entries_chirho[0].clone());
    write_entries_chirho(&root_chirho, &entries_chirho);

    let error_chirho = verify_ledger_chirho(&root_chirho).unwrap_err().to_string();
    assert!(
        error_chirho.contains("at least one posting"),
        "an entry with zero postings must be refused: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn balances_fold_verified_and_unverified_alike_on_an_intact_root_chirho() {
    // The read model over the same core. On an intact ledger both folds agree; the difference
    // between them is only whether the signatures were checked first, and that difference is what
    // the arms above pin.
    let root_chirho = root_with_one_entry_chirho();
    let plain_chirho = balances_chirho(&root_chirho).unwrap();
    let verified_chirho = verified_balances_chirho(&root_chirho).unwrap();
    assert_eq!(plain_chirho, verified_chirho);
    assert_eq!(
        plain_chirho
            .get(&("payee-chirho".to_string(), AssetChirho::TokenChirho))
            .copied(),
        Some(100)
    );
    assert_eq!(
        plain_chirho
            .get(&("payer-chirho".to_string(), AssetChirho::TokenChirho))
            .copied(),
        Some(-100)
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn the_cross_entry_balance_fold_refuses_rather_than_wrapping_chirho() {
    // ARM SELECTED AND WRITTEN BY THE SECOND SEAT (claude_chirho) post-landing — the arm the mover's
    // own eleven pins could not supply, because pins chosen by the mover cannot reveal a property
    // the mover did not think of. RETARGETED, on its own written instruction, after the defect it
    // found was fixed.
    //
    // WHAT IT ORIGINALLY PINNED, kept because the history is the evidence the fix was real:
    // `assert_balanced_chirho` guarded each entry's per-asset sums in i128 with `checked_add`, while
    // `balances_from_entries_chirho` folded the SAME money ACROSS entries in plain `+=` on i64.
    // Two entries that each verify clean end-to-end pushed one pair past `i64::MAX` — a panic under
    // dev, and under this workspace's release profile (no `overflow-checks` set anywhere) a SILENT
    // WRAP that misreported balances to `verified_balances_chirho` and to
    // `assert_balance_requirements_chirho`, the min-balance spend guard.
    //
    // WHAT IT PINS NOW: the fold REFUSES. The fixture is unchanged, so this arm going green is a
    // statement about the code and not about the test.
    let root_chirho = root_with_one_entry_chirho();
    let mut entries_chirho = load_entries_chirho(&root_chirho).unwrap();
    entries_chirho[0].postings_chirho = postings_chirho(-i64::MAX, i64::MAX);
    entries_chirho[0] = resign_v1_chirho(&root_chirho, entries_chirho[0].clone());
    let mut second_chirho = entries_chirho[0].clone();
    second_chirho.seq_chirho = 1;
    second_chirho.postings_chirho = postings_chirho(-1, 1);
    let second_chirho = resign_v1_chirho(&root_chirho, second_chirho);
    entries_chirho.push(second_chirho);
    write_entries_chirho(&root_chirho, &entries_chirho);

    assert_eq!(
        verify_ledger_chirho(&root_chirho).unwrap(),
        2,
        "both entries must verify clean end-to-end (each balanced, correctly signed, seqs \
         contiguous); a refusal here means VERIFICATION changed, not the fold"
    );
    let error_chirho = format!(
        "{}",
        verified_balances_chirho(&root_chirho)
            .expect_err("the fold must REFUSE a total that leaves i64 range, never wrap it")
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
    assert!(
        error_chirho.contains("leaves i64 range"),
        "the refusal must be the range check itself, not an incidental failure: {error_chirho}"
    );
    assert!(
        !error_chirho.contains("signature") && !error_chirho.contains("unbalanced"),
        "a signature or conservation refusal would mean this arm proves nothing about the FOLD: \
         {error_chirho}"
    );
}

// ---------------------------------------------------------------------------------------------
// CF6-D2 brick (a2-1): the three VERIFIED read entry points kept code still calls.
//
// Measured consumers OUTSIDE the deleting spine, production only: `verify_ledger_chirho` is reached
// by the CLI, by `ops_restore_drill_chirho`, and by `data_rights_chirho` -- the SUBJECT EXPORT path.
// `verified_balances_chirho` and `verified_gas_balance_chirho` are reached by the CLI.
//
// Unlike bricks (a2-0) and (a2-2), which lifted road-agnostic cores that take data as PARAMETERS,
// these three are thin wrappers over `verified_entries_chirho` -- and that function IS the gate-1
// road selection, which stays with the spine and dies with it. So what kept code calls here is the
// road selection itself, one level up. These arms pin what those entry points answer on an
// unflipped root, which is the only road that survives the deletion.
// ---------------------------------------------------------------------------------------------

#[test]
fn the_verified_entry_points_agree_with_the_evidence_on_an_unflipped_root_chirho() {
    let root_chirho = root_with_one_entry_chirho();

    // `verify_ledger_chirho` reports the COUNT it verified. Asserting the count rather than `is_ok`
    // is deliberate: `is_ok()` passes at zero entries too, and zero is exactly what a fixture that
    // silently wrote nowhere would produce.
    assert_eq!(
        verify_ledger_chirho(&root_chirho).unwrap(),
        1,
        "the subject-export path's verifier must report the entry it verified"
    );

    // The verified fold and the unverified fold agree on an honest root. They are DIFFERENT
    // guarantees -- `balances_chirho` performs no signature check at all -- so this arm pins that
    // the difference is in what they PROVE, not in what they ANSWER, when the evidence is sound.
    let verified_chirho = verified_balances_chirho(&root_chirho).unwrap();
    assert_eq!(
        verified_chirho,
        balances_chirho(&root_chirho).unwrap(),
        "on an honest root the verified and unverified folds must not disagree"
    );
    assert_eq!(
        verified_chirho
            .get(&("payee-chirho".to_string(), AssetChirho::TokenChirho))
            .copied(),
        Some(100)
    );
    assert_eq!(
        verified_chirho
            .get(&("payer-chirho".to_string(), AssetChirho::TokenChirho))
            .copied(),
        Some(-100)
    );

    assert_eq!(
        verified_gas_balance_chirho(&root_chirho, "payee-chirho").unwrap(),
        100,
        "the gas lookup must read through the VERIFIED fold"
    );
    assert_eq!(
        verified_gas_balance_chirho(&root_chirho, "no-such-account-chirho").unwrap(),
        0,
        "an account with no postings reads as zero, not as an error"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn the_verified_entry_points_refuse_a_tampered_ledger_chirho() {
    // The property that makes these three the SUBJECT-EXPORT path's verifier rather than a
    // convenience: they must refuse evidence they cannot authenticate. Mutated WITHOUT re-signing,
    // so only the signature gate can fire.
    let root_chirho = root_with_one_entry_chirho();
    let mut entry_chirho = load_entries_chirho(&root_chirho).unwrap().remove(0);
    entry_chirho.postings_chirho = postings_chirho(-100, 100);
    entry_chirho.memo_chirho = "tampered".to_string();
    write_entries_chirho(&root_chirho, &[entry_chirho]);

    for error_chirho in [
        verify_ledger_chirho(&root_chirho).expect_err("verify must refuse a tampered ledger"),
        verified_balances_chirho(&root_chirho)
            .expect_err("the verified fold must refuse a tampered ledger"),
        verified_gas_balance_chirho(&root_chirho, "payee-chirho")
            .expect_err("the verified gas lookup must refuse a tampered ledger"),
    ] {
        let text_chirho = error_chirho.to_string();
        assert!(
            text_chirho.contains("signature"),
            "the refusal must be authentication, not an incidental failure: {text_chirho}"
        );
    }

    // The UNVERIFIED fold still answers, and that is not a defect -- it is the documented difference
    // between the two families. Pinned so a later change cannot quietly give `balances_chirho` a
    // signature check and leave this file claiming a distinction that no longer exists.
    assert!(
        balances_chirho(&root_chirho).is_ok(),
        "balances_chirho performs no signature check by design; if this now refuses, the two \
         families have merged and the arm above needs rewriting rather than deleting"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Give a root a Gate-1 authority-mode branch. The hash is deliberately arbitrary: a PRESENCE-only
/// probe never dereferences it, and a fixture that had to build a valid signed mode record would be
/// testing the mode reader instead of the probe.
fn add_gate1_authority_branch_chirho(root_chirho: &Path) {
    // Written DIRECTLY rather than through `save_refs_chirho`, and not to dodge a guard: the
    // ha2 mutable-head guard counts direct-refs mutation DEBT and requires it not to grow, so
    // allowlisting a fixture would spend a real authority budget on a test. Constructing the file
    // here also makes the fixture an independent reconstruction of the refs shape, the same
    // discipline the signature helpers in this file follow.
    let mut refs_chirho = crate::refs_chirho::load_refs_chirho(root_chirho).expect("load refs");
    refs_chirho.branches_chirho.insert(
        cairn_model_gate1_chirho::GATE1_AUTHORITY_MODE_BRANCH_CHIRHO.to_string(),
        crate::model_chirho::HashChirho("0".repeat(64)),
    );
    std::fs::write(
        root_chirho.join("refs-chirho.json"),
        serde_json::to_vec_pretty(&refs_chirho).expect("encode refs"),
    )
    .expect("write refs fixture");
}

#[test]
fn the_single_road_read_refuses_a_root_carrying_a_gate1_authority_branch_chirho() {
    use crate::legacy_ledger_evidence_chirho::verified_entries_single_road_chirho;

    // Clean first, so the refusal below is attributable to the branch and nothing else. Asserting
    // the COUNT rather than is_ok: is_ok passes at zero entries, which is what a broken fixture
    // produces.
    let root_chirho = root_with_one_entry_chirho();
    assert_eq!(
        verified_entries_single_road_chirho(&root_chirho)
            .unwrap()
            .len(),
        1
    );

    add_gate1_authority_branch_chirho(&root_chirho);
    let error_chirho = verified_entries_single_road_chirho(&root_chirho)
        .expect_err("a root carrying the gate-1 authority-mode branch must be refused")
        .to_string();

    // NAME THE BRANCH, so an operator knows where to look -- and assert it through the CONSTANT
    // rather than its spelling. A pin that asserts the literal keeps checking a string nobody emits
    // once the constant is renamed: green against a stale target.
    assert!(
        error_chirho.contains(cairn_model_gate1_chirho::GATE1_AUTHORITY_MODE_BRANCH_CHIRHO),
        "the refusal must name the branch an operator has to go and inspect: {error_chirho}"
    );

    // THE NEGATIVE, and it is the property most likely to be lost under time pressure: a
    // PRESENCE-only probe does NOT know this root is in authority-log mode. A flipped-then-flipped-
    // BACK root still carries the branch and is refused here too, so claiming the mode would be a
    // FALSE statement about exactly the root this design accepted refusing -- and would send an
    // operator hunting a state that may not exist. State the observation, never the inference.
    assert!(
        !error_chirho.contains("is in authority-log")
            && !error_chirho.contains("authority-log mode"),
        "the refusal must report what was OBSERVED (a branch exists), not what it would imply: \
         {error_chirho}"
    );

    // The UNVERIFIED fold is deliberately NOT probed: it carries a different guarantee (no signature
    // check at all), and letting it inherit the probe would blur which family promises what.
    assert!(
        balances_chirho(&root_chirho).is_ok(),
        "balances_chirho is unverified by design and must not silently inherit the probe"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn the_verified_entry_points_now_route_through_the_gate1_probe_chirho() {
    // ACCEPTANCE for brick (a2-1)'s rebase. The arm above proves the PROBE refuses; this proves the
    // three entry points kept code actually calls are WIRED to it. Those are different claims: a
    // rebase that silently reverted to the dispatcher would leave the probe green and these three
    // answering from the authority stream, with nothing red.
    //
    // MIGRATION PATH: if these start ACCEPTING again, the wrappers were rebased back onto the
    // gate-1 dispatcher and a flipped root's subject export is once more answered from whichever
    // road that dispatcher picks. If they refuse on "signature", the fixture rotted.
    let root_chirho = root_with_one_entry_chirho();
    assert_eq!(verify_ledger_chirho(&root_chirho).unwrap(), 1);

    add_gate1_authority_branch_chirho(&root_chirho);
    for (label_chirho, error_chirho) in [
        (
            "verify_ledger_chirho",
            verify_ledger_chirho(&root_chirho).expect_err("must route through the probe"),
        ),
        (
            "verified_balances_chirho",
            verified_balances_chirho(&root_chirho).expect_err("must route through the probe"),
        ),
        (
            "verified_gas_balance_chirho",
            verified_gas_balance_chirho(&root_chirho, "payee-chirho")
                .expect_err("must route through the probe"),
        ),
    ] {
        let text_chirho = error_chirho.to_string();
        assert!(
            text_chirho.contains(cairn_model_gate1_chirho::GATE1_AUTHORITY_MODE_BRANCH_CHIRHO),
            "{label_chirho} must refuse via the branch probe, not incidentally: {text_chirho}"
        );
    }

    // And the unverified family still answers, because it was deliberately NOT rebased.
    assert!(
        gas_balance_chirho(&root_chirho, "payee-chirho").is_ok(),
        "the unverified family must not have inherited the probe"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}
