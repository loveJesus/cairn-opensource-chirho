// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The F4 read door: a live read unseals viewer-scoped, and every way it can go wrong fails closed.
//!
//! # WHAT IS REAL HERE AND WHAT IS NOT
//!
//! Every arm drives the real `ReadStoreChirho` arm through `run_effect_with_context_chirho` over a
//! row the real write door sealed — no hand-built envelopes standing in for production's, because an
//! envelope this module assembled would prove this module's composition rather than the door's.
//! What IS hand-made is TAMPER: rows are corrupted by writing bytes straight through
//! `VersionedStoreChirho::put_chirho`, which is the honest model of at-rest tampering precisely
//! because it bypasses the door the way an attacker with file access would.
//!
//! # WHY THE WRITES BELOW USE THE SCOPED REQUEST SHAPE
//!
//! The legacy reify shape sends the value AS its own request bytes, so request and response share
//! one address and the plaintext survives in public CAS as the REQUEST copy (§2.6 residual 1, pinned
//! by `legacy_reify_leaves_its_request_copy_public_while_the_store_row_is_sealed_chirho` next door). A
//! "no public copy" assertion over a root built that way would measure that residual instead of this
//! brick, and would fail for a reason that has nothing to do with the read path. The scoped shape
//! keeps the raw plaintext out of public CAS on the write side, so what the address check sees
//! afterwards is attributable to the READ.

use super::*;
use crate::model_chirho::RequestContextChirho;
use crate::{dag_private_value_chirho, store_seal_chirho, verify_chirho};
use std::sync::atomic::{AtomicU64, Ordering};

/// A needle no fixture value carries by accident, so a hit in a file is a real leak.
const READ_NEEDLE_CHIRHO: &str = "Hepzibah Read-Needle chirho";

fn read_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-seal-read-{label_chirho}-{nanos_chirho}-{n_chirho}"
    ))
}

fn request_context_chirho(app_chirho: &str) -> RequestContextChirho {
    RequestContextChirho {
        user_principal_chirho: "user/seal-read".to_string(),
        app_chirho: app_chirho.to_string(),
        owner_principal_chirho: "owner/seal-read".to_string(),
        client_id_chirho: "client-seal-read".to_string(),
        token_hash_chirho: "token-hash-seal-read".to_string(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    }
}

/// Seals one row through the REAL write door, scoped shape, and returns the effect it logged.
fn seal_row_through_the_write_door_chirho(
    root_chirho: &Path,
    context_chirho: Option<&RequestContextChirho>,
    idem_chirho: &str,
    prefix_chirho: &str,
    key_chirho: &str,
    value_chirho: &[u8],
) -> EffectChirho {
    let request_chirho = ScopedWriteStoreRequestChirho {
        schema_chirho: SCOPED_WRITE_STORE_SCHEMA_CHIRHO.to_string(),
        key_chirho: key_chirho.to_string(),
        value_base64_chirho: BASE64_CHIRHO.encode(value_chirho),
    };
    run_effect_with_context_chirho(
        root_chirho,
        0,
        HashChirho(idem_chirho.to_string()),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: prefix_chirho.to_string(),
        },
        &serde_json::to_vec(&request_chirho).unwrap(),
        context_chirho,
    )
    .unwrap()
}

/// Drives the REAL live-read arm.
fn live_read_chirho(
    root_chirho: &Path,
    context_chirho: Option<&RequestContextChirho>,
    idem_chirho: &str,
    key_chirho: &str,
) -> Result<EffectChirho> {
    run_effect_with_context_chirho(
        root_chirho,
        1,
        HashChirho(idem_chirho.to_string()),
        CapabilityChirho::ReadStoreChirho {
            prefix_chirho: key_chirho.to_string(),
        },
        b"",
        context_chirho,
    )
}

fn row_envelope_chirho(
    root_chirho: &Path,
    key_chirho: &str,
) -> store_seal_chirho::SealedStoreValueChirho {
    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(root_chirho))
            .unwrap();
    let row_chirho = store_chirho.get_chirho(key_chirho).unwrap().unwrap();
    match store_seal_chirho::detect_sealed_store_value_chirho(&row_chirho).unwrap() {
        store_seal_chirho::StoreValueViewChirho::SealedChirho(sealed_chirho) => *sealed_chirho,
        store_seal_chirho::StoreValueViewChirho::NotSealedChirho => {
            panic!("the write door left an unsealed row at {key_chirho}")
        }
    }
}

/// At-rest tamper: writes bytes into the store WITHOUT the sealing door, the way file access would.
fn put_row_bytes_chirho(root_chirho: &Path, key_chirho: &str, bytes_chirho: &[u8]) {
    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(root_chirho))
            .unwrap();
    store_chirho.put_chirho(key_chirho, bytes_chirho).unwrap();
}

/// Scans the whole public object plane rather than the one address we predicted.
///
/// RECURSIVE ON PURPOSE. The CAS shards objects under a two-hex prefix directory
/// (`objects-chirho/<ab>/<rest>`), so a flat `read_dir` here sees only DIRECTORIES, skips every one
/// of them, and reports "no needle" about a plane it never opened. That is why the caller pairs this
/// with a positive control: a scan of this shape is exactly the kind that passes by finding nothing.
fn public_objects_contain_chirho(root_chirho: &Path, needle_chirho: &str) -> bool {
    fn walk_chirho(dir_chirho: &Path, needle_chirho: &str) -> bool {
        let Ok(entries_chirho) = std::fs::read_dir(dir_chirho) else {
            return false;
        };
        for entry_chirho in entries_chirho.filter_map(|entry_chirho| entry_chirho.ok()) {
            let path_chirho = entry_chirho.path();
            let found_chirho = if path_chirho.is_dir() {
                walk_chirho(&path_chirho, needle_chirho)
            } else {
                std::fs::read(&path_chirho)
                    .map(|bytes_chirho| {
                        bytes_chirho
                            .windows(needle_chirho.len())
                            .any(|window_chirho| window_chirho == needle_chirho.as_bytes())
                    })
                    .unwrap_or(false)
            };
            if found_chirho {
                return true;
            }
        }
        false
    }
    walk_chirho(&root_chirho.join("objects-chirho"), needle_chirho)
}

/// THE ARM THIS BRICK EXISTS FOR: the DAG receives the row's plaintext, and no public copy of those
/// bytes exists anywhere on the object plane.
///
/// MIGRATION PATH — if this goes red, read WHICH assertion fired:
/// * the response-identity equality → the arm stopped handing the DAG plaintext (either it returned
///   the envelope again, or the unseal is not running). Check the envelope-inequality assertion
///   below: if BOTH fired, the arm is returning the envelope, which is the pre-S3 behaviour.
/// * the address or needle check → the live-read response is resting in public CAS again, which is
///   the regression this brick exists to prevent. Do NOT relax it; find what stopped forcing the
///   response private (the single site is the seal-subject match in `run_effect_...`).
/// * the private-resolution assertion → the response is neither public nor privately resolvable,
///   so a downstream node would look for bytes that do not exist. That is a DAG breakage, not a
///   privacy win.
#[test]
fn a_live_read_hands_the_dag_plaintext_while_no_public_copy_appears_chirho() {
    let root_chirho = read_root_chirho("live-read");
    let key_chirho = "reads-chirho/one";
    let value_chirho = format!("order for {READ_NEEDLE_CHIRHO}");
    let context_chirho = request_context_chirho("read-app-chirho");

    seal_row_through_the_write_door_chirho(
        &root_chirho,
        Some(&context_chirho),
        "seal-read-write",
        "reads-chirho",
        key_chirho,
        value_chirho.as_bytes(),
    );
    let envelope_chirho = row_envelope_chirho(&root_chirho, key_chirho);
    let envelope_bytes_chirho =
        store_seal_chirho::encode_sealed_store_value_chirho(&envelope_chirho).unwrap();

    let effect_chirho = live_read_chirho(
        &root_chirho,
        Some(&context_chirho),
        "seal-read-read",
        key_chirho,
    )
    .unwrap();
    let response_hash_chirho = effect_chirho.response_chirho.clone().unwrap();

    // The DAG's value identity IS the plaintext's — unchanged from the unsealed world, so caches,
    // provenance and downstream coordinates do not move.
    assert_eq!(
        response_hash_chirho,
        cas_chirho::hash_chirho(value_chirho.as_bytes()),
        "the live read did not hand the DAG the row's plaintext"
    );
    // Causal pin: at S2 this arm returned the ENVELOPE. Asserting the difference is what makes the
    // equality above evidence that the unseal ran, rather than a coincidence of the fixture.
    assert_ne!(
        response_hash_chirho,
        cas_chirho::hash_chirho(&envelope_bytes_chirho),
        "the live read returned the sealed envelope, which is the pre-S3 behaviour"
    );

    // No public copy — by address…
    //
    // WHY `is_err()` IS SOUND HERE AND MUST NOT BE COPIED INTO PRODUCTION EVIDENCE. Read as
    // "absent", `is_err()` also swallows PRESENT-BUT-UNREADABLE, so it can claim an absence the
    // read never established — the defect closed in the operator smokes, which now go through
    // `read_verified_chirho`. Three fixture facts, not the idiom, are what make it safe here: this
    // arm builds its own root inside the test, nothing sets a hostile mode or plants a directory at
    // an object path, and the needle scan immediately below is an INDEPENDENT second instrument
    // that does not share the failure mode. A new "absent from CAS" check that ships in evidence
    // has none of those, and must use `cas_chirho::read_verified_chirho`.
    assert!(
        cas_chirho::get_chirho(&root_chirho, &response_hash_chirho).is_err(),
        "the live-read response rests in public CAS"
    );
    // …and by needle, which does not depend on our own addressing being right.
    assert!(
        !public_objects_contain_chirho(&root_chirho, READ_NEEDLE_CHIRHO),
        "a public object carries the plaintext a live read unsealed"
    );
    // Positive control for the needle instrument: the same scan DOES find the needle when a public
    // object carries it, so the clean scan above means the response is private rather than that the
    // scan is blind.
    let control_root_chirho = read_root_chirho("live-read-control");
    cas_chirho::add_chirho(&control_root_chirho, value_chirho.as_bytes()).unwrap();
    assert!(
        public_objects_contain_chirho(&control_root_chirho, READ_NEEDLE_CHIRHO),
        "the needle scan cannot see a needle that IS there — the clean scan above proved nothing"
    );

    // …and the bytes ARE resolvable privately, under the row's own seal subject, so the run can
    // still feed a downstream node.
    assert_eq!(
        dag_private_value_chirho::load_private_dag_value_bytes_chirho(
            &root_chirho,
            &envelope_chirho.subject_chirho,
            &response_hash_chirho,
        )
        .unwrap(),
        value_chirho.as_bytes()
    );
    assert!(envelope_chirho
        .subject_chirho
        .starts_with(store_seal_chirho::APP_STORE_SEAL_SUBJECT_PREFIX_CHIRHO));

    // A live read is audited: it appended exactly one volatile-effect record.
    assert_eq!(
        load_volatile_effect_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        1
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
    let _ = std::fs::remove_dir_all(&control_root_chirho);
}

/// An envelope copied from another row unseals cleanly on every check that travels with the blob —
/// coverage, subject binding, MAC, AEAD, keyed digest — so only binding the KEY catches it.
///
/// MIGRATION PATH — if this goes red because the read SUCCEEDED, the key binding was lost and an
/// envelope can be replayed onto any row. If it goes red with a DIFFERENT refusal name, the binding
/// check merely moved behind another check: retarget the assertion, do not delete the arm, and
/// confirm the new refusal fires for the copied case specifically rather than for all reads.
#[test]
fn an_envelope_copied_onto_another_key_refuses_at_the_key_binding_chirho() {
    let root_chirho = read_root_chirho("copied-envelope");
    let context_chirho = request_context_chirho("read-app-chirho");
    let first_value_chirho = format!("first row for {READ_NEEDLE_CHIRHO}");

    seal_row_through_the_write_door_chirho(
        &root_chirho,
        Some(&context_chirho),
        "copy-write-a",
        "reads-chirho",
        "reads-chirho/a",
        first_value_chirho.as_bytes(),
    );
    seal_row_through_the_write_door_chirho(
        &root_chirho,
        Some(&context_chirho),
        "copy-write-b",
        "reads-chirho",
        "reads-chirho/b",
        b"second row",
    );

    // POSITIVE CONTROL, taken BEFORE the tamper: both rows read cleanly, so the refusal below is
    // caused by the copy and not by a fixture that never worked.
    let control_chirho = live_read_chirho(
        &root_chirho,
        Some(&context_chirho),
        "copy-control-a",
        "reads-chirho/a",
    )
    .unwrap();
    assert_eq!(
        control_chirho.response_chirho.unwrap(),
        cas_chirho::hash_chirho(first_value_chirho.as_bytes())
    );

    // Copy row A's envelope onto row B's key.
    let envelope_a_chirho = row_envelope_chirho(&root_chirho, "reads-chirho/a");
    put_row_bytes_chirho(
        &root_chirho,
        "reads-chirho/b",
        &store_seal_chirho::encode_sealed_store_value_chirho(&envelope_a_chirho).unwrap(),
    );

    let refusal_chirho = live_read_chirho(
        &root_chirho,
        Some(&context_chirho),
        "copy-read-b",
        "reads-chirho/b",
    )
    .expect_err("a live read returned an envelope sealed for a DIFFERENT key")
    .to_string();

    // The refusal is the key binding's OWN, asserted by identity rather than by redness…
    assert!(
        refusal_chirho.contains("does not bind this store key"),
        "the copied envelope was refused for some other reason: {refusal_chirho}"
    );
    // …and specifically NOT any of the checks that a substituted blob satisfies, because if one of
    // those fired instead it would mean this attack is being caught by accident.
    assert!(
        !refusal_chirho.contains("keyed digest mismatch"),
        "expected the key-binding refusal, got the digest refusal: {refusal_chirho}"
    );
    assert!(
        !refusal_chirho.contains("length mismatch"),
        "expected the key-binding refusal, got the length refusal: {refusal_chirho}"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// A tampered envelope refuses by the keyed-digest identity, and the read that preceded the tamper
/// is the control that says the fixture was sound.
#[test]
fn a_tampered_envelope_refuses_the_live_read_by_the_digest_identity_chirho() {
    let root_chirho = read_root_chirho("tampered-envelope");
    let context_chirho = request_context_chirho("read-app-chirho");
    let value_chirho = format!("tamper row for {READ_NEEDLE_CHIRHO}");

    seal_row_through_the_write_door_chirho(
        &root_chirho,
        Some(&context_chirho),
        "tamper-write",
        "reads-chirho",
        "reads-chirho/t",
        value_chirho.as_bytes(),
    );
    // Control first: the untampered row reads.
    live_read_chirho(
        &root_chirho,
        Some(&context_chirho),
        "tamper-control",
        "reads-chirho/t",
    )
    .expect("the untampered row must read — otherwise the refusal below proves nothing");

    // Tamper the ONE field that binds the envelope to its plaintext, leaving every other check
    // satisfiable, so only the digest check can fire.
    let mut tampered_chirho = row_envelope_chirho(&root_chirho, "reads-chirho/t");
    tampered_chirho.keyed_plaintext_digest_chirho = "0".repeat(64);
    put_row_bytes_chirho(
        &root_chirho,
        "reads-chirho/t",
        &store_seal_chirho::encode_sealed_store_value_chirho(&tampered_chirho).unwrap(),
    );

    let refusal_chirho = live_read_chirho(
        &root_chirho,
        Some(&context_chirho),
        "tamper-read",
        "reads-chirho/t",
    )
    .expect_err("a live read accepted an envelope whose digest does not bind its plaintext")
    .to_string();
    assert!(
        refusal_chirho.contains("keyed digest mismatch"),
        "expected the keyed-digest refusal: {refusal_chirho}"
    );
    assert!(
        !refusal_chirho.contains("does not bind this store key"),
        "expected the digest refusal, got the key-binding refusal: {refusal_chirho}"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// A crypto-shredded row fails the live read CLOSED: erasure removes the key, and the read that
/// worked moments earlier is what proves the shred caused it.
#[test]
fn a_shredded_row_fails_the_live_read_closed_chirho() {
    let root_chirho = read_root_chirho("shredded-row");
    let context_chirho = request_context_chirho("read-app-chirho");
    let value_chirho = format!("shred row for {READ_NEEDLE_CHIRHO}");

    seal_row_through_the_write_door_chirho(
        &root_chirho,
        Some(&context_chirho),
        "shred-write",
        "reads-chirho",
        "reads-chirho/s",
        value_chirho.as_bytes(),
    );
    let envelope_chirho = row_envelope_chirho(&root_chirho, "reads-chirho/s");

    // Control: before the shred, the row reads.
    live_read_chirho(
        &root_chirho,
        Some(&context_chirho),
        "shred-control",
        "reads-chirho/s",
    )
    .expect("the unshredded row must read — otherwise the refusal below proves nothing");

    assert!(
        crate::privacy_chirho::erase_private_blob_key_chirho(
            &root_chirho,
            &envelope_chirho.blob_chirho.key_id_chirho,
        )
        .unwrap(),
        "the shred did not remove a key, so nothing was erased"
    );

    let refusal_chirho = live_read_chirho(
        &root_chirho,
        Some(&context_chirho),
        "shred-read",
        "reads-chirho/s",
    )
    .expect_err("a live read served a row whose shred key was erased")
    .to_string();
    // Erasure semantics: the refusal names THIS row's key, so the row is unreadable because its own
    // key is gone rather than because some unrelated check failed.
    assert!(
        refusal_chirho.contains(&envelope_chirho.blob_chirho.key_id_chirho),
        "the shredded-read refusal does not name the erased key: {refusal_chirho}"
    );
    // The ciphertext survives the shred — erasure is key deletion, not object deletion.
    assert!(
        cas_chirho::get_chirho(&root_chirho, &envelope_chirho.blob_chirho.ciphertext_chirho)
            .is_ok()
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// A row that was never sealed still reads through, so a legacy root does not brick mid-transition
/// (§3a seal-forward: no migration, and reads of unsealed rows keep working).
#[test]
fn an_unsealed_legacy_row_still_reads_through_chirho() {
    let root_chirho = read_root_chirho("legacy-row");
    let context_chirho = request_context_chirho("read-app-chirho");

    // Stand a root up through the real door first so signing keys and logs exist, then plant a
    // legacy plaintext row beside it.
    seal_row_through_the_write_door_chirho(
        &root_chirho,
        Some(&context_chirho),
        "legacy-write",
        "reads-chirho",
        "reads-chirho/sealed",
        b"sealed row",
    );
    put_row_bytes_chirho(&root_chirho, "reads-chirho/legacy", b"legacy plaintext row");

    let effect_chirho = live_read_chirho(
        &root_chirho,
        Some(&context_chirho),
        "legacy-read",
        "reads-chirho/legacy",
    )
    .unwrap();
    assert_eq!(
        effect_chirho.response_chirho.clone().unwrap(),
        cas_chirho::hash_chirho(b"legacy plaintext row")
    );
    // An unsealed row has no seal subject, so its response keeps the ordinary public-CAS storage.
    assert!(cas_chirho::get_chirho(&root_chirho, &effect_chirho.response_chirho.unwrap()).is_ok());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// THE SECOND-RISKIEST SEAM: `volatile-effects-verify` is green over a root with sealed live reads,
/// and an unresolvable private response FAILS IT CLOSED rather than passing.
///
/// MIGRATION PATH — if the tampered half goes red because verification SUCCEEDED, the verify surface
/// has gone green over evidence that is not there, which is the exact failure this arm was written
/// for. Do not weaken it to a warning: a private response hash that no verifying record claims must
/// stop the verifier. If the clean half goes red instead, sealed live reads have stopped being
/// verifiable at all — check that the private-DAG-value record is being written, before suspecting
/// the verifier.
#[test]
fn volatile_verify_is_green_over_sealed_reads_and_fails_closed_when_the_record_breaks_chirho() {
    let root_chirho = read_root_chirho("volatile-verify");
    let context_chirho = request_context_chirho("read-app-chirho");
    let value_chirho = format!("verify row for {READ_NEEDLE_CHIRHO}");

    seal_row_through_the_write_door_chirho(
        &root_chirho,
        Some(&context_chirho),
        "verify-write",
        "reads-chirho",
        "reads-chirho/v",
        value_chirho.as_bytes(),
    );
    let effect_chirho = live_read_chirho(
        &root_chirho,
        Some(&context_chirho),
        "verify-read",
        "reads-chirho/v",
    )
    .unwrap();
    let response_hash_chirho = effect_chirho.response_chirho.clone().unwrap();

    // Non-vacuity: the response really did take the private route, so the verify below is exercising
    // the private resolution rather than an ordinary public object.
    assert!(
        cas_chirho::get_chirho(&root_chirho, &response_hash_chirho).is_err(),
        "the response is public, so this arm would not touch the private path at all"
    );

    // Clean: the verifier is green over a root whose live reads are sealed.
    let report_chirho = verify_chirho::verify_volatile_effect_records_chirho(&root_chirho).unwrap();
    assert_eq!(report_chirho.records_chirho, 1);
    // …and the listing agrees, with no validation error to label.
    let listing_chirho = load_volatile_effect_records_for_display_chirho(&root_chirho).unwrap();
    assert_eq!(listing_chirho.len(), 1);
    assert!(
        listing_chirho[0].valid_chirho(),
        "a sealed live read is labelled invalid: {:?}",
        listing_chirho[0].validation_error_chirho
    );

    // Now break EVERY record standing behind that private hash.
    //
    // There is more than one, and breaking a single record proves nothing: the write's response and
    // the read's response are the SAME plaintext, so they share one value hash and each minted its
    // own record. Resolution accepts the first record that verifies (deliberately — the same bytes
    // may legitimately rest under more than one subject), so a tamper that leaves a sibling intact
    // leaves the evidence intact too, and the verifier is right to stay green.
    let records_path_chirho = root_chirho.join("private-dag-values-chirho.jsonl");
    let text_chirho = std::fs::read_to_string(&records_path_chirho).unwrap();
    let mut lines_chirho: Vec<String> = text_chirho.lines().map(str::to_string).collect();
    let mut tampered_count_chirho = 0_usize;
    for line_chirho in lines_chirho
        .iter_mut()
        .filter(|line_chirho| line_chirho.contains(&response_hash_chirho.0))
    {
        let mut parsed_chirho: serde_json::Value = serde_json::from_str(line_chirho).unwrap();
        let original_sig_chirho = parsed_chirho["sig_chirho"].as_str().unwrap().to_string();
        let tampered_sig_chirho: String = original_sig_chirho.chars().rev().collect();
        assert_ne!(
            tampered_sig_chirho, original_sig_chirho,
            "the tamper did not change the signature, so nothing was mutated"
        );
        parsed_chirho["sig_chirho"] = serde_json::Value::String(tampered_sig_chirho);
        *line_chirho = serde_json::to_string(&parsed_chirho).unwrap();
        tampered_count_chirho += 1;
    }
    // Proof the mutation applied before the assertion that depends on it runs.
    assert!(
        tampered_count_chirho > 0,
        "no private DAG value record claims the live-read response, so nothing was mutated"
    );
    std::fs::write(
        &records_path_chirho,
        format!("{}\n", lines_chirho.join("\n")),
    )
    .unwrap();

    // FAIL CLOSED: a response hash claimed only by a record that does not verify stops the verifier.
    let refusal_chirho = verify_chirho::verify_volatile_effect_records_chirho(&root_chirho)
        .expect_err("volatile verify went green over a private response with no valid evidence")
        .to_string();
    assert!(
        refusal_chirho.contains("do not verify") || refusal_chirho.contains("signature invalid"),
        "the verifier failed for some other reason: {refusal_chirho}"
    );

    // The LISTING labels the same row rather than hiding it or refusing the whole listing (M144).
    let listing_chirho = load_volatile_effect_records_for_display_chirho(&root_chirho).unwrap();
    assert_eq!(listing_chirho.len(), 1);
    assert!(!listing_chirho[0].valid_chirho());
    assert!(listing_chirho[0]
        .validation_error_chirho
        .as_ref()
        .unwrap()
        .contains("verified private DAG value"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The other half of fail-closed: a private response hash NOTHING claims keeps the accurate
/// "object missing", so the two failure modes stay distinguishable in the report an operator reads.
#[test]
fn a_private_response_no_record_claims_fails_as_a_missing_object_chirho() {
    let root_chirho = read_root_chirho("missing-record");
    let context_chirho = request_context_chirho("read-app-chirho");

    seal_row_through_the_write_door_chirho(
        &root_chirho,
        Some(&context_chirho),
        "missing-write",
        "reads-chirho",
        "reads-chirho/m",
        b"row whose record will vanish",
    );
    let effect_chirho = live_read_chirho(
        &root_chirho,
        Some(&context_chirho),
        "missing-read",
        "reads-chirho/m",
    )
    .unwrap();
    let response_hash_chirho = effect_chirho.response_chirho.clone().unwrap();
    verify_chirho::verify_volatile_effect_records_chirho(&root_chirho)
        .expect("control: the verifier is green before the record is removed");

    // Drop every record claiming the response hash.
    let records_path_chirho = root_chirho.join("private-dag-values-chirho.jsonl");
    let text_chirho = std::fs::read_to_string(&records_path_chirho).unwrap();
    let kept_chirho: Vec<&str> = text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.contains(&response_hash_chirho.0))
        .collect();
    assert!(
        kept_chirho.len() < text_chirho.lines().count(),
        "the removal matched no line, so nothing was mutated"
    );
    std::fs::write(&records_path_chirho, kept_chirho.join("\n")).unwrap();

    let refusal_chirho = verify_chirho::verify_volatile_effect_records_chirho(&root_chirho)
        .expect_err("volatile verify went green over a response nothing holds")
        .to_string();
    assert!(
        refusal_chirho.contains("missing"),
        "an unclaimed private hash should keep the missing-object refusal: {refusal_chirho}"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The public object path for a hash, built the way the CAS shards it.
fn public_object_path_chirho(root_chirho: &Path, hash_chirho: &HashChirho) -> PathBuf {
    root_chirho
        .join("objects-chirho")
        .join(&hash_chirho.0[0..2])
        .join(&hash_chirho.0[2..])
}

/// Drives the REAL crash-resume arm for the live read above — the same replay path a resumed run
/// takes, entered through the execution mode that turns volatile replay on.
fn resume_read_chirho(root_chirho: &Path, idem_chirho: &str, key_chirho: &str) -> Result<()> {
    run_intent_chirho::with_run_intent_execution_chirho(&HashChirho("a".repeat(64)), true, || {
        let resumed_chirho = replay_volatile_effect_for_resume_chirho(
            root_chirho,
            &HashChirho(idem_chirho.to_string()),
            &CapabilityChirho::ReadStoreChirho {
                prefix_chirho: key_chirho.to_string(),
            },
            b"",
        )?;
        assert!(
            resumed_chirho.is_some(),
            "resume found no prior effect, so this arm is not exercising resume resolution"
        );
        Ok(())
    })
}

/// F4-S3 review finding 1: ABSENCE, TAMPER and UNREADABLE are three outcomes, and only the first
/// may be answered by looking at the private plane.
///
/// The fallback used to catch every `Err` from the public read and offer the private record to all
/// of them, so a TAMPERED public object — bytes present at an address they do not hash to, the
/// loudest signal any of these surfaces can receive — passed CLEAN whenever a valid private record
/// claimed the same hash. Sealing makes that coincidence the NORMAL case rather than a rare one:
/// every live `ReadStore` response is a private DAG value, so every volatile row routes here.
///
/// THREE CASES, because a two-case arm cannot see the near-miss fix. Gating the fallback on "the
/// read did not SUCCEED" still rescues a present-but-unreadable object (IO, permission, a
/// directory in its place) — the same defect through a smaller door, and harder to spot because
/// the code then LOOKS like it distinguishes. Case 3 is the one that catches that.
///
/// THREE SURFACES, because they held the defect independently rather than inheriting it: `verify`,
/// the display listing, and volatile RESUME each carried their own "any read failure may fall back".
///
/// MIGRATION PATH — if the tamper or unreadable arm goes red with a PASS, the fallback has widened
/// again. If it goes red naming the missing-object refusal, the outcomes are being collapsed at the
/// CAS boundary instead of distinguished there.
#[test]
fn only_absence_may_reach_the_private_fallback_on_verify_display_and_resume_chirho() {
    let root_chirho = read_root_chirho("absence-only");
    let context_chirho = request_context_chirho("read-app-chirho");
    let value_chirho = format!("absence-only row for {READ_NEEDLE_CHIRHO}");

    seal_row_through_the_write_door_chirho(
        &root_chirho,
        Some(&context_chirho),
        "absence-write",
        "reads-chirho",
        "reads-chirho/a",
        value_chirho.as_bytes(),
    );
    let effect_chirho = live_read_chirho(
        &root_chirho,
        Some(&context_chirho),
        "absence-read",
        "reads-chirho/a",
    )
    .unwrap();
    let response_hash_chirho = effect_chirho.response_chirho.clone().unwrap();

    // CASE 1 — ABSENT: the fallback is legitimate, and all three surfaces are green. This is also
    // the positive control for cases 2 and 3: without it a later refusal could be coming from a
    // fixture that was already broken, and the arm would pass for the wrong reason.
    assert!(
        matches!(
            cas_chirho::read_verified_chirho(&root_chirho, &response_hash_chirho),
            cas_chirho::CasReadOutcomeChirho::AbsentChirho(_)
        ),
        "fixture: the sealed response must be ABSENT from public CAS, or this arm never reaches \
         the private fallback at all"
    );
    verify_chirho::verify_volatile_effect_records_chirho(&root_chirho)
        .expect("control: verify is green while the object is merely absent");
    let listing_chirho = load_volatile_effect_records_for_display_chirho(&root_chirho).unwrap();
    assert_eq!(listing_chirho.len(), 1);
    assert!(
        listing_chirho[0].valid_chirho(),
        "control: the listing labelled a legitimately absent response invalid: {:?}",
        listing_chirho[0].validation_error_chirho
    );
    resume_read_chirho(&root_chirho, "absence-read", "reads-chirho/a")
        .expect("control: resume resolves the absent-but-recorded response");

    // CASE 2 — PRESENT AND TAMPERED. Bytes that do not hash to the address they sit at, planted at
    // exactly the hash the intact private record covers. The record still verifies, so the ONLY
    // thing that can refuse below is the tamper: every other refusal is removed from play.
    let object_path_chirho = public_object_path_chirho(&root_chirho, &response_hash_chirho);
    std::fs::create_dir_all(object_path_chirho.parent().unwrap()).unwrap();
    std::fs::write(&object_path_chirho, b"tampered public bytes chirho").unwrap();
    assert!(
        matches!(
            cas_chirho::read_verified_chirho(&root_chirho, &response_hash_chirho),
            cas_chirho::CasReadOutcomeChirho::TamperedChirho { .. }
        ),
        "fixture: the plant did not produce a TAMPERED outcome, so nothing below measures tamper"
    );

    let verify_refusal_chirho = format!(
        "{:#}",
        verify_chirho::verify_volatile_effect_records_chirho(&root_chirho)
            .expect_err("verify passed a tampered public object because a private record existed")
    );
    assert!(
        verify_refusal_chirho.contains("tamper detected"),
        "verify must refuse by the TAMPER identity: {verify_refusal_chirho}"
    );
    assert!(
        !verify_refusal_chirho.contains("missing"),
        "verify reported a present, corrupt object as missing: {verify_refusal_chirho}"
    );
    assert!(
        !verify_refusal_chirho.contains("could not be read"),
        "verify confused tamper with an unreadable object: {verify_refusal_chirho}"
    );

    let tampered_listing_chirho =
        load_volatile_effect_records_for_display_chirho(&root_chirho).unwrap();
    assert_eq!(tampered_listing_chirho.len(), 1, "the listing hid the row");
    let tampered_label_chirho = tampered_listing_chirho[0]
        .validation_error_chirho
        .clone()
        .expect("the listing labelled a tampered public object VALID");
    assert!(
        tampered_label_chirho.contains("re-hashes to"),
        "the listing must name the tamper: {tampered_label_chirho}"
    );

    let resume_refusal_chirho = format!(
        "{:#}",
        resume_read_chirho(&root_chirho, "absence-read", "reads-chirho/a")
            .expect_err("resume replayed over a tampered public object")
    );
    assert!(
        resume_refusal_chirho.contains("re-hashes to"),
        "resume must refuse by the TAMPER identity: {resume_refusal_chirho}"
    );

    // DIFFERENTIAL: remove the planted bytes and all three are green again, so the refusals above
    // are attributable to the tamper rather than to anything the fixture did earlier.
    std::fs::remove_file(&object_path_chirho).unwrap();
    verify_chirho::verify_volatile_effect_records_chirho(&root_chirho).expect(
        "removing the tamper did not restore the verifier, so it refused for another reason",
    );

    // CASE 3 — PRESENT BUT UNREADABLE. A directory at the object path: the read fails for a reason
    // that is NOT NotFound, deterministically and without depending on file modes (which a test
    // running as root would not honour). This is the case a "did the read succeed?" fix keeps
    // broken while looking as though it distinguishes.
    std::fs::create_dir_all(&object_path_chirho).unwrap();
    assert!(
        matches!(
            cas_chirho::read_verified_chirho(&root_chirho, &response_hash_chirho),
            cas_chirho::CasReadOutcomeChirho::UnreadableChirho(_)
        ),
        "fixture: a directory at the object path did not produce an UNREADABLE outcome, so case 3 \
         is not being measured — check what this platform returns for a read of a directory"
    );

    let unreadable_refusal_chirho = format!(
        "{:#}",
        verify_chirho::verify_volatile_effect_records_chirho(&root_chirho).expect_err(
            "verify rescued a present-but-unreadable object through the private fallback"
        )
    );
    assert!(
        unreadable_refusal_chirho.contains("could not be read"),
        "verify must refuse by the UNREADABLE identity: {unreadable_refusal_chirho}"
    );
    assert!(
        !unreadable_refusal_chirho.contains("missing"),
        "verify reported an unreadable object as missing: {unreadable_refusal_chirho}"
    );

    let unreadable_listing_chirho =
        load_volatile_effect_records_for_display_chirho(&root_chirho).unwrap();
    assert!(
        unreadable_listing_chirho[0]
            .validation_error_chirho
            .as_ref()
            .is_some_and(|label_chirho| label_chirho.contains("could not be read")),
        "the listing labelled an unreadable public object VALID: {:?}",
        unreadable_listing_chirho[0].validation_error_chirho
    );

    let unreadable_resume_chirho = format!(
        "{:#}",
        resume_read_chirho(&root_chirho, "absence-read", "reads-chirho/a")
            .expect_err("resume replayed over a present-but-unreadable object")
    );
    assert!(
        unreadable_resume_chirho.contains("could not be read"),
        "resume must refuse by the UNREADABLE identity: {unreadable_resume_chirho}"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}
