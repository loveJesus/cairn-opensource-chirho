// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use crate::cas_chirho;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A distinctive customer-shaped needle. Every arm that refuses puts this in the sealed plaintext
/// (and, where it applies, in the offending field) so a leak into an error would be visible.
const NEEDLE_CHIRHO: &str = "alice.needle@example.com";

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let pid_chirho = std::process::id();
    std::env::temp_dir().join(format!(
        "cairn-store-seal-test-{pid_chirho}-{nanos_chirho}-{n_chirho}"
    ))
}

fn keys_dir_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("privacy-keys-chirho")
}

fn key_file_count_chirho(root_chirho: &Path) -> usize {
    std::fs::read_dir(keys_dir_chirho(root_chirho))
        .map(|entries_chirho| entries_chirho.count())
        .unwrap_or(0)
}

fn privacy_blob_log_lines_chirho(root_chirho: &Path) -> usize {
    std::fs::read_to_string(root_chirho.join("privacy-blob-records-chirho.jsonl"))
        .map(|text_chirho| text_chirho.lines().count())
        .unwrap_or(0)
}

/// Flips the leading hex digit so the result stays well-formed hex of the same length.
fn flip_leading_hex_chirho(hex_chirho: &str) -> String {
    let mut flipped_chirho = hex_chirho.to_string();
    let replacement_chirho = if hex_chirho.starts_with('a') {
        'b'
    } else {
        'a'
    };
    flipped_chirho.replace_range(0..1, &replacement_chirho.to_string());
    flipped_chirho
}

fn assert_error_is_plaintext_free_chirho(error_chirho: &anyhow::Error, context_chirho: &str) {
    let display_chirho = format!("{error_chirho:#}");
    let debug_chirho = format!("{error_chirho:?}");
    assert!(
        !display_chirho.contains(NEEDLE_CHIRHO),
        "{context_chirho}: refusal Display leaked sealed plaintext: {display_chirho}"
    );
    assert!(
        !debug_chirho.contains(NEEDLE_CHIRHO),
        "{context_chirho}: refusal Debug leaked sealed plaintext: {debug_chirho}"
    );
}

fn contact_record_bytes_chirho(status_chirho: &str, extra_chirho: Option<(&str, &str)>) -> Vec<u8> {
    let mut record_chirho = serde_json::json!({
        "schema_chirho": "contact-record-v1-chirho",
        "status_chirho": status_chirho,
        "subject_chirho": "app/contact/row-1",
        "blob_chirho": {
            "ciphertext_chirho": "a".repeat(64),
            "key_id_chirho": "b".repeat(32),
            "nonce_chirho": "c".repeat(48),
            "mac_chirho": "d".repeat(64),
            "alg_chirho": "xchacha20poly1305+blake3-keyed-mac/v1",
        },
    });
    if let Some((key_chirho, value_chirho)) = extra_chirho {
        record_chirho
            .as_object_mut()
            .unwrap()
            .insert(key_chirho.to_string(), serde_json::json!(value_chirho));
    }
    serde_json::to_vec(&record_chirho).unwrap()
}

// ---------------------------------------------------------------------------
// Subject derivation (§3c) — the app-store namespace, disjoint from person subjects.
// ---------------------------------------------------------------------------

#[test]
fn store_seal_subject_derivation_matches_the_ruled_namespace_chirho() {
    let subject_chirho =
        store_seal_subject_chirho(Some("contact"), "contacts-chirho/abc123").unwrap();
    let segments_chirho: Vec<&str> = subject_chirho.split('/').collect();
    assert_eq!(segments_chirho.len(), 4, "subject was {subject_chirho}");
    assert_eq!(segments_chirho[0], "app-store");
    assert_eq!(segments_chirho[1], "contact");
    assert_eq!(segments_chirho[2], "contacts-chirho");
    assert_eq!(segments_chirho[3].len(), SUBJECT_KEY_DIGEST_HEX_LEN_CHIRHO);
    ensure_store_seal_subject_chirho(&subject_chirho).unwrap();

    // Deterministic per row key, and distinct across row keys.
    assert_eq!(
        subject_chirho,
        store_seal_subject_chirho(Some("contact"), "contacts-chirho/abc123").unwrap()
    );
    assert_ne!(
        subject_chirho,
        store_seal_subject_chirho(Some("contact"), "contacts-chirho/abc124").unwrap()
    );

    // No app context: the operator namespace, still a valid store-seal subject.
    let operator_subject_chirho =
        store_seal_subject_chirho(None, "contacts-chirho/abc123").unwrap();
    assert!(operator_subject_chirho.starts_with(OPERATOR_STORE_SEAL_SUBJECT_PREFIX_CHIRHO));
    ensure_store_seal_subject_chirho(&operator_subject_chirho).unwrap();

    // A key whose leading segment cannot be represented in a subject collapses to a fixed label
    // instead of refusing the write or mangling the key, and the key text never appears verbatim.
    let awkward_key_chirho = format!("orders {NEEDLE_CHIRHO}/row-9");
    let awkward_subject_chirho =
        store_seal_subject_chirho(Some("pizzeria"), &awkward_key_chirho).unwrap();
    assert!(
        awkward_subject_chirho.contains(OPAQUE_KEY_PREFIX_LABEL_CHIRHO),
        "subject was {awkward_subject_chirho}"
    );
    assert!(
        !awkward_subject_chirho.contains(NEEDLE_CHIRHO),
        "the store key must be embedded by digest, never verbatim: {awkward_subject_chirho}"
    );
    ensure_store_seal_subject_chirho(&awkward_subject_chirho).unwrap();

    let error_chirho = store_seal_subject_chirho(Some("contact"), "").unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("non-empty store key"),
        "expected the empty-key refusal, got: {error_chirho:#}"
    );
}

#[test]
fn ensure_store_seal_subject_rejects_person_and_free_text_subjects_chirho() {
    // Positive control: a well-formed store-seal subject is accepted.
    ensure_store_seal_subject_chirho(&format!(
        "app-store/contact/contacts-chirho/{}",
        "0".repeat(32)
    ))
    .unwrap();
    ensure_store_seal_subject_chirho(&format!("operator-store/{}", "0".repeat(32))).unwrap();

    // The F12 person namespace must never satisfy the store-seal namespace (ruling (c)).
    for person_subject_chirho in [
        "app/contact/row-1",
        "user/alice",
        "anon",
        "555-123-4567",
        "app-store/contact/contacts-chirho/not-a-digest",
        "app-store/contact/contacts-chirho",
        "app-store//contacts-chirho/00000000000000000000000000000000",
    ] {
        let error_chirho = ensure_store_seal_subject_chirho(person_subject_chirho).unwrap_err();
        assert!(
            format!("{error_chirho:#}").contains("store seal subject"),
            "expected a store-seal namespace refusal for '{person_subject_chirho}', got: {error_chirho:#}"
        );
    }
}

// ---------------------------------------------------------------------------
// Round trip + the positive controls the tamper arms lean on.
// ---------------------------------------------------------------------------

#[test]
fn seal_then_unseal_round_trips_the_exact_value_chirho() {
    let root_chirho = tmp_root_chirho();
    let value_chirho =
        format!(r#"{{"order_chirho":"2 pizzas","contact_chirho":"{NEEDLE_CHIRHO}"}}"#);
    let sealed_chirho = seal_store_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho(),
        Some("pizzeria"),
        "orders-chirho/row-1",
        value_chirho.as_bytes(),
    )
    .unwrap();

    assert_eq!(
        sealed_chirho.schema_chirho,
        SEALED_STORE_VALUE_SCHEMA_CHIRHO
    );
    assert_eq!(sealed_chirho.bytes_chirho, value_chirho.len());
    // The digest is keyed, so it is NOT the content address of the plaintext. Asserting the
    // inequality is the point: a future change that reverted to `blake3(plaintext)` would restore
    // the F1 offline oracle, and this line would go red for exactly that reason.
    assert_eq!(
        sealed_chirho.keyed_plaintext_digest_chirho,
        privacy_chirho::private_blob_keyed_plaintext_digest_chirho(
            &root_chirho,
            &sealed_chirho.blob_chirho,
            value_chirho.as_bytes(),
        )
        .unwrap()
    );
    assert_ne!(
        sealed_chirho.keyed_plaintext_digest_chirho,
        cas_chirho::hash_chirho(value_chirho.as_bytes()).0,
        "the sealed row must not carry a key-free digest of its plaintext"
    );
    assert!(
        sealed_chirho.safe_metadata_chirho.is_empty(),
        "a value outside the reviewed safe-envelope set must seal fully opaque"
    );

    // The bytes that rest carry no plaintext.
    let envelope_bytes_chirho = encode_sealed_store_value_chirho(&sealed_chirho).unwrap();
    let envelope_text_chirho = String::from_utf8(envelope_bytes_chirho.clone()).unwrap();
    assert!(
        !envelope_text_chirho.contains(NEEDLE_CHIRHO),
        "the sealed envelope must not carry the plaintext: {envelope_text_chirho}"
    );
    assert!(!envelope_text_chirho.contains("2 pizzas"));

    assert_eq!(
        unseal_store_value_chirho(&root_chirho, &sealed_chirho).unwrap(),
        value_chirho.as_bytes()
    );

    // Detection over the real at-rest bytes returns the same envelope.
    match detect_sealed_store_value_chirho(&envelope_bytes_chirho).unwrap() {
        StoreValueViewChirho::SealedChirho(detected_chirho) => {
            assert_eq!(*detected_chirho, sealed_chirho)
        }
        StoreValueViewChirho::NotSealedChirho => panic!("sealed envelope bytes read as unsealed"),
    }
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn seal_extracts_only_reviewed_safe_metadata_chirho() {
    let root_chirho = tmp_root_chirho();
    let value_chirho =
        contact_record_bytes_chirho("received", Some(("note_chirho", NEEDLE_CHIRHO)));
    let sealed_chirho = seal_store_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho(),
        Some("contact"),
        "contacts-chirho/row-1",
        &value_chirho,
    )
    .unwrap();

    let keys_chirho: Vec<&str> = sealed_chirho
        .safe_metadata_chirho
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys_chirho, SAFE_METADATA_KEYS_CHIRHO.to_vec());
    assert_eq!(
        sealed_chirho.safe_metadata_chirho.get("schema_chirho"),
        Some(&"contact-record-v1-chirho".to_string())
    );
    assert_eq!(
        sealed_chirho.safe_metadata_chirho.get("status_chirho"),
        Some(&"received".to_string())
    );

    let envelope_text_chirho =
        String::from_utf8(encode_sealed_store_value_chirho(&sealed_chirho).unwrap()).unwrap();
    assert!(
        !envelope_text_chirho.contains(NEEDLE_CHIRHO),
        "a free-text field outside the allowlist must not reach safe metadata: {envelope_text_chirho}"
    );
    assert!(!envelope_text_chirho.contains("note_chirho"));

    assert_eq!(
        unseal_store_value_chirho(&root_chirho, &sealed_chirho).unwrap(),
        value_chirho
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// ---------------------------------------------------------------------------
// Tamper refusals — each asserts the refusal IDENTITY, not merely that it errored.
// ---------------------------------------------------------------------------

/// The plaintext-identity check is KEPT by the F1 fix, only re-keyed — so the check must still fire.
/// Without this arm, "the oracle is gone" could be satisfied by deleting the check rather than
/// hardening it.
#[test]
fn tampered_keyed_plaintext_digest_fails_closed_with_the_digest_identity_chirho() {
    let root_chirho = tmp_root_chirho();
    let value_chirho = format!("contact {NEEDLE_CHIRHO}");
    let sealed_chirho = seal_store_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho(),
        Some("contact"),
        "contacts-chirho/row-1",
        value_chirho.as_bytes(),
    )
    .unwrap();
    // Positive control: the untouched envelope unseals.
    unseal_store_value_chirho(&root_chirho, &sealed_chirho).unwrap();

    let mut tampered_chirho = sealed_chirho.clone();
    tampered_chirho.keyed_plaintext_digest_chirho =
        flip_leading_hex_chirho(&sealed_chirho.keyed_plaintext_digest_chirho);
    let error_chirho = unseal_store_value_chirho(&root_chirho, &tampered_chirho).unwrap_err();
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("sealed store value keyed digest mismatch"),
        "expected the keyed plaintext-identity refusal, got: {text_chirho}"
    );
    assert!(
        !text_chirho.contains("mac") && !text_chirho.contains("length mismatch"),
        "the digest refusal must not be reported as a mac or length failure: {text_chirho}"
    );
    assert_error_is_plaintext_free_chirho(&error_chirho, "tampered keyed plaintext digest");

    // A digest that is not a well-formed digest at all is refused by the shape gate, BEFORE any
    // decrypt — so a hostile row cannot drive the compare with an arbitrary string.
    let mut malformed_chirho = sealed_chirho.clone();
    malformed_chirho.keyed_plaintext_digest_chirho = NEEDLE_CHIRHO.to_string();
    let error_chirho = unseal_store_value_chirho(&root_chirho, &malformed_chirho).unwrap_err();
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("keyed plaintext digest must be"),
        "expected the digest shape refusal, got: {text_chirho}"
    );
    assert!(
        !text_chirho.contains("privacy blob log") && !text_chirho.contains("mac"),
        "the shape gate must refuse before coverage or decrypt: {text_chirho}"
    );
    assert_error_is_plaintext_free_chirho(&error_chirho, "malformed keyed plaintext digest");
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The attack the plaintext-identity check actually exists to stop, and the reason keying it with
/// the RECORD's own key (rather than a root-wide secret) matters: substituting one version's blob
/// ref into another version's envelope passes subject binding, signed-log coverage, the blob MAC and
/// the AEAD — every one of those is a property of the substituted blob itself. Both plaintexts are
/// the same byte length here, so the declared-length gate cannot be what refuses.
#[test]
fn a_same_subject_blob_substitution_fails_closed_at_the_keyed_digest_chirho() {
    let root_chirho = tmp_root_chirho();
    let first_chirho = format!("contact {NEEDLE_CHIRHO} v1");
    let second_chirho = format!("contact {NEEDLE_CHIRHO} v2");
    assert_eq!(first_chirho.len(), second_chirho.len());

    let v1_chirho = seal_store_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho(),
        Some("contact"),
        "contacts-chirho/row-1",
        first_chirho.as_bytes(),
    )
    .unwrap();
    let v2_chirho = seal_store_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho(),
        Some("contact"),
        "contacts-chirho/row-1",
        second_chirho.as_bytes(),
    )
    .unwrap();
    // Same store key ⇒ same store-seal subject, so subject binding cannot be what refuses.
    assert_eq!(v1_chirho.subject_chirho, v2_chirho.subject_chirho);
    // Positive controls: both envelopes unseal to their own plaintext.
    unseal_store_value_chirho(&root_chirho, &v1_chirho).unwrap();
    unseal_store_value_chirho(&root_chirho, &v2_chirho).unwrap();

    let mut substituted_chirho = v2_chirho.clone();
    substituted_chirho.blob_chirho = v1_chirho.blob_chirho.clone();
    let error_chirho = unseal_store_value_chirho(&root_chirho, &substituted_chirho).unwrap_err();
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("sealed store value keyed digest mismatch"),
        "a same-subject blob substitution must refuse at the keyed digest, got: {text_chirho}"
    );
    assert!(
        !text_chirho.contains("length mismatch") && !text_chirho.contains("belongs to subject"),
        "the substitution refusal must not be reported as a length or subject failure: {text_chirho}"
    );
    assert_error_is_plaintext_free_chirho(&error_chirho, "same-subject blob substitution");
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn tampered_byte_length_fails_closed_with_the_length_identity_chirho() {
    let root_chirho = tmp_root_chirho();
    let value_chirho = format!("contact {NEEDLE_CHIRHO}");
    let sealed_chirho = seal_store_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho(),
        Some("contact"),
        "contacts-chirho/row-1",
        value_chirho.as_bytes(),
    )
    .unwrap();
    unseal_store_value_chirho(&root_chirho, &sealed_chirho).unwrap();

    let mut tampered_chirho = sealed_chirho.clone();
    tampered_chirho.bytes_chirho += 1;
    let error_chirho = unseal_store_value_chirho(&root_chirho, &tampered_chirho).unwrap_err();
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("sealed store value length mismatch"),
        "expected the declared-length refusal, got: {text_chirho}"
    );
    assert!(
        !text_chirho.contains("hash mismatch"),
        "the length refusal must not be reported as a hash failure: {text_chirho}"
    );
    assert_error_is_plaintext_free_chirho(&error_chirho, "tampered byte length");
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn tampered_blob_mac_fails_closed_at_privacy_log_coverage_chirho() {
    let root_chirho = tmp_root_chirho();
    let value_chirho = format!("contact {NEEDLE_CHIRHO}");
    let sealed_chirho = seal_store_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho(),
        Some("contact"),
        "contacts-chirho/row-1",
        value_chirho.as_bytes(),
    )
    .unwrap();
    unseal_store_value_chirho(&root_chirho, &sealed_chirho).unwrap();

    let mut tampered_chirho = sealed_chirho.clone();
    tampered_chirho.blob_chirho.mac_chirho =
        flip_leading_hex_chirho(&sealed_chirho.blob_chirho.mac_chirho);
    let error_chirho = unseal_store_value_chirho(&root_chirho, &tampered_chirho).unwrap_err();
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("privacy blob log"),
        "a mutated blob ref must fail the signed-log coverage gate, got: {text_chirho}"
    );
    assert!(
        text_chirho.contains("sealed store value"),
        "the refusal must name the store-seal context, got: {text_chirho}"
    );
    assert_error_is_plaintext_free_chirho(&error_chirho, "tampered blob mac");
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn tampered_shred_key_fails_closed_with_the_mac_identity_chirho() {
    let root_chirho = tmp_root_chirho();
    let value_chirho = format!("contact {NEEDLE_CHIRHO}");
    let sealed_chirho = seal_store_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho(),
        Some("contact"),
        "contacts-chirho/row-1",
        value_chirho.as_bytes(),
    )
    .unwrap();
    unseal_store_value_chirho(&root_chirho, &sealed_chirho).unwrap();

    // Swap the stored shred key for a different well-formed key, leaving the log row and the
    // envelope untouched, so coverage and subject binding still pass and the MAC is what refuses.
    let key_path_chirho = keys_dir_chirho(&root_chirho)
        .join(format!("{}.json", sealed_chirho.blob_chirho.key_id_chirho));
    let mut key_record_chirho: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&key_path_chirho).unwrap()).unwrap();
    let original_key_chirho = key_record_chirho["key_hex_chirho"]
        .as_str()
        .unwrap()
        .to_string();
    key_record_chirho["key_hex_chirho"] =
        serde_json::json!(flip_leading_hex_chirho(&original_key_chirho));
    std::fs::write(
        &key_path_chirho,
        serde_json::to_vec(&key_record_chirho).unwrap(),
    )
    .unwrap();

    let error_chirho = unseal_store_value_chirho(&root_chirho, &sealed_chirho).unwrap_err();
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("mac mismatch"),
        "expected the private-blob MAC refusal, got: {text_chirho}"
    );
    assert!(
        !text_chirho.contains("hash mismatch"),
        "the MAC refusal must not be reported as a plaintext-hash failure: {text_chirho}"
    );
    assert_error_is_plaintext_free_chirho(&error_chirho, "tampered shred key");
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn cross_subject_envelope_fails_closed_with_the_subject_binding_identity_chirho() {
    let root_chirho = tmp_root_chirho();
    let sealed_chirho = seal_store_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho(),
        Some("contact"),
        "contacts-chirho/row-1",
        format!("contact {NEEDLE_CHIRHO}").as_bytes(),
    )
    .unwrap();
    let other_chirho = seal_store_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho(),
        Some("pizzeria"),
        "orders-chirho/row-1",
        b"a second row",
    )
    .unwrap();
    unseal_store_value_chirho(&root_chirho, &sealed_chirho).unwrap();

    let mut tampered_chirho = sealed_chirho.clone();
    tampered_chirho.subject_chirho = other_chirho.subject_chirho.clone();
    let error_chirho = unseal_store_value_chirho(&root_chirho, &tampered_chirho).unwrap_err();
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("belongs to subject"),
        "expected the single-subject key-namespace refusal, got: {text_chirho}"
    );
    assert_error_is_plaintext_free_chirho(&error_chirho, "cross-subject envelope");
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn person_subject_envelope_is_refused_before_any_decrypt_chirho() {
    let root_chirho = tmp_root_chirho();
    // A real F12 person blob, exactly as the inner contact envelope holds one.
    let person_blob_chirho = privacy_chirho::store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            "app/contact/person-1",
        ),
        "app/contact/person-1",
        format!("name and email {NEEDLE_CHIRHO}").as_bytes(),
    )
    .unwrap();
    // Every other field is genuinely valid — including a correctly keyed digest — so the ONLY thing
    // this arm can be measuring is the subject-namespace gate.
    let person_envelope_chirho = SealedStoreValueChirho {
        schema_chirho: SEALED_STORE_VALUE_SCHEMA_CHIRHO.to_string(),
        subject_chirho: "app/contact/person-1".to_string(),
        keyed_plaintext_digest_chirho: privacy_chirho::private_blob_keyed_plaintext_digest_chirho(
            &root_chirho,
            &person_blob_chirho,
            format!("name and email {NEEDLE_CHIRHO}").as_bytes(),
        )
        .unwrap(),
        bytes_chirho: format!("name and email {NEEDLE_CHIRHO}").len(),
        blob_chirho: person_blob_chirho,
        safe_metadata_chirho: BTreeMap::new(),
    };

    let error_chirho =
        unseal_store_value_chirho(&root_chirho, &person_envelope_chirho).unwrap_err();
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("store seal subject"),
        "a person subject must be refused by the store-seal namespace gate, got: {text_chirho}"
    );
    assert!(
        !text_chirho.contains("privacy blob log") && !text_chirho.contains("mac"),
        "the namespace gate must refuse before any coverage check or decrypt: {text_chirho}"
    );
    assert_error_is_plaintext_free_chirho(&error_chirho, "person-subject envelope");
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// ---------------------------------------------------------------------------
// Bounded safe metadata (§2.5) — oversize and bad charset refused, nothing minted.
// ---------------------------------------------------------------------------

#[test]
fn oversize_and_bad_charset_safe_metadata_is_refused_chirho() {
    // Positive control: the same record with a bounded status extracts four entries.
    let good_chirho =
        safe_store_metadata_chirho(&contact_record_bytes_chirho("received", None)).unwrap();
    assert_eq!(good_chirho.len(), SAFE_METADATA_KEYS_CHIRHO.len());

    let oversize_status_chirho = format!("received-{}", NEEDLE_CHIRHO.repeat(30));
    let error_chirho =
        safe_store_metadata_chirho(&contact_record_bytes_chirho(&oversize_status_chirho, None))
            .unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("status_chirho must be 1 to"),
        "expected the status length bound, got: {error_chirho:#}"
    );
    assert_error_is_plaintext_free_chirho(&error_chirho, "oversize status");

    let error_chirho = safe_store_metadata_chirho(&contact_record_bytes_chirho(
        &format!("Received <{NEEDLE_CHIRHO}>"),
        None,
    ))
    .unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("status_chirho must be a lowercase slug"),
        "expected the status charset bound, got: {error_chirho:#}"
    );
    assert_error_is_plaintext_free_chirho(&error_chirho, "bad-charset status");
}

#[test]
fn free_text_subject_and_blob_safe_metadata_is_refused_chirho() {
    let mut record_chirho: serde_json::Value =
        serde_json::from_slice(&contact_record_bytes_chirho("received", None)).unwrap();

    let mut free_text_subject_chirho = record_chirho.clone();
    free_text_subject_chirho["subject_chirho"] = serde_json::json!(NEEDLE_CHIRHO);
    let error_chirho =
        safe_store_metadata_chirho(&serde_json::to_vec(&free_text_subject_chirho).unwrap())
            .unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("subject_chirho is not a valid privacy subject"),
        "expected the subject validation refusal, got: {error_chirho:#}"
    );
    assert_error_is_plaintext_free_chirho(&error_chirho, "free-text subject metadata");

    record_chirho["blob_chirho"]["mac_chirho"] = serde_json::json!(NEEDLE_CHIRHO);
    let error_chirho =
        safe_store_metadata_chirho(&serde_json::to_vec(&record_chirho).unwrap()).unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("blob mac is not a mac digest"),
        "expected the blob-field digest bound, got: {error_chirho:#}"
    );
    assert_error_is_plaintext_free_chirho(&error_chirho, "free-text blob mac metadata");

    let mut string_blob_chirho: serde_json::Value =
        serde_json::from_slice(&contact_record_bytes_chirho("received", None)).unwrap();
    string_blob_chirho["blob_chirho"] = serde_json::json!(NEEDLE_CHIRHO);
    let error_chirho =
        safe_store_metadata_chirho(&serde_json::to_vec(&string_blob_chirho).unwrap()).unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("blob_chirho is not a private blob ref"),
        "expected the blob shape refusal, got: {error_chirho:#}"
    );
    assert_error_is_plaintext_free_chirho(&error_chirho, "string blob metadata");

    let mut non_string_status_chirho: serde_json::Value =
        serde_json::from_slice(&contact_record_bytes_chirho("received", None)).unwrap();
    non_string_status_chirho["status_chirho"] = serde_json::json!(7);
    let error_chirho =
        safe_store_metadata_chirho(&serde_json::to_vec(&non_string_status_chirho).unwrap())
            .unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("status_chirho must be a string"),
        "expected the status type refusal, got: {error_chirho:#}"
    );
}

#[test]
fn hostile_safe_metadata_map_is_refused_without_echoing_the_key_chirho() {
    let mut safe_metadata_chirho = BTreeMap::new();
    safe_metadata_chirho.insert(NEEDLE_CHIRHO.to_string(), "received".to_string());
    let error_chirho = validate_safe_store_metadata_chirho(&safe_metadata_chirho).unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("unsupported key (digest"),
        "expected the unsupported-key refusal, got: {error_chirho:#}"
    );
    assert_error_is_plaintext_free_chirho(&error_chirho, "hostile metadata key");

    let mut overfull_chirho = BTreeMap::new();
    for index_chirho in 0..(SAFE_METADATA_KEYS_CHIRHO.len() + 1) {
        overfull_chirho.insert(format!("key-{index_chirho}"), "received".to_string());
    }
    let error_chirho = validate_safe_store_metadata_chirho(&overfull_chirho).unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("at most"),
        "expected the metadata entry-count bound, got: {error_chirho:#}"
    );

    // Positive control: the map a real seal produces validates.
    let good_chirho =
        safe_store_metadata_chirho(&contact_record_bytes_chirho("received", None)).unwrap();
    validate_safe_store_metadata_chirho(&good_chirho).unwrap();
}

#[test]
fn a_refused_seal_mints_no_shred_key_and_no_privacy_log_row_chirho() {
    let root_chirho = tmp_root_chirho();
    // Prime the root so the counters read a real, non-empty baseline.
    seal_store_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho(),
        Some("contact"),
        "contacts-chirho/row-0",
        &contact_record_bytes_chirho("received", None),
    )
    .unwrap();
    let keys_before_chirho = key_file_count_chirho(&root_chirho);
    let log_before_chirho = privacy_blob_log_lines_chirho(&root_chirho);
    assert_eq!(keys_before_chirho, 1);
    assert_eq!(log_before_chirho, 1);

    let error_chirho = seal_store_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho(),
        Some("contact"),
        "contacts-chirho/row-1",
        &contact_record_bytes_chirho(&format!("Received <{NEEDLE_CHIRHO}>"), None),
    )
    .unwrap_err();
    assert_error_is_plaintext_free_chirho(&error_chirho, "refused seal");
    assert_eq!(
        key_file_count_chirho(&root_chirho),
        keys_before_chirho,
        "a refused seal must mint no shred key"
    );
    assert_eq!(
        privacy_blob_log_lines_chirho(&root_chirho),
        log_before_chirho,
        "a refused seal must append no privacy-blob log row"
    );

    // Positive control: the counters do move for an accepted seal, so the assertion above is
    // measuring a refusal rather than a broken counter.
    seal_store_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho(),
        Some("contact"),
        "contacts-chirho/row-2",
        &contact_record_bytes_chirho("received", None),
    )
    .unwrap();
    assert_eq!(key_file_count_chirho(&root_chirho), keys_before_chirho + 1);
    assert_eq!(
        privacy_blob_log_lines_chirho(&root_chirho),
        log_before_chirho + 1
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// ---------------------------------------------------------------------------
// F1 (S2 adversarial review) — the offline dictionary attack on the row alone.
// ---------------------------------------------------------------------------

/// The four-candidate set the S2 reviewer used: a low-entropy value from a small, guessable domain,
/// which is precisely where a cleartext plaintext digest is fatal.
const F1_CANDIDATES_CHIRHO: [&str; 4] = [
    "diagnosis: HIV-negative",
    "diagnosis: HIV-positive",
    "diagnosis: pregnant",
    "diagnosis: none",
];
const F1_TRUTH_CHIRHO: &str = "diagnosis: HIV-positive";

/// Digests of a candidate that an attacker holding ONLY the row could recompute: the plaintext, its
/// bare content address, and the same address salted or keyed with each value that TRAVELS IN THE
/// ROW (the key id, the subject, the nonce, the ciphertext address) — because a salt the attacker
/// already holds is not a secret. A zero key stands for "keyed, but with a constant".
///
/// This family is deliberately not claimed to be exhaustive; no finite probe set can be. The
/// exhaustive half of the property — that the digest depends on key material which does NOT travel
/// with the row — is carried by `the_sealed_plaintext_digest_depends_on_the_shred_key_chirho`.
fn f1_row_recomputable_probes_chirho(
    candidate_chirho: &str,
    row_public_values_chirho: &[String],
) -> Vec<String> {
    let mut probes_chirho = vec![
        candidate_chirho.to_string(),
        cas_chirho::hash_chirho(candidate_chirho.as_bytes()).0,
    ];
    let mut salts_chirho: Vec<String> = vec![String::new()];
    salts_chirho.extend(row_public_values_chirho.iter().cloned());
    for salt_chirho in salts_chirho {
        let salted_chirho = format!("{salt_chirho}{candidate_chirho}");
        probes_chirho.push(cas_chirho::hash_chirho(salted_chirho.as_bytes()).0);
        probes_chirho.push(
            blake3::Hasher::new_keyed(&[0_u8; 32])
                .update(salted_chirho.as_bytes())
                .finalize()
                .to_hex()
                .to_string(),
        );
    }
    probes_chirho
}

/// The reviewer's attack, run against a row: which candidate does this row confirm?
fn f1_recover_from_row_bytes_chirho(
    row_bytes_chirho: &[u8],
    row_public_values_chirho: &[String],
) -> Option<String> {
    let row_text_chirho = String::from_utf8_lossy(row_bytes_chirho).to_string();
    F1_CANDIDATES_CHIRHO
        .iter()
        .find(|candidate_chirho| {
            f1_row_recomputable_probes_chirho(candidate_chirho, row_public_values_chirho)
                .iter()
                .any(|probe_chirho| row_text_chirho.contains(probe_chirho))
        })
        .map(|candidate_chirho| candidate_chirho.to_string())
}

/// Every value of the sealed row an attacker holding that row also holds.
fn f1_row_public_values_chirho(sealed_chirho: &SealedStoreValueChirho) -> Vec<String> {
    vec![
        sealed_chirho.blob_chirho.key_id_chirho.clone(),
        sealed_chirho.subject_chirho.clone(),
        sealed_chirho.blob_chirho.nonce_chirho.clone(),
        sealed_chirho.blob_chirho.ciphertext_chirho.0.clone(),
        sealed_chirho.blob_chirho.mac_chirho.clone(),
    ]
}

/// The causal pin for F1, and the one a constant-keyed digest fails.
///
/// Every other property of the digest — that it is 64 lowercase hex, that unseal compares it, that a
/// tampered plaintext refuses — is satisfied just as well by a digest keyed with a CONSTANT. A
/// constant-keyed digest is still an offline oracle, because every other input it takes (the key id)
/// rests in the row in the clear. So the property that actually closes F1 is narrower than "the
/// digest is keyed": it is that the digest depends on key material which does not travel with the
/// row, and disappears when that material is shredded.
///
/// MIGRATION PATH — if this goes red:
///   * the two digests EQUAL means the digest stopped depending on the shred key. F1 is back, in the
///     exact shape a probe-based arm cannot see. Fix the envelope, not this arm.
///   * the shredded-key case RETURNING a digest means a plaintext identity survived crypto-shredding
///     — the row would stay confirmable after erasure.
///   * an earlier panic means the key-file fixture drifted, not the property.
#[test]
fn the_sealed_plaintext_digest_depends_on_the_shred_key_chirho() {
    let root_chirho = tmp_root_chirho();
    let sealed_chirho = seal_store_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho(),
        Some("clinic"),
        "notes-chirho/row-1",
        F1_TRUTH_CHIRHO.as_bytes(),
    )
    .unwrap();
    let first_chirho = privacy_chirho::private_blob_keyed_plaintext_digest_chirho(
        &root_chirho,
        &sealed_chirho.blob_chirho,
        F1_TRUTH_CHIRHO.as_bytes(),
    )
    .unwrap();
    assert_eq!(first_chirho, sealed_chirho.keyed_plaintext_digest_chirho);

    // Same plaintext, same blob ref, same key id, same subject. ONLY the secret key bytes change.
    let key_path_chirho = keys_dir_chirho(&root_chirho)
        .join(format!("{}.json", sealed_chirho.blob_chirho.key_id_chirho));
    let mut key_record_chirho: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&key_path_chirho).unwrap()).unwrap();
    let original_key_chirho = key_record_chirho["key_hex_chirho"]
        .as_str()
        .unwrap()
        .to_string();
    key_record_chirho["key_hex_chirho"] =
        serde_json::json!(flip_leading_hex_chirho(&original_key_chirho));
    std::fs::write(
        &key_path_chirho,
        serde_json::to_vec(&key_record_chirho).unwrap(),
    )
    .unwrap();

    let second_chirho = privacy_chirho::private_blob_keyed_plaintext_digest_chirho(
        &root_chirho,
        &sealed_chirho.blob_chirho,
        F1_TRUTH_CHIRHO.as_bytes(),
    )
    .unwrap();
    assert_ne!(
        first_chirho, second_chirho,
        "the plaintext digest did not change when the shred key changed, so it is keyed by \
         something the row itself carries — that is still an offline oracle"
    );

    // And once the key is shredded the digest cannot be computed at all, by anyone.
    std::fs::remove_file(&key_path_chirho).unwrap();
    assert!(privacy_chirho::private_blob_keyed_plaintext_digest_chirho(
        &root_chirho,
        &sealed_chirho.blob_chirho,
        F1_TRUTH_CHIRHO.as_bytes(),
    )
    .is_err());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// **F1 — RETARGETED from the S2 reviewer's arm, which PROVED the attack succeeded.**
///
/// v1's `value_hash_chirho` was an unsalted `blake3(plaintext)` resting in the clear in the very row
/// §2.7 designates for mirroring to holders who must never read it. The reviewer sealed a
/// low-entropy value, DELETED `privacy-keys-chirho/` and `objects-chirho/`, confirmed the legitimate
/// reader was locked out, and then recovered the plaintext by hashing four candidates against the
/// cleartext hash. This arm runs the same attack and asserts it now FAILS.
///
/// MIGRATION PATH — if this arm goes red, read WHICH assertion fired:
///   * the ATTACK assertion (`recovered_chirho` is `Some`) means the offline oracle is BACK: some
///     field of the sealed row is again a key-free function of the plaintext. That is F1 regressing.
///     It is a MEDIUM privacy defect on the mirror boundary, and the fix is in the envelope, never
///     in this arm.
///   * the ATTACK-INSTRUMENT control (the v1-shaped fixture) means the attack code stopped working
///     and the clean result above proves nothing — repair the probe before trusting any green here.
///   * the LOCKOUT control means the fixture no longer deletes what it thinks it deletes.
///   * the LENGTH RESIDUAL assertion means `bytes_chirho` stopped being the exact plaintext length.
///     If that is because a later brick padded or bucketed it, this arm should be RELAXED and the
///     residual struck from the envelope doc — that would be a real improvement, not a regression.
#[test]
fn a_row_holder_without_the_shred_key_cannot_recover_a_low_entropy_plaintext_chirho() {
    let root_chirho = tmp_root_chirho();
    let sealed_chirho = seal_store_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho(),
        Some("clinic"),
        "notes-chirho/row-1",
        F1_TRUTH_CHIRHO.as_bytes(),
    )
    .unwrap();
    // Precondition: this really is a working seal, so a failed attack below cannot be an artifact of
    // a broken fixture.
    assert_eq!(
        unseal_store_value_chirho(&root_chirho, &sealed_chirho).unwrap(),
        F1_TRUTH_CHIRHO.as_bytes()
    );

    // ATTACK-INSTRUMENT CONTROL: the same probe against a v1-shaped row — the exact shape this fix
    // replaced — DOES recover the truth. Without this, a clean result below could mean the probe is
    // blind rather than that the row is safe.
    let v1_row_chirho = serde_json::json!({
        "schema_chirho": LEGACY_UNSALTED_SEALED_STORE_VALUE_SCHEMA_CHIRHO,
        "subject_chirho": sealed_chirho.subject_chirho,
        "value_hash_chirho": cas_chirho::hash_chirho(F1_TRUTH_CHIRHO.as_bytes()).0,
        "bytes_chirho": F1_TRUTH_CHIRHO.len(),
        "blob_chirho": sealed_chirho.blob_chirho,
        "safe_metadata_chirho": {},
    });
    let row_public_values_chirho = f1_row_public_values_chirho(&sealed_chirho);
    assert_eq!(
        f1_recover_from_row_bytes_chirho(
            &serde_json::to_vec(&v1_row_chirho).unwrap(),
            &row_public_values_chirho,
        )
        .as_deref(),
        Some(F1_TRUTH_CHIRHO),
        "the attack probe must be able to succeed, or a clean v2 result proves nothing"
    );

    // The mirror holder's position: the row travels, the keys and the ciphertext do not.
    let row_bytes_chirho = encode_sealed_store_value_chirho(&sealed_chirho).unwrap();
    std::fs::remove_dir_all(keys_dir_chirho(&root_chirho)).unwrap();
    std::fs::remove_dir_all(root_chirho.join("objects-chirho")).unwrap();

    // LOCKOUT CONTROL: even the legitimate reader is now locked out, so the attack below really is
    // being run from the row alone.
    let locked_out_chirho = unseal_store_value_chirho(&root_chirho, &sealed_chirho).unwrap_err();
    assert!(
        !format!("{locked_out_chirho:#}").contains(F1_TRUTH_CHIRHO),
        "the lockout refusal leaked the sealed plaintext: {locked_out_chirho:#}"
    );

    // THE ATTACK.
    let recovered_chirho =
        f1_recover_from_row_bytes_chirho(&row_bytes_chirho, &row_public_values_chirho);
    assert_eq!(
        recovered_chirho, None,
        "the sealed row alone confirmed a candidate plaintext: F1 is back"
    );

    // LENGTH RESIDUAL, pinned rather than hidden: `bytes_chirho` is still the exact plaintext
    // length, so a mirror holder can still EXCLUDE every candidate of a different length. What v2
    // removes is CONFIRMATION, and this fixture shows the difference concretely — the length narrows
    // these four to two, and the two it cannot separate are the positive and the negative, which is
    // the whole question. Both halves are asserted, so neither is a comment anyone has to trust.
    assert_eq!(sealed_chirho.bytes_chirho, F1_TRUTH_CHIRHO.len());
    let same_length_chirho = F1_CANDIDATES_CHIRHO
        .iter()
        .filter(|candidate_chirho| candidate_chirho.len() == sealed_chirho.bytes_chirho)
        .count();
    assert!(
        same_length_chirho >= 2,
        "the length residual alone identifies the truth in this fixture, so the attack result \
         above is weaker than it reads — give the candidate set a same-length sibling"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// ---------------------------------------------------------------------------
// Non-envelope passthrough detection.
// ---------------------------------------------------------------------------

/// A v1 row must fail CLOSED rather than pass through as "never sealed". The reverse would hand a
/// caller the envelope JSON as if it were the plaintext value.
#[test]
fn a_legacy_v1_envelope_fails_closed_rather_than_passing_through_chirho() {
    let v1_row_chirho = serde_json::json!({
        "schema_chirho": LEGACY_UNSALTED_SEALED_STORE_VALUE_SCHEMA_CHIRHO,
        "subject_chirho": format!("app-store/contact/contacts-chirho/{}", "0".repeat(32)),
        "value_hash_chirho": cas_chirho::hash_chirho(NEEDLE_CHIRHO.as_bytes()).0,
        "bytes_chirho": NEEDLE_CHIRHO.len(),
        "blob_chirho": {
            "ciphertext_chirho": "a".repeat(64),
            "key_id_chirho": "b".repeat(32),
            "nonce_chirho": "c".repeat(48),
            "mac_chirho": "d".repeat(64),
            "alg_chirho": "xchacha20poly1305+blake3-keyed-mac/v1",
        },
        "safe_metadata_chirho": {},
    });
    let error_chirho =
        detect_sealed_store_value_chirho(&serde_json::to_vec(&v1_row_chirho).unwrap()).unwrap_err();
    assert!(
        format!("{error_chirho:#}")
            .contains("claims the sealed schema but is not a valid envelope"),
        "a v1 envelope must fail closed at detect, got: {error_chirho:#}"
    );
}

#[test]
fn values_that_were_never_sealed_detect_as_not_sealed_chirho() {
    for legacy_chirho in [
        NEEDLE_CHIRHO.as_bytes().to_vec(),
        b"\x00\x01\x02not json at all".to_vec(),
        Vec::new(),
        br#"{"order_chirho":"2 pizzas"}"#.to_vec(),
        contact_record_bytes_chirho("received", None),
        br#"["a","b"]"#.to_vec(),
        br#""just a json string""#.to_vec(),
        br#"{"schema_chirho":42}"#.to_vec(),
    ] {
        assert_eq!(
            detect_sealed_store_value_chirho(&legacy_chirho).unwrap(),
            StoreValueViewChirho::NotSealedChirho,
            "an unsealed legacy value must pass through as NotSealedChirho"
        );
    }
}

#[test]
fn a_value_claiming_the_sealed_schema_fails_closed_when_malformed_chirho() {
    let root_chirho = tmp_root_chirho();
    let sealed_chirho = seal_store_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho(),
        Some("contact"),
        "contacts-chirho/row-1",
        format!("contact {NEEDLE_CHIRHO}").as_bytes(),
    )
    .unwrap();
    let envelope_bytes_chirho = encode_sealed_store_value_chirho(&sealed_chirho).unwrap();
    // Positive control: the well-formed envelope detects as sealed.
    assert!(matches!(
        detect_sealed_store_value_chirho(&envelope_bytes_chirho).unwrap(),
        StoreValueViewChirho::SealedChirho(_)
    ));

    // A bare schema tag with no envelope body.
    let error_chirho = detect_sealed_store_value_chirho(
        format!(r#"{{"schema_chirho":"{SEALED_STORE_VALUE_SCHEMA_CHIRHO}"}}"#).as_bytes(),
    )
    .unwrap_err();
    assert!(
        format!("{error_chirho:#}")
            .contains("claims the sealed schema but is not a valid envelope"),
        "expected the fail-closed detect refusal, got: {error_chirho:#}"
    );

    // Plaintext smuggled beside a valid seal must not read as a well-formed envelope, or a
    // coverage scan would call the row sealed while the plaintext rests next to it.
    let mut smuggled_chirho: serde_json::Value =
        serde_json::from_slice(&envelope_bytes_chirho).unwrap();
    smuggled_chirho
        .as_object_mut()
        .unwrap()
        .insert("leak_chirho".to_string(), serde_json::json!(NEEDLE_CHIRHO));
    let error_chirho =
        detect_sealed_store_value_chirho(&serde_json::to_vec(&smuggled_chirho).unwrap())
            .unwrap_err();
    assert!(
        format!("{error_chirho:#}")
            .contains("claims the sealed schema but is not a valid envelope"),
        "expected the extra-field refusal, got: {error_chirho:#}"
    );
    assert_error_is_plaintext_free_chirho(&error_chirho, "smuggled plaintext field");
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_wrong_schema_envelope_is_refused_on_unseal_chirho() {
    let root_chirho = tmp_root_chirho();
    let sealed_chirho = seal_store_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho(),
        Some("contact"),
        "contacts-chirho/row-1",
        format!("contact {NEEDLE_CHIRHO}").as_bytes(),
    )
    .unwrap();
    unseal_store_value_chirho(&root_chirho, &sealed_chirho).unwrap();

    let mut tampered_chirho = sealed_chirho.clone();
    tampered_chirho.schema_chirho = "contact-record-v1-chirho".to_string();
    let error_chirho = unseal_store_value_chirho(&root_chirho, &tampered_chirho).unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("sealed store value schema is not"),
        "expected the schema refusal, got: {error_chirho:#}"
    );
    assert_error_is_plaintext_free_chirho(&error_chirho, "wrong schema envelope");

    // Safe metadata that would smuggle free text into a listing is refused on the read path too.
    let mut smuggled_chirho = sealed_chirho.clone();
    smuggled_chirho
        .safe_metadata_chirho
        .insert("status_chirho".to_string(), NEEDLE_CHIRHO.to_string());
    let error_chirho = unseal_store_value_chirho(&root_chirho, &smuggled_chirho).unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("status_chirho must be a lowercase slug"),
        "expected the read-path metadata bound, got: {error_chirho:#}"
    );
    assert_error_is_plaintext_free_chirho(&error_chirho, "read-path metadata smuggling");
    let _ = std::fs::remove_dir_all(&root_chirho);
}
