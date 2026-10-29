// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The F4 write door: no production write rests a plaintext value, and a replay mints nothing.

use super::*;
use crate::model_chirho::RequestContextChirho;
use crate::store_seal_chirho;
use std::sync::atomic::{AtomicU64, Ordering};

/// A needle no fixture value carries by accident, so a hit in a file is a real leak.
const PLANTED_NEEDLE_CHIRHO: &str = "Zebediah Planted-Needle chirho";

/// A second needle, written to the public object plane ON PURPOSE through the real CAS writer, so
/// the object-plane sweep can be shown to FIND what is there before it is trusted to report clean.
const CONTROL_NEEDLE_CHIRHO: &str = "Obadiah Control-Needle chirho";

fn door_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-seal-door-{label_chirho}-{nanos_chirho}-{n_chirho}"
    ))
}

/// Reads the real `.redb` FILE and answers whether the needle is anywhere in its bytes.
///
/// This is the strongest instrument available for the sealing claim because it is independent of
/// every type and reader in this repo: it does not ask the store what it holds, it reads the file.
fn redb_file_contains_chirho(root_chirho: &Path, needle_chirho: &str) -> bool {
    let bytes_chirho = std::fs::read(versioned_path_chirho(root_chirho)).unwrap();
    bytes_chirho
        .windows(needle_chirho.len())
        .any(|window_chirho| window_chirho == needle_chirho.as_bytes())
}

/// Every REGULAR FILE on the public object plane, walked RECURSIVELY.
///
/// The CAS shards by hash prefix: `cas_chirho::object_path_chirho` writes
/// `objects-chirho/<ab>/<rest>`, and the publisher's temp files live inside the shard too. So a
/// flat `read_dir` over `objects-chirho` yields only shard DIRECTORIES — an `is_file()` filter at
/// that level skips every entry, and anything asserted inside such a loop never runs at all. The
/// call sites below pair this with a planted control for exactly that reason.
fn public_object_files_chirho(root_chirho: &Path) -> Vec<PathBuf> {
    fn walk_chirho(dir_chirho: &Path, files_chirho: &mut Vec<PathBuf>) {
        let Ok(entries_chirho) = std::fs::read_dir(dir_chirho) else {
            return;
        };
        for entry_chirho in entries_chirho {
            let path_chirho = entry_chirho.unwrap().path();
            if path_chirho.is_dir() {
                walk_chirho(&path_chirho, files_chirho);
            } else if path_chirho.is_file() {
                files_chirho.push(path_chirho);
            }
        }
    }
    let mut files_chirho = Vec::new();
    walk_chirho(&root_chirho.join("objects-chirho"), &mut files_chirho);
    files_chirho.sort();
    files_chirho
}

fn file_contains_needle_chirho(path_chirho: &Path, needle_chirho: &str) -> bool {
    std::fs::read(path_chirho)
        .unwrap()
        .windows(needle_chirho.len())
        .any(|window_chirho| window_chirho == needle_chirho.as_bytes())
}

fn privacy_blob_row_count_chirho(root_chirho: &Path) -> usize {
    crate::privacy_chirho::load_privacy_blob_records_chirho(root_chirho)
        .unwrap()
        .len()
}

fn privacy_key_file_count_chirho(root_chirho: &Path) -> usize {
    let keys_dir_chirho = root_chirho.join("privacy-keys-chirho");
    if !keys_dir_chirho.exists() {
        return 0;
    }
    std::fs::read_dir(&keys_dir_chirho).unwrap().count()
}

fn request_context_chirho(app_chirho: &str) -> RequestContextChirho {
    RequestContextChirho {
        user_principal_chirho: "user/seal-door".to_string(),
        app_chirho: app_chirho.to_string(),
        owner_principal_chirho: "owner/seal-door".to_string(),
        client_id_chirho: "client-seal-door".to_string(),
        token_hash_chirho: "token-hash-seal-door".to_string(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    }
}

/// The oracle this brick exists for: a value an app author never sealed still cannot rest in the
/// clear, and the byte-level check reads the actual `.redb` file rather than our own types.
#[test]
fn a_plain_value_through_the_write_door_never_rests_in_the_redb_file_chirho() {
    let root_chirho = door_root_chirho("plain-value");
    let value_chirho = format!("{{\"note_chirho\":\"{PLANTED_NEEDLE_CHIRHO}\"}}");

    // Positive control: the same needle IS findable in a file we deliberately write plainly, so a
    // clean scan below means the seal worked rather than that the instrument is blind.
    std::fs::create_dir_all(&root_chirho).unwrap();
    let control_path_chirho = root_chirho.join("planted-control-chirho.txt");
    std::fs::write(&control_path_chirho, value_chirho.as_bytes()).unwrap();
    let control_bytes_chirho = std::fs::read(&control_path_chirho).unwrap();
    assert!(control_bytes_chirho
        .windows(PLANTED_NEEDLE_CHIRHO.len())
        .any(|window_chirho| window_chirho == PLANTED_NEEDLE_CHIRHO.as_bytes()));

    run_effect_chirho(
        &root_chirho,
        0,
        HashChirho("seal-door-plain".to_string()),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "plain-chirho/row".to_string(),
        },
        value_chirho.as_bytes(),
    )
    .unwrap();

    assert!(
        !redb_file_contains_chirho(&root_chirho, PLANTED_NEEDLE_CHIRHO),
        "the versioned store FILE rests a plaintext value the app author never sealed"
    );

    // The row is an envelope, and the envelope still carries the exact plaintext identity.
    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(&root_chirho))
            .unwrap();
    let row_chirho = store_chirho
        .get_chirho("plain-chirho/row")
        .unwrap()
        .unwrap();
    let store_seal_chirho::StoreValueViewChirho::SealedChirho(sealed_chirho) =
        store_seal_chirho::detect_sealed_store_value_chirho(&row_chirho).unwrap()
    else {
        panic!("the write door left an unsealed row");
    };
    // The plaintext identity is KEYED (F1): it authenticates the plaintext to a holder of this
    // row's own shred key, and is not the content address anyone could recompute from a guess.
    assert_eq!(
        sealed_chirho.keyed_plaintext_digest_chirho,
        crate::privacy_chirho::private_blob_keyed_plaintext_digest_chirho(
            &root_chirho,
            &sealed_chirho.blob_chirho,
            value_chirho.as_bytes(),
        )
        .unwrap()
    );
    assert_ne!(
        sealed_chirho.keyed_plaintext_digest_chirho,
        cas_chirho::hash_chirho(value_chirho.as_bytes()).0
    );
    assert_eq!(sealed_chirho.bytes_chirho, value_chirho.len());
    // A value outside the reviewed safe-envelope set seals FULLY OPAQUE — no label may escape.
    assert!(sealed_chirho.safe_metadata_chirho.is_empty());
    assert_eq!(
        store_seal_chirho::unseal_store_value_chirho(&root_chirho, &sealed_chirho).unwrap(),
        value_chirho.as_bytes()
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The DAG response contract on the shape every shipped app uses (a scoped write request): the
/// effect still returns the plaintext it wrote under the SAME hash it always had, while that
/// hash's at-rest copy leaves public CAS for a private DAG value.
#[test]
fn a_sealed_write_keeps_its_response_identity_and_leaves_public_cas_chirho() {
    let root_chirho = door_root_chirho("response-identity");
    let value_chirho = format!("order for {PLANTED_NEEDLE_CHIRHO}");
    let request_chirho = ScopedWriteStoreRequestChirho {
        schema_chirho: SCOPED_WRITE_STORE_SCHEMA_CHIRHO.to_string(),
        key_chirho: "orders-chirho/one".to_string(),
        value_base64_chirho: BASE64_CHIRHO.encode(value_chirho.as_bytes()),
    };

    let effect_chirho = run_effect_chirho(
        &root_chirho,
        0,
        HashChirho("seal-door-response".to_string()),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "orders-chirho".to_string(),
        },
        &serde_json::to_vec(&request_chirho).unwrap(),
    )
    .unwrap();

    // Identity preserved: the response hash is still blake3 of the written plaintext, so cache,
    // provenance and every downstream node coordinate are byte-identical to the unsealed world.
    let response_hash_chirho = effect_chirho.response_chirho.clone().unwrap();
    assert_eq!(
        response_hash_chirho,
        cas_chirho::hash_chirho(value_chirho.as_bytes())
    );

    // Address check: the response plaintext is not retrievable from public CAS…
    assert!(cas_chirho::get_chirho(&root_chirho, &response_hash_chirho).is_err());
    // …and it IS a recorded private DAG value under the row's own seal subject.
    let seal_subject_chirho =
        store_seal_chirho::store_seal_subject_chirho(None, "orders-chirho/one").unwrap();
    assert!(seal_subject_chirho
        .starts_with(store_seal_chirho::OPERATOR_STORE_SEAL_SUBJECT_PREFIX_CHIRHO));
    assert_eq!(
        dag_private_value_chirho::load_private_dag_value_bytes_chirho(
            &root_chirho,
            &seal_subject_chirho,
            &response_hash_chirho,
        )
        .unwrap(),
        value_chirho.as_bytes()
    );

    // Needle check over the whole public object plane, not just the one address we predicted.
    // NOT closed by this brick, and deliberately visible here: the REQUEST object still carries
    // the value base64-encoded (§2.6 residual 1 — it was persisted upstream of the write arm,
    // which cannot retroactively seal it). The RAW needle must appear nowhere.
    let request_bytes_chirho =
        cas_chirho::get_chirho(&root_chirho, &effect_chirho.request_chirho).unwrap();
    assert!(String::from_utf8_lossy(&request_bytes_chirho)
        .contains(&BASE64_CHIRHO.encode(value_chirho.as_bytes())));
    // POSITIVE CONTROL FIRST, written through the real CAS writer into this same root: the sweep
    // has to FIND a needle that IS on the public object plane. Without it, "clean" and "read
    // nothing at all" are the same result — and reading nothing is exactly what this sweep used to
    // do, because the CAS shards objects and every entry directly under `objects-chirho` is a
    // DIRECTORY.
    let control_addr_chirho =
        cas_chirho::add_chirho(&root_chirho, CONTROL_NEEDLE_CHIRHO.as_bytes()).unwrap();
    assert!(
        root_chirho
            .join("objects-chirho")
            .join(&control_addr_chirho.0[..2])
            .join(&control_addr_chirho.0[2..])
            .is_file(),
        "the CAS no longer writes objects-chirho/<ab>/<rest>; retarget this sweep at the new layout"
    );
    let object_files_chirho = public_object_files_chirho(&root_chirho);
    assert!(
        object_files_chirho
            .iter()
            .any(|path_chirho| file_contains_needle_chirho(path_chirho, CONTROL_NEEDLE_CHIRHO)),
        "the public object-plane sweep is BLIND: it missed a needle written through the real \
         cas_chirho::add_chirho, so a clean result below would prove nothing. Files read: {:?}",
        object_files_chirho
    );

    for path_chirho in &object_files_chirho {
        assert!(
            !file_contains_needle_chirho(path_chirho, PLANTED_NEEDLE_CHIRHO),
            "public object {} leaked the planted needle",
            path_chirho.display()
        );
    }

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The legacy-reify shape sends the value as its own request bytes, so request and response share
/// ONE address and the plaintext survives in public CAS as the REQUEST copy. The seal still does
/// its job — the versioned store rests only the envelope — but the response's "left public CAS"
/// claim does not hold for this shape, and pinning that keeps the residual from being read as
/// closed.
#[test]
fn legacy_reify_leaves_its_request_copy_public_while_the_store_row_is_sealed_chirho() {
    let root_chirho = door_root_chirho("legacy-reify-residual");
    let value_chirho = format!("legacy body for {PLANTED_NEEDLE_CHIRHO}");

    let effect_chirho = run_effect_chirho(
        &root_chirho,
        0,
        HashChirho("seal-door-legacy-reify".to_string()),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "legacy-chirho/row".to_string(),
        },
        value_chirho.as_bytes(),
    )
    .unwrap();

    let response_hash_chirho = effect_chirho.response_chirho.clone().unwrap();
    assert_eq!(response_hash_chirho, effect_chirho.request_chirho);
    // Public CAS still answers at that address — through the REQUEST copy, not the response path.
    assert_eq!(
        cas_chirho::get_chirho(&root_chirho, &response_hash_chirho).unwrap(),
        value_chirho.as_bytes()
    );
    // The response nonetheless went through the private policy…
    assert!(dag_private_value_chirho::private_dag_value_recorded_chirho(
        &root_chirho,
        &response_hash_chirho
    )
    .unwrap());
    // …and the thing this brick actually owns holds: the store FILE rests no plaintext.
    assert!(!redb_file_contains_chirho(
        &root_chirho,
        PLANTED_NEEDLE_CHIRHO
    ));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Idempotent replay: the same key returns the same effect and mints NO second privacy artifact.
/// The counters are proven to MOVE on a genuine first write, so the unchanged counts after replay
/// are a real fixed point rather than a vacuous comparison of two zeroes.
#[test]
fn replaying_a_write_mints_no_second_key_blob_or_privacy_log_row_chirho() {
    let root_chirho = door_root_chirho("replay-mints-nothing");
    let idem_key_chirho = HashChirho("seal-door-replay".to_string());
    let capability_chirho = CapabilityChirho::WriteStoreChirho {
        prefix_chirho: "replay-chirho/row".to_string(),
    };

    assert_eq!(privacy_blob_row_count_chirho(&root_chirho), 0);
    assert_eq!(privacy_key_file_count_chirho(&root_chirho), 0);

    let first_chirho = run_effect_chirho(
        &root_chirho,
        0,
        idem_key_chirho.clone(),
        capability_chirho.clone(),
        b"replayed value",
    )
    .unwrap();

    // Non-vacuity: a genuine first write DOES move both counters. Two artifacts land — the store
    // row's seal and the effect response's private DAG value.
    let blobs_after_first_chirho = privacy_blob_row_count_chirho(&root_chirho);
    let keys_after_first_chirho = privacy_key_file_count_chirho(&root_chirho);
    assert_eq!(blobs_after_first_chirho, 2);
    assert_eq!(keys_after_first_chirho, 2);

    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(&root_chirho))
            .unwrap();
    let view_after_first_chirho = store_chirho.current_view_chirho().unwrap();
    let row_after_first_chirho = store_chirho
        .get_chirho("replay-chirho/row")
        .unwrap()
        .unwrap();
    drop(store_chirho);

    let replayed_chirho = run_effect_chirho(
        &root_chirho,
        1,
        idem_key_chirho,
        capability_chirho,
        b"replayed value",
    )
    .unwrap();

    // The replay returns the ORIGINAL effect verbatim — no new seq, no re-signature, no drift of
    // the kind a double-charge would show on a paid door.
    assert_eq!(replayed_chirho, first_chirho);
    assert_eq!(privacy_blob_row_count_chirho(&root_chirho), 2);
    assert_eq!(privacy_key_file_count_chirho(&root_chirho), 2);

    // And no second put: same store version, byte-identical envelope (a fresh seal would carry a
    // fresh key id and nonce, so equality here is a strong statement).
    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(&root_chirho))
            .unwrap();
    assert_eq!(
        store_chirho.current_view_chirho().unwrap(),
        view_after_first_chirho
    );
    assert_eq!(
        store_chirho
            .get_chirho("replay-chirho/row")
            .unwrap()
            .unwrap(),
        row_after_first_chirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Z13 ordering, at the boundary where it is observable: the store write precedes the effect
/// record, so a write door that refuses leaves NO effect record and NO privacy artifact behind.
#[test]
fn a_refused_write_leaves_no_effect_record_and_no_privacy_artifact_chirho() {
    let root_chirho = door_root_chirho("refused-write");

    run_effect_chirho(
        &root_chirho,
        0,
        HashChirho("seal-door-ordering-ok".to_string()),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "scoped-chirho".to_string(),
        },
        &serde_json::to_vec(&ScopedWriteStoreRequestChirho {
            schema_chirho: SCOPED_WRITE_STORE_SCHEMA_CHIRHO.to_string(),
            key_chirho: "scoped-chirho/in-scope".to_string(),
            value_base64_chirho: BASE64_CHIRHO.encode(b"in scope"),
        })
        .unwrap(),
    )
    .unwrap();
    let blobs_before_chirho = privacy_blob_row_count_chirho(&root_chirho);
    let keys_before_chirho = privacy_key_file_count_chirho(&root_chirho);
    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(&root_chirho))
            .unwrap();
    let view_before_chirho = store_chirho.current_view_chirho().unwrap();
    drop(store_chirho);

    let refused_idem_chirho = HashChirho("seal-door-ordering-refused".to_string());
    let refusal_chirho = run_effect_chirho(
        &root_chirho,
        1,
        refused_idem_chirho.clone(),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "scoped-chirho".to_string(),
        },
        &serde_json::to_vec(&ScopedWriteStoreRequestChirho {
            schema_chirho: SCOPED_WRITE_STORE_SCHEMA_CHIRHO.to_string(),
            key_chirho: "elsewhere-chirho/out-of-scope".to_string(),
            value_base64_chirho: BASE64_CHIRHO.encode(PLANTED_NEEDLE_CHIRHO.as_bytes()),
        })
        .unwrap(),
    )
    .unwrap_err();
    assert!(
        refusal_chirho
            .to_string()
            .contains("is outside capability prefix"),
        "unexpected refusal: {refusal_chirho}"
    );

    assert!(load_effect_chirho(&root_chirho, &refused_idem_chirho)
        .unwrap()
        .is_none());
    assert_eq!(
        privacy_blob_row_count_chirho(&root_chirho),
        blobs_before_chirho
    );
    assert_eq!(
        privacy_key_file_count_chirho(&root_chirho),
        keys_before_chirho
    );
    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(&root_chirho))
            .unwrap();
    assert_eq!(
        store_chirho.current_view_chirho().unwrap(),
        view_before_chirho
    );
    drop(store_chirho);
    assert!(!redb_file_contains_chirho(
        &root_chirho,
        PLANTED_NEEDLE_CHIRHO
    ));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// An ADMISSION change this brick introduces, pinned so it is reviewable rather than incidental:
/// a value that claims one of cairn's own reviewed safe-envelope schemas but is malformed for that
/// schema is now refused AT THE WRITE DOOR, because S1's bounded metadata extraction fails closed
/// rather than downgrading to opaque.
///
/// Scope, measured: this bites only values that IMPERSONATE a reviewed cairn schema. App-authored
/// schemas are outside the reviewed set, seal fully opaque, and are unaffected — as are the real
/// contact and perffection records, whose blob refs are well formed.
///
/// MIGRATION PATH: if a future ruling prefers §2.5's "any other value gets an empty metadata map"
/// to cover this case too, this arm flips from a refusal to an opaque seal — retarget it to assert
/// an empty `safe_metadata_chirho` and keep the no-residue assertions below unchanged, because
/// they hold either way.
#[test]
fn a_value_falsely_claiming_a_reviewed_schema_is_refused_at_the_write_door_chirho() {
    let root_chirho = door_root_chirho("false-schema-claim");

    // Positive control: the same shape with an app-authored schema writes fine and seals opaque.
    run_effect_chirho(
        &root_chirho,
        0,
        HashChirho("seal-door-app-schema".to_string()),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "notes-chirho/ok".to_string(),
        },
        br#"{"schema_chirho":"app-note-v1-chirho","blob_chirho":"not-a-ref"}"#,
    )
    .unwrap();
    let blobs_before_chirho = privacy_blob_row_count_chirho(&root_chirho);
    let keys_before_chirho = privacy_key_file_count_chirho(&root_chirho);

    let refused_idem_chirho = HashChirho("seal-door-false-claim".to_string());
    let refusal_chirho = run_effect_chirho(
        &root_chirho,
        1,
        refused_idem_chirho.clone(),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "notes-chirho/bad".to_string(),
        },
        br#"{"schema_chirho":"contact-record-v1-chirho","blob_chirho":"not-a-ref"}"#,
    )
    .unwrap_err();
    assert!(
        format!("{refusal_chirho:#}").contains("blob_chirho is not a private blob ref"),
        "expected the S1 metadata refusal identity, got: {refusal_chirho:#}"
    );

    // Fail-closed with no residue: no row, no effect record, no shred key, no privacy-log row.
    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(&root_chirho))
            .unwrap();
    assert!(store_chirho
        .get_chirho("notes-chirho/bad")
        .unwrap()
        .is_none());
    drop(store_chirho);
    assert!(load_effect_chirho(&root_chirho, &refused_idem_chirho)
        .unwrap()
        .is_none());
    assert_eq!(
        privacy_blob_row_count_chirho(&root_chirho),
        blobs_before_chirho
    );
    assert_eq!(
        privacy_key_file_count_chirho(&root_chirho),
        keys_before_chirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// An app-context write seals under the `app-store/` namespace, an operator write under
/// `operator-store/`, and the two namespaces never collide for the same key.
#[test]
fn seal_subjects_separate_app_writes_from_operator_writes_chirho() {
    let root_chirho = door_root_chirho("subject-namespaces");
    let context_chirho = request_context_chirho("contact");

    run_effect_with_context_chirho(
        &root_chirho,
        0,
        HashChirho("seal-door-app-context".to_string()),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "contacts-chirho/row".to_string(),
        },
        b"app value",
        Some(&context_chirho),
    )
    .unwrap();

    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(&root_chirho))
            .unwrap();
    let row_chirho = store_chirho
        .get_chirho("contacts-chirho/row")
        .unwrap()
        .unwrap();
    drop(store_chirho);
    let store_seal_chirho::StoreValueViewChirho::SealedChirho(sealed_chirho) =
        store_seal_chirho::detect_sealed_store_value_chirho(&row_chirho).unwrap()
    else {
        panic!("the app write door left an unsealed row");
    };
    assert_eq!(
        sealed_chirho.subject_chirho,
        store_seal_chirho::store_seal_subject_chirho(Some("contact"), "contacts-chirho/row")
            .unwrap()
    );
    assert!(sealed_chirho
        .subject_chirho
        .starts_with("app-store/contact/contacts-chirho/"));
    assert_ne!(
        sealed_chirho.subject_chirho,
        store_seal_chirho::store_seal_subject_chirho(None, "contacts-chirho/row").unwrap()
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}
