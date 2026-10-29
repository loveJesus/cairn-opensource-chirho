// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;

pub(super) fn assert_runtime_tree_excludes_bytes_chirho(
    root_chirho: &std::path::Path,
    needle_chirho: &[u8],
) {
    assert_path_tree_excludes_bytes_chirho(root_chirho, "runtime root", needle_chirho);
}

pub(super) fn assert_path_tree_excludes_bytes_chirho(
    path_chirho: &std::path::Path,
    surface_chirho: &str,
    needle_chirho: &[u8],
) {
    if !path_chirho.exists() {
        return;
    }
    if path_chirho.is_file() {
        let bytes_chirho = std::fs::read(path_chirho).unwrap();
        assert!(
            !bytes_chirho
                .windows(needle_chirho.len())
                .any(|window_chirho| window_chirho == needle_chirho),
            "{surface_chirho} leaked realtime payload bytes"
        );
        return;
    }
    for entry_chirho in std::fs::read_dir(path_chirho).unwrap() {
        let path_chirho = entry_chirho.unwrap().path();
        let surface_chirho = path_chirho.display().to_string();
        assert_path_tree_excludes_bytes_chirho(&path_chirho, &surface_chirho, needle_chirho);
    }
}

/// The privacy-blob records that are NOT F4 store-seal artifacts — the person / app-input blobs a
/// test means when it says "exactly one private blob was persisted".
///
/// The F4 write door seals every store row, so a raw total now also counts the row's seal and the
/// effect response's private DAG value. Filtering by the store-seal subject namespaces keeps these
/// assertions measuring what they were written to measure.
pub(super) fn non_store_seal_blob_subjects_chirho(root_chirho: &std::path::Path) -> Vec<String> {
    cairn_chirho::privacy_chirho::load_privacy_blob_records_chirho(root_chirho)
        .unwrap()
        .into_iter()
        .map(|record_chirho| record_chirho.subject_chirho)
        .filter(|subject_chirho| {
            !subject_chirho
                .starts_with(cairn_chirho::store_seal_chirho::APP_STORE_SEAL_SUBJECT_PREFIX_CHIRHO)
                && !subject_chirho.starts_with(
                    cairn_chirho::store_seal_chirho::OPERATOR_STORE_SEAL_SUBJECT_PREFIX_CHIRHO,
                )
        })
        .collect()
}

/// The plaintext a sealed write landed under `key_chirho`, unsealing the F4 envelope the write
/// door rests. A row that was never sealed passes straight through.
pub(super) fn sealed_row_plaintext_chirho(
    root_chirho: &std::path::Path,
    key_chirho: &str,
) -> Option<Vec<u8>> {
    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    let row_chirho = store_chirho.get_chirho(key_chirho).unwrap()?;
    match cairn_chirho::store_seal_chirho::detect_sealed_store_value_chirho(&row_chirho).unwrap() {
        cairn_chirho::store_seal_chirho::StoreValueViewChirho::SealedChirho(sealed_chirho) => Some(
            cairn_chirho::store_seal_chirho::unseal_store_value_chirho(root_chirho, &sealed_chirho)
                .unwrap(),
        ),
        cairn_chirho::store_seal_chirho::StoreValueViewChirho::NotSealedChirho => Some(row_chirho),
    }
}

/// The store files this repo scans at the raw bytes, and the label each gets in a refusal.
pub(super) const RAW_SCANNED_STORE_FILES_CHIRHO: [(&str, &str); 2] = [
    ("versioned-chirho.redb", "versioned store FILE"),
    ("readmodel-chirho.sqlite", "readmodel FILE"),
];

/// Does this file's raw bytes contain `needle_chirho` as a CONTIGUOUS window?
///
/// **Known limitation, and it bounds every claim built on this scanner:** the match is contiguous.
/// A value large enough for the store to split across pages — or to compress, or to encode — could
/// be present and not found, and the scan would report clean. Today's fixtures are small single-page
/// values, so the arms that use this are sound; a future arm that plants a large value must not
/// treat a clean result here as proof of absence.
pub(super) fn store_file_contains_needle_chirho(
    path_chirho: &std::path::Path,
    needle_chirho: &str,
) -> bool {
    let Ok(bytes_chirho) = std::fs::read(path_chirho) else {
        return false;
    };
    bytes_chirho
        .windows(needle_chirho.len())
        .any(|window_chirho| window_chirho == needle_chirho.as_bytes())
}

/// The real `.redb` FILE must never hold a PII needle in its bytes.
///
/// This is the strongest instrument for the F4 sealing claim because it is independent of every
/// type and reader in this repo: it does not ask the store what it holds, it reads the file. The
/// disposable readmodel is scanned the same way, for the same reason.
///
/// That an instrument reads a file is not yet evidence that it can SEE INSIDE one. The standing
/// positive control for that is
/// `the_redb_file_scanner_is_sighted_inside_a_real_redb_file_chirho`, which plants a needle in a
/// real `.redb` through the store's own writer and asserts this function finds it.
pub(super) fn assert_store_files_have_no_contact_pii_chirho(
    root_chirho: &std::path::Path,
    needles_chirho: &[&str],
) {
    for (file_chirho, surface_chirho) in RAW_SCANNED_STORE_FILES_CHIRHO {
        let path_chirho = root_chirho.join(file_chirho);
        if !path_chirho.exists() {
            continue;
        }
        for needle_chirho in needles_chirho {
            assert!(
                !store_file_contains_needle_chirho(&path_chirho, needle_chirho),
                "{surface_chirho} leaked contact PII needle '{needle_chirho}' at the raw bytes"
            );
        }
    }
}

/// **F4 (S2 adversarial review) — the standing positive control for the `.redb` byte scanner.**
///
/// Every sealing claim in this suite rests on "the needle is not in the `.redb` file". The controls
/// that shipped with those claims plant the needle in a `.txt` — which proves the WINDOW MATCH
/// works, and says nothing about whether a needle written into a real redb file is findable at all.
/// A scanner blind inside `.redb` would report every seal clean, including a seal that never
/// happened. So this plants a needle in a real `.redb`, through the store's own writer, and asserts
/// the scanner finds it.
///
/// LIMITATION, deliberately visible rather than discovered later: the match is CONTIGUOUS. This
/// control uses a small single-page value; a value large enough to be split across redb pages could
/// evade the same scan. Any future arm that plants a large value must not read a clean result here
/// as proof of absence.
///
/// MIGRATION PATH — if this goes red:
///   * the PLANTED assertion means the scanner can no longer see inside a `.redb`, and every clean
///     `.redb` result elsewhere in this suite is unproven until it is fixed. That is a bigger
///     finding than whatever else is failing.
///   * the ABSENT assertion means the scanner reports hits for needles that are not there, which
///     would make those same clean results meaningless in the other direction.
#[test]
fn the_redb_file_scanner_is_sighted_inside_a_real_redb_file_chirho() {
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-redb-sight-control-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    let planted_chirho = "Zerubbabel Sighted-Needle chirho";
    let never_written_chirho = "Habakkuk Absent-Needle chirho";

    // Plant it the only way that proves anything: through the store's own writer, into the real
    // file, WITHOUT the seal door — this is exactly the shape an unsealed write would leave.
    let path_chirho = root_chirho.join("versioned-chirho.redb");
    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(&path_chirho).unwrap();
    store_chirho
        .put_chirho(
            "redb-sight-control-chirho/row",
            format!(r#"{{"customer_chirho":"{planted_chirho}"}}"#).as_bytes(),
        )
        .unwrap();
    drop(store_chirho);

    assert!(
        store_file_contains_needle_chirho(&path_chirho, planted_chirho),
        "the .redb byte scanner is BLIND inside a real redb file: a needle written through the \
         store's own writer was not found, so every clean .redb result in this suite is unproven"
    );
    assert!(
        !store_file_contains_needle_chirho(&path_chirho, never_written_chirho),
        "the .redb byte scanner reports a needle that was never written"
    );

    // The assertion helper is a thin wrapper over the primitive proven above, so the one way it
    // could still pass over a planted needle is by never reaching the file: it SKIPS a store file
    // that does not exist. Pin the selection, so a renamed store file surfaces here as a red arm
    // rather than as a suite that quietly stops scanning anything.
    assert!(
        RAW_SCANNED_STORE_FILES_CHIRHO
            .iter()
            .any(|(file_chirho, _surface_chirho)| *file_chirho == "versioned-chirho.redb"),
        "the raw store-file scan no longer covers the versioned .redb file"
    );
    assert!(
        path_chirho.exists(),
        "the file the helper would scan is not the file this control planted into"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

pub(super) fn assert_contact_persisted_surfaces_no_pii_chirho(
    root_chirho: &std::path::Path,
    versioned_views_chirho: &[u64],
    needles_chirho: &[&str],
) {
    assert_path_tree_has_no_contact_pii_chirho(
        &root_chirho.join("objects-chirho"),
        "objects-chirho",
        needles_chirho,
    );
    assert_effect_records_no_contact_pii_chirho(root_chirho, needles_chirho);
    assert_volatile_effect_records_no_contact_pii_chirho(root_chirho, needles_chirho);
    assert_optional_file_no_contact_pii_chirho(
        &root_chirho.join("privacy-blob-records-chirho.jsonl"),
        "privacy blob records",
        needles_chirho,
    );
    assert_optional_file_no_contact_pii_chirho(
        &root_chirho.join("privacy-access-records-chirho.jsonl"),
        "privacy access records",
        needles_chirho,
    );
    assert_store_files_have_no_contact_pii_chirho(root_chirho, needles_chirho);

    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    for view_chirho in versioned_views_chirho {
        for (key_chirho, value_chirho) in store_chirho
            .current_entries_at_chirho(*view_chirho)
            .unwrap()
            .into_iter()
            .filter(|(key_chirho, _value_chirho)| contact_store_key_chirho(key_chirho))
        {
            assert_no_contact_pii_chirho(
                &format!("versioned key at v{view_chirho}"),
                key_chirho.as_bytes(),
                needles_chirho,
            );
            assert_no_contact_pii_chirho(
                &format!("versioned value at v{view_chirho}:{key_chirho}"),
                &value_chirho,
                needles_chirho,
            );
        }
    }
    for (key_chirho, value_chirho) in store_chirho.current_entries_chirho().unwrap() {
        assert_no_contact_pii_chirho(
            &format!("current versioned key:{key_chirho}"),
            key_chirho.as_bytes(),
            needles_chirho,
        );
        assert_no_contact_pii_chirho(
            &format!("current versioned value:{key_chirho}"),
            &value_chirho,
            needles_chirho,
        );
    }
    drop(store_chirho);

    for row_chirho in
        cairn_chirho::query_chirho::query_prefix_chirho(root_chirho, "contacts-chirho", 50).unwrap()
    {
        assert_no_contact_pii_chirho(
            &format!("read model key:{}", row_chirho.key_chirho),
            row_chirho.key_chirho.as_bytes(),
            needles_chirho,
        );
        assert_no_contact_pii_chirho(
            &format!("read model value:{}", row_chirho.key_chirho),
            row_chirho.value_chirho.as_bytes(),
            needles_chirho,
        );
    }
}

pub(super) fn assert_effect_records_no_contact_pii_chirho(
    root_chirho: &std::path::Path,
    needles_chirho: &[&str],
) {
    let effects_dir_chirho = root_chirho.join("effects-chirho");
    if !effects_dir_chirho.exists() {
        return;
    }
    for entry_chirho in std::fs::read_dir(&effects_dir_chirho).unwrap() {
        let path_chirho = entry_chirho.unwrap().path();
        let bytes_chirho = std::fs::read(&path_chirho).unwrap();
        let surface_chirho = path_chirho.display().to_string();
        assert_no_contact_pii_chirho(&surface_chirho, &bytes_chirho, needles_chirho);
        let effect_chirho: cairn_chirho::model_chirho::EffectChirho =
            serde_json::from_slice(&bytes_chirho).unwrap();
        cairn_chirho::effect_chirho::verify_effect_chirho(root_chirho, &effect_chirho).unwrap();
        assert_effect_cas_objects_no_contact_pii_chirho(
            root_chirho,
            &effect_chirho,
            &surface_chirho,
            needles_chirho,
        );
    }
}

pub(super) fn assert_volatile_effect_records_no_contact_pii_chirho(
    root_chirho: &std::path::Path,
    needles_chirho: &[&str],
) {
    let records_chirho =
        cairn_chirho::effect_chirho::load_volatile_effect_records_chirho(root_chirho).unwrap();
    for record_chirho in records_chirho {
        let record_bytes_chirho = serde_json::to_vec(&record_chirho).unwrap();
        let surface_chirho = format!("volatile effect record {}", record_chirho.seq_chirho);
        assert_no_contact_pii_chirho(&surface_chirho, &record_bytes_chirho, needles_chirho);
        assert_effect_cas_objects_no_contact_pii_chirho(
            root_chirho,
            &record_chirho.effect_chirho,
            &surface_chirho,
            needles_chirho,
        );
    }
}

pub(super) fn assert_effect_cas_objects_no_contact_pii_chirho(
    root_chirho: &std::path::Path,
    effect_chirho: &cairn_chirho::model_chirho::EffectChirho,
    surface_chirho: &str,
    needles_chirho: &[&str],
) {
    let request_chirho =
        cairn_chirho::cas_chirho::get_chirho(root_chirho, &effect_chirho.request_chirho).unwrap();
    assert_no_contact_pii_chirho(
        &format!("{surface_chirho} request object"),
        &request_chirho,
        needles_chirho,
    );
    if let Some(response_chirho) = &effect_chirho.response_chirho {
        // A sealed write's response is stored as a private DAG value, so public CAS need not hold
        // it at all — but only genuine NotFound is ABSENCE. Tamper and unreadable objects are both
        // present-or-possibly-present and must fail this privacy assertion rather than being rescued
        // by the private plane. The private record must verify too: a bare JSONL claim is not
        // evidence that sealing occurred.
        match cairn_chirho::cas_chirho::read_verified_chirho(root_chirho, response_chirho) {
            cairn_chirho::cas_chirho::CasReadOutcomeChirho::VerifiedChirho(
                response_bytes_chirho,
            ) => assert_no_contact_pii_chirho(
                &format!("{surface_chirho} response object"),
                &response_bytes_chirho,
                needles_chirho,
            ),
            cairn_chirho::cas_chirho::CasReadOutcomeChirho::AbsentChirho(_absent_chirho) => {
                match cairn_chirho::dag_private_value_chirho::verified_private_dag_value_record_chirho(
                    root_chirho,
                    response_chirho,
                ) {
                    Ok(Some(_record_chirho)) => {}
                    Ok(None) => panic!(
                        "{surface_chirho} response is neither in public CAS nor a verified private value"
                    ),
                    Err(error_chirho) => panic!(
                        "{surface_chirho} response private evidence failed verification: {error_chirho:#}"
                    ),
                }
            }
            cairn_chirho::cas_chirho::CasReadOutcomeChirho::TamperedChirho {
                actual_chirho, ..
            } => panic!(
                "{surface_chirho} response is present in public CAS and re-hashes to {} instead of {}",
                actual_chirho.0, response_chirho.0
            ),
            cairn_chirho::cas_chirho::CasReadOutcomeChirho::UnreadableChirho(error_chirho) => {
                panic!(
                    "{surface_chirho} response is present but could not be read: {error_chirho}"
                )
            }
        }
    }
}

pub(super) fn assert_path_tree_has_no_contact_pii_chirho(
    path_chirho: &std::path::Path,
    surface_chirho: &str,
    needles_chirho: &[&str],
) {
    if !path_chirho.exists() {
        return;
    }
    if path_chirho.is_file() {
        let bytes_chirho = std::fs::read(path_chirho).unwrap();
        assert_no_contact_pii_chirho(surface_chirho, &bytes_chirho, needles_chirho);
        return;
    }
    for entry_chirho in std::fs::read_dir(path_chirho).unwrap() {
        let path_chirho = entry_chirho.unwrap().path();
        let surface_chirho = path_chirho.display().to_string();
        assert_path_tree_has_no_contact_pii_chirho(&path_chirho, &surface_chirho, needles_chirho);
    }
}

pub(super) fn assert_optional_file_no_contact_pii_chirho(
    path_chirho: &std::path::Path,
    surface_chirho: &str,
    needles_chirho: &[&str],
) {
    if path_chirho.exists() {
        let bytes_chirho = std::fs::read(path_chirho).unwrap();
        assert_no_contact_pii_chirho(surface_chirho, &bytes_chirho, needles_chirho);
    }
}

pub(super) fn assert_no_contact_pii_chirho(
    surface_chirho: &str,
    bytes_chirho: &[u8],
    needles_chirho: &[&str],
) {
    let text_chirho = String::from_utf8_lossy(bytes_chirho);
    for needle_chirho in needles_chirho {
        assert!(
            !text_chirho.contains(needle_chirho),
            "{surface_chirho} leaked contact PII needle '{needle_chirho}'"
        );
    }
}
