// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::model_chirho::DagChirho;
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-pricebook-test-{nanos_chirho}-{n_chirho}"))
}

fn deploy_owned_app_chirho(root_chirho: &Path, name_chirho: &str) -> String {
    let owner_chirho = crate::identity_chirho::register_identity_chirho(
        root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let marker_chirho = crate::cas_chirho::add_chirho(root_chirho, b"node marker").unwrap();
    let dag_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![marker_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap();
    app_chirho::deploy_app_chirho(root_chirho, name_chirho, dag_chirho, &owner_chirho).unwrap();
    owner_chirho
}

#[test]
fn registered_effect_price_catalog_is_kept_and_unambiguous_chirho() {
    let prices_chirho = registered_effect_prices_chirho();
    assert_eq!(prices_chirho.len(), 8);
    assert!(prices_chirho
        .iter()
        .all(|(name_chirho, price_chirho, provider_chirho)| {
            name_chirho.ends_with("_chirho") && *price_chirho > 0 && !provider_chirho.is_empty()
        }));

    let unique_names_chirho = prices_chirho
        .iter()
        .map(|(name_chirho, _, _)| *name_chirho)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(unique_names_chirho.len(), prices_chirho.len());
    assert_eq!(
        registered_effect_price_chirho("card_charge_chirho"),
        Some((17, "provider/card"))
    );
    assert_eq!(registered_effect_price_chirho("unknown_chirho"), None);
}

fn write_jsonl_chirho<T: Serialize>(path_chirho: &Path, rows_chirho: &[T]) {
    if let Some(parent_chirho) = path_chirho.parent() {
        std::fs::create_dir_all(parent_chirho).unwrap();
    }
    let mut text_chirho = String::new();
    for row_chirho in rows_chirho {
        text_chirho.push_str(&serde_json::to_string(row_chirho).unwrap());
        text_chirho.push('\n');
    }
    std::fs::write(path_chirho, text_chirho).unwrap();
}

fn resign_price_record_for_test_chirho(
    root_chirho: &Path,
    mut record_chirho: PriceBookRecordChirho,
) -> PriceBookRecordChirho {
    record_chirho.sig_chirho.clear();
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &price_record_message_chirho(&record_chirho).unwrap(),
    )
    .unwrap();
    record_chirho
}

#[test]
fn price_book_signed_message_bytes_stay_stable_chirho() {
    let record_chirho = PriceBookRecordChirho {
        seq_chirho: 7,
        schema_chirho: PRICE_BOOK_RECORD_SCHEMA_CHIRHO.to_string(),
        app_chirho: "pricedapp".to_string(),
        owner_principal_chirho: "owner/test".to_string(),
        price_book_chirho: HashChirho("b".repeat(64)),
        previous_chirho: Some(HashChirho("a".repeat(64))),
        at_ms_chirho: 123_456,
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: None,
        sig_chirho: "not-signed-for-message".to_string(),
    };

    assert_eq!(
        std::str::from_utf8(&price_record_message_chirho(&record_chirho).unwrap()).unwrap(),
        concat!(
            r#"{"seq_chirho":7,"schema_chirho":"price-book-record-v1-chirho","#,
            r#""app_chirho":"pricedapp","owner_principal_chirho":"owner/test","#,
            r#""price_book_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","#,
            r#""previous_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
            r#""at_ms_chirho":123456}"#
        )
    );
    assert_eq!(
        serde_json::to_string(&record_chirho).unwrap(),
        concat!(
            r#"{"seq_chirho":7,"schema_chirho":"price-book-record-v1-chirho","#,
            r#""app_chirho":"pricedapp","owner_principal_chirho":"owner/test","#,
            r#""price_book_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","#,
            r#""previous_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
            r#""at_ms_chirho":123456,"sig_chirho":"not-signed-for-message"}"#
        )
    );
}

#[test]
fn price_book_records_are_schema_tagged_and_unknown_schema_fails_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "schemaprice");
    let (price_book_chirho, _book_chirho, record_chirho) = set_price_book_chirho(
        &root_chirho,
        "schemaprice",
        &owner_chirho,
        Some(23),
        BTreeMap::new(),
        0,
    )
    .unwrap();

    assert_eq!(
        record_chirho.schema_chirho,
        PRICE_BOOK_RECORD_V2_SCHEMA_CHIRHO
    );
    assert_eq!(verify_price_books_chirho(&root_chirho).unwrap(), 1);
    assert_eq!(
        current_price_book_hash_chirho(&root_chirho, "schemaprice").unwrap(),
        Some(price_book_chirho)
    );

    let mut bad_record_chirho = record_chirho.clone();
    bad_record_chirho.schema_chirho = "price-book-record-v9-chirho".to_string();
    write_jsonl_chirho(
        &price_records_path_chirho(&root_chirho),
        &[bad_record_chirho],
    );
    let error_chirho = verify_price_books_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("unsupported price book record schema"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn legacy_price_book_records_without_schema_still_verify_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "legacyprice");
    set_price_book_chirho(
        &root_chirho,
        "legacyprice",
        &owner_chirho,
        Some(31),
        BTreeMap::new(),
        0,
    )
    .unwrap();

    let mut records_chirho = load_price_book_records_chirho(&root_chirho).unwrap();
    for record_chirho in &mut records_chirho {
        record_chirho.schema_chirho.clear();
        record_chirho.transition_id_chirho.clear();
        record_chirho.prepared_writer_fence_epoch_chirho = None;
        *record_chirho = resign_price_record_for_test_chirho(&root_chirho, record_chirho.clone());
    }
    write_jsonl_chirho(&price_records_path_chirho(&root_chirho), &records_chirho);
    assert!(
        !std::fs::read_to_string(price_records_path_chirho(&root_chirho))
            .unwrap()
            .contains("schema_chirho")
    );
    assert_eq!(verify_price_books_chirho(&root_chirho).unwrap(), 1);
    assert!(load_price_book_records_chirho(&root_chirho)
        .unwrap()
        .iter()
        .all(|record_chirho| record_chirho.schema_chirho.is_empty()));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn price_book_owner_gate_requires_verified_app_owner_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_a_chirho = deploy_owned_app_chirho(&root_chirho, "tamperprice");
    let owner_b_chirho = crate::identity_chirho::register_identity_chirho(
        &root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let mut app_records_chirho = app_chirho::load_app_records_chirho(&root_chirho).unwrap();
    app_records_chirho[0].owner_principal_chirho = owner_b_chirho.clone();
    write_jsonl_chirho(
        &root_chirho.join("app-records-chirho.jsonl"),
        &app_records_chirho,
    );
    assert_eq!(
        app_chirho::app_owner_chirho(&root_chirho, "tamperprice").unwrap(),
        Some(owner_b_chirho.clone())
    );

    let forged_owner_error_chirho = set_price_book_chirho(
        &root_chirho,
        "tamperprice",
        &owner_b_chirho,
        Some(10),
        BTreeMap::new(),
        0,
    )
    .unwrap_err()
    .to_string();
    assert!(forged_owner_error_chirho.contains("app record 0 signature invalid"));
    let original_owner_error_chirho = set_price_book_chirho(
        &root_chirho,
        "tamperprice",
        &owner_a_chirho,
        Some(10),
        BTreeMap::new(),
        0,
    )
    .unwrap_err()
    .to_string();
    assert!(original_owner_error_chirho.contains("app record 0 signature invalid"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn price_book_ref_cannot_authorize_shape_valid_state_outside_signed_history_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "unloggedprice");
    let forged_book_chirho = pricebook_policy_chirho::propose_price_book_chirho(
        "unloggedprice",
        &owner_chirho,
        Some(777),
        BTreeMap::new(),
        0,
        None,
        now_ms_chirho(),
    )
    .unwrap();
    let forged_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &forged_book_chirho).unwrap();
    refs_chirho::set_branch_chirho(
        &root_chirho,
        &pricebook_ref_chirho("unloggedprice"),
        forged_hash_chirho,
    )
    .unwrap();

    assert_eq!(verify_price_books_chirho(&root_chirho).unwrap(), 0);
    let error_chirho = resolve_price_chirho(&root_chirho, "unloggedprice", "paid-effect-chirho")
        .unwrap_err()
        .to_string();
    assert!(
        error_chirho.contains("does not select verified signed history"),
        "{error_chirho}"
    );

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn owner_sets_versioned_price_books_and_ref_rollback_changes_current_price_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "pricedapp");
    let other_owner_chirho = crate::identity_chirho::register_identity_chirho(
        &root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;

    let mut effect_prices_chirho = BTreeMap::new();
    effect_prices_chirho.insert("echo_paid_chirho".to_string(), 17);
    let (first_hash_chirho, first_book_chirho, first_record_chirho) = set_price_book_chirho(
        &root_chirho,
        "pricedapp",
        &owner_chirho,
        Some(11),
        effect_prices_chirho,
        250,
    )
    .unwrap();
    assert_eq!(first_book_chirho.previous_chirho, None);
    assert_eq!(first_record_chirho.price_book_chirho, first_hash_chirho);
    assert_eq!(
        resolve_price_chirho(&root_chirho, "pricedapp", "echo_paid_chirho")
            .unwrap()
            .price_chirho,
        17
    );
    assert_eq!(
        resolve_price_chirho(&root_chirho, "pricedapp", "llm_chirho")
            .unwrap()
            .price_chirho,
        11
    );

    assert!(set_price_book_chirho(
        &root_chirho,
        "pricedapp",
        &other_owner_chirho,
        Some(22),
        BTreeMap::new(),
        0,
    )
    .is_err());

    let (second_hash_chirho, second_book_chirho, _second_record_chirho) = set_price_book_chirho(
        &root_chirho,
        "pricedapp",
        &owner_chirho,
        Some(29),
        BTreeMap::new(),
        0,
    )
    .unwrap();
    assert_eq!(
        second_book_chirho.previous_chirho,
        Some(first_hash_chirho.clone())
    );
    assert_eq!(
        resolve_price_chirho(&root_chirho, "pricedapp", "echo_paid_chirho")
            .unwrap()
            .price_chirho,
        29
    );
    assert_eq!(
        price_book_history_chirho(&root_chirho, "pricedapp")
            .unwrap()
            .len(),
        2
    );
    refs_chirho::rollback_chirho(
        &root_chirho,
        "pricebook/pricedapp",
        first_hash_chirho.clone(),
    )
    .unwrap();
    assert_eq!(
        resolve_price_chirho(&root_chirho, "pricedapp", "echo_paid_chirho")
            .unwrap()
            .price_chirho,
        17
    );
    assert_eq!(
        current_price_book_hash_chirho(&root_chirho, "pricedapp").unwrap(),
        Some(first_hash_chirho.clone())
    );
    assert_ne!(first_hash_chirho, second_hash_chirho);
    assert_eq!(verify_price_books_chirho(&root_chirho).unwrap(), 2);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

include!("ha2_head_commit_tests_chirho.rs");
