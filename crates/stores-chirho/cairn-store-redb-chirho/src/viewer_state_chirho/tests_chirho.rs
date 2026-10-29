// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

fn temp_store_chirho(label_chirho: &str) -> (tempfile::TempDir, ViewerStateStoreChirho) {
    let root_chirho = tempfile::tempdir().unwrap();
    let store_chirho = ViewerStateStoreChirho::open_chirho(
        &root_chirho.path().join(format!("{label_chirho}.redb")),
    )
    .unwrap();
    (root_chirho, store_chirho)
}

fn receipt_digest_chirho(label_chirho: &str) -> HashChirho {
    HashChirho(blake3::hash(label_chirho.as_bytes()).to_hex().to_string())
}

fn head_transition_chirho(
    expected_chirho: Option<&ViewerStateHeadChirho>,
    next_version_chirho: u64,
    next_digest_chirho: HashChirho,
) -> ViewerStateHeadTransitionChirho {
    ViewerStateHeadTransitionChirho {
        expected_chirho: expected_chirho.cloned(),
        next_chirho: ViewerStateHeadChirho {
            version_chirho: next_version_chirho,
            receipt_digest_chirho: next_digest_chirho,
        },
    }
}

#[test]
fn append_is_per_key_and_compare_guarded_chirho() {
    let (_root_chirho, store_chirho) = temp_store_chirho("compare-chirho");
    let viewer_scope_chirho = "viewer/chirho/";
    let a_one_digest_chirho = receipt_digest_chirho("a-one-chirho");
    assert_eq!(
        store_chirho
            .append_bounded_chirho(
                viewer_scope_chirho,
                "viewer/chirho/a-chirho",
                &head_transition_chirho(None, 1, a_one_digest_chirho.clone()),
                b"one",
                4,
                8,
            )
            .unwrap(),
        1
    );
    assert_eq!(
        store_chirho
            .append_bounded_chirho(
                viewer_scope_chirho,
                "viewer/chirho/b-chirho",
                &head_transition_chirho(None, 1, receipt_digest_chirho("b-one-chirho")),
                b"other",
                4,
                8,
            )
            .unwrap(),
        1
    );
    assert!(store_chirho
        .append_bounded_chirho(
            viewer_scope_chirho,
            "viewer/chirho/a-chirho",
            &head_transition_chirho(None, 1, receipt_digest_chirho("a-stale-chirho")),
            b"stale",
            4,
            8,
        )
        .unwrap_err()
        .to_string()
        .contains("authoritative head changed"));
    let a_one_head_chirho = ViewerStateHeadChirho {
        version_chirho: 1,
        receipt_digest_chirho: a_one_digest_chirho,
    };
    let wrong_a_one_head_chirho = ViewerStateHeadChirho {
        version_chirho: 1,
        receipt_digest_chirho: receipt_digest_chirho("wrong-a-one-chirho"),
    };
    assert!(store_chirho
        .append_bounded_chirho(
            viewer_scope_chirho,
            "viewer/chirho/a-chirho",
            &head_transition_chirho(
                Some(&wrong_a_one_head_chirho),
                2,
                receipt_digest_chirho("wrong-a-two-chirho"),
            ),
            b"wrong-two",
            4,
            8,
        )
        .unwrap_err()
        .to_string()
        .contains("authoritative head changed"));
    let a_two_digest_chirho = receipt_digest_chirho("a-two-chirho");
    assert_eq!(
        store_chirho
            .append_bounded_chirho(
                viewer_scope_chirho,
                "viewer/chirho/a-chirho",
                &head_transition_chirho(Some(&a_one_head_chirho), 2, a_two_digest_chirho.clone(),),
                b"two",
                4,
                8,
            )
            .unwrap(),
        2
    );
    assert_eq!(
        store_chirho
            .latest_chirho("viewer/chirho/b-chirho")
            .unwrap(),
        Some(ViewerStateEntryChirho {
            version_chirho: 1,
            value_chirho: b"other".to_vec(),
        })
    );
    assert_eq!(
        store_chirho.head_chirho("viewer/chirho/a-chirho").unwrap(),
        Some(ViewerStateHeadChirho {
            version_chirho: 2,
            receipt_digest_chirho: a_two_digest_chirho,
        })
    );
}

#[test]
fn retained_history_is_bounded_and_exact_chirho() {
    let (_root_chirho, store_chirho) = temp_store_chirho("bounded-chirho");
    let viewer_scope_chirho = "viewer/chirho/";
    let key_chirho = "viewer/chirho/a-chirho";
    let mut expected_head_chirho = None;
    for version_chirho in 1..=7_u64 {
        let value_chirho = format!("value-{version_chirho}");
        let receipt_digest_chirho = receipt_digest_chirho(&format!("receipt-{version_chirho}"));
        let stored_chirho = store_chirho
            .append_bounded_chirho(
                viewer_scope_chirho,
                key_chirho,
                &head_transition_chirho(
                    expected_head_chirho.as_ref(),
                    version_chirho,
                    receipt_digest_chirho.clone(),
                ),
                value_chirho.as_bytes(),
                3,
                8,
            )
            .unwrap();
        assert_eq!(stored_chirho, version_chirho);
        expected_head_chirho = Some(ViewerStateHeadChirho {
            version_chirho: stored_chirho,
            receipt_digest_chirho,
        });
    }
    let history_chirho = store_chirho.history_chirho(key_chirho, 3).unwrap();
    assert_eq!(
        history_chirho
            .iter()
            .map(|entry_chirho| entry_chirho.version_chirho)
            .collect::<Vec<_>>(),
        vec![7, 6, 5]
    );
    assert!(store_chirho.exact_chirho(key_chirho, 4).unwrap().is_none());
    assert_eq!(
        store_chirho
            .exact_chirho(key_chirho, 5)
            .unwrap()
            .unwrap()
            .value_chirho,
        b"value-5"
    );
}

#[test]
fn key_count_is_atomic_scoped_and_bounded_chirho() {
    let (_root_chirho, store_chirho) = temp_store_chirho("keys-chirho");
    let viewer_a_chirho = "viewer/a-chirho/";
    for key_chirho in [
        "viewer/a-chirho/name-chirho",
        "viewer/a-chirho/theme-chirho",
    ] {
        store_chirho
            .append_bounded_chirho(
                viewer_a_chirho,
                key_chirho,
                &head_transition_chirho(None, 1, receipt_digest_chirho(key_chirho)),
                b"value",
                2,
                2,
            )
            .unwrap();
    }
    assert_eq!(
        store_chirho
            .key_count_for_viewer_chirho(viewer_a_chirho)
            .unwrap(),
        2
    );
    assert!(store_chirho
        .append_bounded_chirho(
            viewer_a_chirho,
            "viewer/a-chirho/third-chirho",
            &head_transition_chirho(None, 1, receipt_digest_chirho("third-chirho")),
            b"value",
            2,
            2,
        )
        .unwrap_err()
        .to_string()
        .contains("key limit of 2 reached"));
    let name_head_chirho = store_chirho
        .head_chirho("viewer/a-chirho/name-chirho")
        .unwrap()
        .unwrap();
    assert_eq!(
        store_chirho
            .append_bounded_chirho(
                viewer_a_chirho,
                "viewer/a-chirho/name-chirho",
                &head_transition_chirho(
                    Some(&name_head_chirho),
                    2,
                    receipt_digest_chirho("renamed-chirho"),
                ),
                b"renamed",
                2,
                2,
            )
            .unwrap(),
        2
    );
    assert_eq!(
        store_chirho
            .key_count_for_viewer_chirho(viewer_a_chirho)
            .unwrap(),
        2
    );
    assert!(store_chirho
        .append_bounded_chirho(
            viewer_a_chirho,
            "viewer/b-chirho/name-chirho",
            &head_transition_chirho(None, 1, receipt_digest_chirho("outside-chirho")),
            b"outside",
            2,
            2,
        )
        .unwrap_err()
        .to_string()
        .contains("outside its host-derived viewer scope"));
}

#[test]
fn authoritative_head_refuses_a_truncated_valid_prefix_chirho() {
    let (_root_chirho, store_chirho) = temp_store_chirho("truncated-prefix-chirho");
    let viewer_scope_chirho = "viewer/chirho/";
    let key_chirho = "viewer/chirho/a-chirho";
    let mut expected_head_chirho = None;
    for version_chirho in 1..=3_u64 {
        let receipt_digest_chirho = receipt_digest_chirho(&format!("valid-{version_chirho}"));
        store_chirho
            .append_bounded_chirho(
                viewer_scope_chirho,
                key_chirho,
                &head_transition_chirho(
                    expected_head_chirho.as_ref(),
                    version_chirho,
                    receipt_digest_chirho.clone(),
                ),
                format!("value-{version_chirho}").as_bytes(),
                4,
                8,
            )
            .unwrap();
        expected_head_chirho = Some(ViewerStateHeadChirho {
            version_chirho,
            receipt_digest_chirho,
        });
    }

    let transaction_chirho = store_chirho.begin_immediate_write_chirho().unwrap();
    {
        let mut entries_chirho = transaction_chirho
            .open_table(VIEWER_STATE_ENTRIES_CHIRHO)
            .unwrap();
        entries_chirho.remove((key_chirho, 3)).unwrap();
    }
    transaction_chirho.commit().unwrap();

    let error_chirho = store_chirho
        .history_chirho(key_chirho, 4)
        .expect_err("removing the canonical tail must not expose an older valid prefix");
    assert!(
        error_chirho
            .to_string()
            .contains("authoritative head disagrees"),
        "unexpected truncation refusal: {error_chirho:#}"
    );
}
