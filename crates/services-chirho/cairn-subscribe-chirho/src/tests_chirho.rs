// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use cairn_gate1_authority_log_chirho::authority_log_chirho::{
    append_gate1_authority_record_chirho, gate1_authority_log_path_chirho,
    Gate1AuthorityAppendInputChirho,
};
use cairn_model_gate1_chirho::{
    canonical_gate1_authority_record_json_chirho, GATE1_LEDGER_FAMILY_CHIRHO,
};
use cairn_writer_head_chirho::writer_head_chirho::issue_writer_fence_for_root_chirho;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-subscribe-{label_chirho}-{}-{nanos_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    root_chirho
}

fn append_ledger_record_chirho(
    root_chirho: &Path,
    family_seq_chirho: u64,
    family_line_chirho: &str,
) -> Gate1AuthorityLogRecordChirho {
    let token_chirho = issue_writer_fence_for_root_chirho(root_chirho).unwrap();
    append_gate1_authority_record_chirho(
        root_chirho,
        &token_chirho,
        Gate1AuthorityAppendInputChirho {
            family_chirho: GATE1_LEDGER_FAMILY_CHIRHO,
            family_seq_chirho,
            family_line_chirho,
            at_ms_chirho: 1_000 + family_seq_chirho,
        },
    )
    .unwrap()
    .record_chirho
}

struct CountingTailReaderChirho<RChirho> {
    inner_chirho: RChirho,
    read_count_chirho: u64,
    read_cursors_chirho: Vec<Gate1AuthorityCursorChirho>,
}

impl<RChirho: SourceTailReaderChirho> SourceTailReaderChirho for CountingTailReaderChirho<RChirho> {
    fn read_after_chirho(
        &mut self,
        cursor_chirho: Gate1AuthorityCursorChirho,
    ) -> Result<SourceTailBatchChirho> {
        self.read_count_chirho += 1;
        self.read_cursors_chirho.push(cursor_chirho);
        self.inner_chirho.read_after_chirho(cursor_chirho)
    }
}

#[test]
fn view_dependency_roles_borrow_one_literal_key_set_chirho() {
    let dependencies_chirho =
        ViewDependencySetChirho::gate1_group_chirho(GATE1_LEDGER_FAMILY_CHIRHO).unwrap();
    let subscription_chirho = dependencies_chirho.subscription_dependencies_chirho();
    let render_chirho = dependencies_chirho.render_dag_inputs_chirho();
    let invalidation_chirho = dependencies_chirho.cache_invalidation_keys_chirho();

    assert!(std::ptr::eq(subscription_chirho, render_chirho));
    assert!(std::ptr::eq(subscription_chirho, invalidation_chirho));
    assert_eq!(subscription_chirho, render_chirho);
    assert_eq!(subscription_chirho, invalidation_chirho);
}

#[test]
fn subscription_ids_are_server_minted_and_deterministic_chirho() {
    let mut first_issuer_chirho = SubscriptionIdIssuerChirho::default();
    let mut second_issuer_chirho = SubscriptionIdIssuerChirho::default();
    let first_sequence_chirho = [
        first_issuer_chirho.mint_chirho().unwrap().value_chirho(),
        first_issuer_chirho.mint_chirho().unwrap().value_chirho(),
        first_issuer_chirho.mint_chirho().unwrap().value_chirho(),
    ];
    let second_sequence_chirho = [
        second_issuer_chirho.mint_chirho().unwrap().value_chirho(),
        second_issuer_chirho.mint_chirho().unwrap().value_chirho(),
        second_issuer_chirho.mint_chirho().unwrap().value_chirho(),
    ];

    assert_eq!(first_sequence_chirho, [0, 1, 2]);
    assert_eq!(first_sequence_chirho, second_sequence_chirho);
}

#[test]
fn one_verified_tail_read_and_one_dispatch_pass_fan_out_to_many_chirho() {
    let root_chirho = temp_root_chirho("fanout");
    append_ledger_record_chirho(&root_chirho, 0, r#"{"seq_chirho":0,"amount_chirho":7}"#);
    let dependencies_chirho =
        ViewDependencySetChirho::gate1_group_chirho(GATE1_LEDGER_FAMILY_CHIRHO).unwrap();
    let mut issuer_chirho = SubscriptionIdIssuerChirho::default();
    let mut index_chirho = DispatchIndexChirho::default();
    for _subscriber_index_chirho in 0..64 {
        index_chirho.register_chirho(issuer_chirho.mint_chirho().unwrap(), &dependencies_chirho);
    }
    let mut reader_chirho = CountingTailReaderChirho {
        inner_chirho: Gate1AuthorityTailReaderChirho::new_chirho(&root_chirho),
        read_count_chirho: 0,
        read_cursors_chirho: Vec::new(),
    };

    let tick_chirho = SubscriptionDispatcherChirho
        .tick_chirho(
            &mut reader_chirho,
            &index_chirho,
            Gate1AuthorityCursorChirho::default(),
        )
        .unwrap();

    assert_eq!(reader_chirho.read_count_chirho, 1);
    assert_eq!(tick_chirho.source_reads_chirho, 1);
    assert_eq!(tick_chirho.dispatch_passes_chirho, 1);
    assert_eq!(tick_chirho.matched_keys_chirho.len(), 1);
    assert_eq!(tick_chirho.invalidated_subscriptions_chirho.len(), 64);
    assert_eq!(tick_chirho.next_cursor_chirho.next_authority_seq_chirho, 1);
    let rendered_chirho = format!("{tick_chirho:?}");
    assert!(!rendered_chirho.contains("amount_chirho"));
    assert!(!rendered_chirho.contains("family_line_chirho"));
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn empty_tick_still_reads_and_dispatches_once_without_advancing_chirho() {
    let root_chirho = temp_root_chirho("empty-tick");
    append_ledger_record_chirho(&root_chirho, 0, r#"{"seq_chirho":0}"#);
    let cursor_chirho = Gate1AuthorityCursorChirho {
        next_authority_seq_chirho: 1,
    };
    let mut reader_chirho = CountingTailReaderChirho {
        inner_chirho: Gate1AuthorityTailReaderChirho::new_chirho(&root_chirho),
        read_count_chirho: 0,
        read_cursors_chirho: Vec::new(),
    };

    let tick_chirho = SubscriptionDispatcherChirho
        .tick_chirho(
            &mut reader_chirho,
            &DispatchIndexChirho::default(),
            cursor_chirho,
        )
        .unwrap();

    assert_eq!(reader_chirho.read_count_chirho, 1);
    assert_eq!(tick_chirho.source_reads_chirho, 1);
    assert_eq!(tick_chirho.dispatch_passes_chirho, 1);
    assert!(tick_chirho.matched_keys_chirho.is_empty());
    assert!(tick_chirho.invalidated_subscriptions_chirho.is_empty());
    assert_eq!(tick_chirho.next_cursor_chirho, cursor_chirho);
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn cursor_past_verified_length_fails_closed_chirho() {
    let root_chirho = temp_root_chirho("cursor-gap");
    append_ledger_record_chirho(&root_chirho, 0, r#"{"seq_chirho":0}"#);
    let mut reader_chirho = Gate1AuthorityTailReaderChirho::new_chirho(&root_chirho);
    let error_chirho = reader_chirho
        .read_after_chirho(Gate1AuthorityCursorChirho {
            next_authority_seq_chirho: 2,
        })
        .unwrap_err()
        .to_string();

    assert!(error_chirho.contains("exceeds verified authority length"));
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn non_dense_verified_sequence_fails_closed_chirho() {
    let root_chirho = temp_root_chirho("non-dense");
    let mut record_chirho = append_ledger_record_chirho(&root_chirho, 0, r#"{"seq_chirho":0}"#);
    record_chirho.authority_seq_chirho = 7;

    let error_chirho = gate1_tail_batch_from_records_chirho(
        &[record_chirho],
        Gate1AuthorityCursorChirho::default(),
    )
    .unwrap_err()
    .to_string();

    assert!(error_chirho.contains("non-dense verified Gate 1 authority sequence"));
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn private_family_lines_never_influence_or_appear_in_opaque_key_chirho() {
    let root_chirho = temp_root_chirho("privacy-key");
    let first_chirho = append_ledger_record_chirho(
        &root_chirho,
        0,
        r#"{"note_chirho":"contact alice@example.com"}"#,
    );
    let mut second_chirho = first_chirho.clone();
    second_chirho.authority_seq_chirho = 1;
    second_chirho.family_seq_chirho = 1;
    second_chirho.family_line_chirho = r#"{"note_chirho":"private customer 555-0101"}"#.to_string();
    let batch_chirho = gate1_tail_batch_from_records_chirho(
        &[first_chirho, second_chirho],
        Gate1AuthorityCursorChirho::default(),
    )
    .unwrap();

    assert_eq!(
        batch_chirho.events_chirho[0].dependency_key_chirho,
        batch_chirho.events_chirho[1].dependency_key_chirho
    );
    let key_text_chirho = batch_chirho.events_chirho[0]
        .dependency_key_chirho
        .as_hash_chirho()
        .0
        .as_str();
    assert!(!key_text_chirho.contains("alice@example.com"));
    assert!(!key_text_chirho.contains("555-0101"));
    assert!(!key_text_chirho.contains(GATE1_LEDGER_FAMILY_CHIRHO));
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn foreign_signed_authority_record_fails_before_dispatch_chirho() {
    let target_root_chirho = temp_root_chirho("target-key");
    let foreign_root_chirho = temp_root_chirho("foreign-key");
    append_ledger_record_chirho(&target_root_chirho, 0, r#"{"seq_chirho":0}"#);
    let foreign_record_chirho =
        append_ledger_record_chirho(&foreign_root_chirho, 0, r#"{"seq_chirho":0}"#);
    std::fs::write(
        gate1_authority_log_path_chirho(&target_root_chirho),
        format!(
            "{}\n",
            canonical_gate1_authority_record_json_chirho(&foreign_record_chirho).unwrap()
        ),
    )
    .unwrap();
    let mut reader_chirho = Gate1AuthorityTailReaderChirho::new_chirho(&target_root_chirho);

    let error_chirho = format!(
        "{:#}",
        reader_chirho
            .read_after_chirho(Gate1AuthorityCursorChirho::default())
            .unwrap_err()
    );

    assert!(
        error_chirho.contains("key id mismatch"),
        "unexpected verified-reader error: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(target_root_chirho);
    let _ = std::fs::remove_dir_all(foreign_root_chirho);
}

#[test]
fn heterogeneous_cursors_share_one_verified_read_and_dispatch_pass_chirho() {
    let root_chirho = temp_root_chirho("heterogeneous");
    for family_seq_chirho in 0..8 {
        append_ledger_record_chirho(
            &root_chirho,
            family_seq_chirho,
            &format!(r#"{{"seq_chirho":{family_seq_chirho},"amount_chirho":7}}"#),
        );
    }
    let dependencies_chirho =
        ViewDependencySetChirho::gate1_group_chirho(GATE1_LEDGER_FAMILY_CHIRHO).unwrap();
    let mut issuer_chirho = SubscriptionIdIssuerChirho::default();
    let mut index_chirho = DispatchIndexChirho::default();
    let mut subscription_ids_chirho = Vec::new();
    let mut expected_invalidated_chirho = BTreeSet::new();
    for subscriber_index_chirho in 0..64_u64 {
        let subscription_id_chirho = issuer_chirho.mint_chirho().unwrap();
        let next_authority_seq_chirho = subscriber_index_chirho % 9;
        index_chirho.register_at_cursor_chirho(
            subscription_id_chirho,
            &dependencies_chirho,
            Gate1AuthorityCursorChirho {
                next_authority_seq_chirho,
            },
        );
        if next_authority_seq_chirho < 8 {
            expected_invalidated_chirho.insert(subscription_id_chirho);
        }
        subscription_ids_chirho.push(subscription_id_chirho);
    }
    let mut reader_chirho = CountingTailReaderChirho {
        inner_chirho: Gate1AuthorityTailReaderChirho::new_chirho(&root_chirho),
        read_count_chirho: 0,
        read_cursors_chirho: Vec::new(),
    };

    let tick_chirho = SubscriptionDispatcherChirho
        .tick_heterogeneous_chirho(&mut reader_chirho, &mut index_chirho)
        .unwrap();

    assert_eq!(reader_chirho.read_count_chirho, 1);
    assert_eq!(
        reader_chirho.read_cursors_chirho,
        [Gate1AuthorityCursorChirho {
            next_authority_seq_chirho: 0,
        }]
    );
    assert_eq!(tick_chirho.source_reads_chirho, 1);
    assert_eq!(tick_chirho.dispatch_passes_chirho, 1);
    assert_eq!(tick_chirho.matched_keys_chirho.len(), 1);
    assert_eq!(
        tick_chirho.invalidated_subscriptions_chirho,
        expected_invalidated_chirho
    );
    assert!(tick_chirho
        .resnapshot_required_subscriptions_chirho
        .is_empty());
    assert_eq!(tick_chirho.next_cursors_by_subscription_chirho.len(), 64);
    for subscription_id_chirho in subscription_ids_chirho {
        let expected_cursor_chirho = Gate1AuthorityCursorChirho {
            next_authority_seq_chirho: 8,
        };
        assert_eq!(
            tick_chirho
                .next_cursors_by_subscription_chirho
                .get(&subscription_id_chirho),
            Some(&expected_cursor_chirho)
        );
        assert_eq!(
            index_chirho.cursor_chirho(subscription_id_chirho),
            Some(expected_cursor_chirho)
        );
    }
    let rendered_chirho = format!("{tick_chirho:?}");
    assert!(!rendered_chirho.contains("amount_chirho"));
    assert!(!rendered_chirho.contains("family_line_chirho"));
    assert!(!rendered_chirho.contains(&root_chirho.to_string_lossy().to_string()));
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn beyond_tail_cursor_resnapshots_without_blocking_clean_subscriber_chirho() {
    let root_chirho = temp_root_chirho("stale-isolation");
    for family_seq_chirho in 0..3 {
        append_ledger_record_chirho(
            &root_chirho,
            family_seq_chirho,
            &format!(r#"{{"seq_chirho":{family_seq_chirho}}}"#),
        );
    }
    let dependencies_chirho =
        ViewDependencySetChirho::gate1_group_chirho(GATE1_LEDGER_FAMILY_CHIRHO).unwrap();
    let mut issuer_chirho = SubscriptionIdIssuerChirho::default();
    let clean_subscription_id_chirho = issuer_chirho.mint_chirho().unwrap();
    let stale_subscription_id_chirho = issuer_chirho.mint_chirho().unwrap();
    let mut index_chirho = DispatchIndexChirho::default();
    index_chirho.register_at_cursor_chirho(
        clean_subscription_id_chirho,
        &dependencies_chirho,
        Gate1AuthorityCursorChirho {
            next_authority_seq_chirho: 1,
        },
    );
    index_chirho.register_at_cursor_chirho(
        stale_subscription_id_chirho,
        &dependencies_chirho,
        Gate1AuthorityCursorChirho {
            next_authority_seq_chirho: 9,
        },
    );
    let mut reader_chirho = CountingTailReaderChirho {
        inner_chirho: Gate1AuthorityTailReaderChirho::new_chirho(&root_chirho),
        read_count_chirho: 0,
        read_cursors_chirho: Vec::new(),
    };

    let tick_chirho = SubscriptionDispatcherChirho
        .tick_heterogeneous_chirho(&mut reader_chirho, &mut index_chirho)
        .unwrap();

    assert_eq!(reader_chirho.read_count_chirho, 1);
    assert_eq!(
        reader_chirho.read_cursors_chirho,
        [Gate1AuthorityCursorChirho {
            next_authority_seq_chirho: 1,
        }]
    );
    assert_eq!(tick_chirho.source_reads_chirho, 1);
    assert_eq!(tick_chirho.dispatch_passes_chirho, 1);
    assert_eq!(
        tick_chirho.resnapshot_required_subscriptions_chirho,
        BTreeSet::from([stale_subscription_id_chirho])
    );
    assert_eq!(
        tick_chirho.invalidated_subscriptions_chirho,
        BTreeSet::from([clean_subscription_id_chirho])
    );
    let verified_cut_chirho = Gate1AuthorityCursorChirho {
        next_authority_seq_chirho: 3,
    };
    assert_eq!(
        tick_chirho.next_cursors_by_subscription_chirho,
        BTreeMap::from([(clean_subscription_id_chirho, verified_cut_chirho)])
    );
    assert_eq!(
        index_chirho.cursor_chirho(clean_subscription_id_chirho),
        Some(verified_cut_chirho)
    );
    assert_eq!(
        index_chirho.cursor_chirho(stale_subscription_id_chirho),
        Some(Gate1AuthorityCursorChirho {
            next_authority_seq_chirho: 9,
        })
    );
    let rendered_chirho = format!("{tick_chirho:?}");
    assert!(!rendered_chirho.contains("family_line_chirho"));
    assert!(!rendered_chirho.contains("principal"));
    assert!(!rendered_chirho.contains(&root_chirho.to_string_lossy().to_string()));
    let _ = std::fs::remove_dir_all(root_chirho);
}
