// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::bundle_chirho::load_verified_bundle_page_chirho;
use super::*;
use crate::FsLedgerStorageChirho;
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;
use cairn_ledger_model_chirho::ids_chirho::{AccountIdChirho, AssetKindIdChirho};
use cairn_ledger_read_model_chirho::{
    AccountNetProjectionPageSliceChirho, AccountNetProjectionRowChirho,
    ACCOUNT_NET_PROJECTION_PAGE_ROWS_CHIRHO,
};
use cairn_writer_elector_chirho::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    compose_writer_epoch_chirho, ConsistencyGroupIdChirho,
};
use std::cell::Cell;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

struct BundleTestRootChirho {
    path_chirho: PathBuf,
}

impl BundleTestRootChirho {
    fn new_chirho(label_chirho: &str) -> Self {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock remains after the Unix epoch")
            .as_nanos();
        let path_chirho = std::env::temp_dir().join(format!(
            "cairn-gd7-view-bundle-{label_chirho}-{nanos_chirho}-{counter_chirho}"
        ));
        fs::create_dir_all(&path_chirho).expect("create bundle test root");
        Self { path_chirho }
    }

    fn storage_chirho(&self) -> FsLedgerStorageChirho {
        FsLedgerStorageChirho::open_existing_chirho(&self.path_chirho)
            .expect("open bundle test storage")
    }
}

impl Drop for BundleTestRootChirho {
    fn drop(&mut self) {
        let _remove_result_chirho = fs::remove_dir_all(&self.path_chirho);
    }
}

fn account_chirho(index_chirho: usize) -> AccountIdChirho {
    AccountIdChirho {
        owner_chirho: format!("bundle-account-{index_chirho:04}-chirho"),
        kind_id_chirho: AssetKindIdChirho("prepaid-credit-chirho".to_owned()),
    }
}

fn rows_chirho(count_chirho: usize) -> Vec<AccountNetProjectionRowChirho> {
    (0..count_chirho)
        .map(|index_chirho| AccountNetProjectionRowChirho {
            account_chirho: account_chirho(index_chirho),
            account_net_chirho: u64::try_from(index_chirho + 1).expect("test row count fits u64"),
        })
        .collect()
}

fn page_slice_chirho(
    all_rows_chirho: &[AccountNetProjectionRowChirho],
    cursor_chirho: Option<&AccountIdChirho>,
) -> AccountNetProjectionPageSliceChirho {
    let end_chirho = cursor_chirho
        .map(|cursor_chirho| {
            all_rows_chirho
                .binary_search_by(|row_chirho| row_chirho.account_chirho.cmp(cursor_chirho))
                .expect("test cursor exists")
        })
        .unwrap_or(all_rows_chirho.len());
    let start_chirho = end_chirho.saturating_sub(ACCOUNT_NET_PROJECTION_PAGE_ROWS_CHIRHO);
    let page_rows_chirho = all_rows_chirho[start_chirho..end_chirho].to_vec();
    let next_upper_exclusive_account_chirho =
        (start_chirho > 0).then(|| page_rows_chirho[0].account_chirho.clone());
    AccountNetProjectionPageSliceChirho {
        rows_chirho: page_rows_chirho,
        next_upper_exclusive_account_chirho,
    }
}

fn bundle_fixture_chirho() -> (
    BundleTestRootChirho,
    FsLedgerStorageChirho,
    RaftWriterElectorChirho,
    LocalAppendAuthorityHandleChirho,
    Gd7WinnerJournalSnapshotChirho,
) {
    let root_chirho = BundleTestRootChirho::new_chirho("fixture");
    let storage_chirho = root_chirho.storage_chirho();
    let node_chirho = NodeIdChirho("31".repeat(32));
    let group_chirho = ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "bundle-group-chirho".to_owned(),
    };
    let elector_chirho =
        RaftWriterElectorChirho::new_single_node_chirho(node_chirho, group_chirho.clone())
            .expect("construct bundle elector")
            .with_leadership_warmup_lease_chirho();
    elector_chirho
        .campaign_chirho()
        .expect("campaign bundle elector");
    for _tick_chirho in 0..10 {
        let _messages_chirho = elector_chirho.tick_chirho();
    }
    let leadership_chirho = elector_chirho.leadership_chirho(&group_chirho);
    let snapshot_chirho = Gd7WinnerJournalSnapshotChirho {
        genesis_digest_chirho: "51".repeat(32),
        cut_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(leadership_chirho.term_chirho, 7)
                .expect("compose bundle epoch"),
            seq_chirho: 19,
            record_digest_chirho: "52".repeat(32),
        },
    };
    let authority_chirho = elector_chirho.local_append_authority_handle_chirho();
    (
        root_chirho,
        storage_chirho,
        elector_chirho,
        authority_chirho,
        snapshot_chirho,
    )
}

fn continue_restart_chirho(
    outcome_chirho: Gd7WinnerViewBundleStageOutcomeChirho,
) -> Gd7WinnerViewBundleRestartChirho {
    match outcome_chirho {
        Gd7WinnerViewBundleStageOutcomeChirho::ContinueChirho { restart_chirho } => restart_chirho,
        Gd7WinnerViewBundleStageOutcomeChirho::CompleteChirho { .. } => {
            panic!("expected another bounded bundle page")
        }
    }
}

fn complete_root_chirho(
    outcome_chirho: Gd7WinnerViewBundleStageOutcomeChirho,
) -> VerifiedGd7WinnerViewBundleRootChirho {
    match outcome_chirho {
        Gd7WinnerViewBundleStageOutcomeChirho::CompleteChirho { bundle_root_chirho } => {
            bundle_root_chirho
        }
        Gd7WinnerViewBundleStageOutcomeChirho::ContinueChirho { .. } => {
            panic!("expected a complete bounded bundle root")
        }
    }
}

#[test]
fn bounded_pages_restart_exactly_and_form_one_complete_chain_chirho() {
    let (_root_chirho, storage_chirho, _elector_chirho, authority_chirho, snapshot_chirho) =
        bundle_fixture_chirho();
    let rows_chirho = rows_chirho(513);
    let snapshot_guard_held_chirho = Cell::new(false);
    let page_guard_held_chirho = Cell::new(false);

    let first_chirho = stage_next_gd7_winner_view_bundle_page_chirho(
        &storage_chirho,
        &authority_chirho,
        None,
        || {
            snapshot_guard_held_chirho.set(matches!(
                authority_chirho.try_acquire_chirho(),
                Err(LocalAppendAuthorityRefusalChirho::GuardBusyChirho)
            ));
            Ok(snapshot_chirho.clone())
        },
        |cursor_chirho| {
            page_guard_held_chirho.set(matches!(
                authority_chirho.try_acquire_chirho(),
                Err(LocalAppendAuthorityRefusalChirho::GuardBusyChirho)
            ));
            Ok(page_slice_chirho(&rows_chirho, cursor_chirho))
        },
    )
    .expect("stage first bounded bundle page");
    let first_restart_chirho = continue_restart_chirho(first_chirho);
    let restarted_first_chirho = continue_restart_chirho(
        stage_next_gd7_winner_view_bundle_page_chirho(
            &storage_chirho,
            &authority_chirho,
            None,
            || Ok(snapshot_chirho.clone()),
            |cursor_chirho| Ok(page_slice_chirho(&rows_chirho, cursor_chirho)),
        )
        .expect("restart bundle safely from its highest page"),
    );
    assert_eq!(
        restarted_first_chirho.page_ref_chirho(),
        first_restart_chirho.page_ref_chirho()
    );
    let second_restart_chirho = continue_restart_chirho(
        stage_next_gd7_winner_view_bundle_page_chirho(
            &storage_chirho,
            &authority_chirho,
            Some(&first_restart_chirho),
            || Ok(snapshot_chirho.clone()),
            |cursor_chirho| Ok(page_slice_chirho(&rows_chirho, cursor_chirho)),
        )
        .expect("stage second bounded bundle page"),
    );
    let second_ref_chirho = second_restart_chirho.page_ref_chirho().to_owned();
    let complete_chirho = complete_root_chirho(
        stage_next_gd7_winner_view_bundle_page_chirho(
            &storage_chirho,
            &authority_chirho,
            Some(&second_restart_chirho),
            || Ok(snapshot_chirho.clone()),
            |cursor_chirho| Ok(page_slice_chirho(&rows_chirho, cursor_chirho)),
        )
        .expect("stage final bounded bundle page"),
    );
    assert!(snapshot_guard_held_chirho.get());
    assert!(page_guard_held_chirho.get());
    assert!(authority_chirho.try_acquire_chirho().is_ok());
    assert_eq!(complete_chirho.root_chirho().page_count_chirho, 3);
    assert_eq!(complete_chirho.root_chirho().row_count_chirho, 513);
    let lowest_page_ref_chirho = complete_chirho
        .root_chirho()
        .lowest_page_ref_chirho
        .clone()
        .expect("complete nonempty bundle has a lowest page");
    assert_ne!(lowest_page_ref_chirho, second_ref_chirho);

    let mut reconstructed_chirho = Vec::new();
    let mut next_ref_chirho = Some(lowest_page_ref_chirho.clone());
    let mut expected_index_chirho = 2_u64;
    while let Some(page_ref_chirho) = next_ref_chirho {
        let page_chirho = load_verified_bundle_page_chirho(&storage_chirho, &page_ref_chirho)
            .expect("load linked bundle page");
        assert_eq!(
            page_chirho.page_chirho.page_index_chirho,
            expected_index_chirho
        );
        reconstructed_chirho.extend(page_chirho.page_chirho.rows_chirho.clone());
        next_ref_chirho = page_chirho.page_chirho.higher_page_ref_chirho.clone();
        expected_index_chirho = expected_index_chirho.saturating_sub(1);
    }
    assert_eq!(reconstructed_chirho, rows_chirho);

    let replay_chirho = complete_root_chirho(
        stage_next_gd7_winner_view_bundle_page_chirho(
            &storage_chirho,
            &authority_chirho,
            Some(&second_restart_chirho),
            || Ok(snapshot_chirho.clone()),
            |cursor_chirho| Ok(page_slice_chirho(&rows_chirho, cursor_chirho)),
        )
        .expect("replay final page idempotently"),
    );
    assert_eq!(
        replay_chirho.object_digest_chirho(),
        complete_chirho.object_digest_chirho()
    );
}

#[test]
fn empty_bundle_finishes_without_page_and_one_page_finishes_directly_chirho() {
    let (_root_chirho, storage_chirho, _elector_chirho, authority_chirho, snapshot_chirho) =
        bundle_fixture_chirho();
    let empty_chirho = complete_root_chirho(
        stage_next_gd7_winner_view_bundle_page_chirho(
            &storage_chirho,
            &authority_chirho,
            None,
            || Ok(snapshot_chirho.clone()),
            |_cursor_chirho| {
                Ok(AccountNetProjectionPageSliceChirho {
                    rows_chirho: Vec::new(),
                    next_upper_exclusive_account_chirho: None,
                })
            },
        )
        .expect("stage empty bundle"),
    );
    assert_eq!(empty_chirho.root_chirho().page_count_chirho, 0);
    assert_eq!(empty_chirho.root_chirho().row_count_chirho, 0);
    assert!(empty_chirho.root_chirho().lowest_page_ref_chirho.is_none());

    let one_row_chirho = rows_chirho(1);
    let one_chirho = complete_root_chirho(
        stage_next_gd7_winner_view_bundle_page_chirho(
            &storage_chirho,
            &authority_chirho,
            None,
            || Ok(snapshot_chirho),
            |cursor_chirho| Ok(page_slice_chirho(&one_row_chirho, cursor_chirho)),
        )
        .expect("stage one-row bundle"),
    );
    assert_eq!(one_chirho.root_chirho().page_count_chirho, 1);
    assert_eq!(one_chirho.root_chirho().row_count_chirho, 1);
}

#[test]
fn maximum_wire_bounded_coordinates_fit_one_full_bundle_page_chirho() {
    let (_root_chirho, storage_chirho, _elector_chirho, authority_chirho, snapshot_chirho) =
        bundle_fixture_chirho();
    let rows_chirho = (0..ACCOUNT_NET_PROJECTION_PAGE_ROWS_CHIRHO)
        .map(|index_chirho| {
            let owner_prefix_chirho = format!("{index_chirho:04}");
            let owner_chirho = format!(
                "{owner_prefix_chirho}{}",
                "\\".repeat(
                    cairn_ledger_model_chirho::wire_chirho::MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO
                        - owner_prefix_chirho.len()
                )
            );
            AccountNetProjectionRowChirho {
                account_chirho: AccountIdChirho {
                    owner_chirho,
                    kind_id_chirho: AssetKindIdChirho("\"".repeat(
                        cairn_ledger_model_chirho::wire_chirho::MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
                    )),
                },
                account_net_chirho: u64::MAX,
            }
        })
        .collect::<Vec<_>>();

    let complete_chirho = complete_root_chirho(
        stage_next_gd7_winner_view_bundle_page_chirho(
            &storage_chirho,
            &authority_chirho,
            None,
            || Ok(snapshot_chirho),
            |_cursor_chirho| {
                Ok(AccountNetProjectionPageSliceChirho {
                    rows_chirho,
                    next_upper_exclusive_account_chirho: None,
                })
            },
        )
        .expect("stage one maximal wire-bounded page"),
    );
    let page_ref_chirho = complete_chirho
        .root_chirho()
        .lowest_page_ref_chirho
        .as_ref()
        .expect("nonempty maximal page has a ref");
    let page_chirho = load_verified_bundle_page_chirho(&storage_chirho, page_ref_chirho)
        .expect("reload maximal wire-bounded page");
    let bytes_chirho =
        canonical_json_chirho(&page_chirho.page_chirho).expect("encode maximal wire-bounded page");

    assert_eq!(
        page_chirho.page_chirho.rows_chirho.len(),
        ACCOUNT_NET_PROJECTION_PAGE_ROWS_CHIRHO
    );
    assert!(bytes_chirho.len() <= MAX_GD7_WINNER_VIEW_BUNDLE_PAGE_BYTES_CHIRHO);
}

#[test]
fn cut_change_and_missing_or_oversized_restart_refuse_before_extraction_chirho() {
    let (_root_chirho, storage_chirho, _elector_chirho, authority_chirho, snapshot_chirho) =
        bundle_fixture_chirho();
    let rows_chirho = rows_chirho(257);
    let first_restart_chirho = continue_restart_chirho(
        stage_next_gd7_winner_view_bundle_page_chirho(
            &storage_chirho,
            &authority_chirho,
            None,
            || Ok(snapshot_chirho.clone()),
            |cursor_chirho| Ok(page_slice_chirho(&rows_chirho, cursor_chirho)),
        )
        .expect("stage first cut-bound page"),
    );

    let mut changed_snapshot_chirho = snapshot_chirho.clone();
    changed_snapshot_chirho.cut_chirho.seq_chirho += 1;
    changed_snapshot_chirho.cut_chirho.record_digest_chirho = "53".repeat(32);
    let extraction_called_chirho = Cell::new(false);
    assert_eq!(
        stage_next_gd7_winner_view_bundle_page_chirho(
            &storage_chirho,
            &authority_chirho,
            Some(&first_restart_chirho),
            || Ok(changed_snapshot_chirho),
            |_cursor_chirho| {
                extraction_called_chirho.set(true);
                Ok(page_slice_chirho(&rows_chirho, None))
            },
        )
        .unwrap_err(),
        Gd7WinnerCurrentViewRefusalChirho::JournalCutMismatchChirho
    );
    assert!(!extraction_called_chirho.get());

    let tampered_page_path_chirho =
        gd7_winner_view_bundle_page_path_chirho(first_restart_chirho.page_ref_chirho())
            .expect("derive staged page path");
    storage_chirho
        .atomic_write_chirho(&tampered_page_path_chirho, b"{\"tampered_chirho\":true}")
        .expect("tamper staged page bytes");
    assert_eq!(
        stage_next_gd7_winner_view_bundle_page_chirho(
            &storage_chirho,
            &authority_chirho,
            Some(&first_restart_chirho),
            || Ok(snapshot_chirho.clone()),
            |_cursor_chirho| panic!("tampered restart must refuse before page extraction"),
        )
        .unwrap_err(),
        Gd7WinnerCurrentViewRefusalChirho::ObjectDigestMismatchChirho
    );

    assert_eq!(
        load_verified_bundle_page_chirho(&storage_chirho, &"aa".repeat(32)).unwrap_err(),
        Gd7WinnerCurrentViewRefusalChirho::MissingBundlePageChirho
    );

    let oversized_digest_chirho = "bb".repeat(32);
    let oversized_path_chirho = gd7_winner_view_bundle_page_path_chirho(&oversized_digest_chirho)
        .expect("derive oversized page path");
    storage_chirho
        .atomic_write_chirho(
            &oversized_path_chirho,
            &vec![b'x'; MAX_GD7_WINNER_VIEW_BUNDLE_PAGE_BYTES_CHIRHO + 1],
        )
        .expect("write oversized test page");
    assert_eq!(
        load_verified_bundle_page_chirho(&storage_chirho, &oversized_digest_chirho).unwrap_err(),
        Gd7WinnerCurrentViewRefusalChirho::OversizedBundlePageChirho
    );
}
