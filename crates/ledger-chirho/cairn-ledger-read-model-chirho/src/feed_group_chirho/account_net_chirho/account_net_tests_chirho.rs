// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::test_support_chirho::{
    mint_request_chirho, AllMembersChirho, MemStorageChirho, OpenAuthorityChirho,
    OpenRegistryChirho, StepClockChirho, TestSignerChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::AssetKindIdChirho;
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use std::cell::Cell;

fn account_chirho(owner_chirho: &str) -> AccountIdChirho {
    AccountIdChirho {
        owner_chirho: owner_chirho.to_owned(),
        kind_id_chirho: AssetKindIdChirho("prepaid-credit-chirho".to_owned()),
    }
}

#[test]
fn account_net_view_reuses_money_state_and_is_canonical_chirho() {
    let mut heads_chirho = BTreeMap::new();
    heads_chirho.insert(
        account_chirho("bob-chirho"),
        LegPostStateChirho {
            credits_total_chirho: 90,
            debits_total_chirho: 10,
            held_chirho: 70,
        },
    );
    heads_chirho.insert(
        account_chirho("alice-chirho"),
        LegPostStateChirho {
            credits_total_chirho: 600,
            debits_total_chirho: 25,
            held_chirho: 400,
        },
    );
    let view_chirho = account_net_view_from_verified_heads_chirho(&heads_chirho).unwrap();
    assert_eq!(
        view_chirho.rows_chirho[0].account_chirho.owner_chirho,
        "alice-chirho"
    );
    assert_eq!(view_chirho.rows_chirho[0].account_net_chirho, 575);
    assert_eq!(view_chirho.rows_chirho[1].account_net_chirho, 80);

    let bytes_chirho = canonical_account_net_projection_view_chirho(&view_chirho).unwrap();
    assert_eq!(
        bytes_chirho,
        br#"{"rows_chirho":[{"account_chirho":{"kind_id_chirho":"prepaid-credit-chirho","owner_chirho":"alice-chirho"},"account_net_chirho":575},{"account_chirho":{"kind_id_chirho":"prepaid-credit-chirho","owner_chirho":"bob-chirho"},"account_net_chirho":80}],"schema_chirho":"ledger-account-net-projection-view-v1-chirho"}"#
    );
    assert_eq!(
        parse_canonical_account_net_projection_view_chirho(&bytes_chirho).unwrap(),
        view_chirho
    );
    let typed_order_chirho = br#"{"schema_chirho":"ledger-account-net-projection-view-v1-chirho","rows_chirho":[{"account_chirho":{"owner_chirho":"alice-chirho","kind_id_chirho":"prepaid-credit-chirho"},"account_net_chirho":575},{"account_chirho":{"owner_chirho":"bob-chirho","kind_id_chirho":"prepaid-credit-chirho"},"account_net_chirho":80}]}"#;
    assert!(parse_canonical_account_net_projection_view_chirho(typed_order_chirho).is_err());

    let mut noncanonical_chirho = bytes_chirho.clone();
    noncanonical_chirho.push(b'\n');
    assert!(parse_canonical_account_net_projection_view_chirho(&noncanonical_chirho).is_err());
}

#[test]
fn account_net_view_refuses_negative_verified_state_chirho() {
    let mut heads_chirho = BTreeMap::new();
    heads_chirho.insert(
        account_chirho("alice-chirho"),
        LegPostStateChirho {
            credits_total_chirho: 9,
            debits_total_chirho: 10,
            held_chirho: 0,
        },
    );
    assert!(account_net_view_from_verified_heads_chirho(&heads_chirho).is_err());
}

#[test]
fn account_net_fold_consumes_verified_journal_state_chirho() {
    let storage_chirho = MemStorageChirho::default();
    let signer_chirho = TestSignerChirho {
        name_chirho: "account-net-journal-root-chirho",
    };
    let clock_chirho = StepClockChirho {
        now_ms_chirho: Cell::new(1_000),
    };
    let membership_chirho = AllMembersChirho;
    let registry_chirho = OpenRegistryChirho;
    let authority_chirho = OpenAuthorityChirho;
    let ports_chirho = JournalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: &signer_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &registry_chirho,
        authority_chirho: &authority_chirho,
    };
    let mut journal_chirho = LedgerJournalChirho::create_chirho(
        ports_chirho,
        StoragePathChirho("journals/account-net-chirho.jsonl".to_owned()),
        ClusterIdChirho("account-net-cluster-chirho".to_owned()),
        1,
    )
    .unwrap();
    journal_chirho
        .append_chirho(mint_request_chirho(
            "alice-chirho",
            600,
            "account-net-mint-chirho",
        ))
        .unwrap();

    let source_chirho = VerifiedSourceStateChirho {
        journal_chirho: &journal_chirho,
    };
    let bytes_chirho = AccountNetProjectionFoldChirho
        .fold_chirho(&source_chirho)
        .unwrap();
    let view_chirho = parse_canonical_account_net_projection_view_chirho(&bytes_chirho).unwrap();
    assert_eq!(view_chirho.rows_chirho.len(), 1);
    assert_eq!(view_chirho.rows_chirho[0].account_net_chirho, 600);
}

#[test]
fn account_net_fold_and_source_refs_are_stable_distinct_digests_chirho() {
    let fold_chirho = account_net_projection_fold_ref_chirho();
    let source_chirho = account_net_source_schema_ref_chirho();
    assert_eq!(fold_chirho.0.len(), 64);
    assert_eq!(source_chirho.0.len(), 64);
    assert_ne!(fold_chirho, source_chirho);
}

#[test]
fn account_net_pages_are_fixed_bounded_exact_and_canonical_chirho() {
    let mut heads_chirho = BTreeMap::new();
    for index_chirho in 0..513_u64 {
        heads_chirho.insert(
            account_chirho(&format!("account-{index_chirho:04}-chirho")),
            LegPostStateChirho {
                credits_total_chirho: index_chirho + 1,
                debits_total_chirho: 0,
                held_chirho: 0,
            },
        );
    }

    let first_chirho =
        account_net_projection_page_from_verified_heads_chirho(&heads_chirho, None).unwrap();
    assert_eq!(
        first_chirho.rows_chirho.len(),
        ACCOUNT_NET_PROJECTION_PAGE_ROWS_CHIRHO
    );
    assert_eq!(
        first_chirho.rows_chirho.first().unwrap().account_chirho,
        account_chirho("account-0257-chirho")
    );
    assert_eq!(
        first_chirho.rows_chirho.last().unwrap().account_chirho,
        account_chirho("account-0512-chirho")
    );
    let first_cursor_chirho = first_chirho
        .next_upper_exclusive_account_chirho
        .as_ref()
        .unwrap();
    assert_eq!(*first_cursor_chirho, account_chirho("account-0257-chirho"));

    let second_chirho = account_net_projection_page_from_verified_heads_chirho(
        &heads_chirho,
        Some(first_cursor_chirho),
    )
    .unwrap();
    assert_eq!(
        second_chirho.rows_chirho.len(),
        ACCOUNT_NET_PROJECTION_PAGE_ROWS_CHIRHO
    );
    assert_eq!(
        second_chirho.rows_chirho.first().unwrap().account_chirho,
        account_chirho("account-0001-chirho")
    );
    assert_eq!(
        second_chirho.rows_chirho.last().unwrap().account_chirho,
        account_chirho("account-0256-chirho")
    );
    let second_cursor_chirho = second_chirho
        .next_upper_exclusive_account_chirho
        .as_ref()
        .unwrap();
    assert_eq!(*second_cursor_chirho, account_chirho("account-0001-chirho"));

    let third_chirho = account_net_projection_page_from_verified_heads_chirho(
        &heads_chirho,
        Some(second_cursor_chirho),
    )
    .unwrap();
    assert_eq!(third_chirho.rows_chirho.len(), 1);
    assert_eq!(
        third_chirho.rows_chirho[0].account_chirho,
        account_chirho("account-0000-chirho")
    );
    assert!(third_chirho.next_upper_exclusive_account_chirho.is_none());

    let reconstructed_chirho = third_chirho
        .rows_chirho
        .iter()
        .chain(second_chirho.rows_chirho.iter())
        .chain(first_chirho.rows_chirho.iter())
        .map(|row_chirho| row_chirho.account_chirho.clone())
        .collect::<Vec<_>>();
    assert_eq!(reconstructed_chirho.len(), heads_chirho.len());
    assert!(reconstructed_chirho
        .windows(2)
        .all(|pair_chirho| pair_chirho[0] < pair_chirho[1]));
}

#[test]
fn account_net_page_boundaries_cover_empty_one_and_exact_page_chirho() {
    let empty_chirho = BTreeMap::new();
    let empty_page_chirho =
        account_net_projection_page_from_verified_heads_chirho(&empty_chirho, None).unwrap();
    assert!(empty_page_chirho.rows_chirho.is_empty());
    assert!(empty_page_chirho
        .next_upper_exclusive_account_chirho
        .is_none());

    let mut exact_chirho = BTreeMap::new();
    for index_chirho in 0..ACCOUNT_NET_PROJECTION_PAGE_ROWS_CHIRHO {
        exact_chirho.insert(
            account_chirho(&format!("exact-{index_chirho:04}-chirho")),
            LegPostStateChirho {
                credits_total_chirho: 1,
                debits_total_chirho: 0,
                held_chirho: 0,
            },
        );
    }
    let exact_page_chirho =
        account_net_projection_page_from_verified_heads_chirho(&exact_chirho, None).unwrap();
    assert_eq!(
        exact_page_chirho.rows_chirho.len(),
        ACCOUNT_NET_PROJECTION_PAGE_ROWS_CHIRHO
    );
    assert!(exact_page_chirho
        .next_upper_exclusive_account_chirho
        .is_none());
}

#[test]
fn account_net_page_reapplies_the_ledger_identifier_bound_chirho() {
    let mut heads_chirho = BTreeMap::new();
    heads_chirho.insert(
        AccountIdChirho {
            owner_chirho: "x".repeat(
                cairn_ledger_model_chirho::wire_chirho::MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO + 1,
            ),
            kind_id_chirho: AssetKindIdChirho("prepaid-credit-chirho".to_owned()),
        },
        LegPostStateChirho {
            credits_total_chirho: 1,
            debits_total_chirho: 0,
            held_chirho: 0,
        },
    );

    assert!(
        account_net_projection_page_from_verified_heads_chirho(&heads_chirho, None).is_err(),
        "a forged unbounded head coordinate must fail before page serialization"
    );
}
