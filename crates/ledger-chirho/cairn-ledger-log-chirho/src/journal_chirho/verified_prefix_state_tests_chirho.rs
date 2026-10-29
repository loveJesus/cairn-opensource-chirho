// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::journal_chirho::{
    JournalErrorChirho, LedgerJournalChirho, ReadOnlyRecoveryReasonChirho,
};
use crate::journal_tests_chirho::{mint_request_chirho, HarnessChirho, MONEY_KIND_CHIRHO};
use crate::ports_chirho::LedgerStoragePortChirho;
use crate::verified_prefix_state_chirho::{
    open_read_only_verified_prefix_state_chirho, open_read_only_verified_tail_cut_chirho,
    LedgerPrefixCutChirho,
};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::LogIdChirho;

#[test]
fn verified_prefix_state_binds_an_interior_cut_without_writes_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut journal_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        7,
    )
    .expect("create prefix-state journal");
    harness_chirho.clock_chirho.now_ms_chirho.set(1_001);
    let alice_receipt_chirho = journal_chirho
        .append_chirho(mint_request_chirho(
            "alice-chirho",
            100,
            "prefix-alice-chirho",
        ))
        .expect("append prefix alice");
    harness_chirho.clock_chirho.now_ms_chirho.set(1_002);
    let bob_receipt_chirho = journal_chirho
        .append_chirho(mint_request_chirho("bob-chirho", 40, "prefix-bob-chirho"))
        .expect("append suffix bob");
    drop(journal_chirho);

    let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();
    let prefix_chirho = open_read_only_verified_prefix_state_chirho(
        harness_chirho.ports_chirho(),
        &harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
        &LedgerPrefixCutChirho::new_chirho(
            7,
            alice_receipt_chirho.seq_chirho,
            alice_receipt_chirho.record_digest_chirho.clone(),
        ),
    )
    .expect("verify the interior prefix");

    assert_eq!(prefix_chirho.prefix_cut_chirho().seq_chirho(), 1);
    assert_eq!(
        prefix_chirho.prefix_cut_chirho().record_digest_chirho(),
        &alice_receipt_chirho.record_digest_chirho
    );
    assert_eq!(
        prefix_chirho.source_tail_cut_chirho().seq_chirho(),
        bob_receipt_chirho.seq_chirho
    );
    assert_eq!(
        prefix_chirho
            .source_tail_cut_chirho()
            .record_digest_chirho(),
        &bob_receipt_chirho.record_digest_chirho
    );
    assert_eq!(
        prefix_chirho
            .head_states_chirho()
            .get(&LogIdChirho::new_chirho("alice-chirho", MONEY_KIND_CHIRHO))
            .expect("alice is in the prefix")
            .credits_total_chirho,
        100
    );
    assert!(
        !prefix_chirho
            .head_states_chirho()
            .contains_key(&LogIdChirho::new_chirho("bob-chirho", MONEY_KIND_CHIRHO)),
        "a post-cut account must not enter the prefix state"
    );
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho(),
        writes_before_chirho,
        "prefix verification must not gain repair or write authority"
    );
}

#[test]
fn verified_prefix_state_refuses_a_wrong_interior_digest_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut journal_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        9,
    )
    .expect("create prefix-state refusal journal");
    harness_chirho.clock_chirho.now_ms_chirho.set(1_001);
    let receipt_chirho = journal_chirho
        .append_chirho(mint_request_chirho(
            "alice-chirho",
            100,
            "prefix-refusal-chirho",
        ))
        .expect("append prefix refusal record");
    drop(journal_chirho);

    let error_chirho = open_read_only_verified_prefix_state_chirho(
        harness_chirho.ports_chirho(),
        &harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
        &LedgerPrefixCutChirho::new_chirho(
            9,
            receipt_chirho.seq_chirho,
            DigestChirho("f".repeat(64)),
        ),
    )
    .expect_err("wrong prefix digest must refuse");
    assert!(matches!(
        error_chirho,
        JournalErrorChirho::ChainChirho { detail_chirho }
            if detail_chirho.contains("requested prefix cut")
    ));
}

#[test]
fn verified_tail_cut_refuses_corrupt_history_instead_of_wrapping_it_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut journal_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        11,
    )
    .expect("create verified-tail refusal journal");
    harness_chirho.clock_chirho.now_ms_chirho.set(1_001);
    journal_chirho
        .append_chirho(mint_request_chirho(
            "alice-chirho",
            100,
            "tail-cut-corrupt-chirho",
        ))
        .expect("append verified-tail refusal record");
    drop(journal_chirho);

    let journal_path_chirho = harness_chirho.path_chirho();
    let mut journal_bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&journal_path_chirho)
        .expect("read journal bytes")
        .expect("journal bytes exist");
    let journal_text_chirho =
        String::from_utf8(journal_bytes_chirho.clone()).expect("fixture journal bytes are UTF-8");
    let tail_signature_index_chirho = journal_text_chirho
        .rmatch_indices("fake-sig-")
        .next()
        .expect("fixture tail carries a fake signature")
        .0;
    journal_bytes_chirho
        [tail_signature_index_chirho..tail_signature_index_chirho + "fake-sig-".len()]
        .copy_from_slice(b"fake-SIG-");
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&journal_path_chirho, &journal_bytes_chirho)
        .expect("write corrupt journal bytes");

    assert_eq!(
        open_read_only_verified_tail_cut_chirho(
            harness_chirho.ports_chirho(),
            &journal_path_chirho,
            &harness_chirho.cluster_chirho(),
        ),
        Err(JournalErrorChirho::TailSignatureInvalidChirho)
    );
}

#[test]
fn verified_tail_cut_refuses_a_torn_tail_by_recovery_identity_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut journal_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        11,
    )
    .expect("create torn verified-tail refusal journal");
    harness_chirho.clock_chirho.now_ms_chirho.set(1_001);
    journal_chirho
        .append_chirho(mint_request_chirho(
            "alice-chirho",
            100,
            "tail-cut-torn-chirho",
        ))
        .expect("append torn verified-tail refusal record");
    drop(journal_chirho);

    let journal_path_chirho = harness_chirho.path_chirho();
    let mut journal_bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&journal_path_chirho)
        .expect("read journal bytes")
        .expect("journal bytes exist");
    journal_bytes_chirho.truncate(
        journal_bytes_chirho
            .len()
            .checked_sub(5)
            .expect("fixture tail is longer than truncation"),
    );
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&journal_path_chirho, &journal_bytes_chirho)
        .expect("write torn journal bytes");

    assert_eq!(
        open_read_only_verified_tail_cut_chirho(
            harness_chirho.ports_chirho(),
            &journal_path_chirho,
            &harness_chirho.cluster_chirho(),
        ),
        Err(JournalErrorChirho::ReadOnlyRecoveryRequiredChirho {
            reason_chirho: ReadOnlyRecoveryReasonChirho::TornTailChirho,
        })
    );
}
