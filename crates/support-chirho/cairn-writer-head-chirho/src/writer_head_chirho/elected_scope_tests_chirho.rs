// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use std::cell::Cell;
use std::path::PathBuf;

fn elected_temp_root_chirho(label_chirho: &str) -> PathBuf {
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-writer-head-{label_chirho}-{}-{}",
        std::process::id(),
        now_ms_chirho()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    root_chirho
}

#[test]
fn elected_scope_reuses_current_refuses_stale_and_regrants_after_restart_chirho() {
    let root_chirho = elected_temp_root_chirho("elected-reuse");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let group_chirho = consistency_group_for_root_chirho(&root_chirho).unwrap();
    let (first_chirho, first_value_chirho) = with_reused_or_issued_elected_writer_fence_chirho(
        &root_chirho,
        &group_chirho,
        7,
        None,
        |_| Ok(11_u64),
    )
    .unwrap();
    let fence_path_chirho = writer_fence_path_chirho(&root_chirho, &group_chirho).unwrap();
    let first_bytes_chirho = std::fs::read(&fence_path_chirho).unwrap();

    let (reused_chirho, second_value_chirho) = with_reused_or_issued_elected_writer_fence_chirho(
        &root_chirho,
        &group_chirho,
        7,
        Some(&first_chirho),
        |_| Ok(12_u64),
    )
    .unwrap();
    assert_eq!(first_value_chirho, 11);
    assert_eq!(second_value_chirho, 12);
    assert_eq!(reused_chirho, first_chirho);
    assert_eq!(
        std::fs::read(&fence_path_chirho).unwrap(),
        first_bytes_chirho
    );

    let zero_term_error_chirho = with_reused_or_issued_elected_writer_fence_chirho(
        &root_chirho,
        &group_chirho,
        0,
        Some(&first_chirho),
        |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(
        zero_term_error_chirho.downcast_ref::<CompositeWriterEpochRefusalChirho>(),
        Some(&CompositeWriterEpochRefusalChirho::ZeroElectedTermChirho),
    );
    let forged_chirho = WriterFenceTokenChirho {
        group_chirho: group_chirho.clone(),
        epoch_chirho: 0,
        issued_at_ms_chirho: first_chirho.issued_at_ms_chirho,
    };
    let forged_error_chirho = with_reused_or_issued_elected_writer_fence_chirho(
        &root_chirho,
        &group_chirho,
        7,
        Some(&forged_chirho),
        |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(
        forged_error_chirho.downcast_ref::<WriterFenceVerifyErrorChirho>(),
        Some(&WriterFenceVerifyErrorChirho::ForgedEpochChirho),
    );

    let competing_chirho =
        issue_elected_writer_fence_chirho(&root_chirho, &group_chirho, 7).unwrap();
    let stale_action_ran_chirho = Cell::new(false);
    let stale_error_chirho = with_reused_or_issued_elected_writer_fence_chirho(
        &root_chirho,
        &group_chirho,
        7,
        Some(&first_chirho),
        |_| {
            stale_action_ran_chirho.set(true);
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(
        stale_error_chirho.downcast_ref::<WriterFenceVerifyErrorChirho>(),
        Some(&WriterFenceVerifyErrorChirho::StaleWriterFenceChirho),
    );
    assert!(!stale_action_ran_chirho.get());

    let (reissued_chirho, ()) = with_reused_or_issued_elected_writer_fence_chirho(
        &root_chirho,
        &group_chirho,
        7,
        None,
        |_| Ok(()),
    )
    .unwrap();
    assert!(reissued_chirho.epoch_chirho > competing_chirho.epoch_chirho);
    verify_writer_fence_chirho(&root_chirho, &group_chirho, &reissued_chirho).unwrap();

    std::fs::write(
        &fence_path_chirho,
        vec![b'x'; MAX_WRITER_FENCE_FILE_BYTES_CHIRHO + 1],
    )
    .unwrap();
    let action_ran_chirho = Cell::new(false);
    let oversized_error_chirho = with_reused_or_issued_elected_writer_fence_chirho(
        &root_chirho,
        &group_chirho,
        7,
        Some(&reissued_chirho),
        |_| {
            action_ran_chirho.set(true);
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(
        oversized_error_chirho.downcast_ref::<WriterFenceVerifyErrorChirho>(),
        Some(&WriterFenceVerifyErrorChirho::CorruptFenceFileChirho),
    );
    assert!(!action_ran_chirho.get());
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn pure_elected_fence_resolver_preserves_exact_state_and_restart_monotonicity_chirho() {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/pure-fence-root-chirho".to_owned(),
    };
    let first_chirho =
        prepare_reused_or_issued_elected_writer_fence_chirho(&group_chirho, 7, None, None, 7_000)
            .unwrap();
    assert_eq!(first_chirho.durable_state_epoch_before_chirho(), None);
    assert_eq!(first_chirho.token_chirho().issued_at_ms_chirho, 7_000);
    assert_eq!(
        split_writer_epoch_chirho(first_chirho.token_chirho().epoch_chirho),
        CompositeWriterEpochChirho {
            geo_term_chirho: 7,
            local_grant_seq_chirho: 0,
        }
    );
    let first_bytes_chirho = first_chirho
        .replacement_state_bytes_chirho()
        .unwrap()
        .to_vec();

    let reused_chirho = prepare_reused_or_issued_elected_writer_fence_chirho(
        &group_chirho,
        7,
        Some(first_chirho.token_chirho()),
        Some(&first_bytes_chirho),
        7_001,
    )
    .unwrap();
    assert_eq!(reused_chirho.token_chirho(), first_chirho.token_chirho());
    assert_eq!(reused_chirho.replacement_state_bytes_chirho(), None);
    assert_eq!(
        reused_chirho.durable_state_epoch_before_chirho(),
        Some(first_chirho.token_chirho().epoch_chirho)
    );

    let restarted_chirho = prepare_reused_or_issued_elected_writer_fence_chirho(
        &group_chirho,
        7,
        None,
        Some(&first_bytes_chirho),
        7_002,
    )
    .unwrap();
    assert_eq!(
        split_writer_epoch_chirho(restarted_chirho.token_chirho().epoch_chirho),
        CompositeWriterEpochChirho {
            geo_term_chirho: 7,
            local_grant_seq_chirho: 1,
        }
    );
    assert_eq!(restarted_chirho.token_chirho().issued_at_ms_chirho, 7_002);
    let restarted_bytes_chirho = restarted_chirho
        .replacement_state_bytes_chirho()
        .unwrap()
        .to_vec();
    let stale_error_chirho = prepare_reused_or_issued_elected_writer_fence_chirho(
        &group_chirho,
        7,
        Some(first_chirho.token_chirho()),
        Some(&restarted_bytes_chirho),
        7_003,
    )
    .unwrap_err();
    assert_eq!(
        stale_error_chirho.downcast_ref::<WriterFenceVerifyErrorChirho>(),
        Some(&WriterFenceVerifyErrorChirho::StaleWriterFenceChirho)
    );

    let next_term_chirho = prepare_reused_or_issued_elected_writer_fence_chirho(
        &group_chirho,
        8,
        None,
        Some(&restarted_bytes_chirho),
        8_000,
    )
    .unwrap();
    assert_eq!(
        split_writer_epoch_chirho(next_term_chirho.token_chirho().epoch_chirho),
        CompositeWriterEpochChirho {
            geo_term_chirho: 8,
            local_grant_seq_chirho: 0,
        }
    );
    assert_eq!(next_term_chirho.token_chirho().issued_at_ms_chirho, 8_000);
}

#[test]
fn pure_elected_fence_resolver_fails_closed_on_untrusted_bytes_chirho() {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/pure-fence-hostile-chirho".to_owned(),
    };
    for bytes_chirho in [
        b"not-json-chirho".to_vec(),
        vec![b'x'; MAX_WRITER_FENCE_FILE_BYTES_CHIRHO + 1],
    ] {
        let error_chirho = prepare_reused_or_issued_elected_writer_fence_chirho(
            &group_chirho,
            1,
            None,
            Some(&bytes_chirho),
            1_000,
        )
        .unwrap_err();
        assert_eq!(
            error_chirho.downcast_ref::<WriterFenceVerifyErrorChirho>(),
            Some(&WriterFenceVerifyErrorChirho::CorruptFenceFileChirho)
        );
    }
}
