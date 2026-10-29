// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::{retry_resident_generation_contention_chirho, ResidentLedgerAuthorityRefusalChirho};
use cairn_writer_elector_chirho::LocalAppendAuthorityRefusalChirho;
use std::collections::VecDeque;

#[test]
fn both_resident_open_generation_brackets_use_the_contention_retry_chirho() {
    let source_chirho = include_str!("resident_mutation_chirho/authority_open_view_chirho.rs");
    let acquisition_chirho = "acquire_resident_startup_generation_chirho(&local_authority_chirho)";
    assert_eq!(
        source_chirho.matches(acquisition_chirho).count(),
        2,
        "the initial and final resident-open generation acquisitions must both retry only bounded contention"
    );
}

#[test]
fn local_generation_display_names_the_preserved_refusal_identity_chirho() {
    let error_chirho = ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho {
        reason_chirho: LocalAppendAuthorityRefusalChirho::TransitionPendingChirho,
    };
    assert_eq!(
        error_chirho.to_string(),
        "resident authority local generation was refused: a local Raft transition is pending"
    );
}

#[test]
fn startup_retries_only_self_clearing_generation_contention_chirho() {
    let mut outcomes_chirho = VecDeque::from([
        Err(LocalAppendAuthorityRefusalChirho::TransitionPendingChirho),
        Err(LocalAppendAuthorityRefusalChirho::GuardBusyChirho),
        Ok(73_u64),
    ]);
    let mut acquire_count_chirho = 0_usize;
    let mut pause_count_chirho = 0_usize;

    let mut observed_chirho = Vec::new();
    let accepted_chirho = retry_resident_generation_contention_chirho(
        || {
            acquire_count_chirho += 1;
            outcomes_chirho
                .pop_front()
                .expect("canned startup acquisition outcome remains")
        },
        |reason_chirho| Some(*reason_chirho),
        |reason_chirho| observed_chirho.push(reason_chirho),
        || pause_count_chirho += 1,
        4,
    )
    .expect("self-clearing contention reaches the successful generation");

    assert_eq!(accepted_chirho, 73);
    assert_eq!(acquire_count_chirho, 3);
    assert_eq!(pause_count_chirho, 2);
    assert_eq!(
        observed_chirho,
        [
            LocalAppendAuthorityRefusalChirho::TransitionPendingChirho,
            LocalAppendAuthorityRefusalChirho::GuardBusyChirho,
        ]
    );
}

#[test]
fn startup_propagates_every_non_contention_refusal_without_retry_chirho() {
    let terminal_refusals_chirho = [
        LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho,
        LocalAppendAuthorityRefusalChirho::ElectorDroppedChirho,
        LocalAppendAuthorityRefusalChirho::AuthorityUnavailableChirho,
        LocalAppendAuthorityRefusalChirho::NotLocalLeaderChirho,
        LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho,
        LocalAppendAuthorityRefusalChirho::NotPromotableVoterChirho,
        LocalAppendAuthorityRefusalChirho::LeadershipTransferInProgressChirho,
        LocalAppendAuthorityRefusalChirho::HandoffActiveChirho,
        LocalAppendAuthorityRefusalChirho::HandoffIdentityMismatchChirho,
        LocalAppendAuthorityRefusalChirho::InvalidHandoffIdentityChirho,
        LocalAppendAuthorityRefusalChirho::HandoffGenerationExhaustedChirho,
        LocalAppendAuthorityRefusalChirho::PublishedRaftTermOutOfRangeChirho,
    ];

    for refusal_chirho in terminal_refusals_chirho {
        let mut acquire_count_chirho = 0_usize;
        let actual_chirho = retry_resident_generation_contention_chirho::<(), _>(
            || {
                acquire_count_chirho += 1;
                Err(refusal_chirho)
            },
            |reason_chirho| Some(*reason_chirho),
            |_reason_chirho| panic!("non-contention refusal must not be observed as contention"),
            || panic!("non-contention refusal must not pause or retry"),
            4,
        )
        .expect_err("non-contention refusal remains terminal");
        assert_eq!(actual_chirho, refusal_chirho);
        assert_eq!(acquire_count_chirho, 1);
    }
}

#[test]
fn startup_contention_retry_stops_at_its_exact_attempt_bound_chirho() {
    let mut acquire_count_chirho = 0_usize;
    let mut pause_count_chirho = 0_usize;
    let mut observed_chirho = Vec::new();
    let refusal_chirho = retry_resident_generation_contention_chirho::<(), _>(
        || {
            acquire_count_chirho += 1;
            Err(LocalAppendAuthorityRefusalChirho::TransitionPendingChirho)
        },
        |reason_chirho| Some(*reason_chirho),
        |reason_chirho| observed_chirho.push(reason_chirho),
        || pause_count_chirho += 1,
        3,
    )
    .expect_err("persistent contention refuses at the bounded attempt");

    assert_eq!(
        refusal_chirho,
        LocalAppendAuthorityRefusalChirho::TransitionPendingChirho
    );
    assert_eq!(acquire_count_chirho, 3);
    assert_eq!(pause_count_chirho, 2);
    assert_eq!(
        observed_chirho,
        [LocalAppendAuthorityRefusalChirho::TransitionPendingChirho; 3]
    );
}
