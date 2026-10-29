// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! The recovery revalidation retry, driven by scripted attempts: what waits, what does not, and what
//! the tally says.

use super::*;
use cairn_writer_elector_chirho::LocalAppendAuthorityRefusalChirho as LocalChirho;
use std::cell::Cell;
use std::collections::VecDeque;

/// Run a scripted sequence of attempt outcomes through the retry. Returns the outcome, the tally,
/// how many attempts ran and how many pauses were requested.
fn run_script_chirho(
    script_chirho: Vec<Result<u64, RecoveryRevalidationRefusalChirho>>,
) -> (
    Result<u64, RecoveryRevalidationRefusalChirho>,
    RecoveryContentionTallyChirho,
    usize,
    usize,
) {
    let mut script_chirho: VecDeque<_> = script_chirho.into();
    let attempts_chirho = Cell::new(0usize);
    let pauses_chirho = Cell::new(0usize);
    let (outcome_chirho, tally_chirho) = retry_recovery_revalidation_chirho(
        || {
            attempts_chirho.set(attempts_chirho.get() + 1);
            script_chirho
                .pop_front()
                .expect("the script covers every attempt the retry makes")
        },
        || pauses_chirho.set(pauses_chirho.get() + 1),
    );
    (
        outcome_chirho,
        tally_chirho,
        attempts_chirho.get(),
        pauses_chirho.get(),
    )
}

fn slot_chirho(refusal_chirho: LocalChirho) -> RecoveryRevalidationRefusalChirho {
    RecoveryRevalidationRefusalChirho::SlotChirho(
        ResidentAppendBarrierRefusalChirho::LocalRecoverySlotChirho(refusal_chirho),
    )
}

fn acquire_chirho(refusal_chirho: LocalChirho) -> RecoveryRevalidationRefusalChirho {
    RecoveryRevalidationRefusalChirho::LocalAuthorityChirho(refusal_chirho)
}

const NON_TRANSIENT_LOCAL_CHIRHO: [LocalChirho; 12] = [
    LocalChirho::AuthorityPoisonedChirho,
    LocalChirho::ElectorDroppedChirho,
    LocalChirho::AuthorityUnavailableChirho,
    LocalChirho::NotLocalLeaderChirho,
    LocalChirho::WarmupLeaseInvalidChirho,
    LocalChirho::NotPromotableVoterChirho,
    LocalChirho::LeadershipTransferInProgressChirho,
    LocalChirho::HandoffActiveChirho,
    LocalChirho::HandoffIdentityMismatchChirho,
    LocalChirho::InvalidHandoffIdentityChirho,
    LocalChirho::HandoffGenerationExhaustedChirho,
    LocalChirho::PublishedRaftTermOutOfRangeChirho,
];

#[test]
fn contention_from_either_source_is_waited_out_and_the_whole_check_runs_again_chirho() {
    // Both sources, both contention identities: the slot probe and the acquire each refuse with a
    // pending transition or a busy guard. Each is retried, and success needs a fresh attempt.
    let (outcome_chirho, tally_chirho, attempts_chirho, pauses_chirho) = run_script_chirho(vec![
        Err(slot_chirho(LocalChirho::TransitionPendingChirho)),
        Err(slot_chirho(LocalChirho::GuardBusyChirho)),
        Err(acquire_chirho(LocalChirho::TransitionPendingChirho)),
        Err(acquire_chirho(LocalChirho::GuardBusyChirho)),
        Ok(7),
    ]);
    assert_eq!(outcome_chirho.expect("the fifth attempt succeeds"), 7);
    assert_eq!(attempts_chirho, 5);
    assert_eq!(pauses_chirho, 4);
    assert_eq!(
        tally_chirho,
        RecoveryContentionTallyChirho {
            contended_attempts_chirho: 4,
            pauses_chirho: 4,
        }
    );
}

#[test]
fn an_uncontended_revalidation_neither_pauses_nor_reports_chirho() {
    let (outcome_chirho, tally_chirho, attempts_chirho, pauses_chirho) =
        run_script_chirho(vec![Ok(1)]);
    assert_eq!(outcome_chirho.expect("one clean attempt"), 1);
    assert_eq!((attempts_chirho, pauses_chirho), (1, 0));
    assert_eq!(tally_chirho.contended_attempts_chirho, 0);
}

#[test]
fn permanent_contention_spends_the_attempt_budget_and_refuses_with_its_identity_chirho() {
    // The budget is attempts, not time: it ends even if no clock ever advances. The final attempt is
    // counted as contended and is followed by no pause, so the tally names both numbers.
    let budget_chirho = RESIDENT_GENERATION_CONTENTION_ATTEMPTS_CHIRHO;
    let (outcome_chirho, tally_chirho, attempts_chirho, pauses_chirho) = run_script_chirho(
        (0..budget_chirho)
            .map(|_attempt_chirho| Err(slot_chirho(LocalChirho::TransitionPendingChirho)))
            .collect(),
    );
    assert!(matches!(
        outcome_chirho,
        Err(RecoveryRevalidationRefusalChirho::SlotChirho(
            ResidentAppendBarrierRefusalChirho::LocalRecoverySlotChirho(
                LocalChirho::TransitionPendingChirho
            )
        ))
    ));
    assert_eq!(attempts_chirho, budget_chirho);
    assert_eq!(pauses_chirho, budget_chirho - 1);
    assert_eq!(
        tally_chirho,
        RecoveryContentionTallyChirho {
            contended_attempts_chirho: budget_chirho,
            pauses_chirho: budget_chirho - 1,
        }
    );
}

#[test]
fn an_authority_refusal_after_contention_stops_at_once_with_no_further_pause_chirho() {
    // Waiting must never outlive a real refusal: the attempt after the pause re-ran the authority
    // check, it refused, and nothing more runs.
    let (outcome_chirho, tally_chirho, attempts_chirho, pauses_chirho) = run_script_chirho(vec![
        Err(acquire_chirho(LocalChirho::TransitionPendingChirho)),
        Err(RecoveryRevalidationRefusalChirho::AuthorityChirho(
            "LedgerMirrorRecoveryCandidateAuthorityExpiredChirho".to_owned(),
        )),
    ]);
    match outcome_chirho {
        Err(RecoveryRevalidationRefusalChirho::AuthorityChirho(detail_chirho)) => {
            assert_eq!(
                detail_chirho,
                "LedgerMirrorRecoveryCandidateAuthorityExpiredChirho"
            )
        }
        other_chirho => panic!("expected the authority refusal, got {other_chirho:?}"),
    }
    assert_eq!((attempts_chirho, pauses_chirho), (2, 1));
    assert_eq!(tally_chirho.contended_attempts_chirho, 1);
}

#[test]
fn every_non_transient_local_refusal_returns_on_the_first_attempt_from_either_source_chirho() {
    for refusal_chirho in NON_TRANSIENT_LOCAL_CHIRHO {
        for wrapped_chirho in [slot_chirho(refusal_chirho), acquire_chirho(refusal_chirho)] {
            let label_chirho = wrapped_chirho.to_string();
            let (outcome_chirho, tally_chirho, attempts_chirho, pauses_chirho) =
                run_script_chirho(vec![Err(wrapped_chirho)]);
            assert!(outcome_chirho.is_err(), "{label_chirho} must refuse");
            assert_eq!(
                (
                    attempts_chirho,
                    pauses_chirho,
                    tally_chirho.contended_attempts_chirho
                ),
                (1, 0, 0),
                "{label_chirho} must not wait"
            );
        }
    }
}

#[test]
fn durable_owner_refusals_and_authority_refusals_never_wait_chirho() {
    for refusal_chirho in [
        RecoveryRevalidationRefusalChirho::SlotChirho(
            ResidentAppendBarrierRefusalChirho::Gd7RecoveryOwnerActiveChirho,
        ),
        RecoveryRevalidationRefusalChirho::SlotChirho(
            ResidentAppendBarrierRefusalChirho::MigrationRecoveryOwnerActiveChirho,
        ),
        RecoveryRevalidationRefusalChirho::SlotChirho(
            ResidentAppendBarrierRefusalChirho::TwoActiveDurableOwnersChirho,
        ),
        RecoveryRevalidationRefusalChirho::AuthorityChirho(
            "LedgerMirrorRecoveryCandidateAssignmentExpiredChirho".to_owned(),
        ),
    ] {
        assert_eq!(refusal_chirho.local_refusal_chirho(), None);
        let (outcome_chirho, _tally_chirho, attempts_chirho, pauses_chirho) =
            run_script_chirho(vec![Err(refusal_chirho)]);
        assert!(outcome_chirho.is_err());
        assert_eq!((attempts_chirho, pauses_chirho), (1, 0));
    }
}
