// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! Recovery revalidation against a real elector: a tick queued behind another thread's guard is
//! waited out, a guard at another term refuses, a caller holding a guard refuses instead of hanging,
//! and a same-term membership change refuses before the guard and waits after it (A6-c).

use super::*;
use crate::resident_authority_chirho::RESIDENT_GENERATION_CONTENTION_ATTEMPTS_CHIRHO;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::LocalAppendAuthorityRefusalChirho;
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Mutex;
use std::time::Duration;

/// How long an arm here may run before its watchdog counts it as hung.
const HANG_BUDGET_CHIRHO: Duration = Duration::from_secs(60);

/// Makes a hang fail loudly. `cargo test` has no per-test timeout, so a deadlocked arm would hang the
/// suite rather than fail it. These arms keep their borrowed fixture on the test thread, so the work
/// cannot move to a worker that a `recv_timeout` abandons. Instead, a detached thread waits on a
/// channel and ABORTS the test binary if the arm has not finished within its budget. Dropping the
/// watchdog disconnects the channel and stands it down. That happens at the end of the arm, or while
/// a panic unwinds, after every scoped thread has been joined.
///
/// The reason is written to the raw stderr handle, not with `eprintln!`. The test harness captures
/// `eprintln!` from threads a test spawns and prints it only when that test finishes, and an abort
/// means it never finishes. Measured with the lock-order mutant: the binary died on SIGABRT and the
/// `eprintln!` line was gone, which leaves a reader a signal with no reason.
struct HangWatchdogChirho {
    _armed_chirho: mpsc::Sender<()>,
}

impl HangWatchdogChirho {
    fn arm_chirho(arm_chirho: &'static str) -> Self {
        let (armed_chirho, disarmed_chirho) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            if let Err(RecvTimeoutError::Timeout) = disarmed_chirho.recv_timeout(HANG_BUDGET_CHIRHO)
            {
                let _reported_chirho = writeln!(
                    std::io::stderr(),
                    "HangWatchdogChirho: {arm_chirho} ran past {HANG_BUDGET_CHIRHO:?}; aborting \
                     the test binary so the hang fails instead of stalling the suite"
                );
                std::process::abort();
            }
        });
        Self {
            _armed_chirho: armed_chirho,
        }
    }
}

/// The candidate port, with the production port's lock footprint added. Production revalidation
/// first joins the elector's current view, and that join takes the `RawNode` lock. Suppose a local
/// transition ever locked the node BEFORE announcing itself to append admission. A transition queued
/// behind a held guard would then hold the node lock, this join would block on it, and the arm would
/// hang into its watchdog instead of passing (claude2 #29674).
struct ElectorJoiningRecoveryPortChirho<'port_chirho> {
    candidate_port_chirho: &'port_chirho TestRecoveryPortChirho,
    elector_chirho: &'port_chirho RaftWriterElectorChirho,
}

impl LedgerMirrorRecoveryPortChirho for ElectorJoiningRecoveryPortChirho<'_> {
    fn select_recovery_candidate_chirho(
        &self,
        local_tail_chirho: &LedgerAppendMirrorTailChirho,
        local_source_chirho: &dyn LedgerMirrorPrefixSourceChirho,
    ) -> std::result::Result<
        Option<LedgerMirrorRecoveryCandidateChirho>,
        LedgerMirrorRecoveryPortErrorChirho,
    > {
        self.candidate_port_chirho
            .select_recovery_candidate_chirho(local_tail_chirho, local_source_chirho)
    }

    fn revalidate_recovery_authority_chirho(
        &self,
        candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
    ) -> std::result::Result<(), LedgerMirrorRecoveryPortErrorChirho> {
        // The lock is the point. What this single-node fixture's view says is not under test.
        let _joined_view_chirho = self.elector_chirho.current_election_observation_chirho();
        self.candidate_port_chirho
            .revalidate_recovery_authority_chirho(candidate_chirho)
    }

    fn read_recovery_record_chirho(
        &self,
        candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
        seq_chirho: u64,
        record_digest_chirho: &str,
    ) -> std::result::Result<Vec<u8>, LedgerMirrorRecoveryPortErrorChirho> {
        self.candidate_port_chirho.read_recovery_record_chirho(
            candidate_chirho,
            seq_chirho,
            record_digest_chirho,
        )
    }

    fn ensure_verified_prefix_bootstrapped_chirho(
        &self,
        source_tail_chirho: &LedgerAppendMirrorTailChirho,
        source_chirho: &dyn LedgerMirrorPrefixSourceChirho,
    ) -> std::result::Result<(), LedgerMirrorRecoveryPortErrorChirho> {
        self.candidate_port_chirho
            .ensure_verified_prefix_bootstrapped_chirho(source_tail_chirho, source_chirho)
    }
}

fn effect_context_chirho<'context_chirho>(
    fixture_chirho: &StagingFixtureChirho<'context_chirho>,
    pause_chirho: &'context_chirho (dyn Fn() + Sync),
) -> ResidentRecoveryEffectContextChirho<'context_chirho> {
    ResidentRecoveryEffectContextChirho {
        storage_chirho: fixture_chirho.storage_chirho,
        gd7_store_chirho: fixture_chirho.gd7_store_chirho,
        migration_store_chirho: None,
        handoff_control_chirho: fixture_chirho.handoff_control_chirho,
        local_authority_chirho: fixture_chirho.local_authority_chirho,
        contention_pause_chirho: pause_chirho,
    }
}

/// Spin until a local transition has announced itself to append admission. Before that, a held guard
/// makes acquisition refuse `GuardBusyChirho`. From then until the transition publishes, every
/// acquisition refuses `TransitionPendingChirho`.
fn wait_until_transition_announced_chirho(authority_chirho: &LocalAppendAuthorityHandleChirho) {
    loop {
        match authority_chirho
            .try_acquire_chirho()
            .map(|_guard_chirho| ())
        {
            Err(LocalAppendAuthorityRefusalChirho::TransitionPendingChirho) => return,
            Err(LocalAppendAuthorityRefusalChirho::GuardBusyChirho) => std::thread::yield_now(),
            other_chirho => {
                panic!("expected a held guard or an announced transition, got {other_chirho:?}")
            }
        }
    }
}

#[test]
fn a_tick_queued_behind_another_threads_guard_is_waited_out_and_the_whole_check_reruns_chirho() {
    let _watchdog_chirho = HangWatchdogChirho::arm_chirho("the hold-and-release arm");
    with_staging_fixture_named_chirho("recovery-contention-hold-release", |fixture_chirho| {
        let authority_chirho = fixture_chirho.local_authority_chirho;
        let elector_chirho = fixture_chirho.elector_chirho;
        let port_chirho = ElectorJoiningRecoveryPortChirho {
            candidate_port_chirho: fixture_chirho.recovery_chirho,
            elector_chirho,
        };
        let (held_sender_chirho, held_chirho) = mpsc::channel::<()>();
        let (release_sender_chirho, release_chirho) = mpsc::channel::<()>();
        let (ticked_sender_chirho, ticked_chirho) = mpsc::channel::<()>();
        std::thread::scope(|scope_chirho| {
            // Another thread's append is in flight and holds the only guard until it is released.
            scope_chirho.spawn(move || {
                let guard_chirho = authority_chirho
                    .try_acquire_chirho()
                    .expect("the warm elector grants the in-flight append its guard");
                held_sender_chirho.send(()).unwrap();
                // A disconnect releases too, so a failing arm unwinds instead of hanging here.
                let _released_chirho = release_chirho.recv();
                drop(guard_chirho);
            });
            held_chirho.recv().unwrap();
            // A clock tick arrives, and it must wait for that guard.
            scope_chirho.spawn(move || {
                let _outbound_chirho = elector_chirho.tick_chirho();
                let _published_chirho = ticked_sender_chirho.send(());
            });
            wait_until_transition_announced_chirho(authority_chirho);

            // The third pause releases the append and waits until the tick has published. So
            // attempts one to three meet the pending tick, and the fourth is the first that can pass.
            let pauses_chirho = AtomicUsize::new(0);
            let release_sender_chirho = Mutex::new(Some(release_sender_chirho));
            let ticked_chirho = Mutex::new(ticked_chirho);
            let pause_chirho = || {
                if pauses_chirho.fetch_add(1, Ordering::SeqCst) + 1 == 3 {
                    if let Some(sender_chirho) = release_sender_chirho.lock().unwrap().take() {
                        sender_chirho.send(()).unwrap();
                    }
                    ticked_chirho.lock().unwrap().recv().unwrap();
                }
            };
            let context_chirho = effect_context_chirho(&fixture_chirho, &pause_chirho);
            let guard_chirho = revalidate_before_recovery_effect_chirho(
                &port_chirho,
                fixture_chirho.candidate_chirho,
                &context_chirho,
            )
            .expect("a tick queued behind another thread's guard is waited out");
            assert_eq!(
                guard_chirho.published_raft_term_chirho(),
                fixture_chirho.candidate_chirho.current_term_chirho()
            );
            drop(guard_chirho);
            assert_eq!(pauses_chirho.load(Ordering::SeqCst), 3);
            assert_eq!(
                fixture_chirho.recovery_chirho.revalidation_calls_chirho(),
                5,
                "each attempt reran the whole check, starting with the port's authority, and the \
                 attempt that acquired checked it once more under the guard"
            );
        });
    });
}

#[test]
fn a_guard_at_another_term_than_the_candidates_refuses_and_never_waits_chirho() {
    with_staging_fixture_named_chirho("recovery-contention-term-binding", |fixture_chirho| {
        // The candidate was validated at a term the local guard does not carry.
        let stale_candidate_chirho =
            candidate_edited_chirho(fixture_chirho.candidate_chirho, |input_chirho| {
                input_chirho.current_term_chirho += 1;
            });
        let stale_port_chirho =
            TestRecoveryPortChirho::new_chirho(stale_candidate_chirho.clone(), BTreeMap::new());
        let pauses_chirho = AtomicUsize::new(0);
        let pause_chirho = || {
            pauses_chirho.fetch_add(1, Ordering::SeqCst);
        };
        let context_chirho = effect_context_chirho(&fixture_chirho, &pause_chirho);
        let refusal_chirho = match revalidate_before_recovery_effect_chirho(
            &stale_port_chirho,
            &stale_candidate_chirho,
            &context_chirho,
        ) {
            Ok(_guard_chirho) => panic!("a guard at another term than the candidate's must refuse"),
            Err(refusal_chirho) => refusal_chirho,
        };
        assert_eq!(
            refusal_chirho.to_string(),
            "LedgerMirrorRecoveryAuthorityTermChangedChirho"
        );
        assert_eq!(pauses_chirho.load(Ordering::SeqCst), 0);
        assert_eq!(
            stale_port_chirho.revalidation_calls_chirho(),
            2,
            "the port passed both checks; the term binding refused after them"
        );
        drop(
            fixture_chirho
                .local_authority_chirho
                .try_acquire_chirho()
                .expect("the refused guard was released with its refusal"),
        );
    });
}

#[test]
fn a_caller_holding_a_guard_refuses_at_the_attempt_budget_instead_of_hanging_chirho() {
    let _watchdog_chirho = HangWatchdogChirho::arm_chirho("the held-guard caller arm");
    with_staging_fixture_named_chirho("recovery-contention-held-guard", |fixture_chirho| {
        let authority_chirho = fixture_chirho.local_authority_chirho;
        let elector_chirho = fixture_chirho.elector_chirho;
        let port_chirho = ElectorJoiningRecoveryPortChirho {
            candidate_port_chirho: fixture_chirho.recovery_chirho,
            elector_chirho,
        };
        // This caller breaks the documented invariant: it holds a guard on the revalidating thread.
        let held_guard_chirho = authority_chirho
            .try_acquire_chirho()
            .expect("the warm elector grants the caller a guard");
        std::thread::scope(|scope_chirho| {
            let tick_chirho = scope_chirho.spawn(move || {
                let _outbound_chirho = elector_chirho.tick_chirho();
            });
            wait_until_transition_announced_chirho(authority_chirho);
            let pauses_chirho = AtomicUsize::new(0);
            let pause_chirho = || {
                pauses_chirho.fetch_add(1, Ordering::SeqCst);
            };
            let context_chirho = effect_context_chirho(&fixture_chirho, &pause_chirho);
            let outcome_chirho = revalidate_before_recovery_effect_chirho(
                &port_chirho,
                fixture_chirho.candidate_chirho,
                &context_chirho,
            );
            // Let go before asserting, so a failed assertion unwinds instead of waiting on the tick.
            drop(held_guard_chirho);
            let refusal_chirho = match outcome_chirho {
                Ok(_guard_chirho) => panic!("a caller holding a guard must not get another"),
                Err(refusal_chirho) => refusal_chirho,
            };
            assert_eq!(
                refusal_chirho
                    .downcast_ref::<RecoveryRevalidationRefusalChirho>()
                    .expect("the refusal keeps its typed identity")
                    .local_refusal_chirho(),
                Some(LocalAppendAuthorityRefusalChirho::TransitionPendingChirho)
            );
            assert_eq!(
                pauses_chirho.load(Ordering::SeqCst),
                RESIDENT_GENERATION_CONTENTION_ATTEMPTS_CHIRHO - 1
            );
            assert_eq!(
                fixture_chirho.recovery_chirho.revalidation_calls_chirho(),
                RESIDENT_GENERATION_CONTENTION_ATTEMPTS_CHIRHO
            );
            tick_chirho
                .join()
                .expect("the queued tick publishes once the caller lets go");
        });
        drop(
            authority_chirho
                .try_acquire_chirho()
                .expect("the published tick left the authority grantable"),
        );
    });
}

/// The membership a candidate's authority rests on, as the elector's coherent observation reports it:
/// the authenticated roster, the voters, the learners, and the applied configuration index.
type MembershipViewChirho = (Vec<(u64, NodeIdChirho)>, Vec<u64>, Vec<u64>, u64);

fn membership_view_chirho(elector_chirho: &RaftWriterElectorChirho) -> MembershipViewChirho {
    let observation_chirho = elector_chirho
        .current_election_observation_chirho()
        .expect("the elector reports a coherent observation");
    (
        observation_chirho.authenticated_members_chirho().to_vec(),
        observation_chirho.voter_raft_ids_chirho().to_vec(),
        observation_chirho.learner_raft_ids_chirho().to_vec(),
        observation_chirho.applied_conf_index_chirho(),
    )
}

fn elected_term_chirho(elector_chirho: &RaftWriterElectorChirho) -> u64 {
    elector_chirho
        .current_election_observation_chirho()
        .expect("the elector reports a coherent observation")
        .leadership_chirho()
        .term_chirho
}

/// A raft id and an identity the roster does not already hold.
fn fresh_member_chirho(roster_chirho: &[(u64, NodeIdChirho)]) -> (u64, NodeIdChirho) {
    let raft_id_chirho = roster_chirho
        .iter()
        .map(|(raft_id_chirho, _)| *raft_id_chirho)
        .max()
        .unwrap_or(0)
        + 1;
    let node_chirho = ["b", "c", "d", "e"]
        .iter()
        .map(|digit_chirho| NodeIdChirho(digit_chirho.repeat(64)))
        .find(|candidate_chirho| {
            roster_chirho
                .iter()
                .all(|(_, member_chirho)| member_chirho != candidate_chirho)
        })
        .expect("one of four identities is free");
    (raft_id_chirho, node_chirho)
}

fn add_fresh_learner_chirho(elector_chirho: &RaftWriterElectorChirho) {
    let (learner_chirho, _) = fresh_member_chirho(&elector_chirho.authenticated_members_chirho());
    elector_chirho
        .add_learner_chirho(learner_chirho)
        .expect("the leader proposes a learner");
}

fn add_fresh_roster_member_chirho(elector_chirho: &RaftWriterElectorChirho) {
    let mut roster_chirho = elector_chirho.authenticated_members_chirho();
    roster_chirho.push(fresh_member_chirho(&roster_chirho));
    elector_chirho
        .update_members_chirho(roster_chirho)
        .expect("a valid roster update applies");
}

/// The candidate port, made to refuse membership drift as the production port's view-digest
/// comparison does. Its first revalidation pins the elector's membership and then lets one same-term
/// change land, before the caller acquires its guard. Every later revalidation refuses if the
/// membership moved. Each call also records whether a local guard was held while it ran.
struct DriftingRecoveryPortChirho<'port_chirho> {
    candidate_port_chirho: &'port_chirho TestRecoveryPortChirho,
    elector_chirho: &'port_chirho RaftWriterElectorChirho,
    authority_chirho: &'port_chirho LocalAppendAuthorityHandleChirho,
    drift_chirho: fn(&RaftWriterElectorChirho),
    pinned_chirho: Mutex<Option<MembershipViewChirho>>,
    under_guard_chirho: Mutex<Vec<bool>>,
}

impl LedgerMirrorRecoveryPortChirho for DriftingRecoveryPortChirho<'_> {
    fn select_recovery_candidate_chirho(
        &self,
        local_tail_chirho: &LedgerAppendMirrorTailChirho,
        local_source_chirho: &dyn LedgerMirrorPrefixSourceChirho,
    ) -> std::result::Result<
        Option<LedgerMirrorRecoveryCandidateChirho>,
        LedgerMirrorRecoveryPortErrorChirho,
    > {
        self.candidate_port_chirho
            .select_recovery_candidate_chirho(local_tail_chirho, local_source_chirho)
    }

    fn revalidate_recovery_authority_chirho(
        &self,
        candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
    ) -> std::result::Result<(), LedgerMirrorRecoveryPortErrorChirho> {
        // Admission never blocks, so this probe cannot wait. A busy refusal means a guard is held,
        // and in these arms only the caller ever holds one.
        let under_guard_chirho = matches!(
            self.authority_chirho
                .try_acquire_chirho()
                .map(|_probe_chirho| ()),
            Err(LocalAppendAuthorityRefusalChirho::GuardBusyChirho)
        );
        self.under_guard_chirho
            .lock()
            .unwrap()
            .push(under_guard_chirho);
        self.candidate_port_chirho
            .revalidate_recovery_authority_chirho(candidate_chirho)?;
        let current_chirho = membership_view_chirho(self.elector_chirho);
        let mut pinned_chirho = self.pinned_chirho.lock().unwrap();
        let Some(pinned_view_chirho) = pinned_chirho.as_ref() else {
            *pinned_chirho = Some(current_chirho.clone());
            drop(pinned_chirho);
            (self.drift_chirho)(self.elector_chirho);
            assert_ne!(
                membership_view_chirho(self.elector_chirho),
                current_chirho,
                "the drift must move the membership, or the arm proves nothing"
            );
            return Ok(());
        };
        if *pinned_view_chirho == current_chirho {
            Ok(())
        } else {
            Err(LedgerMirrorRecoveryPortErrorChirho::new_chirho(
                "LedgerMirrorRecoveryCandidateAuthorityExpiredChirho",
            ))
        }
    }

    fn read_recovery_record_chirho(
        &self,
        candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
        seq_chirho: u64,
        record_digest_chirho: &str,
    ) -> std::result::Result<Vec<u8>, LedgerMirrorRecoveryPortErrorChirho> {
        self.candidate_port_chirho.read_recovery_record_chirho(
            candidate_chirho,
            seq_chirho,
            record_digest_chirho,
        )
    }

    fn ensure_verified_prefix_bootstrapped_chirho(
        &self,
        source_tail_chirho: &LedgerAppendMirrorTailChirho,
        source_chirho: &dyn LedgerMirrorPrefixSourceChirho,
    ) -> std::result::Result<(), LedgerMirrorRecoveryPortErrorChirho> {
        self.candidate_port_chirho
            .ensure_verified_prefix_bootstrapped_chirho(source_tail_chirho, source_chirho)
    }
}

/// The first interval (gpt #29658): a same-term change between the first check and the acquisition
/// keeps the term, so the term binding cannot see it. The check under the guard must refuse it, as an
/// authority refusal that releases the guard and is not retried.
fn same_term_drift_before_acquisition_refuses_under_the_guard_chirho(
    label_chirho: &'static str,
    drift_chirho: fn(&RaftWriterElectorChirho),
) {
    // The drift is a local transition. Were the first check ever run under a guard, it would wait on
    // that guard, so a hang here is a lock-order failure and must abort, not stall the suite.
    let _watchdog_chirho = HangWatchdogChirho::arm_chirho(label_chirho);
    with_staging_fixture_named_chirho(label_chirho, |fixture_chirho| {
        let elector_chirho = fixture_chirho.elector_chirho;
        let term_before_chirho = elected_term_chirho(elector_chirho);
        let port_chirho = DriftingRecoveryPortChirho {
            candidate_port_chirho: fixture_chirho.recovery_chirho,
            elector_chirho,
            authority_chirho: fixture_chirho.local_authority_chirho,
            drift_chirho,
            pinned_chirho: Mutex::new(None),
            under_guard_chirho: Mutex::new(Vec::new()),
        };
        let pauses_chirho = AtomicUsize::new(0);
        let pause_chirho = || {
            pauses_chirho.fetch_add(1, Ordering::SeqCst);
        };
        let context_chirho = effect_context_chirho(&fixture_chirho, &pause_chirho);
        let refusal_chirho = match revalidate_before_recovery_effect_chirho(
            &port_chirho,
            fixture_chirho.candidate_chirho,
            &context_chirho,
        ) {
            Ok(_guard_chirho) => {
                panic!("a same-term membership change before acquisition must refuse")
            }
            Err(refusal_chirho) => refusal_chirho,
        };
        assert!(
            matches!(
                refusal_chirho.downcast_ref::<RecoveryRevalidationRefusalChirho>(),
                Some(RecoveryRevalidationRefusalChirho::AuthorityChirho(detail_chirho))
                    if detail_chirho == "LedgerMirrorRecoveryCandidateAuthorityExpiredChirho"
            ),
            "{refusal_chirho:#}"
        );
        assert_eq!(
            *port_chirho.under_guard_chirho.lock().unwrap(),
            vec![false, true],
            "the first check ran before the guard, and the refusing one under it"
        );
        assert_eq!(
            pauses_chirho.load(Ordering::SeqCst),
            0,
            "an authority refusal is not retried"
        );
        assert_eq!(
            elected_term_chirho(elector_chirho),
            term_before_chirho,
            "the drift kept the term, which is why the term binding alone cannot see it"
        );
        drop(
            fixture_chirho
                .local_authority_chirho
                .try_acquire_chirho()
                .expect("the refused guard was released with its refusal"),
        );
    });
}

#[test]
fn a_same_term_conf_change_before_acquisition_refuses_under_the_guard_chirho() {
    same_term_drift_before_acquisition_refuses_under_the_guard_chirho(
        "recovery-drift-conf-change",
        add_fresh_learner_chirho,
    );
}

#[test]
fn a_same_term_roster_update_before_acquisition_refuses_under_the_guard_chirho() {
    same_term_drift_before_acquisition_refuses_under_the_guard_chirho(
        "recovery-drift-roster",
        add_fresh_roster_member_chirho,
    );
}

/// The first interval at the effect itself (gpt #29847): the drifted candidate is refused before the
/// first staged byte, and the selected resident journal is untouched.
#[test]
fn a_same_term_conf_change_refuses_before_the_first_staged_byte_chirho() {
    let _watchdog_chirho = HangWatchdogChirho::arm_chirho("recovery-drift-staging");
    with_staging_fixture_named_chirho("recovery-drift-staging", |fixture_chirho| {
        let port_chirho = DriftingRecoveryPortChirho {
            candidate_port_chirho: fixture_chirho.recovery_chirho,
            elector_chirho: fixture_chirho.elector_chirho,
            authority_chirho: fixture_chirho.local_authority_chirho,
            drift_chirho: add_fresh_learner_chirho,
            pinned_chirho: Mutex::new(None),
            under_guard_chirho: Mutex::new(Vec::new()),
        };
        let pause_chirho = || {};
        let context_chirho = effect_context_chirho(&fixture_chirho, &pause_chirho);
        let refusal_chirho = match stage_candidate_records_chirho(
            &context_chirho,
            &port_chirho,
            fixture_chirho.candidate_chirho,
            fixture_chirho.binding_digest_chirho,
        ) {
            Ok(_staged_chirho) => panic!("a drifted candidate must stage nothing"),
            Err(refusal_chirho) => refusal_chirho,
        };
        assert!(
            format!("{refusal_chirho:#}")
                .contains("LedgerMirrorRecoveryCandidateAuthorityExpiredChirho"),
            "{refusal_chirho:#}"
        );
        assert_eq!(
            *port_chirho.under_guard_chirho.lock().unwrap(),
            vec![false, true],
            "the refusal came from the check under the guard"
        );
        assert!(
            fixture_chirho
                .storage_chirho
                .list_chirho(&StoragePathChirho::new_chirho(format!(
                    "{RECOVERY_ROOT_CHIRHO}/{RECOVERY_STAGING_DIR_CHIRHO}/{}/",
                    fixture_chirho.binding_digest_chirho
                )))
                .unwrap()
                .is_empty(),
            "nothing was staged"
        );
        assert_eq!(
            fixture_chirho
                .storage_chirho
                .read_all_chirho(fixture_chirho.source_path_chirho)
                .unwrap(),
            Some(fixture_chirho.original_journal_bytes_chirho.to_vec()),
            "the selected resident journal is untouched"
        );
    });
}

/// The second interval: once the check under the guard has passed, a membership change parks behind
/// the recovery guard until it drops, so the effect commits against the view that check saw.
fn membership_change_waits_while_the_recovery_guard_is_held_chirho(
    label_chirho: &'static str,
    change_chirho: fn(&RaftWriterElectorChirho),
) {
    let _watchdog_chirho = HangWatchdogChirho::arm_chirho(label_chirho);
    with_staging_fixture_named_chirho(label_chirho, |fixture_chirho| {
        let authority_chirho = fixture_chirho.local_authority_chirho;
        let elector_chirho = fixture_chirho.elector_chirho;
        let port_chirho = ElectorJoiningRecoveryPortChirho {
            candidate_port_chirho: fixture_chirho.recovery_chirho,
            elector_chirho,
        };
        let pause_chirho = || {};
        let context_chirho = effect_context_chirho(&fixture_chirho, &pause_chirho);
        let guard_chirho = revalidate_before_recovery_effect_chirho(
            &port_chirho,
            fixture_chirho.candidate_chirho,
            &context_chirho,
        )
        .expect("an undrifted candidate revalidates");
        let view_under_guard_chirho = membership_view_chirho(elector_chirho);
        std::thread::scope(|scope_chirho| {
            let change_thread_chirho = scope_chirho.spawn(|| change_chirho(elector_chirho));
            // Wait for the change to announce itself, or to finish without waiting at all. The
            // second is the failure this arm exists for, so it must fail an assertion, not hang.
            while !change_thread_chirho.is_finished() {
                match authority_chirho
                    .try_acquire_chirho()
                    .map(|_probe_chirho| ())
                {
                    Err(LocalAppendAuthorityRefusalChirho::TransitionPendingChirho) => break,
                    Err(LocalAppendAuthorityRefusalChirho::GuardBusyChirho) => {
                        std::thread::yield_now()
                    }
                    other_chirho => {
                        panic!(
                            "expected the held guard or an announced change, got {other_chirho:?}"
                        )
                    }
                }
            }
            assert_eq!(
                membership_view_chirho(elector_chirho),
                view_under_guard_chirho,
                "the view the check under the guard saw holds while the guard is held"
            );
            assert!(
                !change_thread_chirho.is_finished(),
                "the change is parked behind the recovery guard"
            );
            drop(guard_chirho);
            change_thread_chirho
                .join()
                .expect("the parked change applies once the guard drops");
        });
        assert_ne!(
            membership_view_chirho(elector_chirho),
            view_under_guard_chirho,
            "control: the parked change did land"
        );
        drop(
            authority_chirho
                .try_acquire_chirho()
                .expect("the change republished usable authority"),
        );
    });
}

#[test]
fn a_conf_change_waits_while_the_recovery_guard_is_held_chirho() {
    membership_change_waits_while_the_recovery_guard_is_held_chirho(
        "recovery-parked-conf-change",
        add_fresh_learner_chirho,
    );
}

#[test]
fn a_roster_update_waits_while_the_recovery_guard_is_held_chirho() {
    membership_change_waits_while_the_recovery_guard_is_held_chirho(
        "recovery-parked-roster",
        add_fresh_roster_member_chirho,
    );
}
