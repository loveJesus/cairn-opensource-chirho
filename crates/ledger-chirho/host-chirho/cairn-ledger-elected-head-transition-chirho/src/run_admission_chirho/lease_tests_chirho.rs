// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::tests_chirho::temp_root_chirho;
use cairn_writer_elector_chirho::monotonic_clock_chirho::{
    FakeMonotonicClockChirho, MonotonicClockChirho,
};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::run_admission_authority_chirho::RunAdmissionCommitScopeChirho;
use cairn_writer_head_chirho::writer_head_chirho::issue_elected_writer_fence_for_root_chirho;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct FixtureChirho {
    root_chirho: PathBuf,
    elector_chirho: RaftWriterElectorChirho,
    adapter_chirho: ElectedHeadTransitionAdapterChirho,
    clock_chirho: Arc<FakeMonotonicClockChirho>,
}

impl FixtureChirho {
    fn new_chirho() -> Self {
        let root_chirho = temp_root_chirho("held-lease");
        std::fs::create_dir_all(&root_chirho).unwrap();
        let group_chirho = consistency_group_for_root_chirho(&root_chirho).unwrap();
        let clock_chirho = FakeMonotonicClockChirho::new_chirho();
        let elector_chirho = RaftWriterElectorChirho::new_single_node_with_election_timeout_monotonic_leadership_lease_chirho(
            NodeIdChirho("a".repeat(64)), group_chirho, clock_chirho.clone(), Duration::from_millis(10),
        ).unwrap();
        elector_chirho.campaign_chirho().unwrap();
        clock_chirho.advance_millis_chirho(1);
        elector_chirho.tick_chirho();
        clock_chirho.advance_millis_chirho(100);
        elector_chirho.tick_chirho();
        issue_elected_writer_fence_for_root_chirho(&root_chirho, 1).unwrap();
        let adapter_chirho = ElectedHeadTransitionAdapterChirho::new_chirho(
            &root_chirho,
            elector_chirho.local_append_authority_handle_chirho(),
        )
        .unwrap();
        Self {
            root_chirho,
            elector_chirho,
            adapter_chirho,
            clock_chirho,
        }
    }
}

impl Drop for FixtureChirho {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root_chirho).unwrap();
    }
}

#[test]
fn a_held_generation_expires_at_the_exact_deadline_without_a_tick_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let handle_chirho = fixture_chirho
        .elector_chirho
        .local_append_authority_handle_chirho();
    let guard_chirho = handle_chirho.try_acquire_chirho().unwrap();
    guard_chirho.validate_current_chirho().unwrap();
    fixture_chirho.clock_chirho.advance_millis_chirho(99);
    guard_chirho.validate_current_chirho().unwrap();
    fixture_chirho.clock_chirho.advance_millis_chirho(1);
    assert_eq!(
        guard_chirho.validate_current_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho)
    );
    drop(guard_chirho);
    assert!(
        matches!(
            handle_chirho.try_acquire_chirho(),
            Err(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho)
        ),
        "the guard is released, but expiry is not refreshed by checking"
    );
    fixture_chirho.elector_chirho.tick_chirho();
    handle_chirho
        .try_acquire_chirho()
        .unwrap()
        .validate_current_chirho()
        .unwrap();
}

struct ExpiryActionChirho<'action_chirho> {
    root_chirho: &'action_chirho Path,
    clock_chirho: &'action_chirho FakeMonotonicClockChirho,
    elapsed_chirho: u64,
    calls_chirho: usize,
}

impl RunAdmissionCommitActionChirho for ExpiryActionChirho<'_> {
    fn call_chirho(&mut self, scope_chirho: RunAdmissionCommitScopeChirho<'_>) -> Result<()> {
        self.calls_chirho += 1;
        scope_chirho.validate_sink_chirho(self.root_chirho)?;
        self.clock_chirho.advance_millis_chirho(self.elapsed_chirho);
        scope_chirho.validate_sink_chirho(self.root_chirho)
    }
}

#[test]
fn expiry_inside_the_callback_refuses_then_releases_generation_and_fence_cache_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let mut action_chirho = ExpiryActionChirho {
        root_chirho: &fixture_chirho.root_chirho,
        clock_chirho: &fixture_chirho.clock_chirho,
        elapsed_chirho: 100,
        calls_chirho: 0,
    };
    let error_chirho = fixture_chirho
        .adapter_chirho
        .with_elected_run_admission_scope_chirho(&fixture_chirho.root_chirho, &mut action_chirho)
        .unwrap_err();
    assert_eq!(action_chirho.calls_chirho, 1);
    assert_eq!(
        error_chirho.downcast_ref::<ElectedHeadTransitionRefusalChirho>(),
        Some(&ElectedHeadTransitionRefusalChirho::LeaseExpiredChirho)
    );
    let handle_chirho = fixture_chirho
        .elector_chirho
        .local_append_authority_handle_chirho();
    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho)
    ));
    fixture_chirho.elector_chirho.tick_chirho();
    action_chirho.elapsed_chirho = 0;
    fixture_chirho
        .adapter_chirho
        .with_elected_run_admission_scope_chirho(&fixture_chirho.root_chirho, &mut action_chirho)
        .unwrap();
    assert_eq!(action_chirho.calls_chirho, 2);
}

#[derive(Debug)]
struct RegressingClockChirho(AtomicU64);

impl MonotonicClockChirho for RegressingClockChirho {
    fn now_millis_chirho(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

#[test]
fn a_held_generation_refuses_a_clock_before_its_confirmation_chirho() {
    let clock_chirho = Arc::new(RegressingClockChirho(AtomicU64::new(1_000)));
    let elector_chirho = RaftWriterElectorChirho::new_single_node_with_election_timeout_monotonic_leadership_lease_chirho(
        NodeIdChirho("b".repeat(64)),
        ConsistencyGroupIdChirho::RootPathChirho { canonical_root_chirho: "/held-clock-regression-chirho".to_owned() },
        clock_chirho.clone(), Duration::from_millis(10),
    ).unwrap();
    elector_chirho.campaign_chirho().unwrap();
    elector_chirho.tick_chirho();
    for now_chirho in [1_100, 1_200] {
        clock_chirho.0.store(now_chirho, Ordering::Release);
        elector_chirho.tick_chirho();
    }
    let handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    let guard_chirho = handle_chirho.try_acquire_chirho().unwrap();
    guard_chirho.validate_current_chirho().unwrap();
    clock_chirho.0.store(1_150, Ordering::Release);
    assert_eq!(
        guard_chirho.validate_current_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho)
    );
}
