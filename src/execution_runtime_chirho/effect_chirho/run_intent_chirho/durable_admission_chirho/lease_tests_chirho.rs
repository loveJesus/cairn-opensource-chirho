// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_ledger_elected_head_transition_chirho::ElectedHeadTransitionRefusalChirho;
use cairn_writer_elector_chirho::monotonic_clock_chirho::FakeMonotonicClockChirho;
use std::cell::RefCell;
use std::sync::Arc;

struct ExpiryHoldChirho {
    point_chirho: SinkPointChirho,
    clock_chirho: Arc<FakeMonotonicClockChirho>,
    elapsed_chirho: u64,
}

std::thread_local! {
    static EXPIRY_HOLD_CHIRHO: RefCell<Option<ExpiryHoldChirho>> = const { RefCell::new(None) };
    static EXPIRY_FIRED_CHIRHO: Cell<bool> = const { Cell::new(false) };
    static EXPIRY_SNAPSHOT_CHIRHO: RefCell<Option<BTreeMap<PathBuf, String>>> = const { RefCell::new(None) };
}

struct ExpiryResetChirho;

impl Drop for ExpiryResetChirho {
    fn drop(&mut self) {
        EXPIRY_HOLD_CHIRHO.with(|hold_chirho| *hold_chirho.borrow_mut() = None);
        EXPIRY_FIRED_CHIRHO.with(|fired_chirho| fired_chirho.set(false));
        EXPIRY_SNAPSHOT_CHIRHO.with(|snapshot_chirho| *snapshot_chirho.borrow_mut() = None);
    }
}

fn arm_expiry_chirho(
    point_chirho: SinkPointChirho,
    clock_chirho: &Arc<FakeMonotonicClockChirho>,
    elapsed_chirho: u64,
) -> ExpiryResetChirho {
    EXPIRY_HOLD_CHIRHO.with(|hold_chirho| {
        assert!(hold_chirho.borrow().is_none());
        *hold_chirho.borrow_mut() = Some(ExpiryHoldChirho {
            point_chirho,
            clock_chirho: Arc::clone(clock_chirho),
            elapsed_chirho,
        });
    });
    ExpiryResetChirho
}

pub(super) fn hold_before_sink_chirho(root_chirho: &Path, point_chirho: SinkPointChirho) {
    EXPIRY_HOLD_CHIRHO.with(|hold_chirho| {
        let mut hold_chirho = hold_chirho.borrow_mut();
        if hold_chirho
            .as_ref()
            .is_some_and(|hold_chirho| hold_chirho.point_chirho == point_chirho)
        {
            let hold_chirho = hold_chirho.take().unwrap();
            EXPIRY_SNAPSHOT_CHIRHO.with(|files_chirho| {
                *files_chirho.borrow_mut() = Some(digest_snapshot_chirho(root_chirho));
            });
            hold_chirho
                .clock_chirho
                .advance_millis_chirho(hold_chirho.elapsed_chirho);
            EXPIRY_FIRED_CHIRHO.with(|fired_chirho| fired_chirho.set(true));
        }
    });
}

fn digest_snapshot_chirho(root_chirho: &Path) -> BTreeMap<PathBuf, String> {
    // Failure diagnostics must compare hashes, never dump the root's private key bytes.
    snapshot_chirho(root_chirho)
        .into_iter()
        .map(|(path_chirho, bytes_chirho)| (path_chirho, cas_chirho::hash_chirho(&bytes_chirho).0))
        .collect()
}

fn fixture_chirho(clock_chirho: &Arc<FakeMonotonicClockChirho>) -> FixtureChirho {
    let mut fixture_chirho = FixtureChirho::new_chirho();
    let group_chirho = consistency_group_for_root_chirho(&fixture_chirho.root_chirho).unwrap();
    let elector_chirho =
        RaftWriterElectorChirho::new_single_node_with_election_timeout_monotonic_leadership_lease_chirho(
            NodeIdChirho("a".repeat(64)),
            group_chirho,
            clock_chirho.clone(),
            std::time::Duration::from_millis(10),
        )
        .unwrap();
    elector_chirho.campaign_chirho().unwrap();
    clock_chirho.advance_millis_chirho(1);
    elector_chirho.tick_chirho();
    clock_chirho.advance_millis_chirho(100);
    elector_chirho.tick_chirho();
    assert_eq!(
        elector_chirho.current_lease_remaining_millis_chirho(),
        Some(100)
    );
    fixture_chirho.authority_chirho = ElectedHeadTransitionAdapterChirho::new_chirho(
        &fixture_chirho.root_chirho,
        elector_chirho.local_append_authority_handle_chirho(),
    )
    .unwrap();
    fixture_chirho.elector_chirho = Some(elector_chirho);
    fixture_chirho
}

fn assert_expired_sink_chirho(point_chirho: SinkPointChirho) {
    let clock_chirho = FakeMonotonicClockChirho::new_chirho();
    let fixture_chirho = fixture_chirho(&clock_chirho);
    let _reset_chirho = arm_expiry_chirho(point_chirho, &clock_chirho, 100);
    let bytes_chirho = b"encrypted request at expired sink chirho";
    let subject_chirho = "user/lease-chirho";
    let error_chirho = fixture_chirho
        .admit_chirho(subject_chirho, bytes_chirho)
        .unwrap_err();
    assert!(
        EXPIRY_FIRED_CHIRHO.with(Cell::get),
        "the clock must actually advance"
    );
    assert_eq!(
        error_chirho.downcast_ref::<ElectedHeadTransitionRefusalChirho>(),
        Some(&ElectedHeadTransitionRefusalChirho::LeaseExpiredChirho)
    );
    assert!(!run_intent_records_path_chirho(&fixture_chirho.root_chirho).exists());
    assert_eq!(
        digest_snapshot_chirho(&fixture_chirho.root_chirho),
        EXPIRY_SNAPSHOT_CHIRHO.with(|files_chirho| files_chirho.borrow().as_ref().unwrap().clone()),
        "no durable bytes may change after this checkpoint observes expiry",
    );
    let request_chirho = crate::dag_private_value_chirho::load_private_dag_value_bytes_chirho(
        &fixture_chirho.root_chirho,
        subject_chirho,
        &cas_chirho::hash_chirho(bytes_chirho),
    );
    if point_chirho == SinkPointChirho::StoreChirho {
        assert!(
            request_chirho.is_err(),
            "expiry before store must not persist the request"
        );
    } else {
        assert_eq!(
            request_chirho.unwrap(),
            bytes_chirho,
            "store completed before expiry; append must not follow it"
        );
        let files_chirho = snapshot_chirho(&fixture_chirho.root_chirho);
        assert!(!files_chirho.values().any(|value_chirho| value_chirho
            .windows(bytes_chirho.len())
            .any(|window_chirho| window_chirho == bytes_chirho)));
    }
}

#[test]
fn expiry_before_private_store_refuses_without_storing_the_request_chirho() {
    assert_expired_sink_chirho(SinkPointChirho::StoreChirho);
}

#[test]
fn expiry_before_pending_append_keeps_only_the_encrypted_request_chirho() {
    assert_expired_sink_chirho(SinkPointChirho::AppendChirho);
}

#[test]
fn admission_one_millisecond_before_the_deadline_still_verifies_chirho() {
    let clock_chirho = FakeMonotonicClockChirho::new_chirho();
    let fixture_chirho = fixture_chirho(&clock_chirho);
    let _reset_chirho = arm_expiry_chirho(SinkPointChirho::StoreChirho, &clock_chirho, 99);
    let record_chirho = fixture_chirho
        .admit_chirho("user/live-chirho", b"live request chirho")
        .unwrap();
    assert!(EXPIRY_FIRED_CHIRHO.with(Cell::get));
    assert_eq!(record_chirho.status_chirho, RUN_INTENT_PENDING_CHIRHO);
    verify_run_intent_records_chirho(&fixture_chirho.root_chirho).unwrap();
    assert_eq!(
        fixture_chirho
            .elector_chirho
            .as_ref()
            .unwrap()
            .current_lease_remaining_millis_chirho(),
        Some(1)
    );
}

#[test]
fn an_expired_acquisition_refuses_without_mutating_a_primed_root_chirho() {
    let clock_chirho = FakeMonotonicClockChirho::new_chirho();
    let fixture_chirho = fixture_chirho(&clock_chirho);
    let lock_chirho = format!(
        "run-intent-caller-key-v1-chirho:{}",
        caller_idempotency_key_digest_chirho(&fixture_chirho.caller_chirho).0
    );
    seqlog_chirho::with_named_lock_chirho(&fixture_chirho.root_chirho, &lock_chirho, || Ok(()))
        .unwrap();
    let before_chirho = digest_snapshot_chirho(&fixture_chirho.root_chirho);
    clock_chirho.advance_millis_chirho(100);
    let error_chirho = fixture_chirho
        .admit_chirho("user/expired-chirho", b"must not persist chirho")
        .unwrap_err();
    assert_eq!(
        error_chirho.downcast_ref::<ElectedHeadTransitionRefusalChirho>(),
        Some(&ElectedHeadTransitionRefusalChirho::LeaseExpiredChirho)
    );
    assert_eq!(
        digest_snapshot_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
}
