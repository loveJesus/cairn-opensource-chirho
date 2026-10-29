// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_ledger_elected_head_transition_chirho::ElectedHeadTransitionAdapterChirho;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_for_root_chirho, issue_elected_writer_fence_for_root_chirho,
    verify_writer_fence_for_root_chirho, writer_fence_path_chirho,
};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

struct FixtureChirho {
    root_chirho: PathBuf,
    dag_chirho: HashChirho,
    elector_chirho: Option<RaftWriterElectorChirho>,
    authority_chirho: ElectedHeadTransitionAdapterChirho,
    caller_chirho: CallerIdempotencyKeyChirho,
}

impl FixtureChirho {
    fn new_chirho() -> Self {
        Self::with_era_chirho(true)
    }

    fn with_era_chirho(elected_chirho: bool) -> Self {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let root_chirho = std::env::temp_dir().join(format!(
            "durable-run-admission-{}-{}-chirho",
            std::process::id(),
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root_chirho).unwrap();
        let dag_chirho = store_chirho::put_object_chirho(
            &root_chirho,
            &DagChirho {
                nodes_chirho: vec![],
                edges_chirho: vec![],
            },
        )
        .unwrap();
        let group_chirho = consistency_group_for_root_chirho(&root_chirho).unwrap();
        let elector_chirho = RaftWriterElectorChirho::new_single_node_chirho(
            NodeIdChirho("a".repeat(64)),
            group_chirho,
        )
        .unwrap()
        .with_leadership_warmup_lease_chirho();
        elector_chirho.campaign_chirho().unwrap();
        for _tick_chirho in 0..10 {
            elector_chirho.tick_chirho();
        }
        if elected_chirho {
            issue_elected_writer_fence_for_root_chirho(&root_chirho, 1).unwrap();
        }
        let authority_chirho = ElectedHeadTransitionAdapterChirho::new_chirho(
            &root_chirho,
            elector_chirho.local_append_authority_handle_chirho(),
        )
        .unwrap();
        Self {
            root_chirho,
            dag_chirho,
            elector_chirho: Some(elector_chirho),
            authority_chirho,
            caller_chirho: CallerIdempotencyKeyChirho::new_chirho("admission-fixture-0001-chirho")
                .unwrap(),
        }
    }

    fn admit_chirho(
        &self,
        subject_chirho: &str,
        bytes_chirho: &[u8],
    ) -> Result<RunIntentRecordChirho> {
        // These fixtures admit a user's own private request with no context, so they declare its owner.
        let declared_chirho =
            crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                subject_chirho,
            );
        admit_private_run_intent_chirho(
            &self.root_chirho,
            &self.authority_chirho,
            PrivateRunAdmissionRequestChirho {
                dag_chirho: &self.dag_chirho,
                subject_chirho,
                bytes_chirho,
                context_chirho: None,
                declared_attribution_chirho: Some(&declared_chirho),
                caller_key_chirho: &self.caller_chirho,
                operation_chirho: None,
            },
        )
    }
}

impl Drop for FixtureChirho {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root_chirho).unwrap();
        let held_root_chirho = self.root_chirho.with_extension("held-chirho");
        if held_root_chirho.exists() {
            std::fs::remove_dir_all(held_root_chirho).unwrap();
        }
    }
}

fn snapshot_chirho(root_chirho: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk_chirho(
        root_chirho: &Path,
        path_chirho: &Path,
        files_chirho: &mut BTreeMap<PathBuf, Vec<u8>>,
    ) {
        for entry_chirho in std::fs::read_dir(path_chirho).unwrap() {
            let path_chirho = entry_chirho.unwrap().path();
            if path_chirho.is_dir() {
                walk_chirho(root_chirho, &path_chirho, files_chirho);
            } else {
                files_chirho.insert(
                    path_chirho.strip_prefix(root_chirho).unwrap().to_path_buf(),
                    std::fs::read(path_chirho).unwrap(),
                );
            }
        }
    }
    let mut files_chirho = BTreeMap::new();
    walk_chirho(root_chirho, root_chirho, &mut files_chirho);
    files_chirho
}

#[test]
fn a_real_private_admission_verifies_and_replays_without_writing_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let bytes_chirho = b"private admission payload chirho";
    let first_chirho = fixture_chirho
        .admit_chirho("user/admitted-chirho", bytes_chirho)
        .unwrap();
    assert_eq!(first_chirho.status_chirho, RUN_INTENT_PENDING_CHIRHO);
    verify_run_intent_records_chirho(&fixture_chirho.root_chirho).unwrap();
    assert_eq!(
        crate::dag_private_value_chirho::load_private_dag_value_bytes_chirho(
            &fixture_chirho.root_chirho,
            "user/admitted-chirho",
            &first_chirho.request_chirho,
        )
        .unwrap(),
        bytes_chirho
    );
    assert!(
        cas_chirho::get_chirho(&fixture_chirho.root_chirho, &first_chirho.request_chirho).is_err(),
        "private input must never be public CAS"
    );
    let before_chirho = snapshot_chirho(&fixture_chirho.root_chirho);
    assert!(!before_chirho.values().any(|value_chirho| value_chirho
        .windows(bytes_chirho.len())
        .any(|window_chirho| window_chirho == bytes_chirho)));
    let replay_chirho = fixture_chirho
        .admit_chirho("user/admitted-chirho", bytes_chirho)
        .unwrap();
    assert_eq!(
        serde_json::to_value(replay_chirho).unwrap(),
        serde_json::to_value(first_chirho).unwrap()
    );
    assert_eq!(snapshot_chirho(&fixture_chirho.root_chirho), before_chirho);
    assert_eq!(
        load_run_intent_records_chirho(&fixture_chirho.root_chirho)
            .unwrap()
            .len(),
        1
    );
    assert!(!fixture_chirho.root_chirho.join("runs-chirho").exists());
}

#[test]
fn the_caller_key_binds_the_private_subject_and_request_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    fixture_chirho
        .admit_chirho("user/one-chirho", b"one private payload chirho")
        .unwrap();
    let before_chirho = snapshot_chirho(&fixture_chirho.root_chirho);
    for (subject_chirho, bytes_chirho) in [
        ("user/two-chirho", b"one private payload chirho".as_slice()),
        (
            "user/one-chirho",
            b"different private payload chirho".as_slice(),
        ),
    ] {
        let error_chirho = fixture_chirho
            .admit_chirho(subject_chirho, bytes_chirho)
            .unwrap_err();
        assert!(error_chirho
            .to_string()
            .starts_with("RelayCallerKeyCollisionChirho:"));
        assert_eq!(snapshot_chirho(&fixture_chirho.root_chirho), before_chirho);
    }
}

#[test]
fn a_tampered_admission_refuses_before_another_private_store_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    fixture_chirho
        .admit_chirho("user/one-chirho", b"payload chirho")
        .unwrap();
    let path_chirho = run_intent_records_path_chirho(&fixture_chirho.root_chirho);
    let mut row_chirho: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path_chirho).unwrap()).unwrap();
    row_chirho["sig_chirho"] = serde_json::Value::String("0".repeat(128));
    let mut bytes_chirho = serde_json::to_vec(&row_chirho).unwrap();
    bytes_chirho.push(b'\n');
    std::fs::write(&path_chirho, bytes_chirho).unwrap();
    let before_chirho = snapshot_chirho(&fixture_chirho.root_chirho);
    let error_chirho = fixture_chirho
        .admit_chirho("user/one-chirho", b"payload chirho")
        .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "run intent record 0 signature invalid"
    );
    assert_eq!(snapshot_chirho(&fixture_chirho.root_chirho), before_chirho);
}

#[test]
fn a_dropped_owner_never_stores_a_request_or_pending_record_chirho() {
    let mut fixture_chirho = FixtureChirho::new_chirho();
    // Prime the existing per-caller lock, so this snapshot measures admission writes, not lock allocation.
    let lock_name_chirho = format!(
        "run-intent-caller-key-v1-chirho:{}",
        caller_idempotency_key_digest_chirho(&fixture_chirho.caller_chirho).0
    );
    seqlog_chirho::with_named_lock_chirho(
        &fixture_chirho.root_chirho,
        &lock_name_chirho,
        || Ok(()),
    )
    .unwrap();
    drop(fixture_chirho.elector_chirho.take());
    let before_chirho = snapshot_chirho(&fixture_chirho.root_chirho);
    let error_chirho = fixture_chirho
        .admit_chirho("user/one-chirho", b"must not persist chirho")
        .unwrap_err();
    assert_eq!(
        error_chirho.downcast_ref::<
            cairn_ledger_elected_head_transition_chirho::ElectedHeadTransitionRefusalChirho,
        >(),
        Some(&cairn_ledger_elected_head_transition_chirho::ElectedHeadTransitionRefusalChirho::AuthorityUnavailableChirho),
    );
    assert_eq!(snapshot_chirho(&fixture_chirho.root_chirho), before_chirho);
    assert!(!run_intent_records_path_chirho(&fixture_chirho.root_chirho).exists());
}

#[test]
fn admission_does_not_recreate_an_erased_private_request_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    fixture_chirho
        .admit_chirho("user/erase-chirho", b"erase this payload chirho")
        .unwrap();
    crate::privacy_chirho::erase_subject_keys_chirho(
        &fixture_chirho.root_chirho,
        "user/erase-chirho",
    )
    .unwrap();
    let before_chirho = snapshot_chirho(&fixture_chirho.root_chirho);
    let _outcome_chirho =
        fixture_chirho.admit_chirho("user/erase-chirho", b"erase this payload chirho");
    assert_eq!(snapshot_chirho(&fixture_chirho.root_chirho), before_chirho);
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SinkPointChirho {
    StoreChirho,
    AppendChirho,
}

std::thread_local! {
    static SWAP_POINT_CHIRHO: Cell<Option<SinkPointChirho>> = const { Cell::new(None) };
    static SWAP_FIRED_CHIRHO: Cell<bool> = const { Cell::new(false) };
}

struct SwapResetChirho;

impl Drop for SwapResetChirho {
    fn drop(&mut self) {
        SWAP_POINT_CHIRHO.with(|point_chirho| point_chirho.set(None));
        SWAP_FIRED_CHIRHO.with(|fired_chirho| fired_chirho.set(false));
    }
}

fn arm_swap_chirho(point_chirho: SinkPointChirho) -> SwapResetChirho {
    SWAP_POINT_CHIRHO.with(|slot_chirho| {
        assert!(slot_chirho.replace(Some(point_chirho)).is_none());
    });
    SWAP_FIRED_CHIRHO.with(|fired_chirho| fired_chirho.set(false));
    SwapResetChirho
}

pub(super) fn hold_before_sink_chirho(
    root_chirho: &Path,
    point_chirho: SinkPointChirho,
) -> Result<()> {
    lease_tests_chirho::hold_before_sink_chirho(root_chirho, point_chirho);
    let swap_chirho = SWAP_POINT_CHIRHO.with(|slot_chirho| {
        if slot_chirho.get() == Some(point_chirho) {
            slot_chirho.set(None);
            true
        } else {
            false
        }
    });
    if !swap_chirho {
        return Ok(());
    }
    let group_chirho = consistency_group_for_root_chirho(root_chirho)?;
    let original_path_chirho = writer_fence_path_chirho(root_chirho, &group_chirho)?;
    // Read the actual host-refreshed fence; this test projection grants no authority.
    let fence_chirho: cairn_writer_head_chirho::writer_head_chirho::WriterFenceTokenChirho =
        serde_json::from_slice(&std::fs::read(original_path_chirho)?)?;
    let held_root_chirho = root_chirho.with_extension("held-chirho");
    std::fs::rename(root_chirho, &held_root_chirho)?;
    std::fs::create_dir(root_chirho)?;
    let source_chirho = writer_fence_path_chirho(&held_root_chirho, &fence_chirho.group_chirho)?;
    let replacement_chirho = writer_fence_path_chirho(root_chirho, &fence_chirho.group_chirho)?;
    std::fs::create_dir_all(replacement_chirho.parent().unwrap())?;
    std::fs::copy(source_chirho, replacement_chirho)?;
    verify_writer_fence_for_root_chirho(root_chirho, &fence_chirho)?;
    SWAP_FIRED_CHIRHO.with(|fired_chirho| fired_chirho.set(true));
    Ok(())
}

fn assert_swap_refuses_chirho(point_chirho: SinkPointChirho) {
    // These swaps pin the later checks, not the first check already shadowed at callback entry.
    // A surviving deletion of that first check is not permission to remove it.
    let fixture_chirho = FixtureChirho::new_chirho();
    let _reset_chirho = arm_swap_chirho(point_chirho);
    let subject_chirho = "user/swap-chirho";
    let bytes_chirho = b"private request before swapped append chirho";
    let error_chirho = fixture_chirho
        .admit_chirho(subject_chirho, bytes_chirho)
        .unwrap_err();
    assert!(
        SWAP_FIRED_CHIRHO.with(Cell::get),
        "the swap must actually occur"
    );
    assert_eq!(error_chirho.to_string(), "RunAdmissionWrongRootChirho");
    let replacement_files_chirho = snapshot_chirho(&fixture_chirho.root_chirho);
    assert_eq!(
        replacement_files_chirho.len(),
        1,
        "only the copied fence may exist"
    );
    let held_root_chirho = fixture_chirho.root_chirho.with_extension("held-chirho");
    let (relative_fence_path_chirho, copied_fence_bytes_chirho) =
        replacement_files_chirho.iter().next().unwrap();
    assert_eq!(
        copied_fence_bytes_chirho,
        &std::fs::read(held_root_chirho.join(relative_fence_path_chirho)).unwrap(),
    );
    assert!(!run_intent_records_path_chirho(&fixture_chirho.root_chirho).exists());
    assert!(!run_intent_records_path_chirho(&held_root_chirho).exists());
    if point_chirho == SinkPointChirho::AppendChirho {
        assert_eq!(
            crate::dag_private_value_chirho::load_private_dag_value_bytes_chirho(
                &held_root_chirho,
                subject_chirho,
                &cas_chirho::hash_chirho(bytes_chirho),
            )
            .unwrap(),
            bytes_chirho,
            "the held root retains the stored request, without a pending record",
        );
    }
}

#[test]
fn a_root_swap_before_private_store_refuses_at_that_sink_chirho() {
    assert_swap_refuses_chirho(SinkPointChirho::StoreChirho);
}

#[test]
fn a_root_swap_before_pending_append_keeps_only_the_held_private_request_chirho() {
    assert_swap_refuses_chirho(SinkPointChirho::AppendChirho);
}

#[test]
fn a_local_era_door_call_refuses_before_even_allocating_the_caller_lock_chirho() {
    let fixture_chirho = FixtureChirho::with_era_chirho(false);
    let before_chirho = snapshot_chirho(&fixture_chirho.root_chirho);
    let entries_before_chirho = std::fs::read_dir(&fixture_chirho.root_chirho)
        .unwrap()
        .map(|entry_chirho| entry_chirho.unwrap().file_name())
        .collect::<std::collections::BTreeSet<_>>();
    let error_chirho = fixture_chirho
        .admit_chirho("user/local-chirho", b"never stored chirho")
        .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "RunAdmissionElectedEraRequiredChirho"
    );
    assert_eq!(snapshot_chirho(&fixture_chirho.root_chirho), before_chirho);
    assert_eq!(
        std::fs::read_dir(&fixture_chirho.root_chirho)
            .unwrap()
            .map(|entry_chirho| entry_chirho.unwrap().file_name())
            .collect::<std::collections::BTreeSet<_>>(),
        entries_before_chirho
    );
}

#[path = "lease_tests_chirho.rs"]
mod lease_tests_chirho;
