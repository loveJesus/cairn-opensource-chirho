// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Equality both ways with DIFFERENT names, fail-closed on an unarmed sink, and the DURABLE half:
//! monotone advance plus survival across a real reopen from disk.
//!
//! **THESE ARMS DRIVE THE MECHANISM DIRECTLY, NOT THROUGH THE APPEND.** That is legitimate for this
//! cut and must never be read as end-to-end: 5c ships the mechanism with no live call site, because
//! no production mutation carries a winner term yet. A green run here says the decision function and
//! its storage are correct — including a real FsLedgerStorageChirho round trip — but it says nothing
//! about any append being fenced, because no production caller supplies a term yet.
//!
//! The two directions are pinned separately on purpose: an equality check that refuses by one name
//! cannot tell a deposed writer (term BELOW the high-water) from a sink that never saw an election
//! (term ABOVE it), and drill evidence needs that distinction to say what actually happened.

use super::*;
// Production no longer names a storage here; the tests still open one to build fixtures.
use crate::storage_chirho::FsLedgerStorageChirho;
use cairn_seqlog_chirho::seqlog_chirho::named_lock_storage_key_chirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, ConsistencyGroupIdChirho, WRITER_FENCE_LOCK_CHIRHO,
};

/// A REAL production-shaped coordinate, not a hand-written string.
///
/// The first version of these tests used "group-digest-chirho" and "abc123" — colon-free strings that
/// CANNOT OCCUR in production, because a canonical digest is `writer-fence-group-blake3-chirho:<hex>`.
/// Every arm passed while the mechanism refused every real coordinate at the path check. A fixture
/// that cannot occur in production tests a function that does not exist.
fn production_group_digest_chirho() -> String {
    consistency_group_digest_chirho(&ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "sink-term-fence-shape-chirho".to_owned(),
    })
    .expect("derive a production-shaped group digest")
}

fn state_chirho(term_chirho: u64) -> SinkTermFenceStateChirho {
    SinkTermFenceStateChirho {
        schema_chirho: SINK_TERM_FENCE_SCHEMA_CHIRHO.to_string(),
        group_digest_chirho: production_group_digest_chirho(),
        highest_accepted_winner_term_chirho: term_chirho,
    }
}

#[test]
fn the_exactly_current_term_is_accepted_chirho() {
    // Non-vacuity's other edge: every refusal test below would still pass if this function refused
    // EVERYTHING. Something must get through, or the fence is a wall.
    assert!(
        verify_supplied_winner_term_is_strictly_current_chirho(Some(&state_chirho(7)), 7).is_ok()
    );
}

#[test]
fn a_term_below_the_high_water_is_a_stale_writer_chirho() {
    let refusal_chirho =
        verify_supplied_winner_term_is_strictly_current_chirho(Some(&state_chirho(7)), 6)
            .expect_err("a deposed term must refuse");
    assert_eq!(refusal_chirho.name_chirho(), "StaleWinnerTermChirho");
    assert_eq!(
        refusal_chirho,
        SinkTermFenceRefusalChirho::StaleWinnerTermChirho {
            supplied_term_chirho: 6,
            highest_accepted_term_chirho: 7,
        },
        "the refusal must carry BOTH terms — an operator reading drill evidence needs to know how far \
         behind the writer was, not merely that it was behind"
    );
}

#[test]
fn a_term_above_the_high_water_is_an_unseen_election_chirho() {
    // THE ARM THAT >= WOULD LOSE. A monotone-greater check would ACCEPT this: a term the sink has
    // never accepted, from an election it never verified. "Strictly current" excludes the future as
    // well as the past, and this is the only test that catches the wrong comparison operator.
    let refusal_chirho =
        verify_supplied_winner_term_is_strictly_current_chirho(Some(&state_chirho(7)), 8)
            .expect_err("a term the sink never accepted must refuse");
    assert_eq!(refusal_chirho.name_chirho(), "UnseenWinnerTermChirho");
    assert_ne!(
        refusal_chirho.name_chirho(),
        "StaleWinnerTermChirho",
        "above and below must refuse by DIFFERENT names, or evidence cannot distinguish a deposed \
         writer from a sink that is behind the cluster"
    );
}

#[test]
fn an_unarmed_sink_accepts_nothing_chirho() {
    // Fail closed. A sink with no cell has accepted no winner term, so there is no term it can
    // recognise as current. The permissive reading — "no fence yet, let it through" — is how a fence
    // that has not been installed reads as a fence that passed.
    let refusal_chirho = verify_supplied_winner_term_is_strictly_current_chirho(None, 7)
        .expect_err("an unarmed sink must refuse");
    assert_eq!(refusal_chirho.name_chirho(), "NoAcceptedWinnerTermChirho");
}

#[test]
fn zero_is_not_a_special_case_chirho() {
    // A term of 0 against a high-water of 0 is CURRENT, not "unset". Treating 0 as a sentinel is how
    // a genuine first term gets refused, or worse, how an unarmed sink gets read as accepting 0.
    assert!(
        verify_supplied_winner_term_is_strictly_current_chirho(Some(&state_chirho(0)), 0).is_ok()
    );
    assert_eq!(
        verify_supplied_winner_term_is_strictly_current_chirho(Some(&state_chirho(0)), 1)
            .expect_err("above the high-water refuses even at zero")
            .name_chirho(),
        "UnseenWinnerTermChirho"
    );
}

#[test]
fn the_storage_key_is_group_scoped_and_carries_no_genesis_chirho() {
    // Genesis is deliberately absent from the key: a genesis-keyed cell starts fresh at zero after a
    // second genesis and accepts low terms — it fails OPEN. Group-keyed inherits the high-water.
    let digest_chirho = production_group_digest_chirho();
    let key_chirho = sink_term_fence_storage_key_chirho(&digest_chirho)
        .expect("a canonical digest derives a key");
    assert!(
        key_chirho.starts_with(SINK_TERM_FENCES_DIR_CHIRHO),
        "key must live in its own directory, not share the writer fence's: {key_chirho}"
    );
    // THE BUG THIS ARM NOW CATCHES: a canonical digest CONTAINS A COLON, and the storage layer
    // rejects any byte outside ASCII alphanumerics and - _ . / as an unsafe logical path. The first
    // version put the whole digest in the filename, so every PRODUCTION coordinate failed the path
    // check before any I/O while every test passed on colon-free fixtures.
    assert!(
        !key_chirho.contains(':'),
        "the key must carry only the digest SUFFIX — a colon makes the path unsafe and the fence \
         would refuse 100% of legitimate compensations as a storage error: {key_chirho}"
    );
    let other_chirho = consistency_group_digest_chirho(&ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "sink-term-fence-other-shape-chirho".to_owned(),
    })
    .expect("derive a second production-shaped digest");
    assert_ne!(
        key_chirho,
        sink_term_fence_storage_key_chirho(&other_chirho).expect("second key"),
        "two groups must not share one cell — a shared cell would fence one group's appends against \
         another group's elections"
    );
}

#[test]
fn a_non_canonical_coordinate_refuses_instead_of_deriving_a_key_chirho() {
    // HOSTILE ARM. A key builder that cannot fail is one that will eventually be handed something
    // illegal. Each of these is a shape a caller could plausibly pass, and none is a canonical
    // consistency-group digest — so derivation must REFUSE rather than emit a path.
    for hostile_chirho in [
        "abc123",                                  // a bare id, the old fixture's shape
        "group-a",                                 // a human label
        "wrong-prefix-blake3-chirho:0011deadbeef", // colon-bearing but wrong prefix
        "",                                        // empty
    ] {
        assert!(
            sink_term_fence_storage_key_chirho(hostile_chirho).is_err(),
            "non-canonical coordinate {hostile_chirho:?} must refuse — deriving a key from it would \
             either produce an unsafe path or silently fence the wrong group"
        );
    }
}

#[test]
fn the_operand_is_the_current_authority_term_not_the_historical_fork_term_chirho() {
    // A REGRESSION PIN FOR A LIVENESS FAILURE, not a safety one — the rarer and more dangerous kind
    // to lose, because the safety arms above all stay green while it is broken.
    //
    // Item 5 has TWO winner terms. The HISTORICAL term (which fork a losing effect came from) is by
    // construction from a DEPOSED fork, so it is always BELOW the sink high-water. If a future wiring
    // passed that instead of the CURRENT authorizing term, StaleWinnerTermChirho would fire on every
    // legitimate compensation: 100% of correct traffic refused, by name, exactly as specified.
    //
    // This test states the shape so the next reader sees it before wiring. Historical -> refused;
    // current -> accepted. Both behaviours are correct for their inputs; only one input is the operand.
    let high_water_chirho = state_chirho(9);
    let historical_fork_term_chirho = 4; // a deposed fork's term
    let current_authority_term_chirho = 9; // the authority signing this compensation now

    assert_eq!(
        verify_supplied_winner_term_is_strictly_current_chirho(
            Some(&high_water_chirho),
            historical_fork_term_chirho
        )
        .expect_err("a historical fork term is below the high-water and refuses")
        .name_chirho(),
        "StaleWinnerTermChirho",
        "this refusal is CORRECT for this input — which is exactly why passing the historical term \
         here would be a silent liveness failure rather than a visible bug"
    );
    assert!(
        verify_supplied_winner_term_is_strictly_current_chirho(
            Some(&high_water_chirho),
            current_authority_term_chirho
        )
        .is_ok(),
        "the CURRENT authorizing term is the operand and must pass; if this ever fails, the fence has \
         been wired to the wrong one of item 5's two winner terms and nothing will be compensable"
    );
}

// --- the DURABLE half: these use a real store on disk, not a struct literal ---

fn temp_fence_root_chirho() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let now_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("cairn-sink-fence-test-{n_chirho}-{now_chirho}"))
}

fn under_test_writer_lock_chirho<ResultChirho>(
    storage_chirho: &FsLedgerStorageChirho,
    action_chirho: impl FnOnce(&StableLedgerExclusiveLockGuardChirho<'_>) -> ResultChirho,
) -> ResultChirho {
    let path_chirho =
        StoragePathChirho::new_chirho(named_lock_storage_key_chirho(WRITER_FENCE_LOCK_CHIRHO));
    let mut handle_chirho = storage_chirho
        .provision_exclusive_lock_handle_chirho(&path_chirho)
        .expect("provision test writer lock");
    let guard_chirho = handle_chirho
        .try_acquire_chirho()
        .expect("acquire test writer lock");
    action_chirho(&guard_chirho)
}

#[test]
fn the_high_water_survives_a_real_reopen_and_then_refuses_a_lower_term_chirho() {
    // THE PERSISTENCE ARM. A fence that forgets on restart is worse than none, because the window is
    // invisible: the sink silently accepts terms it had already moved past. The reopen is a genuine
    // drop-and-reconstruct from disk, NOT a flag — an in-memory reset would prove only that a field
    // was cleared, which is not the property.
    let root_chirho = temp_fence_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let group_digest_owned_chirho = production_group_digest_chirho();
    let group_chirho = group_digest_owned_chirho.as_str();

    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&root_chirho).unwrap();
    under_test_writer_lock_chirho(&storage_chirho, |writer_lock_guard_chirho| {
        create_sink_term_fence_at_birth_chirho(writer_lock_guard_chirho, group_chirho, 9).unwrap();
    });
    drop(storage_chirho);

    let reopened_chirho = FsLedgerStorageChirho::open_existing_chirho(&root_chirho).unwrap();
    let state_chirho = under_test_writer_lock_chirho(&reopened_chirho, |guard_chirho| {
        read_sink_term_fence_chirho(guard_chirho, group_chirho)
    })
    .unwrap()
    .expect("the cell must survive the reopen");
    assert_eq!(state_chirho.highest_accepted_winner_term_chirho, 9);

    let refusal_chirho =
        verify_supplied_winner_term_is_strictly_current_chirho(Some(&state_chirho), 8)
            .expect_err("a term below the surviving high-water must refuse after restart");
    assert_eq!(
        refusal_chirho.name_chirho(),
        "StaleWinnerTermChirho",
        "the refusal must be BY NAME after a restart, not merely an Err — a restart that degraded the \
         reason would hide which property failed"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn advance_refuses_when_birth_never_created_the_cell_chirho() {
    let root_chirho = temp_fence_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&root_chirho).unwrap();
    let group_chirho = production_group_digest_chirho();
    let error_chirho = under_test_writer_lock_chirho(&storage_chirho, |writer_lock_guard_chirho| {
        advance_accepted_winner_term_chirho(writer_lock_guard_chirho, &group_chirho, 9)
            .expect_err("advance cannot recreate a missing birth cell")
    });
    assert!(
        error_chirho
            .to_string()
            .contains("SinkTermFenceMissingAtAdvanceChirho"),
        "{error_chirho:#}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn the_high_water_never_walks_backward_under_sequential_advance_chirho() {
    // THE MONOTONICITY GUARD, which is the money-authority link in this module: if advance accepted a
    // LOWER term, a deposed writer's stale term would afterwards read as strictly current and pass
    // the fence. A replayed or reordered revoke must be a no-op, not a rewind.
    let root_chirho = temp_fence_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let group_digest_owned_chirho = production_group_digest_chirho();
    let group_chirho = group_digest_owned_chirho.as_str();
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&root_chirho).unwrap();

    let (after_lower_chirho, equal_chirho) =
        under_test_writer_lock_chirho(&storage_chirho, |writer_lock_guard_chirho| {
            create_sink_term_fence_at_birth_chirho(writer_lock_guard_chirho, group_chirho, 9)
                .unwrap();
            let after_lower_chirho =
                advance_accepted_winner_term_chirho(writer_lock_guard_chirho, group_chirho, 4)
                    .unwrap();
            let equal_chirho =
                advance_accepted_winner_term_chirho(writer_lock_guard_chirho, group_chirho, 9)
                    .unwrap();
            (after_lower_chirho, equal_chirho)
        });
    assert_eq!(
        after_lower_chirho.highest_accepted_winner_term_chirho, 9,
        "advancing to a LOWER term must be a no-op; if this reads 4 the high-water walked backward \
         and every term between 4 and 9 just became acceptable again"
    );
    assert_eq!(
        equal_chirho.highest_accepted_winner_term_chirho, 9,
        "equal is also a no-op"
    );

    let persisted_chirho = under_test_writer_lock_chirho(&storage_chirho, |guard_chirho| {
        read_sink_term_fence_chirho(guard_chirho, group_chirho)
    })
    .unwrap()
    .expect("cell present");
    assert_eq!(
        persisted_chirho.highest_accepted_winner_term_chirho, 9,
        "the no-op must not have rewritten the CELL either — returning the old value while writing \
         the new one would pass the assertion above and still lose the property"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_higher_term_does_advance_chirho() {
    // Non-vacuity for the two arms above: they would both pass if advance never wrote anything.
    let root_chirho = temp_fence_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let group_digest_owned_chirho = production_group_digest_chirho();
    let group_chirho = group_digest_owned_chirho.as_str();
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&root_chirho).unwrap();
    under_test_writer_lock_chirho(&storage_chirho, |writer_lock_guard_chirho| {
        create_sink_term_fence_at_birth_chirho(writer_lock_guard_chirho, group_chirho, 3).unwrap();
        advance_accepted_winner_term_chirho(writer_lock_guard_chirho, group_chirho, 11).unwrap();
    });
    assert_eq!(
        under_test_writer_lock_chirho(&storage_chirho, |guard_chirho| {
            read_sink_term_fence_chirho(guard_chirho, group_chirho)
        })
        .unwrap()
        .expect("cell present")
        .highest_accepted_winner_term_chirho,
        11
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}
