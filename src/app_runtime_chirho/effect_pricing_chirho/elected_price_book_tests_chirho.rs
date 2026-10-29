// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! S3 behaviour arms for the price-book elected door, mirroring S1's app-Deploy set.
//!
//! Categories: never-latched byte-identity, exactly-one row/ref/receipt on elected success, named
//! refusals with neighbour discriminators before any durable output, and the elected half of the
//! two-era pending-transition guard.

use super::*;
use cairn_durable_chirho::cas_lifecycle_chirho::migrate_cas_lifecycle_offline_chirho;
use cairn_writer_head_chirho::head_transition_authority_chirho::{
    with_elected_head_transition_scope_chirho, HeadTransitionAuthorityPortChirho,
    HeadTransitionCommitActionChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    issue_elected_writer_fence_for_root_chirho, ConsistencyGroupIdChirho,
};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const APP_CHIRHO: &str = "price-door-app-chirho";

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-s3-{label_chirho}-{nanos_chirho}-{n_chirho}-chirho"
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

/// A live elected authority: it really runs the commit under a real elected scope.
struct LiveElectedAuthorityChirho {
    group_chirho: ConsistencyGroupIdChirho,
    term_chirho: u64,
}

impl HeadTransitionAuthorityPortChirho for LiveElectedAuthorityChirho {
    fn with_elected_head_transition_scope_chirho(
        &self,
        root_chirho: &Path,
        action_chirho: &mut dyn HeadTransitionCommitActionChirho,
    ) -> Result<()> {
        with_elected_head_transition_scope_chirho(
            root_chirho,
            &self.group_chirho,
            self.term_chirho,
            None,
            |scope_chirho| action_chirho.call_chirho(scope_chirho),
        )
        .into_result_chirho()
    }
}

/// Refuses by a named identity without ever entering a scope — the shape of every authority
/// refusal that must land BEFORE a durable output exists.
struct RefusingAuthorityChirho {
    refusal_chirho: &'static str,
}

impl HeadTransitionAuthorityPortChirho for RefusingAuthorityChirho {
    fn with_elected_head_transition_scope_chirho(
        &self,
        _root_chirho: &Path,
        _action_chirho: &mut dyn HeadTransitionCommitActionChirho,
    ) -> Result<()> {
        Err(anyhow!(self.refusal_chirho))
    }
}

/// Records whether the elected port was reached at all. A never-latched root must never touch it.
struct ObservedOnlyAuthorityChirho {
    called_chirho: Cell<bool>,
}

impl HeadTransitionAuthorityPortChirho for ObservedOnlyAuthorityChirho {
    fn with_elected_head_transition_scope_chirho(
        &self,
        _root_chirho: &Path,
        _action_chirho: &mut dyn HeadTransitionCommitActionChirho,
    ) -> Result<()> {
        self.called_chirho.set(true);
        Err(anyhow!(
            "NeverLatchedRootMustNotReachElectedAuthorityChirho"
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PriceDurableCountsChirho {
    records_chirho: usize,
    selected_chirho: bool,
    receipts_chirho: usize,
}

/// The three durable price surfaces from the ZR-2b Z9 census: the family log, the ref, the reflog.
fn durable_counts_chirho(root_chirho: &Path, app_chirho: &str) -> PriceDurableCountsChirho {
    let branch_chirho = pricebook_ref_chirho(app_chirho);
    PriceDurableCountsChirho {
        records_chirho: verified_price_book_records_chirho(root_chirho)
            .expect("load verified price records")
            .len(),
        selected_chirho: refs_chirho::load_refs_chirho(root_chirho)
            .expect("load refs")
            .branches_chirho
            .contains_key(&branch_chirho),
        receipts_chirho: refs_chirho::reflog_chirho(root_chirho)
            .expect("load reflog")
            .into_iter()
            .filter(|entry_chirho| entry_chirho.branch_chirho == branch_chirho)
            .count(),
    }
}

fn owner_chirho(root_chirho: &Path) -> String {
    crate::identity_chirho::register_identity_chirho(
        root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .expect("register owner")
    .principal_chirho
}

/// An owned app so `ensure_app_owner_chirho` passes before the price door is exercised.
fn owned_app_root_chirho(label_chirho: &str) -> (PathBuf, String) {
    let root_chirho = tmp_root_chirho(label_chirho);
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &crate::model_chirho::DagChirho {
            nodes_chirho: Vec::new(),
            edges_chirho: Vec::new(),
        },
    )
    .expect("store empty dag");
    app_chirho::deploy_app_unreviewed_dev_chirho(
        &root_chirho,
        APP_CHIRHO,
        dag_chirho,
        &owner_chirho,
    )
    .expect("deploy owning app on the never-latched path");
    (root_chirho, owner_chirho)
}

fn geo_latched_fixture_chirho(label_chirho: &str) -> (PathBuf, String, LiveElectedAuthorityChirho) {
    let (root_chirho, owner_chirho) = owned_app_root_chirho(label_chirho);
    migrate_cas_lifecycle_offline_chirho(&root_chirho)
        .expect("offline lifecycle migration before elected serving");
    let fence_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 7)
        .expect("latch the elected writer era");
    let authority_chirho = LiveElectedAuthorityChirho {
        group_chirho: fence_chirho.group_chirho,
        term_chirho: 7,
    };
    (root_chirho, owner_chirho, authority_chirho)
}

fn prices_chirho() -> BTreeMap<String, i64> {
    BTreeMap::from([("query_chirho".to_string(), 3)])
}

/// **NEVER-LATCHED BYTE-IDENTITY.** A root that never latched runs the pre-S3 local body and the
/// elected authority is never entered — the property the extraction at `11d7c0e0` preserved, whose
/// body diffs to ZERO lines against the pre-S3 bytes.
#[test]
fn never_latched_price_book_stays_on_the_existing_local_path_chirho() {
    let (root_chirho, owner_chirho) = owned_app_root_chirho("never-latched");
    let authority_chirho = ObservedOnlyAuthorityChirho {
        called_chirho: Cell::new(false),
    };

    let (hash_chirho, book_chirho, record_chirho) =
        set_price_book_with_head_transition_authority_chirho(
            &root_chirho,
            APP_CHIRHO,
            &owner_chirho,
            Some(2),
            prices_chirho(),
            0,
            &authority_chirho,
        )
        .expect("a never-latched root must complete on the existing local path");

    assert!(
        !authority_chirho.called_chirho.get(),
        "a never-latched root must NOT reach the elected authority port"
    );

    // ARGUMENT FORWARDING — every caller-supplied policy field, asserted against what was passed.
    //
    // The first version of this arm asserted only port-not-entered plus the app name, and CALLED
    // that byte-identity. gpt's S3 review mutated a forwarded field
    // (`external_markup_bps.saturating_add(1)`) and this arm STAYED GREEN. Port-not-entered proves
    // the dispatcher chose the local branch; it proves nothing about what the branch was handed.
    // A dispatcher is exactly the place a forwarding slip hides, because every call it makes looks
    // structurally right.
    assert_eq!(book_chirho.app_chirho, APP_CHIRHO);
    assert_eq!(book_chirho.owner_principal_chirho, owner_chirho);
    assert_eq!(
        book_chirho.price_per_request_chirho,
        Some(2),
        "price_per_request must forward unchanged through the dispatcher"
    );
    assert_eq!(
        book_chirho.effect_prices_chirho,
        prices_chirho(),
        "the effect-price map must forward unchanged through the dispatcher"
    );
    assert_eq!(
        book_chirho.external_markup_bps_chirho, 0,
        "external_markup_bps must forward unchanged -- this is the exact field whose mutation this arm previously missed"
    );
    assert_eq!(
        book_chirho.previous_chirho, None,
        "a first price book has no predecessor"
    );

    assert_eq!(record_chirho.price_book_chirho, hash_chirho);
    assert_eq!(record_chirho.owner_principal_chirho, owner_chirho);
    assert_eq!(
        current_price_book_hash_chirho(&root_chirho, APP_CHIRHO).expect("read price head"),
        Some(hash_chirho)
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// **EXACTLY ONE ROW, REF AND RECEIPT** on a fresh elected success — and the stored book is at the
/// address PREPARE bound without writing, which is the S3-specific claim.
#[test]
fn elected_fresh_price_book_publishes_exactly_one_row_ref_and_receipt_chirho() {
    let (root_chirho, owner_chirho, authority_chirho) = geo_latched_fixture_chirho("elected-fresh");
    let before_chirho = durable_counts_chirho(&root_chirho, APP_CHIRHO);
    assert_eq!(before_chirho.records_chirho, 0);
    assert!(!before_chirho.selected_chirho);

    let (hash_chirho, book_chirho, record_chirho) =
        set_price_book_with_head_transition_authority_chirho(
            &root_chirho,
            APP_CHIRHO,
            &owner_chirho,
            Some(5),
            prices_chirho(),
            0,
            &authority_chirho,
        )
        .expect("a geo-latched root must succeed through the elected door");

    let after_chirho = durable_counts_chirho(&root_chirho, APP_CHIRHO);
    assert_eq!(
        after_chirho,
        PriceDurableCountsChirho {
            records_chirho: 1,
            selected_chirho: true,
            receipts_chirho: 1,
        },
        "an elected success must publish EXACTLY one row, one ref and one receipt"
    );
    // The book is retrievable at the address PREPARE bound before any write happened.
    let stored_chirho: PriceBookChirho =
        store_chirho::get_object_chirho(&root_chirho, &hash_chirho)
            .expect("load stored price book");
    assert_eq!(stored_chirho, book_chirho);
    assert_eq!(record_chirho.price_book_chirho, hash_chirho);
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// **NAMED REFUSALS PRECEDE EVERY DURABLE OUTPUT**, each excluding its NEIGHBOUR.
///
/// Counters are asserted UNCHANGED against a pre-state snapshot rather than against literal zero:
/// a literal-zero assertion would pass vacuously if `durable_counts_chirho` were broken and always
/// returned zero. The non-vacuity control is
/// `elected_fresh_price_book_publishes_exactly_one_row_ref_and_receipt_chirho` above, which proves
/// the same counter MOVES on success.
#[test]
fn elected_price_book_refusals_precede_every_durable_output_chirho() {
    let cases_chirho = [
        (
            "deposed",
            "ElectedAuthorityDeposedChirho",
            "ElectedAuthorityLeaseExpiredChirho",
        ),
        (
            "expired",
            "ElectedAuthorityLeaseExpiredChirho",
            "ElectedAuthorityDeposedChirho",
        ),
        (
            "wrongroot",
            "ElectedAuthorityWrongRootChirho",
            "ElectedAuthorityWrongGroupChirho",
        ),
        (
            "wronggroup",
            "ElectedAuthorityWrongGroupChirho",
            "ElectedAuthorityWrongRootChirho",
        ),
    ];
    for (label_chirho, expected_chirho, neighbour_chirho) in cases_chirho {
        let (root_chirho, owner_chirho, _live_chirho) = geo_latched_fixture_chirho(label_chirho);
        let authority_chirho = RefusingAuthorityChirho {
            refusal_chirho: expected_chirho,
        };
        let before_chirho = durable_counts_chirho(&root_chirho, APP_CHIRHO);

        let error_chirho = set_price_book_with_head_transition_authority_chirho(
            &root_chirho,
            APP_CHIRHO,
            &owner_chirho,
            Some(11),
            prices_chirho(),
            0,
            &authority_chirho,
        )
        .expect_err("an unsafe elected authority must refuse before any price output")
        .to_string();

        assert!(error_chirho.contains(expected_chirho), "{error_chirho}");
        assert!(
            !error_chirho.contains(neighbour_chirho),
            "failure means the refusal identities collapsed; preserve the named authority cause: {error_chirho}"
        );
        assert_eq!(
            durable_counts_chirho(&root_chirho, APP_CHIRHO),
            before_chirho,
            "failure means a refusal wrote a price row, ref, or receipt; keep every mutation behind the elected callback"
        );
        let _ = std::fs::remove_dir_all(root_chirho);
    }
}

/// **THE ELECTED HALF OF THE TWO-ERA PENDING GUARD.**
///
/// The scan guard pins that the NEVER-LATCHED body recovers a pending transition before reading
/// previous and appending. On an ELECTED root the ruling is the opposite: PREPARE must REFUSE by
/// name and run no recovery mutation, because a repair inside read-only PREPARE happens before the
/// authority check and can only strand a half-state.
///
/// The fixture deliberately violates what production never should — it truncates the reflog so a
/// completed transition reads as unreceipted — which is the only way to present a pending row.
///
/// MIGRATION PATH, and the directions are not equally serious:
/// - the elected path RECOVERS instead of refusing → **the disposition regressed; stop.**
/// - the local path refuses instead of recovering → the local contract broke; stop, and see the
///   scan-crate twin `pricebook_local_body_recovers_before_reading_previous_or_appending_chirho`.
#[test]
fn elected_pending_price_transition_refuses_and_runs_no_recovery_chirho() {
    let (root_chirho, owner_chirho, authority_chirho) = geo_latched_fixture_chirho("pending");
    set_price_book_with_head_transition_authority_chirho(
        &root_chirho,
        APP_CHIRHO,
        &owner_chirho,
        Some(4),
        prices_chirho(),
        0,
        &authority_chirho,
    )
    .expect("seed one completed elected price transition");

    // Make the completed transition read as UNRECEIPTED by emptying the reflog.
    let reflog_chirho = refs_chirho::reflog_path_chirho(&root_chirho);
    std::fs::write(&reflog_chirho, b"").expect("truncate reflog to simulate a pending transition");
    let before_chirho = durable_counts_chirho(&root_chirho, APP_CHIRHO);
    assert_eq!(
        before_chirho.receipts_chirho, 0,
        "fixture precondition: the transition must now read as unreceipted"
    );

    let error_chirho = set_price_book_with_head_transition_authority_chirho(
        &root_chirho,
        APP_CHIRHO,
        &owner_chirho,
        Some(9),
        prices_chirho(),
        0,
        &authority_chirho,
    )
    .expect_err("a pending unreceipted transition must refuse on the elected path")
    .to_string();

    assert!(
        error_chirho.contains("PriceBookPendingHeadTransitionChirho"),
        "the refusal must be the NAMED pending-transition refusal: {error_chirho}"
    );
    assert_eq!(
        durable_counts_chirho(&root_chirho, APP_CHIRHO),
        before_chirho,
        "a pending refusal must run NO recovery mutation: no row, ref, or receipt may move"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// Appends one valid row to an AUTHORIZATION family between PREPARE and the elected scope — gpt's
/// S3-review attack, kept as a fixture. The row is well-formed; the point is not corruption but
/// that the evidence PREPARE authorized against is no longer current.
struct StaleTailPlantingAuthorityChirho {
    group_chirho: ConsistencyGroupIdChirho,
    term_chirho: u64,
    family_chirho: &'static str,
    planted_chirho: Cell<bool>,
}

impl HeadTransitionAuthorityPortChirho for StaleTailPlantingAuthorityChirho {
    fn with_elected_head_transition_scope_chirho(
        &self,
        root_chirho: &Path,
        action_chirho: &mut dyn HeadTransitionCommitActionChirho,
    ) -> Result<()> {
        use std::io::Write as _;
        let path_chirho = root_chirho.join(self.family_chirho);
        let before_chirho = std::fs::metadata(&path_chirho)
            .expect("the authorization family must exist before planting")
            .len();
        let mut file_chirho = std::fs::OpenOptions::new()
            .append(true)
            .open(&path_chirho)
            .expect("open authorization family for the planted append");
        file_chirho
            .write_all(b"{\"planted_chirho\":true}\n")
            .expect("plant one appended row");
        drop(file_chirho);
        let after_chirho = std::fs::metadata(&path_chirho).expect("restat").len();
        assert!(
            after_chirho > before_chirho,
            "the plant must actually apply before the commit-state recheck runs"
        );
        self.planted_chirho.set(true);
        with_elected_head_transition_scope_chirho(
            root_chirho,
            &self.group_chirho,
            self.term_chirho,
            None,
            |scope_chirho| action_chirho.call_chirho(scope_chirho),
        )
        .into_result_chirho()
    }
}

/// **A PRICE MUTATION MUST NOT COMMIT ON STALE AUTHORIZATION EVIDENCE.**
///
/// The regression arm for the bug gpt's S3 review executed: `ensure_app_owner_chirho` authorizes
/// from the verified app-owner and identity maps, PREPARE did not fingerprint them, and a valid
/// append between PREPARE and the elected scope let the mutation commit on evidence that had moved.
///
/// Each family gets its OWN case with its OWN named refusal and its neighbour excluded, because an
/// operator hitting this needs to know WHICH authorization map moved — an ownership change and a
/// principal change are different incidents.
///
/// MIGRATION PATH: if either case stops refusing, the stale-authorization hole is back — stop, and
/// do not widen the expected refusal. If the refusals swap, the two tails are being compared in the
/// wrong order.
#[test]
fn elected_price_book_refuses_stale_authorization_tails_chirho() {
    let cases_chirho = [
        (
            "stale-owner",
            "app-records-chirho.jsonl",
            "StaleAppOwnerTailChirho",
            "StaleIdentityTailChirho",
        ),
        (
            "stale-identity",
            "identities-chirho.jsonl",
            "StaleIdentityTailChirho",
            "StaleAppOwnerTailChirho",
        ),
    ];
    for (label_chirho, family_chirho, expected_chirho, neighbour_chirho) in cases_chirho {
        let (root_chirho, owner_chirho, live_chirho) = geo_latched_fixture_chirho(label_chirho);
        let authority_chirho = StaleTailPlantingAuthorityChirho {
            group_chirho: live_chirho.group_chirho,
            term_chirho: live_chirho.term_chirho,
            family_chirho,
            planted_chirho: Cell::new(false),
        };
        let before_chirho = durable_counts_chirho(&root_chirho, APP_CHIRHO);

        let error_chirho = set_price_book_with_head_transition_authority_chirho(
            &root_chirho,
            APP_CHIRHO,
            &owner_chirho,
            Some(7),
            prices_chirho(),
            0,
            &authority_chirho,
        )
        .expect_err("a moved authorization tail must refuse before any price output")
        .to_string();

        assert!(
            authority_chirho.planted_chirho.get(),
            "fixture precondition: the plant must have run"
        );
        assert!(
            error_chirho.contains(expected_chirho),
            "the refusal must name WHICH authorization map moved: {error_chirho}"
        );
        assert!(
            !error_chirho.contains(neighbour_chirho),
            "the two stale-tail refusals must stay distinct: {error_chirho}"
        );
        assert_eq!(
            durable_counts_chirho(&root_chirho, APP_CHIRHO),
            before_chirho,
            "a stale-authorization refusal must publish no row, ref, or receipt"
        );
        let _ = std::fs::remove_dir_all(root_chirho);
    }
}
