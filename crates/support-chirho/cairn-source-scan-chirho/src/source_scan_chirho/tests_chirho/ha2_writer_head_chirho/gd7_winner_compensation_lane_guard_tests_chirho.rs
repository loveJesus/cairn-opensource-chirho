// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Bounds the ONE lawful narrowing of the GD7 winner-handoff append freeze (ruled (a), 2026-08-05).

use super::super::*;

const LANE_ACQUISITION_NEEDLE_CHIRHO: &str = "try_acquire_active_handoff_append_chirho(";
const LANE_DEFINITION_NEEDLE_CHIRHO: &str = "pub fn try_acquire_active_handoff_append_chirho(";
const STARTUP_ACQUISITION_NEEDLE_CHIRHO: &str = "try_acquire_startup_coordinates_chirho(";
const STARTUP_DEFINITION_NEEDLE_CHIRHO: &str = "pub fn try_acquire_startup_coordinates_chirho(";
const LANE_GUARD_IMPL_NEEDLE_CHIRHO: &str = "impl LocalActiveHandoffAppendGenerationGuardChirho";
const MARKER_RELEASE_NEEDLE_CHIRHO: &str = "release_chirho";

const ELECTOR_MODULE_CHIRHO: &str =
    "crates/support-chirho/cairn-writer-elector-chirho/src/local_append_authority_chirho.rs";
const RESIDENT_ROOT_MODULE_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho.rs";

/// The exempt append lane and the handoff-aware startup seal each have ONE production consumer.
///
/// WHAT THIS BOUNDS, stated as the confinement claim it is: an active winner-handoff marker refuses
/// every ordinary append, and this brick narrowed that totality by exactly two admissions — the
/// fenced compensation append, and a coordinate-only startup seal that yields no append authority.
/// A NEW file in either set is a new admission through a money-authority freeze and must be reviewed
/// as one; the assertion is a SET rather than a count so a new site names itself in the failure.
///
/// HONEST SCOPE, so nobody reads this guard as wider than it is. It is anti-mistake, not
/// anti-adversary: it keys on the acquisition's own symbol, so it sees the natural caller — one that
/// invokes the elector API the only supported way. An author who re-exports the method under another
/// name, or wraps it in a helper in an already-listed file, walks past this census. The load-bearing
/// defenses against that class are the elector's own gates (exact-digest match against the live
/// marker, and a guard type carrying no release authority) and review of this file set.
#[test]
fn gd7_winner_compensation_lane_has_one_production_consumer_chirho() {
    let production_files_chirho = workspace_production_rs_files_chirho();
    let mut lane_sites_chirho = Vec::new();
    let mut lane_definition_sites_chirho = Vec::new();
    let mut startup_sites_chirho = Vec::new();
    let mut startup_definition_sites_chirho = Vec::new();
    for path_chirho in production_files_chirho {
        let raw_source_chirho =
            std::fs::read_to_string(&path_chirho).expect("read production source");
        let source_chirho = production_text_chirho(&raw_source_chirho);
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        if source_chirho.contains(LANE_ACQUISITION_NEEDLE_CHIRHO) {
            lane_sites_chirho.push(relative_chirho.clone());
        }
        if source_chirho.contains(LANE_DEFINITION_NEEDLE_CHIRHO) {
            lane_definition_sites_chirho.push(relative_chirho.clone());
        }
        if source_chirho.contains(STARTUP_ACQUISITION_NEEDLE_CHIRHO) {
            startup_sites_chirho.push(relative_chirho.clone());
        }
        if source_chirho.contains(STARTUP_DEFINITION_NEEDLE_CHIRHO) {
            startup_definition_sites_chirho.push(relative_chirho.clone());
        }
    }
    lane_sites_chirho.sort();
    lane_definition_sites_chirho.sort();
    startup_sites_chirho.sort();
    startup_definition_sites_chirho.sort();

    assert_eq!(
        lane_definition_sites_chirho,
        vec![ELECTOR_MODULE_CHIRHO.to_owned()],
        "the exempt append lane must be defined in exactly one elector module"
    );
    // Sorted, so the expectation is the path order the census produces, not the order they were
    // written about.
    assert_eq!(
        lane_sites_chirho,
        vec![
            RESIDENT_ROOT_MODULE_CHIRHO.to_owned(),
            ELECTOR_MODULE_CHIRHO.to_owned()
        ],
        "the exempt compensation lane's definition and its ONE resident append-seam caller must be \
         the whole production population; a new file here is a new admission through the winner \
         handoff freeze"
    );
    assert_eq!(
        startup_definition_sites_chirho,
        vec![ELECTOR_MODULE_CHIRHO.to_owned()],
        "the handoff-aware startup seal must be defined in exactly one elector module"
    );
    assert_eq!(
        startup_sites_chirho,
        vec![
            RESIDENT_ROOT_MODULE_CHIRHO.to_owned(),
            ELECTOR_MODULE_CHIRHO.to_owned()
        ],
        "the startup coordinate seal's definition and its ONE resident startup-helper caller must \
         be the whole production population"
    );
}

/// THE LANE BORROWS THE FREEZE AND CANNOT CLEAR IT — pinned at the guard type, not at prose.
///
/// `LocalAppendHandoffGenerationGuardChirho` carries `release_chirho` so the handoff's OWN evidence
/// work can retire its marker. The compensation lane's guard is a DIFFERENT type precisely so it
/// cannot: if a `release_chirho` ever appears in its impl, an exempt append gained the power to end
/// the freeze it was admitted under, which is the one thing this lane must never be able to do.
///
/// The slice is resolved from the impl header to the next item rather than searched file-wide,
/// because the sibling type's legitimate `release_chirho` lives in the same file — a file-wide
/// census would be green by matching the wrong impl.
#[test]
fn gd7_winner_compensation_lane_guard_carries_no_marker_release_chirho() {
    let elector_path_chirho = workspace_root_chirho().join(ELECTOR_MODULE_CHIRHO);
    let raw_source_chirho = std::fs::read_to_string(elector_path_chirho)
        .expect("read the elector append-authority module");
    let source_chirho = production_text_chirho(&raw_source_chirho);
    let impl_start_chirho = source_chirho
        .find(LANE_GUARD_IMPL_NEEDLE_CHIRHO)
        .expect("the exempt lane's guard type must have an impl block to bound");
    // POSITIVE CONTROL for the slicing itself: the sibling release exists in this same file, so a
    // slice that silently captured nothing would pass this guard while measuring nothing.
    assert!(
        source_chirho.contains(MARKER_RELEASE_NEEDLE_CHIRHO),
        "this file must still contain the sibling handoff guard's release, or the absence asserted \
         below is green-by-emptiness rather than a property of the lane's guard"
    );
    let after_impl_chirho =
        &source_chirho[impl_start_chirho + LANE_GUARD_IMPL_NEEDLE_CHIRHO.len()..];
    let impl_body_chirho = match after_impl_chirho.find("\nimpl ") {
        Some(next_item_chirho) => &after_impl_chirho[..next_item_chirho],
        None => after_impl_chirho,
    };
    assert!(
        !impl_body_chirho.contains(MARKER_RELEASE_NEEDLE_CHIRHO),
        "the compensation lane's guard must expose NO marker release; it borrows the winner handoff \
         freeze and may never clear it"
    );
}
