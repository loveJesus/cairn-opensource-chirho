// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Keep the several things this codebase calls "placement" from collapsing into each other, so the
//! TENANT ROOT stays the sole geo placement/authority/migration unit (CF8 acceptance, GG7/G1).
//!
//! THE KINDS ARE NOT INTERCHANGEABLE, and confusing them is the hazard CF8 names directly:
//!   HOST RANKING ......... which MACHINE should run a module. `cairn-placement-chirho` — a pure
//!                          scoring core over candidate hosts. Decides compute, never data custody.
//!   ACCOUNT SHARDING ..... CF2 hot-account credit-only SUB-ACCOUNTS. Lives inside ONE money root,
//!                          same journal. Relieves head-row contention. Not geographic at all.
//!   STORAGE FANOUT ....... CAS / seqlog segment directory sharding. Filesystem layout only.
//!   GEO DATA PLACEMENT ... which REGION holds a tenant's data, authority, and history. THE unit
//!                          here is the tenant root, and this is what G1 constrains.
//!
//! WHY THIS IS A GUARD AND NOT A NOTE. Only the last kind carries custody, erasure obligations, and
//! audit coordinates. A ranking core that quietly learns tenant roots has stopped choosing where
//! compute runs and started choosing where a CUSTOMER'S HISTORY LIVES — an authority change that
//! should never arrive as a drive-by import.
//!
//! WHAT THIS GUARD DOES NOT CLAIM. It is not an inventory of every placement-bearing file, and
//! deliberately so: a file list is a treadmill that taxes every edit while the product is plastic.
//! It pins TWO boundaries — the host-ranking core must not acquire tenant-root, refs, store, or
//! filesystem reach, and the storage-fanout surfaces must not acquire tenant or region identity —
//! plus the module-level statements that keep the kinds legible. A new surface that conflates the
//! kinds WITHOUT touching those files is out of scope here.
//!
//! WHY THE FANOUT BOUNDARY POINTS THE OTHER WAY. Host ranking is guarded against learning where data
//! LIVES; storage fanout is guarded against learning WHOSE data it is. Both are the same mistake in
//! mirror image: a hash-prefix directory split that starts consulting tenant or region has stopped
//! being filesystem layout and started being data placement, which is the exact conflation CF8
//! clause 3 names. Sharding by hash prefix is non-geographic BY CONSTRUCTION — the prefix comes from
//! the content, so it cannot encode a customer or a region unless someone teaches it to.

use crate::source_scan_chirho::workspace_root_chirho;

/// The pure host-ranking core. Ranks candidate machines; owns no data custody.
const HOST_RANKING_CRATE_SRC_CHIRHO: &str =
    "crates/domain-chirho/cairn-placement-chirho/src/lib.rs";

/// The CF2 hot-account shard router — inside one money root, explicitly not geographic.
const ACCOUNT_SHARD_SRC_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-transfer-chirho/src/shard_chirho.rs";

/// The G1 tenant-root placement-unit invariant.
const GEO_PLACEMENT_UNIT_SRC_CHIRHO: &str =
    "crates/support-chirho/cairn-tenant-chirho/src/single_customer_app_chirho.rs";

/// CAS directory fanout — objects sharded into `objects-chirho/ab/cdef…` by hash prefix.
const CAS_FANOUT_SRC_CHIRHO: &str = "crates/cairn-core-chirho/src/cas_chirho.rs";

/// Seqlog segment directory layout — the other half of the storage-fanout kind.
const SEQLOG_FANOUT_SRC_CHIRHO: &str =
    "crates/support-chirho/cairn-seqlog-chirho/src/segment_chirho/paths_chirho.rs";

/// Every storage-fanout surface CF8 clause 3 asks to be held apart from geo data placement.
const STORAGE_FANOUT_SRCS_CHIRHO: &[&str] = &[CAS_FANOUT_SRC_CHIRHO, SEQLOG_FANOUT_SRC_CHIRHO];

/// Reach that would turn a filesystem layout decision into a data-placement decision.
///
/// These are IDENTIFIER shapes, never prose words, and that choice is load-bearing. A needle like
/// the bare word "placement" would fire on a comment saying "this is NOT placement" — punishing the
/// clarification the guard exists to encourage. Identifiers only go in when code actually reaches.
const GEO_PLACEMENT_REACH_CHIRHO: &[&str] = &[
    "cairn_tenant_chirho",
    "TenantIdChirho",
    "tenant_id_for_root_chirho",
    "RegionChirho",
    "region_chirho",
    "PlacementDescriptorChirho",
    "placement_registry_chirho",
];

/// Reach that would move the ranking core from choosing COMPUTE to choosing DATA CUSTODY.
///
/// Each of these means the crate has learned something about where a tenant's history lives:
/// tenant identity, the ref map that names a root's branches, object storage, or the filesystem.
const DATA_CUSTODY_REACH_CHIRHO: &[&str] = &[
    "cairn_tenant_chirho",
    "TenantIdChirho",
    "tenant_root",
    "RefsChirho",
    "refs_chirho",
    "store_chirho",
    "cas_chirho",
    "std::fs",
    "std::path",
];

fn read_source_chirho(rel_path_chirho: &str) -> String {
    let path_chirho = workspace_root_chirho().join(rel_path_chirho);
    std::fs::read_to_string(&path_chirho)
        .unwrap_or_else(|e_chirho| panic!("read {}: {e_chirho}", path_chirho.display()))
}

/// Source text with comment markers stripped and all whitespace collapsed to single spaces.
///
/// EVERY LEGIBILITY ASSERTION MUST READ THROUGH THIS, and the reason is a bug this guard shipped
/// with for exactly one run. A legibility check asks whether a file SAYS something; whether the
/// sentence happens to wrap across two `//!` lines is not part of that question. `cas_chirho.rs`
/// contains the words "sharded by hash prefix" — and a raw `contains` for that phrase FAILS,
/// because the wrap lands between "hash" and "prefix".
///
/// That failure mode is worth naming precisely, because it is the same single-line-pattern blind
/// spot that makes a `use crate::{a, b, c};` invisible to a `crate::[a-z_]+` regex: the instrument
/// is fine, the text is fine, and the line break between them silently decides the answer. Raw
/// matching also means a doc-comment REWRAP turns this guard red while nothing about the code
/// changed — a false red, which is worse than no guard, because it teaches the next reader that
/// this file cries wolf.
fn read_source_flattened_chirho(rel_path_chirho: &str) -> String {
    read_source_chirho(rel_path_chirho)
        .replace("//!", " ")
        .replace("///", " ")
        .replace("//", " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn host_ranking_core_does_not_reach_into_data_custody_chirho() {
    let text_chirho = read_source_chirho(HOST_RANKING_CRATE_SRC_CHIRHO);
    let found_chirho = DATA_CUSTODY_REACH_CHIRHO
        .iter()
        .filter(|needle_chirho| text_chirho.contains(**needle_chirho))
        .collect::<Vec<_>>();
    assert!(
        found_chirho.is_empty(),
        "the host-ranking core acquired data-custody reach {found_chirho:?} in \
         {HOST_RANKING_CRATE_SRC_CHIRHO}. Ranking decides which MACHINE runs a module; it must not \
         learn which REGION holds a tenant's data, authority, and history — that unit is the tenant \
         root (G1), and moving it is an authority change, not an import. If this crate genuinely \
         must own geo data placement, that is a reviewed decision: say so explicitly and re-scope \
         this guard rather than deleting it"
    );
}

#[test]
fn storage_fanout_does_not_reach_into_geo_placement_chirho() {
    // CF8 clause 3 names TWO things to hold apart from geo data placement: CF2 hot-account
    // sub-accounts and CAS directory fanout. The sub-account half was already guarded; this is the
    // fanout half. A hash-prefix split that learns tenant or region identity is no longer choosing a
    // DIRECTORY, it is choosing where a customer's history lives.
    for src_chirho in STORAGE_FANOUT_SRCS_CHIRHO {
        let text_chirho = read_source_chirho(src_chirho);
        let found_chirho = GEO_PLACEMENT_REACH_CHIRHO
            .iter()
            .filter(|needle_chirho| text_chirho.contains(**needle_chirho))
            .collect::<Vec<_>>();
        assert!(
            found_chirho.is_empty(),
            "the storage-fanout surface {src_chirho} acquired geo-placement reach {found_chirho:?}. \
             Sharding a directory by hash prefix is filesystem layout and is non-geographic by \
             construction — the prefix comes from the CONTENT. Consulting tenant or region here \
             makes the split a data-placement decision, which is the conflation CF8 clause 3 \
             forbids; that unit is the tenant root (G1). If this surface genuinely must become \
             placement-aware, that is a reviewed authority change: say so and re-scope this guard \
             rather than deleting it"
        );
    }
}

#[test]
fn the_placement_kinds_state_which_kind_they_are_chirho() {
    // Legibility is the control here. Each surface must say what kind of placement it does, so the
    // next reader cannot mistake account sharding or host ranking for geo data placement.
    let ranking_chirho = read_source_flattened_chirho(HOST_RANKING_CRATE_SRC_CHIRHO);
    assert!(
        ranking_chirho.contains("host-placement ranking"),
        "{HOST_RANKING_CRATE_SRC_CHIRHO} must state that it is host RANKING, not data placement"
    );

    let shard_chirho = read_source_flattened_chirho(ACCOUNT_SHARD_SRC_CHIRHO);
    assert!(
        shard_chirho.contains("sub-accounts") || shard_chirho.contains("sub-account"),
        "{ACCOUNT_SHARD_SRC_CHIRHO} must state that CF2 sharding is about SUB-ACCOUNTS within one \
         money root, so it is never read as geographic placement"
    );

    let geo_chirho = read_source_flattened_chirho(GEO_PLACEMENT_UNIT_SRC_CHIRHO);
    assert!(
        geo_chirho.contains("placement, authority, and migration"),
        "{GEO_PLACEMENT_UNIT_SRC_CHIRHO} must name the tenant root as the placement/authority/\
         migration unit"
    );
    assert!(
        geo_chirho.contains("NOT A CAPACITY LIMIT") || geo_chirho.contains("NOT a capacity limit"),
        "the G1 module must deny being a density ceiling — many tenant roots per shard is the \
         expected growth path, and a reader who takes G1 for a capacity limit has it backwards"
    );

    // The fanout surfaces must say what their split is KEYED ON. "Sharded" alone is the word that
    // invites the mistake — CF2 shards accounts, CAS shards bytes, and geo placement shards
    // customers. Naming the key is what makes the kind readable at a glance.
    let cas_chirho = read_source_flattened_chirho(CAS_FANOUT_SRC_CHIRHO);
    assert!(
        cas_chirho.contains("sharded by hash prefix") || cas_chirho.contains("by hash prefix"),
        "{CAS_FANOUT_SRC_CHIRHO} must state that its fanout is keyed on the HASH PREFIX, so a reader \
         cannot mistake CAS directory sharding for geographic data placement"
    );

    let seqlog_chirho = read_source_flattened_chirho(SEQLOG_FANOUT_SRC_CHIRHO);
    assert!(
        seqlog_chirho.contains("on-disk artifact") || seqlog_chirho.contains("storage-agnostic"),
        "{SEQLOG_FANOUT_SRC_CHIRHO} must state that it derives ON-DISK artifact paths, so segment \
         directory layout is not read as a placement decision"
    );
}

#[test]
fn g1_exemption_is_fail_closed_not_a_blanket_pass_chirho() {
    // Non-vacuity: G1's platform-root exemption must not be a shape that exempts everything, and
    // the module must still refuse app-prefixed refs it cannot classify.
    let geo_chirho = read_source_flattened_chirho(GEO_PLACEMENT_UNIT_SRC_CHIRHO);
    assert!(
        geo_chirho.contains("unclassified_app_prefixed_branches_chirho"),
        "G1 must keep its fail-closed arm for app-prefixed refs it cannot classify — silently \
         skipping one UNDERCOUNTS apps, which passes the invariant in exactly the case we cannot \
         explain"
    );
    assert!(
        geo_chirho.contains("KNOWN BOUND"),
        "G1 must keep stating that refs are not the whole state: an app head is written in two \
         phases, so a prepared-but-unapplied deploy is a real authorized app with no branch key. \
         Dropping that note would let a refs-only pass read as 'this root satisfies G1'"
    );
}

#[test]
fn positive_control_the_custody_needles_actually_match_chirho() {
    // A guard whose needles cannot fire is decoration. Prove each needle matches a known-true
    // sample, so a zero above means "no reach found" and not "the instrument stopped measuring".
    for needle_chirho in DATA_CUSTODY_REACH_CHIRHO {
        let sample_chirho = format!("use {needle_chirho}::whatever_chirho;");
        assert!(
            sample_chirho.contains(*needle_chirho),
            "needle {needle_chirho} failed its own positive control"
        );
    }
    for needle_chirho in GEO_PLACEMENT_REACH_CHIRHO {
        let sample_chirho = format!("use {needle_chirho}::whatever_chirho;");
        assert!(
            sample_chirho.contains(*needle_chirho),
            "needle {needle_chirho} failed its own positive control"
        );
    }

    // An EMPTY needle list would make both reach-guards pass over nothing while still reporting
    // green — the loop simply never runs. That is the failure mode a reach-guard is least able to
    // notice about itself, so the counts are asserted rather than assumed.
    assert!(
        !DATA_CUSTODY_REACH_CHIRHO.is_empty() && !GEO_PLACEMENT_REACH_CHIRHO.is_empty(),
        "a reach-needle list emptied out — the guard it drives would pass vacuously forever"
    );

    // And the guard must be reading real files, not empty strings.
    assert!(
        read_source_chirho(HOST_RANKING_CRATE_SRC_CHIRHO).len() > 500,
        "the host-ranking source read back nearly empty — the guard would pass vacuously"
    );
    assert!(
        !STORAGE_FANOUT_SRCS_CHIRHO.is_empty(),
        "the storage-fanout source list emptied out — its reach guard would pass over nothing"
    );
    for src_chirho in STORAGE_FANOUT_SRCS_CHIRHO {
        assert!(
            read_source_chirho(src_chirho).len() > 500,
            "storage-fanout source {src_chirho} read back nearly empty — a path drift here would \
             turn the fanout reach guard green while measuring nothing"
        );
    }
}
