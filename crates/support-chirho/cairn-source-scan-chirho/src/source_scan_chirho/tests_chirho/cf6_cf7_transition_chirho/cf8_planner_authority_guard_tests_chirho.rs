// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! CF8 clause 10's *"planner source cannot mint fences or commit heads"* — ENFORCED, not merely written down.
//!
//! **Why this guard exists is the interesting part.** That clause phrase was already asserted
//! somewhere: `public_root_inventory_guard_tests_chirho` requires the PRD's CF8 acceptance TEXT to
//! contain it. That is a guard on the REQUIREMENT, not on the property — it proves the sentence is
//! written down and would stay green if the planner grew head-mutating authority tomorrow. Finding a
//! clause phrase in the tree is not finding the property enforced, which is the same lesson
//! `cf8_clause_map_guard_tests_chirho` was built for one level up.
//!
//! The property currently holds STRUCTURALLY: `cairn-placement-chirho` declares only `anyhow`,
//! `cairn-core-chirho` and `serde`, so it cannot reach a fence or a head — not because it declines to,
//! but because those types are not in its dependency closure. Structural is the strongest kind, and
//! it is also the kind that a single convenient `Cargo.toml` line silently ends. So it is pinned here.
//!
//! Modelled on `p3_replication_guard_tests_chirho`, which pins the same shape for replication crates:
//! forbidden dependency edges, forbidden source tokens, and a non-empty assertion so that path drift
//! fails loudly instead of passing over an empty file set.

use crate::source_scan_chirho::{workspace_production_rs_files_chirho, workspace_root_chirho};

/// The planner/placement authority surface CF8 clause 10 constrains.
const PLANNER_CRATES_CHIRHO: &[&str] = &["crates/domain-chirho/cairn-placement-chirho"];

/// Crates the planner must NEVER depend on — anything that can advance a head, mint a fence, hold
/// Ring-A authority, or reach the money root.
const FORBIDDEN_PLANNER_DEPS_CHIRHO: &[&str] = &[
    "cairn-writer-head-chirho",
    "cairn-head-removal-chirho",
    "cairn-gate1-authority-log-chirho",
    "cairn-economic-governance-chirho",
    "cairn-ledger-log-chirho",
    "cairn-chirho",
    "cairn-serve-runtime-chirho",
    "cairn-app-control-chirho",
];

/// Source tokens the planner must never name. A crate cannot mint what it cannot call.
const FORBIDDEN_PLANNER_TOKENS_CHIRHO: &[&str] = &[
    "commit_head_chirho(",
    "advance_head_chirho(",
    "mint_fence_chirho(",
    "install_fence_chirho(",
    "append_authority_chirho(",
];

fn declares_dep_chirho(cargo_chirho: &str, dep_chirho: &str) -> bool {
    cargo_chirho
        .lines()
        .any(|line_chirho| line_chirho.trim_start().starts_with(dep_chirho))
}

#[test]
fn the_planner_declares_no_head_or_fence_authority_dependency_chirho() {
    for crate_dir_chirho in PLANNER_CRATES_CHIRHO {
        let cargo_path_chirho = workspace_root_chirho()
            .join(crate_dir_chirho)
            .join("Cargo.toml");
        let cargo_chirho = std::fs::read_to_string(&cargo_path_chirho)
            .unwrap_or_else(|_| panic!("read {}", cargo_path_chirho.display()));
        for forbidden_chirho in FORBIDDEN_PLANNER_DEPS_CHIRHO {
            assert!(
                !declares_dep_chirho(&cargo_chirho, forbidden_chirho),
                "{crate_dir_chirho} must not depend on {forbidden_chirho}: CF8 clause 10 requires \
                 that planner source cannot mint fences or commit heads, and a dependency edge is \
                 how that capability arrives"
            );
        }
    }
}

#[test]
fn the_planner_source_never_names_a_head_or_fence_mutator_chirho() {
    let planner_files_chirho: Vec<_> = workspace_production_rs_files_chirho()
        .into_iter()
        .filter(|path_chirho| {
            let text_chirho = path_chirho.to_string_lossy().replace('\\', "/");
            PLANNER_CRATES_CHIRHO
                .iter()
                .any(|crate_dir_chirho| text_chirho.contains(&format!("{crate_dir_chirho}/src")))
        })
        .collect();
    // Non-empty is the guard on the guard: a filter that matched nothing would pass every assertion
    // below while measuring an empty world.
    assert!(
        !planner_files_chirho.is_empty(),
        "the CF8 planner-authority guard found no placement source files — path drift?"
    );
    for path_chirho in planner_files_chirho {
        let raw_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        for forbidden_chirho in FORBIDDEN_PLANNER_TOKENS_CHIRHO {
            assert!(
                !raw_chirho.contains(forbidden_chirho),
                "{} names {forbidden_chirho}: the planner must not be able to mint a fence or \
                 commit a head",
                path_chirho.display()
            );
        }
    }
}

#[test]
fn positive_control_the_dependency_reader_can_see_a_declared_dep_chirho() {
    // Proves the instrument works before its zero answers are believed: the same reader must find a
    // dependency the planner DOES declare. Without this, a broken reader reports "no forbidden deps"
    // for every crate in the tree.
    let cargo_chirho = std::fs::read_to_string(
        workspace_root_chirho()
            .join(PLANNER_CRATES_CHIRHO[0])
            .join("Cargo.toml"),
    )
    .expect("read the planner manifest");
    assert!(
        declares_dep_chirho(&cargo_chirho, "cairn-core-chirho"),
        "the dependency reader failed to see a dep the planner really declares — the zero answers \
         above would be meaningless"
    );
    assert!(
        !declares_dep_chirho(&cargo_chirho, "cairn-nonexistent-crate-chirho"),
        "the dependency reader claimed a dep that is not declared"
    );
}
