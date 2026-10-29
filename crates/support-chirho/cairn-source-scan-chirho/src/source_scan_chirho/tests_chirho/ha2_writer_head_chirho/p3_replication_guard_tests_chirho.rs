// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! P3 no-transport-advances-a-head guard: the replication crates must have ZERO dependency on any
//! head/ref-mutating crate and must never name a head mutator, so a replica is structurally unable
//! to advance authority — the core P3 invariant, enforced at the crate boundary, not just by review.

use super::super::*;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::process::Command;

const REPLICATION_CRATES_CHIRHO: &[&str] = &[
    "crates/services-chirho/cairn-replication-chirho",
    "crates/stores-chirho/cairn-roster-config-chirho",
    "crates/stores-chirho/cairn-roster-convergence-chirho",
    "crates/stores-chirho/cairn-replication-localfs-chirho",
    "crates/stores-chirho/cairn-replication-http-chirho",
    "crates/stores-chirho/cairn-store-s3-chirho",
    "crates/stores-chirho/cairn-replica-serve-http-chirho",
    "crates/runtime-chirho/cairn-pure-executor-chirho",
];

/// Crates a replication crate must NEVER depend on — anything that can advance a head, hold Ring-A
/// authority, or reach the money root.
const FORBIDDEN_DEPS_CHIRHO: &[&str] = &[
    "cairn-writer-head-chirho",
    "cairn-head-removal-chirho",
    "cairn-gate1-authority-log-chirho",
    "cairn-economic-governance-chirho",
    "cairn-chirho",
    "cairn-serve-runtime-chirho",
    "cairn-app-control-chirho",
];

/// Source tokens a replication crate must never name — any head/ref mutation or authority append.
const FORBIDDEN_TOKENS_CHIRHO: &[&str] = &[
    "commit_head_chirho(",
    "with_head_commit_chirho(",
    "set_branch_chirho(",
    "rollback_chirho(",
    "remove_branch_chirho(",
    "compare_and_set_branch_chirho(",
    "append_gate1_authority_record",
    "save_refs_chirho(",
    "issue_writer_fence",
];

fn declares_dep_chirho(cargo_chirho: &str, dep_chirho: &str) -> bool {
    cargo_chirho
        .lines()
        .any(|line_chirho| line_chirho.split('=').next().unwrap_or("").trim() == dep_chirho)
}

fn package_name_chirho(crate_dir_chirho: &str) -> String {
    let cargo_path_chirho = workspace_root_chirho()
        .join(crate_dir_chirho)
        .join("Cargo.toml");
    let cargo_chirho = std::fs::read_to_string(&cargo_path_chirho)
        .unwrap_or_else(|_| panic!("read {}", cargo_path_chirho.display()));
    cargo_chirho
        .parse::<toml::Value>()
        .expect("parse guarded replication Cargo.toml")
        .get("package")
        .and_then(|package_chirho| package_chirho.get("name"))
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("{} has no package.name", cargo_path_chirho.display()))
        .to_string()
}

fn production_dependency_graph_chirho() -> BTreeMap<String, BTreeSet<String>> {
    let cargo_chirho = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output_chirho = Command::new(cargo_chirho)
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(workspace_root_chirho())
        .output()
        .expect("execute cargo metadata for P3 dependency closure");
    assert!(
        output_chirho.status.success(),
        "cargo metadata failed for P3 dependency closure: {}",
        String::from_utf8_lossy(&output_chirho.stderr)
    );
    let metadata_chirho: serde_json::Value =
        serde_json::from_slice(&output_chirho.stdout).expect("parse cargo metadata JSON");
    let mut names_by_id_chirho = BTreeMap::<String, String>::new();
    for package_chirho in metadata_chirho
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .expect("cargo metadata package population")
    {
        let id_chirho = package_chirho
            .get("id")
            .and_then(serde_json::Value::as_str)
            .expect("cargo metadata package id");
        let name_chirho = package_chirho
            .get("name")
            .and_then(serde_json::Value::as_str)
            .expect("cargo metadata package name");
        names_by_id_chirho.insert(id_chirho.to_string(), name_chirho.to_string());
    }

    let mut graph_chirho = BTreeMap::<String, BTreeSet<String>>::new();
    for node_chirho in metadata_chirho
        .pointer("/resolve/nodes")
        .and_then(serde_json::Value::as_array)
        .expect("cargo metadata resolved-node population")
    {
        let package_id_chirho = node_chirho
            .get("id")
            .and_then(serde_json::Value::as_str)
            .expect("resolved package id");
        let package_name_chirho = names_by_id_chirho
            .get(package_id_chirho)
            .unwrap_or_else(|| panic!("resolved package id has no name: {package_id_chirho}"))
            .clone();
        let dependencies_chirho = graph_chirho.entry(package_name_chirho).or_default();
        for dependency_chirho in node_chirho
            .get("deps")
            .and_then(serde_json::Value::as_array)
            .expect("resolved dependency population")
        {
            let production_edge_chirho = dependency_chirho
                .get("dep_kinds")
                .and_then(serde_json::Value::as_array)
                .expect("resolved dependency kinds")
                .iter()
                .any(|kind_chirho| {
                    kind_chirho
                        .get("kind")
                        .is_none_or(serde_json::Value::is_null)
                        || kind_chirho.get("kind").and_then(serde_json::Value::as_str)
                            == Some("build")
                });
            if production_edge_chirho {
                let dependency_id_chirho = dependency_chirho
                    .get("pkg")
                    .and_then(serde_json::Value::as_str)
                    .expect("resolved dependency package id");
                let dependency_name_chirho = names_by_id_chirho
                    .get(dependency_id_chirho)
                    .unwrap_or_else(|| panic!("dependency id has no name: {dependency_id_chirho}"));
                dependencies_chirho.insert(dependency_name_chirho.clone());
            }
        }
    }
    graph_chirho
}

fn reachable_dependencies_chirho(
    graph_chirho: &BTreeMap<String, BTreeSet<String>>,
    package_chirho: &str,
) -> BTreeSet<String> {
    let mut reachable_chirho = BTreeSet::new();
    let mut pending_chirho = VecDeque::from([package_chirho.to_string()]);
    while let Some(candidate_chirho) = pending_chirho.pop_front() {
        if !reachable_chirho.insert(candidate_chirho.clone()) {
            continue;
        }
        if let Some(dependencies_chirho) = graph_chirho.get(&candidate_chirho) {
            pending_chirho.extend(dependencies_chirho.iter().cloned());
        }
    }
    reachable_chirho
}

#[test]
fn replication_crates_have_no_write_authority_dependency_chirho() {
    for crate_dir_chirho in REPLICATION_CRATES_CHIRHO {
        let cargo_path_chirho = workspace_root_chirho()
            .join(crate_dir_chirho)
            .join("Cargo.toml");
        let cargo_chirho = std::fs::read_to_string(&cargo_path_chirho)
            .unwrap_or_else(|_| panic!("read {}", cargo_path_chirho.display()));
        for forbidden_chirho in FORBIDDEN_DEPS_CHIRHO {
            assert!(
                !declares_dep_chirho(&cargo_chirho, forbidden_chirho),
                "{crate_dir_chirho} must not depend on {forbidden_chirho}: a P3 replica has zero write authority"
            );
        }
    }
}

#[test]
fn replication_crates_have_no_transitive_write_authority_dependency_chirho() {
    let graph_chirho = production_dependency_graph_chirho();
    assert!(
        graph_chirho
            .get("cairn-replication-http-chirho")
            .is_some_and(|dependencies_chirho| {
                dependencies_chirho.contains("cairn-replication-chirho")
            }),
        "the P3 dependency-closure guard lost its known replication dependency positive control"
    );

    for crate_dir_chirho in REPLICATION_CRATES_CHIRHO {
        let package_chirho = package_name_chirho(crate_dir_chirho);
        let reachable_chirho = reachable_dependencies_chirho(&graph_chirho, &package_chirho);
        assert!(
            reachable_chirho.contains(&package_chirho),
            "the P3 closure for {package_chirho} measured an empty world"
        );
        for forbidden_chirho in FORBIDDEN_DEPS_CHIRHO {
            assert!(
                !reachable_chirho.contains(*forbidden_chirho),
                "{package_chirho} transitively reaches {forbidden_chirho}: a P3 replica has zero write authority across its whole production dependency closure"
            );
        }
    }
}

#[test]
fn replication_crate_source_never_names_a_head_mutator_chirho() {
    let replication_files_chirho: Vec<_> = workspace_production_rs_files_chirho()
        .into_iter()
        .filter(|path_chirho| {
            let rel_chirho = workspace_relative_chirho(path_chirho);
            REPLICATION_CRATES_CHIRHO
                .iter()
                .any(|crate_dir_chirho| rel_chirho.starts_with(&format!("{crate_dir_chirho}/src")))
        })
        .collect();
    assert!(
        !replication_files_chirho.is_empty(),
        "the P3 replication guard found no replication source files — path drift?"
    );
    for path_chirho in replication_files_chirho {
        let raw_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let text_chirho = production_text_chirho(&raw_chirho);
        for token_chirho in FORBIDDEN_TOKENS_CHIRHO {
            assert!(
                !text_chirho.contains(token_chirho),
                "{} names head mutator {token_chirho}: a P3 replica must not advance any head",
                workspace_relative_chirho(&path_chirho)
            );
        }
    }
}

#[test]
fn roster_config_remains_a_verifier_without_signing_custody_chirho() {
    const ROSTER_CONFIG_CRATE_CHIRHO: &str = "crates/stores-chirho/cairn-roster-config-chirho";
    const FORBIDDEN_SIGNING_TOKENS_CHIRHO: &[&str] = &[
        "sign_with_existing_key_possession_chirho(",
        "sign_message_chirho(",
        "existing_keypair_pubkey_hex_chirho(",
    ];

    let cargo_chirho = std::fs::read_to_string(
        workspace_root_chirho()
            .join(ROSTER_CONFIG_CRATE_CHIRHO)
            .join("Cargo.toml"),
    )
    .unwrap();
    let production_dependencies_chirho = cargo_chirho
        .split_once("[dev-dependencies]")
        .map_or(cargo_chirho.as_str(), |(before_chirho, _)| before_chirho);
    assert!(
        !declares_dep_chirho(production_dependencies_chirho, "cairn-signer-chirho"),
        "roster config must verify and derive configuration without production signing custody"
    );

    for path_chirho in workspace_production_rs_files_chirho()
        .into_iter()
        .filter(|path_chirho| {
            workspace_relative_chirho(path_chirho)
                .starts_with(&format!("{ROSTER_CONFIG_CRATE_CHIRHO}/src"))
        })
    {
        let raw_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let source_chirho = production_text_chirho(&raw_chirho);
        for token_chirho in FORBIDDEN_SIGNING_TOKENS_CHIRHO {
            assert!(
                !source_chirho.contains(token_chirho),
                "{} names {token_chirho}: offline roster authoring belongs in the authoring crate",
                workspace_relative_chirho(&path_chirho)
            );
        }
    }
}

#[test]
fn projection_replication_source_remains_read_only_and_verification_only_chirho() {
    const PROJECTION_REPLICATION_PRODUCTION_PATHS_CHIRHO: &[&str] = &[
        "crates/stores-chirho/cairn-replication-http-chirho/src/projection_replication_chirho/model_chirho.rs",
        "crates/stores-chirho/cairn-replication-http-chirho/src/projection_replication_chirho/pull_chirho.rs",
        "crates/stores-chirho/cairn-replication-http-chirho/src/projection_replication_chirho/source_chirho.rs",
        "crates/stores-chirho/cairn-replication-http-chirho/src/bin/projection_replica_pull_chirho.rs",
        "crates/stores-chirho/cairn-replication-http-chirho/src/bin/projection_replication_source_chirho.rs",
    ];
    const FORBIDDEN_SIGNING_TOKENS_CHIRHO: &[&str] = &[
        "sign_message_chirho(",
        "sign_message_with_existing_key_chirho(",
        "sign_with_existing_key_possession_chirho(",
        "load_or_create_signing_key_chirho(",
        "pubkey_hex_chirho(",
    ];
    const SOURCE_ONLY_PATHS_CHIRHO: &[&str] = &[
        "crates/stores-chirho/cairn-replication-http-chirho/src/projection_replication_chirho/source_chirho.rs",
        "crates/stores-chirho/cairn-replication-http-chirho/src/bin/projection_replication_source_chirho.rs",
    ];
    const FORBIDDEN_SOURCE_MUTATION_TOKENS_CHIRHO: &[&str] = &[
        "write_file_durable_chirho(",
        "create_file_durable_chirho(",
        "append_durable_line_chirho(",
        "atomic_write_chirho(",
        "append_durable_chirho(",
        "LedgerStoragePortChirho",
    ];

    for relative_chirho in PROJECTION_REPLICATION_PRODUCTION_PATHS_CHIRHO {
        let source_chirho =
            std::fs::read_to_string(workspace_root_chirho().join(relative_chirho)).unwrap();
        for token_chirho in FORBIDDEN_SIGNING_TOKENS_CHIRHO {
            assert!(
                !source_chirho.contains(token_chirho),
                "{relative_chirho} names signing capability {token_chirho}: projection replication may verify but never sign"
            );
        }
    }
    for relative_chirho in SOURCE_ONLY_PATHS_CHIRHO {
        let source_chirho =
            std::fs::read_to_string(workspace_root_chirho().join(relative_chirho)).unwrap();
        for token_chirho in FORBIDDEN_SOURCE_MUTATION_TOKENS_CHIRHO {
            assert!(
                !source_chirho.contains(token_chirho),
                "{relative_chirho} names mutation capability {token_chirho}: the projection source must be read-only"
            );
        }
    }
}

/// Replica-side production paths that must never name signing capability.
///
/// **PER-PATH IS THE CORRECT SHAPE HERE, NOT A COMPROMISE — do not "simplify" this to crate-wide.**
/// `cairn-replication-chirho` legitimately contains the SOURCE-side publisher: `ref_snapshot_chirho`
/// signs the snapshot head with the source root's key, which is the one signing call P3 requires. A
/// blanket crate-wide ban would forbid it and break the publisher. So the ban is scoped to the
/// modules that run on the REPLICA side, and the publisher is pinned by count instead (below).
///
/// WHAT THIS CLOSES. CF8 clause 2 requires these properties green "without transferring signing,
/// head, or append authority to replicas". Head and append are guarded crate-wide by the two tests
/// above. Signing was guarded only for `cairn-roster-config-chirho` and five named projection-
/// replication files — leaving the replica SERVE path unguarded. Measured before this guard existed:
/// none of these eight files named a signing token, and the only sign site in the serve crate was a
/// test fixture (`tests/replica_serve_chirho.rs:114`).
///
/// **So this is not fixing a live defect — it is retiring an unguarded invariant.** The property was
/// TRUE BY CENSUS, and a census is true today and silent tomorrow: the first replica-serve change
/// that added a signing call would have passed every gate we run. An acceptance clause on the final
/// gate cannot rest on someone having looked once.
const REPLICA_SIDE_NO_SIGNING_PATHS_CHIRHO: &[&str] = &[
    "crates/services-chirho/cairn-replication-chirho/src/fold_plane_chirho.rs",
    "crates/services-chirho/cairn-replication-chirho/src/lib.rs",
    "crates/services-chirho/cairn-replication-chirho/src/membership_chirho.rs",
    "crates/services-chirho/cairn-replication-chirho/src/receiver_chirho.rs",
    "crates/services-chirho/cairn-replication-chirho/src/sync_floor_chirho.rs",
    "crates/stores-chirho/cairn-replica-serve-http-chirho/src/lib.rs",
    "crates/stores-chirho/cairn-replica-serve-http-chirho/src/composition_chirho.rs",
    "crates/stores-chirho/cairn-replica-serve-http-chirho/src/bin/replica_serve_chirho.rs",
];

/// The ONE file that may sign, and the EXACT number of times it may.
///
/// Excluding this file from the path list above would leave its replica-side code — the verified
/// snapshot-head readers that share it — unguarded. Pinning the count instead keeps the legitimate
/// publisher working while making a SECOND signing call anywhere in the file fail closed.
const SOURCE_PUBLISHER_PATH_CHIRHO: &str =
    "crates/services-chirho/cairn-replication-chirho/src/ref_snapshot_chirho.rs";
const SOURCE_PUBLISHER_SIGN_SITES_CHIRHO: usize = 1;

#[test]
fn replica_side_modules_verify_but_never_sign_chirho() {
    // An emptied path list makes the loop below run ZERO times and report green — the guard would
    // pass forever while measuring nothing, which is how a coverage guard dies quietly. The count is
    // asserted so shrinking the population is a RED rather than a silent narrowing.
    assert_eq!(
        REPLICA_SIDE_NO_SIGNING_PATHS_CHIRHO.len(),
        8,
        "the replica-side path population changed. If a replica module was added, guard it; if one \
         was removed or became source-side, update this count deliberately and say why — a guard \
         that silently covers fewer paths still reports success"
    );
    for relative_chirho in REPLICA_SIDE_NO_SIGNING_PATHS_CHIRHO {
        let source_chirho =
            std::fs::read_to_string(workspace_root_chirho().join(relative_chirho)).unwrap();
        for token_chirho in [
            "sign_message_chirho(",
            "sign_message_with_existing_key_chirho(",
            "sign_with_existing_key_possession_chirho(",
            "load_or_create_signing_key_chirho(",
        ] {
            assert!(
                !source_chirho.contains(token_chirho),
                "{relative_chirho} names signing capability {token_chirho}: a replica VERIFIES with \
                 the pinned source key and holds no signing authority of its own (CF8 clause 2). If \
                 this path genuinely became source-side, move it out of this list deliberately and \
                 say why — do not widen the list to make a red go away"
            );
        }
    }
}

#[test]
fn the_source_publisher_signs_exactly_once_chirho() {
    // The publisher's single call is allowlisted BY COUNT, so the file keeps working while a new
    // signing call anywhere in it — including in its replica-side readers — goes red.
    let source_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(SOURCE_PUBLISHER_PATH_CHIRHO))
            .unwrap();
    let sites_chirho = source_chirho.matches("sign_message_chirho(").count();
    assert_eq!(
        sites_chirho, SOURCE_PUBLISHER_SIGN_SITES_CHIRHO,
        "{SOURCE_PUBLISHER_PATH_CHIRHO} has {sites_chirho} signing call sites, expected \
         {SOURCE_PUBLISHER_SIGN_SITES_CHIRHO}. The ONE permitted site is the source-side snapshot-head \
         export, which signs with the SOURCE root's key. A second site is either a replica acquiring \
         signing authority — which CF8 clause 2 forbids — or a real new source-side capability that \
         needs its own review. Neither should be absorbed by bumping this number"
    );
    // Non-vacuity: the token must actually be findable, or a rename would make this pass at zero.
    assert!(
        sites_chirho > 0,
        "no signing call site found at all — if sign_message_chirho was renamed, this guard is \
         measuring nothing and must be retargeted, not deleted"
    );
}
