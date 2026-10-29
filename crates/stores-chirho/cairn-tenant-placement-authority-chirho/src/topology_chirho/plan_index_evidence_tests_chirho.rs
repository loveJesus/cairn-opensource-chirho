// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Exercises the complete index audit, its read bounds, and its no-write boundary.

use super::*;
use crate::topology_chirho::plan_store_chirho::{
    store_topology_plan_chirho, TOPOLOGY_PLAN_INDEX_LOG_CHIRHO,
    TOPOLOGY_PLAN_INDEX_MAX_BYTES_CHIRHO,
};
use cairn_core_chirho::{cas_chirho, store_chirho};
use cairn_placement_chirho::topology_chirho::topology_grant_chirho::{
    NodeRoleChirho, PlannedNodeChirho,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

fn plan_chirho(rate_chirho: u64) -> DesiredTopologyPlanChirho {
    DesiredTopologyPlanChirho {
        cited_grant_id_chirho: "unapproved-fixture-grant-chirho".to_owned(),
        nodes_chirho: vec![PlannedNodeChirho {
            provider_chirho: "fixture-provider-chirho".to_owned(),
            role_chirho: NodeRoleChirho::WorkerChirho,
        }],
        spend_rate_micros_per_hour_chirho: rate_chirho,
        proposed_grant_chirho: None,
    }
}

fn object_path_chirho(root_chirho: &Path, address_chirho: &str) -> PathBuf {
    root_chirho
        .join("objects-chirho")
        .join(&address_chirho[..2])
        .join(&address_chirho[2..])
}

fn write_rows_chirho(root_chirho: &Path, rows_chirho: &[TopologyPlanIndexRowChirho]) {
    let mut bytes_chirho = Vec::new();
    for row_chirho in rows_chirho {
        serde_json::to_writer(&mut bytes_chirho, row_chirho).unwrap();
        bytes_chirho.push(b'\n');
    }
    fs::write(
        root_chirho.join(TOPOLOGY_PLAN_INDEX_LOG_CHIRHO),
        bytes_chirho,
    )
    .unwrap();
}

fn tree_bytes_chirho(root_chirho: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut bytes_chirho = BTreeMap::new();
    for entry_chirho in fs::read_dir(root_chirho).unwrap() {
        let path_chirho = entry_chirho.unwrap().path();
        if path_chirho.is_dir() {
            bytes_chirho.extend(tree_bytes_chirho(&path_chirho));
        } else {
            bytes_chirho.insert(path_chirho.clone(), fs::read(path_chirho).unwrap());
        }
    }
    bytes_chirho
}

#[test]
fn topology_index_audit_preserves_duplicate_rows_without_writing_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    for rate_chirho in [10, 20, 10] {
        store_topology_plan_chirho(root_chirho.path(), &plan_chirho(rate_chirho)).unwrap();
    }
    let before_chirho = tree_bytes_chirho(root_chirho.path());
    let rows_chirho = load_verified_topology_plan_index_chirho(root_chirho.path()).unwrap();
    assert_eq!(rows_chirho.len(), 3);
    assert_eq!(rows_chirho[0], rows_chirho[2]);
    assert_ne!(rows_chirho[0], rows_chirho[1]);
    assert_eq!(verify_topology_plan_index_chirho(root_chirho.path()), Ok(3));
    assert_eq!(tree_bytes_chirho(root_chirho.path()), before_chirho);
}

#[test]
fn topology_index_audit_checks_the_binding_of_every_row_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    store_topology_plan_chirho(root_chirho.path(), &plan_chirho(10)).unwrap();
    store_topology_plan_chirho(root_chirho.path(), &plan_chirho(20)).unwrap();
    let mut rows_chirho = load_verified_topology_plan_index_chirho(root_chirho.path()).unwrap();
    rows_chirho[1].serde_address_chirho = rows_chirho[0].serde_address_chirho.clone();
    write_rows_chirho(root_chirho.path(), &rows_chirho);
    let before_chirho = tree_bytes_chirho(root_chirho.path());
    assert_eq!(
        verify_topology_plan_index_chirho(root_chirho.path()),
        Err(TopologyPlanIndexEvidenceRefusalChirho::CanonicalBindingMismatchChirho)
    );
    assert_eq!(tree_bytes_chirho(root_chirho.path()), before_chirho);
}

#[test]
fn topology_index_audit_requires_both_objects_to_exist_and_rehash_chirho() {
    for canonical_chirho in [true, false] {
        let root_chirho = tempfile::tempdir().unwrap();
        store_topology_plan_chirho(root_chirho.path(), &plan_chirho(10)).unwrap();
        let rows_chirho = load_verified_topology_plan_index_chirho(root_chirho.path()).unwrap();
        let address_chirho = if canonical_chirho {
            &rows_chirho[0].plan_hash_chirho
        } else {
            &rows_chirho[0].serde_address_chirho
        };
        let path_chirho = object_path_chirho(root_chirho.path(), address_chirho);
        let original_chirho = fs::read(&path_chirho).unwrap();
        fs::write(&path_chirho, b"tampered-private-marker-chirho").unwrap();
        assert_eq!(
            verify_topology_plan_index_chirho(root_chirho.path()),
            Err(TopologyPlanIndexEvidenceRefusalChirho::ObjectTamperedChirho)
        );
        fs::write(&path_chirho, original_chirho).unwrap();
        assert_eq!(verify_topology_plan_index_chirho(root_chirho.path()), Ok(1));
        fs::remove_file(&path_chirho).unwrap();
        assert_eq!(
            verify_topology_plan_index_chirho(root_chirho.path()),
            Err(TopologyPlanIndexEvidenceRefusalChirho::ObjectAbsentChirho)
        );
    }
}

#[test]
fn topology_index_audit_refuses_non_plan_objects_and_malformed_rows_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    store_topology_plan_chirho(root_chirho.path(), &plan_chirho(10)).unwrap();
    let mut rows_chirho = load_verified_topology_plan_index_chirho(root_chirho.path()).unwrap();
    rows_chirho[0].serde_address_chirho =
        cas_chirho::add_chirho(root_chirho.path(), br#"{"not_a_plan_chirho":true}"#)
            .unwrap()
            .0;
    write_rows_chirho(root_chirho.path(), &rows_chirho);
    assert_eq!(
        verify_topology_plan_index_chirho(root_chirho.path()),
        Err(TopologyPlanIndexEvidenceRefusalChirho::PlanDecodeChirho)
    );

    for malformed_chirho in [
        b"not JSON".as_slice(),
        b"\xff",
        br#"{"plan_hash_chirho":7}"#,
    ] {
        fs::write(
            root_chirho.path().join(TOPOLOGY_PLAN_INDEX_LOG_CHIRHO),
            malformed_chirho,
        )
        .unwrap();
        assert!(matches!(
            verify_topology_plan_index_chirho(root_chirho.path()),
            Err(TopologyPlanIndexEvidenceRefusalChirho::IndexChirho(
                PlanStoreRefusalChirho::DecodeChirho { .. }
            ))
        ));
    }

    rows_chirho[0].serde_address_chirho = store_chirho::hash_object_chirho(&plan_chirho(10))
        .unwrap()
        .0;
    let mut extra_chirho = serde_json::to_value(&rows_chirho[0]).unwrap();
    extra_chirho["private_note_chirho"] = serde_json::json!("must-not-be-discarded-chirho");
    fs::write(
        root_chirho.path().join(TOPOLOGY_PLAN_INDEX_LOG_CHIRHO),
        serde_json::to_vec(&extra_chirho).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        verify_topology_plan_index_chirho(root_chirho.path()),
        Err(TopologyPlanIndexEvidenceRefusalChirho::IndexChirho(
            PlanStoreRefusalChirho::DecodeChirho { .. }
        ))
    ));
}

#[test]
fn topology_index_audit_enforces_index_and_object_byte_bounds_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    store_topology_plan_chirho(root_chirho.path(), &plan_chirho(10)).unwrap();
    let rows_chirho = load_verified_topology_plan_index_chirho(root_chirho.path()).unwrap();
    let path_chirho = root_chirho.path().join(TOPOLOGY_PLAN_INDEX_LOG_CHIRHO);
    let mut bytes_chirho = fs::read(&path_chirho).unwrap();
    bytes_chirho.resize(TOPOLOGY_PLAN_INDEX_MAX_BYTES_CHIRHO as usize, b' ');
    fs::write(&path_chirho, &bytes_chirho).unwrap();
    assert_eq!(verify_topology_plan_index_chirho(root_chirho.path()), Ok(1));
    bytes_chirho.push(b' ');
    fs::write(&path_chirho, &bytes_chirho).unwrap();
    assert_eq!(
        verify_topology_plan_index_chirho(root_chirho.path()),
        Err(TopologyPlanIndexEvidenceRefusalChirho::IndexChirho(
            PlanStoreRefusalChirho::StoreIdentityUnstableChirho
        ))
    );
    write_rows_chirho(root_chirho.path(), &rows_chirho);
    fs::OpenOptions::new()
        .write(true)
        .open(object_path_chirho(
            root_chirho.path(),
            &rows_chirho[0].serde_address_chirho,
        ))
        .unwrap()
        .set_len(TOPOLOGY_PLAN_EVIDENCE_OBJECT_MAX_BYTES_CHIRHO + 1)
        .unwrap();
    assert_eq!(
        verify_topology_plan_index_chirho(root_chirho.path()),
        Err(TopologyPlanIndexEvidenceRefusalChirho::ObjectUnreadableChirho)
    );
}

#[test]
fn bounded_cas_read_checks_addresses_and_its_exact_byte_budget_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let bytes_chirho = b"bounded-object-chirho";
    let address_chirho = cas_chirho::add_chirho(root_chirho.path(), bytes_chirho).unwrap();
    assert!(matches!(
        read_verified_bounded_chirho(root_chirho.path(), &address_chirho, bytes_chirho.len() as u64),
        CasReadOutcomeChirho::VerifiedChirho(found_chirho) if found_chirho == bytes_chirho
    ));
    assert!(matches!(
        read_verified_bounded_chirho(
            root_chirho.path(),
            &address_chirho,
            bytes_chirho.len() as u64 - 1
        ),
        CasReadOutcomeChirho::UnreadableChirho(_)
    ));
    for invalid_chirho in [
        "".to_owned(),
        "A".repeat(64),
        "z".repeat(64),
        "../x".repeat(16),
    ] {
        assert!(matches!(
            read_verified_bounded_chirho(root_chirho.path(), &HashChirho(invalid_chirho), 1024),
            CasReadOutcomeChirho::UnreadableChirho(error_chirho)
                if error_chirho.kind() == std::io::ErrorKind::InvalidInput
        ));
    }
}

#[test]
fn topology_index_audit_does_not_create_an_absent_root_chirho() {
    let parent_chirho = tempfile::tempdir().unwrap();
    let absent_chirho = parent_chirho.path().join("absent-root-chirho");
    assert!(!absent_chirho.exists());
    assert_eq!(verify_topology_plan_index_chirho(&absent_chirho), Ok(0));
    assert!(!absent_chirho.exists());
    assert_eq!(fs::read_dir(parent_chirho.path()).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn topology_index_audit_refuses_symlinks_hardlinks_and_directories_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let index_chirho = root_chirho.path().join(TOPOLOGY_PLAN_INDEX_LOG_CHIRHO);
    let target_chirho = root_chirho.path().join("missing-index-target-chirho");
    std::os::unix::fs::symlink(&target_chirho, &index_chirho).unwrap();
    assert!(fs::symlink_metadata(&index_chirho)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(!target_chirho.exists());
    assert_eq!(
        verify_topology_plan_index_chirho(root_chirho.path()),
        Err(TopologyPlanIndexEvidenceRefusalChirho::IndexChirho(
            PlanStoreRefusalChirho::StoreIdentityUnstableChirho
        ))
    );
    fs::remove_file(&index_chirho).unwrap();
    fs::create_dir(&index_chirho).unwrap();
    assert!(verify_topology_plan_index_chirho(root_chirho.path()).is_err());
    fs::remove_dir(&index_chirho).unwrap();
    store_topology_plan_chirho(root_chirho.path(), &plan_chirho(10)).unwrap();
    fs::hard_link(&index_chirho, &target_chirho).unwrap();
    assert_eq!(
        verify_topology_plan_index_chirho(root_chirho.path()),
        Err(TopologyPlanIndexEvidenceRefusalChirho::IndexChirho(
            PlanStoreRefusalChirho::StoreIdentityUnstableChirho
        ))
    );
    fs::remove_file(&target_chirho).unwrap();
    let rows_chirho = load_verified_topology_plan_index_chirho(root_chirho.path()).unwrap();
    let object_chirho = object_path_chirho(root_chirho.path(), &rows_chirho[0].plan_hash_chirho);
    fs::remove_file(&object_chirho).unwrap();
    std::os::unix::fs::symlink(&target_chirho, &object_chirho).unwrap();
    assert_eq!(
        verify_topology_plan_index_chirho(root_chirho.path()),
        Err(TopologyPlanIndexEvidenceRefusalChirho::ObjectUnreadableChirho)
    );
}
