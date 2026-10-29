// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::*;
use super::shared_guard_helpers_chirho::*;
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn gate1_authority_log_surfaces_are_inventory_covered_chirho() {
    let required_chirho = [
        (
            "src/governance_flows_chirho/gc_chirho.rs",
            "\"gate1-authority-head-chirho\"",
        ),
        (
            "src/privacy_compliance_chirho/privacy_chirho/scan_chirho.rs",
            "\"gate1-authority-head-chirho\"",
        ),
        (
            "src/privacy_compliance_chirho/compliance_evidence_chirho.rs",
            "\"gate1-authority-log-chirho.jsonl\"",
        ),
        (
            "src/privacy_compliance_chirho/compliance_evidence_chirho/source_snapshots_chirho.rs",
            "verify_gate1_authority_log_chirho",
        ),
        (
            "src/privacy_compliance_chirho/data_rights_chirho.rs",
            "gate1.authority-log-chirho",
        ),
        (
            "src/governance_flows_chirho/privacy_backup_chirho.rs",
            "\"gate1-authority-log-chirho.jsonl\"",
        ),
        (
            "crates/support-chirho/cairn-seqlog-chirho/src/seqlog_chirho.rs",
            "\"gate1-authority-head-chirho\"",
        ),
    ];
    for (rel_chirho, needle_chirho) in required_chirho {
        let text_chirho = std::fs::read_to_string(workspace_root_chirho().join(rel_chirho))
            .unwrap_or_else(|error_chirho| panic!("read {rel_chirho}: {error_chirho}"));
        assert!(
            production_text_chirho(&text_chirho).contains(needle_chirho),
            "Gate 1 authority-log surface inventory coverage missing from {rel_chirho}"
        );
    }
}

#[test]
fn gate1_ring_a_old_road_surface_set_stays_frozen_chirho() {
    let root_chirho = workspace_root_chirho();
    let model_text_chirho = std::fs::read_to_string(
        root_chirho.join("crates/domain-chirho/cairn-model-gate1-chirho/src/lib.rs"),
    )
    .unwrap();
    let target_region_chirho = between_markers_chirho(
        &model_text_chirho,
        "GATE1_RING_A_ANCHOR_TARGETS_CHIRHO",
        "#[derive(",
    );
    assert_eq!(
        GATE1_OLD_ROAD_RING_A_SURFACE_CONSTS_CHIRHO
            .iter()
            .map(|(_name_chirho, surface_chirho)| *surface_chirho)
            .collect::<BTreeSet<_>>(),
        GATE1_OLD_ROAD_RING_A_SURFACES_CHIRHO
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        "Gate 1 surface constants and literal inventory must describe the same old-road family set"
    );
    for (name_chirho, surface_chirho) in GATE1_OLD_ROAD_RING_A_SURFACE_CONSTS_CHIRHO {
        assert!(
            model_text_chirho.contains(&format!("pub const {name_chirho}: &str")),
            "Gate 1 surface constant {name_chirho} is missing"
        );
        assert!(
            model_text_chirho.contains(&format!("\"{surface_chirho}\"")),
            "Gate 1 surface constant {name_chirho} no longer binds {surface_chirho}"
        );
    }
    let actual_chirho = gate1_family_const_names_in_region_chirho(target_region_chirho);
    let expected_chirho = expected_surface_const_set_chirho();
    assert_eq!(
        actual_chirho, expected_chirho,
        "Gate 1 old-road Ring-A surface set changed; new surfaces must be reviewed into the authority-log/canary plan before they can land"
    );
}

#[test]
fn gate1_typed_ingestion_surface_set_stays_frozen_chirho() {
    let root_chirho = workspace_root_chirho();
    let typed_text_chirho = std::fs::read_to_string(
        root_chirho.join("crates/cairn-projection-chirho/src/typed_ingestion_chirho.rs"),
    )
    .unwrap();
    let typed_region_chirho = between_markers_chirho(
        &typed_text_chirho,
        "fn ring_a_typed_surfaces_chirho()",
        "fn typed_surface_by_name_chirho",
    );
    let actual_chirho = quoted_jsonl_literals_in_region_chirho(typed_region_chirho);
    let expected_chirho = expected_set_chirho(GATE1_TYPED_INGESTION_SURFACES_CHIRHO);
    assert_eq!(
        actual_chirho, expected_chirho,
        "Gate 1 typed ingestion surface set changed; update the canary/oracle manifest deliberately with the same brick"
    );
}

#[test]
fn gate1_ring_a_old_road_seqlog_call_map_stays_frozen_chirho() {
    let mut expected_chirho = BTreeMap::new();
    for (file_chirho, token_chirho, count_chirho) in GATE1_OLD_ROAD_SEQLOG_CALL_COUNTS_CHIRHO {
        expected_chirho.insert(
            ((*file_chirho).to_string(), (*token_chirho).to_string()),
            *count_chirho,
        );
    }

    let mut actual_chirho = expected_chirho
        .keys()
        .map(|key_chirho| (key_chirho.clone(), 0usize))
        .collect::<BTreeMap<_, _>>();
    let mut sites_chirho = Vec::new();
    for (file_chirho, token_chirho, _count_chirho) in GATE1_OLD_ROAD_SEQLOG_CALL_COUNTS_CHIRHO {
        for (actual_file_chirho, line_chirho, text_chirho) in
            production_source_lines_matching_chirho(token_chirho)
        {
            if actual_file_chirho != *file_chirho {
                continue;
            }
            *actual_chirho
                .entry((actual_file_chirho.clone(), (*token_chirho).to_string()))
                .or_insert(0) += 1;
            sites_chirho.push(format!(
                "{actual_file_chirho}:{line_chirho}:{token_chirho}: {text_chirho}"
            ));
        }
    }

    assert_eq!(
        actual_chirho, expected_chirho,
        "Gate 1 old-road Ring-A seqlog call map changed; dual-write authority wrappers must be reviewed before append/recover sites move or grow: {sites_chirho:?}"
    );
}

#[test]
fn gate1_old_road_surface_literals_stay_in_reviewed_files_chirho() {
    let mut actual_files_chirho = BTreeSet::new();
    let mut sites_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let rel_chirho = workspace_relative_chirho(&path_chirho);
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let file_sites_chirho =
            gate1_old_road_surface_literal_sites_in_text_chirho(&rel_chirho, &text_chirho);
        if !file_sites_chirho.is_empty() {
            actual_files_chirho.insert(rel_chirho);
            sites_chirho.extend(file_sites_chirho);
        }
    }
    let expected_chirho = expected_old_road_surface_literal_file_set_chirho();
    assert_eq!(
        actual_files_chirho, expected_chirho,
        "Gate 1 old-road Ring-A surface literals may only appear in reviewed files until authority-log wrappers land; this catches new raw append/read surfaces even outside the five current family files: {sites_chirho:?}"
    );
}

// gate1_old_road_guard_fixture_catches_surface_growth_chirho was demoted to the advisory structure
// report (it validates the frozen-const-set detector — pure shape). See structure_report_chirho.

#[test]
fn gate1_old_road_guard_fixture_catches_unreviewed_surface_literal_file_chirho() {
    let rel_chirho = "src/economic_flows_chirho/gate1_gap_probe_chirho.rs";
    let text_chirho = r#"
        fn rogue_chirho(root_chirho: &std::path::Path) {
            let _path_chirho = root_chirho.join("ledger-chirho.jsonl");
        }
    "#;
    let sites_chirho = gate1_old_road_surface_literal_sites_in_text_chirho(rel_chirho, text_chirho);
    assert!(
        sites_chirho
            .iter()
            .any(|site_chirho| site_chirho.contains("ledger-chirho.jsonl")),
        "fixture must see a Ring-A surface literal in an unreviewed production file"
    );
    assert!(
        !expected_old_road_surface_literal_file_set_chirho().contains(rel_chirho),
        "fixture file must not be in the reviewed Ring-A literal allowlist"
    );
}
