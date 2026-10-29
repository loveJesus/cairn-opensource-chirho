// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::*;
use std::collections::BTreeMap;

const DIRECT_REFS_MUTATION_CALL_COUNT_CHIRHO: usize = 0;
const REVIEWED_HEAD_REMOVAL_HELPER_CHIRHO: &str =
    "crates/support-chirho/cairn-head-removal-chirho/src/head_removal_chirho.rs";
fn direct_refs_expected_counts_chirho() -> BTreeMap<&'static str, usize> {
    // The direct-refs mutation debt is ZERO: every production head move goes through the
    // reviewed writer/head boundary (typed-precondition commit_head, the signed positive-head
    // transition protocol, or the receipted removal protocol). New raw mutations must not appear.
    BTreeMap::new()
}

fn misleading_head_commit_claims_in_text_chirho(
    file_chirho: &str,
    text_chirho: &str,
) -> Vec<String> {
    let mut offenders_chirho = Vec::new();
    for (line_index_chirho, line_chirho) in text_chirho.lines().enumerate() {
        let lower_chirho = line_chirho.to_ascii_lowercase();
        if (lower_chirho.contains("head_commit") || lower_chirho.contains("commit_head"))
            && (lower_chirho.contains("fence") || lower_chirho.contains("stale-writer"))
        {
            offenders_chirho.push(format!(
                "{}:{}: {}",
                file_chirho,
                line_index_chirho + 1,
                line_chirho.trim()
            ));
        }
    }
    offenders_chirho
}

fn misleading_head_commit_claims_chirho() -> Vec<String> {
    let mut offenders_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let rel_chirho = workspace_relative_chirho(&path_chirho);
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        offenders_chirho.extend(misleading_head_commit_claims_in_text_chirho(
            &rel_chirho,
            &text_chirho,
        ));
    }
    offenders_chirho
}

#[test]
fn ha2_direct_refs_mutation_debt_does_not_grow_chirho() {
    let mutation_markers_chirho = [
        "refs_chirho::set_branch_chirho(",
        "refs_chirho::rollback_chirho(",
        "refs_chirho::compare_and_set_branch_chirho(",
        "refs_chirho::remove_branch_chirho(",
    ];
    let mut actual_counts_chirho: BTreeMap<String, usize> = BTreeMap::new();
    let mut actual_sites_chirho = Vec::new();
    for marker_chirho in mutation_markers_chirho {
        for (file_chirho, line_chirho, text_chirho) in
            production_source_lines_matching_chirho(marker_chirho)
        {
            if marker_chirho == "refs_chirho::remove_branch_chirho("
                && file_chirho == REVIEWED_HEAD_REMOVAL_HELPER_CHIRHO
            {
                continue;
            }
            *actual_counts_chirho.entry(file_chirho.clone()).or_default() += 1;
            actual_sites_chirho.push(format!("{file_chirho}:{line_chirho}: {text_chirho}"));
        }
    }
    let expected_counts_chirho = direct_refs_expected_counts_chirho()
        .into_iter()
        .map(|(file_chirho, count_chirho)| (file_chirho.to_string(), count_chirho))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        actual_counts_chirho, expected_counts_chirho,
        "HA2 direct refs mutation debt changed; new sites must go through the writer/head boundary, and shrinks must lower this debt-ratchet: {actual_sites_chirho:?}"
    );
    assert_eq!(
        actual_sites_chirho.len(),
        DIRECT_REFS_MUTATION_CALL_COUNT_CHIRHO,
        "HA2 direct refs mutation call count must stay frozen until a reviewed writer/head facade migration shrinks it"
    );
    assert!(
        production_source_lines_matching_chirho("refs_chirho::save_refs_chirho(").is_empty(),
        "production code outside refs_chirho must not call save_refs_chirho directly"
    );
}

#[test]
fn ha2_head_removal_raw_remove_stays_inside_reviewed_helper_chirho() {
    let actual_chirho =
        production_source_lines_matching_chirho("refs_chirho::remove_branch_chirho(")
            .into_iter()
            .map(|(file_chirho, _line_chirho, _text_chirho)| file_chirho)
            .collect::<Vec<_>>();
    assert_eq!(
        actual_chirho,
        vec![REVIEWED_HEAD_REMOVAL_HELPER_CHIRHO.to_string()],
        "production remove_branch_chirho calls must stay behind the reviewed signed head-removal helper"
    );
}

#[test]
fn ha2_head_commits_stay_behind_reviewed_scope_chirho() {
    // The exact per-file commit_head callsite count MAP freeze was demoted to the advisory
    // structure report; the every-commit_head-sits-inside-a-reviewed-scope engine claim stays RED.
    let mut actual_counts_chirho: BTreeMap<String, usize> = BTreeMap::new();
    for (file_chirho, _line_chirho, _text_chirho) in
        production_source_lines_matching_chirho("refs_chirho::commit_head_chirho(")
    {
        *actual_counts_chirho.entry(file_chirho).or_default() += 1;
    }
    for file_chirho in actual_counts_chirho.keys() {
        let text_chirho = std::fs::read_to_string(workspace_root_chirho().join(file_chirho))
            .unwrap_or_else(|_| panic!("read {file_chirho}"));
        let production_chirho = production_text_chirho(&text_chirho);
        assert!(
            production_chirho.contains("with_head_commit_chirho(")
                || production_chirho.contains("with_gate1_authority_scope_chirho("),
            "{file_chirho} calls commit_head_chirho without a reviewed mutable-head scope"
        );
    }
}

#[test]
fn ha2_head_commit_claims_do_not_imply_writer_fencing_chirho() {
    assert!(
        misleading_head_commit_claims_chirho().is_empty(),
        "HA2.2 head-commit docs or code imply fence/stale-writer safety without a token: {:?}",
        misleading_head_commit_claims_chirho()
    );
}

#[test]
fn ha2_head_commit_claim_guard_catches_doc_comment_claims_chirho() {
    let refs_text_chirho = r#"
        /// commit_head_chirho fences stale writers across nodes.
        pub fn commit_head_chirho() {}
    "#;
    let writer_head_text_chirho = r#"
        //! with_head_commit_chirho fences stale writers.
        pub fn with_head_commit_chirho() {}
    "#;
    assert!(
        !misleading_head_commit_claims_in_text_chirho("refs_chirho.rs", refs_text_chirho)
            .is_empty(),
        "commit_head doc comments must be scanned for misleading fence claims"
    );
    assert!(
        !misleading_head_commit_claims_in_text_chirho(
            "writer_head_chirho.rs",
            writer_head_text_chirho,
        )
        .is_empty(),
        "writer-head module docs must be scanned for misleading fence claims"
    );
}

#[test]
fn writer_fence_mutable_surface_is_covered_by_inventory_guards_chirho() {
    let required_chirho = [
        (
            "crates/support-chirho/cairn-seqlog-chirho/src/seqlog_chirho.rs",
            "\"writer-fences-chirho\"",
        ),
        (
            "src/governance_flows_chirho/gc_chirho.rs",
            "\"writer-fences-chirho\"",
        ),
        (
            "src/privacy_compliance_chirho/privacy_chirho/scan_chirho.rs",
            "\"writer-fences-chirho\"",
        ),
        (
            "src/governance_flows_chirho/privacy_backup_chirho.rs",
            "\"writer-fences-chirho\"",
        ),
        (
            "src/privacy_compliance_chirho/data_rights_chirho.rs",
            "writer-fences-chirho mutable-head control files are retained root-scope inventory",
        ),
    ];
    for (rel_chirho, needle_chirho) in required_chirho {
        let path_chirho = workspace_root_chirho().join(rel_chirho);
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        assert!(
            production_text_chirho(&text_chirho).contains(needle_chirho),
            "writer-fences-chirho mutable surface coverage missing from {rel_chirho}"
        );
    }
}

#[test]
fn head_removal_log_surface_is_covered_by_inventory_guards_chirho() {
    let required_chirho = [
        (
            "src/privacy_compliance_chirho/privacy_chirho/scan_chirho.rs",
            "\"head-removals-chirho.jsonl\"",
        ),
        (
            "src/privacy_compliance_chirho/compliance_evidence_chirho.rs",
            "\"refs.head-removals-chirho\"",
        ),
        (
            "src/privacy_compliance_chirho/compliance_evidence_chirho/source_snapshots_chirho.rs",
            "verify_head_removal_records_chirho",
        ),
        (
            "src/privacy_compliance_chirho/data_rights_chirho.rs",
            "refs.head-removals-chirho",
        ),
        (
            "src/privacy_compliance_chirho/data_rights_chirho/source_collectors_chirho.rs",
            "load_head_removal_evidence_values_chirho",
        ),
        (
            "src/governance_flows_chirho/privacy_backup_chirho.rs",
            "\"head-removals-chirho.jsonl\"",
        ),
    ];
    for (rel_chirho, needle_chirho) in required_chirho {
        let path_chirho = workspace_root_chirho().join(rel_chirho);
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        assert!(
            production_text_chirho(&text_chirho).contains(needle_chirho),
            "head-removals-chirho coverage missing from {rel_chirho}"
        );
    }
}
