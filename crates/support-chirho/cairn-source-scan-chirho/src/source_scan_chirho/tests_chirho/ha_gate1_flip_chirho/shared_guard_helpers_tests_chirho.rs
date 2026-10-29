// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::*;
use std::collections::BTreeSet;

pub(super) const GATE1_AUTHORITY_LOG_CRATE_CHIRHO: &str =
    "crates/services-chirho/cairn-gate1-authority-log-chirho";
pub(super) const GATE1_AUTHORITY_LOG_CRATE_SRC_CHIRHO: &str =
    "crates/services-chirho/cairn-gate1-authority-log-chirho/src/";
pub(super) const GATE1_PROJECTION_ORACLE_SRC_CHIRHO: &str =
    "crates/cairn-projection-chirho/src/gate1_authority_oracle_chirho.rs";
pub(super) const GATE1_PROJECTION_SRC_CHIRHO: &str =
    "crates/cairn-projection-chirho/src/projection_chirho.rs";
pub(super) const GATE1_TYPED_INGESTION_SRC_CHIRHO: &str =
    "crates/cairn-projection-chirho/src/typed_ingestion_chirho.rs";

pub(super) const GATE1_OLD_ROAD_RING_A_SURFACES_CHIRHO: &[&str] = &[
    "ledger-chirho.jsonl",
    "credit-holds-chirho.jsonl",
    "resource-policy-records-chirho.jsonl",
    "resource-policy-unset-records-chirho.jsonl",
    "resource-usage-chirho.jsonl",
    "billing-policy-records-chirho.jsonl",
    "billing-usage-chirho.jsonl",
    "billing-compensations-chirho.jsonl",
];

pub(super) const GATE1_OLD_ROAD_RING_A_SURFACE_CONSTS_CHIRHO: &[(&str, &str)] = &[
    ("GATE1_LEDGER_FAMILY_CHIRHO", "ledger-chirho.jsonl"),
    (
        "GATE1_CREDIT_HOLDS_FAMILY_CHIRHO",
        "credit-holds-chirho.jsonl",
    ),
    (
        "GATE1_RESOURCE_POLICIES_FAMILY_CHIRHO",
        "resource-policy-records-chirho.jsonl",
    ),
    (
        "GATE1_RESOURCE_POLICY_UNSETS_FAMILY_CHIRHO",
        "resource-policy-unset-records-chirho.jsonl",
    ),
    (
        "GATE1_RESOURCE_USAGE_FAMILY_CHIRHO",
        "resource-usage-chirho.jsonl",
    ),
    (
        "GATE1_BILLING_POLICIES_FAMILY_CHIRHO",
        "billing-policy-records-chirho.jsonl",
    ),
    (
        "GATE1_BILLING_USAGE_FAMILY_CHIRHO",
        "billing-usage-chirho.jsonl",
    ),
    (
        "GATE1_BILLING_COMPENSATIONS_FAMILY_CHIRHO",
        "billing-compensations-chirho.jsonl",
    ),
];

pub(super) const GATE1_TYPED_INGESTION_SURFACES_CHIRHO: &[&str] = &[
    "ledger-chirho.jsonl",
    "billing-policy-records-chirho.jsonl",
    "billing-usage-chirho.jsonl",
    "billing-compensations-chirho.jsonl",
    "credit-holds-chirho.jsonl",
    "resource-policy-records-chirho.jsonl",
    "resource-policy-unset-records-chirho.jsonl",
    "resource-usage-chirho.jsonl",
    "review-policy-envelopes-chirho.jsonl",
    "gate1-log-anchors-chirho.jsonl",
];

// RE-INVENTORIED 2026-07-26 at CF6 wave-1: THIRTEEN -> FIVE. The eight removed rows were all
// `economic_flows_chirho` Ring-A dual-write wrappers that died with the money spine; the five
// survivors are `app_metering_chirho` and are unchanged.
//
// SCOPE, because the construction invites a wrong reading: the companion arm seeds its actual map
// from THESE keys and skips any other file, so it censuses call counts only within the listed
// Ring-A files. That is deliberate, not a hole -- these three seqlog tokens are GENERAL primitives
// with 9 to 19 production callers each, so an unfiltered census would pin unrelated code. A NEW
// Ring-A wrapper file is caught by a different instrument:
// `gate1_authority_unlocked_append_stays_inside_reviewed_ring_a_wrappers_chirho` censuses
// `append_gate1_authority_record_unlocked_chirho` UNFILTERED and count-matches it against an
// allowlist. The two arms are complementary; neither alone covers both growth directions.
pub(super) const GATE1_OLD_ROAD_SEQLOG_CALL_COUNTS_CHIRHO: &[(&str, &str, usize)] = &[
    (
        "src/app_metering_chirho/resource_chirho.rs",
        "recover_jsonl_len_unlocked_chirho",
        1,
    ),
    (
        "src/app_metering_chirho/resource_chirho.rs",
        "append_recovered_jsonl_unlocked_chirho",
        1,
    ),
    (
        "src/app_metering_chirho/resource_chirho.rs",
        "append_serialized_jsonl_chirho",
        0,
    ),
    (
        "src/app_metering_chirho/resource_chirho.rs",
        "append_serialized_jsonl_unlocked_chirho",
        2,
    ),
    (
        "src/app_metering_chirho/resource_chirho/gate1_authority_chirho.rs",
        "recover_jsonl_len_unlocked_chirho",
        3,
    ),
];

pub(super) const GATE1_OLD_ROAD_SURFACE_LITERAL_FILES_CHIRHO: &[&str] = &[
    "crates/cairn-projection-chirho/src/projection_chirho.rs",
    "crates/cairn-projection-chirho/src/typed_ingestion_chirho.rs",
    "crates/domain-chirho/cairn-model-gate1-chirho/src/lib.rs",
    // The LocalPhaseB no-legacy census deliberately freezes the delete-candidate filenames so
    // the census survives deletion of their live path helpers; it neither reads nor appends them.
    "crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho/constants_chirho.rs",
    // holds_chirho/mod.rs REMOVED 2026-07-25 by CF6-D2 brick (a1) -- and its removal is the EVIDENCE
    // the extraction is real. That file held "credit-holds-chirho.jsonl" via records_path_chirho for
    // the whole life of this guard; the helper moved to legacy_evidence_readers_chirho.rs, so the
    // file no longer contains ANY old-road surface literal. A guard firing on the ABSENCE is the
    // cheapest proof that something moved rather than a no-op wearing a diff.
    // billing_chirho.rs REMOVED 2026-07-26 by CF6-D2 brick (a2-3), the third file to leave this list
    // by EXTRACTION rather than by edit. It held "billing-usage-chirho.jsonl" and
    // "billing-policy-records-chirho.jsonl" via usage_records_path_chirho / policy_records_path_chirho;
    // both helpers and the BILLING_POLICY_RECORDS_LOG_CHIRHO constant moved to
    // legacy_billing_evidence_chirho.rs, so the file no longer contains ANY old-road surface literal.
    // A guard that fires on the ABSENCE cannot be satisfied by a no-op wearing a diff.
    // ledger_chirho.rs REMOVED 2026-07-25 by CF6-D2 brick (a2-0), and its removal is the EVIDENCE the
    // extraction is real -- the same proof shape brick (a1) left on holds_chirho/mod.rs above. That
    // file held "ledger-chirho.jsonl" via ledger_path_chirho for the whole life of this guard; the
    // helper moved to legacy_ledger_evidence_chirho.rs, so the file no longer contains ANY old-road
    // surface literal. A guard that fires on the ABSENCE cannot be satisfied by a no-op wearing a diff.
    "src/app_metering_chirho/resource_chirho.rs",
    "src/privacy_compliance_chirho/compliance_evidence_chirho.rs",
    "src/privacy_compliance_chirho/privacy_chirho/scan_chirho.rs",
    // The CF6-D2 brick (a) acceptance instrument. It is a #[cfg(test)] module and writes these
    // filenames only into temp-dir fixtures it then deletes — it neither reads nor appends a real
    // root. It appears here at all because its declaration uses `cfg(all(test, feature = ...))`,
    // which the scanner treats as ambiguous and FAILS SAFE by keeping the file in the production
    // surface. Reviewed and listed rather than suppressed: over-scanning is the correct error for
    // this guard, so the allowlist is where the exception belongs. Leaves with brick (a).
    "src/privacy_compliance_chirho/legacy_evidence_characterization_tests_chirho.rs",
    // CF6-D2 brick (a1): the RETAINED read-only evidence readers, extracted out of
    // src/economic_flows_chirho so they survive that directory's deletion. It holds these filenames
    // because reading those logs IS its job -- it is the subject-export read surface, and the whole
    // point of the extraction is that this file outlives the spine. It appends nothing: the five
    // functions are load/path/schema-validate only, and they were moved byte-exactly with the
    // characterization instrument (14 arms) green before and after.
    "src/privacy_compliance_chirho/legacy_evidence_readers_chirho.rs",
    // CF6-D2 brick (a2-0): the money-integrity acceptance instrument for the shared ledger
    // read/verify core. Same ambiguous-cfg fail-safe as the brick (a) instrument above. It holds
    // "ledger-chirho.jsonl" because it RECONSTRUCTS that path independently of the production
    // helper -- a pin in its own right, since a relocated evidence file would make subject exports
    // read an empty ledger and report nothing rather than fail. Writes only into temp-dir fixtures
    // it then deletes; touches no real root. Leaves with brick (a2).
    "src/legacy_evidence_chirho/legacy_ledger_characterization_tests_chirho.rs",
    // CF6-D2 brick (a2-2): the money-integrity acceptance instrument for the credit-hold
    // read/verify core, admitted for the same ambiguous-cfg fail-safe reason as the two above. It
    // holds BOTH "credit-hold" and "ledger-chirho.jsonl" surface literals because its corpus binds
    // hold records to REAL signed ledger entries -- a hold verifier's whole job is that binding, so
    // a corpus without a ledger could only ever exercise the "missing entry" refusal. Writes only
    // into temp-dir fixtures it then deletes; touches no real root. Leaves with brick (a2).
    "src/legacy_evidence_chirho/legacy_holds_characterization_tests_chirho.rs",
    // CF6-D2 brick (a2-3): the money-integrity acceptance instrument for the billing usage
    // read/verify core, admitted for the same ambiguous-cfg fail-safe reason as the three above. It
    // holds BOTH "billing-usage-chirho.jsonl" and "ledger-chirho.jsonl" because billing usage
    // verification BINDS each record to its ledger entry -- a corpus without a real signed ledger
    // could only ever exercise the "missing ledger entry" refusal, which says nothing about whether
    // the binding is sound. Writes only into temp-dir fixtures it then deletes; touches no real
    // root. Leaves with brick (a2).
    "src/legacy_evidence_chirho/legacy_billing_characterization_tests_chirho.rs",
    // CF6-D2 brick (a2-3): the RETAINED legacy billing read/verify core, extracted out of
    // src/economic_flows_chirho so loading and AUTHENTICATING historical billing evidence survives
    // that directory's deletion. It holds these filenames because reading those logs IS its job, and
    // the whole point of the extraction is that this file outlives the spine. It appends nothing --
    // the moved functions are load/path/verify only, and the write path stayed with the spine.
    "src/legacy_evidence_chirho/legacy_billing_evidence_chirho.rs",
    // CF6-D2 brick (a2-0): the RETAINED legacy ledger read/verify core, extracted out of
    // src/economic_flows_chirho so loading and AUTHENTICATING historical ledger evidence survives
    // that directory's deletion. It holds "ledger-chirho.jsonl" because reading that log IS its job,
    // and the whole point of the extraction is that this file outlives the spine. It appends nothing:
    // the eleven functions are path/load/schema-validate/verify only, moved byte-exactly with an
    // 11-arm money-integrity instrument green before and after.
    "src/legacy_evidence_chirho/legacy_ledger_evidence_chirho.rs",
];

pub(super) fn quoted_jsonl_literals_in_region_chirho(text_chirho: &str) -> BTreeSet<String> {
    let mut literals_chirho = BTreeSet::new();
    for line_chirho in production_text_chirho(text_chirho).lines() {
        let mut rest_chirho = line_chirho;
        while let Some(start_chirho) = rest_chirho.find('"') {
            rest_chirho = &rest_chirho[start_chirho + 1..];
            let Some(end_chirho) = rest_chirho.find('"') else {
                break;
            };
            let literal_chirho = &rest_chirho[..end_chirho];
            if literal_chirho.ends_with(".jsonl") {
                literals_chirho.insert(literal_chirho.to_string());
            }
            rest_chirho = &rest_chirho[end_chirho + 1..];
        }
    }
    literals_chirho
}

pub(super) fn gate1_old_road_surface_literal_sites_in_text_chirho(
    rel_chirho: &str,
    text_chirho: &str,
) -> Vec<String> {
    let mut sites_chirho = Vec::new();
    let production_chirho = production_text_chirho(text_chirho);
    for (line_index_chirho, line_chirho) in production_chirho.lines().enumerate() {
        let trimmed_chirho = line_chirho.trim();
        if trimmed_chirho.is_empty() || trimmed_chirho.starts_with("//") {
            continue;
        }
        for surface_chirho in GATE1_OLD_ROAD_RING_A_SURFACES_CHIRHO {
            if trimmed_chirho.contains(surface_chirho) {
                sites_chirho.push(format!(
                    "{rel_chirho}:{}:{surface_chirho}: {trimmed_chirho}",
                    line_index_chirho + 1
                ));
            }
        }
    }
    sites_chirho
}

pub(super) fn gate1_family_const_names_in_region_chirho(text_chirho: &str) -> BTreeSet<String> {
    let mut names_chirho = BTreeSet::new();
    for token_chirho in text_chirho
        .split(|char_chirho: char| !(char_chirho.is_ascii_alphanumeric() || char_chirho == '_'))
    {
        if token_chirho.starts_with("GATE1_") && token_chirho.ends_with("_FAMILY_CHIRHO") {
            names_chirho.insert(token_chirho.to_string());
        }
    }
    names_chirho
}

pub(super) fn between_markers_chirho<'a>(
    text_chirho: &'a str,
    start_marker_chirho: &str,
    end_marker_chirho: &str,
) -> &'a str {
    let start_chirho = text_chirho
        .find(start_marker_chirho)
        .unwrap_or_else(|| panic!("missing start marker {start_marker_chirho}"));
    let after_start_chirho = &text_chirho[start_chirho..];
    let end_chirho = after_start_chirho
        .find(end_marker_chirho)
        .unwrap_or_else(|| panic!("missing end marker {end_marker_chirho}"));
    &after_start_chirho[..end_chirho]
}

pub(super) fn expected_set_chirho(values_chirho: &[&str]) -> BTreeSet<String> {
    values_chirho
        .iter()
        .map(|value_chirho| (*value_chirho).to_string())
        .collect()
}

pub(super) fn expected_surface_const_set_chirho() -> BTreeSet<String> {
    GATE1_OLD_ROAD_RING_A_SURFACE_CONSTS_CHIRHO
        .iter()
        .map(|(name_chirho, _surface_chirho)| (*name_chirho).to_string())
        .collect()
}

pub(super) fn expected_old_road_surface_literal_file_set_chirho() -> BTreeSet<String> {
    expected_set_chirho(GATE1_OLD_ROAD_SURFACE_LITERAL_FILES_CHIRHO)
}

pub(super) fn gate1_canary_writer_token_sites_in_text_chirho(text_chirho: &str) -> Vec<String> {
    let forbidden_tokens_chirho = [
        "append_gate1_authority_record_chirho(",
        "recover_gate1_authority_head_chirho(",
        "append_gate1_ring_a_anchors_chirho(",
        "append_gate1_anchor_for_family_chirho(",
        "append_gate1_ledger_anchor_chirho(",
        "append_jsonl",
        "append_recovered_jsonl",
        "append_serialized_jsonl",
        "write_file_durable_chirho(",
        "std::fs::write(",
        "std::fs::File::create(",
        "create_dir_all(",
        "commit_head_chirho(",
        "with_head_commit_chirho(",
        "set_branch_chirho(",
        "remove_branch_chirho(",
        "transfer_chirho(",
        "post_entry",
        "paid_chirho::",
        "settlement_chirho::",
    ];
    let mut offenders_chirho = Vec::new();
    for (line_index_chirho, line_chirho) in production_text_chirho(text_chirho).lines().enumerate()
    {
        let trimmed_chirho = line_chirho.trim();
        for token_chirho in forbidden_tokens_chirho {
            if trimmed_chirho.contains(token_chirho) {
                offenders_chirho.push(format!(
                    "{}:{token_chirho}: {trimmed_chirho}",
                    line_index_chirho + 1
                ));
            }
        }
    }
    offenders_chirho
}

pub(super) fn gate1_checkpoint_forbidden_writer_sites_in_text_chirho(
    text_chirho: &str,
) -> Vec<String> {
    let forbidden_tokens_chirho = [
        "append_gate1_authority_record_chirho(",
        "append_gate1_authority_record_unlocked_chirho(",
        "recover_gate1_authority_head_chirho(",
        "recover_gate1_authority_head_unlocked_chirho(",
        "repair_gate1_authority",
        "append_gate1_anchor_for_family_chirho(",
        "append_gate1_ledger_anchor_chirho(",
        "append_jsonl",
        "append_recovered_jsonl",
        "append_serialized_jsonl",
        "write_file_durable_chirho(",
        "std::fs::write(",
        "std::fs::File::create(",
        "create_dir_all(",
        "commit_head_chirho(",
        "with_head_commit_chirho(",
        "set_branch_chirho(",
        "remove_branch_chirho(",
        "with_ledger_authority_lock_chirho(",
        "post_entry",
        "transfer_chirho(",
        "create_stripe_transfer_chirho(",
        "settlement_chirho::",
        "paid_chirho::",
    ];
    let mut offenders_chirho = Vec::new();
    for (line_index_chirho, line_chirho) in production_text_chirho(text_chirho).lines().enumerate()
    {
        let trimmed_chirho = line_chirho.trim();
        for token_chirho in forbidden_tokens_chirho {
            if trimmed_chirho.contains(token_chirho) {
                offenders_chirho.push(format!(
                    "{}:{token_chirho}: {trimmed_chirho}",
                    line_index_chirho + 1
                ));
            }
        }
    }
    offenders_chirho
}

pub(super) fn gate1_authority_flip_forbidden_writer_sites_in_text_chirho(
    text_chirho: &str,
) -> Vec<String> {
    let forbidden_tokens_chirho = [
        "append_gate1_authority_record_chirho(",
        "append_gate1_authority_record_unlocked_chirho(",
        "recover_gate1_authority_head_chirho(",
        "recover_gate1_authority_head_unlocked_chirho(",
        "repair_gate1_authority",
        "append_jsonl",
        "append_recovered_jsonl",
        "append_serialized_jsonl",
        "write_file_durable_chirho(",
        "std::fs::write(",
        "std::fs::File::create(",
        "create_dir_all(",
        "commit_head_chirho(",
        "with_head_commit_chirho(",
        "remove_branch_chirho(",
        "with_ledger_authority_lock_chirho(",
        "post_entry",
        "transfer_chirho(",
        "create_stripe_transfer_chirho(",
        "settlement_chirho::",
        "paid_chirho::",
    ];
    let mut offenders_chirho = Vec::new();
    for (line_index_chirho, line_chirho) in production_text_chirho(text_chirho).lines().enumerate()
    {
        let trimmed_chirho = line_chirho.trim();
        for token_chirho in forbidden_tokens_chirho {
            if trimmed_chirho.contains(token_chirho) {
                offenders_chirho.push(format!(
                    "{}:{token_chirho}: {trimmed_chirho}",
                    line_index_chirho + 1
                ));
            }
        }
    }
    offenders_chirho
}

pub(super) fn gate1_authority_soak_forbidden_writer_sites_in_text_chirho(
    text_chirho: &str,
) -> Vec<String> {
    let forbidden_tokens_chirho = [
        "gate1_authority_flip_report_chirho(",
        "gate1_authority_rollback_report_chirho(",
        "gate1_checkpoint_report_chirho(",
        "ensure_gate1_checkpoint_report_clean_chirho(",
        "write_gate1_authority_mode_record_chirho(",
        "signed_gate1_authority_mode_record_chirho(",
        "signed_gate1_authority_old_road_mode_record_chirho(",
        "append_gate1_authority_record_chirho(",
        "append_gate1_authority_record_unlocked_chirho(",
        "recover_gate1_authority_head_chirho(",
        "recover_gate1_authority_head_unlocked_chirho(",
        "repair_gate1_authority",
        "append_gate1_ring_a_anchors_chirho(",
        "append_gate1_anchor_for_family_chirho(",
        "append_gate1_ledger_anchor_chirho(",
        "append_jsonl",
        "append_recovered_jsonl",
        "append_serialized_jsonl",
        "write_file_durable_chirho(",
        "std::fs::write(",
        "fs::write(",
        "std::fs::File::create(",
        "File::create(",
        "OpenOptions",
        "create_dir_all(",
        "commit_head_chirho(",
        "with_head_commit_chirho(",
        "set_branch_chirho(",
        "compare_and_set",
        "remove_branch_chirho(",
        "with_ledger_authority_lock_chirho(",
        "with_gate1_authority_scope_chirho(",
        "with_fenced_append_lock_chirho(",
        "post_entry",
        "transfer_chirho(",
        "create_stripe_transfer_chirho(",
        "settlement_chirho::",
        "paid_chirho::",
    ];
    let mut offenders_chirho = Vec::new();
    for (line_index_chirho, line_chirho) in production_text_chirho(text_chirho).lines().enumerate()
    {
        let trimmed_chirho = line_chirho.trim();
        for token_chirho in forbidden_tokens_chirho {
            if trimmed_chirho.contains(token_chirho) {
                offenders_chirho.push(format!(
                    "{}:{token_chirho}: {trimmed_chirho}",
                    line_index_chirho + 1
                ));
            }
        }
    }
    offenders_chirho
}

pub(super) fn gate1_authority_backfill_forbidden_sites_in_text_chirho(
    text_chirho: &str,
) -> Vec<String> {
    let forbidden_tokens_chirho = [
        "gate1_authority_flip_report_chirho(",
        "run_gate1_authority_flip_command_chirho(",
        "gate1_authority_rollback_report_chirho(",
        "run_gate1_authority_rollback_command_chirho(",
        "write_gate1_authority_mode_record_chirho(",
        "signed_gate1_authority_mode_record_chirho(",
        "signed_gate1_authority_old_road_mode_record_chirho(",
        "append_gate1_authority_record_chirho(",
        "append_gate1_authority_record_unlocked_chirho(",
        "read_gate1_authority_records_unverified_chirho",
        "parse_canonical_gate1_authority_record_chirho",
        "serde_json::from_str::<Gate1AuthorityLogRecordChirho>",
        "append_serialized_jsonl",
        "append_recovered_jsonl",
        "commit_head_chirho(",
        "set_branch_chirho(",
        "remove_branch_chirho(",
        "transfer_chirho(",
        "post_entry",
        "create_stripe_transfer_chirho(",
        "settlement_chirho::",
        "paid_chirho::",
    ];
    let mut offenders_chirho = Vec::new();
    for (line_index_chirho, line_chirho) in production_text_chirho(text_chirho).lines().enumerate()
    {
        let trimmed_chirho = line_chirho.trim();
        for token_chirho in forbidden_tokens_chirho {
            if trimmed_chirho.contains(token_chirho) {
                offenders_chirho.push(format!(
                    "{}:{token_chirho}: {trimmed_chirho}",
                    line_index_chirho + 1
                ));
            }
        }
    }
    offenders_chirho
}
pub(super) fn gate1_authority_unlocked_append_sites_outside_crate_chirho() -> Vec<String> {
    production_source_lines_matching_chirho("append_gate1_authority_record_unlocked_chirho(")
        .into_iter()
        .filter(|(rel_chirho, _line_chirho, _text_chirho)| {
            !rel_chirho.starts_with(GATE1_AUTHORITY_LOG_CRATE_SRC_CHIRHO)
        })
        .map(|(rel_chirho, line_chirho, text_chirho)| {
            format!("{rel_chirho}:{line_chirho}: {text_chirho}")
        })
        .collect()
}
pub(super) fn gate1_authority_projection_call_sites_chirho() -> Vec<String> {
    production_source_lines_matching_chirho(
        "gate1_authority_projection_from_verified_records_chirho(",
    )
    .into_iter()
    .filter(|(rel_chirho, _line_chirho, _text_chirho)| {
        rel_chirho != GATE1_PROJECTION_ORACLE_SRC_CHIRHO
    })
    .map(|(rel_chirho, line_chirho, text_chirho)| {
        format!("{rel_chirho}:{line_chirho}: {text_chirho}")
    })
    .collect()
}

pub(super) fn function_body_after_signature_chirho<'a>(
    production_chirho: &'a str,
    signature_chirho: &str,
) -> &'a str {
    let start_chirho = production_chirho
        .find(signature_chirho)
        .unwrap_or_else(|| panic!("missing function signature {signature_chirho}"));
    let tail_chirho = &production_chirho[start_chirho..];
    let body_start_chirho = tail_chirho
        .find('{')
        .unwrap_or_else(|| panic!("missing function body for {signature_chirho}"));
    let mut depth_chirho = 0isize;
    let mut end_offset_chirho = None;
    for (offset_chirho, char_chirho) in tail_chirho[body_start_chirho..].char_indices() {
        match char_chirho {
            '{' => depth_chirho += 1,
            '}' => {
                depth_chirho -= 1;
                if depth_chirho == 0 {
                    end_offset_chirho = Some(body_start_chirho + offset_chirho + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    &tail_chirho[..end_offset_chirho.unwrap_or(tail_chirho.len())]
}
