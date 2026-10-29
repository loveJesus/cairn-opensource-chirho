// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::*;
use super::shared_guard_helpers_chirho::*;

#[test]
fn gate1_authority_log_crate_stays_leaf_and_never_uses_jsonl_len_sequence_chirho() {
    let root_chirho = workspace_root_chirho();
    let cargo_chirho = std::fs::read_to_string(
        root_chirho
            .join(GATE1_AUTHORITY_LOG_CRATE_CHIRHO)
            .join("Cargo.toml"),
    )
    .unwrap();
    assert!(
        !cargo_chirho.contains("cairn-chirho ="),
        "Gate 1 authority-log crate must not depend on the root composition crate"
    );
    let mut offenders_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let rel_chirho = workspace_relative_chirho(&path_chirho);
        if !rel_chirho.starts_with(GATE1_AUTHORITY_LOG_CRATE_SRC_CHIRHO) {
            continue;
        }
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        for (line_index_chirho, line_chirho) in
            production_text_chirho(&text_chirho).lines().enumerate()
        {
            let trimmed_chirho = line_chirho.trim();
            for token_chirho in [
                "cairn_chirho::",
                "recover_jsonl_len_unlocked_chirho",
                "append_recovered_jsonl_unlocked_chirho",
                "append_serialized_jsonl_chirho",
                "append_serialized_jsonl_unlocked_chirho",
            ] {
                if trimmed_chirho.contains(token_chirho) {
                    offenders_chirho.push(format!(
                        "{}:{}:{token_chirho}: {trimmed_chirho}",
                        rel_chirho,
                        line_index_chirho + 1
                    ));
                }
            }
        }
    }
    assert!(
        offenders_chirho.is_empty(),
        "Gate 1 authority-log sequencing must stay persisted-head/fence gated, not root-bound or jsonl_len-derived:\n{}",
        offenders_chirho.join("\n")
    );
}

#[test]
fn gate1_typed_ingestion_parity_keeps_byte_baseline_comparator_chirho() {
    let root_chirho = workspace_root_chirho();
    let text_chirho = std::fs::read_to_string(root_chirho.join(GATE1_TYPED_INGESTION_SRC_CHIRHO))
        .unwrap_or_else(|error_chirho| {
            panic!("read Gate 1 typed ingestion source: {error_chirho}")
        });
    let projection_text_chirho =
        std::fs::read_to_string(root_chirho.join(GATE1_PROJECTION_SRC_CHIRHO))
            .unwrap_or_else(|error_chirho| panic!("read Gate 1 projection source: {error_chirho}"));
    let production_chirho = production_text_chirho(&text_chirho);
    let projection_production_chirho = production_text_chirho(&projection_text_chirho);
    let report_body_chirho = function_body_after_signature_chirho(
        &production_chirho,
        "pub fn typed_ingestion_parity_report_chirho(",
    );
    assert!(
        report_body_chirho.contains("materialize_typed_recover_chirho(root_chirho)?"),
        "typed-ingestion parity report must keep a separate typed-recover view"
    );
    assert!(
        report_body_chirho.contains(
            "let byte_baseline_state_chirho = materialize_live_byte_baseline_chirho(root_chirho)?;"
        ),
        "typed-ingestion parity report must bind byte_baseline_state_chirho directly from the independent byte-baseline comparator"
    );
    assert_eq!(
        report_body_chirho
            .matches("let byte_baseline_state_chirho")
            .count(),
        1,
        "typed-ingestion parity report must have exactly one byte_baseline_state_chirho binding"
    );
    assert!(
        !report_body_chirho.contains("let byte_baseline_state_chirho = typed_state_chirho")
            && !report_body_chirho.contains("let live_state_chirho = typed_state_chirho")
            && !report_body_chirho
                .contains("let byte_baseline_digest_chirho = typed_digest_chirho"),
        "typed-ingestion parity report must not collapse into a typed-vs-typed tautology"
    );
    assert!(
        function_body_after_signature_chirho(
            &projection_production_chirho,
            "pub fn materialize_live_chirho(",
        )
        .contains("materialize_live_byte_baseline_chirho(root_chirho)"),
        "materialize_live_chirho must remain a compatibility wrapper over the byte baseline"
    );
}

// RETIRED 2026-07-26 at CF6 wave-1: `gate1_authority_mode_reader_is_root_pinned_and_witness_fed_chirho`.
// Its subject file, `economic_flows_chirho/ledger_chirho/gate1_authority_mode_chirho.rs`, was the
// TWO-ROAD mode reader and died with the money spine. Retired only after asking where each property
// it pinned went, because a security arm whose properties MOVED must be repointed, not dropped:
//
//   * the mode-record key-binding and no-self-certification assertions were about the mode reader
//     itself -- no successor, nothing left to violate;
//   * "mint the verified witness" / "fold only witness records" have a LIVE home in
//     `cairn-gate1-authority-log-chirho`, and its live consumers (`cairn-subscribe-chirho`,
//     `cairn-subscription-control-plane-chirho`) are pinned by `subscribe_read_only_guard_tests_chirho`;
//   * the forbidden-bypass assertion named `read_gate1_authority_records_unverified_chirho`, which is
//     now a PRIVATE fn in `authority_log_chirho.rs` with exactly one in-crate caller. That is
//     compiler-enforced confinement, strictly stronger than the text check retired here.
//
// `GATE1_AUTHORITY_MODE_SRC_CHIRHO` went with it -- this arm was its only consumer.
//
// ITS LAST PROPERTY WAS NOT DROPPED, IT WAS STRENGTHENED -- see the arm directly below. The retired
// arm required the authoritative projection call to sit BEHIND the root mode reader; with the mode
// reader gone the measured state is better than that requirement: the call has NO production caller
// outside its own oracle module at all. That is a real confinement worth pinning, so the orphaned
// census helper was turned into an absence guard rather than deleted with the arm.

/// Replaces the confinement half of the retired G1.7 mode-reader arm. Polarity is deliberate: this
/// is an ABSENCE guard, and empty is exactly what it asserts, so passing over an empty census is
/// correct here rather than vacuous.
///
/// MIGRATION PATH, so a future red is an instruction and not an archaeology session: if this fires,
/// someone added a production call to `gate1_authority_projection_from_verified_records_chirho`
/// outside `cairn-projection-chirho`'s own oracle module. That is not automatically wrong -- it is
/// the authoritative projection entry point, and a legitimate consumer may appear. What it must not
/// be is UNREVIEWED. Read the new call site, decide whether it belongs behind a verified-witness
/// mint, and then either repoint the caller or convert this arm into a reviewed allowlist with one
/// row per site and an exact count, the shape
/// `gate1_authority_unlocked_append_stays_inside_reviewed_ring_a_wrappers_chirho` already uses.
#[test]
fn gate1_authoritative_projection_has_no_caller_outside_its_oracle_module_chirho() {
    // POSITIVE CONTROL FIRST. An absence assertion is only evidence if the instrument can still
    // see; a scanner that silently matched nothing would make the real check below pass forever.
    // The oracle module defines and exercises this call, so the UNFILTERED matcher must find it.
    let all_sites_chirho = production_source_lines_matching_chirho(
        "gate1_authority_projection_from_verified_records_chirho(",
    );
    assert!(
        all_sites_chirho
            .iter()
            .any(|(rel_chirho, _line_chirho, _text_chirho)| rel_chirho
                == GATE1_PROJECTION_ORACLE_SRC_CHIRHO),
        "positive control failed: the production scanner no longer sees the oracle module's own \
         call, so the absence check below would pass without measuring anything"
    );

    let sites_chirho = gate1_authority_projection_call_sites_chirho();
    assert!(
        sites_chirho.is_empty(),
        "authoritative Gate 1 projection gained a production caller outside its oracle module; \
         review it before it ships: {sites_chirho:?}"
    );
}

#[test]
fn gate1_authority_backfill_guard_fixture_catches_activation_money_and_raw_bypass_chirho() {
    let fixture_chirho = r#"
        pub fn gate1_authority_backfill_report_chirho(root_chirho: &std::path::Path) {
            let _ = gate1_authority_flip_report_chirho(root_chirho);
            let _ = transfer_chirho(root_chirho, "bad", "a", "b", AssetChirho::TokenChirho, 1);
            let _ = read_gate1_authority_records_unverified_chirho(root_chirho);
        }
    "#;
    let offenders_chirho = gate1_authority_backfill_forbidden_sites_in_text_chirho(fixture_chirho);
    assert!(
        offenders_chirho
            .iter()
            .any(|site_chirho| site_chirho.contains("gate1_authority_flip_report_chirho(")),
        "fixture must catch activation inside the backfill command"
    );
    assert!(
        offenders_chirho
            .iter()
            .any(|site_chirho| site_chirho.contains("transfer_chirho(")),
        "fixture must catch money posting inside the backfill command"
    );
    assert!(
        offenders_chirho.iter().any(|site_chirho| {
            site_chirho.contains("read_gate1_authority_records_unverified_chirho")
        }),
        "fixture must catch raw authority-record bypass inside the backfill command"
    );
}

#[test]
fn gate1_authority_oracle_feed_guard_fixture_catches_unverified_call_chirho() {
    let fixture_chirho = r#"
        fn rogue_chirho(root_chirho: &std::path::Path) {
            let records_chirho = read_gate1_authority_records_unverified_chirho(root_chirho).unwrap();
            gate1_oracle_report_from_verified_records_chirho(root_chirho, &records_chirho, &[]);
        }
    "#;
    let production_chirho = production_text_chirho(fixture_chirho);
    assert!(
        production_chirho.contains("read_gate1_authority_records_unverified_chirho")
            && production_chirho.contains("gate1_oracle_report_from_verified_records_chirho("),
        "fixture must catch a raw authority record feed into the projection oracle"
    );
}

#[test]
fn gate1_typed_ingestion_guard_fixture_catches_typed_tautology_chirho() {
    let fixture_chirho = r#"
        pub fn typed_ingestion_parity_report_chirho(root_chirho: &Path) {
            let (typed_state_chirho, _) = materialize_typed_recover_chirho(root_chirho)?;
            let byte_baseline_state_chirho = typed_state_chirho.clone();
            let typed_digest_chirho = clsd_digest_chirho(&typed_state_chirho);
            let byte_baseline_digest_chirho = typed_digest_chirho.clone();
        }

        pub fn materialize_live_chirho(root_chirho: &Path) {
            materialize_live_byte_baseline_chirho(root_chirho)
        }
    "#;
    let production_chirho = production_text_chirho(fixture_chirho);
    let report_body_chirho = function_body_after_signature_chirho(
        &production_chirho,
        "pub fn typed_ingestion_parity_report_chirho(",
    );
    assert!(
        !report_body_chirho.contains("materialize_live_byte_baseline_chirho(root_chirho)?")
            && report_body_chirho.contains("let byte_baseline_state_chirho = typed_state_chirho")
            && report_body_chirho.contains("let byte_baseline_digest_chirho = typed_digest_chirho"),
        "fixture must model the typed-vs-typed tautology the real guard rejects"
    );
}

#[test]
fn gate1_authority_mode_guard_fixture_catches_self_certifying_verify_chirho() {
    let fixture_chirho = r#"
        fn rogue_mode_reader_chirho(record_chirho: &RecordChirho, message_chirho: &[u8]) {
            verify_with_pubkey_chirho(&record_chirho.key_id_chirho, message_chirho, &record_chirho.sig_chirho);
        }
    "#;
    assert!(
        production_text_chirho(fixture_chirho).contains("&record_chirho.key_id_chirho"),
        "fixture must catch a self-certifying authority-mode verifier"
    );
}

#[test]
fn gate1_authority_flip_guard_fixture_catches_money_write_chirho() {
    let fixture_chirho = r#"
        pub fn rogue_flip_chirho(root_chirho: &std::path::Path) {
            gate1_checkpoint_report_chirho(root_chirho).unwrap();
            transfer_chirho(root_chirho);
            append_gate1_authority_record_chirho(root_chirho);
        }
    "#;
    let offenders_chirho =
        gate1_authority_flip_forbidden_writer_sites_in_text_chirho(fixture_chirho);
    assert!(
        offenders_chirho
            .iter()
            .any(|site_chirho| site_chirho.contains("transfer_chirho(")),
        "fixture must catch money transfer inside flip command"
    );
    assert!(
        offenders_chirho
            .iter()
            .any(|site_chirho| site_chirho.contains("append_gate1_authority_record_chirho(")),
        "fixture must catch authority-log append inside flip command"
    );
}

#[test]
fn gate1_authority_soak_guard_fixture_catches_writer_token_chirho() {
    let fixture_chirho = r#"
        pub fn rogue_soak_chirho(root_chirho: &std::path::Path) {
            gate1_checkpoint_report_chirho(root_chirho).unwrap();
            use std::fs;
            fs::write(root_chirho, b"accident-chirho").unwrap();
            write_gate1_authority_mode_record_chirho(root_chirho);
            append_gate1_authority_record_chirho(root_chirho);
            transfer_chirho(root_chirho);
        }
    "#;
    let offenders_chirho =
        gate1_authority_soak_forbidden_writer_sites_in_text_chirho(fixture_chirho);
    for token_chirho in [
        "gate1_checkpoint_report_chirho(",
        "fs::write(",
        "write_gate1_authority_mode_record_chirho(",
        "append_gate1_authority_record_chirho(",
        "transfer_chirho(",
    ] {
        assert!(
            offenders_chirho
                .iter()
                .any(|site_chirho| site_chirho.contains(token_chirho)),
            "fixture must catch {token_chirho} inside authority soak"
        );
    }
}

#[test]
fn gate1_checkpoint_guard_fixture_catches_non_anchor_write_chirho() {
    let text_chirho = r#"
        pub fn rogue_checkpoint_chirho(root_chirho: &std::path::Path) {
            append_gate1_ring_a_anchors_chirho(root_chirho).unwrap();
            append_gate1_authority_record_chirho(root_chirho);
            set_branch_chirho(root_chirho);
        }
    "#;
    let offenders_chirho = gate1_checkpoint_forbidden_writer_sites_in_text_chirho(text_chirho);
    assert!(
        offenders_chirho
            .iter()
            .any(|site_chirho| site_chirho.contains("append_gate1_authority_record_chirho(")),
        "fixture must catch authority-log writes inside checkpoint"
    );
    assert!(
        offenders_chirho
            .iter()
            .any(|site_chirho| site_chirho.contains("set_branch_chirho(")),
        "fixture must catch ref mutation inside checkpoint"
    );
}

#[test]
fn gate1_authority_unlocked_append_stays_inside_reviewed_ring_a_wrappers_chirho() {
    let sites_chirho = gate1_authority_unlocked_append_sites_outside_crate_chirho();
    // RE-INVENTORIED 2026-07-26 at CF6 wave-1: EIGHT -> THREE. The five removed rows were all
    // `economic_flows_chirho` wrappers that died with the money spine; the three survivors are
    // unchanged, and they are the reason this arm was re-inventoried instead of retired.
    //
    // THIS GUARD WAS RULED "RETIRE" AND THAT RULING WAS WRONG -- it confines a LIVE property with
    // LIVE call sites. `append_gate1_authority_record_unlocked_chirho` appends to the Gate 1
    // authority log WITHOUT taking the lock, so who may call it is an authority invariant, and
    // deleting the spine made the legitimate caller set SMALLER, which makes the confinement tighter
    // rather than moot. Verified rather than assumed: all three sites sit inside `pub(super)`
    // fence-bearing Ring-A dual-write wrappers in a module whose own header reads "Gate 1 companion
    // authority envelopes for resource Ring-A families" -- reconcile prefix, write old road, then
    // append the authority record.
    //
    // The repetition is deliberate and load-bearing: this is a COUNT-matched list, one row per call
    // site, compared with `sites.len() == allowed.len()`. A fourth unlocked append inside an already
    // allowed file still fires. Do not collapse these three rows into one.
    let allowed_chirho = [
        "src/app_metering_chirho/resource_chirho/gate1_authority_chirho.rs:",
        "src/app_metering_chirho/resource_chirho/gate1_authority_chirho.rs:",
        "src/app_metering_chirho/resource_chirho/gate1_authority_chirho.rs:",
    ];
    assert!(
        sites_chirho.len() == allowed_chirho.len()
            && sites_chirho
                .iter()
                .all(|site_chirho| allowed_chirho
                    .iter()
                    .any(|prefix_chirho| site_chirho.starts_with(prefix_chirho))),
        "Gate 1 authority-log unlocked append may only be called by reviewed Ring-A dual-write wrappers outside the authority-log crate: {sites_chirho:?}"
    );
}

#[test]
fn gate1_authority_unlocked_append_guard_fixture_catches_rogue_call_chirho() {
    let fixture_chirho = r#"
        fn rogue_chirho(root_chirho: &std::path::Path) {
            append_gate1_authority_record_unlocked_chirho(root_chirho);
        }
    "#;
    let offenders_chirho = fixture_chirho
        .lines()
        .enumerate()
        .filter(|(_line_chirho, text_chirho)| {
            production_text_chirho(text_chirho)
                .contains("append_gate1_authority_record_unlocked_chirho(")
        })
        .collect::<Vec<_>>();
    assert!(
        !offenders_chirho.is_empty(),
        "fixture must catch a rogue authority-log unlocked append call"
    );
}

#[test]
fn gate1_canary_guard_fixture_catches_writer_token_chirho() {
    let text_chirho = r#"
        pub fn rogue_canary_chirho(root_chirho: &std::path::Path) {
            append_gate1_authority_record_chirho(root_chirho);
            remove_branch_chirho(root_chirho);
        }
    "#;
    let offenders_chirho = gate1_canary_writer_token_sites_in_text_chirho(text_chirho);
    assert!(
        offenders_chirho
            .iter()
            .any(|site_chirho| site_chirho.contains("append_gate1_authority_record_chirho(")),
        "fixture must catch authority-log appends inside the canary"
    );
    assert!(
        offenders_chirho
            .iter()
            .any(|site_chirho| site_chirho.contains("remove_branch_chirho(")),
        "fixture must catch ref mutation inside the canary"
    );
}
