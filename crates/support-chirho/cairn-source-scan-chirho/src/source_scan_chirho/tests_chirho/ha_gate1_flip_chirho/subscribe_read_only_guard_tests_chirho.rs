// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::super::*;

const SUBSCRIBE_CRATE_CHIRHO: &str = "crates/services-chirho/cairn-subscribe-chirho";
const SUBSCRIBE_CRATE_SRC_CHIRHO: &str = "crates/services-chirho/cairn-subscribe-chirho/src/";

fn subscribe_forbidden_sites_in_text_chirho(text_chirho: &str) -> Vec<String> {
    let forbidden_tokens_chirho = [
        "load_gate1_authority_records_chirho(",
        "read_gate1_authority_records_unverified_chirho(",
        "parse_canonical_gate1_authority_record_chirho(",
        "serde_json::from_",
        "append_gate1_authority_record_chirho(",
        "append_gate1_authority_record_unlocked_chirho(",
        "recover_gate1_authority_head_chirho(",
        "repair_gate1_authority",
        "append_gate1_ring_a_anchors_chirho(",
        "write_gate1_authority_mode_record_chirho(",
        "gate1_checkpoint_report_chirho(",
        "gate1_authority_flip_report_chirho(",
        "gate1_authority_rollback_report_chirho(",
        "append_jsonl",
        "append_serialized_jsonl",
        "write_file_durable_chirho(",
        "std::fs::write(",
        "fs::write(",
        "File::create(",
        "OpenOptions",
        "create_dir_all(",
        "set_branch_chirho(",
        "compare_and_set",
        "remove_branch_chirho(",
        "versioned_chirho::",
        "query_chirho::project",
        "post_entry",
        "transfer_chirho(",
        "create_stripe_transfer_chirho(",
        "settlement_chirho::",
        "paid_chirho::",
        "provider_chirho::",
        "TcpListener",
        "axum::",
        "tokio::net",
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

#[test]
fn subscribe_phase1_stays_verified_read_only_and_transport_free_chirho() {
    let root_chirho = workspace_root_chirho();
    let cargo_chirho =
        std::fs::read_to_string(root_chirho.join(SUBSCRIBE_CRATE_CHIRHO).join("Cargo.toml"))
            .unwrap();
    for forbidden_dependency_chirho in [
        "cairn-chirho =",
        "cairn-cli-chirho",
        "cairn-serve-runtime-chirho",
        "clap =",
        "axum =",
        "tokio =",
    ] {
        assert!(
            !cargo_chirho.contains(forbidden_dependency_chirho),
            "Subscribe Phase 1 must remain a lower read-only service without root/CLI/serve/transport dependency: {forbidden_dependency_chirho}"
        );
    }

    let mut production_chirho = String::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        if !relative_chirho.starts_with(SUBSCRIBE_CRATE_SRC_CHIRHO) {
            continue;
        }
        production_chirho.push_str(&std::fs::read_to_string(path_chirho).unwrap());
        production_chirho.push('\n');
    }
    assert_eq!(
        production_text_chirho(&production_chirho)
            .matches("verified_gate1_authority_records_chirho(")
            .count(),
        1,
        "Subscribe Phase 1 must mint exactly one verified Gate 1 witness in its one shared tail reader"
    );
    let offenders_chirho = subscribe_forbidden_sites_in_text_chirho(&production_chirho);
    assert!(
        offenders_chirho.is_empty(),
        "Subscribe Phase 1 must stay verified-read-only, money-free, ref-free, and transport-free:\n{}",
        offenders_chirho.join("\n")
    );
}

#[test]
fn subscribe_read_only_guard_fixture_catches_authority_append_chirho() {
    let planted_chirho = r#"
        fn tick_chirho(root_chirho: &Path) {
            append_gate1_authority_record_chirho(root_chirho);
        }
    "#;
    let offenders_chirho = subscribe_forbidden_sites_in_text_chirho(planted_chirho);
    assert!(
        offenders_chirho
            .iter()
            .any(|site_chirho| site_chirho.contains("append_gate1_authority_record_chirho(")),
        "Subscribe read-only guard fixture must catch an authority append in the subscribe path"
    );
}
