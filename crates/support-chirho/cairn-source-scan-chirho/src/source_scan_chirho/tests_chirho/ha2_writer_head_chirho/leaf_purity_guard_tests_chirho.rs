// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::*;
use std::collections::{BTreeMap, BTreeSet};

const ECONOMIC_GOVERNANCE_CRATE_CHIRHO: &str =
    "crates/services-chirho/cairn-economic-governance-chirho";
const ECONOMIC_GOVERNANCE_CRATE_SRC_CHIRHO: &str =
    "crates/services-chirho/cairn-economic-governance-chirho/src/";
const ECONOMIC_GOVERNANCE_BILLING_POLICY_CHIRHO: &str =
    "crates/services-chirho/cairn-economic-governance-chirho/src/billing_policy_chirho.rs";
const ECONOMIC_GOVERNANCE_PRICEBOOK_POLICY_CHIRHO: &str =
    "crates/services-chirho/cairn-economic-governance-chirho/src/pricebook_policy_chirho.rs";
const HEAD_REMOVAL_CRATE_CHIRHO: &str = "crates/support-chirho/cairn-head-removal-chirho";
const HEAD_REMOVAL_CRATE_SRC_CHIRHO: &str = "crates/support-chirho/cairn-head-removal-chirho/src/";
const MODEL_AGENT_AUTHORITY_CRATE_CHIRHO: &str =
    "crates/domain-chirho/cairn-model-agent-authority-chirho";
const MODEL_AGENT_AUTHORITY_CRATE_SRC_CHIRHO: &str =
    "crates/domain-chirho/cairn-model-agent-authority-chirho/src/";
const MODEL_AGENT_REPORT_CRATE_CHIRHO: &str =
    "crates/domain-chirho/cairn-model-agent-report-chirho";
const MODEL_AGENT_REPORT_CRATE_SRC_CHIRHO: &str =
    "crates/domain-chirho/cairn-model-agent-report-chirho/src/";
const MODEL_IDENTITY_CRATE_CHIRHO: &str = "crates/domain-chirho/cairn-model-identity-chirho";
const MODEL_IDENTITY_CRATE_SRC_CHIRHO: &str =
    "crates/domain-chirho/cairn-model-identity-chirho/src/";
const MODEL_ECONOMIC_CRATE_CHIRHO: &str = "crates/domain-chirho/cairn-model-economic-chirho";
const MODEL_ECONOMIC_CRATE_SRC_CHIRHO: &str =
    "crates/domain-chirho/cairn-model-economic-chirho/src/";
const MODEL_PRIVACY_CRATE_CHIRHO: &str = "crates/domain-chirho/cairn-model-privacy-chirho";
const MODEL_PRIVACY_CRATE_SRC_CHIRHO: &str = "crates/domain-chirho/cairn-model-privacy-chirho/src/";
const SIGNER_CRATE_CHIRHO: &str = "crates/support-chirho/cairn-signer-chirho";
const SIGNER_CRATE_SRC_CHIRHO: &str = "crates/support-chirho/cairn-signer-chirho/src/";
// SIGNER_PUBLIC_FN_ALLOWLIST_CHIRHO (the frozen public API surface) moved to the advisory structure
// report as a set-freeze; the key-custody engine claims stay RED via signer_public_raw_key_material_sites_chirho.

const ECONOMIC_GOVERNANCE_FORBIDDEN_SOURCE_TOKENS_CHIRHO: &[&str] = &[
    "cairn_chirho::",
    "use cairn_chirho",
    "effect_chirho::",
    "ledger_chirho::",
    "paid_chirho::",
    "cache_chirho::",
    "native_worker_chirho::",
    "settlement_chirho::",
    "std::env",
    "std::fs",
    "std::net",
    "std::time",
    "SystemTime",
    "Instant",
    "UNIX_EPOCH",
    "cairn_durable_chirho",
    "run_intent_chirho::",
    "invoke_priced_with_run_chirho(",
    "run_authorized_explicit_paid_effect_chirho(",
    "refs_chirho::",
    "store_chirho::",
    "cairn_signer_chirho",
    "cairn_seqlog_chirho",
    "cairn_writer_head_chirho",
    "with_head_commit_chirho(",
    "commit_head_chirho(",
    "append_serialized_jsonl",
    "load_or_create_signing_key_chirho(",
];

const PRICEBOOK_POLICY_FORBIDDEN_SOURCE_TOKENS_CHIRHO: &[&str] = &[
    "cairn_chirho::",
    "use cairn_chirho",
    "effect_chirho::",
    "ledger_chirho::",
    "paid_chirho::",
    "settlement_chirho::",
    "std::env",
    "std::fs",
    "std::net",
    "std::time",
    "SystemTime",
    "Instant",
    "UNIX_EPOCH",
    "cairn_durable_chirho",
    "run_intent_chirho::",
    "invoke_priced_with_run_chirho(",
    "run_authorized_explicit_paid_effect_chirho(",
    "sign_message_chirho(",
    "pubkey_hex_chirho(",
    "verify_with_pubkey_chirho(",
    "cairn_signer_chirho",
    "cairn_seqlog_chirho",
    "append_serialized_jsonl",
    "cairn_writer_head_chirho",
    "with_head_commit_chirho(",
    "refs_chirho::",
    "commit_head_chirho(",
    "store_chirho::",
    "put_object_chirho(",
    "get_object_chirho(",
    "load_or_create_signing_key_chirho(",
];

const BILLING_POLICY_FORBIDDEN_SOURCE_TOKENS_CHIRHO: &[&str] = &[
    "cairn_chirho::",
    "use cairn_chirho",
    "app_chirho::",
    "ensure_app_owner_chirho(",
    "verified_app_owner_chirho(",
    "effect_chirho::",
    "ledger_chirho::",
    "paid_chirho::",
    "settlement_chirho::",
    "std::env",
    "std::fs",
    "std::net",
    "std::time",
    "SystemTime",
    "Instant",
    "UNIX_EPOCH",
    "cairn_durable_chirho",
    "run_intent_chirho::",
    "invoke_priced_with_run_chirho(",
    "run_authorized_explicit_paid_effect_chirho(",
    "sign_message_chirho(",
    "pubkey_hex_chirho(",
    "verify_with_pubkey_chirho(",
    "cairn_signer_chirho",
    "cairn_seqlog_chirho",
    "append_serialized_jsonl",
    "cairn_writer_head_chirho",
    "with_head_commit_chirho(",
    "refs_chirho::",
    "commit_head_chirho(",
    "store_chirho::",
    "put_object_chirho(",
    "get_object_chirho(",
    "enforce_spend_caps_chirho(",
    "subsidy_used_chirho(",
    "net_billing_spend_chirho(",
    "load_billing_usage_chirho(",
    "load_billing_compensations_chirho(",
    "verify_billing_compensations_chirho(",
    "load_or_create_signing_key_chirho(",
];

const HEAD_REMOVAL_FORBIDDEN_SOURCE_TOKENS_CHIRHO: &[&str] = &[
    "cairn_chirho::",
    "use cairn_chirho",
    "effect_chirho::",
    "ledger_chirho::",
    "paid_chirho::",
    "cache_chirho::",
    "native_worker_chirho::",
    "run_intent_chirho::",
    "invoke_priced_with_run_chirho(",
    "run_authorized_explicit_paid_effect_chirho(",
    "refs_chirho::set_branch_chirho(",
    "refs_chirho::rollback_chirho(",
    "refs_chirho::compare_and_set_branch_chirho(",
    "refs_chirho::save_refs_chirho(",
    "load_or_create_signing_key_chirho(",
];

fn economic_governance_forbidden_source_sites_in_text_chirho(
    rel_chirho: &str,
    text_chirho: &str,
) -> Vec<String> {
    let mut offenders_chirho = Vec::new();
    let production_chirho = production_text_chirho(text_chirho);
    for (line_index_chirho, line_chirho) in production_chirho.lines().enumerate() {
        let trimmed_chirho = line_chirho.trim();
        if trimmed_chirho.is_empty() || trimmed_chirho.starts_with("//") {
            continue;
        }
        for token_chirho in ECONOMIC_GOVERNANCE_FORBIDDEN_SOURCE_TOKENS_CHIRHO {
            if trimmed_chirho.contains(token_chirho) {
                offenders_chirho.push(format!(
                    "{rel_chirho}:{}:{token_chirho}: {trimmed_chirho}",
                    line_index_chirho + 1
                ));
            }
        }
    }
    offenders_chirho
}

fn economic_governance_forbidden_source_sites_chirho() -> Vec<String> {
    let mut offenders_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let rel_chirho = workspace_relative_chirho(&path_chirho);
        if !rel_chirho.starts_with(ECONOMIC_GOVERNANCE_CRATE_SRC_CHIRHO) {
            continue;
        }
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        offenders_chirho.extend(economic_governance_forbidden_source_sites_in_text_chirho(
            &rel_chirho,
            &text_chirho,
        ));
    }
    offenders_chirho.sort();
    offenders_chirho
}

fn pricebook_policy_forbidden_source_sites_in_text_chirho(
    rel_chirho: &str,
    text_chirho: &str,
) -> Vec<String> {
    let mut offenders_chirho = Vec::new();
    let production_chirho = production_text_chirho(text_chirho);
    for (line_index_chirho, line_chirho) in production_chirho.lines().enumerate() {
        let trimmed_chirho = line_chirho.trim();
        if trimmed_chirho.is_empty() || trimmed_chirho.starts_with("//") {
            continue;
        }
        for token_chirho in PRICEBOOK_POLICY_FORBIDDEN_SOURCE_TOKENS_CHIRHO {
            if trimmed_chirho.contains(token_chirho) {
                offenders_chirho.push(format!(
                    "{rel_chirho}:{}:{token_chirho}: {trimmed_chirho}",
                    line_index_chirho + 1
                ));
            }
        }
    }
    offenders_chirho
}

fn pricebook_policy_forbidden_source_sites_chirho() -> Vec<String> {
    let path_chirho = workspace_root_chirho().join(ECONOMIC_GOVERNANCE_PRICEBOOK_POLICY_CHIRHO);
    let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    pricebook_policy_forbidden_source_sites_in_text_chirho(
        ECONOMIC_GOVERNANCE_PRICEBOOK_POLICY_CHIRHO,
        &text_chirho,
    )
}

fn billing_policy_forbidden_source_sites_in_text_chirho(
    rel_chirho: &str,
    text_chirho: &str,
) -> Vec<String> {
    let mut offenders_chirho = Vec::new();
    let production_chirho = production_text_chirho(text_chirho);
    for (line_index_chirho, line_chirho) in production_chirho.lines().enumerate() {
        let trimmed_chirho = line_chirho.trim();
        if trimmed_chirho.is_empty() || trimmed_chirho.starts_with("//") {
            continue;
        }
        for token_chirho in BILLING_POLICY_FORBIDDEN_SOURCE_TOKENS_CHIRHO {
            if trimmed_chirho.contains(token_chirho) {
                offenders_chirho.push(format!(
                    "{rel_chirho}:{}:{token_chirho}: {trimmed_chirho}",
                    line_index_chirho + 1
                ));
            }
        }
    }
    offenders_chirho
}

fn billing_policy_forbidden_source_sites_chirho() -> Vec<String> {
    let path_chirho = workspace_root_chirho().join(ECONOMIC_GOVERNANCE_BILLING_POLICY_CHIRHO);
    let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    billing_policy_forbidden_source_sites_in_text_chirho(
        ECONOMIC_GOVERNANCE_BILLING_POLICY_CHIRHO,
        &text_chirho,
    )
}

fn economic_governance_forbidden_cargo_dependency_sites_chirho() -> Vec<String> {
    let cargo_chirho = workspace_root_chirho()
        .join(ECONOMIC_GOVERNANCE_CRATE_CHIRHO)
        .join("Cargo.toml");
    let text_chirho = std::fs::read_to_string(&cargo_chirho).unwrap();
    let forbidden_deps_chirho = [
        "cairn-chirho",
        "cairn_chirho",
        "cairn-signer-chirho",
        "cairn_signer_chirho",
        "cairn-seqlog-chirho",
        "cairn_seqlog_chirho",
        "cairn-writer-head-chirho",
        "cairn_writer_head_chirho",
        "cairn-store-chirho",
        "cairn_store_chirho",
    ];
    text_chirho
        .lines()
        .enumerate()
        .filter_map(|(line_index_chirho, line_chirho)| {
            let trimmed_chirho = line_chirho.trim();
            forbidden_deps_chirho
                .iter()
                .any(|dep_chirho| {
                    trimmed_chirho.starts_with(&format!("{dep_chirho} ="))
                        || trimmed_chirho.starts_with(&format!("\"{dep_chirho}\" ="))
                })
                .then(|| {
                    format!(
                        "{}/Cargo.toml:{}: {trimmed_chirho}",
                        ECONOMIC_GOVERNANCE_CRATE_CHIRHO,
                        line_index_chirho + 1
                    )
                })
        })
        .collect()
}

fn head_removal_forbidden_source_sites_chirho() -> Vec<String> {
    let mut offenders_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let rel_chirho = workspace_relative_chirho(&path_chirho);
        if !rel_chirho.starts_with(HEAD_REMOVAL_CRATE_SRC_CHIRHO) {
            continue;
        }
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let production_chirho = production_text_chirho(&text_chirho);
        for (line_index_chirho, line_chirho) in production_chirho.lines().enumerate() {
            let trimmed_chirho = line_chirho.trim();
            if trimmed_chirho.is_empty() || trimmed_chirho.starts_with("//") {
                continue;
            }
            for token_chirho in HEAD_REMOVAL_FORBIDDEN_SOURCE_TOKENS_CHIRHO {
                if trimmed_chirho.contains(token_chirho) {
                    offenders_chirho.push(format!(
                        "{rel_chirho}:{}:{token_chirho}: {trimmed_chirho}",
                        line_index_chirho + 1
                    ));
                }
            }
        }
    }
    offenders_chirho.sort();
    offenders_chirho
}

fn head_removal_forbidden_cargo_dependency_sites_chirho() -> Vec<String> {
    let cargo_chirho = workspace_root_chirho()
        .join(HEAD_REMOVAL_CRATE_CHIRHO)
        .join("Cargo.toml");
    let text_chirho = std::fs::read_to_string(&cargo_chirho).unwrap();
    text_chirho
        .lines()
        .enumerate()
        .filter_map(|(line_index_chirho, line_chirho)| {
            let trimmed_chirho = line_chirho.trim();
            (trimmed_chirho.starts_with("cairn-chirho =")
                || trimmed_chirho.starts_with("cairn_chirho =")
                || trimmed_chirho.starts_with("cairn-model-")
                || trimmed_chirho.starts_with("cairn_model_"))
            .then(|| {
                format!(
                    "{}/Cargo.toml:{}: {trimmed_chirho}",
                    HEAD_REMOVAL_CRATE_CHIRHO,
                    line_index_chirho + 1
                )
            })
        })
        .collect()
}

const SIGNER_FORBIDDEN_SOURCE_TOKENS_CHIRHO: &[&str] = &[
    "cairn_chirho::",
    "use cairn_chirho",
    "cairn_core_chirho",
    "cairn_model",
    "model_chirho::",
    "effect_chirho::",
    "ledger_chirho::",
    "paid_chirho::",
    "cache_chirho::",
    "native_worker_chirho::",
    "refs_chirho::",
];

const DTO_MODEL_FORBIDDEN_SOURCE_TOKENS_CHIRHO: &[&str] = &[
    "cairn_chirho::",
    "use cairn_chirho",
    "cairn_model_",
    "effect_chirho::",
    "ledger_chirho::",
    "paid_chirho::",
    "privacy_chirho::",
    "refs_chirho::",
    "seqlog_chirho::",
];

fn dto_model_crates_chirho() -> BTreeMap<&'static str, &'static str> {
    [
        (
            MODEL_AGENT_AUTHORITY_CRATE_CHIRHO,
            MODEL_AGENT_AUTHORITY_CRATE_SRC_CHIRHO,
        ),
        (
            MODEL_AGENT_REPORT_CRATE_CHIRHO,
            MODEL_AGENT_REPORT_CRATE_SRC_CHIRHO,
        ),
        (MODEL_ECONOMIC_CRATE_CHIRHO, MODEL_ECONOMIC_CRATE_SRC_CHIRHO),
        (MODEL_IDENTITY_CRATE_CHIRHO, MODEL_IDENTITY_CRATE_SRC_CHIRHO),
        (MODEL_PRIVACY_CRATE_CHIRHO, MODEL_PRIVACY_CRATE_SRC_CHIRHO),
    ]
    .into_iter()
    .collect()
}

fn dto_model_source_token_allowed_chirho(
    rel_chirho: &str,
    token_chirho: &str,
    line_chirho: &str,
) -> bool {
    if rel_chirho.starts_with(MODEL_AGENT_AUTHORITY_CRATE_SRC_CHIRHO)
        && token_chirho == "cairn_model_"
    {
        return line_chirho.contains("cairn_model_agent_report_chirho");
    }
    if !rel_chirho.starts_with(MODEL_ECONOMIC_CRATE_SRC_CHIRHO) {
        return false;
    }
    match token_chirho {
        "cairn_model_" => line_chirho.contains("cairn_model_privacy_chirho"),
        "privacy_chirho::" => line_chirho.contains("cairn_model_privacy_chirho::"),
        "ledger_chirho::" => true,
        _ => false,
    }
}

fn dto_model_forbidden_source_sites_chirho() -> Vec<String> {
    let crate_srcs_chirho = dto_model_crates_chirho().into_values().collect::<Vec<_>>();
    let mut offenders_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let rel_chirho = workspace_relative_chirho(&path_chirho);
        if !crate_srcs_chirho
            .iter()
            .any(|src_chirho| rel_chirho.starts_with(src_chirho))
        {
            continue;
        }
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let production_chirho = production_text_chirho(&text_chirho);
        for (line_index_chirho, line_chirho) in production_chirho.lines().enumerate() {
            let trimmed_chirho = line_chirho.trim();
            if trimmed_chirho.is_empty() || trimmed_chirho.starts_with("//") {
                continue;
            }
            for token_chirho in DTO_MODEL_FORBIDDEN_SOURCE_TOKENS_CHIRHO {
                if dto_model_source_token_allowed_chirho(
                    rel_chirho.as_str(),
                    token_chirho,
                    trimmed_chirho,
                ) {
                    continue;
                }
                if trimmed_chirho.contains(token_chirho) {
                    offenders_chirho.push(format!(
                        "{rel_chirho}:{}:{token_chirho}: {trimmed_chirho}",
                        line_index_chirho + 1
                    ));
                }
            }
        }
    }
    offenders_chirho.sort();
    offenders_chirho
}

fn dto_model_forbidden_cargo_dependency_sites_chirho() -> Vec<String> {
    let mut offenders_chirho = Vec::new();
    for crate_chirho in dto_model_crates_chirho().into_keys() {
        let cargo_chirho = workspace_root_chirho()
            .join(crate_chirho)
            .join("Cargo.toml");
        let text_chirho = std::fs::read_to_string(&cargo_chirho).unwrap();
        for (line_index_chirho, line_chirho) in text_chirho.lines().enumerate() {
            let trimmed_chirho = line_chirho.trim();
            if trimmed_chirho.starts_with("cairn-chirho =")
                || trimmed_chirho.starts_with("cairn_chirho =")
                || (trimmed_chirho.starts_with("cairn-model-")
                    && !((crate_chirho == MODEL_ECONOMIC_CRATE_CHIRHO
                        && trimmed_chirho.starts_with("cairn-model-privacy-chirho ="))
                        || (crate_chirho == MODEL_AGENT_AUTHORITY_CRATE_CHIRHO
                            && trimmed_chirho.starts_with("cairn-model-agent-report-chirho ="))))
                || trimmed_chirho.starts_with("cairn_model_")
            {
                offenders_chirho.push(format!(
                    "{crate_chirho}/Cargo.toml:{}: {trimmed_chirho}",
                    line_index_chirho + 1
                ));
            }
        }
    }
    offenders_chirho
}

fn signer_forbidden_source_sites_chirho() -> Vec<String> {
    let mut offenders_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let rel_chirho = workspace_relative_chirho(&path_chirho);
        if !rel_chirho.starts_with(SIGNER_CRATE_SRC_CHIRHO) {
            continue;
        }
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let production_chirho = production_text_chirho(&text_chirho);
        for (line_index_chirho, line_chirho) in production_chirho.lines().enumerate() {
            let trimmed_chirho = line_chirho.trim();
            if trimmed_chirho.is_empty() || trimmed_chirho.starts_with("//") {
                continue;
            }
            for token_chirho in SIGNER_FORBIDDEN_SOURCE_TOKENS_CHIRHO {
                if trimmed_chirho.contains(token_chirho) {
                    offenders_chirho.push(format!(
                        "{rel_chirho}:{}:{token_chirho}: {trimmed_chirho}",
                        line_index_chirho + 1
                    ));
                }
            }
        }
    }
    offenders_chirho.sort();
    offenders_chirho
}

fn signer_forbidden_cargo_dependency_sites_chirho() -> Vec<String> {
    let cargo_chirho = workspace_root_chirho()
        .join(SIGNER_CRATE_CHIRHO)
        .join("Cargo.toml");
    let text_chirho = std::fs::read_to_string(&cargo_chirho).unwrap();
    text_chirho
        .lines()
        .enumerate()
        .filter_map(|(line_index_chirho, line_chirho)| {
            let trimmed_chirho = line_chirho.trim();
            (trimmed_chirho.starts_with("cairn-chirho =")
                || trimmed_chirho.starts_with("cairn_chirho =")
                || trimmed_chirho.starts_with("cairn-core-chirho =")
                || trimmed_chirho.starts_with("cairn_core_chirho =")
                || trimmed_chirho.starts_with("cairn-model"))
            .then(|| {
                format!(
                    "{}/Cargo.toml:{}: {trimmed_chirho}",
                    SIGNER_CRATE_CHIRHO,
                    line_index_chirho + 1
                )
            })
        })
        .collect()
}

// The exact public-fn allowlist SET freeze (the signer's whole public API surface) was demoted to
// the advisory structure report. This helper keeps the ENGINE key-custody claims: the public API
// exposes no raw key material (SigningKey/key bytes/key paths in a pub struct/const/static) and the
// raw key loader stays private.
fn signer_public_raw_key_material_sites_chirho() -> Vec<String> {
    let path_chirho = workspace_root_chirho()
        .join(SIGNER_CRATE_SRC_CHIRHO)
        .join("signer_chirho.rs");
    let rel_chirho = workspace_relative_chirho(&path_chirho);
    let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    let production_chirho = production_text_chirho(&text_chirho);
    let mut offenders_chirho = Vec::new();
    for (line_index_chirho, line_chirho) in production_chirho.lines().enumerate() {
        let trimmed_chirho = line_chirho.trim();
        if line_chirho.starts_with("pub fn ")
            && trimmed_chirho.contains("load_or_create_signing_key_chirho")
        {
            offenders_chirho.push(format!(
                "{rel_chirho}:{}: raw key loader must stay private: {trimmed_chirho}",
                line_index_chirho + 1
            ));
        }
        if (line_chirho.starts_with("pub struct ")
            || line_chirho.starts_with("pub const ")
            || line_chirho.starts_with("pub static "))
            && (trimmed_chirho.contains("SigningKey")
                || trimmed_chirho.contains("key_bytes")
                || trimmed_chirho.contains("key_bytes_chirho")
                || trimmed_chirho.contains("signing_key")
                || trimmed_chirho.contains("signing_key_chirho")
                || trimmed_chirho.contains("signing_key_path_chirho")
                || trimmed_chirho.contains("pubkey_path_chirho"))
        {
            offenders_chirho.push(format!(
                "{rel_chirho}:{}: {trimmed_chirho}",
                line_index_chirho + 1
            ));
        }
    }
    offenders_chirho
}

#[test]
fn ha2_dto_model_crates_stay_leaf_no_root_or_model_up_chirho() {
    let files_chirho = workspace_production_rs_files_chirho()
        .into_iter()
        .map(|path_chirho| workspace_relative_chirho(&path_chirho))
        .collect::<BTreeSet<_>>();
    for src_chirho in dto_model_crates_chirho().into_values() {
        assert!(
            files_chirho
                .iter()
                .any(|file_chirho| file_chirho.starts_with(src_chirho)),
            "workspace production walker must see DTO model crate source {src_chirho}"
        );
    }
    let mut offenders_chirho = dto_model_forbidden_source_sites_chirho();
    offenders_chirho.extend(dto_model_forbidden_cargo_dependency_sites_chirho());
    assert!(
        offenders_chirho.is_empty(),
        "DTO model crates must stay below root and other model crates:\n{}",
        offenders_chirho.join("\n")
    );
}

#[test]
fn ha2_signer_crate_stays_leaf_no_root_or_model_chirho() {
    let files_chirho = workspace_production_rs_files_chirho()
        .into_iter()
        .map(|path_chirho| workspace_relative_chirho(&path_chirho))
        .collect::<BTreeSet<_>>();
    assert!(
        files_chirho
            .iter()
            .any(|file_chirho| file_chirho.starts_with(SIGNER_CRATE_SRC_CHIRHO)),
        "workspace production walker must see the signer crate"
    );
    let mut offenders_chirho = signer_forbidden_source_sites_chirho();
    offenders_chirho.extend(signer_forbidden_cargo_dependency_sites_chirho());
    assert!(
        offenders_chirho.is_empty(),
        "signer crate must stay below root/model/money surfaces:\n{}",
        offenders_chirho.join("\n")
    );
}

#[test]
fn ha2_signer_public_api_does_not_expose_raw_key_material_chirho() {
    // The public-fn allowlist SET freeze moved to the advisory structure report; the raw-key-material
    // and private-key-loader key-custody claims stay RED here.
    let offenders_chirho = signer_public_raw_key_material_sites_chirho();
    assert!(
        offenders_chirho.is_empty(),
        "signer crate public API must not expose raw signing keys, key loaders, key paths, or key bytes:\n{}",
        offenders_chirho.join("\n")
    );
}

#[test]
fn ha2_economic_governance_crate_is_seen_by_workspace_walker_chirho() {
    let files_chirho = workspace_production_rs_files_chirho()
        .into_iter()
        .map(|path_chirho| workspace_relative_chirho(&path_chirho))
        .collect::<BTreeSet<_>>();
    assert!(
        files_chirho
            .iter()
            .any(|file_chirho| file_chirho.starts_with(ECONOMIC_GOVERNANCE_CRATE_SRC_CHIRHO)),
        "workspace production walker must see the economic/governance extraction crate"
    );
    assert!(
        files_chirho.contains(
            "crates/services-chirho/cairn-economic-governance-chirho/src/ports_chirho.rs"
        ),
        "economic/governance port home must stay in the workspace production walker"
    );
}

#[test]
fn ha2_economic_governance_crate_has_no_root_dependency_chirho() {
    assert!(
        economic_governance_forbidden_cargo_dependency_sites_chirho().is_empty(),
        "economic/governance crate must not depend on root cairn-chirho; root implements narrow ports instead: {:?}",
        economic_governance_forbidden_cargo_dependency_sites_chirho()
    );
}

#[test]
fn ha2_economic_governance_crate_uses_ports_not_root_money_primitives_chirho() {
    assert!(
        economic_governance_forbidden_source_sites_chirho().is_empty(),
        "economic/governance crate must not import root authority or call raw money/head primitives; use narrow ports and lower crates instead: {:?}",
        economic_governance_forbidden_source_sites_chirho()
    );
}

#[test]
fn ha2_pricebook_policy_stays_pure_computation_chirho() {
    let offenders_chirho = pricebook_policy_forbidden_source_sites_chirho();
    assert!(
        offenders_chirho.is_empty(),
        "pricebook policy must stay pure computation/proposal code; root keeps signing, store, seqlog, and ref commits:\n{}",
        offenders_chirho.join("\n")
    );
}

#[test]
fn ha2_billing_policy_stays_pure_computation_chirho() {
    let offenders_chirho = billing_policy_forbidden_source_sites_chirho();
    assert!(
        offenders_chirho.is_empty(),
        "billing policy must stay pure computation/proposal code; root keeps app authz, signed records, spend scans, usage logs, ledger checks, and ref commits:\n{}",
        offenders_chirho.join("\n")
    );
}

#[test]
fn ha2_head_removal_crate_stays_leaf_no_root_or_money_primitives_chirho() {
    let files_chirho = workspace_production_rs_files_chirho()
        .into_iter()
        .map(|path_chirho| workspace_relative_chirho(&path_chirho))
        .collect::<BTreeSet<_>>();
    assert!(
        files_chirho
            .iter()
            .any(|file_chirho| file_chirho.starts_with(HEAD_REMOVAL_CRATE_SRC_CHIRHO)),
        "workspace production walker must see the head-removal crate"
    );
    let mut offenders_chirho = head_removal_forbidden_source_sites_chirho();
    offenders_chirho.extend(head_removal_forbidden_cargo_dependency_sites_chirho());
    assert!(
        offenders_chirho.is_empty(),
        "head-removal crate must stay below root/model/money surfaces and use signer/core/seqlog only:\n{}",
        offenders_chirho.join("\n")
    );
}

#[test]
fn ha2_head_removal_crate_guard_catches_root_authority_tokens_chirho() {
    let text_chirho = r#"
        use cairn_chirho::ledger_chirho;
        fn bad_chirho(root_chirho: &Path) -> Result<()> {
            effect_chirho::sign_message_chirho(root_chirho, b"bad")?;
            refs_chirho::set_branch_chirho(root_chirho, "app/bad", hash_chirho)?;
            run_intent_chirho::run_dag_with_intent_chirho(root_chirho, input_chirho)?;
            Ok(())
        }
    "#;
    let offenders_chirho = {
        let mut offenders_chirho = Vec::new();
        let production_chirho = production_text_chirho(text_chirho);
        for (line_index_chirho, line_chirho) in production_chirho.lines().enumerate() {
            let trimmed_chirho = line_chirho.trim();
            for token_chirho in HEAD_REMOVAL_FORBIDDEN_SOURCE_TOKENS_CHIRHO {
                if trimmed_chirho.contains(token_chirho) {
                    offenders_chirho.push(format!(
                        "crates/support-chirho/cairn-head-removal-chirho/src/probe_chirho.rs:{}:{token_chirho}: {trimmed_chirho}",
                        line_index_chirho + 1
                    ));
                }
            }
        }
        offenders_chirho
    };
    for token_chirho in [
        "use cairn_chirho",
        "effect_chirho::",
        "refs_chirho::set_branch_chirho(",
        "run_intent_chirho::",
    ] {
        assert!(
            offenders_chirho
                .iter()
                .any(|offender_chirho| offender_chirho.contains(token_chirho)),
            "guard must catch {token_chirho}: {offenders_chirho:?}"
        );
    }
}

#[test]
fn ha2_app_owner_port_stays_read_only_and_narrow_chirho() {
    let ports_path_chirho = workspace_root_chirho()
        .join(ECONOMIC_GOVERNANCE_CRATE_CHIRHO)
        .join("src/ports_chirho.rs");
    let text_chirho = std::fs::read_to_string(&ports_path_chirho).unwrap();
    let start_chirho = text_chirho
        .find("pub trait EconomicGovernanceAppOwnerPortChirho")
        .expect("app-owner port trait must exist");
    let rest_chirho = &text_chirho[start_chirho..];
    let end_chirho = rest_chirho
        .find("\npub trait EconomicGovernanceIdentityPortChirho")
        .expect("app-owner port trait must stay before identity port trait");
    let trait_chirho = &rest_chirho[..end_chirho];
    // The exact method-name list freeze was demoted to the advisory structure report; the
    // read-only/no-authority-verb engine claim stays RED.
    for forbidden_chirho in [
        "grant",
        "deploy",
        "set_branch",
        "remove_branch",
        "post_entry",
        "sign_message",
    ] {
        assert!(
            !trait_chirho.contains(forbidden_chirho),
            "app-owner port must not grow authority/mutation verb {forbidden_chirho}"
        );
    }
}

#[test]
fn ha2_economic_governance_guard_catches_raw_money_primitives_chirho() {
    let text_chirho = r#"
        use cairn_chirho::effect_chirho::run_intent_chirho;
        fn bad_chirho(root_chirho: &Path) -> Result<()> {
            ledger_chirho::post_entry_tagged_checked_unlocked_chirho(root_chirho, "memo", vec![], Default::default(), &[])?;
            effect_chirho::sign_message_chirho(root_chirho, b"bad")?;
            refs_chirho::remove_branch_chirho(root_chirho, "app/bad")?;
            run_intent_chirho::run_dag_with_intent_chirho(root_chirho, input_chirho)?;
            Ok(())
        }
    "#;
    let offenders_chirho = economic_governance_forbidden_source_sites_in_text_chirho(
        "crates/services-chirho/cairn-economic-governance-chirho/src/probe_chirho.rs",
        text_chirho,
    );
    for token_chirho in [
        "use cairn_chirho",
        "ledger_chirho::",
        "effect_chirho::",
        "refs_chirho::remove_branch_chirho(",
        "run_intent_chirho::",
    ] {
        assert!(
            offenders_chirho
                .iter()
                .any(|offender_chirho| offender_chirho.contains(token_chirho)),
            "guard must catch {token_chirho}: {offenders_chirho:?}"
        );
    }
}

#[test]
fn ha2_pricebook_policy_purity_guard_catches_authority_tokens_chirho() {
    let text_chirho = r#"
        use cairn_chirho::effect_chirho;
        use cairn_signer_chirho::signer_chirho;
        use cairn_writer_head_chirho::writer_head_chirho;
        fn bad_chirho(root_chirho: &Path) -> Result<()> {
            effect_chirho::sign_message_chirho(root_chirho, b"bad")?;
            ledger_chirho::post_entry_tagged_checked_unlocked_chirho(root_chirho, "memo", vec![], Default::default(), &[])?;
            settlement_chirho::record_payout_chirho(root_chirho, request_chirho)?;
            std::fs::read_to_string(path_chirho)?;
            std::env::var("BAD_CHIRHO")?;
            let _ = std::net::TcpStream::connect("127.0.0.1:9")?;
            let _ = SystemTime::now();
            cairn_durable_chirho::sync_parent_dir_chirho(path_chirho)?;
            seqlog_chirho::append_serialized_jsonl_chirho(path_chirho, |_| Ok(row_chirho))?;
            store_chirho::put_object_chirho(root_chirho, &row_chirho)?;
            refs_chirho::commit_head_chirho(root_chirho, "pricebook/app", precondition_chirho, hash_chirho, "price-book")?;
            writer_head_chirho::with_head_commit_chirho(root_chirho, || Ok(()))?;
            run_intent_chirho::run_dag_with_intent_chirho(root_chirho, input_chirho)?;
            let _ = signer_chirho::pubkey_hex_chirho(root_chirho)?;
            Ok(())
        }
    "#;
    let offenders_chirho = pricebook_policy_forbidden_source_sites_in_text_chirho(
        ECONOMIC_GOVERNANCE_PRICEBOOK_POLICY_CHIRHO,
        text_chirho,
    );
    for token_chirho in [
        "use cairn_chirho",
        "cairn_signer_chirho",
        "cairn_writer_head_chirho",
        "effect_chirho::",
        "sign_message_chirho(",
        "ledger_chirho::",
        "settlement_chirho::",
        "std::fs",
        "std::env",
        "std::net",
        "SystemTime",
        "cairn_durable_chirho",
        "append_serialized_jsonl",
        "store_chirho::",
        "refs_chirho::",
        "commit_head_chirho(",
        "with_head_commit_chirho(",
        "run_intent_chirho::",
        "pubkey_hex_chirho(",
    ] {
        assert!(
            offenders_chirho
                .iter()
                .any(|offender_chirho| offender_chirho.contains(token_chirho)),
            "pricebook purity guard must catch {token_chirho}: {offenders_chirho:?}"
        );
    }
}

#[test]
fn ha2_billing_policy_purity_guard_catches_authority_tokens_chirho() {
    let text_chirho = r#"
        use cairn_chirho::app_chirho;
        use cairn_signer_chirho::signer_chirho;
        use cairn_writer_head_chirho::writer_head_chirho;
        fn bad_chirho(root_chirho: &Path) -> Result<()> {
            app_chirho::ensure_app_owner_chirho(root_chirho, "app", "owner/test")?;
            let _ = verified_app_owner_chirho(root_chirho, "app")?;
            effect_chirho::sign_message_chirho(root_chirho, b"bad")?;
            ledger_chirho::post_entry_tagged_checked_unlocked_chirho(root_chirho, "memo", vec![], Default::default(), &[])?;
            settlement_chirho::record_payout_chirho(root_chirho, request_chirho)?;
            std::fs::read_to_string(path_chirho)?;
            std::env::var("BAD_CHIRHO")?;
            let _ = std::net::TcpStream::connect("127.0.0.1:9")?;
            let _ = SystemTime::now();
            cairn_durable_chirho::sync_parent_dir_chirho(path_chirho)?;
            seqlog_chirho::append_serialized_jsonl_chirho(path_chirho, |_| Ok(row_chirho))?;
            store_chirho::get_object_chirho(root_chirho, &hash_chirho)?;
            refs_chirho::commit_head_chirho(root_chirho, "billing/app", precondition_chirho, hash_chirho, "billing-policy")?;
            writer_head_chirho::with_head_commit_chirho(root_chirho, || Ok(()))?;
            let _ = signer_chirho::pubkey_hex_chirho(root_chirho)?;
            enforce_spend_caps_chirho(root_chirho, "app", "user", 1, &caps_chirho)?;
            let _ = subsidy_used_chirho(root_chirho, "app", "user", &hash_chirho)?;
            let _ = net_billing_spend_chirho(root_chirho, "app", Some("user"))?;
            load_billing_usage_chirho(root_chirho)?;
            load_billing_compensations_chirho(root_chirho)?;
            verify_billing_compensations_chirho(root_chirho)?;
            Ok(())
        }
    "#;
    let offenders_chirho = billing_policy_forbidden_source_sites_in_text_chirho(
        ECONOMIC_GOVERNANCE_BILLING_POLICY_CHIRHO,
        text_chirho,
    );
    for token_chirho in [
        "use cairn_chirho",
        "app_chirho::",
        "ensure_app_owner_chirho(",
        "verified_app_owner_chirho(",
        "cairn_signer_chirho",
        "cairn_writer_head_chirho",
        "effect_chirho::",
        "sign_message_chirho(",
        "ledger_chirho::",
        "settlement_chirho::",
        "std::fs",
        "std::env",
        "std::net",
        "SystemTime",
        "cairn_durable_chirho",
        "append_serialized_jsonl",
        "store_chirho::",
        "refs_chirho::",
        "commit_head_chirho(",
        "with_head_commit_chirho(",
        "pubkey_hex_chirho(",
        "enforce_spend_caps_chirho(",
        "subsidy_used_chirho(",
        "net_billing_spend_chirho(",
        "load_billing_usage_chirho(",
        "load_billing_compensations_chirho(",
        "verify_billing_compensations_chirho(",
    ] {
        assert!(
            offenders_chirho
                .iter()
                .any(|offender_chirho| offender_chirho.contains(token_chirho)),
            "billing purity guard must catch {token_chirho}: {offenders_chirho:?}"
        );
    }
}

#[test]
fn ha2_economic_governance_guards_are_active_and_functional_chirho() {
    let mock_cargo_text = r#"
[dependencies]
cairn-signer-chirho = { path = "../cairn-signer-chirho" }
"#;
    let forbidden_deps_chirho = [
        "cairn-chirho",
        "cairn_chirho",
        "cairn-signer-chirho",
        "cairn_signer_chirho",
        "cairn-seqlog-chirho",
        "cairn_seqlog_chirho",
        "cairn-writer-head-chirho",
        "cairn_writer_head_chirho",
        "cairn-store-chirho",
        "cairn_store_chirho",
    ];
    let matched_chirho = mock_cargo_text.lines().any(|line_chirho| {
        let trimmed_chirho = line_chirho.trim();
        forbidden_deps_chirho.iter().any(|dep_chirho| {
            trimmed_chirho.starts_with(&format!("{dep_chirho} ="))
                || trimmed_chirho.starts_with(&format!("\"{dep_chirho}\" ="))
        })
    });
    assert!(matched_chirho, "mock cargo dependency should be matched");

    let mock_source_text = r#"
    fn some_fn_chirho() {
        let _ = store_chirho::put_object_chirho();
    }
"#;
    let offenders_chirho =
        economic_governance_forbidden_source_sites_in_text_chirho("mock_file.rs", mock_source_text);
    assert!(
        !offenders_chirho.is_empty(),
        "mock source should contain forbidden tokens"
    );
    assert!(
        offenders_chirho[0].contains("store_chirho::"),
        "should find store_chirho:: in {:?}",
        offenders_chirho
    );
}
