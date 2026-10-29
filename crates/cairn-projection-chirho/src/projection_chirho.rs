// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Deterministic Gate 1 projection skeleton over JSONL log bytes plus CAS byte rehash checks.

use anyhow::{anyhow, Context, Result};
use cairn_core_chirho::clsd_chirho::ProjectionStateChirho;
use cairn_core_chirho::model_chirho::HashChirho;
use std::fs;
use std::path::Path;

pub fn static_surface_manifest_chirho() -> &'static [&'static str] {
    &[
        "agent-authority-responses-chirho.jsonl",
        "agent-report-budgets-chirho.jsonl",
        "agent-report-charges-chirho.jsonl",
        "agent-reports-chirho.jsonl",
        "app-build-request-records-chirho.jsonl",
        "app-static-asset-records-chirho.jsonl",
        "client-owner-bindings-chirho.jsonl",
        "app-input-policy-records-chirho.jsonl",
        "app-request-access-policy-records-chirho.jsonl",
        "app-key-authority-chirho.jsonl",
        "app-params-records-chirho.jsonl",
        "app-records-chirho.jsonl",
        "app-response-policy-records-chirho.jsonl",
        "app-route-response-policy-records-chirho.jsonl",
        "app-route-records-chirho.jsonl",
        "billing-compensations-chirho.jsonl",
        "billing-policy-records-chirho.jsonl",
        "billing-usage-chirho.jsonl",
        "capability-grants-chirho.jsonl",
        "compensation-executions-chirho.jsonl",
        "compensations-chirho.jsonl",
        "compliance-evidence-chirho.jsonl",
        "connect-accounts-chirho.jsonl",
        "credit-holds-chirho.jsonl",
        "crm-connectors-chirho.jsonl",
        "crm-email-deliveries-chirho.jsonl",
        "crm-customers-chirho.jsonl",
        "crm-interactions-chirho.jsonl",
        "crm-read-models-chirho.jsonl",
        "data-residency-attestations-chirho.jsonl",
        "data-residency-policies-chirho.jsonl",
        "dns-applies-chirho.jsonl",
        "dns-zones-chirho.jsonl",
        "domain-bindings-chirho.jsonl",
        "external-usage-chirho.jsonl",
        "feedback-chirho.jsonl",
        "feedback-policy-records-chirho.jsonl",
        "feedback-retention-records-chirho.jsonl",
        "gate1-log-anchors-chirho.jsonl",
        "identities-chirho.jsonl",
        "identity-auth-attempts-chirho.jsonl",
        "identity-session-revocations-chirho.jsonl",
        "identity-sessions-chirho.jsonl",
        "knowledge-answers-chirho.jsonl",
        "knowledge-records-chirho.jsonl",
        "ledger-chirho.jsonl",
        "legal-hold-records-chirho.jsonl",
        "mailbox-applies-chirho.jsonl",
        "mailboxes-chirho.jsonl",
        "manual-remediations-chirho.jsonl",
        "native-stateless-attestations-chirho.jsonl",
        "news-center-records-chirho.jsonl",
        "node-capacity-attestations-chirho.jsonl",
        "node-lifecycle-transitions-chirho.jsonl",
        "node-usage-measurements-chirho.jsonl",
        "topology-plan-index-chirho.jsonl",
        "infrastructure-budget-events-chirho.jsonl",
        "tenant-placement-records-chirho.jsonl",
        "tenant-root-move-stages-chirho.jsonl",
        "oauth-clients-chirho.jsonl",
        // K4's successor-only connection stores: declared here, so a move carries them with the root as it carries
        // the legacy oauth logs above and below.
        "oauth-connection-clients-chirho.jsonl",
        "connection-tokens-chirho.jsonl",
        "connection-token-uses-chirho.jsonl",
        "onboarding-records-chirho.jsonl",
        "payouts-chirho.jsonl",
        "pricebook-records-chirho.jsonl",
        "privacy-access-records-chirho.jsonl",
        "privacy-blob-records-chirho.jsonl",
        "private-dag-values-chirho.jsonl",
        "privacy-backup-key-policies-chirho.jsonl",
        "privacy-erasure-propagations-chirho.jsonl",
        "privacy-erasure-records-chirho.jsonl",
        "privacy-export-records-chirho.jsonl",
        "privacy-replica-targets-chirho.jsonl",
        "privacy-retention-records-chirho.jsonl",
        "provider-invoices-chirho.jsonl",
        "provider-price-records-chirho.jsonl",
        "realtime-epilogues-chirho.jsonl",
        "realtime-events-chirho.jsonl",
        "realtime-sessions-chirho.jsonl",
        "reconciliation-reports-chirho.jsonl",
        "reflog-chirho.jsonl",
        "resource-policy-records-chirho.jsonl",
        "resource-policy-unset-records-chirho.jsonl",
        "resource-usage-chirho.jsonl",
        "review-policy-envelopes-chirho.jsonl",
        "review-records-chirho.jsonl",
        "rollback-completions-chirho.jsonl",
        "rollback-events-chirho.jsonl",
        "run-intents-chirho.jsonl",
        "scoped-token-uses-chirho.jsonl",
        "scoped-tokens-chirho.jsonl",
        "statements-chirho.jsonl",
        "stripe-dispute-observations-chirho.jsonl",
        "stripe-payout-observations-chirho.jsonl",
        "stripe-topup-observations-chirho.jsonl",
        "template-app-deploy-records-chirho.jsonl",
        "template-registry-records-chirho.jsonl",
        "topology-grant-attestations-chirho.jsonl",
        "support-approval-decisions-chirho.jsonl",
        "support-approval-requests-chirho.jsonl",
        "support-approval-uses-chirho.jsonl",
        "support-content-access-chirho.jsonl",
        "support-delegation-uses-chirho.jsonl",
        "support-dogfood-records-chirho.jsonl",
        "support-thread-events-chirho.jsonl",
        "volatile-effects-chirho.jsonl",
    ]
}

/// Builds the byte-level Gate 1 live baseline directly from on-disk JSONL log bytes and
/// verifies all 64-hex values except declared non-CAS metadata names by reading the CAS files and
/// recomputing their BLAKE3 hashes.
///
/// This stays independent of typed recovery on purpose: typed-ingestion parity compares this
/// physical-byte baseline with `materialize_typed_recover_chirho` so the report cannot collapse
/// into a typed-vs-typed tautology. Current CAS dependency detection is a non-CAS denylist v0
/// extractor. The denylist shape is deliberate: a missed denylist name fails noisily as a
/// false-RED, while a missed allowlist name would fail silently as a false-GREEN.
pub fn materialize_live_byte_baseline_chirho(root_chirho: &Path) -> Result<ProjectionStateChirho> {
    let mut state_chirho = ProjectionStateChirho::default();

    for filename_chirho in static_surface_manifest_chirho() {
        let path_chirho = root_chirho.join(filename_chirho);
        if !path_chirho.exists() {
            continue;
        }

        let content_chirho = fs::read_to_string(&path_chirho)
            .with_context(|| format!("read manifest log file {}", path_chirho.display()))?;

        let mut line_idx_chirho = 0;
        for line_chirho in content_chirho.lines() {
            let trimmed_chirho = line_chirho.trim();
            if trimmed_chirho.is_empty() {
                continue;
            }

            // 1. Re-hash the raw log line itself
            let line_hash_chirho =
                HashChirho(blake3::hash(trimmed_chirho.as_bytes()).to_hex().to_string());

            // 2. Parse the line as JSON to locate and verify CAS hashes
            if let Ok(value_chirho) = serde_json::from_str::<serde_json::Value>(trimmed_chirho) {
                verify_cas_dependencies_in_value_chirho(
                    root_chirho,
                    filename_chirho,
                    line_idx_chirho,
                    &value_chirho,
                )?;
            }

            state_chirho.insert_chirho(
                *filename_chirho,
                line_idx_chirho.to_string(),
                line_hash_chirho,
            );

            line_idx_chirho += 1;
        }
    }

    Ok(state_chirho)
}

/// Compatibility wrapper for callers that already know `materialize_live_chirho`; the role is the
/// byte-level baseline, while typed recovery lives in `materialize_typed_recover_chirho`.
pub fn materialize_live_chirho(root_chirho: &Path) -> Result<ProjectionStateChirho> {
    materialize_live_byte_baseline_chirho(root_chirho)
}

pub(crate) fn verify_cas_dependencies_in_value_chirho(
    root_chirho: &Path,
    filename_chirho: &str,
    line_idx_chirho: usize,
    value_chirho: &serde_json::Value,
) -> Result<()> {
    let mut cas_hashes_chirho = Vec::new();
    collect_cas_hashes_recursive_chirho(value_chirho, &mut cas_hashes_chirho);

    for hash_ref_chirho in cas_hashes_chirho {
        let hex_chirho = &hash_ref_chirho.0;
        if hex_chirho.len() != 64 {
            continue;
        }
        cairn_core_chirho::cas_chirho::get_chirho(root_chirho, &hash_ref_chirho).map_err(|e| {
            anyhow!(
                "Missing or tampered CAS dependency {} referenced in {} line {}: {}",
                hex_chirho,
                filename_chirho,
                line_idx_chirho,
                e
            )
        })?;
    }

    Ok(())
}

fn collect_cas_hashes_recursive_chirho(
    val_chirho: &serde_json::Value,
    out_chirho: &mut Vec<HashChirho>,
) {
    collect_cas_hashes_for_field_chirho(false, val_chirho, out_chirho);
}

fn collect_cas_hashes_for_field_chirho(
    skip_non_cas_subtree_chirho: bool,
    val_chirho: &serde_json::Value,
    out_chirho: &mut Vec<HashChirho>,
) {
    if skip_non_cas_subtree_chirho {
        return;
    }

    match val_chirho {
        serde_json::Value::String(s_chirho) => {
            if hash_hex_string_chirho(s_chirho) {
                out_chirho.push(HashChirho(s_chirho.to_ascii_lowercase()));
            }
        }
        serde_json::Value::Array(arr_chirho) => {
            for item_chirho in arr_chirho {
                collect_cas_hashes_for_field_chirho(false, item_chirho, out_chirho);
            }
        }
        serde_json::Value::Object(map_chirho) => {
            let private_request_hash_only_chirho =
                object_field_non_null_chirho(map_chirho, "request_private_subject_chirho");
            for (child_field_chirho, val_chirho) in map_chirho {
                let skip_child_chirho = non_cas_hash_metadata_field_chirho(child_field_chirho)
                    || (private_request_hash_only_chirho && child_field_chirho == "request_chirho");
                collect_cas_hashes_for_field_chirho(skip_child_chirho, val_chirho, out_chirho);
            }
        }
        _ => {}
    }
}

fn object_field_non_null_chirho(
    map_chirho: &serde_json::Map<String, serde_json::Value>,
    field_chirho: &str,
) -> bool {
    map_chirho
        .get(field_chirho)
        .is_some_and(|value_chirho| !value_chirho.is_null())
}

fn hash_hex_string_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .chars()
            .all(|c_chirho| c_chirho.is_ascii_hexdigit())
}

fn non_cas_hash_metadata_field_chirho(field_chirho: &str) -> bool {
    // Keep this list alphabetized by exact field. Unknown 64-hex fields are CAS dependencies by
    // default so maintenance misses fail noisily instead of green-lighting missing CAS bytes.
    matches!(
        field_chirho,
        "app_hash_chirho"
            | "client_id_hash_chirho"
            | "idem_key_chirho"
            | "idempotency_context_hash_chirho"
            | "idempotency_key_chirho"
            | "key_id_chirho"
            | "mac_chirho"
            | "nonce_chirho"
            | "owner_principal_hash_chirho"
            | "prefix_digest_chirho"
            | "prev_anchor_hash_chirho"
            | "pubkey_chirho"
            | "registered_pubkey_chirho"
            | "related_run_ids_chirho"
            | "run_chirho"
            | "run_id_chirho"
            | "sig_chirho"
            | "state_digest_chirho"
            | "token_hash_chirho"
            | "user_principal_hash_chirho"
    ) || field_chirho.ends_with("_sig_chirho")
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_core_chirho::clsd_chirho::clsd_digest_chirho;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        let now_ms_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        std::env::temp_dir().join(format!("cairn-projection-test-{n_chirho}-{now_ms_chirho}"))
    }

    #[test]
    fn materialize_rebuilds_correctly_and_detects_tamper_and_truncation_chirho() {
        let root_chirho = tmp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();

        // 1. Create a dummy CAS file
        let cas_data_chirho = b"WASM manifest bytes";
        let cas_hash_chirho = blake3::hash(cas_data_chirho).to_hex().to_string();
        let shard_dir_chirho = &cas_hash_chirho[0..2];
        let shard_file_chirho = &cas_hash_chirho[2..];
        let cas_dir_path_chirho = root_chirho.join("objects-chirho").join(shard_dir_chirho);
        fs::create_dir_all(&cas_dir_path_chirho).unwrap();
        let cas_file_path_chirho = cas_dir_path_chirho.join(shard_file_chirho);
        fs::write(&cas_file_path_chirho, cas_data_chirho).unwrap();

        // 2. Create a log referencing the CAS hash
        let log_file_chirho = root_chirho.join("app-records-chirho.jsonl");
        let log_line_chirho = format!(
            "{{\"app_chirho\":\"test-app\",\"manifest_hash_chirho\":\"{}\"}}\n",
            cas_hash_chirho
        );
        fs::write(&log_file_chirho, &log_line_chirho).unwrap();

        // Materialization should succeed (GREEN)
        let first_projection_chirho = materialize_live_chirho(&root_chirho).unwrap();
        assert!(!first_projection_chirho.is_empty_chirho());

        // 3. Dropped CAS file test -> RED
        fs::remove_file(&cas_file_path_chirho).unwrap();
        assert!(materialize_live_chirho(&root_chirho).is_err());

        // Restore CAS file
        fs::write(&cas_file_path_chirho, cas_data_chirho).unwrap();
        assert!(materialize_live_chirho(&root_chirho).is_ok());

        // 4. Tampered CAS file test -> RED
        fs::write(&cas_file_path_chirho, b"Tampered manifest bytes").unwrap();
        assert!(materialize_live_chirho(&root_chirho).is_err());

        // Restore CAS file
        fs::write(&cas_file_path_chirho, cas_data_chirho).unwrap();
        assert!(materialize_live_chirho(&root_chirho).is_ok());

        // 5. Truncated Log file test -> RED (different digest)
        let truncated_log_file_chirho = root_chirho.join("app-records-chirho.jsonl");
        fs::write(&truncated_log_file_chirho, "").unwrap();
        let second_projection_chirho = materialize_live_chirho(&root_chirho).unwrap();
        assert_ne!(first_projection_chirho, second_projection_chirho);

        // 6. Dropped Log file test -> RED (different digest)
        fs::remove_file(&truncated_log_file_chirho).unwrap();
        let third_projection_chirho = materialize_live_chirho(&root_chirho).unwrap();
        assert_ne!(first_projection_chirho, third_projection_chirho);

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn materialize_ignores_hash_shaped_non_cas_metadata_chirho() {
        let root_chirho = tmp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();

        let pubkey_chirho = "a".repeat(64);
        let run_id_chirho = "b".repeat(64);
        let log_line_chirho = format!(
            "{{\"schema_chirho\":\"identity-test-v1-chirho\",\"pubkey_chirho\":\"{}\",\"billing_tags_chirho\":{{\"run_id_chirho\":\"{}\"}}}}\n",
            pubkey_chirho, run_id_chirho
        );
        fs::write(root_chirho.join("identities-chirho.jsonl"), log_line_chirho).unwrap();

        let projection_chirho = materialize_live_chirho(&root_chirho)
            .expect("hash-shaped pubkeys and run ids are not CAS dependencies");
        assert!(!projection_chirho.is_empty_chirho());

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn materialize_unknown_hash_fields_fail_closed_as_cas_dependencies_chirho() {
        let root_chirho = tmp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();

        let missing_manifest_chirho = "c".repeat(64);
        let log_line_chirho = format!(
            "{{\"app_chirho\":\"missing-manifest\",\"manifest_hash_chirho\":\"{}\"}}\n",
            missing_manifest_chirho
        );
        fs::write(
            root_chirho.join("app-records-chirho.jsonl"),
            log_line_chirho,
        )
        .unwrap();

        let error_chirho = materialize_live_chirho(&root_chirho).unwrap_err();
        assert!(
            format!("{error_chirho:#}").contains("Missing or tampered CAS dependency"),
            "unknown 64-hex fields must still fail closed by re-reading real CAS bytes"
        );

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn materialize_checks_real_private_blob_ciphertext_dependency_chirho() {
        let root_chirho = tmp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();

        let ciphertext_chirho =
            cairn_core_chirho::cas_chirho::add_chirho(&root_chirho, b"encrypted-private-bytes")
                .unwrap();
        let log_line_chirho = format!(
            "{{\"schema_chirho\":\"privacy-blob-record-v1-chirho\",\"seq_chirho\":0,\"subject_chirho\":\"subject/demo-chirho\",\"blob_chirho\":{{\"ciphertext_chirho\":\"{}\",\"key_id_chirho\":\"key-id-chirho\",\"nonce_chirho\":\"nonce-chirho\",\"mac_chirho\":\"{}\",\"alg_chirho\":\"xchacha20poly1305+blake3-keyed-mac/v1\"}},\"bytes_chirho\":23,\"at_ms_chirho\":1,\"sig_chirho\":\"{}\"}}\n",
            ciphertext_chirho.0,
            "d".repeat(64),
            "e".repeat(128)
        );
        fs::write(
            root_chirho.join("privacy-blob-records-chirho.jsonl"),
            log_line_chirho,
        )
        .unwrap();

        materialize_live_chirho(&root_chirho)
            .expect("real privacy-blob ciphertext CAS dependency should materialize when present");

        fs::remove_file(
            root_chirho
                .join("objects-chirho")
                .join(&ciphertext_chirho.0[0..2])
                .join(&ciphertext_chirho.0[2..]),
        )
        .unwrap();
        let error_chirho = materialize_live_chirho(&root_chirho).unwrap_err();
        assert!(
            format!("{error_chirho:#}").contains("Missing or tampered CAS dependency"),
            "missing private ciphertext CAS bytes must fail RED"
        );

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn materialize_private_run_intent_request_hash_only_is_non_cas_chirho() {
        let root_chirho = tmp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();

        let request_hash_only_chirho = "f".repeat(64);
        let log_line_chirho = format!(
            "{{\"schema_chirho\":\"run-intent-record-v1-chirho\",\"request_chirho\":\"{}\",\"request_private_subject_chirho\":\"subject/private-chirho\"}}\n",
            request_hash_only_chirho
        );
        fs::write(
            root_chirho.join("run-intents-chirho.jsonl"),
            log_line_chirho,
        )
        .unwrap();

        let projection_chirho = materialize_live_chirho(&root_chirho)
            .expect("private-input run-intent request_chirho is hash-only, not stored CAS");
        assert!(!projection_chirho.is_empty_chirho());

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn generate_fixtures_chirho() {
        if std::env::var("CAIRN_GENERATE_FIXTURES_CHIRHO").is_err() {
            return;
        }

        let fixtures_dir_chirho = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures_chirho");
        let _ = fs::remove_dir_all(&fixtures_dir_chirho);

        let cas_a_content_chirho = b"manifest-a-content";
        let cas_a_hash_chirho = blake3::hash(cas_a_content_chirho).to_hex().to_string();
        let cas_b_content_chirho = b"manifest-b-content";
        let cas_b_hash_chirho = blake3::hash(cas_b_content_chirho).to_hex().to_string();

        let line_0_chirho = format!(
            "{{\"app_chirho\":\"app-a\",\"manifest_hash_chirho\":\"{}\"}}\n",
            cas_a_hash_chirho
        );
        let line_1_chirho = format!(
            "{{\"app_chirho\":\"app-b\",\"manifest_hash_chirho\":\"{}\"}}\n",
            cas_b_hash_chirho
        );

        // 1. green_root_chirho
        let green_dir_chirho = fixtures_dir_chirho.join("green_root_chirho");
        fs::create_dir_all(
            green_dir_chirho
                .join("objects-chirho")
                .join(&cas_a_hash_chirho[0..2]),
        )
        .unwrap();
        fs::create_dir_all(
            green_dir_chirho
                .join("objects-chirho")
                .join(&cas_b_hash_chirho[0..2]),
        )
        .unwrap();
        fs::write(
            green_dir_chirho
                .join("objects-chirho")
                .join(&cas_a_hash_chirho[0..2])
                .join(&cas_a_hash_chirho[2..]),
            cas_a_content_chirho,
        )
        .unwrap();
        fs::write(
            green_dir_chirho
                .join("objects-chirho")
                .join(&cas_b_hash_chirho[0..2])
                .join(&cas_b_hash_chirho[2..]),
            cas_b_content_chirho,
        )
        .unwrap();
        fs::write(
            green_dir_chirho.join("app-records-chirho.jsonl"),
            format!("{}{}", line_0_chirho, line_1_chirho),
        )
        .unwrap();

        // 2. red_truncated_root_chirho
        let trunc_dir_chirho = fixtures_dir_chirho.join("red_truncated_root_chirho");
        fs::create_dir_all(
            trunc_dir_chirho
                .join("objects-chirho")
                .join(&cas_a_hash_chirho[0..2]),
        )
        .unwrap();
        fs::create_dir_all(
            trunc_dir_chirho
                .join("objects-chirho")
                .join(&cas_b_hash_chirho[0..2]),
        )
        .unwrap();
        fs::write(
            trunc_dir_chirho
                .join("objects-chirho")
                .join(&cas_a_hash_chirho[0..2])
                .join(&cas_a_hash_chirho[2..]),
            cas_a_content_chirho,
        )
        .unwrap();
        fs::write(
            trunc_dir_chirho
                .join("objects-chirho")
                .join(&cas_b_hash_chirho[0..2])
                .join(&cas_b_hash_chirho[2..]),
            cas_b_content_chirho,
        )
        .unwrap();
        fs::write(
            trunc_dir_chirho.join("app-records-chirho.jsonl"),
            line_0_chirho.clone(),
        )
        .unwrap();

        // 3. red_dropped_manifest_root_chirho
        let drop_dir_chirho = fixtures_dir_chirho.join("red_dropped_manifest_root_chirho");
        fs::create_dir_all(
            drop_dir_chirho
                .join("objects-chirho")
                .join(&cas_a_hash_chirho[0..2]),
        )
        .unwrap();
        fs::write(
            drop_dir_chirho
                .join("objects-chirho")
                .join(&cas_a_hash_chirho[0..2])
                .join(&cas_a_hash_chirho[2..]),
            cas_a_content_chirho,
        )
        .unwrap();
        fs::write(
            drop_dir_chirho.join("app-records-chirho.jsonl"),
            format!("{}{}", line_0_chirho, line_1_chirho),
        )
        .unwrap();

        // 4. red_tampered_cas_root_chirho
        let tamper_dir_chirho = fixtures_dir_chirho.join("red_tampered_cas_root_chirho");
        fs::create_dir_all(
            tamper_dir_chirho
                .join("objects-chirho")
                .join(&cas_a_hash_chirho[0..2]),
        )
        .unwrap();
        fs::create_dir_all(
            tamper_dir_chirho
                .join("objects-chirho")
                .join(&cas_b_hash_chirho[0..2]),
        )
        .unwrap();
        fs::write(
            tamper_dir_chirho
                .join("objects-chirho")
                .join(&cas_a_hash_chirho[0..2])
                .join(&cas_a_hash_chirho[2..]),
            cas_a_content_chirho,
        )
        .unwrap();
        fs::write(
            tamper_dir_chirho
                .join("objects-chirho")
                .join(&cas_b_hash_chirho[0..2])
                .join(&cas_b_hash_chirho[2..]),
            b"tampered content for B",
        )
        .unwrap();
        fs::write(
            tamper_dir_chirho.join("app-records-chirho.jsonl"),
            format!("{}{}", line_0_chirho, line_1_chirho),
        )
        .unwrap();

        println!("Fixtures generated successfully!");
    }

    #[test]
    fn assert_checked_in_fixtures_behave_as_expected_chirho() {
        let fixtures_dir_chirho = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures_chirho");

        let green_root_chirho = fixtures_dir_chirho.join("green_root_chirho");
        let trunc_root_chirho = fixtures_dir_chirho.join("red_truncated_root_chirho");
        let drop_root_chirho = fixtures_dir_chirho.join("red_dropped_manifest_root_chirho");
        let tamper_root_chirho = fixtures_dir_chirho.join("red_tampered_cas_root_chirho");

        // Verify the green fixture compiles/succeeds
        let green_proj_chirho = materialize_live_chirho(&green_root_chirho)
            .expect("green fixture must materialize successfully");
        assert!(!green_proj_chirho.is_empty_chirho());
        assert_eq!(
            clsd_digest_chirho(&green_proj_chirho).0,
            "d485d701c2847593a0a516fa04f17517b1a6e6eba5001f12ea0306cebd94468a",
            "green fixture CLSD digest must stay pinned so log-side fixture tests cannot pass with content-blind materialization"
        );

        // Verify the truncated fixture generates a DIFFERENT digest (reconciliation goes RED)
        let trunc_proj_chirho = materialize_live_chirho(&trunc_root_chirho).expect(
            "truncated fixture must still materialize successfully (but with different result)",
        );
        assert_ne!(green_proj_chirho, trunc_proj_chirho);

        // Verify the dropped manifest fixture fails (RED)
        let drop_result_chirho = materialize_live_chirho(&drop_root_chirho);
        assert!(
            drop_result_chirho.is_err(),
            "dropped manifest fixture must fail materialize"
        );

        // Verify the tampered CAS fixture fails (RED)
        let tamper_result_chirho = materialize_live_chirho(&tamper_root_chirho);
        assert!(
            tamper_result_chirho.is_err(),
            "tampered CAS fixture must fail materialize"
        );
    }
}
