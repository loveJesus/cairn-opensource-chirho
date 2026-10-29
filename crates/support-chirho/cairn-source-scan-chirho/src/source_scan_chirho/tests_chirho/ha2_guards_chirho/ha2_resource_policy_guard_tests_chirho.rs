// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

const ECONOMIC_GOVERNANCE_RESOURCE_POLICY_CHIRHO: &str =
    "crates/services-chirho/cairn-economic-governance-chirho/src/resource_policy_chirho.rs";

const RESOURCE_POLICY_FORBIDDEN_SOURCE_TOKENS_CHIRHO: &[&str] = &[
    "cairn_chirho::",
    "use cairn_chirho",
    "app_chirho::",
    "ensure_app_owner_chirho(",
    "verified_app_owner_chirho(",
    "identity_chirho::",
    "find_identity_chirho(",
    "effect_chirho::",
    "ledger_chirho::",
    "paid_chirho::",
    "settlement_chirho::",
    "head_removal_chirho::",
    "std::env",
    "std::fs",
    "std::net",
    "std::time",
    "SystemTime",
    "Instant",
    "UNIX_EPOCH",
    "cairn_durable_chirho",
    "cairn_seqlog_chirho",
    "append_serialized_jsonl",
    "append_recovered_jsonl",
    "cairn_writer_head_chirho",
    "with_head_commit_chirho(",
    "refs_chirho::",
    "commit_head_chirho(",
    "set_branch_chirho(",
    "remove_branch_chirho(",
    "store_chirho::",
    "put_object_chirho(",
    "get_object_chirho(",
    "run_intent_chirho::",
    "invoke_priced_with_run_chirho(",
    "run_authorized_explicit_paid_effect_chirho(",
    "sign_message_chirho(",
    "pubkey_hex_chirho(",
    "verify_with_pubkey_chirho(",
    "cairn_signer_chirho",
    "load_resource_policy_records_chirho(",
    "load_resource_usage_chirho(",
    "load_resource_policy_unset_records_chirho(",
    "verify_resource_policies_chirho(",
    "verify_resource_usage_chirho(",
    "validate_resource_bridges_chirho(",
    "validate_billing_bridge_chirho(",
    "validate_external_bridge_chirho(",
    "post_entry_tagged_checked_unlocked_chirho(",
    "load_or_create_signing_key_chirho(",
];

fn resource_policy_forbidden_source_sites_in_text_chirho(
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
        for token_chirho in RESOURCE_POLICY_FORBIDDEN_SOURCE_TOKENS_CHIRHO {
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

fn resource_policy_forbidden_source_sites_chirho() -> Vec<String> {
    let path_chirho = workspace_root_chirho().join(ECONOMIC_GOVERNANCE_RESOURCE_POLICY_CHIRHO);
    let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    resource_policy_forbidden_source_sites_in_text_chirho(
        ECONOMIC_GOVERNANCE_RESOURCE_POLICY_CHIRHO,
        &text_chirho,
    )
}

#[test]
fn ha2_resource_policy_stays_pure_computation_chirho() {
    let offenders_chirho = resource_policy_forbidden_source_sites_chirho();
    assert!(
        offenders_chirho.is_empty(),
        "resource policy must stay pure policy/decision code; root keeps app authz, bridge evidence, signatures, seqlogs, store writes, refs, head-removal, and accounting choke points:\n{}",
        offenders_chirho.join("\n")
    );
}

#[test]
fn ha2_resource_policy_purity_guard_catches_authority_tokens_chirho() {
    let text_chirho = r#"
        use cairn_chirho::resource_chirho;
        use cairn_signer_chirho::signer_chirho;
        use cairn_writer_head_chirho::writer_head_chirho;
        fn bad_chirho(root_chirho: &Path) -> Result<()> {
            app_chirho::ensure_app_owner_chirho(root_chirho, "app", "owner/test")?;
            identity_chirho::find_identity_chirho(root_chirho, "user/test")?;
            effect_chirho::sign_message_chirho(root_chirho, b"bad")?;
            ledger_chirho::post_entry_tagged_checked_unlocked_chirho(root_chirho, "memo", vec![], Default::default(), &[])?;
            settlement_chirho::record_payout_chirho(root_chirho, request_chirho)?;
            head_removal_chirho::remove_branch_after_evidence_chirho(root_chirho, evidence_chirho)?;
            std::fs::read_to_string(path_chirho)?;
            std::env::var("BAD_CHIRHO")?;
            let _ = std::net::TcpStream::connect("127.0.0.1:9")?;
            let _ = SystemTime::now().duration_since(UNIX_EPOCH)?;
            let _ = std::time::Duration::from_secs(1);
            let _ = Instant::now();
            cairn_durable_chirho::sync_parent_dir_chirho(path_chirho)?;
            seqlog_chirho::append_serialized_jsonl_chirho(path_chirho, |_| Ok(row_chirho))?;
            store_chirho::put_object_chirho(root_chirho, &row_chirho)?;
            refs_chirho::commit_head_chirho(root_chirho, "resource-policy/app", precondition_chirho, hash_chirho, "resource-policy")?;
            refs_chirho::remove_branch_chirho(root_chirho, "resource-policy/app")?;
            writer_head_chirho::with_head_commit_chirho(root_chirho, || Ok(()))?;
            let _ = signer_chirho::pubkey_hex_chirho(root_chirho)?;
            load_resource_policy_records_chirho(root_chirho)?;
            load_resource_usage_chirho(root_chirho)?;
            verify_resource_usage_chirho(root_chirho)?;
            validate_resource_bridges_chirho(root_chirho)?;
            Ok(())
        }
    "#;
    let offenders_chirho = resource_policy_forbidden_source_sites_in_text_chirho(
        ECONOMIC_GOVERNANCE_RESOURCE_POLICY_CHIRHO,
        text_chirho,
    );
    for token_chirho in [
        "use cairn_chirho",
        "app_chirho::",
        "ensure_app_owner_chirho(",
        "identity_chirho::",
        "find_identity_chirho(",
        "cairn_signer_chirho",
        "cairn_writer_head_chirho",
        "effect_chirho::",
        "sign_message_chirho(",
        "ledger_chirho::",
        "post_entry_tagged_checked_unlocked_chirho(",
        "settlement_chirho::",
        "head_removal_chirho::",
        "std::fs",
        "std::env",
        "std::net",
        "std::time",
        "SystemTime",
        "Instant",
        "UNIX_EPOCH",
        "cairn_durable_chirho",
        "append_serialized_jsonl",
        "store_chirho::",
        "refs_chirho::",
        "commit_head_chirho(",
        "remove_branch_chirho(",
        "with_head_commit_chirho(",
        "pubkey_hex_chirho(",
        "load_resource_policy_records_chirho(",
        "load_resource_usage_chirho(",
        "verify_resource_usage_chirho(",
        "validate_resource_bridges_chirho(",
    ] {
        assert!(
            offenders_chirho
                .iter()
                .any(|offender_chirho| offender_chirho.contains(token_chirho)),
            "resource purity guard must catch {token_chirho}: {offenders_chirho:?}"
        );
    }
}
