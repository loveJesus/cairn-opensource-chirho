// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Signed capability grants can only delegate strictly narrower authority.

use crate::model_chirho::{CapabilityChirho, HashChirho};
use crate::{cas_chirho, seqlog_chirho, tenant_chirho};
use anyhow::{bail, Context, Result};
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const CAPABILITY_GRANT_RECORD_SCHEMA_CHIRHO: &str = "capability-grant-record-v1-chirho";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityLimitsChirho {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms_chirho: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_invokes_chirho: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_token_chirho: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrantRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub grant_id_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_grant_id_chirho: Option<String>,
    pub grantor_chirho: String,
    pub grantee_chirho: String,
    pub capability_chirho: CapabilityChirho,
    pub limits_chirho: CapabilityLimitsChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

fn grants_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("capability-grants-chirho.jsonl")
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

pub fn issue_root_grant_chirho(
    root_chirho: &Path,
    grantor_chirho: &str,
    grantee_chirho: &str,
    capability_chirho: CapabilityChirho,
    limits_chirho: CapabilityLimitsChirho,
) -> Result<CapabilityGrantRecordChirho> {
    validate_actor_chirho("grantor_chirho", grantor_chirho)?;
    validate_actor_chirho("grantee_chirho", grantee_chirho)?;
    validate_grant_capability_chirho(root_chirho, &capability_chirho)?;
    let path_chirho = grants_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        sign_grant_chirho(
            root_chirho,
            CapabilityGrantRecordChirho {
                seq_chirho,
                schema_chirho: CAPABILITY_GRANT_RECORD_SCHEMA_CHIRHO.to_string(),
                grant_id_chirho: String::new(),
                parent_grant_id_chirho: None,
                grantor_chirho: grantor_chirho.to_string(),
                grantee_chirho: grantee_chirho.to_string(),
                capability_chirho: capability_chirho.clone(),
                limits_chirho: limits_chirho.clone(),
                at_ms_chirho: now_ms_chirho(),
                sig_chirho: String::new(),
            },
        )
    })
}

pub fn delegate_grant_chirho(
    root_chirho: &Path,
    parent_grant_id_chirho: &str,
    delegator_chirho: &str,
    grantee_chirho: &str,
    capability_chirho: CapabilityChirho,
    limits_chirho: CapabilityLimitsChirho,
) -> Result<CapabilityGrantRecordChirho> {
    validate_actor_chirho("delegator_chirho", delegator_chirho)?;
    validate_actor_chirho("grantee_chirho", grantee_chirho)?;
    validate_grant_capability_chirho(root_chirho, &capability_chirho)?;
    let path_chirho = grants_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        let grants_chirho = load_grants_chirho(root_chirho)?;
        let parent_chirho = grants_chirho
            .iter()
            .find(|grant_chirho| grant_chirho.grant_id_chirho == parent_grant_id_chirho)
            .ok_or_else(|| anyhow::anyhow!("parent capability grant not found"))?;
        if parent_chirho.grantee_chirho != delegator_chirho {
            bail!(
                "delegator '{}' is not parent grant grantee '{}'",
                delegator_chirho,
                parent_chirho.grantee_chirho
            );
        }
        require_strictly_narrower_chirho(
            &parent_chirho.capability_chirho,
            &parent_chirho.limits_chirho,
            &capability_chirho,
            &limits_chirho,
        )?;
        sign_grant_chirho(
            root_chirho,
            CapabilityGrantRecordChirho {
                seq_chirho,
                schema_chirho: CAPABILITY_GRANT_RECORD_SCHEMA_CHIRHO.to_string(),
                grant_id_chirho: String::new(),
                parent_grant_id_chirho: Some(parent_grant_id_chirho.to_string()),
                grantor_chirho: delegator_chirho.to_string(),
                grantee_chirho: grantee_chirho.to_string(),
                capability_chirho: capability_chirho.clone(),
                limits_chirho: limits_chirho.clone(),
                at_ms_chirho: now_ms_chirho(),
                sig_chirho: String::new(),
            },
        )
    })
}

pub fn load_grants_chirho(root_chirho: &Path) -> Result<Vec<CapabilityGrantRecordChirho>> {
    let path_chirho = grants_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let mut out_chirho = Vec::new();
    for line_chirho in std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?
        .lines()
    {
        let line_chirho = line_chirho.trim();
        if line_chirho.is_empty() {
            continue;
        }
        out_chirho.push(serde_json::from_str(line_chirho)?);
    }
    Ok(out_chirho)
}

pub fn verify_grants_chirho(root_chirho: &Path) -> Result<usize> {
    let grants_chirho = load_grants_chirho(root_chirho)?;
    if grants_chirho.is_empty() {
        return Ok(0);
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let mut by_id_chirho: BTreeMap<String, CapabilityGrantRecordChirho> = BTreeMap::new();
    for (i_chirho, grant_chirho) in grants_chirho.iter().enumerate() {
        verify_grant_schema_chirho(grant_chirho)?;
        if grant_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "capability grant seq gap at index {}: entry seq is {}",
                i_chirho,
                grant_chirho.seq_chirho
            );
        }
        validate_grant_capability_chirho(root_chirho, &grant_chirho.capability_chirho)?;
        let expected_id_chirho = grant_id_chirho(grant_chirho)?;
        if grant_chirho.grant_id_chirho != expected_id_chirho.0 {
            bail!("capability grant {} id mismatch", grant_chirho.seq_chirho);
        }
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &grant_message_chirho(grant_chirho)?,
            &grant_chirho.sig_chirho,
        )? {
            bail!(
                "capability grant {} signature invalid",
                grant_chirho.seq_chirho
            );
        }
        if let Some(parent_id_chirho) = &grant_chirho.parent_grant_id_chirho {
            let parent_chirho = by_id_chirho.get(parent_id_chirho).ok_or_else(|| {
                anyhow::anyhow!(
                    "grant {} references missing parent",
                    grant_chirho.seq_chirho
                )
            })?;
            if parent_chirho.grantee_chirho != grant_chirho.grantor_chirho {
                bail!(
                    "grant {} grantor is not parent grantee",
                    grant_chirho.seq_chirho
                );
            }
            require_strictly_narrower_chirho(
                &parent_chirho.capability_chirho,
                &parent_chirho.limits_chirho,
                &grant_chirho.capability_chirho,
                &grant_chirho.limits_chirho,
            )?;
        }
        by_id_chirho.insert(grant_chirho.grant_id_chirho.clone(), grant_chirho.clone());
    }
    Ok(grants_chirho.len())
}

fn verify_grant_schema_chirho(record_chirho: &CapabilityGrantRecordChirho) -> Result<()> {
    if !record_chirho.schema_chirho.is_empty()
        && record_chirho.schema_chirho != CAPABILITY_GRANT_RECORD_SCHEMA_CHIRHO
    {
        bail!(
            "unsupported capability grant schema '{}'",
            record_chirho.schema_chirho
        );
    }
    Ok(())
}

pub fn require_strictly_narrower_chirho(
    parent_capability_chirho: &CapabilityChirho,
    parent_limits_chirho: &CapabilityLimitsChirho,
    child_capability_chirho: &CapabilityChirho,
    child_limits_chirho: &CapabilityLimitsChirho,
) -> Result<()> {
    let cap_strict_chirho =
        capability_is_subset_chirho(parent_capability_chirho, child_capability_chirho)?;
    let limits_strict_chirho = limits_are_subset_chirho(parent_limits_chirho, child_limits_chirho)?;
    if !cap_strict_chirho && !limits_strict_chirho {
        bail!("delegated capability must be strictly narrower than its parent");
    }
    Ok(())
}

fn capability_is_subset_chirho(
    parent_chirho: &CapabilityChirho,
    child_chirho: &CapabilityChirho,
) -> Result<bool> {
    match (parent_chirho, child_chirho) {
        (
            CapabilityChirho::ReadStoreChirho {
                prefix_chirho: parent_prefix_chirho,
            },
            CapabilityChirho::ReadStoreChirho {
                prefix_chirho: child_prefix_chirho,
            },
        ) => prefix_subset_chirho(parent_prefix_chirho, child_prefix_chirho),
        (
            CapabilityChirho::WriteStoreChirho {
                prefix_chirho: parent_prefix_chirho,
            },
            CapabilityChirho::WriteStoreChirho {
                prefix_chirho: child_prefix_chirho,
            },
        ) => prefix_subset_chirho(parent_prefix_chirho, child_prefix_chirho),
        (
            CapabilityChirho::NetChirho {
                allowlist_chirho: parent_chirho,
            },
            CapabilityChirho::NetChirho {
                allowlist_chirho: child_chirho,
            },
        ) => set_subset_chirho(parent_chirho, child_chirho),
        (
            CapabilityChirho::QueryChirho {
                prefix_chirho: parent_prefix_chirho,
                caller_chirho: parent_caller_chirho,
                max_rows_chirho: parent_max_rows_chirho,
            },
            CapabilityChirho::QueryChirho {
                prefix_chirho: child_prefix_chirho,
                caller_chirho: child_caller_chirho,
                max_rows_chirho: child_max_rows_chirho,
            },
        ) if parent_caller_chirho == child_caller_chirho => {
            let prefix_narrowed_chirho =
                prefix_subset_chirho(parent_prefix_chirho, child_prefix_chirho)?;
            if child_max_rows_chirho > parent_max_rows_chirho {
                bail!("delegated query max rows widens parent capability");
            }
            Ok(prefix_narrowed_chirho || child_max_rows_chirho < parent_max_rows_chirho)
        }
        (
            CapabilityChirho::PaidEffectChirho {
                effect_chirho: parent_effect_chirho,
                caller_chirho: parent_caller_chirho,
            },
            CapabilityChirho::PaidEffectChirho {
                effect_chirho: child_effect_chirho,
                caller_chirho: child_caller_chirho,
            },
        ) if parent_effect_chirho == child_effect_chirho
            && parent_caller_chirho == child_caller_chirho =>
        {
            Ok(false)
        }
        (
            CapabilityChirho::SecretRefChirho {
                name_chirho: parent_name_chirho,
            },
            CapabilityChirho::SecretRefChirho {
                name_chirho: child_name_chirho,
            },
        ) if parent_name_chirho == child_name_chirho => Ok(false),
        (
            CapabilityChirho::RealtimeSessionChirho {
                app_chirho: parent_app_chirho,
                caller_chirho: parent_caller_chirho,
            },
            CapabilityChirho::RealtimeSessionChirho {
                app_chirho: child_app_chirho,
                caller_chirho: child_caller_chirho,
            },
        ) if parent_app_chirho == child_app_chirho
            && parent_caller_chirho == child_caller_chirho =>
        {
            Ok(false)
        }
        (
            CapabilityChirho::SupportIssueChirho {
                issue_chirho: parent_issue_chirho,
                actions_chirho: parent_actions_chirho,
            },
            CapabilityChirho::SupportIssueChirho {
                issue_chirho: child_issue_chirho,
                actions_chirho: child_actions_chirho,
            },
        ) if parent_issue_chirho == child_issue_chirho => {
            set_subset_chirho(parent_actions_chirho, child_actions_chirho)
        }
        (
            CapabilityChirho::CausalReversionChirho {
                branch_chirho: parent_branch_chirho,
            },
            CapabilityChirho::CausalReversionChirho {
                branch_chirho: child_branch_chirho,
            },
        ) if parent_branch_chirho == child_branch_chirho => Ok(false),
        (CapabilityChirho::ClockChirho, CapabilityChirho::ClockChirho)
        | (CapabilityChirho::RandomChirho, CapabilityChirho::RandomChirho) => Ok(false),
        (
            CapabilityChirho::InvokeChirho {
                node_chirho: parent_node_chirho,
            },
            CapabilityChirho::InvokeChirho {
                node_chirho: child_node_chirho,
            },
        ) if parent_node_chirho == child_node_chirho => Ok(false),
        (
            CapabilityChirho::UserIdentityChirho {
                principal_chirho: parent_principal_chirho,
                client_id_chirho: parent_client_chirho,
                token_hash_chirho: parent_token_chirho,
            },
            CapabilityChirho::UserIdentityChirho {
                principal_chirho: child_principal_chirho,
                client_id_chirho: child_client_chirho,
                token_hash_chirho: child_token_chirho,
            },
        ) if parent_principal_chirho == child_principal_chirho
            && parent_client_chirho == child_client_chirho
            && parent_token_chirho == child_token_chirho =>
        {
            Ok(false)
        }
        _ => bail!("delegated capability changes or widens the parent capability type"),
    }
}

fn prefix_subset_chirho(parent_chirho: &str, child_chirho: &str) -> Result<bool> {
    if parent_chirho.is_empty() {
        return Ok(!child_chirho.is_empty());
    }
    if child_chirho == parent_chirho {
        return Ok(false);
    }
    if child_chirho
        .strip_prefix(parent_chirho)
        .is_some_and(|rest_chirho| rest_chirho.starts_with('/'))
    {
        return Ok(true);
    }
    bail!("delegated store prefix is wider than parent prefix");
}

fn set_subset_chirho(parent_chirho: &[String], child_chirho: &[String]) -> Result<bool> {
    let parent_chirho: BTreeSet<&String> = parent_chirho.iter().collect();
    let child_chirho: BTreeSet<&String> = child_chirho.iter().collect();
    if child_chirho.is_subset(&parent_chirho) {
        Ok(child_chirho.len() < parent_chirho.len())
    } else {
        bail!("delegated set is not a subset of parent set");
    }
}

fn limits_are_subset_chirho(
    parent_chirho: &CapabilityLimitsChirho,
    child_chirho: &CapabilityLimitsChirho,
) -> Result<bool> {
    let mut strict_chirho = false;
    strict_chirho |= option_u64_narrows_chirho(
        parent_chirho.expires_at_ms_chirho,
        child_chirho.expires_at_ms_chirho,
        "expires_at_ms_chirho",
    )?;
    strict_chirho |= option_u64_narrows_chirho(
        parent_chirho.max_invokes_chirho,
        child_chirho.max_invokes_chirho,
        "max_invokes_chirho",
    )?;
    strict_chirho |= option_i64_narrows_chirho(
        parent_chirho.budget_token_chirho,
        child_chirho.budget_token_chirho,
        "budget_token_chirho",
    )?;
    Ok(strict_chirho)
}

fn option_u64_narrows_chirho(
    parent_chirho: Option<u64>,
    child_chirho: Option<u64>,
    name_chirho: &str,
) -> Result<bool> {
    match (parent_chirho, child_chirho) {
        (None, None) => Ok(false),
        (None, Some(_)) => Ok(true),
        (Some(_), None) => bail!("delegated {name_chirho} removes parent limit"),
        (Some(parent_chirho), Some(child_chirho)) if child_chirho <= parent_chirho => {
            Ok(child_chirho < parent_chirho)
        }
        (Some(_), Some(_)) => bail!("delegated {name_chirho} widens parent limit"),
    }
}

fn option_i64_narrows_chirho(
    parent_chirho: Option<i64>,
    child_chirho: Option<i64>,
    name_chirho: &str,
) -> Result<bool> {
    match (parent_chirho, child_chirho) {
        (None, None) => Ok(false),
        (None, Some(child_chirho)) if child_chirho >= 0 => Ok(true),
        (None, Some(_)) => bail!("delegated {name_chirho} must be nonnegative"),
        (Some(_), None) => bail!("delegated {name_chirho} removes parent limit"),
        (Some(parent_chirho), Some(child_chirho))
            if child_chirho >= 0 && child_chirho <= parent_chirho =>
        {
            Ok(child_chirho < parent_chirho)
        }
        (Some(_), Some(_)) => bail!("delegated {name_chirho} widens parent limit"),
    }
}

fn sign_grant_chirho(
    root_chirho: &Path,
    mut record_chirho: CapabilityGrantRecordChirho,
) -> Result<CapabilityGrantRecordChirho> {
    record_chirho.grant_id_chirho = grant_id_chirho(&record_chirho)?.0;
    record_chirho.sig_chirho =
        signer_chirho::sign_message_chirho(root_chirho, &grant_message_chirho(&record_chirho)?)?;
    Ok(record_chirho)
}

fn grant_id_chirho(record_chirho: &CapabilityGrantRecordChirho) -> Result<HashChirho> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.grant_id_chirho.clear();
    signed_chirho.sig_chirho.clear();
    Ok(cas_chirho::hash_chirho(&serde_json::to_vec(
        &signed_chirho,
    )?))
}

fn grant_message_chirho(record_chirho: &CapabilityGrantRecordChirho) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

fn validate_actor_chirho(name_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.trim().is_empty() || value_chirho.chars().any(char::is_whitespace) {
        bail!("{name_chirho} must be nonempty and contain no whitespace");
    }
    Ok(())
}

fn validate_grant_capability_chirho(
    root_chirho: &Path,
    capability_chirho: &CapabilityChirho,
) -> Result<()> {
    if let CapabilityChirho::SupportIssueChirho {
        issue_chirho,
        actions_chirho,
    } = capability_chirho
    {
        validate_support_issue_capability_chirho(issue_chirho, actions_chirho)?;
    }
    if let CapabilityChirho::CausalReversionChirho { branch_chirho } = capability_chirho {
        validate_branch_capability_chirho(branch_chirho)?;
    }
    tenant_chirho::assert_capability_tenant_chirho(root_chirho, capability_chirho)
}

fn validate_branch_capability_chirho(branch_chirho: &str) -> Result<()> {
    if branch_chirho.trim().is_empty()
        || branch_chirho.chars().any(char::is_whitespace)
        || branch_chirho.starts_with('/')
        || branch_chirho.contains('\\')
        || branch_chirho
            .split('/')
            .any(|part_chirho| part_chirho.is_empty() || part_chirho == "." || part_chirho == "..")
    {
        bail!("causal reversion branch_chirho is invalid");
    }
    Ok(())
}

fn validate_support_issue_capability_chirho(
    issue_chirho: &str,
    actions_chirho: &[String],
) -> Result<()> {
    if issue_chirho.trim().is_empty()
        || !issue_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_alphanumeric() || matches!(byte_chirho, b'-' | b'_')
        })
    {
        bail!("support issue capability issue_chirho is invalid");
    }
    if actions_chirho.is_empty() {
        bail!("support issue capability actions_chirho is required");
    }
    let mut seen_chirho = BTreeSet::new();
    for action_chirho in actions_chirho {
        if action_chirho.trim().is_empty() || action_chirho.chars().any(char::is_whitespace) {
            bail!("support issue capability action is invalid");
        }
        if !seen_chirho.insert(action_chirho) {
            bail!("support issue capability actions_chirho must be unique");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use serde::Serialize;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!(
            "cairn-attenuation-test-{n_chirho}-{}",
            now_ms_chirho()
        ))
    }

    fn write_jsonl_chirho<T: Serialize>(path_chirho: &Path, records_chirho: &[T]) {
        if let Some(parent_chirho) = path_chirho.parent() {
            std::fs::create_dir_all(parent_chirho).unwrap();
        }
        let mut out_chirho = String::new();
        for record_chirho in records_chirho {
            out_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
            out_chirho.push('\n');
        }
        std::fs::write(path_chirho, out_chirho).unwrap();
    }

    fn resign_grant_for_test_chirho(
        root_chirho: &Path,
        mut record_chirho: CapabilityGrantRecordChirho,
    ) -> CapabilityGrantRecordChirho {
        record_chirho.grant_id_chirho.clear();
        record_chirho.sig_chirho.clear();
        record_chirho.grant_id_chirho = grant_id_chirho(&record_chirho).unwrap().0;
        record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            root_chirho,
            &grant_message_chirho(&record_chirho).unwrap(),
        )
        .unwrap();
        record_chirho
    }

    #[test]
    fn delegation_allows_strict_prefix_and_limit_narrowing_chirho() {
        let root_chirho = tmp_root_chirho();
        let parent_chirho = issue_root_grant_chirho(
            &root_chirho,
            "admin",
            "agent-a",
            CapabilityChirho::ReadStoreChirho {
                prefix_chirho: "thread".to_string(),
            },
            CapabilityLimitsChirho::default(),
        )
        .unwrap();
        let child_chirho = delegate_grant_chirho(
            &root_chirho,
            &parent_chirho.grant_id_chirho,
            "agent-a",
            "agent-b",
            CapabilityChirho::ReadStoreChirho {
                prefix_chirho: "thread/123".to_string(),
            },
            CapabilityLimitsChirho {
                expires_at_ms_chirho: Some(now_ms_chirho() + 3_600_000),
                max_invokes_chirho: Some(5),
                budget_token_chirho: Some(500),
            },
        )
        .unwrap();
        assert_eq!(
            child_chirho.parent_grant_id_chirho.as_deref(),
            Some(parent_chirho.grant_id_chirho.as_str())
        );
        assert_eq!(verify_grants_chirho(&root_chirho).unwrap(), 2);
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn capability_grants_are_schema_tagged_and_unknown_schemas_fail_chirho() {
        let root_chirho = tmp_root_chirho();
        let parent_chirho = issue_root_grant_chirho(
            &root_chirho,
            "admin",
            "agent-a",
            CapabilityChirho::ReadStoreChirho {
                prefix_chirho: "thread".to_string(),
            },
            CapabilityLimitsChirho::default(),
        )
        .unwrap();
        let child_chirho = delegate_grant_chirho(
            &root_chirho,
            &parent_chirho.grant_id_chirho,
            "agent-a",
            "agent-b",
            CapabilityChirho::ReadStoreChirho {
                prefix_chirho: "thread/123".to_string(),
            },
            CapabilityLimitsChirho {
                expires_at_ms_chirho: Some(now_ms_chirho() + 3_600_000),
                max_invokes_chirho: Some(5),
                budget_token_chirho: None,
            },
        )
        .unwrap();
        assert_eq!(
            parent_chirho.schema_chirho,
            CAPABILITY_GRANT_RECORD_SCHEMA_CHIRHO
        );
        assert_eq!(
            child_chirho.schema_chirho,
            CAPABILITY_GRANT_RECORD_SCHEMA_CHIRHO
        );
        assert_eq!(verify_grants_chirho(&root_chirho).unwrap(), 2);

        let mut bad_schema_chirho = parent_chirho.clone();
        bad_schema_chirho.schema_chirho = "capability-grant-record-v2-chirho".to_string();
        write_jsonl_chirho(&grants_path_chirho(&root_chirho), &[bad_schema_chirho]);
        let error_chirho = verify_grants_chirho(&root_chirho).unwrap_err().to_string();
        assert!(error_chirho.contains("unsupported capability grant schema"));
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn legacy_capability_grants_without_schema_still_verify_chirho() {
        let root_chirho = tmp_root_chirho();
        let parent_chirho = issue_root_grant_chirho(
            &root_chirho,
            "admin",
            "agent-a",
            CapabilityChirho::ReadStoreChirho {
                prefix_chirho: "thread".to_string(),
            },
            CapabilityLimitsChirho::default(),
        )
        .unwrap();
        let child_chirho = delegate_grant_chirho(
            &root_chirho,
            &parent_chirho.grant_id_chirho,
            "agent-a",
            "agent-b",
            CapabilityChirho::ReadStoreChirho {
                prefix_chirho: "thread/123".to_string(),
            },
            CapabilityLimitsChirho {
                expires_at_ms_chirho: Some(now_ms_chirho() + 3_600_000),
                max_invokes_chirho: Some(5),
                budget_token_chirho: None,
            },
        )
        .unwrap();

        let mut legacy_parent_chirho = parent_chirho.clone();
        legacy_parent_chirho.schema_chirho.clear();
        let legacy_parent_chirho = resign_grant_for_test_chirho(&root_chirho, legacy_parent_chirho);
        let mut legacy_child_chirho = child_chirho.clone();
        legacy_child_chirho.schema_chirho.clear();
        legacy_child_chirho.parent_grant_id_chirho =
            Some(legacy_parent_chirho.grant_id_chirho.clone());
        let legacy_child_chirho = resign_grant_for_test_chirho(&root_chirho, legacy_child_chirho);
        write_jsonl_chirho(
            &grants_path_chirho(&root_chirho),
            &[legacy_parent_chirho.clone(), legacy_child_chirho.clone()],
        );

        let log_chirho = std::fs::read_to_string(grants_path_chirho(&root_chirho)).unwrap();
        assert!(!log_chirho.contains("schema_chirho"));
        assert_eq!(verify_grants_chirho(&root_chirho).unwrap(), 2);
        let loaded_chirho = load_grants_chirho(&root_chirho).unwrap();
        assert!(loaded_chirho
            .iter()
            .all(|record_chirho| record_chirho.schema_chirho.is_empty()));
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn delegation_rejects_widened_prefix_type_and_limits_chirho() {
        let root_chirho = tmp_root_chirho();
        let parent_chirho = issue_root_grant_chirho(
            &root_chirho,
            "admin",
            "agent-a",
            CapabilityChirho::ReadStoreChirho {
                prefix_chirho: "thread/123".to_string(),
            },
            CapabilityLimitsChirho {
                expires_at_ms_chirho: Some(1_000),
                max_invokes_chirho: Some(10),
                budget_token_chirho: Some(100),
            },
        )
        .unwrap();
        assert!(delegate_grant_chirho(
            &root_chirho,
            &parent_chirho.grant_id_chirho,
            "agent-a",
            "agent-b",
            CapabilityChirho::ReadStoreChirho {
                prefix_chirho: "thread".to_string(),
            },
            CapabilityLimitsChirho {
                expires_at_ms_chirho: Some(900),
                max_invokes_chirho: Some(5),
                budget_token_chirho: Some(50),
            },
        )
        .is_err());
        assert!(delegate_grant_chirho(
            &root_chirho,
            &parent_chirho.grant_id_chirho,
            "agent-a",
            "agent-b",
            CapabilityChirho::WriteStoreChirho {
                prefix_chirho: "thread/123".to_string(),
            },
            CapabilityLimitsChirho {
                expires_at_ms_chirho: Some(900),
                max_invokes_chirho: Some(5),
                budget_token_chirho: Some(50),
            },
        )
        .is_err());
        assert!(delegate_grant_chirho(
            &root_chirho,
            &parent_chirho.grant_id_chirho,
            "agent-a",
            "agent-b",
            CapabilityChirho::ReadStoreChirho {
                prefix_chirho: "thread/123/comment".to_string(),
            },
            CapabilityLimitsChirho {
                expires_at_ms_chirho: Some(1_100),
                max_invokes_chirho: Some(5),
                budget_token_chirho: Some(50),
            },
        )
        .is_err());
        assert_eq!(verify_grants_chirho(&root_chirho).unwrap(), 1);
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn store_grants_reject_invalid_prefixes_chirho() {
        let root_chirho = tmp_root_chirho();
        assert!(issue_root_grant_chirho(
            &root_chirho,
            "admin",
            "agent-a",
            CapabilityChirho::ReadStoreChirho {
                prefix_chirho: "thread/".to_string(),
            },
            CapabilityLimitsChirho::default(),
        )
        .is_err());
        let parent_chirho = issue_root_grant_chirho(
            &root_chirho,
            "admin",
            "agent-a",
            CapabilityChirho::ReadStoreChirho {
                prefix_chirho: "thread".to_string(),
            },
            CapabilityLimitsChirho::default(),
        )
        .unwrap();
        assert!(delegate_grant_chirho(
            &root_chirho,
            &parent_chirho.grant_id_chirho,
            "agent-a",
            "agent-b",
            CapabilityChirho::ReadStoreChirho {
                prefix_chirho: "thread/../other".to_string(),
            },
            CapabilityLimitsChirho {
                expires_at_ms_chirho: Some(now_ms_chirho() + 3_600_000),
                max_invokes_chirho: None,
                budget_token_chirho: None,
            },
        )
        .is_err());
        assert_eq!(verify_grants_chirho(&root_chirho).unwrap(), 1);
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn net_allowlist_delegation_must_be_subset_chirho() {
        let root_chirho = tmp_root_chirho();
        let parent_chirho = issue_root_grant_chirho(
            &root_chirho,
            "admin",
            "agent-a",
            CapabilityChirho::NetChirho {
                allowlist_chirho: vec![
                    "https://api.a.example".to_string(),
                    "https://api.b.example".to_string(),
                ],
            },
            CapabilityLimitsChirho::default(),
        )
        .unwrap();
        delegate_grant_chirho(
            &root_chirho,
            &parent_chirho.grant_id_chirho,
            "agent-a",
            "agent-b",
            CapabilityChirho::NetChirho {
                allowlist_chirho: vec!["https://api.a.example".to_string()],
            },
            CapabilityLimitsChirho::default(),
        )
        .unwrap();
        assert!(delegate_grant_chirho(
            &root_chirho,
            &parent_chirho.grant_id_chirho,
            "agent-a",
            "agent-c",
            CapabilityChirho::NetChirho {
                allowlist_chirho: vec!["https://api.c.example".to_string()],
            },
            CapabilityLimitsChirho::default(),
        )
        .is_err());
        assert_eq!(verify_grants_chirho(&root_chirho).unwrap(), 2);
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn support_issue_delegation_narrows_actions_chirho() {
        let root_chirho = tmp_root_chirho();
        let _ = std::fs::remove_dir_all(&root_chirho);
        let parent_chirho = issue_root_grant_chirho(
            &root_chirho,
            "owner/app",
            "agent/a",
            CapabilityChirho::SupportIssueChirho {
                issue_chirho: "feedback-7".to_string(),
                actions_chirho: vec!["llm_reply_chirho".to_string(), "reply_chirho".to_string()],
            },
            CapabilityLimitsChirho::default(),
        )
        .unwrap();
        delegate_grant_chirho(
            &root_chirho,
            &parent_chirho.grant_id_chirho,
            "agent/a",
            "user/b",
            CapabilityChirho::SupportIssueChirho {
                issue_chirho: "feedback-7".to_string(),
                actions_chirho: vec!["reply_chirho".to_string()],
            },
            CapabilityLimitsChirho::default(),
        )
        .unwrap();
        assert!(delegate_grant_chirho(
            &root_chirho,
            &parent_chirho.grant_id_chirho,
            "agent/a",
            "user/c",
            CapabilityChirho::SupportIssueChirho {
                issue_chirho: "feedback-8".to_string(),
                actions_chirho: vec!["reply_chirho".to_string()],
            },
            CapabilityLimitsChirho::default(),
        )
        .is_err());
        assert_eq!(verify_grants_chirho(&root_chirho).unwrap(), 2);
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
