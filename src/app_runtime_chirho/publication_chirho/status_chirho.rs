// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The publication status road: a live `read-store:publication-chirho/` read that lists the
//! signed-in viewer's intents from her tenant root and the platform's verified applied records for
//! them, so the workspace can show "publishing…", the live version, and any refusal in customer
//! words — without the tenant process ever writing outside its root.

use super::{
    load_verified_publication_applied_chirho, load_verified_publication_intents_chirho,
    publication_address_chirho, publication_intent_digest_chirho, publication_user_digest_chirho,
    validate_publication_slug_chirho, PublicationAppliedRecordChirho, PublicationKindChirho,
    PublicationOutcomeChirho, PublicationViewerStateBindingChirho,
    PUBLICATION_CAPABILITY_PREFIX_CHIRHO,
};
use crate::model_chirho::{HashChirho, RequestContextChirho};
use crate::tenant_chirho::{tenant_id_for_root_chirho, tenant_root_chirho, TenantIdChirho};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const PUBLICATION_STATUS_REQUEST_SCHEMA_CHIRHO: &str = "publication-status-request-v1-chirho";
pub const PUBLICATION_STATUS_RESPONSE_SCHEMA_CHIRHO: &str = "publication-status-response-v1-chirho";
/// The approval base of a slug that has never been applied.
pub const DARK_PUBLICATION_BASE_CHIRHO: &str = "dark-chirho";
const MAX_STATUS_REQUEST_BYTES_CHIRHO: usize = 4 * 1024;
const MAX_STATUS_PAGE_KEY_BYTES_CHIRHO: usize = 128;

/// Strict except for the two fields the served plain-input path injects into every JSON object
/// body (`user_principal_chirho`, `app_params_chirho`); the read is scoped by the verified
/// session context, never by the claimed principal, which is only checked for agreement.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationStatusRequestChirho {
    pub schema_chirho: String,
    #[serde(default)]
    pub slug_chirho: Option<String>,
    /// A viewer-state logical key whose verified head the response names as `page_head_chirho`
    /// (PFE #21813): the publishing page is a single-input DAG and cannot also read viewer
    /// state, yet its republish / new-address forms must name the saved version.
    #[serde(default)]
    pub page_key_chirho: Option<String>,
    #[serde(default)]
    pub user_principal_chirho: Option<String>,
    #[serde(default)]
    pub app_params_chirho: Option<serde_json::Value>,
}

/// Her verified head for the requested page key: version, receipt digest — never value bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationPageHeadChirho {
    pub key_chirho: String,
    pub version_chirho: u64,
    pub receipt_digest_chirho: HashChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationIntentSummaryChirho {
    pub seq_chirho: u64,
    pub intent_digest_chirho: HashChirho,
    pub kind_chirho: PublicationKindChirho,
    pub params_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub viewer_state_chirho: Option<PublicationViewerStateBindingChirho>,
    pub at_ms_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationAppliedSummaryChirho {
    pub intent_digest_chirho: HashChirho,
    pub kind_chirho: PublicationKindChirho,
    pub outcome_chirho: PublicationOutcomeChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_code_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params_chirho: Option<HashChirho>,
    pub at_ms_chirho: u64,
}

/// The platform's latest APPLIED outcome for a slug: what the public service serves, named by
/// the params record the applier bound. `None` before the first apply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationLiveChirho {
    pub params_chirho: HashChirho,
    pub applied_intent_digest_chirho: HashChirho,
    pub params_record_seq_chirho: u64,
    pub at_ms_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationSlugStatusChirho {
    pub slug_chirho: String,
    pub address_chirho: String,
    pub intents_chirho: Vec<PublicationIntentSummaryChirho>,
    pub applied_chirho: Vec<PublicationAppliedSummaryChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_chirho: Option<PublicationLiveChirho>,
    /// What a form approving the NEXT act on this slug must carry as `base_publication_chirho`:
    /// the live applied intent digest, or `dark-chirho`.
    #[serde(default = "default_approval_base_chirho")]
    pub approval_base_chirho: String,
}

fn default_approval_base_chirho() -> String {
    DARK_PUBLICATION_BASE_CHIRHO.to_string()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationStatusResponseChirho {
    pub schema_chirho: String,
    pub slugs_chirho: Vec<PublicationSlugStatusChirho>,
    /// Present only when the request named `page_key_chirho` and that key has a saved version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_head_chirho: Option<PublicationPageHeadChirho>,
}

pub fn decode_publication_status_request_chirho(
    request_bytes_chirho: &[u8],
) -> Result<Option<PublicationStatusRequestChirho>> {
    if request_bytes_chirho.len() > MAX_STATUS_REQUEST_BYTES_CHIRHO {
        return Ok(None);
    }
    let Ok(value_chirho) = serde_json::from_slice::<serde_json::Value>(request_bytes_chirho) else {
        return Ok(None);
    };
    if value_chirho
        .get("schema_chirho")
        .and_then(|schema_chirho| schema_chirho.as_str())
        != Some(PUBLICATION_STATUS_REQUEST_SCHEMA_CHIRHO)
    {
        return Ok(None);
    }
    serde_json::from_value(value_chirho)
        .map(Some)
        .context("decode PublicationStatusRequestChirho")
}

pub fn reserved_publication_prefix_chirho(capability_prefix_chirho: &str) -> bool {
    capability_prefix_chirho.starts_with(PUBLICATION_CAPABILITY_PREFIX_CHIRHO)
}

/// Where a tenant root's applied records live: its platform root, resolved from the tenant
/// marker and the on-disk shape (`<platform>/tenants-chirho/<id>`), never from a config value.
/// A platform root reads its own applied log.
pub fn applied_records_root_chirho(root_chirho: &Path) -> Result<PathBuf> {
    match tenant_id_for_root_chirho(root_chirho)? {
        TenantIdChirho::PlatformRootChirho => Ok(root_chirho.to_path_buf()),
        TenantIdChirho::TenantChirho(tenant_id_chirho) => {
            let root_canon_chirho = root_chirho
                .canonicalize()
                .with_context(|| format!("canonicalize tenant root {}", root_chirho.display()))?;
            let platform_chirho = root_canon_chirho
                .parent()
                .and_then(Path::parent)
                .ok_or_else(|| anyhow!("tenant root has no platform root above it"))?;
            let expected_chirho = tenant_root_chirho(platform_chirho, &tenant_id_chirho)?
                .canonicalize()
                .with_context(|| "canonicalize expected tenant root".to_string())?;
            if expected_chirho != root_canon_chirho {
                bail!("tenant root does not sit at its platform root's tenants-chirho/<id>");
            }
            Ok(platform_chirho.to_path_buf())
        }
    }
}

/// Part of `spec-chirho/workflows-chirho/publication-chirho/self-service-publication-chirho.md`.
pub fn run_publication_status_read_chirho(
    root_chirho: &Path,
    capability_prefix_chirho: &str,
    request_chirho: &PublicationStatusRequestChirho,
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<Vec<u8>> {
    if capability_prefix_chirho != PUBLICATION_CAPABILITY_PREFIX_CHIRHO {
        bail!(
            "publication status reads require the exact capability prefix '{PUBLICATION_CAPABILITY_PREFIX_CHIRHO}'"
        );
    }
    let context_chirho = request_context_chirho
        .ok_or_else(|| anyhow!("publication status reads require a signed-in app session"))?;
    if let Some(claimed_chirho) = request_chirho.user_principal_chirho.as_deref() {
        if claimed_chirho != context_chirho.user_principal_chirho {
            bail!("user_principal_chirho in the request does not match the signed-in session");
        }
    }
    if let Some(slug_chirho) = request_chirho.slug_chirho.as_deref() {
        validate_publication_slug_chirho(slug_chirho)?;
    }
    let user_digest_chirho = publication_user_digest_chirho(&context_chirho.user_principal_chirho);
    // A tenant-root road only: intents live in tenant roots, and on the platform root the tenant
    // filter below would vanish and leave the user digest as the sole scope (claude2 #21816).
    let tenant_label_chirho = match tenant_id_for_root_chirho(root_chirho)? {
        TenantIdChirho::TenantChirho(id_chirho) => id_chirho,
        TenantIdChirho::PlatformRootChirho => {
            bail!("publication status is a tenant-root road; the platform root has no intents")
        }
    };
    let page_head_chirho = match request_chirho.page_key_chirho.as_deref() {
        None => None,
        Some(key_chirho) => {
            if key_chirho.is_empty() || key_chirho.len() > MAX_STATUS_PAGE_KEY_BYTES_CHIRHO {
                bail!("page_key_chirho must be 1..={MAX_STATUS_PAGE_KEY_BYTES_CHIRHO} bytes");
            }
            crate::effect_chirho::with_verified_head_value_for_key_chirho(
                root_chirho,
                context_chirho,
                key_chirho,
                |head_chirho| {
                    Ok(head_chirho.map(|head_chirho| PublicationPageHeadChirho {
                        key_chirho: key_chirho.to_string(),
                        version_chirho: head_chirho.head_chirho.version_chirho,
                        receipt_digest_chirho: head_chirho.head_chirho.receipt_digest_chirho,
                    }))
                },
            )?
        }
    };

    let mut slugs_chirho: BTreeMap<String, PublicationSlugStatusChirho> = BTreeMap::new();
    for record_chirho in load_verified_publication_intents_chirho(root_chirho)? {
        if record_chirho.user_principal_chirho != context_chirho.user_principal_chirho {
            continue;
        }
        if request_chirho
            .slug_chirho
            .as_deref()
            .is_some_and(|slug_chirho| slug_chirho != record_chirho.slug_chirho)
        {
            continue;
        }
        let entry_chirho = slug_entry_chirho(&mut slugs_chirho, &record_chirho.slug_chirho);
        entry_chirho
            .intents_chirho
            .push(PublicationIntentSummaryChirho {
                seq_chirho: record_chirho.seq_chirho,
                intent_digest_chirho: publication_intent_digest_chirho(&record_chirho)?,
                kind_chirho: record_chirho.kind_chirho,
                params_chirho: record_chirho.params_chirho.clone(),
                viewer_state_chirho: record_chirho.viewer_state_chirho.clone(),
                at_ms_chirho: record_chirho.at_ms_chirho,
            });
    }

    // Every applied row is verified against the PLATFORM key before it is listed; a row that does
    // not verify fails the whole read closed rather than being skipped.
    let applied_root_chirho = applied_records_root_chirho(root_chirho)?;
    for record_chirho in load_verified_publication_applied_chirho(&applied_root_chirho)? {
        if record_chirho.user_digest_chirho != user_digest_chirho {
            continue;
        }
        if tenant_label_chirho != record_chirho.tenant_chirho {
            continue;
        }
        if request_chirho
            .slug_chirho
            .as_deref()
            .is_some_and(|slug_chirho| slug_chirho != record_chirho.slug_chirho)
        {
            continue;
        }
        let entry_chirho = slug_entry_chirho(&mut slugs_chirho, &record_chirho.slug_chirho);
        entry_chirho
            .applied_chirho
            .push(applied_summary_chirho(&record_chirho));
        if record_chirho.outcome_chirho == PublicationOutcomeChirho::AppliedChirho {
            if let (Some(params_chirho), Some(seq_chirho)) = (
                record_chirho.params_chirho.clone(),
                record_chirho.params_record_seq_chirho,
            ) {
                entry_chirho.live_chirho = Some(PublicationLiveChirho {
                    params_chirho,
                    applied_intent_digest_chirho: record_chirho.intent_digest_chirho.clone(),
                    params_record_seq_chirho: seq_chirho,
                    at_ms_chirho: record_chirho.at_ms_chirho,
                });
                entry_chirho.approval_base_chirho = record_chirho.intent_digest_chirho.0.clone();
            }
        }
    }

    serde_json::to_vec(&PublicationStatusResponseChirho {
        schema_chirho: PUBLICATION_STATUS_RESPONSE_SCHEMA_CHIRHO.to_string(),
        slugs_chirho: slugs_chirho.into_values().collect(),
        page_head_chirho,
    })
    .context("encode PublicationStatusResponseChirho")
}

/// The slug's live identity AS THIS VIEWER holds it: the intent digest of HER latest APPLIED-outcome
/// record for the slug — scoped by `user_digest` + `tenant`, exactly as the status listing scopes
/// its applied rows above — or `dark-chirho` when she holds nothing applied under this slug. The
/// intent door compares a request's explicit base to it before any write (PFE gpt #21794).
///
/// The viewer scope is the fix for the occupied-name leak (CAIRN #24144): the prior unscoped
/// slug search returned the intent digest of whoever most recently applied the slug — ANOTHER
/// account's live digest — into the requester's `base-moved-chirho` refusal. Occupancy itself is
/// now decided pre-admission by the canonical ownership model (`apply_chirho`), separate from this
/// viewer-scoped base. A platform log that does not verify fails closed here.
pub(crate) fn live_identity_for_slug_for_viewer_chirho(
    root_chirho: &Path,
    slug_chirho: &str,
    user_digest_chirho: &HashChirho,
    tenant_label_chirho: &str,
) -> Result<String> {
    let applied_root_chirho = applied_records_root_chirho(root_chirho)?;
    let live_chirho = load_verified_publication_applied_chirho(&applied_root_chirho)?
        .into_iter()
        .rev()
        .find(|record_chirho| {
            record_chirho.slug_chirho == slug_chirho
                && &record_chirho.user_digest_chirho == user_digest_chirho
                && record_chirho.tenant_chirho.as_str() == tenant_label_chirho
                && record_chirho.outcome_chirho == PublicationOutcomeChirho::AppliedChirho
                && record_chirho.params_record_seq_chirho.is_some()
        })
        .map(|record_chirho| record_chirho.intent_digest_chirho.0);
    Ok(live_chirho.unwrap_or_else(|| DARK_PUBLICATION_BASE_CHIRHO.to_string()))
}

fn slug_entry_chirho<'a>(
    slugs_chirho: &'a mut BTreeMap<String, PublicationSlugStatusChirho>,
    slug_chirho: &str,
) -> &'a mut PublicationSlugStatusChirho {
    slugs_chirho
        .entry(slug_chirho.to_string())
        .or_insert_with(|| PublicationSlugStatusChirho {
            slug_chirho: slug_chirho.to_string(),
            address_chirho: publication_address_chirho(slug_chirho),
            intents_chirho: Vec::new(),
            applied_chirho: Vec::new(),
            live_chirho: None,
            approval_base_chirho: DARK_PUBLICATION_BASE_CHIRHO.to_string(),
        })
}

fn applied_summary_chirho(
    record_chirho: &PublicationAppliedRecordChirho,
) -> PublicationAppliedSummaryChirho {
    PublicationAppliedSummaryChirho {
        intent_digest_chirho: record_chirho.intent_digest_chirho.clone(),
        kind_chirho: record_chirho.kind_chirho,
        outcome_chirho: record_chirho.outcome_chirho,
        refusal_code_chirho: record_chirho.refusal_code_chirho.clone(),
        params_chirho: record_chirho.params_chirho.clone(),
        at_ms_chirho: record_chirho.at_ms_chirho,
    }
}
