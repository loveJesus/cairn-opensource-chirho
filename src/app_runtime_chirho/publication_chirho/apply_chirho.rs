// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The platform applier: the only writer of platform-level publication state. It reads a tenant's
//! verified intents, judges each one inside the platform root's lock (template, owner, slug policy,
//! params), performs the deploy / republish / rollback under the platform key, and writes exactly
//! one signed applied record per intent — applied, or refused with a fixed token — so the tenant
//! status road can show the outcome and a second run applies nothing twice.

use super::{
    append_publication_applied_record_chirho, load_verified_publication_applied_chirho,
    load_verified_publication_intents_chirho, publication_intent_digest_chirho,
    publication_user_digest_chirho, validate_publication_slug_chirho,
    PublicationAppliedInputChirho, PublicationIntentRecordChirho, PublicationKindChirho,
    PublicationOutcomeChirho,
};
use crate::model_chirho::HashChirho;
use crate::tenant_chirho::{tenant_id_for_root_chirho, tenant_root_chirho, TenantIdChirho};
use crate::{app_chirho, cas_chirho, identity_chirho, seqlog_chirho, store_chirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_model_app_chirho::AppInputModeChirho;
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PUBLICATION_OWNER_RECORD_SCHEMA_CHIRHO: &str = "publication-owner-record-v1-chirho";
pub const PUBLICATION_OWNERS_FILE_CHIRHO: &str = "publication-owners-chirho.jsonl";
pub const SLUG_CLAIM_RECORD_SCHEMA_CHIRHO: &str = "publication-slug-claim-record-v1-chirho";
pub const SLUG_CLAIMS_FILE_CHIRHO: &str = "slug-claims-chirho.jsonl";
pub const RESERVED_SLUG_RECORD_SCHEMA_CHIRHO: &str = "publication-reserved-slug-record-v1-chirho";
pub const RESERVED_SLUGS_FILE_CHIRHO: &str = "publication-reserved-slugs-chirho.jsonl";
pub const PUBLICATION_APPLY_REPORT_SCHEMA_CHIRHO: &str = "publication-apply-report-v1-chirho";
const PUBLICATION_APPLY_LOCK_CHIRHO: &str = "publication-apply-chirho";

/// A viewer's platform-side owner: minted once per (tenant, viewer digest) and bound by a signed
/// record, so republish and rollback authority resolves to the same owner every time without the
/// platform ever holding her principal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationOwnerRecordChirho {
    pub seq_chirho: u64,
    pub schema_chirho: String,
    pub tenant_chirho: String,
    pub user_digest_chirho: HashChirho,
    pub owner_principal_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

/// First-come slug ownership at the platform level: the record, not a table, is the claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlugClaimRecordChirho {
    pub seq_chirho: u64,
    pub schema_chirho: String,
    pub slug_chirho: String,
    pub tenant_chirho: String,
    pub user_digest_chirho: HashChirho,
    pub owner_principal_chirho: String,
    pub intent_digest_chirho: HashChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

/// Why an operator reserved a slug. A closed vocabulary, never a typed sentence: this record is
/// retained forever in a platform-signed log, and the privacy scanner classifies `reason_chirho`
/// as high-risk free text — so the log carries a bounded label the way the money log does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReservedSlugReasonChirho {
    /// The platform's own public app lives under this name.
    PlatformAppChirho,
    /// The workspace (authoring) app lives under this name.
    WorkspaceAppChirho,
    /// A registered template is named this; a tenant site must not shadow it.
    TemplateNameChirho,
    /// Operator policy (a brand, a legal term, a confusing name) with the reasoning kept outside
    /// the log.
    OperatorPolicyChirho,
}

impl ReservedSlugReasonChirho {
    pub const ALL_CHIRHO: [Self; 4] = [
        Self::PlatformAppChirho,
        Self::WorkspaceAppChirho,
        Self::TemplateNameChirho,
        Self::OperatorPolicyChirho,
    ];

    /// The wire word, identical to the serde form, so CLI, JSON, and display never disagree.
    pub fn label_chirho(self) -> &'static str {
        match self {
            Self::PlatformAppChirho => "platform-app-chirho",
            Self::WorkspaceAppChirho => "workspace-app-chirho",
            Self::TemplateNameChirho => "template-name-chirho",
            Self::OperatorPolicyChirho => "operator-policy-chirho",
        }
    }
}

impl std::str::FromStr for ReservedSlugReasonChirho {
    type Err = anyhow::Error;

    /// Exactly the wire words; anything else names every accepted label in the refusal so an
    /// operator never has to guess the vocabulary.
    fn from_str(text_chirho: &str) -> Result<Self> {
        Self::ALL_CHIRHO
            .into_iter()
            .find(|reason_chirho| reason_chirho.label_chirho() == text_chirho)
            .ok_or_else(|| {
                anyhow!(
                    "unknown reserved-slug reason '{}'; expected one of {}",
                    text_chirho,
                    Self::ALL_CHIRHO
                        .iter()
                        .map(|reason_chirho| reason_chirho.label_chirho())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
    }
}

/// An operator's reservation of a slug nobody may claim (the public app's own name, the workspace
/// app's name, a template's name). Written by `publication-reserve-slug`, signed by the platform.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservedSlugRecordChirho {
    pub seq_chirho: u64,
    pub schema_chirho: String,
    pub slug_chirho: String,
    pub reason_kind_chirho: ReservedSlugReasonChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationApplyReportChirho {
    pub schema_chirho: String,
    pub tenant_chirho: String,
    pub intents_seen_chirho: usize,
    pub already_applied_chirho: usize,
    pub applied_chirho: usize,
    pub refused_chirho: usize,
    pub refusals_chirho: BTreeMap<String, usize>,
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

fn owners_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(PUBLICATION_OWNERS_FILE_CHIRHO)
}

fn claims_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(SLUG_CLAIMS_FILE_CHIRHO)
}

fn reserved_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(RESERVED_SLUGS_FILE_CHIRHO)
}

fn load_jsonl_chirho<T: for<'de> Deserialize<'de>>(
    path_chirho: &Path,
    label_chirho: &str,
) -> Result<Vec<T>> {
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .map(|line_chirho| {
            serde_json::from_str(line_chirho)
                .with_context(|| format!("decode {label_chirho} record"))
        })
        .collect()
}

fn unsigned_message_chirho<T: Serialize + Clone>(
    record_chirho: &T,
    clear_chirho: impl Fn(&mut T),
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = record_chirho.clone();
    clear_chirho(&mut unsigned_chirho);
    serde_json::to_vec(&unsigned_chirho).context("encode signed record message")
}

pub fn load_publication_owners_chirho(
    root_chirho: &Path,
) -> Result<Vec<PublicationOwnerRecordChirho>> {
    load_jsonl_chirho(&owners_path_chirho(root_chirho), "publication owner")
}

pub fn load_slug_claims_chirho(root_chirho: &Path) -> Result<Vec<SlugClaimRecordChirho>> {
    load_jsonl_chirho(&claims_path_chirho(root_chirho), "slug claim")
}

pub fn load_reserved_slugs_chirho(root_chirho: &Path) -> Result<Vec<ReservedSlugRecordChirho>> {
    load_jsonl_chirho(&reserved_path_chirho(root_chirho), "reserved slug")
}

pub fn load_verified_publication_owners_chirho(
    root_chirho: &Path,
) -> Result<Vec<PublicationOwnerRecordChirho>> {
    let records_chirho = load_publication_owners_chirho(root_chirho)?;
    // An empty history needs no key and must not mint one. The door's occupancy read reaches this
    // loader, and `existing_pubkey_hex_chirho` below fails closed on a missing key, so a
    // first-publication root with no signing key yet must return BEFORE any key touch.
    if records_chirho.is_empty() {
        return Ok(records_chirho);
    }
    // Read the EXISTING public key only: this is a verification/read path and must never create or
    // chmod a private signing key (`pubkey_hex_chirho` -> `load_or_create_signing_key_chirho`
    // does). Fail closed on a missing/corrupt authority.
    let pubkey_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    // Hoist the per-owner identity read: load the identity log ONCE and index it by principal
    // (first occurrence wins, exactly as `find_identity_chirho`'s `.find` matched), instead of
    // re-reading and re-parsing the whole identity log for every owner record.
    let identities_chirho = identity_chirho::load_identities_chirho(root_chirho)?;
    let mut identity_by_principal_chirho: BTreeMap<&str, &identity_chirho::IdentityRecordChirho> =
        BTreeMap::new();
    for identity_record_chirho in &identities_chirho {
        identity_by_principal_chirho
            .entry(identity_record_chirho.principal_chirho.as_str())
            .or_insert(identity_record_chirho);
    }
    let mut seen_chirho = BTreeSet::new();
    for (index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!("publication owner seq gap at index {index_chirho}");
        }
        if record_chirho.schema_chirho != PUBLICATION_OWNER_RECORD_SCHEMA_CHIRHO {
            bail!(
                "unsupported publication owner schema '{}'",
                record_chirho.schema_chirho
            );
        }
        let owner_identity_chirho = identity_by_principal_chirho
            .get(record_chirho.owner_principal_chirho.as_str())
            .copied()
            .ok_or_else(|| {
                anyhow!(
                    "publication owner {} names an unknown principal",
                    record_chirho.seq_chirho
                )
            })?;
        if owner_identity_chirho.kind_chirho != identity_chirho::PrincipalKindChirho::OwnerChirho {
            bail!(
                "publication owner {} is not an OwnerChirho identity",
                record_chirho.seq_chirho
            );
        }
        if !seen_chirho.insert((
            record_chirho.tenant_chirho.clone(),
            record_chirho.user_digest_chirho.clone(),
        )) {
            bail!("duplicate publication owner binding for one viewer");
        }
        let message_chirho = unsigned_message_chirho(record_chirho, |r_chirho| {
            r_chirho.sig_chirho = String::new()
        })?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "publication owner {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho)
}

pub fn verify_publication_owners_chirho(root_chirho: &Path) -> Result<usize> {
    Ok(load_verified_publication_owners_chirho(root_chirho)?.len())
}

pub fn load_verified_slug_claims_chirho(root_chirho: &Path) -> Result<Vec<SlugClaimRecordChirho>> {
    let records_chirho = load_slug_claims_chirho(root_chirho)?;
    // Empty history: no key, no mint (see `load_verified_publication_owners_chirho`).
    if records_chirho.is_empty() {
        return Ok(records_chirho);
    }
    // Read-only public key; never create/chmod a private key on this read/refusal path.
    let pubkey_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    let mut seen_chirho = BTreeSet::new();
    for (index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!("slug claim seq gap at index {index_chirho}");
        }
        if record_chirho.schema_chirho != SLUG_CLAIM_RECORD_SCHEMA_CHIRHO {
            bail!(
                "unsupported slug claim schema '{}'",
                record_chirho.schema_chirho
            );
        }
        validate_publication_slug_chirho(&record_chirho.slug_chirho)?;
        if !seen_chirho.insert(record_chirho.slug_chirho.clone()) {
            bail!("duplicate slug claim for '{}'", record_chirho.slug_chirho);
        }
        let message_chirho = unsigned_message_chirho(record_chirho, |r_chirho| {
            r_chirho.sig_chirho = String::new()
        })?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!("slug claim {} signature invalid", record_chirho.seq_chirho);
        }
    }
    Ok(records_chirho)
}

pub fn verify_slug_claims_chirho(root_chirho: &Path) -> Result<usize> {
    Ok(load_verified_slug_claims_chirho(root_chirho)?.len())
}

pub fn load_verified_reserved_slugs_chirho(
    root_chirho: &Path,
) -> Result<Vec<ReservedSlugRecordChirho>> {
    let records_chirho = load_reserved_slugs_chirho(root_chirho)?;
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    for (index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!("reserved slug seq gap at index {index_chirho}");
        }
        if record_chirho.schema_chirho != RESERVED_SLUG_RECORD_SCHEMA_CHIRHO {
            bail!(
                "unsupported reserved slug schema '{}'",
                record_chirho.schema_chirho
            );
        }
        validate_publication_slug_chirho(&record_chirho.slug_chirho)?;
        let message_chirho = unsigned_message_chirho(record_chirho, |r_chirho| {
            r_chirho.sig_chirho = String::new()
        })?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "reserved slug {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho)
}

pub fn verify_reserved_slugs_chirho(root_chirho: &Path) -> Result<usize> {
    Ok(load_verified_reserved_slugs_chirho(root_chirho)?.len())
}

/// Operator act on the platform root: nobody may publish under this slug. Idempotent.
pub fn reserve_publication_slug_chirho(
    platform_root_chirho: &Path,
    slug_chirho: &str,
    reason_kind_chirho: ReservedSlugReasonChirho,
) -> Result<ReservedSlugRecordChirho> {
    validate_publication_slug_chirho(slug_chirho)?;
    seqlog_chirho::with_named_lock_chirho(
        platform_root_chirho,
        PUBLICATION_APPLY_LOCK_CHIRHO,
        || {
            if let Some(existing_chirho) =
                load_verified_reserved_slugs_chirho(platform_root_chirho)?
                    .into_iter()
                    .find(|record_chirho| record_chirho.slug_chirho == slug_chirho)
            {
                return Ok(existing_chirho);
            }
            seqlog_chirho::append_serialized_jsonl_chirho(
                platform_root_chirho,
                &reserved_path_chirho(platform_root_chirho),
                |seq_chirho| {
                    let mut record_chirho = ReservedSlugRecordChirho {
                        seq_chirho,
                        schema_chirho: RESERVED_SLUG_RECORD_SCHEMA_CHIRHO.to_string(),
                        slug_chirho: slug_chirho.to_string(),
                        reason_kind_chirho,
                        at_ms_chirho: now_ms_chirho(),
                        sig_chirho: String::new(),
                    };
                    let message_chirho = unsigned_message_chirho(&record_chirho, |r_chirho| {
                        r_chirho.sig_chirho = String::new()
                    })?;
                    record_chirho.sig_chirho =
                        signer_chirho::sign_message_chirho(platform_root_chirho, &message_chirho)?;
                    Ok(record_chirho)
                },
            )
        },
    )
}

fn resolve_or_mint_publication_owner_chirho(
    platform_root_chirho: &Path,
    tenant_chirho: &str,
    user_digest_chirho: &HashChirho,
) -> Result<String> {
    if let Some(record_chirho) = load_verified_publication_owners_chirho(platform_root_chirho)?
        .into_iter()
        .find(|record_chirho| {
            record_chirho.tenant_chirho == tenant_chirho
                && &record_chirho.user_digest_chirho == user_digest_chirho
        })
    {
        return Ok(record_chirho.owner_principal_chirho);
    }
    let owner_chirho = identity_chirho::register_identity_chirho(
        platform_root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )?;
    let record_chirho = seqlog_chirho::append_serialized_jsonl_chirho(
        platform_root_chirho,
        &owners_path_chirho(platform_root_chirho),
        |seq_chirho| {
            let mut record_chirho = PublicationOwnerRecordChirho {
                seq_chirho,
                schema_chirho: PUBLICATION_OWNER_RECORD_SCHEMA_CHIRHO.to_string(),
                tenant_chirho: tenant_chirho.to_string(),
                user_digest_chirho: user_digest_chirho.clone(),
                owner_principal_chirho: owner_chirho.principal_chirho.clone(),
                at_ms_chirho: now_ms_chirho(),
                sig_chirho: String::new(),
            };
            let message_chirho = unsigned_message_chirho(&record_chirho, |r_chirho| {
                r_chirho.sig_chirho = String::new()
            })?;
            record_chirho.sig_chirho =
                signer_chirho::sign_message_chirho(platform_root_chirho, &message_chirho)?;
            Ok(record_chirho)
        },
    )?;
    Ok(record_chirho.owner_principal_chirho)
}

fn append_slug_claim_chirho(
    platform_root_chirho: &Path,
    slug_chirho: &str,
    tenant_chirho: &str,
    user_digest_chirho: &HashChirho,
    owner_principal_chirho: &str,
    intent_digest_chirho: &HashChirho,
) -> Result<SlugClaimRecordChirho> {
    seqlog_chirho::append_serialized_jsonl_chirho(
        platform_root_chirho,
        &claims_path_chirho(platform_root_chirho),
        |seq_chirho| {
            let mut record_chirho = SlugClaimRecordChirho {
                seq_chirho,
                schema_chirho: SLUG_CLAIM_RECORD_SCHEMA_CHIRHO.to_string(),
                slug_chirho: slug_chirho.to_string(),
                tenant_chirho: tenant_chirho.to_string(),
                user_digest_chirho: user_digest_chirho.clone(),
                owner_principal_chirho: owner_principal_chirho.to_string(),
                intent_digest_chirho: intent_digest_chirho.clone(),
                at_ms_chirho: now_ms_chirho(),
                sig_chirho: String::new(),
            };
            let message_chirho = unsigned_message_chirho(&record_chirho, |r_chirho| {
                r_chirho.sig_chirho = String::new()
            })?;
            record_chirho.sig_chirho =
                signer_chirho::sign_message_chirho(platform_root_chirho, &message_chirho)?;
            Ok(record_chirho)
        },
    )
}

/// Whether a slug is free for a requester to publish, decided against the platform's canonical
/// ownership model — first-come slug CLAIMS and deployed-app ownership — exactly as `judge_chirho`
/// decides `slug-taken-chirho`. Read-only: it resolves the requester's owner without minting one,
/// so the tenant door can refuse an occupied name pre-admission and agree with the applier by
/// construction. It carries NO foreign owner principal or live digest — only whether the requester
/// may proceed, and whether a claim/app already exists under her.
pub(crate) enum SlugOccupancyChirho {
    /// A different identity holds this slug (a claim, or a deployed app, owned by another). A
    /// requester with no owner yet also lands here for any existing claim/app: absence is not
    /// permission to take an occupied name.
    OccupiedByAnotherChirho,
    /// Free for the requester. The two flags say whether the slug already carries HER claim / HER
    /// deployed app, so the applier keeps its new-app rule and the door keeps its viewer-scoped
    /// base decision.
    AvailableToRequesterChirho {
        claim_exists_chirho: bool,
        app_exists_chirho: bool,
    },
}

/// Resolve occupancy for a requester named by (tenant, user_digest), READ-ONLY: her owner is
/// looked up in the verified owner log and never minted. The tenant door and `judge_chirho` reach
/// the same decision through `slug_occupancy_for_owner_chirho`, so an occupied name the applier
/// would refuse is refused at the door too, pre-admission.
pub(crate) fn slug_occupancy_for_requester_chirho(
    platform_root_chirho: &Path,
    slug_chirho: &str,
    tenant_chirho: &str,
    user_digest_chirho: &HashChirho,
) -> Result<SlugOccupancyChirho> {
    let requester_owner_chirho = load_verified_publication_owners_chirho(platform_root_chirho)?
        .into_iter()
        .find(|record_chirho| {
            record_chirho.tenant_chirho == tenant_chirho
                && &record_chirho.user_digest_chirho == user_digest_chirho
        })
        .map(|record_chirho| record_chirho.owner_principal_chirho);
    slug_occupancy_for_owner_chirho(
        platform_root_chirho,
        slug_chirho,
        requester_owner_chirho.as_deref(),
    )
}

/// The shared occupancy core: given the requester's ALREADY-resolved owner (minted, for the
/// applier; read-only-resolved or absent, for the door), decide the slug against the platform's
/// verified claims and deployed-app ownership. This is the single definition of `slug-taken-chirho`,
/// so the door and the applier cannot drift apart. A claim binds the slug for good regardless of
/// any deployed app; an unclaimed slug that already names a deployed app belongs to whoever
/// deployed it. The comparison mirrors `judge_chirho`'s prior match exactly.
pub(crate) fn slug_occupancy_for_owner_chirho(
    platform_root_chirho: &Path,
    slug_chirho: &str,
    requester_owner_chirho: Option<&str>,
) -> Result<SlugOccupancyChirho> {
    let claim_chirho = load_verified_slug_claims_chirho(platform_root_chirho)?
        .into_iter()
        .find(|record_chirho| record_chirho.slug_chirho == slug_chirho);
    let app_owner_chirho =
        app_chirho::verified_app_owner_chirho(platform_root_chirho, slug_chirho)?;
    let occupied_chirho = match (&claim_chirho, &app_owner_chirho) {
        (Some(claim_chirho), _) => {
            requester_owner_chirho != Some(claim_chirho.owner_principal_chirho.as_str())
        }
        (None, Some(app_owner_chirho)) => requester_owner_chirho != Some(app_owner_chirho.as_str()),
        (None, None) => false,
    };
    if occupied_chirho {
        return Ok(SlugOccupancyChirho::OccupiedByAnotherChirho);
    }
    Ok(SlugOccupancyChirho::AvailableToRequesterChirho {
        claim_exists_chirho: claim_chirho.is_some(),
        app_exists_chirho: app_owner_chirho.is_some(),
    })
}

/// The judgement of one intent, as a refusal token or the apply plan.
enum JudgementChirho {
    RefuseChirho(&'static str),
    ApplyChirho {
        owner_principal_chirho: String,
        template_root_dag_chirho: HashChirho,
        response_content_type_chirho: String,
        new_app_chirho: bool,
        params_value_chirho: Option<serde_json::Value>,
    },
}

fn judge_chirho(
    platform_root_chirho: &Path,
    tenant_root_chirho: &Path,
    tenant_chirho: &str,
    intent_chirho: &PublicationIntentRecordChirho,
    intent_digest_chirho: &HashChirho,
    user_digest_chirho: &HashChirho,
) -> Result<JudgementChirho> {
    // 1. The template must be registered on THIS root and deployable.
    let templates_chirho = app_chirho::verified_template_registry_chirho(platform_root_chirho)?;
    let Some(template_chirho) = templates_chirho.get(&intent_chirho.template_id_chirho) else {
        return Ok(JudgementChirho::RefuseChirho("unknown-template-chirho"));
    };
    // Registered is not deployable: the descriptor-v2 boundary (every node pure when no undo-plan
    // bindings are presented) is the only gate on this road — nothing downstream re-verifies —
    // and it carries its own token so the status view never collapses it into a registry miss.
    if crate::app_source_manifest_chirho::verify_descriptor_v2_deployment_chirho(
        platform_root_chirho,
        &BTreeSet::from([template_chirho.root_dag_chirho.clone()]),
        None,
    )
    .is_err()
    {
        return Ok(JudgementChirho::RefuseChirho(
            "template-not-deployable-chirho",
        ));
    }
    // 2. Reserved names are nobody's.
    if load_verified_reserved_slugs_chirho(platform_root_chirho)?
        .iter()
        .any(|record_chirho| record_chirho.slug_chirho == intent_chirho.slug_chirho)
    {
        return Ok(JudgementChirho::RefuseChirho("slug-reserved-chirho"));
    }
    // 3. Her owner, minted on first sight.
    let owner_principal_chirho = resolve_or_mint_publication_owner_chirho(
        platform_root_chirho,
        tenant_chirho,
        user_digest_chirho,
    )?;
    // 4. Slug policy, through the shared occupancy resolver so the tenant door refuses exactly the
    //    slugs this applier would (a claim binds a slug to one owner for good; an unclaimed slug
    //    that already names a platform app belongs to whoever deployed that app). Her owner is
    //    already minted above, so it is passed in rather than re-resolved.
    let new_app_chirho = match slug_occupancy_for_owner_chirho(
        platform_root_chirho,
        &intent_chirho.slug_chirho,
        Some(&owner_principal_chirho),
    )? {
        SlugOccupancyChirho::OccupiedByAnotherChirho => {
            return Ok(JudgementChirho::RefuseChirho("slug-taken-chirho"));
        }
        // A new app is one the platform does not already serve under this slug; a matching claim
        // without a deployed app is still a new app (identical to the prior match arms).
        SlugOccupancyChirho::AvailableToRequesterChirho {
            app_exists_chirho, ..
        } => !app_exists_chirho,
    };
    if new_app_chirho && intent_chirho.kind_chirho != PublicationKindChirho::PublishChirho {
        return Ok(JudgementChirho::RefuseChirho("not-your-app-chirho"));
    }
    // 5. The params: publish/republish copy the approved document from the tenant CAS by hash;
    //    rollback names one of THIS app's own prior params records.
    let params_value_chirho = match intent_chirho.kind_chirho {
        PublicationKindChirho::PublishChirho | PublicationKindChirho::RepublishChirho => {
            let bytes_chirho = match cas_chirho::read_verified_chirho(
                tenant_root_chirho,
                &intent_chirho.params_chirho,
            ) {
                cas_chirho::CasReadOutcomeChirho::VerifiedChirho(bytes_chirho) => bytes_chirho,
                _ => return Ok(JudgementChirho::RefuseChirho("params-missing-chirho")),
            };
            let value_chirho: serde_json::Value = match serde_json::from_slice(&bytes_chirho) {
                Ok(value_chirho) => value_chirho,
                Err(_) => return Ok(JudgementChirho::RefuseChirho("params-missing-chirho")),
            };
            if !value_chirho.is_object()
                || store_chirho::hash_object_chirho(&value_chirho)? != intent_chirho.params_chirho
            {
                return Ok(JudgementChirho::RefuseChirho("params-missing-chirho"));
            }
            Some(value_chirho)
        }
        PublicationKindChirho::RollbackChirho => {
            app_chirho::verify_app_params_chirho(platform_root_chirho)?;
            let prior_chirho = app_chirho::load_app_params_records_chirho(platform_root_chirho)?
                .into_iter()
                .any(|record_chirho| {
                    record_chirho.app_chirho == intent_chirho.slug_chirho
                        && record_chirho.route_chirho.is_none()
                        && record_chirho.owner_principal_chirho == owner_principal_chirho
                        && record_chirho.params_chirho == intent_chirho.params_chirho
                });
            if !prior_chirho {
                return Ok(JudgementChirho::RefuseChirho("unknown-prior-params-chirho"));
            }
            None
        }
    };
    let _ = intent_digest_chirho;
    Ok(JudgementChirho::ApplyChirho {
        owner_principal_chirho,
        template_root_dag_chirho: template_chirho.root_dag_chirho.clone(),
        response_content_type_chirho: template_chirho.response_content_type_chirho.clone(),
        new_app_chirho,
        params_value_chirho,
    })
}

/// Apply every not-yet-applied intent of one tenant, in intent order, under the platform lock.
/// Every intent ends in exactly one applied record; a tenant intent log that fails verification
/// applies NOTHING (fail closed, no partial run).
/// Part of `spec-chirho/workflows-chirho/publication-chirho/self-service-publication-chirho.md`.
pub fn apply_publication_intents_chirho(
    platform_root_chirho: &Path,
    tenant_chirho: &str,
) -> Result<PublicationApplyReportChirho> {
    if !tenant_id_for_root_chirho(platform_root_chirho)?.is_platform_root_chirho() {
        bail!("publication-apply runs on the platform root, not inside a tenant root");
    }
    let tenant_root_chirho = tenant_root_chirho(platform_root_chirho, tenant_chirho)?;
    match tenant_id_for_root_chirho(&tenant_root_chirho)? {
        TenantIdChirho::TenantChirho(id_chirho) if id_chirho == tenant_chirho => {}
        _ => bail!(
            "tenant root for '{tenant_chirho}' is not a prepared tenant of this platform root"
        ),
    }
    seqlog_chirho::with_named_lock_chirho(
        platform_root_chirho,
        PUBLICATION_APPLY_LOCK_CHIRHO,
        || {
            let intents_chirho = load_verified_publication_intents_chirho(&tenant_root_chirho)?;
            let applied_digests_chirho: BTreeSet<HashChirho> =
                load_verified_publication_applied_chirho(platform_root_chirho)?
                    .into_iter()
                    .map(|record_chirho| record_chirho.intent_digest_chirho)
                    .collect();
            let mut report_chirho = PublicationApplyReportChirho {
                schema_chirho: PUBLICATION_APPLY_REPORT_SCHEMA_CHIRHO.to_string(),
                tenant_chirho: tenant_chirho.to_string(),
                intents_seen_chirho: intents_chirho.len(),
                already_applied_chirho: 0,
                applied_chirho: 0,
                refused_chirho: 0,
                refusals_chirho: BTreeMap::new(),
            };
            for intent_chirho in &intents_chirho {
                let intent_digest_chirho = publication_intent_digest_chirho(intent_chirho)?;
                if applied_digests_chirho.contains(&intent_digest_chirho) {
                    report_chirho.already_applied_chirho += 1;
                    continue;
                }
                let user_digest_chirho =
                    publication_user_digest_chirho(&intent_chirho.user_principal_chirho);
                let judgement_chirho = judge_chirho(
                    platform_root_chirho,
                    &tenant_root_chirho,
                    tenant_chirho,
                    intent_chirho,
                    &intent_digest_chirho,
                    &user_digest_chirho,
                )?;
                match judgement_chirho {
                    JudgementChirho::RefuseChirho(code_chirho) => {
                        append_publication_applied_record_chirho(
                            platform_root_chirho,
                            PublicationAppliedInputChirho {
                                tenant_chirho: tenant_chirho.to_string(),
                                intent_digest_chirho: intent_digest_chirho.clone(),
                                user_digest_chirho: user_digest_chirho.clone(),
                                kind_chirho: intent_chirho.kind_chirho,
                                slug_chirho: intent_chirho.slug_chirho.clone(),
                                outcome_chirho: PublicationOutcomeChirho::RefusedChirho,
                                refusal_code_chirho: Some(code_chirho.to_string()),
                                params_chirho: None,
                                params_record_seq_chirho: None,
                            },
                        )?;
                        report_chirho.refused_chirho += 1;
                        *report_chirho
                            .refusals_chirho
                            .entry(code_chirho.to_string())
                            .or_insert(0) += 1;
                    }
                    JudgementChirho::ApplyChirho {
                        owner_principal_chirho,
                        template_root_dag_chirho,
                        response_content_type_chirho,
                        new_app_chirho,
                        params_value_chirho,
                    } => {
                        if new_app_chirho {
                            app_chirho::deploy_app_chirho(
                                platform_root_chirho,
                                &intent_chirho.slug_chirho,
                                template_root_dag_chirho,
                                &owner_principal_chirho,
                            )?;
                            app_chirho::set_app_input_policy_chirho(
                                platform_root_chirho,
                                &intent_chirho.slug_chirho,
                                None,
                                &owner_principal_chirho,
                                AppInputModeChirho::PlainChirho,
                            )?;
                            app_chirho::set_app_response_policy_chirho(
                                platform_root_chirho,
                                &intent_chirho.slug_chirho,
                                &owner_principal_chirho,
                                &response_content_type_chirho,
                            )?;
                            append_slug_claim_chirho(
                                platform_root_chirho,
                                &intent_chirho.slug_chirho,
                                tenant_chirho,
                                &user_digest_chirho,
                                &owner_principal_chirho,
                                &intent_digest_chirho,
                            )?;
                        }
                        let params_record_chirho = match params_value_chirho {
                            Some(value_chirho) => app_chirho::set_app_params_chirho(
                                platform_root_chirho,
                                &intent_chirho.slug_chirho,
                                None,
                                &owner_principal_chirho,
                                &value_chirho,
                                true,
                            )?,
                            None => app_chirho::set_app_params_hash_chirho(
                                platform_root_chirho,
                                &intent_chirho.slug_chirho,
                                None,
                                &owner_principal_chirho,
                                intent_chirho.params_chirho.clone(),
                                true,
                            )?,
                        };
                        if params_record_chirho.params_chirho != intent_chirho.params_chirho {
                            bail!(
                                "publication params record does not carry the intent's params hash"
                            );
                        }
                        append_publication_applied_record_chirho(
                            platform_root_chirho,
                            PublicationAppliedInputChirho {
                                tenant_chirho: tenant_chirho.to_string(),
                                intent_digest_chirho: intent_digest_chirho.clone(),
                                user_digest_chirho: user_digest_chirho.clone(),
                                kind_chirho: intent_chirho.kind_chirho,
                                slug_chirho: intent_chirho.slug_chirho.clone(),
                                outcome_chirho: PublicationOutcomeChirho::AppliedChirho,
                                refusal_code_chirho: None,
                                params_chirho: Some(params_record_chirho.params_chirho.clone()),
                                params_record_seq_chirho: Some(params_record_chirho.seq_chirho),
                            },
                        )?;
                        report_chirho.applied_chirho += 1;
                    }
                }
            }
            Ok(report_chirho)
        },
    )
}
