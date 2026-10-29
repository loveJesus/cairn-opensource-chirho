// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Self-service publication: a signed-in viewer's PUBLICATION INTENT in her tenant root (the one
//! place her approved page document leaves the private plane), and the platform-side APPLIED
//! record it becomes once the platform applier has judged it — so a page can be published,
//! republished, and rolled back from the workspace with no operator, with evidence at both ends.
//!
//! Why an intent rather than a cross-root deploy: one writer per root. The tenant service signs
//! with the tenant key and writes only the tenant root; the platform applier (`publication-apply`,
//! brick 2) signs with the platform key and is the only writer of the platform root, where the
//! slug policy is judged inside the platform's own lock. The tenant status road (`status_chirho`)
//! reads the platform's applied records back read-only, verifying them against the platform key.
//!
//! Workflow: `spec-chirho/workflows-chirho/publication-chirho/self-service-publication-chirho.md`.

use crate::model_chirho::{HashChirho, RequestContextChirho};
use crate::tenant_chirho::{tenant_id_for_root_chirho, TenantIdChirho};
use crate::{
    cas_chirho, effect_chirho, identity_chirho, resource_chirho, seqlog_chirho, store_chirho,
};
use anyhow::{anyhow, bail, Context, Result};
use cairn_core_chirho::ports_chirho::StateStoreChirho;
use cairn_signer_chirho::signer_chirho;
use cairn_store_redb_chirho::RedbStateAuditStoreChirho;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PUBLICATION_INTENT_RECORD_SCHEMA_CHIRHO: &str = "publication-intent-record-v1-chirho";
pub const PUBLICATION_INTENT_RESPONSE_SCHEMA_CHIRHO: &str = "publication-intent-response-v1-chirho";
pub const PUBLICATION_APPLIED_RECORD_SCHEMA_CHIRHO: &str = "publication-applied-record-v1-chirho";
pub const PUBLICATION_INTENTS_FILE_CHIRHO: &str = "publication-intents-chirho.jsonl";
pub const PUBLICATION_APPLIED_FILE_CHIRHO: &str = "publication-applied-chirho.jsonl";
/// The reserved `read-store` scope a tenant DAG uses to read publication status (`status_chirho`).
pub const PUBLICATION_CAPABILITY_PREFIX_CHIRHO: &str = "publication-chirho/";
pub const PUBLICATION_RESOURCE_SECTION_CHIRHO: &str = "publication-intent-chirho";
pub const PUBLICATION_RESOURCE_ACTION_CHIRHO: &str = "intend-chirho";
pub const PUBLICATION_INTENT_EFFECT_CHIRHO: &str = "publication_intent_chirho";
const PUBLICATION_INTENT_LOCK_PREFIX_CHIRHO: &str = "publication-intent-state-chirho";
const PUBLICATION_INTENT_STATE_KEY_PREFIX_CHIRHO: &str = "publication-intent-record-chirho";
const PUBLICATION_INTENT_DIGEST_CONTEXT_CHIRHO: &str = "cairn-publication-intent-digest-v1-chirho";
const PUBLICATION_USER_DIGEST_CONTEXT_CHIRHO: &str = "cairn-publication-user-digest-v1-chirho";
const MAX_PUBLICATION_REQUEST_BYTES_CHIRHO: usize = 80 * 1024;
const MAX_PUBLICATION_PARAMS_BYTES_CHIRHO: usize = 64 * 1024;
const MAX_PUBLICATION_SLUG_CHARS_CHIRHO: usize = 48;
const MAX_PUBLICATION_LOGICAL_KEY_BYTES_CHIRHO: usize = 128;

/// What the viewer asks the platform to do with her slug.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicationKindChirho {
    /// First publication of a slug: the platform creates the app under her derived owner.
    PublishChirho,
    /// A new params record on her existing app.
    RepublishChirho,
    /// A new params record naming one of her app's own PRIOR params records.
    RollbackChirho,
}

impl PublicationKindChirho {
    /// The wire word, identical to the serde form (`publish-chirho`, …), so the payload digest
    /// and the JSON never disagree about a kind's spelling.
    pub fn label_chirho(self) -> &'static str {
        match self {
            Self::PublishChirho => "publish-chirho",
            Self::RepublishChirho => "republish-chirho",
            Self::RollbackChirho => "rollback-chirho",
        }
    }
}

/// "The version she is looking at": bound at intent time against her verified head, and carried
/// to the platform so the applied record can be audited against her receipt chain. On the wire
/// the receipt digest is optional — it is a digest of engine serialization a guest should not
/// replicate (PFE #21790) — and (key, version) binds; the door fills the digest from the head it
/// verified, so every RECORDED binding carries it and a supplied one must match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationViewerStateBindingChirho {
    pub key_chirho: String,
    pub version_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_digest_chirho: Option<HashChirho>,
}

/// One signed intent row in the tenant root's append-only log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationIntentRecordChirho {
    pub seq_chirho: u64,
    pub schema_chirho: String,
    pub kind_chirho: PublicationKindChirho,
    pub user_principal_chirho: String,
    pub template_id_chirho: String,
    pub slug_chirho: String,
    /// The approved document's content address (public CAS in the tenant root for publish /
    /// republish; a prior platform params record's address for rollback).
    pub params_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub viewer_state_chirho: Option<PublicationViewerStateBindingChirho>,
    pub idempotency_key_hash_chirho: HashChirho,
    pub request_payload_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_usage_seq_chirho: Option<u64>,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

/// The platform applier's judgement of one intent (brick 2 writes it; the status road reads it).
/// The viewer is named by a digest, never by her principal, because this log lives at the
/// platform level beside every other tenant's outcomes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationAppliedRecordChirho {
    pub seq_chirho: u64,
    pub schema_chirho: String,
    pub tenant_chirho: String,
    pub intent_digest_chirho: HashChirho,
    pub user_digest_chirho: HashChirho,
    pub kind_chirho: PublicationKindChirho,
    pub slug_chirho: String,
    pub outcome_chirho: PublicationOutcomeChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_code_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params_chirho: Option<HashChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params_record_seq_chirho: Option<u64>,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicationOutcomeChirho {
    AppliedChirho,
    RefusedChirho,
}

/// The fixed refusal tokens the applier may write, so a product surface can map them to
/// customer sentences without parsing prose.
pub const PUBLICATION_REFUSAL_CODES_CHIRHO: &[&str] = &[
    "slug-reserved-chirho",
    "slug-taken-chirho",
    "not-your-app-chirho",
    "unknown-prior-params-chirho",
    "unknown-template-chirho",
    "template-not-deployable-chirho",
    "intent-invalid-chirho",
    "params-missing-chirho",
];

/// What the tenant door answers when a correctly built form arrives too late or names the wrong
/// thing — the same shape viewer-state gives a stale write: a typed body on the same road, so the
/// DAG's renderer turns it into a sentence and a "re-open and approve again" link instead of the
/// host's bare 400 (PFE #21813; L.J.'s first-beta scope makes usable errors required). Every
/// refusal here happened BEFORE admission and before any write, and records no attempt, so the
/// next form is judged afresh. Engine refusals (a request that does not decode, an unverifiable
/// platform log, admission itself) stay errors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationIntentRefusalChirho {
    pub schema_chirho: String,
    pub refusal_code_chirho: String,
    /// A fixed sentence per code; never echoes request bytes.
    pub message_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_base_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_version_chirho: Option<u64>,
    /// Only with `slug-taken-chirho`: the caller's OWN validated submitted name, echoed so the
    /// recovery form can hand it back. Never the other owner's name, and never a foreign digest —
    /// `live_base_chirho` stays `None` on an occupied-name refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug_chirho: Option<String>,
}

pub const PUBLICATION_INTENT_REFUSAL_SCHEMA_CHIRHO: &str = "publication-intent-refusal-v1-chirho";
/// The door's typed refusal codes — distinct from the applier's applied-record tokens above.
/// `slug-taken-chirho` is the SAME token the applier writes and the PFE receiver reads, so the
/// occupied-name refusal now surfaces pre-admission at the door on the very same wire.
pub const PUBLICATION_DOOR_REFUSAL_CODES_CHIRHO: &[&str] = &[
    "base-moved-chirho",
    "version-stale-chirho",
    "no-saved-version-chirho",
    "saved-version-not-a-document-chirho",
    "request-invalid-chirho",
    "slug-taken-chirho",
];

fn refusal_bytes_chirho(
    code_chirho: &str,
    message_chirho: &str,
    live_base_chirho: Option<String>,
    head_version_chirho: Option<u64>,
    slug_chirho: Option<String>,
) -> Result<Vec<u8>> {
    debug_assert!(PUBLICATION_DOOR_REFUSAL_CODES_CHIRHO.contains(&code_chirho));
    Ok(serde_json::to_vec(&PublicationIntentRefusalChirho {
        schema_chirho: PUBLICATION_INTENT_REFUSAL_SCHEMA_CHIRHO.to_string(),
        refusal_code_chirho: code_chirho.to_string(),
        message_chirho: message_chirho.to_string(),
        live_base_chirho,
        head_version_chirho,
        slug_chirho,
    })?)
}

/// What the tenant door answers: the intent as recorded, `applied_chirho` always false here —
/// the platform's answer arrives through the status road.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationIntentResponseChirho {
    pub schema_chirho: String,
    pub intent_digest_chirho: HashChirho,
    pub seq_chirho: u64,
    pub kind_chirho: PublicationKindChirho,
    pub slug_chirho: String,
    pub app_chirho: String,
    pub address_chirho: String,
    pub params_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub viewer_state_chirho: Option<PublicationViewerStateBindingChirho>,
    pub at_ms_chirho: u64,
    pub applied_chirho: bool,
}

/// The request the workspace DAG hands the `template-app-deploy` card on a tenant root. Every
/// addition over the platform-root request is optional, so today's request still parses. Unknown
/// fields refuse, EXCEPT the two the served plain-input path injects into every JSON object body
/// (`user_principal_chirho` from the verified session, `app_params_chirho` when the workspace app
/// has params) — named here so a served request is not refused as invalid, and the principal is
/// checked against the session rather than trusted (the served two-root proof found the refusal).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationIntentRequestChirho {
    #[serde(default)]
    schema_chirho: String,
    #[serde(default)]
    user_principal_chirho: Option<String>,
    #[serde(default)]
    app_params_chirho: Option<Value>,
    /// The approval base (PFE gpt #21794): the slug's live applied intent digest as the status
    /// road rendered it into the form, or `dark-chirho`. Part of the attempt identity, and an
    /// expected-before check against the live state — never an implicit lookup at POST time.
    #[serde(default)]
    base_publication_chirho: Option<String>,
    #[serde(default = "default_kind_chirho")]
    kind_chirho: PublicationKindChirho,
    slug_chirho: String,
    idem_key_chirho: String,
    #[serde(default)]
    params_chirho: Option<Value>,
    #[serde(default)]
    params_hash_chirho: Option<HashChirho>,
    #[serde(default)]
    viewer_state_chirho: Option<PublicationViewerStateBindingChirho>,
    #[serde(default)]
    template_id_chirho: Option<String>,
    #[serde(default)]
    owner_principal_chirho: Option<String>,
}

fn default_kind_chirho() -> PublicationKindChirho {
    PublicationKindChirho::PublishChirho
}

/// `params_chirho` is `None` exactly for a publish/republish under a version binding: the
/// document is then her verified head's own bytes, resolved inside the viewer-state lock.
#[derive(Clone, Debug)]
struct ValidatedPublicationIntentChirho {
    kind_chirho: PublicationKindChirho,
    slug_chirho: String,
    idem_key_chirho: String,
    params_value_chirho: Option<Value>,
    params_chirho: Option<HashChirho>,
    viewer_state_chirho: Option<PublicationViewerStateBindingChirho>,
    base_publication_chirho: Option<String>,
    request_payload_chirho: HashChirho,
}

pub fn publication_intents_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(PUBLICATION_INTENTS_FILE_CHIRHO)
}

pub fn publication_applied_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(PUBLICATION_APPLIED_FILE_CHIRHO)
}

fn publication_intent_state_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("publication-intent-state-chirho.redb")
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

fn derive_digest_chirho(context_chirho: &str, material_chirho: &[u8]) -> HashChirho {
    let mut hasher_chirho = blake3::Hasher::new_derive_key(context_chirho);
    hasher_chirho.update(material_chirho);
    HashChirho(hasher_chirho.finalize().to_hex().to_string())
}

/// The digest the platform names an intent by: over the SIGNED message, so it binds every field
/// and the signature's absence would change nothing a forger could exploit.
pub fn publication_intent_digest_chirho(
    record_chirho: &PublicationIntentRecordChirho,
) -> Result<HashChirho> {
    let message_chirho = publication_intent_message_chirho(record_chirho)?;
    Ok(derive_digest_chirho(
        PUBLICATION_INTENT_DIGEST_CONTEXT_CHIRHO,
        &message_chirho,
    ))
}

/// How a platform-level record names a viewer without carrying her principal.
pub fn publication_user_digest_chirho(user_principal_chirho: &str) -> HashChirho {
    derive_digest_chirho(
        PUBLICATION_USER_DIGEST_CONTEXT_CHIRHO,
        user_principal_chirho.as_bytes(),
    )
}

pub fn publication_address_chirho(slug_chirho: &str) -> String {
    format!("/app-chirho/{slug_chirho}/")
}

fn publication_intent_message_chirho(
    record_chirho: &PublicationIntentRecordChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.sig_chirho = String::new();
    serde_json::to_vec(&unsigned_chirho).context("encode publication intent message")
}

fn publication_applied_message_chirho(
    record_chirho: &PublicationAppliedRecordChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.sig_chirho = String::new();
    serde_json::to_vec(&unsigned_chirho).context("encode publication applied message")
}

/// Slug grammar: 1..=48 of `[a-z0-9-]`, no edge dash — the same rule the platform-root door
/// applies, restated here because on the tenant path the slug becomes the app NAME.
pub fn validate_publication_slug_chirho(slug_chirho: &str) -> Result<()> {
    if slug_chirho.is_empty() || slug_chirho.len() > MAX_PUBLICATION_SLUG_CHARS_CHIRHO {
        bail!("slug_chirho must be 1..={MAX_PUBLICATION_SLUG_CHARS_CHIRHO} chars");
    }
    if slug_chirho.starts_with('-') || slug_chirho.ends_with('-') {
        bail!("slug_chirho must not start or end with '-'");
    }
    if !slug_chirho.chars().all(|ch_chirho| {
        ch_chirho.is_ascii_lowercase() || ch_chirho.is_ascii_digit() || ch_chirho == '-'
    }) {
        bail!("slug_chirho must contain only lowercase ascii letters, digits, and '-'");
    }
    Ok(())
}

fn validate_hex_hash_chirho(label_chirho: &str, hash_chirho: &HashChirho) -> Result<()> {
    if hash_chirho.0.len() != 64
        || !hash_chirho
            .0
            .bytes()
            .all(|b_chirho| b_chirho.is_ascii_hexdigit())
    {
        bail!("{label_chirho} must be a 64-character hex content address");
    }
    if hash_chirho
        .0
        .bytes()
        .any(|b_chirho| b_chirho.is_ascii_uppercase())
    {
        bail!("{label_chirho} must be lowercase hex");
    }
    Ok(())
}

/// A claimed principal that disagrees with the signed-in session is tamper-shaped, never a
/// customer situation: it is an engine refusal (the host's bare refusal), checked before the
/// request shape is judged and before any typed refusal could be answered.
fn refuse_foreign_principal_claim_chirho(
    session_principal_chirho: &str,
    request_bytes_chirho: &[u8],
) -> Result<()> {
    if request_bytes_chirho.len() > MAX_PUBLICATION_REQUEST_BYTES_CHIRHO {
        bail!("publication intent request too large");
    }
    let Ok(value_chirho) = serde_json::from_slice::<Value>(request_bytes_chirho) else {
        return Ok(());
    };
    if let Some(claimed_chirho) = value_chirho
        .get("user_principal_chirho")
        .and_then(Value::as_str)
    {
        if claimed_chirho != session_principal_chirho {
            bail!("user_principal_chirho in the request does not match the signed-in session");
        }
    }
    Ok(())
}

fn validate_request_chirho(
    template_id_chirho: &str,
    request_bytes_chirho: &[u8],
) -> Result<ValidatedPublicationIntentChirho> {
    if request_bytes_chirho.len() > MAX_PUBLICATION_REQUEST_BYTES_CHIRHO {
        bail!("publication intent request too large");
    }
    let request_chirho: PublicationIntentRequestChirho =
        serde_json::from_slice(request_bytes_chirho)
            .context("decode publication intent request")?;
    let _served_principal_chirho = request_chirho.user_principal_chirho;
    let _served_app_params_chirho = request_chirho.app_params_chirho;
    if !request_chirho.schema_chirho.is_empty()
        && request_chirho.schema_chirho != "template-app-deploy-request-v1-chirho"
    {
        bail!(
            "unsupported publication intent request schema '{}'",
            request_chirho.schema_chirho
        );
    }
    if let Some(request_template_chirho) = request_chirho.template_id_chirho.as_deref() {
        if request_template_chirho != template_id_chirho {
            bail!("template_id_chirho in request does not match capability template_id_chirho");
        }
    }
    let _ignored_owner_chirho = request_chirho.owner_principal_chirho;
    validate_publication_slug_chirho(&request_chirho.slug_chirho)?;
    cairn_model_app_chirho::validate_app_name_chirho(&request_chirho.slug_chirho)
        .context("a publication slug is the app name the platform will serve")?;
    crate::app_chirho::validate_short_id_chirho(
        "idem_key_chirho",
        &request_chirho.idem_key_chirho,
    )?;
    if let Some(binding_chirho) = &request_chirho.viewer_state_chirho {
        if binding_chirho.key_chirho.is_empty()
            || binding_chirho.key_chirho.len() > MAX_PUBLICATION_LOGICAL_KEY_BYTES_CHIRHO
        {
            bail!("viewer_state_chirho.key_chirho must be 1..={MAX_PUBLICATION_LOGICAL_KEY_BYTES_CHIRHO} bytes");
        }
        if let Some(receipt_digest_chirho) = &binding_chirho.receipt_digest_chirho {
            validate_hex_hash_chirho(
                "viewer_state_chirho.receipt_digest_chirho",
                receipt_digest_chirho,
            )?;
        }
    }
    let (params_value_chirho, params_chirho) = match request_chirho.kind_chirho {
        PublicationKindChirho::PublishChirho | PublicationKindChirho::RepublishChirho => {
            if request_chirho.params_hash_chirho.is_some() {
                bail!("params_hash_chirho is only for rollback; publish and republish carry params_chirho");
            }
            // R1 (PFE #21767, pick b): with a version binding the document is NOT on the wire —
            // the door takes it from her verified head — so a document beside a binding is
            // refused rather than compared. One road per shape.
            match (
                request_chirho.viewer_state_chirho.is_some(),
                request_chirho.params_chirho,
            ) {
                (true, Some(_)) => {
                    bail!("send the version binding or the document, not both: with viewer_state_chirho the door publishes exactly the saved version");
                }
                (true, None) => (None, None),
                (false, None) => {
                    bail!("params_chirho is required to publish or republish without a version binding")
                }
                (false, Some(value_chirho)) => {
                    let hash_chirho = validated_publication_document_chirho(&value_chirho)?;
                    (Some(value_chirho), Some(hash_chirho))
                }
            }
        }
        PublicationKindChirho::RollbackChirho => {
            if request_chirho.params_chirho.is_some() {
                bail!("rollback names a prior params_hash_chirho and carries no params_chirho");
            }
            let hash_chirho = request_chirho
                .params_hash_chirho
                .ok_or_else(|| anyhow!("rollback requires params_hash_chirho"))?;
            validate_hex_hash_chirho("params_hash_chirho", &hash_chirho)?;
            (None, Some(hash_chirho))
        }
    };
    if let Some(base_chirho) = request_chirho.base_publication_chirho.as_deref() {
        validate_publication_base_chirho(base_chirho)?;
    }
    let request_payload_chirho = request_payload_digest_chirho(
        template_id_chirho,
        request_chirho.kind_chirho,
        &request_chirho.slug_chirho,
        &request_chirho.idem_key_chirho,
        params_chirho.as_ref(),
        request_chirho.viewer_state_chirho.as_ref(),
        request_chirho.base_publication_chirho.as_deref(),
    )?;
    Ok(ValidatedPublicationIntentChirho {
        kind_chirho: request_chirho.kind_chirho,
        slug_chirho: request_chirho.slug_chirho,
        idem_key_chirho: request_chirho.idem_key_chirho,
        params_value_chirho,
        params_chirho,
        viewer_state_chirho: request_chirho.viewer_state_chirho,
        base_publication_chirho: request_chirho.base_publication_chirho,
        request_payload_chirho,
    })
}

/// An approval base is exactly what the status road renders: an applied intent digest (64 hex)
/// or the dark marker. Anything else is refused as invalid rather than treated as unbound.
fn validate_publication_base_chirho(base_chirho: &str) -> Result<()> {
    if base_chirho == status_chirho::DARK_PUBLICATION_BASE_CHIRHO {
        return Ok(());
    }
    validate_hex_hash_chirho(
        "base_publication_chirho",
        &HashChirho(base_chirho.to_string()),
    )
    .context("base_publication_chirho must be an applied intent digest or dark-chirho")
}

fn request_payload_digest_chirho(
    template_id_chirho: &str,
    kind_chirho: PublicationKindChirho,
    slug_chirho: &str,
    idem_key_chirho: &str,
    params_chirho: Option<&HashChirho>,
    viewer_state_chirho: Option<&PublicationViewerStateBindingChirho>,
    base_publication_chirho: Option<&str>,
) -> Result<HashChirho> {
    // A binding-shaped publish carries no document hash (JSON null here, a string otherwise),
    // so the two shapes can never collide on one idempotency key.
    let material_chirho = serde_json::to_vec(&serde_json::json!({
        "template_id_chirho": template_id_chirho,
        "kind_chirho": kind_chirho.label_chirho(),
        "slug_chirho": slug_chirho,
        "idem_key_chirho": idem_key_chirho,
        "params_chirho": params_chirho.map(|hash_chirho| hash_chirho.0.as_str()),
        "viewer_state_chirho": viewer_state_chirho,
        "base_publication_chirho": base_publication_chirho,
    }))?;
    Ok(HashChirho(
        blake3::hash(&material_chirho).to_hex().to_string(),
    ))
}

/// The one rule for a publication document wherever it comes from — the request, or her saved
/// head: a JSON object within the size bound; its content address is what the intent names.
fn validated_publication_document_chirho(value_chirho: &Value) -> Result<HashChirho> {
    if !value_chirho.is_object() {
        bail!("a publication document must be a JSON object");
    }
    let bytes_chirho = serde_json::to_vec(value_chirho)?;
    if bytes_chirho.len() > MAX_PUBLICATION_PARAMS_BYTES_CHIRHO {
        bail!("the publication document is too large");
    }
    store_chirho::hash_object_chirho(value_chirho)
}

/// The attempt identity: her principal, her idempotency key, and the approval base the form
/// carried (PFE gpt #21788/#21794). Without the third term a form that derives its key from
/// (kind, slug, version) deduplicates a fresh approval after the live state changed — publish v1,
/// republish v2, roll back to v1, republish v2 again — and the second act is swallowed as a
/// replay of the first. The base is EXPLICIT in the request, never looked up at POST time: an
/// exact retry therefore replays the original receipt however late it arrives, and only a form
/// rendered against a newer base is a new attempt. A request with no base keeps the plain
/// (principal, key) identity.
fn idempotency_hash_chirho(
    user_principal_chirho: &str,
    idem_key_chirho: &str,
    base_publication_chirho: Option<&str>,
) -> HashChirho {
    let material_chirho = match base_publication_chirho {
        Some(base_chirho) => format!("{user_principal_chirho}\n{idem_key_chirho}\n{base_chirho}"),
        None => format!("{user_principal_chirho}\n{idem_key_chirho}"),
    };
    HashChirho(
        blake3::hash(material_chirho.as_bytes())
            .to_hex()
            .to_string(),
    )
}

fn short_hash_chirho(value_chirho: &str) -> String {
    cas_chirho::hash_chirho(value_chirho.as_bytes()).0[..16].to_string()
}

fn state_key_chirho(user_principal_chirho: &str, idem_hash_chirho: &HashChirho) -> String {
    format!(
        "{PUBLICATION_INTENT_STATE_KEY_PREFIX_CHIRHO}/{}/{}",
        short_hash_chirho(user_principal_chirho),
        idem_hash_chirho.0
    )
}

fn mutation_id_chirho(user_principal_chirho: &str, idem_hash_chirho: &HashChirho) -> String {
    format!(
        "{PUBLICATION_INTENT_EFFECT_CHIRHO}:{}:{}",
        short_hash_chirho(user_principal_chirho),
        idem_hash_chirho.0
    )
}

fn ensure_user_principal_chirho(root_chirho: &Path, principal_chirho: &str) -> Result<()> {
    let identity_chirho = identity_chirho::find_identity_chirho(root_chirho, principal_chirho)?
        .ok_or_else(|| anyhow!("unknown user principal '{principal_chirho}'"))?;
    if identity_chirho.kind_chirho != identity_chirho::PrincipalKindChirho::UserChirho {
        bail!("publication intents require a UserChirho session principal");
    }
    Ok(())
}

/// The tenant-side door. Reached from `template-app-deploy` on a TENANT root; the platform-root
/// path is the direct deploy in `template_app_deploy_chirho`.
///
/// Order, and why: session and template id first; the request validated before anything is
/// read; the idempotent replay answered before any state changes; resource admission recorded;
/// her verified head compared to the version she named BEFORE the declassifying CAS write, so a
/// stale act writes nothing public; then the params object, then the signed intent, then the
/// apply-once mark. Everything here stays inside the tenant root.
pub fn run_publication_intent_effect_chirho(
    root_chirho: &Path,
    template_id_chirho: &str,
    request_bytes_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<Vec<u8>> {
    let context_chirho = request_context_chirho
        .ok_or_else(|| anyhow!("publication intents require a signed-in app session"))?;
    ensure_user_principal_chirho(root_chirho, &context_chirho.user_principal_chirho)?;
    crate::app_chirho::validate_template_id_chirho(template_id_chirho)?;
    refuse_foreign_principal_claim_chirho(
        &context_chirho.user_principal_chirho,
        request_bytes_chirho,
    )?;
    let validated_chirho = match validate_request_chirho(template_id_chirho, request_bytes_chirho) {
        Ok(validated_chirho) => validated_chirho,
        Err(_error_chirho) => return refusal_bytes_chirho(
            "request-invalid-chirho",
            "This publication request could not be understood; re-open the page and approve again.",
            None,
            None,
            None,
        ),
    };
    let lock_name_chirho = format!(
        "{PUBLICATION_INTENT_LOCK_PREFIX_CHIRHO}-{}",
        short_hash_chirho(&context_chirho.user_principal_chirho)
    );
    let idem_hash_chirho = idempotency_hash_chirho(
        &context_chirho.user_principal_chirho,
        &validated_chirho.idem_key_chirho,
        validated_chirho.base_publication_chirho.as_deref(),
    );
    seqlog_chirho::with_named_lock_chirho(root_chirho, &lock_name_chirho, || {
        run_locked_chirho(
            root_chirho,
            template_id_chirho,
            context_chirho,
            validated_chirho,
            idem_hash_chirho,
        )
    })
}

/// Her verified current head version for the page a publication binds, or `None` when the request
/// carries no version binding or the key has no saved version. Read-only and viewer-scoped: it
/// reads only THIS viewer's head (never the submitted version), so an occupied-name refusal can
/// state a head the page did not invent without reading or trusting anything of another account's.
fn verified_head_version_for_binding_chirho(
    root_chirho: &Path,
    context_chirho: &RequestContextChirho,
    binding_chirho: Option<&PublicationViewerStateBindingChirho>,
) -> Result<Option<u64>> {
    let Some(binding_chirho) = binding_chirho else {
        return Ok(None);
    };
    effect_chirho::with_verified_head_value_for_key_chirho(
        root_chirho,
        context_chirho,
        &binding_chirho.key_chirho,
        |head_chirho| Ok(head_chirho.map(|head_chirho| head_chirho.head_chirho.version_chirho)),
    )
}

fn run_locked_chirho(
    root_chirho: &Path,
    template_id_chirho: &str,
    context_chirho: &RequestContextChirho,
    validated_chirho: ValidatedPublicationIntentChirho,
    idem_hash_chirho: HashChirho,
) -> Result<Vec<u8>> {
    let store_chirho =
        RedbStateAuditStoreChirho::open_chirho(&publication_intent_state_path_chirho(root_chirho))?;
    let mutation_id_chirho =
        mutation_id_chirho(&context_chirho.user_principal_chirho, &idem_hash_chirho);
    let state_key_chirho =
        state_key_chirho(&context_chirho.user_principal_chirho, &idem_hash_chirho);
    if store_chirho
        .is_applied_chirho(&mutation_id_chirho)
        .map_err(|error_chirho| anyhow!("read publication intent idempotency: {error_chirho}"))?
    {
        let record_chirho =
            load_record_from_state_chirho(root_chirho, &store_chirho, &state_key_chirho)?;
        ensure_replay_matches_chirho(&record_chirho, &validated_chirho)?;
        return response_bytes_chirho(&record_chirho);
    }

    // Eligibility runs BEFORE billable admission (PFE gpt #21810): a refused attempt — an occupied
    // name, a stale base, a stale version, a saved object that is no document — must not consume her
    // publication allowance. Admission is the last step before the writes, inside the same hold.
    //
    // Occupied name (the full-publication RED, CAIRN #24144 / Model B): resolve the slug against the
    // platform's canonical ownership model (verified claims + deployed-app ownership), READ-ONLY,
    // before the base comparison and before admission, so a name a different account already holds
    // is refused `slug-taken-chirho` here — pre-admission, no attempt recorded — and WITHOUT echoing
    // the other owner's live digest. This scans the full verified platform histories (honest
    // O(total history); growth is left open) and shares its decision with the applier's
    // `judge_chirho`, so the door refuses exactly what the applier would. It fires UNCONDITIONALLY:
    // an occupied slug refuses even a base-less publication.
    let platform_root_chirho = status_chirho::applied_records_root_chirho(root_chirho)?;
    let tenant_label_chirho = match tenant_id_for_root_chirho(root_chirho)? {
        TenantIdChirho::TenantChirho(id_chirho) => id_chirho,
        TenantIdChirho::PlatformRootChirho => {
            bail!("the publication intent door is a tenant-root road; it has no platform intents")
        }
    };
    let user_digest_chirho = publication_user_digest_chirho(&context_chirho.user_principal_chirho);
    let requester_holds_slug_chirho = match apply_chirho::slug_occupancy_for_requester_chirho(
        &platform_root_chirho,
        &validated_chirho.slug_chirho,
        &tenant_label_chirho,
        &user_digest_chirho,
    )? {
        apply_chirho::SlugOccupancyChirho::OccupiedByAnotherChirho => {
            // Her OWN validated submitted slug and her OWN verified head version (never the
            // submitted one) go back so the recovery form can offer a fresh name;
            // `live_base_chirho = None` — no foreign digest crosses the door.
            let head_version_chirho = verified_head_version_for_binding_chirho(
                root_chirho,
                context_chirho,
                validated_chirho.viewer_state_chirho.as_ref(),
            )?;
            return refusal_bytes_chirho(
                "slug-taken-chirho",
                "That address belongs to another account; choose a different address and approve again.",
                None,
                head_version_chirho,
                Some(validated_chirho.slug_chirho.clone()),
            );
        }
        // She may proceed. Whether she ALREADY holds this slug (a claim or a deployed app of her
        // own) decides her approval base below: her own latest applied digest, or `dark-chirho`
        // for a name she does not yet hold.
        apply_chirho::SlugOccupancyChirho::AvailableToRequesterChirho {
            claim_exists_chirho,
            app_exists_chirho,
        } => claim_exists_chirho || app_exists_chirho,
    };

    // Expected-before on the approval base: a NEW attempt whose base is no longer the slug's live
    // identity — as SHE holds it — was approved against a view the address has moved past; refuse
    // before any write. The live base is scoped to HER OWN latest applied digest, or `dark-chirho`
    // for a slug she does not hold, so a base-moved refusal never carries another owner's digest.
    // (A replay never reaches here: it was answered above from the recorded attempt.)
    if let Some(base_chirho) = validated_chirho.base_publication_chirho.as_deref() {
        let live_chirho = if requester_holds_slug_chirho {
            status_chirho::live_identity_for_slug_for_viewer_chirho(
                root_chirho,
                &validated_chirho.slug_chirho,
                &user_digest_chirho,
                &tenant_label_chirho,
            )?
        } else {
            status_chirho::DARK_PUBLICATION_BASE_CHIRHO.to_string()
        };
        if base_chirho != live_chirho {
            return refusal_bytes_chirho(
                "base-moved-chirho",
                "This address changed after the page was opened; re-open it and approve again.",
                Some(live_chirho),
                None,
                None,
            );
        }
    }

    let Some(binding_chirho) = &validated_chirho.viewer_state_chirho else {
        // No binding: the document (or the prior record a rollback names) came with the request.
        let params_chirho = validated_chirho
            .params_chirho
            .clone()
            .ok_or_else(|| anyhow!("a publication without a version binding names its document"))?;
        let resource_usage_seq_chirho =
            record_resource_admission_chirho(root_chirho, context_chirho, &idem_hash_chirho)?;
        return declassify_and_append_chirho(
            root_chirho,
            template_id_chirho,
            context_chirho,
            &validated_chirho,
            &idem_hash_chirho,
            resource_usage_seq_chirho,
            validated_chirho.params_value_chirho.clone(),
            params_chirho,
            &store_chirho,
            &mutation_id_chirho,
            &state_key_chirho,
        );
    };

    // The version she is looking at must still be her head, and — the linearization point —
    // the declassifying write and the intent append happen INSIDE the viewer-state lock that
    // read it, so a save of hers cannot land between the head this intent binds and the intent
    // itself (PFE #21787). A stale act refuses before anything public is written; a refusal,
    // not a conflict body — the DAG read the head a moment earlier, so a mismatch is a race and
    // the page re-renders from a fresh read.
    effect_chirho::with_verified_head_value_for_key_chirho(
        root_chirho,
        context_chirho,
        &binding_chirho.key_chirho,
        |head_chirho| {
            let Some(head_chirho) = head_chirho else {
                return refusal_bytes_chirho(
                    "no-saved-version-chirho",
                    "Nothing is saved under this page yet; save a version and approve again.",
                    None,
                    None,
                    None,
                );
            };
            if head_chirho.head_chirho.version_chirho != binding_chirho.version_chirho
                || binding_chirho.receipt_digest_chirho.as_ref().is_some_and(
                    |receipt_digest_chirho| {
                        receipt_digest_chirho != &head_chirho.head_chirho.receipt_digest_chirho
                    },
                )
            {
                return refusal_bytes_chirho(
                    "version-stale-chirho",
                    "The page was saved again after this approval was opened; re-open it and approve the current version.",
                    None,
                    Some(head_chirho.head_chirho.version_chirho),
                    None,
                );
            }
            // The recorded binding always carries the receipt digest of the head that was
            // verified, whether or not the request supplied it.
            let mut validated_chirho = validated_chirho.clone();
            validated_chirho.viewer_state_chirho = Some(PublicationViewerStateBindingChirho {
                key_chirho: binding_chirho.key_chirho.clone(),
                version_chirho: binding_chirho.version_chirho,
                receipt_digest_chirho: Some(head_chirho.head_chirho.receipt_digest_chirho.clone()),
            });
            let finish_chirho = |document_chirho: Option<Value>, params_chirho: HashChirho| {
                // Every eligibility check has passed under the hold; only now is the attempt
                // billable, and the writes follow in the same hold.
                let resource_usage_seq_chirho = record_resource_admission_chirho(
                    root_chirho,
                    context_chirho,
                    &idem_hash_chirho,
                )?;
                declassify_and_append_chirho(
                    root_chirho,
                    template_id_chirho,
                    context_chirho,
                    &validated_chirho,
                    &idem_hash_chirho,
                    resource_usage_seq_chirho,
                    document_chirho,
                    params_chirho,
                    &store_chirho,
                    &mutation_id_chirho,
                    &state_key_chirho,
                )
            };
            match validated_chirho.params_chirho.clone() {
                // A rollback under a binding names a prior record; the head only had to match.
                Some(params_chirho) => {
                    finish_chirho(validated_chirho.params_value_chirho.clone(), params_chirho)
                }
                // Publish / republish under a binding (R1, pick b): the document IS the bytes of
                // the version she approved — never client-supplied — so the published object is
                // version N by construction.
                None => {
                    let document_chirho =
                        serde_json::from_slice::<Value>(&head_chirho.value_chirho)
                            .ok()
                            .and_then(|document_chirho| {
                                validated_publication_document_chirho(&document_chirho)
                                    .ok()
                                    .map(|params_chirho| (document_chirho, params_chirho))
                            });
                    let Some((document_chirho, params_chirho)) = document_chirho else {
                        return refusal_bytes_chirho(
                            "saved-version-not-a-document-chirho",
                            "The saved version is not a page document and cannot be published.",
                            None,
                            Some(head_chirho.head_chirho.version_chirho),
                            None,
                        );
                    };
                    finish_chirho(Some(document_chirho), params_chirho)
                }
            }
        },
    )
}

/// The tail every shape shares: the declassification act (the document becomes a PUBLIC object
/// of the tenant root, named by the hash the intent carries — nothing else in the workspace
/// writes public bytes of her page), the signed intent, and the apply-once mark.
#[allow(clippy::too_many_arguments)]
fn declassify_and_append_chirho(
    root_chirho: &Path,
    template_id_chirho: &str,
    context_chirho: &RequestContextChirho,
    validated_chirho: &ValidatedPublicationIntentChirho,
    idem_hash_chirho: &HashChirho,
    resource_usage_seq_chirho: Option<u64>,
    document_chirho: Option<Value>,
    params_chirho: HashChirho,
    store_chirho: &RedbStateAuditStoreChirho,
    mutation_id_chirho: &str,
    state_key_chirho: &str,
) -> Result<Vec<u8>> {
    if let Some(document_chirho) = &document_chirho {
        let stored_chirho = store_chirho::put_object_chirho(root_chirho, document_chirho)?;
        if stored_chirho != params_chirho {
            bail!("publication params content address mismatch");
        }
    }
    let record_chirho = append_intent_chirho(
        root_chirho,
        PublicationIntentInputChirho {
            kind_chirho: validated_chirho.kind_chirho,
            user_principal_chirho: context_chirho.user_principal_chirho.clone(),
            template_id_chirho: template_id_chirho.to_string(),
            slug_chirho: validated_chirho.slug_chirho.clone(),
            params_chirho,
            viewer_state_chirho: validated_chirho.viewer_state_chirho.clone(),
            idempotency_key_hash_chirho: idem_hash_chirho.clone(),
            request_payload_chirho: validated_chirho.request_payload_chirho.clone(),
            resource_usage_seq_chirho,
        },
    )?;
    let record_bytes_chirho = serde_json::to_vec(&record_chirho)?;
    let applied_chirho = store_chirho
        .apply_once_chirho(mutation_id_chirho, state_key_chirho, &record_bytes_chirho)
        .map_err(|error_chirho| anyhow!("apply publication intent once: {error_chirho}"))?;
    if !applied_chirho {
        let record_chirho =
            load_record_from_state_chirho(root_chirho, store_chirho, state_key_chirho)?;
        ensure_replay_matches_chirho(&record_chirho, validated_chirho)?;
        return response_bytes_chirho(&record_chirho);
    }
    response_bytes_chirho(&record_chirho)
}

fn record_resource_admission_chirho(
    root_chirho: &Path,
    context_chirho: &RequestContextChirho,
    run_chirho: &HashChirho,
) -> Result<Option<u64>> {
    let usage_chirho = resource_chirho::record_resource_usage_chirho(
        root_chirho,
        resource_chirho::ResourceUsageInputChirho {
            app_chirho: context_chirho.app_chirho.clone(),
            user_chirho: context_chirho.user_principal_chirho.clone(),
            actor_chirho: Some(context_chirho.user_principal_chirho.clone()),
            section_chirho: PUBLICATION_RESOURCE_SECTION_CHIRHO.to_string(),
            action_chirho: PUBLICATION_RESOURCE_ACTION_CHIRHO.to_string(),
            effect_chirho: Some(PUBLICATION_INTENT_EFFECT_CHIRHO.to_string()),
            run_chirho: Some(run_chirho.clone()),
            bridges_chirho: Vec::new(),
        },
    )?;
    if let resource_chirho::ResourceDecisionChirho::RoutedChirho { .. } =
        usage_chirho.decision_chirho
    {
        bail!("publication resource admission routed this intent; nothing was recorded");
    }
    Ok(Some(usage_chirho.seq_chirho))
}

struct PublicationIntentInputChirho {
    kind_chirho: PublicationKindChirho,
    user_principal_chirho: String,
    template_id_chirho: String,
    slug_chirho: String,
    params_chirho: HashChirho,
    viewer_state_chirho: Option<PublicationViewerStateBindingChirho>,
    idempotency_key_hash_chirho: HashChirho,
    request_payload_chirho: HashChirho,
    resource_usage_seq_chirho: Option<u64>,
}

fn append_intent_chirho(
    root_chirho: &Path,
    input_chirho: PublicationIntentInputChirho,
) -> Result<PublicationIntentRecordChirho> {
    let path_chirho = publication_intents_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        let mut record_chirho = PublicationIntentRecordChirho {
            seq_chirho,
            schema_chirho: PUBLICATION_INTENT_RECORD_SCHEMA_CHIRHO.to_string(),
            kind_chirho: input_chirho.kind_chirho,
            user_principal_chirho: input_chirho.user_principal_chirho.clone(),
            template_id_chirho: input_chirho.template_id_chirho.clone(),
            slug_chirho: input_chirho.slug_chirho.clone(),
            params_chirho: input_chirho.params_chirho.clone(),
            viewer_state_chirho: input_chirho.viewer_state_chirho.clone(),
            idempotency_key_hash_chirho: input_chirho.idempotency_key_hash_chirho.clone(),
            request_payload_chirho: input_chirho.request_payload_chirho.clone(),
            resource_usage_seq_chirho: input_chirho.resource_usage_seq_chirho,
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = publication_intent_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

fn ensure_replay_matches_chirho(
    record_chirho: &PublicationIntentRecordChirho,
    validated_chirho: &ValidatedPublicationIntentChirho,
) -> Result<()> {
    if record_chirho.request_payload_chirho != validated_chirho.request_payload_chirho {
        bail!("publication idempotency key reused with different request bytes");
    }
    Ok(())
}

fn load_record_from_state_chirho(
    root_chirho: &Path,
    store_chirho: &RedbStateAuditStoreChirho,
    state_key_chirho: &str,
) -> Result<PublicationIntentRecordChirho> {
    let bytes_chirho = store_chirho
        .get_state_chirho(state_key_chirho)
        .map_err(|error_chirho| anyhow!("read publication intent state: {error_chirho}"))?
        .ok_or_else(|| anyhow!("publication intent state missing after idempotency hit"))?;
    let record_chirho: PublicationIntentRecordChirho = serde_json::from_slice(&bytes_chirho)?;
    let verified_chirho = load_verified_publication_intents_chirho(root_chirho)?;
    if !verified_chirho
        .iter()
        .any(|candidate_chirho| candidate_chirho == &record_chirho)
    {
        bail!("publication intent state points at an unverified intent record");
    }
    Ok(record_chirho)
}

fn response_bytes_chirho(record_chirho: &PublicationIntentRecordChirho) -> Result<Vec<u8>> {
    serde_json::to_vec(&PublicationIntentResponseChirho {
        schema_chirho: PUBLICATION_INTENT_RESPONSE_SCHEMA_CHIRHO.to_string(),
        intent_digest_chirho: publication_intent_digest_chirho(record_chirho)?,
        seq_chirho: record_chirho.seq_chirho,
        kind_chirho: record_chirho.kind_chirho,
        slug_chirho: record_chirho.slug_chirho.clone(),
        app_chirho: record_chirho.slug_chirho.clone(),
        address_chirho: publication_address_chirho(&record_chirho.slug_chirho),
        params_chirho: record_chirho.params_chirho.clone(),
        viewer_state_chirho: record_chirho.viewer_state_chirho.clone(),
        at_ms_chirho: record_chirho.at_ms_chirho,
        applied_chirho: false,
    })
    .context("encode PublicationIntentResponseChirho")
}

pub fn load_publication_intents_chirho(
    root_chirho: &Path,
) -> Result<Vec<PublicationIntentRecordChirho>> {
    load_jsonl_chirho(
        &publication_intents_path_chirho(root_chirho),
        "publication intent",
    )
}

pub fn load_publication_applied_chirho(
    root_chirho: &Path,
) -> Result<Vec<PublicationAppliedRecordChirho>> {
    load_jsonl_chirho(
        &publication_applied_path_chirho(root_chirho),
        "publication applied",
    )
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

/// Every intent verified in one pass: dense seqs, schema, a known user principal, a params object
/// present in the tenant CAS for publish/republish, one idempotency key per user, and the tenant
/// signature. Returns the records so a caller never routes on a row this did not check.
pub fn load_verified_publication_intents_chirho(
    root_chirho: &Path,
) -> Result<Vec<PublicationIntentRecordChirho>> {
    let records_chirho = load_publication_intents_chirho(root_chirho)?;
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let mut seen_idem_chirho = BTreeSet::new();
    for (index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!("publication intent seq gap at index {index_chirho}");
        }
        if record_chirho.schema_chirho != PUBLICATION_INTENT_RECORD_SCHEMA_CHIRHO {
            bail!(
                "unsupported publication intent schema '{}'",
                record_chirho.schema_chirho
            );
        }
        ensure_user_principal_chirho(root_chirho, &record_chirho.user_principal_chirho)?;
        validate_publication_slug_chirho(&record_chirho.slug_chirho)?;
        validate_hex_hash_chirho("params_chirho", &record_chirho.params_chirho)?;
        if !matches!(
            record_chirho.kind_chirho,
            PublicationKindChirho::RollbackChirho
        ) && !matches!(
            cas_chirho::read_verified_chirho(root_chirho, &record_chirho.params_chirho),
            cas_chirho::CasReadOutcomeChirho::VerifiedChirho(_)
        ) {
            bail!(
                "publication intent {} names params {} that are not in the tenant CAS",
                record_chirho.seq_chirho,
                record_chirho.params_chirho.0
            );
        }
        if !seen_idem_chirho.insert((
            record_chirho.user_principal_chirho.clone(),
            record_chirho.idempotency_key_hash_chirho.clone(),
        )) {
            bail!("duplicate publication intent idempotency key");
        }
        let message_chirho = publication_intent_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "publication intent {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho)
}

pub fn verify_publication_intents_chirho(root_chirho: &Path) -> Result<usize> {
    Ok(load_verified_publication_intents_chirho(root_chirho)?.len())
}

/// The platform's applied records, verified against the EXISTING public key of the root that holds
/// them (`existing_pubkey_hex_chirho` of `platform_root_chirho`, read-only — no key create/chmod).
/// The status road and the door's occupancy read call this on the platform root from a tenant
/// process; the applier calls it on its own root. An empty history returns before any key touch.
pub fn load_verified_publication_applied_chirho(
    platform_root_chirho: &Path,
) -> Result<Vec<PublicationAppliedRecordChirho>> {
    let records_chirho = load_publication_applied_chirho(platform_root_chirho)?;
    // Empty history needs no key and must not mint one (a first-publication platform root).
    if records_chirho.is_empty() {
        return Ok(records_chirho);
    }
    let pubkey_chirho = signer_chirho::existing_pubkey_hex_chirho(platform_root_chirho)?;
    let mut seen_intents_chirho = BTreeSet::new();
    for (index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!("publication applied seq gap at index {index_chirho}");
        }
        if record_chirho.schema_chirho != PUBLICATION_APPLIED_RECORD_SCHEMA_CHIRHO {
            bail!(
                "unsupported publication applied schema '{}'",
                record_chirho.schema_chirho
            );
        }
        validate_publication_slug_chirho(&record_chirho.slug_chirho)?;
        validate_hex_hash_chirho("intent_digest_chirho", &record_chirho.intent_digest_chirho)?;
        validate_hex_hash_chirho("user_digest_chirho", &record_chirho.user_digest_chirho)?;
        match (
            record_chirho.outcome_chirho,
            record_chirho.refusal_code_chirho.as_deref(),
        ) {
            (PublicationOutcomeChirho::AppliedChirho, None) => {
                if record_chirho.params_chirho.is_none()
                    || record_chirho.params_record_seq_chirho.is_none()
                {
                    bail!(
                        "applied publication record {} names no params record",
                        record_chirho.seq_chirho
                    );
                }
            }
            (PublicationOutcomeChirho::RefusedChirho, Some(code_chirho))
                if PUBLICATION_REFUSAL_CODES_CHIRHO.contains(&code_chirho) => {}
            _ => bail!(
                "publication applied record {} has an outcome/refusal shape that is not allowed",
                record_chirho.seq_chirho
            ),
        }
        if !seen_intents_chirho.insert(record_chirho.intent_digest_chirho.clone()) {
            bail!("duplicate publication applied record for one intent");
        }
        let message_chirho = publication_applied_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "publication applied record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho)
}

/// What the applier records for one intent. Signed with the PLATFORM root's key, appended under
/// the platform root's seqlog; one record per intent digest (the verifier refuses a second).
pub struct PublicationAppliedInputChirho {
    pub tenant_chirho: String,
    pub intent_digest_chirho: HashChirho,
    pub user_digest_chirho: HashChirho,
    pub kind_chirho: PublicationKindChirho,
    pub slug_chirho: String,
    pub outcome_chirho: PublicationOutcomeChirho,
    pub refusal_code_chirho: Option<String>,
    pub params_chirho: Option<HashChirho>,
    pub params_record_seq_chirho: Option<u64>,
}

pub fn append_publication_applied_record_chirho(
    platform_root_chirho: &Path,
    input_chirho: PublicationAppliedInputChirho,
) -> Result<PublicationAppliedRecordChirho> {
    match (
        input_chirho.outcome_chirho,
        input_chirho.refusal_code_chirho.as_deref(),
    ) {
        (PublicationOutcomeChirho::AppliedChirho, None) => {
            if input_chirho.params_chirho.is_none()
                || input_chirho.params_record_seq_chirho.is_none()
            {
                bail!("an applied publication record must name its params record");
            }
        }
        (PublicationOutcomeChirho::RefusedChirho, Some(code_chirho))
            if PUBLICATION_REFUSAL_CODES_CHIRHO.contains(&code_chirho) => {}
        _ => bail!("publication applied outcome and refusal code do not agree"),
    }
    let path_chirho = publication_applied_path_chirho(platform_root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(
        platform_root_chirho,
        &path_chirho,
        |seq_chirho| {
            let mut record_chirho = PublicationAppliedRecordChirho {
                seq_chirho,
                schema_chirho: PUBLICATION_APPLIED_RECORD_SCHEMA_CHIRHO.to_string(),
                tenant_chirho: input_chirho.tenant_chirho.clone(),
                intent_digest_chirho: input_chirho.intent_digest_chirho.clone(),
                user_digest_chirho: input_chirho.user_digest_chirho.clone(),
                kind_chirho: input_chirho.kind_chirho,
                slug_chirho: input_chirho.slug_chirho.clone(),
                outcome_chirho: input_chirho.outcome_chirho,
                refusal_code_chirho: input_chirho.refusal_code_chirho.clone(),
                params_chirho: input_chirho.params_chirho.clone(),
                params_record_seq_chirho: input_chirho.params_record_seq_chirho,
                at_ms_chirho: now_ms_chirho(),
                sig_chirho: String::new(),
            };
            let message_chirho = publication_applied_message_chirho(&record_chirho)?;
            record_chirho.sig_chirho =
                signer_chirho::sign_message_chirho(platform_root_chirho, &message_chirho)?;
            Ok(record_chirho)
        },
    )
}

pub fn verify_publication_applied_chirho(platform_root_chirho: &Path) -> Result<usize> {
    Ok(load_verified_publication_applied_chirho(platform_root_chirho)?.len())
}

#[path = "publication_chirho/apply_chirho.rs"]
pub mod apply_chirho;
#[path = "publication_chirho/status_chirho.rs"]
pub mod status_chirho;

#[cfg(test)]
#[path = "publication_chirho/tests_chirho.rs"]
mod tests_chirho;

#[cfg(test)]
#[path = "publication_chirho/apply_tests_chirho.rs"]
mod apply_tests_chirho;

#[cfg(test)]
#[path = "publication_chirho/occupied_name_tests_chirho.rs"]
mod occupied_name_tests_chirho;
