// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Externally signed authorization naming which root a tenant may be migrated ONTO.
//!
//! The migration contract binds root IDENTITY — that the target is a distinct root carrying the same
//! tenant marker — and deliberately stops there: *"that is root identity binding, not placement
//! authorization"*. Identity answers "is this a legitimate root"; it cannot answer "is this the root
//! we were authorized to move to". This module answers the second question and nothing else.
//!
//! **The port verifies and cannot sign, which is the point.** The existing
//! `TenantMigrationControlSignerPortChirho` signs with the NODE's own key and says so: it
//! "authenticates which attempt this node was running". A destination authorization signed by the
//! moving node would be self-authorization — a compromised or confused node would name its own
//! target and satisfy its own check. So this port exposes verification only. A node can refuse a
//! destination it was not given; it cannot mint one.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`.

use serde::{Deserialize, Serialize};

pub const TENANT_MIGRATION_DESTINATION_INTENT_SCHEMA_V1_CHIRHO: &str =
    "tenant-migration-destination-intent-v1-chirho";
pub const TENANT_MIGRATION_DESTINATION_RECORD_SCHEMA_V1_CHIRHO: &str =
    "tenant-migration-destination-record-v1-chirho";
pub const TENANT_MIGRATION_DESTINATION_INTENT_DOMAIN_V1_CHIRHO: &str =
    "tenant-migration-destination-intent-digest-v1-chirho";
pub const TENANT_MIGRATION_DESTINATION_RECORD_DOMAIN_V1_CHIRHO: &str =
    "tenant-migration-destination-record-signature-v1-chirho";
pub const MAX_TENANT_MIGRATION_DESTINATION_RECORD_BYTES_CHIRHO: usize = 16 * 1024;

/// Verification-only authority port. There is deliberately no `sign_chirho`.
pub trait TenantMigrationDestinationAuthorityPortChirho {
    /// The key id this node will accept destination authorizations from.
    fn authority_key_id_chirho(&self) -> String;
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool;
}

/// What an authority actually authorizes: this tenant, moving off this source, onto that target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantMigrationDestinationIntentChirho {
    pub schema_chirho: String,
    pub digest_domain_chirho: String,
    pub tenant_id_chirho: String,
    /// Bound so one authorization cannot be replayed to move a DIFFERENT source onto this target.
    pub source_root_digest_chirho: String,
    pub destination_root_digest_chirho: String,
    pub revision_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantMigrationDestinationRecordChirho {
    pub schema_chirho: String,
    pub signature_domain_chirho: String,
    pub intent_chirho: TenantMigrationDestinationIntentChirho,
    pub intent_digest_chirho: String,
    pub authority_key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantMigrationDestinationRefusalChirho {
    SchemaChirho,
    DigestDomainChirho,
    SignatureDomainChirho,
    TenantIdentityChirho,
    SourceRootBindingChirho,
    DestinationRootBindingChirho,
    RootDigestShapeChirho,
    SourceAndDestinationIdenticalChirho,
    IntentDigestChirho,
    AuthorityKeyChirho,
    SignatureChirho,
    EncodeChirho,
}

/// Proof-carrying result. Holding one means every check below already passed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedTenantMigrationDestinationChirho {
    tenant_id_chirho: String,
    source_root_digest_chirho: String,
    destination_root_digest_chirho: String,
    revision_chirho: u64,
    authority_key_id_chirho: String,
}

impl VerifiedTenantMigrationDestinationChirho {
    pub fn tenant_id_chirho(&self) -> &str {
        &self.tenant_id_chirho
    }
    pub fn source_root_digest_chirho(&self) -> &str {
        &self.source_root_digest_chirho
    }
    pub fn destination_root_digest_chirho(&self) -> &str {
        &self.destination_root_digest_chirho
    }
    pub fn revision_chirho(&self) -> u64 {
        self.revision_chirho
    }
    pub fn authority_key_id_chirho(&self) -> &str {
        &self.authority_key_id_chirho
    }
}

fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

pub fn tenant_migration_destination_intent_digest_chirho(
    intent_chirho: &TenantMigrationDestinationIntentChirho,
) -> Result<String, TenantMigrationDestinationRefusalChirho> {
    let bytes_chirho = serde_json::to_vec(intent_chirho)
        .map_err(|_error_chirho| TenantMigrationDestinationRefusalChirho::EncodeChirho)?;
    Ok(blake3::hash(&bytes_chirho).to_hex().to_string())
}

/// The exact bytes an authority signs. Includes the record's own domain, so a signature over an
/// intent digest cannot be replayed as a signature over a record.
pub fn unsigned_tenant_migration_destination_message_chirho(
    record_chirho: &TenantMigrationDestinationRecordChirho,
) -> String {
    format!(
        "{}:{}:{}",
        record_chirho.signature_domain_chirho,
        record_chirho.authority_key_id_chirho,
        record_chirho.intent_digest_chirho
    )
}

/// Verify one destination authorization against what the CALLER already knows.
///
/// The expected tenant and both roots are inputs rather than outputs: a verifier that reports what
/// a record claims, instead of checking it against the move actually being attempted, would accept a
/// perfectly valid authorization for some other migration or destination.
pub fn verify_tenant_migration_destination_record_chirho(
    record_chirho: &TenantMigrationDestinationRecordChirho,
    authority_chirho: &dyn TenantMigrationDestinationAuthorityPortChirho,
    expected_tenant_id_chirho: &str,
    expected_source_root_digest_chirho: &str,
    expected_destination_root_digest_chirho: &str,
) -> Result<VerifiedTenantMigrationDestinationChirho, TenantMigrationDestinationRefusalChirho> {
    if record_chirho.schema_chirho != TENANT_MIGRATION_DESTINATION_RECORD_SCHEMA_V1_CHIRHO
        || record_chirho.intent_chirho.schema_chirho
            != TENANT_MIGRATION_DESTINATION_INTENT_SCHEMA_V1_CHIRHO
    {
        return Err(TenantMigrationDestinationRefusalChirho::SchemaChirho);
    }
    if record_chirho.intent_chirho.digest_domain_chirho
        != TENANT_MIGRATION_DESTINATION_INTENT_DOMAIN_V1_CHIRHO
    {
        return Err(TenantMigrationDestinationRefusalChirho::DigestDomainChirho);
    }
    if record_chirho.signature_domain_chirho != TENANT_MIGRATION_DESTINATION_RECORD_DOMAIN_V1_CHIRHO
    {
        return Err(TenantMigrationDestinationRefusalChirho::SignatureDomainChirho);
    }
    if record_chirho.intent_chirho.tenant_id_chirho != expected_tenant_id_chirho {
        return Err(TenantMigrationDestinationRefusalChirho::TenantIdentityChirho);
    }
    if record_chirho.intent_chirho.source_root_digest_chirho != expected_source_root_digest_chirho {
        return Err(TenantMigrationDestinationRefusalChirho::SourceRootBindingChirho);
    }
    if !is_lower_hex_digest_chirho(&record_chirho.intent_chirho.source_root_digest_chirho)
        || !is_lower_hex_digest_chirho(&record_chirho.intent_chirho.destination_root_digest_chirho)
    {
        return Err(TenantMigrationDestinationRefusalChirho::RootDigestShapeChirho);
    }
    if record_chirho.intent_chirho.source_root_digest_chirho
        == record_chirho.intent_chirho.destination_root_digest_chirho
    {
        return Err(TenantMigrationDestinationRefusalChirho::SourceAndDestinationIdenticalChirho);
    }
    if record_chirho.intent_chirho.destination_root_digest_chirho
        != expected_destination_root_digest_chirho
    {
        return Err(TenantMigrationDestinationRefusalChirho::DestinationRootBindingChirho);
    }
    let recomputed_chirho =
        tenant_migration_destination_intent_digest_chirho(&record_chirho.intent_chirho)?;
    if recomputed_chirho != record_chirho.intent_digest_chirho {
        return Err(TenantMigrationDestinationRefusalChirho::IntentDigestChirho);
    }
    // The key is checked BEFORE the signature so a valid signature from an unexpected authority
    // refuses as a key problem rather than passing a signature check the caller never asked for.
    if record_chirho.authority_key_id_chirho != authority_chirho.authority_key_id_chirho() {
        return Err(TenantMigrationDestinationRefusalChirho::AuthorityKeyChirho);
    }
    let message_chirho = unsigned_tenant_migration_destination_message_chirho(record_chirho);
    if !authority_chirho.verify_chirho(&message_chirho, &record_chirho.sig_chirho) {
        return Err(TenantMigrationDestinationRefusalChirho::SignatureChirho);
    }
    Ok(VerifiedTenantMigrationDestinationChirho {
        tenant_id_chirho: record_chirho.intent_chirho.tenant_id_chirho.clone(),
        source_root_digest_chirho: record_chirho
            .intent_chirho
            .source_root_digest_chirho
            .clone(),
        destination_root_digest_chirho: record_chirho
            .intent_chirho
            .destination_root_digest_chirho
            .clone(),
        revision_chirho: record_chirho.intent_chirho.revision_chirho,
        authority_key_id_chirho: record_chirho.authority_key_id_chirho.clone(),
    })
}

#[cfg(test)]
#[path = "destination_authority_tests_chirho.rs"]
mod destination_authority_tests_chirho;
