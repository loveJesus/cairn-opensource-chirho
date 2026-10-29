// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

const SOURCE_DIGEST_CHIRHO: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const DESTINATION_DIGEST_CHIRHO: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
const TENANT_CHIRHO: &str = "tenant-demo-chirho";

struct FixedAuthorityChirho {
    key_id_chirho: String,
    accepts_chirho: bool,
}

impl TenantMigrationDestinationAuthorityPortChirho for FixedAuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }
    fn verify_chirho(&self, _canonical_unsigned_chirho: &str, _sig_chirho: &str) -> bool {
        self.accepts_chirho
    }
}

fn authority_chirho() -> FixedAuthorityChirho {
    FixedAuthorityChirho {
        key_id_chirho: "authority-key-chirho".to_owned(),
        accepts_chirho: true,
    }
}

fn record_chirho() -> TenantMigrationDestinationRecordChirho {
    let intent_chirho = TenantMigrationDestinationIntentChirho {
        schema_chirho: TENANT_MIGRATION_DESTINATION_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
        digest_domain_chirho: TENANT_MIGRATION_DESTINATION_INTENT_DOMAIN_V1_CHIRHO.to_owned(),
        tenant_id_chirho: TENANT_CHIRHO.to_owned(),
        source_root_digest_chirho: SOURCE_DIGEST_CHIRHO.to_owned(),
        destination_root_digest_chirho: DESTINATION_DIGEST_CHIRHO.to_owned(),
        revision_chirho: 3,
    };
    let intent_digest_chirho =
        tenant_migration_destination_intent_digest_chirho(&intent_chirho).unwrap();
    TenantMigrationDestinationRecordChirho {
        schema_chirho: TENANT_MIGRATION_DESTINATION_RECORD_SCHEMA_V1_CHIRHO.to_owned(),
        signature_domain_chirho: TENANT_MIGRATION_DESTINATION_RECORD_DOMAIN_V1_CHIRHO.to_owned(),
        intent_chirho,
        intent_digest_chirho,
        authority_key_id_chirho: "authority-key-chirho".to_owned(),
        sig_chirho: "signature-chirho".to_owned(),
    }
}

fn verify_chirho(
    record_chirho: &TenantMigrationDestinationRecordChirho,
) -> Result<VerifiedTenantMigrationDestinationChirho, TenantMigrationDestinationRefusalChirho> {
    verify_tenant_migration_destination_record_chirho(
        record_chirho,
        &authority_chirho(),
        TENANT_CHIRHO,
        SOURCE_DIGEST_CHIRHO,
        DESTINATION_DIGEST_CHIRHO,
    )
}

#[test]
fn a_well_formed_authorization_verifies_and_carries_its_coordinates_chirho() {
    let verified_chirho = verify_chirho(&record_chirho()).unwrap();
    assert_eq!(verified_chirho.tenant_id_chirho(), TENANT_CHIRHO);
    assert_eq!(
        verified_chirho.source_root_digest_chirho(),
        SOURCE_DIGEST_CHIRHO
    );
    assert_eq!(
        verified_chirho.destination_root_digest_chirho(),
        DESTINATION_DIGEST_CHIRHO
    );
    assert_eq!(verified_chirho.revision_chirho(), 3);
}

/// The replay this binding exists to stop: a genuine authorization for ANOTHER source, presented to
/// move this one. Every field is internally consistent; only the caller's expectation disagrees.
#[test]
fn an_authorization_for_a_different_source_is_refused_chirho() {
    let mut record_value_chirho = record_chirho();
    record_value_chirho.intent_chirho.source_root_digest_chirho =
        "3333333333333333333333333333333333333333333333333333333333333333".to_owned();
    record_value_chirho.intent_digest_chirho =
        tenant_migration_destination_intent_digest_chirho(&record_value_chirho.intent_chirho)
            .unwrap();
    assert_eq!(
        verify_chirho(&record_value_chirho),
        Err(TenantMigrationDestinationRefusalChirho::SourceRootBindingChirho)
    );
}

/// A genuine authorization for another destination must not become permission for the target path
/// selected beside it. This is distinct from source replay: tenant and source both match.
#[test]
fn an_authorization_for_a_different_destination_is_refused_chirho() {
    assert_eq!(
        verify_tenant_migration_destination_record_chirho(
            &record_chirho(),
            &authority_chirho(),
            TENANT_CHIRHO,
            SOURCE_DIGEST_CHIRHO,
            "3333333333333333333333333333333333333333333333333333333333333333",
        ),
        Err(TenantMigrationDestinationRefusalChirho::DestinationRootBindingChirho)
    );
}

#[test]
fn an_authorization_for_a_different_tenant_is_refused_chirho() {
    let mut record_value_chirho = record_chirho();
    record_value_chirho.intent_chirho.tenant_id_chirho = "tenant-other-chirho".to_owned();
    record_value_chirho.intent_digest_chirho =
        tenant_migration_destination_intent_digest_chirho(&record_value_chirho.intent_chirho)
            .unwrap();
    assert_eq!(
        verify_chirho(&record_value_chirho),
        Err(TenantMigrationDestinationRefusalChirho::TenantIdentityChirho)
    );
}

/// Moving a root onto itself is not a migration, and a signed record saying so must not make it one.
#[test]
fn a_destination_identical_to_the_source_is_refused_chirho() {
    let mut record_value_chirho = record_chirho();
    record_value_chirho
        .intent_chirho
        .destination_root_digest_chirho = SOURCE_DIGEST_CHIRHO.to_owned();
    record_value_chirho.intent_digest_chirho =
        tenant_migration_destination_intent_digest_chirho(&record_value_chirho.intent_chirho)
            .unwrap();
    assert_eq!(
        verify_chirho(&record_value_chirho),
        Err(TenantMigrationDestinationRefusalChirho::SourceAndDestinationIdenticalChirho)
    );
}

/// Tampering the intent without recomputing its digest must not survive.
#[test]
fn a_tampered_intent_fails_its_own_digest_chirho() {
    let mut record_value_chirho = record_chirho();
    record_value_chirho.intent_chirho.revision_chirho = 99;
    assert_eq!(
        verify_chirho(&record_value_chirho),
        Err(TenantMigrationDestinationRefusalChirho::IntentDigestChirho)
    );
}

/// A VALID signature from an authority this node does not accept must refuse as a KEY problem, not
/// slip through because the signature itself checks out.
#[test]
fn a_signature_from_an_unaccepted_authority_refuses_by_key_chirho() {
    let mut record_value_chirho = record_chirho();
    record_value_chirho.authority_key_id_chirho = "other-authority-chirho".to_owned();
    assert_eq!(
        verify_chirho(&record_value_chirho),
        Err(TenantMigrationDestinationRefusalChirho::AuthorityKeyChirho)
    );
}

#[test]
fn a_rejected_signature_is_refused_chirho() {
    let refusing_chirho = FixedAuthorityChirho {
        key_id_chirho: "authority-key-chirho".to_owned(),
        accepts_chirho: false,
    };
    assert_eq!(
        verify_tenant_migration_destination_record_chirho(
            &record_chirho(),
            &refusing_chirho,
            TENANT_CHIRHO,
            SOURCE_DIGEST_CHIRHO,
            DESTINATION_DIGEST_CHIRHO,
        ),
        Err(TenantMigrationDestinationRefusalChirho::SignatureChirho)
    );
}

#[test]
fn wrong_schemas_and_domains_refuse_by_their_own_identities_chirho() {
    let mut schema_chirho = record_chirho();
    schema_chirho.schema_chirho = "tenant-migration-destination-record-v2-chirho".to_owned();
    assert_eq!(
        verify_chirho(&schema_chirho),
        Err(TenantMigrationDestinationRefusalChirho::SchemaChirho)
    );

    let mut digest_domain_chirho = record_chirho();
    digest_domain_chirho.intent_chirho.digest_domain_chirho = "other-domain-chirho".to_owned();
    digest_domain_chirho.intent_digest_chirho =
        tenant_migration_destination_intent_digest_chirho(&digest_domain_chirho.intent_chirho)
            .unwrap();
    assert_eq!(
        verify_chirho(&digest_domain_chirho),
        Err(TenantMigrationDestinationRefusalChirho::DigestDomainChirho)
    );

    let mut signature_domain_chirho = record_chirho();
    signature_domain_chirho.signature_domain_chirho = "other-signature-domain-chirho".to_owned();
    assert_eq!(
        verify_chirho(&signature_domain_chirho),
        Err(TenantMigrationDestinationRefusalChirho::SignatureDomainChirho)
    );
}

/// The signed message must carry the record's own domain and key id, so a signature cannot be lifted
/// from one record onto another that shares only its intent digest.
#[test]
fn the_signed_message_binds_domain_and_key_id_chirho() {
    let record_value_chirho = record_chirho();
    let message_chirho = unsigned_tenant_migration_destination_message_chirho(&record_value_chirho);
    assert!(message_chirho.contains(TENANT_MIGRATION_DESTINATION_RECORD_DOMAIN_V1_CHIRHO));
    assert!(message_chirho.contains(&record_value_chirho.authority_key_id_chirho));
    assert!(message_chirho.contains(&record_value_chirho.intent_digest_chirho));
}
