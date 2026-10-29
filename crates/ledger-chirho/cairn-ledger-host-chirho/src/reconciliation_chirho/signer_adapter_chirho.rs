// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Existing-node-key adapter for signed GD7 control-plane records.

use super::contract_chirho::{
    is_bounded_label_chirho, is_lower_hex_digest_chirho, Gd7LedgerRecordVerifierPortChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
    MAX_GD7_RECONCILIATION_LABEL_BYTES_CHIRHO,
};
use anyhow::{bail, Result};
use cairn_ledger_tenant_migration_durable_chirho::TenantMigrationControlSignerPortChirho;
use cairn_ledger_tenant_migration_durable_chirho::TenantMigrationDestinationAuthorityPortChirho;
use cairn_signer_chirho::signer_chirho::{
    existing_keypair_pubkey_hex_chirho, sign_with_existing_key_possession_chirho,
    verify_with_pubkey_chirho,
};
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use std::path::{Path, PathBuf};

/// Bounded existing-key signer whose public identity is the elected writer node id.
pub struct ExistingNodeGd7SignerChirho {
    canonical_root_chirho: PathBuf,
    node_id_chirho: NodeIdChirho,
}

impl ExistingNodeGd7SignerChirho {
    pub fn open_existing_with_key_id_chirho(
        root_chirho: &Path,
        key_id_chirho: &str,
    ) -> Result<Self> {
        Self::open_existing_chirho(root_chirho, &NodeIdChirho(key_id_chirho.to_owned()))
    }

    pub fn open_existing_chirho(
        root_chirho: &Path,
        expected_node_chirho: &NodeIdChirho,
    ) -> Result<Self> {
        let canonical_root_chirho = root_chirho.canonicalize()?;
        let actual_node_chirho =
            NodeIdChirho(existing_keypair_pubkey_hex_chirho(&canonical_root_chirho)?);
        if &actual_node_chirho != expected_node_chirho {
            bail!("existing GD7 signer key does not match the elected node identity");
        }
        Ok(Self {
            canonical_root_chirho,
            node_id_chirho: actual_node_chirho,
        })
    }

    pub fn node_id_chirho(&self) -> &NodeIdChirho {
        &self.node_id_chirho
    }
}

impl Gd7ReconciliationVerifierPortChirho for ExistingNodeGd7SignerChirho {
    fn key_id_chirho(&self) -> String {
        self.node_id_chirho.0.clone()
    }

    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        verify_with_pubkey_chirho(
            &self.node_id_chirho.0,
            canonical_unsigned_chirho.as_bytes(),
            sig_chirho,
        )
        .unwrap_or(false)
    }
}

impl Gd7ReconciliationSignerPortChirho for ExistingNodeGd7SignerChirho {
    fn sign_chirho(&self, canonical_unsigned_chirho: &str) -> Result<String> {
        let possession_chirho = sign_with_existing_key_possession_chirho(
            &self.canonical_root_chirho,
            canonical_unsigned_chirho.as_bytes(),
        )?;
        if possession_chirho.key_id_chirho() != self.node_id_chirho.0 {
            bail!("GD7 signing custody changed after the signer was opened");
        }
        Ok(possession_chirho.into_signature_hex_chirho())
    }
}

impl TenantMigrationControlSignerPortChirho for ExistingNodeGd7SignerChirho {
    fn key_id_chirho(&self) -> String {
        self.node_id_chirho.0.clone()
    }

    fn sign_chirho(&self, canonical_unsigned_chirho: &str) -> Result<String> {
        Gd7ReconciliationSignerPortChirho::sign_chirho(self, canonical_unsigned_chirho)
    }

    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        Gd7ReconciliationVerifierPortChirho::verify_chirho(
            self,
            canonical_unsigned_chirho,
            sig_chirho,
        )
    }
}

/// Read-only verification root for winner evidence replicated to a held node.
pub struct PinnedNodeGd7VerifierChirho {
    node_id_chirho: NodeIdChirho,
}

impl PinnedNodeGd7VerifierChirho {
    pub fn new_from_key_id_chirho(key_id_chirho: String) -> Result<Self> {
        Self::new_chirho(NodeIdChirho(key_id_chirho))
    }

    pub fn new_chirho(node_id_chirho: NodeIdChirho) -> Result<Self> {
        if !is_lower_hex_digest_chirho(&node_id_chirho.0) {
            bail!("pinned GD7 verifier node identity is not canonical lower hex");
        }
        Ok(Self { node_id_chirho })
    }

    pub fn node_id_chirho(&self) -> &NodeIdChirho {
        &self.node_id_chirho
    }
}

impl Gd7ReconciliationVerifierPortChirho for PinnedNodeGd7VerifierChirho {
    fn key_id_chirho(&self) -> String {
        self.node_id_chirho.0.clone()
    }

    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        verify_with_pubkey_chirho(
            &self.node_id_chirho.0,
            canonical_unsigned_chirho.as_bytes(),
            sig_chirho,
        )
        .unwrap_or(false)
    }
}

/// Read-only verification root for one winner journal's signed records.
pub struct PinnedGd7LedgerRecordVerifierChirho {
    key_id_chirho: String,
    public_key_hex_chirho: String,
}

impl PinnedGd7LedgerRecordVerifierChirho {
    pub fn new_chirho(key_id_chirho: String, public_key_hex_chirho: String) -> Result<Self> {
        if !is_bounded_label_chirho(&key_id_chirho, MAX_GD7_RECONCILIATION_LABEL_BYTES_CHIRHO) {
            bail!("pinned GD7 ledger verifier key label is invalid");
        }
        if !is_lower_hex_digest_chirho(&public_key_hex_chirho) {
            bail!("pinned GD7 ledger verifier public key is not canonical lower hex");
        }
        Ok(Self {
            key_id_chirho,
            public_key_hex_chirho,
        })
    }
}

impl Gd7LedgerRecordVerifierPortChirho for PinnedGd7LedgerRecordVerifierChirho {
    fn key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        verify_with_pubkey_chirho(
            &self.public_key_hex_chirho,
            signed_content_line_chirho.as_bytes(),
            sig_chirho,
        )
        .unwrap_or(false)
    }
}

/// Read-only verification root for one tenant-migration DESTINATION authority.
///
/// Pinned to one key id and one public key, and it can only verify. There is deliberately no signing
/// counterpart here: the node that would migrate must never be able to author its own destination
/// authorization, so the adapter that a migrating node holds exposes exactly one direction.
///
/// `key_id_chirho` is checked against the record's declared key BEFORE the signature is verified, so
/// a genuine signature from a different authority refuses as a key mismatch rather than passing a
/// check nobody asked for. That ordering lives in the verifier; this type only supplies the pin.
pub struct PinnedTenantMigrationDestinationAuthorityChirho {
    key_id_chirho: String,
    public_key_hex_chirho: String,
}

impl PinnedTenantMigrationDestinationAuthorityChirho {
    pub fn new_chirho(key_id_chirho: String, public_key_hex_chirho: String) -> Result<Self> {
        if !is_bounded_label_chirho(&key_id_chirho, MAX_GD7_RECONCILIATION_LABEL_BYTES_CHIRHO) {
            bail!("pinned tenant migration destination authority key label is invalid");
        }
        if !is_lower_hex_digest_chirho(&public_key_hex_chirho) {
            bail!("pinned tenant migration destination authority public key is not canonical lower hex");
        }
        Ok(Self {
            key_id_chirho,
            public_key_hex_chirho,
        })
    }
}

impl TenantMigrationDestinationAuthorityPortChirho
    for PinnedTenantMigrationDestinationAuthorityChirho
{
    fn authority_key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }

    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        verify_with_pubkey_chirho(
            &self.public_key_hex_chirho,
            canonical_unsigned_chirho.as_bytes(),
            sig_chirho,
        )
        .unwrap_or(false)
    }
}

#[cfg(test)]
mod destination_authority_adapter_tests_chirho {
    use super::*;
    use crate::tests_chirho::temp_root_chirho;
    use cairn_ledger_tenant_migration_durable_chirho::{
        tenant_migration_destination_intent_digest_chirho,
        unsigned_tenant_migration_destination_message_chirho,
        verify_tenant_migration_destination_record_chirho, TenantMigrationDestinationIntentChirho,
        TenantMigrationDestinationRecordChirho, TenantMigrationDestinationRefusalChirho,
        TENANT_MIGRATION_DESTINATION_INTENT_DOMAIN_V1_CHIRHO,
        TENANT_MIGRATION_DESTINATION_INTENT_SCHEMA_V1_CHIRHO,
        TENANT_MIGRATION_DESTINATION_RECORD_DOMAIN_V1_CHIRHO,
        TENANT_MIGRATION_DESTINATION_RECORD_SCHEMA_V1_CHIRHO,
    };
    use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};

    const SOURCE_DIGEST_CHIRHO: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const DESTINATION_DIGEST_CHIRHO: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";
    const TENANT_CHIRHO: &str = "tenant-adapter-chirho";

    fn unsigned_record_chirho(key_id_chirho: &str) -> TenantMigrationDestinationRecordChirho {
        let intent_chirho = TenantMigrationDestinationIntentChirho {
            schema_chirho: TENANT_MIGRATION_DESTINATION_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
            digest_domain_chirho: TENANT_MIGRATION_DESTINATION_INTENT_DOMAIN_V1_CHIRHO.to_owned(),
            tenant_id_chirho: TENANT_CHIRHO.to_owned(),
            source_root_digest_chirho: SOURCE_DIGEST_CHIRHO.to_owned(),
            destination_root_digest_chirho: DESTINATION_DIGEST_CHIRHO.to_owned(),
            revision_chirho: 1,
        };
        let intent_digest_chirho =
            tenant_migration_destination_intent_digest_chirho(&intent_chirho).unwrap();
        TenantMigrationDestinationRecordChirho {
            schema_chirho: TENANT_MIGRATION_DESTINATION_RECORD_SCHEMA_V1_CHIRHO.to_owned(),
            signature_domain_chirho: TENANT_MIGRATION_DESTINATION_RECORD_DOMAIN_V1_CHIRHO
                .to_owned(),
            intent_chirho,
            intent_digest_chirho,
            authority_key_id_chirho: key_id_chirho.to_owned(),
            sig_chirho: String::new(),
        }
    }

    /// The whole chain under REAL ed25519: a genuine authority signature verifies, and one flipped
    /// signature character does not. A fake port returning `true` proves the wiring; this proves the
    /// wiring carries actual cryptography.
    #[test]
    fn a_real_signature_verifies_and_a_tampered_one_does_not_chirho() {
        let root_chirho = temp_root_chirho("destination-authority-adapter");
        std::fs::create_dir_all(&root_chirho).unwrap();
        let public_key_chirho = pubkey_hex_chirho(&root_chirho).unwrap();

        let mut record_chirho = unsigned_record_chirho(&public_key_chirho);
        let message_chirho = unsigned_tenant_migration_destination_message_chirho(&record_chirho);
        record_chirho.sig_chirho =
            sign_message_chirho(&root_chirho, message_chirho.as_bytes()).unwrap();

        let authority_chirho = PinnedTenantMigrationDestinationAuthorityChirho::new_chirho(
            public_key_chirho.clone(),
            public_key_chirho,
        )
        .unwrap();
        verify_tenant_migration_destination_record_chirho(
            &record_chirho,
            &authority_chirho,
            TENANT_CHIRHO,
            SOURCE_DIGEST_CHIRHO,
            DESTINATION_DIGEST_CHIRHO,
        )
        .expect("a genuine authority signature must verify");

        let mut tampered_chirho = record_chirho.clone();
        let flipped_chirho = if tampered_chirho.sig_chirho.starts_with('a') {
            'b'
        } else {
            'a'
        };
        tampered_chirho.sig_chirho = format!("{flipped_chirho}{}", &record_chirho.sig_chirho[1..]);
        assert_eq!(
            verify_tenant_migration_destination_record_chirho(
                &tampered_chirho,
                &authority_chirho,
                TENANT_CHIRHO,
                SOURCE_DIGEST_CHIRHO,
                DESTINATION_DIGEST_CHIRHO,
            ),
            Err(TenantMigrationDestinationRefusalChirho::SignatureChirho)
        );
    }

    /// A genuine signature from a DIFFERENT authority refuses on the key, before the signature is
    /// ever checked. Otherwise a node would accept any authority that happens to sign correctly.
    #[test]
    fn a_genuine_signature_from_another_authority_refuses_on_the_key_chirho() {
        let authorized_root_chirho = temp_root_chirho("destination-authority-accepted");
        let other_root_chirho = temp_root_chirho("destination-authority-other");
        std::fs::create_dir_all(&authorized_root_chirho).unwrap();
        std::fs::create_dir_all(&other_root_chirho).unwrap();
        let accepted_key_chirho = pubkey_hex_chirho(&authorized_root_chirho).unwrap();
        let other_key_chirho = pubkey_hex_chirho(&other_root_chirho).unwrap();
        assert_ne!(accepted_key_chirho, other_key_chirho);

        let mut record_chirho = unsigned_record_chirho(&other_key_chirho);
        let message_chirho = unsigned_tenant_migration_destination_message_chirho(&record_chirho);
        record_chirho.sig_chirho =
            sign_message_chirho(&other_root_chirho, message_chirho.as_bytes()).unwrap();

        let authority_chirho = PinnedTenantMigrationDestinationAuthorityChirho::new_chirho(
            accepted_key_chirho.clone(),
            accepted_key_chirho,
        )
        .unwrap();
        assert_eq!(
            verify_tenant_migration_destination_record_chirho(
                &record_chirho,
                &authority_chirho,
                TENANT_CHIRHO,
                SOURCE_DIGEST_CHIRHO,
                DESTINATION_DIGEST_CHIRHO,
            ),
            Err(TenantMigrationDestinationRefusalChirho::AuthorityKeyChirho)
        );
    }

    #[test]
    fn a_non_hex_public_key_is_refused_at_construction_chirho() {
        assert!(PinnedTenantMigrationDestinationAuthorityChirho::new_chirho(
            "key-chirho".to_owned(),
            "not-hex-chirho".to_owned(),
        )
        .is_err());
    }
}
