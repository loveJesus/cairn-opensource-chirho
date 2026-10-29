// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The typed, key-byte-free mirror closure manifest (non-F4). Its closed family enum currently
//! supports F12 sealed private blobs and F1 canonical signed ledger records; there is deliberately no
//! opaque arbitrary-byte member.
//!
//! Custody honesty (OQ-7): an ABSENT or malformed custody confirmation REFUSES
//! (`MirrorCustodyConfirmationMissingChirho`), so 7.2a never presumes custody. A well-formed
//! placeholder is accepted only so the durable-store-then-receipt MECHANISM can be proven; its status
//! is `PlaceholderPendingCustodyChirho`, the single status a 7.2a author can set, and the receipt
//! carries that status forward so no serving gate (7.4) treats placeholder custody as real
//! 7.2c-confirmed custody.

use crate::digest_chirho::{
    update_digest_field_chirho, valid_lower_hex_chirho, DIGEST_HEX_BYTES_CHIRHO,
    KEY_ID_HEX_BYTES_CHIRHO, MAC_HEX_BYTES_CHIRHO, NODE_ID_HEX_BYTES_CHIRHO,
    NONCE_HEX_BYTES_CHIRHO,
};
use crate::refusal_chirho::{MirrorContractErrorChirho, MirrorRefusalIdentityChirho};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_privacy_chirho::PrivateBlobRefChirho;
use serde::{Deserialize, Serialize};

pub const MIRROR_CLOSURE_MANIFEST_SCHEMA_V2_CHIRHO: &str = "mirror-closure-manifest-v2-chirho";
pub const PRIVATE_BLOB_ALG_CHIRHO: &str = "xchacha20poly1305-blake3mac-v1-chirho";

const MIRROR_CLOSURE_MANIFEST_DIGEST_DOMAIN_V2_CHIRHO: &[u8] =
    b"cairn-mirror-closure-manifest-v2-chirho";
const MIRROR_SEALED_MEMBER_DIGEST_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-mirror-sealed-member-v1-chirho";
const MIRROR_SIGNED_LEDGER_MEMBER_DIGEST_DOMAIN_V1_CHIRHO: &[u8] =
    b"cairn-mirror-signed-ledger-member-v1-chirho";
const MIRROR_PREFIX_BINDING_DIGEST_DOMAIN_V1_CHIRHO: &[u8] =
    b"cairn-mirror-log-prefix-binding-v1-chirho";
const MIRROR_MAX_MEMBERS_CHIRHO: usize = 64;
const MIRROR_FAMILY_NAME_MAX_BYTES_CHIRHO: usize = 128;
const MIRROR_REGION_LABEL_MAX_BYTES_CHIRHO: usize = 64;
const MIRROR_MAX_CUSTODY_REGIONS_CHIRHO: usize = 16;
const MIRROR_LEDGER_RECORD_MAX_BYTES_CHIRHO: usize = 256 * 1024;
const MIRROR_CLUSTER_ID_MAX_BYTES_CHIRHO: usize = 128;

/// A verified log-prefix binding (the MANIFESTED_PREFIX_CLOSURE shape). In 7.2a it travels beside the
/// inline sealed bytes; carrying the count/length/digest now lets 7.2b send verified deltas instead
/// of whole growing files, with no wire break.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogPrefixBindingChirho {
    pub family_name_chirho: String,
    pub record_count_chirho: u64,
    pub byte_length_chirho: u64,
    pub verified_prefix_digest_chirho: String,
}

impl LogPrefixBindingChirho {
    fn validate_chirho(&self) -> Result<(), MirrorContractErrorChirho> {
        if self.family_name_chirho.is_empty()
            || self.family_name_chirho.len() > MIRROR_FAMILY_NAME_MAX_BYTES_CHIRHO
            || !valid_lower_hex_chirho(&self.verified_prefix_digest_chirho, DIGEST_HEX_BYTES_CHIRHO)
        {
            return Err(MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorSealedFamilyIncompleteChirho,
                "sealed member log-prefix binding is malformed",
            ));
        }
        Ok(())
    }

    fn update_digest_chirho(&self, hasher_chirho: &mut blake3::Hasher) {
        hasher_chirho.update(MIRROR_PREFIX_BINDING_DIGEST_DOMAIN_V1_CHIRHO);
        update_digest_field_chirho(
            hasher_chirho,
            b"family-name-chirho",
            self.family_name_chirho.as_bytes(),
        );
        update_digest_field_chirho(
            hasher_chirho,
            b"record-count-chirho",
            &self.record_count_chirho.to_le_bytes(),
        );
        update_digest_field_chirho(
            hasher_chirho,
            b"byte-length-chirho",
            &self.byte_length_chirho.to_le_bytes(),
        );
        update_digest_field_chirho(
            hasher_chirho,
            b"verified-prefix-digest-chirho",
            self.verified_prefix_digest_chirho.as_bytes(),
        );
    }
}

/// The one custody status a 7.2a author may set: the confirmation CHANNEL (7.2c) is unbuilt, so the
/// custody slot is bound but not cryptographically proven. Having only this variant means 7.2a cannot
/// fabricate a "confirmed" custody, so no receipt can claim real custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyCustodyStatusChirho {
    PlaceholderPendingCustodyChirho,
}

/// The 7.2a key-custody confirmation placeholder. It binds the sealed blob's key id and names the
/// failure-domain regions 7.2c must later prove custody across. An empty key id or empty region set
/// is fail-closed (`MirrorCustodyConfirmationMissingChirho`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyCustodyConfirmationChirho {
    pub bound_key_id_chirho: String,
    pub required_custody_regions_chirho: Vec<String>,
    pub status_chirho: KeyCustodyStatusChirho,
}

impl KeyCustodyConfirmationChirho {
    /// The only 7.2a constructor: a bound-but-unproven placeholder. Validated here so a malformed one
    /// cannot be built; 7.2c will replace the mechanism, never this fail-closed default.
    pub fn placeholder_chirho(
        bound_key_id_chirho: impl Into<String>,
        required_custody_regions_chirho: Vec<String>,
    ) -> Result<Self, MirrorContractErrorChirho> {
        let confirmation_chirho = Self {
            bound_key_id_chirho: bound_key_id_chirho.into(),
            required_custody_regions_chirho,
            status_chirho: KeyCustodyStatusChirho::PlaceholderPendingCustodyChirho,
        };
        confirmation_chirho.validate_chirho()?;
        Ok(confirmation_chirho)
    }

    fn validate_chirho(&self) -> Result<(), MirrorContractErrorChirho> {
        if !valid_lower_hex_chirho(&self.bound_key_id_chirho, KEY_ID_HEX_BYTES_CHIRHO) {
            // Absent, empty, or key-material-shaped id => custody unconfirmed => fail closed.
            return Err(MirrorContractErrorChirho::custody_confirmation_missing_chirho());
        }
        if self.required_custody_regions_chirho.is_empty()
            || self.required_custody_regions_chirho.len() > MIRROR_MAX_CUSTODY_REGIONS_CHIRHO
            || self
                .required_custody_regions_chirho
                .iter()
                .any(|region_chirho| {
                    region_chirho.is_empty()
                        || region_chirho.len() > MIRROR_REGION_LABEL_MAX_BYTES_CHIRHO
                })
        {
            return Err(MirrorContractErrorChirho::custody_confirmation_missing_chirho());
        }
        Ok(())
    }

    fn update_digest_chirho(&self, hasher_chirho: &mut blake3::Hasher) {
        update_digest_field_chirho(
            hasher_chirho,
            b"custody-bound-key-id-chirho",
            self.bound_key_id_chirho.as_bytes(),
        );
        update_digest_field_chirho(
            hasher_chirho,
            b"custody-region-count-chirho",
            &(self.required_custody_regions_chirho.len() as u64).to_le_bytes(),
        );
        for region_chirho in &self.required_custody_regions_chirho {
            update_digest_field_chirho(
                hasher_chirho,
                b"custody-region-chirho",
                region_chirho.as_bytes(),
            );
        }
        update_digest_field_chirho(
            hasher_chirho,
            b"custody-status-chirho",
            b"placeholder-pending",
        );
    }
}

/// One closed mirror-family member. By construction NO variant field can hold an F12 shred key and
/// there is no generic byte-family escape hatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "family_chirho")]
pub enum MirrorFamilyMemberChirho {
    #[serde(rename = "f12-sealed-private-blob-chirho")]
    SealedPrivateBlobChirho {
        ciphertext_addr_chirho: HashChirho,
        privacy_record_prefix_chirho: LogPrefixBindingChirho,
        blob_ref_chirho: PrivateBlobRefChirho,
        key_custody_confirmation_chirho: KeyCustodyConfirmationChirho,
    },
    /// F1: one exact canonical ledger record after signing and full local admission but before the
    /// leader's durable append. The line is carried directly because it is already signed, bounded,
    /// and content-addressed; it is not an opaque byte-family admission.
    #[serde(rename = "f1-signed-ledger-record-chirho")]
    SignedLedgerRecordChirho {
        cluster_id_chirho: String,
        journal_genesis_digest_chirho: String,
        predecessor_seq_chirho: u64,
        predecessor_digest_chirho: String,
        record_seq_chirho: u64,
        record_digest_chirho: HashChirho,
        record_epoch_chirho: u64,
        record_hlc_physical_ms_chirho: u64,
        record_hlc_logical_chirho: u32,
        canonical_record_line_chirho: String,
    },
}

/// Borrowed view of an F1 manifest member for a family-specific native durability adapter.
pub struct SignedLedgerRecordMirrorMemberViewChirho<'member_chirho> {
    pub cluster_id_chirho: &'member_chirho str,
    pub journal_genesis_digest_chirho: &'member_chirho str,
    pub predecessor_seq_chirho: u64,
    pub predecessor_digest_chirho: &'member_chirho str,
    pub record_seq_chirho: u64,
    pub record_digest_chirho: &'member_chirho HashChirho,
    pub record_epoch_chirho: u64,
    pub record_hlc_physical_ms_chirho: u64,
    pub record_hlc_logical_chirho: u32,
    pub canonical_record_line_chirho: &'member_chirho str,
}

impl MirrorFamilyMemberChirho {
    fn validate_chirho(&self) -> Result<(), MirrorContractErrorChirho> {
        match self {
            Self::SealedPrivateBlobChirho {
                ciphertext_addr_chirho,
                privacy_record_prefix_chirho,
                blob_ref_chirho,
                key_custody_confirmation_chirho,
            } => {
                // Defense-in-depth (A4): the key id is a short 16-byte id (32 hex). A 64-hex value in
                // that slot is a full 32-byte key on the wire; refuse it by its own named reason even
                // though the type already has no field for raw key bytes.
                if valid_lower_hex_chirho(&blob_ref_chirho.key_id_chirho, NODE_ID_HEX_BYTES_CHIRHO)
                {
                    return Err(MirrorContractErrorChirho::key_bytes_on_wire_chirho());
                }
                if !valid_lower_hex_chirho(&blob_ref_chirho.key_id_chirho, KEY_ID_HEX_BYTES_CHIRHO)
                    || !valid_lower_hex_chirho(
                        &blob_ref_chirho.nonce_chirho,
                        NONCE_HEX_BYTES_CHIRHO,
                    )
                    || !valid_lower_hex_chirho(&blob_ref_chirho.mac_chirho, MAC_HEX_BYTES_CHIRHO)
                    || !valid_lower_hex_chirho(
                        &blob_ref_chirho.ciphertext_chirho.0,
                        DIGEST_HEX_BYTES_CHIRHO,
                    )
                    || blob_ref_chirho.alg_chirho != PRIVATE_BLOB_ALG_CHIRHO
                {
                    return Err(MirrorContractErrorChirho::new_chirho(
                        MirrorRefusalIdentityChirho::MirrorClosureUnverifiedChirho,
                        "sealed private blob ref is malformed or not the supported sealed algorithm",
                    ));
                }
                if ciphertext_addr_chirho != &blob_ref_chirho.ciphertext_chirho {
                    return Err(MirrorContractErrorChirho::new_chirho(
                        MirrorRefusalIdentityChirho::MirrorSealedFamilyIncompleteChirho,
                        "sealed member ciphertext address does not match its blob ref",
                    ));
                }
                privacy_record_prefix_chirho.validate_chirho()?;
                key_custody_confirmation_chirho.validate_chirho()?;
                if key_custody_confirmation_chirho.bound_key_id_chirho
                    != blob_ref_chirho.key_id_chirho
                {
                    return Err(MirrorContractErrorChirho::custody_confirmation_missing_chirho());
                }
                Ok(())
            }
            Self::SignedLedgerRecordChirho {
                cluster_id_chirho,
                journal_genesis_digest_chirho,
                predecessor_seq_chirho,
                predecessor_digest_chirho,
                record_seq_chirho,
                record_digest_chirho,
                canonical_record_line_chirho,
                ..
            } => {
                let next_seq_chirho = predecessor_seq_chirho.checked_add(1);
                if cluster_id_chirho.is_empty()
                    || cluster_id_chirho.len() > MIRROR_CLUSTER_ID_MAX_BYTES_CHIRHO
                    || !cluster_id_chirho.bytes().all(|byte_chirho| {
                        byte_chirho.is_ascii_alphanumeric()
                            || matches!(byte_chirho, b'-' | b'_' | b':' | b'/')
                    })
                    || !valid_lower_hex_chirho(
                        journal_genesis_digest_chirho,
                        DIGEST_HEX_BYTES_CHIRHO,
                    )
                    || !valid_lower_hex_chirho(predecessor_digest_chirho, DIGEST_HEX_BYTES_CHIRHO)
                    || !valid_lower_hex_chirho(&record_digest_chirho.0, DIGEST_HEX_BYTES_CHIRHO)
                    || next_seq_chirho != Some(*record_seq_chirho)
                    || canonical_record_line_chirho.is_empty()
                    || canonical_record_line_chirho.len() > MIRROR_LEDGER_RECORD_MAX_BYTES_CHIRHO
                    || canonical_record_line_chirho
                        .bytes()
                        .any(|byte_chirho| matches!(byte_chirho, b'\r' | b'\n'))
                    || blake3::hash(canonical_record_line_chirho.as_bytes())
                        .to_hex()
                        .as_str()
                        != record_digest_chirho.0
                {
                    return Err(MirrorContractErrorChirho::new_chirho(
                        MirrorRefusalIdentityChirho::MirrorSealedFamilyIncompleteChirho,
                        "signed ledger member is malformed or its canonical line binding disagrees",
                    ));
                }
                Ok(())
            }
        }
    }

    fn update_digest_chirho(&self, hasher_chirho: &mut blake3::Hasher) {
        match self {
            Self::SealedPrivateBlobChirho {
                ciphertext_addr_chirho,
                privacy_record_prefix_chirho,
                blob_ref_chirho,
                key_custody_confirmation_chirho,
            } => {
                hasher_chirho.update(MIRROR_SEALED_MEMBER_DIGEST_DOMAIN_V1_CHIRHO);
                update_digest_field_chirho(
                    hasher_chirho,
                    b"family-chirho",
                    b"f12-sealed-private-blob",
                );
                update_digest_field_chirho(
                    hasher_chirho,
                    b"ciphertext-addr-chirho",
                    ciphertext_addr_chirho.0.as_bytes(),
                );
                update_digest_field_chirho(
                    hasher_chirho,
                    b"blob-key-id-chirho",
                    blob_ref_chirho.key_id_chirho.as_bytes(),
                );
                update_digest_field_chirho(
                    hasher_chirho,
                    b"blob-nonce-chirho",
                    blob_ref_chirho.nonce_chirho.as_bytes(),
                );
                update_digest_field_chirho(
                    hasher_chirho,
                    b"blob-mac-chirho",
                    blob_ref_chirho.mac_chirho.as_bytes(),
                );
                update_digest_field_chirho(
                    hasher_chirho,
                    b"blob-alg-chirho",
                    blob_ref_chirho.alg_chirho.as_bytes(),
                );
                privacy_record_prefix_chirho.update_digest_chirho(hasher_chirho);
                key_custody_confirmation_chirho.update_digest_chirho(hasher_chirho);
            }
            Self::SignedLedgerRecordChirho {
                cluster_id_chirho,
                journal_genesis_digest_chirho,
                predecessor_seq_chirho,
                predecessor_digest_chirho,
                record_seq_chirho,
                record_digest_chirho,
                record_epoch_chirho,
                record_hlc_physical_ms_chirho,
                record_hlc_logical_chirho,
                canonical_record_line_chirho,
            } => {
                hasher_chirho.update(MIRROR_SIGNED_LEDGER_MEMBER_DIGEST_DOMAIN_V1_CHIRHO);
                update_digest_field_chirho(
                    hasher_chirho,
                    b"family-chirho",
                    b"f1-signed-ledger-record",
                );
                update_digest_field_chirho(
                    hasher_chirho,
                    b"cluster-id-chirho",
                    cluster_id_chirho.as_bytes(),
                );
                update_digest_field_chirho(
                    hasher_chirho,
                    b"journal-genesis-digest-chirho",
                    journal_genesis_digest_chirho.as_bytes(),
                );
                update_digest_field_chirho(
                    hasher_chirho,
                    b"predecessor-seq-chirho",
                    &predecessor_seq_chirho.to_le_bytes(),
                );
                update_digest_field_chirho(
                    hasher_chirho,
                    b"predecessor-digest-chirho",
                    predecessor_digest_chirho.as_bytes(),
                );
                update_digest_field_chirho(
                    hasher_chirho,
                    b"record-seq-chirho",
                    &record_seq_chirho.to_le_bytes(),
                );
                update_digest_field_chirho(
                    hasher_chirho,
                    b"record-digest-chirho",
                    record_digest_chirho.0.as_bytes(),
                );
                update_digest_field_chirho(
                    hasher_chirho,
                    b"record-epoch-chirho",
                    &record_epoch_chirho.to_le_bytes(),
                );
                update_digest_field_chirho(
                    hasher_chirho,
                    b"record-hlc-physical-ms-chirho",
                    &record_hlc_physical_ms_chirho.to_le_bytes(),
                );
                update_digest_field_chirho(
                    hasher_chirho,
                    b"record-hlc-logical-chirho",
                    &record_hlc_logical_chirho.to_le_bytes(),
                );
                update_digest_field_chirho(
                    hasher_chirho,
                    b"canonical-record-line-chirho",
                    canonical_record_line_chirho.as_bytes(),
                );
            }
        }
    }

    /// The sealed ciphertext CAS address this member commits to durably store and verify.
    pub fn ciphertext_addr_chirho(&self) -> Option<&HashChirho> {
        match self {
            Self::SealedPrivateBlobChirho {
                ciphertext_addr_chirho,
                ..
            } => Some(ciphertext_addr_chirho),
            Self::SignedLedgerRecordChirho { .. } => None,
        }
    }

    pub fn signed_ledger_record_chirho(
        &self,
    ) -> Option<SignedLedgerRecordMirrorMemberViewChirho<'_>> {
        match self {
            Self::SignedLedgerRecordChirho {
                cluster_id_chirho,
                journal_genesis_digest_chirho,
                predecessor_seq_chirho,
                predecessor_digest_chirho,
                record_seq_chirho,
                record_digest_chirho,
                record_epoch_chirho,
                record_hlc_physical_ms_chirho,
                record_hlc_logical_chirho,
                canonical_record_line_chirho,
            } => Some(SignedLedgerRecordMirrorMemberViewChirho {
                cluster_id_chirho,
                journal_genesis_digest_chirho,
                predecessor_seq_chirho: *predecessor_seq_chirho,
                predecessor_digest_chirho,
                record_seq_chirho: *record_seq_chirho,
                record_digest_chirho,
                record_epoch_chirho: *record_epoch_chirho,
                record_hlc_physical_ms_chirho: *record_hlc_physical_ms_chirho,
                record_hlc_logical_chirho: *record_hlc_logical_chirho,
                canonical_record_line_chirho,
            }),
            Self::SealedPrivateBlobChirho { .. } => None,
        }
    }
}

/// The input a leader assembles before sealing the manifest. `mirror_closure_id` and
/// `manifest_digest` are derived, never supplied.
pub struct MirrorClosureManifestInputChirho {
    pub consistency_group_digest_chirho: String,
    pub caller_idempotency_key_digest_chirho: String,
    pub members_chirho: Vec<MirrorFamilyMemberChirho>,
}

/// The typed sealed closure. Its digest is its own identity (`mirror_closure_id_chirho`), the
/// mirror-internal deterministic key — which never substitutes for the caller idempotency key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorClosureManifestChirho {
    schema_chirho: String,
    consistency_group_digest_chirho: String,
    caller_idempotency_key_digest_chirho: String,
    mirror_closure_id_chirho: String,
    members_chirho: Vec<MirrorFamilyMemberChirho>,
    manifest_digest_chirho: String,
}

impl MirrorClosureManifestChirho {
    pub fn new_chirho(
        input_chirho: MirrorClosureManifestInputChirho,
    ) -> Result<Self, MirrorContractErrorChirho> {
        let mut manifest_chirho = Self {
            schema_chirho: MIRROR_CLOSURE_MANIFEST_SCHEMA_V2_CHIRHO.to_string(),
            consistency_group_digest_chirho: input_chirho.consistency_group_digest_chirho,
            caller_idempotency_key_digest_chirho: input_chirho.caller_idempotency_key_digest_chirho,
            mirror_closure_id_chirho: String::new(),
            members_chirho: input_chirho.members_chirho,
            manifest_digest_chirho: String::new(),
        };
        manifest_chirho.validate_semantics_chirho()?;
        let digest_chirho = manifest_chirho.compute_digest_chirho();
        manifest_chirho.mirror_closure_id_chirho = digest_chirho.clone();
        manifest_chirho.manifest_digest_chirho = digest_chirho;
        Ok(manifest_chirho)
    }

    /// Re-validate a manifest that arrived over the wire: its fields are well formed, its members are
    /// sealed and key-byte-free, and its self-binding digest / closure id recompute exactly.
    pub fn verify_received_chirho(&self) -> Result<(), MirrorContractErrorChirho> {
        self.validate_semantics_chirho()?;
        let digest_chirho = self.compute_digest_chirho();
        if self.manifest_digest_chirho != digest_chirho
            || self.mirror_closure_id_chirho != digest_chirho
        {
            return Err(MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorManifestDigestMismatchChirho,
                "mirror closure manifest digest or closure id does not bind its sealed contents",
            ));
        }
        Ok(())
    }

    fn validate_semantics_chirho(&self) -> Result<(), MirrorContractErrorChirho> {
        if self.schema_chirho != MIRROR_CLOSURE_MANIFEST_SCHEMA_V2_CHIRHO {
            return Err(MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorSchemaUnsupportedChirho,
                "mirror closure manifest schema is unsupported",
            ));
        }
        if !valid_lower_hex_chirho(
            &self.consistency_group_digest_chirho,
            DIGEST_HEX_BYTES_CHIRHO,
        ) {
            return Err(MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorConsistencyGroupMismatchChirho,
                "mirror closure manifest group digest is not canonical hex",
            ));
        }
        if !valid_lower_hex_chirho(
            &self.caller_idempotency_key_digest_chirho,
            DIGEST_HEX_BYTES_CHIRHO,
        ) {
            return Err(MirrorContractErrorChirho::caller_key_missing_chirho());
        }
        if self.members_chirho.is_empty() || self.members_chirho.len() > MIRROR_MAX_MEMBERS_CHIRHO {
            return Err(MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorSealedFamilyIncompleteChirho,
                "mirror closure manifest must carry between one and the bounded number of sealed members",
            ));
        }
        for member_chirho in &self.members_chirho {
            member_chirho.validate_chirho()?;
        }
        Ok(())
    }

    fn compute_digest_chirho(&self) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(MIRROR_CLOSURE_MANIFEST_DIGEST_DOMAIN_V2_CHIRHO);
        update_digest_field_chirho(
            &mut hasher_chirho,
            b"schema-chirho",
            self.schema_chirho.as_bytes(),
        );
        update_digest_field_chirho(
            &mut hasher_chirho,
            b"group-digest-chirho",
            self.consistency_group_digest_chirho.as_bytes(),
        );
        update_digest_field_chirho(
            &mut hasher_chirho,
            b"caller-key-digest-chirho",
            self.caller_idempotency_key_digest_chirho.as_bytes(),
        );
        update_digest_field_chirho(
            &mut hasher_chirho,
            b"member-count-chirho",
            &(self.members_chirho.len() as u64).to_le_bytes(),
        );
        for member_chirho in &self.members_chirho {
            member_chirho.update_digest_chirho(&mut hasher_chirho);
        }
        hasher_chirho.finalize().to_hex().to_string()
    }

    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.consistency_group_digest_chirho
    }

    pub fn caller_idempotency_key_digest_chirho(&self) -> &str {
        &self.caller_idempotency_key_digest_chirho
    }

    pub fn mirror_closure_id_chirho(&self) -> &str {
        &self.mirror_closure_id_chirho
    }

    pub fn manifest_digest_chirho(&self) -> &str {
        &self.manifest_digest_chirho
    }

    pub fn members_chirho(&self) -> &[MirrorFamilyMemberChirho] {
        &self.members_chirho
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn key_id_chirho() -> String {
        "a".repeat(KEY_ID_HEX_BYTES_CHIRHO)
    }

    fn sealed_member_chirho(key_id_chirho: &str) -> MirrorFamilyMemberChirho {
        let ciphertext_chirho = HashChirho("c".repeat(DIGEST_HEX_BYTES_CHIRHO));
        MirrorFamilyMemberChirho::SealedPrivateBlobChirho {
            ciphertext_addr_chirho: ciphertext_chirho.clone(),
            privacy_record_prefix_chirho: LogPrefixBindingChirho {
                family_name_chirho: "privacy-blobs-chirho".to_string(),
                record_count_chirho: 1,
                byte_length_chirho: 512,
                verified_prefix_digest_chirho: "d".repeat(DIGEST_HEX_BYTES_CHIRHO),
            },
            blob_ref_chirho: PrivateBlobRefChirho {
                ciphertext_chirho,
                key_id_chirho: key_id_chirho.to_string(),
                nonce_chirho: "e".repeat(NONCE_HEX_BYTES_CHIRHO),
                mac_chirho: "f".repeat(MAC_HEX_BYTES_CHIRHO),
                alg_chirho: PRIVATE_BLOB_ALG_CHIRHO.to_string(),
            },
            // Built as a struct literal (not `placeholder_chirho`) so a key-material-shaped key id can
            // reach the manifest's own key-bytes-on-wire guard rather than being stopped earlier by
            // the custody constructor's validation.
            key_custody_confirmation_chirho: KeyCustodyConfirmationChirho {
                bound_key_id_chirho: key_id_chirho.to_string(),
                required_custody_regions_chirho: vec![
                    "region-a-chirho".to_string(),
                    "region-b-chirho".to_string(),
                ],
                status_chirho: KeyCustodyStatusChirho::PlaceholderPendingCustodyChirho,
            },
        }
    }

    fn manifest_chirho(
        members_chirho: Vec<MirrorFamilyMemberChirho>,
    ) -> MirrorClosureManifestChirho {
        MirrorClosureManifestChirho::new_chirho(MirrorClosureManifestInputChirho {
            consistency_group_digest_chirho: "1".repeat(DIGEST_HEX_BYTES_CHIRHO),
            caller_idempotency_key_digest_chirho: "2".repeat(DIGEST_HEX_BYTES_CHIRHO),
            members_chirho,
        })
        .expect("well-formed manifest")
    }

    #[test]
    fn a_well_formed_manifest_binds_its_closure_id_to_its_digest_chirho() {
        let manifest_chirho = manifest_chirho(vec![sealed_member_chirho(&key_id_chirho())]);
        assert_eq!(
            manifest_chirho.mirror_closure_id_chirho(),
            manifest_chirho.manifest_digest_chirho(),
            "the mirror-internal key IS the manifest digest"
        );
        manifest_chirho
            .verify_received_chirho()
            .expect("a freshly built manifest re-verifies");
    }

    #[test]
    fn a_64_hex_key_id_is_key_bytes_on_the_wire_and_refuses_chirho() {
        // A 16-byte key id is 32 hex; a 32-byte SHRED KEY is 64 hex. A 64-hex value in the key-id
        // slot is key material on the wire, refused by its own named reason.
        let key_shaped_chirho = "b".repeat(NODE_ID_HEX_BYTES_CHIRHO);
        let error_chirho =
            MirrorClosureManifestChirho::new_chirho(MirrorClosureManifestInputChirho {
                consistency_group_digest_chirho: "1".repeat(DIGEST_HEX_BYTES_CHIRHO),
                caller_idempotency_key_digest_chirho: "2".repeat(DIGEST_HEX_BYTES_CHIRHO),
                members_chirho: vec![sealed_member_chirho(&key_shaped_chirho)],
            })
            .expect_err("a key-material-shaped key id must refuse");
        assert_eq!(
            error_chirho.identity_chirho(),
            MirrorRefusalIdentityChirho::MirrorKeyBytesOnWireChirho
        );
    }

    #[test]
    fn an_empty_custody_region_set_fails_closed_chirho() {
        // OQ-7 fail-closed: an unconfirmed custody placeholder (no required regions) refuses.
        let error_chirho =
            KeyCustodyConfirmationChirho::placeholder_chirho(key_id_chirho(), vec![])
                .expect_err("empty custody region set must fail closed");
        assert_eq!(
            error_chirho.identity_chirho(),
            MirrorRefusalIdentityChirho::MirrorCustodyConfirmationMissingChirho
        );
    }

    #[test]
    fn a_tampered_digest_field_fails_verification_chirho() {
        let mut manifest_chirho = manifest_chirho(vec![sealed_member_chirho(&key_id_chirho())]);
        manifest_chirho.caller_idempotency_key_digest_chirho = "3".repeat(DIGEST_HEX_BYTES_CHIRHO);
        assert_eq!(
            manifest_chirho
                .verify_received_chirho()
                .expect_err("a mutated field must break the self-binding digest")
                .identity_chirho(),
            MirrorRefusalIdentityChirho::MirrorManifestDigestMismatchChirho
        );
    }
}
