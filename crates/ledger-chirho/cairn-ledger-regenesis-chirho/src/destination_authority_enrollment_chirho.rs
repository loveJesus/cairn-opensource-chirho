// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Establish one public-only migration destination authority against a retained cluster-genesis
//! roster bundle.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`
//!
//! The roster, signed roster head, and reviewed roster-operator public key are verified before the
//! external destination-authority key is read. Parsing and signature verification GATE the head;
//! its identity is BLAKE3 of the original retained bytes, never a parsed-value reserialization.
//! The resulting enrollment proves key possession plus binding to that verified genesis bundle. It
//! does not prove operator review, key legitimacy, or external custody; those remain procedural at
//! cluster genesis.

use crate::bounded_file_chirho::read_bounded_regular_file_chirho;
use crate::error_chirho::{LedgerRegenesisRefusalChirho, LedgerRegenesisResultChirho};
use cairn_config_chirho::config_chirho::LedgerHostMigrationDestinationAuthorityConfigChirho;
use cairn_replication_chirho::membership_chirho::verify_membership_roster_with_head_chirho;
use cairn_signer_chirho::signer_chirho::{
    existing_keypair_pubkey_hex_chirho, sign_with_existing_key_possession_chirho,
    verify_with_pubkey_chirho, ExistingKeyPossessionChirho,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const DESTINATION_AUTHORITY_ENROLLMENT_INTENT_SCHEMA_V1_CHIRHO: &str =
    "ledger-host-destination-authority-enrollment-intent-v1-chirho";
pub const DESTINATION_AUTHORITY_ENROLLMENT_RECORD_SCHEMA_V1_CHIRHO: &str =
    "ledger-host-destination-authority-enrollment-record-v1-chirho";
pub const DESTINATION_AUTHORITY_ENROLLMENT_SIGNATURE_DOMAIN_V1_CHIRHO: &str =
    "ledger-host-destination-authority-enrollment-signature-v1-chirho";

const MAX_DESTINATION_AUTHORITY_ENROLLMENT_BYTES_CHIRHO: u64 = 16 * 1024;
const MAX_CLUSTER_GENESIS_ROSTER_BYTES_CHIRHO: u64 = 512 * 1024;
const MAX_CLUSTER_GENESIS_ROSTER_HEAD_BYTES_CHIRHO: u64 = 16 * 1024;
const ED25519_PUBLIC_KEY_HEX_BYTES_CHIRHO: usize = 64;
const BLAKE3_HEX_BYTES_CHIRHO: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationAuthorityEnrollmentIntentV1Chirho {
    pub schema_chirho: String,
    /// BLAKE3 of the exact retained signed roster-HEAD bytes, not a reserialization.
    pub cluster_genesis_roster_head_blake3_chirho: String,
    /// The independently reviewed public key used to verify the retained roster plus head.
    pub cluster_genesis_roster_operator_pubkey_hex_chirho: String,
    /// The public half the host config will pin. The corresponding seed never enters node custody.
    pub destination_authority_verifying_key_hex_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationAuthorityEnrollmentRecordV1Chirho {
    pub schema_chirho: String,
    pub signature_domain_chirho: String,
    pub intent_chirho: DestinationAuthorityEnrollmentIntentV1Chirho,
    pub intent_digest_chirho: String,
    /// Exactly the destination public key, following the roster family's existing key-id rule.
    pub authority_key_id_chirho: String,
    pub sig_chirho: String,
}

/// Inputs to the one external-key authoring act. The output path is a CLI concern so this function
/// can self-verify before any artifact is written.
pub struct DestinationAuthorityEnrollmentAuthorRequestChirho<'request_chirho> {
    pub destination_authority_signing_root_chirho: &'request_chirho Path,
    pub cluster_genesis_roster_path_chirho: &'request_chirho Path,
    pub cluster_genesis_roster_head_path_chirho: &'request_chirho Path,
    pub cluster_genesis_roster_operator_pubkey_hex_chirho: &'request_chirho str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthoredDestinationAuthorityEnrollmentChirho {
    pub canonical_record_bytes_chirho: Vec<u8>,
    pub enrollment_digest_chirho: String,
    pub cluster_genesis_roster_head_blake3_chirho: String,
    pub verified_roster_record_count_chirho: u64,
    pub verified_active_member_count_chirho: u64,
}

/// A public-only enrollment obtainable only through full record and retained-genesis verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDestinationAuthorityEnrollmentChirho {
    record_chirho: DestinationAuthorityEnrollmentRecordV1Chirho,
    enrollment_digest_chirho: String,
    verified_roster_record_count_chirho: u64,
    verified_active_member_count_chirho: u64,
}

impl VerifiedDestinationAuthorityEnrollmentChirho {
    pub fn enrollment_digest_chirho(&self) -> &str {
        &self.enrollment_digest_chirho
    }

    pub fn cluster_genesis_roster_head_blake3_chirho(&self) -> &str {
        &self
            .record_chirho
            .intent_chirho
            .cluster_genesis_roster_head_blake3_chirho
    }

    pub fn verified_roster_record_count_chirho(&self) -> u64 {
        self.verified_roster_record_count_chirho
    }

    pub fn verified_active_member_count_chirho(&self) -> u64 {
        self.verified_active_member_count_chirho
    }

    pub(crate) fn destination_authority_config_chirho(
        &self,
    ) -> LedgerHostMigrationDestinationAuthorityConfigChirho {
        LedgerHostMigrationDestinationAuthorityConfigChirho {
            key_id_chirho: self.record_chirho.authority_key_id_chirho.clone(),
            verifying_key_hex_chirho: self
                .record_chirho
                .intent_chirho
                .destination_authority_verifying_key_hex_chirho
                .clone(),
        }
    }
}

struct VerifiedClusterGenesisRosterChirho {
    roster_head_blake3_chirho: String,
    roster_operator_pubkey_hex_chirho: String,
    roster_record_count_chirho: u64,
    active_member_count_chirho: u64,
}

/// Author and self-verify one purpose-specific enrollment with an EXISTING external keypair.
///
/// The genesis bundle is fully verified first. A wrong roster/head/operator-key combination must
/// therefore refuse before this function reads the destination authority's private custody.
pub fn author_destination_authority_enrollment_chirho(
    request_chirho: DestinationAuthorityEnrollmentAuthorRequestChirho<'_>,
) -> LedgerRegenesisResultChirho<AuthoredDestinationAuthorityEnrollmentChirho> {
    let genesis_chirho = read_and_verify_cluster_genesis_roster_chirho(
        request_chirho.cluster_genesis_roster_path_chirho,
        request_chirho.cluster_genesis_roster_head_path_chirho,
        request_chirho.cluster_genesis_roster_operator_pubkey_hex_chirho,
    )?;
    let destination_authority_key_chirho = existing_keypair_pubkey_hex_chirho(
        request_chirho.destination_authority_signing_root_chirho,
    )
    .map_err(|_error_chirho| {
        LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentSigningKeyRefusedChirho
    })?;
    validate_public_key_hex_chirho(&destination_authority_key_chirho).map_err(
        |_refusal_chirho| {
            LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentSigningKeyRefusedChirho
        },
    )?;

    let intent_chirho = DestinationAuthorityEnrollmentIntentV1Chirho {
        schema_chirho: DESTINATION_AUTHORITY_ENROLLMENT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
        cluster_genesis_roster_head_blake3_chirho: genesis_chirho.roster_head_blake3_chirho.clone(),
        cluster_genesis_roster_operator_pubkey_hex_chirho: genesis_chirho
            .roster_operator_pubkey_hex_chirho
            .clone(),
        destination_authority_verifying_key_hex_chirho: destination_authority_key_chirho.clone(),
    };
    let intent_digest_chirho =
        destination_authority_enrollment_intent_digest_chirho(&intent_chirho)?;
    let mut record_chirho = DestinationAuthorityEnrollmentRecordV1Chirho {
        schema_chirho: DESTINATION_AUTHORITY_ENROLLMENT_RECORD_SCHEMA_V1_CHIRHO.to_owned(),
        signature_domain_chirho: DESTINATION_AUTHORITY_ENROLLMENT_SIGNATURE_DOMAIN_V1_CHIRHO
            .to_owned(),
        intent_chirho,
        intent_digest_chirho,
        authority_key_id_chirho: destination_authority_key_chirho,
        sig_chirho: String::new(),
    };
    let unsigned_message_chirho =
        destination_authority_enrollment_unsigned_message_chirho(&record_chirho);
    let possession_chirho = sign_with_existing_key_possession_chirho(
        request_chirho.destination_authority_signing_root_chirho,
        unsigned_message_chirho.as_bytes(),
    )
    .map_err(|_error_chirho| {
        LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentSigningKeyRefusedChirho
    })?;
    bind_destination_authority_possession_chirho(&mut record_chirho, possession_chirho)?;
    let canonical_record_bytes_chirho =
        serde_json::to_vec(&record_chirho).map_err(|_error_chirho| {
            LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentInvalidChirho
        })?;
    let enrollment_digest_chirho =
        destination_authority_enrollment_digest_chirho(&canonical_record_bytes_chirho);
    let verified_chirho = verify_destination_authority_enrollment_bytes_chirho(
        &canonical_record_bytes_chirho,
        enrollment_digest_chirho,
        &genesis_chirho,
    )?;
    Ok(AuthoredDestinationAuthorityEnrollmentChirho {
        canonical_record_bytes_chirho,
        enrollment_digest_chirho: verified_chirho.enrollment_digest_chirho().to_owned(),
        cluster_genesis_roster_head_blake3_chirho: verified_chirho
            .cluster_genesis_roster_head_blake3_chirho()
            .to_owned(),
        verified_roster_record_count_chirho: verified_chirho.verified_roster_record_count_chirho,
        verified_active_member_count_chirho: verified_chirho.verified_active_member_count_chirho,
    })
}

/// Review one enrollment without a caller-supplied digest. It writes nothing and reports the exact
/// digest the emitting host-author road must later require.
pub fn read_destination_authority_enrollment_chirho(
    enrollment_path_chirho: &Path,
    cluster_genesis_roster_path_chirho: &Path,
    cluster_genesis_roster_head_path_chirho: &Path,
    cluster_genesis_roster_operator_pubkey_hex_chirho: &str,
) -> LedgerRegenesisResultChirho<VerifiedDestinationAuthorityEnrollmentChirho> {
    let enrollment_bytes_chirho =
        read_destination_authority_enrollment_bytes_chirho(enrollment_path_chirho)?;
    let enrollment_digest_chirho =
        destination_authority_enrollment_digest_chirho(&enrollment_bytes_chirho);
    let genesis_chirho = read_and_verify_cluster_genesis_roster_chirho(
        cluster_genesis_roster_path_chirho,
        cluster_genesis_roster_head_path_chirho,
        cluster_genesis_roster_operator_pubkey_hex_chirho,
    )?;
    verify_destination_authority_enrollment_bytes_chirho(
        &enrollment_bytes_chirho,
        enrollment_digest_chirho,
        &genesis_chirho,
    )
}

/// Load the exact reviewed enrollment. Digest shape and byte equality are decided before the
/// record is parsed, the destination pin is derived, or any node-root signer custody is opened.
pub fn read_digest_bound_destination_authority_enrollment_chirho(
    enrollment_path_chirho: &Path,
    expected_enrollment_digest_chirho: &str,
    cluster_genesis_roster_path_chirho: &Path,
    cluster_genesis_roster_head_path_chirho: &Path,
    cluster_genesis_roster_operator_pubkey_hex_chirho: &str,
) -> LedgerRegenesisResultChirho<VerifiedDestinationAuthorityEnrollmentChirho> {
    validate_blake3_hex_chirho(expected_enrollment_digest_chirho).map_err(|_refusal_chirho| {
        LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentDigestInvalidChirho
    })?;
    let enrollment_bytes_chirho =
        read_destination_authority_enrollment_bytes_chirho(enrollment_path_chirho)?;
    let enrollment_digest_chirho =
        destination_authority_enrollment_digest_chirho(&enrollment_bytes_chirho);
    if enrollment_digest_chirho != expected_enrollment_digest_chirho {
        return Err(
            LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentDigestMismatchChirho,
        );
    }
    let genesis_chirho = read_and_verify_cluster_genesis_roster_chirho(
        cluster_genesis_roster_path_chirho,
        cluster_genesis_roster_head_path_chirho,
        cluster_genesis_roster_operator_pubkey_hex_chirho,
    )?;
    verify_destination_authority_enrollment_bytes_chirho(
        &enrollment_bytes_chirho,
        enrollment_digest_chirho,
        &genesis_chirho,
    )
}

pub fn destination_authority_enrollment_digest_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}

fn destination_authority_enrollment_intent_digest_chirho(
    intent_chirho: &DestinationAuthorityEnrollmentIntentV1Chirho,
) -> LedgerRegenesisResultChirho<String> {
    let bytes_chirho = serde_json::to_vec(intent_chirho).map_err(|_error_chirho| {
        LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentInvalidChirho
    })?;
    Ok(blake3::hash(&bytes_chirho).to_hex().to_string())
}

pub(crate) fn destination_authority_enrollment_unsigned_message_chirho(
    record_chirho: &DestinationAuthorityEnrollmentRecordV1Chirho,
) -> String {
    // Authoring supplies constants plus validated hex, and verification validates every variable
    // field before calling this function. Preserve that ordering: it is what keeps `|` unavailable
    // to a delimiter injection.
    format!(
        "{}|{}|{}|{}",
        record_chirho.signature_domain_chirho,
        record_chirho.schema_chirho,
        record_chirho.authority_key_id_chirho,
        record_chirho.intent_digest_chirho
    )
}

pub(crate) fn bind_destination_authority_possession_chirho(
    record_chirho: &mut DestinationAuthorityEnrollmentRecordV1Chirho,
    possession_chirho: ExistingKeyPossessionChirho,
) -> LedgerRegenesisResultChirho<()> {
    if possession_chirho.key_id_chirho() != record_chirho.authority_key_id_chirho {
        return Err(
            LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentSigningKeyRefusedChirho,
        );
    }
    record_chirho.sig_chirho = possession_chirho.into_signature_hex_chirho();
    Ok(())
}

fn read_destination_authority_enrollment_bytes_chirho(
    path_chirho: &Path,
) -> LedgerRegenesisResultChirho<Vec<u8>> {
    read_bounded_regular_file_chirho(
        path_chirho,
        MAX_DESTINATION_AUTHORITY_ENROLLMENT_BYTES_CHIRHO,
    )
    .map_err(|error_chirho| match error_chirho.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
            LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentUnavailableChirho
        }
        _ => LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentNotRegularChirho,
    })
}

fn read_and_verify_cluster_genesis_roster_chirho(
    roster_path_chirho: &Path,
    roster_head_path_chirho: &Path,
    roster_operator_pubkey_hex_chirho: &str,
) -> LedgerRegenesisResultChirho<VerifiedClusterGenesisRosterChirho> {
    validate_public_key_hex_chirho(roster_operator_pubkey_hex_chirho).map_err(
        |_refusal_chirho| {
            LedgerRegenesisRefusalChirho::ClusterGenesisRosterOperatorKeyInvalidChirho
        },
    )?;
    let roster_bytes_chirho = read_bounded_regular_file_chirho(
        roster_path_chirho,
        MAX_CLUSTER_GENESIS_ROSTER_BYTES_CHIRHO,
    )
    .map_err(|error_chirho| match error_chirho.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
            LedgerRegenesisRefusalChirho::ClusterGenesisRosterUnavailableChirho
        }
        _ => LedgerRegenesisRefusalChirho::ClusterGenesisRosterNotRegularChirho,
    })?;
    let roster_head_bytes_chirho = read_bounded_regular_file_chirho(
        roster_head_path_chirho,
        MAX_CLUSTER_GENESIS_ROSTER_HEAD_BYTES_CHIRHO,
    )
    .map_err(|error_chirho| match error_chirho.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
            LedgerRegenesisRefusalChirho::ClusterGenesisRosterHeadUnavailableChirho
        }
        _ => LedgerRegenesisRefusalChirho::ClusterGenesisRosterHeadNotRegularChirho,
    })?;
    let roster_text_chirho =
        std::str::from_utf8(&roster_bytes_chirho).map_err(|_error_chirho| {
            LedgerRegenesisRefusalChirho::ClusterGenesisRosterVerificationRefusedChirho
        })?;
    let roster_lines_chirho: Vec<Vec<u8>> = roster_text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .map(|line_chirho| line_chirho.as_bytes().to_vec())
        .collect();
    if roster_lines_chirho.is_empty() {
        return Err(LedgerRegenesisRefusalChirho::ClusterGenesisRosterVerificationRefusedChirho);
    }
    let verified_membership_chirho = verify_membership_roster_with_head_chirho(
        &roster_lines_chirho,
        &roster_head_bytes_chirho,
        roster_operator_pubkey_hex_chirho,
    )
    .map_err(|_error_chirho| {
        LedgerRegenesisRefusalChirho::ClusterGenesisRosterVerificationRefusedChirho
    })?;
    Ok(VerifiedClusterGenesisRosterChirho {
        // Parse and verify to gate, hash the ORIGINAL bytes to identify. Re-serializing here would
        // make field-order or escaping changes look like genesis tamper on a coordinate that does
        // not rotate.
        roster_head_blake3_chirho: blake3::hash(&roster_head_bytes_chirho).to_hex().to_string(),
        roster_operator_pubkey_hex_chirho: roster_operator_pubkey_hex_chirho.to_owned(),
        roster_record_count_chirho: roster_lines_chirho.len() as u64,
        active_member_count_chirho: verified_membership_chirho.active_count_chirho() as u64,
    })
}

fn verify_destination_authority_enrollment_bytes_chirho(
    bytes_chirho: &[u8],
    enrollment_digest_chirho: String,
    genesis_chirho: &VerifiedClusterGenesisRosterChirho,
) -> LedgerRegenesisResultChirho<VerifiedDestinationAuthorityEnrollmentChirho> {
    let record_chirho: DestinationAuthorityEnrollmentRecordV1Chirho =
        serde_json::from_slice(bytes_chirho).map_err(|_error_chirho| {
            LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentInvalidChirho
        })?;
    let canonical_bytes_chirho = serde_json::to_vec(&record_chirho).map_err(|_error_chirho| {
        LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentInvalidChirho
    })?;
    if canonical_bytes_chirho != bytes_chirho {
        return Err(LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentNonCanonicalChirho);
    }
    let DestinationAuthorityEnrollmentIntentV1Chirho {
        schema_chirho: intent_schema_chirho,
        cluster_genesis_roster_head_blake3_chirho,
        cluster_genesis_roster_operator_pubkey_hex_chirho,
        destination_authority_verifying_key_hex_chirho,
    } = &record_chirho.intent_chirho;
    if record_chirho.schema_chirho != DESTINATION_AUTHORITY_ENROLLMENT_RECORD_SCHEMA_V1_CHIRHO
        || intent_schema_chirho != DESTINATION_AUTHORITY_ENROLLMENT_INTENT_SCHEMA_V1_CHIRHO
        || record_chirho.signature_domain_chirho
            != DESTINATION_AUTHORITY_ENROLLMENT_SIGNATURE_DOMAIN_V1_CHIRHO
    {
        return Err(
            LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentSchemaRefusedChirho,
        );
    }
    validate_public_key_hex_chirho(&record_chirho.authority_key_id_chirho)?;
    validate_public_key_hex_chirho(destination_authority_verifying_key_hex_chirho)?;
    validate_public_key_hex_chirho(cluster_genesis_roster_operator_pubkey_hex_chirho)?;
    validate_blake3_hex_chirho(&record_chirho.intent_digest_chirho)?;
    validate_blake3_hex_chirho(cluster_genesis_roster_head_blake3_chirho)?;
    if record_chirho.authority_key_id_chirho != *destination_authority_verifying_key_hex_chirho {
        return Err(
            LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentAuthorityBindingRefusedChirho,
        );
    }
    let recomputed_intent_digest_chirho =
        destination_authority_enrollment_intent_digest_chirho(&record_chirho.intent_chirho)?;
    if recomputed_intent_digest_chirho != record_chirho.intent_digest_chirho {
        return Err(
            LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentIntentDigestMismatchChirho,
        );
    }
    let unsigned_message_chirho =
        destination_authority_enrollment_unsigned_message_chirho(&record_chirho);
    let signature_valid_chirho = verify_with_pubkey_chirho(
        destination_authority_verifying_key_hex_chirho,
        unsigned_message_chirho.as_bytes(),
        &record_chirho.sig_chirho,
    )
    .map_err(|_error_chirho| {
        LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentSignatureRefusedChirho
    })?;
    if !signature_valid_chirho {
        return Err(
            LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentSignatureRefusedChirho,
        );
    }
    if cluster_genesis_roster_head_blake3_chirho != &genesis_chirho.roster_head_blake3_chirho
        || cluster_genesis_roster_operator_pubkey_hex_chirho
            != &genesis_chirho.roster_operator_pubkey_hex_chirho
    {
        return Err(
            LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentGenesisBindingRefusedChirho,
        );
    }
    Ok(VerifiedDestinationAuthorityEnrollmentChirho {
        record_chirho,
        enrollment_digest_chirho,
        verified_roster_record_count_chirho: genesis_chirho.roster_record_count_chirho,
        verified_active_member_count_chirho: genesis_chirho.active_member_count_chirho,
    })
}

fn validate_public_key_hex_chirho(value_chirho: &str) -> LedgerRegenesisResultChirho<()> {
    if value_chirho.len() != ED25519_PUBLIC_KEY_HEX_BYTES_CHIRHO
        || !value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || matches!(byte_chirho, b'a'..=b'f'))
        || value_chirho.bytes().all(|byte_chirho| byte_chirho == b'0')
    {
        return Err(
            LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentAuthorityBindingRefusedChirho,
        );
    }
    Ok(())
}

fn validate_blake3_hex_chirho(value_chirho: &str) -> LedgerRegenesisResultChirho<()> {
    if value_chirho.len() != BLAKE3_HEX_BYTES_CHIRHO
        || !value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || matches!(byte_chirho, b'a'..=b'f'))
    {
        return Err(LedgerRegenesisRefusalChirho::DestinationAuthorityEnrollmentInvalidChirho);
    }
    Ok(())
}

/// Broad derivation/custody tests exercise laws outside enrollment verification. Give those tests a
/// typed value without exporting a production constructor; the dedicated enrollment tests below
/// obtain the type only through the real author/read verifier.
#[cfg(test)]
pub(crate) fn test_verified_destination_authority_enrollment_chirho(
) -> &'static VerifiedDestinationAuthorityEnrollmentChirho {
    use ed25519_dalek::SigningKey;
    use std::sync::OnceLock;

    static ENROLLMENT_CHIRHO: OnceLock<VerifiedDestinationAuthorityEnrollmentChirho> =
        OnceLock::new();
    ENROLLMENT_CHIRHO.get_or_init(|| {
        let destination_key_chirho = SigningKey::from_bytes(&[91_u8; 32])
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|byte_chirho| format!("{byte_chirho:02x}"))
            .collect::<String>();
        let operator_key_chirho = SigningKey::from_bytes(&[92_u8; 32])
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|byte_chirho| format!("{byte_chirho:02x}"))
            .collect::<String>();
        let intent_chirho = DestinationAuthorityEnrollmentIntentV1Chirho {
            schema_chirho: DESTINATION_AUTHORITY_ENROLLMENT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
            cluster_genesis_roster_head_blake3_chirho: "ab".repeat(32),
            cluster_genesis_roster_operator_pubkey_hex_chirho: operator_key_chirho,
            destination_authority_verifying_key_hex_chirho: destination_key_chirho.clone(),
        };
        let intent_digest_chirho =
            destination_authority_enrollment_intent_digest_chirho(&intent_chirho)
                .expect("the fixed test-only intent serializes");
        let record_chirho = DestinationAuthorityEnrollmentRecordV1Chirho {
            schema_chirho: DESTINATION_AUTHORITY_ENROLLMENT_RECORD_SCHEMA_V1_CHIRHO.to_owned(),
            signature_domain_chirho: DESTINATION_AUTHORITY_ENROLLMENT_SIGNATURE_DOMAIN_V1_CHIRHO
                .to_owned(),
            intent_chirho,
            intent_digest_chirho,
            authority_key_id_chirho: destination_key_chirho,
            sig_chirho: "cd".repeat(64),
        };
        let canonical_bytes_chirho =
            serde_json::to_vec(&record_chirho).expect("the fixed test-only record serializes");
        VerifiedDestinationAuthorityEnrollmentChirho {
            record_chirho,
            enrollment_digest_chirho: destination_authority_enrollment_digest_chirho(
                &canonical_bytes_chirho,
            ),
            verified_roster_record_count_chirho: 1,
            verified_active_member_count_chirho: 1,
        }
    })
}
