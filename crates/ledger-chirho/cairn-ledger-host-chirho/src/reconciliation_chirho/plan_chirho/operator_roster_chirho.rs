// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Signed, custody-anchored authorization for GD7 manual dispositions.

use super::super::contract_chirho::{
    consistency_group_digest_suffix_chirho, is_lower_hex_digest_chirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use serde::{Deserialize, Serialize};

pub const GD7_OPERATOR_ROSTER_SCHEMA_V1_CHIRHO: &str = "gd7-operator-roster-v1-chirho";
const GD7_OPERATOR_ROSTER_NAMESPACE_CHIRHO: &str =
    "gd7-reconciliation-chirho/operator-roster-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Gd7OperatorRosterRoleChirho {
    Gd7DispositionChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7OperatorRosterMemberChirho {
    pub operator_key_id_chirho: String,
    pub role_chirho: Gd7OperatorRosterRoleChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7OperatorRosterChirho {
    pub schema_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub roster_epoch_chirho: u64,
    pub signer_key_id_chirho: String,
    pub members_chirho: Vec<Gd7OperatorRosterMemberChirho>,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gd7OperatorRosterRefusalChirho {
    MissingChirho,
    InvalidLatestChirho,
    InvalidSignatureChirho,
    InvalidShapeChirho,
    UnauthorizedOperatorChirho,
    StorageChirho,
    SerializationChirho,
    EpochRegressionChirho,
}

impl std::fmt::Display for Gd7OperatorRosterRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message_chirho = match self {
            Self::MissingChirho => "GD7 operator roster is missing",
            Self::InvalidLatestChirho => "latest GD7 operator roster is invalid",
            Self::InvalidSignatureChirho => "GD7 operator roster signature is invalid",
            Self::InvalidShapeChirho => "GD7 operator roster shape is invalid",
            Self::UnauthorizedOperatorChirho => "operator lacks the GD7 disposition role",
            Self::StorageChirho => "GD7 operator roster storage failed",
            Self::SerializationChirho => "GD7 operator roster serialization failed",
            Self::EpochRegressionChirho => "GD7 operator roster epoch regressed",
        };
        formatter_chirho.write_str(message_chirho)
    }
}
impl std::error::Error for Gd7OperatorRosterRefusalChirho {}

fn roster_prefix_chirho(
    group_chirho: &str,
) -> Result<StoragePathChirho, Gd7OperatorRosterRefusalChirho> {
    if !is_lower_hex_digest_chirho(group_chirho)
        && consistency_group_digest_suffix_chirho(group_chirho).is_none()
    {
        return Err(Gd7OperatorRosterRefusalChirho::InvalidShapeChirho);
    }
    let path_group_chirho =
        consistency_group_digest_suffix_chirho(group_chirho).unwrap_or(group_chirho);
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_OPERATOR_ROSTER_NAMESPACE_CHIRHO}/{path_group_chirho}/"
    )))
}

fn unsigned_bytes_chirho(
    roster_chirho: &Gd7OperatorRosterChirho,
) -> Result<Vec<u8>, Gd7OperatorRosterRefusalChirho> {
    let mut unsigned_chirho = roster_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    serde_json::to_vec(&unsigned_chirho)
        .map_err(|_| Gd7OperatorRosterRefusalChirho::SerializationChirho)
}

fn validate_roster_chirho(
    roster_chirho: &Gd7OperatorRosterChirho,
    group_chirho: &str,
) -> Result<(), Gd7OperatorRosterRefusalChirho> {
    if roster_chirho.schema_chirho != GD7_OPERATOR_ROSTER_SCHEMA_V1_CHIRHO
        || roster_chirho.consistency_group_digest_chirho != group_chirho
        || roster_chirho.roster_epoch_chirho == 0
        || !is_lower_hex_digest_chirho(&roster_chirho.signer_key_id_chirho)
        || roster_chirho.members_chirho.is_empty()
        || roster_chirho
            .members_chirho
            .iter()
            .any(|member_chirho| !is_lower_hex_digest_chirho(&member_chirho.operator_key_id_chirho))
    {
        return Err(Gd7OperatorRosterRefusalChirho::InvalidShapeChirho);
    }
    Ok(())
}

/// Verify the latest revision only. A malformed newest revision is never bypassed by an older one.
pub fn load_verified_gd7_operator_roster_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    group_chirho: &str,
    expected_signer_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    operator_key_id_chirho: &str,
) -> Result<Gd7OperatorRosterChirho, Gd7OperatorRosterRefusalChirho> {
    let prefix_chirho = roster_prefix_chirho(group_chirho)?;
    let paths_chirho = storage_chirho
        .list_chirho(&prefix_chirho)
        .map_err(|_| Gd7OperatorRosterRefusalChirho::StorageChirho)?;
    let mut latest_chirho: Option<(u64, StoragePathChirho)> = None;
    for path_chirho in paths_chirho {
        let key_chirho = path_chirho.key_chirho();
        let Some(epoch_text_chirho) = key_chirho
            .strip_suffix(".json")
            .and_then(|value_chirho| value_chirho.rsplit('/').next())
        else {
            continue;
        };
        let Ok(epoch_chirho) = epoch_text_chirho.parse::<u64>() else {
            continue;
        };
        if latest_chirho
            .as_ref()
            .is_none_or(|(current_chirho, _)| epoch_chirho > *current_chirho)
        {
            latest_chirho = Some((epoch_chirho, path_chirho));
        }
    }
    let (_, path_chirho) = latest_chirho.ok_or(Gd7OperatorRosterRefusalChirho::MissingChirho)?;
    let bytes_chirho = storage_chirho
        .read_all_chirho(&path_chirho)
        .map_err(|_| Gd7OperatorRosterRefusalChirho::StorageChirho)?
        .ok_or(Gd7OperatorRosterRefusalChirho::MissingChirho)?;
    let roster_chirho: Gd7OperatorRosterChirho = serde_json::from_slice(&bytes_chirho)
        .map_err(|_| Gd7OperatorRosterRefusalChirho::InvalidLatestChirho)?;
    validate_roster_chirho(&roster_chirho, group_chirho)?;
    if roster_chirho.signer_key_id_chirho != expected_signer_chirho.key_id_chirho() {
        return Err(Gd7OperatorRosterRefusalChirho::InvalidSignatureChirho);
    }
    let unsigned_chirho = unsigned_bytes_chirho(&roster_chirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_chirho)
        .map_err(|_| Gd7OperatorRosterRefusalChirho::SerializationChirho)?;
    if !expected_signer_chirho.verify_chirho(unsigned_line_chirho, &roster_chirho.sig_chirho) {
        return Err(Gd7OperatorRosterRefusalChirho::InvalidSignatureChirho);
    }
    if !roster_chirho.members_chirho.iter().any(|member_chirho| {
        member_chirho.operator_key_id_chirho == operator_key_id_chirho
            && matches!(
                member_chirho.role_chirho,
                Gd7OperatorRosterRoleChirho::Gd7DispositionChirho
            )
    }) {
        return Err(Gd7OperatorRosterRefusalChirho::UnauthorizedOperatorChirho);
    }
    Ok(roster_chirho)
}

/// Create or rotate one signed revision. The custody signer is the only signing authority.
pub fn write_gd7_operator_roster_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    group_chirho: &str,
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    mut roster_chirho: Gd7OperatorRosterChirho,
) -> Result<Gd7OperatorRosterChirho, Gd7OperatorRosterRefusalChirho> {
    validate_roster_chirho(&roster_chirho, group_chirho)?;
    if roster_chirho.signer_key_id_chirho != signer_chirho.key_id_chirho() {
        return Err(Gd7OperatorRosterRefusalChirho::InvalidSignatureChirho);
    }
    let prefix_chirho = roster_prefix_chirho(group_chirho)?;
    let current_epoch_chirho = storage_chirho
        .list_chirho(&prefix_chirho)
        .map_err(|_| Gd7OperatorRosterRefusalChirho::StorageChirho)?
        .into_iter()
        .filter_map(|path_chirho| {
            path_chirho
                .key_chirho()
                .strip_suffix(".json")
                .and_then(|value_chirho| value_chirho.rsplit('/').next())
                .and_then(|value_chirho| value_chirho.parse::<u64>().ok())
        })
        .max()
        .unwrap_or(0);
    if roster_chirho.roster_epoch_chirho <= current_epoch_chirho {
        return Err(Gd7OperatorRosterRefusalChirho::EpochRegressionChirho);
    }
    roster_chirho.sig_chirho = signer_chirho
        .sign_chirho(
            std::str::from_utf8(&unsigned_bytes_chirho(&roster_chirho)?)
                .map_err(|_| Gd7OperatorRosterRefusalChirho::SerializationChirho)?,
        )
        .map_err(|_| Gd7OperatorRosterRefusalChirho::SerializationChirho)?;
    let bytes_chirho = serde_json::to_vec(&roster_chirho)
        .map_err(|_| Gd7OperatorRosterRefusalChirho::SerializationChirho)?;
    let path_chirho = StoragePathChirho::new_chirho(format!(
        "{}{}/{}.json",
        prefix_chirho.key_chirho(),
        roster_chirho.roster_epoch_chirho,
        roster_chirho.roster_epoch_chirho
    ));
    match storage_chirho
        .create_durable_chirho(&path_chirho, &bytes_chirho)
        .map_err(|_| Gd7OperatorRosterRefusalChirho::StorageChirho)?
    {
        CreateDurableOutcomeChirho::CreatedChirho => Ok(roster_chirho),
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            Err(Gd7OperatorRosterRefusalChirho::EpochRegressionChirho)
        }
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::FsLedgerStorageChirho;
    use anyhow::Result;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE_SEQUENCE_CHIRHO: AtomicU64 = AtomicU64::new(0);

    struct TestSignerChirho {
        key_id_chirho: String,
    }
    impl Gd7ReconciliationVerifierPortChirho for TestSignerChirho {
        fn key_id_chirho(&self) -> String {
            self.key_id_chirho.clone()
        }
        fn verify_chirho(&self, bytes_chirho: &str, sig_chirho: &str) -> bool {
            blake3::hash(bytes_chirho.as_bytes()).to_hex().to_string() == sig_chirho
        }
    }
    impl Gd7ReconciliationSignerPortChirho for TestSignerChirho {
        fn sign_chirho(&self, bytes_chirho: &str) -> Result<String> {
            Ok(blake3::hash(bytes_chirho.as_bytes()).to_hex().to_string())
        }
    }

    fn fixture_chirho() -> (PathBuf, FsLedgerStorageChirho, TestSignerChirho, String) {
        let directory_chirho = std::env::temp_dir().join(format!(
            "gd7-roster-test-{}-{}",
            std::process::id(),
            FIXTURE_SEQUENCE_CHIRHO.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&directory_chirho);
        fs::create_dir_all(&directory_chirho).unwrap();
        let storage_chirho =
            FsLedgerStorageChirho::open_existing_chirho(&directory_chirho).unwrap();
        let signer_chirho = TestSignerChirho {
            key_id_chirho: "a".repeat(64),
        };
        (
            directory_chirho,
            storage_chirho,
            signer_chirho,
            "b".repeat(64),
        )
    }

    fn roster_chirho(
        signer_chirho: &TestSignerChirho,
        group_chirho: &str,
        epoch_chirho: u64,
        operator_chirho: &str,
    ) -> Gd7OperatorRosterChirho {
        Gd7OperatorRosterChirho {
            schema_chirho: GD7_OPERATOR_ROSTER_SCHEMA_V1_CHIRHO.to_owned(),
            consistency_group_digest_chirho: group_chirho.to_owned(),
            roster_epoch_chirho: epoch_chirho,
            signer_key_id_chirho: signer_chirho.key_id_chirho(),
            members_chirho: vec![Gd7OperatorRosterMemberChirho {
                operator_key_id_chirho: operator_chirho.to_owned(),
                role_chirho: Gd7OperatorRosterRoleChirho::Gd7DispositionChirho,
            }],
            sig_chirho: String::new(),
        }
    }

    #[test]
    fn missing_roster_refuses_disposition_authority_chirho() {
        let (_directory_chirho, storage_chirho, signer_chirho, group_chirho) = fixture_chirho();
        let refusal_chirho = load_verified_gd7_operator_roster_chirho(
            &storage_chirho,
            &group_chirho,
            &signer_chirho,
            &"c".repeat(64),
        )
        .unwrap_err();
        assert_eq!(
            refusal_chirho,
            Gd7OperatorRosterRefusalChirho::MissingChirho
        );
    }

    #[test]
    // The absent-member arm is distinct from a wrong-role arm: the role enum has one variant
    // today, so a wrong-role record is unrepresentable until the second role is introduced.
    fn valid_signature_absent_member_refuses_by_name_chirho() {
        let (_directory_chirho, storage_chirho, signer_chirho, group_chirho) = fixture_chirho();
        let member_chirho = "c".repeat(64);
        let roster_value_chirho = roster_chirho(&signer_chirho, &group_chirho, 1, &"d".repeat(64));
        write_gd7_operator_roster_chirho(
            &storage_chirho,
            &group_chirho,
            &signer_chirho,
            roster_value_chirho,
        )
        .unwrap();
        let refusal_chirho = load_verified_gd7_operator_roster_chirho(
            &storage_chirho,
            &group_chirho,
            &signer_chirho,
            &member_chirho,
        )
        .unwrap_err();
        assert_eq!(
            refusal_chirho,
            Gd7OperatorRosterRefusalChirho::UnauthorizedOperatorChirho
        );
    }

    #[test]
    fn latest_tamper_refuses_without_fallback_to_intact_older_revision_chirho() {
        let (_directory_chirho, storage_chirho, signer_chirho, group_chirho) = fixture_chirho();
        write_gd7_operator_roster_chirho(
            &storage_chirho,
            &group_chirho,
            &signer_chirho,
            roster_chirho(&signer_chirho, &group_chirho, 1, &"c".repeat(64)),
        )
        .unwrap();
        write_gd7_operator_roster_chirho(
            &storage_chirho,
            &group_chirho,
            &signer_chirho,
            roster_chirho(&signer_chirho, &group_chirho, 2, &"c".repeat(64)),
        )
        .unwrap();
        let tampered_path_chirho = StoragePathChirho::new_chirho(format!(
            "{GD7_OPERATOR_ROSTER_NAMESPACE_CHIRHO}/{group_chirho}/2/2.json"
        ));
        storage_chirho
            .atomic_write_chirho(&tampered_path_chirho, b"{}\n")
            .unwrap();
        let refusal_chirho = load_verified_gd7_operator_roster_chirho(
            &storage_chirho,
            &group_chirho,
            &signer_chirho,
            &"c".repeat(64),
        )
        .unwrap_err();
        assert_eq!(
            refusal_chirho,
            Gd7OperatorRosterRefusalChirho::InvalidLatestChirho
        );
    }

    #[test]
    fn write_read_round_trip_consumes_signed_roster_chirho() {
        let (_directory_chirho, storage_chirho, signer_chirho, group_chirho) = fixture_chirho();
        let operator_chirho = "c".repeat(64);
        write_gd7_operator_roster_chirho(
            &storage_chirho,
            &group_chirho,
            &signer_chirho,
            roster_chirho(&signer_chirho, &group_chirho, 1, &operator_chirho),
        )
        .unwrap();
        let loaded_chirho = load_verified_gd7_operator_roster_chirho(
            &storage_chirho,
            &group_chirho,
            &signer_chirho,
            &operator_chirho,
        )
        .unwrap();
        assert_eq!(loaded_chirho.roster_epoch_chirho, 1);
        assert_eq!(
            loaded_chirho.members_chirho[0].operator_key_id_chirho,
            operator_chirho
        );
    }

    #[test]
    fn roster_epoch_revert_refuses_by_name_chirho() {
        let (_directory_chirho, storage_chirho, signer_chirho, group_chirho) = fixture_chirho();
        write_gd7_operator_roster_chirho(
            &storage_chirho,
            &group_chirho,
            &signer_chirho,
            roster_chirho(&signer_chirho, &group_chirho, 2, &"c".repeat(64)),
        )
        .unwrap();
        let refusal_chirho = write_gd7_operator_roster_chirho(
            &storage_chirho,
            &group_chirho,
            &signer_chirho,
            roster_chirho(&signer_chirho, &group_chirho, 1, &"c".repeat(64)),
        )
        .unwrap_err();
        assert_eq!(
            refusal_chirho,
            Gd7OperatorRosterRefusalChirho::EpochRegressionChirho
        );
    }
}
