// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The credential families: an HTTP credential's set, hash and inventory here, and its change and reset as this
//! module's children, in this folder (R2a's placement, PFE #26036). R2's recovery code joins them.

use super::*;
use argon2::{Algorithm, Argon2, Params, Version};

#[path = "credential_change_chirho.rs"]
mod credential_change_chirho;
#[cfg(test)]
#[path = "credential_change_tests_chirho.rs"]
mod credential_change_tests_chirho;
#[cfg(test)]
#[path = "credential_floor_tests_chirho.rs"]
mod credential_floor_tests_chirho;
#[path = "credential_reset_chirho.rs"]
mod credential_reset_chirho;
#[cfg(test)]
#[path = "credential_reset_tests_chirho.rs"]
mod credential_reset_tests_chirho;
#[cfg(test)]
#[path = "recover_road_tests_chirho.rs"]
mod recover_road_tests_chirho;
#[path = "recovery_code_chirho.rs"]
mod recovery_code_chirho;
#[cfg(all(test, unix))]
#[path = "recovery_code_cut_tests_chirho.rs"]
mod recovery_code_cut_tests_chirho;
#[path = "recovery_code_events_chirho.rs"]
mod recovery_code_events_chirho;
#[cfg(test)]
#[path = "recovery_code_lifecycle_tests_chirho.rs"]
mod recovery_code_lifecycle_tests_chirho;
#[path = "recovery_code_mint_chirho.rs"]
mod recovery_code_mint_chirho;
#[path = "recovery_code_redeem_chirho.rs"]
mod recovery_code_redeem_chirho;
#[cfg(test)]
#[path = "recovery_code_tests_chirho.rs"]
mod recovery_code_tests_chirho;
pub use credential_change_chirho::{
    change_identity_credential_for_session_chirho, credential_change_refusal_token_chirho,
    load_verified_credential_change_attempts_chirho, verify_credential_change_attempts_chirho,
    CredentialChangeRefusalChirho, IdentityCredentialChangeAttemptChirho,
    CREDENTIAL_CHANGE_SESSION_MAX_FAILURES_CHIRHO,
    CREDENTIAL_GUESS_EXHAUSTED_REVOCATION_REASON_CHIRHO,
    SELF_SERVICE_CREDENTIAL_CHANGE_REASON_CHIRHO,
};
#[cfg(test)]
use credential_reset_chirho::credential_fault_points_chirho;
pub(in crate::identity_chirho) use credential_reset_chirho::{
    commit_credential_replacement_locked_chirho, credential_lock_name_chirho,
    prepare_credential_replacement_locked_chirho, reset_identity_credential_locked_chirho,
    CredentialReplacementCauseChirho,
};
pub use credential_reset_chirho::{
    load_credential_resets_chirho, reset_identity_credential_chirho,
    verify_credential_resets_chirho, IdentityCredentialResetRecordChirho,
    IdentityCredentialResetRefusalChirho, IdentityCredentialResetReportChirho,
    CREDENTIAL_RESET_SESSION_REVOCATION_REASON_CHIRHO,
    IDENTITY_CREDENTIAL_RESET_RECORD_SCHEMA_CHIRHO,
};
#[cfg(test)]
use recovery_code_chirho::recovery_code_hash_metrics_chirho;
pub use recovery_code_chirho::RECOVERY_CODE_OPERATOR_LIFETIME_MS_CHIRHO;
use recovery_code_chirho::{
    fresh_recovery_code_chirho, normalize_recovery_code_chirho, recovery_code_hash_chirho,
    stored_recovery_code_chirho, StoredRecoveryCodeChirho,
};
use recovery_code_events_chirho::append_recovery_code_event_chirho;
pub use recovery_code_events_chirho::{
    load_recovery_code_events_chirho, load_recovery_code_events_for_display_chirho,
    verify_recovery_code_events_chirho, IdentityRecoveryCodeEventChirho,
    RecoveryCodeEventDisplayRowChirho, RecoveryCodeEventKindChirho, RecoveryCodeReasonKindChirho,
    IDENTITY_RECOVERY_CODE_EVENT_SCHEMA_CHIRHO,
};
pub use recovery_code_mint_chirho::{
    invite_identity_chirho, mint_operator_recovery_code_chirho, IssuedRecoveryCodeChirho,
    RECOVERY_CODE_OPERATOR_ACTOR_CHIRHO,
};
pub use recovery_code_redeem_chirho::{
    recovery_code_refusal_token_chirho, redeem_recovery_code_chirho,
    redeem_recovery_code_with_public_limit_chirho,
    redeem_recovery_code_with_public_limit_outcome_chirho, RecoveryCodeRefusalChirho,
    INVITATION_CODE_RESET_REASON_CHIRHO, RECOVERY_CODE_RESET_REASON_CHIRHO,
};

pub const IDENTITY_CREDENTIAL_INVENTORY_SCHEMA_CHIRHO: &str =
    "identity-credential-inventory-v1-chirho";
pub(super) const CREDENTIAL_HASH_ARGON2ID_V1_CHIRHO: &str = "argon2id-v1-chirho";
const ARGON2_MEMORY_KIB_CHIRHO: u32 = 19 * 1024;
const ARGON2_ITERATIONS_CHIRHO: u32 = 2;
const ARGON2_LANES_CHIRHO: u32 = 1;
pub(super) const ARGON2_OUTPUT_LEN_CHIRHO: usize = 32;
const ARGON2_MAX_MEMORY_KIB_CHIRHO: u32 = ARGON2_MEMORY_KIB_CHIRHO;
const ARGON2_MAX_ITERATIONS_CHIRHO: u32 = ARGON2_ITERATIONS_CHIRHO;
const ARGON2_MAX_LANES_CHIRHO: u32 = ARGON2_LANES_CHIRHO;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityCredentialInventoryChirho {
    pub schema_chirho: String,
    pub identity_records_chirho: usize,
    pub key_files_chirho: usize,
    pub argon2id_credentials_chirho: usize,
    pub legacy_blake3_credentials_chirho: usize,
    pub credentialless_keys_chirho: usize,
    pub invalid_key_files_chirho: usize,
    pub missing_key_files_chirho: usize,
    pub extra_key_files_chirho: usize,
    pub legacy_principal_hashes_chirho: Vec<String>,
    pub invalid_principal_hashes_chirho: Vec<String>,
    pub missing_key_principal_hashes_chirho: Vec<String>,
    pub extra_key_principal_hashes_chirho: Vec<String>,
    /// Keys holding a recovery or setup code (R2), live or expired.
    pub recovery_codes_chirho: usize,
    /// Keys whose code fields break the both-or-neither rule, or carry malformed values: invalid key state.
    pub invalid_recovery_codes_chirho: usize,
    pub invalid_recovery_code_principal_hashes_chirho: Vec<String>,
    /// Principals whose key carries a credential generation above their count of reset records: a replacement that
    /// committed without its evidence (R2's interruption contract). Reported, never fatal to readiness.
    pub generation_ahead_of_reset_records_chirho: usize,
    pub generation_ahead_principal_hashes_chirho: Vec<String>,
    pub legacy_rotation_ready_chirho: bool,
}

pub fn set_identity_credential_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    credential_chirho: &str,
) -> Result<()> {
    seqlog_chirho::with_named_lock_chirho(
        root_chirho,
        &credential_lock_name_chirho(principal_chirho),
        || {
            if !credential_meets_floor_chirho(credential_chirho) {
                bail!("{IDENTITY_CREDENTIAL_FLOOR_MESSAGE_CHIRHO}");
            }
            // Verified, not raw: a forged identity row never receives a credential.
            let known_chirho = load_verified_identities_chirho(root_chirho)?
                .into_iter()
                .any(|record_chirho| record_chirho.principal_chirho == principal_chirho);
            if !known_chirho {
                bail!("unknown principal '{principal_chirho}'");
            }
            let mut key_record_chirho =
                load_identity_key_record_chirho(root_chirho, principal_chirho)?;
            if key_record_chirho.credential_salt_chirho.is_some()
                || key_record_chirho.credential_hash_chirho.is_some()
            {
                bail!("principal '{principal_chirho}' already has an HTTP credential");
            }
            // An invited principal's setup code is the OTHER authenticator: setting her credential clears it in the same
            // write and records the burn (R2). A malformed code state refuses the set before any write.
            let held_code_chirho = stored_recovery_code_chirho(&key_record_chirho)?;
            let salt_chirho = random_salt_chirho();
            let hash_chirho = credential_hash_chirho(&salt_chirho, credential_chirho)?;
            key_record_chirho.credential_salt_chirho = Some(salt_chirho);
            key_record_chirho.credential_hash_chirho = Some(hash_chirho);
            key_record_chirho.recovery_code_salt_chirho = None;
            key_record_chirho.recovery_code_hash_chirho = None;
            key_record_chirho.recovery_code_expires_ms_chirho = None;
            write_identity_key_record_chirho(root_chirho, &key_record_chirho)?;
            let verified_key_chirho =
                load_identity_key_record_chirho(root_chirho, principal_chirho)?;
            verify_identity_credential_chirho(&verified_key_chirho, credential_chirho)?;
            if stored_recovery_code_chirho(&verified_key_chirho)?.is_some() {
                bail!("credential set wrote a key record that still holds a recovery code");
            }
            if let Some(held_chirho) = held_code_chirho {
                append_recovery_code_event_chirho(
                    root_chirho,
                    principal_chirho,
                    RecoveryCodeReasonKindChirho::CredentialSetChirho,
                    RECOVERY_CODE_OPERATOR_ACTOR_CHIRHO,
                    &held_chirho,
                    verified_key_chirho.credential_generation_chirho,
                )?;
            }
            Ok(())
        },
    )
}

pub fn credential_inventory_chirho(
    root_chirho: &Path,
) -> Result<IdentityCredentialInventoryChirho> {
    // ONE verified load, replacing a `verify_identities_chirho` + raw-load PAIR. Scope honestly: the
    // verify ran FIRST, so a forged row was already refused — this closes the TOCTOU window between
    // the two reads and the false verified-label the pair hands a reader, not a static hole. The raw
    // loader checks only the schema string, so the second read carried no signature evidence of its
    // own; `load_verified_identities_chirho` is documented as the single place verified records come
    // from. Also one parse instead of two, on operator-evidence output.
    let identities_chirho = load_verified_identities_chirho(root_chirho)?;
    let mut inventory_chirho = IdentityCredentialInventoryChirho {
        schema_chirho: IDENTITY_CREDENTIAL_INVENTORY_SCHEMA_CHIRHO.to_string(),
        identity_records_chirho: identities_chirho.len(),
        key_files_chirho: identity_key_file_count_chirho(root_chirho)?,
        ..IdentityCredentialInventoryChirho::default()
    };
    let mut resets_by_principal_chirho = std::collections::HashMap::<String, u64>::new();
    for reset_chirho in load_credential_resets_chirho(root_chirho)? {
        *resets_by_principal_chirho
            .entry(reset_chirho.principal_chirho)
            .or_default() += 1;
    }
    let mut known_key_paths_chirho = std::collections::BTreeSet::new();
    for identity_chirho in &identities_chirho {
        let key_path_chirho =
            identity_key_path_chirho(root_chirho, &identity_chirho.principal_chirho);
        known_key_paths_chirho.insert(key_path_chirho.clone());
        if !key_path_chirho.exists() {
            inventory_chirho.missing_key_files_chirho += 1;
            inventory_chirho.missing_key_principal_hashes_chirho.push(
                identity_inventory_principal_hash_chirho(&identity_chirho.principal_chirho),
            );
            continue;
        }
        match load_identity_key_record_chirho(root_chirho, &identity_chirho.principal_chirho) {
            Ok(key_chirho) => {
                classify_credential_key_chirho(&key_chirho, &mut inventory_chirho);
                classify_recovery_code_chirho(&key_chirho, &mut inventory_chirho);
                let resets_chirho = resets_by_principal_chirho
                    .get(&identity_chirho.principal_chirho)
                    .copied()
                    .unwrap_or(0);
                if key_chirho.credential_generation_chirho > resets_chirho {
                    inventory_chirho.generation_ahead_of_reset_records_chirho += 1;
                    inventory_chirho
                        .generation_ahead_principal_hashes_chirho
                        .push(identity_inventory_principal_hash_chirho(
                            &identity_chirho.principal_chirho,
                        ));
                }
            }
            Err(_) => {
                inventory_chirho.invalid_key_files_chirho += 1;
                inventory_chirho.invalid_principal_hashes_chirho.push(
                    identity_inventory_principal_hash_chirho(&identity_chirho.principal_chirho),
                );
            }
        }
    }
    let dir_chirho = identity_keys_dir_chirho(root_chirho);
    if dir_chirho.exists() {
        for entry_chirho in std::fs::read_dir(&dir_chirho)
            .with_context(|| format!("read {}", dir_chirho.display()))?
        {
            let entry_chirho = entry_chirho?;
            let path_chirho = entry_chirho.path();
            if !path_chirho.is_file() {
                continue;
            }
            if known_key_paths_chirho.contains(&path_chirho) {
                continue;
            }
            inventory_chirho.extra_key_files_chirho += 1;
            let bytes_chirho = match std::fs::read(&path_chirho) {
                Ok(bytes_chirho) => bytes_chirho,
                Err(_) => {
                    inventory_chirho.invalid_key_files_chirho += 1;
                    continue;
                }
            };
            let record_chirho: IdentityKeyChirho = match serde_json::from_slice(&bytes_chirho) {
                Ok(record_chirho) => record_chirho,
                Err(_) => {
                    inventory_chirho.invalid_key_files_chirho += 1;
                    continue;
                }
            };
            inventory_chirho.extra_key_principal_hashes_chirho.push(
                identity_inventory_principal_hash_chirho(&record_chirho.principal_chirho),
            );
        }
    }
    inventory_chirho.legacy_principal_hashes_chirho.sort();
    inventory_chirho.invalid_principal_hashes_chirho.sort();
    inventory_chirho.missing_key_principal_hashes_chirho.sort();
    inventory_chirho.extra_key_principal_hashes_chirho.sort();
    inventory_chirho
        .invalid_recovery_code_principal_hashes_chirho
        .sort();
    inventory_chirho
        .generation_ahead_principal_hashes_chirho
        .sort();
    inventory_chirho.legacy_rotation_ready_chirho =
        inventory_chirho.legacy_blake3_credentials_chirho == 0
            && inventory_chirho.invalid_key_files_chirho == 0
            && inventory_chirho.missing_key_files_chirho == 0
            && inventory_chirho.extra_key_files_chirho == 0
            && inventory_chirho.invalid_recovery_codes_chirho == 0;
    Ok(inventory_chirho)
}

/// Verify a credential against a key record. Returns whether the stored hash is the LEGACY blake3
/// form (so a caller on a road that holds the credential lock may upgrade it). This function does
/// NOT write: the old code upgraded from in here, on the lockless login road, which could clobber a
/// concurrent reset. The upgrade now lives in `upgrade_legacy_identity_credential_locked_chirho`,
/// called by login while it holds the principal credential lock.
pub(super) fn verify_identity_credential_chirho(
    record_chirho: &IdentityKeyChirho,
    credential_chirho: &str,
) -> Result<bool> {
    #[cfg(test)]
    credential_verification_metrics_chirho::note_chirho();
    let salt_chirho = record_chirho
        .credential_salt_chirho
        .as_deref()
        .ok_or_else(|| {
            anyhow!(
                "principal '{}' has no HTTP credential",
                record_chirho.principal_chirho
            )
        })?;
    let expected_hash_chirho =
        record_chirho
            .credential_hash_chirho
            .as_deref()
            .ok_or_else(|| {
                anyhow!(
                    "principal '{}' has no HTTP credential",
                    record_chirho.principal_chirho
                )
            })?;
    let legacy_hash_chirho = parse_argon2id_credential_hash_chirho(expected_hash_chirho)?.is_none();
    let actual_hash_chirho = credential_hash_for_existing_record_chirho(
        salt_chirho,
        credential_chirho,
        expected_hash_chirho,
    )?;
    if !constant_time_string_eq_chirho(&actual_hash_chirho, expected_hash_chirho) {
        return Err(CredentialMismatchChirho {
            principal_chirho: record_chirho.principal_chirho.clone(),
        }
        .into());
    }
    Ok(legacy_hash_chirho)
}

/// The presented credential does not match the principal's stored hash: the refusal of a proof that read the stored
/// credential and compared it, and no other. Its text is the one this refusal always had; its type lets K4 Part 3's
/// served road record exactly a refused credential as a failed attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialMismatchChirho {
    principal_chirho: String,
}

impl std::fmt::Display for CredentialMismatchChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter_chirho,
            "invalid credential_chirho for '{}'",
            self.principal_chirho
        )
    }
}

impl std::error::Error for CredentialMismatchChirho {}

/// Re-hash a legacy blake3 credential to argon2id. The CALLER MUST HOLD the principal credential
/// lock (login does, across its proof and session append); this re-reads and rewrites only while
/// the on-disk record is STILL the legacy one whose credential was proved. A reset that raced this
/// login leaves an argon2id record (or a different credential), which this leaves untouched — so
/// the upgrade can never resurrect a superseded credential or roll back the generation. Generation
/// is unchanged: a hash-format upgrade is not a credential change.
pub(super) fn upgrade_legacy_identity_credential_locked_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    credential_chirho: &str,
) -> Result<()> {
    let mut record_chirho = load_identity_key_record_chirho(root_chirho, principal_chirho)?;
    let (Some(salt_chirho), Some(expected_hash_chirho)) = (
        record_chirho.credential_salt_chirho.clone(),
        record_chirho.credential_hash_chirho.clone(),
    ) else {
        return Ok(());
    };
    if parse_argon2id_credential_hash_chirho(&expected_hash_chirho)?.is_some() {
        return Ok(());
    }
    let actual_hash_chirho = credential_hash_for_existing_record_chirho(
        &salt_chirho,
        credential_chirho,
        &expected_hash_chirho,
    )?;
    if !constant_time_string_eq_chirho(&actual_hash_chirho, &expected_hash_chirho) {
        return Ok(());
    }
    let new_salt_chirho = random_salt_chirho();
    let new_hash_chirho = credential_hash_chirho(&new_salt_chirho, credential_chirho)?;
    record_chirho.credential_salt_chirho = Some(new_salt_chirho);
    record_chirho.credential_hash_chirho = Some(new_hash_chirho);
    write_identity_key_record_chirho(root_chirho, &record_chirho)?;
    Ok(())
}

fn classify_recovery_code_chirho(
    record_chirho: &IdentityKeyChirho,
    inventory_chirho: &mut IdentityCredentialInventoryChirho,
) {
    match stored_recovery_code_chirho(record_chirho) {
        Ok(None) => {}
        Ok(Some(_)) => inventory_chirho.recovery_codes_chirho += 1,
        Err(_) => {
            inventory_chirho.invalid_recovery_codes_chirho += 1;
            inventory_chirho
                .invalid_recovery_code_principal_hashes_chirho
                .push(identity_inventory_principal_hash_chirho(
                    &record_chirho.principal_chirho,
                ));
        }
    }
}

fn classify_credential_key_chirho(
    record_chirho: &IdentityKeyChirho,
    inventory_chirho: &mut IdentityCredentialInventoryChirho,
) {
    match (
        record_chirho.credential_salt_chirho.as_deref(),
        record_chirho.credential_hash_chirho.as_deref(),
    ) {
        (None, None) => {
            inventory_chirho.credentialless_keys_chirho += 1;
        }
        (Some(_), Some(hash_chirho)) => match classify_credential_hash_chirho(hash_chirho) {
            CredentialHashClassChirho::Argon2idChirho => {
                inventory_chirho.argon2id_credentials_chirho += 1;
            }
            CredentialHashClassChirho::LegacyBlake3Chirho => {
                inventory_chirho.legacy_blake3_credentials_chirho += 1;
                inventory_chirho.legacy_principal_hashes_chirho.push(
                    identity_inventory_principal_hash_chirho(&record_chirho.principal_chirho),
                );
            }
            CredentialHashClassChirho::InvalidChirho => {
                inventory_chirho.invalid_key_files_chirho += 1;
                inventory_chirho.invalid_principal_hashes_chirho.push(
                    identity_inventory_principal_hash_chirho(&record_chirho.principal_chirho),
                );
            }
        },
        _ => {
            inventory_chirho.invalid_key_files_chirho += 1;
            inventory_chirho.invalid_principal_hashes_chirho.push(
                identity_inventory_principal_hash_chirho(&record_chirho.principal_chirho),
            );
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CredentialHashClassChirho {
    Argon2idChirho,
    LegacyBlake3Chirho,
    InvalidChirho,
}

fn classify_credential_hash_chirho(hash_chirho: &str) -> CredentialHashClassChirho {
    match parse_argon2id_credential_hash_chirho(hash_chirho) {
        Ok(Some(_)) => CredentialHashClassChirho::Argon2idChirho,
        Ok(None)
            if hash_chirho.len() == 64
                && hash_chirho
                    .chars()
                    .all(|c_chirho| c_chirho.is_ascii_hexdigit()) =>
        {
            CredentialHashClassChirho::LegacyBlake3Chirho
        }
        _ => CredentialHashClassChirho::InvalidChirho,
    }
}

pub fn identity_inventory_principal_hash_chirho(principal_chirho: &str) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(b"cairn-chirho/identity-credential-inventory-principal/v1");
    hasher_chirho.update(principal_chirho.as_bytes());
    hex_encode_chirho(hasher_chirho.finalize().as_bytes())
}

pub(super) fn credential_hash_chirho(salt_chirho: &str, credential_chirho: &str) -> Result<String> {
    credential_hash_argon2id_chirho(
        salt_chirho,
        credential_chirho,
        ARGON2_MEMORY_KIB_CHIRHO,
        ARGON2_ITERATIONS_CHIRHO,
        ARGON2_LANES_CHIRHO,
        ARGON2_OUTPUT_LEN_CHIRHO,
    )
}

fn credential_hash_for_existing_record_chirho(
    salt_chirho: &str,
    credential_chirho: &str,
    expected_hash_chirho: &str,
) -> Result<String> {
    if let Some((memory_kib_chirho, iterations_chirho, lanes_chirho, output_hex_chirho)) =
        parse_argon2id_credential_hash_chirho(expected_hash_chirho)?
    {
        let output_len_chirho = output_hex_chirho
            .len()
            .checked_div(2)
            .ok_or_else(|| anyhow!("argon2id credential output length overflow"))?;
        return credential_hash_argon2id_chirho(
            salt_chirho,
            credential_chirho,
            memory_kib_chirho,
            iterations_chirho,
            lanes_chirho,
            output_len_chirho,
        );
    }
    Ok(legacy_credential_hash_blake3_chirho(
        salt_chirho,
        credential_chirho,
    ))
}

fn credential_hash_argon2id_chirho(
    salt_chirho: &str,
    credential_chirho: &str,
    memory_kib_chirho: u32,
    iterations_chirho: u32,
    lanes_chirho: u32,
    output_len_chirho: usize,
) -> Result<String> {
    let salt_bytes_chirho = hex_decode_chirho(salt_chirho)?;
    let params_chirho = Params::new(
        memory_kib_chirho,
        iterations_chirho,
        lanes_chirho,
        Some(output_len_chirho),
    )
    .map_err(|e_chirho| anyhow!("invalid argon2id credential params: {e_chirho}"))?;
    let argon2_chirho = Argon2::new(Algorithm::Argon2id, Version::V0x13, params_chirho);
    let mut output_chirho = vec![0_u8; output_len_chirho];
    argon2_chirho
        .hash_password_into(
            credential_chirho.as_bytes(),
            &salt_bytes_chirho,
            &mut output_chirho,
        )
        .map_err(|e_chirho| anyhow!("argon2id credential hash failed: {e_chirho}"))?;
    Ok(format!(
        "{CREDENTIAL_HASH_ARGON2ID_V1_CHIRHO}$m{memory_kib_chirho}$t{iterations_chirho}$p{lanes_chirho}${}",
        hex_encode_chirho(&output_chirho)
    ))
}

pub(super) fn legacy_credential_hash_blake3_chirho(
    salt_chirho: &str,
    credential_chirho: &str,
) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(b"cairn-chirho/identity-credential/v1");
    hasher_chirho.update(salt_chirho.as_bytes());
    hasher_chirho.update(credential_chirho.as_bytes());
    hex_encode_chirho(hasher_chirho.finalize().as_bytes())
}

fn parse_argon2id_credential_hash_chirho(
    hash_chirho: &str,
) -> Result<Option<(u32, u32, u32, &str)>> {
    if !hash_chirho.starts_with(CREDENTIAL_HASH_ARGON2ID_V1_CHIRHO) {
        return Ok(None);
    }
    let mut parts_chirho = hash_chirho.split('$');
    let Some(kind_chirho) = parts_chirho.next() else {
        bail!("missing argon2id credential marker");
    };
    if kind_chirho != CREDENTIAL_HASH_ARGON2ID_V1_CHIRHO {
        bail!("unsupported argon2id credential marker '{kind_chirho}'");
    }
    let memory_chirho = parse_prefixed_u32_chirho(parts_chirho.next(), 'm', "memory")?;
    let iterations_chirho = parse_prefixed_u32_chirho(parts_chirho.next(), 't', "iterations")?;
    let lanes_chirho = parse_prefixed_u32_chirho(parts_chirho.next(), 'p', "lanes")?;
    if memory_chirho == 0 || memory_chirho > ARGON2_MAX_MEMORY_KIB_CHIRHO {
        bail!("argon2id credential memory param exceeds supported bound");
    }
    if iterations_chirho == 0 || iterations_chirho > ARGON2_MAX_ITERATIONS_CHIRHO {
        bail!("argon2id credential iteration param exceeds supported bound");
    }
    if lanes_chirho == 0 || lanes_chirho > ARGON2_MAX_LANES_CHIRHO {
        bail!("argon2id credential lane param exceeds supported bound");
    }
    let Some(output_hex_chirho) = parts_chirho.next() else {
        bail!("missing argon2id credential output");
    };
    if parts_chirho.next().is_some() {
        bail!("extra argon2id credential hash fields");
    }
    if output_hex_chirho.len() != ARGON2_OUTPUT_LEN_CHIRHO * 2
        || !output_hex_chirho
            .chars()
            .all(|c_chirho| c_chirho.is_ascii_hexdigit())
    {
        bail!("invalid argon2id credential output hex");
    }
    Ok(Some((
        memory_chirho,
        iterations_chirho,
        lanes_chirho,
        output_hex_chirho,
    )))
}

fn parse_prefixed_u32_chirho(
    value_chirho: Option<&str>,
    prefix_chirho: char,
    label_chirho: &str,
) -> Result<u32> {
    let value_chirho =
        value_chirho.ok_or_else(|| anyhow!("missing argon2id credential {label_chirho}"))?;
    let raw_chirho = value_chirho
        .strip_prefix(prefix_chirho)
        .ok_or_else(|| anyhow!("argon2id credential {label_chirho} missing prefix"))?;
    raw_chirho
        .parse::<u32>()
        .with_context(|| format!("parse argon2id credential {label_chirho}"))
}

pub(crate) fn constant_time_string_eq_chirho(left_chirho: &str, right_chirho: &str) -> bool {
    let left_bytes_chirho = left_chirho.as_bytes();
    let right_bytes_chirho = right_chirho.as_bytes();
    let max_len_chirho = left_bytes_chirho.len().max(right_bytes_chirho.len());
    let mut diff_chirho = left_bytes_chirho.len() ^ right_bytes_chirho.len();
    for i_chirho in 0..max_len_chirho {
        let left_byte_chirho = left_bytes_chirho.get(i_chirho).copied().unwrap_or(0);
        let right_byte_chirho = right_bytes_chirho.get(i_chirho).copied().unwrap_or(0);
        diff_chirho |= usize::from(left_byte_chirho ^ right_byte_chirho);
    }
    diff_chirho == 0
}

/// How many credentials this thread verified, for the sign-in velocity arms: a rate refusal must do none (brick 4a).
#[cfg(test)]
pub(super) mod credential_verification_metrics_chirho {
    use std::cell::Cell;

    thread_local! {
        static VERIFICATIONS_CHIRHO: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn note_chirho() {
        VERIFICATIONS_CHIRHO.with(|cell_chirho| cell_chirho.set(cell_chirho.get() + 1));
    }

    pub(crate) fn count_chirho() -> u64 {
        VERIFICATIONS_CHIRHO.with(Cell::get)
    }
}
