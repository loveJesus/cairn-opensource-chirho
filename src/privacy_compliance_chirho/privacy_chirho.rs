// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Stores private blobs as content-addressed ciphertext with mutable shred keys.

use crate::cas_chirho;
use crate::legal_hold_chirho;
use crate::seqlog_chirho;
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use cairn_account_attribution_chirho::{
    admit_private_key_unlocked_chirho, refuse_if_account_frozen_chirho,
    with_account_attribution_lock_chirho,
};
use cairn_seqlog_chirho::jsonl_read_chirho::read_log_text_chirho;
use cairn_signer_chirho::signer_chirho;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "privacy_chirho/blob_subject_lookup_chirho.rs"]
mod blob_subject_lookup_chirho;
#[path = "privacy_chirho/blob_view_chirho.rs"]
mod blob_view_chirho;
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
pub use blob_view_chirho::private_blob_view_metrics_chirho;
pub use blob_view_chirho::{spawn_private_blob_view_warm_up_chirho, warm_private_blob_view_chirho};
#[path = "privacy_chirho/blob_attribution_chirho.rs"]
mod blob_attribution_chirho;
#[path = "privacy_chirho/erasure_capture_chirho.rs"]
mod erasure_capture_chirho;
pub use erasure_capture_chirho::{
    EarlierErasureEvidenceChirho, ErasureCaptureChirho, ErasureRequirementSinkChirho,
};
#[path = "privacy_chirho/erasure_binding_chirho.rs"]
mod erasure_binding_chirho;
pub use erasure_binding_chirho::{
    erasure_record_digest_hex_chirho, reconcile_subject_erasure_bindings_chirho,
    ErasureRecordedBindingPendingChirho,
};
#[path = "privacy_chirho/scan_chirho.rs"]
mod scan_chirho;
#[cfg(test)]
#[path = "privacy_chirho/store_hold_chirho.rs"]
pub(crate) mod store_hold_chirho;
pub use crate::privacy_model_chirho::PrivateBlobRefChirho;
pub use blob_attribution_chirho::{
    BlobContainerChirho, NotAccountScopedReasonChirho, PrivateBlobAttributionChirho,
};
pub(crate) use blob_subject_lookup_chirho::private_blob_ref_subject_from_log_chirho;
pub use blob_subject_lookup_chirho::verify_private_blob_ref_subject_chirho;
#[cfg(test)]
pub use scan_chirho::unexplained_literal_root_gaps_chirho;
#[cfg(test)]
use scan_chirho::{
    contains_ssn_like_chirho, inspect_privacy_string_chirho, looks_like_phone_number_chirho,
    looks_like_timestamp_value_chirho, phone_like_field_chirho, privacy_scan_field_chirho,
    privacy_scan_timestamp_field_chirho, RUNTIME_JSON_SCAN_DIRS_CHIRHO,
};
pub use scan_chirho::{
    production_logs_pending_owner_review_chirho, reviewed_signed_log_files_chirho,
    scan_privacy_surfaces_chirho, PrivacyScanFindingChirho, PrivacyScanReportChirho,
    PRIVACY_SCAN_REPORT_SCHEMA_CHIRHO,
};

const PRIVATE_BLOB_ALG_CHIRHO: &str = "xchacha20poly1305+blake3-keyed-mac/v1";
/// Domain separator for the plaintext-identity digest subkey. `blake3::derive_key` is one-way, so
/// the digest key never yields the AEAD key even if the digest key itself were to leak.
const KEYED_PLAINTEXT_DIGEST_CONTEXT_CHIRHO: &str =
    "cairn-chirho 2026 private-blob keyed plaintext digest v1";
const PRIVACY_BLOB_RECORDS_LOCK_CHIRHO: &str = "privacy-blob-records-chirho";
const PRIVACY_ERASURE_RECORDS_LOCK_CHIRHO: &str = "privacy-erasure-records-chirho";
const PRIVACY_ACCESS_RECORDS_LOCK_CHIRHO: &str = "privacy-access-records-chirho";
const PRIVACY_BLOB_RECORD_SCHEMA_CHIRHO: &str = "privacy-blob-record-v1-chirho";
const PRIVACY_ERASURE_RECORD_SCHEMA_CHIRHO: &str = "privacy-erasure-record-v1-chirho";
const PRIVACY_ACCESS_RECORD_SCHEMA_CHIRHO: &str = "privacy-access-record-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBlobRecordChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub subject_chirho: String,
    pub blob_chirho: PrivateBlobRefChirho,
    pub bytes_chirho: usize,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyErasureRecordChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub subject_chirho: String,
    pub requested_by_chirho: String,
    pub reason_chirho: String,
    pub key_ids_chirho: Vec<String>,
    pub removed_keys_chirho: usize,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyAccessRecordChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub subject_chirho: String,
    pub accessed_by_chirho: String,
    pub app_chirho: String,
    pub row_key_chirho: String,
    pub purpose_chirho: String,
    pub blob_chirho: PrivateBlobRefChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectPrivateBlobExportChirho {
    pub record_chirho: PrivacyBlobRecordChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_base64_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason_chirho: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectDataExportChirho {
    pub subject_chirho: String,
    pub generated_ms_chirho: u64,
    pub include_private_chirho: bool,
    pub private_blobs_chirho: Vec<SubjectPrivateBlobExportChirho>,
    pub erasures_chirho: Vec<PrivacyErasureRecordChirho>,
    pub access_records_chirho: Vec<PrivacyAccessRecordChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyVerifyReportChirho {
    pub blob_records_chirho: usize,
    pub erasure_records_chirho: usize,
    pub access_records_chirho: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ShredKeyChirho {
    subject_chirho: String,
    key_hex_chirho: String,
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

fn keys_dir_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("privacy-keys-chirho")
}

fn key_path_chirho(root_chirho: &Path, key_id_chirho: &str) -> PathBuf {
    keys_dir_chirho(root_chirho).join(format!("{key_id_chirho}.json"))
}

fn privacy_blob_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("privacy-blob-records-chirho.jsonl")
}

fn privacy_erasure_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("privacy-erasure-records-chirho.jsonl")
}

fn privacy_access_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("privacy-access-records-chirho.jsonl")
}

fn create_keys_dir_chirho(root_chirho: &Path) -> Result<()> {
    let dir_chirho = keys_dir_chirho(root_chirho);
    std::fs::create_dir_all(&dir_chirho)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir_chirho, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_private_key_file_chirho(path_chirho: &Path, bytes_chirho: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        let mut file_chirho = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path_chirho)?;
        file_chirho.write_all(bytes_chirho)?;
        // The key that un-shreds the private blob must be as crash-durable as the ciphertext (CAS)
        // and the record (seqlog) it accompanies: fsync the key bytes, then fsync the parent
        // directory so the key file's own directory entry survives a crash too. Matches the
        // fsync-file + fsync-dir durability pattern in cairn-durable-chirho.
        file_chirho.sync_all()?;
        std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(0o600))?;
        if let Some(parent_chirho) = path_chirho.parent() {
            crate::durable_chirho::fsync_dir_chirho(parent_chirho)?;
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path_chirho, bytes_chirho)?;
    }
    Ok(())
}

fn validate_subject_chirho(subject_chirho: &str) -> Result<()> {
    if subject_chirho.trim().is_empty()
        || subject_chirho.len() > 256
        || !subject_chirho.chars().all(|ch_chirho| {
            ch_chirho.is_ascii_alphanumeric() || matches!(ch_chirho, '-' | '_' | '/' | ':' | '.')
        })
    {
        bail!("privacy subject_chirho must be a short opaque id");
    }
    Ok(())
}

pub fn validate_privacy_subject_chirho(subject_chirho: &str) -> Result<()> {
    validate_subject_chirho(subject_chirho)
}

/// Store one private blob. Before its key exists, the key is admitted: a frozen account refuses, the
/// subject must belong to this same owner (its first key claims it), and an account's key gets its
/// attribution row. Admission, the key file and the blob record happen under the account-attribution
/// lock, which also orders a store against a freeze or an erasure of the same subject (R-C5-4a): an
/// erasure either sees this key or runs after it.
/// The ciphertext goes to CAS first, OUTSIDE that lock, so the lock never nests the CAS lifecycle
/// guard; a refused store leaves only keyless ciphertext, which nothing can read and GC collects.
/// Lock order: [subject-rights | append-log] -> account-attribution -> blob-records.
pub fn store_private_blob_chirho(
    root_chirho: &Path,
    attribution_chirho: &PrivateBlobAttributionChirho,
    subject_chirho: &str,
    plaintext_chirho: &[u8],
) -> Result<PrivateBlobRefChirho> {
    validate_subject_chirho(subject_chirho)?;
    let mut key_chirho = [0_u8; 32];
    let mut nonce_chirho = [0_u8; 24];
    let mut id_seed_chirho = [0_u8; 16];
    OsRng.fill_bytes(&mut key_chirho);
    OsRng.fill_bytes(&mut nonce_chirho);
    OsRng.fill_bytes(&mut id_seed_chirho);

    let key_id_chirho = hex_encode_chirho(&blake3::hash(&id_seed_chirho).as_bytes()[..16]);
    let cipher_chirho = XChaCha20Poly1305::new(Key::from_slice(&key_chirho));
    let ciphertext_bytes_chirho = cipher_chirho
        .encrypt(XNonce::from_slice(&nonce_chirho), plaintext_chirho)
        .map_err(|e_chirho| anyhow!("encrypt private blob: {e_chirho}"))?;
    let mac_chirho = mac_chirho(&key_chirho, &nonce_chirho, &ciphertext_bytes_chirho);
    // Only spares the ciphertext write: admission re-checks both accounts under the lock.
    if let BlobContainerChirho::AccountChirho(account_chirho) =
        attribution_chirho.container_chirho()
    {
        refuse_if_account_frozen_chirho(root_chirho, account_chirho)?;
    }
    if let Some(actor_chirho) = attribution_chirho.actor_chirho() {
        refuse_if_account_frozen_chirho(root_chirho, actor_chirho)?;
    }
    let ciphertext_chirho = cas_chirho::add_chirho(root_chirho, &ciphertext_bytes_chirho)?;
    with_account_attribution_lock_chirho(root_chirho, || {
        // Admission writes a coverage-debt reason's marker and binds the debt into the subject's owner
        // record before the key exists.
        admit_private_key_unlocked_chirho(
            root_chirho,
            &attribution_chirho.subject_owner_chirho(),
            attribution_chirho.actor_chirho(),
            subject_chirho,
            &key_id_chirho,
        )?;
        #[cfg(test)]
        store_hold_chirho::reach_chirho(root_chirho);
        create_keys_dir_chirho(root_chirho)?;
        let key_record_chirho = ShredKeyChirho {
            subject_chirho: subject_chirho.to_string(),
            key_hex_chirho: hex_encode_chirho(&key_chirho),
        };
        write_private_key_file_chirho(
            &key_path_chirho(root_chirho, &key_id_chirho),
            &serde_json::to_vec_pretty(&key_record_chirho)?,
        )?;

        let blob_chirho = PrivateBlobRefChirho {
            ciphertext_chirho: ciphertext_chirho.clone(),
            key_id_chirho: key_id_chirho.clone(),
            nonce_chirho: hex_encode_chirho(&nonce_chirho),
            mac_chirho: mac_chirho.clone(),
            alg_chirho: PRIVATE_BLOB_ALG_CHIRHO.to_string(),
        };
        append_privacy_blob_record_chirho(
            root_chirho,
            subject_chirho,
            &blob_chirho,
            plaintext_chirho.len(),
        )?;
        Ok(blob_chirho)
    })
}

pub fn load_private_blob_chirho(
    root_chirho: &Path,
    blob_chirho: &PrivateBlobRefChirho,
) -> Result<Vec<u8>> {
    if blob_chirho.alg_chirho != PRIVATE_BLOB_ALG_CHIRHO {
        bail!("unsupported private blob alg '{}'", blob_chirho.alg_chirho);
    }
    let key_record_chirho = load_key_chirho(root_chirho, &blob_chirho.key_id_chirho)?;
    let key_bytes_chirho = hex_decode_fixed_chirho::<32>(&key_record_chirho.key_hex_chirho)?;
    let nonce_bytes_chirho = hex_decode_fixed_chirho::<24>(&blob_chirho.nonce_chirho)?;
    let ciphertext_chirho = cas_chirho::get_chirho(root_chirho, &blob_chirho.ciphertext_chirho)
        .with_context(|| {
            format!(
                "private ciphertext {} missing",
                blob_chirho.ciphertext_chirho.0
            )
        })?;
    let expected_mac_chirho =
        mac_chirho(&key_bytes_chirho, &nonce_bytes_chirho, &ciphertext_chirho);
    if expected_mac_chirho != blob_chirho.mac_chirho {
        bail!("private blob mac mismatch");
    }
    let cipher_chirho = XChaCha20Poly1305::new(Key::from_slice(&key_bytes_chirho));
    cipher_chirho
        .decrypt(
            XNonce::from_slice(&nonce_bytes_chirho),
            ciphertext_chirho.as_ref(),
        )
        .map_err(|e_chirho| anyhow!("decrypt private blob: {e_chirho}"))
}

/// The keyed plaintext-identity digest of ONE private blob — the only plaintext-identity value that
/// may rest beside a sealed row.
///
/// An unsalted `blake3(plaintext)` resting in the clear is an offline dictionary ORACLE: anyone
/// holding the row (a cross-region mirror holder, by design) can confirm a low-entropy plaintext by
/// hashing candidates. This digest is `blake3::keyed_hash` under a subkey derived from THIS record's
/// shred key, so only a holder of that key can compute or check it — and when the key is
/// crypto-shredded the digest becomes uncomputable, which is exactly the property shredding is meant
/// to give. The key id is bound into the digest so a value can never be replayed across records.
pub fn private_blob_keyed_plaintext_digest_chirho(
    root_chirho: &Path,
    blob_chirho: &PrivateBlobRefChirho,
    plaintext_chirho: &[u8],
) -> Result<String> {
    validate_key_id_chirho(&blob_chirho.key_id_chirho)?;
    let key_record_chirho = load_key_chirho(root_chirho, &blob_chirho.key_id_chirho)?;
    let key_bytes_chirho = hex_decode_fixed_chirho::<32>(&key_record_chirho.key_hex_chirho)?;
    Ok(keyed_plaintext_digest_chirho(
        &key_bytes_chirho,
        &blob_chirho.key_id_chirho,
        plaintext_chirho,
    ))
}

fn keyed_plaintext_digest_chirho(
    key_chirho: &[u8; 32],
    key_id_chirho: &str,
    plaintext_chirho: &[u8],
) -> String {
    let subkey_chirho = blake3::derive_key(KEYED_PLAINTEXT_DIGEST_CONTEXT_CHIRHO, key_chirho);
    let mut hasher_chirho = blake3::Hasher::new_keyed(&subkey_chirho);
    hasher_chirho.update(key_id_chirho.as_bytes());
    hasher_chirho.update(&[0_u8]);
    hasher_chirho.update(plaintext_chirho);
    hex_encode_chirho(hasher_chirho.finalize().as_bytes())
}

pub fn verify_private_blob_ref_chirho(
    root_chirho: &Path,
    blob_chirho: &PrivateBlobRefChirho,
) -> Result<()> {
    private_blob_ref_subject_from_log_chirho(root_chirho, blob_chirho).map(|_| ())
}

fn validate_private_blob_ref_shape_chirho(
    root_chirho: &Path,
    blob_chirho: &PrivateBlobRefChirho,
) -> Result<()> {
    if blob_chirho.alg_chirho != PRIVATE_BLOB_ALG_CHIRHO {
        bail!("unsupported private blob alg '{}'", blob_chirho.alg_chirho);
    }
    validate_key_id_chirho(&blob_chirho.key_id_chirho)?;
    let _nonce_chirho = hex_decode_fixed_chirho::<24>(&blob_chirho.nonce_chirho)?;
    let _mac_chirho = hex_decode_fixed_chirho::<32>(&blob_chirho.mac_chirho)?;
    cas_chirho::get_chirho(root_chirho, &blob_chirho.ciphertext_chirho).with_context(|| {
        format!(
            "private ciphertext {} missing",
            blob_chirho.ciphertext_chirho.0
        )
    })?;
    Ok(())
}

/// Remove a subject's key files, under the account-attribution lock so no store interleaves.
pub fn erase_subject_keys_chirho(root_chirho: &Path, subject_chirho: &str) -> Result<usize> {
    with_account_attribution_lock_chirho(root_chirho, || {
        Ok(erase_subject_keys_with_ids_chirho(root_chirho, subject_chirho)?.len())
    })
}

/// The key removal itself. The caller holds the account-attribution lock, and it cannot take it here,
/// because the erasure path calls this under erasure-records, which ranks below account-attribution.
pub(crate) fn erase_subject_keys_with_ids_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
) -> Result<Vec<String>> {
    validate_subject_chirho(subject_chirho)?;
    validate_private_blob_key_namespace_chirho(root_chirho)?;
    remove_subject_key_files_chirho(root_chirho, subject_chirho)
}

/// Unlink the subject's key files. The caller validated the blob log's key namespace.
fn remove_subject_key_files_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
) -> Result<Vec<String>> {
    let mut removed_chirho = Vec::new();
    for (key_id_chirho, path_chirho) in subject_key_files_chirho(root_chirho, subject_chirho)? {
        std::fs::remove_file(&path_chirho)?;
        removed_chirho.push(key_id_chirho);
    }
    Ok(removed_chirho)
}

/// The subject's local key ids, removing nothing. The caller validated the blob log's key namespace.
fn local_subject_key_ids_chirho(root_chirho: &Path, subject_chirho: &str) -> Result<Vec<String>> {
    Ok(subject_key_files_chirho(root_chirho, subject_chirho)?
        .into_iter()
        .map(|(key_id_chirho, _)| key_id_chirho)
        .collect())
}

/// The subject's key files by id, every one parsed before any caller acts on them. Only `.json`
/// entries are keys. The capture and the removal share this, so under one lock the cut's local ids are
/// exactly the ids the removal unlinks.
fn subject_key_files_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
) -> Result<Vec<(String, PathBuf)>> {
    let mut files_chirho = Vec::new();
    for path_chirho in key_paths_chirho(root_chirho)? {
        if path_chirho
            .extension()
            .and_then(|ext_chirho| ext_chirho.to_str())
            != Some("json")
        {
            continue;
        }
        let bytes_chirho = std::fs::read(&path_chirho)?;
        let key_chirho: ShredKeyChirho = serde_json::from_slice(&bytes_chirho)?;
        if key_chirho.subject_chirho == subject_chirho {
            let key_id_chirho = path_chirho
                .file_stem()
                .and_then(|stem_chirho| stem_chirho.to_str())
                .ok_or_else(|| anyhow!("bad private key filename {}", path_chirho.display()))?
                .to_string();
            files_chirho.push((key_id_chirho, path_chirho));
        }
    }
    Ok(files_chirho)
}

pub fn subject_private_key_ids_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
) -> Result<Vec<String>> {
    validate_subject_chirho(subject_chirho)?;
    validate_private_blob_key_namespace_chirho(root_chirho)?;
    let mut ids_chirho = Vec::new();
    for path_chirho in key_paths_chirho(root_chirho)? {
        let bytes_chirho = std::fs::read(&path_chirho)?;
        let key_chirho: ShredKeyChirho = serde_json::from_slice(&bytes_chirho)?;
        if key_chirho.subject_chirho == subject_chirho {
            let key_id_chirho = path_chirho
                .file_stem()
                .and_then(|stem_chirho| stem_chirho.to_str())
                .ok_or_else(|| anyhow!("bad private key filename {}", path_chirho.display()))?
                .to_string();
            ids_chirho.push(key_id_chirho);
        }
    }
    Ok(ids_chirho)
}

pub fn erase_private_blob_key_chirho(root_chirho: &Path, key_id_chirho: &str) -> Result<bool> {
    validate_key_id_chirho(key_id_chirho)?;
    validate_private_blob_key_namespace_chirho(root_chirho)?;
    let path_chirho = key_path_chirho(root_chirho, key_id_chirho);
    if !private_key_file_exists_chirho(&path_chirho)? {
        return Ok(false);
    }
    std::fs::remove_file(&path_chirho)?;
    Ok(true)
}

pub fn private_blob_key_subject_chirho(
    root_chirho: &Path,
    key_id_chirho: &str,
) -> Result<Option<String>> {
    validate_key_id_chirho(key_id_chirho)?;
    let path_chirho = key_path_chirho(root_chirho, key_id_chirho);
    if !private_key_file_exists_chirho(&path_chirho)? {
        return Ok(None);
    }
    let key_chirho = load_key_chirho(root_chirho, key_id_chirho)?;
    Ok(Some(key_chirho.subject_chirho))
}

pub fn erase_private_blob_key_for_subject_chirho(
    root_chirho: &Path,
    key_id_chirho: &str,
    subject_chirho: &str,
) -> Result<bool> {
    validate_key_id_chirho(key_id_chirho)?;
    validate_subject_chirho(subject_chirho)?;
    let key_subjects_chirho = validate_private_blob_key_namespace_chirho(root_chirho)?;
    if let Some(record_subject_chirho) = key_subjects_chirho.get(key_id_chirho) {
        if record_subject_chirho != subject_chirho {
            bail!(
                "private blob key {key_id_chirho} is recorded for subject '{}', not '{}'",
                record_subject_chirho,
                subject_chirho
            );
        }
    }
    let path_chirho = key_path_chirho(root_chirho, key_id_chirho);
    if !private_key_file_exists_chirho(&path_chirho)? {
        return Ok(false);
    }
    let key_chirho = load_key_chirho(root_chirho, key_id_chirho)?;
    if key_chirho.subject_chirho != subject_chirho {
        bail!(
            "private blob key {key_id_chirho} belongs to subject '{}', not '{}'",
            key_chirho.subject_chirho,
            subject_chirho
        );
    }
    std::fs::remove_file(&path_chirho)?;
    Ok(true)
}

pub fn erase_subject_data_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    requested_by_chirho: &str,
    reason_chirho: &str,
) -> Result<PrivacyErasureRecordChirho> {
    erase_subject_data_with_optional_sink_chirho(
        root_chirho,
        subject_chirho,
        requested_by_chirho,
        reason_chirho,
        None,
    )
}

/// The elected road's erasure: the same erasure, but the sink makes the propagation requirement durable
/// under the erasure lock before the first key is removed, and its refusal stops the erasure (C5 B3-a1).
/// The root classifies the subject's earlier attempts from its own authenticated erasure log first, and
/// binds the requirement to the record right after the append. `required_key_ids_chirho` joins a NEW cut;
/// the caller takes it from a verified frozen inventory (C5 B3-a2-ii). A binding that fails after the
/// append returns `ErasureRecordedBindingPendingChirho`: the erasure is recorded and must not be repeated.
pub fn erase_subject_data_with_requirement_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    requested_by_chirho: &str,
    reason_chirho: &str,
    required_key_ids_chirho: &BTreeSet<String>,
    sink_chirho: &dyn ErasureRequirementSinkChirho,
) -> Result<PrivacyErasureRecordChirho> {
    erase_subject_data_with_optional_sink_chirho(
        root_chirho,
        subject_chirho,
        requested_by_chirho,
        reason_chirho,
        Some((sink_chirho, required_key_ids_chirho)),
    )
}

fn erase_subject_data_with_optional_sink_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    requested_by_chirho: &str,
    reason_chirho: &str,
    elected_chirho: Option<(&dyn ErasureRequirementSinkChirho, &BTreeSet<String>)>,
) -> Result<PrivacyErasureRecordChirho> {
    validate_subject_chirho(subject_chirho)?;
    validate_subject_chirho(requested_by_chirho)?;
    validate_safe_token_chirho("privacy erasure reason_chirho", reason_chirho)?;
    seqlog_chirho::with_named_lock_chirho(
        root_chirho,
        legal_hold_chirho::SUBJECT_RIGHTS_LOCK_CHIRHO,
        || {
            let active_holds_chirho = legal_hold_chirho::active_legal_holds_for_subject_chirho(
                root_chirho,
                subject_chirho,
            )?;
            if !active_holds_chirho.is_empty() {
                bail!(
                    "privacy erasure for subject '{}' is blocked by {} active legal hold(s)",
                    subject_chirho,
                    active_holds_chirho.len()
                );
            }
            // subject-rights -> account-attribution -> erasure-records: a store of the same subject
            // either finishes before this erasure reads the keys, or starts after it (R-C5-4a).
            with_account_attribution_lock_chirho(root_chirho, || {
                append_privacy_erasure_record_chirho(
                    root_chirho,
                    subject_chirho,
                    requested_by_chirho,
                    reason_chirho,
                    elected_chirho,
                )
            })
        },
    )
}

fn append_privacy_erasure_record_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    requested_by_chirho: &str,
    reason_chirho: &str,
    elected_chirho: Option<(&dyn ErasureRequirementSinkChirho, &BTreeSet<String>)>,
) -> Result<PrivacyErasureRecordChirho> {
    seqlog_chirho::with_named_lock_chirho(root_chirho, PRIVACY_ERASURE_RECORDS_LOCK_CHIRHO, || {
        let path_chirho = privacy_erasure_records_path_chirho(root_chirho);
        let records_chirho = load_privacy_erasure_records_chirho(root_chirho)?;
        let seq_chirho = records_chirho.len() as u64;
        let (key_ids_chirho, sign_with_existing_key_only_chirho) = match elected_chirho {
            // B3-a1: prove the existing key pair, then make the requirement durable from one
            // authenticated load, all before the first unlink. This road never mints (gpt #29719).
            Some((sink_chirho, required_key_ids_chirho)) => {
                let possessed_pubkey_chirho =
                    signer_chirho::existing_keypair_pubkey_hex_chirho(root_chirho)?;
                // a2-ii: authenticate the erasure log with the possessed key, then classify each of the
                // subject's unbound earlier attempts from it, before the store's lock is ever taken.
                verify_privacy_erasure_records_with_pubkey_chirho(
                    &records_chirho,
                    &possessed_pubkey_chirho,
                )?;
                let earlier_chirho = erasure_binding_chirho::classify_unbound_chirho(
                    &records_chirho,
                    subject_chirho,
                    &sink_chirho.unbound_requirement_seqs_chirho(subject_chirho)?,
                    seq_chirho,
                )?;
                let capture_chirho = erasure_capture_chirho::capture_erasure_unlocked_chirho(
                    root_chirho,
                    seq_chirho,
                    subject_chirho,
                    &possessed_pubkey_chirho,
                    required_key_ids_chirho,
                )?;
                sink_chirho.record_requirement_chirho(&capture_chirho, &earlier_chirho)?;
                (
                    remove_subject_key_files_chirho(root_chirho, subject_chirho)?,
                    true,
                )
            }
            None => (
                erase_subject_keys_with_ids_chirho(root_chirho, subject_chirho)?,
                false,
            ),
        };
        let mut record_chirho = PrivacyErasureRecordChirho {
            schema_chirho: PRIVACY_ERASURE_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho,
            subject_chirho: subject_chirho.to_string(),
            requested_by_chirho: requested_by_chirho.to_string(),
            reason_chirho: reason_chirho.to_string(),
            removed_keys_chirho: key_ids_chirho.len(),
            key_ids_chirho,
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = privacy_erasure_record_message_chirho(&record_chirho)?;
        // If custody vanished after the proof, the elected road refuses here rather than mint a
        // replacement key; its durable requirement is then recovery work.
        record_chirho.sig_chirho = if sign_with_existing_key_only_chirho {
            signer_chirho::sign_message_with_existing_key_chirho(root_chirho, &message_chirho)?
        } else {
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?
        };
        // The digest is fixed before the append, so a recorded erasure always has it to report.
        let record_digest_chirho =
            erasure_binding_chirho::erasure_record_digest_hex_chirho(&record_chirho)?;
        seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
            &path_chirho,
            record_chirho.seq_chirho,
            &record_chirho,
        )?;
        if let Some((sink_chirho, _)) = elected_chirho {
            // The sink's refusal is dropped, not carried: its text is not bounded (gpt #29956).
            if sink_chirho
                .record_binding_chirho(seq_chirho, subject_chirho, &record_digest_chirho)
                .is_err()
            {
                return Err(anyhow::Error::new(
                    erasure_binding_chirho::ErasureRecordedBindingPendingChirho {
                        erasure_seq_chirho: seq_chirho,
                        erasure_record_digest_chirho: record_digest_chirho,
                    },
                ));
            }
        }
        Ok(record_chirho)
    })
}

pub fn load_privacy_blob_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<PrivacyBlobRecordChirho>> {
    #[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
    private_blob_view_metrics_chirho::note_full_log_load_chirho();
    load_jsonl_chirho(
        &privacy_blob_records_path_chirho(root_chirho),
        "privacy blob record",
    )
}

pub fn load_privacy_erasure_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<PrivacyErasureRecordChirho>> {
    load_jsonl_chirho(
        &privacy_erasure_records_path_chirho(root_chirho),
        "privacy erasure record",
    )
}

pub fn load_privacy_access_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<PrivacyAccessRecordChirho>> {
    load_jsonl_chirho(
        &privacy_access_records_path_chirho(root_chirho),
        "privacy access record",
    )
}

pub fn append_privacy_access_record_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    accessed_by_chirho: &str,
    app_chirho: &str,
    row_key_chirho: &str,
    purpose_chirho: &str,
    blob_chirho: &PrivateBlobRefChirho,
) -> Result<PrivacyAccessRecordChirho> {
    validate_subject_chirho(subject_chirho)?;
    validate_subject_chirho(accessed_by_chirho)?;
    validate_key_id_chirho(&blob_chirho.key_id_chirho)?;
    validate_access_blob_subject_chirho(root_chirho, subject_chirho, blob_chirho)?;
    seqlog_chirho::with_named_lock_chirho(root_chirho, PRIVACY_ACCESS_RECORDS_LOCK_CHIRHO, || {
        let path_chirho = privacy_access_records_path_chirho(root_chirho);
        let seq_chirho = load_privacy_access_records_chirho(root_chirho)?.len() as u64;
        let mut record_chirho = PrivacyAccessRecordChirho {
            schema_chirho: PRIVACY_ACCESS_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho,
            subject_chirho: subject_chirho.to_string(),
            accessed_by_chirho: accessed_by_chirho.to_string(),
            app_chirho: app_chirho.to_string(),
            row_key_chirho: row_key_chirho.to_string(),
            purpose_chirho: purpose_chirho.to_string(),
            blob_chirho: blob_chirho.clone(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = privacy_access_record_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
            &path_chirho,
            record_chirho.seq_chirho,
            &record_chirho,
        )?;
        Ok(record_chirho)
    })
}

pub fn export_subject_data_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    include_private_chirho: bool,
) -> Result<SubjectDataExportChirho> {
    validate_subject_chirho(subject_chirho)?;
    verify_privacy_logs_chirho(root_chirho)?;
    let blob_records_chirho = load_privacy_blob_records_chirho(root_chirho)?;
    validate_private_blob_key_namespace_for_records_chirho(root_chirho, &blob_records_chirho)?;
    let private_blobs_chirho = blob_records_chirho
        .into_iter()
        .filter(|record_chirho| record_chirho.subject_chirho == subject_chirho)
        .map(|record_chirho| {
            let mut item_chirho = SubjectPrivateBlobExportChirho {
                record_chirho,
                plaintext_base64_chirho: None,
                unavailable_reason_chirho: None,
            };
            if include_private_chirho {
                match load_private_blob_chirho(root_chirho, &item_chirho.record_chirho.blob_chirho)
                {
                    Ok(bytes_chirho) => {
                        item_chirho.plaintext_base64_chirho =
                            Some(general_purpose::STANDARD.encode(bytes_chirho));
                    }
                    Err(error_chirho) => {
                        item_chirho.unavailable_reason_chirho = Some(error_chirho.to_string());
                    }
                }
            }
            item_chirho
        })
        .collect();
    let erasures_chirho = load_privacy_erasure_records_chirho(root_chirho)?
        .into_iter()
        .filter(|record_chirho| record_chirho.subject_chirho == subject_chirho)
        .collect();
    let access_records_chirho = load_privacy_access_records_chirho(root_chirho)?
        .into_iter()
        .filter(|record_chirho| {
            record_chirho.subject_chirho == subject_chirho
                || record_chirho.accessed_by_chirho == subject_chirho
        })
        .collect();
    Ok(SubjectDataExportChirho {
        subject_chirho: subject_chirho.to_string(),
        generated_ms_chirho: now_ms_chirho(),
        include_private_chirho,
        private_blobs_chirho,
        erasures_chirho,
        access_records_chirho,
    })
}

pub fn verify_privacy_logs_chirho(root_chirho: &Path) -> Result<PrivacyVerifyReportChirho> {
    let (blob_records_chirho, key_subjects_chirho) =
        verify_privacy_blob_records_chirho(root_chirho)?;
    let erasure_records_chirho = verify_privacy_erasure_records_chirho(root_chirho)?;
    let access_records_chirho =
        verify_privacy_access_records_chirho(root_chirho, &key_subjects_chirho)?;
    Ok(PrivacyVerifyReportChirho {
        blob_records_chirho,
        erasure_records_chirho,
        access_records_chirho,
    })
}

fn load_key_chirho(root_chirho: &Path, key_id_chirho: &str) -> Result<ShredKeyChirho> {
    #[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
    private_blob_view_metrics_chirho::note_key_file_read_chirho();
    let path_chirho = key_path_chirho(root_chirho, key_id_chirho);
    private_key_file_exists_chirho(&path_chirho)?;
    let bytes_chirho =
        std::fs::read(&path_chirho).with_context(|| format!("read {}", path_chirho.display()))?;
    Ok(serde_json::from_slice(&bytes_chirho)?)
}

fn private_key_file_exists_chirho(path_chirho: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path_chirho) {
        Ok(metadata_chirho) => {
            if metadata_chirho.file_type().is_symlink() {
                bail!(
                    "private blob key file {} must not be a symlink",
                    path_chirho.display()
                );
            }
            Ok(true)
        }
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error_chirho) => Err(error_chirho)
            .with_context(|| format!("inspect private key file {}", path_chirho.display())),
    }
}

fn key_paths_chirho(root_chirho: &Path) -> Result<Vec<PathBuf>> {
    let dir_chirho = keys_dir_chirho(root_chirho);
    if !dir_chirho.exists() {
        return Ok(Vec::new());
    }
    let mut paths_chirho = Vec::new();
    for entry_chirho in std::fs::read_dir(&dir_chirho)? {
        paths_chirho.push(entry_chirho?.path());
    }
    paths_chirho.sort();
    Ok(paths_chirho)
}

fn validate_key_id_chirho(key_id_chirho: &str) -> Result<()> {
    if key_id_chirho.is_empty()
        || key_id_chirho.len() > 128
        || !key_id_chirho
            .chars()
            .all(|ch_chirho| ch_chirho.is_ascii_hexdigit())
    {
        bail!("private blob key_id_chirho is invalid");
    }
    Ok(())
}

fn validate_safe_token_chirho(name_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.trim().is_empty()
        || value_chirho.len() > 128
        || !value_chirho.chars().all(|ch_chirho| {
            ch_chirho.is_ascii_alphanumeric() || matches!(ch_chirho, '-' | '_' | '/' | ':' | '.')
        })
    {
        bail!("{name_chirho} must be a short opaque token");
    }
    Ok(())
}

fn append_privacy_blob_record_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    blob_chirho: &PrivateBlobRefChirho,
    bytes_chirho: usize,
) -> Result<PrivacyBlobRecordChirho> {
    seqlog_chirho::with_named_lock_chirho(root_chirho, PRIVACY_BLOB_RECORDS_LOCK_CHIRHO, || {
        let path_chirho = privacy_blob_records_path_chirho(root_chirho);
        // Checkpoint brick S1 (PFE #25789, agy #25796): a store refuses exactly when a lookup would. The blob view is
        // brought current FIRST, O(delta), and refuses on any complete bad line or key-file fault while it is still in
        // the log. Only then may recovery repair the log, and it touches only an unterminated tail (a crash mid-append),
        // which the view leaves alone. Recovery first would have quarantined a complete bad final line and let the root
        // resume as if nothing happened.
        let verified_records_chirho =
            blob_view_chirho::current_blob_record_count_chirho(root_chirho)?;
        // O(1) from the log's head sidecar. This was a full typed load, O(blob records) per private store (census
        // execution-effects row A3, blob half).
        let seq_chirho = seqlog_chirho::recover_jsonl_len_unlocked_chirho(&path_chirho)?;
        if seq_chirho != verified_records_chirho {
            bail!(
                "privacy blob log holds {seq_chirho} records by recovery but {verified_records_chirho} verified records; \
                 refusing to append"
            );
        }
        let mut record_chirho = PrivacyBlobRecordChirho {
            schema_chirho: PRIVACY_BLOB_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho,
            subject_chirho: subject_chirho.to_string(),
            blob_chirho: blob_chirho.clone(),
            bytes_chirho,
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = privacy_blob_record_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
            &path_chirho,
            record_chirho.seq_chirho,
            &record_chirho,
        )?;
        Ok(record_chirho)
    })
}

fn verify_privacy_blob_records_chirho(
    root_chirho: &Path,
) -> Result<(usize, BTreeMap<String, String>)> {
    let records_chirho = load_privacy_blob_records_chirho(root_chirho)?;
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let key_subjects_chirho = verify_privacy_blob_records_with_pubkey_chirho(
        root_chirho,
        &records_chirho,
        &pubkey_chirho,
    )?;
    Ok((records_chirho.len(), key_subjects_chirho))
}

/// Authenticate loaded blob records against one public key: seqs dense from 0, schema, shape, each
/// existing key file's subject and every signature. The caller decides how the key is obtained.
fn verify_privacy_blob_records_with_pubkey_chirho(
    root_chirho: &Path,
    records_chirho: &[PrivacyBlobRecordChirho],
    pubkey_chirho: &str,
) -> Result<BTreeMap<String, String>> {
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "privacy blob record seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        if !record_chirho.schema_chirho.is_empty()
            && record_chirho.schema_chirho != PRIVACY_BLOB_RECORD_SCHEMA_CHIRHO
        {
            bail!(
                "unsupported privacy blob record schema '{}'",
                record_chirho.schema_chirho
            );
        }
        validate_subject_chirho(&record_chirho.subject_chirho)?;
        validate_key_id_chirho(&record_chirho.blob_chirho.key_id_chirho)?;
        if record_chirho.blob_chirho.alg_chirho != PRIVATE_BLOB_ALG_CHIRHO {
            bail!(
                "privacy blob record {} unsupported alg '{}'",
                record_chirho.seq_chirho,
                record_chirho.blob_chirho.alg_chirho
            );
        }
        validate_private_blob_ref_shape_chirho(root_chirho, &record_chirho.blob_chirho)?;
        validate_existing_key_subject_chirho(root_chirho, record_chirho)?;
        let message_chirho = privacy_blob_record_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "privacy blob record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    private_blob_key_subjects_chirho(records_chirho)
}

fn verify_privacy_erasure_records_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_privacy_erasure_records_chirho(root_chirho)?;
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    verify_privacy_erasure_records_with_pubkey_chirho(&records_chirho, &pubkey_chirho)?;
    Ok(records_chirho.len())
}

/// Authenticate the erasure log against one public key: dense seqs, schema, shape and every signature. The
/// elected road passes the POSSESSED key, so authenticating never mints one (C5 B3-a2-ii).
fn verify_privacy_erasure_records_with_pubkey_chirho(
    records_chirho: &[PrivacyErasureRecordChirho],
    pubkey_chirho: &str,
) -> Result<()> {
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "privacy erasure record seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        if !record_chirho.schema_chirho.is_empty()
            && record_chirho.schema_chirho != PRIVACY_ERASURE_RECORD_SCHEMA_CHIRHO
        {
            bail!(
                "unsupported privacy erasure record schema '{}'",
                record_chirho.schema_chirho
            );
        }
        validate_subject_chirho(&record_chirho.subject_chirho)?;
        validate_subject_chirho(&record_chirho.requested_by_chirho)?;
        for key_id_chirho in &record_chirho.key_ids_chirho {
            validate_key_id_chirho(key_id_chirho)?;
        }
        if record_chirho.removed_keys_chirho != record_chirho.key_ids_chirho.len() {
            bail!(
                "privacy erasure record {} removed_keys_chirho mismatch",
                record_chirho.seq_chirho
            );
        }
        let message_chirho = privacy_erasure_record_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "privacy erasure record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(())
}

fn verify_privacy_access_records_chirho(
    root_chirho: &Path,
    key_subjects_chirho: &BTreeMap<String, String>,
) -> Result<usize> {
    let records_chirho = load_privacy_access_records_chirho(root_chirho)?;
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "privacy access record seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        if !record_chirho.schema_chirho.is_empty()
            && record_chirho.schema_chirho != PRIVACY_ACCESS_RECORD_SCHEMA_CHIRHO
        {
            bail!(
                "unsupported privacy access record schema '{}'",
                record_chirho.schema_chirho
            );
        }
        validate_subject_chirho(&record_chirho.subject_chirho)?;
        validate_subject_chirho(&record_chirho.accessed_by_chirho)?;
        validate_key_id_chirho(&record_chirho.blob_chirho.key_id_chirho)?;
        if record_chirho.blob_chirho.alg_chirho != PRIVATE_BLOB_ALG_CHIRHO {
            bail!(
                "privacy access record {} unsupported alg '{}'",
                record_chirho.seq_chirho,
                record_chirho.blob_chirho.alg_chirho
            );
        }
        validate_access_record_key_subject_chirho(record_chirho, key_subjects_chirho)?;
        let message_chirho = privacy_access_record_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "privacy access record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho.len())
}

pub(crate) fn validate_private_blob_key_namespace_chirho(
    root_chirho: &Path,
) -> Result<BTreeMap<String, String>> {
    let records_chirho = load_privacy_blob_records_chirho(root_chirho)?;
    validate_private_blob_key_namespace_for_records_chirho(root_chirho, &records_chirho)
}

fn validate_private_blob_key_namespace_for_records_chirho(
    root_chirho: &Path,
    records_chirho: &[PrivacyBlobRecordChirho],
) -> Result<BTreeMap<String, String>> {
    let subjects_chirho = private_blob_key_subjects_chirho(records_chirho)?;
    for record_chirho in records_chirho {
        validate_existing_key_subject_chirho(root_chirho, record_chirho)?;
    }
    Ok(subjects_chirho)
}

fn private_blob_key_subjects_chirho(
    records_chirho: &[PrivacyBlobRecordChirho],
) -> Result<BTreeMap<String, String>> {
    let mut subjects_chirho = BTreeMap::new();
    for record_chirho in records_chirho {
        validate_subject_chirho(&record_chirho.subject_chirho)?;
        validate_key_id_chirho(&record_chirho.blob_chirho.key_id_chirho)?;
        if let Some(existing_subject_chirho) =
            subjects_chirho.get(&record_chirho.blob_chirho.key_id_chirho)
        {
            if existing_subject_chirho != &record_chirho.subject_chirho {
                bail!(
                    "private blob key {} is claimed by multiple subjects: '{}' and '{}'",
                    record_chirho.blob_chirho.key_id_chirho,
                    existing_subject_chirho,
                    record_chirho.subject_chirho
                );
            }
        } else {
            subjects_chirho.insert(
                record_chirho.blob_chirho.key_id_chirho.clone(),
                record_chirho.subject_chirho.clone(),
            );
        }
    }
    Ok(subjects_chirho)
}

fn validate_existing_key_subject_chirho(
    root_chirho: &Path,
    record_chirho: &PrivacyBlobRecordChirho,
) -> Result<()> {
    validate_existing_key_subject_for_chirho(
        root_chirho,
        &record_chirho.blob_chirho.key_id_chirho,
        &record_chirho.subject_chirho,
    )
}

/// A blob record's key file, if present, must name the record's subject: the full scan's check (c), shared with the
/// blob view's fold and its per-lookup target-key check so all three refuse with one message.
fn validate_existing_key_subject_for_chirho(
    root_chirho: &Path,
    key_id_chirho: &str,
    subject_chirho: &str,
) -> Result<()> {
    if let Some(key_subject_chirho) = private_blob_key_subject_chirho(root_chirho, key_id_chirho)? {
        if key_subject_chirho != subject_chirho {
            bail!(
                "private blob key {} belongs to subject '{}', not privacy blob record subject '{}'",
                key_id_chirho,
                key_subject_chirho,
                subject_chirho
            );
        }
    }
    Ok(())
}

fn validate_access_blob_subject_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    blob_chirho: &PrivateBlobRefChirho,
) -> Result<()> {
    match private_blob_key_subject_chirho(root_chirho, &blob_chirho.key_id_chirho)? {
        Some(key_subject_chirho) if key_subject_chirho == subject_chirho => Ok(()),
        Some(key_subject_chirho) => bail!(
            "private blob key {} belongs to subject '{}', not privacy access subject '{}'",
            blob_chirho.key_id_chirho,
            key_subject_chirho,
            subject_chirho
        ),
        None => bail!(
            "private blob key {} is unavailable; cannot append privacy access record",
            blob_chirho.key_id_chirho
        ),
    }
}

fn validate_access_record_key_subject_chirho(
    record_chirho: &PrivacyAccessRecordChirho,
    key_subjects_chirho: &BTreeMap<String, String>,
) -> Result<()> {
    let key_id_chirho = &record_chirho.blob_chirho.key_id_chirho;
    let key_subject_chirho = key_subjects_chirho.get(key_id_chirho).ok_or_else(|| {
        anyhow!(
            "privacy access record {} references unknown private blob key {}",
            record_chirho.seq_chirho,
            key_id_chirho
        )
    })?;
    if key_subject_chirho != &record_chirho.subject_chirho {
        bail!(
            "privacy access record {} key {} belongs to subject '{}', not '{}'",
            record_chirho.seq_chirho,
            key_id_chirho,
            key_subject_chirho,
            record_chirho.subject_chirho
        );
    }
    Ok(())
}

fn privacy_blob_record_message_chirho(record_chirho: &PrivacyBlobRecordChirho) -> Result<Vec<u8>> {
    let mut message_chirho = record_chirho.clone();
    message_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&message_chirho)?)
}

fn privacy_erasure_record_message_chirho(
    record_chirho: &PrivacyErasureRecordChirho,
) -> Result<Vec<u8>> {
    let mut message_chirho = record_chirho.clone();
    message_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&message_chirho)?)
}

fn privacy_access_record_message_chirho(
    record_chirho: &PrivacyAccessRecordChirho,
) -> Result<Vec<u8>> {
    let mut message_chirho = record_chirho.clone();
    message_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&message_chirho)?)
}

fn load_jsonl_chirho<T>(path_chirho: &Path, label_chirho: &str) -> Result<Vec<T>>
where
    T: for<'de> Deserialize<'de>,
{
    let Some(text_chirho) = read_log_text_chirho(path_chirho)? else {
        return Ok(Vec::new());
    };
    let mut out_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        out_chirho.push(
            serde_json::from_str(line_chirho)
                .map_err(|e_chirho| anyhow!("bad {label_chirho}: {e_chirho}"))?,
        );
    }
    Ok(out_chirho)
}

fn mac_chirho(key_chirho: &[u8; 32], nonce_chirho: &[u8; 24], ciphertext_chirho: &[u8]) -> String {
    let mut hasher_chirho = blake3::Hasher::new_keyed(key_chirho);
    hasher_chirho.update(b"cairn-chirho/private-blob-mac/v1");
    hasher_chirho.update(nonce_chirho);
    hasher_chirho.update(ciphertext_chirho);
    hex_encode_chirho(hasher_chirho.finalize().as_bytes())
}

fn hex_encode_chirho(bytes_chirho: &[u8]) -> String {
    const HEX_CHIRHO: &[u8; 16] = b"0123456789abcdef";
    let mut out_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for b_chirho in bytes_chirho {
        out_chirho.push(HEX_CHIRHO[(b_chirho >> 4) as usize] as char);
        out_chirho.push(HEX_CHIRHO[(b_chirho & 0x0f) as usize] as char);
    }
    out_chirho
}

fn hex_decode_fixed_chirho<const N_CHIRHO: usize>(hex_chirho: &str) -> Result<[u8; N_CHIRHO]> {
    let bytes_chirho = hex_decode_chirho(hex_chirho)?;
    bytes_chirho
        .try_into()
        .map_err(|v_chirho: Vec<u8>| anyhow!("expected {N_CHIRHO} bytes, got {}", v_chirho.len()))
}

fn hex_decode_chirho(hex_chirho: &str) -> Result<Vec<u8>> {
    if !hex_chirho.len().is_multiple_of(2) {
        bail!("odd-length hex string");
    }
    (0..hex_chirho.len())
        .step_by(2)
        .map(|i_chirho| {
            u8::from_str_radix(&hex_chirho[i_chirho..i_chirho + 2], 16)
                .map_err(|e_chirho| anyhow!("bad hex: {e_chirho}"))
        })
        .collect()
}

#[cfg(test)]
#[path = "privacy_chirho/tests_chirho.rs"]
mod tests_chirho;
