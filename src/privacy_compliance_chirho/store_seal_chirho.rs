// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Wraps a store value in a per-record encrypted envelope and unseals it back to verified plaintext.

use crate::{privacy_chirho, versioned_chirho};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// The schema tag that marks a store row as a sealed envelope rather than a plaintext value.
pub const SEALED_STORE_VALUE_SCHEMA_CHIRHO: &str = "sealed-store-value-v2-chirho";

/// The v1 envelope tag. v1 rows carried `value_hash_chirho`, an unsalted `blake3(plaintext)` resting
/// in the clear — the S2 review's F1 offline dictionary oracle. v2 replaces it with a keyed digest.
///
/// Per the standing seal-forward ruling there is NO migration: a v1 row keeps its unsalted hash and
/// this build will not read it. The tag stays recognized here for one reason only — so a v1 row
/// FAILS CLOSED as an envelope this build cannot read, instead of passing through
/// `NotSealedChirho` and handing a caller the envelope JSON as if it were the plaintext value.
pub const LEGACY_UNSALTED_SEALED_STORE_VALUE_SCHEMA_CHIRHO: &str = "sealed-store-value-v1-chirho";

/// Store-seal subjects for app writes. Deliberately disjoint from person subjects (ruling (c)).
pub const APP_STORE_SEAL_SUBJECT_PREFIX_CHIRHO: &str = "app-store/";

/// Store-seal subjects for operator writes that carry no app context.
pub const OPERATOR_STORE_SEAL_SUBJECT_PREFIX_CHIRHO: &str = "operator-store/";

/// The reviewed safe-envelope schema set: exactly the schemas the owner reveal path accepts.
pub const REVIEWED_SAFE_ENVELOPE_SCHEMAS_CHIRHO: [&str; 3] = [
    "app-private-input-ref-v1-chirho",
    "contact-record-v1-chirho",
    "perffection-intake-record-v1-chirho",
];

/// The only fields ever copied out of a reviewed safe envelope into bounded safe metadata.
pub const SAFE_METADATA_KEYS_CHIRHO: [&str; 4] = [
    "blob_chirho",
    "schema_chirho",
    "status_chirho",
    "subject_chirho",
];

/// Fixed label used when a store key's leading segment is not representable in a subject.
const OPAQUE_KEY_PREFIX_LABEL_CHIRHO: &str = "opaque-prefix-chirho";
const SUBJECT_KEY_DIGEST_BYTES_CHIRHO: usize = 16;
const SUBJECT_KEY_DIGEST_HEX_LEN_CHIRHO: usize = SUBJECT_KEY_DIGEST_BYTES_CHIRHO * 2;
const SUBJECT_SEGMENT_MAX_BYTES_CHIRHO: usize = 64;
const SAFE_METADATA_STATUS_MAX_BYTES_CHIRHO: usize = 64;
const SAFE_METADATA_ALG_MAX_BYTES_CHIRHO: usize = 64;
const BLOB_KEY_ID_HEX_LEN_CHIRHO: usize = 32;
const BLOB_NONCE_HEX_LEN_CHIRHO: usize = 48;
const BLOB_MAC_HEX_LEN_CHIRHO: usize = 64;
const BLOB_CIPHERTEXT_HEX_LEN_CHIRHO: usize = 64;
const KEYED_PLAINTEXT_DIGEST_HEX_LEN_CHIRHO: usize = 64;

/// The at-rest form of a sealed store value: safe labels plus a private blob ref, never plaintext.
///
/// `deny_unknown_fields` is load-bearing: a row that carries plaintext in an extra field alongside
/// a sealed schema tag must fail detection rather than read as a well-formed envelope, or a
/// coverage scan would report it sealed while the plaintext rests beside the seal.
///
/// **No field here may be a key-free function of the plaintext.** v1 held `value_hash_chirho`, an
/// unsalted `blake3(plaintext)`, and the S2 review PROVED the consequence: holding the row alone —
/// with the shred keys and the ciphertext both gone — a low-entropy value was recovered by hashing
/// candidates against it. `keyed_plaintext_digest_chirho` replaces it. The one residual this shape
/// still leaks is `bytes_chirho`, the exact plaintext LENGTH; that is named in §2.6 and pinned by
/// the F1 arm rather than quietly carried.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedStoreValueChirho {
    pub schema_chirho: String,
    pub subject_chirho: String,
    /// `blake3::keyed_hash` of the plaintext under a subkey derived from this row's own shred key.
    /// NOT a content address: nothing may look this up in CAS, and no one without the key can
    /// compute it.
    pub keyed_plaintext_digest_chirho: String,
    pub bytes_chirho: usize,
    pub blob_chirho: privacy_chirho::PrivateBlobRefChirho,
    #[serde(default)]
    pub safe_metadata_chirho: BTreeMap<String, String>,
}

/// What a stored row turned out to be: a sealed envelope, or bytes that were never sealed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreValueViewChirho {
    SealedChirho(Box<SealedStoreValueChirho>),
    NotSealedChirho,
}

fn hex_encode_chirho(bytes_chirho: &[u8]) -> String {
    bytes_chirho
        .iter()
        .map(|byte_chirho| format!("{byte_chirho:02x}"))
        .collect()
}

fn is_lower_hex_of_len_chirho(text_chirho: &str, len_chirho: usize) -> bool {
    text_chirho.len() == len_chirho
        && text_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

/// A short, disclosure-free correlation digest for values that must never reach an error message.
fn correlation_digest_chirho(bytes_chirho: &[u8]) -> String {
    hex_encode_chirho(&blake3::hash(bytes_chirho).as_bytes()[..SUBJECT_KEY_DIGEST_BYTES_CHIRHO])
}

fn is_subject_segment_chirho(segment_chirho: &str) -> bool {
    !segment_chirho.is_empty()
        && segment_chirho.len() <= SUBJECT_SEGMENT_MAX_BYTES_CHIRHO
        && segment_chirho != "."
        && segment_chirho != ".."
        && segment_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_alphanumeric()
                || byte_chirho == b'-'
                || byte_chirho == b'_'
                || byte_chirho == b'.'
        })
}

/// Derives the store-seal subject of §3c: `app-store/<app>/<key prefix>/<blake3-16(key)>`, or
/// `operator-store/<blake3-16(key)>` when the write carries no app context.
pub fn store_seal_subject_chirho(app_chirho: Option<&str>, key_chirho: &str) -> Result<String> {
    if key_chirho.is_empty() {
        bail!("store seal subject requires a non-empty store key");
    }
    let key_digest_chirho = correlation_digest_chirho(key_chirho.as_bytes());
    let subject_chirho = match app_chirho {
        None => format!("{OPERATOR_STORE_SEAL_SUBJECT_PREFIX_CHIRHO}{key_digest_chirho}"),
        Some(app_chirho) => {
            if !is_subject_segment_chirho(app_chirho) {
                bail!(
                    "store seal subject requires an app name of at most {SUBJECT_SEGMENT_MAX_BYTES_CHIRHO} slug bytes"
                );
            }
            // The leading key segment is a readability grouping only; row identity in the subject
            // comes from the key digest, so an unrepresentable prefix collapses to a fixed label
            // rather than refusing the write or mangling the key.
            let prefix_chirho = key_chirho.split('/').next().unwrap_or_default();
            let prefix_chirho = if is_subject_segment_chirho(prefix_chirho) {
                prefix_chirho
            } else {
                OPAQUE_KEY_PREFIX_LABEL_CHIRHO
            };
            format!(
                "{APP_STORE_SEAL_SUBJECT_PREFIX_CHIRHO}{app_chirho}/{prefix_chirho}/{key_digest_chirho}"
            )
        }
    };
    ensure_store_seal_subject_chirho(&subject_chirho)?;
    Ok(subject_chirho)
}

/// Fails closed unless the subject is a well-formed store-seal subject; a person subject, or any
/// subject carrying free text, is refused here before it can reach the privacy key namespace.
pub fn ensure_store_seal_subject_chirho(subject_chirho: &str) -> Result<()> {
    privacy_chirho::validate_privacy_subject_chirho(subject_chirho).map_err(|_error_chirho| {
        anyhow::anyhow!("store seal subject is not a valid privacy subject")
    })?;
    let segments_chirho: Vec<&str> = subject_chirho.split('/').collect();
    let tail_chirho = match segments_chirho.as_slice() {
        ["app-store", app_chirho, prefix_chirho, digest_chirho] => {
            if !is_subject_segment_chirho(app_chirho) || !is_subject_segment_chirho(prefix_chirho) {
                bail!("store seal subject app/prefix segments must be bounded slugs");
            }
            *digest_chirho
        }
        ["operator-store", digest_chirho] => *digest_chirho,
        _ => bail!(
            "store seal subject must be '{APP_STORE_SEAL_SUBJECT_PREFIX_CHIRHO}<app>/<prefix>/<key digest>' or '{OPERATOR_STORE_SEAL_SUBJECT_PREFIX_CHIRHO}<key digest>'"
        ),
    };
    if !is_lower_hex_of_len_chirho(tail_chirho, SUBJECT_KEY_DIGEST_HEX_LEN_CHIRHO) {
        bail!(
            "store seal subject must end in a {SUBJECT_KEY_DIGEST_HEX_LEN_CHIRHO}-character key digest"
        );
    }
    Ok(())
}

/// Fails closed unless `subject_chirho` is the store-seal subject of `key_chirho` itself.
///
/// Blob subject binding proves an envelope's ciphertext belongs to SOME store row; only this proves
/// it belongs to THIS one. Without it, an envelope copied from key A to key B unseals cleanly —
/// privacy-log coverage, blob subject binding, the blob MAC, the AEAD and the keyed plaintext digest
/// are every one of them properties of the substituted blob, so they travel with it to the new key.
///
/// This binds the KEY DIGEST only, deliberately. The app and prefix segments are a readability
/// grouping (§3c); requiring them to match would make unsealing a second, undeclared authorization
/// rule layered on the capability prefix scope that already authorizes the read, and would refuse an
/// operator-seeded row to an app that is plainly entitled to it.
pub fn ensure_store_seal_subject_binds_key_chirho(
    subject_chirho: &str,
    key_chirho: &str,
) -> Result<()> {
    ensure_store_seal_subject_chirho(subject_chirho)?;
    let expected_digest_chirho = correlation_digest_chirho(key_chirho.as_bytes());
    let actual_digest_chirho = subject_chirho.rsplit('/').next().unwrap_or_default();
    if actual_digest_chirho != expected_digest_chirho {
        bail!(
            "sealed store value subject does not bind this store key (subject binds {actual_digest_chirho}, key digests to {expected_digest_chirho})"
        );
    }
    Ok(())
}

fn validate_safe_blob_ref_chirho(blob_chirho: &privacy_chirho::PrivateBlobRefChirho) -> Result<()> {
    if !is_lower_hex_of_len_chirho(
        &blob_chirho.ciphertext_chirho.0,
        BLOB_CIPHERTEXT_HEX_LEN_CHIRHO,
    ) {
        bail!("safe metadata blob ciphertext is not a content address");
    }
    if !is_lower_hex_of_len_chirho(&blob_chirho.key_id_chirho, BLOB_KEY_ID_HEX_LEN_CHIRHO) {
        bail!("safe metadata blob key id is not a key digest");
    }
    if !is_lower_hex_of_len_chirho(&blob_chirho.nonce_chirho, BLOB_NONCE_HEX_LEN_CHIRHO) {
        bail!("safe metadata blob nonce is not a nonce digest");
    }
    if !is_lower_hex_of_len_chirho(&blob_chirho.mac_chirho, BLOB_MAC_HEX_LEN_CHIRHO) {
        bail!("safe metadata blob mac is not a mac digest");
    }
    if blob_chirho.alg_chirho.is_empty()
        || blob_chirho.alg_chirho.len() > SAFE_METADATA_ALG_MAX_BYTES_CHIRHO
        || !blob_chirho.alg_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_alphanumeric()
                || matches!(byte_chirho, b'-' | b'_' | b'+' | b'.' | b'/')
        })
    {
        bail!(
            "safe metadata blob alg must be at most {SAFE_METADATA_ALG_MAX_BYTES_CHIRHO} algorithm-name bytes"
        );
    }
    Ok(())
}

/// Bounds one safe-metadata entry. No caller-supplied value is ever echoed: a refusal names the
/// field and its bound, or a correlation digest, so plaintext cannot ride out on an error.
fn validate_safe_metadata_value_chirho(key_chirho: &str, value_chirho: &str) -> Result<()> {
    match key_chirho {
        "schema_chirho" => {
            if !REVIEWED_SAFE_ENVELOPE_SCHEMAS_CHIRHO.contains(&value_chirho) {
                bail!("safe metadata schema_chirho is not a reviewed safe-envelope schema");
            }
        }
        "status_chirho" => {
            if value_chirho.is_empty() || value_chirho.len() > SAFE_METADATA_STATUS_MAX_BYTES_CHIRHO
            {
                bail!(
                    "safe metadata status_chirho must be 1 to {SAFE_METADATA_STATUS_MAX_BYTES_CHIRHO} bytes"
                );
            }
            if !value_chirho.bytes().all(|byte_chirho| {
                byte_chirho.is_ascii_lowercase()
                    || byte_chirho.is_ascii_digit()
                    || byte_chirho == b'-'
                    || byte_chirho == b'_'
            }) {
                bail!("safe metadata status_chirho must be a lowercase slug");
            }
        }
        "subject_chirho" => {
            privacy_chirho::validate_privacy_subject_chirho(value_chirho).map_err(
                |_error_chirho| {
                    anyhow::anyhow!("safe metadata subject_chirho is not a valid privacy subject")
                },
            )?;
        }
        "blob_chirho" => {
            let blob_chirho: privacy_chirho::PrivateBlobRefChirho =
                serde_json::from_str(value_chirho).map_err(|_error_chirho| {
                    anyhow::anyhow!("safe metadata blob_chirho is not a private blob ref")
                })?;
            validate_safe_blob_ref_chirho(&blob_chirho)?;
        }
        _ => bail!(
            "safe metadata carries an unsupported key (digest {})",
            correlation_digest_chirho(key_chirho.as_bytes())
        ),
    }
    Ok(())
}

/// Bounds a whole safe-metadata map, so a hostile envelope cannot smuggle free text into a listing.
pub fn validate_safe_store_metadata_chirho(
    safe_metadata_chirho: &BTreeMap<String, String>,
) -> Result<()> {
    if safe_metadata_chirho.len() > SAFE_METADATA_KEYS_CHIRHO.len() {
        bail!(
            "safe metadata carries at most {} entries",
            SAFE_METADATA_KEYS_CHIRHO.len()
        );
    }
    for (key_chirho, value_chirho) in safe_metadata_chirho {
        validate_safe_metadata_value_chirho(key_chirho, value_chirho)?;
    }
    Ok(())
}

/// Extracts the bounded safe metadata of §2.5: labels are copied only out of a reviewed
/// safe-envelope schema, and any other value seals fully opaque with an empty map.
pub fn safe_store_metadata_chirho(value_chirho: &[u8]) -> Result<BTreeMap<String, String>> {
    let Ok(parsed_chirho) = serde_json::from_slice::<serde_json::Value>(value_chirho) else {
        return Ok(BTreeMap::new());
    };
    let Some(object_chirho) = parsed_chirho.as_object() else {
        return Ok(BTreeMap::new());
    };
    let schema_chirho = object_chirho
        .get("schema_chirho")
        .and_then(|schema_chirho| schema_chirho.as_str())
        .unwrap_or_default();
    if !REVIEWED_SAFE_ENVELOPE_SCHEMAS_CHIRHO.contains(&schema_chirho) {
        return Ok(BTreeMap::new());
    }
    let mut safe_metadata_chirho = BTreeMap::new();
    safe_metadata_chirho.insert("schema_chirho".to_string(), schema_chirho.to_string());
    for field_chirho in ["status_chirho", "subject_chirho"] {
        let Some(raw_chirho) = object_chirho.get(field_chirho) else {
            continue;
        };
        let text_chirho = raw_chirho
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("safe metadata {field_chirho} must be a string"))?;
        safe_metadata_chirho.insert(field_chirho.to_string(), text_chirho.to_string());
    }
    if let Some(raw_blob_chirho) = object_chirho.get("blob_chirho") {
        let blob_chirho: privacy_chirho::PrivateBlobRefChirho =
            serde_json::from_value(raw_blob_chirho.clone()).map_err(|_error_chirho| {
                anyhow::anyhow!("safe metadata blob_chirho is not a private blob ref")
            })?;
        safe_metadata_chirho.insert(
            "blob_chirho".to_string(),
            serde_json::to_string(&blob_chirho)?,
        );
    }
    validate_safe_store_metadata_chirho(&safe_metadata_chirho)?;
    Ok(safe_metadata_chirho)
}

/// Seals one store value: bounded metadata is extracted and refused first, so a rejected value
/// mints no key, no ciphertext and no privacy-log row.
///
/// The blob is stored BEFORE the plaintext-identity digest is computed, because the digest is keyed
/// by the shred key that storing the blob mints. Both refusals that must leave nothing behind —
/// the subject namespace and the bounded safe metadata — still run ahead of the blob store, so a
/// rejected value is rejected before any key, ciphertext or log row exists.
pub fn seal_store_value_chirho(
    root_chirho: &Path,
    attribution_chirho: &privacy_chirho::PrivateBlobAttributionChirho,
    app_chirho: Option<&str>,
    key_chirho: &str,
    value_chirho: &[u8],
) -> Result<SealedStoreValueChirho> {
    let subject_chirho = store_seal_subject_chirho(app_chirho, key_chirho)?;
    let safe_metadata_chirho = safe_store_metadata_chirho(value_chirho)?;
    let blob_chirho = privacy_chirho::store_private_blob_chirho(
        root_chirho,
        attribution_chirho,
        &subject_chirho,
        value_chirho,
    )?;
    let keyed_plaintext_digest_chirho = privacy_chirho::private_blob_keyed_plaintext_digest_chirho(
        root_chirho,
        &blob_chirho,
        value_chirho,
    )?;
    Ok(SealedStoreValueChirho {
        schema_chirho: SEALED_STORE_VALUE_SCHEMA_CHIRHO.to_string(),
        subject_chirho,
        keyed_plaintext_digest_chirho,
        bytes_chirho: value_chirho.len(),
        blob_chirho,
        safe_metadata_chirho,
    })
}

/// The canonical at-rest bytes of a sealed envelope.
pub fn encode_sealed_store_value_chirho(sealed_chirho: &SealedStoreValueChirho) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(sealed_chirho)?)
}

/// What one sealed write left behind: the store version it landed at and the envelope that rests.
pub struct SealedStorePutChirho {
    pub version_chirho: u64,
    pub sealed_chirho: SealedStoreValueChirho,
}

/// The single production write door: seal, then put ONLY the envelope.
///
/// Both blessed `WriteStoreChirho` reify and the operator `kv-put` route through here, so an app
/// cannot rest a plaintext customer value in the versioned store whether or not its author
/// remembered to seal. Sealing precedes the put, so a crash in the window leaves an orphan
/// key + ciphertext + privacy-log row with no consuming row — internally consistent, GC/inventory
/// visible, and re-driven by the retry as a fresh envelope. The reverse order is what must never
/// happen: a put before its seal would rest plaintext, which is the failure this door exists to
/// make impossible.
pub fn seal_and_put_store_value_chirho(
    root_chirho: &Path,
    store_chirho: &versioned_chirho::VersionedStoreChirho,
    attribution_chirho: &privacy_chirho::PrivateBlobAttributionChirho,
    app_chirho: Option<&str>,
    key_chirho: &str,
    value_chirho: &[u8],
) -> Result<SealedStorePutChirho> {
    let sealed_chirho = seal_store_value_chirho(
        root_chirho,
        attribution_chirho,
        app_chirho,
        key_chirho,
        value_chirho,
    )?;
    let envelope_bytes_chirho = encode_sealed_store_value_chirho(&sealed_chirho)?;
    let version_chirho = store_chirho.put_chirho(key_chirho, &envelope_bytes_chirho)?;
    Ok(SealedStorePutChirho {
        version_chirho,
        sealed_chirho,
    })
}

/// Tells a sealed envelope from bytes that were never sealed. Bytes that claim the sealed schema
/// but do not parse as an envelope fail closed rather than passing through as legacy plaintext.
pub fn detect_sealed_store_value_chirho(value_chirho: &[u8]) -> Result<StoreValueViewChirho> {
    let Ok(parsed_chirho) = serde_json::from_slice::<serde_json::Value>(value_chirho) else {
        return Ok(StoreValueViewChirho::NotSealedChirho);
    };
    let claims_sealed_chirho = parsed_chirho
        .get("schema_chirho")
        .and_then(|schema_chirho| schema_chirho.as_str())
        .is_some_and(|schema_chirho| {
            schema_chirho == SEALED_STORE_VALUE_SCHEMA_CHIRHO
                || schema_chirho == LEGACY_UNSALTED_SEALED_STORE_VALUE_SCHEMA_CHIRHO
        });
    if !claims_sealed_chirho {
        return Ok(StoreValueViewChirho::NotSealedChirho);
    }
    let sealed_chirho: SealedStoreValueChirho =
        serde_json::from_value(parsed_chirho).map_err(|_error_chirho| {
            anyhow::anyhow!(
                "store row claims the sealed schema but is not a valid envelope (digest {})",
                correlation_digest_chirho(value_chirho)
            )
        })?;
    Ok(StoreValueViewChirho::SealedChirho(Box::new(sealed_chirho)))
}

fn ensure_sealed_store_value_shape_chirho(sealed_chirho: &SealedStoreValueChirho) -> Result<()> {
    if sealed_chirho.schema_chirho != SEALED_STORE_VALUE_SCHEMA_CHIRHO {
        bail!("sealed store value schema is not '{SEALED_STORE_VALUE_SCHEMA_CHIRHO}'");
    }
    ensure_store_seal_subject_chirho(&sealed_chirho.subject_chirho)?;
    if !is_lower_hex_of_len_chirho(
        &sealed_chirho.keyed_plaintext_digest_chirho,
        KEYED_PLAINTEXT_DIGEST_HEX_LEN_CHIRHO,
    ) {
        bail!(
            "sealed store value keyed plaintext digest must be {KEYED_PLAINTEXT_DIGEST_HEX_LEN_CHIRHO} lowercase hex characters"
        );
    }
    validate_safe_store_metadata_chirho(&sealed_chirho.safe_metadata_chirho)?;
    Ok(())
}

/// Unseals a store envelope back to plaintext after proving the envelope's blob is covered by the
/// signed privacy log, bound to this store subject, and matches the recorded keyed plaintext
/// identity.
///
/// The identity check is what stops a SAME-SUBJECT blob substitution — swapping one version's blob
/// ref into another version's envelope passes subject binding, log coverage, the blob MAC and the
/// AEAD, because every one of those is a property of the substituted blob itself. Keying the digest
/// with the blob's own shred key means the check is available to a legitimate unsealer (who has just
/// loaded that key to decrypt) and to nobody else.
pub fn unseal_store_value_chirho(
    root_chirho: &Path,
    sealed_chirho: &SealedStoreValueChirho,
) -> Result<Vec<u8>> {
    ensure_sealed_store_value_shape_chirho(sealed_chirho)?;
    privacy_chirho::verify_private_blob_ref_subject_chirho(
        root_chirho,
        "sealed store value",
        &sealed_chirho.blob_chirho,
        &sealed_chirho.subject_chirho,
    )?;
    let plaintext_chirho =
        privacy_chirho::load_private_blob_chirho(root_chirho, &sealed_chirho.blob_chirho)?;
    if plaintext_chirho.len() != sealed_chirho.bytes_chirho {
        bail!(
            "sealed store value length mismatch: envelope key id {} says {} bytes, sealed plaintext is {} bytes",
            sealed_chirho.blob_chirho.key_id_chirho,
            sealed_chirho.bytes_chirho,
            plaintext_chirho.len()
        );
    }
    let actual_digest_chirho = privacy_chirho::private_blob_keyed_plaintext_digest_chirho(
        root_chirho,
        &sealed_chirho.blob_chirho,
        &plaintext_chirho,
    )?;
    if actual_digest_chirho != sealed_chirho.keyed_plaintext_digest_chirho {
        bail!(
            "sealed store value keyed digest mismatch: envelope key id {} does not bind the sealed plaintext",
            sealed_chirho.blob_chirho.key_id_chirho
        );
    }
    Ok(plaintext_chirho)
}

/// Test-only reader for rows the sealed write door produced: unseals an envelope, passes a row
/// that was never sealed straight through. Production read-path wiring is brick S3; this exists so
/// arms that assert "the write landed these bytes" keep asserting the PLAINTEXT rather than being
/// weakened to assert the envelope.
#[cfg(test)]
pub(crate) fn test_store_row_plaintext_chirho(
    root_chirho: &Path,
    store_chirho: &versioned_chirho::VersionedStoreChirho,
    key_chirho: &str,
) -> Result<Option<Vec<u8>>> {
    let Some(row_chirho) = store_chirho.get_chirho(key_chirho)? else {
        return Ok(None);
    };
    match detect_sealed_store_value_chirho(&row_chirho)? {
        StoreValueViewChirho::SealedChirho(sealed_chirho) => Ok(Some(unseal_store_value_chirho(
            root_chirho,
            &sealed_chirho,
        )?)),
        StoreValueViewChirho::NotSealedChirho => Ok(Some(row_chirho)),
    }
}

#[cfg(test)]
#[path = "store_seal_chirho/tests_chirho.rs"]
mod tests_chirho;
