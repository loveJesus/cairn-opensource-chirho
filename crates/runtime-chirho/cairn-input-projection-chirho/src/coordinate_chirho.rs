// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Public and subject-keyed cache coordinates over exact projected bytes.

use anyhow::{bail, Context, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use serde::{Deserialize, Serialize};

const PRIVATE_COORDINATE_DOMAIN_CHIRHO: &[u8] =
    b"cairn-input-projection-private-coordinate-v1-chirho";
pub const MAX_COORDINATE_LABEL_BYTES_CHIRHO: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum ProjectedInputCoordinateChirho {
    #[serde(rename = "public-hash-chirho")]
    PublicHashChirho { hash_chirho: HashChirho },
    #[serde(rename = "private-keyed-digest-chirho")]
    PrivateKeyedDigestChirho {
        key_generation_chirho: String,
        digest_chirho: String,
    },
}

/// Subject-held key material used only inside the coordinate boundary.
///
/// It intentionally implements neither `Debug`, `Clone`, `Serialize`, nor `Deserialize`.
pub struct PrivateInputKeyChirho([u8; 32]);

impl PrivateInputKeyChirho {
    pub fn try_from_bytes_chirho(bytes_chirho: [u8; 32]) -> Result<Self> {
        if bytes_chirho.iter().all(|byte_chirho| *byte_chirho == 0) {
            bail!("private input key must not be the all-zero sentinel");
        }
        Ok(Self(bytes_chirho))
    }

    fn as_bytes_chirho(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for PrivateInputKeyChirho {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub fn public_projected_coordinate_chirho(
    projected_bytes_chirho: &[u8],
) -> ProjectedInputCoordinateChirho {
    ProjectedInputCoordinateChirho::PublicHashChirho {
        hash_chirho: HashChirho(blake3::hash(projected_bytes_chirho).to_hex().to_string()),
    }
}

pub fn validate_projected_input_coordinate_chirho(
    coordinate_chirho: &ProjectedInputCoordinateChirho,
) -> Result<()> {
    match coordinate_chirho {
        ProjectedInputCoordinateChirho::PublicHashChirho { hash_chirho } => {
            validate_lower_hex_hash_chirho(hash_chirho, "public projection hash")
        }
        ProjectedInputCoordinateChirho::PrivateKeyedDigestChirho {
            key_generation_chirho,
            digest_chirho,
        } => {
            validate_label_chirho(key_generation_chirho, "private key generation")?;
            validate_lower_hex_text_chirho(digest_chirho, "private projection digest")
        }
    }
}

pub fn parse_canonical_projected_input_coordinate_chirho(
    text_chirho: &str,
) -> Result<ProjectedInputCoordinateChirho> {
    let coordinate_chirho: ProjectedInputCoordinateChirho =
        serde_json::from_str(text_chirho).context("decode projected input coordinate")?;
    validate_projected_input_coordinate_chirho(&coordinate_chirho)?;
    if serde_json::to_string(&coordinate_chirho)? != text_chirho {
        bail!("projected input coordinate has a byte-canonical mismatch");
    }
    Ok(coordinate_chirho)
}

pub fn private_projected_coordinate_chirho(
    node_chirho: &HashChirho,
    port_chirho: &str,
    projection_contract_digest_chirho: &HashChirho,
    key_generation_chirho: &str,
    key_chirho: &PrivateInputKeyChirho,
    projected_bytes_chirho: &[u8],
) -> Result<ProjectedInputCoordinateChirho> {
    validate_lower_hex_hash_chirho(node_chirho, "node")?;
    validate_lower_hex_hash_chirho(projection_contract_digest_chirho, "projection contract")?;
    validate_label_chirho(port_chirho, "input port")?;
    validate_label_chirho(key_generation_chirho, "private key generation")?;

    let mut hasher_chirho = blake3::Hasher::new_keyed(key_chirho.as_bytes_chirho());
    update_framed_chirho(&mut hasher_chirho, PRIVATE_COORDINATE_DOMAIN_CHIRHO);
    update_framed_chirho(&mut hasher_chirho, node_chirho.0.as_bytes());
    update_framed_chirho(&mut hasher_chirho, port_chirho.as_bytes());
    update_framed_chirho(
        &mut hasher_chirho,
        projection_contract_digest_chirho.0.as_bytes(),
    );
    update_framed_chirho(&mut hasher_chirho, key_generation_chirho.as_bytes());
    update_framed_chirho(&mut hasher_chirho, projected_bytes_chirho);

    Ok(ProjectedInputCoordinateChirho::PrivateKeyedDigestChirho {
        key_generation_chirho: key_generation_chirho.to_string(),
        digest_chirho: hasher_chirho.finalize().to_hex().to_string(),
    })
}

fn update_framed_chirho(hasher_chirho: &mut blake3::Hasher, value_chirho: &[u8]) {
    hasher_chirho.update(&(value_chirho.len() as u64).to_le_bytes());
    hasher_chirho.update(value_chirho);
}

fn validate_lower_hex_hash_chirho(hash_chirho: &HashChirho, label_chirho: &str) -> Result<()> {
    validate_lower_hex_text_chirho(&hash_chirho.0, label_chirho)
}

fn validate_lower_hex_text_chirho(value_chirho: &str, label_chirho: &str) -> Result<()> {
    if value_chirho.len() != 64
        || !value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit() && !byte_chirho.is_ascii_uppercase())
    {
        bail!("{label_chirho} must be a lower-case 64-hex BLAKE3 digest");
    }
    Ok(())
}

fn validate_label_chirho(value_chirho: &str, label_chirho: &str) -> Result<()> {
    if value_chirho.is_empty() || value_chirho.len() > MAX_COORDINATE_LABEL_BYTES_CHIRHO {
        bail!("{label_chirho} must be nonempty and bounded");
    }
    if !value_chirho.bytes().all(|byte_chirho| {
        byte_chirho.is_ascii_alphanumeric() || matches!(byte_chirho, b'.' | b'_' | b'-')
    }) {
        bail!("{label_chirho} contains a non-canonical character");
    }
    Ok(())
}
