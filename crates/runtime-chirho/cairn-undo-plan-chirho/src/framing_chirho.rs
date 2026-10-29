// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The one unambiguous framing grammar for every CF5-derived coordinate.

use anyhow::{bail, Context, Result};
use cairn_core_chirho::model_chirho::HashChirho;

const DOOR_FINGERPRINT_DOMAIN_CHIRHO: &[u8] = b"cairn-undo-door-capability-fingerprint-v1-chirho";
const EFFECT_INSTANCE_DOMAIN_CHIRHO: &[u8] = b"cairn-undo-effect-instance-v1-chirho";
const COMPENSATION_STEP_DOMAIN_CHIRHO: &[u8] = b"cairn-undo-step-v1-chirho";

pub fn framed_blake3_hash_chirho(
    domain_chirho: &[u8],
    components_chirho: &[&[u8]],
) -> Result<HashChirho> {
    if domain_chirho.is_empty() {
        bail!("derived-coordinate domain must be nonempty");
    }
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(domain_chirho);
    for component_chirho in components_chirho {
        update_framed_chirho(&mut hasher_chirho, component_chirho)?;
    }
    Ok(HashChirho(hasher_chirho.finalize().to_hex().to_string()))
}

pub fn door_capability_fingerprint_chirho(
    complete_capability_bytes_chirho: &[u8],
    selected_effect_capability_bytes_chirho: &[u8],
) -> Result<HashChirho> {
    framed_blake3_hash_chirho(
        DOOR_FINGERPRINT_DOMAIN_CHIRHO,
        &[
            complete_capability_bytes_chirho,
            selected_effect_capability_bytes_chirho,
        ],
    )
}

pub fn effect_instance_key_chirho(
    run_hash_chirho: &HashChirho,
    effect_seq_chirho: u64,
    idempotency_key_chirho: &HashChirho,
) -> Result<HashChirho> {
    let run_bytes_chirho = hash_bytes_chirho(run_hash_chirho, "run hash")?;
    let idempotency_bytes_chirho = hash_bytes_chirho(idempotency_key_chirho, "idempotency key")?;
    let effect_seq_bytes_chirho = effect_seq_chirho.to_le_bytes();
    framed_blake3_hash_chirho(
        EFFECT_INSTANCE_DOMAIN_CHIRHO,
        &[
            run_bytes_chirho.as_bytes(),
            &effect_seq_bytes_chirho,
            idempotency_bytes_chirho.as_bytes(),
        ],
    )
}

pub fn compensation_step_key_chirho(
    plan_hash_chirho: &HashChirho,
    door_fingerprint_chirho: &HashChirho,
    effect_instance_chirho: &HashChirho,
    step_index_chirho: u32,
) -> Result<HashChirho> {
    let plan_bytes_chirho = hash_bytes_chirho(plan_hash_chirho, "plan hash")?;
    let door_bytes_chirho = hash_bytes_chirho(door_fingerprint_chirho, "door fingerprint")?;
    let effect_instance_bytes_chirho =
        hash_bytes_chirho(effect_instance_chirho, "effect instance")?;
    let step_index_bytes_chirho = step_index_chirho.to_le_bytes();
    framed_blake3_hash_chirho(
        COMPENSATION_STEP_DOMAIN_CHIRHO,
        &[
            plan_bytes_chirho.as_bytes(),
            door_bytes_chirho.as_bytes(),
            effect_instance_bytes_chirho.as_bytes(),
            &step_index_bytes_chirho,
        ],
    )
}

pub(crate) fn update_framed_chirho(
    hasher_chirho: &mut blake3::Hasher,
    value_chirho: &[u8],
) -> Result<()> {
    let len_chirho = u64::try_from(value_chirho.len())
        .context("derived-coordinate component length exceeds u64")?;
    hasher_chirho.update(&len_chirho.to_le_bytes());
    hasher_chirho.update(value_chirho);
    Ok(())
}

pub(crate) fn validate_hash_chirho(hash_chirho: &HashChirho, label_chirho: &str) -> Result<()> {
    let _digest_chirho = hash_bytes_chirho(hash_chirho, label_chirho)?;
    Ok(())
}

fn hash_bytes_chirho(hash_chirho: &HashChirho, label_chirho: &str) -> Result<blake3::Hash> {
    if hash_chirho.0.len() != 64
        || !hash_chirho
            .0
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit() && !byte_chirho.is_ascii_uppercase())
    {
        bail!("{label_chirho} must be a lower-case 64-hex BLAKE3 digest");
    }
    blake3::Hash::from_hex(&hash_chirho.0)
        .with_context(|| format!("decode {label_chirho} BLAKE3 digest"))
}
