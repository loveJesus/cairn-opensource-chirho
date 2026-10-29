// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::contract_chirho::Gd7ReadOnlyBranchRefusalChirho;
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use serde::{de::DeserializeOwned, Serialize};

const GD7_RECONCILIATION_NAMESPACE_CHIRHO: &str = "gd7-reconciliation-chirho";

pub(super) fn canonical_json_chirho(
    value_chirho: &impl Serialize,
) -> Result<Vec<u8>, Gd7ReadOnlyBranchRefusalChirho> {
    serde_json::to_vec(value_chirho)
        .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::SerializationChirho)
}

pub(super) fn parse_canonical_chirho<ValueChirho: DeserializeOwned + Serialize>(
    bytes_chirho: &[u8],
) -> Result<ValueChirho, Gd7ReadOnlyBranchRefusalChirho> {
    let value_chirho: ValueChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::MalformedObjectChirho)?;
    if canonical_json_chirho(&value_chirho)? != bytes_chirho {
        return Err(Gd7ReadOnlyBranchRefusalChirho::NonCanonicalObjectChirho);
    }
    Ok(value_chirho)
}

pub(super) fn digest_bytes_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}

pub(super) fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

pub(super) fn digest_path_chirho(
    family_chirho: &str,
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7ReadOnlyBranchRefusalChirho> {
    if !is_lower_hex_digest_chirho(object_digest_chirho) {
        return Err(Gd7ReadOnlyBranchRefusalChirho::InvalidIdentityChirho);
    }
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/{family_chirho}/{}/{}/{object_digest_chirho}.json",
        &object_digest_chirho[..2],
        &object_digest_chirho[2..4],
    )))
}

pub(super) fn create_exact_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    bytes_chirho: &[u8],
    maximum_chirho: usize,
) -> Result<(), Gd7ReadOnlyBranchRefusalChirho> {
    match storage_chirho
        .create_durable_chirho(path_chirho, bytes_chirho)
        .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::StorageChirho)?
    {
        CreateDurableOutcomeChirho::CreatedChirho => Ok(()),
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_chirho = read_bounded_chirho(storage_chirho, path_chirho, maximum_chirho)?
                .ok_or(Gd7ReadOnlyBranchRefusalChirho::ImmutableCollisionChirho)?;
            if existing_chirho == bytes_chirho {
                Ok(())
            } else {
                Err(Gd7ReadOnlyBranchRefusalChirho::ImmutableCollisionChirho)
            }
        }
    }
}

pub(super) fn read_bounded_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    maximum_chirho: usize,
) -> Result<Option<Vec<u8>>, Gd7ReadOnlyBranchRefusalChirho> {
    let Some(len_chirho) = storage_chirho
        .object_len_chirho(path_chirho)
        .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::StorageChirho)?
    else {
        return Ok(None);
    };
    if len_chirho > maximum_chirho as u64 {
        return Err(Gd7ReadOnlyBranchRefusalChirho::OversizedObjectChirho);
    }
    let bytes_chirho = if len_chirho == 0 {
        Vec::new()
    } else {
        storage_chirho
            .read_exact_range_chirho(path_chirho, 0, len_chirho)
            .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::StorageChirho)?
    };
    if bytes_chirho.len() != len_chirho as usize
        || storage_chirho
            .object_len_chirho(path_chirho)
            .map_err(|_| Gd7ReadOnlyBranchRefusalChirho::StorageChirho)?
            != Some(len_chirho)
    {
        return Err(Gd7ReadOnlyBranchRefusalChirho::StorageChirho);
    }
    Ok(Some(bytes_chirho))
}
