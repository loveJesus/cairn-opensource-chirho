// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::contract_chirho::Gd7PlanRefusalChirho;
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};

const GD7_RECONCILIATION_NAMESPACE_CHIRHO: &str = "gd7-reconciliation-chirho";

pub fn gd7_reconciliation_plan_page_path_chirho(
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7PlanRefusalChirho> {
    content_addressed_path_chirho("plan-pages-chirho", object_digest_chirho)
}

pub(crate) fn content_addressed_path_chirho(
    family_chirho: &str,
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7PlanRefusalChirho> {
    if !super::super::contract_chirho::is_lower_hex_digest_chirho(object_digest_chirho) {
        return Err(Gd7PlanRefusalChirho::InvalidReferenceChirho);
    }
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/{family_chirho}/{}/{}/{object_digest_chirho}.json",
        &object_digest_chirho[..2],
        &object_digest_chirho[2..4],
    )))
}

pub(crate) fn digest_bytes_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}

pub(crate) fn persist_immutable_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    bytes_chirho: &[u8],
    maximum_chirho: usize,
) -> Result<(), Gd7PlanRefusalChirho> {
    match storage_chirho
        .create_durable_chirho(path_chirho, bytes_chirho)
        .map_err(|_| Gd7PlanRefusalChirho::StorageChirho)?
    {
        CreateDurableOutcomeChirho::CreatedChirho => Ok(()),
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_chirho =
                read_bounded_required_chirho(storage_chirho, path_chirho, maximum_chirho)?;
            if existing_chirho == bytes_chirho {
                Ok(())
            } else {
                Err(Gd7PlanRefusalChirho::ImmutableCollisionChirho)
            }
        }
    }
}

pub(crate) fn read_bounded_optional_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    maximum_chirho: usize,
) -> Result<Option<Vec<u8>>, Gd7PlanRefusalChirho> {
    let Some(length_chirho) = storage_chirho
        .object_len_chirho(path_chirho)
        .map_err(|_| Gd7PlanRefusalChirho::StorageChirho)?
    else {
        return Ok(None);
    };
    if length_chirho > maximum_chirho as u64 {
        return Err(Gd7PlanRefusalChirho::OversizedPlanPageChirho);
    }
    let bytes_chirho = storage_chirho
        .read_exact_range_chirho(path_chirho, 0, length_chirho)
        .map_err(|_| Gd7PlanRefusalChirho::StorageChirho)?;
    if bytes_chirho.len() != length_chirho as usize {
        return Err(Gd7PlanRefusalChirho::StorageChirho);
    }
    Ok(Some(bytes_chirho))
}

pub(crate) fn read_bounded_required_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    maximum_chirho: usize,
) -> Result<Vec<u8>, Gd7PlanRefusalChirho> {
    read_bounded_optional_chirho(storage_chirho, path_chirho, maximum_chirho)?
        .ok_or(Gd7PlanRefusalChirho::MissingObjectChirho)
}
