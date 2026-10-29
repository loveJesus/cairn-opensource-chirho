// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pure folds over app records that a caller has already verified.

use crate::AppRecordChirho;
use std::collections::BTreeMap;

/// Folds already-verified app records into the latest owner per app.
///
/// This helper does not load a root or verify signatures. The root adapter remains responsible for
/// verification before it passes records here.
pub fn verified_app_owner_map_chirho(
    records_chirho: Vec<AppRecordChirho>,
) -> BTreeMap<String, String> {
    let mut owners_chirho = BTreeMap::new();
    for record_chirho in records_chirho {
        owners_chirho.insert(
            record_chirho.app_chirho,
            record_chirho.owner_principal_chirho,
        );
    }
    owners_chirho
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::AppActionChirho;

    fn record_chirho(seq_chirho: u64, app_chirho: &str, owner_chirho: &str) -> AppRecordChirho {
        AppRecordChirho {
            seq_chirho,
            schema_chirho: String::new(),
            app_chirho: app_chirho.to_string(),
            owner_principal_chirho: owner_chirho.to_string(),
            dag_chirho: None,
            action_chirho: AppActionChirho::UndeployChirho,
            at_ms_chirho: 0,
            previous_chirho: None,
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            sig_chirho: String::new(),
        }
    }

    #[test]
    fn verified_app_owner_map_keeps_last_row_per_app_chirho() {
        let owners_chirho = verified_app_owner_map_chirho(vec![
            record_chirho(0, "first-app-chirho", "owner/old-chirho"),
            record_chirho(1, "second-app-chirho", "owner/second-chirho"),
            record_chirho(2, "first-app-chirho", "owner/current-chirho"),
        ]);
        assert_eq!(owners_chirho.len(), 2);
        assert_eq!(
            owners_chirho.get("first-app-chirho").map(String::as_str),
            Some("owner/current-chirho")
        );
        assert_eq!(
            owners_chirho.get("second-app-chirho").map(String::as_str),
            Some("owner/second-chirho")
        );
    }
}
