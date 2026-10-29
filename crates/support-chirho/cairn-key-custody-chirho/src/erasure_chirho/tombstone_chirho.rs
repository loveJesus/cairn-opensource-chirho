// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A holder's durable erasure tombstones: the key ids and subject bounds it has erased, so a custody frame delayed past an erasure can never bring a key back.
//!
//! A holder records an authorized erasure here and stores the tombstones durably BEFORE it removes any
//! key, so a custody frame racing the removal is refused rather than written after it (agy R-C5-4b). The
//! state grows with erasures, not with data: one bound per erased subject plus each erased key id. A
//! newly seated holder applies every erasure before it accepts any key (B4).

use crate::custody_chirho::binding_chirho::CustodyBindingChirho;
use crate::digest_chirho::{
    valid_lower_hex_chirho, DIGEST_HEX_BYTES_CHIRHO, KEY_ID_HEX_BYTES_CHIRHO,
};
use crate::erasure_chirho::frame_chirho::AuthorizedErasureFrameChirho;
use crate::refusal_chirho::{
    refuse_chirho, KeyCustodyErrorChirho, KeyCustodyRefusalIdentityChirho,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HolderTombstonesChirho {
    erased_key_ids_chirho: BTreeSet<String>,
    /// Subject digest to the highest exclusive blob-seq bound any erasure of that subject carried.
    erased_subject_bounds_chirho: BTreeMap<String, u64>,
}

impl HolderTombstonesChirho {
    pub fn new_chirho() -> Self {
        Self::default()
    }

    /// Fold one authorized erasure in. Store the result durably before removing any key.
    pub fn record_erasure_chirho(&mut self, frame_chirho: &AuthorizedErasureFrameChirho) {
        self.erased_key_ids_chirho
            .extend(frame_chirho.key_ids_chirho().iter().cloned());
        let bound_chirho = self
            .erased_subject_bounds_chirho
            .entry(frame_chirho.subject_digest_chirho().to_string())
            .or_insert(0);
        *bound_chirho = (*bound_chirho).max(frame_chirho.erased_below_blob_seq_chirho());
    }

    /// Fold key ids the holder DISCOVERED under this erasure's subject whose blob seq it cannot know (a
    /// key whose stored binding is missing or unreadable), as erased ids, so a delayed custody frame can
    /// never bring one back. The authorized frame is the witness that such an erasure is in progress.
    /// Store the result durably before removing any of them.
    pub fn record_discovered_key_ids_chirho<'a>(
        &mut self,
        _frame_chirho: &AuthorizedErasureFrameChirho,
        key_ids_chirho: impl IntoIterator<Item = &'a String>,
    ) {
        self.erased_key_ids_chirho
            .extend(key_ids_chirho.into_iter().cloned());
    }

    /// Whether a key under this binding is already erased on this holder.
    pub fn covers_chirho(&self, binding_chirho: &CustodyBindingChirho) -> bool {
        self.erased_key_ids_chirho
            .contains(&binding_chirho.key_id_chirho)
            || self
                .erased_subject_bounds_chirho
                .get(&binding_chirho.subject_digest_chirho)
                .is_some_and(|bound_chirho| binding_chirho.blob_seq_chirho < *bound_chirho)
    }

    /// Refuse a custody binding these tombstones cover.
    pub fn check_custody_binding_chirho(
        &self,
        binding_chirho: &CustodyBindingChirho,
    ) -> Result<(), KeyCustodyErrorChirho> {
        if self.covers_chirho(binding_chirho) {
            return Err(refuse_chirho(
                KeyCustodyRefusalIdentityChirho::CustodySubjectAlreadyErasedChirho,
                "an erasure on this holder already covers this key",
            ));
        }
        Ok(())
    }

    /// Check tombstones read back from durable storage before trusting them.
    pub fn validate_chirho(&self) -> Result<(), KeyCustodyErrorChirho> {
        let keys_in_form_chirho = self
            .erased_key_ids_chirho
            .iter()
            .all(|key_id_chirho| valid_lower_hex_chirho(key_id_chirho, KEY_ID_HEX_BYTES_CHIRHO));
        let subjects_in_form_chirho = self
            .erased_subject_bounds_chirho
            .keys()
            .all(|subject_chirho| valid_lower_hex_chirho(subject_chirho, DIGEST_HEX_BYTES_CHIRHO));
        if !keys_in_form_chirho || !subjects_in_form_chirho {
            return Err(refuse_chirho(
                KeyCustodyRefusalIdentityChirho::ErasureFrameInvalidChirho,
                "stored tombstones are not in form",
            ));
        }
        Ok(())
    }
}
