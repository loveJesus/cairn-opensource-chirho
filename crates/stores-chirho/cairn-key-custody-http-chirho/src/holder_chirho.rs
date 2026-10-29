// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A key-custody holder's two admissions, in the reviewed order: authenticate, authorize, hold the group's term high-water, make the state durable, and only then sign.
//!
//! The order is the one agreed in review (#29219, agy #29230). Authorization runs before the
//! high-water moves, so a frame that authenticates but is not from the current leader cannot raise it
//! and block legitimate frames. The high-water is durable before any side effect, so a crash cannot let
//! a lower term in afterwards. One lock serializes every admission on this holder, so an erasure and a
//! custody frame for the same subject never interleave.

use crate::refusal_chirho::{HolderRefusalChirho, HolderRefusalIdentityChirho};
use crate::store_chirho::HolderStoreChirho;
use cairn_key_custody_chirho::{
    authorize_custody_frame_chirho, authorize_erasure_frame_chirho,
    decode_and_authenticate_custody_frame_chirho, decode_and_authenticate_erasure_frame_chirho,
    CustodyAnnouncementV1Chirho, KeyCustodyErrorChirho, NodeCustodySecretChirho,
    PreparedCustodyAnnouncementChirho, PreparedCustodyReceiptChirho, PreparedErasureReceiptChirho,
    CUSTODY_KEY_DERIVATION_CONTEXT_CHIRHO, ERASURE_MAX_KEY_IDS_CHIRHO,
};
use cairn_mirror_chirho::{
    join_mirror_view_chirho, JoinedMirrorViewChirho, MirrorLeadershipViewChirho,
};
use cairn_signer_chirho::signer_chirho::{
    derive_existing_instance_key_chirho, existing_keypair_pubkey_hex_chirho,
    sign_with_existing_key_possession_chirho,
};
use cairn_tenant_placement_authority_chirho::VerifiedTenantPlacementChirho;
use cairn_writer_elector_chirho::monotonic_clock_chirho::MonotonicClockChirho;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

/// Everything a holder needs, all from its own node and never from a frame.
pub struct KeyCustodyHolderConfigChirho {
    /// The holder's private state directory. Its parent must exist.
    pub holder_dir_chirho: PathBuf,
    /// The node's sign root. Its existing key must be `local_node_id_chirho`; none is ever minted here.
    pub sign_root_chirho: PathBuf,
    pub local_node_id_chirho: String,
    pub placement_chirho: Arc<VerifiedTenantPlacementChirho>,
    pub election_view_chirho: Arc<dyn MirrorLeadershipViewChirho>,
    pub clock_chirho: Arc<dyn MonotonicClockChirho>,
    pub transit_budget_millis_chirho: NonZeroU64,
}

pub struct KeyCustodyHolderChirho {
    store_chirho: Mutex<HolderStoreChirho>,
    sign_root_chirho: PathBuf,
    local_node_id_chirho: String,
    custody_secret_chirho: NodeCustodySecretChirho,
    placement_chirho: Arc<VerifiedTenantPlacementChirho>,
    election_view_chirho: Arc<dyn MirrorLeadershipViewChirho>,
    clock_chirho: Arc<dyn MonotonicClockChirho>,
    transit_budget_millis_chirho: NonZeroU64,
}

impl KeyCustodyHolderChirho {
    /// Open the holder. The sign root's existing key must be this node's key, and the custody secret
    /// is derived from it inside the signer, so the node key never leaves it.
    pub fn open_chirho(
        config_chirho: KeyCustodyHolderConfigChirho,
    ) -> Result<Self, HolderRefusalChirho> {
        match existing_keypair_pubkey_hex_chirho(&config_chirho.sign_root_chirho) {
            Ok(public_chirho) if public_chirho == config_chirho.local_node_id_chirho => {}
            _ => return Err(signer_unavailable_chirho()),
        }
        let derived_chirho = derive_existing_instance_key_chirho(
            &config_chirho.sign_root_chirho,
            CUSTODY_KEY_DERIVATION_CONTEXT_CHIRHO,
        )
        .map_err(|_| signer_unavailable_chirho())?;
        let store_chirho = HolderStoreChirho::open_chirho(&config_chirho.holder_dir_chirho)?;
        Ok(Self {
            store_chirho: Mutex::new(store_chirho),
            sign_root_chirho: config_chirho.sign_root_chirho,
            local_node_id_chirho: config_chirho.local_node_id_chirho,
            custody_secret_chirho: NodeCustodySecretChirho::from_derived_secret_chirho(
                derived_chirho,
            ),
            placement_chirho: config_chirho.placement_chirho,
            election_view_chirho: config_chirho.election_view_chirho,
            clock_chirho: config_chirho.clock_chirho,
            transit_budget_millis_chirho: config_chirho.transit_budget_millis_chirho,
        })
    }

    /// This holder's signed custody announcement, which a leader seals keys to.
    pub fn announcement_chirho(&self) -> Result<CustodyAnnouncementV1Chirho, HolderRefusalChirho> {
        let prepared_chirho = PreparedCustodyAnnouncementChirho::new_chirho(
            &self.local_node_id_chirho,
            &self.custody_secret_chirho,
        )?;
        let signature_chirho = self.sign_digest_chirho(&prepared_chirho.signing_digest_chirho())?;
        Ok(prepared_chirho.into_signed_chirho(signature_chirho)?)
    }

    /// Admit one custody frame and answer with the signed receipt's wire bytes.
    pub fn admit_custody_chirho(&self, wire_chirho: &[u8]) -> Result<Vec<u8>, HolderRefusalChirho> {
        let authenticated_chirho = decode_and_authenticate_custody_frame_chirho(wire_chirho)?;
        let store_chirho = self.lock_store_chirho()?;
        let tombstones_chirho = store_chirho.subject_tombstones_chirho(
            &authenticated_chirho.binding_chirho().subject_digest_chirho,
        )?;
        let authorized_chirho = authorize_custody_frame_chirho(
            authenticated_chirho,
            &self.joined_view_chirho()?,
            &self.local_node_id_chirho,
            &tombstones_chirho,
            self.clock_chirho.as_ref(),
            self.transit_budget_millis_chirho,
        )?;
        let binding_chirho = authorized_chirho.binding_chirho();
        hold_term_high_water_chirho(
            &store_chirho,
            &binding_chirho.consistency_group_digest_chirho,
            binding_chirho.elected_term_chirho,
        )?;
        let opened_chirho = authorized_chirho.open_chirho(&self.custody_secret_chirho)?;
        store_chirho.store_custody_key_chirho(&opened_chirho)?;
        let prepared_chirho =
            PreparedCustodyReceiptChirho::for_durably_stored_key_chirho(&opened_chirho);
        let signature_chirho = self.sign_digest_chirho(&prepared_chirho.signing_digest_chirho())?;
        Ok(prepared_chirho
            .into_signed_chirho(signature_chirho)?
            .to_wire_bytes_chirho()?)
    }

    /// Admit one erasure frame and answer with the signed receipt's wire bytes.
    ///
    /// After the high-water, the frame's tombstones are made durable FIRST, before the subject is
    /// scanned, so no key the frame covers can be admitted afterwards, even across a crash. Then what
    /// the erasure removes is fixed once in a durable record (agy B2-A), any key whose binding cannot be
    /// read is tombstoned by id (agy B2-B), and only then is anything unlinked. A retry of the same
    /// frame reads the record instead of scanning again, so it reports the same keys.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/key-custody-chirho/erasure-propagation-workflow-chirho.md`.
    pub fn admit_erasure_chirho(&self, wire_chirho: &[u8]) -> Result<Vec<u8>, HolderRefusalChirho> {
        let authenticated_chirho = decode_and_authenticate_erasure_frame_chirho(wire_chirho)?;
        let store_chirho = self.lock_store_chirho()?;
        let authorized_chirho = authorize_erasure_frame_chirho(
            authenticated_chirho,
            &self.joined_view_chirho()?,
            &self.local_node_id_chirho,
            self.clock_chirho.as_ref(),
            self.transit_budget_millis_chirho,
        )?;
        hold_term_high_water_chirho(
            &store_chirho,
            authorized_chirho.consistency_group_digest_chirho(),
            authorized_chirho.elected_term_chirho(),
        )?;
        let subject_chirho = authorized_chirho.subject_digest_chirho();
        let stored_tombstones_chirho = store_chirho.subject_tombstones_chirho(subject_chirho)?;
        let mut tombstones_chirho = stored_tombstones_chirho.clone();
        tombstones_chirho.record_erasure_chirho(&authorized_chirho);
        if tombstones_chirho != stored_tombstones_chirho {
            store_chirho.store_subject_tombstones_chirho(subject_chirho, &tombstones_chirho)?;
        } else {
            // Already folded by an earlier attempt that may have crashed before its directory sync.
            store_chirho.sync_tombstone_dir_chirho(subject_chirho)?;
        }
        let record_chirho = match store_chirho.erasure_record_chirho(&authorized_chirho)? {
            Some(record_chirho) => {
                store_chirho
                    .sync_erasure_record_dir_chirho(authorized_chirho.frame_digest_chirho())?;
                record_chirho
            }
            None => {
                let record_chirho = store_chirho.classify_erasure_chirho(&authorized_chirho)?;
                store_chirho.store_erasure_record_chirho(&record_chirho)?;
                record_chirho
            }
        };
        let mut with_discovered_chirho = tombstones_chirho.clone();
        with_discovered_chirho.record_discovered_key_ids_chirho(
            &authorized_chirho,
            &record_chirho.unverifiable_key_ids_chirho,
        );
        if with_discovered_chirho != tombstones_chirho {
            store_chirho
                .store_subject_tombstones_chirho(subject_chirho, &with_discovered_chirho)?;
        }
        store_chirho.remove_erased_keys_chirho(&record_chirho)?;
        if !record_chirho.unverifiable_key_ids_chirho.is_empty() {
            return Err(HolderRefusalIdentityChirho::HolderErasureBindingUnverifiableChirho.into());
        }
        // The contract caps each receipt list. Subject-rule finds beyond the cap are removed but not
        // reported, so they stay pending until a later frame lists them as already absent.
        let removed_by_subject_chirho = record_chirho
            .removed_by_subject_key_ids_chirho
            .iter()
            .take(ERASURE_MAX_KEY_IDS_CHIRHO)
            .cloned()
            .collect();
        let prepared_chirho = PreparedErasureReceiptChirho::after_durable_erasure_chirho(
            &authorized_chirho,
            record_chirho.removed_key_ids_chirho.clone(),
            record_chirho.already_absent_key_ids_chirho.clone(),
            removed_by_subject_chirho,
        )?;
        let signature_chirho = self.sign_digest_chirho(&prepared_chirho.signing_digest_chirho())?;
        Ok(prepared_chirho
            .into_signed_chirho(signature_chirho)?
            .to_wire_bytes_chirho()?)
    }

    /// Test-only: how many directories this holder remembers as synced.
    #[cfg(test)]
    pub(crate) fn remembered_directory_count_chirho(&self) -> usize {
        self.store_chirho
            .lock()
            .map(|store_chirho| store_chirho.remembered_directory_count_chirho())
            .unwrap_or(0)
    }

    /// A poisoned lock means an admission panicked mid-way, so every later one refuses until restart.
    fn lock_store_chirho(&self) -> Result<MutexGuard<'_, HolderStoreChirho>, HolderRefusalChirho> {
        self.store_chirho
            .lock()
            .map_err(|_| HolderRefusalIdentityChirho::HolderStoreUnreadableChirho.into())
    }

    /// The mirror's own two-authority join over this holder's placement and election view.
    fn joined_view_chirho(&self) -> Result<JoinedMirrorViewChirho, HolderRefusalChirho> {
        join_mirror_view_chirho(&self.placement_chirho, self.election_view_chirho.as_ref()).map_err(
            |error_chirho| KeyCustodyErrorChirho::from_mirror_authority_chirho(error_chirho).into(),
        )
    }

    /// Sign with the node's existing key, re-checking at signing time that it is still this node's.
    fn sign_digest_chirho(&self, digest_chirho: &[u8; 32]) -> Result<String, HolderRefusalChirho> {
        let possession_chirho =
            sign_with_existing_key_possession_chirho(&self.sign_root_chirho, digest_chirho)
                .map_err(|_| signer_unavailable_chirho())?;
        if possession_chirho.key_id_chirho() != self.local_node_id_chirho {
            return Err(signer_unavailable_chirho());
        }
        Ok(possession_chirho.into_signature_hex_chirho())
    }
}

/// Refuse a term below the group's high-water, and durably raise the high-water to a higher one before
/// any side effect.
fn hold_term_high_water_chirho(
    store_chirho: &HolderStoreChirho,
    group_digest_chirho: &str,
    term_chirho: u64,
) -> Result<(), HolderRefusalChirho> {
    let high_water_chirho = store_chirho.term_high_water_chirho(group_digest_chirho)?;
    if term_chirho < high_water_chirho {
        return Err(HolderRefusalIdentityChirho::HolderStaleTermChirho.into());
    }
    if term_chirho > high_water_chirho {
        store_chirho.raise_term_high_water_chirho(group_digest_chirho, term_chirho)
    } else {
        // Equal: an earlier crashed attempt may have raised it without the directory sync.
        store_chirho.sync_term_dir_chirho(group_digest_chirho)
    }
}

fn signer_unavailable_chirho() -> HolderRefusalChirho {
    HolderRefusalIdentityChirho::HolderSignerUnavailableChirho.into()
}
