// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A bound requirement's holder receipts, each verified and kept where it belongs, and a subject's erasure status computed over them.
//!
//! C5 B3-a3 (item 14 D5 and D6; gpt #30156, agy #30163). A receipt sits at
//! `<seq>.receipts/<holder>/<frame digest>.json` beside its requirement. It is recorded only for a BOUND
//! requirement, only when it names that requirement's group and subject and one of its holders, and only when
//! it closes that holder's share by itself, judged by B1's own status predicate, so a hostile holder cannot
//! spend the slots. It is created new and durable. An equal replay passes its barrier even at the cap, and a
//! different receipt at the same path refuses. Every read verifies every receipt the same way and binds it to
//! its place. A read proves the holder's signed receipt, the requirement's context and the path; it does not
//! re-authenticate the frame that was sent, which is not stored.

use super::{
    unreadable_chirho, write_failed_chirho, ErasurePropagationStoreChirho, LoadedSubjectChirho,
    RequirementStandingChirho, DIGEST_HEX_LEN_CHIRHO, RECEIPTS_SUFFIX_CHIRHO,
};
use crate::barrier_chirho::sync_dir_chirho;
use crate::leader_chirho::refusal_chirho::{LeaderRefusalChirho, LeaderRefusalIdentityChirho};
use crate::private_tree_chirho::{
    durable_temp_final_name_chirho, hex_chirho, read_stored_chirho, StoredChirho,
    PRIVATE_FILE_MODE_CHIRHO,
};
use cairn_durable_chirho::{
    create_complete_file_durable_with_mode_chirho, CreateFileDurableOutcomeChirho,
};
use cairn_key_custody_chirho::{
    decode_and_verify_erasure_receipt_chirho, erasure_status_chirho, ErasureRequirementChirho,
    ErasureStatusChirho, VerifiedErasurePropagationRequirementChirho, VerifiedErasureReceiptChirho,
    ERASURE_PROPAGATION_MAX_HOLDERS_CHIRHO, ERASURE_WIRE_MAX_BYTES_CHIRHO,
};
use cairn_mirror_chirho::MirrorMembershipViewChirho;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// The most receipts one requirement keeps for one holder.
pub const ERASURE_RECEIPTS_MAX_PER_HOLDER_CHIRHO: usize = 64;
const RECEIPT_FILE_SUFFIX_CHIRHO: &str = ".json";
const RECEIPT_MAX_BYTES_CHIRHO: u64 = ERASURE_WIRE_MAX_BYTES_CHIRHO as u64;
/// The most entries one scan of a holder's receipt directory reads: its receipts, and a stranded temp of each.
const HOLDER_SCAN_MAX_ENTRIES_CHIRHO: usize = 2 * ERASURE_RECEIPTS_MAX_PER_HOLDER_CHIRHO;

/// How a receipt was recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErasureReceiptRecordedChirho {
    /// Newly created, and durable before this returned.
    CreatedChirho,
    /// The same receipt was already stored there; its barrier passed again.
    ReplayedChirho,
}

/// How one requirement stands in its subject's erasure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequirementErasureChirho {
    /// Bound, with B1's status over its stored receipts under the caller's current view.
    BoundChirho { status_chirho: ErasureStatusChirho },
    /// Unbound and carried by the bound requirement at this seq, so discharged exactly when that one is.
    CarriedByChirho {
        bound_seq_chirho: u64,
        discharged_chirho: bool,
    },
    /// Unbound and carried by nothing bound: not yet reconciled, and it blocks the subject.
    PendingChirho,
}

impl RequirementErasureChirho {
    pub fn is_discharged_chirho(&self) -> bool {
        match self {
            Self::BoundChirho { status_chirho } => status_chirho.is_complete_chirho(),
            Self::CarriedByChirho {
                discharged_chirho, ..
            } => *discharged_chirho,
            Self::PendingChirho => false,
        }
    }
}

/// A subject's erasure status: every requirement in its directory, by ascending seq. It is complete only when
/// the directory holds at least one requirement and every one is discharged (item 9's conjunction).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectErasureStatusChirho {
    entries_chirho: Vec<(u64, RequirementErasureChirho)>,
}

impl SubjectErasureStatusChirho {
    pub fn entries_chirho(&self) -> &[(u64, RequirementErasureChirho)] {
        &self.entries_chirho
    }

    pub fn is_complete_chirho(&self) -> bool {
        !self.entries_chirho.is_empty()
            && self
                .entries_chirho
                .iter()
                .all(|(_, erasure_chirho)| erasure_chirho.is_discharged_chirho())
    }
}

impl ErasurePropagationStoreChirho {
    /// Record one holder's receipt for the BOUND requirement at (subject, seq). It must verify, name the
    /// requirement's group and subject and one of its holders, and close that holder's share by itself. An
    /// equal replay passes its barrier, even at the cap; a different receipt at the same path refuses, and so
    /// does a new one past the cap. Nothing already stored is ever changed or removed.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/key-custody-chirho/erasure-propagation-workflow-chirho.md`.
    pub fn record_erasure_receipt_chirho(
        &self,
        subject_digest_chirho: &str,
        erasure_seq_chirho: u64,
        receipt_chirho: &VerifiedErasureReceiptChirho,
    ) -> Result<ErasureReceiptRecordedChirho, LeaderRefusalChirho> {
        self.with_store_lock_chirho(|| {
            let loaded_chirho = self.load_subject_chirho(subject_digest_chirho)?;
            let requirement_chirho = bound_requirement_chirho(&loaded_chirho, erasure_seq_chirho)?;
            let status_requirement_chirho = requirement_chirho.status_requirement_chirho()?;
            if receipt_chirho.consistency_group_digest_chirho()
                != self.context_chirho.consistency_group_digest_chirho()
                || receipt_chirho.subject_digest_chirho() != subject_digest_chirho
                || !requirement_chirho
                    .holders_chirho()
                    .iter()
                    .any(|holder_chirho| holder_chirho == receipt_chirho.holder_node_id_chirho())
            {
                return Err(
                    LeaderRefusalIdentityChirho::ErasureReceiptNotForRequirementChirho.into(),
                );
            }
            if !status_requirement_chirho.closes_share_alone_chirho(receipt_chirho) {
                return Err(LeaderRefusalIdentityChirho::ErasureReceiptDoesNotCloseChirho.into());
            }
            let stored_chirho = self.read_requirement_receipts_locked_chirho(
                &loaded_chirho,
                erasure_seq_chirho,
                requirement_chirho,
                &status_requirement_chirho,
            )?;
            let holder_dir_chirho = self.holder_receipts_dir_chirho(
                subject_digest_chirho,
                erasure_seq_chirho,
                receipt_chirho.holder_node_id_chirho(),
            )?;
            let mine_chirho = stored_chirho
                .get(receipt_chirho.holder_node_id_chirho())
                .map(Vec::as_slice)
                .unwrap_or_default();
            if let Some(existing_chirho) = mine_chirho.iter().find(|existing_chirho| {
                existing_chirho.erasure_frame_digest_chirho()
                    == receipt_chirho.erasure_frame_digest_chirho()
            }) {
                if existing_chirho != receipt_chirho {
                    return Err(LeaderRefusalIdentityChirho::ErasureReceiptConflictChirho.into());
                }
                // An earlier attempt may have left the file visible and not yet durable.
                self.receipt_barrier_chirho(&holder_dir_chirho)?;
                return Ok(ErasureReceiptRecordedChirho::ReplayedChirho);
            }
            if mine_chirho.len() >= ERASURE_RECEIPTS_MAX_PER_HOLDER_CHIRHO {
                return Err(LeaderRefusalIdentityChirho::ErasureReceiptHolderFullChirho.into());
            }
            let bytes_chirho = receipt_chirho.record_chirho().to_wire_bytes_chirho()?;
            self.tree_chirho
                .ensure_private_dir_chirho(&holder_dir_chirho)
                .map_err(|_| write_failed_chirho())?;
            let path_chirho = holder_dir_chirho.join(format!(
                "{}{RECEIPT_FILE_SUFFIX_CHIRHO}",
                receipt_chirho.erasure_frame_digest_chirho()
            ));
            match create_complete_file_durable_with_mode_chirho(
                &path_chirho,
                &bytes_chirho,
                PRIVATE_FILE_MODE_CHIRHO,
            )
            .map_err(|_| write_failed_chirho())?
            {
                CreateFileDurableOutcomeChirho::CreatedChirho => {
                    Ok(ErasureReceiptRecordedChirho::CreatedChirho)
                }
                // Under the store's lock the read saw no file here, so finding one now is state this store did
                // not write.
                CreateFileDurableOutcomeChirho::AlreadyExistsChirho => Err(unreadable_chirho()),
            }
        })
    }

    /// B1's status for the BOUND requirement at (subject, seq), over its stored receipts, under the caller's
    /// current view. A holder whose stored receipts close its share needs no frame.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/key-custody-chirho/erasure-propagation-workflow-chirho.md`.
    pub fn requirement_erasure_status_chirho(
        &self,
        subject_digest_chirho: &str,
        erasure_seq_chirho: u64,
        current_view_chirho: &MirrorMembershipViewChirho,
    ) -> Result<ErasureStatusChirho, LeaderRefusalChirho> {
        self.with_store_lock_chirho(|| {
            let loaded_chirho = self.load_subject_chirho(subject_digest_chirho)?;
            let requirement_chirho = bound_requirement_chirho(&loaded_chirho, erasure_seq_chirho)?;
            self.bound_status_locked_chirho(
                &loaded_chirho,
                erasure_seq_chirho,
                requirement_chirho,
                current_view_chirho,
            )
        })
    }

    /// The subject's erasure status under the caller's current view: each bound requirement by B1's status over
    /// its stored receipts, each carried one with its bound carrier, and each other unbound one pending.
    /// Attestations are not read here; B3-c stores them.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/key-custody-chirho/erasure-propagation-workflow-chirho.md`.
    pub fn subject_erasure_status_chirho(
        &self,
        subject_digest_chirho: &str,
        current_view_chirho: &MirrorMembershipViewChirho,
    ) -> Result<SubjectErasureStatusChirho, LeaderRefusalChirho> {
        self.with_store_lock_chirho(|| {
            let loaded_chirho = self.load_subject_chirho(subject_digest_chirho)?;
            let view_chirho = loaded_chirho.view_chirho();
            let mut bound_statuses_chirho = BTreeMap::new();
            for (requirement_chirho, standing_chirho) in view_chirho.entries_chirho() {
                if let RequirementStandingChirho::BoundChirho(_) = standing_chirho {
                    let seq_chirho = requirement_chirho.erasure_seq_chirho();
                    let status_chirho = self.bound_status_locked_chirho(
                        &loaded_chirho,
                        seq_chirho,
                        requirement_chirho,
                        current_view_chirho,
                    )?;
                    bound_statuses_chirho.insert(seq_chirho, status_chirho);
                }
            }
            let entries_chirho = view_chirho
                .entries_chirho()
                .iter()
                .map(|(requirement_chirho, standing_chirho)| {
                    let seq_chirho = requirement_chirho.erasure_seq_chirho();
                    let erasure_chirho = match standing_chirho {
                        RequirementStandingChirho::BoundChirho(_) => {
                            RequirementErasureChirho::BoundChirho {
                                status_chirho: bound_statuses_chirho[&seq_chirho].clone(),
                            }
                        }
                        RequirementStandingChirho::CarriedByChirho { bound_seq_chirho } => {
                            RequirementErasureChirho::CarriedByChirho {
                                bound_seq_chirho: *bound_seq_chirho,
                                discharged_chirho: bound_statuses_chirho
                                    .get(bound_seq_chirho)
                                    .is_some_and(ErasureStatusChirho::is_complete_chirho),
                            }
                        }
                        RequirementStandingChirho::PendingChirho => {
                            RequirementErasureChirho::PendingChirho
                        }
                    };
                    (seq_chirho, erasure_chirho)
                })
                .collect();
            Ok(SubjectErasureStatusChirho { entries_chirho })
        })
    }

    pub(super) fn bound_status_locked_chirho(
        &self,
        loaded_chirho: &LoadedSubjectChirho,
        erasure_seq_chirho: u64,
        requirement_chirho: &VerifiedErasurePropagationRequirementChirho,
        current_view_chirho: &MirrorMembershipViewChirho,
    ) -> Result<ErasureStatusChirho, LeaderRefusalChirho> {
        let status_requirement_chirho = requirement_chirho.status_requirement_chirho()?;
        let receipts_chirho = self
            .read_requirement_receipts_locked_chirho(
                loaded_chirho,
                erasure_seq_chirho,
                requirement_chirho,
                &status_requirement_chirho,
            )?
            .into_values()
            .flatten()
            .collect::<Vec<_>>();
        Ok(erasure_status_chirho(
            &status_requirement_chirho,
            current_view_chirho,
            &receipts_chirho,
            &[],
        )?)
    }

    /// Every receipt stored for the requirement at `seq`, by holder, each verified and bound to its place. The
    /// receipts directory and each holder's directory must be private real directories; a name this store never
    /// writes, a link, an over-full directory, or a receipt that does not belong where it sits refuses the whole
    /// read. A stranded temp from a crashed write was never published, so it is skipped.
    fn read_requirement_receipts_locked_chirho(
        &self,
        loaded_chirho: &LoadedSubjectChirho,
        erasure_seq_chirho: u64,
        requirement_chirho: &VerifiedErasurePropagationRequirementChirho,
        status_requirement_chirho: &ErasureRequirementChirho,
    ) -> Result<BTreeMap<String, Vec<VerifiedErasureReceiptChirho>>, LeaderRefusalChirho> {
        let mut receipts_chirho = BTreeMap::new();
        if !loaded_chirho
            .receipt_seqs_chirho
            .contains(&erasure_seq_chirho)
        {
            return Ok(receipts_chirho);
        }
        let receipts_dir_chirho =
            self.receipts_dir_chirho(&loaded_chirho.subject_digest_chirho, erasure_seq_chirho)?;
        if !self
            .tree_chirho
            .existing_private_dir_chirho(&receipts_dir_chirho)
            .map_err(|_| unreadable_chirho())?
        {
            // The subject's scan saw it under this same lock, so it vanishing now is not "no receipts".
            return Err(unreadable_chirho());
        }
        let entries_chirho = fs::read_dir(&receipts_dir_chirho).map_err(|_| unreadable_chirho())?;
        for (index_chirho, entry_chirho) in entries_chirho.enumerate() {
            if index_chirho >= ERASURE_PROPAGATION_MAX_HOLDERS_CHIRHO {
                return Err(LeaderRefusalIdentityChirho::LeaderStoreScanTooLargeChirho.into());
            }
            let entry_chirho = entry_chirho.map_err(|_| unreadable_chirho())?;
            if !entry_chirho
                .file_type()
                .map_err(|_| unreadable_chirho())?
                .is_dir()
            {
                return Err(unreadable_chirho());
            }
            let holder_chirho = entry_chirho
                .file_name()
                .to_str()
                .ok_or_else(unreadable_chirho)?
                .to_string();
            if hex_chirho(&holder_chirho, DIGEST_HEX_LEN_CHIRHO).is_err()
                || !requirement_chirho.holders_chirho().contains(&holder_chirho)
            {
                return Err(unreadable_chirho());
            }
            let holder_dir_chirho = receipts_dir_chirho.join(&holder_chirho);
            if !self
                .tree_chirho
                .existing_private_dir_chirho(&holder_dir_chirho)
                .map_err(|_| unreadable_chirho())?
            {
                return Err(unreadable_chirho());
            }
            let held_chirho = self.read_holder_receipts_chirho(
                &holder_dir_chirho,
                &holder_chirho,
                &loaded_chirho.subject_digest_chirho,
                status_requirement_chirho,
            )?;
            receipts_chirho.insert(holder_chirho, held_chirho);
        }
        Ok(receipts_chirho)
    }

    fn read_holder_receipts_chirho(
        &self,
        holder_dir_chirho: &Path,
        holder_chirho: &str,
        subject_digest_chirho: &str,
        status_requirement_chirho: &ErasureRequirementChirho,
    ) -> Result<Vec<VerifiedErasureReceiptChirho>, LeaderRefusalChirho> {
        let mut receipts_chirho = Vec::new();
        let entries_chirho = fs::read_dir(holder_dir_chirho).map_err(|_| unreadable_chirho())?;
        for (index_chirho, entry_chirho) in entries_chirho.enumerate() {
            if index_chirho >= HOLDER_SCAN_MAX_ENTRIES_CHIRHO {
                return Err(LeaderRefusalIdentityChirho::LeaderStoreScanTooLargeChirho.into());
            }
            let entry_chirho = entry_chirho.map_err(|_| unreadable_chirho())?;
            if !entry_chirho
                .file_type()
                .map_err(|_| unreadable_chirho())?
                .is_file()
            {
                return Err(unreadable_chirho());
            }
            let name_chirho = entry_chirho.file_name();
            let name_chirho = name_chirho.to_str().ok_or_else(unreadable_chirho)?;
            if name_chirho.starts_with('.') {
                durable_temp_final_name_chirho(name_chirho)
                    .and_then(receipt_frame_digest_chirho)
                    .ok_or_else(unreadable_chirho)?;
                continue;
            }
            let frame_digest_chirho =
                receipt_frame_digest_chirho(name_chirho).ok_or_else(unreadable_chirho)?;
            if receipts_chirho.len() >= ERASURE_RECEIPTS_MAX_PER_HOLDER_CHIRHO {
                return Err(unreadable_chirho());
            }
            let bytes_chirho = match read_stored_chirho(
                &holder_dir_chirho.join(name_chirho),
                RECEIPT_MAX_BYTES_CHIRHO,
            ) {
                StoredChirho::PresentChirho(bytes_chirho) => bytes_chirho,
                StoredChirho::AbsentChirho | StoredChirho::UnreadableChirho => {
                    return Err(unreadable_chirho())
                }
            };
            let receipt_chirho = decode_and_verify_erasure_receipt_chirho(&bytes_chirho)?;
            if receipt_chirho.holder_node_id_chirho() != holder_chirho
                || receipt_chirho.erasure_frame_digest_chirho() != frame_digest_chirho
                || receipt_chirho.consistency_group_digest_chirho()
                    != self.context_chirho.consistency_group_digest_chirho()
                || receipt_chirho.subject_digest_chirho() != subject_digest_chirho
                || !status_requirement_chirho.closes_share_alone_chirho(&receipt_chirho)
            {
                return Err(unreadable_chirho());
            }
            receipts_chirho.push(receipt_chirho);
        }
        Ok(receipts_chirho)
    }

    fn receipts_dir_chirho(
        &self,
        subject_digest_chirho: &str,
        erasure_seq_chirho: u64,
    ) -> Result<PathBuf, LeaderRefusalChirho> {
        Ok(self
            .subject_dir_chirho(subject_digest_chirho)?
            .join(format!("{erasure_seq_chirho}{RECEIPTS_SUFFIX_CHIRHO}")))
    }

    fn holder_receipts_dir_chirho(
        &self,
        subject_digest_chirho: &str,
        erasure_seq_chirho: u64,
        holder_chirho: &str,
    ) -> Result<PathBuf, LeaderRefusalChirho> {
        let holder_chirho =
            hex_chirho(holder_chirho, DIGEST_HEX_LEN_CHIRHO).map_err(|_| unreadable_chirho())?;
        Ok(self
            .receipts_dir_chirho(subject_digest_chirho, erasure_seq_chirho)?
            .join(holder_chirho))
    }

    /// Barrier: the holder's receipt directory chain and its entries are durable, even when this attempt wrote
    /// nothing.
    fn receipt_barrier_chirho(&self, holder_dir_chirho: &Path) -> Result<(), LeaderRefusalChirho> {
        self.tree_chirho
            .ensure_private_dir_chirho(holder_dir_chirho)
            .map_err(|_| write_failed_chirho())?;
        sync_dir_chirho(holder_dir_chirho).map_err(|_| write_failed_chirho())
    }
}

/// The requirement at `seq`, which must exist and be BOUND: nothing is propagated for, or recorded against, an
/// unbound or carried requirement.
fn bound_requirement_chirho(
    loaded_chirho: &LoadedSubjectChirho,
    erasure_seq_chirho: u64,
) -> Result<&VerifiedErasurePropagationRequirementChirho, LeaderRefusalChirho> {
    let requirement_chirho = loaded_chirho
        .requirements_chirho
        .get(&erasure_seq_chirho)
        .ok_or(LeaderRefusalIdentityChirho::ErasureRequirementMissingChirho)?;
    if !loaded_chirho
        .bindings_chirho
        .contains_key(&erasure_seq_chirho)
    {
        return Err(LeaderRefusalIdentityChirho::ErasureReceiptRequirementUnboundChirho.into());
    }
    Ok(requirement_chirho)
}

/// The frame digest a receipt file's name carries: `<64 lowercase hex>.json`, or `None` for any other name.
fn receipt_frame_digest_chirho(name_chirho: &str) -> Option<&str> {
    let digest_chirho = name_chirho.strip_suffix(RECEIPT_FILE_SUFFIX_CHIRHO)?;
    hex_chirho(digest_chirho, DIGEST_HEX_LEN_CHIRHO).ok()
}
