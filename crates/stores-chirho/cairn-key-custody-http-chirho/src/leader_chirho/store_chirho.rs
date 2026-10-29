// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The leader's erasure-propagation store: one signed requirement per erasure seq and subject, its binding to the root's erasure record, and how each requirement stands, in private files under the root.
//!
//! C5 B3-a2. A subject's files live in `privacy-erasure-propagation-chirho/<h2>/<subject digest>/`:
//! `<seq>.requirement.json` and `<seq>.binding.json`, each created new and durable and never rewritten, and a
//! bound requirement's holders' receipts under `<seq>.receipts/` (B3-a3, in `receipts_chirho`). An attempt's
//! identity and status are read from these same files and add none (B3-a4-i, in `attempt_chirho`).
//! Every operation holds the root's named lock `erasure-propagation-store-chirho`. The erasure takes it
//! INSIDE the root's erasure-records lock, and seqlog refuses the reverse nesting by name, which is why the
//! lock lives in the root's own lock directory. The store never reads the root's logs: what it needs from
//! the root, the in-flight seq and which earlier seqs were recorded with which record digests, is computed
//! before its lock and handed in. Every load verifies every file against the store's context and where the
//! file sits. Nothing is rebuilt from logs, and an exceeded bound refuses rather than omits. Design:
//! `spec-chirho/workstream-state-chirho/item7-2c-key-custody-and-erasure-design-chirho.md`, section 5a,
//! items 1 to 10.

use super::refusal_chirho::{LeaderRefusalChirho, LeaderRefusalIdentityChirho};
use crate::barrier_chirho::sync_dir_chirho;
use crate::private_tree_chirho::{
    durable_temp_final_name_chirho, hex_chirho, read_stored_chirho, PrivateTreeChirho,
    StoredChirho, PRIVATE_FILE_MODE_CHIRHO,
};
use cairn_durable_chirho::{
    create_complete_file_durable_with_mode_chirho, CreateFileDurableOutcomeChirho,
};
use cairn_key_custody_chirho::{
    ErasureFrameV1Chirho, ErasurePropagationBindingV1Chirho, ErasurePropagationContextChirho,
    ErasurePropagationRequirementInputChirho, ErasurePropagationRequirementV1Chirho,
    PreparedErasureFrameChirho, PreparedErasurePropagationBindingChirho,
    PreparedErasurePropagationRequirementChirho, VerifiedErasurePropagationBindingChirho,
    VerifiedErasurePropagationRequirementChirho, ERASURE_PROPAGATION_MAX_SUCCEEDS_CHIRHO,
    ERASURE_WIRE_MAX_BYTES_CHIRHO,
};
use cairn_seqlog_chirho::seqlog_chirho::{with_named_lock_chirho, NamedLockOrderErrorChirho};
use cairn_signer_chirho::signer_chirho::sign_with_existing_key_possession_chirho;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub const ERASURE_PROPAGATION_STORE_DIR_CHIRHO: &str = "privacy-erasure-propagation-chirho";
pub const ERASURE_PROPAGATION_STORE_LOCK_CHIRHO: &str = "erasure-propagation-store-chirho";
/// The most requirements one subject's directory may hold.
pub const ERASURE_PROPAGATION_MAX_SUBJECT_REQUIREMENTS_CHIRHO: usize =
    ERASURE_PROPAGATION_MAX_SUCCEEDS_CHIRHO + 1;
/// The most entries one scan of a subject's directory reads: each requirement, its binding and its receipts
/// directory, and a stranded temp of each file.
pub(crate) const SUBJECT_SCAN_MAX_ENTRIES_CHIRHO: usize =
    5 * ERASURE_PROPAGATION_MAX_SUBJECT_REQUIREMENTS_CHIRHO;
const REQUIREMENT_MAX_BYTES_CHIRHO: u64 = ERASURE_WIRE_MAX_BYTES_CHIRHO as u64;
const BINDING_MAX_BYTES_CHIRHO: u64 = 16 * 1024;
/// Only the two-hex shard directories are remembered as synced; a subject's own directory never is.
const REMEMBERED_DEPTH_CHIRHO: usize = 1;
const DIGEST_HEX_LEN_CHIRHO: usize = 64;
const REQUIREMENT_SUFFIX_CHIRHO: &str = ".requirement.json";
const BINDING_SUFFIX_CHIRHO: &str = ".binding.json";
const RECEIPTS_SUFFIX_CHIRHO: &str = ".receipts";

/// What the root's own authenticated erasure log holds at one earlier unbound seq of the subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EarlierErasureChirho {
    /// The record there is this subject's, with this digest: the requirement is bound to it.
    RecordedChirho {
        erasure_record_digest_chirho: String,
    },
    /// The record there is another subject's: the attempt was never recorded, and is carried.
    NeverRecordedChirho,
}

/// One erasure's requirement to record, with the root's evidence about the subject's earlier unbound seqs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordRequirementRequestChirho {
    pub subject_digest_chirho: String,
    /// The in-flight seq: the root's erasure-log length.
    pub erasure_seq_chirho: u64,
    pub erased_below_blob_seq_chirho: u64,
    pub key_ids_chirho: BTreeSet<String>,
    pub holders_chirho: BTreeSet<String>,
    /// Every unbound seq of the subject below the in-flight one, exactly, with what the root holds there.
    pub earlier_chirho: BTreeMap<u64, EarlierErasureChirho>,
}

/// How one stored requirement stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequirementStandingChirho {
    /// Bound to the root's record at its seq. It is its own term in the subject's conjunction. Boxed, so
    /// the standing stays small beside its two field-free siblings.
    BoundChirho(Box<VerifiedErasurePropagationBindingChirho>),
    /// Unbound, and carried, directly or through unbound links, by the bound requirement at this seq.
    CarriedByChirho { bound_seq_chirho: u64 },
    /// Unbound and carried by nothing bound: not yet reconciled. It blocks the subject.
    PendingChirho,
}

/// One subject's requirements, each verified, with how it stands, by ascending seq.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectPropagationViewChirho {
    entries_chirho: Vec<(
        VerifiedErasurePropagationRequirementChirho,
        RequirementStandingChirho,
    )>,
}

impl SubjectPropagationViewChirho {
    pub fn entries_chirho(
        &self,
    ) -> &[(
        VerifiedErasurePropagationRequirementChirho,
        RequirementStandingChirho,
    )] {
        &self.entries_chirho
    }

    /// The seqs of every requirement without a binding, ascending.
    pub fn unbound_seqs_chirho(&self) -> Vec<u64> {
        self.entries_chirho
            .iter()
            .filter(|(_, standing_chirho)| {
                !matches!(standing_chirho, RequirementStandingChirho::BoundChirho(_))
            })
            .map(|(requirement_chirho, _)| requirement_chirho.erasure_seq_chirho())
            .collect()
    }
}

pub struct ErasurePropagationStoreChirho {
    root_chirho: PathBuf,
    tree_chirho: PrivateTreeChirho,
    context_chirho: ErasurePropagationContextChirho,
}

impl ErasurePropagationStoreChirho {
    /// Open the store under `root_chirho` for one context. The root must exist; the store's directory is
    /// created private if it is absent.
    pub fn open_chirho(
        root_chirho: &Path,
        context_chirho: ErasurePropagationContextChirho,
    ) -> Result<Self, LeaderRefusalChirho> {
        let tree_chirho = PrivateTreeChirho::open_chirho(
            &root_chirho.join(ERASURE_PROPAGATION_STORE_DIR_CHIRHO),
            REMEMBERED_DEPTH_CHIRHO,
        )
        .map_err(|_| unreadable_chirho())?;
        Ok(Self {
            root_chirho: root_chirho.to_path_buf(),
            tree_chirho,
            context_chirho,
        })
    }

    /// The subject's requirements, verified, with how each stands.
    pub fn subject_view_chirho(
        &self,
        subject_digest_chirho: &str,
    ) -> Result<SubjectPropagationViewChirho, LeaderRefusalChirho> {
        self.with_store_lock_chirho(|| {
            Ok(self
                .load_subject_chirho(subject_digest_chirho)?
                .view_chirho())
        })
    }

    /// Record the in-flight erasure's requirement, the sink's body. An exact retry returns the stored
    /// requirement, whose cut is authoritative. Otherwise every earlier attempt the root recorded is bound,
    /// every never-recorded one that nothing bound already carries is carried, and the new requirement is
    /// signed and made durable before this returns.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/key-custody-chirho/erasure-propagation-workflow-chirho.md`.
    pub fn record_requirement_chirho(
        &self,
        request_chirho: &RecordRequirementRequestChirho,
    ) -> Result<VerifiedErasurePropagationRequirementChirho, LeaderRefusalChirho> {
        self.with_store_lock_chirho(|| self.record_requirement_locked_chirho(request_chirho))
    }

    /// Bind the requirement at `erasure_seq_chirho` to the digest of the record the root appended there. An
    /// equal replay passes its barrier again; a different record digest refuses.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/key-custody-chirho/erasure-propagation-workflow-chirho.md`.
    pub fn record_binding_chirho(
        &self,
        subject_digest_chirho: &str,
        erasure_seq_chirho: u64,
        erasure_record_digest_chirho: &str,
    ) -> Result<VerifiedErasurePropagationBindingChirho, LeaderRefusalChirho> {
        self.with_store_lock_chirho(|| {
            let loaded_chirho = self.load_subject_chirho(subject_digest_chirho)?;
            self.bind_locked_chirho(
                &loaded_chirho,
                erasure_seq_chirho,
                erasure_record_digest_chirho,
            )
        })
    }

    fn record_requirement_locked_chirho(
        &self,
        request_chirho: &RecordRequirementRequestChirho,
    ) -> Result<VerifiedErasurePropagationRequirementChirho, LeaderRefusalChirho> {
        let subject_chirho = &request_chirho.subject_digest_chirho;
        let in_flight_chirho = request_chirho.erasure_seq_chirho;
        let mut loaded_chirho = self.load_subject_chirho(subject_chirho)?;
        if loaded_chirho
            .requirements_chirho
            .keys()
            .next_back()
            .is_some_and(|seq_chirho| *seq_chirho > in_flight_chirho)
        {
            return Err(
                LeaderRefusalIdentityChirho::ErasureRequirementSeqRollbackRefusedChirho.into(),
            );
        }
        if let Some(stored_chirho) = loaded_chirho.requirements_chirho.get(&in_flight_chirho) {
            if loaded_chirho
                .bindings_chirho
                .contains_key(&in_flight_chirho)
            {
                return Err(
                    LeaderRefusalIdentityChirho::ErasureRequirementSeqAlreadyBoundChirho.into(),
                );
            }
            // An earlier attempt may have left the file visible and not yet durable.
            self.sync_subject_dir_chirho(subject_chirho)?;
            return Ok(stored_chirho.clone());
        }
        if request_chirho
            .earlier_chirho
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            != loaded_chirho.unbound_seqs_chirho()
        {
            return Err(LeaderRefusalIdentityChirho::ErasureRequirementEvidenceStaleChirho.into());
        }
        for (seq_chirho, earlier_chirho) in &request_chirho.earlier_chirho {
            if let EarlierErasureChirho::RecordedChirho {
                erasure_record_digest_chirho,
            } = earlier_chirho
            {
                let binding_chirho = self.bind_locked_chirho(
                    &loaded_chirho,
                    *seq_chirho,
                    erasure_record_digest_chirho,
                )?;
                loaded_chirho
                    .bindings_chirho
                    .insert(*seq_chirho, binding_chirho);
            }
        }
        if loaded_chirho.requirements_chirho.len()
            >= ERASURE_PROPAGATION_MAX_SUBJECT_REQUIREMENTS_CHIRHO
        {
            return Err(LeaderRefusalIdentityChirho::ErasureRequirementSubjectFullChirho.into());
        }
        let carried_by_bound_chirho = loaded_chirho.carried_by_bound_chirho();
        let mut input_chirho = ErasurePropagationRequirementInputChirho {
            subject_digest_chirho: subject_chirho.clone(),
            erasure_seq_chirho: in_flight_chirho,
            erased_below_blob_seq_chirho: request_chirho.erased_below_blob_seq_chirho,
            key_ids_chirho: request_chirho.key_ids_chirho.clone(),
            holders_chirho: request_chirho.holders_chirho.clone(),
            succeeds_chirho: BTreeSet::new(),
        };
        for (seq_chirho, earlier_chirho) in &request_chirho.earlier_chirho {
            if *earlier_chirho != EarlierErasureChirho::NeverRecordedChirho
                || carried_by_bound_chirho.contains_key(seq_chirho)
            {
                continue;
            }
            let carried_chirho = &loaded_chirho.requirements_chirho[seq_chirho];
            input_chirho
                .key_ids_chirho
                .extend(carried_chirho.key_ids_chirho().iter().cloned());
            input_chirho
                .holders_chirho
                .extend(carried_chirho.holders_chirho().iter().cloned());
            input_chirho.erased_below_blob_seq_chirho = input_chirho
                .erased_below_blob_seq_chirho
                .max(carried_chirho.erased_below_blob_seq_chirho());
            input_chirho
                .succeeds_chirho
                .insert(carried_chirho.reference_chirho());
        }
        let prepared_chirho = PreparedErasurePropagationRequirementChirho::new_chirho(
            &self.context_chirho,
            input_chirho,
        )?;
        let signature_chirho = self.sign_chirho(&prepared_chirho.signing_digest_chirho())?;
        let record_chirho = prepared_chirho.into_signed_chirho(signature_chirho)?;
        let verified_chirho = record_chirho.verify_chirho(&self.context_chirho)?;
        let bytes_chirho = serde_json::to_vec(&record_chirho).map_err(|_| write_failed_chirho())?;
        self.publish_chirho(
            subject_chirho,
            &self.entry_path_chirho(subject_chirho, in_flight_chirho, REQUIREMENT_SUFFIX_CHIRHO)?,
            &bytes_chirho,
        )?;
        Ok(verified_chirho)
    }

    fn bind_locked_chirho(
        &self,
        loaded_chirho: &LoadedSubjectChirho,
        erasure_seq_chirho: u64,
        erasure_record_digest_chirho: &str,
    ) -> Result<VerifiedErasurePropagationBindingChirho, LeaderRefusalChirho> {
        let requirement_chirho = loaded_chirho
            .requirements_chirho
            .get(&erasure_seq_chirho)
            .ok_or(LeaderRefusalIdentityChirho::ErasureRequirementMissingChirho)?;
        let subject_chirho = &loaded_chirho.subject_digest_chirho;
        if let Some(existing_chirho) = loaded_chirho.bindings_chirho.get(&erasure_seq_chirho) {
            if existing_chirho.erasure_record_digest_chirho() != erasure_record_digest_chirho {
                return Err(
                    LeaderRefusalIdentityChirho::ErasureRequirementBindingConflictChirho.into(),
                );
            }
            self.sync_subject_dir_chirho(subject_chirho)?;
            return Ok(existing_chirho.clone());
        }
        // Carried means unbound for good: binding it would give it two terminal readings.
        if loaded_chirho
            .requirements_chirho
            .values()
            .any(|carrier_chirho| {
                carrier_chirho
                    .succeeds_chirho()
                    .iter()
                    .any(|carried_chirho| carried_chirho.erasure_seq_chirho == erasure_seq_chirho)
            })
        {
            return Err(
                LeaderRefusalIdentityChirho::ErasureRequirementAlreadySucceededChirho.into(),
            );
        }
        let prepared_chirho = PreparedErasurePropagationBindingChirho::new_chirho(
            &self.context_chirho,
            requirement_chirho,
            erasure_record_digest_chirho,
        )?;
        let signature_chirho = self.sign_chirho(&prepared_chirho.signing_digest_chirho())?;
        let record_chirho = prepared_chirho.into_signed_chirho(signature_chirho)?;
        let verified_chirho =
            record_chirho.verify_chirho(&self.context_chirho, requirement_chirho)?;
        let bytes_chirho = serde_json::to_vec(&record_chirho).map_err(|_| write_failed_chirho())?;
        self.publish_chirho(
            subject_chirho,
            &self.entry_path_chirho(subject_chirho, erasure_seq_chirho, BINDING_SUFFIX_CHIRHO)?,
            &bytes_chirho,
        )?;
        Ok(verified_chirho)
    }

    /// Load and verify every file of one subject. A binding must name its own requirement, every carried
    /// requirement must be present, covered and unbound, and every file must be where it sits.
    fn load_subject_chirho(
        &self,
        subject_digest_chirho: &str,
    ) -> Result<LoadedSubjectChirho, LeaderRefusalChirho> {
        // Read-only and link-refusing: the store's directory, the shard and the subject's directory must each
        // be a private real directory, and only a genuinely absent shard or subject reads as empty.
        let dir_chirho = self.subject_dir_chirho(subject_digest_chirho)?;
        let present_chirho = self
            .tree_chirho
            .existing_private_dir_chirho(&dir_chirho)
            .map_err(|_| unreadable_chirho())?;
        let scanned_chirho = if present_chirho {
            scan_subject_dir_chirho(&dir_chirho)?
        } else {
            SubjectScanChirho::default()
        };
        let SubjectScanChirho {
            requirement_seqs_chirho,
            binding_seqs_chirho,
            receipt_seqs_chirho,
        } = scanned_chirho;
        if requirement_seqs_chirho.len() > ERASURE_PROPAGATION_MAX_SUBJECT_REQUIREMENTS_CHIRHO {
            return Err(unreadable_chirho());
        }
        if !binding_seqs_chirho.is_subset(&requirement_seqs_chirho) {
            return Err(
                LeaderRefusalIdentityChirho::ErasureRequirementSeqRollbackRefusedChirho.into(),
            );
        }
        // Receipts are recorded only for a bound requirement, so receipts beside an unbound or missing one are
        // state this store did not write.
        if !receipt_seqs_chirho.is_subset(&binding_seqs_chirho) {
            return Err(unreadable_chirho());
        }
        let mut requirements_chirho = BTreeMap::new();
        for seq_chirho in requirement_seqs_chirho {
            let bytes_chirho = self.read_entry_chirho(
                subject_digest_chirho,
                seq_chirho,
                REQUIREMENT_SUFFIX_CHIRHO,
                REQUIREMENT_MAX_BYTES_CHIRHO,
            )?;
            let record_chirho: ErasurePropagationRequirementV1Chirho =
                serde_json::from_slice(&bytes_chirho).map_err(|_| unreadable_chirho())?;
            let verified_chirho = record_chirho.verify_chirho(&self.context_chirho)?;
            if verified_chirho.subject_digest_chirho() != subject_digest_chirho
                || verified_chirho.erasure_seq_chirho() != seq_chirho
            {
                return Err(unreadable_chirho());
            }
            requirements_chirho.insert(seq_chirho, verified_chirho);
        }
        let mut bindings_chirho = BTreeMap::new();
        for seq_chirho in binding_seqs_chirho {
            let bytes_chirho = self.read_entry_chirho(
                subject_digest_chirho,
                seq_chirho,
                BINDING_SUFFIX_CHIRHO,
                BINDING_MAX_BYTES_CHIRHO,
            )?;
            let record_chirho: ErasurePropagationBindingV1Chirho =
                serde_json::from_slice(&bytes_chirho).map_err(|_| unreadable_chirho())?;
            let verified_chirho = record_chirho
                .verify_chirho(&self.context_chirho, &requirements_chirho[&seq_chirho])?;
            bindings_chirho.insert(seq_chirho, verified_chirho);
        }
        for requirement_chirho in requirements_chirho.values() {
            for carried_ref_chirho in requirement_chirho.succeeds_chirho() {
                let carried_chirho = requirements_chirho
                    .get(&carried_ref_chirho.erasure_seq_chirho)
                    .ok_or(LeaderRefusalIdentityChirho::ErasureRequirementCarriedMissingChirho)?;
                requirement_chirho.verify_carries_chirho(carried_chirho)?;
                if bindings_chirho.contains_key(&carried_ref_chirho.erasure_seq_chirho) {
                    return Err(
                        LeaderRefusalIdentityChirho::ErasureRequirementCarriedBoundChirho.into(),
                    );
                }
            }
        }
        Ok(LoadedSubjectChirho {
            subject_digest_chirho: subject_digest_chirho.to_string(),
            requirements_chirho,
            bindings_chirho,
            receipt_seqs_chirho,
        })
    }

    fn read_entry_chirho(
        &self,
        subject_digest_chirho: &str,
        erasure_seq_chirho: u64,
        suffix_chirho: &str,
        max_bytes_chirho: u64,
    ) -> Result<Vec<u8>, LeaderRefusalChirho> {
        match read_stored_chirho(
            &self.entry_path_chirho(subject_digest_chirho, erasure_seq_chirho, suffix_chirho)?,
            max_bytes_chirho,
        ) {
            StoredChirho::PresentChirho(bytes_chirho) => Ok(bytes_chirho),
            StoredChirho::AbsentChirho | StoredChirho::UnreadableChirho => Err(unreadable_chirho()),
        }
    }

    fn subject_dir_chirho(
        &self,
        subject_digest_chirho: &str,
    ) -> Result<PathBuf, LeaderRefusalChirho> {
        let subject_chirho = hex_chirho(subject_digest_chirho, DIGEST_HEX_LEN_CHIRHO)
            .map_err(|_| unreadable_chirho())?;
        Ok(self
            .tree_chirho
            .dir_chirho()
            .join(&subject_chirho[..2])
            .join(subject_chirho))
    }

    fn entry_path_chirho(
        &self,
        subject_digest_chirho: &str,
        erasure_seq_chirho: u64,
        suffix_chirho: &str,
    ) -> Result<PathBuf, LeaderRefusalChirho> {
        Ok(self
            .subject_dir_chirho(subject_digest_chirho)?
            .join(format!("{erasure_seq_chirho}{suffix_chirho}")))
    }

    /// Create one new file, durable before this returns. Under the store's lock the load saw no such
    /// file, so finding one now is state this store did not write.
    fn publish_chirho(
        &self,
        subject_digest_chirho: &str,
        path_chirho: &Path,
        bytes_chirho: &[u8],
    ) -> Result<(), LeaderRefusalChirho> {
        self.tree_chirho
            .ensure_private_dir_chirho(&self.subject_dir_chirho(subject_digest_chirho)?)
            .map_err(|_| write_failed_chirho())?;
        match create_complete_file_durable_with_mode_chirho(
            path_chirho,
            bytes_chirho,
            PRIVATE_FILE_MODE_CHIRHO,
        )
        .map_err(|_| write_failed_chirho())?
        {
            CreateFileDurableOutcomeChirho::CreatedChirho => Ok(()),
            CreateFileDurableOutcomeChirho::AlreadyExistsChirho => Err(unreadable_chirho()),
        }
    }

    /// Barrier: the subject's directory chain and its entries are durable, even when this attempt wrote
    /// nothing, because an earlier attempt may have made them visible and crashed before its sync.
    fn sync_subject_dir_chirho(
        &self,
        subject_digest_chirho: &str,
    ) -> Result<(), LeaderRefusalChirho> {
        let dir_chirho = self.subject_dir_chirho(subject_digest_chirho)?;
        self.tree_chirho
            .ensure_private_dir_chirho(&dir_chirho)
            .map_err(|_| write_failed_chirho())?;
        sync_dir_chirho(&dir_chirho).map_err(|_| write_failed_chirho())
    }

    /// The node that issues this store's records: the elected leader that may propagate them.
    pub(crate) fn issuer_node_id_chirho(&self) -> &str {
        self.context_chirho.issuer_node_id_chirho()
    }

    /// The consistency group this store's requirements belong to.
    pub(crate) fn group_digest_chirho(&self) -> &str {
        self.context_chirho.consistency_group_digest_chirho()
    }

    /// Sign one prepared erasure frame through the same existing-key signer as every record here, so a frame is
    /// only ever the issuer's (C5 B3-a3, item 14 D3). It never mints a key.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/key-custody-chirho/erasure-propagation-workflow-chirho.md`.
    pub(crate) fn sign_erasure_frame_chirho(
        &self,
        prepared_chirho: PreparedErasureFrameChirho,
    ) -> Result<ErasureFrameV1Chirho, LeaderRefusalChirho> {
        let signature_chirho = self.sign_chirho(&prepared_chirho.signing_digest_chirho())?;
        Ok(prepared_chirho.into_signed_chirho(signature_chirho)?)
    }

    /// Sign with the root's EXISTING key, which must be the store's issuer. It never mints one.
    fn sign_chirho(&self, digest_chirho: &[u8; 32]) -> Result<String, LeaderRefusalChirho> {
        let possession_chirho =
            sign_with_existing_key_possession_chirho(&self.root_chirho, digest_chirho)
                .map_err(|_| LeaderRefusalIdentityChirho::LeaderSignerUnavailableChirho)?;
        if possession_chirho.key_id_chirho() != self.context_chirho.issuer_node_id_chirho() {
            return Err(LeaderRefusalIdentityChirho::LeaderSignerUnavailableChirho.into());
        }
        Ok(possession_chirho.into_signature_hex_chirho())
    }

    /// Run `action_chirho` holding the root's store lock. Asking for it while holding a lock the root
    /// takes before it refuses by name, before blocking.
    pub(crate) fn with_store_lock_chirho<TChirho>(
        &self,
        action_chirho: impl FnOnce() -> Result<TChirho, LeaderRefusalChirho>,
    ) -> Result<TChirho, LeaderRefusalChirho> {
        match with_named_lock_chirho(
            &self.root_chirho,
            ERASURE_PROPAGATION_STORE_LOCK_CHIRHO,
            || Ok(action_chirho()),
        ) {
            Ok(result_chirho) => result_chirho,
            Err(error_chirho)
                if error_chirho
                    .downcast_ref::<NamedLockOrderErrorChirho>()
                    .is_some() =>
            {
                Err(LeaderRefusalIdentityChirho::LeaderStoreLockOrderRefusedChirho.into())
            }
            Err(_) => Err(LeaderRefusalIdentityChirho::LeaderStoreLockUnavailableChirho.into()),
        }
    }
}

/// One subject's verified files. Receipts are named by seq here and read only by the receipts module.
struct LoadedSubjectChirho {
    subject_digest_chirho: String,
    requirements_chirho: BTreeMap<u64, VerifiedErasurePropagationRequirementChirho>,
    bindings_chirho: BTreeMap<u64, VerifiedErasurePropagationBindingChirho>,
    receipt_seqs_chirho: BTreeSet<u64>,
}

impl LoadedSubjectChirho {
    fn unbound_seqs_chirho(&self) -> BTreeSet<u64> {
        self.requirements_chirho
            .keys()
            .filter(|seq_chirho| !self.bindings_chirho.contains_key(seq_chirho))
            .copied()
            .collect()
    }

    /// For each unbound requirement that a bound one carries, directly or through unbound links, the
    /// lowest such bound seq. Each carry is a verified superset, so coverage is transitive.
    fn carried_by_bound_chirho(&self) -> BTreeMap<u64, u64> {
        let mut carried_chirho = BTreeMap::new();
        for bound_seq_chirho in self.bindings_chirho.keys() {
            let mut stack_chirho = self.requirements_chirho[bound_seq_chirho]
                .succeeds_chirho()
                .iter()
                .map(|carried_ref_chirho| carried_ref_chirho.erasure_seq_chirho)
                .collect::<Vec<_>>();
            let mut visited_chirho = BTreeSet::new();
            while let Some(seq_chirho) = stack_chirho.pop() {
                if !visited_chirho.insert(seq_chirho)
                    || self.bindings_chirho.contains_key(&seq_chirho)
                {
                    continue;
                }
                carried_chirho
                    .entry(seq_chirho)
                    .or_insert(*bound_seq_chirho);
                if let Some(requirement_chirho) = self.requirements_chirho.get(&seq_chirho) {
                    stack_chirho.extend(
                        requirement_chirho
                            .succeeds_chirho()
                            .iter()
                            .map(|carried_ref_chirho| carried_ref_chirho.erasure_seq_chirho),
                    );
                }
            }
        }
        carried_chirho
    }

    fn view_chirho(&self) -> SubjectPropagationViewChirho {
        let carried_by_bound_chirho = self.carried_by_bound_chirho();
        SubjectPropagationViewChirho {
            entries_chirho: self
                .requirements_chirho
                .iter()
                .map(|(seq_chirho, requirement_chirho)| {
                    let standing_chirho = match self.bindings_chirho.get(seq_chirho) {
                        Some(binding_chirho) => {
                            RequirementStandingChirho::BoundChirho(Box::new(binding_chirho.clone()))
                        }
                        None => match carried_by_bound_chirho.get(seq_chirho) {
                            Some(bound_seq_chirho) => RequirementStandingChirho::CarriedByChirho {
                                bound_seq_chirho: *bound_seq_chirho,
                            },
                            None => RequirementStandingChirho::PendingChirho,
                        },
                    };
                    (requirement_chirho.clone(), standing_chirho)
                })
                .collect(),
        }
    }
}

/// What one file in a subject's directory is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LeaderEntryKindChirho {
    RequirementChirho,
    BindingChirho,
}

/// What one scan of a subject's directory found, by seq.
#[derive(Default)]
struct SubjectScanChirho {
    requirement_seqs_chirho: BTreeSet<u64>,
    binding_seqs_chirho: BTreeSet<u64>,
    receipt_seqs_chirho: BTreeSet<u64>,
}

/// The seqs with a requirement, a binding and a receipts directory in one subject's directory, which the
/// caller has probed as a private real directory. A name this store never writes, a link, or a directory
/// other than `<seq>.receipts` refuses, and so does a directory larger than one scan may read. A stranded
/// temp from a crashed write was never published, so it is skipped. The directory vanishing after the probe
/// refuses; it is never read as empty. A receipts directory is admitted by its name only; the receipts
/// module reads inside it.
fn scan_subject_dir_chirho(dir_chirho: &Path) -> Result<SubjectScanChirho, LeaderRefusalChirho> {
    let mut scanned_chirho = SubjectScanChirho::default();
    let entries_chirho = fs::read_dir(dir_chirho).map_err(|_| unreadable_chirho())?;
    for (index_chirho, entry_chirho) in entries_chirho.enumerate() {
        if index_chirho >= SUBJECT_SCAN_MAX_ENTRIES_CHIRHO {
            return Err(LeaderRefusalIdentityChirho::LeaderStoreScanTooLargeChirho.into());
        }
        let entry_chirho = entry_chirho.map_err(|_| unreadable_chirho())?;
        let file_type_chirho = entry_chirho.file_type().map_err(|_| unreadable_chirho())?;
        let name_chirho = entry_chirho.file_name();
        let name_chirho = name_chirho.to_str().ok_or_else(unreadable_chirho)?;
        if file_type_chirho.is_dir() {
            let seq_chirho = name_chirho
                .strip_suffix(RECEIPTS_SUFFIX_CHIRHO)
                .and_then(parse_seq_chirho)
                .ok_or_else(unreadable_chirho)?;
            scanned_chirho.receipt_seqs_chirho.insert(seq_chirho);
            continue;
        }
        if !file_type_chirho.is_file() {
            return Err(unreadable_chirho());
        }
        if name_chirho.starts_with('.') {
            durable_temp_final_name_chirho(name_chirho)
                .and_then(classify_final_chirho)
                .ok_or_else(unreadable_chirho)?;
            continue;
        }
        match classify_final_chirho(name_chirho).ok_or_else(unreadable_chirho)? {
            (seq_chirho, LeaderEntryKindChirho::RequirementChirho) => {
                scanned_chirho.requirement_seqs_chirho.insert(seq_chirho);
            }
            (seq_chirho, LeaderEntryKindChirho::BindingChirho) => {
                scanned_chirho.binding_seqs_chirho.insert(seq_chirho);
            }
        }
    }
    Ok(scanned_chirho)
}

fn classify_final_chirho(name_chirho: &str) -> Option<(u64, LeaderEntryKindChirho)> {
    let (seq_text_chirho, kind_chirho) =
        if let Some(seq_text_chirho) = name_chirho.strip_suffix(REQUIREMENT_SUFFIX_CHIRHO) {
            (seq_text_chirho, LeaderEntryKindChirho::RequirementChirho)
        } else {
            (
                name_chirho.strip_suffix(BINDING_SUFFIX_CHIRHO)?,
                LeaderEntryKindChirho::BindingChirho,
            )
        };
    Some((parse_seq_chirho(seq_text_chirho)?, kind_chirho))
}

/// A seq in a file name: canonical decimal, with no sign and no leading zero.
fn parse_seq_chirho(text_chirho: &str) -> Option<u64> {
    if text_chirho.is_empty()
        || !text_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit())
        || (text_chirho.len() > 1 && text_chirho.starts_with('0'))
    {
        return None;
    }
    text_chirho.parse().ok()
}

fn unreadable_chirho() -> LeaderRefusalChirho {
    LeaderRefusalIdentityChirho::LeaderStoreUnreadableChirho.into()
}

fn write_failed_chirho() -> LeaderRefusalChirho {
    LeaderRefusalIdentityChirho::LeaderStoreWriteFailedChirho.into()
}

#[path = "receipts_chirho.rs"]
mod receipts_chirho;
pub use receipts_chirho::{
    ErasureReceiptRecordedChirho, RequirementErasureChirho, SubjectErasureStatusChirho,
    ERASURE_RECEIPTS_MAX_PER_HOLDER_CHIRHO,
};

#[path = "attempt_chirho.rs"]
mod attempt_chirho;
pub(crate) use attempt_chirho::requirement_for_identity_chirho;
pub use attempt_chirho::{ErasureAttemptChirho, ErasureAttemptIdentityChirho};
