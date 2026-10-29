// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Bounded, content-addressed public intent and terminal evidence.
//!
//! New objects use two digest-prefix shards. Reads probe only that canonical coordinate and the
//! prior flat coordinate, so compatibility is O(1) and never requires a directory scan.
//!
//! # Consumption contract: these lines are WARRANTS, never commit receipts
//!
//! A stored line asserts only that a signed intent or terminal outcome EXISTS. **Its presence is
//! not evidence that anything was appended to a journal, and no reader may treat it as such.**
//! Producers publish a warrant BEFORE the money append it warrants (see the CF3 commit
//! coordinator and the resident effect-warrant publisher), so a crash between the two leaves an
//! ORPHAN warrant with no corresponding record. That residue is deliberate and is safe only
//! because every reader looks a warrant up by a ref it already took from a record found in the
//! journal — an orphan is therefore unreachable rather than merely ignored.
//!
//! Two rules follow, and a new consumer that breaks either one turns an inert orphan into a false
//! commitment claim:
//!
//! - **Establish the record first.** Resolve the ref from a verified journal record (or an
//!   equivalent authority), then load the warrant. Never the reverse.
//! - **Never enumerate this store to answer "what committed".** Enumeration belongs to the
//!   journal. This store has no listing door on purpose.
//!
//! # RECORDED DISPOSITION: retained forever, outside the privacy-scan and GC inventories
//!
//! This store is absent from BOTH the privacy-scan runtime surfaces and the GC reachability roots.
//! That was an accident of omission; it is now a decision, and here is what each side actually
//! required — measured, because "add it to the list" turned out to be wrong for both.
//!
//! **GC — not a root, and not at risk.** `gc_chirho` marks from its roots and then sweeps
//! `objects-chirho/` ALONE. This directory is not under `objects-chirho/`, so no GC pass can
//! collect it, and adding it as a reachability root would retain nothing new: the 64-hex tokens in
//! a warrant name an intent's content ref and journal-cut digests — journal coordinates and warrant
//! content — not CAS objects, so the conservative marker would find no stored object behind them.
//! DECISION: **not a GC root**, because the retention it would provide already holds structurally
//! and the entry would imply a reachability relation that does not exist.
//!
//! **Privacy scan — a real gap, and NOT a one-line entry.** `reviewed_signed_log_files_chirho()`
//! inventories root-level `*.jsonl` SIGNED LOGS. This store is a sharded directory of per-coordinate
//! `.json` objects, so it does not fit that surface model at all: entering it needs a second surface
//! KIND in the scanner (or a restructure of this store), not a new string in a list. DECISION for
//! now: **recorded, not entered**, with the entry named as follow-up.
//!
//! **What makes the retention defensible in the meantime — and what does NOT.** Since the minimal
//! warrant landed, an intent warrant carries no account owner and no causer principal, only their
//! digests; and both this object and the terminal outcome now apply the money log's own
//! bounded-identifier law to every free string they still carry. So what is retained forever is
//! bounded, non-identifying coordinates. That is a statement about SHAPE, not about erasure: this
//! store still has no deletion door, so a subject-erasure request cannot reach it. If a future field
//! here ever becomes subject-linkable, the privacy-scan entry stops being a follow-up and becomes a
//! blocker.

use cairn_durable_chirho::{
    fsync_dir_chirho, read_identity_stable_bounded_regular_file_chirho, rename_no_replace_chirho,
    write_file_durable_chirho,
};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const EFFECT_COMMIT_EVIDENCE_DIRECTORY_CHIRHO: &str = "effect-commit-evidence-chirho";
pub const MAX_PUBLIC_EFFECT_EVIDENCE_LINE_BYTES_CHIRHO: usize = 64 * 1024;
const EFFECT_INTENT_EVIDENCE_FAMILY_CHIRHO: &str = "intents-chirho";
const EFFECT_WARRANT_EVIDENCE_FAMILY_CHIRHO: &str = "warrants-chirho";
const EFFECT_TERMINAL_EVIDENCE_FAMILY_CHIRHO: &str = "terminals-chirho";
static PUBLIC_EVIDENCE_TEMP_COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicEffectEvidenceKindChirho {
    IntentChirho,
    WarrantChirho,
    TerminalChirho,
}

impl PublicEffectEvidenceKindChirho {
    fn family_chirho(self) -> &'static str {
        match self {
            Self::IntentChirho => EFFECT_INTENT_EVIDENCE_FAMILY_CHIRHO,
            Self::WarrantChirho => EFFECT_WARRANT_EVIDENCE_FAMILY_CHIRHO,
            Self::TerminalChirho => EFFECT_TERMINAL_EVIDENCE_FAMILY_CHIRHO,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicEffectEvidenceRefusalChirho {
    InvalidCoordinateChirho,
    OversizedLineChirho,
    ImmutableCollisionChirho,
    UnavailableChirho { detail_chirho: String },
}

impl fmt::Display for PublicEffectEvidenceRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCoordinateChirho => {
                formatter_chirho.write_str("public effect evidence coordinate is invalid")
            }
            Self::OversizedLineChirho => {
                formatter_chirho.write_str("public effect evidence line exceeds its fixed bound")
            }
            Self::ImmutableCollisionChirho => formatter_chirho
                .write_str("public effect evidence coordinates bind different bytes"),
            Self::UnavailableChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "public effect evidence is unavailable: {detail_chirho}"
                )
            }
        }
    }
}

impl Error for PublicEffectEvidenceRefusalChirho {}

#[derive(Clone, Debug)]
pub struct RootPublicEffectEvidenceStoreChirho {
    root_chirho: PathBuf,
}

impl RootPublicEffectEvidenceStoreChirho {
    pub fn new_chirho(root_chirho: &Path) -> Self {
        Self {
            root_chirho: root_chirho.to_path_buf(),
        }
    }

    pub fn load_bounded_chirho(
        &self,
        kind_chirho: PublicEffectEvidenceKindChirho,
        coordinate_chirho: &str,
        maximum_bytes_chirho: usize,
    ) -> Result<Option<Vec<u8>>, PublicEffectEvidenceRefusalChirho> {
        let maximum_bytes_chirho =
            maximum_bytes_chirho.min(MAX_PUBLIC_EFFECT_EVIDENCE_LINE_BYTES_CHIRHO);
        let canonical_path_chirho =
            public_effect_evidence_path_chirho(&self.root_chirho, kind_chirho, coordinate_chirho)?;
        let legacy_path_chirho = legacy_public_effect_evidence_path_chirho(
            &self.root_chirho,
            kind_chirho,
            coordinate_chirho,
        )?;
        let canonical_chirho = read_optional_chirho(&canonical_path_chirho, maximum_bytes_chirho)?;
        let legacy_chirho = read_optional_chirho(&legacy_path_chirho, maximum_bytes_chirho)?;
        match (canonical_chirho, legacy_chirho) {
            (None, None) => Ok(None),
            (Some(bytes_chirho), None) | (None, Some(bytes_chirho)) => Ok(Some(bytes_chirho)),
            (Some(canonical_chirho), Some(legacy_chirho)) if canonical_chirho == legacy_chirho => {
                Ok(Some(canonical_chirho))
            }
            (Some(_canonical_chirho), Some(_legacy_chirho)) => {
                Err(PublicEffectEvidenceRefusalChirho::ImmutableCollisionChirho)
            }
        }
    }

    pub fn store_line_chirho(
        &self,
        kind_chirho: PublicEffectEvidenceKindChirho,
        coordinate_chirho: &str,
        bytes_chirho: &[u8],
    ) -> Result<(), PublicEffectEvidenceRefusalChirho> {
        if bytes_chirho.len() > MAX_PUBLIC_EFFECT_EVIDENCE_LINE_BYTES_CHIRHO {
            return Err(PublicEffectEvidenceRefusalChirho::OversizedLineChirho);
        }
        if let Some(existing_chirho) = self.load_bounded_chirho(
            kind_chirho,
            coordinate_chirho,
            MAX_PUBLIC_EFFECT_EVIDENCE_LINE_BYTES_CHIRHO,
        )? {
            return if existing_chirho == bytes_chirho {
                Ok(())
            } else {
                Err(PublicEffectEvidenceRefusalChirho::ImmutableCollisionChirho)
            };
        }

        let canonical_path_chirho =
            public_effect_evidence_path_chirho(&self.root_chirho, kind_chirho, coordinate_chirho)?;
        create_or_load_immutable_chirho(&canonical_path_chirho, bytes_chirho)?;
        match self.load_bounded_chirho(
            kind_chirho,
            coordinate_chirho,
            MAX_PUBLIC_EFFECT_EVIDENCE_LINE_BYTES_CHIRHO,
        )? {
            Some(loaded_chirho) if loaded_chirho == bytes_chirho => Ok(()),
            Some(_loaded_chirho) => {
                Err(PublicEffectEvidenceRefusalChirho::ImmutableCollisionChirho)
            }
            None => Err(unavailable_chirho(
                "created public effect evidence is missing",
            )),
        }
    }
}

pub fn public_effect_evidence_path_chirho(
    root_chirho: &Path,
    kind_chirho: PublicEffectEvidenceKindChirho,
    coordinate_chirho: &str,
) -> Result<PathBuf, PublicEffectEvidenceRefusalChirho> {
    validate_coordinate_chirho(coordinate_chirho)?;
    Ok(root_chirho
        .join(EFFECT_COMMIT_EVIDENCE_DIRECTORY_CHIRHO)
        .join(kind_chirho.family_chirho())
        .join(&coordinate_chirho[..2])
        .join(&coordinate_chirho[2..4])
        .join(format!("{coordinate_chirho}.json")))
}

pub fn legacy_public_effect_evidence_path_chirho(
    root_chirho: &Path,
    kind_chirho: PublicEffectEvidenceKindChirho,
    coordinate_chirho: &str,
) -> Result<PathBuf, PublicEffectEvidenceRefusalChirho> {
    validate_coordinate_chirho(coordinate_chirho)?;
    Ok(root_chirho
        .join(EFFECT_COMMIT_EVIDENCE_DIRECTORY_CHIRHO)
        .join(kind_chirho.family_chirho())
        .join(format!("{coordinate_chirho}.json")))
}

fn validate_coordinate_chirho(
    coordinate_chirho: &str,
) -> Result<(), PublicEffectEvidenceRefusalChirho> {
    if coordinate_chirho.len() != 64
        || !coordinate_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit() && !byte_chirho.is_ascii_uppercase())
    {
        return Err(PublicEffectEvidenceRefusalChirho::InvalidCoordinateChirho);
    }
    Ok(())
}

fn read_optional_chirho(
    path_chirho: &Path,
    maximum_bytes_chirho: usize,
) -> Result<Option<Vec<u8>>, PublicEffectEvidenceRefusalChirho> {
    let maximum_bytes_chirho = u64::try_from(maximum_bytes_chirho)
        .map_err(|_error_chirho| PublicEffectEvidenceRefusalChirho::OversizedLineChirho)?;
    match read_identity_stable_bounded_regular_file_chirho(path_chirho, maximum_bytes_chirho) {
        Ok(bytes_chirho) => Ok(Some(bytes_chirho)),
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error_chirho) => Err(unavailable_chirho(error_chirho)),
    }
}

fn create_or_load_immutable_chirho(
    path_chirho: &Path,
    proposed_chirho: &[u8],
) -> Result<(), PublicEffectEvidenceRefusalChirho> {
    if path_chirho.exists() {
        return Ok(());
    }
    let parent_chirho = path_chirho
        .parent()
        .ok_or_else(|| unavailable_chirho("public effect evidence path has no parent"))?;
    fs::create_dir_all(parent_chirho).map_err(unavailable_chirho)?;
    let counter_chirho = PUBLIC_EVIDENCE_TEMP_COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let temp_chirho = parent_chirho.join(format!(
        ".candidate-chirho-{}-{counter_chirho}",
        std::process::id()
    ));
    write_file_durable_chirho(&temp_chirho, proposed_chirho).map_err(unavailable_chirho)?;
    match rename_no_replace_chirho(&temp_chirho, path_chirho) {
        Ok(()) => fsync_dir_chirho(parent_chirho).map_err(unavailable_chirho)?,
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error_chirho) => {
            let _remove_result_chirho = fs::remove_file(&temp_chirho);
            return Err(unavailable_chirho(error_chirho));
        }
    }
    if temp_chirho.exists() {
        fs::remove_file(&temp_chirho).map_err(unavailable_chirho)?;
        fsync_dir_chirho(parent_chirho).map_err(unavailable_chirho)?;
    }
    Ok(())
}

fn unavailable_chirho(error_chirho: impl fmt::Display) -> PublicEffectEvidenceRefusalChirho {
    PublicEffectEvidenceRefusalChirho::UnavailableChirho {
        detail_chirho: error_chirho.to_string(),
    }
}
