// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The privacy blob log as an incremental, verified view, so a blob ref resolves to its subject from memory plus only
//! the records appended since the last call, instead of re-reading the whole log and every shred-key file per lookup.
//!
//! Checkpoint brick S1 (`spec-chirho/workflows-chirho/perf-chirho/execution-checkpoint-brick-design-chirho.md`;
//! design approved by agy #25778/#25781 and PFE #25782). The full scan it replaces proved, per lookup: (a) every
//! record parses; (b) every key id is valid and claimed by one subject; (c) every record's key file, if present,
//! names the record's subject; (d) the looked-up ref is logged, which gives its subject.
//! - **(a), (b) and (c) run once per record, when the view folds it.** Nothing more: the lookup never checked record
//!   signatures, sequence numbers or schemas (the audit verifier does), so neither does the view. With one fault
//!   present, the view refuses exactly when the full scan refuses, with the same message; with several, it may name
//!   a different one first.
//! - **The target key's file is re-checked on every lookup** (option (i), agy #25778): the looked-up value's own
//!   property stays exact. A key file changed AFTER its record was folded is otherwise found by the hourly
//!   INTEGRITY PASS, which re-folds the whole log in the background, so every key file is checked again (#25781
//!   (b')). Any inconsistency found either way DROPS the view, so the root refuses every lookup again, as today,
//!   until it is fixed. The window for an UNRELATED key file changed after its fold is therefore the integrity
//!   interval or the next lookup of that key, whichever comes first.
//! - **A store refuses exactly when a lookup would** (PFE #25789, agy #25796). The store path brings this view
//!   current under the blob log's append lock, BEFORE the seqlog's recovery, and refuses if the view refuses. A
//!   complete bad line therefore stays in the log and keeps everything refusing, where recovery alone would have
//!   quarantined it and let the root resume. No health flag is kept: after a drop, the next store's full rebuild
//!   refuses while the fault is there and succeeds once it is repaired.
//! - **Write-access tracking is on the blob LOG only** (#25781 (b')): every private store adds a key file, so a
//!   key-directory trigger would rebuild on every write. The store writes its key file BEFORE it appends the record,
//!   so the fold checks each new key file as its record arrives.
//! - **A final line without its newline that does not parse is left for later** (the engine's rule): a write in
//!   flight, or a torn tail the next store's recovery truncates. The full scan refused on it. It is never trusted.
//! - **Startup** (#25781 (a')): the serve runtime warms the view on a background thread after it binds. A lookup that
//!   arrives first does the same full load itself, under the view's lock. No answer comes from an unverified view.
//! - **Memory:** the view keeps every logged ref and its subject, about half a kilobyte per blob record. The full
//!   scan held the same records transiently, once per concurrent lookup.

use super::{
    now_ms_chirho, privacy_blob_records_path_chirho, validate_existing_key_subject_for_chirho,
    validate_key_id_chirho, validate_subject_chirho, PrivacyBlobRecordChirho, PrivateBlobRefChirho,
};
use crate::model_chirho::HashChirho;
use anyhow::{anyhow, bail, Result};
use cairn_verified_prefix_view_chirho::{
    drop_view_chirho, with_current_view_chirho, PrefixLogChirho, RegistryChirho,
    UpdateStatusChirho, ViewRulesChirho,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The blob log's index: each ciphertext's logged refs and subjects in log order, and each key id's subject.
#[derive(Default)]
pub(super) struct BlobIndexChirho {
    by_ciphertext_chirho: HashMap<HashChirho, Vec<(PrivateBlobRefChirho, String)>>,
    key_subjects_chirho: HashMap<String, String>,
}

impl BlobIndexChirho {
    /// The subject of the FIRST record carrying exactly this ref. An equal ref has an equal ciphertext, so the first
    /// match in its bucket is the first match in the log, compared with the ref's own `==`, never a narrower key.
    fn first_subject_chirho(&self, blob_chirho: &PrivateBlobRefChirho) -> Option<String> {
        self.by_ciphertext_chirho
            .get(&blob_chirho.ciphertext_chirho)?
            .iter()
            .find(|(logged_chirho, _)| logged_chirho == blob_chirho)
            .map(|(_, subject_chirho)| subject_chirho.clone())
    }
}

/// Every root's blob view, one slot per log.
static BLOB_REGISTRY_CHIRHO: RegistryChirho<BlobIndexChirho> = RegistryChirho::new_chirho();

/// The whole verified prefix, every key file included, is re-verified in the background at this interval.
pub(super) const BLOB_FULL_VERIFY_EVERY_MS_CHIRHO: u64 = 60 * 60 * 1000;

#[cfg(not(any(test, feature = "serve-runtime-test-hooks-chirho")))]
const BLOB_SLOT_CAP_CHIRHO: usize = 32;
// Parallel tests each use their own root; a large cap keeps them from evicting each other.
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
const BLOB_SLOT_CAP_CHIRHO: usize = 8192;

pub(super) fn blob_view_rules_chirho() -> ViewRulesChirho {
    ViewRulesChirho {
        full_verify_every_ms_chirho: BLOB_FULL_VERIFY_EVERY_MS_CHIRHO,
        slot_cap_chirho: BLOB_SLOT_CAP_CHIRHO,
    }
}

#[derive(Clone)]
struct BlobLogChirho {
    root_chirho: PathBuf,
    path_chirho: PathBuf,
}

impl BlobLogChirho {
    fn new_chirho(root_chirho: &Path) -> Self {
        Self {
            root_chirho: root_chirho.to_path_buf(),
            path_chirho: privacy_blob_records_path_chirho(root_chirho),
        }
    }
}

impl PrefixLogChirho for BlobLogChirho {
    type RecordChirho = PrivacyBlobRecordChirho;
    type IndexChirho = BlobIndexChirho;
    type JobLogChirho = BlobLogChirho;

    fn job_log_chirho(&self) -> BlobLogChirho {
        self.clone()
    }

    fn path_chirho(&self) -> &Path {
        &self.path_chirho
    }

    /// The namespace checks use no verification key. Change this name when the fold's checks change.
    fn verifier_id_chirho(&self) -> &str {
        "privacy-blob-namespace-v1-chirho"
    }

    fn registry_chirho(&self) -> &'static RegistryChirho<BlobIndexChirho> {
        &BLOB_REGISTRY_CHIRHO
    }

    /// The full scan's parse, with its message.
    fn parse_chirho(&self, line_chirho: &str) -> Result<PrivacyBlobRecordChirho> {
        serde_json::from_str(line_chirho)
            .map_err(|error_chirho| anyhow!("bad privacy blob record: {error_chirho}"))
    }

    /// The full scan's checks (a) to (c) for one record, with their messages, in the full scan's order for one
    /// record. The sequence number is not checked: the lookup this replaces never checked it.
    fn verify_and_fold_chirho(
        &self,
        index_chirho: &mut BlobIndexChirho,
        record_chirho: PrivacyBlobRecordChirho,
        _expected_seq_chirho: u64,
    ) -> Result<()> {
        let key_id_chirho = &record_chirho.blob_chirho.key_id_chirho;
        validate_subject_chirho(&record_chirho.subject_chirho)?;
        validate_key_id_chirho(key_id_chirho)?;
        if let Some(existing_subject_chirho) = index_chirho.key_subjects_chirho.get(key_id_chirho) {
            if existing_subject_chirho != &record_chirho.subject_chirho {
                bail!(
                    "private blob key {} is claimed by multiple subjects: '{}' and '{}'",
                    key_id_chirho,
                    existing_subject_chirho,
                    record_chirho.subject_chirho
                );
            }
        }
        validate_existing_key_subject_for_chirho(
            &self.root_chirho,
            key_id_chirho,
            &record_chirho.subject_chirho,
        )?;
        index_chirho
            .key_subjects_chirho
            .entry(key_id_chirho.clone())
            .or_insert_with(|| record_chirho.subject_chirho.clone());
        index_chirho
            .by_ciphertext_chirho
            .entry(record_chirho.blob_chirho.ciphertext_chirho.clone())
            .or_default()
            .push((record_chirho.blob_chirho, record_chirho.subject_chirho));
        Ok(())
    }

    fn job_thread_name_chirho(&self) -> &'static str {
        "cairn-blob-view-job-chirho"
    }
}

/// The subject named by the FIRST privacy blob record carrying exactly this ref, from the current verified view,
/// with that ref's key file re-checked.
pub(super) fn logged_blob_subject_chirho(
    root_chirho: &Path,
    blob_chirho: &PrivateBlobRefChirho,
) -> Result<String> {
    logged_blob_subject_with_chirho(
        root_chirho,
        blob_chirho,
        &blob_view_rules_chirho(),
        now_ms_chirho,
    )
    .map(|(subject_chirho, _status_chirho)| subject_chirho)
}

/// `logged_blob_subject_chirho` with its rules and clock given, and the view's update status returned: the tests'
/// door to the integrity pass and its interval.
pub(super) fn logged_blob_subject_with_chirho(
    root_chirho: &Path,
    blob_chirho: &PrivateBlobRefChirho,
    rules_chirho: &ViewRulesChirho,
    clock_chirho: impl FnOnce() -> u64,
) -> Result<(String, UpdateStatusChirho)> {
    let log_chirho = BlobLogChirho::new_chirho(root_chirho);
    let (subject_chirho, status_chirho) = with_current_view_chirho(
        &log_chirho,
        rules_chirho,
        clock_chirho,
        |index_chirho, _| {
            index_chirho.and_then(|index_chirho| index_chirho.first_subject_chirho(blob_chirho))
        },
    )?;
    #[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
    private_blob_view_metrics_chirho::note_lookup_chirho(&status_chirho);
    let subject_chirho = subject_chirho.ok_or_else(|| {
        anyhow!(
            "private blob ref {} is not represented in the privacy blob log",
            blob_chirho.ciphertext_chirho.0
        )
    })?;
    // Check (c) for the target key, on every lookup. A failure is an inconsistency in the root, so the view drops
    // and the next lookup, whatever its ref, verifies everything again and refuses, as the full scan did.
    if let Err(error_chirho) = validate_existing_key_subject_for_chirho(
        root_chirho,
        &blob_chirho.key_id_chirho,
        &subject_chirho,
    ) {
        drop_view_chirho(&log_chirho);
        return Err(error_chirho);
    }
    Ok((subject_chirho, status_chirho))
}

/// Bring the root's blob view current and return how many records it has verified. The store path's gate: it runs
/// under the blob log's append lock, before the seqlog's recovery, so a store refuses exactly when a lookup would.
pub(super) fn current_blob_record_count_chirho(root_chirho: &Path) -> Result<u64> {
    let ((), status_chirho) = with_current_view_chirho(
        &BlobLogChirho::new_chirho(root_chirho),
        &blob_view_rules_chirho(),
        now_ms_chirho,
        |_, _| (),
    )?;
    #[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
    private_blob_view_metrics_chirho::note_update_chirho(&status_chirho);
    Ok(status_chirho.verified_records_chirho)
}

/// Build the root's blob view now, so the first lookups find it ready. The serve runtime calls this on a background
/// thread after it binds. It verifies the whole log and every key file, as the first lookup otherwise would.
pub fn warm_private_blob_view_chirho(root_chirho: &Path) -> Result<()> {
    current_blob_record_count_chirho(root_chirho).map(|_| ())
}

/// Warm the root's blob view on its own thread: the serve runtime calls this after it binds (agy #25781 (a')). A
/// failure is not fatal, since lookups and stores refuse on their own until the log verifies. The line it prints names
/// no record, key or subject; the operator's privacy-verify command shows the details.
pub fn spawn_private_blob_view_warm_up_chirho(root_chirho: &Path) {
    let root_chirho = root_chirho.to_path_buf();
    let spawned_chirho = std::thread::Builder::new()
        .name("cairn-blob-view-warm-chirho".to_string())
        .spawn(move || {
            if warm_private_blob_view_chirho(&root_chirho).is_err() {
                eprintln!(
                    "cairn-chirho: the privacy blob log did not verify at startup; private lookups and stores \
                     refuse until it does (privacy-verify shows why)"
                );
            }
        });
    if spawned_chirho.is_err() {
        eprintln!("cairn-chirho: the privacy blob view warm-up did not start; the first private lookup builds it");
    }
}

/// What the blob road did on the calling thread, for the growth arms. In the `serve-runtime-test-hooks-chirho`
/// family. Thread-local, so parallel tests with their own roots never perturb one another's counts; the background
/// integrity pass runs on its own thread and is not counted.
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
pub mod private_blob_view_metrics_chirho {
    use cairn_verified_prefix_view_chirho::{PathTakenChirho, UpdateStatusChirho};
    use std::cell::Cell;

    /// One thread's blob-road work since the last reset.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct BlobRoadCountsChirho {
        /// Ref-to-subject lookups answered by the view.
        pub lookups_chirho: u64,
        /// Whole-log reads: the view built from the whole log, or a full typed load of it (the audit loader).
        pub full_log_loads_chirho: u64,
        /// Records the view verified and folded: the appended delta, or the whole log on a full build.
        pub records_folded_chirho: u64,
        /// Shred-key files read through the key loader: the fold's (c), the target check, and decryption.
        pub key_file_reads_chirho: u64,
    }

    thread_local! {
        static COUNTS_CHIRHO: Cell<BlobRoadCountsChirho> = const {
            Cell::new(BlobRoadCountsChirho {
                lookups_chirho: 0,
                full_log_loads_chirho: 0,
                records_folded_chirho: 0,
                key_file_reads_chirho: 0,
            })
        };
    }

    pub fn reset_chirho() {
        COUNTS_CHIRHO.with(|cell_chirho| cell_chirho.set(BlobRoadCountsChirho::default()));
    }

    pub fn counts_chirho() -> BlobRoadCountsChirho {
        COUNTS_CHIRHO.with(Cell::get)
    }

    /// Add work counted on another thread, such as a served run's blocking-pool thread, to this thread's counts. The
    /// destructuring is exhaustive, so a new field cannot be left out.
    pub fn absorb_chirho(other_chirho: BlobRoadCountsChirho) {
        let BlobRoadCountsChirho {
            lookups_chirho,
            full_log_loads_chirho,
            records_folded_chirho,
            key_file_reads_chirho,
        } = other_chirho;
        change_chirho(|counts_chirho| {
            counts_chirho.lookups_chirho += lookups_chirho;
            counts_chirho.full_log_loads_chirho += full_log_loads_chirho;
            counts_chirho.records_folded_chirho += records_folded_chirho;
            counts_chirho.key_file_reads_chirho += key_file_reads_chirho;
        });
    }

    fn change_chirho(change_chirho: impl FnOnce(&mut BlobRoadCountsChirho)) {
        COUNTS_CHIRHO.with(|cell_chirho| {
            let mut counts_chirho = cell_chirho.get();
            change_chirho(&mut counts_chirho);
            cell_chirho.set(counts_chirho);
        });
    }

    pub(in crate::privacy_chirho) fn note_lookup_chirho(status_chirho: &UpdateStatusChirho) {
        change_chirho(|counts_chirho| counts_chirho.lookups_chirho += 1);
        note_update_chirho(status_chirho);
    }

    pub(in crate::privacy_chirho) fn note_update_chirho(status_chirho: &UpdateStatusChirho) {
        change_chirho(|counts_chirho| match status_chirho.path_chirho {
            PathTakenChirho::MissingLogChirho | PathTakenChirho::UnchangedChirho => {}
            PathTakenChirho::IncrementalChirho { folded_chirho } => {
                counts_chirho.records_folded_chirho += folded_chirho;
            }
            PathTakenChirho::FullFromFallbackChirho {
                verified_chirho, ..
            } => {
                counts_chirho.full_log_loads_chirho += 1;
                counts_chirho.records_folded_chirho += verified_chirho;
            }
        });
    }

    pub(in crate::privacy_chirho) fn note_full_log_load_chirho() {
        change_chirho(|counts_chirho| counts_chirho.full_log_loads_chirho += 1);
    }

    pub(in crate::privacy_chirho) fn note_key_file_read_chirho() {
        change_chirho(|counts_chirho| counts_chirho.key_file_reads_chirho += 1);
    }
}
