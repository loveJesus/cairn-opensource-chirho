// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The private-value log as an incremental, parsed INDEX (checkpoint brick S2), so the records claiming a value hash,
//! or a (subject, value hash) pair, come from memory plus only the records appended since the last call, instead of a
//! whole-log load per lookup.
//!
//! Design: `spec-chirho/workflows-chirho/perf-chirho/execution-checkpoint-brick-design-chirho.md`, section S2.
//! - **It indexes; it does not verify.** A lookup still runs the unchanged per-record check on its claiming records
//!   (schema, subject, blob ownership through S1's blob view, signature), usually one, with the signing key read only
//!   when a record claims the value, exactly as the whole-log resolver did. No verdict is cached here, so a refusal is
//!   always produced by freshly run code and a repaired key file is seen on the next lookup.
//! - **A line that does not parse refuses**, as the whole-log loader did; the engine then drops the view, so every
//!   lookup refuses until the line is gone. A final line without its newline that does not parse is waited out (the
//!   engine's rule): a write in flight, or a torn tail the next store's recovery truncates.
//! - **A store refuses exactly when a lookup would** (the S1 rule, PFE #25789, agy #25796). The store path brings this
//!   index current under the log's append lock, BEFORE the seqlog's recovery, so a complete bad line stays in the log.
//! - **Claims are read out ONE AT A TIME, in the lookup's order.** The store does not deduplicate, and a replayed read
//!   stores its viewer-state response again (PFE measured one value per replayed read), so each identical read adds
//!   a claim on the same pair, until checkpoint brick S5 stops reads from storing. A lookup whose first claim
//!   verifies therefore copies out one record however many claim its key. A later claim is fetched by its place among
//!   the key's claims, which an append-only log never moves; if that place has vanished, the log changed shape during
//!   the lookup, and the lookup refuses.
//! - **Memory:** the index keeps every parsed record, about half a kilobyte each, as S1's blob index keeps a ref and a
//!   subject for every blob record. The whole-log loader held the same records transiently, once per concurrent
//!   lookup.

use super::{private_dag_values_path_chirho, PrivateDagValueRecordChirho};
use crate::model_chirho::HashChirho;
use anyhow::{anyhow, Context, Result};
use cairn_verified_prefix_view_chirho::{
    with_current_view_chirho, PrefixLogChirho, RegistryChirho, ViewRulesChirho,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The private-value log's index: every parsed record in log order, with the log positions of each value hash and
/// of each (subject, value hash) pair.
#[derive(Default)]
pub(super) struct ValueIndexChirho {
    records_chirho: Vec<PrivateDagValueRecordChirho>,
    by_hash_chirho: HashMap<HashChirho, Vec<usize>>,
    by_pair_chirho: HashMap<(String, HashChirho), Vec<usize>>,
}

impl ValueIndexChirho {
    /// The log positions of the records claiming a key, in log order.
    fn positions_chirho(&self, key_chirho: &ClaimKeyChirho) -> &[usize] {
        let positions_chirho = match key_chirho {
            ClaimKeyChirho::HashChirho(hash_chirho) => self.by_hash_chirho.get(hash_chirho),
            ClaimKeyChirho::PairChirho(pair_chirho) => self.by_pair_chirho.get(pair_chirho),
        };
        positions_chirho.map_or(&[], Vec::as_slice)
    }
}

/// What a lookup asks about: the records claiming a value hash, or a (subject, value hash) pair.
pub(super) enum ClaimKeyChirho {
    HashChirho(HashChirho),
    PairChirho((String, HashChirho)),
}

/// The order a lookup tries its claims in: the hash lookup earliest first, the subject lookup latest first.
#[derive(Clone, Copy)]
pub(super) enum ClaimOrderChirho {
    EarliestFirstChirho,
    LatestFirstChirho,
}

/// Every root's value index, one slot per log.
static VALUE_REGISTRY_CHIRHO: RegistryChirho<ValueIndexChirho> = RegistryChirho::new_chirho();

/// The parsed prefix is re-parsed in the background at this interval.
const VALUE_FULL_VERIFY_EVERY_MS_CHIRHO: u64 = 60 * 60 * 1000;

#[cfg(not(any(test, feature = "serve-runtime-test-hooks-chirho")))]
const VALUE_SLOT_CAP_CHIRHO: usize = 32;
// Parallel tests each use their own root; a large cap keeps them from evicting each other.
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
const VALUE_SLOT_CAP_CHIRHO: usize = 8192;

fn value_view_rules_chirho() -> ViewRulesChirho {
    ViewRulesChirho {
        full_verify_every_ms_chirho: VALUE_FULL_VERIFY_EVERY_MS_CHIRHO,
        slot_cap_chirho: VALUE_SLOT_CAP_CHIRHO,
    }
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Clone)]
struct ValueLogChirho {
    path_chirho: PathBuf,
}

impl PrefixLogChirho for ValueLogChirho {
    type RecordChirho = PrivateDagValueRecordChirho;
    type IndexChirho = ValueIndexChirho;
    type JobLogChirho = ValueLogChirho;

    fn job_log_chirho(&self) -> ValueLogChirho {
        self.clone()
    }

    fn path_chirho(&self) -> &Path {
        &self.path_chirho
    }

    /// The index parses and positions records; it verifies none, so it depends on no key.
    fn verifier_id_chirho(&self) -> &str {
        "private-dag-value-index-v1-chirho"
    }

    fn registry_chirho(&self) -> &'static RegistryChirho<ValueIndexChirho> {
        &VALUE_REGISTRY_CHIRHO
    }

    /// The whole-log loader's parse, with its message.
    fn parse_chirho(&self, line_chirho: &str) -> Result<PrivateDagValueRecordChirho> {
        serde_json::from_str(line_chirho).context("decode PrivateDagValueRecordChirho")
    }

    fn verify_and_fold_chirho(
        &self,
        index_chirho: &mut ValueIndexChirho,
        record_chirho: PrivateDagValueRecordChirho,
        _expected_seq_chirho: u64,
    ) -> Result<()> {
        let position_chirho = index_chirho.records_chirho.len();
        index_chirho
            .by_hash_chirho
            .entry(record_chirho.value_hash_chirho.clone())
            .or_default()
            .push(position_chirho);
        index_chirho
            .by_pair_chirho
            .entry((
                record_chirho.subject_chirho.clone(),
                record_chirho.value_hash_chirho.clone(),
            ))
            .or_default()
            .push(position_chirho);
        index_chirho.records_chirho.push(record_chirho);
        Ok(())
    }

    fn job_thread_name_chirho(&self) -> &'static str {
        "cairn-value-view-job-chirho"
    }
}

/// Read the current index under its lock. The closure only copies out: it must not call back into the engine.
fn with_index_chirho<T>(
    root_chirho: &Path,
    read_chirho: impl FnOnce(Option<&ValueIndexChirho>) -> T,
) -> Result<T> {
    let (value_chirho, status_chirho) = with_current_view_chirho(
        &ValueLogChirho {
            path_chirho: private_dag_values_path_chirho(root_chirho),
        },
        &value_view_rules_chirho(),
        now_ms_chirho,
        |index_chirho, _now_ms_chirho| read_chirho(index_chirho),
    )?;
    #[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
    private_value_view_metrics_chirho::note_update_chirho(&status_chirho);
    let _ = status_chirho;
    Ok(value_chirho)
}

/// The records claiming one key, read out one at a time in the lookup's order. Opening the reader counts the key's
/// claims and copies out the first; each later claim is fetched by its place among them, so a lookup whose first
/// claim verifies copies out one record. The count is fixed when the reader opens: a record appended during the
/// lookup is not among its claims, as it was not in the whole-log loader's snapshot.
pub(super) struct ClaimsChirho<'a> {
    root_chirho: &'a Path,
    key_chirho: ClaimKeyChirho,
    order_chirho: ClaimOrderChirho,
    count_chirho: usize,
    next_rank_chirho: usize,
    first_chirho: Option<PrivateDagValueRecordChirho>,
}

impl ClaimsChirho<'_> {
    pub(super) fn is_empty(&self) -> bool {
        self.count_chirho == 0
    }

    /// The place, among the key's claims in log order, of the claim tried at `rank`.
    fn ordinal_chirho(&self, rank_chirho: usize) -> usize {
        match self.order_chirho {
            ClaimOrderChirho::EarliestFirstChirho => rank_chirho,
            ClaimOrderChirho::LatestFirstChirho => self.count_chirho - 1 - rank_chirho,
        }
    }
}

impl Iterator for ClaimsChirho<'_> {
    type Item = Result<PrivateDagValueRecordChirho>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_rank_chirho >= self.count_chirho {
            return None;
        }
        let rank_chirho = self.next_rank_chirho;
        self.next_rank_chirho += 1;
        if let Some(first_chirho) = self.first_chirho.take() {
            return Some(Ok(first_chirho));
        }
        Some(claim_at_chirho(
            self.root_chirho,
            &self.key_chirho,
            self.ordinal_chirho(rank_chirho),
        ))
    }
}

/// Open a claims reader on a key: one index read that counts the claims and copies out the first in `order`.
pub(super) fn claims_chirho(
    root_chirho: &Path,
    key_chirho: ClaimKeyChirho,
    order_chirho: ClaimOrderChirho,
) -> Result<ClaimsChirho<'_>> {
    #[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
    private_value_view_metrics_chirho::note_lookup_chirho();
    let (count_chirho, first_chirho) = with_index_chirho(root_chirho, |index_chirho| {
        let Some(index_chirho) = index_chirho else {
            return (0, None);
        };
        let positions_chirho = index_chirho.positions_chirho(&key_chirho);
        let first_position_chirho = match order_chirho {
            ClaimOrderChirho::EarliestFirstChirho => positions_chirho.first(),
            ClaimOrderChirho::LatestFirstChirho => positions_chirho.last(),
        };
        (
            positions_chirho.len(),
            first_position_chirho
                .map(|&position_chirho| index_chirho.records_chirho[position_chirho].clone()),
        )
    })?;
    #[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
    if first_chirho.is_some() {
        private_value_view_metrics_chirho::note_copy_chirho();
    }
    Ok(ClaimsChirho {
        root_chirho,
        key_chirho,
        order_chirho,
        count_chirho,
        next_rank_chirho: 0,
        first_chirho,
    })
}

/// The claim at one place among a key's claims, in log order.
fn claim_at_chirho(
    root_chirho: &Path,
    key_chirho: &ClaimKeyChirho,
    ordinal_chirho: usize,
) -> Result<PrivateDagValueRecordChirho> {
    let claim_chirho = with_index_chirho(root_chirho, |index_chirho| {
        index_chirho.and_then(|index_chirho| {
            index_chirho
                .positions_chirho(key_chirho)
                .get(ordinal_chirho)
                .map(|&position_chirho| index_chirho.records_chirho[position_chirho].clone())
        })
    })?;
    #[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
    if claim_chirho.is_some() {
        private_value_view_metrics_chirho::note_copy_chirho();
    }
    claim_chirho.ok_or_else(|| {
        anyhow!(
            "the private-value log changed shape during this lookup; refusing to answer from it"
        )
    })
}

/// How many records claim one key, copying none out: the presence checks.
pub(super) fn claim_count_chirho(root_chirho: &Path, key_chirho: ClaimKeyChirho) -> Result<usize> {
    #[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
    private_value_view_metrics_chirho::note_lookup_chirho();
    with_index_chirho(root_chirho, |index_chirho| {
        index_chirho.map_or(0, |index_chirho| {
            index_chirho.positions_chirho(&key_chirho).len()
        })
    })
}

/// Every record, in log order: the display listing's input, which verifies each one by design.
pub(super) fn all_records_chirho(root_chirho: &Path) -> Result<Vec<PrivateDagValueRecordChirho>> {
    with_index_chirho(root_chirho, |index_chirho| {
        index_chirho.map_or_else(Vec::new, |index_chirho| index_chirho.records_chirho.clone())
    })
}

/// Bring the index current and return how many records it holds: the store path's gate, run under the log's append
/// lock before the seqlog's recovery, so a store refuses exactly when a lookup would.
pub(super) fn current_value_record_count_chirho(root_chirho: &Path) -> Result<u64> {
    with_index_chirho(root_chirho, |index_chirho| {
        index_chirho.map_or(0, |index_chirho| index_chirho.records_chirho.len() as u64)
    })
}

/// Build the root's value index now, so the first lookups find it ready; for the serve runtime's warm-up thread.
pub fn warm_private_value_view_chirho(root_chirho: &Path) -> Result<()> {
    current_value_record_count_chirho(root_chirho).map(|_| ())
}

/// Warm the root's value index on its own thread: the serve runtime calls this after it binds, beside the blob
/// view's warm-up. A failure is not fatal: lookups and stores refuse on their own until the log parses. The line it
/// prints names no record, value or subject.
pub fn spawn_private_value_view_warm_up_chirho(root_chirho: &Path) {
    let root_chirho = root_chirho.to_path_buf();
    let spawned_chirho = std::thread::Builder::new()
        .name("cairn-value-view-warm-chirho".to_string())
        .spawn(move || {
            if warm_private_value_view_chirho(&root_chirho).is_err() {
                eprintln!(
                    "cairn-chirho: the private-value log did not parse at startup; private lookups and stores refuse \
                     until it does (privacy-verify shows why)"
                );
            }
        });
    if spawned_chirho.is_err() {
        eprintln!("cairn-chirho: the private-value index warm-up did not start; the first lookup builds it");
    }
}

/// What the value road did on the calling thread, for the growth arms. In the `serve-runtime-test-hooks-chirho`
/// family. Thread-local, so parallel tests with their own roots never perturb one another; the background integrity
/// pass runs on its own thread and is not counted.
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
pub mod private_value_view_metrics_chirho {
    use cairn_verified_prefix_view_chirho::{PathTakenChirho, UpdateStatusChirho};
    use std::cell::Cell;

    /// One thread's value-road work since the last reset.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct ValueRoadCountsChirho {
        /// Claim lookups answered by the index.
        pub lookups_chirho: u64,
        /// Whole-log reads: the index built from the whole log.
        pub full_log_loads_chirho: u64,
        /// Records parsed and folded: the appended delta, or the whole log on a full build.
        pub records_folded_chirho: u64,
        /// Records copied out of the index to be verified: one per claim a lookup tries.
        pub claims_copied_chirho: u64,
    }

    thread_local! {
        static COUNTS_CHIRHO: Cell<ValueRoadCountsChirho> = const {
            Cell::new(ValueRoadCountsChirho {
                lookups_chirho: 0,
                full_log_loads_chirho: 0,
                records_folded_chirho: 0,
                claims_copied_chirho: 0,
            })
        };
    }

    pub fn reset_chirho() {
        COUNTS_CHIRHO.with(|cell_chirho| cell_chirho.set(ValueRoadCountsChirho::default()));
    }

    pub fn counts_chirho() -> ValueRoadCountsChirho {
        COUNTS_CHIRHO.with(Cell::get)
    }

    /// Add work counted on another thread, such as a served run's blocking-pool thread, to this thread's counts. The
    /// destructuring is exhaustive, so a new field cannot be left out.
    pub fn absorb_chirho(other_chirho: ValueRoadCountsChirho) {
        let ValueRoadCountsChirho {
            lookups_chirho,
            full_log_loads_chirho,
            records_folded_chirho,
            claims_copied_chirho,
        } = other_chirho;
        change_chirho(|counts_chirho| {
            counts_chirho.lookups_chirho += lookups_chirho;
            counts_chirho.full_log_loads_chirho += full_log_loads_chirho;
            counts_chirho.records_folded_chirho += records_folded_chirho;
            counts_chirho.claims_copied_chirho += claims_copied_chirho;
        });
    }

    fn change_chirho(change_chirho: impl FnOnce(&mut ValueRoadCountsChirho)) {
        COUNTS_CHIRHO.with(|cell_chirho| {
            let mut counts_chirho = cell_chirho.get();
            change_chirho(&mut counts_chirho);
            cell_chirho.set(counts_chirho);
        });
    }

    pub(in crate::dag_private_value_chirho) fn note_lookup_chirho() {
        change_chirho(|counts_chirho| counts_chirho.lookups_chirho += 1);
    }

    pub(in crate::dag_private_value_chirho) fn note_copy_chirho() {
        change_chirho(|counts_chirho| counts_chirho.claims_copied_chirho += 1);
    }

    pub(in crate::dag_private_value_chirho) fn note_update_chirho(
        status_chirho: &UpdateStatusChirho,
    ) {
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
}

#[cfg(test)]
#[path = "value_view_tests_chirho.rs"]
mod value_view_tests_chirho;
