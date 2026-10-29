// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Process-global, stat-fingerprint-invalidated cache of fully verified app control-plane views so a warm serve request re-verifies nothing.
//!
//! Before any cached field is accepted, every fingerprinted file is examined without following a link: a link, a
//! directory, a pipe or an examination error refuses, and so does a file this root's entry saw present that is now
//! missing. That second memory lives as long as the root's entry, a bounded cache entry in this process; it is not
//! durable completeness across eviction or a fresh process.
//!
//! Boundary: the (dev, ino, len, mtime_ns, mode, ctime_ns) fingerprint invalidates on every normal control-plane
//! change. A same-LENGTH in-place tamper keeps the fingerprint only if it also forges mtime_ns AND ctime_ns back to
//! their originals. ctime is set by the kernel on every change and no timestamp call restores it, so that means setting
//! the clock back or writing beneath the filesystem. Even then only the STALE-but-previously-VERIFIED view would be
//! served (never an unverified one: only fully verified results are ever cached). That is past this perf cache's threat
//! model; it is a performance cache, not an integrity mechanism, and full re-verification (any miss, verify commands,
//! audits) remains the integrity layer. A content hash here would defeat "warm = zero log reads".

use anyhow::{Context, Result};
use cairn_durable_chirho::log_path_chirho::{classify_log_path_chirho, LogPathChirho};
use cairn_model_app_chirho::{
    AppInputPolicyRecordChirho, AppParamsRecordChirho, AppRecordChirho,
    AppRequestAccessPolicyRecordChirho, AppResponsePolicyRecordChirho, AppRouteRecordChirho,
    AppRouteResponsePolicyRecordChirho, AppStaticAssetRecordChirho,
};
use cairn_model_identity_chirho::PrincipalKindChirho;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// Log/state files whose bytes gate a verification or selection result; any stat change drops the
/// whole root entry. CAS objects are content-addressed and therefore exempt. Missing file = a
/// distinct state, not an error (its slot fingerprints as `None`).
const FINGERPRINT_FILES_CHIRHO: &[&str] = &[
    "app-records-chirho.jsonl",
    "app-route-records-chirho.jsonl",
    "app-input-policy-records-chirho.jsonl",
    "app-request-access-policy-records-chirho.jsonl",
    "app-response-policy-records-chirho.jsonl",
    "app-route-response-policy-records-chirho.jsonl",
    "app-params-records-chirho.jsonl",
    "app-static-asset-records-chirho.jsonl",
    "domain-bindings-chirho.jsonl",
    "identities-chirho.jsonl",
    "refs-chirho.json",
    "reflog-chirho.jsonl",
    "head-removals-chirho.jsonl",
    "pubkey-chirho.hex",
];

#[cfg(not(any(test, feature = "test-hooks-chirho")))]
const ROOT_VERIFIED_VIEW_CAP_CHIRHO: usize = 32;
// Tests run in parallel with their own temp roots; a large cap keeps concurrent roots from evicting
// each other so warm-count assertions stay deterministic. Eviction logic is unit-tested directly.
#[cfg(any(test, feature = "test-hooks-chirho"))]
const ROOT_VERIFIED_VIEW_CAP_CHIRHO: usize = 8192;

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileStatChirho {
    dev_chirho: u64,
    ino_chirho: u64,
    len_chirho: u64,
    mtime_ns_chirho: i128,
    /// Access rights and the change time: a permission changed in place, on the same inode with the same length and
    /// modification time, is a new state, so a cached field never outlives an open that now fails.
    mode_chirho: u32,
    ctime_ns_chirho: i128,
}

/// Stat tuple of every mutable file consulted during verification/selection, in fixed order.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RootFingerprintChirho {
    slots_chirho: Vec<Option<FileStatChirho>>,
}

/// One fingerprinted file's stat, examined without following a link: `None` only for a genuine absence, and an error
/// for anything the engine cannot examine.
fn file_stat_chirho(path_chirho: &Path) -> Result<Option<FileStatChirho>> {
    let metadata_chirho = match classify_log_path_chirho(path_chirho)
        .with_context(|| format!("examine {}", path_chirho.display()))?
    {
        LogPathChirho::AbsentChirho => return Ok(None),
        LogPathChirho::PresentChirho(metadata_chirho) => metadata_chirho,
    };
    let mtime_ns_chirho = metadata_chirho
        .modified()
        .ok()
        .and_then(|time_chirho| {
            time_chirho
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d_chirho| d_chirho.as_nanos() as i128)
                .or_else(|| {
                    std::time::UNIX_EPOCH
                        .duration_since(time_chirho)
                        .ok()
                        .map(|d_chirho| -(d_chirho.as_nanos() as i128))
                })
        })
        .unwrap_or(0);
    #[cfg(unix)]
    let (dev_chirho, ino_chirho, mode_chirho, ctime_ns_chirho) = {
        use std::os::unix::fs::MetadataExt;
        (
            metadata_chirho.dev(),
            metadata_chirho.ino(),
            metadata_chirho.mode(),
            i128::from(metadata_chirho.ctime()) * 1_000_000_000
                + i128::from(metadata_chirho.ctime_nsec()),
        )
    };
    #[cfg(not(unix))]
    let (dev_chirho, ino_chirho, mode_chirho, ctime_ns_chirho) = (0u64, 0u64, 0u32, 0i128);
    Ok(Some(FileStatChirho {
        dev_chirho,
        ino_chirho,
        len_chirho: metadata_chirho.len(),
        mtime_ns_chirho,
        mode_chirho,
        ctime_ns_chirho,
    }))
}

fn root_fingerprint_chirho(root_chirho: &Path) -> Result<RootFingerprintChirho> {
    Ok(RootFingerprintChirho {
        slots_chirho: FINGERPRINT_FILES_CHIRHO
            .iter()
            .map(|name_chirho| file_stat_chirho(&root_chirho.join(name_chirho)))
            .collect::<Result<_>>()?,
    })
}

/// A file this root's entry saw present that now reads as absent refuses: it is never taken for a fresh, empty log.
fn refuse_vanished_chirho(
    root_chirho: &Path,
    seen_chirho: &RootFingerprintChirho,
    now_chirho: &RootFingerprintChirho,
) -> Result<()> {
    for (index_chirho, name_chirho) in FINGERPRINT_FILES_CHIRHO.iter().enumerate() {
        if seen_chirho.slots_chirho[index_chirho].is_some()
            && now_chirho.slots_chirho[index_chirho].is_none()
        {
            anyhow::bail!(
                "{} was present and is now missing: a log seen present is refused, never read as empty",
                root_chirho.join(name_chirho).display()
            );
        }
    }
    Ok(())
}

fn canonical_key_chirho(root_chirho: &Path) -> PathBuf {
    std::fs::canonicalize(root_chirho).unwrap_or_else(|_| root_chirho.to_path_buf())
}

/// Selection inputs a verified route record is a pure function of, alongside the root fingerprint.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SelectedRouteKeyChirho {
    pub app_chirho: String,
    pub route_chirho: String,
    pub app_ref_dag_chirho: String,
    pub route_ref_target_chirho: String,
    pub owner_principal_chirho: String,
}

/// Selection inputs a verified app record is a pure function of, alongside the root fingerprint.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SelectedAppKeyChirho {
    pub app_chirho: String,
    pub app_ref_dag_chirho: String,
}

struct RootVerifiedViewChirho {
    fingerprint_chirho: RootFingerprintChirho,
    last_tick_chirho: u64,
    app_records_chirho: Option<Arc<Vec<AppRecordChirho>>>,
    app_route_records_chirho: Option<Arc<Vec<AppRouteRecordChirho>>>,
    input_policy_records_chirho: Option<Arc<Vec<AppInputPolicyRecordChirho>>>,
    request_access_policy_records_chirho: Option<Arc<Vec<AppRequestAccessPolicyRecordChirho>>>,
    response_policy_records_chirho: Option<Arc<Vec<AppResponsePolicyRecordChirho>>>,
    route_response_policy_records_chirho: Option<Arc<Vec<AppRouteResponsePolicyRecordChirho>>>,
    params_records_chirho: Option<Arc<Vec<AppParamsRecordChirho>>>,
    static_asset_records_chirho: Option<Arc<Vec<AppStaticAssetRecordChirho>>>,
    owner_map_chirho: Option<Arc<BTreeMap<String, String>>>,
    identity_kind_map_chirho: Option<Arc<BTreeMap<String, PrincipalKindChirho>>>,
    selected_route_records_chirho: BTreeMap<SelectedRouteKeyChirho, Arc<AppRouteRecordChirho>>,
    selected_app_records_chirho: BTreeMap<SelectedAppKeyChirho, Arc<AppRecordChirho>>,
}

impl RootVerifiedViewChirho {
    fn empty_chirho(fingerprint_chirho: RootFingerprintChirho, tick_chirho: u64) -> Self {
        Self {
            fingerprint_chirho,
            last_tick_chirho: tick_chirho,
            app_records_chirho: None,
            app_route_records_chirho: None,
            input_policy_records_chirho: None,
            request_access_policy_records_chirho: None,
            response_policy_records_chirho: None,
            route_response_policy_records_chirho: None,
            params_records_chirho: None,
            static_asset_records_chirho: None,
            owner_map_chirho: None,
            identity_kind_map_chirho: None,
            selected_route_records_chirho: BTreeMap::new(),
            selected_app_records_chirho: BTreeMap::new(),
        }
    }
}

struct VerifiedViewMapChirho {
    entries_chirho: HashMap<PathBuf, RootVerifiedViewChirho>,
    tick_chirho: u64,
}

fn cache_chirho() -> &'static Mutex<VerifiedViewMapChirho> {
    static CACHE_CHIRHO: OnceLock<Mutex<VerifiedViewMapChirho>> = OnceLock::new();
    CACHE_CHIRHO.get_or_init(|| {
        Mutex::new(VerifiedViewMapChirho {
            entries_chirho: HashMap::new(),
            tick_chirho: 0,
        })
    })
}

fn next_tick_chirho(map_chirho: &mut VerifiedViewMapChirho) -> u64 {
    map_chirho.tick_chirho = map_chirho.tick_chirho.wrapping_add(1);
    map_chirho.tick_chirho
}

/// Evict least-recently-used roots until a fresh `incoming_key` can be inserted within `cap`.
fn evict_to_fit_chirho(
    map_chirho: &mut VerifiedViewMapChirho,
    cap_chirho: usize,
    incoming_key_chirho: &Path,
) {
    while !map_chirho.entries_chirho.contains_key(incoming_key_chirho)
        && map_chirho.entries_chirho.len() >= cap_chirho
    {
        let victim_chirho = map_chirho
            .entries_chirho
            .iter()
            .min_by_key(|(_, entry_chirho)| entry_chirho.last_tick_chirho)
            .map(|(key_chirho, _)| key_chirho.clone());
        match victim_chirho {
            Some(victim_chirho) => {
                map_chirho.entries_chirho.remove(&victim_chirho);
            }
            None => break,
        }
    }
}

/// Return a fully verified per-log view, recomputing only when the root fingerprint changed.
///
/// The compute thunk runs the real load + verify; it is invoked only on a miss and only its result
/// (never a failure) is cached. The lock is never held across `compute_chirho`, so re-entrant cache
/// use (e.g. the owner map recomputing verified app records) cannot deadlock.
fn cached_field_chirho<T>(
    root_chirho: &Path,
    select_chirho: impl Fn(&RootVerifiedViewChirho) -> Option<Arc<T>>,
    store_chirho: impl Fn(&mut RootVerifiedViewChirho, Arc<T>),
    compute_chirho: impl FnOnce() -> Result<T>,
) -> Result<Arc<T>> {
    let key_chirho = canonical_key_chirho(root_chirho);
    // Refuses before any cached field is accepted, not only on a miss.
    let fingerprint_chirho = root_fingerprint_chirho(root_chirho)?;
    {
        let mut guard_chirho = cache_chirho().lock().unwrap();
        let tick_chirho = next_tick_chirho(&mut guard_chirho);
        if let Some(entry_chirho) = guard_chirho.entries_chirho.get_mut(&key_chirho) {
            refuse_vanished_chirho(
                root_chirho,
                &entry_chirho.fingerprint_chirho,
                &fingerprint_chirho,
            )?;
            if entry_chirho.fingerprint_chirho == fingerprint_chirho {
                entry_chirho.last_tick_chirho = tick_chirho;
                if let Some(value_chirho) = select_chirho(entry_chirho) {
                    return Ok(value_chirho);
                }
            }
        }
    }
    #[cfg(any(test, feature = "test-hooks-chirho"))]
    test_metrics_chirho::note_miss_chirho();
    let value_chirho = Arc::new(compute_chirho()?);
    if root_fingerprint_chirho(root_chirho).ok().as_ref() == Some(&fingerprint_chirho) {
        let mut guard_chirho = cache_chirho().lock().unwrap();
        let tick_chirho = next_tick_chirho(&mut guard_chirho);
        insert_field_chirho(
            &mut guard_chirho,
            &key_chirho,
            &fingerprint_chirho,
            tick_chirho,
            |entry_chirho| store_chirho(entry_chirho, value_chirho.clone()),
        );
    }
    Ok(value_chirho)
}

fn insert_field_chirho(
    guard_chirho: &mut VerifiedViewMapChirho,
    key_chirho: &Path,
    fingerprint_chirho: &RootFingerprintChirho,
    tick_chirho: u64,
    apply_chirho: impl FnOnce(&mut RootVerifiedViewChirho),
) {
    let stale_chirho = match guard_chirho.entries_chirho.get(key_chirho) {
        Some(entry_chirho) => &entry_chirho.fingerprint_chirho != fingerprint_chirho,
        None => true,
    };
    if stale_chirho {
        evict_to_fit_chirho(guard_chirho, ROOT_VERIFIED_VIEW_CAP_CHIRHO, key_chirho);
        guard_chirho.entries_chirho.insert(
            key_chirho.to_path_buf(),
            RootVerifiedViewChirho::empty_chirho(fingerprint_chirho.clone(), tick_chirho),
        );
    }
    let entry_chirho = guard_chirho.entries_chirho.get_mut(key_chirho).unwrap();
    entry_chirho.last_tick_chirho = tick_chirho;
    apply_chirho(entry_chirho);
}

pub fn cached_app_records_chirho(
    root_chirho: &Path,
    compute_chirho: impl FnOnce() -> Result<Vec<AppRecordChirho>>,
) -> Result<Arc<Vec<AppRecordChirho>>> {
    cached_field_chirho(
        root_chirho,
        |entry_chirho| entry_chirho.app_records_chirho.clone(),
        |entry_chirho, value_chirho| entry_chirho.app_records_chirho = Some(value_chirho),
        compute_chirho,
    )
}

pub fn cached_app_route_records_chirho(
    root_chirho: &Path,
    compute_chirho: impl FnOnce() -> Result<Vec<AppRouteRecordChirho>>,
) -> Result<Arc<Vec<AppRouteRecordChirho>>> {
    cached_field_chirho(
        root_chirho,
        |entry_chirho| entry_chirho.app_route_records_chirho.clone(),
        |entry_chirho, value_chirho| entry_chirho.app_route_records_chirho = Some(value_chirho),
        compute_chirho,
    )
}

pub fn cached_input_policy_records_chirho(
    root_chirho: &Path,
    compute_chirho: impl FnOnce() -> Result<Vec<AppInputPolicyRecordChirho>>,
) -> Result<Arc<Vec<AppInputPolicyRecordChirho>>> {
    cached_field_chirho(
        root_chirho,
        |entry_chirho| entry_chirho.input_policy_records_chirho.clone(),
        |entry_chirho, value_chirho| entry_chirho.input_policy_records_chirho = Some(value_chirho),
        compute_chirho,
    )
}

pub fn cached_request_access_policy_records_chirho(
    root_chirho: &Path,
    compute_chirho: impl FnOnce() -> Result<Vec<AppRequestAccessPolicyRecordChirho>>,
) -> Result<Arc<Vec<AppRequestAccessPolicyRecordChirho>>> {
    cached_field_chirho(
        root_chirho,
        |entry_chirho| entry_chirho.request_access_policy_records_chirho.clone(),
        |entry_chirho, value_chirho| {
            entry_chirho.request_access_policy_records_chirho = Some(value_chirho)
        },
        compute_chirho,
    )
}

pub fn cached_response_policy_records_chirho(
    root_chirho: &Path,
    compute_chirho: impl FnOnce() -> Result<Vec<AppResponsePolicyRecordChirho>>,
) -> Result<Arc<Vec<AppResponsePolicyRecordChirho>>> {
    cached_field_chirho(
        root_chirho,
        |entry_chirho| entry_chirho.response_policy_records_chirho.clone(),
        |entry_chirho, value_chirho| {
            entry_chirho.response_policy_records_chirho = Some(value_chirho)
        },
        compute_chirho,
    )
}

pub fn cached_route_response_policy_records_chirho(
    root_chirho: &Path,
    compute_chirho: impl FnOnce() -> Result<Vec<AppRouteResponsePolicyRecordChirho>>,
) -> Result<Arc<Vec<AppRouteResponsePolicyRecordChirho>>> {
    cached_field_chirho(
        root_chirho,
        |entry_chirho| entry_chirho.route_response_policy_records_chirho.clone(),
        |entry_chirho, value_chirho| {
            entry_chirho.route_response_policy_records_chirho = Some(value_chirho)
        },
        compute_chirho,
    )
}

pub fn cached_params_records_chirho(
    root_chirho: &Path,
    compute_chirho: impl FnOnce() -> Result<Vec<AppParamsRecordChirho>>,
) -> Result<Arc<Vec<AppParamsRecordChirho>>> {
    cached_field_chirho(
        root_chirho,
        |entry_chirho| entry_chirho.params_records_chirho.clone(),
        |entry_chirho, value_chirho| entry_chirho.params_records_chirho = Some(value_chirho),
        compute_chirho,
    )
}

pub fn cached_static_asset_records_chirho(
    root_chirho: &Path,
    compute_chirho: impl FnOnce() -> Result<Vec<AppStaticAssetRecordChirho>>,
) -> Result<Arc<Vec<AppStaticAssetRecordChirho>>> {
    cached_field_chirho(
        root_chirho,
        |entry_chirho| entry_chirho.static_asset_records_chirho.clone(),
        |entry_chirho, value_chirho| entry_chirho.static_asset_records_chirho = Some(value_chirho),
        compute_chirho,
    )
}

pub fn cached_owner_map_chirho(
    root_chirho: &Path,
    compute_chirho: impl FnOnce() -> Result<BTreeMap<String, String>>,
) -> Result<Arc<BTreeMap<String, String>>> {
    cached_field_chirho(
        root_chirho,
        |entry_chirho| entry_chirho.owner_map_chirho.clone(),
        |entry_chirho, value_chirho| entry_chirho.owner_map_chirho = Some(value_chirho),
        compute_chirho,
    )
}

/// The verified (principal -> kind) map, cached per root fingerprint. `identities-chirho.jsonl` is a
/// fingerprint file, so any identity append drops the whole root entry and forces a fresh compute;
/// only successful loads are cached, so a hit is behaviorally identical to a fresh identity read.
pub fn cached_identity_kind_map_chirho(
    root_chirho: &Path,
    compute_chirho: impl FnOnce() -> Result<BTreeMap<String, PrincipalKindChirho>>,
) -> Result<Arc<BTreeMap<String, PrincipalKindChirho>>> {
    cached_field_chirho(
        root_chirho,
        |entry_chirho| entry_chirho.identity_kind_map_chirho.clone(),
        |entry_chirho, value_chirho| entry_chirho.identity_kind_map_chirho = Some(value_chirho),
        compute_chirho,
    )
}

/// Return the verified selected route record for one exact selection key, recomputing only when the
/// fingerprint changed or this key was never resolved for the current fingerprint.
pub fn cached_selected_route_record_chirho(
    root_chirho: &Path,
    selection_key_chirho: SelectedRouteKeyChirho,
    compute_chirho: impl FnOnce() -> Result<AppRouteRecordChirho>,
) -> Result<Arc<AppRouteRecordChirho>> {
    cached_selection_chirho(
        root_chirho,
        selection_key_chirho,
        selected_route_map_chirho,
        compute_chirho,
    )
}

/// The verified app record an app ref selects, cached by its selection key per root fingerprint.
pub fn cached_selected_app_record_chirho(
    root_chirho: &Path,
    selection_key_chirho: SelectedAppKeyChirho,
    compute_chirho: impl FnOnce() -> Result<AppRecordChirho>,
) -> Result<Arc<AppRecordChirho>> {
    cached_selection_chirho(
        root_chirho,
        selection_key_chirho,
        selected_app_map_chirho,
        compute_chirho,
    )
}

fn selected_route_map_chirho(
    entry_chirho: &mut RootVerifiedViewChirho,
) -> &mut BTreeMap<SelectedRouteKeyChirho, Arc<AppRouteRecordChirho>> {
    &mut entry_chirho.selected_route_records_chirho
}

fn selected_app_map_chirho(
    entry_chirho: &mut RootVerifiedViewChirho,
) -> &mut BTreeMap<SelectedAppKeyChirho, Arc<AppRecordChirho>> {
    &mut entry_chirho.selected_app_records_chirho
}

/// One verified selection, cached per root fingerprint. It is computed outside the lock and stored
/// only if the fingerprint did not move meanwhile, so a result computed across a concurrent write is
/// never cached under the old fingerprint.
fn cached_selection_chirho<K: Ord, V>(
    root_chirho: &Path,
    selection_key_chirho: K,
    map_chirho: fn(&mut RootVerifiedViewChirho) -> &mut BTreeMap<K, Arc<V>>,
    compute_chirho: impl FnOnce() -> Result<V>,
) -> Result<Arc<V>> {
    let key_chirho = canonical_key_chirho(root_chirho);
    // Refuses before any cached field is accepted, not only on a miss.
    let fingerprint_chirho = root_fingerprint_chirho(root_chirho)?;
    {
        let mut guard_chirho = cache_chirho().lock().unwrap();
        let tick_chirho = next_tick_chirho(&mut guard_chirho);
        if let Some(entry_chirho) = guard_chirho.entries_chirho.get_mut(&key_chirho) {
            refuse_vanished_chirho(
                root_chirho,
                &entry_chirho.fingerprint_chirho,
                &fingerprint_chirho,
            )?;
            if entry_chirho.fingerprint_chirho == fingerprint_chirho {
                entry_chirho.last_tick_chirho = tick_chirho;
                if let Some(record_chirho) = map_chirho(entry_chirho).get(&selection_key_chirho) {
                    return Ok(record_chirho.clone());
                }
            }
        }
    }
    #[cfg(any(test, feature = "test-hooks-chirho"))]
    test_metrics_chirho::note_miss_chirho();
    let record_chirho = Arc::new(compute_chirho()?);
    if root_fingerprint_chirho(root_chirho).ok().as_ref() == Some(&fingerprint_chirho) {
        let mut guard_chirho = cache_chirho().lock().unwrap();
        let tick_chirho = next_tick_chirho(&mut guard_chirho);
        insert_field_chirho(
            &mut guard_chirho,
            &key_chirho,
            &fingerprint_chirho,
            tick_chirho,
            |entry_chirho| {
                map_chirho(entry_chirho).insert(selection_key_chirho, record_chirho.clone());
            },
        );
    }
    Ok(record_chirho)
}

/// Thread-local counters (test-only) proving warm requests re-verify nothing. Thread-local so
/// parallel tests with their own roots never perturb one another's counts.
#[cfg(any(test, feature = "test-hooks-chirho"))]
pub mod test_metrics_chirho {
    use std::cell::Cell;

    thread_local! {
        static MISSES_CHIRHO: Cell<u64> = const { Cell::new(0) };
        static FULL_LOG_LOADS_CHIRHO: Cell<u64> = const { Cell::new(0) };
        static ED25519_VERIFIES_CHIRHO: Cell<u64> = const { Cell::new(0) };
    }

    pub struct MetricsSnapshotChirho {
        pub misses_chirho: u64,
        pub full_log_loads_chirho: u64,
        pub ed25519_verifies_chirho: u64,
    }

    pub fn reset_chirho() {
        MISSES_CHIRHO.with(|cell_chirho| cell_chirho.set(0));
        FULL_LOG_LOADS_CHIRHO.with(|cell_chirho| cell_chirho.set(0));
        ED25519_VERIFIES_CHIRHO.with(|cell_chirho| cell_chirho.set(0));
    }

    pub fn snapshot_chirho() -> MetricsSnapshotChirho {
        MetricsSnapshotChirho {
            misses_chirho: MISSES_CHIRHO.with(|cell_chirho| cell_chirho.get()),
            full_log_loads_chirho: FULL_LOG_LOADS_CHIRHO.with(|cell_chirho| cell_chirho.get()),
            ed25519_verifies_chirho: ED25519_VERIFIES_CHIRHO.with(|cell_chirho| cell_chirho.get()),
        }
    }

    pub fn note_miss_chirho() {
        MISSES_CHIRHO.with(|cell_chirho| cell_chirho.set(cell_chirho.get() + 1));
    }

    pub fn note_full_log_load_chirho() {
        FULL_LOG_LOADS_CHIRHO.with(|cell_chirho| cell_chirho.set(cell_chirho.get() + 1));
    }

    pub fn note_ed25519_verify_chirho() {
        ED25519_VERIFIES_CHIRHO.with(|cell_chirho| cell_chirho.set(cell_chirho.get() + 1));
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!("cairn-view-cache-test-{nanos_chirho}-{n_chirho}"))
    }

    #[test]
    fn fingerprint_tracks_growth_replacement_and_absence_chirho() {
        let root_chirho = tmp_root_chirho();
        std::fs::create_dir_all(&root_chirho).unwrap();
        let base_chirho = root_fingerprint_chirho(&root_chirho).unwrap();
        assert_eq!(base_chirho, root_fingerprint_chirho(&root_chirho).unwrap());

        let records_path_chirho = root_chirho.join("app-records-chirho.jsonl");
        std::fs::write(&records_path_chirho, b"one\n").unwrap();
        let after_create_chirho = root_fingerprint_chirho(&root_chirho).unwrap();
        assert_ne!(
            base_chirho, after_create_chirho,
            "creating a file is a new state"
        );

        std::fs::write(&records_path_chirho, b"one\ntwo\n").unwrap();
        assert_ne!(
            after_create_chirho,
            root_fingerprint_chirho(&root_chirho).unwrap(),
            "appended length is a new state"
        );

        std::fs::remove_file(&records_path_chirho).unwrap();
        assert_eq!(
            base_chirho,
            root_fingerprint_chirho(&root_chirho).unwrap(),
            "removing the file returns to the absent state"
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn evict_to_fit_drops_least_recently_used_chirho() {
        let mut map_chirho = VerifiedViewMapChirho {
            entries_chirho: HashMap::new(),
            tick_chirho: 0,
        };
        let empty_fp_chirho = RootFingerprintChirho {
            slots_chirho: Vec::new(),
        };
        for (index_chirho, name_chirho) in ["a", "b", "c"].into_iter().enumerate() {
            map_chirho.entries_chirho.insert(
                PathBuf::from(name_chirho),
                RootVerifiedViewChirho::empty_chirho(empty_fp_chirho.clone(), index_chirho as u64),
            );
        }
        // "a" is least-recently-used (tick 0); inserting "d" under cap 3 must evict it.
        evict_to_fit_chirho(&mut map_chirho, 3, &PathBuf::from("d"));
        assert!(!map_chirho.entries_chirho.contains_key(&PathBuf::from("a")));
        assert!(map_chirho.entries_chirho.contains_key(&PathBuf::from("b")));
        assert!(map_chirho.entries_chirho.contains_key(&PathBuf::from("c")));
        assert_eq!(map_chirho.entries_chirho.len(), 2);
        // Re-touching an already-present key never evicts.
        evict_to_fit_chirho(&mut map_chirho, 2, &PathBuf::from("b"));
        assert_eq!(map_chirho.entries_chirho.len(), 2);
    }

    #[test]
    fn cached_field_serves_warm_and_reverifies_on_change_chirho() {
        let root_chirho = tmp_root_chirho();
        std::fs::create_dir_all(&root_chirho).unwrap();
        let computes_chirho = AtomicU64::new(0);
        let load_chirho = || {
            computes_chirho.fetch_add(1, Ordering::Relaxed);
            Ok(vec![AppRecordChirho {
                seq_chirho: 0,
                schema_chirho: String::new(),
                app_chirho: "app".to_string(),
                owner_principal_chirho: "owner".to_string(),
                dag_chirho: None,
                action_chirho: cairn_model_app_chirho::AppActionChirho::UndeployChirho,
                at_ms_chirho: 0,
                previous_chirho: None,
                transition_id_chirho: String::new(),
                prepared_writer_fence_epoch_chirho: None,
                sig_chirho: String::new(),
            }])
        };
        let first_chirho = cached_app_records_chirho(&root_chirho, load_chirho).unwrap();
        assert_eq!(computes_chirho.load(Ordering::Relaxed), 1);
        let warm_chirho = cached_app_records_chirho(&root_chirho, load_chirho).unwrap();
        assert_eq!(
            computes_chirho.load(Ordering::Relaxed),
            1,
            "warm hit must not recompute"
        );
        assert!(Arc::ptr_eq(&first_chirho, &warm_chirho));

        std::fs::write(root_chirho.join("refs-chirho.json"), b"{}").unwrap();
        let after_change_chirho = cached_app_records_chirho(&root_chirho, load_chirho).unwrap();
        assert_eq!(
            computes_chirho.load(Ordering::Relaxed),
            2,
            "a fingerprint change must force a fresh verify"
        );
        assert!(!Arc::ptr_eq(&first_chirho, &after_change_chirho));
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    fn app_record_chirho(app_chirho: &str) -> AppRecordChirho {
        AppRecordChirho {
            seq_chirho: 0,
            schema_chirho: String::new(),
            app_chirho: app_chirho.to_string(),
            owner_principal_chirho: "owner".to_string(),
            dag_chirho: None,
            action_chirho: cairn_model_app_chirho::AppActionChirho::UndeployChirho,
            at_ms_chirho: 0,
            previous_chirho: None,
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            sig_chirho: String::new(),
        }
    }

    /// The race guard on a cached selection. A compute that began before a write must not store its
    /// result: storing under the older fingerprint would REPLACE the root's whole newer entry, so every
    /// cached view on that root would re-verify on the next request. Nesting forces the interleaving
    /// without threads: compute A writes a fingerprinted file, then a fresh lookup (compute B) caches
    /// under the new fingerprint, then A returns.
    #[test]
    fn a_stale_selection_never_evicts_a_newer_one_chirho() {
        let root_chirho = tmp_root_chirho();
        std::fs::create_dir_all(&root_chirho).unwrap();
        let computes_chirho = AtomicU64::new(0);
        let key_chirho = || SelectedAppKeyChirho {
            app_chirho: "app".to_string(),
            app_ref_dag_chirho: "dag".to_string(),
        };
        cached_selected_app_record_chirho(&root_chirho, key_chirho(), || {
            computes_chirho.fetch_add(1, Ordering::Relaxed);
            std::fs::write(root_chirho.join("reflog-chirho.jsonl"), b"{}\n").unwrap();
            cached_selected_app_record_chirho(&root_chirho, key_chirho(), || {
                computes_chirho.fetch_add(1, Ordering::Relaxed);
                Ok(app_record_chirho("app"))
            })
            .unwrap();
            Ok(app_record_chirho("app"))
        })
        .unwrap();
        assert_eq!(
            computes_chirho.load(Ordering::Relaxed),
            2,
            "A and B each computed once"
        );
        cached_selected_app_record_chirho(&root_chirho, key_chirho(), || {
            computes_chirho.fetch_add(1, Ordering::Relaxed);
            Ok(app_record_chirho("app"))
        })
        .unwrap();
        assert_eq!(
            computes_chirho.load(Ordering::Relaxed),
            2,
            "B's newer entry must still serve: the stale compute A must not have replaced it"
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
