// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pure O(window) usage-checkpoint aggregate — fold/prune/window math, serde, and closure-parameterized load/decide/persist — for cairn-chirho resource metering.
//!
//! WHERE THE TESTS LIVE. `cargo test -p cairn-usage-checkpoint-chirho` reports **0 tests**, and that
//! is deliberate rather than a coverage gap. Every function here is closure-parameterized precisely so
//! it does not depend on the policy/decision types, which live in the root crate — so the behaviour is
//! exercised in `src/app_metering_chirho/resource_chirho/usage_checkpoint_tests_chirho.rs`, whose
//! dev-dependency enables this crate's `test-hooks-chirho` feature to reach
//! `max_folded_at_ms_chirho()`. The money-critical property —
//! `decide_with_regression_guard_chirho` routing a detected clock regression to the full scan instead
//! of the under-counting aggregate — is pinned there by
//! `usage_checkpoint_regression_decides_from_full_scan_chirho`, and that test was **mutation-verified**
//! (2026-07-25): disabling the regression branch turns it red. Stated here so a reader who runs the
//! obvious per-crate command does not read `0` as "untested" — the coverage is real, it just lives
//! where the types it needs live.

use anyhow::{Context, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_economic_chirho::{
    AppResourcePolicyChirho, ResourceChargeChirho, ResourceDecisionChirho, ResourceMeterChirho,
    ResourceUsageRecordChirho,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Schema tag for the `<usage-log>.usage-checkpoint-chirho` sidecar. Any other value is a miss
/// (rebuild from the full scan), so bumping this string safely retires an old checkpoint layout.
/// v2 adds `max_folded_at_ms_chirho`; the bump makes every v1 sidecar read as a miss and rebuild once,
/// with no serde-default backfill that could resurrect a field-less checkpoint through the fast path.
pub const USAGE_CHECKPOINT_SCHEMA_CHIRHO: &str = "usage-checkpoint-v2-chirho";

/// Filename suffix appended to the usage-log path to name its sibling checkpoint. Chosen so the
/// sidecar has no `.jsonl` extension: the GC/privacy walkers only collect `.jsonl` surfaces, so this
/// engine metadata is ignored exactly like the F1 `<log>.head-chirho` sidecar next to it.
const USAGE_CHECKPOINT_SUFFIX_CHIRHO: &str = ".usage-checkpoint-chirho";

/// App-wide (`user_chirho == None`) synthetic principal. Real user labels are whitespace-free
/// (`validate_principal_label_chirho`), so this whitespace-bearing sentinel can never equal a real
/// user — it carries app-wide-only usage into the reconstructed prior without being counted per-user.
const APP_WIDE_SENTINEL_USER_CHIRHO: &str = "usage checkpoint app wide sentinel chirho";

/// The sibling checkpoint path for `usage_log_path_chirho`.
pub fn usage_checkpoint_path_chirho(usage_log_path_chirho: &Path) -> PathBuf {
    let mut name_chirho = usage_log_path_chirho.as_os_str().to_os_string();
    name_chirho.push(USAGE_CHECKPOINT_SUFFIX_CHIRHO);
    PathBuf::from(name_chirho)
}

/// One recorded windowed contribution: the record's decision time and the amount it charged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct UsageEntryChirho {
    at_ms_chirho: u64,
    amount_chirho: i64,
}

/// A per-(user-scope, resource) aggregate. Unwindowed meters keep a running total (a scalar is exact
/// with no window to age); windowed meters keep the in-window rows so the sliding-window sum matches
/// the full scan exactly — a scalar that never ages out would be wrong for a window.
#[derive(Clone, Debug, PartialEq, Eq)]
enum UsageBucketBodyChirho {
    UnwindowedChirho {
        total_chirho: i64,
    },
    WindowedChirho {
        entries_chirho: Vec<UsageEntryChirho>,
    },
}

/// `(user-scope, resource)`. `None` user-scope is the app-wide bucket (all users), mirroring the
/// `Some(user)` / `None` split of `used_amount_chirho`. The policy hash and app are checkpoint-wide,
/// so they are not repeated per key.
type UsageKeyChirho = (Option<String>, String);

/// The in-memory aggregate for exactly one current policy hash. `byte_len`/`next_seq` are the
/// behind-never-ahead stale-guard against the usage log; `policy_hash`/`app` force a rebuild when the
/// enforced policy changes (only current-policy rows count in `used_amount_chirho`).
pub struct UsageAggregateChirho {
    byte_len_chirho: u64,
    next_seq_chirho: u64,
    policy_hash_chirho: String,
    app_chirho: String,
    /// High-water mark: the maximum `at_ms` of any record ever folded in (monotone; raised on every
    /// fold, append and rebuild alike). Because a windowed bucket is pruned using each folded record's
    /// own `at_ms`, a decision whose `at_ms` is below this mark may sit behind an already-pruned but
    /// still-in-window prior and thus under-count `used` — a fail-OPEN on a money gate. The decision
    /// path treats `at_ms < max_folded_at_ms_chirho` as a detected clock regression and bypasses the
    /// aggregate for the regression-correct full scan (see `decide_with_regression_guard_chirho`).
    max_folded_at_ms_chirho: u64,
    buckets_chirho: BTreeMap<UsageKeyChirho, UsageBucketBodyChirho>,
}

/// The serialized checkpoint file (sorted buckets for a byte-stable durable write).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct UsageCheckpointFileChirho {
    schema_chirho: String,
    usage_log_byte_len_chirho: u64,
    next_seq_chirho: u64,
    // Deliberately NOT `#[serde(default)]`: a v1 sidecar lacking this key must fail to parse (a miss),
    // never silently backfill 0 and defeat the regression guard on a stale checkpoint.
    max_folded_at_ms_chirho: u64,
    policy_hash_chirho: String,
    app_chirho: String,
    buckets_chirho: Vec<UsageBucketFileChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct UsageBucketFileChirho {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user_chirho: Option<String>,
    resource_chirho: String,
    windowed_chirho: bool,
    total_chirho: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    entries_chirho: Vec<UsageEntryChirho>,
}

impl UsageAggregateChirho {
    pub fn empty_chirho(policy_hash_chirho: &HashChirho, app_chirho: &str) -> Self {
        UsageAggregateChirho {
            byte_len_chirho: 0,
            next_seq_chirho: 0,
            max_folded_at_ms_chirho: 0,
            policy_hash_chirho: policy_hash_chirho.0.clone(),
            app_chirho: app_chirho.to_string(),
            buckets_chirho: BTreeMap::new(),
        }
    }

    fn to_file_chirho(&self) -> UsageCheckpointFileChirho {
        let buckets_chirho = self
            .buckets_chirho
            .iter()
            .map(
                |((user_chirho, resource_chirho), body_chirho)| match body_chirho {
                    UsageBucketBodyChirho::UnwindowedChirho { total_chirho } => {
                        UsageBucketFileChirho {
                            user_chirho: user_chirho.clone(),
                            resource_chirho: resource_chirho.clone(),
                            windowed_chirho: false,
                            total_chirho: *total_chirho,
                            entries_chirho: Vec::new(),
                        }
                    }
                    UsageBucketBodyChirho::WindowedChirho { entries_chirho } => {
                        UsageBucketFileChirho {
                            user_chirho: user_chirho.clone(),
                            resource_chirho: resource_chirho.clone(),
                            windowed_chirho: true,
                            total_chirho: 0,
                            entries_chirho: entries_chirho.clone(),
                        }
                    }
                },
            )
            .collect();
        UsageCheckpointFileChirho {
            schema_chirho: USAGE_CHECKPOINT_SCHEMA_CHIRHO.to_string(),
            usage_log_byte_len_chirho: self.byte_len_chirho,
            next_seq_chirho: self.next_seq_chirho,
            max_folded_at_ms_chirho: self.max_folded_at_ms_chirho,
            policy_hash_chirho: self.policy_hash_chirho.clone(),
            app_chirho: self.app_chirho.clone(),
            buckets_chirho,
        }
    }

    fn from_file_chirho(file_chirho: UsageCheckpointFileChirho) -> Self {
        let mut buckets_chirho = BTreeMap::new();
        for bucket_chirho in file_chirho.buckets_chirho {
            let body_chirho = if bucket_chirho.windowed_chirho {
                UsageBucketBodyChirho::WindowedChirho {
                    entries_chirho: bucket_chirho.entries_chirho,
                }
            } else {
                UsageBucketBodyChirho::UnwindowedChirho {
                    total_chirho: bucket_chirho.total_chirho,
                }
            };
            buckets_chirho.insert(
                (bucket_chirho.user_chirho, bucket_chirho.resource_chirho),
                body_chirho,
            );
        }
        UsageAggregateChirho {
            byte_len_chirho: file_chirho.usage_log_byte_len_chirho,
            next_seq_chirho: file_chirho.next_seq_chirho,
            max_folded_at_ms_chirho: file_chirho.max_folded_at_ms_chirho,
            policy_hash_chirho: file_chirho.policy_hash_chirho,
            app_chirho: file_chirho.app_chirho,
            buckets_chirho,
        }
    }

    /// The regression floor for tests: the maximum `at_ms` folded so far.
    #[cfg(feature = "test-hooks-chirho")]
    pub fn max_folded_at_ms_chirho(&self) -> u64 {
        self.max_folded_at_ms_chirho
    }
}

/// A prior windowed row is in the look-back window of a decision at `at_ms` iff it is not in the
/// future and is younger than `window_ms` — byte-identical to the `used_amount_chirho` filter
/// (`record.at_ms > at_ms` skipped, then `at_ms - record.at_ms >= window_ms` skipped). `checked_sub`
/// makes a future row (clock regression) a clean non-count rather than an underflow.
fn entry_counts_in_window_chirho(
    entry_at_ms_chirho: u64,
    at_ms_chirho: u64,
    window_ms_chirho: u64,
) -> bool {
    at_ms_chirho
        .checked_sub(entry_at_ms_chirho)
        .is_some_and(|age_chirho| age_chirho < window_ms_chirho)
}

/// A windowed row is kept by pruning iff it could still count for a decision at/after this reference
/// time: a future row (a clock regression) is kept, and a past row is kept while younger than the
/// window. Pruning bounds stored size to O(window), but it is NOT free of correctness impact. Because
/// the reference is each folded record's own `at_ms`, a forward clock step of >= one window drops an
/// entry that a later *regressed* decision — whose `at_ms` falls back inside the window — would still
/// count, so the read-time filter over a pruned bucket UNDER-counts `used`: a fail-OPEN on a money
/// gate. The rebuild path folds and prunes through this same function, so it diverges identically and
/// cannot be trusted as a fallback. The decision path closes this by detecting
/// `at_ms < max_folded_at_ms_chirho` and deciding from the row-preserving full scan instead of the
/// aggregate (see `decide_with_regression_guard_chirho`).
fn entry_survives_prune_chirho(
    entry_at_ms_chirho: u64,
    reference_ms_chirho: u64,
    window_ms_chirho: u64,
) -> bool {
    reference_ms_chirho
        .checked_sub(entry_at_ms_chirho)
        .is_none_or(|age_chirho| age_chirho < window_ms_chirho)
}

/// Window-correct `used` for one (user-scope, resource): the sliding-window sum for a windowed meter,
/// the running total for an unwindowed one. The live meter's `window_ms_chirho` is authoritative (the
/// bucket body always matches it, since the meter is fixed by the immutable policy hash).
fn used_amount_from_aggregate_chirho(
    aggregate_chirho: &UsageAggregateChirho,
    user_scope_chirho: Option<&str>,
    resource_chirho: &str,
    window_ms_chirho: Option<u64>,
    at_ms_chirho: u64,
) -> i64 {
    let key_chirho = (
        user_scope_chirho.map(str::to_string),
        resource_chirho.to_string(),
    );
    let Some(body_chirho) = aggregate_chirho.buckets_chirho.get(&key_chirho) else {
        return 0;
    };
    match (window_ms_chirho, body_chirho) {
        (Some(window_ms_chirho), UsageBucketBodyChirho::WindowedChirho { entries_chirho }) => {
            sum_amounts_chirho(entries_chirho.iter().filter(|entry_chirho| {
                entry_counts_in_window_chirho(
                    entry_chirho.at_ms_chirho,
                    at_ms_chirho,
                    window_ms_chirho,
                )
            }))
        }
        (None, UsageBucketBodyChirho::UnwindowedChirho { total_chirho }) => *total_chirho,
        // Meter/body-shape disagreement cannot arise for one immutable policy hash; fall back to the
        // shape actually stored so a hand-forged checkpoint still yields a defined (never panicking)
        // number, which the byte-len/next-seq stale-guard will discard on the next append anyway.
        (Some(_), UsageBucketBodyChirho::UnwindowedChirho { total_chirho }) => *total_chirho,
        (None, UsageBucketBodyChirho::WindowedChirho { entries_chirho }) => {
            sum_amounts_chirho(entries_chirho.iter())
        }
    }
}

/// Saturating sum of entry amounts. Saturation (vs a panic) keeps a decision defined even on absurd
/// forged data; the downstream `decide_resource_usage_chirho` still fails an over-limit charge closed.
fn sum_amounts_chirho<'a_chirho>(
    entries_chirho: impl Iterator<Item = &'a_chirho UsageEntryChirho>,
) -> i64 {
    entries_chirho.fold(0_i64, |acc_chirho, entry_chirho| {
        acc_chirho.saturating_add(entry_chirho.amount_chirho)
    })
}

/// Fold one appended usage record into the aggregate. Only `Allowed` rows contribute (exactly what
/// `used_amount_chirho` counts); a `Routed` row is still logged but adds nothing. Each charge lands in
/// the per-user bucket when the meter has a per-user limit and the app-wide bucket when it has an app
/// limit — i.e. only the buckets a decision will ever read — and windowed buckets are pruned to the
/// window using this record's own decision time as the reference.
///
/// `meter_for_chirho_fn` resolves a charge's meter from the policy (root-side glue supplies
/// `resource_policy_chirho::meter_for_chirho`, keeping this pure core off the services family).
pub fn fold_record_chirho<MeterForFnChirho>(
    aggregate_chirho: &mut UsageAggregateChirho,
    record_chirho: &ResourceUsageRecordChirho,
    policy_chirho: &AppResourcePolicyChirho,
    meter_for_chirho_fn: MeterForFnChirho,
) where
    MeterForFnChirho: for<'policy_chirho> Fn(
        &'policy_chirho AppResourcePolicyChirho,
        &str,
    ) -> Result<&'policy_chirho ResourceMeterChirho>,
{
    // Raise the high-water regression floor on EVERY fold, before the non-Allowed early return: any
    // record handed to the fold — via a warm append or a full-scan rebuild — advances the floor, so a
    // later decision at a regressed `at_ms` is caught. Monotone max: it never moves backward.
    aggregate_chirho.max_folded_at_ms_chirho = aggregate_chirho
        .max_folded_at_ms_chirho
        .max(record_chirho.at_ms_chirho);
    if record_chirho.decision_chirho != ResourceDecisionChirho::AllowedChirho {
        return;
    }
    for charge_chirho in &record_chirho.charges_chirho {
        let Ok(meter_chirho) = meter_for_chirho_fn(policy_chirho, &charge_chirho.resource_chirho)
        else {
            continue;
        };
        if meter_chirho.per_user_limit_chirho.is_some() {
            fold_into_bucket_chirho(
                aggregate_chirho,
                Some(record_chirho.user_chirho.clone()),
                &charge_chirho.resource_chirho,
                meter_chirho.window_ms_chirho,
                record_chirho.at_ms_chirho,
                charge_chirho.amount_chirho,
            );
        }
        if meter_chirho.app_limit_chirho.is_some() {
            fold_into_bucket_chirho(
                aggregate_chirho,
                None,
                &charge_chirho.resource_chirho,
                meter_chirho.window_ms_chirho,
                record_chirho.at_ms_chirho,
                charge_chirho.amount_chirho,
            );
        }
    }
}

fn fold_into_bucket_chirho(
    aggregate_chirho: &mut UsageAggregateChirho,
    user_scope_chirho: Option<String>,
    resource_chirho: &str,
    window_ms_chirho: Option<u64>,
    at_ms_chirho: u64,
    amount_chirho: i64,
) {
    let key_chirho = (user_scope_chirho, resource_chirho.to_string());
    match window_ms_chirho {
        Some(window_ms_chirho) => {
            let body_chirho = aggregate_chirho
                .buckets_chirho
                .entry(key_chirho)
                .or_insert_with(|| UsageBucketBodyChirho::WindowedChirho {
                    entries_chirho: Vec::new(),
                });
            // A bucket's shape is fixed by its meter's immutable policy hash; reset only guards the
            // theoretical case of a hand-edited checkpoint whose body shape disagrees with the meter.
            if !matches!(body_chirho, UsageBucketBodyChirho::WindowedChirho { .. }) {
                *body_chirho = UsageBucketBodyChirho::WindowedChirho {
                    entries_chirho: Vec::new(),
                };
            }
            if let UsageBucketBodyChirho::WindowedChirho { entries_chirho } = body_chirho {
                entries_chirho.push(UsageEntryChirho {
                    at_ms_chirho,
                    amount_chirho,
                });
                entries_chirho.retain(|entry_chirho| {
                    entry_survives_prune_chirho(
                        entry_chirho.at_ms_chirho,
                        at_ms_chirho,
                        window_ms_chirho,
                    )
                });
            }
        }
        None => {
            let body_chirho = aggregate_chirho
                .buckets_chirho
                .entry(key_chirho)
                .or_insert(UsageBucketBodyChirho::UnwindowedChirho { total_chirho: 0 });
            if !matches!(body_chirho, UsageBucketBodyChirho::UnwindowedChirho { .. }) {
                *body_chirho = UsageBucketBodyChirho::UnwindowedChirho { total_chirho: 0 };
            }
            if let UsageBucketBodyChirho::UnwindowedChirho { total_chirho } = body_chirho {
                *total_chirho = total_chirho.saturating_add(amount_chirho);
            }
        }
    }
}

/// Reconstruct the minimal prior slice that reproduces this request's `used` amounts, then hand it to
/// the real `decide_resource_usage_chirho`. Reusing the production decision keeps the outcome —
/// including the exact `Routed` bounds and the fail-closed error message — byte-identical to the full
/// scan; only the `used` inputs come from the aggregate. A per-user row carries the user's in-window
/// usage; an app-wide sentinel row carries the remaining other-users' usage, so `used_amount_chirho`
/// recovers `used_user` for a `Some(user)` query and `used_app` for a `None` query.
///
/// `meter_for_chirho_fn` and `decide_resource_usage_chirho_fn` are the root-side glue closures
/// (`resource_policy_chirho::meter_for_chirho` / `::decide_resource_usage_chirho`).
#[allow(clippy::too_many_arguments)]
pub fn decide_from_aggregate_chirho<MeterForFnChirho, DecideFnChirho>(
    aggregate_chirho: &UsageAggregateChirho,
    policy_chirho: &AppResourcePolicyChirho,
    policy_hash_chirho: &HashChirho,
    app_chirho: &str,
    user_chirho: &str,
    charges_chirho: &[ResourceChargeChirho],
    at_ms_chirho: u64,
    meter_for_chirho_fn: MeterForFnChirho,
    decide_resource_usage_chirho_fn: DecideFnChirho,
) -> Result<ResourceDecisionChirho>
where
    MeterForFnChirho: for<'policy_chirho> Fn(
        &'policy_chirho AppResourcePolicyChirho,
        &str,
    ) -> Result<&'policy_chirho ResourceMeterChirho>,
    DecideFnChirho: Fn(
        &AppResourcePolicyChirho,
        &HashChirho,
        &[ResourceUsageRecordChirho],
        &str,
        &str,
        &[ResourceChargeChirho],
        u64,
    ) -> Result<ResourceDecisionChirho>,
{
    let mut user_charges_chirho: Vec<ResourceChargeChirho> = Vec::new();
    let mut sentinel_charges_chirho: Vec<ResourceChargeChirho> = Vec::new();
    for charge_chirho in charges_chirho {
        let meter_chirho = meter_for_chirho_fn(policy_chirho, &charge_chirho.resource_chirho)?;
        let used_user_chirho = if meter_chirho.per_user_limit_chirho.is_some() {
            used_amount_from_aggregate_chirho(
                aggregate_chirho,
                Some(user_chirho),
                &charge_chirho.resource_chirho,
                meter_chirho.window_ms_chirho,
                at_ms_chirho,
            )
        } else {
            0
        };
        if used_user_chirho > 0 {
            user_charges_chirho.push(ResourceChargeChirho {
                resource_chirho: charge_chirho.resource_chirho.clone(),
                amount_chirho: used_user_chirho,
            });
        }
        if meter_chirho.app_limit_chirho.is_some() {
            let used_app_chirho = used_amount_from_aggregate_chirho(
                aggregate_chirho,
                None,
                &charge_chirho.resource_chirho,
                meter_chirho.window_ms_chirho,
                at_ms_chirho,
            );
            // used_app aggregates every user's in-window usage and used_user only this user's, so the
            // remainder is the other users' usage and is never negative.
            let other_users_chirho = used_app_chirho - used_user_chirho;
            debug_assert!(
                other_users_chirho >= 0,
                "app-wide usage cannot be below per-user usage"
            );
            if other_users_chirho > 0 {
                sentinel_charges_chirho.push(ResourceChargeChirho {
                    resource_chirho: charge_chirho.resource_chirho.clone(),
                    amount_chirho: other_users_chirho,
                });
            }
        }
    }

    let mut prior_chirho: Vec<ResourceUsageRecordChirho> = Vec::new();
    if !user_charges_chirho.is_empty() {
        prior_chirho.push(synthetic_prior_row_chirho(
            policy_hash_chirho,
            app_chirho,
            user_chirho,
            user_charges_chirho,
            at_ms_chirho,
        ));
    }
    if !sentinel_charges_chirho.is_empty() {
        prior_chirho.push(synthetic_prior_row_chirho(
            policy_hash_chirho,
            app_chirho,
            APP_WIDE_SENTINEL_USER_CHIRHO,
            sentinel_charges_chirho,
            at_ms_chirho,
        ));
    }

    decide_resource_usage_chirho_fn(
        policy_chirho,
        policy_hash_chirho,
        &prior_chirho,
        app_chirho,
        user_chirho,
        charges_chirho,
        at_ms_chirho,
    )
}

/// The regression-safe entry point the gated append actually calls. Normally (`at_ms` at or above the
/// high-water mark) it decides from the O(window) aggregate. But a windowed bucket is pruned using each
/// folded record's own `at_ms`, so once the wall clock has stepped forward by >= a window and then
/// regressed, a still-in-window prior row may already be pruned and the aggregate would UNDER-count
/// `used` — silently Allowing a charge the true full scan would Route or fail closed (a fail-OPEN money
/// gate; the rebuild path prunes identically, so it is no safer). On that detected regression
/// (`at_ms < max_folded_at_ms_chirho`) we bypass the aggregate and decide from the regression-correct
/// full scan: `load_resource_usage_chirho` never destroys rows, so `used_amount_chirho` re-counts the
/// still-in-window prior exactly. This abnormal-clock branch is O(n); the warm normal path stays
/// O(window). The caller still appends and folds the resulting record as usual afterward.
///
/// `load_resource_usage_chirho_fn` is the root-side full-scan loader; `meter_for_chirho_fn` /
/// `decide_resource_usage_chirho_fn` are the metering/decision glue closures.
#[allow(clippy::too_many_arguments)]
pub fn decide_with_regression_guard_chirho<LoadFnChirho, MeterForFnChirho, DecideFnChirho>(
    root_chirho: &Path,
    aggregate_chirho: &UsageAggregateChirho,
    policy_chirho: &AppResourcePolicyChirho,
    policy_hash_chirho: &HashChirho,
    app_chirho: &str,
    user_chirho: &str,
    charges_chirho: &[ResourceChargeChirho],
    at_ms_chirho: u64,
    load_resource_usage_chirho_fn: LoadFnChirho,
    meter_for_chirho_fn: MeterForFnChirho,
    decide_resource_usage_chirho_fn: DecideFnChirho,
) -> Result<ResourceDecisionChirho>
where
    LoadFnChirho: Fn(&Path) -> Result<Vec<ResourceUsageRecordChirho>>,
    MeterForFnChirho: for<'policy_chirho> Fn(
        &'policy_chirho AppResourcePolicyChirho,
        &str,
    ) -> Result<&'policy_chirho ResourceMeterChirho>,
    DecideFnChirho: Fn(
        &AppResourcePolicyChirho,
        &HashChirho,
        &[ResourceUsageRecordChirho],
        &str,
        &str,
        &[ResourceChargeChirho],
        u64,
    ) -> Result<ResourceDecisionChirho>,
{
    if at_ms_chirho < aggregate_chirho.max_folded_at_ms_chirho {
        let records_chirho = load_resource_usage_chirho_fn(root_chirho)?;
        return decide_resource_usage_chirho_fn(
            policy_chirho,
            policy_hash_chirho,
            &records_chirho,
            app_chirho,
            user_chirho,
            charges_chirho,
            at_ms_chirho,
        );
    }
    decide_from_aggregate_chirho(
        aggregate_chirho,
        policy_chirho,
        policy_hash_chirho,
        app_chirho,
        user_chirho,
        charges_chirho,
        at_ms_chirho,
        meter_for_chirho_fn,
        decide_resource_usage_chirho_fn,
    )
}

/// One synthetic prior row. Only `resource_policy_chirho`, `app_chirho`, `decision_chirho`,
/// `at_ms_chirho`, `user_chirho`, and `charges_chirho` are read by `used_amount_chirho`; the rest are
/// inert placeholders on a value that is never persisted or signed. `at_ms == at_ms_chirho` puts it in
/// every window (its amount is already the correctly-windowed sum from the aggregate).
fn synthetic_prior_row_chirho(
    policy_hash_chirho: &HashChirho,
    app_chirho: &str,
    user_chirho: &str,
    charges_chirho: Vec<ResourceChargeChirho>,
    at_ms_chirho: u64,
) -> ResourceUsageRecordChirho {
    ResourceUsageRecordChirho {
        seq_chirho: 0,
        schema_chirho: String::new(),
        app_chirho: app_chirho.to_string(),
        user_chirho: user_chirho.to_string(),
        actor_chirho: user_chirho.to_string(),
        section_chirho: String::new(),
        action_chirho: String::new(),
        effect_chirho: None,
        run_chirho: None,
        resource_policy_chirho: policy_hash_chirho.clone(),
        charges_chirho,
        bridges_chirho: Vec::new(),
        decision_chirho: ResourceDecisionChirho::AllowedChirho,
        at_ms_chirho,
        sig_chirho: String::new(),
    }
}

/// Load the O(1) checkpoint, or rebuild it once from the full verified scan on any miss.
///
/// The fast path is taken only when the sidecar is intact AND its byte length equals the log's
/// current length AND its `next_seq`/`policy_hash`/`app` still match — i.e. the log is byte-for-byte
/// the tail this checkpoint was written for, under the same enforced policy. Any mismatch (missing,
/// torn, stale-behind, ahead, a policy change, an unreadable sidecar, or — because the single sidecar
/// tracks one policy while the usage log is shared by every app in the root — an intervening append by
/// a different app or policy) falls through to a single full `load_resource_usage_chirho` scan of the
/// current-policy rows, which is O(n) but happens only on a miss; a same-policy warm append stays
/// O(window). Making interleaved multi-app appends stay warm needs an all-apps-keyed checkpoint and is
/// a recorded follow-up, not this slice.
///
/// `load_resource_usage_chirho_fn` / `meter_for_chirho_fn` are the root-side glue closures used only on
/// the rebuild (miss) path; a warm hit reads the sidecar and calls neither.
#[allow(clippy::too_many_arguments)]
pub fn load_or_rebuild_chirho<LoadFnChirho, MeterForFnChirho>(
    root_chirho: &Path,
    usage_log_path_chirho: &Path,
    expected_next_seq_chirho: u64,
    policy_chirho: &AppResourcePolicyChirho,
    policy_hash_chirho: &HashChirho,
    app_chirho: &str,
    load_resource_usage_chirho_fn: LoadFnChirho,
    meter_for_chirho_fn: MeterForFnChirho,
) -> Result<UsageAggregateChirho>
where
    LoadFnChirho: Fn(&Path) -> Result<Vec<ResourceUsageRecordChirho>>,
    MeterForFnChirho: for<'policy_chirho> Fn(
        &'policy_chirho AppResourcePolicyChirho,
        &str,
    ) -> Result<&'policy_chirho ResourceMeterChirho>,
{
    let current_len_chirho = current_log_len_chirho(usage_log_path_chirho)?;
    if let Some(aggregate_chirho) = try_load_fast_path_chirho(
        usage_log_path_chirho,
        current_len_chirho,
        expected_next_seq_chirho,
        policy_hash_chirho,
        app_chirho,
    ) {
        return Ok(aggregate_chirho);
    }
    rebuild_from_full_scan_chirho(
        root_chirho,
        current_len_chirho,
        policy_chirho,
        policy_hash_chirho,
        app_chirho,
        load_resource_usage_chirho_fn,
        meter_for_chirho_fn,
    )
}

fn current_log_len_chirho(usage_log_path_chirho: &Path) -> Result<u64> {
    match std::fs::metadata(usage_log_path_chirho) {
        Ok(metadata_chirho) => Ok(metadata_chirho.len()),
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error_chirho) => {
            Err(error_chirho).with_context(|| format!("stat {}", usage_log_path_chirho.display()))
        }
    }
}

fn try_load_fast_path_chirho(
    usage_log_path_chirho: &Path,
    current_len_chirho: u64,
    expected_next_seq_chirho: u64,
    policy_hash_chirho: &HashChirho,
    app_chirho: &str,
) -> Option<UsageAggregateChirho> {
    // The sidecar is advisory: unreadable or unparsable for any reason is a miss, never an error.
    let checkpoint_path_chirho = usage_checkpoint_path_chirho(usage_log_path_chirho);
    let bytes_chirho = std::fs::read(&checkpoint_path_chirho).ok()?;
    let file_chirho: UsageCheckpointFileChirho = serde_json::from_slice(&bytes_chirho).ok()?;
    if file_chirho.schema_chirho != USAGE_CHECKPOINT_SCHEMA_CHIRHO
        || file_chirho.usage_log_byte_len_chirho != current_len_chirho
        || file_chirho.next_seq_chirho != expected_next_seq_chirho
        || file_chirho.policy_hash_chirho != policy_hash_chirho.0
        || file_chirho.app_chirho != app_chirho
    {
        return None;
    }
    Some(UsageAggregateChirho::from_file_chirho(file_chirho))
}

fn rebuild_from_full_scan_chirho<LoadFnChirho, MeterForFnChirho>(
    root_chirho: &Path,
    current_len_chirho: u64,
    policy_chirho: &AppResourcePolicyChirho,
    policy_hash_chirho: &HashChirho,
    app_chirho: &str,
    load_resource_usage_chirho_fn: LoadFnChirho,
    meter_for_chirho_fn: MeterForFnChirho,
) -> Result<UsageAggregateChirho>
where
    LoadFnChirho: Fn(&Path) -> Result<Vec<ResourceUsageRecordChirho>>,
    MeterForFnChirho: for<'policy_chirho> Fn(
        &'policy_chirho AppResourcePolicyChirho,
        &str,
    ) -> Result<&'policy_chirho ResourceMeterChirho>,
{
    let records_chirho = load_resource_usage_chirho_fn(root_chirho)?;
    let mut aggregate_chirho = UsageAggregateChirho::empty_chirho(policy_hash_chirho, app_chirho);
    for record_chirho in &records_chirho {
        // Only rows enforced under the current policy for this app count in a current decision; other
        // rows (older policy versions, other apps sharing the log) are excluded exactly as
        // used_amount_chirho excludes them by its policy-hash and app filter.
        if record_chirho.resource_policy_chirho == *policy_hash_chirho
            && record_chirho.app_chirho == app_chirho
        {
            fold_record_chirho(
                &mut aggregate_chirho,
                record_chirho,
                policy_chirho,
                &meter_for_chirho_fn,
            );
        }
    }
    aggregate_chirho.byte_len_chirho = current_len_chirho;
    aggregate_chirho.next_seq_chirho = records_chirho.len() as u64;
    Ok(aggregate_chirho)
}

/// After the appended line is durably fsynced, fold the new row in, advance the sequence, and durably
/// rewrite the checkpoint. Called only post-append so the checkpoint can lag but never lead the log —
/// a crash before it lands just makes the next append's stale-guard miss and rebuild. Every step is
/// advisory: a failed re-stat or durable write is swallowed, because the committed append (and, on an
/// authority/money log, its receipt) must not be turned into an error a caller would retry.
///
/// `meter_for_chirho_fn` is the metering glue; `write_file_durable_chirho_fn` is the root-side durable
/// writer (`cairn_durable_chirho::write_file_durable_chirho`), so this pure core takes no filesystem
/// crate dependency of its own.
pub fn fold_and_persist_after_append_chirho<MeterForFnChirho, WriteDurableFnChirho>(
    usage_log_path_chirho: &Path,
    aggregate_chirho: &mut UsageAggregateChirho,
    record_chirho: &ResourceUsageRecordChirho,
    policy_chirho: &AppResourcePolicyChirho,
    meter_for_chirho_fn: MeterForFnChirho,
    write_file_durable_chirho_fn: WriteDurableFnChirho,
) where
    MeterForFnChirho: for<'policy_chirho> Fn(
        &'policy_chirho AppResourcePolicyChirho,
        &str,
    ) -> Result<&'policy_chirho ResourceMeterChirho>,
    WriteDurableFnChirho: Fn(&Path, &[u8]) -> std::io::Result<()>,
{
    fold_record_chirho(
        aggregate_chirho,
        record_chirho,
        policy_chirho,
        meter_for_chirho_fn,
    );
    aggregate_chirho.next_seq_chirho = record_chirho.seq_chirho.saturating_add(1);
    let _ = persist_after_append_chirho(
        usage_log_path_chirho,
        aggregate_chirho,
        write_file_durable_chirho_fn,
    );
}

fn persist_after_append_chirho<WriteDurableFnChirho>(
    usage_log_path_chirho: &Path,
    aggregate_chirho: &mut UsageAggregateChirho,
    write_file_durable_chirho_fn: WriteDurableFnChirho,
) -> Result<()>
where
    WriteDurableFnChirho: Fn(&Path, &[u8]) -> std::io::Result<()>,
{
    aggregate_chirho.byte_len_chirho = std::fs::metadata(usage_log_path_chirho)
        .with_context(|| format!("stat {}", usage_log_path_chirho.display()))?
        .len();
    let checkpoint_path_chirho = usage_checkpoint_path_chirho(usage_log_path_chirho);
    let text_chirho =
        serde_json::to_string(&aggregate_chirho.to_file_chirho()).with_context(|| {
            format!(
                "encode usage checkpoint {}",
                checkpoint_path_chirho.display()
            )
        })?;
    write_file_durable_chirho_fn(&checkpoint_path_chirho, text_chirho.as_bytes()).with_context(
        || {
            format!(
                "write usage checkpoint {}",
                checkpoint_path_chirho.display()
            )
        },
    )
}
