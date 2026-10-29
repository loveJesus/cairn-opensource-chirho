// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The use window (brick 4a-2): the scoped-token uses of a verified log, counted by rate key inside a window and never
//! discounted, so a bearer request's rate decision reads a few buckets instead of every past use.
//!
//! Today's rule, which this count must equal exactly (`oauth_chirho::scoped_token_use_matches_rate_key_chirho`): a
//! use counts for a requesting token when it is of the token's app, `at_ms >= now - window` with no upper bound, and
//! it is of the token's principal OR of the token's device. The OR is a union, so a use matching both counts once:
//! |app, principal| + |app, device| - |app, principal, device|. A use without a device enters no device bucket, and a
//! token without one counts its principal bucket alone: an absent device never matches, on either side.
//!
//! The view that owns this index prunes below `high_water - window ceiling - tolerance`; a decision whose window starts
//! at or above that cutoff is exact, the same argument as the sign-in window's. Unlike the sign-in log, the use log's
//! own verifier checks every record's rate against every earlier record, so an APPEND decided from pruned history
//! could write a record the verifier refuses forever: `exact_count_chirho` therefore answers only when the window
//! starts inside the retained history, and the append door refuses (transiently) when it cannot.

use std::collections::{BTreeMap, HashMap};

/// What the use window needs from one verified use record.
pub trait UseRecordChirho {
    fn app_chirho(&self) -> &str;
    fn principal_chirho(&self) -> &str;
    fn device_chirho(&self) -> Option<&str>;
    fn at_ms_chirho(&self) -> u64;
}

/// One rate decision's key: the requesting token's app, principal and device, and its window.
#[derive(Clone, Copy, Debug)]
pub struct UseRateKeyChirho<'key_chirho> {
    pub app_chirho: &'key_chirho str,
    pub principal_chirho: &'key_chirho str,
    pub device_chirho: Option<&'key_chirho str>,
    pub window_ms_chirho: u64,
}

/// Each bucket maps a use time to how many uses happened at it.
type BucketChirho = BTreeMap<u64, u64>;

#[derive(Default)]
pub struct UseWindowIndexChirho {
    by_principal_chirho: HashMap<(String, String), BucketChirho>,
    by_device_chirho: HashMap<(String, String), BucketChirho>,
    by_principal_device_chirho: HashMap<(String, String, String), BucketChirho>,
    /// The latest `now` the owning view has decided at.
    high_water_ms_chirho: u64,
    /// Every use at or after this time is retained; uses before it may have been pruned.
    retained_from_ms_chirho: u64,
}

fn count_from_chirho(bucket_chirho: Option<&BucketChirho>, window_start_chirho: u64) -> u64 {
    bucket_chirho.map_or(0, |bucket_chirho| {
        bucket_chirho
            .range(window_start_chirho..)
            .map(|(_, uses_chirho)| uses_chirho)
            .sum()
    })
}

fn add_use_chirho(bucket_chirho: &mut BucketChirho, at_ms_chirho: u64) {
    *bucket_chirho.entry(at_ms_chirho).or_default() += 1;
}

fn prune_bucket_chirho(bucket_chirho: &mut BucketChirho, cutoff_ms_chirho: u64) -> bool {
    *bucket_chirho = bucket_chirho.split_off(&cutoff_ms_chirho);
    !bucket_chirho.is_empty()
}

impl UseWindowIndexChirho {
    /// Today's count for `key_chirho` at `now_ms_chirho`, when the window starts inside the retained history; `None`
    /// when uses the window covers may have been pruned (a clock step back beyond the tolerance), so the count cannot
    /// be exact. The append door decides only from this.
    pub fn exact_count_chirho(
        &self,
        key_chirho: &UseRateKeyChirho<'_>,
        now_ms_chirho: u64,
    ) -> Option<u64> {
        (now_ms_chirho.saturating_sub(key_chirho.window_ms_chirho) >= self.retained_from_ms_chirho)
            .then(|| self.count_chirho(key_chirho, now_ms_chirho))
    }

    /// The count from the retained uses: today's count whenever `exact_count_chirho` answers, and a lower bound
    /// otherwise. The fold checks a record's rate with it.
    pub fn count_chirho(&self, key_chirho: &UseRateKeyChirho<'_>, now_ms_chirho: u64) -> u64 {
        let window_start_chirho = now_ms_chirho.saturating_sub(key_chirho.window_ms_chirho);
        let app_chirho = key_chirho.app_chirho.to_string();
        let principal_chirho = key_chirho.principal_chirho.to_string();
        let by_principal_chirho = count_from_chirho(
            self.by_principal_chirho
                .get(&(app_chirho.clone(), principal_chirho.clone())),
            window_start_chirho,
        );
        let Some(device_chirho) = key_chirho.device_chirho else {
            return by_principal_chirho;
        };
        let device_chirho = device_chirho.to_string();
        let by_device_chirho = count_from_chirho(
            self.by_device_chirho
                .get(&(app_chirho.clone(), device_chirho.clone())),
            window_start_chirho,
        );
        let by_both_chirho = count_from_chirho(
            self.by_principal_device_chirho
                .get(&(app_chirho, principal_chirho, device_chirho)),
            window_start_chirho,
        );
        // Every use in the both-bucket is in each of the other two, so this cannot go below zero.
        by_principal_chirho + by_device_chirho - by_both_chirho
    }

    /// Fold one verified use into every bucket it belongs to.
    pub fn fold_chirho<R: UseRecordChirho>(&mut self, record_chirho: &R) {
        let app_chirho = record_chirho.app_chirho().to_string();
        let principal_chirho = record_chirho.principal_chirho().to_string();
        let at_ms_chirho = record_chirho.at_ms_chirho();
        add_use_chirho(
            self.by_principal_chirho
                .entry((app_chirho.clone(), principal_chirho.clone()))
                .or_default(),
            at_ms_chirho,
        );
        if let Some(device_chirho) = record_chirho.device_chirho() {
            add_use_chirho(
                self.by_device_chirho
                    .entry((app_chirho.clone(), device_chirho.to_string()))
                    .or_default(),
                at_ms_chirho,
            );
            add_use_chirho(
                self.by_principal_device_chirho
                    .entry((app_chirho, principal_chirho, device_chirho.to_string()))
                    .or_default(),
                at_ms_chirho,
            );
        }
    }

    /// The owning view's clock rule (the sign-in window's): a clock more than `tolerance_ms_chirho` behind the latest
    /// time decided needs the index rebuilt from the whole log, since pruning already used that later time.
    pub fn needs_rebuild_chirho(&self, now_ms_chirho: u64, tolerance_ms_chirho: u64) -> bool {
        now_ms_chirho
            < self
                .high_water_ms_chirho
                .saturating_sub(tolerance_ms_chirho)
    }

    /// After each update: move the high-water mark, then keep `horizon_ms_chirho` of history behind `now_ms_chirho`.
    pub fn advance_chirho(&mut self, now_ms_chirho: u64, horizon_ms_chirho: u64) {
        self.high_water_ms_chirho = self.high_water_ms_chirho.max(now_ms_chirho);
        self.prune_chirho(now_ms_chirho.saturating_sub(horizon_ms_chirho));
    }

    /// Drop every use below `cutoff_ms_chirho`, from all three bucket kinds alike, and empty buckets.
    pub fn prune_chirho(&mut self, cutoff_ms_chirho: u64) {
        self.retained_from_ms_chirho = self.retained_from_ms_chirho.max(cutoff_ms_chirho);
        self.by_principal_chirho
            .retain(|_, bucket_chirho| prune_bucket_chirho(bucket_chirho, cutoff_ms_chirho));
        self.by_device_chirho
            .retain(|_, bucket_chirho| prune_bucket_chirho(bucket_chirho, cutoff_ms_chirho));
        self.by_principal_device_chirho
            .retain(|_, bucket_chirho| prune_bucket_chirho(bucket_chirho, cutoff_ms_chirho));
    }

    /// Buckets retained: the index's memory, bounded by the rate limits times the window.
    pub fn tracked_buckets_chirho(&self) -> usize {
        self.by_principal_chirho.len()
            + self.by_device_chirho.len()
            + self.by_principal_device_chirho.len()
    }
}

#[cfg(test)]
#[path = "use_window_tests_chirho.rs"]
mod use_window_tests_chirho;
