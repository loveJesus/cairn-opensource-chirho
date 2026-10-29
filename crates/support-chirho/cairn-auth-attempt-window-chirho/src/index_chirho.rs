// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The sign-in window's index: each (principal hash, endpoint) key's failures since that key's last success, each
//! key's recent successes, and the latest time a decision was made at.

use crate::AttemptRecordChirho;
use std::collections::HashMap;

#[derive(Default)]
pub(crate) struct AuthIndexChirho {
    /// For each (principal hash, endpoint): the `at_ms` of every failure since that key's last success.
    failures_chirho: HashMap<(String, String), Vec<u64>>,
    /// For each (principal hash, endpoint): the `at_ms` of every retained success. Successes are never discounted;
    /// only a valid credential makes one, so a flood of guesses cannot grow this map (brick 4a, PFE #25922).
    successes_chirho: HashMap<(String, String), Vec<u64>>,
    /// The latest `now` this view has decided at.
    pub(crate) high_water_ms_chirho: u64,
}

fn count_from_chirho(times_chirho: Option<&Vec<u64>>, window_start_chirho: u64) -> u64 {
    times_chirho.map_or(0, |times_chirho| {
        times_chirho
            .iter()
            .filter(|&&at_ms_chirho| at_ms_chirho >= window_start_chirho)
            .count() as u64
    })
}

impl AuthIndexChirho {
    /// The key's retained failures at or after `window_start_chirho`.
    pub(crate) fn recent_failures_chirho(
        &self,
        principal_hash_chirho: &str,
        endpoint_chirho: &str,
        window_start_chirho: u64,
    ) -> u64 {
        count_from_chirho(
            self.failures_chirho.get(&(
                principal_hash_chirho.to_string(),
                endpoint_chirho.to_string(),
            )),
            window_start_chirho,
        )
    }

    /// The principal's retained successes at or after `window_start_chirho`, summed over `endpoints_chirho`.
    pub(crate) fn recent_successes_chirho(
        &self,
        principal_hash_chirho: &str,
        endpoints_chirho: &[&str],
        window_start_chirho: u64,
    ) -> u64 {
        endpoints_chirho
            .iter()
            .map(|endpoint_chirho| {
                count_from_chirho(
                    self.successes_chirho.get(&(
                        principal_hash_chirho.to_string(),
                        (*endpoint_chirho).to_string(),
                    )),
                    window_start_chirho,
                )
            })
            .sum()
    }

    /// Keys with a failure still retained: the part of the view's memory a flood of guesses can grow.
    pub(crate) fn tracked_keys_chirho(&self) -> usize {
        self.failures_chirho.len()
    }

    pub(crate) fn fold_chirho<R: AttemptRecordChirho>(&mut self, record_chirho: &R) {
        let key_chirho = (
            record_chirho.principal_hash_chirho().to_string(),
            record_chirho.endpoint_chirho().to_string(),
        );
        if record_chirho.is_success_chirho() {
            // A success discounts every earlier failure of its key; later failures always come after it.
            self.failures_chirho.remove(&key_chirho);
            self.successes_chirho
                .entry(key_chirho)
                .or_default()
                .push(record_chirho.at_ms_chirho());
        } else {
            self.failures_chirho
                .entry(key_chirho)
                .or_default()
                .push(record_chirho.at_ms_chirho());
        }
    }

    /// Drop failures below `failure_cutoff_ms_chirho` and successes below `success_cutoff_ms_chirho`, and keys
    /// with none left.
    pub(crate) fn prune_chirho(
        &mut self,
        failure_cutoff_ms_chirho: u64,
        success_cutoff_ms_chirho: u64,
    ) {
        for (times_by_key_chirho, cutoff_chirho) in [
            (&mut self.failures_chirho, failure_cutoff_ms_chirho),
            (&mut self.successes_chirho, success_cutoff_ms_chirho),
        ] {
            times_by_key_chirho.retain(|_, times_chirho| {
                times_chirho.retain(|&at_ms_chirho| at_ms_chirho >= cutoff_chirho);
                !times_chirho.is_empty()
            });
        }
    }
}
