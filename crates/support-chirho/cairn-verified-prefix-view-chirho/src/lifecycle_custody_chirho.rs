// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Counts every live job, including an evicted view's detached job, without retaining a path map.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/transient-review-fixture-chirho/producer-source-chirho.md`.

use std::sync::atomic::{AtomicUsize, Ordering};

static ACTIVE_CHIRHO: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct ActiveBackgroundJobGuardChirho {
    _private_chirho: (),
}

impl ActiveBackgroundJobGuardChirho {
    pub(crate) fn begin_chirho() -> Self {
        ACTIVE_CHIRHO
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count_chirho| {
                count_chirho.checked_add(1)
            })
            .expect("BackgroundCustodyOverflowChirho");
        Self {
            _private_chirho: (),
        }
    }
}

impl Drop for ActiveBackgroundJobGuardChirho {
    fn drop(&mut self) {
        ACTIVE_CHIRHO.fetch_sub(1, Ordering::Release);
    }
}

/// Zero is a quiescence witness only AFTER every producer has stopped, not during live admission.
pub fn active_background_jobs_chirho() -> usize {
    ACTIVE_CHIRHO.load(Ordering::Acquire)
}
