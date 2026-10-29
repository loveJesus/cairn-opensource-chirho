// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The slot registry's eviction: least recently used first, and never for a slot already present. Moved here, with
//! its assertions unchanged, from the sign-in window crate when the engine was extracted.

use crate::{evict_to_fit_chirho, SlotChirho, SlotStateChirho};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[test]
fn eviction_drops_the_least_recently_used_slot_chirho() {
    let mut entries_chirho: HashMap<PathBuf, (SlotChirho<()>, u64)> = HashMap::new();
    for (name_chirho, tick_chirho) in [("a", 5u64), ("b", 2), ("c", 9)] {
        entries_chirho.insert(
            PathBuf::from(name_chirho),
            (
                Arc::new(Mutex::new(SlotStateChirho::empty_chirho())),
                tick_chirho,
            ),
        );
    }
    evict_to_fit_chirho(&mut entries_chirho, 3, &PathBuf::from("c"));
    assert_eq!(
        entries_chirho.len(),
        3,
        "a slot already present needs no room"
    );
    evict_to_fit_chirho(&mut entries_chirho, 3, &PathBuf::from("d"));
    assert_eq!(entries_chirho.len(), 2);
    assert!(
        !entries_chirho.contains_key(&PathBuf::from("b")),
        "the least recently used slot goes first"
    );
}
