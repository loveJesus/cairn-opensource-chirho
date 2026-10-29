// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The hash-quarantine half of P3: a substituted object is parked, never served.
//!
//! WHY THIS EXISTS. The crate's adversarial suite is thorough about *authenticated* replication —
//! forged roster head/record signatures, tampered lines, truncated tails, wrong operator key,
//! equivocation, torn floor bytes — but nothing exercised `receive_objects_chirho`'s quarantine
//! BRANCH. The underlying `verify_content_address_chirho` is itself guarded (disabling it reddens
//! `verify_on_read_holds_on_every_node_load_chirho` in the pure-executor crate), yet that proves the
//! primitive, not this receiver's use of it: a receiver that verified correctly and then stored the
//! bytes anyway would keep every one of those tests green.
//!
//! So this pins the receiver's own contract, which is a CF8 acceptance criterion ("hash quarantine"):
//! a lying object never reaches the served store, its TRUE hash is what lands in quarantine, and the
//! evidence counts say so.

use cairn_core_chirho::cas_chirho::hash_chirho;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_core_chirho::ports_chirho::{ContentReadChirho, ContentStoreChirho, StoreResultChirho};
use cairn_replication_chirho::{
    receive_objects_chirho, ObjectReceiptChirho, QuarantineSinkChirho, ReplicationSourceChirho,
    REPLICA_PULL_REPORT_SCHEMA_CHIRHO,
};
use std::cell::RefCell;
use std::collections::BTreeMap;

/// A source that serves whatever bytes it is told to, under whatever address it is told to — so a
/// row whose bytes do not re-hash to its key is a substituted object on the wire.
struct LyingSourceChirho {
    objects_chirho: BTreeMap<HashChirho, Vec<u8>>,
}

impl ReplicationSourceChirho for LyingSourceChirho {
    fn list_object_addrs_chirho(&self) -> StoreResultChirho<Vec<HashChirho>> {
        Ok(self.objects_chirho.keys().cloned().collect())
    }

    fn fetch_object_chirho(&self, addr_chirho: &HashChirho) -> StoreResultChirho<Option<Vec<u8>>> {
        Ok(self.objects_chirho.get(addr_chirho).cloned())
    }

    fn fetch_named_log_chirho(&self, _name_chirho: &str) -> StoreResultChirho<Option<Vec<u8>>> {
        Ok(None)
    }
}

/// Records every byte string that reached the SERVED store. The point of the test is what is absent
/// from here.
#[derive(Default)]
struct RecordingServedStoreChirho {
    stored_chirho: RefCell<Vec<Vec<u8>>>,
}

impl ContentStoreChirho for RecordingServedStoreChirho {
    fn put_chirho(&self, bytes_chirho: &[u8]) -> StoreResultChirho<HashChirho> {
        self.stored_chirho.borrow_mut().push(bytes_chirho.to_vec());
        Ok(hash_chirho(bytes_chirho))
    }
}

impl ContentReadChirho for RecordingServedStoreChirho {
    fn get_chirho(&self, _addr_chirho: &HashChirho) -> StoreResultChirho<Option<Vec<u8>>> {
        Ok(None)
    }
}

#[derive(Default)]
struct RecordingQuarantineChirho {
    parked_chirho: RefCell<Vec<(HashChirho, HashChirho, Vec<u8>)>>,
}

impl QuarantineSinkChirho for RecordingQuarantineChirho {
    fn quarantine_chirho(
        &self,
        requested_chirho: &HashChirho,
        actual_chirho: &HashChirho,
        bytes_chirho: &[u8],
    ) -> StoreResultChirho<()> {
        self.parked_chirho.borrow_mut().push((
            requested_chirho.clone(),
            actual_chirho.clone(),
            bytes_chirho.to_vec(),
        ));
        Ok(())
    }
}

#[test]
fn a_substituted_object_is_quarantined_and_never_reaches_the_served_store_chirho() {
    let honest_bytes_chirho = b"honest-object-chirho".to_vec();
    let honest_addr_chirho = hash_chirho(&honest_bytes_chirho);

    // The lie: bytes offered under an address they do not hash to.
    let substituted_bytes_chirho = b"substituted-payload-chirho".to_vec();
    let claimed_addr_chirho = hash_chirho(b"what-the-replica-asked-for-chirho");
    let true_addr_chirho = hash_chirho(&substituted_bytes_chirho);
    assert_ne!(
        claimed_addr_chirho, true_addr_chirho,
        "the fixture must actually lie, or this test proves nothing"
    );

    let mut objects_chirho = BTreeMap::new();
    objects_chirho.insert(honest_addr_chirho.clone(), honest_bytes_chirho.clone());
    objects_chirho.insert(
        claimed_addr_chirho.clone(),
        substituted_bytes_chirho.clone(),
    );
    let source_chirho = LyingSourceChirho { objects_chirho };
    let served_chirho = RecordingServedStoreChirho::default();
    let quarantine_chirho = RecordingQuarantineChirho::default();

    let (report_chirho, receipts_chirho) =
        receive_objects_chirho(&source_chirho, &served_chirho, &quarantine_chirho)
            .expect("pull completes; a lying object is quarantined, not an error");

    // THE PROPERTY: the substituted bytes never reached the served store.
    let stored_chirho = served_chirho.stored_chirho.borrow();
    assert!(
        !stored_chirho.contains(&substituted_bytes_chirho),
        "substituted bytes reached the SERVED store — a replica would serve them"
    );
    assert!(
        stored_chirho.contains(&honest_bytes_chirho),
        "the honest object must still be stored, or the receiver is failing shut on everything and \
         this test would pass for the wrong reason"
    );

    // The quarantine records the TRUE hash, since the requested address is the lie.
    let parked_chirho = quarantine_chirho.parked_chirho.borrow();
    assert_eq!(
        parked_chirho.len(),
        1,
        "exactly one object should be parked"
    );
    assert_eq!(parked_chirho[0].0, claimed_addr_chirho, "requested address");
    assert_eq!(
        parked_chirho[0].1, true_addr_chirho,
        "quarantine must record the bytes' TRUE blake3, not the address they were requested under"
    );
    assert_eq!(parked_chirho[0].2, substituted_bytes_chirho);

    // The evidence counts say so, and carry no paths or bytes.
    assert_eq!(
        report_chirho.schema_chirho,
        REPLICA_PULL_REPORT_SCHEMA_CHIRHO
    );
    assert_eq!(report_chirho.listed_chirho, 2);
    assert_eq!(report_chirho.stored_chirho, 1);
    assert_eq!(report_chirho.quarantined_chirho, 1);
    assert_eq!(report_chirho.missing_chirho, 0);

    assert!(
        receipts_chirho.contains(&ObjectReceiptChirho::StoredChirho {
            addr_chirho: honest_addr_chirho,
        })
    );
    assert!(
        receipts_chirho.contains(&ObjectReceiptChirho::QuarantinedChirho {
            requested_chirho: claimed_addr_chirho,
            actual_chirho: true_addr_chirho,
        })
    );
}
