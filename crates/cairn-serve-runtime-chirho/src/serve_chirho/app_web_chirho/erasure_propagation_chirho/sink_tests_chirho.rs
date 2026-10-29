// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! C5 B3-a2-ii's integration arms: the root's elected erasure driving the real leader store through the sink, so the store's own retry, carry, binding and evidence rules meet the root's classification and locks.

use super::ErasurePropagationSinkChirho;
use anyhow::{bail, Result};
use cairn_chirho::privacy_chirho::{
    erase_subject_data_with_requirement_chirho, erasure_record_digest_hex_chirho,
    load_privacy_erasure_records_chirho, reconcile_subject_erasure_bindings_chirho,
    store_private_blob_chirho, EarlierErasureEvidenceChirho, ErasureCaptureChirho,
    ErasureRecordedBindingPendingChirho, ErasureRequirementSinkChirho, PrivacyErasureRecordChirho,
    PrivateBlobAttributionChirho,
};
use cairn_key_custody_chirho::{
    subject_digest_hex_chirho, ErasurePropagationContextChirho,
    VerifiedErasurePropagationRequirementChirho,
};
use cairn_key_custody_http_chirho::{
    ErasurePropagationStoreChirho, RequirementStandingChirho, ERASURE_PROPAGATION_STORE_DIR_CHIRHO,
};
use cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho;
use cairn_tenant_chirho::surface_disposition_chirho::{
    policy_for_surface_chirho, RootSurfacePolicyChirho, SourceRetirementDispositionChirho,
    SurfaceDispositionChirho, SurfacePayloadDispositionChirho,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const ALICE_CHIRHO: &str = "user/alice";
const BOB_CHIRHO: &str = "user/bob";

static NEXT_ROOT_CHIRHO: AtomicU64 = AtomicU64::new(0);

fn tmp_root_chirho() -> PathBuf {
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-a2ii-sink-{}-{}-chirho",
        std::process::id(),
        NEXT_ROOT_CHIRHO.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn store_blob_chirho(root_chirho: &Path, subject_chirho: &str) -> String {
    store_private_blob_chirho(
        root_chirho,
        &PrivateBlobAttributionChirho::account_owned_chirho(subject_chirho).unwrap(),
        subject_chirho,
        b"a2-ii sink fixture",
    )
    .unwrap()
    .key_id_chirho
}

/// The store for this root, issued by the root's own existing key, which the first blob minted.
fn open_store_chirho(root_chirho: &Path) -> ErasurePropagationStoreChirho {
    let issuer_chirho = existing_keypair_pubkey_hex_chirho(root_chirho).unwrap();
    let context_chirho = ErasurePropagationContextChirho::new_chirho(
        &"c".repeat(64),
        "tenant-a2ii-chirho",
        "genesis-a2ii-chirho",
        &issuer_chirho,
    )
    .unwrap();
    ErasurePropagationStoreChirho::open_chirho(root_chirho, context_chirho).unwrap()
}

/// The current serving members: here, only the leader itself.
fn holders_chirho(root_chirho: &Path) -> BTreeSet<String> {
    BTreeSet::from([existing_keypair_pubkey_hex_chirho(root_chirho).unwrap()])
}

fn erase_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    required_chirho: &[&str],
    sink_chirho: &dyn ErasureRequirementSinkChirho,
) -> Result<PrivacyErasureRecordChirho> {
    erase_subject_data_with_requirement_chirho(
        root_chirho,
        subject_chirho,
        "owner/admin",
        "gdpr-erasure",
        &required_chirho
            .iter()
            .map(|key_id_chirho| key_id_chirho.to_string())
            .collect(),
        sink_chirho,
    )
}

fn entries_chirho(
    store_chirho: &ErasurePropagationStoreChirho,
    subject_chirho: &str,
) -> Vec<(
    VerifiedErasurePropagationRequirementChirho,
    RequirementStandingChirho,
)> {
    store_chirho
        .subject_view_chirho(&subject_digest_hex_chirho(subject_chirho))
        .unwrap()
        .entries_chirho()
        .to_vec()
}

fn ids_chirho(ids_chirho: &[&String]) -> BTreeSet<String> {
    ids_chirho
        .iter()
        .map(|id_chirho| id_chirho.to_string())
        .collect()
}

fn key_ids_chirho(
    requirement_chirho: &VerifiedErasurePropagationRequirementChirho,
) -> BTreeSet<String> {
    requirement_chirho
        .key_ids_chirho()
        .iter()
        .cloned()
        .collect()
}

/// The digest the requirement's binding names, or a panic naming how it stands instead.
fn bound_digest_chirho(standing_chirho: &RequirementStandingChirho) -> String {
    match standing_chirho {
        RequirementStandingChirho::BoundChirho(binding_chirho) => {
            binding_chirho.erasure_record_digest_chirho().to_string()
        }
        other_chirho => panic!("expected a bound requirement, found {other_chirho:?}"),
    }
}

/// Makes the requirement durable through the real sink, then stops the erasure before any unlink, as a
/// crash after the store's write would.
struct StopAfterRequirementChirho<'sink_chirho, 'store_chirho>(
    &'sink_chirho ErasurePropagationSinkChirho<'store_chirho>,
);

impl ErasureRequirementSinkChirho for StopAfterRequirementChirho<'_, '_> {
    fn unbound_requirement_seqs_chirho(&self, subject_chirho: &str) -> Result<Vec<u64>> {
        self.0.unbound_requirement_seqs_chirho(subject_chirho)
    }

    fn record_requirement_chirho(
        &self,
        capture_chirho: &ErasureCaptureChirho,
        earlier_chirho: &BTreeMap<u64, EarlierErasureEvidenceChirho>,
    ) -> Result<()> {
        self.0
            .record_requirement_chirho(capture_chirho, earlier_chirho)?;
        bail!("stopped after the requirement became durable")
    }

    fn record_binding_chirho(
        &self,
        erasure_seq_chirho: u64,
        subject_chirho: &str,
        erasure_record_digest_chirho: &str,
    ) -> Result<()> {
        self.0.record_binding_chirho(
            erasure_seq_chirho,
            subject_chirho,
            erasure_record_digest_chirho,
        )
    }
}

/// Records the requirement through the real sink, then loses the binding after the record's append.
struct LoseBindingChirho<'sink_chirho, 'store_chirho>(
    &'sink_chirho ErasurePropagationSinkChirho<'store_chirho>,
);

impl ErasureRequirementSinkChirho for LoseBindingChirho<'_, '_> {
    fn unbound_requirement_seqs_chirho(&self, subject_chirho: &str) -> Result<Vec<u64>> {
        self.0.unbound_requirement_seqs_chirho(subject_chirho)
    }

    fn record_requirement_chirho(
        &self,
        capture_chirho: &ErasureCaptureChirho,
        earlier_chirho: &BTreeMap<u64, EarlierErasureEvidenceChirho>,
    ) -> Result<()> {
        self.0
            .record_requirement_chirho(capture_chirho, earlier_chirho)
    }

    fn record_binding_chirho(
        &self,
        _seq_chirho: u64,
        _subject_chirho: &str,
        _digest_chirho: &str,
    ) -> Result<()> {
        bail!("binding lost")
    }
}

#[test]
fn an_exact_retry_keeps_its_stored_cut_and_the_next_new_requirement_takes_the_required_key_chirho()
{
    // gpt's producer arm (design item 10), against the real store.
    let root_chirho = tmp_root_chirho();
    let first_key_chirho = store_blob_chirho(&root_chirho, ALICE_CHIRHO);
    let store_chirho = open_store_chirho(&root_chirho);
    let sink_chirho =
        ErasurePropagationSinkChirho::new_chirho(&store_chirho, holders_chirho(&root_chirho));

    // A pre-freeze attempt: its requirement is durable, and the erasure stops before any unlink or record.
    erase_chirho(
        &root_chirho,
        ALICE_CHIRHO,
        &[],
        &StopAfterRequirementChirho(&sink_chirho),
    )
    .unwrap_err();
    assert!(load_privacy_erasure_records_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    // K2 is a key the frozen inventory gives Alice, with no key file and no blob row in this root.
    let required_key_chirho = "cd".repeat(16);

    let retry_chirho = erase_chirho(
        &root_chirho,
        ALICE_CHIRHO,
        &[&required_key_chirho],
        &sink_chirho,
    )
    .unwrap();
    let next_chirho = erase_chirho(
        &root_chirho,
        ALICE_CHIRHO,
        &[&required_key_chirho],
        &sink_chirho,
    )
    .unwrap();

    assert_eq!((retry_chirho.seq_chirho, next_chirho.seq_chirho), (0, 1));
    let entries_chirho = entries_chirho(&store_chirho, ALICE_CHIRHO);
    assert_eq!(entries_chirho.len(), 2);
    assert_eq!(
        key_ids_chirho(&entries_chirho[0].0),
        ids_chirho(&[&first_key_chirho]),
        "the exact retry keeps the stored cut, which does not cover K2"
    );
    assert_eq!(
        key_ids_chirho(&entries_chirho[1].0),
        ids_chirho(&[&first_key_chirho, &required_key_chirho]),
        "the next new requirement covers K2, with no file and no blob row"
    );
    for ((_, standing_chirho), record_chirho) in
        entries_chirho.iter().zip([&retry_chirho, &next_chirho])
    {
        assert_eq!(
            bound_digest_chirho(standing_chirho),
            erasure_record_digest_hex_chirho(record_chirho).unwrap()
        );
    }
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_never_recorded_attempt_is_carried_by_the_next_requirement_chirho() {
    let root_chirho = tmp_root_chirho();
    let alice_key_chirho = store_blob_chirho(&root_chirho, ALICE_CHIRHO);
    store_blob_chirho(&root_chirho, BOB_CHIRHO);
    let store_chirho = open_store_chirho(&root_chirho);
    let sink_chirho =
        ErasurePropagationSinkChirho::new_chirho(&store_chirho, holders_chirho(&root_chirho));
    erase_chirho(
        &root_chirho,
        ALICE_CHIRHO,
        &[],
        &StopAfterRequirementChirho(&sink_chirho),
    )
    .unwrap_err();
    // Bob's erasure takes seq 0, so Alice's attempt there was never recorded.
    assert_eq!(
        erase_chirho(&root_chirho, BOB_CHIRHO, &[], &sink_chirho)
            .unwrap()
            .seq_chirho,
        0
    );

    let record_chirho = erase_chirho(&root_chirho, ALICE_CHIRHO, &[], &sink_chirho).unwrap();

    assert_eq!(record_chirho.seq_chirho, 1);
    let entries_chirho = entries_chirho(&store_chirho, ALICE_CHIRHO);
    assert_eq!(entries_chirho.len(), 2);
    assert_eq!(
        entries_chirho[0].1,
        RequirementStandingChirho::CarriedByChirho {
            bound_seq_chirho: 1
        }
    );
    assert_eq!(
        bound_digest_chirho(&entries_chirho[1].1),
        erasure_record_digest_hex_chirho(&record_chirho).unwrap()
    );
    assert!(key_ids_chirho(&entries_chirho[1].0).contains(&alice_key_chirho));
    assert!(entries_chirho[1]
        .0
        .succeeds_chirho()
        .iter()
        .any(|carried_chirho| carried_chirho.erasure_seq_chirho == 0));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_binding_lost_after_the_append_stays_pending_until_reconcile_binds_it_chirho() {
    let root_chirho = tmp_root_chirho();
    store_blob_chirho(&root_chirho, ALICE_CHIRHO);
    let store_chirho = open_store_chirho(&root_chirho);
    let sink_chirho =
        ErasurePropagationSinkChirho::new_chirho(&store_chirho, holders_chirho(&root_chirho));

    let error_chirho = erase_chirho(
        &root_chirho,
        ALICE_CHIRHO,
        &[],
        &LoseBindingChirho(&sink_chirho),
    )
    .unwrap_err();

    assert!(!format!("{error_chirho:#}").contains("binding lost"));
    let pending_chirho = error_chirho
        .downcast_ref::<ErasureRecordedBindingPendingChirho>()
        .expect("a binding lost after the append is typed pending")
        .clone();
    assert_eq!(
        entries_chirho(&store_chirho, ALICE_CHIRHO)[0].1,
        RequirementStandingChirho::PendingChirho
    );

    let bound_chirho =
        reconcile_subject_erasure_bindings_chirho(&root_chirho, ALICE_CHIRHO, &sink_chirho)
            .unwrap();

    assert_eq!(bound_chirho, vec![0]);
    assert_eq!(
        bound_digest_chirho(&entries_chirho(&store_chirho, ALICE_CHIRHO)[0].1),
        pending_chirho.erasure_record_digest_chirho
    );
    assert_eq!(
        load_privacy_erasure_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        1
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn the_next_erasure_binds_a_recorded_attempt_instead_of_carrying_it_chirho() {
    let root_chirho = tmp_root_chirho();
    store_blob_chirho(&root_chirho, ALICE_CHIRHO);
    let store_chirho = open_store_chirho(&root_chirho);
    let sink_chirho =
        ErasurePropagationSinkChirho::new_chirho(&store_chirho, holders_chirho(&root_chirho));
    let pending_chirho = erase_chirho(
        &root_chirho,
        ALICE_CHIRHO,
        &[],
        &LoseBindingChirho(&sink_chirho),
    )
    .unwrap_err()
    .downcast_ref::<ErasureRecordedBindingPendingChirho>()
    .expect("typed pending")
    .clone();

    let record_chirho = erase_chirho(&root_chirho, ALICE_CHIRHO, &[], &sink_chirho).unwrap();

    assert_eq!(record_chirho.seq_chirho, 1);
    let entries_chirho = entries_chirho(&store_chirho, ALICE_CHIRHO);
    assert_eq!(
        bound_digest_chirho(&entries_chirho[0].1),
        pending_chirho.erasure_record_digest_chirho,
        "the recorded attempt is bound to its own record"
    );
    assert_eq!(
        bound_digest_chirho(&entries_chirho[1].1),
        erasure_record_digest_hex_chirho(&record_chirho).unwrap()
    );
    assert!(
        entries_chirho[1].0.succeeds_chirho().is_empty(),
        "a recorded attempt is never carried"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn the_store_directory_is_carried_and_retained_at_source_chirho() {
    // The store's constant and the CF8 table's row must name the same surface. A drift would fail closed
    // as an unknown surface, but this arm names it before any migration has to.
    assert_eq!(
        policy_for_surface_chirho(ERASURE_PROPAGATION_STORE_DIR_CHIRHO),
        Some(RootSurfacePolicyChirho {
            movement_disposition_chirho: SurfaceDispositionChirho::CarriedWithTheRootChirho,
            payload_disposition_chirho: SurfacePayloadDispositionChirho::CommittedPayloadChirho,
            source_retirement_disposition_chirho:
                SourceRetirementDispositionChirho::RetainAtSourceChirho,
        })
    );
}
