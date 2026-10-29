// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use crate::reconciliation_chirho::{
    gd7_reconciliation_checkpoint_path_chirho, gd7_reconciliation_group_has_any_active_hold_chirho,
    gd7_reconciliation_group_head_path_chirho, gd7_reconciliation_head_path_chirho,
    Gd7ForkCoordinateChirho, Gd7JournalTailCoordinateChirho, Gd7ReconciliationCheckpointChirho,
    Gd7ReconciliationCheckpointStateChirho, Gd7ReconciliationIdentityChirho,
    Gd7ReconciliationPhaseChirho, Gd7ReconciliationSignerPortChirho, Gd7ReconciliationStoreChirho,
    Gd7ReconciliationStoreRefusalChirho, Gd7ReconciliationVerifierPortChirho,
    MAX_GD7_RECONCILIATION_CHECKPOINT_BYTES_CHIRHO, MAX_GD7_RECONCILIATION_HEAD_BYTES_CHIRHO,
};
use anyhow::{anyhow, Result};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    compose_writer_epoch_chirho, consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

#[derive(Default)]
struct FakeReconciliationStorageChirho {
    objects_chirho: RefCell<BTreeMap<String, Vec<u8>>>,
    operation_count_chirho: Cell<usize>,
    list_count_chirho: Cell<usize>,
    read_all_count_chirho: Cell<usize>,
}

impl FakeReconciliationStorageChirho {
    fn observe_operation_chirho(&self) {
        self.operation_count_chirho
            .set(self.operation_count_chirho.get() + 1);
    }

    fn force_put_chirho(&self, path_chirho: &StoragePathChirho, bytes_chirho: Vec<u8>) {
        self.objects_chirho
            .borrow_mut()
            .insert(path_chirho.key_chirho().to_owned(), bytes_chirho);
    }

    fn force_remove_chirho(&self, path_chirho: &StoragePathChirho) {
        self.objects_chirho
            .borrow_mut()
            .remove(path_chirho.key_chirho());
    }

    fn bytes_chirho(&self, path_chirho: &StoragePathChirho) -> Option<Vec<u8>> {
        self.objects_chirho
            .borrow()
            .get(path_chirho.key_chirho())
            .cloned()
    }
}

impl LedgerStoragePortChirho for FakeReconciliationStorageChirho {
    fn create_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<CreateDurableOutcomeChirho> {
        self.observe_operation_chirho();
        let mut objects_chirho = self.objects_chirho.borrow_mut();
        if objects_chirho.contains_key(path_chirho.key_chirho()) {
            return Ok(CreateDurableOutcomeChirho::AlreadyExistsChirho);
        }
        objects_chirho.insert(path_chirho.key_chirho().to_owned(), bytes_chirho.to_vec());
        Ok(CreateDurableOutcomeChirho::CreatedChirho)
    }

    fn append_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        self.observe_operation_chirho();
        self.objects_chirho
            .borrow_mut()
            .entry(path_chirho.key_chirho().to_owned())
            .or_default()
            .extend_from_slice(bytes_chirho);
        Ok(())
    }

    fn read_all_chirho(&self, path_chirho: &StoragePathChirho) -> Result<Option<Vec<u8>>> {
        self.observe_operation_chirho();
        self.read_all_count_chirho
            .set(self.read_all_count_chirho.get() + 1);
        Ok(self.bytes_chirho(path_chirho))
    }

    fn object_len_chirho(&self, path_chirho: &StoragePathChirho) -> Result<Option<u64>> {
        self.observe_operation_chirho();
        self.objects_chirho
            .borrow()
            .get(path_chirho.key_chirho())
            .map(|bytes_chirho| {
                u64::try_from(bytes_chirho.len())
                    .map_err(|_| anyhow!("fake object length cannot fit u64"))
            })
            .transpose()
    }

    fn read_exact_range_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        offset_chirho: u64,
        len_chirho: u64,
    ) -> Result<Vec<u8>> {
        self.observe_operation_chirho();
        let offset_chirho =
            usize::try_from(offset_chirho).map_err(|_| anyhow!("invalid fake offset"))?;
        let len_chirho = usize::try_from(len_chirho).map_err(|_| anyhow!("invalid fake length"))?;
        let end_chirho = offset_chirho
            .checked_add(len_chirho)
            .ok_or_else(|| anyhow!("invalid fake range"))?;
        let objects_chirho = self.objects_chirho.borrow();
        let bytes_chirho = objects_chirho
            .get(path_chirho.key_chirho())
            .ok_or_else(|| anyhow!("missing fake object"))?;
        if end_chirho > bytes_chirho.len() {
            return Err(anyhow!("fake range exceeds object"));
        }
        Ok(bytes_chirho[offset_chirho..end_chirho].to_vec())
    }

    fn atomic_write_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        self.observe_operation_chirho();
        self.objects_chirho
            .borrow_mut()
            .insert(path_chirho.key_chirho().to_owned(), bytes_chirho.to_vec());
        Ok(())
    }

    fn truncate_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        new_len_chirho: u64,
    ) -> Result<()> {
        self.observe_operation_chirho();
        let new_len_chirho =
            usize::try_from(new_len_chirho).map_err(|_| anyhow!("invalid fake length"))?;
        let mut objects_chirho = self.objects_chirho.borrow_mut();
        let bytes_chirho = objects_chirho
            .get_mut(path_chirho.key_chirho())
            .ok_or_else(|| anyhow!("missing fake object"))?;
        if new_len_chirho > bytes_chirho.len() {
            return Err(anyhow!("fake truncate would extend object"));
        }
        bytes_chirho.truncate(new_len_chirho);
        Ok(())
    }

    fn rename_chirho(
        &self,
        from_chirho: &StoragePathChirho,
        to_chirho: &StoragePathChirho,
    ) -> Result<()> {
        self.observe_operation_chirho();
        let bytes_chirho = self
            .objects_chirho
            .borrow_mut()
            .remove(from_chirho.key_chirho())
            .ok_or_else(|| anyhow!("missing fake rename source"))?;
        self.objects_chirho
            .borrow_mut()
            .insert(to_chirho.key_chirho().to_owned(), bytes_chirho);
        Ok(())
    }

    fn remove_chirho(&self, path_chirho: &StoragePathChirho) -> Result<()> {
        self.observe_operation_chirho();
        self.objects_chirho
            .borrow_mut()
            .remove(path_chirho.key_chirho());
        Ok(())
    }

    fn list_chirho(&self, _prefix_chirho: &StoragePathChirho) -> Result<Vec<StoragePathChirho>> {
        self.observe_operation_chirho();
        self.list_count_chirho.set(self.list_count_chirho.get() + 1);
        Err(anyhow!("GD7 reconciliation must not list storage"))
    }

    fn exists_chirho(&self, path_chirho: &StoragePathChirho) -> Result<bool> {
        self.observe_operation_chirho();
        Ok(self
            .objects_chirho
            .borrow()
            .contains_key(path_chirho.key_chirho()))
    }
}

pub(super) struct FakeReconciliationSignerChirho {
    key_id_chirho: String,
    secret_chirho: Vec<u8>,
}

impl FakeReconciliationSignerChirho {
    pub(super) fn new_chirho(secret_chirho: u8) -> Self {
        Self {
            key_id_chirho: digest_chirho('b'),
            secret_chirho: vec![secret_chirho; 32],
        }
    }

    fn signature_chirho(&self, line_chirho: &str) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(&self.secret_chirho);
        hasher_chirho.update(line_chirho.as_bytes());
        hasher_chirho.finalize().to_hex().to_string()
    }
}

impl Gd7ReconciliationVerifierPortChirho for FakeReconciliationSignerChirho {
    fn key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.signature_chirho(signed_content_line_chirho) == sig_chirho
    }
}

impl Gd7ReconciliationSignerPortChirho for FakeReconciliationSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(self.signature_chirho(signed_content_line_chirho))
    }
}

fn digest_chirho(nibble_chirho: char) -> String {
    std::iter::repeat_n(nibble_chirho, 64).collect()
}

pub(super) fn identity_chirho() -> Gd7ReconciliationIdentityChirho {
    let group_chirho = ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "gd7-reconciliation-tenant-chirho".to_owned(),
    };
    Gd7ReconciliationIdentityChirho {
        consistency_group_digest_chirho: consistency_group_digest_chirho(&group_chirho).unwrap(),
        winner_node_chirho: digest_chirho('a'),
        held_node_chirho: digest_chirho('b'),
        winner_term_chirho: 9,
        losing_term_chirho: 8,
        winner_journal_genesis_digest_chirho: digest_chirho('2'),
        winner_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(9, 0).unwrap(),
            seq_chirho: 12,
            record_digest_chirho: digest_chirho('3'),
        },
        fork_chirho: Gd7ForkCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(8, 0).unwrap(),
            seq_chirho: 5,
            record_digest_chirho: digest_chirho('4'),
        },
        losing_journal_genesis_digest_chirho: digest_chirho('2'),
        losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(8, 3).unwrap(),
            seq_chirho: 10,
            record_digest_chirho: digest_chirho('6'),
        },
    }
}

pub(super) fn observed_state_chirho() -> Gd7ReconciliationCheckpointStateChirho {
    Gd7ReconciliationCheckpointStateChirho {
        phase_chirho: Gd7ReconciliationPhaseChirho::ObservedHeldChirho,
        transition_seq_chirho: 0,
        previous_checkpoint_ref_chirho: None,
        manifest_head_ref_chirho: None,
        manifest_page_count_chirho: 0,
        manifest_record_count_chirho: 0,
        plan_head_ref_chirho: None,
        plan_page_count_chirho: 0,
        sealed_plan_ref_chirho: None,
        effect_obligation_count_chirho: 0,
        cursor_object_ref_chirho: None,
        adoption_binding_chirho: None,
    }
}

fn manifesting_state_chirho(prior_ref_chirho: &str) -> Gd7ReconciliationCheckpointStateChirho {
    Gd7ReconciliationCheckpointStateChirho {
        phase_chirho: Gd7ReconciliationPhaseChirho::ManifestingChirho,
        transition_seq_chirho: 1,
        previous_checkpoint_ref_chirho: Some(prior_ref_chirho.to_owned()),
        manifest_head_ref_chirho: Some(digest_chirho('7')),
        manifest_page_count_chirho: 1,
        manifest_record_count_chirho: 3,
        plan_head_ref_chirho: None,
        plan_page_count_chirho: 0,
        sealed_plan_ref_chirho: None,
        effect_obligation_count_chirho: 0,
        cursor_object_ref_chirho: Some(digest_chirho('8')),
        adoption_binding_chirho: None,
    }
}

fn sealed_state_chirho(prior_ref_chirho: &str) -> Gd7ReconciliationCheckpointStateChirho {
    Gd7ReconciliationCheckpointStateChirho {
        phase_chirho: Gd7ReconciliationPhaseChirho::PlanSealedChirho,
        transition_seq_chirho: 2,
        previous_checkpoint_ref_chirho: Some(prior_ref_chirho.to_owned()),
        manifest_head_ref_chirho: Some(digest_chirho('7')),
        manifest_page_count_chirho: 1,
        manifest_record_count_chirho: 3,
        plan_head_ref_chirho: Some(digest_chirho('9')),
        plan_page_count_chirho: 1,
        sealed_plan_ref_chirho: Some(digest_chirho('9')),
        effect_obligation_count_chirho: 2,
        cursor_object_ref_chirho: None,
        adoption_binding_chirho: None,
    }
}

#[test]
fn observed_hold_persists_reloads_and_retries_deterministically_chirho() {
    let storage_chirho = FakeReconciliationStorageChirho::default();
    let signer_chirho = FakeReconciliationSignerChirho::new_chirho(0x41);
    let identity_chirho = identity_chirho();
    let store_chirho =
        Gd7ReconciliationStoreChirho::new_chirho(&storage_chirho, &signer_chirho, identity_chirho)
            .unwrap();
    assert!(!store_chirho.has_active_hold_chirho().unwrap());

    let first_chirho = store_chirho
        .commit_checkpoint_chirho(None, observed_state_chirho())
        .unwrap();
    let head_path_chirho =
        gd7_reconciliation_head_path_chirho(store_chirho.identity_chirho()).unwrap();
    let checkpoint_path_chirho =
        gd7_reconciliation_checkpoint_path_chirho(&first_chirho.checkpoint_ref_chirho).unwrap();
    let group_suffix_chirho = store_chirho
        .identity_chirho()
        .consistency_group_digest_chirho
        .strip_prefix("writer-fence-group-blake3-chirho:")
        .unwrap();
    assert!(head_path_chirho.key_chirho().contains(&format!(
        "/groups-chirho/{}/{}/",
        &group_suffix_chirho[..2],
        &group_suffix_chirho[2..4]
    )));
    assert!(checkpoint_path_chirho.key_chirho().contains(&format!(
        "/checkpoints-chirho/{}/{}/",
        &first_chirho.checkpoint_ref_chirho[..2],
        &first_chirho.checkpoint_ref_chirho[2..4]
    )));
    assert!(store_chirho.has_active_hold_chirho().unwrap());
    let restarted_chirho = Gd7ReconciliationStoreChirho::new_chirho(
        &storage_chirho,
        &signer_chirho,
        store_chirho.identity_chirho().clone(),
    )
    .unwrap();
    let reloaded_chirho = restarted_chirho.load_active_chirho().unwrap().unwrap();
    assert_eq!(
        reloaded_chirho.checkpoint_ref_chirho,
        first_chirho.checkpoint_ref_chirho
    );
    assert_eq!(
        reloaded_chirho.checkpoint_chirho.state_chirho.phase_chirho,
        Gd7ReconciliationPhaseChirho::ObservedHeldChirho
    );

    let retried_chirho = restarted_chirho
        .commit_checkpoint_chirho(None, observed_state_chirho())
        .unwrap();
    assert_eq!(
        retried_chirho.checkpoint_ref_chirho,
        first_chirho.checkpoint_ref_chirho
    );
    assert_eq!(storage_chirho.list_count_chirho.get(), 0);
    assert_eq!(storage_chirho.read_all_count_chirho.get(), 0);
}

#[test]
fn group_hold_presence_fails_closed_before_exact_identity_is_known_chirho() {
    let storage_chirho = FakeReconciliationStorageChirho::default();
    let identity_chirho = identity_chirho();
    let group_chirho = &identity_chirho.consistency_group_digest_chirho;
    assert!(
        !gd7_reconciliation_group_has_any_active_hold_chirho(&storage_chirho, group_chirho)
            .unwrap()
    );
    let head_path_chirho = gd7_reconciliation_group_head_path_chirho(group_chirho).unwrap();
    storage_chirho.force_put_chirho(&head_path_chirho, b"malformed-held-head".to_vec());
    assert!(
        gd7_reconciliation_group_has_any_active_hold_chirho(&storage_chirho, group_chirho).unwrap()
    );
    assert_eq!(storage_chirho.list_count_chirho.get(), 0);
    assert_eq!(storage_chirho.read_all_count_chirho.get(), 0);
}

#[test]
fn reconciliation_store_refuses_a_signer_not_bound_to_the_held_node_chirho() {
    let storage_chirho = FakeReconciliationStorageChirho::default();
    let mut signer_chirho = FakeReconciliationSignerChirho::new_chirho(0x4b);
    signer_chirho.key_id_chirho = digest_chirho('c');
    assert_eq!(
        Gd7ReconciliationStoreChirho::new_chirho(
            &storage_chirho,
            &signer_chirho,
            identity_chirho()
        )
        .err()
        .unwrap(),
        Gd7ReconciliationStoreRefusalChirho::SignerKeyMismatchChirho
    );
    assert_eq!(storage_chirho.operation_count_chirho.get(), 0);
}

#[test]
fn wrong_expected_prior_refuses_without_moving_head_chirho() {
    let storage_chirho = FakeReconciliationStorageChirho::default();
    let signer_chirho = FakeReconciliationSignerChirho::new_chirho(0x42);
    let identity_chirho = identity_chirho();
    let head_path_chirho = gd7_reconciliation_head_path_chirho(&identity_chirho).unwrap();
    let store_chirho =
        Gd7ReconciliationStoreChirho::new_chirho(&storage_chirho, &signer_chirho, identity_chirho)
            .unwrap();
    store_chirho
        .commit_checkpoint_chirho(None, observed_state_chirho())
        .unwrap();
    let head_before_chirho = storage_chirho.bytes_chirho(&head_path_chirho).unwrap();
    let wrong_ref_chirho = digest_chirho('f');
    let error_chirho = store_chirho
        .commit_checkpoint_chirho(
            Some(&wrong_ref_chirho),
            manifesting_state_chirho(&wrong_ref_chirho),
        )
        .unwrap_err();
    assert_eq!(
        error_chirho,
        Gd7ReconciliationStoreRefusalChirho::WrongExpectedPriorChirho
    );
    assert_eq!(
        storage_chirho.bytes_chirho(&head_path_chirho).unwrap(),
        head_before_chirho
    );
}

#[test]
fn orphan_checkpoint_recovers_while_immutable_collision_refuses_chirho() {
    let source_storage_chirho = FakeReconciliationStorageChirho::default();
    let orphan_storage_chirho = FakeReconciliationStorageChirho::default();
    let collision_storage_chirho = FakeReconciliationStorageChirho::default();
    let signer_chirho = FakeReconciliationSignerChirho::new_chirho(0x43);
    let identity_chirho = identity_chirho();
    let source_store_chirho = Gd7ReconciliationStoreChirho::new_chirho(
        &source_storage_chirho,
        &signer_chirho,
        identity_chirho.clone(),
    )
    .unwrap();
    let source_commit_chirho = source_store_chirho
        .commit_checkpoint_chirho(None, observed_state_chirho())
        .unwrap();
    let checkpoint_path_chirho =
        gd7_reconciliation_checkpoint_path_chirho(&source_commit_chirho.checkpoint_ref_chirho)
            .unwrap();
    let checkpoint_bytes_chirho = source_storage_chirho
        .bytes_chirho(&checkpoint_path_chirho)
        .unwrap();
    orphan_storage_chirho.force_put_chirho(&checkpoint_path_chirho, checkpoint_bytes_chirho);
    let orphan_store_chirho = Gd7ReconciliationStoreChirho::new_chirho(
        &orphan_storage_chirho,
        &signer_chirho,
        identity_chirho.clone(),
    )
    .unwrap();
    let recovered_chirho = orphan_store_chirho
        .commit_checkpoint_chirho(None, observed_state_chirho())
        .unwrap();
    assert_eq!(
        recovered_chirho.checkpoint_ref_chirho,
        source_commit_chirho.checkpoint_ref_chirho
    );
    assert!(orphan_store_chirho.has_active_hold_chirho().unwrap());

    collision_storage_chirho.force_put_chirho(
        &checkpoint_path_chirho,
        b"{\"collision_chirho\":true}".to_vec(),
    );
    let collision_store_chirho = Gd7ReconciliationStoreChirho::new_chirho(
        &collision_storage_chirho,
        &signer_chirho,
        identity_chirho.clone(),
    )
    .unwrap();
    assert_eq!(
        collision_store_chirho
            .commit_checkpoint_chirho(None, observed_state_chirho())
            .unwrap_err(),
        Gd7ReconciliationStoreRefusalChirho::ImmutableCollisionChirho
    );
    assert!(collision_storage_chirho
        .bytes_chirho(&gd7_reconciliation_head_path_chirho(&identity_chirho).unwrap())
        .is_none());
}

#[test]
fn malformed_and_oversized_heads_fail_closed_chirho() {
    let signer_chirho = FakeReconciliationSignerChirho::new_chirho(0x44);
    let identity_chirho = identity_chirho();
    let head_path_chirho = gd7_reconciliation_head_path_chirho(&identity_chirho).unwrap();

    let malformed_storage_chirho = FakeReconciliationStorageChirho::default();
    malformed_storage_chirho.force_put_chirho(&head_path_chirho, b"{".to_vec());
    let malformed_store_chirho = Gd7ReconciliationStoreChirho::new_chirho(
        &malformed_storage_chirho,
        &signer_chirho,
        identity_chirho.clone(),
    )
    .unwrap();
    assert_eq!(
        malformed_store_chirho.load_active_chirho().unwrap_err(),
        Gd7ReconciliationStoreRefusalChirho::MalformedHeadChirho
    );

    let oversized_storage_chirho = FakeReconciliationStorageChirho::default();
    oversized_storage_chirho.force_put_chirho(
        &head_path_chirho,
        vec![b'x'; MAX_GD7_RECONCILIATION_HEAD_BYTES_CHIRHO + 1],
    );
    let oversized_store_chirho = Gd7ReconciliationStoreChirho::new_chirho(
        &oversized_storage_chirho,
        &signer_chirho,
        identity_chirho,
    )
    .unwrap();
    assert_eq!(
        oversized_store_chirho.load_active_chirho().unwrap_err(),
        Gd7ReconciliationStoreRefusalChirho::OversizedHeadChirho
    );
}

#[test]
fn malformed_oversized_and_missing_checkpoints_fail_closed_chirho() {
    let signer_chirho = FakeReconciliationSignerChirho::new_chirho(0x45);
    let identity_chirho = identity_chirho();

    let malformed_storage_chirho = FakeReconciliationStorageChirho::default();
    let malformed_store_chirho = Gd7ReconciliationStoreChirho::new_chirho(
        &malformed_storage_chirho,
        &signer_chirho,
        identity_chirho.clone(),
    )
    .unwrap();
    let malformed_commit_chirho = malformed_store_chirho
        .commit_checkpoint_chirho(None, observed_state_chirho())
        .unwrap();
    let malformed_path_chirho =
        gd7_reconciliation_checkpoint_path_chirho(&malformed_commit_chirho.checkpoint_ref_chirho)
            .unwrap();
    malformed_storage_chirho.force_put_chirho(&malformed_path_chirho, b"{".to_vec());
    assert_eq!(
        malformed_store_chirho.load_active_chirho().unwrap_err(),
        Gd7ReconciliationStoreRefusalChirho::MalformedCheckpointChirho
    );

    let oversized_storage_chirho = FakeReconciliationStorageChirho::default();
    let oversized_store_chirho = Gd7ReconciliationStoreChirho::new_chirho(
        &oversized_storage_chirho,
        &signer_chirho,
        identity_chirho.clone(),
    )
    .unwrap();
    let oversized_commit_chirho = oversized_store_chirho
        .commit_checkpoint_chirho(None, observed_state_chirho())
        .unwrap();
    let oversized_path_chirho =
        gd7_reconciliation_checkpoint_path_chirho(&oversized_commit_chirho.checkpoint_ref_chirho)
            .unwrap();
    oversized_storage_chirho.force_put_chirho(
        &oversized_path_chirho,
        vec![b'x'; MAX_GD7_RECONCILIATION_CHECKPOINT_BYTES_CHIRHO + 1],
    );
    assert_eq!(
        oversized_store_chirho.load_active_chirho().unwrap_err(),
        Gd7ReconciliationStoreRefusalChirho::OversizedCheckpointChirho
    );

    let missing_storage_chirho = FakeReconciliationStorageChirho::default();
    let missing_store_chirho = Gd7ReconciliationStoreChirho::new_chirho(
        &missing_storage_chirho,
        &signer_chirho,
        identity_chirho,
    )
    .unwrap();
    let missing_commit_chirho = missing_store_chirho
        .commit_checkpoint_chirho(None, observed_state_chirho())
        .unwrap();
    let missing_path_chirho =
        gd7_reconciliation_checkpoint_path_chirho(&missing_commit_chirho.checkpoint_ref_chirho)
            .unwrap();
    missing_storage_chirho.force_remove_chirho(&missing_path_chirho);
    assert_eq!(
        missing_store_chirho.load_active_chirho().unwrap_err(),
        Gd7ReconciliationStoreRefusalChirho::MissingReferencedCheckpointChirho
    );
}

#[test]
fn tampered_signature_and_foreign_injected_root_fail_closed_chirho() {
    let storage_chirho = FakeReconciliationStorageChirho::default();
    let signer_chirho = FakeReconciliationSignerChirho::new_chirho(0x46);
    let foreign_signer_chirho = FakeReconciliationSignerChirho::new_chirho(0x47);
    let identity_chirho = identity_chirho();
    let store_chirho = Gd7ReconciliationStoreChirho::new_chirho(
        &storage_chirho,
        &signer_chirho,
        identity_chirho.clone(),
    )
    .unwrap();
    let commit_chirho = store_chirho
        .commit_checkpoint_chirho(None, observed_state_chirho())
        .unwrap();
    let foreign_store_chirho = Gd7ReconciliationStoreChirho::new_chirho(
        &storage_chirho,
        &foreign_signer_chirho,
        identity_chirho,
    )
    .unwrap();
    assert_eq!(
        foreign_store_chirho.load_active_chirho().unwrap_err(),
        Gd7ReconciliationStoreRefusalChirho::InvalidHeadSignatureChirho
    );

    let checkpoint_path_chirho =
        gd7_reconciliation_checkpoint_path_chirho(&commit_chirho.checkpoint_ref_chirho).unwrap();
    let checkpoint_bytes_chirho = storage_chirho
        .bytes_chirho(&checkpoint_path_chirho)
        .unwrap();
    let mut checkpoint_value_chirho: Gd7ReconciliationCheckpointChirho =
        serde_json::from_slice(&checkpoint_bytes_chirho).unwrap();
    checkpoint_value_chirho.sig_chirho = "tampered-signature-chirho".to_owned();
    storage_chirho.force_put_chirho(
        &checkpoint_path_chirho,
        serde_json::to_vec(&checkpoint_value_chirho).unwrap(),
    );
    assert_eq!(
        store_chirho.load_active_chirho().unwrap_err(),
        Gd7ReconciliationStoreRefusalChirho::InvalidCheckpointSignatureChirho
    );
}

#[test]
fn wrong_identity_head_fails_closed_even_with_a_valid_signature_chirho() {
    let storage_chirho = FakeReconciliationStorageChirho::default();
    let signer_chirho = FakeReconciliationSignerChirho::new_chirho(0x48);
    let expected_identity_chirho = identity_chirho();
    let expected_store_chirho = Gd7ReconciliationStoreChirho::new_chirho(
        &storage_chirho,
        &signer_chirho,
        expected_identity_chirho.clone(),
    )
    .unwrap();
    let mut foreign_identity_chirho = expected_identity_chirho;
    foreign_identity_chirho.held_node_chirho = digest_chirho('c');
    let mut foreign_signer_chirho = FakeReconciliationSignerChirho::new_chirho(0x48);
    foreign_signer_chirho.key_id_chirho = digest_chirho('c');
    let foreign_store_chirho = Gd7ReconciliationStoreChirho::new_chirho(
        &storage_chirho,
        &foreign_signer_chirho,
        foreign_identity_chirho,
    )
    .unwrap();
    foreign_store_chirho
        .commit_checkpoint_chirho(None, observed_state_chirho())
        .unwrap();
    assert_eq!(
        expected_store_chirho.load_active_chirho().unwrap_err(),
        Gd7ReconciliationStoreRefusalChirho::WrongIdentityChirho
    );
}

#[test]
fn invalid_identity_and_path_inputs_fail_before_storage_chirho() {
    let storage_chirho = FakeReconciliationStorageChirho::default();
    let signer_chirho = FakeReconciliationSignerChirho::new_chirho(0x49);
    let mut invalid_identity_chirho = identity_chirho();
    invalid_identity_chirho.consistency_group_digest_chirho = "ABC".to_owned();
    assert_eq!(
        Gd7ReconciliationStoreChirho::new_chirho(
            &storage_chirho,
            &signer_chirho,
            invalid_identity_chirho.clone(),
        )
        .err()
        .unwrap(),
        Gd7ReconciliationStoreRefusalChirho::InvalidIdentityChirho
    );
    assert_eq!(
        gd7_reconciliation_head_path_chirho(&invalid_identity_chirho).unwrap_err(),
        Gd7ReconciliationStoreRefusalChirho::InvalidIdentityChirho
    );
    assert_eq!(
        gd7_reconciliation_checkpoint_path_chirho("not-a-digest-chirho").unwrap_err(),
        Gd7ReconciliationStoreRefusalChirho::InvalidReferenceChirho
    );

    let mut raw_group_digest_chirho = identity_chirho();
    raw_group_digest_chirho.consistency_group_digest_chirho = digest_chirho('1');
    assert_eq!(
        Gd7ReconciliationStoreChirho::new_chirho(
            &storage_chirho,
            &signer_chirho,
            raw_group_digest_chirho,
        )
        .err()
        .unwrap(),
        Gd7ReconciliationStoreRefusalChirho::InvalidIdentityChirho
    );
    let mut invalid_term_chirho = identity_chirho();
    invalid_term_chirho.winner_term_chirho = invalid_term_chirho.losing_term_chirho;
    assert_eq!(
        Gd7ReconciliationStoreChirho::new_chirho(
            &storage_chirho,
            &signer_chirho,
            invalid_term_chirho,
        )
        .err()
        .unwrap(),
        Gd7ReconciliationStoreRefusalChirho::InvalidIdentityChirho
    );
    let mut invalid_tail_digest_chirho = identity_chirho();
    invalid_tail_digest_chirho
        .winner_journal_tail_chirho
        .record_digest_chirho = "A".repeat(64);
    assert_eq!(
        Gd7ReconciliationStoreChirho::new_chirho(
            &storage_chirho,
            &signer_chirho,
            invalid_tail_digest_chirho,
        )
        .err()
        .unwrap(),
        Gd7ReconciliationStoreRefusalChirho::InvalidIdentityChirho
    );
    let mut unequal_genesis_chirho = identity_chirho();
    unequal_genesis_chirho.losing_journal_genesis_digest_chirho = digest_chirho('5');
    assert_eq!(
        Gd7ReconciliationStoreChirho::new_chirho(
            &storage_chirho,
            &signer_chirho,
            unequal_genesis_chirho,
        )
        .err()
        .unwrap(),
        Gd7ReconciliationStoreRefusalChirho::InvalidIdentityChirho
    );
    let mut wrong_composite_term_chirho = identity_chirho();
    wrong_composite_term_chirho
        .winner_journal_tail_chirho
        .epoch_chirho = compose_writer_epoch_chirho(10, 0).unwrap();
    assert_eq!(
        Gd7ReconciliationStoreChirho::new_chirho(
            &storage_chirho,
            &signer_chirho,
            wrong_composite_term_chirho,
        )
        .err()
        .unwrap(),
        Gd7ReconciliationStoreRefusalChirho::InvalidIdentityChirho
    );
    let mut oversized_node_chirho = identity_chirho();
    oversized_node_chirho.winner_node_chirho = "n".repeat(257);
    assert_eq!(
        Gd7ReconciliationStoreChirho::new_chirho(
            &storage_chirho,
            &signer_chirho,
            oversized_node_chirho,
        )
        .err()
        .unwrap(),
        Gd7ReconciliationStoreRefusalChirho::InvalidIdentityChirho
    );
    assert_eq!(storage_chirho.operation_count_chirho.get(), 0);
}

#[test]
fn plan_sealed_remains_an_active_restart_persistent_hold_chirho() {
    let storage_chirho = FakeReconciliationStorageChirho::default();
    let signer_chirho = FakeReconciliationSignerChirho::new_chirho(0x4a);
    let identity_chirho = identity_chirho();
    let store_chirho = Gd7ReconciliationStoreChirho::new_chirho(
        &storage_chirho,
        &signer_chirho,
        identity_chirho.clone(),
    )
    .unwrap();
    let observed_chirho = store_chirho
        .commit_checkpoint_chirho(None, observed_state_chirho())
        .unwrap();
    let mut final_manifesting_state_chirho =
        manifesting_state_chirho(&observed_chirho.checkpoint_ref_chirho);
    final_manifesting_state_chirho.cursor_object_ref_chirho = None;
    let manifesting_chirho = store_chirho
        .commit_checkpoint_chirho(
            Some(&observed_chirho.checkpoint_ref_chirho),
            final_manifesting_state_chirho,
        )
        .unwrap();
    let sealed_chirho = store_chirho
        .commit_checkpoint_chirho(
            Some(&manifesting_chirho.checkpoint_ref_chirho),
            sealed_state_chirho(&manifesting_chirho.checkpoint_ref_chirho),
        )
        .unwrap();
    assert_eq!(
        sealed_chirho.checkpoint_chirho.state_chirho.phase_chirho,
        Gd7ReconciliationPhaseChirho::PlanSealedChirho
    );
    let restarted_chirho =
        Gd7ReconciliationStoreChirho::new_chirho(&storage_chirho, &signer_chirho, identity_chirho)
            .unwrap();
    assert!(restarted_chirho.has_active_hold_chirho().unwrap());
    assert_eq!(
        restarted_chirho
            .load_active_chirho()
            .unwrap()
            .unwrap()
            .checkpoint_chirho
            .state_chirho
            .phase_chirho,
        Gd7ReconciliationPhaseChirho::PlanSealedChirho
    );
    assert_eq!(storage_chirho.list_count_chirho.get(), 0);
}

#[test]
fn observed_hold_cannot_skip_manifesting_chirho() {
    let storage_chirho = FakeReconciliationStorageChirho::default();
    let signer_chirho = FakeReconciliationSignerChirho::new_chirho(0x4c);
    let store_chirho = Gd7ReconciliationStoreChirho::new_chirho(
        &storage_chirho,
        &signer_chirho,
        identity_chirho(),
    )
    .unwrap();
    let observed_chirho = store_chirho
        .commit_checkpoint_chirho(None, observed_state_chirho())
        .unwrap();
    let mut skipped_chirho = sealed_state_chirho(&observed_chirho.checkpoint_ref_chirho);
    skipped_chirho.transition_seq_chirho = 1;
    assert_eq!(
        store_chirho
            .commit_checkpoint_chirho(Some(&observed_chirho.checkpoint_ref_chirho), skipped_chirho,)
            .unwrap_err(),
        Gd7ReconciliationStoreRefusalChirho::InvalidPhaseTransitionChirho
    );
}

#[test]
fn checkpoint_reload_binds_the_exact_authenticated_winner_witness_chirho() {
    let storage_chirho = FakeReconciliationStorageChirho::default();
    let signer_chirho = FakeReconciliationSignerChirho::new_chirho(0x4d);
    let identity_chirho = identity_chirho();
    let original_store_chirho = Gd7ReconciliationStoreChirho::new_authenticated_chirho(
        &storage_chirho,
        &signer_chirho,
        identity_chirho.clone(),
        digest_chirho('8'),
    )
    .unwrap();
    original_store_chirho
        .commit_checkpoint_chirho(None, observed_state_chirho())
        .unwrap();
    let foreign_witness_store_chirho = Gd7ReconciliationStoreChirho::new_authenticated_chirho(
        &storage_chirho,
        &signer_chirho,
        identity_chirho,
        digest_chirho('9'),
    )
    .unwrap();
    assert_eq!(
        foreign_witness_store_chirho
            .load_active_chirho()
            .unwrap_err(),
        Gd7ReconciliationStoreRefusalChirho::WinnerWitnessMismatchChirho
    );
}
