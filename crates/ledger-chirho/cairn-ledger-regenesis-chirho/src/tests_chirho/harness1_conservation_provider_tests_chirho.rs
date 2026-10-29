// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Spawn-owned conservation provider for the HARNESS-1 actor fixture.
//!
//! The provider owns coordinates only. Every certification request reopens the custody-bound
//! storage, signer, registry, and journal ports, then derives a fresh signed monitor snapshot.
//! It intentionally retains no snapshot between calls.

use super::request_chirho;
use super::RegenesisFixtureChirho;
use crate::run_ledger_regenesis_chirho;
use cairn_config_chirho::config_chirho::load_config_chirho;
use cairn_kind_registry_chirho::chain_chirho::{
    load_verified_registry_chirho, KindRegistryPortsChirho,
};
use cairn_ledger_composition_chirho::composition_chirho::{
    gd7_conservation_adapter_chirho::Gd7SignedConservationSnapshotSourceChirho,
    JournalConservationSourceChirho,
};
use cairn_ledger_host_chirho::reconciliation_chirho::{
    ExistingNodeGd7SignerChirho, Gd7ConservationSnapshotProviderChirho,
    Gd7ConservationSnapshotSourcePortChirho, Gd7PlanRefusalChirho,
    SignedGd7ConservationSnapshotChirho,
};
use cairn_ledger_host_chirho::{
    host_ledger_signer_refs_from_config_chirho, FsLedgerStorageChirho, HostLedgerSignersChirho,
    PinnedKindIssuerVerifierChirho, PlatformPolicyMintAuthorityChirho,
    StaticClusterMembershipChirho, SystemLedgerClockChirho,
};
use cairn_ledger_log_chirho::journal_chirho::JournalPortsChirho;
use cairn_ledger_log_chirho::journal_chirho::LedgerJournalChirho;
use cairn_ledger_log_chirho::losing_suffix_chirho::VerifiedLosingJournalTailChirho;
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::{ClusterIdChirho, MoneyGroupIdChirho};
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use std::path::PathBuf;

pub(super) struct RegenesisGd7ConservationProviderChirho {
    root_chirho: PathBuf,
    config_path_chirho: PathBuf,
    plan_chirho: crate::plan_chirho::LedgerRegenesisPlanV1Chirho,
}

impl RegenesisGd7ConservationProviderChirho {
    pub(super) fn from_fixture_chirho(fixture_chirho: &RegenesisFixtureChirho) -> Self {
        Self {
            root_chirho: fixture_chirho.root_chirho.clone(),
            config_path_chirho: fixture_chirho.config_path_chirho.clone(),
            plan_chirho: fixture_chirho.plan_chirho.clone(),
        }
    }

    pub(super) fn verified_losing_tail_chirho(
        &self,
    ) -> Result<VerifiedLosingJournalTailChirho, Gd7PlanRefusalChirho> {
        let config_chirho = load_config_chirho(&self.config_path_chirho)
            .map_err(|_| Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?
            .ledger_host_chirho
            .ok_or(Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?;
        let signer_refs_chirho =
            host_ledger_signer_refs_from_config_chirho(&config_chirho.signer_secrets_chirho)
                .map_err(|_| Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?;
        let signers_chirho =
            HostLedgerSignersChirho::load_existing_chirho(&self.root_chirho, &signer_refs_chirho)
                .map_err(|_| Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?;
        let storage_root_chirho = self
            .root_chirho
            .join(&config_chirho.storage_namespace_chirho);
        let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&storage_root_chirho)
            .map_err(|_| Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?;
        let issuer_verify_chirho =
            PinnedKindIssuerVerifierChirho::from_config_chirho(&config_chirho.kind_issuer_chirho)
                .map_err(|_| Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?;
        let registry_chirho = load_verified_registry_chirho(
            KindRegistryPortsChirho {
                storage_chirho: &storage_chirho,
                registry_root_chirho: signers_chirho.kind_root_signer_chirho(),
                issuer_verify_chirho: &issuer_verify_chirho,
            },
            &StoragePathChirho::new_chirho(&self.plan_chirho.kind_registry_path_chirho),
            &self.plan_chirho.kind_registry_id_chirho,
        )
        .map_err(|_| Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?;
        let authority_chirho = PlatformPolicyMintAuthorityChirho::new_chirho(&registry_chirho);
        let membership_chirho = StaticClusterMembershipChirho::from_config_chirho(
            config_chirho.local_epoch_chirho,
            &config_chirho.members_chirho,
        )
        .map_err(|_| Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?;
        let clock_chirho = SystemLedgerClockChirho;
        let journal_chirho = LedgerJournalChirho::open_read_only_chirho(
            JournalPortsChirho {
                storage_chirho: &storage_chirho,
                signer_chirho: signers_chirho.journal_signer_chirho(),
                clock_chirho: &clock_chirho,
                membership_chirho: &membership_chirho,
                kind_registry_chirho: &registry_chirho,
                authority_chirho: &authority_chirho,
            },
            StoragePathChirho::new_chirho(&self.plan_chirho.journal_path_chirho),
            &ClusterIdChirho(self.plan_chirho.cluster_id_chirho.clone()),
        )
        .map_err(|_| Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?;
        Ok(journal_chirho.verified_losing_tail_chirho())
    }
}

impl Gd7ConservationSnapshotProviderChirho for RegenesisGd7ConservationProviderChirho {
    fn load_signed_conservation_snapshot_chirho(
        &self,
    ) -> Result<SignedGd7ConservationSnapshotChirho, Gd7PlanRefusalChirho> {
        let config_chirho = load_config_chirho(&self.config_path_chirho)
            .map_err(|_| Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?
            .ledger_host_chirho
            .ok_or(Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?;
        let signer_refs_chirho =
            host_ledger_signer_refs_from_config_chirho(&config_chirho.signer_secrets_chirho)
                .map_err(|_| Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?;
        let signers_chirho =
            HostLedgerSignersChirho::load_existing_chirho(&self.root_chirho, &signer_refs_chirho)
                .map_err(|_| Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?;
        let storage_root_chirho = self
            .root_chirho
            .join(&config_chirho.storage_namespace_chirho);
        let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&storage_root_chirho)
            .map_err(|_| Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?;
        let issuer_verify_chirho =
            PinnedKindIssuerVerifierChirho::from_config_chirho(&config_chirho.kind_issuer_chirho)
                .map_err(|_| Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?;
        let registry_ports_chirho = KindRegistryPortsChirho {
            storage_chirho: &storage_chirho,
            registry_root_chirho: signers_chirho.kind_root_signer_chirho(),
            issuer_verify_chirho: &issuer_verify_chirho,
        };
        let registry_chirho = load_verified_registry_chirho(
            registry_ports_chirho,
            &StoragePathChirho::new_chirho(&self.plan_chirho.kind_registry_path_chirho),
            &self.plan_chirho.kind_registry_id_chirho,
        )
        .map_err(|_| Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?;
        let authority_chirho = PlatformPolicyMintAuthorityChirho::new_chirho(&registry_chirho);
        let membership_chirho = StaticClusterMembershipChirho::from_config_chirho(
            config_chirho.local_epoch_chirho,
            &config_chirho.members_chirho,
        )
        .map_err(|_| Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?;
        let clock_chirho = SystemLedgerClockChirho;
        let journal_ports_chirho = JournalPortsChirho {
            storage_chirho: &storage_chirho,
            signer_chirho: signers_chirho.journal_signer_chirho(),
            clock_chirho: &clock_chirho,
            membership_chirho: &membership_chirho,
            kind_registry_chirho: &registry_chirho,
            authority_chirho: &authority_chirho,
        };
        let source_chirho = JournalConservationSourceChirho {
            journal_ports_chirho,
            journal_path_chirho: StoragePathChirho::new_chirho(
                &self.plan_chirho.journal_path_chirho,
            ),
            cluster_chirho: ClusterIdChirho(self.plan_chirho.cluster_id_chirho.clone()),
            money_group_chirho: MoneyGroupIdChirho(self.plan_chirho.money_group_id_chirho.clone()),
        };
        let node_chirho = NodeIdChirho(
            cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho(
                &self.root_chirho,
            )
            .map_err(|_| Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?,
        );
        let signer_chirho =
            ExistingNodeGd7SignerChirho::open_existing_chirho(&self.root_chirho, &node_chirho)
                .map_err(|_| Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?;
        let adapter_chirho = Gd7SignedConservationSnapshotSourceChirho {
            snapshot_source_chirho: source_chirho,
            signer_chirho: &signer_chirho,
        };
        adapter_chirho
            .load_signed_conservation_snapshot_chirho()
            .map_err(|_| Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)
    }
}

#[test]
fn regenesis_provider_reopens_and_signs_a_fresh_snapshot_chirho() {
    let fixture_chirho = super::fixture_chirho();
    run_ledger_regenesis_chirho(request_chirho(&fixture_chirho))
        .expect("the published fixture supplies the verified journal roots");
    let provider_chirho =
        RegenesisGd7ConservationProviderChirho::from_fixture_chirho(&fixture_chirho);
    let snapshot_chirho = provider_chirho
        .load_signed_conservation_snapshot_chirho()
        .expect("the owned provider reopens and verifies the current conservation cut");
    assert!(!snapshot_chirho.sig_chirho.is_empty());
    assert!(!snapshot_chirho.key_id_chirho.is_empty());
}
