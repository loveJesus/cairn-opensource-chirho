// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::client_chirho::{
    LedgerMirrorDirectoryChirho, ProductionLedgerAppendMirrorInputChirho,
    ProductionLedgerAppendMirrorPortChirho,
};
use crate::family_chirho::LedgerMirrorJournalVerifierBindingChirho;
use crate::recovery_chirho::{
    LedgerMirrorRecoveryHeadReceiptChirho, ProductionLedgerMirrorRecoveryInputChirho,
    ProductionLedgerMirrorRecoveryPortChirho,
};
use crate::server_chirho::{ledger_mirror_router_chirho, LedgerMirrorServerStateChirho};
use crate::store_chirho::{
    LedgerMirrorFollowerStoreChirho, LedgerMirrorLeaderStoreChirho,
    LedgerMirrorLiveHeadStoreOpenRefusalChirho,
};
use anyhow::{bail, Context, Result};
use axum::Router;
use cairn_ledger_log_chirho::append_mirror_chirho::LedgerAppendMirrorPortChirho;
use cairn_ledger_log_chirho::recovery_mirror_chirho::{
    LedgerMirrorOrdinaryTermAcceptanceEvidenceSourceChirho,
    LedgerMirrorOrdinaryTermAcceptancePlacementBindingChirho, LedgerMirrorRecoveryPortChirho,
    LedgerMirrorRuntimePortsChirho,
};
use cairn_mirror_chirho::{
    MirrorContractErrorChirho, MirrorLeadershipViewChirho, MirrorRefusalIdentityChirho,
    MirrorResidencyPolicyChirho,
};
use cairn_tenant_placement_authority_chirho::VerifiedTenantPlacementChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

const LEDGER_MIRROR_ROOT_DIR_CHIRHO: &str = "ledger-mirror-f1-chirho";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerMirrorLiveHeadReadRefusalChirho {
    StoreTypeRefusedChirho,
    StoreUnreadableChirho,
    LiveHeadMalformedChirho,
    LiveHeadUnreadableChirho,
    LiveHeadInvalidChirho,
    BootstrapPresentChirho,
    AttestationRefusedChirho,
}

impl LedgerMirrorLiveHeadReadRefusalChirho {
    pub const fn as_str_chirho(self) -> &'static str {
        match self {
            Self::StoreTypeRefusedChirho => "LedgerMirrorLiveHeadStoreTypeRefusedChirho",
            Self::StoreUnreadableChirho => "LedgerMirrorLiveHeadStoreUnreadableChirho",
            Self::LiveHeadMalformedChirho => "LedgerMirrorLiveHeadMalformedRefusedChirho",
            Self::LiveHeadUnreadableChirho => "LedgerMirrorLiveHeadUnreadableChirho",
            Self::LiveHeadInvalidChirho => "LedgerMirrorLiveHeadInvalidRefusedChirho",
            Self::BootstrapPresentChirho => "LedgerMirrorLiveHeadBootstrapPresentRefusedChirho",
            Self::AttestationRefusedChirho => "LedgerMirrorLiveHeadAttestationRefusedChirho",
        }
    }
}

impl fmt::Display for LedgerMirrorLiveHeadReadRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(self.as_str_chirho())
    }
}

impl Error for LedgerMirrorLiveHeadReadRefusalChirho {}

/// Read and re-attest only an existing verified LIVE follower high-water. This path creates no
/// directory and never calls the generic recovery selector, whose bootstrap result is valid for
/// recovery but categorically invalid for healthy-window evidence.
pub fn read_live_ledger_mirror_recovery_head_receipt_chirho(
    selected_root_chirho: &Path,
    sign_root_chirho: &Path,
    local_node_id_chirho: &str,
    journal_verifier_chirho: LedgerMirrorJournalVerifierBindingChirho,
) -> std::result::Result<
    Option<LedgerMirrorRecoveryHeadReceiptChirho>,
    LedgerMirrorLiveHeadReadRefusalChirho,
> {
    let mirror_root_chirho = selected_root_chirho.join(LEDGER_MIRROR_ROOT_DIR_CHIRHO);
    let Some(store_chirho) = LedgerMirrorFollowerStoreChirho::open_existing_read_only_chirho(
        &mirror_root_chirho,
        local_node_id_chirho.to_owned(),
        Arc::new(journal_verifier_chirho),
    )
    .map_err(map_live_head_store_open_refusal_chirho)?
    else {
        return Ok(None);
    };
    if !store_chirho
        .live_high_water_coordinate_exists_chirho()
        .map_err(map_live_head_store_open_refusal_chirho)?
    {
        if store_chirho
            .bootstrap_head_coordinate_exists_chirho()
            .map_err(map_live_head_store_open_refusal_chirho)?
        {
            return Err(LedgerMirrorLiveHeadReadRefusalChirho::BootstrapPresentChirho);
        }
        return Ok(None);
    }
    let high_water_chirho = store_chirho
        .load_high_water_chirho()
        .map_err(classify_live_head_load_refusal_chirho)?
        .ok_or(LedgerMirrorLiveHeadReadRefusalChirho::LiveHeadUnreadableChirho)?;
    LedgerMirrorRecoveryHeadReceiptChirho::sign_from_high_water_chirho(
        &high_water_chirho,
        sign_root_chirho,
    )
    .map(Some)
    .map_err(|_| LedgerMirrorLiveHeadReadRefusalChirho::AttestationRefusedChirho)
}

fn map_live_head_store_open_refusal_chirho(
    refusal_chirho: LedgerMirrorLiveHeadStoreOpenRefusalChirho,
) -> LedgerMirrorLiveHeadReadRefusalChirho {
    match refusal_chirho {
        LedgerMirrorLiveHeadStoreOpenRefusalChirho::TypeRefusedChirho => {
            LedgerMirrorLiveHeadReadRefusalChirho::StoreTypeRefusedChirho
        }
        LedgerMirrorLiveHeadStoreOpenRefusalChirho::UnreadableChirho => {
            LedgerMirrorLiveHeadReadRefusalChirho::StoreUnreadableChirho
        }
    }
}

fn classify_live_head_load_refusal_chirho(
    error_chirho: anyhow::Error,
) -> LedgerMirrorLiveHeadReadRefusalChirho {
    if error_chirho.downcast_ref::<serde_json::Error>().is_some() {
        LedgerMirrorLiveHeadReadRefusalChirho::LiveHeadMalformedChirho
    } else if error_chirho.downcast_ref::<std::io::Error>().is_some() {
        LedgerMirrorLiveHeadReadRefusalChirho::LiveHeadUnreadableChirho
    } else {
        LedgerMirrorLiveHeadReadRefusalChirho::LiveHeadInvalidChirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerMirrorPeerEndpointChirho {
    node_id_chirho: String,
    socket_addr_chirho: SocketAddr,
}

impl LedgerMirrorPeerEndpointChirho {
    pub fn new_chirho(node_id_chirho: String, socket_addr_chirho: SocketAddr) -> Result<Self> {
        if node_id_chirho.len() != 64
            || !node_id_chirho.bytes().all(|byte_chirho| {
                byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho)
            })
            || socket_addr_chirho.ip().is_unspecified()
            || socket_addr_chirho.ip().is_multicast()
        {
            bail!("LedgerMirrorPeerEndpointRefusedChirho");
        }
        Ok(Self {
            node_id_chirho,
            socket_addr_chirho,
        })
    }
}

pub struct LedgerAppendMirrorCompositionChirho {
    pub runtime_ports_chirho: LedgerMirrorRuntimePortsChirho,
    pub router_chirho: Router,
}

/// Compose the production F1 path documented in
/// `spec-chirho/workflows-chirho/distributed-ha-chirho/zone-mirror-before-ack-contract-chirho.md`.
pub fn compose_ledger_append_mirror_chirho(
    selected_root_chirho: &Path,
    sign_root_chirho: &Path,
    local_node_id_chirho: &str,
    placement_chirho: Arc<VerifiedTenantPlacementChirho>,
    journal_verifier_chirho: LedgerMirrorJournalVerifierBindingChirho,
    elector_chirho: Arc<RaftWriterElectorChirho>,
    endpoints_chirho: Vec<LedgerMirrorPeerEndpointChirho>,
) -> Result<LedgerAppendMirrorCompositionChirho> {
    if cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho(sign_root_chirho)?
        != local_node_id_chirho
    {
        bail!("LedgerMirrorCompositionSignerIdentityRefusedChirho");
    }
    let assigned_node_ids_chirho: [String; 3] = placement_chirho
        .assigned_nodes_chirho()
        .iter()
        .map(|binding_chirho| binding_chirho.node_id_chirho.clone())
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| anyhow::anyhow!("LedgerMirrorAssignedNodePopulationRefusedChirho"))?;
    let expected_nodes_chirho = assigned_node_ids_chirho
        .iter()
        .cloned()
        .chain(std::iter::once(
            placement_chirho
                .held_observer_node_chirho()
                .node_id_chirho
                .clone(),
        ))
        .collect::<BTreeSet<_>>();
    let endpoint_nodes_chirho = endpoints_chirho
        .iter()
        .map(|endpoint_chirho| endpoint_chirho.node_id_chirho.clone())
        .collect::<BTreeSet<_>>();
    if expected_nodes_chirho != endpoint_nodes_chirho
        || endpoint_nodes_chirho.len() != endpoints_chirho.len()
        || !expected_nodes_chirho.contains(local_node_id_chirho)
    {
        bail!("LedgerMirrorEndpointPopulationRefusedChirho");
    }
    if expected_nodes_chirho.contains(journal_verifier_chirho.verifying_key_hex_chirho()) {
        bail!("LedgerMirrorJournalControlKeyConflationRefusedChirho");
    }
    let endpoint_map_chirho = endpoints_chirho
        .into_iter()
        .map(|endpoint_chirho| {
            (
                endpoint_chirho.node_id_chirho,
                format!("http://{}", endpoint_chirho.socket_addr_chirho),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let directory_chirho = LedgerMirrorDirectoryChirho::new_chirho(endpoint_map_chirho);
    let election_view_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(RaftMirrorLeadershipViewChirho {
            elector_chirho: Arc::clone(&elector_chirho),
        });
    let residency_chirho = MirrorResidencyPolicyChirho::allowed_domains_chirho(
        placement_chirho
            .intent_chirho()
            .residency_chirho
            .allowed_domains_chirho
            .clone(),
    );
    let mirror_root_chirho = selected_root_chirho.join(LEDGER_MIRROR_ROOT_DIR_CHIRHO);
    let journal_verifier_chirho = Arc::new(journal_verifier_chirho);
    let follower_store_chirho = Arc::new(
        LedgerMirrorFollowerStoreChirho::open_chirho(
            &mirror_root_chirho,
            local_node_id_chirho.to_string(),
            Arc::clone(&journal_verifier_chirho),
        )
        .context("open inert F1 follower mirror store")?,
    );
    let leader_store_chirho = LedgerMirrorLeaderStoreChirho::open_chirho(&mirror_root_chirho)
        .context("open F1 leader reconciliation store")?;
    let server_chirho = LedgerMirrorServerStateChirho::new_chirho(
        local_node_id_chirho.to_string(),
        sign_root_chirho.to_path_buf(),
        Arc::clone(&placement_chirho),
        Arc::clone(&election_view_chirho),
        residency_chirho.clone(),
        Arc::clone(&follower_store_chirho),
    )?;
    let recovery_adapter_chirho = Arc::new(ProductionLedgerMirrorRecoveryPortChirho::new_chirho(
        ProductionLedgerMirrorRecoveryInputChirho {
            local_node_id_chirho: local_node_id_chirho.to_string(),
            sign_root_chirho: sign_root_chirho.to_path_buf(),
            placement_chirho: Arc::clone(&placement_chirho),
            election_view_chirho: Arc::clone(&election_view_chirho),
            residency_chirho: residency_chirho.clone(),
            directory_chirho: directory_chirho.clone(),
            follower_store_chirho,
        },
    ));
    let recovery_port_chirho: Arc<dyn LedgerMirrorRecoveryPortChirho> =
        recovery_adapter_chirho.clone();
    let ordinary_term_acceptance_source_chirho: Arc<
        dyn LedgerMirrorOrdinaryTermAcceptanceEvidenceSourceChirho,
    > = recovery_adapter_chirho;
    let ordinary_term_acceptance_placement_binding_chirho =
        LedgerMirrorOrdinaryTermAcceptancePlacementBindingChirho::new_chirho(
            placement_chirho.assignment_digest_chirho().to_owned(),
            assigned_node_ids_chirho,
        )
        .map_err(|error_chirho| anyhow::anyhow!(error_chirho.to_string()))?;
    let port_chirho: Arc<dyn LedgerAppendMirrorPortChirho> =
        Arc::new(ProductionLedgerAppendMirrorPortChirho::new_chirho(
            ProductionLedgerAppendMirrorInputChirho {
                local_node_id_chirho: local_node_id_chirho.to_string(),
                sign_root_chirho: sign_root_chirho.to_path_buf(),
                placement_chirho,
                election_view_chirho,
                residency_chirho,
                directory_chirho,
                leader_store_chirho,
                journal_verifier_chirho,
            },
        ));
    Ok(LedgerAppendMirrorCompositionChirho {
        runtime_ports_chirho: LedgerMirrorRuntimePortsChirho::new_chirho(
            port_chirho,
            recovery_port_chirho,
            ordinary_term_acceptance_source_chirho,
            ordinary_term_acceptance_placement_binding_chirho,
        ),
        router_chirho: ledger_mirror_router_chirho(server_chirho),
    })
}

struct RaftMirrorLeadershipViewChirho {
    elector_chirho: Arc<RaftWriterElectorChirho>,
}

impl MirrorLeadershipViewChirho for RaftMirrorLeadershipViewChirho {
    fn observe_election_chirho(
        &self,
    ) -> Result<cairn_mirror_chirho::MirrorElectionObservationChirho, MirrorContractErrorChirho>
    {
        self.elector_chirho
            .current_election_observation_chirho()
            .map(|observation_chirho| {
                cairn_mirror_chirho::MirrorElectionObservationChirho::from_raft_chirho(
                    &observation_chirho,
                )
            })
            .map_err(|_error_chirho| {
                MirrorContractErrorChirho::new_chirho(
                    MirrorRefusalIdentityChirho::MirrorMembershipViewMismatchChirho,
                    "live election observation unavailable",
                )
            })
    }
}

#[cfg(test)]
mod live_head_read_tests_chirho {
    use super::*;
    use crate::store_chirho::{LedgerMirrorHighWaterChirho, LedgerMirrorHighWaterInputChirho};
    use crate::tests_chirho::{
        journal_verifier_chirho, provision_node_chirho, signed_record_chirho, JOURNAL_KEY_ID_CHIRHO,
    };
    use std::fs;

    fn verifier_chirho(journal_root_chirho: &Path) -> LedgerMirrorJournalVerifierBindingChirho {
        journal_verifier_chirho(journal_root_chirho)
            .as_ref()
            .clone()
    }

    #[test]
    fn absent_live_store_is_reported_without_creating_a_coordinate_chirho() {
        let selected_root_chirho = tempfile::tempdir().unwrap();
        let journal_root_chirho = tempfile::tempdir().unwrap();
        let node_id_chirho = provision_node_chirho(selected_root_chirho.path());
        provision_node_chirho(journal_root_chirho.path());
        let mirror_root_chirho = selected_root_chirho
            .path()
            .join(LEDGER_MIRROR_ROOT_DIR_CHIRHO);
        assert!(!mirror_root_chirho.exists());
        assert!(read_live_ledger_mirror_recovery_head_receipt_chirho(
            selected_root_chirho.path(),
            selected_root_chirho.path(),
            &node_id_chirho,
            verifier_chirho(journal_root_chirho.path()),
        )
        .unwrap()
        .is_none());
        assert!(!mirror_root_chirho.exists());
    }

    #[test]
    fn wrong_type_and_bootstrap_only_are_never_reported_as_live_absence_chirho() {
        let wrong_type_root_chirho = tempfile::tempdir().unwrap();
        let journal_root_chirho = tempfile::tempdir().unwrap();
        let wrong_type_node_chirho = provision_node_chirho(wrong_type_root_chirho.path());
        provision_node_chirho(journal_root_chirho.path());
        let wrong_type_mirror_chirho = wrong_type_root_chirho
            .path()
            .join(LEDGER_MIRROR_ROOT_DIR_CHIRHO);
        fs::create_dir(&wrong_type_mirror_chirho).unwrap();
        fs::write(
            wrong_type_mirror_chirho.join("follower-f1-chirho"),
            b"not a directory",
        )
        .unwrap();
        assert_eq!(
            read_live_ledger_mirror_recovery_head_receipt_chirho(
                wrong_type_root_chirho.path(),
                wrong_type_root_chirho.path(),
                &wrong_type_node_chirho,
                verifier_chirho(journal_root_chirho.path()),
            )
            .unwrap_err(),
            LedgerMirrorLiveHeadReadRefusalChirho::StoreTypeRefusedChirho
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let symlink_root_chirho = tempfile::tempdir().unwrap();
            let symlink_target_chirho = tempfile::tempdir().unwrap();
            let symlink_node_chirho = provision_node_chirho(symlink_root_chirho.path());
            fs::create_dir_all(
                symlink_target_chirho
                    .path()
                    .join("follower-f1-chirho")
                    .join("records-chirho"),
            )
            .unwrap();
            symlink(
                symlink_target_chirho.path(),
                symlink_root_chirho
                    .path()
                    .join(LEDGER_MIRROR_ROOT_DIR_CHIRHO),
            )
            .unwrap();
            assert_eq!(
                read_live_ledger_mirror_recovery_head_receipt_chirho(
                    symlink_root_chirho.path(),
                    symlink_root_chirho.path(),
                    &symlink_node_chirho,
                    verifier_chirho(journal_root_chirho.path()),
                )
                .unwrap_err(),
                LedgerMirrorLiveHeadReadRefusalChirho::StoreTypeRefusedChirho
            );
        }

        let bootstrap_root_chirho = tempfile::tempdir().unwrap();
        let bootstrap_node_chirho = provision_node_chirho(bootstrap_root_chirho.path());
        let follower_root_chirho = bootstrap_root_chirho
            .path()
            .join(LEDGER_MIRROR_ROOT_DIR_CHIRHO)
            .join("follower-f1-chirho");
        fs::create_dir_all(follower_root_chirho.join("records-chirho")).unwrap();
        fs::write(
            follower_root_chirho.join("bootstrap-head-chirho.json"),
            b"present but categorically ineligible",
        )
        .unwrap();
        assert_eq!(
            read_live_ledger_mirror_recovery_head_receipt_chirho(
                bootstrap_root_chirho.path(),
                bootstrap_root_chirho.path(),
                &bootstrap_node_chirho,
                verifier_chirho(journal_root_chirho.path()),
            )
            .unwrap_err(),
            LedgerMirrorLiveHeadReadRefusalChirho::BootstrapPresentChirho
        );
    }

    #[test]
    fn unreadable_and_malformed_live_stores_are_not_absence_or_bootstrap_chirho() {
        let journal_root_chirho = tempfile::tempdir().unwrap();
        provision_node_chirho(journal_root_chirho.path());

        let unreadable_root_chirho = tempfile::tempdir().unwrap();
        let unreadable_node_chirho = provision_node_chirho(unreadable_root_chirho.path());
        fs::create_dir_all(
            unreadable_root_chirho
                .path()
                .join(LEDGER_MIRROR_ROOT_DIR_CHIRHO)
                .join("follower-f1-chirho"),
        )
        .unwrap();
        assert_eq!(
            read_live_ledger_mirror_recovery_head_receipt_chirho(
                unreadable_root_chirho.path(),
                unreadable_root_chirho.path(),
                &unreadable_node_chirho,
                verifier_chirho(journal_root_chirho.path()),
            )
            .unwrap_err(),
            LedgerMirrorLiveHeadReadRefusalChirho::StoreUnreadableChirho
        );

        let malformed_root_chirho = tempfile::tempdir().unwrap();
        let malformed_node_chirho = provision_node_chirho(malformed_root_chirho.path());
        let malformed_follower_chirho = malformed_root_chirho
            .path()
            .join(LEDGER_MIRROR_ROOT_DIR_CHIRHO)
            .join("follower-f1-chirho");
        fs::create_dir_all(malformed_follower_chirho.join("records-chirho")).unwrap();
        fs::write(
            malformed_follower_chirho.join("high-water-chirho.json"),
            b"{not-json-chirho",
        )
        .unwrap();
        assert_eq!(
            read_live_ledger_mirror_recovery_head_receipt_chirho(
                malformed_root_chirho.path(),
                malformed_root_chirho.path(),
                &malformed_node_chirho,
                verifier_chirho(journal_root_chirho.path()),
            )
            .unwrap_err(),
            LedgerMirrorLiveHeadReadRefusalChirho::LiveHeadMalformedChirho
        );
    }

    #[test]
    fn existing_verified_live_high_water_is_re_attested_without_store_mutation_chirho() {
        let selected_root_chirho = tempfile::tempdir().unwrap();
        let writer_root_chirho = tempfile::tempdir().unwrap();
        let third_root_chirho = tempfile::tempdir().unwrap();
        let journal_root_chirho = tempfile::tempdir().unwrap();
        let holder_node_id_chirho = provision_node_chirho(selected_root_chirho.path());
        let writer_node_id_chirho = provision_node_chirho(writer_root_chirho.path());
        let third_node_id_chirho = provision_node_chirho(third_root_chirho.path());
        provision_node_chirho(journal_root_chirho.path());
        let record_chirho = signed_record_chirho(journal_root_chirho.path(), JOURNAL_KEY_ID_CHIRHO);
        let high_water_chirho = LedgerMirrorHighWaterChirho::sign_chirho(
            LedgerMirrorHighWaterInputChirho {
                consistency_group_digest_chirho: "1".repeat(64),
                origin_leader_node_id_chirho: writer_node_id_chirho.clone(),
                holder_node_id_chirho: holder_node_id_chirho.clone(),
                assignment_digest_chirho: "2".repeat(64),
                assigned_node_ids_chirho: [
                    writer_node_id_chirho.clone(),
                    holder_node_id_chirho.clone(),
                    third_node_id_chirho,
                ],
                membership_view_digest_chirho: "3".repeat(64),
                historical_term_chirho: 7,
                mirror_closure_id_chirho: "4".repeat(64),
                prepare_frame_digest_chirho: "5".repeat(64),
                caller_idempotency_key_digest_chirho: "6".repeat(64),
                record_chirho: record_chirho.clone(),
            },
            selected_root_chirho.path(),
        )
        .unwrap();
        let follower_root_chirho = selected_root_chirho
            .path()
            .join(LEDGER_MIRROR_ROOT_DIR_CHIRHO)
            .join("follower-f1-chirho");
        let records_root_chirho = follower_root_chirho.join("records-chirho");
        fs::create_dir_all(&records_root_chirho).unwrap();
        let high_water_path_chirho = follower_root_chirho.join("high-water-chirho.json");
        let high_water_bytes_chirho = serde_json::to_vec(&high_water_chirho).unwrap();
        fs::write(&high_water_path_chirho, &high_water_bytes_chirho).unwrap();
        let record_path_chirho = records_root_chirho.join(format!(
            "{:020}-{}.jsonl",
            record_chirho.record_seq_chirho, record_chirho.record_digest_chirho
        ));
        let mut record_bytes_chirho = record_chirho
            .canonical_record_line_chirho
            .as_bytes()
            .to_vec();
        record_bytes_chirho.push(b'\n');
        fs::write(&record_path_chirho, &record_bytes_chirho).unwrap();
        let entry_count_chirho = fs::read_dir(&follower_root_chirho).unwrap().count();

        let receipt_chirho = read_live_ledger_mirror_recovery_head_receipt_chirho(
            selected_root_chirho.path(),
            selected_root_chirho.path(),
            &holder_node_id_chirho,
            verifier_chirho(journal_root_chirho.path()),
        )
        .unwrap()
        .expect("verified live high-water is present");
        assert_eq!(
            receipt_chirho.holder_node_id_chirho(),
            holder_node_id_chirho
        );
        assert_eq!(
            receipt_chirho.historical_leader_node_id_chirho(),
            writer_node_id_chirho
        );
        assert_eq!(
            fs::read(&high_water_path_chirho).unwrap(),
            high_water_bytes_chirho
        );
        assert_eq!(fs::read(&record_path_chirho).unwrap(), record_bytes_chirho);
        assert_eq!(
            fs::read_dir(&follower_root_chirho).unwrap().count(),
            entry_count_chirho
        );

        let mut invalid_high_water_chirho: serde_json::Value =
            serde_json::from_slice(&high_water_bytes_chirho).unwrap();
        let original_state_digest_chirho = invalid_high_water_chirho["state_digest_chirho"]
            .as_str()
            .unwrap();
        let wrong_state_digest_chirho = if original_state_digest_chirho == "f".repeat(64) {
            "e".repeat(64)
        } else {
            "f".repeat(64)
        };
        invalid_high_water_chirho["state_digest_chirho"] =
            serde_json::Value::String(wrong_state_digest_chirho);
        fs::write(
            &high_water_path_chirho,
            serde_json::to_vec(&invalid_high_water_chirho).unwrap(),
        )
        .unwrap();
        assert_eq!(
            read_live_ledger_mirror_recovery_head_receipt_chirho(
                selected_root_chirho.path(),
                selected_root_chirho.path(),
                &holder_node_id_chirho,
                verifier_chirho(journal_root_chirho.path()),
            )
            .unwrap_err(),
            LedgerMirrorLiveHeadReadRefusalChirho::LiveHeadInvalidChirho
        );
    }
}
