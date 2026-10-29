// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Production composition for the served-write relay over the exact geo elector and signed mesh.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/serve-write-forwarding-design-chirho.md`.

use anyhow::{bail, Context, Result};
use axum::Router;
use cairn_ledger_mirror_http_chirho::LedgerMirrorPeerEndpointChirho;
use cairn_roster_config_chirho::{
    derive_verified_relay_mesh_chirho, verify_active_relay_mesh_interface_chirho,
    ELECTOR_PORT_CHIRHO,
};
use cairn_serve_runtime_chirho::ServedWriteRelayDestinationSlotChirho;
use cairn_write_relay_chirho::{
    relay_tenant_consistency_group_digest_chirho, ServedLocalReadAuthorityPortChirho,
    ServedWriteDispatchPortChirho,
};
use cairn_write_relay_http_chirho::{
    relay_router_chirho, ExistingKeyRelayRequestSignerChirho, ExistingKeyRelayResponseSignerChirho,
    FixedGroupLeadershipViewChirho, FixedRelayDirectoryChirho, HttpServedWriteDispatchPortChirho,
    HttpServedWriteRelayPortChirho, LocalRelayAuthorityReadinessChirho,
    LocalRelayDispatchPolicyChirho, RelayHttpTimeoutsChirho, RelayServerConfigChirho,
    RelayServerStateChirho,
};
use cairn_writer_elector_chirho::elector_port_chirho::LeadershipChirho;
use cairn_writer_elector_chirho::monotonic_clock_chirho::{
    MonotonicClockChirho, SystemMonotonicClockChirho, DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO,
};
use cairn_writer_elector_chirho::raft_elector_chirho::{
    validate_election_timeout_relay_margin_chirho, RaftWriterElectorChirho,
};
use cairn_writer_elector_http_chirho::cluster_node_chirho::ClusterNodeChirho;
use cairn_writer_elector_http_chirho::membership_control_chirho::MembershipControlConfigChirho;
#[cfg(test)]
use cairn_writer_elector_http_chirho::membership_control_chirho::{
    MembershipTargetAuthorityChirho, RosterAuthorityConfigChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const RELAY_ROSTER_FILE_MAX_BYTES_CHIRHO: u64 = 4 * 1024 * 1024;
const RELAY_ROSTER_HEAD_MAX_BYTES_CHIRHO: u64 = 64 * 1024;
const RELAY_ROSTER_MAX_LINES_CHIRHO: usize = 4096;
const SERVED_WRITE_RELAY_BUDGET_MILLIS_CHIRHO: NonZeroU64 = NonZeroU64::new(8_000).unwrap();

pub(crate) struct ServedWriteRelayCompositionChirho {
    pub(crate) dispatch_chirho: Arc<dyn ServedWriteDispatchPortChirho>,
    pub(crate) local_read_authority_chirho: Arc<dyn ServedLocalReadAuthorityPortChirho>,
    pub(crate) destination_slot_chirho: ServedWriteRelayDestinationSlotChirho,
    pub(crate) router_chirho: Router,
    pub(crate) mirror_peer_endpoints_chirho: Vec<LedgerMirrorPeerEndpointChirho>,
    local_authority_readiness_chirho: LocalRelayAuthorityReadinessChirho,
}

impl ServedWriteRelayCompositionChirho {
    pub(crate) fn mark_local_authority_ready_chirho(&self) {
        self.local_authority_readiness_chirho.mark_ready_chirho();
    }
}

struct SharedRaftLeadershipViewChirho {
    elector_chirho: Arc<RaftWriterElectorChirho>,
}

impl FixedGroupLeadershipViewChirho for SharedRaftLeadershipViewChirho {
    fn current_leadership_chirho(&self) -> LeadershipChirho {
        self.elector_chirho.current_leadership_chirho()
    }
}

pub(crate) fn compose_served_write_relay_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
    sign_root_chirho: &Path,
    listen_addr_chirho: &str,
    local_node_id_chirho: &str,
    membership_chirho: &MembershipControlConfigChirho,
    cluster_node_chirho: &ClusterNodeChirho,
) -> Result<ServedWriteRelayCompositionChirho> {
    validate_relay_lease_timing_chirho(cluster_node_chirho.tick_interval_chirho())?;
    let elector_chirho = Arc::clone(cluster_node_chirho.elector_chirho());
    if membership_chirho.local_node_pubkey_hex_chirho != local_node_id_chirho {
        bail!("relay membership control and election config name different local nodes");
    }
    if membership_chirho.group_id_chirho != group_chirho.canonical_id_chirho() {
        bail!("relay membership control and election config name different consistency groups");
    }
    let tenant_id_chirho = match group_chirho {
        ConsistencyGroupIdChirho::TenantChirho { tenant_id_chirho } => tenant_id_chirho,
        ConsistencyGroupIdChirho::RootPathChirho { .. } => {
            bail!("RelayPlatformRootIdentityUnavailableChirho")
        }
    };
    let group_digest_chirho = relay_tenant_consistency_group_digest_chirho(tenant_id_chirho)
        .map_err(anyhow::Error::from)?;
    let roster_bytes_chirho = read_bounded_file_chirho(
        &membership_chirho.roster_authority_chirho.roster_path_chirho,
        RELAY_ROSTER_FILE_MAX_BYTES_CHIRHO,
        "relay roster",
    )?;
    let roster_lines_chirho = split_bounded_roster_lines_chirho(&roster_bytes_chirho)?;
    let roster_head_chirho = read_bounded_file_chirho(
        &membership_chirho
            .roster_authority_chirho
            .roster_head_path_chirho,
        RELAY_ROSTER_HEAD_MAX_BYTES_CHIRHO,
        "relay roster head",
    )?;
    let verified_mesh_chirho = derive_verified_relay_mesh_chirho(
        &roster_lines_chirho,
        &roster_head_chirho,
        &membership_chirho
            .roster_authority_chirho
            .operator_pubkey_hex_chirho,
        local_node_id_chirho,
    )
    .context("derive complete operator-signed relay mesh")?;
    if verified_mesh_chirho.local_node_id_chirho() != local_node_id_chirho {
        bail!("relay mesh local node differs from the exact election node");
    }
    // The interface is a CONFIGURED coordinate, defaulting to `RELAY_WIREGUARD_INTERFACE_CHIRHO`
    // when the cluster config omits it. Naming a different interface admits nothing: the verifier
    // below requires it to be UP, to carry the SIGNED local mesh address, and to have a peer set
    // exactly equal to the signed roster — which must in turn equal the election population.
    let active_mesh_chirho = verify_active_relay_mesh_interface_chirho(
        verified_mesh_chirho,
        &membership_chirho
            .roster_authority_chirho
            .relay_interface_chirho,
    )
    .context("verify signed relay identity on the active WireGuard interface")?;
    verify_relay_listener_chirho(listen_addr_chirho, &active_mesh_chirho)?;
    let mirror_peer_endpoints_chirho = active_mesh_chirho
        .members_chirho()
        .iter()
        .map(|member_chirho| {
            LedgerMirrorPeerEndpointChirho::new_chirho(
                member_chirho.node_id_chirho().to_string(),
                SocketAddr::new(member_chirho.mesh_ip_chirho(), ELECTOR_PORT_CHIRHO),
            )
        })
        .collect::<Result<Vec<_>>>()
        .context("derive private F1 mirror endpoints from the active signed relay mesh")?;
    let mesh_members_chirho = active_mesh_chirho
        .members_chirho()
        .iter()
        .map(|member_chirho| member_chirho.node_id_chirho().to_string())
        .collect::<Vec<_>>();
    let authenticated_members_chirho = elector_chirho.authenticated_members_chirho();
    let election_members_chirho = authenticated_members_chirho
        .iter()
        .map(|(_member_id_chirho, node_chirho)| node_chirho.0.clone())
        .collect::<Vec<_>>();
    verify_matching_relay_population_chirho(&mesh_members_chirho, &election_members_chirho)?;
    let leadership_chirho: Arc<dyn FixedGroupLeadershipViewChirho> =
        Arc::new(SharedRaftLeadershipViewChirho {
            elector_chirho: Arc::clone(&elector_chirho),
        });
    let clock_chirho: Arc<dyn MonotonicClockChirho> =
        Arc::new(SystemMonotonicClockChirho::new_chirho());
    let (directory_chirho, roster_chirho) =
        FixedRelayDirectoryChirho::new_from_verified_active_mesh_chirho(
            group_digest_chirho.clone(),
            Arc::clone(&leadership_chirho),
            &active_mesh_chirho,
            Arc::clone(&clock_chirho),
            DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO,
        )
        .context("compose fixed relay directory from active signed mesh")?;
    let roster_chirho = Arc::new(roster_chirho);
    let relay_chirho = Arc::new(HttpServedWriteRelayPortChirho::new_chirho(
        Arc::new(directory_chirho),
        Arc::clone(&roster_chirho),
        RelayHttpTimeoutsChirho::default(),
    ));
    let request_signer_chirho = Arc::new(
        ExistingKeyRelayRequestSignerChirho::new_chirho(
            sign_root_chirho,
            local_node_id_chirho.to_string(),
        )
        .context("bind relay request signer to the election node identity")?,
    );
    let local_authority_readiness_chirho = LocalRelayAuthorityReadinessChirho::new_chirho();
    let dispatcher_chirho = Arc::new(
        HttpServedWriteDispatchPortChirho::new_chirho(
            local_node_id_chirho.to_string(),
            group_digest_chirho.clone(),
            Arc::clone(&roster_chirho),
            Arc::clone(&leadership_chirho),
            request_signer_chirho,
            relay_chirho,
            LocalRelayDispatchPolicyChirho::new_chirho(
                SERVED_WRITE_RELAY_BUDGET_MILLIS_CHIRHO,
                local_authority_readiness_chirho.clone(),
            ),
        )
        .context("compose served-write dispatcher")?,
    );
    let dispatch_chirho: Arc<dyn ServedWriteDispatchPortChirho> = dispatcher_chirho.clone();
    let local_read_authority_chirho: Arc<dyn ServedLocalReadAuthorityPortChirho> =
        dispatcher_chirho;
    let destination_slot_chirho = ServedWriteRelayDestinationSlotChirho::new_chirho();
    let response_signer_chirho = Arc::new(
        ExistingKeyRelayResponseSignerChirho::new_chirho(
            sign_root_chirho,
            local_node_id_chirho.to_string(),
        )
        .context("bind relay response signer to the election node identity")?,
    );
    let server_chirho = RelayServerStateChirho::new_chirho(RelayServerConfigChirho {
        group_digest_chirho,
        node_id_chirho: local_node_id_chirho.to_string(),
        roster_chirho,
        leadership_chirho,
        clock_chirho,
        transit_budget_millis_chirho: DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO,
        signer_chirho: response_signer_chirho,
        execution_chirho: Arc::new(destination_slot_chirho.clone()),
    })
    .context("compose served-write relay endpoint")?;
    let router_chirho = relay_router_chirho(server_chirho);
    Ok(ServedWriteRelayCompositionChirho {
        dispatch_chirho,
        local_read_authority_chirho,
        destination_slot_chirho,
        router_chirho,
        mirror_peer_endpoints_chirho,
        local_authority_readiness_chirho,
    })
}

pub(crate) fn validate_relay_lease_timing_chirho(tick_interval_chirho: Duration) -> Result<()> {
    validate_election_timeout_relay_margin_chirho(
        tick_interval_chirho,
        DEFAULT_TRANSIT_BUDGET_MILLIS_CHIRHO,
    )
}

fn verify_relay_listener_chirho(
    listen_addr_chirho: &str,
    active_mesh_chirho: &cairn_roster_config_chirho::VerifiedActiveRelayMeshChirho,
) -> Result<()> {
    verify_relay_listener_for_mesh_ip_chirho(
        listen_addr_chirho,
        active_mesh_chirho.local_mesh_ip_chirho(),
    )
}

fn verify_relay_listener_for_mesh_ip_chirho(
    listen_addr_chirho: &str,
    mesh_ip_chirho: std::net::IpAddr,
) -> Result<()> {
    let actual_chirho = listen_addr_chirho
        .parse::<SocketAddr>()
        .context("parse numeric geo election and relay listener")?;
    let expected_chirho = SocketAddr::new(mesh_ip_chirho, ELECTOR_PORT_CHIRHO);
    if actual_chirho != expected_chirho {
        bail!("RelayMeshListenerMismatchChirho");
    }
    Ok(())
}

fn verify_matching_relay_population_chirho(
    mesh_members_chirho: &[String],
    election_members_chirho: &[String],
) -> Result<()> {
    let mesh_set_chirho = mesh_members_chirho.iter().cloned().collect::<BTreeSet<_>>();
    let election_set_chirho = election_members_chirho
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if mesh_set_chirho.len() != mesh_members_chirho.len()
        || election_set_chirho.len() != election_members_chirho.len()
        || mesh_set_chirho != election_set_chirho
    {
        bail!("RelayRosterElectionPopulationMismatchChirho");
    }
    Ok(())
}

fn read_bounded_file_chirho(
    path_chirho: &Path,
    max_bytes_chirho: u64,
    label_chirho: &str,
) -> Result<Vec<u8>> {
    cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        path_chirho,
        max_bytes_chirho,
    )
    .with_context(|| {
        format!(
            "read identity-stable bounded {label_chirho} {}",
            path_chirho.display()
        )
    })
}

fn split_bounded_roster_lines_chirho(bytes_chirho: &[u8]) -> Result<Vec<Vec<u8>>> {
    let lines_chirho = bytes_chirho
        .split(|byte_chirho| *byte_chirho == b'\n')
        .filter(|line_chirho| {
            !line_chirho
                .iter()
                .all(|byte_chirho| byte_chirho.is_ascii_whitespace())
        })
        .map(|line_chirho| line_chirho.to_vec())
        .collect::<Vec<_>>();
    if lines_chirho.is_empty() || lines_chirho.len() > RELAY_ROSTER_MAX_LINES_CHIRHO {
        bail!("relay roster is empty or exceeds its bounded record population");
    }
    Ok(lines_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
    use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
    use cairn_writer_elector_http_chirho::cluster_node_chirho::ClusterNodeConfigChirho;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn relay_timing_test_root_chirho() -> PathBuf {
        let nonce_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "cairn-relay-timing-{}-{nonce_chirho}-chirho",
            std::process::id()
        ))
    }

    #[test]
    fn relay_population_requires_exact_unique_election_members_chirho() {
        let node_a_chirho = "a".repeat(64);
        let node_b_chirho = "b".repeat(64);
        verify_matching_relay_population_chirho(
            &[node_a_chirho.clone(), node_b_chirho.clone()],
            &[node_b_chirho.clone(), node_a_chirho.clone()],
        )
        .expect("ordering does not change the exact population");

        for election_chirho in [
            vec![node_a_chirho.clone()],
            vec![
                node_a_chirho.clone(),
                node_b_chirho.clone(),
                node_b_chirho.clone(),
            ],
        ] {
            assert!(verify_matching_relay_population_chirho(
                &[node_a_chirho.clone(), node_b_chirho.clone()],
                &election_chirho,
            )
            .unwrap_err()
            .to_string()
            .contains("RelayRosterElectionPopulationMismatchChirho"));
        }
    }

    #[test]
    fn relay_listener_is_the_signed_mesh_address_on_the_named_port_chirho() {
        let mesh_ip_chirho = "10.100.0.7".parse().unwrap();
        verify_relay_listener_for_mesh_ip_chirho("10.100.0.7:8300", mesh_ip_chirho)
            .expect("exact signed mesh listener");
        for listener_chirho in ["127.0.0.1:8300", "10.100.0.7:8301"] {
            assert!(
                verify_relay_listener_for_mesh_ip_chirho(listener_chirho, mesh_ip_chirho)
                    .unwrap_err()
                    .to_string()
                    .contains("RelayMeshListenerMismatchChirho")
            );
        }
    }

    #[test]
    fn relay_lease_timing_refuses_the_exact_incompatible_tick_boundary_chirho() {
        let incompatible_chirho = validate_relay_lease_timing_chirho(Duration::from_millis(27))
            .expect_err("27ms leaves less than the selected transit budget after one tick");
        assert!(
            incompatible_chirho
                .to_string()
                .contains("RelayLeaseTransitBudgetIncompatibleChirho"),
            "the compatibility miss must retain its named startup refusal"
        );
        validate_relay_lease_timing_chirho(Duration::from_millis(28))
            .expect("28ms leaves positive lease time after one healthy tick and transit deduction");
    }

    #[test]
    fn relay_composition_checks_lease_timing_before_roster_or_signer_io_chirho() {
        let root_chirho = relay_timing_test_root_chirho();
        let sign_root_chirho = root_chirho.join("sign-chirho");
        sign_message_chirho(&sign_root_chirho, b"provision relay timing node key")
            .expect("provision relay timing node key");
        let group_chirho = ConsistencyGroupIdChirho::TenantChirho {
            tenant_id_chirho: "relay-timing-chirho".to_string(),
        };
        let node_id_chirho =
            pubkey_hex_chirho(&sign_root_chirho).expect("read relay timing node identity");
        let membership_chirho = MembershipControlConfigChirho {
            roster_authority_chirho: RosterAuthorityConfigChirho {
                roster_path_chirho: PathBuf::from("/nonexistent/relay-roster-chirho.jsonl"),
                roster_head_path_chirho: PathBuf::from(
                    "/nonexistent/relay-roster-head-chirho.json",
                ),
                operator_pubkey_hex_chirho: "b".repeat(64),
                relay_interface_chirho:
                    cairn_roster_config_chirho::RELAY_WIREGUARD_INTERFACE_CHIRHO.to_string(),
            },
            local_node_pubkey_hex_chirho: node_id_chirho.clone(),
            group_id_chirho: group_chirho.canonical_id_chirho(),
            target_authority_chirho: MembershipTargetAuthorityChirho::RosterWideChirho,
            operator_token_chirho: None,
            fixpoint_step_sleep_chirho: Duration::from_millis(1),
            fixpoint_max_steps_chirho: 1,
        };
        let cluster_node_chirho = ClusterNodeChirho::build_chirho(ClusterNodeConfigChirho {
            group_chirho: group_chirho.clone(),
            local_raft_id_chirho: 1,
            voters_chirho: vec![(1, NodeIdChirho(node_id_chirho.clone()))],
            learners_chirho: Vec::new(),
            peers_chirho: Vec::new(),
            durable_dir_chirho: root_chirho.join("raft-chirho"),
            sign_root_chirho: sign_root_chirho.clone(),
            tick_interval_chirho: Duration::from_millis(27),
            membership_control_chirho: None,
        })
        .expect("build the actual deployable cluster-node composition");
        let failure_chirho = compose_served_write_relay_chirho(
            &group_chirho,
            &sign_root_chirho,
            "10.100.0.1:8300",
            &node_id_chirho,
            &membership_chirho,
            &cluster_node_chirho,
        )
        .err()
        .expect("incompatible timing must refuse before external state is read");
        assert!(
            failure_chirho
                .to_string()
                .contains("RelayLeaseTransitBudgetIncompatibleChirho"),
            "the production composition must surface the timing refusal rather than a later roster or signer error"
        );
        drop(cluster_node_chirho);
        std::fs::remove_dir_all(root_chirho).expect("remove relay timing fixture");
    }
}
