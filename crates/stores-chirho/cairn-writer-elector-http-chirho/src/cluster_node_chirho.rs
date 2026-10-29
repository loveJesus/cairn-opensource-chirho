// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The deployable cluster node — the composition capstone that wires the P4 primitives into one runnable
//! unit for a real ≥3-domain fleet. `ClusterNodeChirho::build_chirho` assembles a DURABLE, crash-safe,
//! AUTHENTICATED elector (voters + non-voting learners) behind a fire-and-forget driver;
//! `serve_blocking_chirho` serves the Raft-fire + leader-discovery endpoints and ticks the elector on a
//! timer until asked to stop. Build-then-serve is split so a caller can read leadership (or wire routing)
//! from the same node it is about to run. It is ELECTION-ONLY — it mints nothing; a live geo cluster
//! gains mint authority only at the separate, hard-gated P5 cutover, which is not here.

use crate::driver_chirho::{validate_outbound_config_chirho, RaftDriverChirho};
use crate::membership_control_chirho::{
    membership_control_router_chirho, MembershipControlChirho, MembershipControlConfigChirho,
};
use crate::{raft_fire_router_chirho, serve_router_blocking_with_shutdown_chirho};
use anyhow::{Context, Result};
use axum::Router;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::monotonic_clock_chirho::{
    MonotonicClockChirho, SystemMonotonicClockChirho,
};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::collections::BTreeSet;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const MIN_CLUSTER_TICK_INTERVAL_CHIRHO: Duration = Duration::from_millis(10);
const MAX_CLUSTER_TICK_INTERVAL_CHIRHO: Duration = Duration::from_secs(1);

/// Everything needed to run one production cluster node.
pub struct ClusterNodeConfigChirho {
    /// The consistency group (tenant/root) this node serves.
    pub group_chirho: ConsistencyGroupIdChirho,
    /// This node's raft id (must appear in `voters_chirho` or `learners_chirho`).
    pub local_raft_id_chirho: u64,
    /// The voting quorum: `(raft_id, node_id/pubkey)`. A commit waits on a majority of THESE.
    pub voters_chirho: Vec<(u64, NodeIdChirho)>,
    /// Non-voting learners (async DR replicas): `(raft_id, node_id/pubkey)`.
    pub learners_chirho: Vec<(u64, NodeIdChirho)>,
    /// Where to deliver this node's messages: `(raft_id, base_url)` for every peer EXCEPT self.
    pub peers_chirho: Vec<(u64, String)>,
    /// Directory for the durable Raft store (term/vote/log survive a restart).
    pub durable_dir_chirho: PathBuf,
    /// This node's signing root — its key signs outbound messages and the roster verifies inbound.
    pub sign_root_chirho: PathBuf,
    /// How often the driver ticks the elector (drives elections + heartbeats).
    pub tick_interval_chirho: Duration,
    /// A1.5: optional membership drive/observe surface. `Some` ⇒ the node ALSO serves the
    /// `/converge-chirho`, `/re-home-chirho`, and `/membership-chirho` endpoints (token-gated mutations,
    /// open observe) so a shadow-fleet drill can converge/re-home/observe over HTTP. `None` ⇒ a plain P4
    /// election node, byte-for-byte the prior served surface (backward compatible).
    pub membership_control_chirho: Option<MembershipControlConfigChirho>,
}

/// A target-free capability for asking the current Raft leader to transfer leadership to this node.
///
/// Closing over the driver's verified local elector keeps callers from turning resident recomposition
/// into an arbitrary-target leadership-transfer surface. The request still traverses authenticated Raft
/// transport and must win a real quorum election before the caller observes local leadership.
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/cf8-canary-window-loss-sequence-chirho.md`.
#[derive(Clone)]
pub struct LocalLeadershipTransferPortChirho {
    driver_chirho: Arc<RaftDriverChirho>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalLeadershipTransferRequestOutcomeChirho {
    AlreadyLocalLeaderChirho,
    DispatchedChirho,
}

impl LocalLeadershipTransferPortChirho {
    pub fn request_chirho(&self) -> Result<LocalLeadershipTransferRequestOutcomeChirho> {
        let elector_chirho = self.driver_chirho.elector_chirho();
        let local_raft_id_chirho = elector_chirho.local_raft_id_chirho();
        let (voters_chirho, _learners_chirho) = elector_chirho
            .membership_snapshot_chirho()
            .context("LocalLeadershipTransferMembershipReadRefusedChirho")?;
        if !voters_chirho.contains(&local_raft_id_chirho) {
            anyhow::bail!("LocalLeadershipTransferLocalVoterRefusedChirho");
        }
        if elector_chirho.current_leadership_chirho().is_leader_chirho {
            return Ok(LocalLeadershipTransferRequestOutcomeChirho::AlreadyLocalLeaderChirho);
        }
        let outbound_chirho = elector_chirho
            .transfer_leadership_to_chirho(local_raft_id_chirho)
            .context("LocalLeadershipTransferRequestRefusedChirho")?;
        if outbound_chirho.is_empty() {
            if elector_chirho.current_leadership_chirho().is_leader_chirho {
                return Ok(LocalLeadershipTransferRequestOutcomeChirho::AlreadyLocalLeaderChirho);
            }
            anyhow::bail!("LocalLeadershipTransferBatchEmptyRefusedChirho");
        }
        self.driver_chirho
            .deliver_required_control_chirho(outbound_chirho)
            .context("LocalLeadershipTransferDeliveryRefusedChirho")?;
        Ok(LocalLeadershipTransferRequestOutcomeChirho::DispatchedChirho)
    }
}

/// A built (not-yet-serving) cluster node: its elector (for reading leadership / wiring routing) and the
/// driver that will pump its messages.
pub struct ClusterNodeChirho {
    elector_chirho: Arc<RaftWriterElectorChirho>,
    driver_chirho: Arc<RaftDriverChirho>,
    tick_interval_chirho: Duration,
    /// A1.5 membership drive/observe surface, built when the config asked for it (shares this node's
    /// driver + elector). `None` ⇒ the node serves only the P4 election endpoints.
    membership_control_chirho: Option<Arc<MembershipControlChirho>>,
}

impl ClusterNodeChirho {
    /// Assemble the node from `config_chirho`: a durable, authenticated elector (voters + learners) behind
    /// a fire-and-forget driver. Does not bind or serve — call `serve_blocking_chirho` for that.
    pub fn build_chirho(config_chirho: ClusterNodeConfigChirho) -> Result<Self> {
        Self::build_with_existing_requirement_and_clock_chirho(
            config_chirho,
            false,
            Arc::new(SystemMonotonicClockChirho::new_chirho()),
        )
    }

    /// Reopen a previously initialized node without creating or seeding durable Raft membership.
    ///
    /// Authority-bearing serving uses this posture: missing election state, recovered roster drift,
    /// or a half-applied joint membership transition refuses before a transport or ticker starts.
    pub fn open_existing_chirho(config_chirho: ClusterNodeConfigChirho) -> Result<Self> {
        Self::build_with_existing_requirement_and_clock_chirho(
            config_chirho,
            true,
            Arc::new(SystemMonotonicClockChirho::new_chirho()),
        )
    }

    fn build_with_existing_requirement_and_clock_chirho(
        config_chirho: ClusterNodeConfigChirho,
        existing_only_chirho: bool,
        clock_chirho: Arc<dyn MonotonicClockChirho>,
    ) -> Result<Self> {
        let ClusterNodeConfigChirho {
            group_chirho,
            local_raft_id_chirho,
            voters_chirho,
            learners_chirho,
            peers_chirho,
            durable_dir_chirho,
            sign_root_chirho,
            tick_interval_chirho,
            membership_control_chirho,
        } = config_chirho;
        validate_cluster_tick_interval_chirho(tick_interval_chirho)?;
        validate_outbound_config_chirho(&peers_chirho, Duration::from_secs(2))?;
        let expected_peer_ids_chirho = voters_chirho
            .iter()
            .chain(&learners_chirho)
            .map(|(raft_id_chirho, _node_id_chirho)| *raft_id_chirho)
            .filter(|raft_id_chirho| *raft_id_chirho != local_raft_id_chirho)
            .collect::<BTreeSet<_>>();
        let actual_peer_ids_chirho = peers_chirho
            .iter()
            .map(|(raft_id_chirho, _base_url_chirho)| *raft_id_chirho)
            .collect::<BTreeSet<_>>();
        if actual_peer_ids_chirho.contains(&local_raft_id_chirho) {
            anyhow::bail!("outbound raft peers must exclude the local node");
        }
        // Every ACTIVE member needs a route before durable state can be opened or seeded. Bounded extra
        // routes are deliberate: they preprovision reviewed prospective learners so a verified
        // membership add can deliver immediately without restarting the node or accepting an ambient URL.
        if !expected_peer_ids_chirho.is_subset(&actual_peer_ids_chirho) {
            anyhow::bail!("outbound raft peers must cover every other voter and learner");
        }
        // P5/A6 workflow:
        // `spec-chirho/workflows-chirho/distributed-ha-chirho/
        // p5-cutover-and-lease-design-chirho.md`.
        //
        // Tier 1 and its sealed local-authority pair are born together. There is no later builder
        // that could replace the mutex domain after a handle or guard escaped.
        let elector_chirho = if existing_only_chirho {
            RaftWriterElectorChirho::open_existing_durable_cluster_node_with_learners_and_election_timeout_monotonic_lease_chirho(
                durable_dir_chirho,
                group_chirho,
                local_raft_id_chirho,
                voters_chirho,
                learners_chirho,
                clock_chirho,
                tick_interval_chirho,
            )?
        } else {
            RaftWriterElectorChirho::new_durable_cluster_node_with_learners_and_election_timeout_monotonic_lease_chirho(
                durable_dir_chirho,
                group_chirho,
                local_raft_id_chirho,
                voters_chirho,
                learners_chirho,
                clock_chirho,
                tick_interval_chirho,
            )?
        };
        let elector_chirho =
            Arc::new(elector_chirho.with_message_authentication_chirho(sign_root_chirho));
        let driver_chirho = Arc::new(RaftDriverChirho::new_chirho(
            elector_chirho.clone(),
            peers_chirho,
            Duration::from_secs(2),
        )?);
        // A1.5: build the membership-control surface iff configured (it shares this node's driver, so it
        // drives the SAME elector the timer ticks and observes its live membership).
        let membership_control_chirho = membership_control_chirho.map(|control_config_chirho| {
            Arc::new(MembershipControlChirho::new_chirho(
                driver_chirho.clone(),
                control_config_chirho,
            ))
        });
        Ok(Self {
            elector_chirho,
            driver_chirho,
            tick_interval_chirho,
            membership_control_chirho,
        })
    }

    /// This node's elector — read leadership (e.g. to answer "am I the master") or drive routing.
    pub fn elector_chirho(&self) -> &Arc<RaftWriterElectorChirho> {
        &self.elector_chirho
    }

    /// Mint the target-free local transfer capability before this node is moved into its serve thread.
    pub fn local_leadership_transfer_port_chirho(&self) -> LocalLeadershipTransferPortChirho {
        LocalLeadershipTransferPortChirho {
            driver_chirho: Arc::clone(&self.driver_chirho),
        }
    }

    pub fn tick_interval_chirho(&self) -> Duration {
        self.tick_interval_chirho
    }

    /// Run the node on `listener_chirho`: start the timer loop (ticks until `stop_chirho` is set) and serve
    /// the Raft-fire + leader-discovery endpoints, blocking the calling thread on the server. A caller
    /// binds the address it wants and runs this on the main thread (a deployed node) or a spawned thread.
    pub fn serve_blocking_chirho(
        &self,
        listener_chirho: TcpListener,
        stop_chirho: Arc<AtomicBool>,
    ) -> Result<()> {
        self.serve_blocking_with_optional_router_chirho(listener_chirho, stop_chirho, None)
    }

    /// Run the node with one reviewed composition router on the exact election listener.
    ///
    /// The additional routes share the transport's sole ticker, process stop signal, and graceful
    /// shutdown. They gain no access to the driver or elector through this API; the composition
    /// supplies only its own already-bounded state.
    pub fn serve_blocking_with_additional_router_chirho(
        &self,
        listener_chirho: TcpListener,
        stop_chirho: Arc<AtomicBool>,
        additional_router_chirho: Router,
    ) -> Result<()> {
        self.serve_blocking_with_optional_router_chirho(
            listener_chirho,
            stop_chirho,
            Some(additional_router_chirho),
        )
    }

    fn serve_blocking_with_optional_router_chirho(
        &self,
        listener_chirho: TcpListener,
        stop_chirho: Arc<AtomicBool>,
        additional_router_chirho: Option<Router>,
    ) -> Result<()> {
        let tick_driver_chirho = self.driver_chirho.clone();
        let tick_stop_chirho = stop_chirho.clone();
        let tick_interval_chirho = self.tick_interval_chirho;
        let tick_handle_chirho = std::thread::spawn(move || {
            // A node whose ticks fail serves normally, dials nobody and persists nothing, so its
            // health endpoint is indistinguishable from an idle node's. Say it out loud instead:
            // report the first failure immediately, then only on a change, so a wedged node is
            // obvious in the log without a healthy one being noisy.
            let mut reported_failures_chirho = 0_u64;
            while !tick_stop_chirho.load(Ordering::Relaxed) {
                tick_driver_chirho.tick_once_chirho();
                let failures_chirho = tick_driver_chirho.tick_failures_chirho();
                if failures_chirho > reported_failures_chirho {
                    eprintln!(
                        "cairn cluster node: NOT MAKING PROGRESS -- {failures_chirho} elector tick(s) \
                         have failed; this node is serving but not participating in raft. last error: {}",
                        tick_driver_chirho
                            .last_tick_error_chirho()
                            .unwrap_or_else(|| "<none recorded>".to_string())
                    );
                    reported_failures_chirho = failures_chirho;
                }
                std::thread::park_timeout(tick_interval_chirho);
            }
        });

        let mut router_chirho = raft_fire_router_chirho(self.driver_chirho.clone());
        // A1.5: if this node carries a membership-control surface, merge its endpoints onto the same served
        // socket (each sub-router keeps its own body-limit layer). Absent ⇒ the served surface is unchanged.
        if let Some(control_chirho) = &self.membership_control_chirho {
            router_chirho =
                router_chirho.merge(membership_control_router_chirho(control_chirho.clone()));
        }
        if let Some(additional_router_chirho) = additional_router_chirho {
            router_chirho = router_chirho.merge(additional_router_chirho);
        }
        // Serve until `stop_chirho` is set, then gracefully shut down and return — so the node is cleanly
        // restartable (drain/roll), not only killable.
        let serve_result_chirho = serve_router_blocking_with_shutdown_chirho(
            listener_chirho,
            router_chirho,
            stop_chirho.clone(),
        );

        // Serving ended (stop was set, or an error) — wind down the timer loop too.
        stop_chirho.store(true, Ordering::Relaxed);
        tick_handle_chirho.thread().unpark();
        let _ = tick_handle_chirho.join();
        serve_result_chirho
    }
}

pub(crate) fn validate_cluster_tick_interval_chirho(tick_interval_chirho: Duration) -> Result<()> {
    if !(MIN_CLUSTER_TICK_INTERVAL_CHIRHO..=MAX_CLUSTER_TICK_INTERVAL_CHIRHO)
        .contains(&tick_interval_chirho)
    {
        anyhow::bail!(
            "cluster tick interval must be between {} and {} milliseconds",
            MIN_CLUSTER_TICK_INTERVAL_CHIRHO.as_millis(),
            MAX_CLUSTER_TICK_INTERVAL_CHIRHO.as_millis()
        );
    }
    if !tick_interval_chirho
        .subsec_nanos()
        .is_multiple_of(1_000_000)
    {
        anyhow::bail!("cluster tick interval must be a whole number of milliseconds");
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::{
        discover_leader_chirho, raft_fire_router_chirho, serve_router_blocking_with_shutdown_chirho,
    };
    use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
    use cairn_writer_elector_chirho::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
    use cairn_writer_elector_chirho::monotonic_clock_chirho::FakeMonotonicClockChirho;
    use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
    use cairn_writer_elector_chirho::LocalAppendAuthorityRefusalChirho;
    use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;

    fn test_dir_chirho(label_chirho: &str) -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
        let path_chirho = std::env::temp_dir().join(format!(
            "cairn-tier-one-{label_chirho}-{}-{counter_chirho}-chirho",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path_chirho);
        path_chirho
    }

    fn warmed_elector_chirho(
        tick_interval_chirho: Duration,
        label_chirho: &str,
    ) -> (
        RaftWriterElectorChirho,
        Arc<FakeMonotonicClockChirho>,
        ConsistencyGroupIdChirho,
    ) {
        let clock_chirho = FakeMonotonicClockChirho::new_chirho();
        let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: format!("/var/lib/cairn-{label_chirho}-chirho"),
        };
        let elector_chirho =
            RaftWriterElectorChirho::new_single_node_with_election_timeout_monotonic_leadership_lease_chirho(
            NodeIdChirho("a".repeat(64)),
            group_chirho.clone(),
            clock_chirho.clone(),
            tick_interval_chirho,
        )
        .expect("derive tier-one lease from a whole-millisecond tick");
        elector_chirho
            .campaign_chirho()
            .expect("elect deterministic tier-one leader");
        for _tick_chirho in 0..32 {
            clock_chirho.advance_millis_chirho(
                u64::try_from(tick_interval_chirho.as_millis())
                    .expect("validated test tick fits u64"),
            );
            elector_chirho.tick_chirho();
            if elector_chirho
                .leadership_chirho(&group_chirho)
                .lease_valid_chirho
            {
                return (elector_chirho, clock_chirho, group_chirho);
            }
        }
        panic!("tier-one lease did not warm inside two election intervals");
    }

    #[test]
    fn production_lease_bounds_track_both_validated_tick_extremes_chirho() {
        let (minimum_chirho, _minimum_clock_chirho, _minimum_group_chirho) =
            warmed_elector_chirho(MIN_CLUSTER_TICK_INTERVAL_CHIRHO, "minimum-bound");
        let (maximum_chirho, _maximum_clock_chirho, _maximum_group_chirho) =
            warmed_elector_chirho(MAX_CLUSTER_TICK_INTERVAL_CHIRHO, "maximum-bound");
        assert_eq!(
            minimum_chirho.current_lease_remaining_millis_chirho(),
            Some(100),
            "the 10ms validated tick derives one 100ms election-timeout lease"
        );
        assert_eq!(
            maximum_chirho.current_lease_remaining_millis_chirho(),
            Some(10_000),
            "the 1000ms validated tick derives one 10s election-timeout lease"
        );
    }

    #[test]
    fn production_warmup_refuses_at_e_minus_one_and_opens_at_e_chirho() {
        let clock_chirho = FakeMonotonicClockChirho::new_chirho();
        let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: "/var/lib/cairn-warmup-boundary-chirho".to_string(),
        };
        let elector_chirho =
            RaftWriterElectorChirho::new_single_node_with_election_timeout_monotonic_leadership_lease_chirho(
            NodeIdChirho("c".repeat(64)),
            group_chirho.clone(),
            clock_chirho.clone(),
            Duration::from_millis(10),
        )
        .expect("derive warm-up boundary lease");
        elector_chirho
            .campaign_chirho()
            .expect("campaign warm-up boundary elector");
        clock_chirho.advance_millis_chirho(1);
        elector_chirho.tick_chirho();
        clock_chirho.advance_millis_chirho(99);
        elector_chirho.tick_chirho();
        assert!(
            !elector_chirho
                .leadership_chirho(&group_chirho)
                .lease_valid_chirho,
            "E-1 since the first leader confirmation must remain unwarmed"
        );
        assert_eq!(elector_chirho.current_lease_remaining_millis_chirho(), None);
        assert!(matches!(
            elector_chirho
                .local_append_authority_handle_chirho()
                .try_acquire_chirho(),
            Err(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho)
        ));

        clock_chirho.advance_millis_chirho(1);
        elector_chirho.tick_chirho();
        assert!(
            elector_chirho
                .leadership_chirho(&group_chirho)
                .lease_valid_chirho,
            "exactly one derived election interval opens the warm-up gate"
        );
        assert_eq!(
            elector_chirho.current_lease_remaining_millis_chirho(),
            Some(100)
        );
        drop(
            elector_chirho
                .local_append_authority_handle_chirho()
                .try_acquire_chirho()
                .expect("wire and local admission open at the same warm-up boundary"),
        );
    }

    #[test]
    fn minimum_production_lease_has_exact_expiry_under_injected_healthy_cadence_chirho() {
        let (elector_chirho, clock_chirho, group_chirho) =
            warmed_elector_chirho(MIN_CLUSTER_TICK_INTERVAL_CHIRHO, "minimum-liveness");
        for _tick_chirho in 0..20 {
            clock_chirho.advance_millis_chirho(
                u64::try_from(MIN_CLUSTER_TICK_INTERVAL_CHIRHO.as_millis())
                    .expect("minimum tick fits u64"),
            );
            elector_chirho.tick_chirho();
            assert!(
                elector_chirho
                    .leadership_chirho(&group_chirho)
                    .lease_valid_chirho,
                "a healthy minimum-tick leader must not flicker while confirmations continue"
            );
        }

        clock_chirho.advance_millis_chirho(99);
        assert_eq!(
            elector_chirho.current_lease_remaining_millis_chirho(),
            Some(1),
            "one millisecond before expiry remains live and rounds toward less time"
        );
        drop(
            elector_chirho
                .local_append_authority_handle_chirho()
                .try_acquire_chirho()
                .expect("the local append handle shares the live E-1 boundary"),
        );
        clock_chirho.advance_millis_chirho(1);
        let expired_chirho = elector_chirho.leadership_chirho(&group_chirho);
        assert!(
            expired_chirho.is_leader_chirho && !expired_chirho.lease_valid_chirho,
            "the same minimum-tick leader must fail closed at exact expiry"
        );
        assert_eq!(
            elector_chirho.current_lease_remaining_millis_chirho(),
            None,
            "exact expiry emits no wire duration"
        );
        assert!(matches!(
            elector_chirho
                .local_append_authority_handle_chirho()
                .try_acquire_chirho(),
            Err(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho)
        ));
    }

    #[test]
    fn fractional_millisecond_deployable_ticks_refuse_instead_of_rounding_chirho() {
        let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: "/var/lib/cairn-fractional-tick-chirho".to_string(),
        };
        let result_chirho =
            RaftWriterElectorChirho::new_single_node_with_election_timeout_monotonic_leadership_lease_chirho(
            NodeIdChirho("b".repeat(64)),
            group_chirho,
            FakeMonotonicClockChirho::new_chirho(),
            Duration::from_micros(10_500),
        );
        assert!(
            result_chirho.is_err(),
            "a fractional-millisecond tick must refuse rather than silently lengthen or shorten authority"
        );
    }

    #[test]
    fn fractional_cluster_tick_refuses_before_durable_membership_is_seeded_chirho() {
        let sign_root_chirho = test_dir_chirho("fractional-cluster-sign");
        sign_message_chirho(&sign_root_chirho, b"provision fractional cluster key")
            .expect("provision fractional cluster key");
        let node_id_chirho = NodeIdChirho(
            pubkey_hex_chirho(&sign_root_chirho).expect("read fractional cluster node identity"),
        );
        let durable_dir_chirho = test_dir_chirho("fractional-cluster-durable");
        let result_chirho = ClusterNodeChirho::build_chirho(ClusterNodeConfigChirho {
            group_chirho: ConsistencyGroupIdChirho::RootPathChirho {
                canonical_root_chirho: "/var/lib/cairn-fractional-cluster-chirho".to_string(),
            },
            local_raft_id_chirho: 1,
            voters_chirho: vec![(1, node_id_chirho)],
            learners_chirho: Vec::new(),
            peers_chirho: Vec::new(),
            durable_dir_chirho: durable_dir_chirho.clone(),
            sign_root_chirho: sign_root_chirho.clone(),
            tick_interval_chirho: Duration::from_micros(10_500),
            membership_control_chirho: None,
        });
        assert!(result_chirho.is_err());
        assert!(
            !durable_dir_chirho.exists(),
            "fractional authority timing must refuse before durable membership is seeded"
        );
        let _ = std::fs::remove_dir_all(sign_root_chirho);
    }

    #[test]
    fn fresh_and_reopened_nodes_derive_the_same_lease_from_the_same_tick_chirho() {
        let tick_interval_chirho = Duration::from_millis(50);
        let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: "/var/lib/cairn-reopen-lease-chirho".to_string(),
        };
        let sign_root_chirho = test_dir_chirho("reopen-sign");
        sign_message_chirho(&sign_root_chirho, b"provision reopen lease key")
            .expect("provision reopen lease key");
        let node_id_chirho =
            NodeIdChirho(pubkey_hex_chirho(&sign_root_chirho).expect("read reopen node identity"));
        let durable_dir_chirho = test_dir_chirho("reopen-durable");
        let config_chirho = || ClusterNodeConfigChirho {
            group_chirho: group_chirho.clone(),
            local_raft_id_chirho: 1,
            voters_chirho: vec![(1, node_id_chirho.clone())],
            learners_chirho: Vec::new(),
            peers_chirho: Vec::new(),
            durable_dir_chirho: durable_dir_chirho.clone(),
            sign_root_chirho: sign_root_chirho.clone(),
            tick_interval_chirho,
            membership_control_chirho: None,
        };
        let warm_chirho = |elector_chirho: &Arc<RaftWriterElectorChirho>,
                           clock_chirho: &Arc<FakeMonotonicClockChirho>| {
            elector_chirho
                .campaign_chirho()
                .expect("campaign fresh or reopened node");
            for _tick_chirho in 0..32 {
                clock_chirho.advance_millis_chirho(50);
                elector_chirho.tick_chirho();
                if elector_chirho
                    .leadership_chirho(&group_chirho)
                    .lease_valid_chirho
                {
                    return;
                }
            }
            panic!("fresh or reopened node did not warm");
        };

        let fresh_clock_chirho = FakeMonotonicClockChirho::new_chirho();
        let fresh_chirho = ClusterNodeChirho::build_with_existing_requirement_and_clock_chirho(
            config_chirho(),
            false,
            fresh_clock_chirho.clone(),
        )
        .expect("build fresh deterministic node");
        warm_chirho(fresh_chirho.elector_chirho(), &fresh_clock_chirho);
        assert_eq!(
            fresh_chirho
                .elector_chirho()
                .current_lease_remaining_millis_chirho(),
            Some(500)
        );
        drop(fresh_chirho);

        let reopened_clock_chirho = FakeMonotonicClockChirho::new_chirho();
        let reopened_chirho = ClusterNodeChirho::build_with_existing_requirement_and_clock_chirho(
            config_chirho(),
            true,
            reopened_clock_chirho.clone(),
        )
        .expect("reopen deterministic node");
        warm_chirho(reopened_chirho.elector_chirho(), &reopened_clock_chirho);
        assert_eq!(
            reopened_chirho
                .elector_chirho()
                .current_lease_remaining_millis_chirho(),
            Some(500),
            "fresh and existing-only paths must derive the same lease from the same driver tick"
        );

        drop(reopened_chirho);
        let _ = std::fs::remove_dir_all(sign_root_chirho);
        let _ = std::fs::remove_dir_all(durable_dir_chirho);
    }

    #[test]
    fn leader_http_stays_up_while_wire_and_local_authority_expire_chirho() {
        let tick_interval_chirho = Duration::from_millis(10);
        let clock_chirho = FakeMonotonicClockChirho::new_chirho();
        let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: "/var/lib/cairn-http-expiry-chirho".to_string(),
        };
        let sign_root_chirho = test_dir_chirho("http-expiry-sign");
        sign_message_chirho(&sign_root_chirho, b"provision HTTP expiry key")
            .expect("provision HTTP expiry key");
        let node_id_chirho = NodeIdChirho(
            pubkey_hex_chirho(&sign_root_chirho).expect("read HTTP expiry node identity"),
        );
        let durable_dir_chirho = test_dir_chirho("http-expiry-durable");
        let node_chirho = ClusterNodeChirho::build_with_existing_requirement_and_clock_chirho(
            ClusterNodeConfigChirho {
                group_chirho: group_chirho.clone(),
                local_raft_id_chirho: 1,
                voters_chirho: vec![(1, node_id_chirho)],
                learners_chirho: Vec::new(),
                peers_chirho: Vec::new(),
                durable_dir_chirho: durable_dir_chirho.clone(),
                sign_root_chirho: sign_root_chirho.clone(),
                tick_interval_chirho,
                membership_control_chirho: None,
            },
            false,
            clock_chirho.clone(),
        )
        .expect("build HTTP expiry node with deterministic clock");
        let elector_chirho = node_chirho.elector_chirho().clone();
        elector_chirho
            .campaign_chirho()
            .expect("campaign HTTP expiry node");
        for _tick_chirho in 0..32 {
            clock_chirho.advance_millis_chirho(10);
            elector_chirho.tick_chirho();
            if elector_chirho
                .leadership_chirho(&group_chirho)
                .lease_valid_chirho
            {
                break;
            }
        }
        assert!(
            elector_chirho
                .leadership_chirho(&group_chirho)
                .lease_valid_chirho,
            "precondition: deterministic node warmed before its ticker paused"
        );

        let listener_chirho =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind HTTP expiry listener");
        let base_url_chirho = format!(
            "http://{}",
            listener_chirho
                .local_addr()
                .expect("read HTTP expiry listener address")
        );
        let stop_chirho = Arc::new(AtomicBool::new(false));
        let serve_stop_chirho = stop_chirho.clone();
        let router_chirho = raft_fire_router_chirho(node_chirho.driver_chirho.clone());
        let serve_chirho = std::thread::spawn(move || {
            serve_router_blocking_with_shutdown_chirho(
                listener_chirho,
                router_chirho,
                serve_stop_chirho,
            )
            .expect("serve leader HTTP without the ticker loop");
        });
        let agent_chirho = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(1))
            .build();
        let before_chirho = discover_leader_chirho(&agent_chirho, &base_url_chirho)
            .expect("leader HTTP responds before expiry");
        assert_eq!(before_chirho.lease_remaining_millis_chirho, Some(100));

        clock_chirho.advance_millis_chirho(100);
        let after_chirho = discover_leader_chirho(&agent_chirho, &base_url_chirho)
            .expect("the same leader HTTP endpoint remains responsive after ticker expiry");
        assert!(
            after_chirho.is_local_leader_chirho
                && after_chirho.lease_remaining_millis_chirho.is_none(),
            "the role remains observable but dead-ticker authority expires on a still-serving node"
        );
        assert!(matches!(
            elector_chirho
                .local_append_authority_handle_chirho()
                .try_acquire_chirho(),
            Err(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho)
        ));

        stop_chirho.store(true, Ordering::Relaxed);
        serve_chirho
            .join()
            .expect("join still-serving HTTP expiry thread");
        let _ = std::fs::remove_dir_all(sign_root_chirho);
        let _ = std::fs::remove_dir_all(durable_dir_chirho);
    }
}
