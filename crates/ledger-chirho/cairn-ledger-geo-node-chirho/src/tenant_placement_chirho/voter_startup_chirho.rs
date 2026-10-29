// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! One-shot geo voter startup selection and test-kind resident-owner recomposition.
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/cf8-canary-window-loss-sequence-chirho.md`.

use super::promotion_exit_chirho::{
    startup_deadline_chirho, PromotionExitTimingChirho, RemoteOwnerStabilityChirho,
};
use super::VerifiedGeoVoterStartupPolicyChirho;
use anyhow::{bail, Result};
use cairn_writer_elector_chirho::elector_port_chirho::{LeadershipChirho, NodeIdChirho};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_http_chirho::cluster_node_chirho::{
    ClusterNodeConfigChirho, LocalLeadershipTransferPortChirho,
    LocalLeadershipTransferRequestOutcomeChirho,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const VOTER_STARTUP_TIMEOUT_CHIRHO: Duration = Duration::from_secs(30);
const LOCAL_TRANSFER_LEADER_UNAVAILABLE_REFUSAL_CHIRHO: &str =
    "LocalLeadershipTransferLeaderUnavailableRefusedChirho";
const LOCAL_TRANSFER_LOCAL_OWNER_NOT_WARM_REFUSAL_CHIRHO: &str =
    "LocalLeadershipTransferLocalOwnerNotWarmRefusedChirho";
const LOCAL_TRANSFER_ACCEPTANCE_TIMEOUT_REFUSAL_CHIRHO: &str =
    "LocalLeadershipTransferAcceptanceTimeoutRefusedChirho";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GeoVoterStartupRoleChirho {
    LocalWarmOwnerChirho,
    NonResidentChirho(GeoNonResidentVoterRoleChirho),
}

impl GeoVoterStartupRoleChirho {
    /// The role as the serving log line names it.
    pub(super) fn label_chirho(self) -> &'static str {
        match self {
            Self::LocalWarmOwnerChirho => "local-owner",
            Self::NonResidentChirho(GeoNonResidentVoterRoleChirho::RemoteOwnerChirho) => {
                "relay-only-follower"
            }
            Self::NonResidentChirho(GeoNonResidentVoterRoleChirho::RetiringTransportOnlyChirho) => {
                "retiring-transport-only"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GeoNonResidentVoterRoleChirho {
    RemoteOwnerChirho,
    /// Still participates in the old quorum but cannot compose a resident while outside placement.
    RetiringTransportOnlyChirho,
}

/// How the one-shot voter startup role is selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeoVoterStartupOwnershipChirho {
    /// Shipping behavior: accept the first known local or remote elected owner.
    FirstKnownOwnerChirho,
    /// Test-kind recomposition: request authenticated transfer to this voter and wait for local ownership.
    RecomposeLocalOwnerChirho,
}

pub(super) fn configured_local_cluster_node_chirho(
    cluster_chirho: &ClusterNodeConfigChirho,
) -> Result<NodeIdChirho> {
    let local_nodes_chirho = cluster_chirho
        .voters_chirho
        .iter()
        .chain(&cluster_chirho.learners_chirho)
        .filter(|(raft_id_chirho, _node_chirho)| {
            *raft_id_chirho == cluster_chirho.local_raft_id_chirho
        })
        .map(|(_raft_id_chirho, node_chirho)| node_chirho.clone())
        .collect::<Vec<_>>();
    match local_nodes_chirho.as_slice() {
        [local_node_chirho] => Ok(local_node_chirho.clone()),
        _ => bail!("geo node must map its local raft id to exactly one node identity"),
    }
}

/// Wait, bounded, for the one startup role.
///
/// A local warm owner settles at once. A remote owner settles only after the same owner, at the
/// same term, has stayed in place for the stability window derived from the tick. A relay-only
/// winner exits within that window (`promotion_exit_chirho`), so a starting voter never serves
/// relay-only under a winner that is about to leave, and stays inside its own window to win the
/// next election.
pub(super) fn wait_for_known_warm_owner_chirho(
    elector_chirho: &RaftWriterElectorChirho,
    local_node_chirho: &NodeIdChirho,
    placement_startup_chirho: &VerifiedGeoVoterStartupPolicyChirho,
    stop_chirho: &AtomicBool,
    tick_interval_chirho: Duration,
    startup_ownership_chirho: GeoVoterStartupOwnershipChirho,
    local_leadership_transfer_port_chirho: Option<&LocalLeadershipTransferPortChirho>,
) -> Result<GeoVoterStartupRoleChirho> {
    let mut transfer_requested_term_chirho = None;
    let mut leader_observed_chirho = false;
    let remote_owner_stability_chirho =
        PromotionExitTimingChirho::from_driver_tick_chirho(tick_interval_chirho)?
            .remote_owner_stability_chirho;
    let mut settle_chirho = StartupSettleChirho::new_chirho(
        Instant::now() + VOTER_STARTUP_TIMEOUT_CHIRHO,
        remote_owner_stability_chirho,
    );
    loop {
        let leadership_chirho = elector_chirho.current_leadership_chirho();
        leader_observed_chirho |= leadership_chirho.leader_id_chirho.is_some();
        match settle_chirho.step_chirho(
            Instant::now(),
            &leadership_chirho,
            local_node_chirho,
            startup_ownership_chirho,
        ) {
            StartupStepChirho::SettledChirho(role_chirho) => {
                return Ok(placement_startup_chirho.select_voter_startup_role_chirho(role_chirho));
            }
            StartupStepChirho::ExpiredChirho => break,
            StartupStepChirho::WaitChirho => {}
        }
        if startup_ownership_chirho == GeoVoterStartupOwnershipChirho::RecomposeLocalOwnerChirho
            && leadership_chirho
                .leader_id_chirho
                .as_ref()
                .is_some_and(|leader_chirho| leader_chirho != local_node_chirho)
            && transfer_requested_term_chirho != Some(leadership_chirho.term_chirho)
        {
            let transfer_outcome_chirho = local_leadership_transfer_port_chirho
                .ok_or_else(|| anyhow::anyhow!("LocalLeadershipTransferPortMissingRefusedChirho"))?
                .request_chirho()?;
            if transfer_outcome_chirho
                == LocalLeadershipTransferRequestOutcomeChirho::DispatchedChirho
            {
                transfer_requested_term_chirho = Some(leadership_chirho.term_chirho);
            }
        }
        if stop_chirho.load(Ordering::Acquire) {
            bail!("geo election transport stopped before a warm owner was known");
        }
        std::thread::sleep(tick_interval_chirho.min(Duration::from_millis(100)));
    }
    if startup_ownership_chirho == GeoVoterStartupOwnershipChirho::RecomposeLocalOwnerChirho {
        bail!(
            "{}",
            local_transfer_timeout_refusal_chirho(
                leader_observed_chirho,
                transfer_requested_term_chirho.is_some(),
            )
        );
    }
    bail!("no warm elected owner became known within the bounded startup interval")
}

/// What one startup poll decided.
#[allow(
    clippy::enum_variant_names,
    reason = "the Chirho suffix convention names every variant, as across the workspace"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StartupStepChirho {
    SettledChirho(GeoVoterStartupRoleChirho),
    WaitChirho,
    ExpiredChirho,
}

/// The bounded startup decision, one poll at a time, kept pure so its ORDER is testable.
///
/// Each poll observes before it checks the deadline. So the poll at which a remote owner's
/// stability window completes settles instead of expiring; checking the deadline first would let
/// an extended deadline expire on exactly that poll (Agy R-C1-2c).
#[derive(Debug)]
pub(super) struct StartupSettleChirho {
    deadline_chirho: Instant,
    window_chirho: Duration,
    settling_chirho: RemoteOwnerStabilityChirho,
}

impl StartupSettleChirho {
    pub(super) fn new_chirho(deadline_chirho: Instant, window_chirho: Duration) -> Self {
        Self {
            deadline_chirho,
            window_chirho,
            settling_chirho: RemoteOwnerStabilityChirho::default(),
        }
    }

    pub(super) fn step_chirho(
        &mut self,
        now_chirho: Instant,
        leadership_chirho: &LeadershipChirho,
        local_node_chirho: &NodeIdChirho,
        startup_ownership_chirho: GeoVoterStartupOwnershipChirho,
    ) -> StartupStepChirho {
        match selectable_geo_voter_startup_role_chirho(
            leadership_chirho,
            local_node_chirho,
            startup_ownership_chirho,
        ) {
            Some(GeoVoterStartupRoleChirho::LocalWarmOwnerChirho) => {
                return StartupStepChirho::SettledChirho(
                    GeoVoterStartupRoleChirho::LocalWarmOwnerChirho,
                );
            }
            Some(remote_role_chirho) => {
                let settled_chirho =
                    leadership_chirho
                        .leader_id_chirho
                        .as_ref()
                        .is_some_and(|owner_chirho| {
                            self.settling_chirho.observe_chirho(
                                now_chirho,
                                owner_chirho,
                                leadership_chirho.term_chirho,
                                self.window_chirho,
                            )
                        });
                if settled_chirho {
                    return StartupStepChirho::SettledChirho(remote_role_chirho);
                }
            }
            None => self.settling_chirho.reset_chirho(),
        }
        let deadline_chirho = startup_deadline_chirho(
            self.deadline_chirho,
            self.settling_chirho.settles_at_chirho(self.window_chirho),
            self.window_chirho,
        );
        if now_chirho >= deadline_chirho {
            StartupStepChirho::ExpiredChirho
        } else {
            StartupStepChirho::WaitChirho
        }
    }
}

fn local_transfer_timeout_refusal_chirho(
    leader_observed_chirho: bool,
    transfer_requested_chirho: bool,
) -> &'static str {
    if transfer_requested_chirho {
        LOCAL_TRANSFER_ACCEPTANCE_TIMEOUT_REFUSAL_CHIRHO
    } else if leader_observed_chirho {
        LOCAL_TRANSFER_LOCAL_OWNER_NOT_WARM_REFUSAL_CHIRHO
    } else {
        LOCAL_TRANSFER_LEADER_UNAVAILABLE_REFUSAL_CHIRHO
    }
}

fn selectable_geo_voter_startup_role_chirho(
    leadership_chirho: &LeadershipChirho,
    local_node_chirho: &NodeIdChirho,
    startup_ownership_chirho: GeoVoterStartupOwnershipChirho,
) -> Option<GeoVoterStartupRoleChirho> {
    // Local leader plus the configured lease is a startup ordering/liveness gate, not standalone
    // write authority; the resident append path retains the persisted authority fences.
    let role_chirho = classify_geo_voter_startup_role_chirho(leadership_chirho, local_node_chirho)?;
    if startup_ownership_chirho == GeoVoterStartupOwnershipChirho::RecomposeLocalOwnerChirho
        && matches!(
            role_chirho,
            GeoVoterStartupRoleChirho::NonResidentChirho(
                GeoNonResidentVoterRoleChirho::RemoteOwnerChirho
            )
        )
    {
        return None;
    }
    Some(role_chirho)
}

/// Warm local leadership: this node leads, by its own elector, with its liveness lease valid. It is
/// the startup gate for opening the resident actor and the promotion watcher's trigger, never write
/// authority on its own.
pub(super) fn is_warm_local_leader_chirho(
    leadership_chirho: &LeadershipChirho,
    local_node_chirho: &NodeIdChirho,
) -> bool {
    leadership_chirho.is_leader_chirho
        && leadership_chirho.lease_valid_chirho
        && leadership_chirho.leader_id_chirho.as_ref() == Some(local_node_chirho)
}

fn classify_geo_voter_startup_role_chirho(
    leadership_chirho: &LeadershipChirho,
    local_node_chirho: &NodeIdChirho,
) -> Option<GeoVoterStartupRoleChirho> {
    let owner_chirho = leadership_chirho.leader_id_chirho.as_ref()?;
    if owner_chirho == local_node_chirho {
        return is_warm_local_leader_chirho(leadership_chirho, local_node_chirho)
            .then_some(GeoVoterStartupRoleChirho::LocalWarmOwnerChirho);
    }
    Some(GeoVoterStartupRoleChirho::NonResidentChirho(
        GeoNonResidentVoterRoleChirho::RemoteOwnerChirho,
    ))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn voter_startup_role_requires_warm_local_authority_but_accepts_a_remote_owner_chirho() {
        let local_node_chirho = NodeIdChirho("local-chirho".to_owned());
        let cold_local_chirho = LeadershipChirho {
            is_leader_chirho: true,
            leader_id_chirho: Some(local_node_chirho.clone()),
            term_chirho: 4,
            lease_valid_chirho: false,
        };
        assert_eq!(
            classify_geo_voter_startup_role_chirho(&cold_local_chirho, &local_node_chirho),
            None
        );

        let warm_local_chirho = LeadershipChirho {
            lease_valid_chirho: true,
            ..cold_local_chirho
        };
        assert_eq!(
            classify_geo_voter_startup_role_chirho(&warm_local_chirho, &local_node_chirho),
            Some(GeoVoterStartupRoleChirho::LocalWarmOwnerChirho)
        );

        let remote_owner_chirho = LeadershipChirho {
            is_leader_chirho: false,
            leader_id_chirho: Some(NodeIdChirho("remote-chirho".to_owned())),
            term_chirho: 4,
            lease_valid_chirho: false,
        };
        assert_eq!(
            classify_geo_voter_startup_role_chirho(&remote_owner_chirho, &local_node_chirho),
            Some(GeoVoterStartupRoleChirho::NonResidentChirho(
                GeoNonResidentVoterRoleChirho::RemoteOwnerChirho,
            ))
        );
        assert_eq!(
            selectable_geo_voter_startup_role_chirho(
                &remote_owner_chirho,
                &local_node_chirho,
                GeoVoterStartupOwnershipChirho::FirstKnownOwnerChirho,
            ),
            Some(GeoVoterStartupRoleChirho::NonResidentChirho(
                GeoNonResidentVoterRoleChirho::RemoteOwnerChirho,
            )),
            "shipping startup keeps accepting the first verified remote owner"
        );
        assert_eq!(
            selectable_geo_voter_startup_role_chirho(
                &remote_owner_chirho,
                &local_node_chirho,
                GeoVoterStartupOwnershipChirho::RecomposeLocalOwnerChirho,
            ),
            None,
            "recomposition must not latch non-resident while a remote owner is visible"
        );
        assert_eq!(
            selectable_geo_voter_startup_role_chirho(
                &warm_local_chirho,
                &local_node_chirho,
                GeoVoterStartupOwnershipChirho::RecomposeLocalOwnerChirho,
            ),
            Some(GeoVoterStartupRoleChirho::LocalWarmOwnerChirho),
            "recomposition may open the resident only after local leadership and the liveness gate"
        );
        assert_eq!(
            local_transfer_timeout_refusal_chirho(false, false),
            LOCAL_TRANSFER_LEADER_UNAVAILABLE_REFUSAL_CHIRHO,
            "an interval with no observed leader must not imply a sent transfer"
        );
        assert_eq!(
            local_transfer_timeout_refusal_chirho(true, false),
            LOCAL_TRANSFER_LOCAL_OWNER_NOT_WARM_REFUSAL_CHIRHO,
            "a cold local owner must not imply a sent transfer"
        );
        assert_eq!(
            local_transfer_timeout_refusal_chirho(true, true),
            LOCAL_TRANSFER_ACCEPTANCE_TIMEOUT_REFUSAL_CHIRHO,
            "only an actual transfer request may end in an acceptance timeout"
        );
    }
}
