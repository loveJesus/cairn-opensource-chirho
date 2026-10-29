// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A1.5.0 membership drive/observe surface: the explicit HTTP control endpoints that let an operator
//! reload the signed roster and drive one convergence / re-home step on a RUNNING fleet node, and observe
//! its live membership — the primitives the A1.5 shadow-fleet drills (D1–D5) assert over pure HTTP.
//!
//! It wires the already-proven engine (A1.1 ConfChange apply, A1.2 learner/promote, A1.3 convergence,
//! A1.4 re-home) to sockets; it adds NO new consensus. Election-only: it mints nothing, moves no head, and
//! NEVER writes the roster (the roster drives membership one-way; P3 no-write holds).
//!
//! ## Security posture — operator-assisted authority-adjacent control
//!
//! `/converge-chirho` and `/re-home-chirho` MUTATE the running group's voter set, so they must never be
//! openly callable: both require the configured operator token (constant-time compared), and a node with
//! NO token configured serves them FAIL-CLOSED (403). `/membership-chirho` is read-only observability
//! (bounded, non-identifying ids/counters, like `/leader-chirho`) and is open.
//!
//! Tenant-placement targets make this surface authority-adjacent: whoever can drive convergence can
//! influence which already-authorized node holds the write lease. The endpoints remain confined to the
//! signed WireGuard mesh and a configured operator token; placement signatures authorize the target but
//! do NOT upgrade request custody or add an audit record. This is the operator-assisted-alpha actuator,
//! not a public or self-service control plane. Final operation requires a rotated scoped credential (or
//! stronger local control transport) plus durable request audit before widening who can invoke it.

use crate::driver_chirho::RaftDriverChirho;
use anyhow::{Context, Result};
use axum::{
    extract::{DefaultBodyLimit, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use cairn_roster_config_chirho::{
    derive_elector_config_chirho, derive_preferred_leader_chirho,
    derive_tenant_placement_elector_config_chirho, ElectorMemberChirho,
};
use cairn_roster_convergence_chirho::{
    apply_one_convergence_step_chirho, converge_chirho, re_home_step_chirho, ConvergenceStepChirho,
    ReHomeStepChirho,
};
use cairn_tenant_placement_authority_chirho::load_and_verify_tenant_placement_record_chirho;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// POST here (operator-token-gated) to reload+verify the roster and run ONE convergence step.
pub const CONVERGE_PATH_CHIRHO: &str = "/converge-chirho";
/// POST here (operator-token-gated) to reload+verify the roster and run one re-home step.
pub const RE_HOME_PATH_CHIRHO: &str = "/re-home-chirho";
/// GET here (open, read-only) to observe the live membership for drill assertions.
pub const MEMBERSHIP_OBSERVE_PATH_CHIRHO: &str = "/membership-chirho";
/// The header carrying the operator token on the two mutating endpoints (R1).
pub const OPERATOR_TOKEN_HEADER_CHIRHO: &str = "x-cairn-operator-token-chirho";
/// The control endpoints take no request body (params ride the query string); a small cap is defensive.
const MAX_CONTROL_BODY_BYTES_CHIRHO: usize = 64 * 1024;
const MAX_ROSTER_AUTHORITY_FILE_BYTES_CHIRHO: u64 = 4 * 1024 * 1024;
const MAX_ROSTER_AUTHORITY_HEAD_BYTES_CHIRHO: u64 = 64 * 1024;
const MAX_ROSTER_AUTHORITY_LINES_CHIRHO: usize = 4096;

/// Public read coordinates for one signed roster authority.
///
/// Paths and a verification key grant no mutation. Tokens and convergence controls remain in
/// [`MembershipControlConfigChirho`], so a held observer can verify its roster binding without
/// receiving a drive capability merely because the fields shared one configuration block.
#[derive(Clone)]
pub struct RosterAuthorityConfigChirho {
    /// The signed membership-roster JSONL (one signed record per line).
    pub roster_path_chirho: PathBuf,
    /// The roster head length-witness (signed count + prefix digest over ALL roster lines).
    pub roster_head_path_chirho: PathBuf,
    /// The operator public key (hex) the roster records + head verify against (R5).
    pub operator_pubkey_hex_chirho: String,
    /// The WireGuard interface whose live peers must equal this group's signed roster.
    /// Defaults to `RELAY_WIREGUARD_INTERFACE_CHIRHO` when the config omits it.
    pub relay_interface_chirho: String,
}

impl RosterAuthorityConfigChirho {
    /// Read the two public signed-roster inputs through one bounded, non-symlink adapter.
    ///
    /// This does not verify either artifact. Consumers still pass the returned bytes to the roster
    /// verifier with `operator_pubkey_hex_chirho` before deriving any membership or peer evidence.
    pub fn load_bounded_inputs_chirho(&self) -> Result<(Vec<Vec<u8>>, Vec<u8>)> {
        let roster_raw_chirho = read_bounded_roster_authority_file_chirho(
            &self.roster_path_chirho,
            MAX_ROSTER_AUTHORITY_FILE_BYTES_CHIRHO,
            "roster",
        )?;
        let lines_chirho = roster_raw_chirho
            .split(|byte_chirho| *byte_chirho == b'\n')
            .filter(|line_chirho| {
                !line_chirho
                    .iter()
                    .all(|byte_chirho| byte_chirho.is_ascii_whitespace())
            })
            .map(|line_chirho| line_chirho.to_vec())
            .collect::<Vec<_>>();
        if lines_chirho.len() > MAX_ROSTER_AUTHORITY_LINES_CHIRHO {
            anyhow::bail!("RosterAuthorityLinePopulationRefusedChirho");
        }
        let head_chirho = read_bounded_roster_authority_file_chirho(
            &self.roster_head_path_chirho,
            MAX_ROSTER_AUTHORITY_HEAD_BYTES_CHIRHO,
            "roster head",
        )?;
        Ok((lines_chirho, head_chirho))
    }
}

fn read_bounded_roster_authority_file_chirho(
    path_chirho: &Path,
    max_bytes_chirho: u64,
    subject_chirho: &str,
) -> Result<Vec<u8>> {
    let metadata_chirho = std::fs::symlink_metadata(path_chirho)
        .with_context(|| format!("inspect {subject_chirho} {}", path_chirho.display()))?;
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_file() {
        anyhow::bail!("RosterAuthorityStoreEntryTypeRefusedChirho");
    }
    if metadata_chirho.len() > max_bytes_chirho {
        anyhow::bail!("RosterAuthorityStoreSizeRefusedChirho");
    }
    let file_chirho = std::fs::File::open(path_chirho)
        .with_context(|| format!("open {subject_chirho} {}", path_chirho.display()))?;
    let mut bytes_chirho = Vec::new();
    file_chirho
        .take(max_bytes_chirho + 1)
        .read_to_end(&mut bytes_chirho)
        .with_context(|| format!("read {subject_chirho} {}", path_chirho.display()))?;
    if bytes_chirho.len() as u64 > max_bytes_chirho {
        anyhow::bail!("RosterAuthorityStoreSizeRefusedChirho");
    }
    Ok(bytes_chirho)
}

/// Everything the membership-control surface needs to drive the elector.
#[derive(Clone)]
pub struct MembershipControlConfigChirho {
    /// Read-only signed-roster coordinates shared with roles that receive no convergence capability.
    pub roster_authority_chirho: RosterAuthorityConfigChirho,
    /// This node's own node id (pubkey hex) — the roster local-present + local-coords checks.
    pub local_node_pubkey_hex_chirho: String,
    /// This group's canonical id string (`ConsistencyGroupIdChirho::canonical_id_chirho`) for re-home.
    pub group_id_chirho: String,
    /// The independently verified authority that selects this group's target membership.
    pub target_authority_chirho: MembershipTargetAuthorityChirho,
    /// The operator token the two MUTATING endpoints require (R1). `None` ⇒ the mutating endpoints FAIL
    /// CLOSED (403): the drive surface is never openly callable.
    pub operator_token_chirho: Option<String>,
    /// Fixpoint drive (R2, `?to_fixpoint_chirho=true` only): sleep between steps + step bound. Small and
    /// bounded — the node's background ticker also drives commit, so this only bounds the convergence loop.
    pub fixpoint_step_sleep_chirho: Duration,
    pub fixpoint_max_steps_chirho: usize,
}

/// Which signed authority selects the membership-control target.
///
/// Roster-wide is retained explicitly for non-tenant shadow and synthetic drills. Production tenant
/// composition must select `TenantPlacementChirho`; the geo-node preflight owns that fail-closed rule.
#[derive(Clone)]
pub enum MembershipTargetAuthorityChirho {
    RosterWideChirho,
    TenantPlacementChirho(TenantPlacementAuthorityConfigChirho),
}

/// Shared read-only coordinates for one tenant placement authority.
///
/// This value lives at the cluster-file top level so both serving voters and the held observer can
/// verify their role from the same record. Holding it grants no convergence operation.
#[derive(Clone)]
pub struct TenantPlacementAuthorityConfigChirho {
    pub placement_record_path_chirho: PathBuf,
    pub placement_pubkey_hex_chirho: String,
    /// Trusted Geo PlanAuthority pin used here for key separation, not plan-artifact verification.
    pub geo_plan_pubkey_hex_chirho: String,
}

struct VerifiedMembershipTargetChirho {
    members_chirho: Vec<ElectorMemberChirho>,
    preferred_raft_id_chirho: Option<u64>,
}

/// The membership-control state served behind an `Arc`: the driver (its elector + peer pump) plus the
/// config and the R4 control mutex.
pub struct MembershipControlChirho {
    driver_chirho: Arc<RaftDriverChirho>,
    config_chirho: MembershipControlConfigChirho,
    /// R4: serialize the two MUTATING control operations so two converge/re-home steps can never
    /// interleave by construction (A1.1's one-change-at-a-time rule stays the backstop, not the lock).
    control_lock_chirho: Mutex<()>,
}

/// The live membership snapshot a drill asserts on (R6): read-only, bounded, non-identifying.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipObservationChirho {
    pub voters_chirho: Vec<u64>,
    pub learners_chirho: Vec<u64>,
    /// The elected leader's node id (ed25519 pubkey hex), or `None` if no leader is known right now.
    pub leader_node_id_chirho: Option<String>,
    pub is_local_leader_chirho: bool,
    pub local_raft_id_chirho: u64,
    pub term_chirho: u64,
    /// Remaining lease in milliseconds, or `None` for expired. A duration rather than a boolean, for
    /// the reason given on `LeaderInfoChirho`: a serialised validity flag is stale the moment it is
    /// sent, and a serialised instant is meaningless in the receiver's clock domain.
    pub lease_remaining_millis_chirho: Option<u64>,
    /// The durable last-applied conf-change index — proves a committed membership change persisted (R6).
    pub applied_conf_index_chirho: u64,
}

/// What a `/converge-chirho` call did — an explicit NotLeader (R3 fail-put) OR the executed step(s).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConvergeOutcomeChirho {
    /// This node is not the leader, so it proposed NO membership change — no side effect (R3). Carries the
    /// known leader so the drill can retarget.
    NotLeaderChirho {
        leader_node_id_chirho: Option<String>,
    },
    /// The convergence step(s) actually executed — one by default, or the sequence to fixpoint (R2). The
    /// evidence body IS this, so drill artifacts come from the response, not log scraping.
    SteppedChirho {
        steps_chirho: Vec<ConvergenceStepChirho>,
        to_fixpoint_chirho: bool,
    },
}

/// The `/converge-chirho` response: what happened plus the membership after it (one round-trip of evidence).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConvergeResponseChirho {
    pub outcome_chirho: ConvergeOutcomeChirho,
    pub observation_chirho: MembershipObservationChirho,
}

/// The `/re-home-chirho` response: the (always-surfaced) re-home step plus the membership after it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReHomeResponseChirho {
    pub step_chirho: ReHomeStepChirho,
    pub observation_chirho: MembershipObservationChirho,
}

/// `/converge-chirho` query params: single step by default, to-fixpoint only when explicitly asked (R2).
#[derive(Debug, Deserialize)]
struct ConvergeParamsChirho {
    #[serde(default)]
    to_fixpoint_chirho: Option<bool>,
}

impl MembershipControlChirho {
    /// Build the control state over a node's driver.
    pub fn new_chirho(
        driver_chirho: Arc<RaftDriverChirho>,
        config_chirho: MembershipControlConfigChirho,
    ) -> Self {
        Self {
            driver_chirho,
            config_chirho,
            control_lock_chirho: Mutex::new(()),
        }
    }

    /// R1: the mutating endpoints require the configured operator token, constant-time compared. A node
    /// with no token configured FAILS CLOSED — the drive surface is not openly callable. Returns `None`
    /// when the request is authorized, or `Some(rejection)` for the handler to return as-is (an
    /// `Option<Response>` rather than a `Result<(), Response>` so the large axum `Response` is never an
    /// `Err` variant that bloats every caller's `Result`).
    fn check_operator_token_chirho(&self, headers_chirho: &HeaderMap) -> Option<Response> {
        let Some(expected_chirho) = &self.config_chirho.operator_token_chirho else {
            return Some(
                (
                    StatusCode::FORBIDDEN,
                    "membership control surface not enabled (no operator token configured)",
                )
                    .into_response(),
            );
        };
        let provided_chirho = headers_chirho
            .get(OPERATOR_TOKEN_HEADER_CHIRHO)
            .and_then(|value_chirho| value_chirho.to_str().ok())
            .unwrap_or("");
        if constant_time_eq_chirho(provided_chirho.as_bytes(), expected_chirho.as_bytes()) {
            None
        } else {
            Some((StatusCode::FORBIDDEN, "invalid operator token").into_response())
        }
    }

    /// Read the signed roster lines + head bytes from disk (R5 feeds these to the verifying derivation).
    fn load_roster_bytes_chirho(&self) -> Result<(Vec<Vec<u8>>, Vec<u8>)> {
        self.config_chirho
            .roster_authority_chirho
            .load_bounded_inputs_chirho()
    }

    /// Resolve one complete target before any membership or leadership mutation.
    fn derive_membership_target_chirho(
        &self,
        lines_chirho: &[Vec<u8>],
        head_chirho: &[u8],
    ) -> Result<VerifiedMembershipTargetChirho> {
        match &self.config_chirho.target_authority_chirho {
            MembershipTargetAuthorityChirho::RosterWideChirho => {
                let (derived_chirho, _evidence_chirho) = derive_elector_config_chirho(
                    lines_chirho,
                    head_chirho,
                    &self
                        .config_chirho
                        .roster_authority_chirho
                        .operator_pubkey_hex_chirho,
                    &self.config_chirho.local_node_pubkey_hex_chirho,
                )?;
                let preferred_raft_id_chirho = derive_preferred_leader_chirho(
                    lines_chirho,
                    head_chirho,
                    &self
                        .config_chirho
                        .roster_authority_chirho
                        .operator_pubkey_hex_chirho,
                    &self.config_chirho.local_node_pubkey_hex_chirho,
                    &self.config_chirho.group_id_chirho,
                )?;
                Ok(VerifiedMembershipTargetChirho {
                    members_chirho: derived_chirho.members_chirho,
                    preferred_raft_id_chirho,
                })
            }
            MembershipTargetAuthorityChirho::TenantPlacementChirho(placement_config_chirho) => {
                let placement_chirho = load_and_verify_tenant_placement_record_chirho(
                    &placement_config_chirho.placement_record_path_chirho,
                    &placement_config_chirho.placement_pubkey_hex_chirho,
                    &self
                        .config_chirho
                        .roster_authority_chirho
                        .operator_pubkey_hex_chirho,
                    &placement_config_chirho.geo_plan_pubkey_hex_chirho,
                )
                .context("TenantPlacementMembershipAuthorityRefusedChirho")?;
                if placement_chirho.intent_chirho().consistency_group_id_chirho
                    != self.config_chirho.group_id_chirho
                {
                    anyhow::bail!("TenantPlacementMembershipGroupRefusedChirho");
                }
                let (derived_chirho, evidence_chirho) =
                    derive_tenant_placement_elector_config_chirho(
                        lines_chirho,
                        head_chirho,
                        &self
                            .config_chirho
                            .roster_authority_chirho
                            .operator_pubkey_hex_chirho,
                        &self.config_chirho.local_node_pubkey_hex_chirho,
                        &placement_chirho,
                    )?;
                Ok(VerifiedMembershipTargetChirho {
                    members_chirho: derived_chirho.members_chirho,
                    preferred_raft_id_chirho: Some(evidence_chirho.preferred_raft_id_chirho),
                })
            }
        }
    }

    /// R6: the live membership snapshot — read-only, never used for a control decision.
    fn observe_chirho(&self) -> Result<MembershipObservationChirho> {
        let elector_chirho = self.driver_chirho.elector_chirho();
        let (voters_chirho, learners_chirho) = elector_chirho.membership_snapshot_chirho()?;
        let leadership_chirho = elector_chirho.current_leadership_chirho();
        let applied_conf_index_chirho = elector_chirho.applied_conf_index_chirho()?;
        Ok(MembershipObservationChirho {
            voters_chirho,
            learners_chirho,
            leader_node_id_chirho: leadership_chirho
                .leader_id_chirho
                .map(|node_chirho| node_chirho.0),
            is_local_leader_chirho: leadership_chirho.is_leader_chirho,
            local_raft_id_chirho: elector_chirho.local_raft_id_chirho(),
            term_chirho: leadership_chirho.term_chirho,
            lease_remaining_millis_chirho: elector_chirho.current_lease_remaining_millis_chirho(),
            applied_conf_index_chirho,
        })
    }

    /// The synchronous body of `/converge-chirho` (run on a blocking task). R4 mutex → R3 leader gate →
    /// R5 verified-roster reload → R2 one step (or fixpoint). A verification failure returns the error
    /// BEFORE any elector mutation, so a bad roster changes nothing.
    fn run_converge_chirho(&self, to_fixpoint_chirho: bool) -> Result<ConvergeResponseChirho> {
        // R4: only one converge/re-home in flight at a time.
        let _control_guard_chirho = self
            .control_lock_chirho
            .lock()
            .map_err(|_| anyhow::anyhow!("membership control lock poisoned"))?;

        // R3 fail-put: only the leader can propose a ConfChange; a follower returns NotLeader and — crucially
        // — makes NO change (apply_one does a local reconcile-down before proposing, so we must gate BEFORE
        // calling it, not let it error mid-mutation).
        //
        // TOCTOU (audit 3824 LOW-1): the background ticker can drop leadership in the window between this
        // check and apply_one below. If it does, apply_one applies its LOCAL auth-set changes before the raft
        // propose rejects on the now-follower — but those changes are only ever early application of the
        // OPERATOR-SIGNED roster's intent (reconcile-down drops solely peers already gone from this node's
        // ConfState; an auth-include of a to-be-added peer is inert until raft commits it as a member), never
        // arbitrary mutation, and the group re-converges under the new leader on the next drive. Bounded and
        // safe by construction; the A1.5.2 D3 drill asserts a mid-window leadership loss still converges.
        let leadership_chirho = self
            .driver_chirho
            .elector_chirho()
            .current_leadership_chirho();
        if !leadership_chirho.is_leader_chirho {
            return Ok(ConvergeResponseChirho {
                outcome_chirho: ConvergeOutcomeChirho::NotLeaderChirho {
                    leader_node_id_chirho: leadership_chirho
                        .leader_id_chirho
                        .map(|node_chirho| node_chirho.0),
                },
                observation_chirho: self.observe_chirho()?,
            });
        }

        // R5: the target comes ONLY from the fail-closed verifying derivation (head length-witness +
        // operator sigs). An error here returns before any elector mutation — nothing changes.
        let (lines_chirho, head_chirho) = self.load_roster_bytes_chirho()?;
        let target_chirho = self.derive_membership_target_chirho(&lines_chirho, &head_chirho)?;

        let elector_arc_chirho = self.driver_chirho.elector_chirho().clone();
        let steps_chirho = if to_fixpoint_chirho {
            // R2 fixpoint: drive the transport between steps (the background ticker also commits) until the
            // group matches the target or the step bound is hit. converge_chirho returns the final step.
            let final_step_chirho = converge_chirho(
                &elector_arc_chirho,
                &target_chirho.members_chirho,
                || {
                    self.driver_chirho.tick_once_chirho();
                    std::thread::sleep(self.config_chirho.fixpoint_step_sleep_chirho);
                },
                self.config_chirho.fixpoint_max_steps_chirho,
            )?;
            vec![final_step_chirho]
        } else {
            // R2 default: exactly ONE step (the deterministic single-step injection the D3/D4 drills need).
            vec![apply_one_convergence_step_chirho(
                &elector_arc_chirho,
                &target_chirho.members_chirho,
            )?]
        };

        Ok(ConvergeResponseChirho {
            outcome_chirho: ConvergeOutcomeChirho::SteppedChirho {
                steps_chirho,
                to_fixpoint_chirho,
            },
            observation_chirho: self.observe_chirho()?,
        })
    }

    /// The synchronous body of `/re-home-chirho` (run on a blocking task). R4 mutex → R5 verified-roster
    /// preferred-leader derivation → the election-only re-home step (its own R3 leave-put honesty) → deliver
    /// the one-shot transfer message (the ticker will NOT re-send `MsgTimeoutNow`).
    fn run_re_home_chirho(&self) -> Result<ReHomeResponseChirho> {
        // R4: serialized against converge and other re-home calls.
        let _control_guard_chirho = self
            .control_lock_chirho
            .lock()
            .map_err(|_| anyhow::anyhow!("membership control lock poisoned"))?;

        // R5: the preferred leader comes ONLY from the fail-closed verifying derivation. An error (bad
        // roster, or a preference naming a non-member) returns before re_home_step — nothing changes.
        let (lines_chirho, head_chirho) = self.load_roster_bytes_chirho()?;
        let target_chirho = self.derive_membership_target_chirho(&lines_chirho, &head_chirho)?;

        // re_home_step surfaces NoPreference/NotLeader/AlreadyPreferred/PreferredNotVoter without side
        // effect (R3) and returns the transfer's outbound messages when it does transfer.
        let (step_chirho, messages_chirho) = re_home_step_chirho(
            self.driver_chirho.elector_chirho(),
            target_chirho.preferred_raft_id_chirho,
        )?;
        // The transfer emits a one-shot MsgTimeoutNow (a control message, not a replicated entry — the
        // ticker will not re-send it), so it uses the bounded acknowledged path rather than the retryable
        // queue. A network refusal becomes an explicit 422 and the operator can retry re-home.
        self.driver_chirho
            .deliver_required_control_chirho(messages_chirho)?;

        Ok(ReHomeResponseChirho {
            step_chirho,
            observation_chirho: self.observe_chirho()?,
        })
    }
}

/// Build the membership-control router over one node's control state: the two token-gated mutating
/// endpoints plus the open read-only observe endpoint. Merge this into the node's served router.
pub fn membership_control_router_chirho(control_chirho: Arc<MembershipControlChirho>) -> Router {
    Router::new()
        .route(CONVERGE_PATH_CHIRHO, post(post_converge_handler_chirho))
        .route(RE_HOME_PATH_CHIRHO, post(post_re_home_handler_chirho))
        .route(
            MEMBERSHIP_OBSERVE_PATH_CHIRHO,
            get(get_membership_handler_chirho),
        )
        .layer(DefaultBodyLimit::max(MAX_CONTROL_BODY_BYTES_CHIRHO))
        .with_state(control_chirho)
}

async fn post_converge_handler_chirho(
    State(control_chirho): State<Arc<MembershipControlChirho>>,
    headers_chirho: HeaderMap,
    Query(params_chirho): Query<ConvergeParamsChirho>,
) -> Response {
    if let Some(response_chirho) = control_chirho.check_operator_token_chirho(&headers_chirho) {
        return response_chirho;
    }
    let to_fixpoint_chirho = params_chirho.to_fixpoint_chirho.unwrap_or(false);
    let control_for_task_chirho = control_chirho.clone();
    // The elector ops + roster verification are synchronous (locks + file I/O + ed25519); run them on a
    // blocking task so they never stall the async runtime, and the R4 std mutex is never held across await.
    match tokio::task::spawn_blocking(move || {
        control_for_task_chirho.run_converge_chirho(to_fixpoint_chirho)
    })
    .await
    {
        Ok(Ok(response_chirho)) => Json(response_chirho).into_response(),
        Ok(Err(error_chirho)) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("converge failed: {error_chirho:#}"),
        )
            .into_response(),
        Err(join_chirho) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("converge task failed: {join_chirho}"),
        )
            .into_response(),
    }
}

async fn post_re_home_handler_chirho(
    State(control_chirho): State<Arc<MembershipControlChirho>>,
    headers_chirho: HeaderMap,
) -> Response {
    if let Some(response_chirho) = control_chirho.check_operator_token_chirho(&headers_chirho) {
        return response_chirho;
    }
    let control_for_task_chirho = control_chirho.clone();
    match tokio::task::spawn_blocking(move || control_for_task_chirho.run_re_home_chirho()).await {
        Ok(Ok(response_chirho)) => Json(response_chirho).into_response(),
        Ok(Err(error_chirho)) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("re-home failed: {error_chirho:#}"),
        )
            .into_response(),
        Err(join_chirho) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("re-home task failed: {join_chirho}"),
        )
            .into_response(),
    }
}

async fn get_membership_handler_chirho(
    State(control_chirho): State<Arc<MembershipControlChirho>>,
) -> Response {
    let control_for_task_chirho = control_chirho.clone();
    match tokio::task::spawn_blocking(move || control_for_task_chirho.observe_chirho()).await {
        Ok(Ok(observation_chirho)) => Json(observation_chirho).into_response(),
        // LOW-2 (audit 3824): this endpoint is OPEN (no token), so its error body is STATIC — an error
        // chain here can name durable file paths (the applied-index read opens the membership file), and an
        // unauthenticated caller must not learn them. The mutating endpoints stay verbose because they are
        // token-gated (only the operator, who already knows the paths, sees them).
        Ok(Err(_error_chirho)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "membership observe failed",
        )
            .into_response(),
        Err(_join_chirho) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "membership observe task failed",
        )
            .into_response(),
    }
}

/// Constant-time byte-equality for the operator token, so a mismatched token cannot be recovered by a
/// per-byte timing side channel. The length short-circuit only reveals length inequality (not sensitive
/// for a bearer token); equal-length inputs are compared in full every time.
fn constant_time_eq_chirho(a_chirho: &[u8], b_chirho: &[u8]) -> bool {
    if a_chirho.len() != b_chirho.len() {
        return false;
    }
    let mut diff_chirho = 0u8;
    for (x_chirho, y_chirho) in a_chirho.iter().zip(b_chirho.iter()) {
        diff_chirho |= x_chirho ^ y_chirho;
    }
    diff_chirho == 0
}

#[cfg(test)]
mod roster_authority_tests_chirho {
    use super::*;

    #[test]
    fn roster_read_authority_is_bounded_and_refuses_symlinks_chirho() {
        let temp_chirho = tempfile::tempdir().unwrap();
        let roster_chirho = temp_chirho.path().join("roster-chirho.jsonl");
        let head_chirho = temp_chirho.path().join("roster-head-chirho.json");
        std::fs::write(&roster_chirho, b"one-chirho\ntwo-chirho\n").unwrap();
        std::fs::write(&head_chirho, b"{}").unwrap();
        let config_chirho = RosterAuthorityConfigChirho {
            roster_path_chirho: roster_chirho.clone(),
            roster_head_path_chirho: head_chirho.clone(),
            operator_pubkey_hex_chirho: "a".repeat(64),
            relay_interface_chirho: cairn_roster_config_chirho::RELAY_WIREGUARD_INTERFACE_CHIRHO
                .to_string(),
        };
        let (lines_chirho, head_bytes_chirho) = config_chirho.load_bounded_inputs_chirho().unwrap();
        assert_eq!(lines_chirho.len(), 2);
        assert_eq!(head_bytes_chirho, b"{}");

        let too_many_lines_chirho = (0..=MAX_ROSTER_AUTHORITY_LINES_CHIRHO)
            .map(|index_chirho| format!("{index_chirho}\n"))
            .collect::<String>();
        std::fs::write(&roster_chirho, too_many_lines_chirho).unwrap();
        assert!(config_chirho
            .load_bounded_inputs_chirho()
            .unwrap_err()
            .to_string()
            .contains("RosterAuthorityLinePopulationRefusedChirho"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let linked_roster_chirho = temp_chirho.path().join("linked-roster-chirho.jsonl");
            symlink(&roster_chirho, &linked_roster_chirho).unwrap();
            let linked_config_chirho = RosterAuthorityConfigChirho {
                roster_path_chirho: linked_roster_chirho,
                roster_head_path_chirho: head_chirho,
                operator_pubkey_hex_chirho: "a".repeat(64),
                relay_interface_chirho:
                    cairn_roster_config_chirho::RELAY_WIREGUARD_INTERFACE_CHIRHO.to_string(),
            };
            assert!(linked_config_chirho
                .load_bounded_inputs_chirho()
                .unwrap_err()
                .to_string()
                .contains("RosterAuthorityStoreEntryTypeRefusedChirho"));
        }
    }
}
