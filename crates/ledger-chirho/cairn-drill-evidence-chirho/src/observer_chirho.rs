// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The item-6 drill's read-only OBSERVER channel (D1 + D3): from a survivor's leader/term/writer-era/
//! obligation projection and the partition helper's own cut status, produce a typed OBSERVATION that
//! provably carries no signing key and no mutation authority.
//!
//! # WHY THIS IS "PROVEN OBSERVATIONAL" (coordinator ruling (d): D1 + D3, D2 is a NON-GOAL)
//!
//! Ruling (d) is: the authority observer is a read-only leader/term + obligation/writer-era projection
//! polled from a SURVIVOR OUTSIDE the partition (D1); the partition helper's own cut status is D3; and
//! the former owner's own step-down belief is captured in HOST-PRIVATE logs, NOT on the wire — a
//! dedicated on-the-wire deposition-belief endpoint (D2) is a NON-GOAL for item 6. This module carries
//! D1 and D3 and nothing of D2.
//!
//! "Observational" is enforced two ways, mirroring how the 6.1 barrier's `status_chirho` is
//! observational by construction:
//!
//! * **Structurally.** [`observe_from_survivor_chirho`] takes a read-only [`SurvivorLeaderProjectionChirho`]
//!   (plain data, no key, no handle) and a read-only [`CutStatusChirho`], and returns an owned
//!   [`ObservationRecordChirho`]. There is no `&mut`, no signer, no store, no socket in the signature —
//!   there is nothing through which an observer request could mutate. The crate itself links no such
//!   surface (see the Cargo manifest note).
//! * **By type.** The observation carries [`ObserverAuthorityChirho`], whose ONLY variant is
//!   `ReadOnlyProjectionChirho` — no value of that type authorizes a write, so "cannot mutate" is a
//!   fact about the type, not a checked convention. And [`CutStatusChirho`] is a read-only SUMMARY of
//!   the cut (mode, subject label, deadline); it carries none of the plan's executable surface — no
//!   `NftCommandChirho`, no `ProcessControlStepChirho` — so you cannot get from an observation back to a
//!   rule the executor would run.

use cairn_drill_partition_nft_chirho::{
    HostedPartitionModeChirho, HostedPartitionPlanChirho, HostedPartitionRefusalChirho,
};
use serde::{Deserialize, Serialize};

/// The authority an observer channel carries. There is exactly ONE variant, and it is read-only: the
/// observer holds no signing key and no write/relay/activation authority. No value of this type
/// authorizes a mutation, so an observer request CANNOT mutate — the proof is that the mutating
/// variant does not exist to be constructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObserverAuthorityChirho {
    ReadOnlyProjectionChirho,
}

impl ObserverAuthorityChirho {
    /// Every authority an observer may carry. The observational proof is that this is exactly one
    /// read-only variant; a guard asserts the length is 1.
    pub const ALL_CHIRHO: [ObserverAuthorityChirho; 1] =
        [ObserverAuthorityChirho::ReadOnlyProjectionChirho];
}

/// A read-only projection of the winner's writer-era phase. Bounded labels only, never free text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WriterEraPhaseChirho {
    /// Fresh root, writer era not yet activated.
    LocalChirho,
    /// The winner's elected writer era is activated.
    ElectedChirho,
    /// The former owner's era, superseded by the elected winner.
    SupersededChirho,
}

/// A read-only projection of the drilled synthetic obligation's lifecycle phase (the GD7 ladder).
/// Bounded labels only, never free text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObligationPhaseChirho {
    /// No obligation minted yet.
    NoneChirho,
    /// A synthetic obligation is minted against the activated era's owner term.
    MintedChirho,
    /// The reporting-only provider has been observed.
    ProviderObservedChirho,
    /// A compensating effect has been recorded exactly once.
    CompensatedChirho,
    /// The compensated terminal is reached and the receipt is bound.
    CompletedChirho,
}

/// A serializable mirror of the partition helper's cut mode. That crate is deliberately std-only and
/// derives no serde, so the observation cannot embed its enum directly; this mirror maps 1:1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CutModeChirho {
    NetworkPartitionChirho,
    HungDriverChirho,
}

impl CutModeChirho {
    fn from_plan_mode_chirho(mode_chirho: HostedPartitionModeChirho) -> Self {
        match mode_chirho {
            HostedPartitionModeChirho::NetworkPartitionChirho => Self::NetworkPartitionChirho,
            HostedPartitionModeChirho::HungDriverChirho => Self::HungDriverChirho,
        }
    }
}

/// A bounded label projecting WHY a partition request was refused. It is a projection of the 6.5-c
/// refusal taxonomy into fixed labels (no fields, no addresses, no free text), so the D3 cut status
/// stays typed even on the refusal path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CutRefusalLabelChirho {
    NoPlanesChirho,
    PlaneIncompleteChirho,
    DuplicatePlaneChirho,
    OneDirectionOnlyChirho,
    NonTestTargetChirho,
    PortTwentyTwoChirho,
    SubjectNotOverlayChirho,
    LifetimeUnboundedChirho,
    HungDriverProcessInvalidChirho,
    HungDriverPauseUnboundedChirho,
    SubjectMismatchChirho,
}

impl CutRefusalLabelChirho {
    fn from_refusal_chirho(refusal_chirho: &HostedPartitionRefusalChirho) -> Self {
        match refusal_chirho {
            HostedPartitionRefusalChirho::NoPlanesRegisteredChirho => Self::NoPlanesChirho,
            HostedPartitionRefusalChirho::PlaneIncompleteChirho { .. } => {
                Self::PlaneIncompleteChirho
            }
            HostedPartitionRefusalChirho::DuplicatePlaneChirho { .. } => Self::DuplicatePlaneChirho,
            HostedPartitionRefusalChirho::OneDirectionOnlyChirho { .. } => {
                Self::OneDirectionOnlyChirho
            }
            HostedPartitionRefusalChirho::NonTestTargetRefusedChirho { .. } => {
                Self::NonTestTargetChirho
            }
            HostedPartitionRefusalChirho::PortTwentyTwoRefusedChirho { .. } => {
                Self::PortTwentyTwoChirho
            }
            HostedPartitionRefusalChirho::SubjectNotOverlayChirho { .. } => {
                Self::SubjectNotOverlayChirho
            }
            HostedPartitionRefusalChirho::LifetimeUnboundedChirho { .. } => {
                Self::LifetimeUnboundedChirho
            }
            HostedPartitionRefusalChirho::HungDriverProcessInvalidChirho { .. } => {
                Self::HungDriverProcessInvalidChirho
            }
            HostedPartitionRefusalChirho::HungDriverPauseUnboundedChirho { .. } => {
                Self::HungDriverPauseUnboundedChirho
            }
            HostedPartitionRefusalChirho::SubjectMismatchChirho { .. } => {
                Self::SubjectMismatchChirho
            }
        }
    }
}

/// D3: a read-only SUMMARY of the partition helper's own cut status, derived from the 6.5-c
/// plan-or-refusal. When armed it carries the cut's mode, the former-owner subject label, and the
/// bounded deadline in seconds — and NOTHING executable. There is deliberately no field of type
/// `NftCommandChirho` or `ProcessControlStepChirho`: you cannot get from a `CutStatusChirho` back to a
/// rule the executor would run, which keeps the observer a reader of the cut, never a driver of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CutStatusChirho {
    /// The partition is armed: the plan was admitted. Summary only.
    ArmedChirho {
        mode_chirho: CutModeChirho,
        former_owner_label_chirho: String,
        deadline_secs_chirho: u64,
    },
    /// The partition request was refused (nothing armed): a bounded reason label only.
    RefusedChirho {
        reason_label_chirho: CutRefusalLabelChirho,
    },
    /// No partition is armed (baseline, or after heal-cleanup).
    NotArmedChirho,
}

impl CutStatusChirho {
    /// Observe the cut status from an ARMED plan (D3). Read-only: it takes the plan by shared
    /// reference and copies only its mode, subject label, and deadline — never its
    /// setup/teardown/process commands.
    pub fn observed_from_plan_chirho(plan_chirho: &HostedPartitionPlanChirho) -> Self {
        Self::ArmedChirho {
            mode_chirho: CutModeChirho::from_plan_mode_chirho(plan_chirho.mode_chirho()),
            former_owner_label_chirho: plan_chirho
                .subject_chirho()
                .former_owner_label_chirho
                .clone(),
            deadline_secs_chirho: plan_chirho.deadline_chirho().as_secs(),
        }
    }

    /// Observe the cut status from a REFUSED request (D3): nothing armed, one bounded reason label.
    pub fn observed_from_refusal_chirho(refusal_chirho: &HostedPartitionRefusalChirho) -> Self {
        Self::RefusedChirho {
            reason_label_chirho: CutRefusalLabelChirho::from_refusal_chirho(refusal_chirho),
        }
    }

    /// No cut armed (baseline / post-cleanup).
    pub fn not_armed_chirho() -> Self {
        Self::NotArmedChirho
    }
}

/// D1 INPUT: a read-only leader/term + writer-era + obligation projection polled from a SURVIVOR node
/// OUTSIDE the partition. It holds NO signing key and NO handle — it is DATA the observer reads. In
/// 6.5-d this is a fixture; on a host (6.6) it is a projection read over a survivor's read-only
/// endpoint. Every field is a bounded value (hex id, u64 term, or an enum), never free text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurvivorLeaderProjectionChirho {
    /// The elected leader id the survivor currently sees — a 64-hex raft node id (public, like b5's
    /// leader id). Validated 64-hex at observe time.
    pub leader_id_hex_chirho: String,
    /// The observer/survivor node's own term (maps to `ObserverTermChirho` in the shareable packet).
    pub observer_term_chirho: u64,
    /// The elected winner's term (maps to `WinnerTermChirho`). After a heal this is strictly greater
    /// than the deposed former owner's term.
    pub winner_term_chirho: u64,
    /// The deposed former owner's term as last observed — the term being superseded (maps to
    /// `CurrentTermChirho`).
    pub former_owner_term_chirho: u64,
    /// A read-only projection of the winner's writer-era phase.
    pub writer_era_phase_chirho: WriterEraPhaseChirho,
    /// A read-only projection of the drilled obligation's lifecycle phase.
    pub obligation_phase_chirho: ObligationPhaseChirho,
}

/// The typed OBSERVATION the read-only observer produces (D1 authority projection + D3 cut status).
/// Every field is a bounded value or an enum; it carries `ObserverAuthorityChirho::ReadOnlyProjection`
/// and NO executable command, so an observation can be recorded, serialized, and shared without ever
/// being a channel that could mutate the cluster.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationRecordChirho {
    pub authority_chirho: ObserverAuthorityChirho,
    pub leader_id_hex_chirho: String,
    pub observer_term_chirho: u64,
    pub winner_term_chirho: u64,
    pub former_owner_term_chirho: u64,
    pub writer_era_phase_chirho: WriterEraPhaseChirho,
    pub obligation_phase_chirho: ObligationPhaseChirho,
    pub cut_status_chirho: CutStatusChirho,
    pub observed_at_ms_chirho: u64,
}

/// Why the observer refused to record a projection. The observer validates only that the projection is
/// well-formed (a 64-hex leader id, like b5); it fails CLOSED on a malformed projection rather than
/// recording a bad observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObserverRefusalChirho {
    LeaderIdNotHex64Chirho,
}

impl std::fmt::Display for ObserverRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LeaderIdNotHex64Chirho => {
                formatter_chirho.write_str("observer projection leader id is not a 64-hex digest")
            }
        }
    }
}

impl std::error::Error for ObserverRefusalChirho {}

/// Produce an OBSERVATION from a survivor's read-only projection (D1) and the cut status (D3). PURE: it
/// reads the projection and the cut summary and returns an owned record. It takes no signer, no store,
/// no socket — there is no parameter through which it could mutate anything, which is the structural
/// half of "proven observational"; the type-level half is that the record carries
/// `ReadOnlyProjectionChirho` and no executable command.
pub fn observe_from_survivor_chirho(
    projection_chirho: &SurvivorLeaderProjectionChirho,
    cut_status_chirho: CutStatusChirho,
    observed_at_ms_chirho: u64,
) -> Result<ObservationRecordChirho, ObserverRefusalChirho> {
    if !is_hex64_chirho(&projection_chirho.leader_id_hex_chirho) {
        return Err(ObserverRefusalChirho::LeaderIdNotHex64Chirho);
    }
    Ok(ObservationRecordChirho {
        authority_chirho: ObserverAuthorityChirho::ReadOnlyProjectionChirho,
        leader_id_hex_chirho: projection_chirho.leader_id_hex_chirho.clone(),
        observer_term_chirho: projection_chirho.observer_term_chirho,
        winner_term_chirho: projection_chirho.winner_term_chirho,
        former_owner_term_chirho: projection_chirho.former_owner_term_chirho,
        writer_era_phase_chirho: projection_chirho.writer_era_phase_chirho,
        obligation_phase_chirho: projection_chirho.obligation_phase_chirho,
        cut_status_chirho,
        observed_at_ms_chirho,
    })
}

fn is_hex64_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_drill_partition_nft_chirho::{
        plan_partition_chirho, DrillTargetKindChirho, HostedPartitionModeSpecChirho,
        HostedPartitionRequestChirho, OverlayPlaneChirho, OverlayPlanePortChirho,
        PartitionSubjectChirho,
    };
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn leader_id_chirho() -> String {
        "ab".repeat(32)
    }

    fn projection_chirho() -> SurvivorLeaderProjectionChirho {
        SurvivorLeaderProjectionChirho {
            leader_id_hex_chirho: leader_id_chirho(),
            observer_term_chirho: 27,
            winner_term_chirho: 28,
            former_owner_term_chirho: 27,
            writer_era_phase_chirho: WriterEraPhaseChirho::ElectedChirho,
            obligation_phase_chirho: ObligationPhaseChirho::CompletedChirho,
        }
    }

    fn armed_plan_chirho() -> HostedPartitionPlanChirho {
        let request_chirho = HostedPartitionRequestChirho::new_chirho(
            PartitionSubjectChirho {
                former_owner_label_chirho: "boaz3".to_owned(),
                former_owner_overlay_addr_chirho: Ipv4Addr::new(10, 100, 0, 7),
            },
            vec![
                OverlayPlanePortChirho {
                    plane_chirho: OverlayPlaneChirho::ElectorChirho,
                    port_chirho: 8300,
                },
                OverlayPlanePortChirho {
                    plane_chirho: OverlayPlaneChirho::WriteRelayChirho,
                    port_chirho: 8400,
                },
                OverlayPlanePortChirho {
                    plane_chirho: OverlayPlaneChirho::ObservationChirho,
                    port_chirho: 8500,
                },
            ],
            HostedPartitionModeSpecChirho::NetworkPartitionChirho,
            DrillTargetKindChirho::DrillRootSyntheticChirho,
            Duration::from_secs(600),
        );
        plan_partition_chirho(&request_chirho).expect("lawful plan is admitted")
    }

    #[test]
    fn observer_authority_is_exactly_one_read_only_variant_chirho() {
        // The observational proof, at the type level: there is exactly one authority and it is
        // read-only. If a mutating variant were ever added, this guard fires.
        assert_eq!(ObserverAuthorityChirho::ALL_CHIRHO.len(), 1);
        assert_eq!(
            ObserverAuthorityChirho::ALL_CHIRHO[0],
            ObserverAuthorityChirho::ReadOnlyProjectionChirho
        );
    }

    #[test]
    fn observation_reads_the_projection_through_exactly_chirho() {
        let projection_chirho = projection_chirho();
        let observation_chirho = observe_from_survivor_chirho(
            &projection_chirho,
            CutStatusChirho::observed_from_plan_chirho(&armed_plan_chirho()),
            1_725_000_000_000,
        )
        .expect("well-formed projection observes");
        assert_eq!(
            observation_chirho.authority_chirho,
            ObserverAuthorityChirho::ReadOnlyProjectionChirho
        );
        assert_eq!(observation_chirho.leader_id_hex_chirho, leader_id_chirho());
        assert_eq!(observation_chirho.observer_term_chirho, 27);
        assert_eq!(observation_chirho.winner_term_chirho, 28);
        assert_eq!(observation_chirho.former_owner_term_chirho, 27);
        assert_eq!(
            observation_chirho.writer_era_phase_chirho,
            WriterEraPhaseChirho::ElectedChirho
        );
        assert_eq!(
            observation_chirho.obligation_phase_chirho,
            ObligationPhaseChirho::CompletedChirho
        );
        assert_eq!(observation_chirho.observed_at_ms_chirho, 1_725_000_000_000);
    }

    #[test]
    fn observer_is_deterministic_chirho() {
        // A projection READ, not a command: the same inputs yield the same record every time.
        let projection_chirho = projection_chirho();
        let first_chirho = observe_from_survivor_chirho(
            &projection_chirho,
            CutStatusChirho::not_armed_chirho(),
            10,
        )
        .unwrap();
        let second_chirho = observe_from_survivor_chirho(
            &projection_chirho,
            CutStatusChirho::not_armed_chirho(),
            10,
        )
        .unwrap();
        assert_eq!(first_chirho, second_chirho);
    }

    #[test]
    fn observation_is_an_owned_snapshot_not_a_live_view_chirho() {
        // "Cannot mutate" includes "cannot be mutated THROUGH": the record owns its data, so changing
        // the projection after observing does not change what was recorded.
        let mut projection_chirho = projection_chirho();
        let observation_chirho = observe_from_survivor_chirho(
            &projection_chirho,
            CutStatusChirho::not_armed_chirho(),
            5,
        )
        .unwrap();
        projection_chirho.winner_term_chirho = 999;
        projection_chirho.leader_id_hex_chirho = "cd".repeat(32);
        assert_eq!(observation_chirho.winner_term_chirho, 28);
        assert_eq!(observation_chirho.leader_id_hex_chirho, leader_id_chirho());
    }

    #[test]
    fn cut_status_from_plan_strips_the_executable_surface_chirho() {
        // The SOURCE plan carries executable rules (positive control), but the observation derived from
        // it carries only a bounded summary — no `add rule`, no `drop`, no `sigstop`. This is the
        // structural proof that an observation cannot become a channel that drives the cut.
        let plan_chirho = armed_plan_chirho();
        let plan_has_executable_rule_chirho = plan_chirho
            .all_rendered_lines_chirho()
            .iter()
            .any(|line_chirho| line_chirho.contains("add rule") && line_chirho.contains("drop"));
        assert!(
            plan_has_executable_rule_chirho,
            "positive control: the armed plan must carry executable drop rules"
        );

        let cut_status_chirho = CutStatusChirho::observed_from_plan_chirho(&plan_chirho);
        match &cut_status_chirho {
            CutStatusChirho::ArmedChirho {
                mode_chirho,
                former_owner_label_chirho,
                deadline_secs_chirho,
            } => {
                assert_eq!(*mode_chirho, CutModeChirho::NetworkPartitionChirho);
                assert_eq!(former_owner_label_chirho, "boaz3");
                assert_eq!(*deadline_secs_chirho, 600);
            }
            other_chirho => panic!("expected an armed cut status, got {other_chirho:?}"),
        }

        let observation_chirho =
            observe_from_survivor_chirho(&projection_chirho(), cut_status_chirho, 1).unwrap();
        let serialized_chirho = serde_json::to_string(&observation_chirho).unwrap();
        for executable_token_chirho in ["add rule", "add chain", " drop", "sigstop", "sigcont"] {
            assert!(
                !serialized_chirho
                    .to_ascii_lowercase()
                    .contains(executable_token_chirho),
                "observation must not carry the cut's executable token {executable_token_chirho:?}"
            );
        }
    }

    #[test]
    fn cut_status_from_refusal_is_a_bounded_label_chirho() {
        // A one-direction-only PLANT refuses; D3 records only a bounded label, no address, no free text.
        let plant_chirho = HostedPartitionRequestChirho::ingress_only_plant_chirho(
            PartitionSubjectChirho {
                former_owner_label_chirho: "boaz3".to_owned(),
                former_owner_overlay_addr_chirho: Ipv4Addr::new(10, 100, 0, 7),
            },
            vec![
                OverlayPlanePortChirho {
                    plane_chirho: OverlayPlaneChirho::ElectorChirho,
                    port_chirho: 8300,
                },
                OverlayPlanePortChirho {
                    plane_chirho: OverlayPlaneChirho::WriteRelayChirho,
                    port_chirho: 8400,
                },
                OverlayPlanePortChirho {
                    plane_chirho: OverlayPlaneChirho::ObservationChirho,
                    port_chirho: 8500,
                },
            ],
            HostedPartitionModeSpecChirho::NetworkPartitionChirho,
            DrillTargetKindChirho::DrillRootSyntheticChirho,
            Duration::from_secs(600),
        );
        let refusal_chirho = plan_partition_chirho(&plant_chirho).unwrap_err();
        let cut_status_chirho = CutStatusChirho::observed_from_refusal_chirho(&refusal_chirho);
        assert_eq!(
            cut_status_chirho,
            CutStatusChirho::RefusedChirho {
                reason_label_chirho: CutRefusalLabelChirho::OneDirectionOnlyChirho,
            }
        );
        let serialized_chirho = serde_json::to_string(&cut_status_chirho).unwrap();
        assert!(!serialized_chirho.contains("10.100.0"));
    }

    #[test]
    fn observer_refuses_a_malformed_leader_id_chirho() {
        let mut projection_chirho = projection_chirho();
        projection_chirho.leader_id_hex_chirho = "not-a-64-hex-digest".to_owned();
        let refusal_chirho = observe_from_survivor_chirho(
            &projection_chirho,
            CutStatusChirho::not_armed_chirho(),
            1,
        )
        .unwrap_err();
        assert_eq!(
            refusal_chirho,
            ObserverRefusalChirho::LeaderIdNotHex64Chirho
        );
    }
}
