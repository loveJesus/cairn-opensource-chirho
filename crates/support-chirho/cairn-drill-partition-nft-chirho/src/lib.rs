// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Hosted transport-rule GENERATOR for item-6 drills: build the nftables rule set that partitions a
//! former owner's overlay traffic, and reproduce ON THE WIRE the admission contract the 6.1 loopback
//! barrier enforces IN MEMORY. This crate generates rules as data and checks admission; it never runs
//! `nft`, never opens a socket, and never names a host. Execution is a later brick (6.5-e / 6.6).
//!
//! # WHY A GENERATOR, AND WHY IT MIRRORS THE 6.1 BARRIER RATHER THAN REUSING IT
//!
//! The 6.1 barrier ([`cairn-drill-barrier-chirho`]) is std-only loopback: it binds `127.0.0.1:0` and
//! moves loopback bytes, so it cannot cut real overlay traffic between two hosts. The live substrate
//! is multi-host over the `10.100.0.0/24` overlay, and the proven hosted analog of a cut is a packet
//! partition (nftables), exactly the shape the cax11 election drill used when an isolated node
//! stepped down. So the barrier's role here is the SEMANTIC CONTRACT the generated rules must
//! reproduce, not the byte-cutter. The four properties this generator reproduces, each mirrored from
//! the barrier and each independently checked by a test:
//!
//! 1. **BOTH DIRECTIONS, SYMMETRIC.** The barrier refuses [`arm_chirho`] unless a node routes BOTH
//!    ingress and egress through it. This generator refuses a request that would drop traffic in only
//!    one direction ([`HostedPartitionRefusalChirho::OneDirectionOnlyChirho`]); a lawful plan carries
//!    an ingress DROP (hook `input`, `ip daddr <former>`) AND an egress DROP (hook `output`,
//!    `ip saddr <former>`) for every overlay plane. Asymmetric reachability is not a partition.
//! 2. **MODE-NAMED, NO DEFAULT.** Like [`DrillDisconnectModeChirho`], the two modes differ in EXACTLY
//!    one thing — whether the former owner's own process keeps running.
//!    [`HostedPartitionModeChirho::NetworkPartitionChirho`] drops packets and leaves the process
//!    alive (it notices it cannot reach a quorum and steps down);
//!    [`HostedPartitionModeChirho::HungDriverChirho`] drops packets AND adds a SEPARATE, bounded
//!    `SIGSTOP` with a MANDATORY paired `SIGCONT` on cleanup, so the process's own detector is dead.
//!    A request must name the mode; there is no default, because a default would silently pick one
//!    failure to stand for the other.
//! 3. **SUBJECT-BOUND.** Every generated rule names exactly the former owner's overlay address on the
//!    exact overlay port set; a neighbour's address never appears, and an operation naming a different
//!    subject refuses ([`HostedPartitionRefusalChirho::SubjectMismatchChirho`]).
//! 4. **BOUNDED LIFETIME / AUTO-CLEANUP.** Like `cleanup_chirho`/`Drop` on the barrier and the elector
//!    deploy's `teardown-chirho`, every plan carries a bounded deadline and a teardown rule set that
//!    reverses EXACTLY the armed rules, so a forgotten drill heals rather than leaving a node deaf.
//!
//! # WHAT MAKES THIS HOSTED PARTITION "BLESSED" (coordinator ruling (c): C1 + C2 + C4)
//!
//! The hosted partition is an nft/host action, not the barrier crate, so "blessed" needs a different
//! carrier than the barrier's four structural properties. Three controls carry it here, matching the
//! `fleet-elector-deploy-chirho.sh firewall-chirho` discipline:
//!
//! * **C1 — reviewed verb allowlist.** Every command is one of a fixed [`NftVerbChirho`] set; there is
//!   no "run arbitrary command". The only caller-influenced fields (subject label, address, ports,
//!   process match) are constrained by TYPE (`Ipv4Addr`, `u16`, a sanitised `[a-z0-9_]` chain token,
//!   a metacharacter-free process match), so no rendered line can carry a shell escape.
//! * **C2 — test-kind allowlist.** A partition may only target a drill-root synthetic test kind
//!   ([`DrillTargetKindChirho::DrillRootSyntheticChirho`]); a production or real-money target refuses
//!   ([`HostedPartitionRefusalChirho::NonTestTargetRefusedChirho`]). (Coordinator ruling: C3, a signed
//!   operator drill request, is NOT required for item 6's synthetic-test-kind drill.)
//! * **C4 — bounded lifetime / automatic cleanup.** Property 4 above.
//!
//! And a structural floor under all of it: this generator NEVER emits a rule that touches the real
//! `INPUT`/`OUTPUT` base chains or their policy, and NEVER emits a rule matching port 22. It installs
//! its OWN drill base chains (`policy accept`, so they can only drop what they explicitly match) and
//! refuses a request whose overlay port set includes 22
//! ([`HostedPartitionRefusalChirho::PortTwentyTwoRefusedChirho`]). The whole rule set is the
//! whole-node packet partition applied ON THE FORMER OWNER'S HOST (the cax11 shape), so `ip daddr
//! <former>` on `input` cuts peers reaching it and `ip saddr <former>` on `output` cuts it reaching
//! peers.
//!
//! # STILL THE EXECUTOR'S JOB — named, not done here
//!
//! This crate stops at the rule set and the process-control steps as DATA. Resolving a process match
//! to a pid, sending signals, running `nft`, and re-measuring the host are brick 6.5-e / 6.6. This
//! crate cannot do any of them: it names no host and links no process/signal/socket surface.

use std::net::Ipv4Addr;
use std::time::Duration;

/// The overlay the drill subject must live on: `10.100.0.0/24`. A subject address outside it is
/// refused, because a partition of a non-overlay address is not the drill this helper exists for.
const OVERLAY_PREFIX_CHIRHO: [u8; 3] = [10, 100, 0];

/// nft family/table the drill installs into — the same `ip filter` the firewall arm already uses.
const NFT_FAMILY_CHIRHO: &str = "ip";
const NFT_TABLE_CHIRHO: &str = "filter";

/// The reserved SSH port this generator must never express a rule about, in either direction.
const SSH_PORT_CHIRHO: u16 = 22;

/// The upper bound on a partition's armed lifetime. A drill that armed a longer cut than this would
/// outlive the window a healing drill is supposed to occupy; the deadline is a safety floor, not a
/// scheduling knob.
pub const MAX_PARTITION_LIFETIME_CHIRHO: Duration = Duration::from_secs(30 * 60);

/// The upper bound on a HungDriver `SIGSTOP`. A stopped money-authority process (even a test-kind one)
/// must be bounded and self-releasing; the paired `SIGCONT` in cleanup is the release, and this caps
/// how long the pause may be armed for before that release is due.
pub const MAX_HUNG_DRIVER_PAUSE_CHIRHO: Duration = Duration::from_secs(120);

/// Which failure a hosted partition expresses. There is no default; see the crate header. Mirror of
/// the 6.1 barrier's `DrillDisconnectModeChirho`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostedPartitionModeChirho {
    /// Overlay packets dropped, the former owner's process KEEPS RUNNING — a live node that notices it
    /// cannot reach a quorum and steps down on its own.
    NetworkPartitionChirho,
    /// Overlay packets dropped AND the former owner's process bounded-`SIGSTOP`ped — its own detector
    /// is dead, so it cannot notice or report its deposition. Cleanup MUST `SIGCONT` it.
    HungDriverChirho,
}

/// The request-side mode, carrying the extra inputs HungDriver needs and NetworkPartition cannot
/// express. Making the process match and pause bound reachable only through the HungDriver variant is
/// what keeps "name the mode" structural rather than a checked convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostedPartitionModeSpecChirho {
    /// Drop packets only.
    NetworkPartitionChirho,
    /// Drop packets AND stop the named process for a bounded interval.
    HungDriverChirho {
        /// An exact-match process token for the former owner's process (resolved to a pid by the
        /// executor, e.g. `pgrep -x`). Validated metacharacter-free at admission.
        process_match_chirho: String,
        /// How long the `SIGSTOP` may stand before the mandatory `SIGCONT` is due. Bounded by
        /// [`MAX_HUNG_DRIVER_PAUSE_CHIRHO`] and by the partition lifetime.
        max_paused_chirho: Duration,
    },
}

impl HostedPartitionModeSpecChirho {
    /// The named mode this spec expresses.
    pub fn mode_chirho(&self) -> HostedPartitionModeChirho {
        match self {
            Self::NetworkPartitionChirho => HostedPartitionModeChirho::NetworkPartitionChirho,
            Self::HungDriverChirho { .. } => HostedPartitionModeChirho::HungDriverChirho,
        }
    }
}

/// One overlay traffic plane the former owner speaks on. Coordinator ruling (a) = A2: the cut covers
/// ALL of these, so a partition cannot leave the old owner informed through an untouched plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayPlaneChirho {
    /// Raft election RPC (the elector overlay port).
    ElectorChirho,
    /// The write-relay surface.
    WriteRelayChirho,
    /// The winner-view / fork-observation read surfaces.
    ObservationChirho,
}

impl OverlayPlaneChirho {
    /// Every plane a lawful partition must cover, in the fixed order rules render in.
    pub const ALL_CHIRHO: [OverlayPlaneChirho; 3] = [
        OverlayPlaneChirho::ElectorChirho,
        OverlayPlaneChirho::WriteRelayChirho,
        OverlayPlaneChirho::ObservationChirho,
    ];

    fn label_chirho(self) -> &'static str {
        match self {
            Self::ElectorChirho => "elector",
            Self::WriteRelayChirho => "write-relay",
            Self::ObservationChirho => "observation",
        }
    }
}

/// One plane bound to the overlay port it runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlayPlanePortChirho {
    pub plane_chirho: OverlayPlaneChirho,
    pub port_chirho: u16,
}

/// Which test kind the partition targets. Only the drill-root synthetic kind is blessed (C2); the
/// other variants exist so a test can PLANT a non-test target and watch admission refuse it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrillTargetKindChirho {
    /// The only allowed target: a synthetic drill root standing up composed test-kind nodes.
    DrillRootSyntheticChirho,
    /// PLANT-ONLY: a production owner node. Refused.
    ProductionOwnerChirho,
    /// PLANT-ONLY: a real-money node. Refused.
    RealMoneyNodeChirho,
}

impl DrillTargetKindChirho {
    fn is_blessed_test_kind_chirho(self) -> bool {
        matches!(self, Self::DrillRootSyntheticChirho)
    }
}

/// The former owner the partition names: a stable label plus its exact overlay address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionSubjectChirho {
    pub former_owner_label_chirho: String,
    pub former_owner_overlay_addr_chirho: Ipv4Addr,
}

/// Which direction a drop covers. Both are required; a request declaring only one is the
/// one-direction-only plant that admission refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionDirectionChirho {
    /// Peers → former owner (hook `input`, matched by `ip daddr <former>`).
    IngressChirho,
    /// Former owner → peers (hook `output`, matched by `ip saddr <former>`).
    EgressChirho,
}

/// A partition request, before admission. Built lawfully with both directions by
/// [`Self::new_chirho`]; the plant-only [`Self::ingress_only_plant_chirho`] omits egress so the
/// pre-registered one-direction-only arm runs against the real admission check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedPartitionRequestChirho {
    subject_chirho: PartitionSubjectChirho,
    planes_chirho: Vec<OverlayPlanePortChirho>,
    directions_chirho: Vec<PartitionDirectionChirho>,
    mode_chirho: HostedPartitionModeSpecChirho,
    target_kind_chirho: DrillTargetKindChirho,
    lifetime_chirho: Duration,
}

impl HostedPartitionRequestChirho {
    /// The lawful shape: both directions cut. `planes_chirho` must cover every
    /// [`OverlayPlaneChirho::ALL_CHIRHO`] plane exactly once (A2).
    pub fn new_chirho(
        subject_chirho: PartitionSubjectChirho,
        planes_chirho: Vec<OverlayPlanePortChirho>,
        mode_chirho: HostedPartitionModeSpecChirho,
        target_kind_chirho: DrillTargetKindChirho,
        lifetime_chirho: Duration,
    ) -> Self {
        Self {
            subject_chirho,
            planes_chirho,
            directions_chirho: vec![
                PartitionDirectionChirho::IngressChirho,
                PartitionDirectionChirho::EgressChirho,
            ],
            mode_chirho,
            target_kind_chirho,
            lifetime_chirho,
        }
    }

    /// PLANT-ONLY: declare only the ingress direction, so admission refuses `OneDirectionOnlyChirho`.
    ///
    /// This is the on-the-wire analog of the barrier's `register_ingress_only_chirho`: it exists so
    /// the one-direction-only arm is executed against the real admission check rather than argued in
    /// prose. Production drills use [`Self::new_chirho`].
    pub fn ingress_only_plant_chirho(
        subject_chirho: PartitionSubjectChirho,
        planes_chirho: Vec<OverlayPlanePortChirho>,
        mode_chirho: HostedPartitionModeSpecChirho,
        target_kind_chirho: DrillTargetKindChirho,
        lifetime_chirho: Duration,
    ) -> Self {
        Self {
            subject_chirho,
            planes_chirho,
            directions_chirho: vec![PartitionDirectionChirho::IngressChirho],
            mode_chirho,
            target_kind_chirho,
            lifetime_chirho,
        }
    }
}

/// Why a partition request was refused. Every arm fails CLOSED toward a connected cluster: a refusal
/// arms nothing, and its recovery is generated for the refusal path too (see
/// [`HostedPartitionRefusalChirho::cleanup_is_still_generated_chirho`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostedPartitionRefusalChirho {
    /// No plane was named at all; arming an empty partition would report success while cutting
    /// nothing — the vacuous-green shape this refusal prevents.
    NoPlanesRegisteredChirho,
    /// A plane required by A2 was missing; a partition that skips a plane leaves a back channel.
    PlaneIncompleteChirho {
        missing_chirho: Vec<OverlayPlaneChirho>,
    },
    /// A plane was named twice, so the port for that plane is ambiguous.
    DuplicatePlaneChirho { plane_chirho: OverlayPlaneChirho },
    /// The request declared fewer than both directions. Asymmetric reachability is not a partition.
    OneDirectionOnlyChirho { subject_label_chirho: String },
    /// The target was not a blessed synthetic test kind (C2).
    NonTestTargetRefusedChirho {
        target_kind_chirho: DrillTargetKindChirho,
    },
    /// A named overlay port was the reserved SSH port. Never expressed, in either direction.
    PortTwentyTwoRefusedChirho { plane_chirho: OverlayPlaneChirho },
    /// The subject address is outside the `10.100.0.0/24` overlay.
    SubjectNotOverlayChirho { addr_chirho: Ipv4Addr },
    /// The armed lifetime was zero or exceeded [`MAX_PARTITION_LIFETIME_CHIRHO`].
    LifetimeUnboundedChirho {
        requested_chirho: Duration,
        max_chirho: Duration,
    },
    /// The HungDriver process match was empty or carried a shell metacharacter.
    HungDriverProcessInvalidChirho { detail_chirho: String },
    /// The HungDriver pause was zero, exceeded [`MAX_HUNG_DRIVER_PAUSE_CHIRHO`], or exceeded the
    /// partition lifetime (a pause that outlives the cut could never be auto-released within it).
    HungDriverPauseUnboundedChirho {
        requested_chirho: Duration,
        max_chirho: Duration,
    },
    /// An operation named a subject this plan was not armed for. A neighbour cannot borrow a partition
    /// armed for the former owner.
    SubjectMismatchChirho {
        armed_chirho: String,
        requested_chirho: String,
    },
}

impl HostedPartitionRefusalChirho {
    /// A refusal is not a dead end for cleanup: every path — success OR refusal — can still generate a
    /// teardown that removes any drill chains a partial/aborted arm might have created, so a refused
    /// drill heals rather than leaving state armed. The generator itself binds nothing until admission
    /// passes, so on a refusal there is nothing armed; this helper returns the SAFE teardown for the
    /// subject anyway, which the executor can run unconditionally in a `finally`.
    pub fn cleanup_is_still_generated_chirho(
        subject_chirho: &PartitionSubjectChirho,
    ) -> Vec<NftCommandChirho> {
        teardown_commands_chirho(&drill_chain_names_chirho(subject_chirho))
    }
}

impl std::fmt::Display for HostedPartitionRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPlanesRegisteredChirho => {
                formatter_chirho.write_str("hosted partition request named no overlay planes")
            }
            Self::PlaneIncompleteChirho { missing_chirho } => write!(
                formatter_chirho,
                "hosted partition request is missing required plane(s): {}",
                missing_chirho
                    .iter()
                    .map(|plane_chirho| plane_chirho.label_chirho())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::DuplicatePlaneChirho { plane_chirho } => write!(
                formatter_chirho,
                "hosted partition request named plane {} more than once",
                plane_chirho.label_chirho()
            ),
            Self::OneDirectionOnlyChirho {
                subject_label_chirho,
            } => write!(
                formatter_chirho,
                "hosted partition for {subject_label_chirho} declared only one direction; a partition \
                 needs both ingress and egress"
            ),
            Self::NonTestTargetRefusedChirho { target_kind_chirho } => write!(
                formatter_chirho,
                "hosted partition refused a non-test target: {target_kind_chirho:?}"
            ),
            Self::PortTwentyTwoRefusedChirho { plane_chirho } => write!(
                formatter_chirho,
                "hosted partition refused: plane {} named the reserved SSH port",
                plane_chirho.label_chirho()
            ),
            Self::SubjectNotOverlayChirho { addr_chirho } => write!(
                formatter_chirho,
                "hosted partition subject {addr_chirho} is not on the 10.100.0.0/24 overlay"
            ),
            Self::LifetimeUnboundedChirho {
                requested_chirho,
                max_chirho,
            } => write!(
                formatter_chirho,
                "hosted partition lifetime {requested_chirho:?} is zero or exceeds the {max_chirho:?} \
                 bound"
            ),
            Self::HungDriverProcessInvalidChirho { detail_chirho } => write!(
                formatter_chirho,
                "hosted partition HungDriver process match is invalid: {detail_chirho}"
            ),
            Self::HungDriverPauseUnboundedChirho {
                requested_chirho,
                max_chirho,
            } => write!(
                formatter_chirho,
                "hosted partition HungDriver pause {requested_chirho:?} is zero or exceeds the \
                 {max_chirho:?} bound"
            ),
            Self::SubjectMismatchChirho {
                armed_chirho,
                requested_chirho,
            } => write!(
                formatter_chirho,
                "hosted partition armed for {armed_chirho} cannot serve subject {requested_chirho}"
            ),
        }
    }
}

impl std::error::Error for HostedPartitionRefusalChirho {}

/// The fixed reviewed nft verbs this generator may emit (C1). There is no "run arbitrary command":
/// nothing outside this set is constructible, and every rendered line begins with one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftVerbChirho {
    AddTableChirho,
    AddChainChirho,
    AddRuleChirho,
    FlushChainChirho,
    DeleteChainChirho,
}

impl NftVerbChirho {
    /// Every verb in the allowlist, so a test can prove the emitted set is a subset of it.
    pub const ALL_CHIRHO: [NftVerbChirho; 5] = [
        NftVerbChirho::AddTableChirho,
        NftVerbChirho::AddChainChirho,
        NftVerbChirho::AddRuleChirho,
        NftVerbChirho::FlushChainChirho,
        NftVerbChirho::DeleteChainChirho,
    ];

    /// The canonical leading token(s) each rendered line begins with.
    pub fn canonical_chirho(self) -> &'static str {
        match self {
            Self::AddTableChirho => "add table",
            Self::AddChainChirho => "add chain",
            Self::AddRuleChirho => "add rule",
            Self::FlushChainChirho => "flush chain",
            Self::DeleteChainChirho => "delete chain",
        }
    }
}

/// One generated nft command: a fixed verb plus the exact argument line the executor would pass to
/// `nft` as a SINGLE quoted argument (the shape `fleet-elector-deploy-chirho.sh` already uses). The
/// line is data — this crate never runs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftCommandChirho {
    verb_chirho: NftVerbChirho,
    rendered_chirho: String,
}

impl NftCommandChirho {
    pub fn verb_chirho(&self) -> NftVerbChirho {
        self.verb_chirho
    }

    /// The exact `nft` argument line, e.g. `add rule ip filter <chain> ip daddr 10.100.0.7 tcp dport
    /// 8300 drop`.
    pub fn rendered_chirho(&self) -> &str {
        &self.rendered_chirho
    }
}

/// A process signal step for HungDriver mode. This is DATA the executor maps to a real signal; this
/// crate sends nothing. NetworkPartition mode produces none of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessControlStepChirho {
    /// Stop the named process for at most `max_paused_chirho` — the paired [`Self::SigcontChirho`] in
    /// cleanup is the mandatory release.
    SigstopChirho {
        process_match_chirho: String,
        max_paused_chirho: Duration,
    },
    /// Resume the named process. Always present in a HungDriver plan's cleanup, so the stop is
    /// self-releasing on heal, timeout, OR refusal.
    SigcontChirho { process_match_chirho: String },
}

/// The chain names a drill owns, derived from the subject's sanitised label. For item 6's single
/// former-owner drill this is unambiguous; concurrent drills on DISTINCT subjects whose labels sanitise
/// to the SAME token (e.g. `boaz-1` vs `boaz+1`, or two all-symbol labels via the `unnamed` fallback)
/// would share chain names — moot while exactly one former owner is partitioned at a time, and closable
/// by deriving the token from the validated overlay address (reviewer F2, 2026-08-09).
#[derive(Debug, Clone, PartialEq, Eq)]
struct DrillChainNamesChirho {
    ingress_chirho: String,
    egress_chirho: String,
}

/// A fully generated, admitted partition plan: the ordered setup rules, the teardown that reverses
/// exactly the armed rules, the process-control steps for both arm and cleanup, and the bounded
/// deadline. Everything here is data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedPartitionPlanChirho {
    subject_chirho: PartitionSubjectChirho,
    mode_chirho: HostedPartitionModeChirho,
    setup_chirho: Vec<NftCommandChirho>,
    teardown_chirho: Vec<NftCommandChirho>,
    process_arm_chirho: Vec<ProcessControlStepChirho>,
    process_cleanup_chirho: Vec<ProcessControlStepChirho>,
    deadline_chirho: Duration,
}

impl HostedPartitionPlanChirho {
    pub fn subject_chirho(&self) -> &PartitionSubjectChirho {
        &self.subject_chirho
    }
    pub fn mode_chirho(&self) -> HostedPartitionModeChirho {
        self.mode_chirho
    }
    pub fn setup_chirho(&self) -> &[NftCommandChirho] {
        &self.setup_chirho
    }
    pub fn teardown_chirho(&self) -> &[NftCommandChirho] {
        &self.teardown_chirho
    }
    pub fn process_arm_chirho(&self) -> &[ProcessControlStepChirho] {
        &self.process_arm_chirho
    }
    pub fn process_cleanup_chirho(&self) -> &[ProcessControlStepChirho] {
        &self.process_cleanup_chirho
    }
    pub fn deadline_chirho(&self) -> Duration {
        self.deadline_chirho
    }

    /// Every rendered nft line across setup AND teardown, for the scans that prove the structural
    /// floor (no INPUT/OUTPUT base chain, no port 22, no shell escape, allowlisted verbs only).
    pub fn all_rendered_lines_chirho(&self) -> Vec<&str> {
        self.setup_chirho
            .iter()
            .chain(self.teardown_chirho.iter())
            .map(|command_chirho| command_chirho.rendered_chirho())
            .collect()
    }

    /// The teardown for `label_chirho`, refusing if it is not this plan's armed subject. This is the
    /// subject-bound admission on the CLEANUP side: a neighbour cannot borrow a partition armed for
    /// the former owner (mirror of the barrier's `UnknownNodeChirho`).
    pub fn teardown_for_subject_chirho(
        &self,
        label_chirho: &str,
    ) -> Result<Vec<NftCommandChirho>, HostedPartitionRefusalChirho> {
        if label_chirho != self.subject_chirho.former_owner_label_chirho {
            return Err(HostedPartitionRefusalChirho::SubjectMismatchChirho {
                armed_chirho: self.subject_chirho.former_owner_label_chirho.clone(),
                requested_chirho: label_chirho.to_owned(),
            });
        }
        Ok(self.teardown_chirho.clone())
    }
}

/// Sanitise a subject label to the nft identifier charset `[a-z0-9_]`, so the caller's label can
/// never carry a metacharacter into a chain name. Non-matching bytes become `_`.
fn sanitise_label_chirho(label_chirho: &str) -> String {
    let sanitised_chirho: String = label_chirho
        .chars()
        .map(|character_chirho| {
            if character_chirho.is_ascii_alphanumeric() {
                character_chirho.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    if sanitised_chirho.is_empty() {
        "unnamed".to_owned()
    } else {
        sanitised_chirho
    }
}

/// The drill chain names for a subject. Underscore-separated because nft identifiers are not kebab —
/// an external-mandated form the style guide exempts, still Chirho-suffixed.
fn drill_chain_names_chirho(subject_chirho: &PartitionSubjectChirho) -> DrillChainNamesChirho {
    let token_chirho = sanitise_label_chirho(&subject_chirho.former_owner_label_chirho);
    DrillChainNamesChirho {
        ingress_chirho: format!("cairn_drill_partition_ingress_{token_chirho}_chirho"),
        egress_chirho: format!("cairn_drill_partition_egress_{token_chirho}_chirho"),
    }
}

/// The teardown rule set for a pair of drill chains: flush both (so they are empty and deletable),
/// then delete both. Reverse of the arm's chain-and-rule creation, and it names ONLY the drill's own
/// chains — never the real `INPUT`/`OUTPUT` base chains.
fn teardown_commands_chirho(chains_chirho: &DrillChainNamesChirho) -> Vec<NftCommandChirho> {
    vec![
        NftCommandChirho {
            verb_chirho: NftVerbChirho::FlushChainChirho,
            rendered_chirho: format!(
                "flush chain {NFT_FAMILY_CHIRHO} {NFT_TABLE_CHIRHO} {}",
                chains_chirho.egress_chirho
            ),
        },
        NftCommandChirho {
            verb_chirho: NftVerbChirho::FlushChainChirho,
            rendered_chirho: format!(
                "flush chain {NFT_FAMILY_CHIRHO} {NFT_TABLE_CHIRHO} {}",
                chains_chirho.ingress_chirho
            ),
        },
        NftCommandChirho {
            verb_chirho: NftVerbChirho::DeleteChainChirho,
            rendered_chirho: format!(
                "delete chain {NFT_FAMILY_CHIRHO} {NFT_TABLE_CHIRHO} {}",
                chains_chirho.egress_chirho
            ),
        },
        NftCommandChirho {
            verb_chirho: NftVerbChirho::DeleteChainChirho,
            rendered_chirho: format!(
                "delete chain {NFT_FAMILY_CHIRHO} {NFT_TABLE_CHIRHO} {}",
                chains_chirho.ingress_chirho
            ),
        },
    ]
}

/// Resolve the request's planes into one port per [`OverlayPlaneChirho::ALL_CHIRHO`] plane, refusing a
/// missing or duplicated plane (A2), a duplicate, or a port-22 plane.
fn resolve_planes_chirho(
    planes_chirho: &[OverlayPlanePortChirho],
) -> Result<[(OverlayPlaneChirho, u16); 3], HostedPartitionRefusalChirho> {
    if planes_chirho.is_empty() {
        return Err(HostedPartitionRefusalChirho::NoPlanesRegisteredChirho);
    }
    let mut resolved_chirho: [Option<u16>; 3] = [None; 3];
    for entry_chirho in planes_chirho {
        if entry_chirho.port_chirho == SSH_PORT_CHIRHO {
            return Err(HostedPartitionRefusalChirho::PortTwentyTwoRefusedChirho {
                plane_chirho: entry_chirho.plane_chirho,
            });
        }
        let index_chirho = OverlayPlaneChirho::ALL_CHIRHO
            .iter()
            .position(|plane_chirho| *plane_chirho == entry_chirho.plane_chirho)
            .expect("every OverlayPlaneChirho is in ALL_CHIRHO");
        if resolved_chirho[index_chirho].is_some() {
            return Err(HostedPartitionRefusalChirho::DuplicatePlaneChirho {
                plane_chirho: entry_chirho.plane_chirho,
            });
        }
        resolved_chirho[index_chirho] = Some(entry_chirho.port_chirho);
    }
    let missing_chirho: Vec<OverlayPlaneChirho> = OverlayPlaneChirho::ALL_CHIRHO
        .iter()
        .zip(resolved_chirho.iter())
        .filter(|(_plane_chirho, port_chirho)| port_chirho.is_none())
        .map(|(plane_chirho, _port_chirho)| *plane_chirho)
        .collect();
    if !missing_chirho.is_empty() {
        return Err(HostedPartitionRefusalChirho::PlaneIncompleteChirho { missing_chirho });
    }
    Ok([
        (
            OverlayPlaneChirho::ALL_CHIRHO[0],
            resolved_chirho[0].expect("plane 0 present"),
        ),
        (
            OverlayPlaneChirho::ALL_CHIRHO[1],
            resolved_chirho[1].expect("plane 1 present"),
        ),
        (
            OverlayPlaneChirho::ALL_CHIRHO[2],
            resolved_chirho[2].expect("plane 2 present"),
        ),
    ])
}

/// True if the address sits inside the `10.100.0.0/24` overlay.
fn is_overlay_addr_chirho(addr_chirho: Ipv4Addr) -> bool {
    let octets_chirho = addr_chirho.octets();
    octets_chirho[0] == OVERLAY_PREFIX_CHIRHO[0]
        && octets_chirho[1] == OVERLAY_PREFIX_CHIRHO[1]
        && octets_chirho[2] == OVERLAY_PREFIX_CHIRHO[2]
}

/// True if `value_chirho` is a single clean process-NAME token: non-empty and drawn only from
/// `[A-Za-z0-9._-]`. This is deliberately stricter than "carries no shell metacharacter": the
/// executor resolves the former owner's process with exact-name matching (`pgrep -x`), never a
/// full-cmdline `-f`, so a space or `;` is not just an injection risk but a wrong match. It is the
/// elector deploy's own stop-chirho lesson — use exact process-name matching where identity is the
/// question — applied at generation time so the executor is handed a token it can trust.
fn is_clean_process_token_chirho(value_chirho: &str) -> bool {
    !value_chirho.is_empty()
        && value_chirho.chars().all(|character_chirho| {
            character_chirho.is_ascii_alphanumeric() || matches!(character_chirho, '.' | '_' | '-')
        })
}

/// Generate the partition plan for a request, or refuse it. PURE: no host, no socket, no process — it
/// returns data. This is the whole admission contract, mirroring the 6.1 barrier's `arm_chirho`, and
/// it is where the lawful shape is enforced before a drill can draw a conclusion from a cut that was
/// never real.
pub fn plan_partition_chirho(
    request_chirho: &HostedPartitionRequestChirho,
) -> Result<HostedPartitionPlanChirho, HostedPartitionRefusalChirho> {
    // C2: test-kind allowlist.
    if !request_chirho
        .target_kind_chirho
        .is_blessed_test_kind_chirho()
    {
        return Err(HostedPartitionRefusalChirho::NonTestTargetRefusedChirho {
            target_kind_chirho: request_chirho.target_kind_chirho,
        });
    }
    // Subject must live on the overlay this drill partitions.
    if !is_overlay_addr_chirho(
        request_chirho
            .subject_chirho
            .former_owner_overlay_addr_chirho,
    ) {
        return Err(HostedPartitionRefusalChirho::SubjectNotOverlayChirho {
            addr_chirho: request_chirho
                .subject_chirho
                .former_owner_overlay_addr_chirho,
        });
    }
    // Property 1: both directions, symmetric. A request that declared fewer than both is a
    // half-partition and is refused before anything is generated.
    let has_ingress_chirho = request_chirho
        .directions_chirho
        .contains(&PartitionDirectionChirho::IngressChirho);
    let has_egress_chirho = request_chirho
        .directions_chirho
        .contains(&PartitionDirectionChirho::EgressChirho);
    if !(has_ingress_chirho && has_egress_chirho) {
        return Err(HostedPartitionRefusalChirho::OneDirectionOnlyChirho {
            subject_label_chirho: request_chirho
                .subject_chirho
                .former_owner_label_chirho
                .clone(),
        });
    }
    // A2: all three planes, exactly once, none on port 22.
    let planes_chirho = resolve_planes_chirho(&request_chirho.planes_chirho)?;
    // C4: bounded lifetime.
    if request_chirho.lifetime_chirho.is_zero()
        || request_chirho.lifetime_chirho > MAX_PARTITION_LIFETIME_CHIRHO
    {
        return Err(HostedPartitionRefusalChirho::LifetimeUnboundedChirho {
            requested_chirho: request_chirho.lifetime_chirho,
            max_chirho: MAX_PARTITION_LIFETIME_CHIRHO,
        });
    }
    // Property 2: the mode's extra inputs. HungDriver's SIGSTOP must be bounded and its process match
    // clean; NetworkPartition carries neither.
    let (process_arm_chirho, process_cleanup_chirho) = match &request_chirho.mode_chirho {
        HostedPartitionModeSpecChirho::NetworkPartitionChirho => (Vec::new(), Vec::new()),
        HostedPartitionModeSpecChirho::HungDriverChirho {
            process_match_chirho,
            max_paused_chirho,
        } => {
            if process_match_chirho.trim().is_empty() {
                return Err(
                    HostedPartitionRefusalChirho::HungDriverProcessInvalidChirho {
                        detail_chirho: "process match is empty".to_owned(),
                    },
                );
            }
            if !is_clean_process_token_chirho(process_match_chirho) {
                return Err(
                    HostedPartitionRefusalChirho::HungDriverProcessInvalidChirho {
                        detail_chirho: "process match must be a single [A-Za-z0-9._-] token"
                            .to_owned(),
                    },
                );
            }
            if max_paused_chirho.is_zero()
                || *max_paused_chirho > MAX_HUNG_DRIVER_PAUSE_CHIRHO
                || *max_paused_chirho > request_chirho.lifetime_chirho
            {
                let bound_chirho = if MAX_HUNG_DRIVER_PAUSE_CHIRHO < request_chirho.lifetime_chirho
                {
                    MAX_HUNG_DRIVER_PAUSE_CHIRHO
                } else {
                    request_chirho.lifetime_chirho
                };
                return Err(
                    HostedPartitionRefusalChirho::HungDriverPauseUnboundedChirho {
                        requested_chirho: *max_paused_chirho,
                        max_chirho: bound_chirho,
                    },
                );
            }
            (
                vec![ProcessControlStepChirho::SigstopChirho {
                    process_match_chirho: process_match_chirho.clone(),
                    max_paused_chirho: *max_paused_chirho,
                }],
                // The MANDATORY paired resume: always in cleanup, so the stop is self-releasing.
                vec![ProcessControlStepChirho::SigcontChirho {
                    process_match_chirho: process_match_chirho.clone(),
                }],
            )
        }
    };

    let chains_chirho = drill_chain_names_chirho(&request_chirho.subject_chirho);
    let addr_chirho = request_chirho
        .subject_chirho
        .former_owner_overlay_addr_chirho;
    let mut setup_chirho = Vec::new();
    // Idempotent shared ensure — the same `add table` the firewall arm uses. NOT reversed at
    // teardown: the drill does not own the shared `filter` table, only its own chains.
    setup_chirho.push(NftCommandChirho {
        verb_chirho: NftVerbChirho::AddTableChirho,
        rendered_chirho: format!("add table {NFT_FAMILY_CHIRHO} {NFT_TABLE_CHIRHO}"),
    });
    // The drill's OWN base chains. `policy accept` means they can only drop what their explicit rules
    // match; nothing else is affected, and the real INPUT/OUTPUT chains and their policy are never
    // named. Ingress hooks `input` (peers → former owner); egress hooks `output` (former owner →
    // peers).
    setup_chirho.push(NftCommandChirho {
        verb_chirho: NftVerbChirho::AddChainChirho,
        rendered_chirho: format!(
            "add chain {NFT_FAMILY_CHIRHO} {NFT_TABLE_CHIRHO} {} \
             {{ type filter hook input priority filter ; policy accept ; }}",
            chains_chirho.ingress_chirho
        ),
    });
    setup_chirho.push(NftCommandChirho {
        verb_chirho: NftVerbChirho::AddChainChirho,
        rendered_chirho: format!(
            "add chain {NFT_FAMILY_CHIRHO} {NFT_TABLE_CHIRHO} {} \
             {{ type filter hook output priority filter ; policy accept ; }}",
            chains_chirho.egress_chirho
        ),
    });
    // Property 1 rendered: an ingress DROP and an egress DROP for EVERY plane, both naming the exact
    // subject address. Ingress matches the subject as destination; egress matches it as source.
    for (_plane_chirho, port_chirho) in planes_chirho {
        setup_chirho.push(NftCommandChirho {
            verb_chirho: NftVerbChirho::AddRuleChirho,
            rendered_chirho: format!(
                "add rule {NFT_FAMILY_CHIRHO} {NFT_TABLE_CHIRHO} {} ip daddr {addr_chirho} tcp \
                 dport {port_chirho} drop",
                chains_chirho.ingress_chirho
            ),
        });
    }
    for (_plane_chirho, port_chirho) in planes_chirho {
        setup_chirho.push(NftCommandChirho {
            verb_chirho: NftVerbChirho::AddRuleChirho,
            rendered_chirho: format!(
                "add rule {NFT_FAMILY_CHIRHO} {NFT_TABLE_CHIRHO} {} ip saddr {addr_chirho} tcp \
                 dport {port_chirho} drop",
                chains_chirho.egress_chirho
            ),
        });
    }

    Ok(HostedPartitionPlanChirho {
        subject_chirho: request_chirho.subject_chirho.clone(),
        mode_chirho: request_chirho.mode_chirho.mode_chirho(),
        setup_chirho,
        teardown_chirho: teardown_commands_chirho(&chains_chirho),
        process_arm_chirho,
        process_cleanup_chirho,
        deadline_chirho: request_chirho.lifetime_chirho,
    })
}

#[cfg(test)]
mod tests_chirho;
