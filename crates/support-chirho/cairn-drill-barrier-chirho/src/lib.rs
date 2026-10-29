// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Reversible loopback transport barrier for item-6 drills: cut a node off, heal it, prove which.
//!
//! # WHAT MAKES THIS BLESSED
//!
//! A control plane that can partition a cluster is exactly the kind of capability app/DAG code must
//! never touch, so the argument has to be structural rather than a promise in a comment. Four things
//! carry it, and each is independently checkable:
//!
//! 1. **NO PRODUCTION EDGE.** This crate is consumed only through `[dev-dependencies]`, the same
//!    shape the workspace already uses for `cairn-ledger-sim-chirho`'s fault injection. A normal
//!    dependency from any production crate is a defect, and
//!    `drill_barrier_stays_a_dev_only_edge_chirho` in the source-scan suite fires on one.
//! 2. **UNREACHABLE BY CONSTRUCTION FROM APPS.** App/DAG code is guest WASM that reaches the world
//!    only through blessed effect modules; it cannot name a host crate at all. This crate adds no
//!    blessed module and no effect primitive, so it opens no route inward.
//! 3. **FIXED REVIEWED VERBS.** The surface is exactly `arm_chirho`, `disconnect_chirho`,
//!    `heal_chirho`, `status_chirho`, `cleanup_chirho`. There is no "run arbitrary command", no
//!    firewall call, no sleep grant, and no scheduler control. The barrier moves loopback bytes and
//!    flips flags the caller already owns.
//! 4. **BOUNDED LIFETIME.** Every armed barrier owns its listeners and pump threads and really
//!    releases them in [`DrillTransportBarrierChirho::cleanup_chirho`], which `Drop` also runs — the
//!    accept loops end and the ports become rebindable, proven by
//!    `cleanup_releases_the_bound_switch_port_chirho` rather than asserted here.
//!
//! # HEAL IS THE RESTORE; CLEANUP IS TEARDOWN. They are not two names for one thing.
//!
//! [`DrillTransportBarrierChirho::heal_chirho`] is the reversible verb a drill uses mid-run and then
//! keeps OBSERVING through: it reopens both directions and restarts a stopped tick loop, and the
//! switches stay up. [`DrillTransportBarrierChirho::cleanup_chirho`] ends the drill and dismantles
//! the switches, so traffic through a retired switch address stops for good.
//!
//! Wanting both from one verb is incoherent, and saying so is worth more than the code it explains:
//! the switches ARE the transport, so "release the ports" and "keep forwarding" cannot both hold. A
//! drill therefore heals BEFORE it observes a healed cluster, and cleans up at teardown.
//!
//! **What the failure direction actually guarantees**, stated precisely because the loose version
//! ("a forgotten barrier leaves a connected cluster") is not what a retiring barrier can promise: a
//! barrier that is dropped, panicked past, or forgotten never leaves a node ASYMMETRICALLY
//! suppressed. Every cut flag is cleared and every caller tick loop is restored, so no node is left
//! silently deaf while its peers talk on. What retirement does remove is the drill's own transport,
//! symmetrically, for every node at once — which is a torn-down drill rather than a partition.
//!
//! It is std-only on purpose: no elector, driver, ledger, storage, or signer dependency. It cannot
//! mint, append, sign, or move a ref, because it cannot name anything that does.
//!
//! # THE TWO MODES ARE DISTINCT, AND CONFLATING THEM IS THE BUG THIS CRATE EXISTS TO FIX
//!
//! The prior control ([`failback_election_chirho.rs`]'s `isolate_chirho`) closed a node's link **and**
//! stopped its tick loop in one verb. That is one specific failure — a hung driver — wearing the name
//! of the general one. The hosted cax11 evidence measured the other case and it behaves differently:
//! with packets dropped but the tick loop ALIVE, the isolated node stepped down. So:
//!
//! * [`DrillDisconnectModeChirho::NetworkPartitionChirho`] — transport cut, local driver KEEPS
//!   TICKING. The node stays awake, notices it cannot reach a quorum, and steps down on its own.
//! * [`DrillDisconnectModeChirho::HungDriverChirho`] — transport cut AND the local tick loop stopped.
//!   The node's own detector is dead, so it cannot notice or report its deposition. This is F1's
//!   lesson in transport form: *a liveness check that depends on the liveness it checks cannot report
//!   its own death.*
//!
//! A caller must name which one it wants. There is no default, because a default here would silently
//! pick one failure mode to stand for the other — the exact substitution the recon warned about.
//!
//! # WHICH PLANES THE CUT COVERS — ANSWERED BY DESIGN, and it is narrower than it sounds
//!
//! This barrier cuts **exactly the traffic the caller routed through it, in both directions, and
//! nothing else.** It has no view of write relay, replication/source traffic, or resident control
//! RPC unless those are also routed through the same barrier. Routing only elector traffic through
//! it produces a ONE-PLANE partition, which leaves the old owner informed through another plane and
//! makes a drill quietly vacuous.
//!
//! The barrier cannot verify what a caller left outside it — nothing can, from in here — so it
//! enforces the half it CAN see and refuses the rest at admission: a node must register BOTH an
//! ingress and an egress switch or [`arm_chirho`] refuses
//! [`DrillBarrierRefusalChirho::OneDirectionOnlyChirho`]. Asymmetric reachability is not a
//! partition, and this is the one place that can say so before a drill runs.
//!
//! **Why both switches are structurally necessary, measured rather than assumed.** In the prior
//! helper each node sat behind a single INGRESS switch, so closing it stopped peers reaching that
//! node — but the node's own outbound connections went straight to the peers' switches, which were
//! still open. That is why the old `isolate_chirho` had to stop the tick loop: stopping the ticker
//! was the only way to silence outbound. Which means the old helper *could not express* a live
//! network partition at all. An egress switch is what separates the two modes.
//!
//! # STILL OPEN — named, not defaulted (recon §2.3, §8)
//!
//! These are beyond this brick and this crate deliberately takes no position on them:
//!
//! * The barrier AUTHORIZATION format — which test-kind identity, effect intent/ref, owner term, and
//!   caller idempotency key arm a barrier. [`arm_chirho`] here takes transport wiring only; it mints
//!   no subject and accepts no caller-supplied authority.
//! * The OBSERVER CHANNEL — which channel stays open during a cut and how it is proven observational
//!   rather than authoritative. This crate exposes [`status_chirho`], which reports only the
//!   barrier's OWN flag state and never reads cluster state, so it cannot become that channel by
//!   accident.
//! * Evidence retention, and which raw captures stay host-private.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// How prompt a teardown is: a pump wakes at least this often to notice its link closed.
///
/// This is a RESPONSIVENESS bound, not a correctness one. A longer timeout makes teardown lazier; it
/// never makes a closed link forward bytes, because the flag is re-read after every wake.
const PUMP_WAKE_INTERVAL_CHIRHO: Duration = Duration::from_millis(50);

const PUMP_BUFFER_BYTES_CHIRHO: usize = 8192;

/// Which failure a disconnect expresses. There is no default; see the crate header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrillDisconnectModeChirho {
    /// Transport cut, local driver KEEPS TICKING — a live node that will notice and step down.
    NetworkPartitionChirho,
    /// Transport cut AND the local tick loop stopped — the detector itself is dead.
    HungDriverChirho,
}

impl DrillDisconnectModeChirho {
    /// Whether this mode stops the caller's tick loop. The ONLY place the two modes differ.
    fn stops_local_driver_chirho(self) -> bool {
        match self {
            Self::NetworkPartitionChirho => false,
            Self::HungDriverChirho => true,
        }
    }
}

/// Why a barrier operation was refused. Every arm fails CLOSED toward a connected cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrillBarrierRefusalChirho {
    /// A node registered only one direction. Asymmetric reachability is not a partition.
    OneDirectionOnlyChirho { node_label_chirho: String },
    /// Two registrations claimed the same node label; a drill that cannot name its subject
    /// unambiguously cannot prove which node it cut.
    DuplicateNodeLabelChirho { node_label_chirho: String },
    /// No node was registered at all: arming an empty barrier would report success while cutting
    /// nothing, which is the vacuous-green shape this refusal exists to prevent.
    NoNodesRegisteredChirho,
    /// An operation named a node this barrier does not own.
    UnknownNodeChirho { node_label_chirho: String },
    /// A loopback listener could not be bound while arming.
    TransportUnavailableChirho { detail_chirho: String },
    /// The barrier was already cleaned up; its switches no longer exist.
    BarrierRetiredChirho,
}

impl std::fmt::Display for DrillBarrierRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OneDirectionOnlyChirho { node_label_chirho } => write!(
                formatter_chirho,
                "drill node {node_label_chirho} registered only one direction; a partition needs \
                 both ingress and egress"
            ),
            Self::DuplicateNodeLabelChirho { node_label_chirho } => write!(
                formatter_chirho,
                "drill node label {node_label_chirho} was registered twice"
            ),
            Self::NoNodesRegisteredChirho => {
                formatter_chirho.write_str("drill barrier was armed with no nodes registered")
            }
            Self::UnknownNodeChirho { node_label_chirho } => write!(
                formatter_chirho,
                "drill barrier does not own a node labelled {node_label_chirho}"
            ),
            Self::TransportUnavailableChirho { detail_chirho } => write!(
                formatter_chirho,
                "drill barrier could not bind a loopback switch: {detail_chirho}"
            ),
            Self::BarrierRetiredChirho => {
                formatter_chirho.write_str("drill barrier was already cleaned up")
            }
        }
    }
}

impl std::error::Error for DrillBarrierRefusalChirho {}

/// One node's declared transport wiring, before the barrier is armed.
///
/// BOTH directions are required and there is no constructor that omits either: the type makes the
/// lawful shape the only expressible one, and [`DrillBarrierPlanChirho::register_ingress_only_chirho`]
/// exists solely so a test can PLANT the unlawful shape and watch admission refuse it.
pub struct DrillNodeWiringChirho {
    node_label_chirho: String,
    upstream_ingress_chirho: SocketAddr,
    egress_targets_chirho: Vec<SocketAddr>,
    local_driver_alive_chirho: Arc<AtomicBool>,
    declared_both_directions_chirho: bool,
}

/// The wiring declaration collected before arming.
#[derive(Default)]
pub struct DrillBarrierPlanChirho {
    nodes_chirho: Vec<DrillNodeWiringChirho>,
}

impl DrillBarrierPlanChirho {
    pub fn new_chirho() -> Self {
        Self::default()
    }

    /// Register one node with BOTH directions — the lawful shape.
    ///
    /// `upstream_ingress_chirho` is where this node's own server really listens; peers will be given
    /// the barrier's ingress address instead. `egress_targets_chirho` are the addresses this node
    /// dials outward; the barrier hands back one egress address per target, in the same order, and
    /// the caller must configure the node to dial THOSE.
    ///
    /// `local_driver_alive_chirho` is the caller's own tick-loop flag. The barrier only clears and
    /// restores it, and only in [`DrillDisconnectModeChirho::HungDriverChirho`]. It is required even
    /// for network-partition mode so that both modes are always expressible from one armed barrier —
    /// a barrier that could express only one of them is the conflation this crate exists to remove.
    pub fn register_node_chirho(
        mut self,
        node_label_chirho: &str,
        upstream_ingress_chirho: SocketAddr,
        egress_targets_chirho: Vec<SocketAddr>,
        local_driver_alive_chirho: Arc<AtomicBool>,
    ) -> Self {
        self.nodes_chirho.push(DrillNodeWiringChirho {
            node_label_chirho: node_label_chirho.to_owned(),
            upstream_ingress_chirho,
            egress_targets_chirho,
            local_driver_alive_chirho,
            declared_both_directions_chirho: true,
        });
        self
    }

    /// PLANT-ONLY: register a node whose egress is NOT routed through the barrier.
    ///
    /// This exists so the pre-registered one-direction-only arm can be executed against the real
    /// admission check rather than argued in prose. It is deliberately awkward to reach and its name
    /// says what it is; production drills use [`Self::register_node_chirho`].
    pub fn register_ingress_only_chirho(
        mut self,
        node_label_chirho: &str,
        upstream_ingress_chirho: SocketAddr,
        local_driver_alive_chirho: Arc<AtomicBool>,
    ) -> Self {
        self.nodes_chirho.push(DrillNodeWiringChirho {
            node_label_chirho: node_label_chirho.to_owned(),
            upstream_ingress_chirho,
            egress_targets_chirho: Vec::new(),
            local_driver_alive_chirho,
            declared_both_directions_chirho: false,
        });
        self
    }
}

/// What one node's transport looks like right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrillNodeStatusChirho {
    pub node_label_chirho: String,
    pub ingress_open_chirho: bool,
    pub egress_open_chirho: bool,
    /// `None` while connected; `Some(mode)` naming the exact disconnect currently in force.
    pub disconnect_mode_chirho: Option<DrillDisconnectModeChirho>,
    pub local_driver_alive_chirho: bool,
    /// How many disconnects this node has served. A drill that expected one cut and sees two has a
    /// different story than it thinks.
    pub disconnect_count_chirho: usize,
}

/// The barrier's whole observable state. Read-only, and derived from the barrier's OWN flags —
/// it never reads cluster or elector state, so it cannot become the observer channel by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrillBarrierStatusChirho {
    pub armed_chirho: bool,
    pub nodes_chirho: Vec<DrillNodeStatusChirho>,
}

/// Every stream a switch is currently forwarding, so a cut can tear them down SYNCHRONOUSLY.
///
/// WHY THIS EXISTS, and it is a correctness property rather than an optimisation. An earlier draft
/// relied only on the pump threads noticing their flag and shutting their own sockets down. That is
/// eventually-consistent: teardown then depends on a pump thread being SCHEDULED, and under a loaded
/// machine — a whole workspace test run, hundreds of threads — a 50ms poll can be starved long
/// enough that an "already cut" stream is still delivering. It produced an arm that passed alone and
/// intermittently failed in the full run, which is the worst kind of green.
///
/// A drill's cut must mean cut NOW, so `disconnect_chirho` shuts these sockets down itself, in the
/// caller's thread, before it returns. The pumps keep their own flag exits as a second, independent
/// stop — belt and braces on the property this whole crate exists to provide.
#[derive(Debug, Default)]
struct SwitchStreamRegistryChirho {
    live_chirho: std::sync::Mutex<Vec<TcpStream>>,
}

impl SwitchStreamRegistryChirho {
    /// Retain a forwarding stream, dropping any that are already finished so the list stays bounded
    /// by CONCURRENT connections rather than by every connection a drill ever made.
    fn retain_chirho(&self, stream_chirho: TcpStream) {
        let Ok(mut live_chirho) = self.live_chirho.lock() else {
            return;
        };
        live_chirho.retain(|existing_chirho| {
            existing_chirho
                .peer_addr()
                .map(|_addr_chirho| true)
                .unwrap_or(false)
        });
        live_chirho.push(stream_chirho);
    }

    /// Shut every retained stream down immediately, in the CALLER's thread.
    fn shutdown_all_chirho(&self) {
        let Ok(mut live_chirho) = self.live_chirho.lock() else {
            return;
        };
        for stream_chirho in live_chirho.drain(..) {
            let _ = stream_chirho.shutdown(Shutdown::Both);
        }
    }
}

#[derive(Debug)]
struct ArmedNodeChirho {
    node_label_chirho: String,
    ingress_open_chirho: Arc<AtomicBool>,
    egress_open_chirho: Arc<AtomicBool>,
    local_driver_alive_chirho: Arc<AtomicBool>,
    ingress_addr_chirho: SocketAddr,
    egress_addrs_chirho: Vec<SocketAddr>,
    disconnect_mode_chirho: Option<DrillDisconnectModeChirho>,
    disconnect_count_chirho: Arc<AtomicUsize>,
    /// One registry per node, shared by that node's ingress and egress switches, so a cut tears
    /// down both directions' live streams in one synchronous sweep.
    streams_chirho: Arc<SwitchStreamRegistryChirho>,
}

/// An armed, reversible transport barrier over a set of loopback nodes.
///
/// Owns its listeners and pump threads; `cleanup_chirho` (and `Drop`) heals everything and retires
/// the switches. The failure direction is a CONNECTED cluster: a barrier that is dropped, panicked
/// past, or forgotten leaves nothing cut.
#[derive(Debug)]
pub struct DrillTransportBarrierChirho {
    nodes_chirho: Vec<ArmedNodeChirho>,
    retired_chirho: bool,
    /// Cleared by `cleanup_chirho`, which is what actually ENDS the accept loops and releases the
    /// bound ports. Without it, retiring would flip flags while every listener stayed bound and
    /// every accept thread stayed alive until process exit — a leak that accumulates one port per
    /// switch per drill across a suite, and a doc claim the code did not carry.
    switches_live_chirho: Arc<AtomicBool>,
}

/// Arm a barrier from a wiring plan, binding one ingress switch and one egress switch per node.
///
/// Admission is where the lawful shape is enforced, because it is the last moment before a drill can
/// draw a conclusion from a cut that was never real.
pub fn arm_chirho(
    plan_chirho: DrillBarrierPlanChirho,
) -> Result<DrillTransportBarrierChirho, DrillBarrierRefusalChirho> {
    if plan_chirho.nodes_chirho.is_empty() {
        return Err(DrillBarrierRefusalChirho::NoNodesRegisteredChirho);
    }
    let mut seen_labels_chirho: Vec<&str> = Vec::new();
    for node_chirho in &plan_chirho.nodes_chirho {
        if seen_labels_chirho.contains(&node_chirho.node_label_chirho.as_str()) {
            return Err(DrillBarrierRefusalChirho::DuplicateNodeLabelChirho {
                node_label_chirho: node_chirho.node_label_chirho.clone(),
            });
        }
        seen_labels_chirho.push(&node_chirho.node_label_chirho);
        // BOTH-DIRECTIONS ADMISSION. A node that routed no egress through the barrier can still
        // reach its peers while "cut", so the drill would measure a half-partition and report a
        // partition. Refuse before anything is bound.
        if !node_chirho.declared_both_directions_chirho
            || node_chirho.egress_targets_chirho.is_empty()
        {
            return Err(DrillBarrierRefusalChirho::OneDirectionOnlyChirho {
                node_label_chirho: node_chirho.node_label_chirho.clone(),
            });
        }
    }

    let switches_live_chirho = Arc::new(AtomicBool::new(true));
    let mut armed_chirho = Vec::new();
    for node_chirho in plan_chirho.nodes_chirho {
        let ingress_open_chirho = Arc::new(AtomicBool::new(true));
        let egress_open_chirho = Arc::new(AtomicBool::new(true));
        let streams_chirho = Arc::new(SwitchStreamRegistryChirho::default());
        let ingress_addr_chirho = spawn_switch_chirho(
            node_chirho.upstream_ingress_chirho,
            Arc::clone(&ingress_open_chirho),
            Arc::clone(&switches_live_chirho),
            Arc::clone(&streams_chirho),
        )?;
        let mut egress_addrs_chirho = Vec::new();
        for target_chirho in node_chirho.egress_targets_chirho {
            egress_addrs_chirho.push(spawn_switch_chirho(
                target_chirho,
                Arc::clone(&egress_open_chirho),
                Arc::clone(&switches_live_chirho),
                Arc::clone(&streams_chirho),
            )?);
        }
        armed_chirho.push(ArmedNodeChirho {
            node_label_chirho: node_chirho.node_label_chirho,
            ingress_open_chirho,
            egress_open_chirho,
            local_driver_alive_chirho: node_chirho.local_driver_alive_chirho,
            ingress_addr_chirho,
            egress_addrs_chirho,
            disconnect_mode_chirho: None,
            disconnect_count_chirho: Arc::new(AtomicUsize::new(0)),
            streams_chirho,
        });
    }
    Ok(DrillTransportBarrierChirho {
        nodes_chirho: armed_chirho,
        retired_chirho: false,
        switches_live_chirho,
    })
}

impl DrillTransportBarrierChirho {
    /// The address peers must dial to reach this node (its ingress switch).
    pub fn ingress_addr_chirho(
        &self,
        node_label_chirho: &str,
    ) -> Result<SocketAddr, DrillBarrierRefusalChirho> {
        Ok(self.node_chirho(node_label_chirho)?.ingress_addr_chirho)
    }

    /// The addresses this node must dial outward, in the order its egress targets were registered.
    pub fn egress_addrs_chirho(
        &self,
        node_label_chirho: &str,
    ) -> Result<Vec<SocketAddr>, DrillBarrierRefusalChirho> {
        Ok(self
            .node_chirho(node_label_chirho)?
            .egress_addrs_chirho
            .clone())
    }

    /// Cut one node off in BOTH directions, in the named mode.
    ///
    /// Ingress and egress close together — there is no verb that closes one — and the mode decides
    /// the ONE further thing that differs: whether the caller's tick loop keeps running.
    pub fn disconnect_chirho(
        &mut self,
        node_label_chirho: &str,
        mode_chirho: DrillDisconnectModeChirho,
    ) -> Result<DrillNodeStatusChirho, DrillBarrierRefusalChirho> {
        if self.retired_chirho {
            return Err(DrillBarrierRefusalChirho::BarrierRetiredChirho);
        }
        let index_chirho = self.node_index_chirho(node_label_chirho)?;
        {
            let node_chirho = &mut self.nodes_chirho[index_chirho];
            node_chirho
                .ingress_open_chirho
                .store(false, Ordering::SeqCst);
            node_chirho
                .egress_open_chirho
                .store(false, Ordering::SeqCst);
            if mode_chirho.stops_local_driver_chirho() {
                node_chirho
                    .local_driver_alive_chirho
                    .store(false, Ordering::SeqCst);
            }
            node_chirho.disconnect_mode_chirho = Some(mode_chirho);
            node_chirho
                .disconnect_count_chirho
                .fetch_add(1, Ordering::SeqCst);
            // SYNCHRONOUS TEARDOWN, in this thread, before the verb returns. The flags above stop
            // NEW connections and tell the pumps to stop; this ends the streams already in flight
            // without waiting for a pump thread to be scheduled. A cut that is only eventually
            // consistent is a cut a loaded machine can outrun.
            node_chirho.streams_chirho.shutdown_all_chirho();
        }
        Ok(self.node_status_chirho(index_chirho))
    }

    /// Restore both directions and, if this mode stopped it, the caller's tick loop.
    ///
    /// Heal is deliberately total rather than mode-specific: whatever the cut did, heal undoes. A
    /// heal that had to remember which half to restore would be one more place to get it wrong.
    pub fn heal_chirho(
        &mut self,
        node_label_chirho: &str,
    ) -> Result<DrillNodeStatusChirho, DrillBarrierRefusalChirho> {
        if self.retired_chirho {
            return Err(DrillBarrierRefusalChirho::BarrierRetiredChirho);
        }
        let index_chirho = self.node_index_chirho(node_label_chirho)?;
        {
            let node_chirho = &mut self.nodes_chirho[index_chirho];
            node_chirho
                .ingress_open_chirho
                .store(true, Ordering::SeqCst);
            node_chirho.egress_open_chirho.store(true, Ordering::SeqCst);
            node_chirho
                .local_driver_alive_chirho
                .store(true, Ordering::SeqCst);
            node_chirho.disconnect_mode_chirho = None;
        }
        Ok(self.node_status_chirho(index_chirho))
    }

    /// The barrier's own flag state. Never reads cluster, elector, or driver state.
    pub fn status_chirho(&self) -> DrillBarrierStatusChirho {
        DrillBarrierStatusChirho {
            armed_chirho: !self.retired_chirho,
            nodes_chirho: (0..self.nodes_chirho.len())
                .map(|index_chirho| self.node_status_chirho(index_chirho))
                .collect(),
        }
    }

    /// Heal everything and retire the switches. Idempotent, and `Drop` runs it.
    ///
    /// Heal-then-retire, in that order: a barrier that retired its switches while still flagged
    /// closed would leave the caller's tick loops stopped with no verb left to restore them.
    pub fn cleanup_chirho(&mut self) -> DrillBarrierStatusChirho {
        for node_chirho in &mut self.nodes_chirho {
            node_chirho
                .ingress_open_chirho
                .store(true, Ordering::SeqCst);
            node_chirho.egress_open_chirho.store(true, Ordering::SeqCst);
            node_chirho
                .local_driver_alive_chirho
                .store(true, Ordering::SeqCst);
            node_chirho.disconnect_mode_chirho = None;
        }
        // HEAL FIRST, THEN END THE SWITCHES — in that order. Clearing this flag stops every accept
        // loop and drops its listener, releasing the port; doing it before the heal above would
        // leave a caller's tick loops stopped with no verb left to restore them.
        self.switches_live_chirho.store(false, Ordering::SeqCst);
        self.retired_chirho = true;
        self.status_chirho()
    }

    fn node_index_chirho(
        &self,
        node_label_chirho: &str,
    ) -> Result<usize, DrillBarrierRefusalChirho> {
        self.nodes_chirho
            .iter()
            .position(|node_chirho| node_chirho.node_label_chirho == node_label_chirho)
            .ok_or_else(|| DrillBarrierRefusalChirho::UnknownNodeChirho {
                node_label_chirho: node_label_chirho.to_owned(),
            })
    }

    fn node_chirho(
        &self,
        node_label_chirho: &str,
    ) -> Result<&ArmedNodeChirho, DrillBarrierRefusalChirho> {
        let index_chirho = self.node_index_chirho(node_label_chirho)?;
        Ok(&self.nodes_chirho[index_chirho])
    }

    fn node_status_chirho(&self, index_chirho: usize) -> DrillNodeStatusChirho {
        let node_chirho = &self.nodes_chirho[index_chirho];
        DrillNodeStatusChirho {
            node_label_chirho: node_chirho.node_label_chirho.clone(),
            ingress_open_chirho: node_chirho.ingress_open_chirho.load(Ordering::SeqCst),
            egress_open_chirho: node_chirho.egress_open_chirho.load(Ordering::SeqCst),
            disconnect_mode_chirho: node_chirho.disconnect_mode_chirho,
            local_driver_alive_chirho: node_chirho.local_driver_alive_chirho.load(Ordering::SeqCst),
            disconnect_count_chirho: node_chirho.disconnect_count_chirho.load(Ordering::SeqCst),
        }
    }
}

impl Drop for DrillTransportBarrierChirho {
    fn drop(&mut self) {
        if !self.retired_chirho {
            let _ = self.cleanup_chirho();
        }
    }
}

/// Bind one loopback switch in front of `upstream_chirho` and return the address callers must dial.
fn spawn_switch_chirho(
    upstream_chirho: SocketAddr,
    open_chirho: Arc<AtomicBool>,
    switches_live_chirho: Arc<AtomicBool>,
    streams_chirho: Arc<SwitchStreamRegistryChirho>,
) -> Result<SocketAddr, DrillBarrierRefusalChirho> {
    let listener_chirho = TcpListener::bind("127.0.0.1:0").map_err(|error_chirho| {
        DrillBarrierRefusalChirho::TransportUnavailableChirho {
            detail_chirho: error_chirho.to_string(),
        }
    })?;
    let switch_addr_chirho = listener_chirho.local_addr().map_err(|error_chirho| {
        DrillBarrierRefusalChirho::TransportUnavailableChirho {
            detail_chirho: error_chirho.to_string(),
        }
    })?;
    // NON-BLOCKING ACCEPT is what makes retirement possible at all. A blocking `incoming()` parks
    // this thread inside the kernel with the listener still bound, so no flag could end it and the
    // port would stay held until the process died.
    listener_chirho
        .set_nonblocking(true)
        .map_err(
            |error_chirho| DrillBarrierRefusalChirho::TransportUnavailableChirho {
                detail_chirho: error_chirho.to_string(),
            },
        )?;
    std::thread::spawn(move || {
        while switches_live_chirho.load(Ordering::SeqCst) {
            let client_chirho = match listener_chirho.accept() {
                Ok((client_chirho, _peer_chirho)) => client_chirho,
                Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(PUMP_WAKE_INTERVAL_CHIRHO);
                    continue;
                }
                Err(_) => continue,
            };
            // An accepted socket can inherit the listener's non-blocking mode depending on platform,
            // and the pumps below rely on a blocking read with a timeout. Restore it explicitly
            // rather than depending on which platform this runs on.
            let _ = client_chirho.set_nonblocking(false);
            // CLOSED MEANS CLOSED ON ARRIVAL. Refusing only future connections is not a partition:
            // an HTTP client keeps its connection alive, so an already-established stream would keep
            // delivering and the "isolated" node would quietly stay current. That exact mistake
            // produced a passing-but-meaningless run of the prior drill.
            if !open_chirho.load(Ordering::SeqCst) {
                drop(client_chirho);
                continue;
            }
            let Ok(server_chirho) = TcpStream::connect(upstream_chirho) else {
                continue;
            };
            let (Ok(client_copy_chirho), Ok(server_copy_chirho)) =
                (client_chirho.try_clone(), server_chirho.try_clone())
            else {
                continue;
            };
            // Retain BOTH halves: a synchronous cut must be able to end the stream from either
            // side, and shutting only the client half would leave the upstream server's side of a
            // forwarded connection lingering.
            for retained_chirho in [&client_chirho, &server_chirho] {
                if let Ok(retained_chirho) = retained_chirho.try_clone() {
                    streams_chirho.retain_chirho(retained_chirho);
                }
            }
            for (from_chirho, to_chirho) in [
                (client_copy_chirho, server_copy_chirho),
                (server_chirho, client_chirho),
            ] {
                let open_for_pump_chirho = Arc::clone(&open_chirho);
                let live_for_pump_chirho = Arc::clone(&switches_live_chirho);
                std::thread::spawn(move || {
                    pump_until_closed_chirho(
                        from_chirho,
                        to_chirho,
                        open_for_pump_chirho,
                        live_for_pump_chirho,
                    )
                });
            }
        }
    });
    Ok(switch_addr_chirho)
}

/// Copy one direction, abandoning the stream as soon as the link closes.
///
/// The short read timeout is what makes teardown prompt: without it a pump would block in `read`
/// until the peer gave up, and an "already cut" link would keep an established stream alive.
fn pump_until_closed_chirho(
    mut from_chirho: TcpStream,
    mut to_chirho: TcpStream,
    open_chirho: Arc<AtomicBool>,
    switches_live_chirho: Arc<AtomicBool>,
) {
    let _ = from_chirho.set_read_timeout(Some(PUMP_WAKE_INTERVAL_CHIRHO));
    let mut buffer_chirho = [0_u8; PUMP_BUFFER_BYTES_CHIRHO];
    loop {
        // Two independent exits, and they mean different things: `open` is the reversible CUT, and
        // `switches_live` is the barrier's RETIREMENT. A pump that watched only `open` would
        // outlive `cleanup_chirho` for as long as its peer held the connection.
        if !open_chirho.load(Ordering::SeqCst) || !switches_live_chirho.load(Ordering::SeqCst) {
            break;
        }
        match from_chirho.read(&mut buffer_chirho) {
            Ok(0) => break,
            Ok(read_chirho) => {
                // Re-check AFTER the read: a link that closed while this pump was blocked must not
                // deliver the bytes it was already holding. Without this the barrier would leak one
                // buffer's worth of traffic across every cut.
                if !open_chirho.load(Ordering::SeqCst) {
                    break;
                }
                if to_chirho.write_all(&buffer_chirho[..read_chirho]).is_err() {
                    break;
                }
            }
            Err(error_chirho)
                if matches!(
                    error_chirho.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
    }
    let _ = from_chirho.shutdown(Shutdown::Both);
    let _ = to_chirho.shutdown(Shutdown::Both);
}

#[cfg(test)]
mod tests_chirho;
