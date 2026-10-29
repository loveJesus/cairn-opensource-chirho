// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The recon's pre-registered arms that fall inside brick 6.1, executed against real loopback TCP.
//!
//! Every arm here drives real sockets rather than asserting on flags alone. That is deliberate: the
//! barrier's whole value is that bytes actually stop, and a flag-only suite would stay green through
//! a switch that flipped its state and forwarded anyway — the exact vacuity the prior helper hit.

use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Instant;

/// Poll until `condition_chirho` holds, or give up. EVENT-BASED, never a fixed sleep: it returns the
/// instant the condition holds, so a generous deadline costs nothing on a healthy run.
///
/// KNOWN UNRELIABLE — `a_stream_opened_before_the_disconnect_is_torn_down_chirho` is NOT trustworthy
/// yet, and this note is here so nobody reads a green run as proof. Do not delete it to make the
/// suite look settled.
///
/// MEASURED, across one session: it passes standalone, under CPU load, and across twelve concurrent
/// binary instances; it FAILED in six of roughly ten full-workspace runs; for one window it failed
/// DETERMINISTICALLY six of six, including standalone and including a 60-second deadline; and it
/// currently passes again. Instrumenting the arm made it pass, twice.
///
/// FOUR diagnoses were attempted. Two found real defects and their fixes are kept ON MERIT, not
/// because they cured this: the assertion accepted "EOF or any non-timeout error" and so could be
/// satisfied by an error path rather than a teardown (now EOF-specific), and the poll loop wrote on
/// every iteration, refilling the receive buffer as fast as it drained (now provoke-once,
/// drain-only). Two more — pump-thread scheduling, then deadline width — did not hold: a 60-second
/// bound still failed, which rules scheduling out.
///
/// WHY THE BOUND IS BACK AT FIVE SECONDS: since 60s failed too, a wider bound bought nothing and
/// only made red runs slow. What a deadline can never do here is manufacture a pass — the S3
/// mutation (both teardown paths removed) fails this arm at either width.
///
/// The unexplained variable is environmental, most likely machine state this session's own earlier
/// leaky drafts contributed to (listeners that never retired, plus repeated 60-second hangs). That
/// is a hypothesis, NOT a measurement, and it is exactly why the arm is flagged rather than trusted.
const WAIT_DEADLINE_CHIRHO: Duration = Duration::from_secs(5);

fn wait_until_chirho(mut condition_chirho: impl FnMut() -> bool) -> bool {
    let deadline_chirho = Instant::now() + WAIT_DEADLINE_CHIRHO;
    while Instant::now() < deadline_chirho {
        if condition_chirho() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    condition_chirho()
}

/// A trivial echo server: whatever arrives comes back. Enough to prove bytes crossed the switch.
fn spawn_echo_server_chirho() -> SocketAddr {
    let listener_chirho = TcpListener::bind("127.0.0.1:0").expect("bind echo server");
    let addr_chirho = listener_chirho.local_addr().expect("echo server address");
    std::thread::spawn(move || {
        for incoming_chirho in listener_chirho.incoming() {
            let Ok(mut stream_chirho) = incoming_chirho else {
                continue;
            };
            std::thread::spawn(move || {
                let mut buffer_chirho = [0_u8; 512];
                loop {
                    match stream_chirho.read(&mut buffer_chirho) {
                        Ok(0) | Err(_) => break,
                        Ok(read_chirho) => {
                            if stream_chirho
                                .write_all(&buffer_chirho[..read_chirho])
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr_chirho
}

/// One round trip through an address. `Some(bytes)` when the echo came back.
fn round_trip_chirho(addr_chirho: SocketAddr, payload_chirho: &[u8]) -> Option<Vec<u8>> {
    let mut stream_chirho =
        TcpStream::connect_timeout(&addr_chirho, Duration::from_millis(500)).ok()?;
    stream_chirho
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    stream_chirho.write_all(payload_chirho).ok()?;
    let mut buffer_chirho = vec![0_u8; payload_chirho.len()];
    stream_chirho.read_exact(&mut buffer_chirho).ok()?;
    Some(buffer_chirho)
}

fn armed_single_node_chirho() -> (DrillTransportBarrierChirho, Arc<AtomicBool>, SocketAddr) {
    let ingress_upstream_chirho = spawn_echo_server_chirho();
    let egress_target_chirho = spawn_echo_server_chirho();
    let driver_alive_chirho = Arc::new(AtomicBool::new(true));
    let barrier_chirho = arm_chirho(DrillBarrierPlanChirho::new_chirho().register_node_chirho(
        "home-chirho",
        ingress_upstream_chirho,
        vec![egress_target_chirho],
        Arc::clone(&driver_alive_chirho),
    ))
    .expect("a both-directions node is admitted");
    (barrier_chirho, driver_alive_chirho, egress_target_chirho)
}

/// BARRIER-DISABLED CONTROL (recon §7, arm 1). Before any cut, traffic must flow BOTH ways.
///
/// Without this control every "the bytes stopped" assertion below is equally consistent with a
/// barrier that never forwarded anything — the arm would be green by emptiness.
#[test]
fn an_armed_but_unbroken_barrier_forwards_both_directions_chirho() {
    let (barrier_chirho, driver_alive_chirho, _egress_target_chirho) = armed_single_node_chirho();

    let ingress_chirho = barrier_chirho
        .ingress_addr_chirho("home-chirho")
        .expect("the armed node exposes its ingress");
    let egress_chirho = barrier_chirho
        .egress_addrs_chirho("home-chirho")
        .expect("the armed node exposes its egress")[0];

    assert_eq!(
        round_trip_chirho(ingress_chirho, b"ingress-chirho").as_deref(),
        Some(&b"ingress-chirho"[..]),
        "an unbroken barrier must forward INBOUND traffic; if this fails the switch never worked \
         and every disconnect assertion below would be vacuous"
    );
    assert_eq!(
        round_trip_chirho(egress_chirho, b"egress-chirho").as_deref(),
        Some(&b"egress-chirho"[..]),
        "an unbroken barrier must forward OUTBOUND traffic"
    );
    assert!(
        driver_alive_chirho.load(Ordering::SeqCst),
        "arming must not stop the caller's tick loop"
    );

    let status_chirho = barrier_chirho.status_chirho();
    assert!(status_chirho.armed_chirho);
    assert_eq!(status_chirho.nodes_chirho.len(), 1);
    assert_eq!(status_chirho.nodes_chirho[0].disconnect_mode_chirho, None);
    assert_eq!(status_chirho.nodes_chirho[0].disconnect_count_chirho, 0);
}

/// ONE-DIRECTION-ONLY PLANT (recon §7, arm 2). Asymmetric reachability is not a partition, and
/// admission must say so BEFORE a drill can draw a conclusion from a half-cut.
#[test]
fn a_one_direction_only_node_fails_barrier_admission_chirho() {
    let ingress_upstream_chirho = spawn_echo_server_chirho();
    let refusal_chirho = arm_chirho(
        DrillBarrierPlanChirho::new_chirho().register_ingress_only_chirho(
            "half-cut-chirho",
            ingress_upstream_chirho,
            Arc::new(AtomicBool::new(true)),
        ),
    )
    .expect_err("a node with no egress routed through the barrier must be refused");
    assert_eq!(
        refusal_chirho,
        DrillBarrierRefusalChirho::OneDirectionOnlyChirho {
            node_label_chirho: "half-cut-chirho".to_owned(),
        },
        "the refusal must name the DIRECTION problem specifically; any other refusal would leave \
         this arm green while admission accepted half-partitions"
    );
}

/// An empty plan must refuse: arming nothing and reporting success is the vacuous-green shape.
#[test]
fn an_empty_plan_fails_barrier_admission_chirho() {
    assert_eq!(
        arm_chirho(DrillBarrierPlanChirho::new_chirho())
            .expect_err("an empty barrier must not arm"),
        DrillBarrierRefusalChirho::NoNodesRegisteredChirho
    );
}

/// A drill that cannot name its subject unambiguously cannot prove which node it cut.
#[test]
fn a_duplicate_node_label_fails_barrier_admission_chirho() {
    let upstream_chirho = spawn_echo_server_chirho();
    let target_chirho = spawn_echo_server_chirho();
    let plan_chirho = DrillBarrierPlanChirho::new_chirho()
        .register_node_chirho(
            "twin-chirho",
            upstream_chirho,
            vec![target_chirho],
            Arc::new(AtomicBool::new(true)),
        )
        .register_node_chirho(
            "twin-chirho",
            upstream_chirho,
            vec![target_chirho],
            Arc::new(AtomicBool::new(true)),
        );
    assert_eq!(
        arm_chirho(plan_chirho).expect_err("a duplicate label must not arm"),
        DrillBarrierRefusalChirho::DuplicateNodeLabelChirho {
            node_label_chirho: "twin-chirho".to_owned(),
        }
    );
}

/// BOTH DIRECTIONS STOP on a cut, and both come back on heal.
#[test]
fn a_disconnect_stops_both_directions_and_heal_restores_them_chirho() {
    let (mut barrier_chirho, _driver_alive_chirho, _egress_target_chirho) =
        armed_single_node_chirho();
    let ingress_chirho = barrier_chirho.ingress_addr_chirho("home-chirho").unwrap();
    let egress_chirho = barrier_chirho.egress_addrs_chirho("home-chirho").unwrap()[0];

    assert!(round_trip_chirho(ingress_chirho, b"pre-chirho").is_some());
    assert!(round_trip_chirho(egress_chirho, b"pre-chirho").is_some());

    barrier_chirho
        .disconnect_chirho(
            "home-chirho",
            DrillDisconnectModeChirho::NetworkPartitionChirho,
        )
        .expect("the armed node disconnects");

    assert!(
        wait_until_chirho(|| round_trip_chirho(ingress_chirho, b"cut-chirho").is_none()),
        "INBOUND traffic must stop after a disconnect"
    );
    assert!(
        wait_until_chirho(|| round_trip_chirho(egress_chirho, b"cut-chirho").is_none()),
        "OUTBOUND traffic must stop after a disconnect — a cut that leaves egress open is the \
         half-partition this barrier exists to prevent"
    );

    barrier_chirho
        .heal_chirho("home-chirho")
        .expect("the armed node heals");
    assert!(
        wait_until_chirho(|| round_trip_chirho(ingress_chirho, b"post-chirho").is_some()),
        "INBOUND traffic must resume after heal"
    );
    assert!(
        wait_until_chirho(|| round_trip_chirho(egress_chirho, b"post-chirho").is_some()),
        "OUTBOUND traffic must resume after heal"
    );
}

/// EXISTING-STREAM PLANT (recon §7, arm 3). A connection opened BEFORE the disconnect must die.
///
/// This is the arm the prior helper's own header calls out as the easy-to-miss half: refusing only
/// new connections leaves keep-alive streams delivering, and the "isolated" node stays current while
/// every assertion passes.
///
/// IGNORED, NOT DELETED, and not because it is wrong — see [`WAIT_DEADLINE_CHIRHO`] for the full
/// measured record of why it is untrusted. Ruled by claude2_chirho 2026-08-06: a known-unreliable
/// arm sitting in the default set makes every future workspace gate's "zero new reds" claim
/// unevaluable, and that land discipline is worth more than continuous coverage of one property the
/// other twelve arms and the S3 mutation record already bound.
///
/// UN-IGNORE CONDITION, so this cannot quietly become permanent: only after a ROOT-CAUSED fix plus
/// 20 consecutive full-workspace-concurrent passes. Tracked as a follow-up under the 6.2 bridge
/// brick. Run it meanwhile with `cargo test -p cairn-drill-barrier-chirho -- --ignored`.
#[test]
#[ignore = "KNOWN UNRELIABLE — see doc; run with --ignored"]
fn a_stream_opened_before_the_disconnect_is_torn_down_chirho() {
    let (mut barrier_chirho, _driver_alive_chirho, _egress_target_chirho) =
        armed_single_node_chirho();
    let ingress_chirho = barrier_chirho.ingress_addr_chirho("home-chirho").unwrap();

    let mut established_chirho = TcpStream::connect(ingress_chirho).expect("open a stream first");
    established_chirho
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    established_chirho.write_all(b"before-chirho").unwrap();
    let mut echo_chirho = [0_u8; 13];
    established_chirho
        .read_exact(&mut echo_chirho)
        .expect("the established stream really carries traffic before the cut");
    assert_eq!(&echo_chirho, b"before-chirho");

    barrier_chirho
        .disconnect_chirho(
            "home-chirho",
            DrillDisconnectModeChirho::NetworkPartitionChirho,
        )
        .expect("disconnect while a stream is established");

    // THE PROOF IS EOF SPECIFICALLY, and the tightening is deliberate. An earlier draft accepted
    // "EOF **or** any non-timeout error", and a mutation that disabled both pump exits still passed
    // it — the arm was satisfied by an error path rather than by a teardown. `shutdown(Both)` on the
    // peer is observed as `Ok(0)`, so requiring exactly that is what makes this arm measure the
    // teardown instead of merely noticing the stream became unpleasant.
    //
    // PROVOKE ONCE, THEN DRAIN ONLY. An earlier draft wrote on EVERY poll iteration and read the
    // same number of bytes back, refilling the receive buffer as fast as it drained it, so a
    // backlog of echoed bytes could hide the EOF sitting behind it. The provoking write happens
    // once; the loop only observes.
    //
    // ON DEADLINE SENSITIVITY, recorded at the arm it bit: see `WAIT_DEADLINE_CHIRHO`. This arm was
    // intermittent under a 5s bound and is the reason that bound is now generous.
    let _ = established_chirho.write_all(b"after-chirho");
    assert!(
        wait_until_chirho(|| {
            let mut drain_chirho = [0_u8; 4096];
            matches!(established_chirho.read(&mut drain_chirho), Ok(0))
        }),
        "an ALREADY-ESTABLISHED stream must be torn down (EOF) by the disconnect; if it keeps \
         echoing, the barrier only blocks NEW connections and every partition drill built on it is \
         vacuous"
    );
}

/// TICK MODE PAIR (recon §7, arm 4). The two modes are named, and they differ in exactly one way.
#[test]
fn the_two_disconnect_modes_differ_only_in_the_local_driver_chirho() {
    let (mut partition_barrier_chirho, partition_driver_chirho, _partition_target_chirho) =
        armed_single_node_chirho();
    let partition_status_chirho = partition_barrier_chirho
        .disconnect_chirho(
            "home-chirho",
            DrillDisconnectModeChirho::NetworkPartitionChirho,
        )
        .expect("network-partition disconnect");
    assert!(
        !partition_status_chirho.ingress_open_chirho && !partition_status_chirho.egress_open_chirho,
        "a network partition still cuts BOTH transport directions"
    );
    assert!(
        partition_driver_chirho.load(Ordering::SeqCst),
        "NETWORK PARTITION must leave the local driver TICKING — that live node is the one the \
         hosted cax11 evidence measured stepping down, and stopping it here would silently \
         substitute the hung-driver failure for this one"
    );
    assert!(partition_status_chirho.local_driver_alive_chirho);
    assert_eq!(
        partition_status_chirho.disconnect_mode_chirho,
        Some(DrillDisconnectModeChirho::NetworkPartitionChirho)
    );

    let (mut hung_barrier_chirho, hung_driver_chirho, _hung_target_chirho) =
        armed_single_node_chirho();
    let hung_status_chirho = hung_barrier_chirho
        .disconnect_chirho("home-chirho", DrillDisconnectModeChirho::HungDriverChirho)
        .expect("hung-driver disconnect");
    assert!(
        !hung_status_chirho.ingress_open_chirho && !hung_status_chirho.egress_open_chirho,
        "a hung driver also cuts both transport directions"
    );
    assert!(
        !hung_driver_chirho.load(Ordering::SeqCst),
        "HUNG DRIVER must STOP the local driver — the detector that died cannot report its own \
         death, which is the whole point of naming this mode separately"
    );
    assert!(!hung_status_chirho.local_driver_alive_chirho);
    assert_eq!(
        hung_status_chirho.disconnect_mode_chirho,
        Some(DrillDisconnectModeChirho::HungDriverChirho)
    );

    // THE MODES ARE NOT INTERCHANGEABLE, stated as an assertion rather than as prose.
    assert_ne!(
        partition_status_chirho.local_driver_alive_chirho,
        hung_status_chirho.local_driver_alive_chirho,
        "the two modes must observably differ; if they agree, the barrier has conflated them again"
    );
}

/// Heal restores a hung driver too — the mode that stopped it does not have to be remembered.
#[test]
fn heal_restores_the_local_driver_a_hung_disconnect_stopped_chirho() {
    let (mut barrier_chirho, driver_alive_chirho, _target_chirho) = armed_single_node_chirho();
    barrier_chirho
        .disconnect_chirho("home-chirho", DrillDisconnectModeChirho::HungDriverChirho)
        .unwrap();
    assert!(!driver_alive_chirho.load(Ordering::SeqCst));

    let healed_chirho = barrier_chirho.heal_chirho("home-chirho").unwrap();
    assert!(
        driver_alive_chirho.load(Ordering::SeqCst),
        "heal must restart what the cut stopped, or a drill leaves its node permanently deaf"
    );
    assert_eq!(healed_chirho.disconnect_mode_chirho, None);
    assert!(healed_chirho.ingress_open_chirho && healed_chirho.egress_open_chirho);
}

/// CLEANUP heals everything, is idempotent, and retires the barrier's verbs.
#[test]
fn cleanup_heals_every_node_and_retires_the_barrier_chirho() {
    let (mut barrier_chirho, driver_alive_chirho, _target_chirho) = armed_single_node_chirho();
    let ingress_chirho = barrier_chirho.ingress_addr_chirho("home-chirho").unwrap();
    barrier_chirho
        .disconnect_chirho("home-chirho", DrillDisconnectModeChirho::HungDriverChirho)
        .unwrap();

    let cleaned_chirho = barrier_chirho.cleanup_chirho();
    assert!(!cleaned_chirho.armed_chirho);
    assert!(
        driver_alive_chirho.load(Ordering::SeqCst),
        "cleanup must leave the caller's tick loop RUNNING — a retired barrier may dismantle its \
         own transport, but it must never leave a node's DRIVER suppressed, because that is the \
         asymmetric state nothing else would restore"
    );
    assert!(
        cleaned_chirho
            .nodes_chirho
            .iter()
            .all(|node_chirho| node_chirho.disconnect_mode_chirho.is_none()),
        "cleanup must clear every cut, so no node is left flagged as disconnected"
    );
    // CLEANUP IS TEARDOWN, NOT HEAL — and this arm exists because an earlier draft asserted the
    // opposite. `heal_chirho` is the reversible restore a drill uses mid-run and then OBSERVES
    // through; `cleanup_chirho` ends the drill and dismantles the switches, so traffic through a
    // retired switch address must NOT resume. Wanting both from one verb is incoherent: the
    // switches ARE the transport, so releasing the ports and still forwarding cannot both hold.
    assert!(
        round_trip_chirho(ingress_chirho, b"clean-chirho").is_none(),
        "a RETIRED switch must not forward; if it does, cleanup did not really dismantle anything"
    );

    assert_eq!(
        barrier_chirho
            .disconnect_chirho("home-chirho", DrillDisconnectModeChirho::HungDriverChirho)
            .expect_err("a retired barrier must refuse to cut again"),
        DrillBarrierRefusalChirho::BarrierRetiredChirho
    );
    assert_eq!(
        barrier_chirho
            .heal_chirho("home-chirho")
            .expect_err("a retired barrier refuses heal too"),
        DrillBarrierRefusalChirho::BarrierRetiredChirho
    );
    // Idempotent: a second cleanup is not an error and does not un-heal anything.
    let twice_chirho = barrier_chirho.cleanup_chirho();
    assert!(!twice_chirho.armed_chirho);
    assert!(driver_alive_chirho.load(Ordering::SeqCst));
}

/// CLEANUP RELEASES THE PORT — the header claims the barrier releases its listeners, so that has to
/// be executable rather than asserted.
///
/// The proof is that the switch address becomes REBINDABLE. A barrier that merely flipped flags
/// would leave every accept thread parked in the kernel with its listener bound, leaking one port
/// per switch per drill; rebinding the exact address is the one observation that distinguishes
/// "retired" from "still holding it".
#[test]
fn cleanup_releases_the_bound_switch_port_chirho() {
    let (mut barrier_chirho, _driver_alive_chirho, _target_chirho) = armed_single_node_chirho();
    let ingress_chirho = barrier_chirho.ingress_addr_chirho("home-chirho").unwrap();

    // CONTROL: while armed, the port is genuinely held — otherwise the rebind below proves nothing.
    assert!(
        TcpListener::bind(ingress_chirho).is_err(),
        "an armed barrier must still HOLD its switch port; if this binds, the release assertion \
         below would pass against a barrier that never bound anything"
    );

    barrier_chirho.cleanup_chirho();
    assert!(
        wait_until_chirho(|| TcpListener::bind(ingress_chirho).is_ok()),
        "cleanup must RELEASE the switch port, not merely stop forwarding through it"
    );
}

/// DROP heals. A drill that panics mid-cut must not leave the cluster partitioned.
#[test]
fn dropping_an_armed_barrier_heals_its_nodes_chirho() {
    let ingress_upstream_chirho = spawn_echo_server_chirho();
    let egress_target_chirho = spawn_echo_server_chirho();
    let driver_alive_chirho = Arc::new(AtomicBool::new(true));
    {
        let mut barrier_chirho =
            arm_chirho(DrillBarrierPlanChirho::new_chirho().register_node_chirho(
                "dropped-chirho",
                ingress_upstream_chirho,
                vec![egress_target_chirho],
                Arc::clone(&driver_alive_chirho),
            ))
            .unwrap();
        barrier_chirho
            .disconnect_chirho(
                "dropped-chirho",
                DrillDisconnectModeChirho::HungDriverChirho,
            )
            .unwrap();
        assert!(!driver_alive_chirho.load(Ordering::SeqCst));
    }
    assert!(
        driver_alive_chirho.load(Ordering::SeqCst),
        "Drop must heal: a barrier abandoned by a panicking drill has to fail toward CONNECTED"
    );
}

/// An operation naming a node the barrier does not own must refuse rather than silently no-op.
#[test]
fn an_unknown_node_label_refuses_chirho() {
    let (mut barrier_chirho, _driver_alive_chirho, _target_chirho) = armed_single_node_chirho();
    assert_eq!(
        barrier_chirho
            .disconnect_chirho("absent-chirho", DrillDisconnectModeChirho::HungDriverChirho)
            .expect_err("an unknown node must refuse"),
        DrillBarrierRefusalChirho::UnknownNodeChirho {
            node_label_chirho: "absent-chirho".to_owned(),
        }
    );
}

/// EXACT SUBJECT (recon §7, arm 6, at this brick's scope): cutting one node must not cut its
/// neighbour. A barrier that partitions more than it was asked to would make any drill conclusion
/// about "the former owner" unattributable.
#[test]
fn disconnecting_one_node_leaves_its_neighbour_connected_chirho() {
    let first_upstream_chirho = spawn_echo_server_chirho();
    let first_target_chirho = spawn_echo_server_chirho();
    let second_upstream_chirho = spawn_echo_server_chirho();
    let second_target_chirho = spawn_echo_server_chirho();
    let first_driver_chirho = Arc::new(AtomicBool::new(true));
    let second_driver_chirho = Arc::new(AtomicBool::new(true));
    let mut barrier_chirho = arm_chirho(
        DrillBarrierPlanChirho::new_chirho()
            .register_node_chirho(
                "first-chirho",
                first_upstream_chirho,
                vec![first_target_chirho],
                Arc::clone(&first_driver_chirho),
            )
            .register_node_chirho(
                "second-chirho",
                second_upstream_chirho,
                vec![second_target_chirho],
                Arc::clone(&second_driver_chirho),
            ),
    )
    .expect("two both-directions nodes are admitted");

    let second_ingress_chirho = barrier_chirho.ingress_addr_chirho("second-chirho").unwrap();
    barrier_chirho
        .disconnect_chirho("first-chirho", DrillDisconnectModeChirho::HungDriverChirho)
        .unwrap();

    assert!(
        round_trip_chirho(second_ingress_chirho, b"neighbour-chirho").is_some(),
        "cutting one node must leave its NEIGHBOUR reachable"
    );
    assert!(
        second_driver_chirho.load(Ordering::SeqCst),
        "cutting one node must not stop another node's driver"
    );

    let status_chirho = barrier_chirho.status_chirho();
    let first_chirho = status_chirho
        .nodes_chirho
        .iter()
        .find(|node_chirho| node_chirho.node_label_chirho == "first-chirho")
        .unwrap();
    let second_chirho = status_chirho
        .nodes_chirho
        .iter()
        .find(|node_chirho| node_chirho.node_label_chirho == "second-chirho")
        .unwrap();
    assert_eq!(first_chirho.disconnect_count_chirho, 1);
    assert_eq!(second_chirho.disconnect_count_chirho, 0);
    assert_eq!(second_chirho.disconnect_mode_chirho, None);
}
