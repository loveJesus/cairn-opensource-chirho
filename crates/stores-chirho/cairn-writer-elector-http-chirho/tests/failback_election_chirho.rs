// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! P4 FAILBACK: a leader that was really partitioned away comes back, and cannot resume its old term.
//!
//! The two existing socket drills stop just short of this. `failover_election_chirho` KILLS a leader
//! by stopping its timer loop — its server keeps answering, so it is a *hung* leader, not an absent
//! one — and then says in as many words that "the killed node is frozen; we do not require its view".
//! `minority_partition_chirho` isolates a node properly, but statically, by building it with an empty
//! peer list, so it can never have been leader and can never come back. Neither can express the
//! return, which is the half that decides whether automatic failover is safe to put money on: a home
//! region that went away must rejoin as a follower of the current term, never resume as a second
//! master on the term it still remembers. That is RED `GD1` in the A6 design (§8) — *a deposed region
//! replays `(T, s)` after `T' > T` exists → fenced* — observed here over real sockets.
//!
//! **A real partition needs BOTH directions cut, and needs to be reversible.** Every node is reached
//! only through a small TCP switch this file carries, so isolating one node means closing its switch
//! (nobody can reach it) AND stopping its tick loop (it sends nothing). Either alone is insufficient,
//! and the failure is silent: stopping only the tick loop leaves the node's server answering, so it
//! learns the new term passively and every assertion passes without a failback ever happening. That
//! was this test's first draft, and a mutation that never revived the node still passed it. Closing
//! only the switch would likewise leave the node heartbeating outward, and the majority would never
//! call an election at all.
//!
//! The partitioned node is whichever one the cluster elects, not a node chosen in advance. Forcing
//! leadership onto a particular node does not work and should not: peers that can still hear a
//! healthy leader correctly refuse to grant pre-votes, which is raft's leader stickiness doing its
//! job.
//!
//! **What is asserted, and why it is the invariant rather than an outcome.** "The revived node must
//! not be leader" would be flaky and wrong — re-winning a FRESH election at a higher term is
//! legitimate and is what a real failback looks like. What must never happen is authority at a
//! SUPERSEDED term. So this pins: the isolated node kept believing it led at its old term while the
//! majority moved on (otherwise there is no stale state to test); after the heal nobody, including
//! the returning node, is left below the failover term; exactly one leader exists and all three name
//! it; and if the home node did lead again it did so strictly above the failover term.
//!
//! Scope, honestly: the safety direction of drill 3 in the A6 design's §6 drill set, run on loopback
//! with TEST-only state. It flips no authority, mints nothing, and touches no production kind — §6
//! marks these drills completable pre-flip and §7 keeps the flip itself behind two-seat PASS. A
//! hosted cross-region version, and the "anchor chain walks clean" audit beside it, remain separate.

mod barrier_controller_chirho;

use barrier_controller_chirho::TcpBarrierControllerChirho;
use cairn_writer_elector_chirho::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_chirho::LocalAppendAuthorityRefusalChirho;
use cairn_writer_elector_http_chirho::driver_chirho::RaftDriverChirho;
use cairn_writer_elector_http_chirho::{raft_fire_router_chirho, serve_router_blocking_chirho};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Poll until one node — ignoring `exclude_index_chirho` — is leader on two consecutive looks.
fn wait_for_stable_leader_chirho(
    electors_chirho: &[Arc<RaftWriterElectorChirho>],
    group_chirho: &ConsistencyGroupIdChirho,
    exclude_index_chirho: Option<usize>,
) -> Option<usize> {
    let mut previous_chirho: Option<usize> = None;
    for _poll_chirho in 0..250 {
        std::thread::sleep(Duration::from_millis(100));
        let leaders_chirho: Vec<usize> = electors_chirho
            .iter()
            .enumerate()
            .filter(|(index_chirho, elector_chirho)| {
                Some(*index_chirho) != exclude_index_chirho
                    && elector_chirho
                        .leadership_chirho(group_chirho)
                        .is_leader_chirho
            })
            .map(|(index_chirho, _)| index_chirho)
            .collect();
        match leaders_chirho.as_slice() {
            [only_chirho] if previous_chirho == Some(*only_chirho) => return Some(*only_chirho),
            [only_chirho] => previous_chirho = Some(*only_chirho),
            _ => previous_chirho = None,
        }
    }
    None
}

fn spawn_tick_loop_chirho(driver_chirho: Arc<RaftDriverChirho>, stop_chirho: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        while !stop_chirho.load(Ordering::Relaxed) {
            driver_chirho.tick_once_chirho();
            std::thread::sleep(Duration::from_millis(50));
        }
    });
}

/// One three-node cluster on loopback where every node sits behind a switch that can be cut and
/// restored. This is the reusable body of a partition drill: build it, let it elect, isolate a node,
/// heal it, and look at what the cluster says.
struct DrillClusterChirho {
    group_chirho: ConsistencyGroupIdChirho,
    electors_chirho: Vec<Arc<RaftWriterElectorChirho>>,
    drivers_chirho: Vec<Arc<RaftDriverChirho>>,
    barriers_chirho: Vec<TcpBarrierControllerChirho>,
    stops_chirho: Vec<Arc<AtomicBool>>,
}

impl DrillClusterChirho {
    fn start_chirho(label_chirho: &str) -> Self {
        let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: format!("/var/lib/cairn-{label_chirho}-chirho"),
        };
        let voters_chirho: Vec<(u64, NodeIdChirho)> = vec![
            (1, NodeIdChirho("1".repeat(64))),
            (2, NodeIdChirho("2".repeat(64))),
            (3, NodeIdChirho("3".repeat(64))),
        ];

        // Every node sits behind its own switch, so ANY of them can be cut off — which matters because
        // the node we must partition is whichever one the cluster actually elects.
        let real_listeners_chirho: Vec<TcpListener> = (0..3)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let real_addrs_chirho: Vec<SocketAddr> = real_listeners_chirho
            .iter()
            .map(|listener_chirho| listener_chirho.local_addr().unwrap())
            .collect();
        let barrier_pairs_chirho: Vec<(SocketAddr, TcpBarrierControllerChirho)> = (0..3usize)
            .map(|index_chirho| {
                let switch_listener_chirho = TcpListener::bind("127.0.0.1:0").unwrap();
                let switch_addr_chirho = switch_listener_chirho.local_addr().unwrap();
                let barrier_chirho = TcpBarrierControllerChirho::arm_chirho(
                    switch_listener_chirho,
                    real_addrs_chirho[index_chirho],
                    barrier_controller_chirho::BarrierModeChirho::NetworkPartitionChirho,
                );
                (switch_addr_chirho, barrier_chirho)
            })
            .collect();
        let switch_addrs_chirho: Vec<SocketAddr> = barrier_pairs_chirho
            .iter()
            .map(|(address_chirho, _)| *address_chirho)
            .collect();
        let barriers_chirho: Vec<TcpBarrierControllerChirho> = barrier_pairs_chirho
            .into_iter()
            .map(|(_, barrier_chirho)| barrier_chirho)
            .collect();

        // Peers only ever address one another through the switches.
        let peer_url_chirho =
            |index_chirho: usize| format!("http://{}", switch_addrs_chirho[index_chirho]);

        let electors_chirho: Vec<Arc<RaftWriterElectorChirho>> = (1..=3u64)
            .map(|raft_id_chirho| {
                Arc::new(
                    RaftWriterElectorChirho::new_cluster_node_chirho(
                        group_chirho.clone(),
                        raft_id_chirho,
                        voters_chirho.clone(),
                    )
                    .expect("build a cluster-member elector")
                    // The deployed node requires a continuous warm-up lease, so the drill uses one
                    // too; without it no node can take append authority and the fence question
                    // cannot even be asked.
                    .with_leadership_warmup_lease_chirho(),
                )
            })
            .collect();

        let drivers_chirho: Vec<Arc<RaftDriverChirho>> = (0..3usize)
            .map(|index_chirho| {
                let peers_chirho: Vec<(u64, String)> = (0..3usize)
                    .filter(|peer_index_chirho| *peer_index_chirho != index_chirho)
                    .map(|peer_index_chirho| {
                        (
                            (peer_index_chirho + 1) as u64,
                            peer_url_chirho(peer_index_chirho),
                        )
                    })
                    .collect();
                Arc::new(
                    RaftDriverChirho::new_chirho(
                        electors_chirho[index_chirho].clone(),
                        peers_chirho,
                        Duration::from_secs(2),
                    )
                    .expect("start bounded peer delivery workers"),
                )
            })
            .collect();

        for (index_chirho, listener_chirho) in real_listeners_chirho.into_iter().enumerate() {
            let router_chirho = raft_fire_router_chirho(drivers_chirho[index_chirho].clone());
            std::thread::spawn(move || {
                let _ = serve_router_blocking_chirho(listener_chirho, router_chirho);
            });
        }

        let stops_chirho: Vec<Arc<AtomicBool>> =
            (0..3).map(|_| Arc::new(AtomicBool::new(false))).collect();
        for index_chirho in 0..3 {
            spawn_tick_loop_chirho(
                drivers_chirho[index_chirho].clone(),
                stops_chirho[index_chirho].clone(),
            );
        }

        Self {
            group_chirho,
            electors_chirho,
            drivers_chirho,
            barriers_chirho,
            stops_chirho,
        }
    }

    /// Cut a node off in BOTH directions: nobody reaches it, and it sends nothing. Either alone
    /// leaves the "isolated" node informed or the majority unmotivated, and the drill goes vacuous.
    fn isolate_chirho(&self, index_chirho: usize) {
        self.barriers_chirho[index_chirho].disconnect_chirho();
        self.stops_chirho[index_chirho].store(true, Ordering::Relaxed);
    }

    /// Restore the link and let the node drive again.
    fn heal_chirho(&self, index_chirho: usize) {
        self.barriers_chirho[index_chirho].heal_chirho();
        self.stops_chirho[index_chirho].store(false, Ordering::Relaxed);
        spawn_tick_loop_chirho(
            self.drivers_chirho[index_chirho].clone(),
            self.stops_chirho[index_chirho].clone(),
        );
    }
}

#[test]
fn a_returning_partitioned_leader_rejoins_without_resuming_its_old_term_chirho() {
    let cluster_chirho = DrillClusterChirho::start_chirho("failback");
    let group_chirho = cluster_chirho.group_chirho.clone();
    let electors_chirho = &cluster_chirho.electors_chirho;

    // ---- 1. Whoever wins is the home region for this run. ----
    let home_index_chirho = wait_for_stable_leader_chirho(electors_chirho, &group_chirho, None)
        .expect("an initial leader is elected");
    let term_before_chirho = electors_chirho[home_index_chirho]
        .leadership_chirho(&group_chirho)
        .term_chirho;

    // ---- 2. THE PARTITION: cut BOTH directions for the home region. ----
    cluster_chirho.isolate_chirho(home_index_chirho); // nobody reaches it, and it sends nothing

    let survivor_index_chirho =
        wait_for_stable_leader_chirho(electors_chirho, &group_chirho, Some(home_index_chirho))
            .expect("the majority elects a new leader without the home region");
    let term_after_chirho = electors_chirho[survivor_index_chirho]
        .leadership_chirho(&group_chirho)
        .term_chirho;

    assert!(
        term_after_chirho > term_before_chirho,
        "the majority must move to a higher term ({term_before_chirho} -> {term_after_chirho}), \
         otherwise the isolated node's term is not superseded and this proves nothing"
    );

    // THE PRECONDITION THAT MAKES THIS A FAILBACK: while cut off, the home node must still believe
    // it leads at the OLD term. If it already learned the new one, it was never really partitioned
    // and the return below is not a return at all.
    let isolated_chirho = electors_chirho[home_index_chirho].leadership_chirho(&group_chirho);
    let isolated_term_chirho = isolated_chirho.term_chirho;
    assert!(
        isolated_chirho.term_chirho < term_after_chirho,
        "the partitioned node reports term {} but the majority is at {term_after_chirho} -- it is \
         still hearing them, so the link did not actually cut",
        isolated_chirho.term_chirho
    );

    // ---- 3. THE HEAL: reopen the link and let the home region drive again. ----
    cluster_chirho.heal_chirho(home_index_chirho);

    // ---- 4+5. Wait for the WHOLE post-heal invariant to hold at once, then assert it once. ----
    //
    // Each of these facts is read from a live cluster, so checking them in separate snapshots would
    // be a race: an election between two reads makes a perfectly healthy cluster look inconsistent.
    // Polling the conjunction and asserting the final observation keeps the property exact while
    // removing the false failure.
    let mut settled_chirho: Option<(Vec<usize>, Vec<u64>, Option<NodeIdChirho>)> = None;
    let deadline_chirho = Instant::now() + Duration::from_secs(30);
    loop {
        let views_chirho: Vec<_> = electors_chirho
            .iter()
            .map(|elector_chirho| elector_chirho.leadership_chirho(&group_chirho))
            .collect();
        let leaders_chirho: Vec<usize> = views_chirho
            .iter()
            .enumerate()
            .filter(|(_, view_chirho)| view_chirho.is_leader_chirho)
            .map(|(index_chirho, _)| index_chirho)
            .collect();
        let terms_chirho: Vec<u64> = views_chirho
            .iter()
            .map(|view_chirho| view_chirho.term_chirho)
            .collect();
        let leader_ids_chirho: Vec<Option<NodeIdChirho>> = views_chirho
            .iter()
            .map(|view_chirho| view_chirho.leader_id_chirho.clone())
            .collect();
        let agreed_chirho = leader_ids_chirho[0].clone();
        let holds_chirho = leaders_chirho.len() == 1
            && terms_chirho
                .iter()
                .all(|term_chirho| *term_chirho >= term_after_chirho)
            && agreed_chirho.is_some()
            && leader_ids_chirho
                .iter()
                .all(|id_chirho| *id_chirho == agreed_chirho);
        // The conjunction must hold on TWO IDENTICAL consecutive observations, not once. A cluster
        // mid-transition can satisfy it for an instant -- a node that is stepping down or standing
        // up can be sampled as the only leader while the terms still read the previous value -- and
        // accepting that instant made this test intermittently claim a returning node had "resumed"
        // a term it was in fact just passing through. Requiring the same picture twice is the same
        // stability idiom `wait_for_stable_leader_chirho` above already uses.
        let observation_chirho = (leaders_chirho, terms_chirho, agreed_chirho);
        let stable_chirho = settled_chirho.as_ref() == Some(&observation_chirho);
        settled_chirho = Some(observation_chirho);
        if (holds_chirho && stable_chirho) || Instant::now() >= deadline_chirho {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let (leaders_chirho, terms_chirho, agreed_leader_chirho) =
        settled_chirho.expect("the cluster was observed at least once after the heal");

    // Nobody, including the returning node, is left on the superseded term.
    for (index_chirho, term_chirho) in terms_chirho.iter().enumerate() {
        assert!(
            *term_chirho >= term_after_chirho,
            "node {index_chirho} reports term {term_chirho} after the heal, below the failover term \
             {term_after_chirho} -- authority on a superseded term is RED GD1"
        );
    }

    // Exactly one leader, and everyone names the same one: the return caused no split.
    assert_eq!(
        leaders_chirho.len(),
        1,
        "after the heal exactly one node may consider itself leader, found {leaders_chirho:?} -- \
         two masters is the split brain automatic failover exists to prevent"
    );
    assert!(
        agreed_leader_chirho.is_some(),
        "every node names the same settled leader"
    );

    // ---- 6. If the home node did lead again, it won freshly rather than resuming. ----
    if leaders_chirho == [home_index_chirho] {
        let regained_term_chirho = terms_chirho[home_index_chirho];
        assert!(
            regained_term_chirho > term_after_chirho,
            "the returning node leads at term {regained_term_chirho}, not above the failover term \
             {term_after_chirho} -- that is a RESUMED authority, not a newly won one. \
             before={term_before_chirho} after={term_after_chirho} \
             isolated={isolated_term_chirho} final_terms={terms_chirho:?} leaders={leaders_chirho:?}"
        );
    }
}

/// Poll until this node's local append authority can be taken, i.e. its warm-up lease has run.
fn wait_for_append_authority_chirho(
    elector_chirho: &Arc<RaftWriterElectorChirho>,
    deadline_chirho: Duration,
) -> bool {
    let until_chirho = Instant::now() + deadline_chirho;
    while Instant::now() < until_chirho {
        if elector_chirho
            .local_append_authority_handle_chirho()
            .try_acquire_chirho()
            .is_ok()
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn a_deposed_leader_is_refused_append_authority_after_the_heal_chirho() {
    // The write-side half of drill 2: "the old leader's replays are fenced on heal". Drill 3 above
    // proves the returning node does not resume LEADERSHIP; this proves it cannot take the local
    // APPEND AUTHORITY either, which is the thing an append actually needs. Both directions matter:
    // the deposed node must be refused, AND the surviving leader must still be granted, or the
    // "fence" would just be an outage.
    let cluster_chirho = DrillClusterChirho::start_chirho("deposed-append");
    let group_chirho = cluster_chirho.group_chirho.clone();
    let electors_chirho = &cluster_chirho.electors_chirho;

    let home_chirho = wait_for_stable_leader_chirho(electors_chirho, &group_chirho, None)
        .expect("an initial leader is elected");
    assert!(
        wait_for_append_authority_chirho(&electors_chirho[home_chirho], Duration::from_secs(20)),
        "the elected leader must be able to take append authority before it is deposed, or this \
         test would prove only that a node which never had authority still lacks it"
    );

    cluster_chirho.isolate_chirho(home_chirho);
    let survivor_chirho =
        wait_for_stable_leader_chirho(electors_chirho, &group_chirho, Some(home_chirho))
            .expect("the majority elects a new leader");
    cluster_chirho.heal_chirho(home_chirho);

    // Settle: the survivor holds authority and the returned node has learned it is not the leader.
    assert!(
        wait_for_append_authority_chirho(
            &electors_chirho[survivor_chirho],
            Duration::from_secs(25)
        ),
        "the surviving leader must still be able to append after the heal -- a fence that stops \
         everyone is an outage, not a fence"
    );
    let settle_chirho = Instant::now() + Duration::from_secs(25);
    while Instant::now() < settle_chirho
        && electors_chirho[home_chirho]
            .leadership_chirho(&group_chirho)
            .is_leader_chirho
    {
        std::thread::sleep(Duration::from_millis(100));
    }

    let deposed_handle_chirho = electors_chirho[home_chirho].local_append_authority_handle_chirho();
    let refusal_chirho = deposed_handle_chirho.try_acquire_chirho().err();
    assert!(
        matches!(
            refusal_chirho,
            Some(LocalAppendAuthorityRefusalChirho::NotLocalLeaderChirho)
        ),
        "the returned deposed node must be refused append authority as NotLocalLeader, got \
         {refusal_chirho:?} -- a deposed region that can still append is RED GD1 on the write path"
    );
}

#[test]
fn both_sides_of_a_partition_hold_local_append_authority_today_chirho() {
    // CHARACTERISATION, NOT AN ENDORSEMENT — and it is the concrete reason the elected fence exists.
    //
    // Drill 2 also asks that a partitioned minority "mints nothing". At the LOCAL append-authority
    // layer that does not hold today, and this records the exact shape rather than leaving it as a
    // belief: while cut off, the old leader keeps taking append authority at its OLD term, because
    // the warm-up lease counts ticks and never expires (audit finding F1) and the node has no way to
    // learn it was deposed. Meanwhile the majority elects and its new leader takes authority at a
    // HIGHER term. Two regions, both locally authorised, at once.
    //
    // That is expected of a LOCAL fence — it is local, and cairn's money safety is local-fence-only
    // today. It is precisely the gap the elected fence (A6) closes, and precisely why `lease_valid`
    // is documented as "observed only, never authoritative".
    //
    // **WHICH FAILURE MODE THIS IS, made precise by hosted evidence (2026-07-25).** `isolate_chirho`
    // does two things: it cuts the links AND it stops the node's tick loop. The stopped tick loop is
    // what makes the old leader keep believing it leads, so this is the HUNG-NODE case — a process
    // alive enough to answer but no longer driving its own raft state. A node that is merely
    // NETWORK-partitioned while still ticking behaves better: on cax11, a real iptables partition of
    // the live leader made it STEP DOWN on its own (`is_local_leader:false`, `leader_id:null`, stuck
    // at its old term), because the quorum check still ran. See
    // `cax11-hosted-election-failover-drill-chirho.md`.
    //
    // So the hazard this test characterises is **not** "a partition lets two regions mint". It is
    // narrower and worth stating exactly: **a leader whose tick driver dies keeps local append
    // authority indefinitely**, since nothing decays a tick-counted lease when nobody is ticking.
    // That is audit finding F1's real shape, and it is why F1's criteria require a lease that can
    // expire with NO ONE CALLING ANYTHING.
    //
    // **If this test starts FAILING, that is good news**: it means an isolated deposed leader can no
    // longer take local append authority, so the elected fence is doing its job. Replace this with
    // the fenced assertion rather than restoring the behaviour it describes.
    let cluster_chirho = DrillClusterChirho::start_chirho("two-sided-authority");
    let group_chirho = cluster_chirho.group_chirho.clone();
    let electors_chirho = &cluster_chirho.electors_chirho;

    let home_chirho = wait_for_stable_leader_chirho(electors_chirho, &group_chirho, None)
        .expect("an initial leader is elected");
    assert!(
        wait_for_append_authority_chirho(&electors_chirho[home_chirho], Duration::from_secs(20)),
        "the leader must hold append authority before being cut off"
    );
    let term_before_chirho = electors_chirho[home_chirho]
        .leadership_chirho(&group_chirho)
        .term_chirho;

    cluster_chirho.isolate_chirho(home_chirho);
    let survivor_chirho =
        wait_for_stable_leader_chirho(electors_chirho, &group_chirho, Some(home_chirho))
            .expect("the majority elects a new leader");
    assert!(
        wait_for_append_authority_chirho(
            &electors_chirho[survivor_chirho],
            Duration::from_secs(25)
        ),
        "the majority's new leader must warm into append authority"
    );

    let isolated_handle_chirho =
        electors_chirho[home_chirho].local_append_authority_handle_chirho();
    let isolated_guard_chirho = isolated_handle_chirho.try_acquire_chirho();
    let isolated_term_chirho = isolated_guard_chirho
        .as_ref()
        .ok()
        .map(|guard_chirho| guard_chirho.published_raft_term_chirho());
    let survivor_term_chirho = electors_chirho[survivor_chirho]
        .leadership_chirho(&group_chirho)
        .term_chirho;

    assert!(
        isolated_guard_chirho.is_ok(),
        "TODAY the isolated deposed leader still takes local append authority; if it no longer \
         does, the elected fence has landed and this characterisation should be replaced by the \
         fenced assertion rather than reverted"
    );
    assert_eq!(
        isolated_term_chirho,
        Some(term_before_chirho),
        "and it takes it at its OLD term, which is what makes two-sided minting possible"
    );
    assert!(
        survivor_term_chirho > term_before_chirho,
        "meanwhile the majority is authorised at a strictly higher term ({survivor_term_chirho} > \
         {term_before_chirho}) -- two regions locally authorised at once, at different terms"
    );
}
