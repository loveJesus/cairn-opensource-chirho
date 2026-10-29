// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The item-6 pre-registered arms for the hosted transport-rule generator, plus one test per barrier
//! contract property. Every arm drives the real [`plan_partition_chirho`] admission and inspects the
//! generated rule DATA — there is no host, no `nft`, and no socket here, by construction.
//!
//! The instruments here are deliberately DIFFERENT in kind from the generator's own helpers: the
//! metacharacter and port-22 scans read the rendered bytes literally rather than trusting the
//! generator's own defense (which is sanitisation + type-bound fields, NOT a metacharacter detector),
//! so a bug in that defense cannot hide behind a test that reuses it.

use super::*;

const ELECTOR_PORT_CHIRHO: u16 = 8300;
const WRITE_RELAY_PORT_CHIRHO: u16 = 8400;
const OBSERVATION_PORT_CHIRHO: u16 = 8500;

/// The former owner every lawful arm partitions: overlay `10.100.0.7`, label `boaz3-former-owner`.
fn former_owner_subject_chirho() -> PartitionSubjectChirho {
    PartitionSubjectChirho {
        former_owner_label_chirho: "boaz3-former-owner".to_owned(),
        former_owner_overlay_addr_chirho: Ipv4Addr::new(10, 100, 0, 7),
    }
}

/// All three overlay planes, each on a distinct non-SSH port (A2 requires every plane).
fn all_three_planes_chirho() -> Vec<OverlayPlanePortChirho> {
    vec![
        OverlayPlanePortChirho {
            plane_chirho: OverlayPlaneChirho::ElectorChirho,
            port_chirho: ELECTOR_PORT_CHIRHO,
        },
        OverlayPlanePortChirho {
            plane_chirho: OverlayPlaneChirho::WriteRelayChirho,
            port_chirho: WRITE_RELAY_PORT_CHIRHO,
        },
        OverlayPlanePortChirho {
            plane_chirho: OverlayPlaneChirho::ObservationChirho,
            port_chirho: OBSERVATION_PORT_CHIRHO,
        },
    ]
}

fn lawful_network_partition_request_chirho() -> HostedPartitionRequestChirho {
    HostedPartitionRequestChirho::new_chirho(
        former_owner_subject_chirho(),
        all_three_planes_chirho(),
        HostedPartitionModeSpecChirho::NetworkPartitionChirho,
        DrillTargetKindChirho::DrillRootSyntheticChirho,
        Duration::from_secs(300),
    )
}

fn lawful_hung_driver_request_chirho() -> HostedPartitionRequestChirho {
    HostedPartitionRequestChirho::new_chirho(
        former_owner_subject_chirho(),
        all_three_planes_chirho(),
        HostedPartitionModeSpecChirho::HungDriverChirho {
            process_match_chirho: "cairn-ledger-geo-node-testkind-chirho".to_owned(),
            max_paused_chirho: Duration::from_secs(30),
        },
        DrillTargetKindChirho::DrillRootSyntheticChirho,
        Duration::from_secs(300),
    )
}

// ----------------------------------------------------------------------------------------------
// PROPERTY 1 — both directions, symmetric (mirrors the barrier's OneDirectionOnly admission).
// ----------------------------------------------------------------------------------------------

#[test]
fn lawful_plan_drops_both_directions_on_every_plane_chirho() {
    let plan_chirho = plan_partition_chirho(&lawful_network_partition_request_chirho())
        .expect("lawful request must be admitted");
    let addr_chirho = "10.100.0.7";
    for port_chirho in [
        ELECTOR_PORT_CHIRHO,
        WRITE_RELAY_PORT_CHIRHO,
        OBSERVATION_PORT_CHIRHO,
    ] {
        let ingress_present_chirho = plan_chirho.setup_chirho().iter().any(|command_chirho| {
            let line_chirho = command_chirho.rendered_chirho();
            line_chirho.contains(&format!("ip daddr {addr_chirho}"))
                && line_chirho.contains(&format!("dport {port_chirho}"))
                && line_chirho.ends_with("drop")
        });
        let egress_present_chirho = plan_chirho.setup_chirho().iter().any(|command_chirho| {
            let line_chirho = command_chirho.rendered_chirho();
            line_chirho.contains(&format!("ip saddr {addr_chirho}"))
                && line_chirho.contains(&format!("dport {port_chirho}"))
                && line_chirho.ends_with("drop")
        });
        assert!(
            ingress_present_chirho,
            "plane on port {port_chirho} must have an INGRESS drop naming the subject as daddr"
        );
        assert!(
            egress_present_chirho,
            "plane on port {port_chirho} must have an EGRESS drop naming the subject as saddr"
        );
    }
    // Exactly one ingress + one egress drop per plane, and no more: 3 planes × 2 directions.
    let drop_rules_chirho = plan_chirho
        .setup_chirho()
        .iter()
        .filter(|command_chirho| command_chirho.rendered_chirho().ends_with("drop"))
        .count();
    assert_eq!(
        drop_rules_chirho, 6,
        "a both-directions partition of three planes is exactly six drop rules"
    );
}

#[test]
fn one_direction_only_plant_refuses_chirho() {
    let request_chirho = HostedPartitionRequestChirho::ingress_only_plant_chirho(
        former_owner_subject_chirho(),
        all_three_planes_chirho(),
        HostedPartitionModeSpecChirho::NetworkPartitionChirho,
        DrillTargetKindChirho::DrillRootSyntheticChirho,
        Duration::from_secs(300),
    );
    assert_eq!(
        plan_partition_chirho(&request_chirho),
        Err(HostedPartitionRefusalChirho::OneDirectionOnlyChirho {
            subject_label_chirho: "boaz3-former-owner".to_owned(),
        }),
        "a one-direction request is a half-partition and must refuse, like the barrier's arm"
    );
}

// ----------------------------------------------------------------------------------------------
// PROPERTY 2 — mode-named, no default (mirrors DrillDisconnectModeChirho: the two modes differ in
// EXACTLY one thing, here the process control; the packet drop is identical).
// ----------------------------------------------------------------------------------------------

#[test]
fn network_partition_and_hung_driver_are_distinct_and_named_chirho() {
    let network_plan_chirho = plan_partition_chirho(&lawful_network_partition_request_chirho())
        .expect("network partition admitted");
    let hung_plan_chirho =
        plan_partition_chirho(&lawful_hung_driver_request_chirho()).expect("hung driver admitted");

    assert_eq!(
        network_plan_chirho.mode_chirho(),
        HostedPartitionModeChirho::NetworkPartitionChirho
    );
    assert_eq!(
        hung_plan_chirho.mode_chirho(),
        HostedPartitionModeChirho::HungDriverChirho
    );

    // The ONE thing that differs is the process control. The nft rule sets are byte-identical.
    assert_eq!(
        network_plan_chirho.setup_chirho(),
        hung_plan_chirho.setup_chirho(),
        "the packet-drop rules are the same in both modes; only the process control differs"
    );
    assert_eq!(
        network_plan_chirho.teardown_chirho(),
        hung_plan_chirho.teardown_chirho()
    );

    // NetworkPartition leaves the process running: no signals, either armed or on cleanup.
    assert!(network_plan_chirho.process_arm_chirho().is_empty());
    assert!(network_plan_chirho.process_cleanup_chirho().is_empty());

    // HungDriver adds a SEPARATE bounded SIGSTOP with a paired SIGCONT.
    assert_eq!(hung_plan_chirho.process_arm_chirho().len(), 1);
    assert_eq!(hung_plan_chirho.process_cleanup_chirho().len(), 1);
}

#[test]
fn hung_driver_sigstop_is_bounded_and_paired_with_sigcont_chirho() {
    let plan_chirho =
        plan_partition_chirho(&lawful_hung_driver_request_chirho()).expect("hung driver admitted");

    let (stop_match_chirho, stop_bound_chirho) = match &plan_chirho.process_arm_chirho()[0] {
        ProcessControlStepChirho::SigstopChirho {
            process_match_chirho,
            max_paused_chirho,
        } => (process_match_chirho.clone(), *max_paused_chirho),
        other_chirho => panic!("HungDriver arm must be a SIGSTOP, got {other_chirho:?}"),
    };
    assert!(
        !stop_bound_chirho.is_zero() && stop_bound_chirho <= MAX_HUNG_DRIVER_PAUSE_CHIRHO,
        "the SIGSTOP must carry a bounded lifetime"
    );
    assert!(
        stop_bound_chirho <= plan_chirho.deadline_chirho(),
        "the SIGSTOP must not outlive the partition it belongs to"
    );

    let cont_match_chirho = match &plan_chirho.process_cleanup_chirho()[0] {
        ProcessControlStepChirho::SigcontChirho {
            process_match_chirho,
        } => process_match_chirho.clone(),
        other_chirho => panic!("HungDriver cleanup must be a SIGCONT, got {other_chirho:?}"),
    };
    assert_eq!(
        stop_match_chirho, cont_match_chirho,
        "the mandatory SIGCONT must resume the exact process the SIGSTOP paused"
    );
}

#[test]
fn hung_driver_pause_over_bound_refuses_chirho() {
    let request_chirho = HostedPartitionRequestChirho::new_chirho(
        former_owner_subject_chirho(),
        all_three_planes_chirho(),
        HostedPartitionModeSpecChirho::HungDriverChirho {
            process_match_chirho: "cairn-ledger-geo-node-testkind-chirho".to_owned(),
            max_paused_chirho: MAX_HUNG_DRIVER_PAUSE_CHIRHO + Duration::from_secs(1),
        },
        DrillTargetKindChirho::DrillRootSyntheticChirho,
        Duration::from_secs(300),
    );
    assert!(matches!(
        plan_partition_chirho(&request_chirho),
        Err(HostedPartitionRefusalChirho::HungDriverPauseUnboundedChirho { .. })
    ));
}

#[test]
fn hung_driver_process_match_must_be_clean_chirho() {
    for bad_match_chirho in [
        "",
        "  ",
        "geo; rm -rf /",
        "geo`id`",
        "geo$(whoami)",
        "geo|nc",
    ] {
        let request_chirho = HostedPartitionRequestChirho::new_chirho(
            former_owner_subject_chirho(),
            all_three_planes_chirho(),
            HostedPartitionModeSpecChirho::HungDriverChirho {
                process_match_chirho: bad_match_chirho.to_owned(),
                max_paused_chirho: Duration::from_secs(30),
            },
            DrillTargetKindChirho::DrillRootSyntheticChirho,
            Duration::from_secs(300),
        );
        assert!(
            matches!(
                plan_partition_chirho(&request_chirho),
                Err(HostedPartitionRefusalChirho::HungDriverProcessInvalidChirho { .. })
            ),
            "process match {bad_match_chirho:?} must refuse"
        );
    }
}

// ----------------------------------------------------------------------------------------------
// PROPERTY 3 — subject-bound (mirrors the barrier: exactly the named subject, never a neighbour).
// ----------------------------------------------------------------------------------------------

#[test]
fn rules_name_only_the_subject_address_never_a_neighbour_chirho() {
    let plan_chirho = plan_partition_chirho(&lawful_network_partition_request_chirho())
        .expect("lawful request admitted");
    let neighbour_chirho = "10.100.0.9";
    let mut address_bearing_lines_chirho = 0;
    for line_chirho in plan_chirho.all_rendered_lines_chirho() {
        assert!(
            !line_chirho.contains(neighbour_chirho),
            "no rule may name a neighbour address; offending line: {line_chirho}"
        );
        if line_chirho.contains("daddr") || line_chirho.contains("saddr") {
            address_bearing_lines_chirho += 1;
            assert!(
                line_chirho.contains("10.100.0.7"),
                "every address-bearing rule must name the subject; offending line: {line_chirho}"
            );
        }
    }
    assert_eq!(
        address_bearing_lines_chirho, 6,
        "the six drop rules are the address-bearing lines"
    );
}

#[test]
fn subject_mismatch_teardown_refuses_chirho() {
    let plan_chirho = plan_partition_chirho(&lawful_network_partition_request_chirho())
        .expect("lawful request admitted");
    assert_eq!(
        plan_chirho.teardown_for_subject_chirho("ruth1-neighbour"),
        Err(HostedPartitionRefusalChirho::SubjectMismatchChirho {
            armed_chirho: "boaz3-former-owner".to_owned(),
            requested_chirho: "ruth1-neighbour".to_owned(),
        }),
        "a neighbour cannot borrow a partition armed for the former owner"
    );
    assert!(
        plan_chirho
            .teardown_for_subject_chirho("boaz3-former-owner")
            .is_ok(),
        "the armed subject's own teardown must be served"
    );
}

// ----------------------------------------------------------------------------------------------
// PROPERTY 4 — bounded lifetime / auto-cleanup (mirrors cleanup_chirho/Drop + teardown-chirho).
// ----------------------------------------------------------------------------------------------

#[test]
fn plan_deadline_is_bounded_chirho() {
    let plan_chirho = plan_partition_chirho(&lawful_network_partition_request_chirho())
        .expect("lawful request admitted");
    assert!(!plan_chirho.deadline_chirho().is_zero());
    assert!(plan_chirho.deadline_chirho() <= MAX_PARTITION_LIFETIME_CHIRHO);
}

#[test]
fn zero_and_over_bound_lifetimes_refuse_chirho() {
    for bad_lifetime_chirho in [
        Duration::ZERO,
        MAX_PARTITION_LIFETIME_CHIRHO + Duration::from_secs(1),
    ] {
        let request_chirho = HostedPartitionRequestChirho::new_chirho(
            former_owner_subject_chirho(),
            all_three_planes_chirho(),
            HostedPartitionModeSpecChirho::NetworkPartitionChirho,
            DrillTargetKindChirho::DrillRootSyntheticChirho,
            bad_lifetime_chirho,
        );
        assert!(
            matches!(
                plan_partition_chirho(&request_chirho),
                Err(HostedPartitionRefusalChirho::LifetimeUnboundedChirho { .. })
            ),
            "lifetime {bad_lifetime_chirho:?} must refuse"
        );
    }
}

#[test]
fn teardown_reverses_exactly_the_armed_chains_chirho() {
    let plan_chirho = plan_partition_chirho(&lawful_network_partition_request_chirho())
        .expect("lawful request admitted");

    // The chains the arm CREATES.
    let created_chains_chirho: std::collections::BTreeSet<String> = plan_chirho
        .setup_chirho()
        .iter()
        .filter(|command_chirho| command_chirho.verb_chirho() == NftVerbChirho::AddChainChirho)
        .map(|command_chirho| chain_name_token_chirho(command_chirho.rendered_chirho()))
        .collect();
    assert_eq!(
        created_chains_chirho.len(),
        2,
        "arm creates two drill chains"
    );

    // Teardown may ONLY flush and delete — never add, never touch the shared table.
    for command_chirho in plan_chirho.teardown_chirho() {
        assert!(
            matches!(
                command_chirho.verb_chirho(),
                NftVerbChirho::FlushChainChirho | NftVerbChirho::DeleteChainChirho
            ),
            "teardown verbs are flush/delete only; got {:?}",
            command_chirho.verb_chirho()
        );
        assert!(
            !command_chirho.rendered_chirho().contains("table"),
            "teardown must never delete/flush the shared filter table"
        );
    }

    let flushed_chains_chirho: std::collections::BTreeSet<String> = plan_chirho
        .teardown_chirho()
        .iter()
        .filter(|command_chirho| command_chirho.verb_chirho() == NftVerbChirho::FlushChainChirho)
        .map(|command_chirho| chain_name_token_chirho(command_chirho.rendered_chirho()))
        .collect();
    let deleted_chains_chirho: std::collections::BTreeSet<String> = plan_chirho
        .teardown_chirho()
        .iter()
        .filter(|command_chirho| command_chirho.verb_chirho() == NftVerbChirho::DeleteChainChirho)
        .map(|command_chirho| chain_name_token_chirho(command_chirho.rendered_chirho()))
        .collect();

    assert_eq!(
        flushed_chains_chirho, created_chains_chirho,
        "every created chain is flushed at teardown"
    );
    assert_eq!(
        deleted_chains_chirho, created_chains_chirho,
        "every created chain is deleted at teardown — reverses exactly, nothing more, nothing less"
    );

    // Each chain is flushed BEFORE it is deleted (a non-empty base chain cannot be deleted).
    for chain_chirho in &created_chains_chirho {
        let flush_index_chirho =
            teardown_index_of_chirho(&plan_chirho, NftVerbChirho::FlushChainChirho, chain_chirho);
        let delete_index_chirho =
            teardown_index_of_chirho(&plan_chirho, NftVerbChirho::DeleteChainChirho, chain_chirho);
        assert!(
            flush_index_chirho < delete_index_chirho,
            "chain {chain_chirho} must be flushed before it is deleted"
        );
    }
}

#[test]
fn cleanup_is_generated_on_the_refusal_path_too_chirho() {
    // Even where a request would be refused, the SAFE teardown for the subject is available so a
    // caller can run it unconditionally in a `finally` — a refused drill heals rather than leaving
    // chains armed. It must be the same flush-both/delete-both shape a lawful teardown has.
    let subject_chirho = former_owner_subject_chirho();
    let refusal_cleanup_chirho =
        HostedPartitionRefusalChirho::cleanup_is_still_generated_chirho(&subject_chirho);
    let lawful_teardown_chirho = plan_partition_chirho(&lawful_network_partition_request_chirho())
        .expect("lawful request admitted")
        .teardown_chirho()
        .to_vec();
    assert_eq!(
        refusal_cleanup_chirho, lawful_teardown_chirho,
        "the refusal-path cleanup must match the lawful teardown for the same subject"
    );
}

// ----------------------------------------------------------------------------------------------
// BLESSED CONTROLS — C1 verb allowlist, C2 test-kind allowlist, and the structural floor
// (no INPUT/OUTPUT base chain or policy, no port 22, no shell escape).
// ----------------------------------------------------------------------------------------------

#[test]
fn non_test_target_refuses_chirho() {
    for bad_kind_chirho in [
        DrillTargetKindChirho::ProductionOwnerChirho,
        DrillTargetKindChirho::RealMoneyNodeChirho,
    ] {
        let request_chirho = HostedPartitionRequestChirho::new_chirho(
            former_owner_subject_chirho(),
            all_three_planes_chirho(),
            HostedPartitionModeSpecChirho::NetworkPartitionChirho,
            bad_kind_chirho,
            Duration::from_secs(300),
        );
        assert_eq!(
            plan_partition_chirho(&request_chirho),
            Err(HostedPartitionRefusalChirho::NonTestTargetRefusedChirho {
                target_kind_chirho: bad_kind_chirho,
            }),
            "only a synthetic drill-root test kind may be targeted"
        );
    }
}

#[test]
fn every_command_uses_an_allowlisted_verb_chirho() {
    let plan_chirho =
        plan_partition_chirho(&lawful_hung_driver_request_chirho()).expect("admitted");
    for command_chirho in plan_chirho
        .setup_chirho()
        .iter()
        .chain(plan_chirho.teardown_chirho().iter())
    {
        assert!(
            NftVerbChirho::ALL_CHIRHO.contains(&command_chirho.verb_chirho()),
            "verb {:?} is outside the reviewed allowlist",
            command_chirho.verb_chirho()
        );
        assert!(
            command_chirho
                .rendered_chirho()
                .starts_with(command_chirho.verb_chirho().canonical_chirho()),
            "rendered line must begin with its verb's canonical token: {}",
            command_chirho.rendered_chirho()
        );
    }
}

#[test]
fn no_rendered_line_touches_the_input_output_base_chain_or_a_drop_policy_chirho() {
    let plan_chirho =
        plan_partition_chirho(&lawful_hung_driver_request_chirho()).expect("admitted");
    for line_chirho in plan_chirho.all_rendered_lines_chirho() {
        // The real base chains are uppercase INPUT/OUTPUT; the drill's own chains are lowercase. We
        // must never name the real base chains at all — so no rule and no policy can reach them.
        assert!(
            !line_chirho.contains("INPUT") && !line_chirho.contains("OUTPUT"),
            "no rule may name the real INPUT/OUTPUT base chains: {line_chirho}"
        );
        // The only policy this generator sets is `accept`, and only on its own drill base chains.
        if line_chirho.contains("policy") {
            assert!(
                line_chirho.contains("policy accept") && !line_chirho.contains("policy drop"),
                "the only policy allowed is `accept` on a drill chain: {line_chirho}"
            );
        }
    }
}

#[test]
fn port_22_is_never_expressed_and_a_port_22_plane_refuses_chirho() {
    // No lawful plan mentions port 22 in any direction.
    let plan_chirho = plan_partition_chirho(&lawful_network_partition_request_chirho())
        .expect("lawful request admitted");
    for line_chirho in plan_chirho.all_rendered_lines_chirho() {
        assert!(
            !line_chirho.contains("dport 22") && !line_chirho.contains("sport 22"),
            "no rule may name the reserved SSH port: {line_chirho}"
        );
    }
    // And a request that tries to route a plane over port 22 is refused outright.
    let planes_chirho = vec![
        OverlayPlanePortChirho {
            plane_chirho: OverlayPlaneChirho::ElectorChirho,
            port_chirho: SSH_PORT_CHIRHO,
        },
        OverlayPlanePortChirho {
            plane_chirho: OverlayPlaneChirho::WriteRelayChirho,
            port_chirho: WRITE_RELAY_PORT_CHIRHO,
        },
        OverlayPlanePortChirho {
            plane_chirho: OverlayPlaneChirho::ObservationChirho,
            port_chirho: OBSERVATION_PORT_CHIRHO,
        },
    ];
    let request_chirho = HostedPartitionRequestChirho::new_chirho(
        former_owner_subject_chirho(),
        planes_chirho,
        HostedPartitionModeSpecChirho::NetworkPartitionChirho,
        DrillTargetKindChirho::DrillRootSyntheticChirho,
        Duration::from_secs(300),
    );
    assert_eq!(
        plan_partition_chirho(&request_chirho),
        Err(HostedPartitionRefusalChirho::PortTwentyTwoRefusedChirho {
            plane_chirho: OverlayPlaneChirho::ElectorChirho,
        })
    );
}

#[test]
fn no_rendered_line_carries_a_shell_metacharacter_chirho() {
    // A literal scan — NOT a call to the lib's helper — so a bug in that helper cannot hide here.
    let plan_chirho =
        plan_partition_chirho(&lawful_hung_driver_request_chirho()).expect("admitted");
    let dangerous_chirho = [
        '\'', '"', '`', '$', '\\', '|', '&', '<', '>', '\n', '\r', '\0',
    ];
    for line_chirho in plan_chirho.all_rendered_lines_chirho() {
        for character_chirho in dangerous_chirho {
            assert!(
                !line_chirho.contains(character_chirho),
                "rendered line carries shell metacharacter {character_chirho:?}: {line_chirho}"
            );
        }
    }
}

#[test]
fn a_metacharacter_laden_label_cannot_reach_a_chain_name_chirho() {
    // The label is caller free text; it must never carry a metacharacter into a rendered chain name.
    let subject_chirho = PartitionSubjectChirho {
        former_owner_label_chirho: "boaz3; rm -rf / `id` $(whoami)".to_owned(),
        former_owner_overlay_addr_chirho: Ipv4Addr::new(10, 100, 0, 7),
    };
    let request_chirho = HostedPartitionRequestChirho::new_chirho(
        subject_chirho,
        all_three_planes_chirho(),
        HostedPartitionModeSpecChirho::NetworkPartitionChirho,
        DrillTargetKindChirho::DrillRootSyntheticChirho,
        Duration::from_secs(300),
    );
    let plan_chirho =
        plan_partition_chirho(&request_chirho).expect("admitted with sanitised label");
    let dangerous_chirho = ['\'', '"', '`', '$', '\\', '|', '&', '<', '>', ';', ' '];
    for command_chirho in plan_chirho
        .setup_chirho()
        .iter()
        .chain(plan_chirho.teardown_chirho())
    {
        if command_chirho.verb_chirho() == NftVerbChirho::AddChainChirho
            || command_chirho.verb_chirho() == NftVerbChirho::FlushChainChirho
            || command_chirho.verb_chirho() == NftVerbChirho::DeleteChainChirho
        {
            let chain_chirho = chain_name_token_chirho(command_chirho.rendered_chirho());
            for character_chirho in dangerous_chirho {
                assert!(
                    !chain_chirho.contains(character_chirho),
                    "chain name {chain_chirho} must be sanitised free of {character_chirho:?}"
                );
            }
        }
    }
}

// ----------------------------------------------------------------------------------------------
// A2 completeness and overlay binding — refusals that keep a partition from being vacuous.
// ----------------------------------------------------------------------------------------------

#[test]
fn a_missing_plane_refuses_so_no_back_channel_survives_chirho() {
    let two_planes_chirho = vec![
        OverlayPlanePortChirho {
            plane_chirho: OverlayPlaneChirho::ElectorChirho,
            port_chirho: ELECTOR_PORT_CHIRHO,
        },
        OverlayPlanePortChirho {
            plane_chirho: OverlayPlaneChirho::WriteRelayChirho,
            port_chirho: WRITE_RELAY_PORT_CHIRHO,
        },
    ];
    let request_chirho = HostedPartitionRequestChirho::new_chirho(
        former_owner_subject_chirho(),
        two_planes_chirho,
        HostedPartitionModeSpecChirho::NetworkPartitionChirho,
        DrillTargetKindChirho::DrillRootSyntheticChirho,
        Duration::from_secs(300),
    );
    assert_eq!(
        plan_partition_chirho(&request_chirho),
        Err(HostedPartitionRefusalChirho::PlaneIncompleteChirho {
            missing_chirho: vec![OverlayPlaneChirho::ObservationChirho],
        }),
        "A2 requires all three planes; a missing plane is a back channel"
    );
}

#[test]
fn a_duplicate_plane_refuses_chirho() {
    let dup_planes_chirho = vec![
        OverlayPlanePortChirho {
            plane_chirho: OverlayPlaneChirho::ElectorChirho,
            port_chirho: ELECTOR_PORT_CHIRHO,
        },
        OverlayPlanePortChirho {
            plane_chirho: OverlayPlaneChirho::ElectorChirho,
            port_chirho: 8301,
        },
        OverlayPlanePortChirho {
            plane_chirho: OverlayPlaneChirho::WriteRelayChirho,
            port_chirho: WRITE_RELAY_PORT_CHIRHO,
        },
        OverlayPlanePortChirho {
            plane_chirho: OverlayPlaneChirho::ObservationChirho,
            port_chirho: OBSERVATION_PORT_CHIRHO,
        },
    ];
    let request_chirho = HostedPartitionRequestChirho::new_chirho(
        former_owner_subject_chirho(),
        dup_planes_chirho,
        HostedPartitionModeSpecChirho::NetworkPartitionChirho,
        DrillTargetKindChirho::DrillRootSyntheticChirho,
        Duration::from_secs(300),
    );
    assert_eq!(
        plan_partition_chirho(&request_chirho),
        Err(HostedPartitionRefusalChirho::DuplicatePlaneChirho {
            plane_chirho: OverlayPlaneChirho::ElectorChirho,
        })
    );
}

#[test]
fn no_planes_refuses_chirho() {
    let request_chirho = HostedPartitionRequestChirho::new_chirho(
        former_owner_subject_chirho(),
        Vec::new(),
        HostedPartitionModeSpecChirho::NetworkPartitionChirho,
        DrillTargetKindChirho::DrillRootSyntheticChirho,
        Duration::from_secs(300),
    );
    assert_eq!(
        plan_partition_chirho(&request_chirho),
        Err(HostedPartitionRefusalChirho::NoPlanesRegisteredChirho)
    );
}

#[test]
fn a_non_overlay_subject_refuses_chirho() {
    let subject_chirho = PartitionSubjectChirho {
        former_owner_label_chirho: "off-overlay".to_owned(),
        former_owner_overlay_addr_chirho: Ipv4Addr::new(192, 168, 1, 5),
    };
    let request_chirho = HostedPartitionRequestChirho::new_chirho(
        subject_chirho,
        all_three_planes_chirho(),
        HostedPartitionModeSpecChirho::NetworkPartitionChirho,
        DrillTargetKindChirho::DrillRootSyntheticChirho,
        Duration::from_secs(300),
    );
    assert_eq!(
        plan_partition_chirho(&request_chirho),
        Err(HostedPartitionRefusalChirho::SubjectNotOverlayChirho {
            addr_chirho: Ipv4Addr::new(192, 168, 1, 5),
        })
    );
}

// ----------------------------------------------------------------------------------------------
// Small parsing helpers for the reversal/sanitisation arms. The chain name is always the fifth
// whitespace token (index 4) of `<verb> chain ip filter <chain> ...` (add/flush/delete chain).
// ----------------------------------------------------------------------------------------------

fn chain_name_token_chirho(rendered_chirho: &str) -> String {
    rendered_chirho
        .split_whitespace()
        .nth(4)
        .unwrap_or_default()
        .to_owned()
}

fn teardown_index_of_chirho(
    plan_chirho: &HostedPartitionPlanChirho,
    verb_chirho: NftVerbChirho,
    chain_chirho: &str,
) -> usize {
    plan_chirho
        .teardown_chirho()
        .iter()
        .position(|command_chirho| {
            command_chirho.verb_chirho() == verb_chirho
                && chain_name_token_chirho(command_chirho.rendered_chirho()) == chain_chirho
        })
        .expect("teardown must contain the chain")
}
