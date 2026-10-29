// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use stateright::{Checker, HasDiscoveries};
use std::collections::BTreeSet;

/// All protocol laws are enabled. `max_geo_term=2` reaches a real failback and
/// `local_seq_max=2` reaches the modeled saturation boundary without enlarging the BFS casually.
fn all_laws_model_chirho(
    max_records_chirho: usize,
    money_enabled_chirho: bool,
    transition_tracking_enabled_chirho: bool,
    sink_enabled_chirho: bool,
    active_clusters_chirho: usize,
) -> ModelDChirho {
    ModelDChirho {
        max_geo_term_chirho: 2,
        local_seq_max_chirho: 2,
        max_records_chirho,
        mint_legit_law_chirho: true,
        sink_fence_law_chirho: true,
        crossing_anchor_law_chirho: true,
        local_regrant_anchor_law_chirho: true,
        exact_anchor_law_chirho: true,
        conserve_on_handoff_law_chirho: true,
        election_reset_law_chirho: true,
        wrap_refusal_law_chirho: true,
        term_floor_law_chirho: true,
        failback_term_increment_law_chirho: true,
        retire_rejected_pending_law_chirho: true,
        stale_activation_candidate_chirho: false,
        money_enabled_chirho,
        transition_tracking_enabled_chirho,
        sink_enabled_chirho,
        active_clusters_chirho,
    }
}

/// Sink + money composition bound. The second cluster is a commuting Cartesian factor for the
/// per-cluster append laws, so one active cluster preserves their counterexamples while allowing
/// four records for the complete seed/regrant/cutover/failback spine.
fn joined_model_chirho() -> ModelDChirho {
    all_laws_model_chirho(4, true, false, true, 1)
}

/// Transition bound. Both clusters remain active because an election must reset every low half;
/// journal and money dimensions are disabled because they do not participate in that predicate.
fn transition_model_chirho() -> ModelDChirho {
    all_laws_model_chirho(0, false, true, false, NUM_CLUSTERS_CHIRHO)
}

fn report_counts_chirho(label_chirho: &str, checker_chirho: &impl Checker<ModelDChirho>) {
    println!(
        "[model-d:{}] unique_states={} generated={} max_depth={}",
        label_chirho,
        checker_chirho.unique_state_count(),
        checker_chirho.state_count(),
        checker_chirho.max_depth(),
    );
}

/// Halt at the first target discovery and print its concrete action trace. A mutation green here
/// is a proof failure, not an acceptable absence of a counterexample.
fn assert_mutation_reddens_chirho(model_chirho: ModelDChirho, target_chirho: &'static str) {
    let checker_chirho = model_chirho
        .checker()
        .finish_when(HasDiscoveries::AnyOf(BTreeSet::from([target_chirho])))
        .spawn_bfs()
        .join();
    report_counts_chirho(target_chirho, &checker_chirho);
    let discovery_chirho = checker_chirho.discovery(target_chirho);
    assert!(
        discovery_chirho.is_some(),
        "mutation must redden {target_chirho}"
    );
    if let Some(path_chirho) = discovery_chirho {
        println!(
            "  [{target_chirho}] violating state: {:?}",
            path_chirho.last_state()
        );
        let actions_chirho = path_chirho.into_actions();
        println!(
            "  [{target_chirho}] {} action(s) to violation: {:?}",
            actions_chirho.len(),
            actions_chirho
        );
    }
}

#[test]
fn composite_epoch_checked_bounds_chirho() {
    assert_eq!(checked_pack_epoch_chirho(0, 0), Some(0));
    assert_eq!(
        checked_pack_epoch_chirho(u32::MAX as u64, u32::MAX as u64),
        Some(u64::MAX)
    );
    assert_eq!(checked_pack_epoch_chirho(u32::MAX as u64 + 1, 0), None);
    assert_eq!(checked_pack_epoch_chirho(0, u32::MAX as u64 + 1), None);
}

#[test]
fn pre_geo_floor_covers_current_accepted_and_pending_epochs_chirho() {
    let model_chirho = joined_model_chirho();
    let mut state_chirho = model_chirho.init_states().remove(0);
    // Deliberately order the three evidence sources independently. The helper is conservative even
    // if a later model mutation makes accepted or pending evidence exceed the current grant.
    state_chirho.local_seq_chirho = [1, 2];
    state_chirho.journals_chirho[0].push(RecordDChirho {
        identity_chirho: IdentityChirho {
            epoch_chirho: 7,
            seq_chirho: 0,
            digest_chirho: 0,
        },
        region_chirho: HOME_REGION_CHIRHO,
        anchor_chirho: None,
        granted_epoch_at_append_chirho: 7,
        held_at_mint_chirho: true,
    });
    state_chirho.pending_mint_chirho[1][1] = Some(PendingMintChirho {
        identity_chirho: IdentityChirho {
            epoch_chirho: 9,
            seq_chirho: 0,
            digest_chirho: 0,
        },
        region_chirho: 1,
        held_at_mint_chirho: false,
    });

    assert_eq!(
        model_chirho.max_pre_geo_epoch_chirho(&state_chirho),
        Some(9)
    );
    state_chirho.pending_mint_chirho[1][1] = None;
    assert_eq!(
        model_chirho.max_pre_geo_epoch_chirho(&state_chirho),
        Some(7)
    );
    state_chirho.journals_chirho[0].clear();
    assert_eq!(
        model_chirho.max_pre_geo_epoch_chirho(&state_chirho),
        Some(2)
    );
}

#[test]
fn cutover_handoff_stale_failback_spine_holds_exhaustively_chirho() {
    let checker_chirho = joined_model_chirho().checker().spawn_bfs().join();
    report_counts_chirho("joined-cutover-spine", &checker_chirho);
    checker_chirho.assert_properties();
}

#[test]
fn md7_transition_contract_holds_chirho() {
    let checker_chirho = transition_model_chirho().checker().spawn_bfs().join();
    report_counts_chirho("transition-composition", &checker_chirho);
    assert!(
        checker_chirho
            .discovery("md7-transition-contract-chirho")
            .is_none(),
        "MD7 must hold over every grant/election interleaving"
    );
    assert!(
        checker_chirho
            .discovery("md4-failback-term-increments-chirho")
            .is_none(),
        "MD4 must hold on every actual failback election"
    );
    assert!(
        checker_chirho
            .discovery("md6-failback-reachable-chirho")
            .is_some(),
        "a real failback must be reachable"
    );
    assert!(
        checker_chirho
            .discovery("md6-crash-regrant-reachable-chirho")
            .is_some(),
        "crash regrant must be reachable"
    );
}

#[test]
fn dropping_mint_legit_makes_md1_red_chirho() {
    assert_mutation_reddens_chirho(
        ModelDChirho {
            mint_legit_law_chirho: false,
            ..joined_model_chirho()
        },
        "md1-mint-under-held-term-chirho",
    );
}

#[test]
fn weakening_sink_fence_makes_md2_red_chirho() {
    assert_mutation_reddens_chirho(
        ModelDChirho {
            sink_fence_law_chirho: false,
            ..joined_model_chirho()
        },
        "md2-sink-epoch-eq-granted-chirho",
    );
}

#[test]
fn sink_fence_admits_post_crossing_replay_chirho() {
    assert_mutation_reddens_chirho(
        ModelDChirho {
            sink_fence_law_chirho: false,
            ..joined_model_chirho()
        },
        "md2-post-crossing-deposed-replay-chirho",
    );
}

#[test]
fn dropping_handoff_conservation_makes_md3_red_chirho() {
    assert_mutation_reddens_chirho(
        ModelDChirho {
            conserve_on_handoff_law_chirho: false,
            ..joined_model_chirho()
        },
        "md3-handoff-conserves-chirho",
    );
}

#[test]
fn skipping_crossing_anchor_makes_md5_red_chirho() {
    assert_mutation_reddens_chirho(
        ModelDChirho {
            crossing_anchor_law_chirho: false,
            ..joined_model_chirho()
        },
        "md5-anchor-continuity-chirho",
    );
}

#[test]
fn wrong_anchor_makes_md5_red_chirho() {
    assert_mutation_reddens_chirho(
        ModelDChirho {
            exact_anchor_law_chirho: false,
            ..joined_model_chirho()
        },
        "md5-anchor-continuity-chirho",
    );
}

#[test]
fn missing_local_regrant_anchor_makes_md5_red_chirho() {
    assert_mutation_reddens_chirho(
        ModelDChirho {
            local_regrant_anchor_law_chirho: false,
            ..joined_model_chirho()
        },
        "md5-anchor-continuity-chirho",
    );
}

#[test]
fn violating_term_floor_makes_gd5_red_chirho() {
    assert_mutation_reddens_chirho(
        ModelDChirho {
            term_floor_law_chirho: false,
            stale_activation_candidate_chirho: true,
            ..joined_model_chirho()
        },
        "gd5-first-geo-term-floor-chirho",
    );
}

#[test]
fn stale_cutover_candidate_is_refused_by_term_floor_chirho() {
    let model_chirho = ModelDChirho {
        stale_activation_candidate_chirho: true,
        ..joined_model_chirho()
    };
    let state_chirho = model_chirho.init_states().remove(0);
    assert!(
        model_chirho
            .next_state(
                &state_chirho,
                ActionDChirho::ElectionChirho {
                    to_region_chirho: 1,
                },
            )
            .is_none(),
        "the real floor guard must reject a same-term activation candidate"
    );
}

#[test]
fn same_term_failback_makes_md4_red_chirho() {
    assert_mutation_reddens_chirho(
        ModelDChirho {
            failback_term_increment_law_chirho: false,
            ..transition_model_chirho()
        },
        "md4-failback-term-increments-chirho",
    );
}

#[test]
fn retaining_rejected_pending_kills_joined_witness_chirho() {
    let checker_chirho = ModelDChirho {
        retire_rejected_pending_law_chirho: false,
        ..joined_model_chirho()
    }
    .checker()
    .spawn_bfs()
    .join();
    report_counts_chirho("retained-stale-pending", &checker_chirho);
    assert!(
        checker_chirho
            .discovery("gd6-cutover-handoff-stale-failback-spine-chirho")
            .is_none(),
        "retaining the home stale slot must prevent the joined failback append witness"
    );
}

#[test]
fn skipping_election_reset_makes_md7_red_chirho() {
    assert_mutation_reddens_chirho(
        ModelDChirho {
            election_reset_law_chirho: false,
            ..transition_model_chirho()
        },
        "md7-transition-contract-chirho",
    );
}

#[test]
fn illegal_wrap_makes_md7_red_chirho() {
    assert_mutation_reddens_chirho(
        ModelDChirho {
            wrap_refusal_law_chirho: false,
            ..transition_model_chirho()
        },
        "md7-transition-contract-chirho",
    );
}
