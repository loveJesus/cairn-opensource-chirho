// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The first GD7 branch head is evidence only. These guards make any later production consumer or
//! authority-bearing dependency an explicit reviewed migration instead of a silent adoption path.

use super::super::*;

const GD7_READ_ONLY_BRANCH_MODULE_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-host-chirho/src/reconciliation_chirho/current_view_chirho/held_evidence_transfer_chirho/read_only_branch_chirho/";
const GD7_HELD_ACTOR_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/held_coordinator_chirho.rs";
const GD7_HELD_ADOPTION_MATERIALIZER_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/held_coordinator_chirho/adoption_chirho.rs";
const GD7_HELD_ADOPTION_COMMIT_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/held_coordinator_chirho/adoption_commit_chirho.rs";
const GD7_HELD_ADOPTION_ACTOR_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/held_coordinator_chirho/adoption_commit_actor_chirho.rs";
const GD7_LOSING_EFFECT_OBLIGATION_MINT_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-host-chirho/src/reconciliation_chirho/plan_chirho/obligation_mint_chirho/mod.rs";
const GD7_HELD_ACTOR_MAILBOX_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/held_coordinator_chirho/mailbox_chirho.rs";
const GD7_GEO_NODE_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-geo-node-chirho/src/lib.rs";
const GD7_GEO_EVIDENCE_DRIVER_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-geo-node-chirho/src/held_evidence_transfer_chirho.rs";

const BRANCH_CONSUMER_CALLS_CHIRHO: &[&str] = &[
    "prepare_read_only_branch_evidence_chirho(",
    "install_prepared_read_only_branch_evidence_chirho(",
    "prepare_and_install_read_only_branch_evidence_chirho(",
    "load_active_read_only_branch_evidence_chirho(",
    "verify_active_read_only_branch_evidence_chirho(",
    "visit_active_read_only_branch_canonical_lines_chirho(",
    "gd7_read_only_branch_head_path_chirho(",
];

const FORBIDDEN_LIVE_AUTHORITY_NAMES_CHIRHO: &[&str] = &[
    "AdoptedHeldChirho",
    "LocalAppendAuthority",
    "ResidentLedgerAuthorityChirho",
    "WriterElectorChirho",
    "commit_head_chirho(",
    "set_branch_chirho(",
    "save_refs_chirho(",
    "with_head_transition_scope_chirho(",
];

#[test]
fn gd7_read_only_branch_has_only_the_actor_owned_materialization_consumer_chirho() {
    let mut inspected_branch_files_chirho = 0_usize;
    let mut install_callers_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        let raw_chirho = std::fs::read_to_string(&path_chirho)
            .unwrap_or_else(|_| panic!("read {relative_chirho}"));
        let source_chirho = production_text_chirho(&raw_chirho);
        if relative_chirho.starts_with(GD7_READ_ONLY_BRANCH_MODULE_CHIRHO) {
            inspected_branch_files_chirho += 1;
            continue;
        }
        for call_chirho in BRANCH_CONSUMER_CALLS_CHIRHO {
            if source_chirho.contains(call_chirho) {
                assert!(
                    relative_chirho == GD7_HELD_ACTOR_CHIRHO
                        || relative_chirho == GD7_HELD_ADOPTION_MATERIALIZER_CHIRHO
                        || relative_chirho == GD7_HELD_ADOPTION_COMMIT_CHIRHO,
                    "{relative_chirho} consumes GD7 read-only branch evidence through {call_chirho}; \
                     migration path: route preparation through the one actor-owned Cut A command"
                );
            }
        }
        let install_count_chirho = source_chirho
            .matches("prepare_and_install_read_only_branch_evidence_chirho(")
            .count();
        for _install_chirho in 0..install_count_chirho {
            install_callers_chirho.push(relative_chirho.clone());
        }
    }
    assert!(
        inspected_branch_files_chirho >= 2,
        "GD7 read-only branch module census went empty or moved; update this guard with the reviewed placement"
    );
    assert_eq!(
        install_callers_chirho,
        vec![GD7_HELD_ACTOR_CHIRHO.to_owned()],
        "GD7 read-only branch publication must have exactly one production caller, owned by the held actor command"
    );
}

#[test]
fn gd7_adoption_materialization_has_one_actor_mint_and_one_geo_entry_chirho() {
    let mut raw_materializer_callers_chirho = Vec::new();
    let mut mailbox_callers_chirho = Vec::new();
    let mut geo_invocation_callers_chirho = Vec::new();
    let mut namespace_owners_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        let raw_chirho = std::fs::read_to_string(&path_chirho)
            .unwrap_or_else(|_| panic!("read {relative_chirho}"));
        let source_chirho = production_text_chirho(&raw_chirho);
        if relative_chirho != GD7_HELD_ADOPTION_MATERIALIZER_CHIRHO {
            for _call_chirho in
                source_chirho.match_indices("materialize_gd7_held_adoption_candidate_chirho(")
            {
                raw_materializer_callers_chirho.push(relative_chirho.clone());
            }
        }
        if relative_chirho != GD7_HELD_ACTOR_MAILBOX_CHIRHO {
            for _call_chirho in
                source_chirho.match_indices(".prepare_adoption_materialization_chirho(")
            {
                mailbox_callers_chirho.push(relative_chirho.clone());
            }
        }
        if relative_chirho != GD7_GEO_EVIDENCE_DRIVER_CHIRHO {
            for _call_chirho in
                source_chirho.match_indices("invoke_actor_owned_adoption_materialization_chirho(")
            {
                geo_invocation_callers_chirho.push(relative_chirho.clone());
            }
        }
        if source_chirho.contains("\"gd7-adoption-materialization-chirho\"") {
            namespace_owners_chirho.push(relative_chirho);
        }
    }
    assert_eq!(
        raw_materializer_callers_chirho,
        vec![GD7_HELD_ACTOR_CHIRHO.to_owned()],
        "the opaque prepared-adoption value may be minted only inside the held actor command"
    );
    assert_eq!(
        mailbox_callers_chirho,
        vec![GD7_GEO_NODE_CHIRHO.to_owned()],
        "the production geo node must be the sole caller of the actor-owned materialization mailbox"
    );
    assert_eq!(
        geo_invocation_callers_chirho,
        vec![GD7_GEO_NODE_CHIRHO.to_owned()],
        "the completed evidence path must reach the actor through exactly one geo invocation seam"
    );
    assert_eq!(
        namespace_owners_chirho,
        vec![GD7_HELD_ADOPTION_MATERIALIZER_CHIRHO.to_owned()],
        "the actor-owned materializer must remain the sole owner of its candidate namespace"
    );
    let actor_compact_chirho: String = [GD7_HELD_ACTOR_CHIRHO, GD7_HELD_ADOPTION_ACTOR_CHIRHO]
        .into_iter()
        .map(|relative_chirho| {
            let raw_chirho = std::fs::read_to_string(workspace_root_chirho().join(relative_chirho))
                .unwrap_or_else(|_| panic!("read {relative_chirho}"));
            production_text_chirho(&raw_chirho)
                .chars()
                .filter(|character_chirho| !character_chirho.is_whitespace())
                .collect::<String>()
        })
        .collect();
    // SIX, NOT FIVE, SINCE THE MINT TRIGGER LANDED. The sixth binding is the held coordinator's
    // mint dispatch arm, which assembles the obligation-mint ports per command. The count is a
    // deliberate tripwire on this seam — every explicit ordinary-record verifier binding here is a
    // place where the WRONG verifier would silently admit a foreign record — so it is raised with a
    // named reason rather than loosened to a range.
    assert_eq!(
        actor_compact_chirho
            .matches("winner_ledger_verifier_chirho:")
            .count(),
        6,
        "Cut A, adoption commit/restart, the item-5a actor seam, and the mint dispatch arm must \
         retain six explicit ordinary-record verifier bindings"
    );
    // TWO, because the mint dispatch arm uses the SAME custody-checked journal root as Cut A — and
    // that is the property worth pinning rather than the arity. A mint arm that bound anything else
    // would be verifying the winner's ordinary records against an unchecked verifier.
    assert_eq!(
        actor_compact_chirho
            .matches("winner_ledger_verifier_chirho:&held_ledger_verifiers_chirho.journal_chirho,",)
            .count(),
        2,
        "the Cut A actor command and the mint dispatch arm must each use the custody-checked \
         journal root"
    );
    assert_eq!(
        actor_compact_chirho
            .matches(
                "winner_ledger_verifier_chirho:&ports_chirho.held_ledger_verifiers_chirho.journal_chirho,",
            )
            .count(),
        2,
        "adoption commit plus restart must use the actor's custody-checked journal root; migration path: never substitute the adjacent winner control verifier"
    );
    assert_eq!(
        actor_compact_chirho
            .matches(
                "pubwinner_ledger_verifier_chirho:&'ports_chirhodynGd7LedgerRecordVerifierPortChirho,",
            )
            .count(),
        1,
        "the item-5a actor seam must carry one injected ordinary-record verifier distinct from the winner control verifier"
    );
    assert_eq!(
        actor_compact_chirho
            .matches(
                "winner_ledger_verifier_chirho:ports_chirho.winner_ledger_verifier_chirho,",
            )
            .count(),
        1,
        "the item-5a full-plan proof must forward the injected journal verifier rather than the adjacent control verifier"
    );
    assert!(
        !actor_compact_chirho
            .contains("winner_ledger_verifier_chirho:&winner_verifier_chirho,"),
        "Cut A rebound ordinary-record authentication to the winner control key; migration path: restore the configured journal verifier"
    );
}

#[test]
fn gd7_adoption_commit_has_one_actor_mint_one_geo_entry_and_no_item5_authority_chirho() {
    let mut raw_commit_callers_chirho = Vec::new();
    let mut mailbox_callers_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        let raw_chirho = std::fs::read_to_string(&path_chirho)
            .unwrap_or_else(|_| panic!("read {relative_chirho}"));
        let source_chirho = production_text_chirho(&raw_chirho);
        if relative_chirho != GD7_HELD_ADOPTION_COMMIT_CHIRHO {
            for _call_chirho in
                source_chirho.match_indices("commit_or_reload_gd7_held_adoption_chirho(")
            {
                raw_commit_callers_chirho.push(relative_chirho.clone());
            }
        }
        if relative_chirho != GD7_HELD_ACTOR_MAILBOX_CHIRHO {
            for _call_chirho in source_chirho.match_indices(".commit_adoption_chirho(") {
                mailbox_callers_chirho.push(relative_chirho.clone());
            }
        }
    }
    assert_eq!(
        raw_commit_callers_chirho,
        vec![GD7_HELD_ADOPTION_ACTOR_CHIRHO.to_owned()],
        "only the serialized held actor may mint or reload an adoption checkpoint"
    );
    assert_eq!(
        mailbox_callers_chirho,
        vec![GD7_GEO_NODE_CHIRHO.to_owned()],
        "the production geo recovery path must be the sole adoption mailbox caller"
    );

    let adoption_source_chirho = [
        GD7_HELD_ADOPTION_COMMIT_CHIRHO,
        GD7_HELD_ADOPTION_ACTOR_CHIRHO,
    ]
    .into_iter()
    .map(|relative_chirho| {
        std::fs::read_to_string(workspace_root_chirho().join(relative_chirho))
            .unwrap_or_else(|_| panic!("read {relative_chirho}"))
    })
    .collect::<String>();
    for forbidden_chirho in [
        "ResidentLedgerAuthorityChirho",
        "commit_head_chirho(",
        "set_branch_chirho(",
        "save_refs_chirho(",
        "release_winner_barrier_chirho(",
    ] {
        assert!(
            !production_text_chirho(&adoption_source_chirho).contains(forbidden_chirho),
            "adoption commit names item-5 authority {forbidden_chirho}; migration path: keep ref movement, barrier release, compensation, and write enablement in item 5"
        );
    }

    let geo_source_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(GD7_GEO_NODE_CHIRHO))
            .expect("read geo production entry");
    let geo_production_chirho = production_text_chirho(&geo_source_chirho);
    let adopted_route_chirho = geo_production_chirho
        .find("held_geo_recovery_route_chirho(startup_phase_chirho)")
        .expect("geo path routes the restart phase before recovery producers");
    let winner_endpoint_chirho = geo_production_chirho
        .find("configured_peer_base_url_for_node_chirho(")
        .expect("PlanSealed path still resolves the winner endpoint");
    assert!(
        adopted_route_chirho < winner_endpoint_chirho,
        "AdoptedHeldChirho must branch to monitor serving before winner URL, plan, view, evidence, or materialization producers can run"
    );
}

#[test]
fn gd7_losing_effect_obligation_mint_is_opaque_actor_owned_and_production_inert_chirho() {
    let mint_source_chirho = std::fs::read_to_string(
        workspace_root_chirho().join(GD7_LOSING_EFFECT_OBLIGATION_MINT_CHIRHO),
    )
    .expect("read the GD7 losing-effect obligation mint");
    let actor_source_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(GD7_HELD_ADOPTION_ACTOR_CHIRHO))
            .expect("read the actor-owned GD7 adoption seam");
    let mailbox_source_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(GD7_HELD_ACTOR_MAILBOX_CHIRHO))
            .expect("read the held actor mailbox");
    let code_only_chirho = |source_chirho: &str| {
        production_text_chirho(source_chirho)
            .lines()
            .filter(|line_chirho| !line_chirho.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let mint_production_chirho = code_only_chirho(&mint_source_chirho);
    let actor_production_chirho = code_only_chirho(&actor_source_chirho);
    let mailbox_production_chirho = code_only_chirho(&mailbox_source_chirho);

    let token_start_chirho = mint_production_chirho
        .find("pub struct MintedGd7LosingEffectObligationChirho {")
        .expect("opaque obligation type remains production compiled");
    let token_body_chirho = &mint_production_chirho[token_start_chirho..];
    let token_end_chirho = token_body_chirho
        .find("\n}")
        .expect("opaque obligation type remains a bounded named-field struct");
    let token_fields_start_chirho = token_body_chirho
        .find('{')
        .expect("opaque obligation type retains a named-field body")
        + 1;
    let token_fields_chirho = &token_body_chirho[token_fields_start_chirho..token_end_chirho];
    assert!(
        !token_fields_chirho.contains("pub "),
        "the affine GD7 obligation exposed a public field; migration path: keep construction private and expose borrowed coordinates only"
    );
    let token_attributes_chirho = mint_production_chirho[..token_start_chirho]
        .rsplit_once("}\n")
        .map(|(_earlier_chirho, attributes_chirho)| attributes_chirho)
        .unwrap_or("");
    assert!(
        !token_attributes_chirho.contains("derive"),
        "the affine GD7 obligation gained a derived reconstruction trait; migration path: keep the runtime mint non-Clone, non-Default, and non-deserializable"
    );
    for reconstruct_chirho in [
        "impl Clone for MintedGd7LosingEffectObligationChirho",
        "impl Default for MintedGd7LosingEffectObligationChirho",
        "impl<'de> Deserialize<'de> for MintedGd7LosingEffectObligationChirho",
        "for MintedGd7LosingEffectObligationChirho {",
    ] {
        assert!(
            !mint_production_chirho.contains(reconstruct_chirho),
            "the opaque GD7 obligation gained reconstruction surface {reconstruct_chirho}; migration path: keep the runtime mint affine and non-deserializable"
        );
    }

    let mut external_mint_callers_chirho = Vec::new();
    let mut claim_callers_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        let raw_chirho = std::fs::read_to_string(&path_chirho)
            .unwrap_or_else(|_| panic!("read {relative_chirho}"));
        let source_chirho = code_only_chirho(&raw_chirho);
        if relative_chirho != GD7_HELD_ADOPTION_ACTOR_CHIRHO {
            for _call_chirho in
                source_chirho.match_indices("mint_actor_owned_gd7_losing_effect_obligation_chirho(")
            {
                external_mint_callers_chirho.push(relative_chirho.clone());
            }
        }
        if relative_chirho != GD7_LOSING_EFFECT_OBLIGATION_MINT_CHIRHO {
            for _call_chirho in
                source_chirho.match_indices("claim_verified_gd7_losing_effect_obligation_chirho(")
            {
                claim_callers_chirho.push(relative_chirho.clone());
            }
        }
    }
    // THE MINT NOW HAS EXACTLY ONE REVIEWED PRODUCTION CALLER, and this assertion changed shape
    // deliberately rather than being relaxed.
    //
    // It used to require ZERO callers, and its own migration path read "wire mint and consume
    // together in item 5b". The fleet ruling took a different route on purpose: the mint TRIGGER
    // landed as its own reviewed brick (the sixth held-coordinator command) with the consumer still
    // ahead of it. So the property worth guarding is no longer "nothing calls this" — which is now
    // false — but "exactly the one reviewed dispatch arm calls this, and nothing else".
    //
    // WHAT LANDING THE TRIGGER BEFORE THE CONSUMER COSTS, recorded here because this guard is where
    // a future reader will look for it: a durable mint receipt can now exist in production with
    // nothing yet able to consume it. That state is not silent — it is the named refusal
    // `MintedAwaitingConsumptionChirho { receipt_ref }`, and a replay reports it rather than minting
    // twice. Item 5b is what resumes such a receipt, fences the sink, and consumes the affine value.
    // Until then, a receipt awaiting consumption is a REACHABLE production state, and this comment
    // is the record of that being a known consequence rather than an oversight.
    const GD7_HELD_COORDINATOR_DISPATCH_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/held_coordinator_chirho.rs";
    let unreviewed_mint_callers_chirho: Vec<_> = external_mint_callers_chirho
        .iter()
        .filter(|caller_chirho| caller_chirho.as_str() != GD7_HELD_COORDINATOR_DISPATCH_CHIRHO)
        .cloned()
        .collect();
    assert!(
        unreviewed_mint_callers_chirho.is_empty(),
        "item 5a acquired an UNREVIEWED production caller: {unreviewed_mint_callers_chirho:?}; the \
         only reviewed caller is the held coordinator's mint dispatch arm. migration path: if this \
         caller is item 5b's consumer, name it here with its reason; otherwise it should be going \
         through the mailbox command rather than calling the internal mint directly"
    );
    // AND THE REVIEWED CALLER MUST STILL BE THERE. Without this, deleting the dispatch arm would
    // make the filter above trivially empty and this guard would report success over a command that
    // no longer exists — coverage dying quietly, which is the failure mode this file's own header
    // warns about.
    assert_eq!(
        external_mint_callers_chirho
            .iter()
            .filter(|caller_chirho| caller_chirho.as_str() == GD7_HELD_COORDINATOR_DISPATCH_CHIRHO)
            .count(),
        1,
        "the held coordinator's reviewed mint dispatch call is missing or duplicated; exactly one \
         production trigger must exist, or this guard is measuring an absent command"
    );
    assert_eq!(
        actor_production_chirho
            .matches("mint_actor_owned_gd7_losing_effect_obligation_chirho(")
            .count(),
        1,
        "item 5a must retain exactly one uncalled actor-owned entry definition"
    );
    assert_eq!(
        claim_callers_chirho,
        vec![GD7_HELD_ADOPTION_ACTOR_CHIRHO.to_owned()],
        "the low-level durable claim must have exactly one production caller, inside the actor-owned seam"
    );
    assert_eq!(
        mint_production_chirho
            .matches("claim_verified_gd7_losing_effect_obligation_chirho(")
            .count(),
        1,
        "the obligation-mint module must contain only the low-level claim definition; additional in-module callers would bypass the actor-owned census"
    );
    assert!(
        actor_production_chirho.contains("verify_gd7_sealed_plan_obligation_at_checkpoint_chirho("),
        "the production actor mint stopped traversing the exact complete sealed plan"
    );
    // ---------------------------------------------------------------------------------------
    // THIS ASSERTION WAS DELIBERATELY INVERTED, AND IT IS THE ONE CHANGE IN THE MINT-TRIGGER
    // BRICK THAT OVERRIDES A LANDED GUARD'S OWN STATED RATIONALE. It is recorded here in full
    // rather than in a commit message, because this is where the next reader will meet it.
    //
    // IT USED TO SAY: item 5a must NOT be mailbox reachable "before item 5b can atomically resume
    // and consume it" — the mailbox file was forbidden from naming either the minted type or the
    // internal mint. The rationale was real: a mailbox-reachable mint can produce a DURABLE RECEIPT
    // THAT NOTHING CAN YET CONSUME, stranding an affine value.
    //
    // WHAT CHANGED: the fleet ruled the mint TRIGGER as its own reviewed brick — the sixth
    // held-coordinator command — with item 5b's consumer still ahead of it, after an independent
    // measurement found the mailbox to be the seam that FITS the authority boundary (the request
    // carries a selector only; the held signer, port bundle, and adoption CAS checks all stay
    // inward). So the sequencing this assertion encoded is not the sequencing the fleet chose.
    //
    // WHAT IS STILL TRUE, and is what this now guards: mailbox reachability must not have bought
    // the caller any RECONSTRUCTION power over the affine value. The mailbox may NAME the minted
    // type — it has to, to return it — but it must never gain a way to build, clone, or
    // deserialize one, and it must not reach the internal mint directly instead of through the
    // reviewed dispatch arm.
    //
    // THE COST, NAMED: a receipt awaiting consumption is now a reachable production state. It is
    // not silent — `MintedAwaitingConsumptionChirho { receipt_ref }` names it and a replay reports
    // it rather than minting twice — but until item 5b lands, nothing consumes it.
    // ---------------------------------------------------------------------------------------
    assert!(
        !mailbox_production_chirho.contains("mint_actor_owned_gd7_losing_effect_obligation_chirho"),
        "the mailbox reached the internal mint DIRECTLY, bypassing the reviewed dispatch arm that \
         wraps it in custody checks; migration path: the mailbox sends a command, the actor mints"
    );
    for reconstruction_chirho in [
        "MintedGd7LosingEffectObligationChirho {",
        "MintedGd7LosingEffectObligationChirho::",
    ] {
        assert!(
            !mailbox_production_chirho.contains(reconstruction_chirho),
            "the mailbox gained reconstruction surface {reconstruction_chirho} over the affine \
             mint receipt; it may NAME the type to return it and nothing more"
        );
    }
    // NON-VACUITY for the pair above: the mailbox must actually name the type, or these two
    // assertions are passing over a file that no longer carries the command at all.
    assert!(
        mailbox_production_chirho.contains("MintedGd7LosingEffectObligationChirho"),
        "the mailbox no longer names the minted type, so the sixth command's reply is gone and the \
         reconstruction checks above are measuring an absent surface"
    );

    for forbidden_chirho in [
        "VerifiedEffectCompensationChirho",
        "advance_accepted_winner_term_chirho",
        "append_with_current_fence_chirho",
        "execute_or_query_observation_chirho",
        "release_winner_barrier_chirho",
        "set_branch_chirho(",
        "save_refs_chirho(",
    ] {
        assert!(
            !mint_production_chirho.contains(forbidden_chirho),
            "item 5a names downstream authority {forbidden_chirho}; migration path: keep compensation, sink fencing, ref movement, and barrier release in later item-5 cuts"
        );
    }
}

#[test]
fn gd7_read_only_branch_module_carries_no_live_authority_name_chirho() {
    let branch_files_chirho: Vec<_> = workspace_production_rs_files_chirho()
        .into_iter()
        .filter(|path_chirho| {
            workspace_relative_chirho(path_chirho).starts_with(GD7_READ_ONLY_BRANCH_MODULE_CHIRHO)
        })
        .collect();
    assert!(
        !branch_files_chirho.is_empty(),
        "GD7 read-only branch source disappeared; do not let an empty scan certify evidence isolation"
    );
    for path_chirho in branch_files_chirho {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        let raw_chirho = std::fs::read_to_string(&path_chirho)
            .unwrap_or_else(|_| panic!("read {relative_chirho}"));
        let source_chirho = production_text_chirho(&raw_chirho);
        for forbidden_chirho in FORBIDDEN_LIVE_AUTHORITY_NAMES_CHIRHO {
            assert!(
                !source_chirho.contains(forbidden_chirho),
                "{relative_chirho} names live authority {forbidden_chirho}; \
                 migration path: keep evidence construction separate until L.J. authorizes adoption"
            );
        }
    }
}

#[test]
fn gd7_read_only_branch_head_family_has_one_production_owner_chirho() {
    let owners_chirho: Vec<_> = workspace_production_rs_files_chirho()
        .into_iter()
        .filter_map(|path_chirho| {
            let raw_chirho = std::fs::read_to_string(&path_chirho).ok()?;
            production_text_chirho(&raw_chirho)
                .contains("\"held-read-only-branch-heads-chirho\"")
                .then(|| workspace_relative_chirho(&path_chirho))
        })
        .collect();
    assert_eq!(
        owners_chirho,
        vec![format!("{GD7_READ_ONLY_BRANCH_MODULE_CHIRHO}mod.rs")],
        "GD7 branch-head ownership changed; migration path: review every new producer or reader before widening the evidence boundary"
    );
}
