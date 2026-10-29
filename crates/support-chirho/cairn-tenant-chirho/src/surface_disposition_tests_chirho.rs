// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Every surface gets a decision, custody-bearing surfaces REFUSE, and a new surface fails closed.

use super::*;

fn observed_chirho(names_chirho: &[&str]) -> Vec<String> {
    names_chirho
        .iter()
        .map(|n_chirho| n_chirho.to_string())
        .collect()
}

fn carried_is_not_travelling_mutation_chirho(disposition_chirho: SurfaceDispositionChirho) -> bool {
    match disposition_chirho {
        SurfaceDispositionChirho::CarriedWithTheRootChirho => false,
        other_chirho => surface_travels_with_the_root_chirho(other_chirho),
    }
}

#[test]
fn disposition_population_digest_tracks_semantics_not_row_order_chirho() {
    let declared_logs_chirho = declared_log_surfaces_chirho();
    let baseline_chirho = disposition_population_digest_chirho();
    assert_eq!(baseline_chirho.as_str_chirho().len(), 64);
    assert!(baseline_chirho
        .as_str_chirho()
        .bytes()
        .all(|byte_chirho| byte_chirho.is_ascii_digit() || matches!(byte_chirho, b'a'..=b'f')));

    let mut reordered_rows_chirho = NON_LOG_SURFACE_POLICIES_CHIRHO.to_vec();
    reordered_rows_chirho.reverse();
    assert_eq!(
        disposition_population_digest_for_inputs_chirho(
            &reordered_rows_chirho,
            &declared_logs_chirho,
            PLATFORM_ONLY_LOG_SURFACES_CHIRHO,
            surface_travels_with_the_root_chirho,
        ),
        baseline_chirho,
        "declaration order and source comments are not classifier semantics"
    );

    let mut changed_row_chirho = NON_LOG_SURFACE_POLICIES_CHIRHO.to_vec();
    changed_row_chirho[0].1.movement_disposition_chirho = if surface_travels_with_the_root_chirho(
        changed_row_chirho[0].1.movement_disposition_chirho,
    ) {
        SurfaceDispositionChirho::ProvenDisposableChirho
    } else {
        SurfaceDispositionChirho::CarriedWithTheRootChirho
    };
    assert_ne!(
        disposition_population_digest_for_inputs_chirho(
            &changed_row_chirho,
            &declared_logs_chirho,
            PLATFORM_ONLY_LOG_SURFACES_CHIRHO,
            surface_travels_with_the_root_chirho,
        ),
        baseline_chirho,
        "changing one policy row must change classifier identity"
    );

    let mut missing_log_chirho = declared_logs_chirho.clone();
    let removed_log_chirho = missing_log_chirho
        .pop_first()
        .expect("the declared log manifest must not be empty");
    assert!(!removed_log_chirho.is_empty());
    assert_ne!(
        disposition_population_digest_for_inputs_chirho(
            NON_LOG_SURFACE_POLICIES_CHIRHO,
            &missing_log_chirho,
            PLATFORM_ONLY_LOG_SURFACES_CHIRHO,
            surface_travels_with_the_root_chirho,
        ),
        baseline_chirho,
        "removing one declared log must change classifier identity"
    );

    // The platform-only logs are classifier input too. Without this case, a log could leave that
    // list and turn from "not a migration unit" into "undisposed" with the digest unchanged.
    assert_ne!(
        disposition_population_digest_for_inputs_chirho(
            NON_LOG_SURFACE_POLICIES_CHIRHO,
            &declared_logs_chirho,
            &PLATFORM_ONLY_LOG_SURFACES_CHIRHO[1..],
            surface_travels_with_the_root_chirho,
        ),
        baseline_chirho,
        "removing one platform-only log must change classifier identity"
    );
    let mut reordered_platform_chirho = PLATFORM_ONLY_LOG_SURFACES_CHIRHO.to_vec();
    reordered_platform_chirho.reverse();
    assert_eq!(
        disposition_population_digest_for_inputs_chirho(
            NON_LOG_SURFACE_POLICIES_CHIRHO,
            &declared_logs_chirho,
            &reordered_platform_chirho,
            surface_travels_with_the_root_chirho,
        ),
        baseline_chirho,
        "the platform-only list's order is not classifier semantics"
    );

    assert_ne!(
        disposition_population_digest_for_inputs_chirho(
            NON_LOG_SURFACE_POLICIES_CHIRHO,
            &declared_logs_chirho,
            PLATFORM_ONLY_LOG_SURFACES_CHIRHO,
            carried_is_not_travelling_mutation_chirho,
        ),
        baseline_chirho,
        "changing the travel predicate with zero row changes must change classifier identity"
    );
    assert_eq!(
        disposition_population_digest_for_inputs_chirho(
            NON_LOG_SURFACE_POLICIES_CHIRHO,
            &declared_logs_chirho,
            PLATFORM_ONLY_LOG_SURFACES_CHIRHO,
            surface_travels_with_the_root_chirho,
        ),
        baseline_chirho,
        "restoring all semantic inputs must restore the exact identity"
    );
}

#[test]
fn a_surface_nobody_has_disposed_of_refuses_chirho() {
    // The fail-closed rule, and the one that has to survive future platform growth: a surface added
    // next year with no disposition must go RED, not be quietly skipped. Skipping is how a migration
    // leaves something behind while reporting success.
    let verdict_chirho = verify_surface_dispositions_chirho(
        &observed_chirho(&["objects-chirho", "a-surface-invented-next-year-chirho"]),
        None,
    );
    assert_eq!(
        verdict_chirho.refusals_chirho,
        vec![DispositionRefusalChirho::UndisposedSurfaceChirho {
            surface_chirho: "a-surface-invented-next-year-chirho".to_string(),
        }]
    );
    assert!(!verdict_chirho.is_disposed_over_evidence_chirho());
}

#[test]
fn a_signing_key_is_disposed_through_the_move_mechanism_chirho() {
    // RETARGETED, and the fixture is unchanged so this green is a statement about the CODE. This arm
    // previously asserted that a signing key refuses the whole migration, which was correct for as long
    // as no mechanism existed: how a private key moves between hosts is a security design question, not
    // a table entry. `move_chirho::move_stages_chirho` is now that mechanism — custody placed before the
    // writer moves, source key erased only after handoff, reversible until retirement — so the surface
    // is disposed rather than refused.
    //
    // If this arm ever REFUSES again, the ruling was reverted and the move mechanism should be checked
    // first. If it passes with an EMPTY table entry for the key, the disposition was deleted rather
    // than changed, which is a different and worse thing.
    let verdict_chirho = verify_surface_dispositions_chirho(
        &observed_chirho(&["objects-chirho", "signing-key-chirho.bin"]),
        None,
    );
    assert!(
        verdict_chirho.refusals_chirho.is_empty(),
        "the signing key now moves through the staged custody mechanism: {:?}",
        verdict_chirho.refusals_chirho
    );
    assert!(verdict_chirho.is_disposed_over_evidence_chirho());
}

#[test]
fn movement_payload_and_retirement_are_three_independent_axes_chirho() {
    let control_chirho = policy_for_surface_chirho(TENANT_MOVE_CONTROL_SURFACE_CHIRHO)
        .expect("move control has one complete policy row");
    assert!(surface_travels_with_the_root_chirho(
        control_chirho.movement_disposition_chirho
    ));
    assert!(!surface_is_committed_payload_chirho(control_chirho));
    assert!(!source_erases_surface_after_handoff_chirho(control_chirho));

    let private_chirho = policy_for_surface_chirho("signing-key-chirho.bin")
        .expect("private signing key is classified");
    assert!(surface_travels_with_the_root_chirho(
        private_chirho.movement_disposition_chirho
    ));
    assert!(surface_is_committed_payload_chirho(private_chirho));
    assert!(source_erases_surface_after_handoff_chirho(private_chirho));

    let public_chirho = policy_for_surface_chirho("pubkey-chirho.hex")
        .expect("public verifier material is classified");
    assert_eq!(
        public_chirho.movement_disposition_chirho, private_chirho.movement_disposition_chirho,
        "public and private key material travel through the same movement mechanism"
    );
    assert!(surface_is_committed_payload_chirho(public_chirho));
    assert!(
        !source_erases_surface_after_handoff_chirho(public_chirho),
        "public verifier material survives source retirement"
    );

    assert_eq!(
        policy_for_surface_chirho("unclassified-next-surface-chirho"),
        None,
        "classification on one axis must never supply defaults on the other two"
    );
}

#[test]
fn a_surface_nobody_has_disposed_still_fails_the_whole_migration_closed_chirho() {
    // The fail-closed DEFAULT, which the custody ruling did not touch and must not. A surface nobody
    // has decided about stops a migration rather than riding along — and this is the arm that keeps the
    // ruling narrow, because without it "the signing key is fine now" could quietly become "surfaces
    // are fine now".
    let verdict_chirho = verify_surface_dispositions_chirho(
        &observed_chirho(&["objects-chirho", "a-surface-nobody-decided-about-chirho"]),
        None,
    );
    assert_eq!(
        verdict_chirho.refusals_chirho,
        vec![DispositionRefusalChirho::UndisposedSurfaceChirho {
            surface_chirho: "a-surface-nobody-decided-about-chirho".to_string(),
        }]
    );
    assert!(!verdict_chirho.is_disposed_over_evidence_chirho());
}

#[test]
fn a_platform_root_is_not_a_migration_unit_chirho() {
    let verdict_chirho =
        verify_surface_dispositions_chirho(&observed_chirho(&["tenants-chirho"]), None);
    assert_eq!(
        verdict_chirho.refusals_chirho,
        vec![DispositionRefusalChirho::NotAMigrationUnitChirho {
            surface_chirho: "tenants-chirho".to_string(),
        }],
        "G1 says the placement/authority/migration unit is the TENANT root; a platform root holding \
         tenants-chirho is not movable as one"
    );
}

#[test]
fn the_runtime_record_chain_is_carried_never_rebuilt_chirho() {
    // THE CORRECTION, pinned so it cannot quietly revert. These four are GC ROOTS
    // (gc_chirho::RUNTIME_RECORD_DIRS_CHIRHO) and the audit chain: RunResultChirho carries
    // effects_chirho, the signed effect log, and verify re-hashes runkey sidecars. Marking any of
    // them "rebuilt at target" would authorise discarding the signed record of what happened, from
    // what, by what code, and authorised by whom — inside a change that reads like bookkeeping.
    for surface_chirho in [
        "runs-chirho",
        "runkeys-chirho",
        "runseals-chirho",
        "effects-chirho",
    ] {
        assert_eq!(
            disposition_for_surface_chirho(surface_chirho),
            Some(SurfaceDispositionChirho::CarriedWithTheRootChirho),
            "{surface_chirho} is a GC root and part of the audit chain — it must be CARRIED. If this \
             ever reads RebuiltAtTargetChirho, a migration may drop signed effect history while \
             reporting success"
        );
    }
}

#[test]
fn only_authority_state_is_rebuilt_and_each_names_what_it_is_rebuilt_from_chirho() {
    // RETARGETED TWICE on 2026-08-19: first when `writer-fences-chirho` earned the variant, then when
    // `sink-term-fences-chirho` did. Both are AUTHORITY STATE — a writer fence and a sink-side
    // winner-term fence — and that is the only category admitted here. Both were OBSERVED on the
    // real drill root before being given a disposition, which is what this arm's own message demands.
    //
    // If a surface that is not authority state appears in this list, the ruling was made from a name
    // rather than from what the surface holds.
    //
    // ORIGINALLY this arm read `no_surface_claims_to_be_rebuildable_today`
    // and was an honest empty row: the variant existed and nothing had earned it. `writer-fences-chirho`
    // now earns it, so the arm was updated deliberately rather than deleted — its own instruction was
    // to say what the surface is reconstructed FROM and to confirm it is not a GC root, and both are
    // discharged here.
    //
    // REBUILT FROM WHAT: not from carried bytes at all — from the TARGET'S OWN ELECTION. The writer
    // fence records this root's writer epoch, and the target establishes its own through its own
    // elected authority. That is why carrying it would be wrong (a live epoch arriving at the target)
    // and why proving it disposable would also be wrong (a fenceless target refuses a stale source
    // token with the WRONG identity).
    //
    // NOT A GC ROOT, measured rather than asserted: `gc_skip_dir_chirho` lists it among the
    // directories GC does not scan as reference sources, so rebuilding it cannot orphan an object.
    // Its only other uses are root DETECTION in privacy backup and a second skip-list in seqlog;
    // neither treats it as retention.
    //
    // THE TABLE ITSELF MUST BE NON-EMPTY, or this assertion and two others below pass vacuously:
    // "exactly one surface is rebuilt" is checkable, but "no disposed surface is also a declared log
    // surface" is trivially true of an empty table. An emptied table would turn green tests into
    // statements about nothing while the migration lost every disposition.
    // 18 -> 21 on 2026-08-19, and the three were measured exactly as this message demands. The
    // twenty-second row is the dedicated move-control namespace, registered before its first write
    // after controlled host scans proved there are no retained rows needing legacy routing. A
    // hosted migration activated into a target that could not start; the three surfaces holding its
    // signing identity, its per-subject privacy keys and its per-subject identity credentials were
    // OBSERVED on the live drill source root, mode 600, and were undisposed. Each answer is a
    // measurement: a migrated journal cannot open under fresh signer material (verification binds
    // to the injected key), and leaving privacy keys behind is crypto-shredding rather than
    // migration. The twenty-third row is the F1 mirror namespace, added after the original surface
    // census and ruled from the signed recovery/high-water and committed-pending bytes it holds.
    // The twenty-fourth row is viewer-state, registered before the first production write and
    // carried because its bounded versions and signed mutation receipts are customer payload.
    // 24 -> 32 on 2026-10-26 (CF8 Step B, AICEO #29534). Seven rows come from the 21-surface census,
    // each ruled from the module that writes it: three exactly-once state redbs, the geo-genesis
    // guard and the gate1 authority head (all carried), and the read model and native workers
    // (disposable, each rebuilt by its own code). The eighth is C2.1's law marker, registered before
    // its first production write. The census's logs live in the two log lists, not here.
    // 32 -> 33 on 2026-10-27 (C5 B3-a2-ii): the leader's erasure-propagation store, registered before
    // its first production write. Its code first reached main at 262c70c4, after every deployed
    // binary, and nothing in production opens it yet, so no retained root can hold one.
    assert_eq!(
        NON_LOG_SURFACE_POLICIES_CHIRHO.len(),
        33,
        "the policy table changed size. Existing surfaces must be measured with
         `tenant-migration-verify`; a genuinely new top-level surface must be registered before its
         first write and carry a controlled compatibility census. Update this count deliberately,
         because a SHRINKING table makes the other tests in this file vacuous"
    );
    let rebuildable_chirho: Vec<&str> = NON_LOG_SURFACE_POLICIES_CHIRHO
        .iter()
        .filter(|(_, policy_chirho)| {
            policy_chirho.movement_disposition_chirho
                == SurfaceDispositionChirho::RebuiltAtTargetChirho
        })
        .map(|(name_chirho, _)| *name_chirho)
        .collect();
    // 2 -> 1 -> 0 across 2026-08-19, and the arm is now asserting EMPTINESS deliberately rather
    // than by neglect. Both fence surfaces left this set once their contents were measured instead
    // of inferred from their names: the sink-term cell is a tenant-scoped monotonic mark that
    // travels, and the writer fence turned out to DECIDE THE ROOT'S AUTHORITY ERA — absent, a
    // geo-elected root silently comes up locally authorized.
    //
    // An empty set makes this particular assertion carry no information about rebuilt surfaces,
    // which is exactly what this arm's own message warns about — so it is now a TRIPWIRE: if any
    // surface ever claims rebuilt-at-target again, it must be reasoned about here, and something
    // must say what it is reconstructed FROM.
    assert_eq!(
        rebuildable_chirho,
        Vec::<&str>::new(),
        "a surface claims to be rebuilt-at-target that this arm has not reasoned about. That is a \
         real decision, not a default — say in the table's own words what it is reconstructed FROM, \
         and confirm with `gc_skip_dir_chirho` that it is not a GC root"
    );
    // And the audit chain must never join it. If one of these ever reads rebuilt, a migration could
    // drop signed history while reporting success.
    for gc_root_chirho in [
        "runs-chirho",
        "runkeys-chirho",
        "runseals-chirho",
        "effects-chirho",
        "objects-chirho",
    ] {
        assert!(
            !rebuildable_chirho.contains(&gc_root_chirho),
            "{gc_root_chirho} is a GC root and part of the audit chain — it must never be rebuilt"
        );
    }
}

#[test]
fn declared_log_surfaces_are_carried_without_being_restated_chirho() {
    // The 94 log surfaces must NOT be duplicated into the disposition table — that is the same
    // two-lists-drift hazard the declared set was built to avoid. They inherit "carried" from being
    // the tenant's signed history.
    let known_log_chirho = crate::migration_completeness_chirho::declared_log_surfaces_chirho();
    let sample_chirho = known_log_chirho
        .iter()
        .next()
        .expect("the projection manifest must not be empty");
    assert_eq!(
        disposition_for_surface_chirho(sample_chirho),
        Some(SurfaceDispositionChirho::CarriedWithTheRootChirho)
    );
    for (name_chirho, _) in NON_LOG_SURFACE_POLICIES_CHIRHO {
        assert!(
            !known_log_chirho.contains(*name_chirho),
            "{name_chirho} is restated in the disposition table AND declared as a log surface — one \
             of the two lists will drift"
        );
    }
}

#[test]
fn a_fully_disposed_root_passes_over_evidence_chirho() {
    // Non-vacuity's other edge: the refusal tests above would all still pass if this function
    // refused EVERYTHING. A realistic movable root must actually clear.
    let verdict_chirho = verify_surface_dispositions_chirho(
        &observed_chirho(&[
            "objects-chirho",
            "refs-chirho.json",
            "runs-chirho",
            "locks-chirho",
            "tenant-chirho.json",
        ]),
        None,
    );
    assert!(
        verdict_chirho.refusals_chirho.is_empty(),
        "a root of fully disposed surfaces must clear; got {:?}",
        verdict_chirho.refusals_chirho
    );
    assert!(verdict_chirho.is_disposed_over_evidence_chirho());
}

#[test]
fn an_empty_root_is_not_disposed_over_evidence_chirho() {
    let verdict_chirho = verify_surface_dispositions_chirho(&[], None);
    assert!(
        !verdict_chirho.is_disposed_over_evidence_chirho(),
        "zero surfaces considered is not a clearance — the same anti-vacuity rule the other two \
         halves carry"
    );
}

#[test]
fn the_full_manifest_is_the_logs_plus_the_disposed_surfaces_chirho() {
    // Completeness must ask about EVERY declared surface, not only the log ones. Before this,
    // objects-chirho reported as UNDECLARED on every real root while the disposition table named it
    // by hand — reporting a decision that HAD been made as one that had not, and burying the custody
    // refusal under seven false findings.
    let full_chirho = crate::migration_completeness_chirho::declared_root_surfaces_chirho();
    let logs_chirho = crate::migration_completeness_chirho::declared_log_surfaces_chirho();
    for surface_chirho in logs_chirho.iter() {
        assert!(
            full_chirho.contains(surface_chirho),
            "the full manifest dropped log surface {surface_chirho}"
        );
    }
    for (surface_chirho, _) in NON_LOG_SURFACE_POLICIES_CHIRHO {
        assert!(
            full_chirho.contains(*surface_chirho),
            "the full manifest dropped disposed surface {surface_chirho} — it would then report as \
             UNDECLARED on every real root"
        );
    }
    assert!(
        full_chirho.len() > logs_chirho.len(),
        "the full manifest must be strictly larger than the log manifest, or the non-log half is \
         not being added at all"
    );
}

#[test]
fn a_declared_logs_head_sidecar_is_carried_and_a_stray_one_is_not_chirho() {
    use crate::migration_completeness_chirho::declared_log_surfaces_chirho;
    // FOUND BY RUNNING THE DRILL. A real target refused on FOURTEEN `<log>.head-chirho` sidecars —
    // the O(1) head checkpoints beside logs that were themselves carried. The companion of a carried
    // surface is not a separate decision, so this is DERIVED from the log's disposition rather than
    // enumerated: a row per sidecar would need a new row every time a log is added, and would be
    // missing exactly when someone forgot.
    let a_declared_log_chirho = declared_log_surfaces_chirho()
        .into_iter()
        .next()
        .expect("the log manifest is non-empty, or this arm measures nothing");
    let sidecar_chirho = format!("{a_declared_log_chirho}.head-chirho");

    assert_eq!(
        disposition_for_surface_chirho(&sidecar_chirho),
        Some(SurfaceDispositionChirho::CarriedWithTheRootChirho),
        "{sidecar_chirho} is the head of a declared log and must be carried with it"
    );
    // THE DERIVATION MUST NOT BECOME A BLANKET SUFFIX RULE. A sidecar whose stripped name is NOT a
    // declared log is an unknown surface and must still refuse — otherwise anything could be carried
    // by appending the suffix to it, which is a hole rather than a rule.
    assert_eq!(
        disposition_for_surface_chirho("not-a-declared-log-at-all-chirho.head-chirho"),
        None,
        "a sidecar of something that is not a declared log must stay undisposed"
    );
}

#[test]
fn every_surface_the_disposition_half_recognises_is_also_declared_to_completeness_chirho() {
    // THE DRIFT THIS CLOSES, measured on a real target on 2026-08-19. Both halves answer "do I know
    // this surface", and both derive their answer from ONE table — so they should never disagree.
    // They did: disposition learned the head-sidecar derivation, completeness did not, and a
    // fully-disposed target still refused as INCOMPLETE. The operator then read two failing half
    // names for one cause.
    //
    // Derived, never enumerated: a hand-written list of expected surfaces would go stale exactly
    // when a log or a table row is added, which is the failure mode being removed.
    let manifest_chirho = crate::migration_completeness_chirho::declared_root_surfaces_chirho();
    let logs_chirho = crate::migration_completeness_chirho::declared_log_surfaces_chirho();

    // Direction 1: anything disposition recognises must be in the manifest, or completeness refuses
    // a surface that has a ruling.
    for log_chirho in logs_chirho.iter() {
        let sidecar_chirho = format!(
            "{log_chirho}{}",
            cairn_seqlog_chirho::SEQLOG_HEAD_SUFFIX_CHIRHO
        );
        assert!(
            disposition_for_surface_chirho(&sidecar_chirho).is_some(),
            "{sidecar_chirho} lost its derived disposition"
        );
        assert!(
            manifest_chirho.contains(&sidecar_chirho),
            "{sidecar_chirho} has a disposition but is not declared — completeness would refuse a \
             surface disposition carries"
        );
    }

    // Direction 2: anything declared must have a ruling, or disposition refuses a surface the
    // manifest claims to know. Both directions, because drift has no preferred side.
    for surface_chirho in manifest_chirho.iter() {
        assert!(
            disposition_for_surface_chirho(surface_chirho).is_some(),
            "{surface_chirho} is declared to completeness but no disposition rules it"
        );
    }
    assert!(
        !logs_chirho.is_empty() && manifest_chirho.len() > logs_chirho.len() * 2,
        "the manifest must exceed logs-plus-sidecars, or this arm is measuring an empty world"
    );
}

#[test]
fn a_target_missing_a_surface_the_model_says_travels_is_refused_chirho() {
    use crate::surface_disposition_chirho::{
        verify_required_surfaces_chirho, RequiredSurfaceRefusalChirho,
    };
    // THE FINDING OF THE FIRST REAL MIGRATION (2026-08-19), pinned. A target passed all three of
    // the other halves and activated into a root that could not start, because the surfaces holding
    // its signing identity were absent — and absence was invisible to every question being asked.
    let travelling_chirho = NON_LOG_SURFACE_POLICIES_CHIRHO
        .iter()
        .find(|(_, policy_chirho)| {
            crate::surface_disposition_chirho::surface_travels_with_the_root_chirho(
                policy_chirho.movement_disposition_chirho,
            )
        })
        .map(|(surface_chirho, _)| (*surface_chirho).to_owned())
        .expect("the table declares at least one travelling surface, or this arm measures nothing");
    let disposable_chirho = NON_LOG_SURFACE_POLICIES_CHIRHO
        .iter()
        .find(|(_, policy_chirho)| {
            matches!(
                policy_chirho.movement_disposition_chirho,
                SurfaceDispositionChirho::ProvenDisposableChirho
            )
        })
        .map(|(surface_chirho, _)| (*surface_chirho).to_owned())
        .expect("the table declares at least one disposable surface");

    let source_chirho = vec![travelling_chirho.clone(), disposable_chirho.clone()];

    // Missing the travelling one: REFUSED, naming it.
    let missing_chirho = verify_required_surfaces_chirho(&source_chirho, &[disposable_chirho]);
    assert_eq!(
        missing_chirho.refusals_chirho,
        vec![RequiredSurfaceRefusalChirho::MissingAtTargetChirho {
            surface_chirho: travelling_chirho.clone(),
        }],
        "a surface the model says travels was missing at the target and must be named"
    );
    assert!(!missing_chirho.is_complete_over_evidence_chirho());

    // Present: clean, over real evidence.
    let present_chirho = verify_required_surfaces_chirho(&source_chirho, &source_chirho);
    assert!(
        present_chirho.is_complete_over_evidence_chirho(),
        "everything that travels is at the target"
    );

    // A DISPOSABLE surface missing is NOT a refusal — otherwise this half would demand a target
    // carry the very things the disposition model says to leave behind.
    let disposable_absent_chirho =
        verify_required_surfaces_chirho(&source_chirho, &[travelling_chirho]);
    assert!(
        disposable_absent_chirho.is_complete_over_evidence_chirho(),
        "a proven-disposable surface absent at the target is correct, not a fault"
    );

    // ANTI-VACUITY: an empty source offers nothing to be missing, and must not read as complete.
    let vacuous_chirho = verify_required_surfaces_chirho(&[], &[]);
    assert!(
        !vacuous_chirho.is_complete_over_evidence_chirho(),
        "zero required surfaces considered is not a clearance — a silent empty source would make \
         every target look complete, which is the exact shape this half exists to catch"
    );
}

#[test]
fn the_writer_fence_lock_surface_travels_because_only_birth_creates_one_chirho() {
    // REPLACES `a_lock_is_proven_disposable_chirho`, which asserted the opposite. That arm was not
    // wrong about locks in general — it was wrong that this FILE is one.
    // FOUND BY EXECUTING (2026-08-19). `locks-chirho` was proven-disposable on the reasoning that a
    // lock is live process state. The file is not the lock: every lock file is zero bytes and the
    // storage layer refuses a non-empty one, so it carries no state and blocks nobody. What makes it
    // required is that only the root BIRTH path provisions one, and a migrated root is adopted
    // rather than born — so dropping it makes the target permanently unopenable rather than clean.
    assert_eq!(
        disposition_for_surface_chirho("locks-chirho"),
        Some(SurfaceDispositionChirho::CarriedWithTheRootChirho),
        "the lock surface must travel, or a migrated root has no writer-fence lock and nothing to \
         create one"
    );
    assert!(
        crate::surface_disposition_chirho::surface_travels_with_the_root_chirho(
            SurfaceDispositionChirho::CarriedWithTheRootChirho
        ),
        "and it must therefore be REQUIRED at the target, which is what makes an incompletely \
         staged migration fail closed instead of activating into a root that cannot start"
    );
    // The sibling stays disposable, and that contrast is the point: the resident writer directory
    // holds an identity bound to the SOURCE root's device and inode, which the target must not
    // inherit — and unlike the lock, that path DOES provision itself at the target.
    assert_eq!(
        disposition_for_surface_chirho("resident-writer-chirho"),
        Some(SurfaceDispositionChirho::ProvenDisposableChirho),
        "a device/inode-bound identity must not travel"
    );
}

#[test]
fn ledger_mirror_recovery_state_travels_because_empty_open_is_not_reconstruction_chirho() {
    assert_eq!(
        disposition_for_surface_chirho("ledger-mirror-f1-chirho"),
        Some(SurfaceDispositionChirho::CarriedWithTheRootChirho),
        "opening a mirror store recreates only directories; signed follower recovery heads, exact \
         mirrored records, and leader committed-pending evidence must travel"
    );
    assert!(
        crate::surface_disposition_chirho::surface_travels_with_the_root_chirho(
            SurfaceDispositionChirho::CarriedWithTheRootChirho
        ),
        "the required-surface gate must refuse a target that omitted F1 recovery evidence"
    );
}

#[test]
fn the_two_fence_surfaces_have_opposite_dispositions_for_a_measured_reason_chirho() {
    // THE NAMES MERGED THEM AND THE CONTENTS SEPARATE THEM. `sink-term-fences-chirho` read REBUILT
    // on a comment that said it "inherits the SAME unbuilt requirement as writer-fences-chirho".
    // Measured on a real root, the two hold different things: the sink-term cell is a TENANT-scoped
    // monotonic winner term with no root, device or inode, keyed by a group digest that is identical
    // at source and target — while the writer fence carries a COMPOSITE epoch whose low half resets
    // per root, which is the invariant that rules it out from travelling.
    //
    // Carrying the sink-term cell is the FAIL-CLOSED direction: the recover path refuses a carried
    // cell that is ahead of the acting authority by name, where rebuilding silently creates one at
    // the current term and discards a higher mark.
    assert_eq!(
        disposition_for_surface_chirho("sink-term-fences-chirho"),
        Some(SurfaceDispositionChirho::CarriedWithTheRootChirho),
        "the sink-side winner-term mark must travel, or a migration silently resets a monotonic fence"
    );
    // RETARGETED, and the correction is the point. This arm previously asserted the two surfaces
    // had OPPOSITE dispositions, on my own reasoning that the writer fence's composite epoch ruled
    // it out from travelling. Measuring what its ABSENCE does disproved that: `writer_authority_
    // era_chirho` reads this very surface, and with no fence it returns `LocalChirho` — so dropping
    // it downgrades a geo-elected root to locally authorized rather than leaving it to re-elect.
    // The epoch objection survives untouched and simply does not reach here: the era decision
    // consults only the GEO half, which is geo-scoped, never the per-root grant seq.
    assert_eq!(
        disposition_for_surface_chirho("writer-fences-chirho"),
        Some(SurfaceDispositionChirho::CarriedWithTheRootChirho),
        "the writer fence must travel: absent, it silently downgrades the root's authority era"
    );
    // Both travel now, for two DIFFERENT measured reasons, and neither may become disposable —
    // that is the direction that loses a monotonic mark or an authority era without saying so.
    for surface_chirho in ["sink-term-fences-chirho", "writer-fences-chirho"] {
        assert!(
            crate::surface_disposition_chirho::surface_travels_with_the_root_chirho(
                disposition_for_surface_chirho(surface_chirho)
                    .expect("both fence surfaces are disposed")
            ),
            "{surface_chirho} must travel with the root"
        );
    }
}

/// K4'S CONNECTION STORES TRAVEL WITH THE ROOT EXACTLY AS THEIR LEGACY TWINS DO (PFE #26763: the three new files need
/// dispositions, "moving with the root, as the token log does"). Each is declared in the log manifest, its policy is
/// its twin's, carried with the root, and its head sidecar follows it. A move that left one behind would strand a
/// connection's client, keys or uses at the source while reporting success.
#[test]
fn k4_connection_logs_travel_with_the_root_as_their_legacy_twins_chirho() {
    let carried_chirho = Some(RootSurfacePolicyChirho::payload_chirho(
        SurfaceDispositionChirho::CarriedWithTheRootChirho,
    ));
    for (connection_chirho, twin_chirho) in [
        (
            "oauth-connection-clients-chirho.jsonl",
            "oauth-clients-chirho.jsonl",
        ),
        (
            "connection-tokens-chirho.jsonl",
            "scoped-tokens-chirho.jsonl",
        ),
        (
            "connection-token-uses-chirho.jsonl",
            "scoped-token-uses-chirho.jsonl",
        ),
    ] {
        assert!(
            declared_log_surfaces_chirho().contains(connection_chirho),
            "{connection_chirho} is declared"
        );
        assert_eq!(
            policy_for_surface_chirho(connection_chirho),
            policy_for_surface_chirho(twin_chirho),
            "{connection_chirho} is disposed as {twin_chirho}"
        );
        assert_eq!(policy_for_surface_chirho(connection_chirho), carried_chirho);
        assert_eq!(
            policy_for_surface_chirho(&format!("{connection_chirho}{SEQLOG_HEAD_SUFFIX_CHIRHO}")),
            carried_chirho,
            "{connection_chirho}'s head sidecar follows it"
        );
    }
}

/// CF8 STEP B (2026-10-26, AICEO #29534). The census's 18 settled surfaces take the policies their
/// producers' laws give them, and the three unsettled ones still refuse BY NAME.
///
/// Each policy was ruled from the module that writes the surface, in
/// `missing-surface-dispositions-chirho.md`. If this arm goes red, the ruling changed: re-read that
/// surface's row before editing the arm.
#[test]
fn cf8_census_surfaces_take_their_ruled_policies_chirho() {
    let carried_chirho = Some(RootSurfacePolicyChirho::payload_chirho(
        SurfaceDispositionChirho::CarriedWithTheRootChirho,
    ));
    let disposable_chirho = Some(RootSurfacePolicyChirho::payload_chirho(
        SurfaceDispositionChirho::ProvenDisposableChirho,
    ));
    let platform_chirho = Some(RootSurfacePolicyChirho::payload_chirho(
        SurfaceDispositionChirho::NotAMigrationUnitChirho,
    ));

    // Rows 1-5, 10 and 11: carried logs, each with its head sidecar.
    for log_chirho in CARRIED_UNPROJECTED_LOG_SURFACES_CHIRHO {
        assert_eq!(
            policy_for_surface_chirho(log_chirho),
            carried_chirho,
            "{log_chirho}"
        );
        assert_eq!(
            policy_for_surface_chirho(&format!("{log_chirho}{SEQLOG_HEAD_SUFFIX_CHIRHO}")),
            carried_chirho,
            "{log_chirho}'s head sidecar follows it"
        );
    }

    // Rows 6-9: platform-only logs and their sidecars refuse as not a migration unit, under that
    // identity rather than as undisposed.
    for log_chirho in PLATFORM_ONLY_LOG_SURFACES_CHIRHO {
        let sidecar_chirho = format!("{log_chirho}{SEQLOG_HEAD_SUFFIX_CHIRHO}");
        assert_eq!(
            policy_for_surface_chirho(log_chirho),
            platform_chirho,
            "{log_chirho}"
        );
        assert_eq!(
            policy_for_surface_chirho(&sidecar_chirho),
            platform_chirho,
            "{sidecar_chirho} follows its platform-only log"
        );
        assert_eq!(
            verify_surface_dispositions_chirho(
                &observed_chirho(&[log_chirho, &sidecar_chirho]),
                None
            )
            .refusals_chirho,
            vec![
                DispositionRefusalChirho::NotAMigrationUnitChirho {
                    surface_chirho: (*log_chirho).to_string(),
                },
                DispositionRefusalChirho::NotAMigrationUnitChirho {
                    surface_chirho: sidecar_chirho.clone(),
                },
            ],
        );
    }

    // Rows 13-15, 17 and 18, C2.1's law marker and C5's erasure-propagation store: carried, committed
    // payload, retained at source.
    for surface_chirho in [
        "app-build-request-state-chirho.redb",
        "template-app-deploy-state-chirho.redb",
        "publication-intent-state-chirho.redb",
        GEO_GENESIS_GUARD_DIR_CHIRHO,
        "gate1-authority-head-chirho",
        CONTROL_PLANE_LAW_MARKER_FILE_CHIRHO,
        "privacy-erasure-propagation-chirho",
    ] {
        assert_eq!(
            policy_for_surface_chirho(surface_chirho),
            carried_chirho,
            "{surface_chirho}"
        );
    }

    // Rows 19 and 20: disposable, because their own code rebuilds them at the target.
    for surface_chirho in ["readmodel-chirho.sqlite", "native-workers-chirho"] {
        assert_eq!(
            policy_for_surface_chirho(surface_chirho),
            disposable_chirho,
            "{surface_chirho}"
        );
    }

    // Rows 12, 16 and 21 stay refused. The first two wait on a production retirement step that
    // can erase them at the source after handoff; the third waits on a reviewed purge. A row for any
    // of them here, before that exists, would claim a disposition that nothing enforces.
    for surface_chirho in [
        "versioned-chirho.redb",
        "privacy-account-attribution-chirho",
        "seqlog-quarantine-chirho",
    ] {
        assert_eq!(
            policy_for_surface_chirho(surface_chirho),
            None,
            "{surface_chirho}"
        );
        assert_eq!(
            verify_surface_dispositions_chirho(
                &observed_chirho(&["objects-chirho", surface_chirho]),
                None
            )
            .refusals_chirho,
            vec![DispositionRefusalChirho::UndisposedSurfaceChirho {
                surface_chirho: surface_chirho.to_string(),
            }],
        );
    }
}

/// The carried-unprojected list is the projection manifest's COMPLEMENT, and both new lists hold
/// only logs.
///
/// A log in both the manifest and the carried list would be read by the projection while the list
/// claimed it was not, and keeping it out of the projection is the reason the list exists. A
/// platform-only log among the declared logs would be carried and scanned on a tenant root.
#[test]
fn the_log_lists_are_disjoint_and_reach_their_consumers_chirho() {
    let manifest_chirho: BTreeSet<&str> =
        cairn_projection_chirho::projection_chirho::static_surface_manifest_chirho()
            .iter()
            .copied()
            .collect();
    let non_log_chirho: BTreeSet<&str> = NON_LOG_SURFACE_POLICIES_CHIRHO
        .iter()
        .map(|(surface_chirho, _)| *surface_chirho)
        .collect();
    let declared_chirho = declared_log_surfaces_chirho();
    let full_chirho = crate::migration_completeness_chirho::declared_root_surfaces_chirho();
    assert!(
        !CARRIED_UNPROJECTED_LOG_SURFACES_CHIRHO.is_empty()
            && !PLATFORM_ONLY_LOG_SURFACES_CHIRHO.is_empty(),
        "an empty list makes every loop below vacuous"
    );

    for log_chirho in CARRIED_UNPROJECTED_LOG_SURFACES_CHIRHO {
        let sidecar_chirho = format!("{log_chirho}{SEQLOG_HEAD_SUFFIX_CHIRHO}");
        assert!(log_chirho.ends_with(".jsonl"), "{log_chirho} is not a log");
        assert!(
            !manifest_chirho.contains(log_chirho),
            "{log_chirho} is in the projection manifest too, so the projection reads it"
        );
        assert!(!non_log_chirho.contains(log_chirho), "{log_chirho}");
        assert!(!PLATFORM_ONLY_LOG_SURFACES_CHIRHO.contains(log_chirho));
        assert!(
            declared_chirho.contains(*log_chirho),
            "{log_chirho} must reach the declared logs, which the reference scan reads"
        );
        assert!(full_chirho.contains(*log_chirho) && full_chirho.contains(&sidecar_chirho));
    }
    for log_chirho in PLATFORM_ONLY_LOG_SURFACES_CHIRHO {
        let sidecar_chirho = format!("{log_chirho}{SEQLOG_HEAD_SUFFIX_CHIRHO}");
        assert!(log_chirho.ends_with(".jsonl"), "{log_chirho} is not a log");
        assert!(!manifest_chirho.contains(log_chirho), "{log_chirho}");
        assert!(!non_log_chirho.contains(log_chirho), "{log_chirho}");
        assert!(
            !declared_chirho.contains(*log_chirho),
            "{log_chirho} is platform state and must not be carried or scanned as a tenant log"
        );
        assert!(
            full_chirho.contains(*log_chirho) && full_chirho.contains(&sidecar_chirho),
            "{log_chirho} is known, so completeness must name it and its sidecar"
        );
    }
}
