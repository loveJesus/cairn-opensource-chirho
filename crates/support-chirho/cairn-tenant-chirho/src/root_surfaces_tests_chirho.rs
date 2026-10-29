// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The first production implementors, proved against real roots on disk.
//!
//! The arm that matters most is [`an_object_in_a_SIBLING_root_does_not_resolve_chirho`]: a resolver
//! that answered the global "does this object exist" question would pass on exactly the roots the
//! self-containment verifier exists to catch, and nothing in a type signature prevents that — only
//! a test that puts the object somewhere else and demands a refusal.

use super::*;
use crate::migration_completeness_chirho::{
    declared_log_surfaces_chirho, verify_migration_completeness_chirho, CompletenessRefusalChirho,
};
use crate::self_containment_chirho::{
    verify_tenant_self_containment_against_source_chirho, verify_tenant_self_containment_chirho,
    SelfContainmentRefusalChirho, TenantLogReferenceChirho,
};
use cairn_core_chirho::model_chirho::{
    effect_signing_message_chirho, CapabilityChirho, EffectChirho, HashChirho, RunKeyChirho,
};
use std::collections::BTreeMap;

fn tmp_platform_root_chirho() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let now_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("cairn-root-surfaces-test-{n_chirho}-{now_chirho}"))
}

fn tenant_root_chirho(tenant_chirho: &str) -> PathBuf {
    let platform_chirho = tmp_platform_root_chirho();
    crate::tenant_chirho::prepare_tenant_root_chirho(&platform_chirho, tenant_chirho)
        .expect("prepare tenant root")
}

fn store_run_key_record_chirho(root_chirho: &Path) -> String {
    let run_key_chirho = RunKeyChirho {
        node_chirho: HashChirho("11".repeat(32)),
        inputs_chirho: BTreeMap::from([(
            "request-chirho".to_string(),
            HashChirho("22".repeat(32)),
        )]),
        caps_chirho: HashChirho("33".repeat(32)),
    };
    let run_id_chirho = cairn_core_chirho::store_chirho::hash_object_chirho(&run_key_chirho)
        .expect("hash RunKeyChirho");
    let runkeys_chirho = root_chirho.join("runkeys-chirho");
    std::fs::create_dir_all(&runkeys_chirho).expect("create runkeys surface");
    std::fs::write(
        runkeys_chirho.join(&run_id_chirho.0),
        serde_json::to_vec_pretty(&run_key_chirho).expect("encode RunKeyChirho"),
    )
    .expect("store RunKeyChirho");
    run_id_chirho.0
}

fn store_signed_effect_record_chirho(root_chirho: &Path) -> String {
    let idem_key_chirho = cairn_core_chirho::cas_chirho::hash_chirho(b"migration effect id chirho");
    let mut effect_chirho = EffectChirho {
        seq_chirho: 7,
        capability_chirho: CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "tenant/item-chirho".to_string(),
        },
        request_chirho: HashChirho("44".repeat(32)),
        idem_key_chirho: idem_key_chirho.clone(),
        response_chirho: Some(HashChirho("55".repeat(32))),
        sig_chirho: String::new(),
        at_chirho: "1770000000000".to_string(),
    };
    let message_chirho = effect_signing_message_chirho(&effect_chirho)
        .expect("encode canonical effect signing message");
    effect_chirho.sig_chirho =
        cairn_signer_chirho::signer_chirho::sign_message_chirho(root_chirho, &message_chirho)
            .expect("sign effect through root custody");
    let effects_chirho = root_chirho.join("effects-chirho");
    std::fs::create_dir_all(&effects_chirho).expect("create effects surface");
    std::fs::write(
        effects_chirho.join(&idem_key_chirho.0),
        serde_json::to_vec_pretty(&effect_chirho).expect("encode EffectChirho"),
    )
    .expect("store EffectChirho");
    idem_key_chirho.0
}

// --- the enumerator: it must see a REAL root, and must not turn a failure into an empty list ---

#[test]
fn the_snapshot_sees_what_is_actually_in_the_root_chirho() {
    let root_chirho = tenant_root_chirho("acme-chirho");
    std::fs::write(root_chirho.join("app-records-chirho.jsonl"), b"{}\n").expect("write a surface");
    std::fs::create_dir_all(root_chirho.join("objects-chirho")).expect("create objects dir");

    let snapshot_chirho = RootSurfaceSnapshotChirho::open_chirho(&root_chirho).expect("open root");
    let observed_chirho = snapshot_chirho.observed_surfaces_chirho();

    assert!(
        observed_chirho.contains(&"app-records-chirho.jsonl".to_string()),
        "the snapshot missed a log surface that is on disk: {observed_chirho:?}"
    );
    assert!(
        observed_chirho.contains(&"objects-chirho".to_string()),
        "the snapshot missed the object store — a DIRECTORY is a surface too, and it is the one a \
         migration most needs to account for: {observed_chirho:?}"
    );
    assert!(
        snapshot_chirho.observed_count_chirho() > 0,
        "a snapshot over a populated root reported zero surfaces"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn an_unreadable_root_is_an_error_not_an_empty_snapshot_chirho() {
    // These are opposite findings and must never be confused: an empty snapshot says "nothing to
    // migrate", an error says "I could not look". Collapsing the second into the first is how a
    // migration reports a clean bill of health for a root it never read.
    let missing_chirho = tmp_platform_root_chirho().join("no-such-root-chirho");
    let result_chirho = RootSurfaceSnapshotChirho::open_chirho(&missing_chirho);
    assert!(
        result_chirho.is_err(),
        "opening a root that does not exist must ERROR, never return an empty surface list"
    );
}

#[test]
fn an_unread_root_cannot_become_a_preliminary_migration_check_chirho() {
    // Composition guard: even if a caller ignored the error above and somehow produced an empty
    // observation, the completeness verdict's anti-vacuity rule must still refuse to call it
    // complete. Two independent things have to fail before a root with no evidence looks movable.
    let verdict_chirho = verify_migration_completeness_chirho(
        &declared_log_surfaces_chirho(),
        &EmptyEnumeratorChirho,
    );
    assert!(
        !verdict_chirho.is_complete_over_evidence_chirho(),
        "a root observed as having ZERO surfaces must not read as complete"
    );
}

struct EmptyEnumeratorChirho;
impl RootSurfaceEnumeratorChirho for EmptyEnumeratorChirho {
    fn observed_surfaces_chirho(&self) -> Vec<String> {
        Vec::new()
    }
}

// --- the resolver: tenant-scoped BY CONSTRUCTION, and a corrupt object does not resolve ---

#[test]
fn an_object_in_this_root_resolves_chirho() {
    let root_chirho = tenant_root_chirho("acme-chirho");
    let addr_chirho =
        cairn_core_chirho::cas_chirho::add_chirho(&root_chirho, b"a real object").expect("cas add");

    let resolver_chirho = TenantScopedArtifactResolverChirho::for_root_chirho(&root_chirho);
    assert!(
        resolver_chirho.resolves_in_tenant_chirho(&addr_chirho.0),
        "an object stored in THIS root must resolve — otherwise the guard below proves nothing, \
         because a resolver that always answered false would also pass it"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn real_runtime_record_fields_missing_from_target_are_counted_and_refused_chirho() {
    // Reproduces the shipped-root census: five field names, six hash occurrences. Before the
    // artifact resolver, BOTH oracles missed every one, so all six landed in `unresolved_anywhere`
    // and neither the refusal path nor the anti-vacuity evidence count could observe the loss.
    let source_chirho = tenant_root_chirho("source-chirho");
    let target_chirho = tenant_root_chirho("target-chirho");
    let run_id_chirho = store_run_key_record_chirho(&source_chirho);
    let effect_id_chirho = store_signed_effect_record_chirho(&source_chirho);
    std::fs::write(
        source_chirho.join("app-records-chirho.jsonl"),
        format!(
            "{{\"effect_chirho\":\"{effect_id_chirho}\",\"left_chirho\":{{\"ref_chirho\":\"{effect_id_chirho}\"}},\"right_chirho\":{{\"ref_chirho\":\"{effect_id_chirho}\"}},\"related_effect_ids_chirho\":[\"{effect_id_chirho}\"],\"run_id_chirho\":\"{run_id_chirho}\",\"idem_key_chirho\":\"{effect_id_chirho}\"}}\n"
        ),
    )
    .expect("write production-shaped log references");

    let references_chirho = tenant_log_references_chirho(&source_chirho).expect("collect refs");
    assert_eq!(
        references_chirho.len(),
        6,
        "the production-shaped five-field census must retain all six occurrences"
    );
    let source_resolver_chirho =
        TenantScopedArtifactResolverChirho::for_root_chirho(&source_chirho);
    let target_resolver_chirho =
        TenantScopedArtifactResolverChirho::for_root_chirho(&target_chirho);
    assert!(source_resolver_chirho.resolves_in_tenant_chirho(&run_id_chirho));
    assert!(source_resolver_chirho.resolves_in_tenant_chirho(&effect_id_chirho));
    assert!(!target_resolver_chirho.resolves_in_tenant_chirho(&run_id_chirho));
    assert!(!target_resolver_chirho.resolves_in_tenant_chirho(&effect_id_chirho));

    let compared_chirho = verify_tenant_self_containment_against_source_chirho(
        &references_chirho,
        &target_resolver_chirho,
        &source_resolver_chirho,
    );
    assert_eq!(
        compared_chirho.verdict_chirho.references_checked_chirho, 6,
        "every runtime-record occurrence resolved at the source must arm anti-vacuity"
    );
    assert_eq!(
        compared_chirho.unresolved_anywhere_chirho, 0,
        "verified source runtime records must never disappear into the non-reference bucket"
    );
    assert_eq!(compared_chirho.verdict_chirho.refusals_chirho.len(), 6);
    assert!(compared_chirho
        .verdict_chirho
        .refusals_chirho
        .iter()
        .all(|refusal_chirho| matches!(
            refusal_chirho,
            SelfContainmentRefusalChirho::LostAgainstSourceChirho { .. }
        )));

    let _ = std::fs::remove_dir_all(&source_chirho);
    let _ = std::fs::remove_dir_all(&target_chirho);
}

#[test]
fn substituted_runtime_records_do_not_resolve_by_path_presence_chirho() {
    let root_chirho = tenant_root_chirho("tampered-chirho");
    let run_id_chirho = store_run_key_record_chirho(&root_chirho);
    let effect_id_chirho = store_signed_effect_record_chirho(&root_chirho);
    let resolver_chirho = TenantScopedArtifactResolverChirho::for_root_chirho(&root_chirho);
    assert!(resolver_chirho.resolves_in_tenant_chirho(&run_id_chirho));
    assert!(resolver_chirho.resolves_in_tenant_chirho(&effect_id_chirho));

    let substituted_run_key_chirho = RunKeyChirho {
        node_chirho: HashChirho("66".repeat(32)),
        inputs_chirho: BTreeMap::new(),
        caps_chirho: HashChirho("77".repeat(32)),
    };
    std::fs::write(
        root_chirho.join("runkeys-chirho").join(&run_id_chirho),
        serde_json::to_vec_pretty(&substituted_run_key_chirho).expect("encode substitution"),
    )
    .expect("substitute run key bytes");
    assert!(
        !resolver_chirho.resolves_in_tenant_chirho(&run_id_chirho),
        "a run-key file whose structured hash does not bind its filename must not resolve"
    );

    let effect_path_chirho = root_chirho.join("effects-chirho").join(&effect_id_chirho);
    let mut effect_chirho: EffectChirho =
        serde_json::from_slice(&std::fs::read(&effect_path_chirho).expect("read signed effect"))
            .expect("decode signed effect");
    effect_chirho.seq_chirho += 1;
    std::fs::write(
        &effect_path_chirho,
        serde_json::to_vec_pretty(&effect_chirho).expect("encode tampered effect"),
    )
    .expect("tamper signed effect");
    assert!(
        !resolver_chirho.resolves_in_tenant_chirho(&effect_id_chirho),
        "an effect whose signed fields changed must not resolve merely because the path exists"
    );

    let message_chirho = effect_signing_message_chirho(&effect_chirho)
        .expect("encode changed effect signing message");
    effect_chirho.sig_chirho =
        cairn_signer_chirho::signer_chirho::sign_message_chirho(&root_chirho, &message_chirho)
            .expect("re-sign changed effect");
    std::fs::write(
        &effect_path_chirho,
        serde_json::to_vec_pretty(&effect_chirho).expect("encode re-signed effect"),
    )
    .expect("store re-signed effect");
    assert!(
        resolver_chirho.resolves_in_tenant_chirho(&effect_id_chirho),
        "the negative signature arm needs a positive control over the same changed effect"
    );

    effect_chirho.idem_key_chirho = HashChirho("88".repeat(32));
    let message_chirho = effect_signing_message_chirho(&effect_chirho)
        .expect("encode substituted effect signing message");
    effect_chirho.sig_chirho =
        cairn_signer_chirho::signer_chirho::sign_message_chirho(&root_chirho, &message_chirho)
            .expect("sign substituted effect");
    std::fs::write(
        &effect_path_chirho,
        serde_json::to_vec_pretty(&effect_chirho).expect("encode substituted effect"),
    )
    .expect("substitute effect under prior key");
    assert!(
        !resolver_chirho.resolves_in_tenant_chirho(&effect_id_chirho),
        "a correctly signed effect must still bind its idempotency key to the path being resolved"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
#[allow(non_snake_case)]
fn an_object_in_a_SIBLING_root_does_not_resolve_chirho() {
    // THE arm. Resolving somewhere is not resolving here. A tenant root is the migration unit, so a
    // hash that lives in a sibling tenant's store survives the move as a DANGLING reference — the
    // log still names an object that is now unreachable. A resolver with a global view would call
    // this root self-contained and be wrong in the one direction that loses data.
    let ours_chirho = tenant_root_chirho("acme-chirho");
    let sibling_chirho = tenant_root_chirho("other-chirho");
    let addr_chirho = cairn_core_chirho::cas_chirho::add_chirho(&sibling_chirho, b"someone else's")
        .expect("cas add to sibling");

    let resolver_chirho = TenantScopedArtifactResolverChirho::for_root_chirho(&ours_chirho);
    assert!(
        !resolver_chirho.resolves_in_tenant_chirho(&addr_chirho.0),
        "an object that lives only in a SIBLING tenant root must not resolve here — that is the \
         whole distinction the self-containment verifier is built on"
    );

    // And the same reference, run through the verifier, must be reported as dangling with its
    // coordinates — an operator repairing a root needs the site, not just a boolean.
    let verdict_chirho = verify_tenant_self_containment_chirho(
        &[TenantLogReferenceChirho {
            log_name_chirho: "app-records-chirho.jsonl".to_string(),
            seq_chirho: 7,
            hash_chirho: addr_chirho.0.clone(),
        }],
        &resolver_chirho,
    );
    assert!(!verdict_chirho.is_self_contained_over_evidence_chirho());
    assert_eq!(verdict_chirho.references_checked_chirho, 1);
    let _ = std::fs::remove_dir_all(&ours_chirho);
    let _ = std::fs::remove_dir_all(&sibling_chirho);
}

// --- composition: a real root against the real declared set ---

#[test]
fn a_real_root_surfaces_its_undeclared_entries_by_name_chirho() {
    // The end-to-end shape of CF8 clause 5's first half, with nothing injected: a real root, the
    // real projection-derived declared set, and a refusal that NAMES what would be left behind.
    let root_chirho = tenant_root_chirho("acme-chirho");
    std::fs::write(root_chirho.join("app-records-chirho.jsonl"), b"{}\n")
        .expect("declared surface");
    std::fs::write(root_chirho.join("not-declared-anywhere-chirho.dat"), b"x").expect("unknown");

    let snapshot_chirho = RootSurfaceSnapshotChirho::open_chirho(&root_chirho).expect("open root");
    let verdict_chirho =
        verify_migration_completeness_chirho(&declared_log_surfaces_chirho(), &snapshot_chirho);

    assert!(
        verdict_chirho
            .refusals_chirho
            .contains(&CompletenessRefusalChirho::UnknownSurfaceChirho {
                surface_chirho: "not-declared-anywhere-chirho.dat".to_string(),
            }),
        "an undeclared entry on a real root must refuse by name; got {:?}",
        verdict_chirho.refusals_chirho
    );
    assert!(
        !verdict_chirho.refusals_chirho.contains(
            &CompletenessRefusalChirho::UnknownSurfaceChirho {
                surface_chirho: "app-records-chirho.jsonl".to_string(),
            }
        ),
        "a surface that IS in the projection manifest must not be refused — if it is, the declared \
         set is wired to the wrong list and every root would look broken"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// --- the reference collector: conservative, but conservative in a KNOWN direction ---

#[test]
fn a_real_object_named_by_a_real_log_resolves_chirho() {
    let root_chirho = tenant_root_chirho("acme-chirho");
    let addr_chirho =
        cairn_core_chirho::cas_chirho::add_chirho(&root_chirho, b"referenced bytes").expect("add");
    std::fs::write(
        root_chirho.join("app-records-chirho.jsonl"),
        format!("{{\"dag_chirho\":\"{}\"}}\n", addr_chirho.0),
    )
    .expect("write log");

    let references_chirho = tenant_log_references_chirho(&root_chirho).expect("collect refs");
    assert_eq!(references_chirho.len(), 1, "expected exactly the one hash");
    assert_eq!(
        references_chirho[0].log_name_chirho,
        "app-records-chirho.jsonl"
    );
    assert_eq!(
        references_chirho[0].seq_chirho, 1,
        "line ordinal is 1-based"
    );

    let verdict_chirho = verify_tenant_self_containment_chirho(
        &references_chirho,
        &TenantScopedArtifactResolverChirho::for_root_chirho(&root_chirho),
    );
    assert!(
        verdict_chirho.is_self_contained_over_evidence_chirho(),
        "an object stored in this root and named by this root's log must resolve"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_128_hex_signature_is_not_mistaken_for_two_hashes_chirho() {
    // The length rule is load-bearing, not incidental. Signed JSONL logs are full of 128-char
    // ed25519 signatures; a scanner that took any 64-hex WINDOW would report two phantom references
    // per signature, and self-containment would fail on every real root for a reason that has
    // nothing to do with migration. Maximal-run-of-exactly-64 is what prevents that.
    let root_chirho = tenant_root_chirho("acme-chirho");
    let signature_chirho = "ab".repeat(64); // 128 hex chars, the shape of a real signature
    assert_eq!(signature_chirho.len(), 128);
    std::fs::write(
        root_chirho.join("app-records-chirho.jsonl"),
        format!("{{\"sig_chirho\":\"{signature_chirho}\"}}\n"),
    )
    .expect("write log");

    let references_chirho = tenant_log_references_chirho(&root_chirho).expect("collect refs");
    assert!(
        references_chirho.is_empty(),
        "a 128-hex signature must yield NO references; got {references_chirho:?}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_hash_that_lives_nowhere_in_this_root_is_reported_with_its_site_chirho() {
    // An operator repairing a root needs the SITE, not a boolean — which log, which line.
    let root_chirho = tenant_root_chirho("acme-chirho");
    let absent_chirho = "cd".repeat(32); // 64 hex chars, well-formed, no object behind it
    assert_eq!(absent_chirho.len(), 64);
    std::fs::write(
        root_chirho.join("app-records-chirho.jsonl"),
        format!("{{\"first_chirho\":1}}\n{{\"ref_chirho\":\"{absent_chirho}\"}}\n"),
    )
    .expect("write log");

    let references_chirho = tenant_log_references_chirho(&root_chirho).expect("collect refs");
    assert_eq!(references_chirho.len(), 1);
    assert_eq!(
        references_chirho[0].seq_chirho, 2,
        "the reference is on the SECOND line and must be reported there"
    );

    let verdict_chirho = verify_tenant_self_containment_chirho(
        &references_chirho,
        &TenantScopedArtifactResolverChirho::for_root_chirho(&root_chirho),
    );
    assert!(!verdict_chirho.is_self_contained_over_evidence_chirho());
    assert_eq!(verdict_chirho.refusals_chirho.len(), 1);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn only_declared_log_surfaces_are_scanned_chirho() {
    // Scope discipline: an undeclared file is COMPLETENESS's finding, not self-containment's. If
    // this scanned everything, the two halves would report the same problem twice and an operator
    // could not tell which check to act on.
    let root_chirho = tenant_root_chirho("acme-chirho");
    let hash_chirho = "ef".repeat(32);
    std::fs::write(
        root_chirho.join("not-a-declared-surface-chirho.jsonl"),
        format!("{{\"ref_chirho\":\"{hash_chirho}\"}}\n"),
    )
    .expect("write undeclared");

    let references_chirho = tenant_log_references_chirho(&root_chirho).expect("collect refs");
    assert!(
        references_chirho.is_empty(),
        "an undeclared file must not contribute references; got {references_chirho:?}"
    );

    // ...and the same file MUST be caught by the other half, so nothing falls between them.
    let snapshot_chirho = RootSurfaceSnapshotChirho::open_chirho(&root_chirho).expect("open");
    let completeness_chirho =
        verify_migration_completeness_chirho(&declared_log_surfaces_chirho(), &snapshot_chirho);
    assert!(
        completeness_chirho.refusals_chirho.contains(
            &CompletenessRefusalChirho::UnknownSurfaceChirho {
                surface_chirho: "not-a-declared-surface-chirho.jsonl".to_string(),
            }
        ),
        "the undeclared file must be caught by completeness — otherwise scoping self-containment \
         narrowly would open a hole between the two halves"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}
