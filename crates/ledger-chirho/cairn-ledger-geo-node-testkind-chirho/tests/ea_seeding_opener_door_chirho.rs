// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Proves the seeding road's injected opener reaches a door the test-kind fence does NOT guard —
//! differentially, against the production door it replaces, on byte-identical inputs.
//!
//! WHY DIFFERENTIALLY. "The opener reached a provider door" is not directly observable from outside
//! the resident actor: both doors return the same handle type and, on a bare root, both fail. What
//! IS observable, and what the whole widening rests on, is that the two doors differ in exactly one
//! respect on a test-kind-marked config — the production door refuses at the fence, the
//! compensation-provider door does not. So the arm runs both on the SAME root, the SAME 0600 config
//! file and the SAME validated config value, and asserts the refusal IDENTITIES differ in that one
//! way. A control-first ordering keeps the absence assertion from being green-by-emptiness: if the
//! production door ever stops refusing these inputs, this file fails before it claims anything.

use cairn_config_chirho::config_chirho::{
    serialize_config_chirho, ConfigChirho, LedgerHostConfigChirho, LedgerHostIssuerPinConfigChirho,
    LedgerHostMemberConfigChirho, LedgerHostProjectionRouteConfigChirho,
    LedgerHostSignerRefsConfigChirho, LedgerHostTestKindMarkerConfigChirho,
    LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO, LEDGER_HOST_TEST_KIND_MARKER_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_geo_node_testkind_chirho::testkind_seeding_resident_opener_chirho;
use cairn_ledger_host_chirho::{
    open_resident_effect_journal_handle_chirho, TEST_KIND_MARKED_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO,
};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// A VALID, custody-clean, test-kind-MARKED host config on a fresh bare root.
///
/// Valid matters: an invalid config would refuse inside the shared funnel for a reason that has
/// nothing to do with the fence, and the differential would compare two unrelated failures.
fn marked_fixture_chirho(label_chirho: &str) -> (PathBuf, PathBuf, LedgerHostConfigChirho) {
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-testkind-ea-{label_chirho}-{}-chirho",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).expect("create fixture root");

    let ledger_host_chirho = LedgerHostConfigChirho {
        schema_chirho: LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO.to_owned(),
        storage_namespace_chirho: "ledger-substrate-chirho".to_owned(),
        monitor_evidence_namespace_chirho: "monitor-chirho".to_owned(),
        monitor_evidence_path_chirho: "monitor/cycles-chirho.jsonl".to_owned(),
        money_group_id_chirho: "money-group-chirho".to_owned(),
        cluster_id_chirho: "cluster-chirho".to_owned(),
        journal_path_chirho: "journals/main-chirho.jsonl".to_owned(),
        local_epoch_chirho: 1,
        members_chirho: vec![LedgerHostMemberConfigChirho {
            owner_chirho: "test-owner-chirho".to_owned(),
            kind_id_chirho: "drill-credits-chirho".to_owned(),
        }],
        kind_registry_path_chirho: "registries/kinds-chirho.jsonl".to_owned(),
        kind_registry_id_chirho: "kind-registry-chirho".to_owned(),
        kind_issuer_chirho: LedgerHostIssuerPinConfigChirho {
            principal_chirho: "test-kind-chirho-e1e2-seeding-issuer-chirho".to_owned(),
            verifying_key_hex_chirho: "11".repeat(32),
        },
        activation_authority_chirho: None,
        projection_registry_path_chirho: "registries/projections-chirho.jsonl".to_owned(),
        projection_registry_id_chirho: "projection-registry-chirho".to_owned(),
        source_registry_path_chirho: "registries/sources-chirho.jsonl".to_owned(),
        source_registry_id_chirho: "source-registry-chirho".to_owned(),
        projection_routes_chirho: vec![LedgerHostProjectionRouteConfigChirho {
            projection_name_chirho: "balance-chirho".to_owned(),
            head_path_chirho: "published/balance-head-chirho.json".to_owned(),
        }],
        signer_secrets_chirho: LedgerHostSignerRefsConfigChirho {
            journal_chirho: "journal-secret-chirho".to_owned(),
            config_chirho: "config-secret-chirho".to_owned(),
            feeder_chirho: "feeder-secret-chirho".to_owned(),
            kind_root_chirho: "kind-root-secret-chirho".to_owned(),
            effect_intent_chirho: "effect-intent-secret-chirho".to_owned(),
            effect_terminal_chirho: "effect-terminal-secret-chirho".to_owned(),
        },
        held_verifier_pins_chirho: None,
        migration_destination_authority_chirho: None,
        monitor_cadence_ms_chirho: 5_000,
        postgres_effect_chirho: None,
        // THE MARKER: this is what the production door refuses and the provider door does not.
        control_plane_chirho: None,
        test_kind_chirho: Some(LedgerHostTestKindMarkerConfigChirho {
            schema_chirho: LEDGER_HOST_TEST_KIND_MARKER_SCHEMA_V1_CHIRHO.to_owned(),
            loss_witness_exempt_chirho: false,
        }),
        adopt_migrated_root_chirho: false,
    };
    ledger_host_chirho
        .validate_chirho()
        .expect("the fixture config must be VALID, or both doors refuse for an unrelated reason");

    let config_path_chirho = root_chirho.join("ledger-host-config-chirho.toml");
    std::fs::write(
        &config_path_chirho,
        serialize_config_chirho(&ConfigChirho {
            root_chirho: root_chirho.display().to_string(),
            ledger_host_chirho: Some(ledger_host_chirho.clone()),
            ..ConfigChirho::default()
        })
        .expect("serialize marked fixture config"),
    )
    .expect("write marked fixture config");
    let mut permissions_chirho = std::fs::metadata(&config_path_chirho)
        .expect("read config metadata")
        .permissions();
    permissions_chirho.set_mode(0o600);
    std::fs::set_permissions(&config_path_chirho, permissions_chirho)
        .expect("set config custody mode");

    (root_chirho, config_path_chirho, ledger_host_chirho)
}

fn refusal_text_chirho<OpenedChirho>(
    result_chirho: anyhow::Result<OpenedChirho>,
    what_chirho: &str,
) -> String {
    match result_chirho {
        Ok(_) => panic!("{what_chirho} must refuse on a bare root with no ledger substrate"),
        Err(error_chirho) => {
            let rendered_chirho = format!("{error_chirho:#}");
            // Printed so a reader running with --nocapture can SEE both refusals side by side; the
            // assertions below, not this line, carry the claim.
            eprintln!("{what_chirho} refused with: {rendered_chirho}");
            rendered_chirho
        }
    }
}

/// THE WIDENING, executed: the seeding road's injected opener reaches a door the test-kind fence
/// does not guard, while the production door it replaces refuses the same inputs at that fence.
#[test]
fn the_seeding_opener_reaches_a_door_the_test_kind_fence_does_not_guard_chirho() {
    let (root_chirho, config_path_chirho, config_chirho) = marked_fixture_chirho("fence-split");

    // CONTROL FIRST. The production door is the one the seeding road opens when nothing is
    // injected, and on these exact inputs it must refuse at the fence. If this ever stops holding,
    // the absence assertion below would be satisfied by a codebase with no fence at all.
    let production_refusal_chirho = refusal_text_chirho(
        open_resident_effect_journal_handle_chirho(
            &root_chirho,
            &config_path_chirho,
            &config_chirho,
            None,
        ),
        "the production resident door",
    );
    assert!(
        production_refusal_chirho.contains(TEST_KIND_MARKED_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO),
        "control failed: the production door must refuse a test-kind-marked config at the fence, \
         else this file's absence assertion proves nothing. Got: {production_refusal_chirho}"
    );

    // THE CLAIM. Same root, same config file, same config value — only the door differs.
    let injected_refusal_chirho = refusal_text_chirho(
        testkind_seeding_resident_opener_chirho(&root_chirho, &config_path_chirho, &config_chirho),
        "the injected test-kind seeding opener",
    );
    assert!(
        !injected_refusal_chirho.contains(TEST_KIND_MARKED_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO),
        "the injected seeding opener hit the TEST-KIND FENCE, so it is no longer reaching a \
         compensation-provider door. Either the opener was re-pointed at a production door, or the \
         fence moved onto a provider door (which would deny every hosted test-kind drill). Got: \
         {injected_refusal_chirho}"
    );

    // ASSERT THE REASON POSITIVELY, not merely the absence. The injected door must accept this
    // config and get all the way to the resident actor's own substrate check — past validation,
    // past custody, past where the fence sits — and refuse only because a bare root carries no
    // ledger storage. Without this, an opener that refused for ANY new reason (a broken config
    // path, a custody failure, a panic rendered as an error) would satisfy the absence assertion
    // above while proving nothing about which door it reached.
    //
    // MIGRATION PATH, because this pins another module's refusal wording: if this string changes,
    // read the new one before editing. Still a SUBSTRATE refusal under a different name → retarget
    // this needle. A CUSTODY or VALIDATION refusal → the injected door is now refusing earlier than
    // the fence's position, and the differential no longer isolates the fence. The test-kind
    // refusal → the negative assertion above will have fired first and told you directly.
    const INJECTED_DOOR_SUBSTRATE_REFUSAL_CHIRHO: &str = "ledger storage namespace is unavailable";
    assert!(
        injected_refusal_chirho.contains(INJECTED_DOOR_SUBSTRATE_REFUSAL_CHIRHO),
        "the injected seeding opener must reach the resident actor's substrate check on a bare \
         root — i.e. it accepted the test-kind config and refused only for missing storage. Got: \
         {injected_refusal_chirho}"
    );

    std::fs::remove_dir_all(&root_chirho).expect("remove fixture root");
}
