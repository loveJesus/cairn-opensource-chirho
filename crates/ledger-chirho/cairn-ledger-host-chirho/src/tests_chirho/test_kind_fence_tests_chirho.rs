// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Brick #5's CONSUMER-side arms: the production resident-actor doors refuse a test-kind-marked host
//! config, and the compensation-provider door — the one the test-kind binary injects — does not.
//!
//! **How each arm removes the other possible refusals, because a fixture that refuses for the wrong
//! reason is worse than one that fails.** Every arm below runs against a root that has NO ledger
//! storage, so an opener that reached custody at all would fail there. The marked config is
//! otherwise VALID (marker plus the reserved issuer principal, exactly as the author emits), so
//! `validate_chirho` cannot be the refusal either. That leaves one cause for the token, and it makes
//! the arms prove ORDER as well as presence: the fence fires before validation and before the secret
//! store is touched.
//!
//! The unmarked control is the same config with a production issuer principal and no marker: it must
//! reach the storage failure, which is a different refusal identity. Without that control an arm
//! asserting "the marked open failed" would pass against an opener that refuses everything.

use crate::test_kind_fence_chirho::{
    refuse_test_kind_marked_host_config_chirho, require_test_kind_marked_host_config_chirho,
    NON_TEST_KIND_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO,
    TEST_KIND_MARKED_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO,
};
use crate::{
    open_resident_effect_journal_handle_chirho,
    open_resident_effect_journal_handle_testkind_chirho,
    open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho,
    open_resident_effect_journal_handle_with_shared_elector_chirho,
    Gd7CompensationProviderAdapterChirho, Gd7CompensationProviderObservationChirho,
    Gd7CompensationProviderRefusalChirho,
};
use cairn_config_chirho::config_chirho::{
    LedgerHostConfigChirho, LedgerHostIssuerPinConfigChirho, LedgerHostMemberConfigChirho,
    LedgerHostProjectionRouteConfigChirho, LedgerHostSignerRefsConfigChirho,
    LedgerHostTestKindMarkerConfigChirho, LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO,
    LEDGER_HOST_TEST_KIND_ISSUER_PRINCIPAL_PREFIX_CHIRHO,
    LEDGER_HOST_TEST_KIND_MARKER_SCHEMA_V1_CHIRHO,
};
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// One nonzero 32-byte lowercase-hex value. Shape only — this fixture never opens anything that
/// verifies a signature, because every arm refuses long before a key is used.
const ISSUER_PIN_HEX_CHIRHO: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";

/// A production-shaped issuer principal: deliberately NOT carrying the reserved prefix, so the
/// unmarked control is a config the marker/prefix agreement law accepts.
const PRODUCTION_ISSUER_PRINCIPAL_CHIRHO: &str = "offline-kind-issuer-chirho";

fn test_kind_issuer_principal_chirho() -> String {
    format!("{LEDGER_HOST_TEST_KIND_ISSUER_PRINCIPAL_PREFIX_CHIRHO}kind-issuer-chirho")
}

/// A root that exists but carries no ledger storage, so any opener that gets past the fence fails
/// at storage with a plainly different identity.
fn empty_root_chirho() -> PathBuf {
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-test-kind-fence-chirho-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

pub(crate) fn host_config_chirho(test_kind_chirho: bool) -> LedgerHostConfigChirho {
    LedgerHostConfigChirho {
        schema_chirho: LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO.to_owned(),
        storage_namespace_chirho: "ledger-storage-chirho".to_owned(),
        monitor_evidence_namespace_chirho: "monitor-evidence-chirho".to_owned(),
        monitor_evidence_path_chirho: "cycles/conservation-chirho.jsonl".to_owned(),
        money_group_id_chirho: "money-group-chirho".to_owned(),
        cluster_id_chirho: "cluster-chirho".to_owned(),
        journal_path_chirho: "journals-chirho/money-chirho.jsonl".to_owned(),
        local_epoch_chirho: 1,
        members_chirho: vec![LedgerHostMemberConfigChirho {
            owner_chirho: "platform-owner-chirho".to_owned(),
            kind_id_chirho: "credits-chirho".to_owned(),
        }],
        kind_registry_path_chirho: "registries-chirho/kinds-chirho.jsonl".to_owned(),
        kind_registry_id_chirho: "kind-registry-chirho".to_owned(),
        kind_issuer_chirho: LedgerHostIssuerPinConfigChirho {
            principal_chirho: if test_kind_chirho {
                test_kind_issuer_principal_chirho()
            } else {
                PRODUCTION_ISSUER_PRINCIPAL_CHIRHO.to_owned()
            },
            verifying_key_hex_chirho: ISSUER_PIN_HEX_CHIRHO.to_owned(),
        },
        activation_authority_chirho: None,
        projection_registry_path_chirho: "registries-chirho/projections-chirho.jsonl".to_owned(),
        projection_registry_id_chirho: "projection-registry-chirho".to_owned(),
        source_registry_path_chirho: "registries-chirho/sources-chirho.jsonl".to_owned(),
        source_registry_id_chirho: "source-registry-chirho".to_owned(),
        projection_routes_chirho: vec![LedgerHostProjectionRouteConfigChirho {
            projection_name_chirho: "account-net-chirho".to_owned(),
            head_path_chirho: "projection-heads-chirho/account-net-chirho.json".to_owned(),
        }],
        signer_secrets_chirho: LedgerHostSignerRefsConfigChirho {
            journal_chirho: "journal-secret-chirho".to_owned(),
            config_chirho: "config-secret-chirho".to_owned(),
            feeder_chirho: "feeder-secret-chirho".to_owned(),
            kind_root_chirho: "kind-root-secret-chirho".to_owned(),
            effect_intent_chirho: "effect-intent-secret-chirho".to_owned(),
            effect_terminal_chirho: "effect-terminal-secret-chirho".to_owned(),
        },
        migration_destination_authority_chirho: None,
        held_verifier_pins_chirho: None,
        monitor_cadence_ms_chirho: 5_000,
        postgres_effect_chirho: None,
        control_plane_chirho: None,
        test_kind_chirho: test_kind_chirho.then(|| LedgerHostTestKindMarkerConfigChirho {
            schema_chirho: LEDGER_HOST_TEST_KIND_MARKER_SCHEMA_V1_CHIRHO.to_owned(),
            loss_witness_exempt_chirho: false,
        }),
        adopt_migrated_root_chirho: false,
    }
}

/// A provider that reports nothing and is never reached: this arm's open fails at storage long
/// before any compensation runs. It exists only so the test-kind door can be CALLED with the shape
/// its signature requires.
struct NeverReachedProviderChirho;

impl Gd7CompensationProviderAdapterChirho for NeverReachedProviderChirho {
    fn dedup_retention_duration_chirho(&self) -> std::time::Duration {
        std::time::Duration::from_secs(3_600)
    }

    fn execute_gd7_compensation_provider_chirho(
        &self,
        _provider_idempotency_key_chirho: &str,
        _bounded_payload_chirho: &[u8],
    ) -> Result<Gd7CompensationProviderObservationChirho, Gd7CompensationProviderRefusalChirho>
    {
        Err(Gd7CompensationProviderRefusalChirho::ProviderNotConfiguredChirho)
    }
}

/// The fixture's two shapes must both be configs the SERVE boundary accepts, or every arm below
/// could be passing on a validation defect rather than on the property it names.
#[test]
fn both_fence_fixture_shapes_are_valid_host_configs_chirho() {
    host_config_chirho(false).validate_chirho().unwrap();
    host_config_chirho(true).validate_chirho().unwrap();
}

#[test]
fn the_fence_passes_an_unmarked_config_and_refuses_a_marked_one_chirho() {
    // Positive control first: the fence is not a function that refuses everything.
    refuse_test_kind_marked_host_config_chirho(&host_config_chirho(false)).unwrap();

    let refusal_chirho = refuse_test_kind_marked_host_config_chirho(&host_config_chirho(true))
        .unwrap_err()
        .to_string();
    assert!(
        refusal_chirho.contains(TEST_KIND_MARKED_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO),
        "the fence must refuse with its own identity, got: {refusal_chirho}"
    );
}

/// The INVERSE fence, mirror-image of the arm above: it passes a MARKED config and refuses an
/// UNMARKED one, by its own distinct identity. Positive control first (a marked config passes), so a
/// `require_` that refused everything could not masquerade as this property. The two identities are
/// asserted distinct so the inverse refusal can never be confused with the production one.
#[test]
fn the_inverse_fence_passes_a_marked_config_and_refuses_an_unmarked_one_chirho() {
    // Positive control first: the inverse fence is not a function that refuses everything.
    require_test_kind_marked_host_config_chirho(&host_config_chirho(true)).unwrap();

    let refusal_chirho = require_test_kind_marked_host_config_chirho(&host_config_chirho(false))
        .unwrap_err()
        .to_string();
    assert!(
        refusal_chirho.contains(NON_TEST_KIND_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO),
        "the inverse fence must refuse an unmarked config with its own identity, got: {refusal_chirho}"
    );
    assert!(
        !refusal_chirho.contains(TEST_KIND_MARKED_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO),
        "the inverse refusal must NOT carry the production fence's identity, got: {refusal_chirho}"
    );
}

/// THE CONSUMER-SIDE PROOF, and the one whose failure mode is worth stating in its own message.
///
/// If this arm ever reports the STORAGE refusal for the marked config, the fence was removed from
/// `open_resident_effect_journal_handle_chirho` and a production single-node composition will open a
/// resident actor — the elected write and mint authority — from a config authored for a synthetic
/// test kind. That is the regression, not a fixture problem.
#[test]
fn the_production_single_node_door_refuses_a_marked_config_before_touching_the_root_chirho() {
    let root_chirho = empty_root_chirho();
    let config_path_chirho = root_chirho.join("cairn-chirho.toml");

    // CONTROL: the same door, the same absent storage, an unmarked config. It must fail for a
    // reason that is NOT the fence, or the arm below would pass against a door that refuses
    // everything.
    let control_chirho = open_production_door_chirho(
        &root_chirho,
        &config_path_chirho,
        &host_config_chirho(false),
    )
    .expect_err("an unprovisioned root cannot open a resident actor");
    assert!(
        !control_chirho.contains(TEST_KIND_MARKED_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO),
        "an unmarked config must not hit the test-kind fence, got: {control_chirho}"
    );

    let refusal_chirho =
        open_production_door_chirho(&root_chirho, &config_path_chirho, &host_config_chirho(true))
            .expect_err("a marked config must not open a production resident actor");
    assert!(
        refusal_chirho.contains(TEST_KIND_MARKED_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO),
        "the production door must refuse a test-kind-marked config by name, got: {refusal_chirho}"
    );
    assert_ne!(
        refusal_chirho, control_chirho,
        "the marked refusal must differ from the unprovisioned-root refusal; identical text would \
         mean the fence never fired and both arms are reading the same storage failure"
    );

    let _removed_chirho = std::fs::remove_dir_all(&root_chirho);
}

/// **THE SHIPPING DOOR'S OWN ARM — the one the geo voter actually reaches.**
///
/// Brick #5 landed with this door proven only STRUCTURALLY (an AST caller-set guard plus two
/// mutations); only its single-node sibling above carried a behavioural arm. The gap mattered
/// because the two openers differ by two words and this is the one `default_resident_opener_chirho`
/// reaches for a composed geo voter, so a fence deleted HERE is the one that reaches production.
///
/// The elector is built and NOT campaigned on purpose. The fence is the opener's first statement,
/// before any elector state is consulted, so an unwarmed elector is enough to prove ORDER as well
/// as presence: if the fence had moved below the leadership check, the marked config would come
/// back with the elector's refusal instead of its own, and the `assert_ne!` below would fire.
///
/// Migration path, so a future red here is an instruction rather than an archaeology session: if
/// this arm reports the CONTROL's refusal for the marked config, the fence was removed from this
/// door and a composed geo voter can now open the elected write and mint authority from a config
/// authored for a synthetic test kind. That is the regression, not a fixture problem.
#[test]
fn the_shared_elector_production_door_refuses_a_marked_config_before_touching_the_root_chirho() {
    let root_chirho = empty_root_chirho();
    let config_path_chirho = root_chirho.join("cairn-chirho.toml");
    let elector_chirho = Arc::new(
        RaftWriterElectorChirho::new_single_node_chirho(
            NodeIdChirho("test-kind-fence-node-chirho".to_owned()),
            ConsistencyGroupIdChirho::TenantChirho {
                tenant_id_chirho: "test-kind-fence-tenant-chirho".to_owned(),
            },
        )
        .unwrap(),
    );

    // CONTROL: the same door, the same elector, an unmarked config. It must fail for a reason that
    // is NOT the fence, or the arm below would pass against a door that refuses everything.
    let control_chirho = open_shared_elector_door_chirho(
        &root_chirho,
        &config_path_chirho,
        &host_config_chirho(false),
        &elector_chirho,
    )
    .expect_err("an unprovisioned root cannot open a resident actor");
    assert!(
        !control_chirho.contains(TEST_KIND_MARKED_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO),
        "an unmarked config must not hit the test-kind fence, got: {control_chirho}"
    );

    let refusal_chirho = open_shared_elector_door_chirho(
        &root_chirho,
        &config_path_chirho,
        &host_config_chirho(true),
        &elector_chirho,
    )
    .expect_err("a marked config must not open a shared-elector resident actor");
    assert!(
        refusal_chirho.contains(TEST_KIND_MARKED_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO),
        "the shipping geo-voter door must refuse a test-kind-marked config by name, got: \
         {refusal_chirho}"
    );
    assert_ne!(
        refusal_chirho, control_chirho,
        "the marked refusal must differ from the unprovisioned-root refusal; identical text would \
         mean the fence never fired and both arms are reading the same downstream failure"
    );

    let _removed_chirho = std::fs::remove_dir_all(&root_chirho);
}

/// The other half of the fence, and the half that makes the drill still possible: the test-kind door
/// must NOT refuse a marked config. A `TestKindMarked…` refusal here means the fence leaked onto the
/// compensation-provider opener and every hosted item-6 drill authored in test-kind mode is dead.
#[test]
fn the_compensation_provider_door_still_admits_a_marked_config_chirho() {
    let root_chirho = empty_root_chirho();
    let config_path_chirho = root_chirho.join("cairn-chirho.toml");

    let refusal_chirho =
        match open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho(
            &root_chirho,
            &config_path_chirho,
            &host_config_chirho(true),
            None,
            Box::new(NeverReachedProviderChirho),
        ) {
            Ok(_handle_chirho) => panic!("an unprovisioned root cannot open a resident actor"),
            Err(error_chirho) => format!("{error_chirho:#}"),
        };
    assert!(
        !refusal_chirho.contains(TEST_KIND_MARKED_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO),
        "the test-kind door must still admit a marked config, got: {refusal_chirho}"
    );

    let _removed_chirho = std::fs::remove_dir_all(&root_chirho);
}

/// THE DEV-ONLY DOOR'S OWN CONSUMER-SIDE ARM — the mirror image of the production single-node arm.
///
/// The dev-only `open_resident_effect_journal_handle_testkind_chirho` exists to open a SYNTHETIC
/// test-kind root, so its fence direction is inverted: an UNMARKED (production) config is refused by
/// the inverse identity, before storage; a MARKED config passes the fence and reaches storage, where
/// an unprovisioned root fails for a plainly different reason.
///
/// The MARKED control proves two things at once: the inverse fence admits a marked config (it is not
/// a refuse-all), and — because `ReopenOwnedSingleNodeChirho` opens the EXISTING durable single node
/// and never seeds genesis — an unprovisioned root fails closed rather than silently re-genesising.
///
/// Migration path, so a future red is an instruction: if this arm reports the CONTROL's storage
/// refusal for the UNMARKED config, the inverse fence was removed and this dev door would open the
/// elected write and mint authority from a production (unmarked) config. That is the regression.
#[test]
fn the_testkind_door_refuses_an_unmarked_config_before_touching_the_root_chirho() {
    let root_chirho = empty_root_chirho();
    let config_path_chirho = root_chirho.join("cairn-chirho.toml");

    // CONTROL: a MARKED config passes the inverse fence and fails at storage (unprovisioned root),
    // a reason that is NOT the inverse fence. Its Err (no handle) proves the door seeds no genesis.
    let control_chirho =
        open_testkind_door_chirho(&root_chirho, &config_path_chirho, &host_config_chirho(true))
            .expect_err("an unprovisioned root cannot open a resident actor");
    assert!(
        !control_chirho.contains(NON_TEST_KIND_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO),
        "a marked config must pass the inverse fence and fail downstream, got: {control_chirho}"
    );
    assert!(
        !root_chirho.join("fresh-ledger-parent-chirho").exists(),
        "the dev-only door must not seed genesis on an unprovisioned root"
    );

    // THE INVERSE FENCE: an UNMARKED (production) config is refused by name, before storage.
    let refusal_chirho = open_testkind_door_chirho(
        &root_chirho,
        &config_path_chirho,
        &host_config_chirho(false),
    )
    .expect_err("an unmarked config must not open the dev-only test-kind door");
    assert!(
        refusal_chirho.contains(NON_TEST_KIND_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO),
        "the dev-only door must refuse an unmarked config by its own identity, got: {refusal_chirho}"
    );
    assert_ne!(
        refusal_chirho, control_chirho,
        "the unmarked refusal must differ from the unprovisioned-root refusal; identical text would \
         mean the inverse fence never fired and both arms are reading the same storage failure"
    );

    let _removed_chirho = std::fs::remove_dir_all(&root_chirho);
}

fn open_testkind_door_chirho(
    root_chirho: &Path,
    config_path_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
) -> Result<(), String> {
    match open_resident_effect_journal_handle_testkind_chirho(
        root_chirho,
        config_path_chirho,
        config_chirho,
        None,
    ) {
        Ok(_handle_chirho) => Ok(()),
        Err(error_chirho) => Err(format!("{error_chirho:#}")),
    }
}

fn open_production_door_chirho(
    root_chirho: &Path,
    config_path_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
) -> Result<(), String> {
    match open_resident_effect_journal_handle_chirho(
        root_chirho,
        config_path_chirho,
        config_chirho,
        None,
    ) {
        Ok(_handle_chirho) => Ok(()),
        Err(error_chirho) => Err(format!("{error_chirho:#}")),
    }
}

fn open_shared_elector_door_chirho(
    root_chirho: &Path,
    config_path_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
    elector_chirho: &Arc<RaftWriterElectorChirho>,
) -> Result<(), String> {
    match open_resident_effect_journal_handle_with_shared_elector_chirho(
        root_chirho,
        config_path_chirho,
        config_chirho,
        elector_chirho,
        None,
        None,
    ) {
        Ok(_handle_chirho) => Ok(()),
        Err(error_chirho) => Err(format!("{error_chirho:#}")),
    }
}
