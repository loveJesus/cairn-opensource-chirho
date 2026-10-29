// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Arms for the control-plane law composition (C2.1 brick 1a-iii): config decides and evidence can only
//! refuse; a voter's signer is separated before its secret is read; the seed is resolved read-only; and
//! a verifier-only node never resolves it at all.

use super::*;
use crate::signer_chirho::{
    hex_encode_chirho, host_ledger_signer_refs_from_config_chirho, HostLedgerSignersChirho,
};
use cairn_config_chirho::config_chirho::{
    LedgerHostControlPlaneConfigChirho, LedgerHostHeldVerifierPinsConfigChirho,
    LedgerHostIssuerPinConfigChirho, LedgerHostMemberConfigChirho,
    LedgerHostProjectionRouteConfigChirho, LedgerHostSignerRefsConfigChirho,
    LEDGER_HOST_CONFIG_SCHEMA_V4_CHIRHO,
};
use cairn_secret_chirho::secret_chirho::set_secret_chirho;
use cairn_signer_chirho::control_plane_signer_chirho::{
    ControlPlaneFamilyChirho, ControlPlaneLawMarkerChirho,
};
use cairn_tenant_chirho::tenant_chirho::GEO_GENESIS_GUARD_DIR_CHIRHO;
use cairn_writer_head_chirho::control_plane_evidence_chirho::publish_control_plane_law_marker_chirho;
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use std::path::PathBuf;

const TENANT_CHIRHO: &str = "geo-tenant-chirho";
const SIGNER_NAME_CHIRHO: &str = "control-plane-key-chirho";
/// The control-plane role key's seed, and the GD7 control key's.
const PIN_SEED_CHIRHO: u8 = 0x72;
const CONTROL_KEY_SEED_CHIRHO: u8 = 0x71;
/// The six runtime signer roles' secret names and seeds. Journal, effect intent and effect terminal are
/// also pinned as held verifiers; config, feeder and kind root are known only to the loaded signer set.
const ROLE_SECRETS_CHIRHO: [(&str, u8); 6] = [
    ("journal-secret-chirho", 0x61),
    ("config-secret-chirho", 0x62),
    ("feeder-secret-chirho", 0x63),
    ("kind-root-secret-chirho", 0x64),
    ("effect-intent-secret-chirho", 0x65),
    ("effect-terminal-secret-chirho", 0x66),
];

fn key_hex_chirho(seed_chirho: u8) -> String {
    hex_encode_chirho(
        SigningKey::from_bytes(&[seed_chirho; 32])
            .verifying_key()
            .as_bytes(),
    )
}

fn instance_id_chirho() -> String {
    "88".repeat(32)
}

fn control_plane_block_chirho(
    pin_hex_chirho: String,
    signer_chirho: Option<&str>,
) -> LedgerHostControlPlaneConfigChirho {
    LedgerHostControlPlaneConfigChirho {
        verifying_key_hex_chirho: pin_hex_chirho,
        tenant_id_chirho: TENANT_CHIRHO.to_owned(),
        genesis_instance_id_chirho: instance_id_chirho(),
        signer_secret_chirho: signer_chirho.map(str::to_owned),
    }
}

fn role_refs_chirho(names_chirho: [&str; 6]) -> LedgerHostSignerRefsConfigChirho {
    LedgerHostSignerRefsConfigChirho {
        journal_chirho: names_chirho[0].to_owned(),
        config_chirho: names_chirho[1].to_owned(),
        feeder_chirho: names_chirho[2].to_owned(),
        kind_root_chirho: names_chirho[3].to_owned(),
        effect_intent_chirho: names_chirho[4].to_owned(),
        effect_terminal_chirho: names_chirho[5].to_owned(),
    }
}

fn role_names_chirho() -> [&'static str; 6] {
    ROLE_SECRETS_CHIRHO.map(|(name_chirho, _seed_chirho)| name_chirho)
}

fn host_config_chirho(
    control_plane_chirho: Option<LedgerHostControlPlaneConfigChirho>,
) -> LedgerHostConfigChirho {
    LedgerHostConfigChirho {
        schema_chirho: LEDGER_HOST_CONFIG_SCHEMA_V4_CHIRHO.to_owned(),
        storage_namespace_chirho: "ledger-storage-chirho".to_owned(),
        monitor_evidence_namespace_chirho: "monitor-evidence-chirho".to_owned(),
        monitor_evidence_path_chirho: "cycles/conservation-chirho.jsonl".to_owned(),
        money_group_id_chirho: "money-group-chirho".to_owned(),
        cluster_id_chirho: "cluster-chirho".to_owned(),
        journal_path_chirho: "journals-chirho/money-chirho.jsonl".to_owned(),
        local_epoch_chirho: 1,
        members_chirho: vec![LedgerHostMemberConfigChirho {
            owner_chirho: "owner-chirho".to_owned(),
            kind_id_chirho: "credits-chirho".to_owned(),
        }],
        kind_registry_path_chirho: "registries-chirho/kinds-chirho.jsonl".to_owned(),
        kind_registry_id_chirho: "kind-registry-chirho".to_owned(),
        kind_issuer_chirho: LedgerHostIssuerPinConfigChirho {
            principal_chirho: "kind-issuer-chirho".to_owned(),
            verifying_key_hex_chirho: key_hex_chirho(0x59),
        },
        activation_authority_chirho: None,
        adopt_migrated_root_chirho: false,
        projection_registry_path_chirho: "registries-chirho/projections-chirho.jsonl".to_owned(),
        projection_registry_id_chirho: "projection-registry-chirho".to_owned(),
        source_registry_path_chirho: "registries-chirho/sources-chirho.jsonl".to_owned(),
        source_registry_id_chirho: "source-registry-chirho".to_owned(),
        projection_routes_chirho: vec![LedgerHostProjectionRouteConfigChirho {
            projection_name_chirho: "account-net-chirho".to_owned(),
            head_path_chirho: "projection-heads-chirho/account-net-chirho.json".to_owned(),
        }],
        signer_secrets_chirho: role_refs_chirho(role_names_chirho()),
        held_verifier_pins_chirho: Some(LedgerHostHeldVerifierPinsConfigChirho {
            journal_verifying_key_hex_chirho: key_hex_chirho(0x61),
            effect_intent_verifying_key_hex_chirho: Some(key_hex_chirho(0x65)),
            effect_terminal_verifying_key_hex_chirho: Some(key_hex_chirho(0x66)),
        }),
        migration_destination_authority_chirho: None,
        monitor_cadence_ms_chirho: 5_000,
        postgres_effect_chirho: None,
        test_kind_chirho: None,
        control_plane_chirho,
    }
}

/// A born root: its own node keypair and the six runtime role secrets, with the signer set loaded.
struct FixtureChirho {
    root_chirho: PathBuf,
    config_chirho: LedgerHostConfigChirho,
    signers_chirho: HostLedgerSignersChirho,
}

impl Drop for FixtureChirho {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root_chirho);
    }
}

fn new_fixture_chirho(
    control_plane_chirho: Option<LedgerHostControlPlaneConfigChirho>,
) -> FixtureChirho {
    let root_chirho = crate::tests_chirho::temp_root_chirho("control-plane-law");
    std::fs::create_dir_all(&root_chirho).unwrap();
    cairn_signer_chirho::signer_chirho::pubkey_hex_chirho(&root_chirho).unwrap();
    for (name_chirho, seed_chirho) in ROLE_SECRETS_CHIRHO {
        set_secret_chirho(&root_chirho, name_chirho, &[seed_chirho; 32]).unwrap();
    }
    let config_chirho = host_config_chirho(control_plane_chirho);
    let refs_chirho =
        host_ledger_signer_refs_from_config_chirho(&config_chirho.signer_secrets_chirho).unwrap();
    let signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&root_chirho, &refs_chirho).unwrap();
    FixtureChirho {
        root_chirho,
        config_chirho,
        signers_chirho,
    }
}

fn compose_law_chirho(
    fixture_chirho: &FixtureChirho,
    voter_chirho: bool,
    runtime_tenant_chirho: Option<&str>,
) -> Result<ControlPlaneLawChirho> {
    let scope_chirho = if voter_chirho {
        ControlPlaneSignerScopeChirho::VoterChirho(&fixture_chirho.signers_chirho)
    } else {
        ControlPlaneSignerScopeChirho::VerifierOnlyChirho
    };
    configured_control_plane_law_chirho(
        &fixture_chirho.root_chirho,
        Some(&fixture_chirho.config_chirho),
        scope_chirho,
        runtime_tenant_chirho,
        &key_hex_chirho(CONTROL_KEY_SEED_CHIRHO),
    )
}

fn refusal_text_chirho(result_chirho: Result<ControlPlaneLawChirho>) -> String {
    format!(
        "{:#}",
        result_chirho.expect_err("this composition must refuse")
    )
}

/// Every path under the root, with each file's bytes, so an arm can prove nothing was written.
fn snapshot_chirho(root_chirho: &std::path::Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    let mut snapshot_chirho = BTreeMap::new();
    let mut pending_chirho = vec![root_chirho.to_path_buf()];
    while let Some(dir_chirho) = pending_chirho.pop() {
        for entry_chirho in std::fs::read_dir(&dir_chirho).unwrap() {
            let path_chirho = entry_chirho.unwrap().path();
            if std::fs::symlink_metadata(&path_chirho).unwrap().is_dir() {
                snapshot_chirho.insert(path_chirho.clone(), None);
                pending_chirho.push(path_chirho);
            } else {
                let bytes_chirho = std::fs::read(&path_chirho).unwrap();
                snapshot_chirho.insert(path_chirho, Some(bytes_chirho));
            }
        }
    }
    snapshot_chirho
}

fn lineage_law_chirho(
    law_chirho: &ControlPlaneLawChirho,
) -> &cairn_signer_chirho::control_plane_signer_chirho::ControlPlaneLineageLawChirho {
    match law_chirho {
        ControlPlaneLawChirho::LineageRoleChirho(lineage_chirho) => lineage_chirho,
        ControlPlaneLawChirho::NodeKeyChirho => panic!("expected the lineage law"),
    }
}

#[test]
fn no_block_keeps_the_node_key_and_geo_evidence_refuses_chirho() {
    let fixture_chirho = new_fixture_chirho(None);
    assert!(matches!(
        compose_law_chirho(&fixture_chirho, true, Some(TENANT_CHIRHO)).unwrap(),
        ControlPlaneLawChirho::NodeKeyChirho
    ));
    assert!(matches!(
        configured_control_plane_law_chirho(
            &fixture_chirho.root_chirho,
            None,
            ControlPlaneSignerScopeChirho::VerifierOnlyChirho,
            None,
            &key_hex_chirho(CONTROL_KEY_SEED_CHIRHO),
        )
        .unwrap(),
        ControlPlaneLawChirho::NodeKeyChirho
    ));
    std::fs::create_dir(
        fixture_chirho
            .root_chirho
            .join(GEO_GENESIS_GUARD_DIR_CHIRHO),
    )
    .unwrap();
    let refusal_chirho = refusal_text_chirho(compose_law_chirho(
        &fixture_chirho,
        true,
        Some(TENANT_CHIRHO),
    ));
    assert!(
        refusal_chirho.contains("ControlPlaneLawPinMissingOnGeoRootChirho"),
        "{refusal_chirho}"
    );
}

#[test]
fn a_verifier_only_node_selects_the_lineage_law_without_resolving_the_secret_chirho() {
    // The signer secret is named but absent: resolving it would refuse, so a lineage law proves it was
    // never read.
    let fixture_chirho = new_fixture_chirho(Some(control_plane_block_chirho(
        key_hex_chirho(PIN_SEED_CHIRHO),
        Some(SIGNER_NAME_CHIRHO),
    )));
    let before_chirho = snapshot_chirho(&fixture_chirho.root_chirho);
    let law_chirho = compose_law_chirho(&fixture_chirho, false, Some(TENANT_CHIRHO)).unwrap();
    let lineage_chirho = lineage_law_chirho(&law_chirho);
    assert!(lineage_chirho.signer_chirho.is_none());
    assert!(!lineage_chirho.law_marker_present_chirho);
    assert_eq!(
        lineage_chirho
            .verifier_chirho
            .pin_chirho()
            .key_id_hex_chirho(),
        key_hex_chirho(PIN_SEED_CHIRHO)
    );
    let signing_refusal_chirho = law_chirho
        .sign_lineage_chirho(ControlPlaneFamilyChirho::ALL_CHIRHO[0], b"inner-chirho")
        .unwrap_err()
        .to_string();
    assert!(
        signing_refusal_chirho.contains("ControlPlaneSignerUnavailableChirho"),
        "{signing_refusal_chirho}"
    );
    assert_eq!(snapshot_chirho(&fixture_chirho.root_chirho), before_chirho);
}

#[test]
fn a_voter_loads_its_signer_signs_and_writes_nothing_chirho() {
    let fixture_chirho = new_fixture_chirho(Some(control_plane_block_chirho(
        key_hex_chirho(PIN_SEED_CHIRHO),
        Some(SIGNER_NAME_CHIRHO),
    )));
    set_secret_chirho(
        &fixture_chirho.root_chirho,
        SIGNER_NAME_CHIRHO,
        &[PIN_SEED_CHIRHO; 32],
    )
    .unwrap();
    let before_chirho = snapshot_chirho(&fixture_chirho.root_chirho);
    let law_chirho = compose_law_chirho(&fixture_chirho, true, Some(TENANT_CHIRHO)).unwrap();
    let family_chirho = ControlPlaneFamilyChirho::ALL_CHIRHO[0];
    let signature_chirho = law_chirho
        .sign_lineage_chirho(family_chirho, b"inner-chirho")
        .unwrap();
    let verifier_chirho = &lineage_law_chirho(&law_chirho).verifier_chirho;
    assert!(verifier_chirho
        .verify_chirho(family_chirho, b"inner-chirho", &signature_chirho)
        .unwrap());
    assert!(!verifier_chirho
        .verify_chirho(family_chirho, b"other-inner-chirho", &signature_chirho)
        .unwrap());
    assert_eq!(snapshot_chirho(&fixture_chirho.root_chirho), before_chirho);
}

#[test]
fn a_voter_whose_block_names_no_signer_refuses_chirho() {
    let fixture_chirho = new_fixture_chirho(Some(control_plane_block_chirho(
        key_hex_chirho(PIN_SEED_CHIRHO),
        None,
    )));
    let refusal_chirho = refusal_text_chirho(compose_law_chirho(
        &fixture_chirho,
        true,
        Some(TENANT_CHIRHO),
    ));
    assert!(
        refusal_chirho.contains("ControlPlaneVoterSignerMissingChirho"),
        "{refusal_chirho}"
    );
    // The same block on a verifier-only node is a lineage law that cannot sign.
    assert!(lineage_law_chirho(
        &compose_law_chirho(&fixture_chirho, false, Some(TENANT_CHIRHO)).unwrap()
    )
    .signer_chirho
    .is_none());
}

#[test]
fn a_voter_refuses_a_missing_short_zero_or_foreign_seed_and_mints_nothing_chirho() {
    let missing_chirho = new_fixture_chirho(Some(control_plane_block_chirho(
        key_hex_chirho(PIN_SEED_CHIRHO),
        Some(SIGNER_NAME_CHIRHO),
    )));
    let before_chirho = snapshot_chirho(&missing_chirho.root_chirho);
    let refusal_chirho = refusal_text_chirho(compose_law_chirho(
        &missing_chirho,
        true,
        Some(TENANT_CHIRHO),
    ));
    assert!(
        refusal_chirho.contains("ControlPlaneSignerSecretUnavailableChirho"),
        "{refusal_chirho}"
    );
    // Read-only: the missing secret was not created, and nothing else changed.
    assert_eq!(snapshot_chirho(&missing_chirho.root_chirho), before_chirho);

    for (value_chirho, expected_chirho) in [
        (
            vec![PIN_SEED_CHIRHO; 31],
            "ControlPlaneSignerSecretLengthChirho",
        ),
        (vec![0_u8; 32], "ControlPlaneSignerSeedAllZeroChirho"),
        (vec![0x7f_u8; 32], "ControlPlaneSignerPinMismatchChirho"),
    ] {
        let fixture_chirho = new_fixture_chirho(Some(control_plane_block_chirho(
            key_hex_chirho(PIN_SEED_CHIRHO),
            Some(SIGNER_NAME_CHIRHO),
        )));
        set_secret_chirho(
            &fixture_chirho.root_chirho,
            SIGNER_NAME_CHIRHO,
            &value_chirho,
        )
        .unwrap();
        let refusal_chirho = refusal_text_chirho(compose_law_chirho(
            &fixture_chirho,
            true,
            Some(TENANT_CHIRHO),
        ));
        assert!(
            refusal_chirho.contains(expected_chirho),
            "{expected_chirho}: {refusal_chirho}"
        );
    }
}

#[test]
fn the_role_key_must_differ_from_every_runtime_signer_chirho() {
    // The config role's key is pinned nowhere in the config, so config validation passes and only the
    // loaded signer set can see the collision.
    let key_chirho = new_fixture_chirho(Some(control_plane_block_chirho(
        key_hex_chirho(0x62),
        Some(SIGNER_NAME_CHIRHO),
    )));
    set_secret_chirho(&key_chirho.root_chirho, SIGNER_NAME_CHIRHO, &[0x62; 32]).unwrap();
    let refusal_chirho =
        refusal_text_chirho(compose_law_chirho(&key_chirho, true, Some(TENANT_CHIRHO)));
    assert!(
        refusal_chirho.contains("ControlPlaneRoleKeyCollisionChirho: ConfigChirho"),
        "{refusal_chirho}"
    );

    // A signer set loaded under other names than the config's still refuses a shared secret name.
    let mut name_chirho = new_fixture_chirho(Some(control_plane_block_chirho(
        key_hex_chirho(PIN_SEED_CHIRHO),
        Some(SIGNER_NAME_CHIRHO),
    )));
    let mut other_names_chirho = role_names_chirho();
    other_names_chirho[1] = SIGNER_NAME_CHIRHO;
    set_secret_chirho(&name_chirho.root_chirho, SIGNER_NAME_CHIRHO, &[0x62; 32]).unwrap();
    let other_refs_chirho =
        host_ledger_signer_refs_from_config_chirho(&role_refs_chirho(other_names_chirho)).unwrap();
    name_chirho.signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&name_chirho.root_chirho, &other_refs_chirho)
            .unwrap();
    let refusal_chirho =
        refusal_text_chirho(compose_law_chirho(&name_chirho, true, Some(TENANT_CHIRHO)));
    assert!(
        refusal_chirho.contains("ControlPlaneRoleSecretNameCollisionChirho: ConfigChirho"),
        "{refusal_chirho}"
    );
}

#[test]
fn the_role_key_must_differ_from_the_gd7_control_key_and_the_node_key_chirho() {
    let control_chirho = new_fixture_chirho(Some(control_plane_block_chirho(
        key_hex_chirho(CONTROL_KEY_SEED_CHIRHO),
        None,
    )));
    let refusal_chirho = refusal_text_chirho(compose_law_chirho(
        &control_chirho,
        false,
        Some(TENANT_CHIRHO),
    ));
    assert!(
        refusal_chirho.contains("ControlPlaneRoleKeyCollisionChirho: gd7-control-key-chirho"),
        "{refusal_chirho}"
    );

    let mut node_chirho = new_fixture_chirho(None);
    let node_key_hex_chirho =
        cairn_signer_chirho::signer_chirho::existing_pubkey_hex_chirho(&node_chirho.root_chirho)
            .unwrap();
    node_chirho.config_chirho =
        host_config_chirho(Some(control_plane_block_chirho(node_key_hex_chirho, None)));
    let refusal_chirho =
        refusal_text_chirho(compose_law_chirho(&node_chirho, false, Some(TENANT_CHIRHO)));
    assert!(
        refusal_chirho.contains("ControlPlaneRoleKeyCollisionChirho: node-key-chirho"),
        "{refusal_chirho}"
    );
}

#[test]
fn the_tenant_must_be_valid_and_equal_the_runtime_tenant_chirho() {
    let fixture_chirho = new_fixture_chirho(Some(control_plane_block_chirho(
        key_hex_chirho(PIN_SEED_CHIRHO),
        None,
    )));
    compose_law_chirho(&fixture_chirho, false, Some(TENANT_CHIRHO)).unwrap();
    for runtime_chirho in [None, Some("other-tenant-chirho")] {
        let refusal_chirho =
            refusal_text_chirho(compose_law_chirho(&fixture_chirho, false, runtime_chirho));
        assert!(
            refusal_chirho.contains("ControlPlaneTenantMismatchChirho"),
            "{runtime_chirho:?}: {refusal_chirho}"
        );
    }
    // A config token that cairn-tenant's rule refuses: underscores are not tenant characters.
    let mut invalid_chirho = new_fixture_chirho(None);
    let mut block_chirho = control_plane_block_chirho(key_hex_chirho(PIN_SEED_CHIRHO), None);
    block_chirho.tenant_id_chirho = "geo_tenant_chirho".to_owned();
    invalid_chirho.config_chirho = host_config_chirho(Some(block_chirho));
    let refusal_chirho = refusal_text_chirho(compose_law_chirho(
        &invalid_chirho,
        false,
        Some("geo_tenant_chirho"),
    ));
    assert!(
        refusal_chirho.contains("ControlPlaneTenantInvalidChirho"),
        "{refusal_chirho}"
    );
}

#[test]
fn the_law_marker_must_match_the_configured_lineage_chirho() {
    let pin_hex_chirho = key_hex_chirho(PIN_SEED_CHIRHO);
    let equal_chirho = new_fixture_chirho(Some(control_plane_block_chirho(
        pin_hex_chirho.clone(),
        None,
    )));
    publish_control_plane_law_marker_chirho(
        &equal_chirho.root_chirho,
        &ControlPlaneLawMarkerChirho {
            key_id_hex_chirho: pin_hex_chirho.clone(),
            lineage_chirho: ControlPlaneLineageChirho::new_chirho(
                TENANT_CHIRHO,
                &instance_id_chirho(),
            )
            .unwrap(),
        },
    )
    .unwrap();
    assert!(
        lineage_law_chirho(&compose_law_chirho(&equal_chirho, false, Some(TENANT_CHIRHO)).unwrap())
            .law_marker_present_chirho
    );

    let other_chirho = new_fixture_chirho(Some(control_plane_block_chirho(
        pin_hex_chirho.clone(),
        None,
    )));
    publish_control_plane_law_marker_chirho(
        &other_chirho.root_chirho,
        &ControlPlaneLawMarkerChirho {
            key_id_hex_chirho: pin_hex_chirho,
            lineage_chirho: ControlPlaneLineageChirho::new_chirho(TENANT_CHIRHO, &"99".repeat(32))
                .unwrap(),
        },
    )
    .unwrap();
    let refusal_chirho = refusal_text_chirho(compose_law_chirho(
        &other_chirho,
        false,
        Some(TENANT_CHIRHO),
    ));
    assert!(
        refusal_chirho.contains("ControlPlaneLawMarkerMismatchChirho"),
        "{refusal_chirho}"
    );
}

#[test]
fn a_weak_pin_passes_config_and_refuses_at_composition_chirho() {
    // The identity point: nonzero lowercase hex, so config accepts it, but it is a small-order key.
    let weak_pin_chirho = format!("01{}", "00".repeat(31));
    let fixture_chirho =
        new_fixture_chirho(Some(control_plane_block_chirho(weak_pin_chirho, None)));
    fixture_chirho.config_chirho.validate_chirho().unwrap();
    let refusal_chirho = refusal_text_chirho(compose_law_chirho(
        &fixture_chirho,
        false,
        Some(TENANT_CHIRHO),
    ));
    assert!(
        refusal_chirho.contains("ControlPlanePinWeakKeyChirho"),
        "{refusal_chirho}"
    );
}
