// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Arms for the host config's control-plane block (C2.1 brick 1a-iii): admitted only beside
//! held-verifier authority, with a pin distinct from every key the config pins and a signer name
//! distinct from every secret it names.

use super::*;

const TENANT_CHIRHO: &str = "geo-tenant-chirho";
const SIGNER_NAME_CHIRHO: &str = "control-plane-key-chirho";

fn pin_chirho() -> String {
    "77".repeat(32)
}

fn instance_id_chirho() -> String {
    "88".repeat(32)
}

fn block_chirho(
    pin_chirho: &str,
    tenant_chirho: &str,
    instance_chirho: &str,
    signer_chirho: Option<&str>,
) -> String {
    let mut block_chirho = format!(
        "\n[ledger_host_chirho.control_plane_chirho]\n\
         verifying_key_hex_chirho = \"{pin_chirho}\"\n\
         tenant_id_chirho = \"{tenant_chirho}\"\n\
         genesis_instance_id_chirho = \"{instance_chirho}\"\n"
    );
    if let Some(signer_chirho) = signer_chirho {
        block_chirho.push_str(&format!("signer_secret_chirho = \"{signer_chirho}\"\n"));
    }
    block_chirho
}

fn good_block_chirho(signer_chirho: Option<&str>) -> String {
    block_chirho(
        &pin_chirho(),
        TENANT_CHIRHO,
        &instance_id_chirho(),
        signer_chirho,
    )
}

/// A whole config: the runtime tenant the block must name, then the host and control-plane blocks.
fn with_tenant_chirho(host_and_block_chirho: &str) -> String {
    format!("tenant_chirho = \"{TENANT_CHIRHO}\"\n{host_and_block_chirho}")
}

/// The v4 fixture pins the kind issuer (11), the activation authority (22) and the journal, effect
/// intent and effect terminal verifiers (33, 44, 55).
fn v4_with_chirho(block_chirho: &str) -> String {
    with_tenant_chirho(&format!(
        "{}{block_chirho}",
        valid_host_block_with_live_held_pins_chirho()
    ))
}

fn refusal_text_chirho(source_chirho: &str) -> String {
    let refusal_chirho =
        parse_config_chirho(source_chirho).expect_err("this control-plane block must refuse");
    format!("{refusal_chirho:#}")
}

#[test]
fn a_control_plane_block_round_trips_beside_held_verifier_authority_chirho() {
    let config_chirho = parse_config_chirho(&v4_with_chirho(&good_block_chirho(Some(
        SIGNER_NAME_CHIRHO,
    ))))
    .unwrap();
    let block_chirho = config_chirho
        .ledger_host_chirho
        .as_ref()
        .unwrap()
        .control_plane_chirho
        .as_ref()
        .unwrap();
    assert_eq!(block_chirho.verifying_key_hex_chirho, pin_chirho());
    assert_eq!(block_chirho.tenant_id_chirho, TENANT_CHIRHO);
    assert_eq!(
        block_chirho.genesis_instance_id_chirho,
        instance_id_chirho()
    );
    assert_eq!(
        block_chirho.signer_secret_chirho.as_deref(),
        Some(SIGNER_NAME_CHIRHO)
    );
    let serialized_chirho = serialize_config_chirho(&config_chirho).unwrap();
    assert_eq!(
        parse_config_chirho(&serialized_chirho)
            .unwrap()
            .ledger_host_chirho,
        config_chirho.ledger_host_chirho
    );

    // v3 admits the block too, and a verifier-only block names no signer.
    let v3_chirho = with_tenant_chirho(&format!(
        "{}{}",
        valid_host_block_with_held_pins_chirho(),
        good_block_chirho(None)
    ));
    let v3_block_chirho = parse_config_chirho(&v3_chirho)
        .unwrap()
        .ledger_host_chirho
        .unwrap()
        .control_plane_chirho
        .unwrap();
    assert_eq!(v3_block_chirho.signer_secret_chirho, None);
}

#[test]
fn an_absent_block_stays_absent_and_serializes_to_nothing_chirho() {
    let config_chirho =
        parse_config_chirho(&valid_host_block_with_live_held_pins_chirho()).unwrap();
    assert_eq!(
        config_chirho
            .ledger_host_chirho
            .as_ref()
            .unwrap()
            .control_plane_chirho,
        None
    );
    let serialized_chirho = serialize_config_chirho(&config_chirho).unwrap();
    assert!(
        !serialized_chirho.contains("control_plane_chirho"),
        "{serialized_chirho}"
    );
}

#[test]
fn the_block_is_refused_without_held_verifier_authority_chirho() {
    let block_chirho = good_block_chirho(Some(SIGNER_NAME_CHIRHO));
    for base_chirho in [
        valid_host_block_chirho(),
        valid_host_block_with_activation_chirho(),
    ] {
        // The base alone is valid, so the block is the only thing that can refuse here.
        parse_config_chirho(&base_chirho).unwrap();
        let refusal_chirho =
            refusal_text_chirho(&with_tenant_chirho(&format!("{base_chirho}{block_chirho}")));
        assert!(
            refusal_chirho.contains("control-plane authority requires held-verifier authority"),
            "{refusal_chirho}"
        );
    }
}

#[test]
fn the_block_tenant_must_equal_the_runtime_tenant_chirho() {
    let host_and_block_chirho = format!(
        "{}{}",
        valid_host_block_with_live_held_pins_chirho(),
        good_block_chirho(None)
    );
    // The matching tenant is the control for both refusals.
    parse_config_chirho(&with_tenant_chirho(&host_and_block_chirho)).unwrap();
    for outer_chirho in ["", "tenant_chirho = \"other-tenant-chirho\"\n"] {
        let refusal_chirho = refusal_text_chirho(&format!("{outer_chirho}{host_and_block_chirho}"));
        assert!(
            refusal_chirho.contains("control-plane tenant must equal the runtime tenant_chirho"),
            "{outer_chirho:?}: {refusal_chirho}"
        );
    }
}

#[test]
fn the_pin_and_the_instance_id_must_be_nonzero_lower_hex_chirho() {
    let bad_values_chirho = [
        "AB".repeat(32),
        "00".repeat(32),
        "77".repeat(31),
        format!("{}g", "7".repeat(63)),
    ];
    for bad_chirho in &bad_values_chirho {
        let pin_refusal_chirho = refusal_text_chirho(&v4_with_chirho(&block_chirho(
            bad_chirho,
            TENANT_CHIRHO,
            &instance_id_chirho(),
            None,
        )));
        assert!(
            pin_refusal_chirho.contains(
                "control_plane.verifying_key_hex_chirho must be one nonzero 32-byte lowercase-hex value"
            ),
            "{pin_refusal_chirho}"
        );
        let instance_refusal_chirho = refusal_text_chirho(&v4_with_chirho(&block_chirho(
            &pin_chirho(),
            TENANT_CHIRHO,
            bad_chirho,
            None,
        )));
        assert!(
            instance_refusal_chirho.contains(
                "control_plane.genesis_instance_id_chirho must be one nonzero 32-byte lowercase-hex value"
            ),
            "{instance_refusal_chirho}"
        );
    }
}

#[test]
fn the_tenant_and_the_signer_name_must_be_config_tokens_chirho() {
    for bad_tenant_chirho in ["Geo-Tenant-chirho", "", "geo tenant"] {
        let refusal_chirho = refusal_text_chirho(&v4_with_chirho(&block_chirho(
            &pin_chirho(),
            bad_tenant_chirho,
            &instance_id_chirho(),
            None,
        )));
        assert!(
            refusal_chirho
                .contains("control_plane.tenant_id_chirho must be one bounded lowercase token"),
            "{refusal_chirho}"
        );
    }
    for bad_signer_chirho in ["Control-Plane-Key-chirho", "control plane", ""] {
        let refusal_chirho =
            refusal_text_chirho(&v4_with_chirho(&good_block_chirho(Some(bad_signer_chirho))));
        assert!(
            refusal_chirho
                .contains("control_plane.signer_secret_chirho must be one bounded lowercase token"),
            "{refusal_chirho}"
        );
    }
}

#[test]
fn the_pin_must_differ_from_every_key_the_config_pins_chirho() {
    // A destination authority adds a sixth pinned key (66) beside the v4 fixture's five.
    let with_destination_chirho = with_tenant_chirho(&format!(
        "{}\n[ledger_host_chirho.migration_destination_authority_chirho]\n\
         key_id_chirho = \"platform-migration-destination-chirho\"\n\
         verifying_key_hex_chirho = \"{}\"\n",
        valid_host_block_with_live_held_pins_chirho(),
        "66".repeat(32)
    ));
    parse_config_chirho(&format!(
        "{with_destination_chirho}{}",
        good_block_chirho(None)
    ))
    .unwrap();
    for pinned_chirho in ["11", "22", "33", "44", "55", "66"] {
        let refusal_chirho = refusal_text_chirho(&format!(
            "{with_destination_chirho}{}",
            block_chirho(
                &pinned_chirho.repeat(32),
                TENANT_CHIRHO,
                &instance_id_chirho(),
                None
            )
        ));
        assert!(
            refusal_chirho.contains(
                "control-plane verifying key must be distinct from every other key this config pins"
            ),
            "pinned {pinned_chirho}: {refusal_chirho}"
        );
    }
}

#[test]
fn the_signer_name_must_differ_from_every_secret_the_config_names_chirho() {
    let with_postgres_chirho = with_tenant_chirho(&format!(
        "{}\n[ledger_host_chirho.postgres_effect_chirho]\nschema_chirho = \"{}\"\n\
         posture_chirho = \"local-phase-b-chirho\"\nconnection_secret_chirho = \"cf7-postgres-dsn-chirho\"\n\
         billing_kind_chirho = \"credits-chirho\"\n",
        valid_host_block_with_live_held_pins_chirho(),
        LEDGER_HOST_POSTGRES_EFFECT_CONFIG_SCHEMA_V1_CHIRHO,
    ));
    parse_config_chirho(&format!(
        "{with_postgres_chirho}{}",
        good_block_chirho(Some(SIGNER_NAME_CHIRHO))
    ))
    .unwrap();
    for taken_chirho in [
        "ledger-journal-key-chirho",
        "ledger-config-key-chirho",
        "ledger-feeder-key-chirho",
        "ledger-kind-root-key-chirho",
        "effect-intent-key-chirho",
        "effect-terminal-key-chirho",
        "cf7-postgres-dsn-chirho",
    ] {
        let refusal_chirho = refusal_text_chirho(&format!(
            "{with_postgres_chirho}{}",
            good_block_chirho(Some(taken_chirho))
        ));
        assert!(
            refusal_chirho.contains(
                "control-plane signer secret name must be distinct from every other secret this config names"
            ),
            "{taken_chirho}: {refusal_chirho}"
        );
    }
}

#[test]
fn the_block_refuses_unknown_and_missing_fields_chirho() {
    let block_chirho = good_block_chirho(None);
    let unknown_chirho = refusal_text_chirho(&v4_with_chirho(&format!(
        "{block_chirho}lineage_chirho = \"x\"\n"
    )));
    assert!(unknown_chirho.contains("unknown field"), "{unknown_chirho}");
    for (field_chirho, value_chirho) in [
        ("verifying_key_hex_chirho", pin_chirho()),
        ("tenant_id_chirho", TENANT_CHIRHO.to_owned()),
        ("genesis_instance_id_chirho", instance_id_chirho()),
    ] {
        let without_chirho =
            block_chirho.replace(&format!("{field_chirho} = \"{value_chirho}\"\n"), "");
        assert_ne!(
            without_chirho, block_chirho,
            "the {field_chirho} line must have been removed"
        );
        let missing_chirho = refusal_text_chirho(&v4_with_chirho(&without_chirho));
        assert!(
            missing_chirho.contains("missing field") && missing_chirho.contains(field_chirho),
            "{field_chirho}: {missing_chirho}"
        );
    }
}
