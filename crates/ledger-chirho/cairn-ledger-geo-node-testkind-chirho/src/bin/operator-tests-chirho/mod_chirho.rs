// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_ledger_geo_node_testkind_chirho::TestkindCf7OperatorOperationChirho;
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, verify_with_pubkey_chirho};
use cairn_tenant_chirho::tenant_chirho::prepare_tenant_root_chirho;
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_ID_CHIRHO: AtomicU64 = AtomicU64::new(0);

fn activation_secret_fixture_root_chirho(label_chirho: &str) -> PathBuf {
    let platform_chirho = platform_root_chirho(label_chirho);
    std::fs::create_dir_all(&platform_chirho).unwrap();
    prepare_tenant_root_chirho(&platform_chirho, "writer-adoption-tenant-chirho").unwrap()
}

fn response_path_chirho(label_chirho: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "cairn-cf7-operator-client-{label_chirho}-{}-{}-chirho.json",
        std::process::id(),
        FIXTURE_ID_CHIRHO.fetch_add(1, Ordering::Relaxed)
    ))
}

fn platform_root_chirho(label_chirho: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "cairn-writer-adoption-author-{label_chirho}-{}-{}-chirho",
        std::process::id(),
        FIXTURE_ID_CHIRHO.fetch_add(1, Ordering::Relaxed)
    ))
}

/// A VALID-LENGTH BUT WRONG key authors a well-shaped record that the activation authority's
/// own signature check REJECTS -- the "present but wrong authority" case.
///
/// gpt_chirho's review of the first version of this commit caught that absent / wrong-LENGTH /
/// correct omits the case that actually matters operationally: a real 32-byte secret stored under
/// the wrong name. It resolves cleanly, signs cleanly, and produces a record that is malformed in
/// no way at all -- the only thing wrong with it is WHOSE key signed it, which is exactly what the
/// downstream activation-authority check exists to catch.
///
/// SCOPE, stated so this arm is not read as more than it is: it asserts the SIGNATURE RELATION the
/// verifier performs -- `unsigned_..._message_chirho` verified against the pinned activation key --
/// rather than invoking `verify_tenant_migration_writer_adoption_record_chirho`, which the host
/// crate does not re-export. Widening that crate's public surface to reach it from here would be
/// scope creep into another seat's brick; the typed-identity arm for it belongs beside the
/// verifier, in `writer_adoption_chirho/tests_chirho.rs`.
#[test]
fn a_valid_but_wrong_activation_secret_authors_a_record_the_authority_rejects_chirho() {
    let root_chirho = activation_secret_fixture_root_chirho("wrong-authority");
    let good_seed_chirho = [91u8; 32];
    let wrong_seed_chirho = [92u8; 32];
    for (name_chirho, seed_chirho) in [
        ("activation-authority-good-chirho", &good_seed_chirho),
        ("activation-authority-wrong-chirho", &wrong_seed_chirho),
    ] {
        cairn_secret_chirho::secret_chirho::set_secret_chirho(
            &root_chirho,
            name_chirho,
            seed_chirho,
        )
        .unwrap();
    }

    let good_chirho = activation_signing_key_from_root_secret_chirho(
        &root_chirho,
        "activation-authority-good-chirho",
    )
    .expect("the configured activation secret resolves");
    let wrong_chirho = activation_signing_key_from_root_secret_chirho(
        &root_chirho,
        "activation-authority-wrong-chirho",
    )
    .expect("a wrong-but-valid secret ALSO resolves -- that is the whole point of this arm");

    // The pinned authority is the GOOD key: this is the configured activation authority.
    let pinned_chirho = good_chirho.verifying_key();
    let pinned_hex_chirho = hex_lower_chirho(pinned_chirho.as_bytes());

    let message_chirho = b"tenant-migration-writer-adoption-arm-chirho";
    let good_sig_chirho =
        hex_lower_chirho(&ed25519_dalek::Signer::sign(&good_chirho, message_chirho).to_bytes());
    let wrong_sig_chirho =
        hex_lower_chirho(&ed25519_dalek::Signer::sign(&wrong_chirho, message_chirho).to_bytes());

    assert!(
        verify_with_pubkey_chirho(&pinned_hex_chirho, message_chirho, &good_sig_chirho).unwrap(),
        "the configured activation authority's own signature must verify"
    );
    assert!(
        !verify_with_pubkey_chirho(&pinned_hex_chirho, message_chirho, &wrong_sig_chirho).unwrap(),
        "a record signed by a DIFFERENT valid 32-byte secret must NOT verify as the activation \
         authority -- otherwise any resolvable secret could co-sign an adoption"
    );
    assert_ne!(
        wrong_chirho.verifying_key().as_bytes(),
        pinned_chirho.as_bytes(),
        "the two fixtures must actually differ, or the assertion above is vacuous"
    );
}

/// The activation seed is resolved from the ROOT'S OWN SECRET STORE, and the three outcomes stay
/// distinct.
///
/// This arm exists because the authoring command previously took a 64-hex seed FILE PATH, which
/// obliged the operator to materialise a second copy of a private key just to run the ceremony --
/// a custody surface the clause-6 foundation had deliberately avoided by minting raw bytes into
/// `secret-set` and deleting the temporary. Found by gpt_chirho auditing its own brick.
///
/// MIGRATION PATH: if the correct-secret case ever REFUSES, the custody API or the stored form
/// changed -- retarget on the new refusal identity, do NOT reintroduce a seed-file path. If one
/// of the two refusal arms starts returning its neighbour's identity, the absent/malformed
/// distinction has collapsed, which is the exact defect class this repo closed on 2026-08-20.
#[test]
fn activation_secret_resolves_from_the_root_and_keeps_three_outcomes_distinct_chirho() {
    let root_chirho = activation_secret_fixture_root_chirho("activation-secret");
    let seed_chirho = [83u8; 32];

    // (1) PRESENT AND CORRECT: the derived public key must be the one the seed implies, or the
    //     record would be signed by a key the verifier will not accept as the activation authority.
    cairn_secret_chirho::secret_chirho::set_secret_chirho(
        &root_chirho,
        "activation-good-chirho",
        &seed_chirho,
    )
    .unwrap();
    let resolved_chirho =
        activation_signing_key_from_root_secret_chirho(&root_chirho, "activation-good-chirho")
            .expect("a present 32-byte secret must resolve");
    assert_eq!(
        resolved_chirho.verifying_key().as_bytes(),
        ed25519_dalek::SigningKey::from_bytes(&seed_chirho)
            .verifying_key()
            .as_bytes(),
        "the resolved key must be the stored seed's key, not some other key that merely signs"
    );

    // (2) ABSENT: never confused with present-but-wrong.
    let absent_chirho =
        activation_signing_key_from_root_secret_chirho(&root_chirho, "activation-absent-chirho")
            .expect_err("an absent secret must refuse");
    let absent_text_chirho = format!("{absent_chirho}");
    assert!(
        absent_text_chirho.contains("ActivationSecretUnresolvableChirho"),
        "absent secret must refuse as UNRESOLVABLE: {absent_text_chirho}"
    );
    assert!(
        !absent_text_chirho.contains("MalformedChirho"),
        "an absent secret must NOT report the malformed identity: {absent_text_chirho}"
    );

    // (3) PRESENT BUT WRONG LENGTH: its own identity, and NOT the absent one. A two-case version
    //     of this check cannot tell these apart, which is precisely how an Err comes to mean
    //     both "nothing there" and "something wrong there".
    cairn_secret_chirho::secret_chirho::set_secret_chirho(
        &root_chirho,
        "activation-short-chirho",
        &[9u8; 16],
    )
    .unwrap();
    let malformed_chirho =
        activation_signing_key_from_root_secret_chirho(&root_chirho, "activation-short-chirho")
            .expect_err("a wrong-length secret must refuse");
    let malformed_text_chirho = format!("{malformed_chirho}");
    assert!(
        malformed_text_chirho.contains("ActivationSecretMalformedChirho"),
        "wrong-length secret must refuse as MALFORMED: {malformed_text_chirho}"
    );
    assert!(
        !malformed_text_chirho.contains("UnresolvableChirho"),
        "a present secret must NOT report the absent identity: {malformed_text_chirho}"
    );

    // (4) NO LEAK, at exactly the scope this arm measures and no wider: the two RESOLVER
    //     REFUSAL STRINGS must carry neither the stored bytes nor the resolved path. It does NOT
    //     inspect argv, stdout, stderr, or the success record -- gpt_chirho's review caught that
    //     the earlier wording claimed all of those while the assertions covered only these two,
    //     and a claim broader than its arm is the thing a later reader inherits. The needle is
    //     the ACTUAL stored value, so what it does cover cannot pass vacuously.
    let seed_hex_chirho = hex_lower_chirho(&seed_chirho);
    let short_hex_chirho = hex_lower_chirho(&[9u8; 16]);
    for text_chirho in [&absent_text_chirho, &malformed_text_chirho] {
        for needle_chirho in [&seed_hex_chirho, &short_hex_chirho] {
            assert!(
                !text_chirho.contains(needle_chirho.as_str()),
                "refusal text leaked secret material: {text_chirho}"
            );
        }
        assert!(
            !text_chirho.contains(root_chirho.to_string_lossy().as_ref()),
            "refusal text leaked the resolved secret path: {text_chirho}"
        );
    }
}

#[test]
fn writer_adoption_author_mints_nonce_and_refuses_merged_authority_roles_chirho() {
    let source_platform_chirho = platform_root_chirho("source");
    let target_platform_chirho = platform_root_chirho("target");
    std::fs::create_dir_all(&source_platform_chirho).unwrap();
    std::fs::create_dir_all(&target_platform_chirho).unwrap();
    let source_root_chirho =
        prepare_tenant_root_chirho(&source_platform_chirho, "writer-adoption-tenant-chirho")
            .unwrap();
    let target_root_chirho =
        prepare_tenant_root_chirho(&target_platform_chirho, "writer-adoption-tenant-chirho")
            .unwrap();
    pubkey_hex_chirho(&source_root_chirho).expect("mint the source instance key");
    pubkey_hex_chirho(&target_root_chirho).expect("mint the target instance key");
    let source_chirho =
        VerifiedTenantMigrationRootChirho::open_existing_chirho(&source_root_chirho).unwrap();
    let target_chirho =
        VerifiedTenantMigrationRootChirho::open_existing_chirho(&target_root_chirho).unwrap();
    let destination_signing_chirho = ed25519_dalek::SigningKey::from_bytes(&[71; 32]);
    let intent_chirho = TenantMigrationDestinationIntentChirho {
        schema_chirho: TENANT_MIGRATION_DESTINATION_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
        digest_domain_chirho: TENANT_MIGRATION_DESTINATION_INTENT_DOMAIN_V1_CHIRHO.to_owned(),
        tenant_id_chirho: "writer-adoption-tenant-chirho".to_owned(),
        source_root_digest_chirho: source_chirho.binding_identity_digest_hex_chirho().unwrap(),
        destination_root_digest_chirho: target_chirho.binding_identity_digest_hex_chirho().unwrap(),
        revision_chirho: 4,
    };
    let intent_digest_chirho =
        tenant_migration_destination_intent_digest_chirho(&intent_chirho).unwrap();
    let mut destination_chirho = TenantMigrationDestinationRecordChirho {
        schema_chirho: TENANT_MIGRATION_DESTINATION_RECORD_SCHEMA_V1_CHIRHO.to_owned(),
        signature_domain_chirho: TENANT_MIGRATION_DESTINATION_RECORD_DOMAIN_V1_CHIRHO.to_owned(),
        intent_chirho,
        intent_digest_chirho,
        authority_key_id_chirho: hex_lower_chirho(
            destination_signing_chirho.verifying_key().as_bytes(),
        ),
        sig_chirho: String::new(),
    };
    destination_chirho.sig_chirho = hex_lower_chirho(
        &ed25519_dalek::Signer::sign(
            &destination_signing_chirho,
            unsigned_tenant_migration_destination_message_chirho(&destination_chirho).as_bytes(),
        )
        .to_bytes(),
    );

    let activation_signing_chirho = ed25519_dalek::SigningKey::from_bytes(&[72; 32]);
    let first_chirho = build_writer_adoption_record_chirho(
        &source_root_chirho,
        &target_root_chirho,
        &destination_chirho,
        &activation_signing_chirho,
        "platform-writer-activation-chirho",
        "item6-drill-parent-chirho/ledger-chirho",
        "journals/item6-drill-chirho.jsonl",
        "item6-drill-cluster-chirho",
        2,
    )
    .expect("author the first adoption record");
    let second_chirho = build_writer_adoption_record_chirho(
        &source_root_chirho,
        &target_root_chirho,
        &destination_chirho,
        &activation_signing_chirho,
        "platform-writer-activation-chirho",
        "item6-drill-parent-chirho/ledger-chirho",
        "journals/item6-drill-chirho.jsonl",
        "item6-drill-cluster-chirho",
        2,
    )
    .expect("author the second adoption record");
    for nonce_chirho in [
        &first_chirho.intent_chirho.attempt_nonce_chirho,
        &second_chirho.intent_chirho.attempt_nonce_chirho,
    ] {
        assert_eq!(nonce_chirho.len(), 64);
        assert!(nonce_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho)
        }));
    }
    assert_ne!(
        first_chirho.intent_chirho.attempt_nonce_chirho,
        second_chirho.intent_chirho.attempt_nonce_chirho,
        "the OS-random attempt nonce must not be an operator-repeatable coordinate"
    );
    let first_bytes_chirho = serde_json::to_vec(&first_chirho).unwrap();
    assert!(
        !first_bytes_chirho
            .windows(b"term_chirho".len())
            .any(|window_chirho| window_chirho == b"term_chirho"),
        "an election term is deliberately outside the durable adoption ceremony"
    );
    assert!(
        verify_with_pubkey_chirho(
            &hex_lower_chirho(activation_signing_chirho.verifying_key().as_bytes()),
            unsigned_tenant_migration_writer_adoption_message_chirho(&first_chirho).as_bytes(),
            &first_chirho.signature_hex_chirho,
        )
        .unwrap(),
        "the authored record must carry the activation authority's signature"
    );

    let merged_role_refusal_chirho = build_writer_adoption_record_chirho(
        &source_root_chirho,
        &target_root_chirho,
        &destination_chirho,
        &destination_signing_chirho,
        "platform-writer-activation-chirho",
        "item6-drill-parent-chirho/ledger-chirho",
        "journals/item6-drill-chirho.jsonl",
        "item6-drill-cluster-chirho",
        2,
    )
    .expect_err("one key must not choose the destination and authorize writer minting");
    assert!(
        merged_role_refusal_chirho
            .to_string()
            .contains("TestkindCf7OperatorMigrationAuthorityRolesEqualChirho"),
        "{merged_role_refusal_chirho}"
    );

    std::fs::remove_dir_all(source_platform_chirho).unwrap();
    std::fs::remove_dir_all(target_platform_chirho).unwrap();
}

fn write_response_fixture_chirho(label_chirho: &str, outcome_chirho: serde_json::Value) -> PathBuf {
    let path_chirho = response_path_chirho(label_chirho);
    let response_chirho: TestkindCf7OperatorResponseChirho =
        serde_json::from_value(serde_json::json!({
            "schema_chirho": "testkind-cf7-operator-response-v1-chirho",
            "outcome_chirho": outcome_chirho,
        }))
        .unwrap();
    let mut bytes_chirho = serde_json::to_vec(&response_chirho).unwrap();
    bytes_chirho.push(b'\n');
    std::fs::write(&path_chirho, bytes_chirho).unwrap();
    path_chirho
}

fn preview_outcome_chirho() -> serde_json::Value {
    serde_json::json!({
        "outcome_chirho": "preview-chirho",
        "preview_chirho": {
            "schema_chirho": "current-postgres-compensation-preview-v1-chirho",
            "app_chirho": "credits-demo-chirho",
            "source_review_report_chirho": "11".repeat(32),
            "plan_digest_chirho": "22".repeat(32),
            "original_effect_key_chirho": "33".repeat(32),
            "intent_ref_chirho": "44".repeat(32),
            "terminal_outcome_ref_chirho": "55".repeat(32),
            "verdict_chirho": { "kind_chirho": "executable-chirho" },
        },
    })
}

fn executed_outcome_chirho() -> serde_json::Value {
    serde_json::json!({
        "outcome_chirho": "executed-chirho",
        "evidence_chirho": {
            "execution_chirho": {
                "schema_chirho": "current-postgres-compensation-execution-v1-chirho",
                "app_chirho": "credits-demo-chirho",
                "original_effect_key_chirho": "33".repeat(32),
                "compensation_intent_ref_chirho": "66".repeat(32),
                "terminal_outcome_ref_chirho": "77".repeat(32),
                "disposition_chirho": {
                    "kind_chirho": "committed-chirho",
                    "result_ref_chirho": "88".repeat(32),
                },
                "provider_restored_chirho": true,
            },
            "post_compensation_head_chirho": {
                "covered_record_count_chirho": 12,
                "checkpoint_digest_chirho": "99".repeat(32),
            },
        },
    })
}

#[test]
fn typed_preview_and_execute_reuse_one_canonical_preview_chirho() {
    let preview_request_chirho = request_from_command_chirho(&[
        OsString::from("preview-chirho"),
        OsString::from("credits-demo-chirho"),
        OsString::from("user/owner-chirho"),
    ])
    .unwrap();
    assert!(matches!(
        preview_request_chirho.operation_chirho,
        TestkindCf7OperatorOperationChirho::PreviewChirho { .. }
    ));

    let path_chirho = write_response_fixture_chirho("preview", preview_outcome_chirho());
    let execute_request_chirho = request_from_command_chirho(&[
        OsString::from("execute-chirho"),
        OsString::from("credits-demo-chirho"),
        OsString::from("user/owner-chirho"),
        path_chirho.clone().into_os_string(),
    ])
    .unwrap();
    let TestkindCf7OperatorOperationChirho::ExecuteChirho {
        reviewed_preview_chirho,
        ..
    } = execute_request_chirho.operation_chirho
    else {
        panic!("typed execute must carry the prior preview")
    };
    assert_eq!(reviewed_preview_chirho.app_chirho, "credits-demo-chirho");
    std::fs::remove_file(path_chirho).unwrap();
}

#[test]
fn typed_replay_and_conservation_reuse_one_execution_evidence_chirho() {
    let path_chirho = write_response_fixture_chirho("execute", executed_outcome_chirho());
    let replay_request_chirho = request_from_command_chirho(&[
        OsString::from("replay-chirho"),
        OsString::from("credits-demo-chirho"),
        OsString::from("user/owner-chirho"),
        path_chirho.clone().into_os_string(),
    ])
    .unwrap();
    assert!(matches!(
        replay_request_chirho.operation_chirho,
        TestkindCf7OperatorOperationChirho::ReplayChirho { .. }
    ));
    let conservation_request_chirho = request_from_command_chirho(&[
        OsString::from("conservation-read-chirho"),
        path_chirho.clone().into_os_string(),
    ])
    .unwrap();
    let TestkindCf7OperatorOperationChirho::ConservationReadChirho {
        expected_head_chirho,
    } = conservation_request_chirho.operation_chirho
    else {
        panic!("typed conservation read must carry the executed head")
    };
    assert_eq!(expected_head_chirho.covered_record_count_chirho, 12);
    std::fs::remove_file(path_chirho).unwrap();
}

#[test]
fn loss_witness_commands_accept_only_one_fixed_phase_chirho() {
    let current_chirho = request_from_command_chirho(&[
        OsString::from("loss-witness-current-chirho"),
        OsString::from("leader-loss-chirho"),
    ])
    .unwrap();
    assert!(matches!(
        current_chirho.operation_chirho,
        TestkindCf7OperatorOperationChirho::LossWitnessCurrentChirho {
            phase_chirho: ResidentTestkindLossWitnessPhaseChirho::LeaderLossChirho,
        }
    ));
    let heal_chirho = request_from_command_chirho(&[
        OsString::from("loss-witness-current-chirho"),
        OsString::from("heal-chirho"),
    ])
    .unwrap();
    assert!(matches!(
        heal_chirho.operation_chirho,
        TestkindCf7OperatorOperationChirho::LossWitnessCurrentChirho {
            phase_chirho: ResidentTestkindLossWitnessPhaseChirho::HealChirho,
        }
    ));
    let current_value_chirho = serde_json::to_value(&current_chirho).unwrap();
    let operation_chirho = current_value_chirho["operation_chirho"]
        .as_object()
        .expect("the canonical operation is an object");
    assert_eq!(operation_chirho.len(), 2);
    assert_eq!(
        operation_chirho["phase_chirho"],
        serde_json::json!("leader-loss-chirho")
    );

    let deposed_chirho = request_from_command_chirho(&[
        OsString::from("loss-witness-deposed-sink-chirho"),
        OsString::from("failback-chirho"),
    ])
    .unwrap();
    assert!(matches!(
        deposed_chirho.operation_chirho,
        TestkindCf7OperatorOperationChirho::LossWitnessDeposedSinkChirho {
            phase_chirho: ResidentTestkindLossWitnessPhaseChirho::FailbackChirho,
        }
    ));

    assert_eq!(
        request_from_command_chirho(&[
            OsString::from("loss-witness-current-chirho"),
            OsString::from("leader-loss-chirho"),
            OsString::from("caller-supplied-owner-chirho"),
        ])
        .unwrap_err()
        .to_string(),
        USAGE_CHIRHO
    );
    assert!(request_from_command_chirho(&[
        OsString::from("loss-witness-current-chirho"),
        OsString::from("invented-phase-chirho"),
    ])
    .unwrap_err()
    .to_string()
    .contains("TestkindCf8LossWitnessPhaseRefusedChirho"));
}

#[test]
fn prior_response_must_be_one_canonical_line_and_the_right_outcome_chirho() {
    let wrong_path_chirho = write_response_fixture_chirho("wrong", executed_outcome_chirho());
    let wrong_result_chirho = request_from_command_chirho(&[
        OsString::from("execute-chirho"),
        OsString::from("credits-demo-chirho"),
        OsString::from("user/owner-chirho"),
        wrong_path_chirho.clone().into_os_string(),
    ]);
    assert!(wrong_result_chirho
        .unwrap_err()
        .to_string()
        .contains("TestkindCf7OperatorExpectedPreviewResponseChirho"));
    std::fs::remove_file(wrong_path_chirho).unwrap();

    let noncanonical_path_chirho = response_path_chirho("noncanonical");
    std::fs::write(&noncanonical_path_chirho, b"{}\n\n").unwrap();
    let noncanonical_result_chirho = read_canonical_response_chirho(&noncanonical_path_chirho);
    assert!(noncanonical_result_chirho
        .unwrap_err()
        .to_string()
        .contains("TestkindCf7OperatorPriorResponseNoncanonicalChirho"));
    std::fs::remove_file(noncanonical_path_chirho).unwrap();
}
