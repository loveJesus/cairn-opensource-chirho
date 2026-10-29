// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Arms for the control-plane role signer, its verifier and the law's pure selection (C2.1 brick 1a).

use super::*;
use crate::signer_chirho::hex_decode_chirho;

const SEED_A_CHIRHO: [u8; 32] = [7; 32];
const SEED_B_CHIRHO: [u8; 32] = [9; 32];

fn lineage_chirho() -> ControlPlaneLineageChirho {
    ControlPlaneLineageChirho::new_chirho("tenant-alpha-chirho", "genesis-0001-chirho").unwrap()
}

fn pin_for_seed_chirho(seed_chirho: [u8; 32]) -> ControlPlanePinChirho {
    let key_chirho = SigningKey::from_bytes(&seed_chirho);
    ControlPlanePinChirho::from_hex_chirho(&hex_encode_chirho(
        key_chirho.verifying_key().as_bytes(),
    ))
    .unwrap()
}

fn verifier_for_seed_chirho(seed_chirho: [u8; 32]) -> ControlPlaneVerifierChirho {
    ControlPlaneVerifierChirho::new_chirho(pin_for_seed_chirho(seed_chirho), lineage_chirho())
}

fn signer_for_seed_chirho(seed_chirho: [u8; 32]) -> ControlPlaneSignerChirho {
    ControlPlaneSignerChirho::from_seed_chirho(
        Zeroizing::new(seed_chirho),
        verifier_for_seed_chirho(seed_chirho),
    )
    .unwrap()
}

fn config_chirho(with_signer_chirho: bool) -> ControlPlaneConfigChirho {
    let signer_chirho = with_signer_chirho.then(|| signer_for_seed_chirho(SEED_A_CHIRHO));
    ControlPlaneConfigChirho::new_chirho(verifier_for_seed_chirho(SEED_A_CHIRHO), signer_chirho)
        .unwrap()
}

fn no_evidence_chirho() -> ControlPlaneEvidenceChirho {
    ControlPlaneEvidenceChirho {
        era_elected_chirho: false,
        genesis_marker_present_chirho: false,
        law_marker_chirho: None,
    }
}

fn error_text_chirho<T: std::fmt::Debug>(result_chirho: Result<T>) -> String {
    result_chirho.expect_err("must refuse").to_string()
}

// --- the lineage ---

#[test]
fn a_lineage_refuses_empty_nul_and_oversized_fields_chirho() {
    assert!(
        error_text_chirho(ControlPlaneLineageChirho::new_chirho("", "g"))
            .starts_with("ControlPlaneLineageFieldEmptyChirho: tenant id")
    );
    assert!(
        error_text_chirho(ControlPlaneLineageChirho::new_chirho("t", ""))
            .starts_with("ControlPlaneLineageFieldEmptyChirho: genesis instance id")
    );
    assert!(
        error_text_chirho(ControlPlaneLineageChirho::new_chirho("t\0x", "g"))
            .starts_with("ControlPlaneLineageFieldNulChirho")
    );
    assert!(
        error_text_chirho(ControlPlaneLineageChirho::new_chirho("t", "g\0"))
            .starts_with("ControlPlaneLineageFieldNulChirho")
    );
    let long_chirho = "x".repeat(CONTROL_PLANE_LINEAGE_FIELD_MAX_BYTES_CHIRHO + 1);
    assert!(
        error_text_chirho(ControlPlaneLineageChirho::new_chirho(&long_chirho, "g"))
            .starts_with("ControlPlaneLineageFieldTooLongChirho")
    );
    let at_limit_chirho = "x".repeat(CONTROL_PLANE_LINEAGE_FIELD_MAX_BYTES_CHIRHO);
    assert!(ControlPlaneLineageChirho::new_chirho(&at_limit_chirho, "g").is_ok());
}

// --- the domain ---

#[test]
fn the_domain_binds_role_family_and_lineage_before_the_inner_bytes_chirho() {
    let message_chirho = control_plane_message_chirho(
        ControlPlaneRoleChirho::ControlPlaneChirho,
        ControlPlaneFamilyChirho::AppRecordsChirho,
        &lineage_chirho(),
        b"inner\0bytes",
    );
    assert_eq!(
        message_chirho,
        b"cairn-control-plane-v1\0control-plane\0app-records\0tenant-alpha-chirho\0genesis-0001-chirho\0inner\0bytes"
            .to_vec()
    );
}

#[test]
fn every_family_has_a_distinct_nul_free_label_chirho() {
    let labels_chirho: std::collections::BTreeSet<&str> = ControlPlaneFamilyChirho::ALL_CHIRHO
        .iter()
        .map(|family_chirho| family_chirho.label_chirho())
        .collect();
    assert_eq!(
        labels_chirho.len(),
        ControlPlaneFamilyChirho::ALL_CHIRHO.len()
    );
    assert!(labels_chirho
        .iter()
        .all(|label_chirho| !label_chirho.contains('\0')));
}

// --- the pin ---

#[test]
fn a_pin_accepts_only_canonical_lowercase_hex_of_a_strong_point_chirho() {
    let good_hex_chirho = pin_for_seed_chirho(SEED_A_CHIRHO).key_id_hex_chirho();
    assert!(ControlPlanePinChirho::from_hex_chirho(&good_hex_chirho).is_ok());
    assert_eq!(
        error_text_chirho(ControlPlanePinChirho::from_hex_chirho(
            &good_hex_chirho.to_uppercase()
        )),
        "ControlPlanePinNotCanonicalHexChirho"
    );
    assert_eq!(
        error_text_chirho(ControlPlanePinChirho::from_hex_chirho(
            &good_hex_chirho[..62]
        )),
        "ControlPlanePinNotCanonicalHexChirho"
    );
    let non_ascii_chirho = format!("{}€", &good_hex_chirho[..61]);
    assert_eq!(
        error_text_chirho(ControlPlanePinChirho::from_hex_chirho(&non_ascii_chirho)),
        "ControlPlanePinNotCanonicalHexChirho"
    );
    // The identity point is small-order: a pin on it would let trivial signatures through.
    let mut identity_chirho = [0_u8; 32];
    identity_chirho[0] = 1;
    assert_eq!(
        error_text_chirho(ControlPlanePinChirho::from_hex_chirho(&hex_encode_chirho(
            &identity_chirho
        ))),
        "ControlPlanePinWeakKeyChirho"
    );
}

// --- the signer and the verifier ---

#[test]
fn a_signer_refuses_an_all_zero_seed_and_a_seed_that_is_not_the_pin_chirho() {
    assert_eq!(
        error_text_chirho(ControlPlaneSignerChirho::from_seed_chirho(
            Zeroizing::new([0; 32]),
            verifier_for_seed_chirho(SEED_A_CHIRHO)
        )),
        "ControlPlaneSignerSeedAllZeroChirho"
    );
    assert_eq!(
        error_text_chirho(ControlPlaneSignerChirho::from_seed_chirho(
            Zeroizing::new(SEED_B_CHIRHO),
            verifier_for_seed_chirho(SEED_A_CHIRHO)
        )),
        "ControlPlaneSignerPinMismatchChirho"
    );
}

#[test]
fn a_signature_verifies_only_for_its_own_family_lineage_and_bytes_chirho() {
    let signer_chirho = signer_for_seed_chirho(SEED_A_CHIRHO);
    let family_chirho = ControlPlaneFamilyChirho::AppRouteRecordsChirho;
    let sig_chirho = signer_chirho.sign_chirho(family_chirho, b"route record bytes");
    let verifier_chirho = verifier_for_seed_chirho(SEED_A_CHIRHO);
    assert!(verifier_chirho
        .verify_chirho(family_chirho, b"route record bytes", &sig_chirho)
        .unwrap());
    assert!(!verifier_chirho
        .verify_chirho(
            ControlPlaneFamilyChirho::AppRecordsChirho,
            b"route record bytes",
            &sig_chirho
        )
        .unwrap());
    assert!(!verifier_chirho
        .verify_chirho(family_chirho, b"route record byteS", &sig_chirho)
        .unwrap());
    let other_lineage_chirho = ControlPlaneVerifierChirho::new_chirho(
        pin_for_seed_chirho(SEED_A_CHIRHO),
        ControlPlaneLineageChirho::new_chirho("tenant-alpha-chirho", "genesis-0002-chirho")
            .unwrap(),
    );
    assert!(!other_lineage_chirho
        .verify_chirho(family_chirho, b"route record bytes", &sig_chirho)
        .unwrap());
    assert!(!verifier_for_seed_chirho(SEED_B_CHIRHO)
        .verify_chirho(family_chirho, b"route record bytes", &sig_chirho)
        .unwrap());
}

#[test]
fn a_node_key_style_signature_over_the_bare_bytes_never_verifies_chirho() {
    // No downgrade (decision rule 3): the same key signing the inner bytes WITHOUT the domain, the way a
    // node-key record is signed today, must not pass the lineage verifier.
    let bare_sig_chirho = hex_encode_chirho(
        &SigningKey::from_bytes(&SEED_A_CHIRHO)
            .sign(b"app record bytes")
            .to_bytes(),
    );
    assert!(!verifier_for_seed_chirho(SEED_A_CHIRHO)
        .verify_chirho(
            ControlPlaneFamilyChirho::AppRecordsChirho,
            b"app record bytes",
            &bare_sig_chirho
        )
        .unwrap());
}

#[test]
fn a_malformed_signature_refuses_and_never_panics_chirho() {
    let verifier_chirho = verifier_for_seed_chirho(SEED_A_CHIRHO);
    let family_chirho = ControlPlaneFamilyChirho::IdentitiesChirho;
    assert!(
        error_text_chirho(verifier_chirho.verify_chirho(family_chirho, b"x", "abc"))
            .starts_with("odd-length hex string")
    );
    assert!(
        error_text_chirho(verifier_chirho.verify_chirho(family_chirho, b"x", "zz"))
            .starts_with("bad hex")
    );
    assert_eq!(
        error_text_chirho(verifier_chirho.verify_chirho(family_chirho, b"x", "abcd")),
        "ControlPlaneSignatureLengthChirho"
    );
    // A three-byte character puts a char boundary inside a hex pair; slicing would panic there.
    assert!(
        error_text_chirho(verifier_chirho.verify_chirho(family_chirho, b"x", "€a"))
            .starts_with("bad hex")
    );
}

#[test]
fn the_shared_hex_decoder_refuses_multibyte_input_without_panicking_chirho() {
    assert!(hex_decode_chirho("€a")
        .unwrap_err()
        .to_string()
        .starts_with("bad hex"));
    assert!(hex_decode_chirho("éé")
        .unwrap_err()
        .to_string()
        .starts_with("bad hex"));
    assert_eq!(hex_decode_chirho("0aFf").unwrap(), vec![0x0a, 0xff]);
}

#[test]
fn the_signer_debug_output_redacts_the_key_chirho() {
    let rendered_chirho = format!("{:?}", signer_for_seed_chirho(SEED_A_CHIRHO));
    assert!(rendered_chirho.contains("<redacted-chirho>"));
    assert!(!rendered_chirho.contains(&hex_encode_chirho(&SEED_A_CHIRHO)));
}

// --- separation (decision rule 1) ---

#[test]
fn a_role_sharing_a_secret_name_or_a_key_with_another_role_refuses_chirho() {
    let pin_chirho = pin_for_seed_chirho(SEED_A_CHIRHO);
    let journal_chirho = ControlPlaneSeparationPeerChirho {
        label_chirho: "journal".to_string(),
        secret_name_chirho: Some("ledger-journal-chirho".to_string()),
        key_chirho: Some(pin_for_seed_chirho(SEED_B_CHIRHO).key_bytes_chirho()),
    };
    assert!(refuse_control_plane_role_collisions_chirho(
        &pin_chirho,
        Some("control-plane-chirho"),
        std::slice::from_ref(&journal_chirho)
    )
    .is_ok());
    assert_eq!(
        error_text_chirho(refuse_control_plane_role_collisions_chirho(
            &pin_chirho,
            Some("ledger-journal-chirho"),
            std::slice::from_ref(&journal_chirho)
        )),
        "ControlPlaneRoleSecretNameCollisionChirho: journal"
    );
    let node_chirho = ControlPlaneSeparationPeerChirho {
        label_chirho: "node".to_string(),
        secret_name_chirho: None,
        key_chirho: Some(pin_chirho.key_bytes_chirho()),
    };
    assert_eq!(
        error_text_chirho(refuse_control_plane_role_collisions_chirho(
            &pin_chirho,
            None,
            &[journal_chirho, node_chirho]
        )),
        "ControlPlaneRoleKeyCollisionChirho: node"
    );
}

// --- the law's selection (section 3's table, every row) ---

fn marker_for_seed_chirho(seed_chirho: [u8; 32]) -> ControlPlaneLawMarkerChirho {
    ControlPlaneLawMarkerChirho::for_verifier_chirho(&verifier_for_seed_chirho(seed_chirho))
}

#[test]
fn row_1_config_without_a_marker_selects_lineage_and_owes_the_marker_chirho() {
    match select_control_plane_law_chirho(Some(config_chirho(true)), &no_evidence_chirho()) {
        Ok(ControlPlaneLawChirho::LineageRoleChirho(lineage_law_chirho)) => {
            assert!(!lineage_law_chirho.law_marker_present_chirho);
            assert!(lineage_law_chirho.signer_chirho.is_some());
        }
        other_chirho => panic!("expected lineage, got {other_chirho:?}"),
    }
    // Other geo evidence does not change a config-bearing root's law.
    let geo_chirho = ControlPlaneEvidenceChirho {
        era_elected_chirho: true,
        genesis_marker_present_chirho: true,
        law_marker_chirho: None,
    };
    assert!(matches!(
        select_control_plane_law_chirho(Some(config_chirho(true)), &geo_chirho),
        Ok(ControlPlaneLawChirho::LineageRoleChirho(lineage_law_chirho))
            if !lineage_law_chirho.law_marker_present_chirho
    ));
}

#[test]
fn row_2_config_with_its_own_marker_selects_lineage_chirho() {
    let evidence_chirho = ControlPlaneEvidenceChirho {
        law_marker_chirho: Some(marker_for_seed_chirho(SEED_A_CHIRHO)),
        ..no_evidence_chirho()
    };
    assert!(matches!(
        select_control_plane_law_chirho(Some(config_chirho(true)), &evidence_chirho),
        Ok(ControlPlaneLawChirho::LineageRoleChirho(lineage_law_chirho))
            if lineage_law_chirho.law_marker_present_chirho
    ));
}

#[test]
fn row_3_a_marker_for_another_pin_or_lineage_refuses_chirho() {
    let other_pin_chirho = ControlPlaneEvidenceChirho {
        law_marker_chirho: Some(marker_for_seed_chirho(SEED_B_CHIRHO)),
        ..no_evidence_chirho()
    };
    assert_eq!(
        select_control_plane_law_chirho(Some(config_chirho(true)), &other_pin_chirho).unwrap_err(),
        ControlPlaneLawRefusalChirho::MarkerMismatchChirho
    );
    let other_lineage_chirho = ControlPlaneEvidenceChirho {
        law_marker_chirho: Some(ControlPlaneLawMarkerChirho {
            key_id_hex_chirho: pin_for_seed_chirho(SEED_A_CHIRHO).key_id_hex_chirho(),
            lineage_chirho: ControlPlaneLineageChirho::new_chirho(
                "tenant-alpha-chirho",
                "genesis-0002-chirho",
            )
            .unwrap(),
        }),
        ..no_evidence_chirho()
    };
    assert_eq!(
        select_control_plane_law_chirho(Some(config_chirho(true)), &other_lineage_chirho)
            .unwrap_err(),
        ControlPlaneLawRefusalChirho::MarkerMismatchChirho
    );
}

#[test]
fn rows_4_and_5_any_geo_evidence_without_a_pin_refuses_chirho() {
    let marker_only_chirho = ControlPlaneEvidenceChirho {
        law_marker_chirho: Some(marker_for_seed_chirho(SEED_A_CHIRHO)),
        ..no_evidence_chirho()
    };
    let era_only_chirho = ControlPlaneEvidenceChirho {
        era_elected_chirho: true,
        ..no_evidence_chirho()
    };
    let genesis_only_chirho = ControlPlaneEvidenceChirho {
        genesis_marker_present_chirho: true,
        ..no_evidence_chirho()
    };
    for evidence_chirho in [marker_only_chirho, era_only_chirho, genesis_only_chirho] {
        assert_eq!(
            select_control_plane_law_chirho(None, &evidence_chirho).unwrap_err(),
            ControlPlaneLawRefusalChirho::PinMissingOnGeoRootChirho,
            "{evidence_chirho:?}"
        );
    }
}

#[test]
fn row_6_no_config_and_no_evidence_keeps_the_node_key_chirho() {
    assert!(matches!(
        select_control_plane_law_chirho(None, &no_evidence_chirho()),
        Ok(ControlPlaneLawChirho::NodeKeyChirho)
    ));
}

#[test]
fn a_config_whose_signer_is_for_another_pin_or_lineage_refuses_chirho() {
    let other_pin_signer_chirho = signer_for_seed_chirho(SEED_B_CHIRHO);
    assert_eq!(
        ControlPlaneConfigChirho::new_chirho(
            verifier_for_seed_chirho(SEED_A_CHIRHO),
            Some(other_pin_signer_chirho)
        )
        .unwrap_err(),
        ControlPlaneLawRefusalChirho::SignerNotForConfigChirho
    );
    let other_lineage_signer_chirho = ControlPlaneSignerChirho::from_seed_chirho(
        Zeroizing::new(SEED_A_CHIRHO),
        ControlPlaneVerifierChirho::new_chirho(
            pin_for_seed_chirho(SEED_A_CHIRHO),
            ControlPlaneLineageChirho::new_chirho("tenant-beta-chirho", "genesis-0001-chirho")
                .unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(
        ControlPlaneConfigChirho::new_chirho(
            verifier_for_seed_chirho(SEED_A_CHIRHO),
            Some(other_lineage_signer_chirho)
        )
        .unwrap_err(),
        ControlPlaneLawRefusalChirho::SignerNotForConfigChirho
    );
}

#[test]
fn a_verifier_only_law_refuses_to_sign_but_verifies_a_voter_signature_chirho() {
    let law_chirho =
        select_control_plane_law_chirho(Some(config_chirho(false)), &no_evidence_chirho()).unwrap();
    assert_eq!(
        error_text_chirho(
            law_chirho.sign_lineage_chirho(ControlPlaneFamilyChirho::PriceBookChirho, b"book")
        ),
        "ControlPlaneSignerUnavailableChirho"
    );
    let voter_sig_chirho = signer_for_seed_chirho(SEED_A_CHIRHO)
        .sign_chirho(ControlPlaneFamilyChirho::PriceBookChirho, b"book");
    let ControlPlaneLawChirho::LineageRoleChirho(lineage_law_chirho) = &law_chirho else {
        panic!("expected lineage");
    };
    assert!(lineage_law_chirho
        .verifier_chirho
        .verify_chirho(
            ControlPlaneFamilyChirho::PriceBookChirho,
            b"book",
            &voter_sig_chirho
        )
        .unwrap());
}

#[test]
fn a_node_key_law_refuses_a_lineage_signature_request_chirho() {
    let law_chirho = select_control_plane_law_chirho(None, &no_evidence_chirho()).unwrap();
    assert_eq!(
        error_text_chirho(
            law_chirho.sign_lineage_chirho(ControlPlaneFamilyChirho::AppRecordsChirho, b"x")
        ),
        "ControlPlaneLawIsNodeKeyChirho"
    );
}

#[test]
fn a_lineage_law_signs_what_its_verifier_accepts_chirho() {
    let law_chirho =
        select_control_plane_law_chirho(Some(config_chirho(true)), &no_evidence_chirho()).unwrap();
    let sig_chirho = law_chirho
        .sign_lineage_chirho(ControlPlaneFamilyChirho::HeadRemovalsChirho, b"removal")
        .unwrap();
    assert!(verifier_for_seed_chirho(SEED_A_CHIRHO)
        .verify_chirho(
            ControlPlaneFamilyChirho::HeadRemovalsChirho,
            b"removal",
            &sig_chirho
        )
        .unwrap());
    // The decoded signature is 64 bytes, as the node signer's are.
    assert_eq!(hex_decode_chirho(&sig_chirho).unwrap().len(), 64);
}

// --- a held law, checked again against later evidence (C2.1 brick 1b-1a) ---

/// Every combination of the three evidence slots, with the marker absent, ours, or another pin's.
fn every_evidence_chirho() -> Vec<ControlPlaneEvidenceChirho> {
    let mut all_chirho = Vec::new();
    for era_elected_chirho in [false, true] {
        for genesis_marker_present_chirho in [false, true] {
            for law_marker_chirho in [
                None,
                Some(marker_for_seed_chirho(SEED_A_CHIRHO)),
                Some(marker_for_seed_chirho(SEED_B_CHIRHO)),
            ] {
                all_chirho.push(ControlPlaneEvidenceChirho {
                    era_elected_chirho,
                    genesis_marker_present_chirho,
                    law_marker_chirho,
                });
            }
        }
    }
    all_chirho
}

#[test]
fn a_freshly_selected_law_always_stands_on_its_own_evidence_chirho() {
    // The check is the selector's table: whatever selection admits, the check admits on the same evidence.
    for evidence_chirho in every_evidence_chirho() {
        for config_chirho in [None, Some(config_chirho(true))] {
            if let Ok(law_chirho) = select_control_plane_law_chirho(config_chirho, &evidence_chirho)
            {
                assert_eq!(
                    law_chirho.check_evidence_chirho(&evidence_chirho),
                    Ok(()),
                    "{evidence_chirho:?}"
                );
            }
        }
    }
}

#[test]
fn a_held_node_key_law_falls_to_any_later_geo_evidence_chirho() {
    let law_chirho = select_control_plane_law_chirho(None, &no_evidence_chirho()).unwrap();
    for evidence_chirho in every_evidence_chirho() {
        let geo_chirho = evidence_chirho.era_elected_chirho
            || evidence_chirho.genesis_marker_present_chirho
            || evidence_chirho.law_marker_chirho.is_some();
        assert_eq!(
            law_chirho.check_evidence_chirho(&evidence_chirho),
            if geo_chirho {
                Err(ControlPlaneLawRefusalChirho::PinMissingOnGeoRootChirho)
            } else {
                Ok(())
            },
            "{evidence_chirho:?}"
        );
    }
}

#[test]
fn a_held_lineage_law_stands_on_an_absent_or_equal_marker_and_falls_to_another_chirho() {
    let law_chirho =
        select_control_plane_law_chirho(Some(config_chirho(true)), &no_evidence_chirho()).unwrap();
    for evidence_chirho in every_evidence_chirho() {
        let expected_chirho = match &evidence_chirho.law_marker_chirho {
            Some(marker_chirho) if *marker_chirho != marker_for_seed_chirho(SEED_A_CHIRHO) => {
                Err(ControlPlaneLawRefusalChirho::MarkerMismatchChirho)
            }
            _ => Ok(()),
        };
        assert_eq!(
            law_chirho.check_evidence_chirho(&evidence_chirho),
            expected_chirho,
            "{evidence_chirho:?}"
        );
    }
}
