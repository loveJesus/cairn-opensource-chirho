// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The leader's propagation requirement and binding: signed and digest-bound, verified against one context, carried only as a verified superset, and bound to exactly one requirement.

use super::world_chirho::{
    key_id_chirho, node_chirho, NodeChirho, OTHER_SUBJECT_CHIRHO, SUBJECT_CHIRHO,
};
use crate::custody_chirho::binding_chirho::subject_digest_hex_chirho;
use crate::erasure_chirho::propagation_chirho::{
    ErasurePropagationBindingV1Chirho, ErasurePropagationContextChirho,
    ErasurePropagationRefChirho, ErasurePropagationRequirementInputChirho,
    ErasurePropagationRequirementV1Chirho, PreparedErasurePropagationBindingChirho,
    PreparedErasurePropagationRequirementChirho, VerifiedErasurePropagationRequirementChirho,
    ERASURE_PROPAGATION_LINEAGE_FIELD_MAX_BYTES_CHIRHO, ERASURE_PROPAGATION_MAX_HOLDERS_CHIRHO,
    ERASURE_PROPAGATION_MAX_SUCCEEDS_CHIRHO,
};
use crate::refusal_chirho::KeyCustodyRefusalIdentityChirho;
use std::collections::BTreeSet;

const TENANT_CHIRHO: &str = "item6-drill-chirho";
const INSTANCE_CHIRHO: &str = "genesis-instance-one-chirho";
const RECORD_DIGEST_CHIRHO: &str =
    "abababababababababababababababababababababababababababababababab";

fn group_chirho() -> String {
    "11".repeat(32)
}

fn context_chirho(issuer_chirho: &NodeChirho) -> ErasurePropagationContextChirho {
    ErasurePropagationContextChirho::new_chirho(
        &group_chirho(),
        TENANT_CHIRHO,
        INSTANCE_CHIRHO,
        &issuer_chirho.id_chirho,
    )
    .expect("context in form")
}

/// An input for SUBJECT at `seq_chirho`, with key ids numbered `keys_chirho` and holder seeds `holders_chirho`.
fn input_chirho(
    seq_chirho: u64,
    keys_chirho: &[u8],
    holders_chirho: &[u8],
    bound_chirho: u64,
    succeeds_chirho: &[&VerifiedErasurePropagationRequirementChirho],
) -> ErasurePropagationRequirementInputChirho {
    ErasurePropagationRequirementInputChirho {
        subject_digest_chirho: subject_digest_hex_chirho(SUBJECT_CHIRHO),
        erasure_seq_chirho: seq_chirho,
        erased_below_blob_seq_chirho: bound_chirho,
        key_ids_chirho: keys_chirho
            .iter()
            .map(|number_chirho| key_id_chirho(*number_chirho))
            .collect(),
        holders_chirho: holders_chirho
            .iter()
            .map(|seed_chirho| node_chirho(*seed_chirho).id_chirho)
            .collect(),
        succeeds_chirho: succeeds_chirho
            .iter()
            .map(|carried_chirho| carried_chirho.reference_chirho())
            .collect(),
    }
}

fn signed_chirho(
    signer_chirho: &NodeChirho,
    context_chirho: &ErasurePropagationContextChirho,
    input_chirho: ErasurePropagationRequirementInputChirho,
) -> ErasurePropagationRequirementV1Chirho {
    let prepared_chirho =
        PreparedErasurePropagationRequirementChirho::new_chirho(context_chirho, input_chirho)
            .expect("requirement prepares");
    let signature_chirho = signer_chirho.sign_chirho(&prepared_chirho.signing_digest_chirho());
    prepared_chirho
        .into_signed_chirho(signature_chirho)
        .expect("requirement signs")
}

fn verified_chirho(
    input_chirho: ErasurePropagationRequirementInputChirho,
) -> VerifiedErasurePropagationRequirementChirho {
    let leader_chirho = node_chirho(1);
    let context_chirho = context_chirho(&leader_chirho);
    signed_chirho(&leader_chirho, &context_chirho, input_chirho)
        .verify_chirho(&context_chirho)
        .expect("requirement verifies")
}

fn identity_chirho<TChirho>(
    result_chirho: Result<TChirho, crate::refusal_chirho::KeyCustodyErrorChirho>,
) -> KeyCustodyRefusalIdentityChirho {
    match result_chirho {
        Ok(_) => panic!("expected a refusal"),
        Err(error_chirho) => error_chirho.identity_chirho(),
    }
}

/// Re-read a signed requirement with one JSON field replaced, as a tampered stored file would be.
fn tampered_chirho(
    requirement_chirho: &ErasurePropagationRequirementV1Chirho,
    field_chirho: &str,
    value_chirho: serde_json::Value,
) -> ErasurePropagationRequirementV1Chirho {
    let mut json_chirho = serde_json::to_value(requirement_chirho).expect("serializes");
    json_chirho[field_chirho] = value_chirho;
    serde_json::from_value(json_chirho).expect("still parses")
}

#[test]
fn a_signed_requirement_verifies_and_hands_status_its_cut_chirho() {
    let verified_chirho = verified_chirho(input_chirho(4, &[1, 2], &[2, 3, 4], 9, &[]));
    assert_eq!(verified_chirho.erasure_seq_chirho(), 4);
    assert_eq!(verified_chirho.key_ids_chirho().len(), 2);
    assert_eq!(verified_chirho.holders_chirho().len(), 3);
    verified_chirho
        .status_requirement_chirho()
        .expect("the verified cut is a status requirement");
}

#[test]
fn every_requirement_field_is_bound_by_its_digest_chirho() {
    let leader_chirho = node_chirho(1);
    let context_chirho = context_chirho(&leader_chirho);
    let signed_chirho = signed_chirho(
        &leader_chirho,
        &context_chirho,
        input_chirho(4, &[1, 2], &[2, 3], 9, &[]),
    );
    let other_subject_chirho = subject_digest_hex_chirho(OTHER_SUBJECT_CHIRHO);
    for (field_chirho, value_chirho) in [
        (
            "subject_digest_chirho",
            serde_json::json!(other_subject_chirho),
        ),
        ("erasure_seq_chirho", serde_json::json!(5)),
        ("erased_below_blob_seq_chirho", serde_json::json!(8)),
        ("key_ids_chirho", serde_json::json!([key_id_chirho(1)])),
        (
            "holders_chirho",
            serde_json::json!([node_chirho(2).id_chirho]),
        ),
        (
            "succeeds_chirho",
            serde_json::json!([{"erasure_seq_chirho": 1, "requirement_digest_chirho": "cd".repeat(32)}]),
        ),
    ] {
        let tampered_chirho = tampered_chirho(&signed_chirho, field_chirho, value_chirho);
        assert_eq!(
            identity_chirho(tampered_chirho.verify_chirho(&context_chirho)),
            KeyCustodyRefusalIdentityChirho::ErasurePropagationRequirementInvalidChirho,
            "{field_chirho}"
        );
    }
}

#[test]
fn a_requirement_from_another_context_refuses_as_a_mismatch_chirho() {
    let leader_chirho = node_chirho(1);
    let context_chirho = context_chirho(&leader_chirho);
    let signed_chirho = signed_chirho(
        &leader_chirho,
        &context_chirho,
        input_chirho(4, &[1], &[2], 9, &[]),
    );
    let other_contexts_chirho = [
        ErasurePropagationContextChirho::new_chirho(
            &"22".repeat(32),
            TENANT_CHIRHO,
            INSTANCE_CHIRHO,
            &leader_chirho.id_chirho,
        ),
        ErasurePropagationContextChirho::new_chirho(
            &group_chirho(),
            "other-tenant-chirho",
            INSTANCE_CHIRHO,
            &leader_chirho.id_chirho,
        ),
        ErasurePropagationContextChirho::new_chirho(
            &group_chirho(),
            TENANT_CHIRHO,
            "other-instance-chirho",
            &leader_chirho.id_chirho,
        ),
        ErasurePropagationContextChirho::new_chirho(
            &group_chirho(),
            TENANT_CHIRHO,
            INSTANCE_CHIRHO,
            &node_chirho(9).id_chirho,
        ),
    ];
    for other_chirho in other_contexts_chirho {
        let other_chirho = other_chirho.expect("context in form");
        assert_eq!(
            identity_chirho(signed_chirho.verify_chirho(&other_chirho)),
            KeyCustodyRefusalIdentityChirho::ErasurePropagationContextMismatchChirho
        );
    }
    // The lineage fields are part of what is signed, not only compared.
    let tampered_chirho = tampered_chirho(
        &signed_chirho,
        "tenant_id_chirho",
        serde_json::json!("other-tenant-chirho"),
    );
    assert_eq!(
        identity_chirho(tampered_chirho.verify_chirho(&context_chirho)),
        KeyCustodyRefusalIdentityChirho::ErasurePropagationContextMismatchChirho
    );
}

#[test]
fn a_requirement_signed_by_another_key_refuses_chirho() {
    let leader_chirho = node_chirho(1);
    let context_chirho = context_chirho(&leader_chirho);
    let forged_chirho = signed_chirho(
        &node_chirho(9),
        &context_chirho,
        input_chirho(4, &[1], &[2], 9, &[]),
    );
    assert_eq!(
        identity_chirho(forged_chirho.verify_chirho(&context_chirho)),
        KeyCustodyRefusalIdentityChirho::ErasurePropagationRequirementInvalidChirho
    );
}

#[test]
fn requirement_form_and_bounds_refuse_at_their_edges_chirho() {
    let context_chirho = context_chirho(&node_chirho(1));
    let prepare_chirho = |input_chirho| {
        PreparedErasurePropagationRequirementChirho::new_chirho(&context_chirho, input_chirho)
    };
    let invalid_chirho =
        KeyCustodyRefusalIdentityChirho::ErasurePropagationRequirementInvalidChirho;
    assert_eq!(
        identity_chirho(prepare_chirho(input_chirho(4, &[1], &[], 9, &[]))),
        invalid_chirho
    );

    let holders_chirho = |count_chirho: usize| -> BTreeSet<String> {
        (0..count_chirho)
            .map(|number_chirho| format!("{number_chirho:064x}"))
            .collect()
    };
    let mut at_cap_chirho = input_chirho(4, &[1], &[2], 9, &[]);
    at_cap_chirho.holders_chirho = holders_chirho(ERASURE_PROPAGATION_MAX_HOLDERS_CHIRHO);
    assert!(prepare_chirho(at_cap_chirho.clone()).is_ok());
    at_cap_chirho.holders_chirho = holders_chirho(ERASURE_PROPAGATION_MAX_HOLDERS_CHIRHO + 1);
    assert_eq!(
        identity_chirho(prepare_chirho(at_cap_chirho)),
        invalid_chirho
    );

    let carried_chirho = |count_chirho: u64| -> BTreeSet<ErasurePropagationRefChirho> {
        (0..count_chirho)
            .map(|seq_chirho| ErasurePropagationRefChirho {
                erasure_seq_chirho: seq_chirho,
                requirement_digest_chirho: "cd".repeat(32),
            })
            .collect()
    };
    let mut succeeds_chirho = input_chirho(100, &[1], &[2], 9, &[]);
    succeeds_chirho.succeeds_chirho =
        carried_chirho(ERASURE_PROPAGATION_MAX_SUCCEEDS_CHIRHO as u64);
    assert!(prepare_chirho(succeeds_chirho.clone()).is_ok());
    succeeds_chirho.succeeds_chirho =
        carried_chirho(ERASURE_PROPAGATION_MAX_SUCCEEDS_CHIRHO as u64 + 1);
    assert_eq!(
        identity_chirho(prepare_chirho(succeeds_chirho)),
        invalid_chirho
    );

    // A carried requirement must be older, and one seq may be carried once.
    let mut not_older_chirho = input_chirho(4, &[1], &[2], 9, &[]);
    not_older_chirho.succeeds_chirho = carried_chirho(5);
    assert_eq!(
        identity_chirho(prepare_chirho(not_older_chirho)),
        invalid_chirho
    );
    let mut same_seq_chirho = input_chirho(4, &[1], &[2], 9, &[]);
    same_seq_chirho.succeeds_chirho = [
        ErasurePropagationRefChirho {
            erasure_seq_chirho: 1,
            requirement_digest_chirho: "cd".repeat(32),
        },
        ErasurePropagationRefChirho {
            erasure_seq_chirho: 1,
            requirement_digest_chirho: "ef".repeat(32),
        },
    ]
    .into_iter()
    .collect();
    assert_eq!(
        identity_chirho(prepare_chirho(same_seq_chirho)),
        invalid_chirho
    );

    let mut too_many_keys_chirho = input_chirho(4, &[], &[2], 9, &[]);
    too_many_keys_chirho.key_ids_chirho = (0..=crate::ERASURE_MAX_KEY_IDS_CHIRHO)
        .map(|number_chirho| format!("{number_chirho:032x}"))
        .collect();
    assert_eq!(
        identity_chirho(prepare_chirho(too_many_keys_chirho)),
        invalid_chirho
    );

    // A stored file whose lists are out of order refuses, even with every other field intact.
    let leader_chirho = node_chirho(1);
    let signed_chirho = signed_chirho(
        &leader_chirho,
        &context_chirho,
        input_chirho(4, &[1, 2], &[2], 9, &[]),
    );
    let unsorted_chirho = tampered_chirho(
        &signed_chirho,
        "key_ids_chirho",
        serde_json::json!([key_id_chirho(2), key_id_chirho(1)]),
    );
    assert_eq!(
        identity_chirho(unsorted_chirho.verify_chirho(&context_chirho)),
        invalid_chirho
    );

    let context_invalid_chirho =
        KeyCustodyRefusalIdentityChirho::ErasurePropagationContextInvalidChirho;
    for (tenant_chirho, instance_chirho) in [
        (String::new(), INSTANCE_CHIRHO.to_string()),
        (TENANT_CHIRHO.to_string(), "with\0nul".to_string()),
        (
            "t".repeat(ERASURE_PROPAGATION_LINEAGE_FIELD_MAX_BYTES_CHIRHO + 1),
            INSTANCE_CHIRHO.to_string(),
        ),
    ] {
        assert_eq!(
            identity_chirho(ErasurePropagationContextChirho::new_chirho(
                &group_chirho(),
                &tenant_chirho,
                &instance_chirho,
                &leader_chirho.id_chirho,
            )),
            context_invalid_chirho
        );
    }
    assert!(ErasurePropagationContextChirho::new_chirho(
        &group_chirho(),
        &"t".repeat(ERASURE_PROPAGATION_LINEAGE_FIELD_MAX_BYTES_CHIRHO),
        INSTANCE_CHIRHO,
        &leader_chirho.id_chirho,
    )
    .is_ok());
}

#[test]
fn a_successor_carries_its_predecessor_only_as_a_verified_superset_chirho() {
    let predecessor_chirho = verified_chirho(input_chirho(1, &[1, 2], &[2, 3], 5, &[]));
    let carries_chirho = verified_chirho(input_chirho(
        3,
        &[1, 2, 3],
        &[2, 3, 4],
        7,
        &[&predecessor_chirho],
    ));
    carries_chirho
        .verify_carries_chirho(&predecessor_chirho)
        .expect("an exact superset carries its predecessor");

    let succession_chirho =
        KeyCustodyRefusalIdentityChirho::ErasurePropagationSuccessionInvalidChirho;
    for (case_chirho, successor_chirho) in [
        (
            "drops a key id",
            input_chirho(3, &[1, 3], &[2, 3], 7, &[&predecessor_chirho]),
        ),
        (
            "drops a holder",
            input_chirho(3, &[1, 2], &[2], 7, &[&predecessor_chirho]),
        ),
        (
            "a smaller bound",
            input_chirho(3, &[1, 2], &[2, 3], 4, &[&predecessor_chirho]),
        ),
        (
            "does not name it",
            input_chirho(3, &[1, 2], &[2, 3], 7, &[]),
        ),
    ] {
        assert_eq!(
            identity_chirho(
                verified_chirho(successor_chirho).verify_carries_chirho(&predecessor_chirho)
            ),
            succession_chirho,
            "{case_chirho}"
        );
    }

    // Naming the right seq with another digest is not naming this predecessor.
    let mut wrong_digest_chirho = input_chirho(3, &[1, 2], &[2, 3], 7, &[]);
    wrong_digest_chirho.succeeds_chirho = [ErasurePropagationRefChirho {
        erasure_seq_chirho: 1,
        requirement_digest_chirho: "cd".repeat(32),
    }]
    .into_iter()
    .collect();
    assert_eq!(
        identity_chirho(
            verified_chirho(wrong_digest_chirho).verify_carries_chirho(&predecessor_chirho)
        ),
        succession_chirho
    );

    // A predecessor of another subject is never carried, even when the successor names it.
    let mut other_subject_chirho = input_chirho(1, &[1, 2], &[2, 3], 5, &[]);
    other_subject_chirho.subject_digest_chirho = subject_digest_hex_chirho(OTHER_SUBJECT_CHIRHO);
    let other_predecessor_chirho = verified_chirho(other_subject_chirho);
    let names_other_chirho = verified_chirho(input_chirho(
        3,
        &[1, 2],
        &[2, 3],
        7,
        &[&other_predecessor_chirho],
    ));
    assert_eq!(
        identity_chirho(names_other_chirho.verify_carries_chirho(&other_predecessor_chirho)),
        succession_chirho
    );
}

#[test]
fn a_binding_names_exactly_its_requirement_chirho() {
    let leader_chirho = node_chirho(1);
    let context_chirho = context_chirho(&leader_chirho);
    let requirement_chirho = verified_chirho(input_chirho(4, &[1, 2], &[2, 3], 9, &[]));
    let sign_binding_chirho = |signer_chirho: &NodeChirho, record_digest_chirho: &str| {
        let prepared_chirho = PreparedErasurePropagationBindingChirho::new_chirho(
            &context_chirho,
            &requirement_chirho,
            record_digest_chirho,
        )
        .expect("binding prepares");
        let signature_chirho = signer_chirho.sign_chirho(&prepared_chirho.signing_digest_chirho());
        prepared_chirho
            .into_signed_chirho(signature_chirho)
            .expect("binding signs")
    };
    let binding_chirho = sign_binding_chirho(&leader_chirho, RECORD_DIGEST_CHIRHO);
    let verified_binding_chirho = binding_chirho
        .verify_chirho(&context_chirho, &requirement_chirho)
        .expect("binding verifies");
    assert_eq!(
        verified_binding_chirho.erasure_record_digest_chirho(),
        RECORD_DIGEST_CHIRHO
    );
    assert_eq!(
        verified_binding_chirho.requirement_digest_chirho(),
        requirement_chirho.requirement_digest_chirho()
    );

    let invalid_chirho = KeyCustodyRefusalIdentityChirho::ErasurePropagationBindingInvalidChirho;
    let other_requirement_chirho = verified_chirho(input_chirho(5, &[1, 2], &[2, 3], 9, &[]));
    assert_eq!(
        identity_chirho(binding_chirho.verify_chirho(&context_chirho, &other_requirement_chirho)),
        invalid_chirho,
        "a binding never vouches for another requirement"
    );
    let mut json_chirho = serde_json::to_value(&binding_chirho).expect("serializes");
    json_chirho["erasure_record_digest_chirho"] = serde_json::json!("cd".repeat(32));
    let tampered_chirho: ErasurePropagationBindingV1Chirho =
        serde_json::from_value(json_chirho).expect("parses");
    assert_eq!(
        identity_chirho(tampered_chirho.verify_chirho(&context_chirho, &requirement_chirho)),
        invalid_chirho
    );
    assert_eq!(
        identity_chirho(
            sign_binding_chirho(&node_chirho(9), RECORD_DIGEST_CHIRHO)
                .verify_chirho(&context_chirho, &requirement_chirho)
        ),
        invalid_chirho
    );
    let other_issuer_chirho = ErasurePropagationContextChirho::new_chirho(
        &group_chirho(),
        TENANT_CHIRHO,
        INSTANCE_CHIRHO,
        &node_chirho(9).id_chirho,
    )
    .expect("context in form");
    assert_eq!(
        identity_chirho(binding_chirho.verify_chirho(&other_issuer_chirho, &requirement_chirho)),
        KeyCustodyRefusalIdentityChirho::ErasurePropagationContextMismatchChirho
    );
}
