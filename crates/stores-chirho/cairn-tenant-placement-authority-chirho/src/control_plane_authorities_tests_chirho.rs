// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Arms for the control-plane verifiers and their key separation.
//!
//! [`a_real_signature_verifies_through_every_port_chirho`] is the POSITIVE CONTROL and it is load
//! bearing: every other arm here asserts a refusal, and a verifier that returned `false`
//! unconditionally would satisfy all of them. It signs with a real ed25519 key and checks each of the
//! four ports accepts, so the negatives are known to be discriminating rather than merely negative.

use super::*;
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};

/// A real ed25519 keypair on disk, so signatures in these arms are genuine.
fn real_key_chirho() -> (tempfile::TempDir, String) {
    let root_chirho = tempfile::tempdir().expect("tempdir");
    let pubkey_chirho = pubkey_hex_chirho(root_chirho.path()).expect("pubkey");
    (root_chirho, pubkey_chirho)
}

/// A shape-valid key for arms about SEPARATION, which never reach the crypto.
fn shaped_key_chirho(seed_chirho: char) -> String {
    std::iter::repeat_n(seed_chirho, 64).collect()
}

fn authorities_chirho(
    capacity_chirho: &str,
    lifecycle_chirho: &str,
    topology_chirho: &str,
    nodes_chirho: &[(&str, &str)],
) -> Result<ControlPlaneAuthoritiesChirho, ControlPlaneAuthorityRefusalChirho> {
    authorities_with_budget_chirho(
        capacity_chirho,
        lifecycle_chirho,
        topology_chirho,
        // 'e' rather than 'z': keys are LOWER HEX, and a shaped key of non-hex characters is
        // correctly refused as malformed -- which this fixture discovered the hard way.
        &shaped_key_chirho('e'),
        nodes_chirho,
    )
}

fn authorities_with_budget_chirho(
    capacity_chirho: &str,
    lifecycle_chirho: &str,
    topology_chirho: &str,
    budget_chirho: &str,
    nodes_chirho: &[(&str, &str)],
) -> Result<ControlPlaneAuthoritiesChirho, ControlPlaneAuthorityRefusalChirho> {
    let map_chirho = nodes_chirho
        .iter()
        .map(|(node_chirho, key_chirho)| (node_chirho.to_string(), key_chirho.to_string()))
        .collect::<BTreeMap<_, _>>();
    resolve_control_plane_authorities_chirho(
        capacity_chirho,
        lifecycle_chirho,
        topology_chirho,
        budget_chirho,
        &map_chirho,
    )
}

#[test]
fn a_real_signature_verifies_through_every_port_chirho() {
    // POSITIVE CONTROL. Without it, every refusal arm below would pass against a verifier that always
    // said false, and the whole file would be green while proving nothing.
    let (root_chirho, pubkey_chirho) = real_key_chirho();
    let message_chirho = "canonical-unsigned-message-chirho";
    let signature_chirho =
        sign_message_chirho(root_chirho.path(), message_chirho.as_bytes()).expect("sign");
    let authority_chirho = PubkeyAuthorityChirho::new_unchecked_chirho(&pubkey_chirho);

    assert!(NodeRegistrationAuthorityPortChirho::verify_chirho(
        &authority_chirho,
        message_chirho,
        &signature_chirho
    ));
    assert!(LifecycleAuthorityPortChirho::verify_chirho(
        &authority_chirho,
        message_chirho,
        &signature_chirho
    ));
    assert!(TopologyGrantAuthorityPortChirho::verify_chirho(
        &authority_chirho,
        message_chirho,
        &signature_chirho
    ));
    assert!(NodeMeasurementAuthorityPortChirho::verify_chirho(
        &authority_chirho,
        message_chirho,
        &signature_chirho
    ));
}

#[test]
fn a_signature_over_a_different_message_does_not_verify_chirho() {
    let (root_chirho, pubkey_chirho) = real_key_chirho();
    let signature_chirho =
        sign_message_chirho(root_chirho.path(), b"the-message-that-was-signed-chirho")
            .expect("sign");
    let authority_chirho = PubkeyAuthorityChirho::new_unchecked_chirho(&pubkey_chirho);
    assert!(!NodeRegistrationAuthorityPortChirho::verify_chirho(
        &authority_chirho,
        "a-different-message-chirho",
        &signature_chirho
    ));
}

#[test]
fn a_malformed_key_or_signature_fails_closed_rather_than_erroring_chirho() {
    // `verify_with_pubkey_chirho` returns Result<bool>, so there are two failure channels. Both must
    // land on false: an Err that a caller could read as "not applicable" is the dangerous direction.
    let (root_chirho, _pubkey_chirho) = real_key_chirho();
    let signature_chirho = sign_message_chirho(root_chirho.path(), b"m-chirho").expect("sign");

    let bad_key_chirho = PubkeyAuthorityChirho::new_unchecked_chirho("not-a-key-chirho");
    assert!(!NodeRegistrationAuthorityPortChirho::verify_chirho(
        &bad_key_chirho,
        "m-chirho",
        &signature_chirho
    ));

    let (_root2_chirho, good_key_chirho) = real_key_chirho();
    let good_chirho = PubkeyAuthorityChirho::new_unchecked_chirho(&good_key_chirho);
    assert!(!NodeMeasurementAuthorityPortChirho::verify_chirho(
        &good_chirho,
        "m-chirho",
        "not-a-signature-chirho"
    ));
}

#[test]
fn a_well_formed_distinct_set_resolves_chirho() {
    let resolved_chirho = authorities_chirho(
        &shaped_key_chirho('a'),
        &shaped_key_chirho('b'),
        &shaped_key_chirho('c'),
        &[("node-a-chirho", &shaped_key_chirho('d'))],
    )
    .expect("a distinct, well-formed set must resolve");
    assert!(resolved_chirho
        .node_measurement_chirho("node-a-chirho")
        .is_some());
}

#[test]
fn two_fleet_authorities_sharing_a_key_are_refused_chirho() {
    // One holder speaking for two authorities is not two authorities.
    assert_eq!(
        authorities_chirho(
            &shaped_key_chirho('a'),
            &shaped_key_chirho('a'),
            &shaped_key_chirho('c'),
            &[]
        )
        .expect_err("shared fleet keys must refuse"),
        ControlPlaneAuthorityRefusalChirho::FleetAuthorityKeysNotDistinctChirho
    );
}

#[test]
fn a_node_holding_the_registrar_key_would_sign_its_own_allocatable_chirho() {
    // THE arm. Cairn ruled capacity grants registrar-signed with verify-only at the node, because an
    // inflated allocatable is what lets a placement land where it cannot fit. That ruling otherwise
    // lives only in the type system, and the two ports are structurally identical — so one shared key
    // defeats it while every type checks out.
    assert_eq!(
        authorities_chirho(
            &shaped_key_chirho('a'),
            &shaped_key_chirho('b'),
            &shaped_key_chirho('c'),
            &[("node-a-chirho", &shaped_key_chirho('a'))]
        )
        .expect_err("a node holding the registrar key must refuse"),
        ControlPlaneAuthorityRefusalChirho::NodeWouldSignItsOwnEvidenceChirho {
            node_id_chirho: "node-a-chirho".to_string(),
            role_chirho: AuthorityRoleChirho::CapacityRegistrarChirho,
        }
    );
}

#[test]
fn a_node_holding_the_lifecycle_key_could_declare_itself_joined_chirho() {
    // Distinct from the registrar case: JoinedChirho is the only state admitting new placements, so a
    // node that can sign its own transitions can admit its own work.
    assert_eq!(
        authorities_chirho(
            &shaped_key_chirho('a'),
            &shaped_key_chirho('b'),
            &shaped_key_chirho('c'),
            &[("node-b-chirho", &shaped_key_chirho('b'))]
        )
        .expect_err("a node holding the lifecycle key must refuse"),
        ControlPlaneAuthorityRefusalChirho::NodeWouldSignItsOwnEvidenceChirho {
            node_id_chirho: "node-b-chirho".to_string(),
            role_chirho: AuthorityRoleChirho::LifecycleChirho,
        }
    );
}

#[test]
fn a_node_holding_the_topology_grant_key_could_raise_its_own_ceiling_chirho() {
    assert_eq!(
        authorities_chirho(
            &shaped_key_chirho('a'),
            &shaped_key_chirho('b'),
            &shaped_key_chirho('c'),
            &[("node-c-chirho", &shaped_key_chirho('c'))]
        )
        .expect_err("a node holding the topology grant key must refuse"),
        ControlPlaneAuthorityRefusalChirho::NodeWouldSignItsOwnEvidenceChirho {
            node_id_chirho: "node-c-chirho".to_string(),
            role_chirho: AuthorityRoleChirho::TopologyGrantChirho,
        }
    );
}

#[test]
fn a_malformed_key_refuses_by_role_and_prints_no_key_material_chirho() {
    let refusal_chirho = authorities_chirho(
        "short-chirho",
        &shaped_key_chirho('b'),
        &shaped_key_chirho('c'),
        &[],
    )
    .expect_err("a malformed key must refuse");
    assert_eq!(
        refusal_chirho,
        ControlPlaneAuthorityRefusalChirho::MalformedKeyChirho {
            role_chirho: AuthorityRoleChirho::CapacityRegistrarChirho,
        }
    );
    // A refusal reaches operator surfaces, so it names the role and never the value it rejected.
    assert!(!format!("{refusal_chirho:?}").contains("short-chirho"));
}

#[test]
fn an_unknown_node_has_no_verifier_rather_than_a_permissive_one_chirho() {
    // `None` must be read by callers as "cannot verify this node's measurements". Returning some
    // default verifier here would be the permissive direction.
    let resolved_chirho = authorities_chirho(
        &shaped_key_chirho('a'),
        &shaped_key_chirho('b'),
        &shaped_key_chirho('c'),
        &[("node-a-chirho", &shaped_key_chirho('d'))],
    )
    .expect("resolves");
    assert!(resolved_chirho
        .node_measurement_chirho("node-never-registered-chirho")
        .is_none());
}

#[test]
fn a_node_holding_the_budget_key_could_authorize_its_own_spend_chirho() {
    // The fourth collision, and the one with money behind it: a node that can sign budget events can
    // reserve and settle its own credits, so the prepaid ceiling stops bounding the party it exists to
    // bound.
    assert_eq!(
        authorities_with_budget_chirho(
            &shaped_key_chirho('a'),
            &shaped_key_chirho('b'),
            &shaped_key_chirho('c'),
            &shaped_key_chirho('d'),
            &[("node-d-chirho", &shaped_key_chirho('d'))]
        )
        .expect_err("a node holding the budget key must refuse"),
        ControlPlaneAuthorityRefusalChirho::NodeWouldSignItsOwnEvidenceChirho {
            node_id_chirho: "node-d-chirho".to_string(),
            role_chirho: AuthorityRoleChirho::BudgetChirho,
        }
    );
}

#[test]
fn the_budget_key_must_differ_from_the_other_three_fleet_authorities_chirho() {
    assert_eq!(
        authorities_with_budget_chirho(
            &shaped_key_chirho('a'),
            &shaped_key_chirho('b'),
            &shaped_key_chirho('c'),
            &shaped_key_chirho('a'),
            &[]
        )
        .expect_err("a shared fleet key must refuse"),
        ControlPlaneAuthorityRefusalChirho::FleetAuthorityKeysNotDistinctChirho
    );
}

/// A malformed NODE measurement key refuses by an identity that names the node.
///
/// Its fleet-key sibling `MalformedKeyChirho` was already pinned; this one was not (measured
/// 2026-08-21 by a variant census over this enum — which is the right instrument here, because this
/// enum has no `label_chirho` indirection and arms assert variants directly).
///
/// The distinction being pinned is not "it refuses" but WHICH identity it refuses by. The node map is
/// operator-authored and can hold many nodes; a refusal that did not name the offending node would
/// send an operator through the whole map by hand. The generic `MalformedKeyChirho` would be exactly
/// that regression, and it is the neighbour this arm rules out.
#[test]
fn a_malformed_node_measurement_key_refuses_naming_that_node_chirho() {
    let good_node_key_chirho = shaped_key_chirho('a');
    let malformed_node_key_chirho = "not-a-valid-key-chirho";

    // POSITIVE CONTROL: the identical arrangement with a WELL-FORMED node key resolves, so the
    // refusal below is attributable to the key's shape and not to the fixture.
    authorities_chirho(
        &shaped_key_chirho('b'),
        &shaped_key_chirho('c'),
        &shaped_key_chirho('d'),
        &[("node-alpha-chirho", &good_node_key_chirho)],
    )
    .expect("a well-formed node measurement key resolves");

    let refusal_chirho = authorities_chirho(
        &shaped_key_chirho('b'),
        &shaped_key_chirho('c'),
        &shaped_key_chirho('d'),
        &[("node-alpha-chirho", malformed_node_key_chirho)],
    )
    .expect_err("a malformed node measurement key must refuse");

    assert_eq!(
        refusal_chirho,
        ControlPlaneAuthorityRefusalChirho::MalformedNodeMeasurementKeyChirho {
            node_id_chirho: "node-alpha-chirho".to_string(),
        },
        "and it must NAME the node rather than refusing as a generic malformed key: {refusal_chirho:?}"
    );
}
