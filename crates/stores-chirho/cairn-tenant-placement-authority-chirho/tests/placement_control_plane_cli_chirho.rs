// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Proof by EXECUTION of the shipped `cairn-placement-control-verify-chirho` binary.
//!
//! Clause 7's residual was one thing: a production caller. `PlacementRegistryChirho` was only ever
//! constructed by tests, and the CF8 audit's phrase is "production callers rather than caller-supplied
//! in-memory values". So the proof has to be the binary actually running against a root, both
//! directions — a good root reports, and separate plants each refuse by their own identity.
//!
//! Everything here is signed with REAL ed25519 keys, and every value the binary reports comes off disk
//! through a signature check. Nothing supplies a capacity number, a lifecycle state or a measurement.

use cairn_placement_chirho::capacity_chirho::capacity_attestation_chirho::*;
use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use cairn_placement_chirho::capacity_chirho::measurement_freshness_chirho::MeasurementStampChirho;
use cairn_placement_chirho::capacity_chirho::usage_measurement_attestation_chirho::*;
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use cairn_placement_chirho::node_lifecycle_chirho::lifecycle_attestation_chirho::*;
use cairn_placement_chirho::node_lifecycle_chirho::{
    LifecycleTransitionChirho, NodeLifecycleStateChirho,
};
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::capacity_attestation_store_chirho::append_verified_capacity_attestation_chirho;
use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::lifecycle_transition_store_chirho::append_verified_lifecycle_transition_chirho;
use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::usage_measurement_store_chirho::append_verified_usage_measurement_chirho;
use cairn_tenant_placement_authority_chirho::control_plane_authorities_chirho::{
    resolve_control_plane_authorities_chirho, ControlPlaneAuthoritiesChirho,
};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

const NODE_CHIRHO: &str = "node-a-chirho";

// The helpers below are deliberately named `..._control_plane_..._chirho` rather than the obvious
// `run_cli_chirho` / `seed_grant_chirho`. A workspace guard censuses served-runtime boot consumers by
// propagating function NAMES, and it only propagates a name defined EXACTLY ONCE workspace-wide. A
// test-local helper sharing a name with a production entry point therefore stops that name
// propagating and silently drops unrelated files from the census. `run_cli_chirho` is the main CLI
// dispatch entry point (cairn-cli-chirho/src/dispatch_chirho.rs), and naming this helper that dropped
// two cairn-cli test files out of the boot-consumer guard until it was renamed.

/// A signing identity: its own key root plus the public key id others verify against.
struct IdentityChirho {
    key_root_chirho: tempfile::TempDir,
    pubkey_chirho: String,
}

fn identity_chirho() -> IdentityChirho {
    let key_root_chirho = tempfile::tempdir().expect("key root");
    let pubkey_chirho = pubkey_hex_chirho(key_root_chirho.path()).expect("pubkey");
    IdentityChirho {
        key_root_chirho,
        pubkey_chirho,
    }
}

fn sign_chirho(identity_chirho: &IdentityChirho, message_chirho: &str) -> String {
    sign_message_chirho(
        identity_chirho.key_root_chirho.path(),
        message_chirho.as_bytes(),
    )
    .expect("sign")
}

fn seed_control_plane_grant_chirho(
    root_chirho: &Path,
    registrar_chirho: &IdentityChirho,
    authorities_chirho: &ControlPlaneAuthoritiesChirho,
) {
    let intent_chirho = NodeCapacityIntentChirho {
        schema_chirho: NODE_CAPACITY_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: NODE_CHIRHO.to_string(),
        domain_chirho: FailureDomainChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            region_chirho: "fsn1-chirho".to_string(),
        },
        allocatable_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: 8_000,
            memory_bytes_chirho: 32 << 30,
            durable_bytes_chirho: 1_024 << 30,
        },
        registration_seq_chirho: 1,
    };
    let mut record_chirho = NodeCapacityAttestationChirho {
        schema_chirho: NODE_CAPACITY_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: NODE_CAPACITY_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_digest_chirho: node_capacity_intent_digest_chirho(&intent_chirho).expect("digest"),
        intent_chirho,
        authority_key_id_chirho: registrar_chirho.pubkey_chirho.clone(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_chirho(
        registrar_chirho,
        &unsigned_node_capacity_message_chirho(&record_chirho),
    );
    append_verified_capacity_attestation_chirho(
        root_chirho,
        &record_chirho,
        authorities_chirho.capacity_registrar_chirho(),
    )
    .expect("seed grant");
}

fn seed_control_plane_transition_chirho(
    root_chirho: &Path,
    lifecycle_chirho: &IdentityChirho,
    authorities_chirho: &ControlPlaneAuthoritiesChirho,
    from_chirho: NodeLifecycleStateChirho,
    transition_chirho: LifecycleTransitionChirho,
    seq_chirho: u64,
) {
    let intent_chirho = LifecycleTransitionIntentChirho {
        schema_chirho: LIFECYCLE_TRANSITION_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: NODE_CHIRHO.to_string(),
        from_state_chirho: from_chirho,
        transition_chirho,
        asserted_facts_chirho: AssertedLifecycleFactsChirho {
            holds_leadership_chirho: false,
            ownership_proven_chirho: true,
            resident_placements_chirho: 0,
        },
        transition_seq_chirho: seq_chirho,
    };
    let mut record_chirho = LifecycleTransitionAttestationChirho {
        schema_chirho: LIFECYCLE_TRANSITION_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: LIFECYCLE_TRANSITION_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_digest_chirho: lifecycle_intent_digest_chirho(&intent_chirho).expect("digest"),
        intent_chirho,
        authority_key_id_chirho: lifecycle_chirho.pubkey_chirho.clone(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_chirho(
        lifecycle_chirho,
        &unsigned_lifecycle_message_chirho(&record_chirho),
    );
    append_verified_lifecycle_transition_chirho(
        root_chirho,
        &record_chirho,
        authorities_chirho.lifecycle_chirho(),
    )
    .expect("seed transition");
}

fn seed_control_plane_measurement_chirho(
    root_chirho: &Path,
    node_chirho: &IdentityChirho,
    authorities_chirho: &ControlPlaneAuthoritiesChirho,
    hlc_millis_chirho: u64,
    sequence_chirho: u64,
) {
    let intent_chirho = UsageMeasurementIntentChirho {
        schema_chirho: USAGE_MEASUREMENT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: NODE_CHIRHO.to_string(),
        stamp_chirho: MeasurementStampChirho {
            hlc_millis_chirho,
            sequence_chirho,
        },
        observed_usage_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: 1_500,
            memory_bytes_chirho: 2 << 30,
            durable_bytes_chirho: 40 << 30,
        },
    };
    let mut record_chirho = UsageMeasurementAttestationChirho {
        schema_chirho: USAGE_MEASUREMENT_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: USAGE_MEASUREMENT_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_digest_chirho: usage_intent_digest_chirho(&intent_chirho).expect("digest"),
        intent_chirho,
        node_key_id_chirho: node_chirho.pubkey_chirho.clone(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho =
        sign_chirho(node_chirho, &unsigned_usage_message_chirho(&record_chirho));
    append_verified_usage_measurement_chirho(
        root_chirho,
        &record_chirho,
        authorities_chirho
            .node_measurement_chirho(NODE_CHIRHO)
            .expect("node verifier"),
    )
    .expect("seed measurement");
}

struct WorldChirho {
    root_chirho: tempfile::TempDir,
    registrar_chirho: IdentityChirho,
    lifecycle_chirho: IdentityChirho,
    topology_chirho: IdentityChirho,
    budget_chirho: IdentityChirho,
    node_chirho: IdentityChirho,
}

fn authorities_for_chirho(world_chirho: &WorldChirho) -> ControlPlaneAuthoritiesChirho {
    let mut map_chirho = BTreeMap::new();
    map_chirho.insert(
        NODE_CHIRHO.to_string(),
        world_chirho.node_chirho.pubkey_chirho.clone(),
    );
    resolve_control_plane_authorities_chirho(
        &world_chirho.registrar_chirho.pubkey_chirho,
        &world_chirho.lifecycle_chirho.pubkey_chirho,
        &world_chirho.topology_chirho.pubkey_chirho,
        &world_chirho.budget_chirho.pubkey_chirho,
        &map_chirho,
    )
    .expect("distinct real keys resolve")
}

/// A root with a granted, joined, freshly-measured node — all of it signed.
fn joined_and_measured_world_chirho() -> WorldChirho {
    let world_chirho = WorldChirho {
        root_chirho: tempfile::tempdir().expect("root"),
        registrar_chirho: identity_chirho(),
        lifecycle_chirho: identity_chirho(),
        topology_chirho: identity_chirho(),
        budget_chirho: identity_chirho(),
        node_chirho: identity_chirho(),
    };
    let authorities_chirho = authorities_for_chirho(&world_chirho);
    let root_chirho = world_chirho.root_chirho.path();
    seed_control_plane_grant_chirho(
        root_chirho,
        &world_chirho.registrar_chirho,
        &authorities_chirho,
    );
    seed_control_plane_transition_chirho(
        root_chirho,
        &world_chirho.lifecycle_chirho,
        &authorities_chirho,
        NodeLifecycleStateChirho::ProvisionedChirho,
        LifecycleTransitionChirho::InspectChirho,
        1,
    );
    seed_control_plane_transition_chirho(
        root_chirho,
        &world_chirho.lifecycle_chirho,
        &authorities_chirho,
        NodeLifecycleStateChirho::InspectedChirho,
        LifecycleTransitionChirho::JoinChirho,
        2,
    );
    seed_control_plane_measurement_chirho(
        root_chirho,
        &world_chirho.node_chirho,
        &authorities_chirho,
        1_000,
        5,
    );
    world_chirho
}

fn run_control_plane_verify_cli_chirho(
    world_chirho: &WorldChirho,
    node_key_chirho: &str,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_cairn-placement-control-verify-chirho"))
        .arg(world_chirho.root_chirho.path())
        .arg(&world_chirho.registrar_chirho.pubkey_chirho)
        .arg(&world_chirho.lifecycle_chirho.pubkey_chirho)
        .arg(&world_chirho.topology_chirho.pubkey_chirho)
        .arg(&world_chirho.budget_chirho.pubkey_chirho)
        .arg(format!("{NODE_CHIRHO}={node_key_chirho}"))
        .output()
        .expect("run the shipped binary")
}

/// The same invocation plus extra `key=value` arguments, so probe arms differ from the arms above by
/// exactly the probe.
fn run_with_extra_args_chirho(
    world_chirho: &WorldChirho,
    node_key_chirho: &str,
    extra_chirho: &[&str],
) -> std::process::Output {
    let mut command_chirho =
        Command::new(env!("CARGO_BIN_EXE_cairn-placement-control-verify-chirho"));
    command_chirho
        .arg(world_chirho.root_chirho.path())
        .arg(&world_chirho.registrar_chirho.pubkey_chirho)
        .arg(&world_chirho.lifecycle_chirho.pubkey_chirho)
        .arg(&world_chirho.topology_chirho.pubkey_chirho)
        .arg(&world_chirho.budget_chirho.pubkey_chirho)
        .arg(format!("{NODE_CHIRHO}={node_key_chirho}"));
    for argument_chirho in extra_chirho {
        command_chirho.arg(argument_chirho);
    }
    command_chirho.output().expect("run the shipped binary")
}

#[test]
fn an_unprobed_report_says_not_probed_rather_than_no_refusals_chirho() {
    // `null` and `[]` must not collapse. An empty refusal list means "asked, and it would be
    // admitted"; absence means nobody asked. Reading the second as the first is the wrong direction
    // for a report an operator uses to decide whether to place work.
    let world_chirho = joined_and_measured_world_chirho();
    let output_chirho =
        run_control_plane_verify_cli_chirho(&world_chirho, &world_chirho.node_chirho.pubkey_chirho);
    let stdout_chirho = String::from_utf8_lossy(&output_chirho.stdout);
    assert!(
        stdout_chirho.contains("\"probe_refusals_chirho\":null"),
        "an unprobed report must say null, not an empty list: {stdout_chirho}"
    );
}

#[test]
fn a_probe_that_fits_reports_an_empty_refusal_list_chirho() {
    // The positive control for the probe arms: without it, a probe that always refused would satisfy
    // every negative probe arm below.
    let world_chirho = joined_and_measured_world_chirho();
    let output_chirho = run_with_extra_args_chirho(
        &world_chirho,
        &world_chirho.node_chirho.pubkey_chirho,
        &["demand=100,1073741824,1073741824"],
    );
    assert!(output_chirho.status.success());
    let stdout_chirho = String::from_utf8_lossy(&output_chirho.stdout);
    assert!(
        stdout_chirho.contains("\"probe_refusals_chirho\":[]"),
        "a small demand on a joined, freshly measured node must be admissible: {stdout_chirho}"
    );
}

#[test]
fn a_probe_larger_than_the_node_reports_the_capacity_refusal_chirho() {
    let world_chirho = joined_and_measured_world_chirho();
    let output_chirho = run_with_extra_args_chirho(
        &world_chirho,
        &world_chirho.node_chirho.pubkey_chirho,
        &["demand=999999,1073741824,1073741824"],
    );
    assert!(
        output_chirho.status.success(),
        "reporting a refusal is not an error"
    );
    let stdout_chirho = String::from_utf8_lossy(&output_chirho.stdout);
    assert!(
        stdout_chirho.contains("InsufficientFreeCapacityChirho"),
        "the operator asking why it will not land must be told which dimension: {stdout_chirho}"
    );
}

#[test]
fn headroom_without_a_demand_refuses_rather_than_probing_a_zero_demand_chirho() {
    // Defaulting the demand to zero would silently answer a different question than the one asked.
    let world_chirho = joined_and_measured_world_chirho();
    let output_chirho = run_with_extra_args_chirho(
        &world_chirho,
        &world_chirho.node_chirho.pubkey_chirho,
        &["headroom=100,1073741824,1073741824"],
    );
    assert!(!output_chirho.status.success());
    assert!(String::from_utf8_lossy(&output_chirho.stderr)
        .contains("PlacementControlPlaneUsageRefusedChirho"));
}

#[test]
fn the_shipped_binary_reports_a_joined_measured_node_from_signed_evidence_chirho() {
    // The POSITIVE direction, and it is what makes the refusals below meaningful: a binary that
    // refused everything would satisfy every negative arm in this file.
    let world_chirho = joined_and_measured_world_chirho();
    let output_chirho =
        run_control_plane_verify_cli_chirho(&world_chirho, &world_chirho.node_chirho.pubkey_chirho);
    assert!(
        output_chirho.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output_chirho.stderr)
    );
    let stdout_chirho = String::from_utf8_lossy(&output_chirho.stdout);
    assert!(stdout_chirho.contains("placement-control-plane-report-v1-chirho"));
    assert!(stdout_chirho.contains(NODE_CHIRHO));
    assert!(stdout_chirho.contains("JoinedChirho"), "{stdout_chirho}");
    assert!(
        stdout_chirho.contains("\"lifecycle_admits_chirho\":true"),
        "a joined node admits placements: {stdout_chirho}"
    );
    assert!(
        stdout_chirho.contains("\"scale_out_allowed_chirho\":true"),
        "a freshly measured node is not frozen: {stdout_chirho}"
    );
    assert!(
        stdout_chirho.contains("\"cpu_millicores_chirho\":8000"),
        "the capacity comes from the signed grant: {stdout_chirho}"
    );
}

#[test]
fn the_shipped_binary_prints_no_key_material_chirho() {
    // The report reaches operator surfaces. Node ids, states and numbers only.
    let world_chirho = joined_and_measured_world_chirho();
    let output_chirho =
        run_control_plane_verify_cli_chirho(&world_chirho, &world_chirho.node_chirho.pubkey_chirho);
    let stdout_chirho = String::from_utf8_lossy(&output_chirho.stdout);
    for key_chirho in [
        &world_chirho.registrar_chirho.pubkey_chirho,
        &world_chirho.lifecycle_chirho.pubkey_chirho,
        &world_chirho.topology_chirho.pubkey_chirho,
        &world_chirho.budget_chirho.pubkey_chirho,
        &world_chirho.node_chirho.pubkey_chirho,
    ] {
        assert!(
            !stdout_chirho.contains(key_chirho.as_str()),
            "a key id reached the report"
        );
    }
    // And the root path, which names the host's filesystem.
    assert!(!stdout_chirho.contains(&*world_chirho.root_chirho.path().to_string_lossy()));
}

#[test]
fn a_node_holding_the_registrar_key_is_refused_before_any_log_is_read_chirho() {
    // Separation is checked before the root is touched, so this refuses on a root that would otherwise
    // report perfectly well.
    let world_chirho = joined_and_measured_world_chirho();
    let output_chirho = run_control_plane_verify_cli_chirho(
        &world_chirho,
        &world_chirho.registrar_chirho.pubkey_chirho,
    );
    assert!(!output_chirho.status.success());
    let stderr_chirho = String::from_utf8_lossy(&output_chirho.stderr);
    assert!(
        stderr_chirho.contains("NodeWouldSignItsOwnEvidenceChirho"),
        "expected the self-attestation refusal, got: {stderr_chirho}"
    );
}

#[test]
fn a_node_with_no_grant_refuses_rather_than_reporting_an_empty_fleet_chirho() {
    // A registry that quietly omitted the node would print a valid-looking report describing nothing.
    let world_chirho = WorldChirho {
        root_chirho: tempfile::tempdir().expect("root"),
        registrar_chirho: identity_chirho(),
        lifecycle_chirho: identity_chirho(),
        topology_chirho: identity_chirho(),
        budget_chirho: identity_chirho(),
        node_chirho: identity_chirho(),
    };
    let output_chirho =
        run_control_plane_verify_cli_chirho(&world_chirho, &world_chirho.node_chirho.pubkey_chirho);
    assert!(!output_chirho.status.success());
    let stderr_chirho = String::from_utf8_lossy(&output_chirho.stderr);
    assert!(
        stderr_chirho.contains("NoCapacityGrantChirho"),
        "expected the missing-grant refusal, got: {stderr_chirho}"
    );
}

#[test]
fn a_replayed_measurement_on_disk_reports_the_node_frozen_chirho() {
    // The clause end to end through the shipped binary: a node whose latest signed report is a replay
    // is reported frozen in BOTH directions, while still being lifecycle-eligible — which is why the
    // report carries the two separately.
    let world_chirho = joined_and_measured_world_chirho();
    let authorities_chirho = authorities_for_chirho(&world_chirho);
    seed_control_plane_measurement_chirho(
        world_chirho.root_chirho.path(),
        &world_chirho.node_chirho,
        &authorities_chirho,
        2_000,
        5, // same sequence: a replay
    );

    let output_chirho =
        run_control_plane_verify_cli_chirho(&world_chirho, &world_chirho.node_chirho.pubkey_chirho);
    assert!(
        output_chirho.status.success(),
        "a replay freezes, it does not fail the load"
    );
    let stdout_chirho = String::from_utf8_lossy(&output_chirho.stdout);
    assert!(
        stdout_chirho.contains("\"scale_out_allowed_chirho\":false")
            && stdout_chirho.contains("\"scale_in_allowed_chirho\":false"),
        "replayed evidence must freeze both directions: {stdout_chirho}"
    );
    assert!(
        stdout_chirho.contains("\"lifecycle_admits_chirho\":true"),
        "and the node is still lifecycle-eligible, so the freeze is attributable to the measurement \
         rather than to the node having fallen out of Joined: {stdout_chirho}"
    );
}

#[test]
fn probing_a_frozen_node_names_the_own_evidence_clause_chirho() {
    // The operator value, end to end: a node with plenty of free capacity and an open lifecycle still
    // refuses, and the report says WHY — its own latest signed report was a replay. Without the probe
    // an operator sees `scale_out_allowed=false` and has to know what that implies for a placement.
    let world_chirho = joined_and_measured_world_chirho();
    let authorities_chirho = authorities_for_chirho(&world_chirho);
    seed_control_plane_measurement_chirho(
        world_chirho.root_chirho.path(),
        &world_chirho.node_chirho,
        &authorities_chirho,
        2_000,
        5, // a replay
    );

    let output_chirho = run_with_extra_args_chirho(
        &world_chirho,
        &world_chirho.node_chirho.pubkey_chirho,
        &["demand=100,1073741824,1073741824"],
    );
    assert!(output_chirho.status.success());
    let stdout_chirho = String::from_utf8_lossy(&output_chirho.stdout);
    assert!(
        stdout_chirho.contains("FrozenByItsOwnEvidenceChirho"),
        "the probe must name the own-evidence clause: {stdout_chirho}"
    );
    assert!(
        !stdout_chirho.contains("InsufficientFreeCapacityChirho"),
        "and capacity is NOT the reason here, so the arm is not passing for the wrong one: \
         {stdout_chirho}"
    );
    assert!(
        stdout_chirho.contains("\"lifecycle_admits_chirho\":true"),
        "nor lifecycle: {stdout_chirho}"
    );
}
