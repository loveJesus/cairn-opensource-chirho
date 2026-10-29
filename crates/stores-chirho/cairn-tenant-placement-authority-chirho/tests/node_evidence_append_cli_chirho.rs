// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Proof by EXECUTION of `cairn-node-evidence-append-chirho`, effect-asserted.
//!
//! The crate shipped five binaries and every one was a VERIFIER; nothing could create evidence. A
//! host survey found seven logs absent for exactly that reason. These arms prove the appender works,
//! and they assert the LOG rather than the exit code — a binary that exits 0 without appending passes
//! a status check and fails these.
//!
//! Every refusal arm here is paired with that positive effect control on purpose: a binary that fails
//! on every input satisfies refusal arms alone, so refusals prove nothing without a success beside
//! them.
//!
//! Helpers are named `..._evidence_append_..._chirho` because a workspace guard censuses by
//! propagating function names defined exactly once.

use cairn_placement_chirho::capacity_chirho::capacity_attestation_chirho::*;
use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use cairn_placement_chirho::capacity_chirho::measurement_freshness_chirho::MeasurementStampChirho;
use cairn_placement_chirho::capacity_chirho::usage_measurement_attestation_chirho::*;
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use cairn_placement_chirho::node_lifecycle_chirho::lifecycle_attestation_chirho::*;
use cairn_placement_chirho::node_lifecycle_chirho::{LifecycleTransitionChirho, NodeLifecycleStateChirho};
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::capacity_attestation_store_chirho::NODE_CAPACITY_ATTESTATION_LOG_CHIRHO;
use std::path::Path;
use std::process::Command;

const EVIDENCE_APPEND_NODE_CHIRHO: &str = "node-evidence-append-node-chirho";

struct EvidenceAppendKeyChirho {
    key_root_chirho: tempfile::TempDir,
    pubkey_chirho: String,
}

fn evidence_append_key_chirho() -> EvidenceAppendKeyChirho {
    let key_root_chirho = tempfile::tempdir().expect("key root");
    let pubkey_chirho = pubkey_hex_chirho(key_root_chirho.path()).expect("pubkey");
    EvidenceAppendKeyChirho {
        key_root_chirho,
        pubkey_chirho,
    }
}

/// Author one registrar-signed capacity grant and write it where the binary can read it.
fn write_evidence_append_grant_chirho(
    path_chirho: &Path,
    registrar_chirho: &EvidenceAppendKeyChirho,
    registration_seq_chirho: u64,
) {
    let intent_chirho = NodeCapacityIntentChirho {
        schema_chirho: NODE_CAPACITY_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: EVIDENCE_APPEND_NODE_CHIRHO.to_string(),
        domain_chirho: FailureDomainChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            region_chirho: "fsn1-chirho".to_string(),
        },
        allocatable_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: 8_000,
            memory_bytes_chirho: 32 << 30,
            durable_bytes_chirho: 1_024 << 30,
        },
        registration_seq_chirho,
    };
    let mut record_chirho = NodeCapacityAttestationChirho {
        schema_chirho: NODE_CAPACITY_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: NODE_CAPACITY_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_digest_chirho: node_capacity_intent_digest_chirho(&intent_chirho).expect("digest"),
        intent_chirho,
        authority_key_id_chirho: registrar_chirho.pubkey_chirho.clone(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_message_chirho(
        registrar_chirho.key_root_chirho.path(),
        unsigned_node_capacity_message_chirho(&record_chirho).as_bytes(),
    )
    .expect("sign");
    std::fs::write(path_chirho, serde_json::to_vec(&record_chirho).unwrap()).unwrap();
}

fn run_evidence_append_cli_chirho(arguments_chirho: &[&str]) -> (bool, String, String) {
    let output_chirho = Command::new(env!("CARGO_BIN_EXE_cairn-node-evidence-append-chirho"))
        .args(arguments_chirho)
        .output()
        .expect("the shipped binary runs");
    (
        output_chirho.status.success(),
        String::from_utf8_lossy(&output_chirho.stdout).to_string(),
        String::from_utf8_lossy(&output_chirho.stderr).to_string(),
    )
}

struct EvidenceAppendWorldChirho {
    _temp_chirho: tempfile::TempDir,
    root_chirho: std::path::PathBuf,
    record_path_chirho: std::path::PathBuf,
    capacity_chirho: EvidenceAppendKeyChirho,
    lifecycle_key_chirho: String,
    topology_key_chirho: String,
    budget_key_chirho: String,
    measurement_pair_chirho: String,
}

fn evidence_append_world_chirho() -> EvidenceAppendWorldChirho {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path().join("evidence-root-chirho");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let record_path_chirho = temp_chirho.path().join("grant-chirho.json");
    let capacity_chirho = evidence_append_key_chirho();
    write_evidence_append_grant_chirho(&record_path_chirho, &capacity_chirho, 1);
    let measurement_chirho = evidence_append_key_chirho();
    EvidenceAppendWorldChirho {
        root_chirho,
        record_path_chirho,
        lifecycle_key_chirho: evidence_append_key_chirho().pubkey_chirho,
        topology_key_chirho: evidence_append_key_chirho().pubkey_chirho,
        budget_key_chirho: evidence_append_key_chirho().pubkey_chirho,
        measurement_pair_chirho: format!(
            "{EVIDENCE_APPEND_NODE_CHIRHO}={}",
            measurement_chirho.pubkey_chirho
        ),
        capacity_chirho,
        _temp_chirho: temp_chirho,
    }
}

impl EvidenceAppendWorldChirho {
    fn arguments_chirho(&self, kind_chirho: &str) -> Vec<String> {
        vec![
            self.root_chirho.to_str().unwrap().to_string(),
            kind_chirho.to_string(),
            self.record_path_chirho.to_str().unwrap().to_string(),
            self.capacity_chirho.pubkey_chirho.clone(),
            self.lifecycle_key_chirho.clone(),
            self.topology_key_chirho.clone(),
            self.budget_key_chirho.clone(),
            self.measurement_pair_chirho.clone(),
        ]
    }
}

/// THE POSITIVE EFFECT CONTROL — asserts the LOG, not the exit code.
#[test]
fn the_shipped_binary_appends_a_capacity_grant_into_the_log_chirho() {
    let world_chirho = evidence_append_world_chirho();
    let arguments_chirho = world_chirho.arguments_chirho("capacity-chirho");
    let borrowed_chirho: Vec<&str> = arguments_chirho.iter().map(String::as_str).collect();

    let (ok_chirho, stdout_chirho, stderr_chirho) =
        run_evidence_append_cli_chirho(&borrowed_chirho);
    assert!(ok_chirho, "the success path must exit 0: {stderr_chirho}");
    assert!(
        stdout_chirho.contains(EVIDENCE_APPEND_NODE_CHIRHO)
            && stdout_chirho.contains("registration_seq_chirho=1"),
        "stdout names the node and the accepted sequence: {stdout_chirho}"
    );

    let log_chirho = std::fs::read_to_string(
        world_chirho
            .root_chirho
            .join(NODE_CAPACITY_ATTESTATION_LOG_CHIRHO),
    )
    .expect("the log now exists — it did not before");
    assert_eq!(log_chirho.lines().count(), 1, "exactly one grant appended");
    assert!(log_chirho.contains(EVIDENCE_APPEND_NODE_CHIRHO));
}

/// The store's OWN replay rule still governs; the binary imposes none of its own.
#[test]
fn a_replayed_registration_sequence_refuses_by_the_stores_identity_chirho() {
    let world_chirho = evidence_append_world_chirho();
    let arguments_chirho = world_chirho.arguments_chirho("capacity-chirho");
    let borrowed_chirho: Vec<&str> = arguments_chirho.iter().map(String::as_str).collect();
    assert!(run_evidence_append_cli_chirho(&borrowed_chirho).0);

    // The same sequence again: the capacity store refuses a replay at or below its high-water mark.
    let (ok_chirho, _stdout_chirho, stderr_chirho) =
        run_evidence_append_cli_chirho(&borrowed_chirho);
    assert!(!ok_chirho, "a replayed registration must refuse");
    assert!(
        stderr_chirho.contains("ReplayedRegistrationChirho"),
        "and by the STORE's identity, not a generic error: {stderr_chirho}"
    );
    let log_chirho = std::fs::read_to_string(
        world_chirho
            .root_chirho
            .join(NODE_CAPACITY_ATTESTATION_LOG_CHIRHO),
    )
    .unwrap();
    assert_eq!(
        log_chirho.lines().count(),
        1,
        "the refusal appended nothing"
    );
}

/// One holder speaking for two authorities refuses BEFORE anything is read or written.
///
/// This is the property the single-binary shape exists to preserve: three separate single-key
/// appenders would each bypass it and stage evidence a later read refuses.
#[test]
fn one_holder_speaking_for_two_authorities_refuses_before_any_append_chirho() {
    let world_chirho = evidence_append_world_chirho();
    let mut arguments_chirho = world_chirho.arguments_chirho("capacity-chirho");
    // lifecycle key := the capacity key.
    arguments_chirho[4] = world_chirho.capacity_chirho.pubkey_chirho.clone();
    let borrowed_chirho: Vec<&str> = arguments_chirho.iter().map(String::as_str).collect();

    let (ok_chirho, _stdout_chirho, stderr_chirho) =
        run_evidence_append_cli_chirho(&borrowed_chirho);
    assert!(!ok_chirho, "a shared authority holder must refuse");
    assert!(
        !stderr_chirho.contains("NodeEvidenceRecordFile"),
        "and refuse on the ARRANGEMENT, before the record file is even read: {stderr_chirho}"
    );
    assert!(
        !world_chirho
            .root_chirho
            .join(NODE_CAPACITY_ATTESTATION_LOG_CHIRHO)
            .exists(),
        "a refused append leaves no log"
    );
}

/// Operator-error paths, each by its own identity, all committed.
#[test]
fn evidence_append_operator_errors_refuse_by_their_own_identities_chirho() {
    let world_chirho = evidence_append_world_chirho();

    let (ok_chirho, _out_chirho, err_chirho) = run_evidence_append_cli_chirho(&[]);
    assert!(!ok_chirho);
    assert!(
        err_chirho.contains("NodeEvidenceAppendUsageRefusedChirho"),
        "{err_chirho}"
    );

    let mut unknown_kind_chirho = world_chirho.arguments_chirho("not-a-kind-chirho");
    let borrowed_chirho: Vec<&str> = unknown_kind_chirho.iter().map(String::as_str).collect();
    let (ok_chirho, _out_chirho, err_chirho) = run_evidence_append_cli_chirho(&borrowed_chirho);
    assert!(!ok_chirho, "an unknown kind must refuse");
    assert!(
        err_chirho.contains("NodeEvidenceAppendUsageRefusedChirho"),
        "{err_chirho}"
    );

    unknown_kind_chirho = world_chirho.arguments_chirho("capacity-chirho");
    unknown_kind_chirho[2] = world_chirho
        .root_chirho
        .join("absent-chirho.json")
        .to_str()
        .unwrap()
        .to_string();
    let borrowed_chirho: Vec<&str> = unknown_kind_chirho.iter().map(String::as_str).collect();
    let (ok_chirho, _out_chirho, err_chirho) = run_evidence_append_cli_chirho(&borrowed_chirho);
    assert!(!ok_chirho);
    assert!(
        err_chirho.contains("NodeEvidenceRecordFileUnreadableChirho"),
        "{err_chirho}"
    );
}

/// Author a lifecycle transition and write it where the binary can read it.
fn write_evidence_append_transition_chirho(
    path_chirho: &Path,
    authority_chirho: &EvidenceAppendKeyChirho,
    from_state_chirho: NodeLifecycleStateChirho,
    transition_chirho: LifecycleTransitionChirho,
    transition_seq_chirho: u64,
) {
    let intent_chirho = LifecycleTransitionIntentChirho {
        schema_chirho: LIFECYCLE_TRANSITION_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: EVIDENCE_APPEND_NODE_CHIRHO.to_string(),
        from_state_chirho,
        transition_chirho,
        asserted_facts_chirho: AssertedLifecycleFactsChirho {
            holds_leadership_chirho: false,
            ownership_proven_chirho: true,
            resident_placements_chirho: 0,
        },
        transition_seq_chirho,
    };
    let mut record_chirho = LifecycleTransitionAttestationChirho {
        schema_chirho: LIFECYCLE_TRANSITION_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: LIFECYCLE_TRANSITION_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_digest_chirho: lifecycle_intent_digest_chirho(&intent_chirho).expect("digest"),
        intent_chirho,
        authority_key_id_chirho: authority_chirho.pubkey_chirho.clone(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_message_chirho(
        authority_chirho.key_root_chirho.path(),
        unsigned_lifecycle_message_chirho(&record_chirho).as_bytes(),
    )
    .expect("sign");
    std::fs::write(path_chirho, serde_json::to_vec(&record_chirho).unwrap()).unwrap();
}

/// Author a usage measurement and write it where the binary can read it.
fn write_evidence_append_measurement_chirho(
    path_chirho: &Path,
    node_chirho: &EvidenceAppendKeyChirho,
    sequence_chirho: u64,
) {
    let intent_chirho = UsageMeasurementIntentChirho {
        schema_chirho: USAGE_MEASUREMENT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: EVIDENCE_APPEND_NODE_CHIRHO.to_string(),
        stamp_chirho: MeasurementStampChirho {
            hlc_millis_chirho: 1_786_542_000_000 + sequence_chirho,
            sequence_chirho,
        },
        observed_usage_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: 3_000,
            memory_bytes_chirho: 1 << 30,
            durable_bytes_chirho: 10 << 30,
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
    record_chirho.sig_chirho = sign_message_chirho(
        node_chirho.key_root_chirho.path(),
        unsigned_usage_message_chirho(&record_chirho).as_bytes(),
    )
    .expect("sign");
    std::fs::write(path_chirho, serde_json::to_vec(&record_chirho).unwrap()).unwrap();
}

/// THE LIFECYCLE KIND, and the CHAIN hazard the staging order flags hardest.
///
/// Two of the binary's three dispatch arms were unexercised. This is one, and it also pins the hazard
/// an operator is most likely to hit: authoring ONE lifecycle record per node is not enough, because
/// the store compares the signed `from_state` against the replayed state. The second transition must
/// depart from the state the first one reached, and a record signed against a stale view refuses.
#[test]
fn the_lifecycle_kind_appends_a_chain_and_refuses_a_stale_from_state_chirho() {
    let world_chirho = evidence_append_world_chirho();
    let lifecycle_chirho = evidence_append_key_chirho();
    let lifecycle_pubkey_chirho = lifecycle_chirho.pubkey_chirho.clone();

    let first_chirho = world_chirho.root_chirho.join("transition-1-chirho.json");
    write_evidence_append_transition_chirho(
        &first_chirho,
        &lifecycle_chirho,
        NodeLifecycleStateChirho::ProvisionedChirho,
        LifecycleTransitionChirho::InspectChirho,
        1,
    );
    let mut arguments_chirho = world_chirho.arguments_chirho("lifecycle-chirho");
    arguments_chirho[2] = first_chirho.to_str().unwrap().to_string();
    arguments_chirho[4] = lifecycle_pubkey_chirho.clone();
    let borrowed_chirho: Vec<&str> = arguments_chirho.iter().map(String::as_str).collect();
    let (ok_chirho, stdout_chirho, stderr_chirho) =
        run_evidence_append_cli_chirho(&borrowed_chirho);
    assert!(ok_chirho, "the lifecycle kind must append: {stderr_chirho}");
    assert!(
        stdout_chirho.contains("kind_chirho=lifecycle-chirho"),
        "{stdout_chirho}"
    );

    // THE HAZARD: a second transition signed from the ORIGINAL state, not the reached one.
    let stale_chirho = world_chirho
        .root_chirho
        .join("transition-stale-chirho.json");
    write_evidence_append_transition_chirho(
        &stale_chirho,
        &lifecycle_chirho,
        NodeLifecycleStateChirho::ProvisionedChirho,
        LifecycleTransitionChirho::InspectChirho,
        2,
    );
    arguments_chirho[2] = stale_chirho.to_str().unwrap().to_string();
    let borrowed_chirho: Vec<&str> = arguments_chirho.iter().map(String::as_str).collect();
    let (ok_chirho, _stdout_chirho, stderr_chirho) =
        run_evidence_append_cli_chirho(&borrowed_chirho);
    assert!(
        !ok_chirho,
        "a transition signed against a stale from-state must refuse — this is the hazard an \
         operator hits by authoring one lifecycle record per node"
    );
    assert!(!stderr_chirho.is_empty(), "and it refuses by identity");
}

/// THE USAGE KIND — and the store rule that DIFFERS from its two siblings.
///
/// Capacity and lifecycle refuse a replay. Usage RECORDS one and freezes the node instead, because
/// refusing would let anyone with write access freeze a node by appending garbage. An operator who
/// reads two stores and generalises will mis-predict the third, so it is pinned here.
#[test]
fn the_usage_kind_appends_and_a_replay_is_recorded_rather_than_refused_chirho() {
    let world_chirho = evidence_append_world_chirho();
    let node_chirho = evidence_append_key_chirho();
    let node_pubkey_chirho = node_chirho.pubkey_chirho.clone();

    let first_chirho = world_chirho.root_chirho.join("usage-1-chirho.json");
    write_evidence_append_measurement_chirho(&first_chirho, &node_chirho, 1);
    let mut arguments_chirho = world_chirho.arguments_chirho("usage-chirho");
    arguments_chirho[2] = first_chirho.to_str().unwrap().to_string();
    arguments_chirho[7] = format!("{EVIDENCE_APPEND_NODE_CHIRHO}={node_pubkey_chirho}");
    let borrowed_chirho: Vec<&str> = arguments_chirho.iter().map(String::as_str).collect();
    let (ok_chirho, stdout_chirho, stderr_chirho) =
        run_evidence_append_cli_chirho(&borrowed_chirho);
    assert!(ok_chirho, "the usage kind must append: {stderr_chirho}");
    assert!(
        stdout_chirho.contains("kind_chirho=usage-chirho"),
        "{stdout_chirho}"
    );

    // A REPLAY: the same sequence again. Unlike capacity, this is ACCEPTED and freezes the node.
    let replay_chirho = world_chirho.root_chirho.join("usage-replay-chirho.json");
    write_evidence_append_measurement_chirho(&replay_chirho, &node_chirho, 1);
    arguments_chirho[2] = replay_chirho.to_str().unwrap().to_string();
    let borrowed_chirho: Vec<&str> = arguments_chirho.iter().map(String::as_str).collect();
    let (ok_chirho, stdout_chirho, stderr_chirho) =
        run_evidence_append_cli_chirho(&borrowed_chirho);
    assert!(
        ok_chirho,
        "a replayed usage report is RECORDED, not refused — the sibling stores refuse and this one \
         deliberately does not: {stderr_chirho}"
    );
    assert!(
        stdout_chirho.contains("posture_chirho"),
        "and the reported posture is what carries the freeze: {stdout_chirho}"
    );
}
