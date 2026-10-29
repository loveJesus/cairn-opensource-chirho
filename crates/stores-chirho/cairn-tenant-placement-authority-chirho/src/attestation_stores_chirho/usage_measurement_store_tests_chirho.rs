// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Arms for the durable usage store.
//!
//! Two centrepieces, and they are a pair. [`a_replayed_report_freezes_rather_than_being_refused_chirho`]
//! pins the design decision — refusing a stale report would leave the node's last good measurement
//! standing and its posture unfrozen, which is the opposite of what the clause asks. And
//! [`a_fresh_report_after_a_freeze_thaws_the_node_chirho`] pins the other half: frozen means frozen
//! UNTIL fresh evidence arrives, not frozen forever. Either arm alone would permit a wrong
//! implementation.

use super::*;
use cairn_core_chirho::cas_chirho;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use cairn_placement_chirho::capacity_chirho::usage_measurement_attestation_chirho::*;

const NODE_KEY_CHIRHO: &str = "node-a-key-chirho";
const NODE_CHIRHO: &str = "node-a-chirho";

struct NodeAuthorityChirho;

impl NodeMeasurementAuthorityPortChirho for NodeAuthorityChirho {
    fn node_key_id_chirho(&self) -> String {
        NODE_KEY_CHIRHO.to_string()
    }
    fn verify_chirho(&self, msg_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{msg_chirho}")
    }
}

fn report_chirho(
    sequence_chirho: u64,
    hlc_millis_chirho: u64,
) -> UsageMeasurementAttestationChirho {
    let intent_chirho = UsageMeasurementIntentChirho {
        schema_chirho: USAGE_MEASUREMENT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: NODE_CHIRHO.to_string(),
        stamp_chirho: MeasurementStampChirho {
            hlc_millis_chirho,
            sequence_chirho,
        },
        observed_usage_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: 1500,
            memory_bytes_chirho: 2 << 30,
            durable_bytes_chirho: 40 << 30,
        },
    };
    let digest_chirho = usage_intent_digest_chirho(&intent_chirho).expect("digest");
    let mut record_chirho = UsageMeasurementAttestationChirho {
        schema_chirho: USAGE_MEASUREMENT_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: USAGE_MEASUREMENT_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho: digest_chirho,
        node_key_id_chirho: NODE_KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho =
        format!("sig-over:{}", unsigned_usage_message_chirho(&record_chirho));
    record_chirho
}

#[test]
fn a_node_that_was_never_measured_is_frozen_in_both_directions_chirho() {
    // Never having been measured is NOT the same as having been measured and found fine. Admission
    // requires FRESH measurement, not the absence of a bad one.
    let temp_chirho = tempfile::tempdir().unwrap();
    let posture_chirho =
        current_scaling_posture_chirho(temp_chirho.path(), NODE_CHIRHO, &NodeAuthorityChirho)
            .unwrap();
    assert!(!posture_chirho.scale_out_allowed_chirho());
    assert!(!posture_chirho.scale_in_allowed_chirho());
}

#[test]
fn a_fresh_report_thaws_both_directions_chirho() {
    // Positive control: without it, every freeze arm below would pass against a store frozen forever.
    let temp_chirho = tempfile::tempdir().unwrap();
    let posture_chirho = append_verified_usage_measurement_chirho(
        temp_chirho.path(),
        &report_chirho(1, 1_000),
        &NodeAuthorityChirho,
    )
    .expect("a fresh report must append");
    assert!(posture_chirho.scale_out_allowed_chirho());
    assert!(posture_chirho.scale_in_allowed_chirho());
}

#[test]
fn a_replayed_report_freezes_rather_than_being_refused_chirho() {
    // THE design decision. Refusing the stale report would leave the node's last good measurement
    // standing as current, so the node would keep an UNFROZEN posture and go on looking healthy --
    // when a node offering replayed evidence is precisely a node you can no longer see.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    append_verified_usage_measurement_chirho(
        root_chirho,
        &report_chirho(5, 1_000),
        &NodeAuthorityChirho,
    )
    .expect("first report");

    let posture_chirho = append_verified_usage_measurement_chirho(
        root_chirho,
        &report_chirho(5, 2_000),
        &NodeAuthorityChirho,
    )
    .expect("a replayed report must be RECORDED, not refused");
    assert!(
        !posture_chirho.scale_out_allowed_chirho(),
        "replayed evidence must freeze scale-out"
    );
    assert!(
        !posture_chirho.scale_in_allowed_chirho(),
        "replayed evidence must freeze scale-in TOO -- acting on a replayed low-usage number would \
         drain a node that is actually busy"
    );
    assert!(
        root_chirho.join(NODE_USAGE_MEASUREMENT_LOG_CHIRHO).exists(),
        "the stale report is recorded, which is what makes the freeze visible to a later reader"
    );
}

#[test]
fn a_rewound_clock_also_freezes_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    append_verified_usage_measurement_chirho(
        root_chirho,
        &report_chirho(1, 5_000),
        &NodeAuthorityChirho,
    )
    .expect("first report");
    let posture_chirho = append_verified_usage_measurement_chirho(
        root_chirho,
        &report_chirho(2, 1_000),
        &NodeAuthorityChirho,
    )
    .expect("recorded");
    assert!(!posture_chirho.scale_out_allowed_chirho());
    assert!(!posture_chirho.scale_in_allowed_chirho());
}

#[test]
fn a_fresh_report_after_a_freeze_thaws_the_node_chirho() {
    // The other half of the pair. "Freezes" means frozen UNTIL fresh evidence arrives -- an
    // implementation that froze permanently would pass the replay arm and be wrong.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    append_verified_usage_measurement_chirho(
        root_chirho,
        &report_chirho(5, 1_000),
        &NodeAuthorityChirho,
    )
    .expect("first");
    let frozen_chirho = append_verified_usage_measurement_chirho(
        root_chirho,
        &report_chirho(5, 2_000),
        &NodeAuthorityChirho,
    )
    .expect("replay recorded");
    assert!(!frozen_chirho.scale_out_allowed_chirho());

    let thawed_chirho = append_verified_usage_measurement_chirho(
        root_chirho,
        &report_chirho(6, 3_000),
        &NodeAuthorityChirho,
    )
    .expect("a genuinely fresh report");
    assert!(
        thawed_chirho.scale_out_allowed_chirho() && thawed_chirho.scale_in_allowed_chirho(),
        "a freeze must lift when the node can be seen again"
    );
}

#[test]
fn an_inauthentic_report_never_reaches_the_log_chirho() {
    // Authenticity is not weak evidence: an unsigned report is NOT evidence, and recording it would
    // let anyone freeze any node by offering garbage.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let mut forged_chirho = report_chirho(1, 1_000);
    forged_chirho.sig_chirho = "sig-over:not-the-real-message-chirho".to_string();
    assert_eq!(
        append_verified_usage_measurement_chirho(root_chirho, &forged_chirho, &NodeAuthorityChirho)
            .expect_err("an unsigned report must refuse"),
        UsageStoreRefusalChirho::NotVerifiedChirho
    );
    assert!(!root_chirho.join(NODE_USAGE_MEASUREMENT_LOG_CHIRHO).exists());
}

#[test]
fn admission_refuses_a_directly_written_unverifiable_row_that_posture_skips_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    append_verified_usage_measurement_chirho(
        root_chirho,
        &report_chirho(1, 1_000),
        &NodeAuthorityChirho,
    )
    .expect("verified baseline");
    let mut forged_chirho = report_chirho(2, 2_000);
    forged_chirho.sig_chirho = "not-authoritative-chirho".to_string();
    let mut forged_line_chirho = serde_json::to_vec(&forged_chirho).unwrap();
    forged_line_chirho.push(b'\n');
    cairn_durable_chirho::append_durable_line_chirho(
        &root_chirho.join(NODE_USAGE_MEASUREMENT_LOG_CHIRHO),
        &forged_line_chirho,
    )
    .unwrap();

    assert_eq!(
        verified_measurements_in_order_chirho(root_chirho, NODE_CHIRHO, &NodeAuthorityChirho)
            .unwrap()
            .len(),
        1,
        "the posture/report reader keeps its deliberate direct-write skip"
    );
    assert_eq!(
        verified_measurements_in_order_for_admission_chirho(
            root_chirho,
            NODE_CHIRHO,
            &NodeAuthorityChirho,
        )
        .expect_err("admission must never substitute an older lower reading"),
        UsageStoreRefusalChirho::NotVerifiedChirho
    );
}

#[test]
fn the_stored_intent_resolves_in_cas_at_its_declared_digest_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let record_chirho = report_chirho(1, 1_000);
    let declared_chirho = record_chirho.intent_digest_chirho.clone();
    append_verified_usage_measurement_chirho(root_chirho, &record_chirho, &NodeAuthorityChirho)
        .expect("append");
    assert!(cas_chirho::get_chirho(root_chirho, &HashChirho(declared_chirho)).is_ok());
}
