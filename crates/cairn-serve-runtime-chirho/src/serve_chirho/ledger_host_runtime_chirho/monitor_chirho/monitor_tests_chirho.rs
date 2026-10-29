// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use cairn_ledger_host_chirho::{FsLedgerStorageChirho, FsMonitorEvidenceSinkChirho};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const EVIDENCE_PATH_CHIRHO: &str = "cycles/conservation-chirho.jsonl";
static NEXT_MONITOR_TEST_ID_CHIRHO: AtomicU64 = AtomicU64::new(1);

#[derive(Default)]
struct RecordingAlarmChirho {
    red_pages_chirho: AtomicUsize,
    refused_pages_chirho: AtomicUsize,
    evidence_write_pages_chirho: AtomicUsize,
}

impl LedgerConservationAlarmPortChirho for RecordingAlarmChirho {
    fn page_red_chirho(&self) {
        self.red_pages_chirho.fetch_add(1, Ordering::SeqCst);
    }

    fn page_refused_chirho(&self) {
        self.refused_pages_chirho.fetch_add(1, Ordering::SeqCst);
    }

    fn page_evidence_write_chirho(&self) {
        self.evidence_write_pages_chirho
            .fetch_add(1, Ordering::SeqCst);
    }
}

struct MonitorSinkFixtureChirho {
    root_chirho: PathBuf,
    ledger_root_chirho: PathBuf,
    monitor_root_chirho: PathBuf,
    sink_chirho: FsMonitorEvidenceSinkChirho,
}

impl MonitorSinkFixtureChirho {
    fn new_chirho() -> Self {
        let root_chirho = std::env::temp_dir().join(format!(
            "cairn-ledger-monitor-cycle-{}-{}-chirho",
            std::process::id(),
            NEXT_MONITOR_TEST_ID_CHIRHO.fetch_add(1, Ordering::Relaxed)
        ));
        let ledger_root_chirho = root_chirho.join("ledger-chirho");
        let monitor_root_chirho = root_chirho.join("monitor-chirho");
        fs::create_dir_all(&ledger_root_chirho).unwrap();
        fs::create_dir_all(&monitor_root_chirho).unwrap();
        fs::write(
            ledger_root_chirho.join("sentinel-chirho"),
            b"immutable-money-namespace-chirho",
        )
        .unwrap();
        let ledger_chirho =
            FsLedgerStorageChirho::open_existing_chirho(&ledger_root_chirho).unwrap();
        let sink_chirho = FsMonitorEvidenceSinkChirho::open_existing_disjoint_chirho(
            &ledger_chirho,
            &monitor_root_chirho,
        )
        .unwrap();
        Self {
            root_chirho,
            ledger_root_chirho,
            monitor_root_chirho,
            sink_chirho,
        }
    }

    fn ledger_bytes_chirho(&self) -> Vec<u8> {
        fs::read(self.ledger_root_chirho.join("sentinel-chirho")).unwrap()
    }

    fn evidence_lines_chirho(&self) -> Vec<Vec<u8>> {
        fs::read(self.monitor_root_chirho.join(EVIDENCE_PATH_CHIRHO))
            .unwrap()
            .split(|byte_chirho| *byte_chirho == b'\n')
            .filter(|line_chirho| !line_chirho.is_empty())
            .map(<[u8]>::to_vec)
            .collect()
    }
}

impl Drop for MonitorSinkFixtureChirho {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root_chirho);
    }
}

fn head_chirho() -> LedgerConservationHeadEvidenceChirho {
    LedgerConservationHeadEvidenceChirho {
        epoch_chirho: 7,
        checkpoint_digest_chirho: "aa".repeat(32),
        covered_record_count_chirho: 11,
    }
}

#[test]
fn checker_incident_maps_structurally_to_red_chirho() {
    let outcome_chirho = red_outcome_chirho(ConservationIncidentChirho {
        head_chirho: ConservationHeadCoordinateChirho {
            epoch_chirho: 7,
            checkpoint_digest_chirho: cairn_ledger_model_chirho::ids_chirho::DigestChirho(
                "aa".repeat(32),
            ),
            covered_record_count_chirho: 11,
        },
        kind_chirho: Box::new(ConservationIncidentKindChirho::ArithmeticOverflowChirho),
    });
    assert_eq!(
        outcome_chirho,
        LedgerConservationCycleOutcomeChirho::RedChirho {
            head_chirho: head_chirho(),
            incident_chirho: LedgerConservationIncidentEvidenceChirho::ArithmeticOverflowChirho,
        }
    );
}

#[test]
fn red_cycle_records_only_red_and_pages_without_touching_ledger_chirho() {
    let fixture_chirho = MonitorSinkFixtureChirho::new_chirho();
    let before_ledger_chirho = fixture_chirho.ledger_bytes_chirho();
    let alarm_chirho = RecordingAlarmChirho::default();
    let row_chirho = record_cycle_outcome_chirho(
        &fixture_chirho.sink_chirho,
        EVIDENCE_PATH_CHIRHO,
        5_000,
        100,
        104,
        LedgerConservationCycleOutcomeChirho::RedChirho {
            head_chirho: head_chirho(),
            incident_chirho: LedgerConservationIncidentEvidenceChirho::DomainDriftChirho {
                money_group_id_chirho: "money-group-local-chirho".to_string(),
                cluster_id_chirho: "cluster-local-chirho".to_string(),
                kind_id_chirho: "credits-chirho".to_string(),
                account_net_chirho: 600,
                local_supply_chirho: 599,
            },
        },
        &alarm_chirho,
    )
    .unwrap();
    assert!(matches!(
        row_chirho.outcome_chirho,
        LedgerConservationCycleOutcomeChirho::RedChirho { .. }
    ));
    let lines_chirho = fixture_chirho.evidence_lines_chirho();
    assert_eq!(lines_chirho.len(), 1);
    assert_eq!(
        parse_ledger_conservation_cycle_row_chirho(&lines_chirho[0]).unwrap(),
        row_chirho
    );
    let canonical_text_chirho = String::from_utf8(lines_chirho[0].clone()).unwrap();
    assert!(canonical_text_chirho.contains("\"account_net_chirho\":\"600\""));
    let noncanonical_amount_chirho = canonical_text_chirho.replacen("\"600\"", "\"0600\"", 1);
    assert_eq!(
        parse_ledger_conservation_cycle_row_chirho(noncanonical_amount_chirho.as_bytes()),
        Err(LedgerConservationCycleWireRefusalChirho::InvalidJsonChirho)
    );
    let pii_shaped_chirho =
        canonical_text_chirho.replacen("money-group-local-chirho", "john@example.com", 1);
    assert_eq!(
        parse_ledger_conservation_cycle_row_chirho(pii_shaped_chirho.as_bytes()),
        Err(LedgerConservationCycleWireRefusalChirho::InvalidEvidenceChirho)
    );
    assert_eq!(alarm_chirho.red_pages_chirho.load(Ordering::SeqCst), 1);
    assert_eq!(alarm_chirho.refused_pages_chirho.load(Ordering::SeqCst), 0);
    assert_eq!(
        alarm_chirho
            .evidence_write_pages_chirho
            .load(Ordering::SeqCst),
        0
    );
    assert_eq!(fixture_chirho.ledger_bytes_chirho(), before_ledger_chirho);
}

#[test]
fn refused_cycle_records_only_refused_and_pages_without_touching_ledger_chirho() {
    let fixture_chirho = MonitorSinkFixtureChirho::new_chirho();
    let before_ledger_chirho = fixture_chirho.ledger_bytes_chirho();
    let alarm_chirho = RecordingAlarmChirho::default();
    let row_chirho = record_cycle_outcome_chirho(
        &fixture_chirho.sink_chirho,
        EVIDENCE_PATH_CHIRHO,
        5_000,
        200,
        203,
        LedgerConservationCycleOutcomeChirho::RefusedChirho {
            reason_chirho: LedgerConservationRefusalCodeChirho::JournalRecoveryRequiredChirho,
        },
        &alarm_chirho,
    )
    .unwrap();
    assert!(matches!(
        row_chirho.outcome_chirho,
        LedgerConservationCycleOutcomeChirho::RefusedChirho { .. }
    ));
    let lines_chirho = fixture_chirho.evidence_lines_chirho();
    assert_eq!(lines_chirho.len(), 1);
    assert_eq!(
        parse_ledger_conservation_cycle_row_chirho(&lines_chirho[0]).unwrap(),
        row_chirho
    );
    assert_eq!(alarm_chirho.red_pages_chirho.load(Ordering::SeqCst), 0);
    assert_eq!(alarm_chirho.refused_pages_chirho.load(Ordering::SeqCst), 1);
    assert_eq!(
        alarm_chirho
            .evidence_write_pages_chirho
            .load(Ordering::SeqCst),
        0
    );
    assert_eq!(fixture_chirho.ledger_bytes_chirho(), before_ledger_chirho);
}

#[test]
fn failed_row_append_is_represented_by_the_fixed_evidence_page_chirho() {
    let fixture_chirho = MonitorSinkFixtureChirho::new_chirho();
    let before_ledger_chirho = fixture_chirho.ledger_bytes_chirho();
    let alarm_chirho = RecordingAlarmChirho::default();
    let error_chirho = record_cycle_outcome_chirho(
        &fixture_chirho.sink_chirho,
        "../outside-chirho.jsonl",
        5_000,
        300,
        301,
        LedgerConservationCycleOutcomeChirho::GreenChirho {
            head_chirho: head_chirho(),
            money_group_kind_scopes_checked_chirho: 1,
            domain_kind_rollups_checked_chirho: 1,
            global_supplies_checked_chirho: 1,
            work_items_checked_chirho: 3,
        },
        &alarm_chirho,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "ledger logical storage path is unsafe"
    );
    assert_eq!(
        alarm_chirho
            .evidence_write_pages_chirho
            .load(Ordering::SeqCst),
        1
    );
    assert!(!fixture_chirho
        .monitor_root_chirho
        .join(EVIDENCE_PATH_CHIRHO)
        .exists());
    assert_eq!(fixture_chirho.ledger_bytes_chirho(), before_ledger_chirho);
}

#[test]
fn cycle_row_parser_refuses_noncanonical_schema_and_cadence_chirho() {
    let row_chirho = LedgerConservationCycleRowChirho {
        schema_chirho: LEDGER_CONSERVATION_CYCLE_SCHEMA_V1_CHIRHO.to_string(),
        configured_cadence_ms_chirho: 5_000,
        cycle_started_at_ms_chirho: 400,
        cycle_finished_at_ms_chirho: 405,
        outcome_chirho: LedgerConservationCycleOutcomeChirho::GreenChirho {
            head_chirho: head_chirho(),
            money_group_kind_scopes_checked_chirho: 1,
            domain_kind_rollups_checked_chirho: 1,
            global_supplies_checked_chirho: 1,
            work_items_checked_chirho: 3,
        },
    };
    let canonical_chirho = row_chirho.canonical_json_chirho().unwrap();
    assert_eq!(
        parse_ledger_conservation_cycle_row_chirho(&canonical_chirho).unwrap(),
        row_chirho
    );
    let pretty_chirho = serde_json::to_string_pretty(&row_chirho).unwrap();
    assert_eq!(
        parse_ledger_conservation_cycle_row_chirho(pretty_chirho.as_bytes()),
        Err(LedgerConservationCycleWireRefusalChirho::NoncanonicalChirho)
    );
    let mut wrong_schema_chirho = row_chirho.clone();
    wrong_schema_chirho.schema_chirho = "ledger-conservation-cycle-v2-chirho".to_string();
    assert_eq!(
        wrong_schema_chirho.canonical_json_chirho(),
        Err(LedgerConservationCycleWireRefusalChirho::WrongSchemaChirho)
    );
    let mut wrong_cadence_chirho = row_chirho;
    wrong_cadence_chirho.configured_cadence_ms_chirho = 0;
    assert_eq!(
        wrong_cadence_chirho.canonical_json_chirho(),
        Err(LedgerConservationCycleWireRefusalChirho::InvalidCadenceChirho)
    );
    let mut reversed_timing_chirho = wrong_cadence_chirho;
    reversed_timing_chirho.configured_cadence_ms_chirho = 5_000;
    reversed_timing_chirho.cycle_finished_at_ms_chirho =
        reversed_timing_chirho.cycle_started_at_ms_chirho - 1;
    assert_eq!(
        reversed_timing_chirho.canonical_json_chirho(),
        Err(LedgerConservationCycleWireRefusalChirho::InvalidTimingChirho)
    );
}
