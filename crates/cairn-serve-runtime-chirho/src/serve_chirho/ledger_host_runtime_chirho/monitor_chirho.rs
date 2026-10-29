// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Cadenced, detect-only conservation monitoring for the open ledger host.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf6-regenesis-boundary-chirho.md`.

use super::LedgerHostProjectionReadPortChirho;
use anyhow::Result;
use cairn_config_chirho::config_chirho::{
    MAX_LEDGER_MONITOR_CADENCE_MS_CHIRHO, MIN_LEDGER_MONITOR_CADENCE_MS_CHIRHO,
};
use cairn_ledger_composition_chirho::composition_chirho::{
    JournalConservationSourceChirho, JournalConservationSourceErrorChirho,
};
use cairn_ledger_conservation_monitor_chirho::{
    run_conservation_monitor_once_chirho, ConservationGreenEvidenceChirho,
    ConservationHeadCoordinateChirho, ConservationIncidentChirho, ConservationIncidentKindChirho,
    ConservationMonitorFailureChirho,
};
use cairn_ledger_host_chirho::{FsMonitorEvidenceSinkChirho, PlatformPolicyMintAuthorityChirho};
use cairn_ledger_log_chirho::journal_chirho::JournalPortsChirho;
use cairn_ledger_log_chirho::ports_chirho::LedgerClockPortChirho;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

pub const LEDGER_CONSERVATION_CYCLE_SCHEMA_V1_CHIRHO: &str = "ledger-conservation-cycle-v1-chirho";
const MAX_LEDGER_CONSERVATION_TOKEN_BYTES_CHIRHO: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerConservationHeadEvidenceChirho {
    pub epoch_chirho: u64,
    pub checkpoint_digest_chirho: String,
    pub covered_record_count_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum LedgerConservationIncidentEvidenceChirho {
    #[serde(rename = "duplicate-domain-kind-rollup-chirho")]
    DuplicateDomainKindRollupChirho {
        money_group_id_chirho: String,
        cluster_id_chirho: String,
        kind_id_chirho: String,
    },
    #[serde(rename = "duplicate-global-kind-supply-chirho")]
    DuplicateGlobalKindSupplyChirho {
        money_group_id_chirho: String,
        kind_id_chirho: String,
    },
    #[serde(rename = "missing-global-kind-supply-chirho")]
    MissingGlobalKindSupplyChirho {
        money_group_id_chirho: String,
        kind_id_chirho: String,
    },
    #[serde(rename = "global-supply-without-domain-rollup-chirho")]
    GlobalSupplyWithoutDomainRollupChirho {
        money_group_id_chirho: String,
        kind_id_chirho: String,
    },
    #[serde(rename = "arithmetic-overflow-chirho")]
    ArithmeticOverflowChirho,
    #[serde(rename = "domain-drift-chirho")]
    DomainDriftChirho {
        money_group_id_chirho: String,
        cluster_id_chirho: String,
        kind_id_chirho: String,
        #[serde(with = "canonical_u128_chirho")]
        account_net_chirho: u128,
        #[serde(with = "canonical_u128_chirho")]
        local_supply_chirho: u128,
    },
    #[serde(rename = "global-kind-drift-chirho")]
    GlobalKindDriftChirho {
        money_group_id_chirho: String,
        kind_id_chirho: String,
        #[serde(with = "canonical_u128_chirho")]
        account_net_chirho: u128,
        #[serde(with = "canonical_u128_chirho")]
        supply_chirho: u128,
    },
}

mod canonical_u128_chirho {
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S>(
        value_chirho: &u128,
        serializer_chirho: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer_chirho.serialize_str(&value_chirho.to_string())
    }

    pub(super) fn deserialize<'de, D>(deserializer_chirho: D) -> std::result::Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let decimal_chirho = String::deserialize(deserializer_chirho)?;
        if decimal_chirho.is_empty()
            || (decimal_chirho.len() > 1 && decimal_chirho.starts_with('0'))
            || !decimal_chirho
                .bytes()
                .all(|byte_chirho| byte_chirho.is_ascii_digit())
        {
            return Err(D::Error::custom(
                "ledger conservation amount is not canonical decimal",
            ));
        }
        let value_chirho = decimal_chirho
            .parse::<u128>()
            .map_err(|_error_chirho| D::Error::custom("ledger conservation amount exceeds u128"))?;
        if value_chirho.to_string() != decimal_chirho {
            return Err(D::Error::custom(
                "ledger conservation amount is not canonical decimal",
            ));
        }
        Ok(value_chirho)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LedgerConservationRefusalCodeChirho {
    #[serde(rename = "kind-registry-unavailable-chirho")]
    KindRegistryUnavailableChirho,
    #[serde(rename = "journal-recovery-required-chirho")]
    JournalRecoveryRequiredChirho,
    #[serde(rename = "journal-open-unavailable-chirho")]
    JournalOpenUnavailableChirho,
    #[serde(rename = "journal-line-unavailable-chirho")]
    JournalLineUnavailableChirho,
    #[serde(rename = "journal-line-noncanonical-chirho")]
    JournalLineNoncanonicalChirho,
    #[serde(rename = "journal-mixed-cut-chirho")]
    JournalMixedCutChirho,
    #[serde(rename = "snapshot-derivation-refused-chirho")]
    SnapshotDerivationRefusedChirho,
}

/// The variant owns its payload, so RED/REFUSED cannot be serialized as GREEN by changing a flag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict_chirho", deny_unknown_fields)]
pub enum LedgerConservationCycleOutcomeChirho {
    #[serde(rename = "green-chirho")]
    GreenChirho {
        head_chirho: LedgerConservationHeadEvidenceChirho,
        money_group_kind_scopes_checked_chirho: u64,
        domain_kind_rollups_checked_chirho: u64,
        global_supplies_checked_chirho: u64,
        work_items_checked_chirho: u64,
    },
    #[serde(rename = "red-chirho")]
    RedChirho {
        head_chirho: LedgerConservationHeadEvidenceChirho,
        incident_chirho: LedgerConservationIncidentEvidenceChirho,
    },
    #[serde(rename = "refused-chirho")]
    RefusedChirho {
        reason_chirho: LedgerConservationRefusalCodeChirho,
    },
}

/// One unsigned operational observation. It is never journal admission or money evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerConservationCycleRowChirho {
    pub schema_chirho: String,
    pub configured_cadence_ms_chirho: u64,
    pub cycle_started_at_ms_chirho: u64,
    pub cycle_finished_at_ms_chirho: u64,
    pub outcome_chirho: LedgerConservationCycleOutcomeChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerConservationCycleWireRefusalChirho {
    InvalidJsonChirho,
    WrongSchemaChirho,
    InvalidCadenceChirho,
    InvalidTimingChirho,
    InvalidEvidenceChirho,
    NoncanonicalChirho,
}

impl fmt::Display for LedgerConservationCycleWireRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::InvalidJsonChirho => "ledger conservation cycle row is invalid JSON",
            Self::WrongSchemaChirho => "ledger conservation cycle row has the wrong schema",
            Self::InvalidCadenceChirho => {
                "ledger conservation cycle row carries an invalid configured cadence"
            }
            Self::InvalidTimingChirho => {
                "ledger conservation cycle row carries invalid cycle timing"
            }
            Self::InvalidEvidenceChirho => {
                "ledger conservation cycle row carries invalid bounded evidence"
            }
            Self::NoncanonicalChirho => "ledger conservation cycle row is not canonical",
        })
    }
}

impl Error for LedgerConservationCycleWireRefusalChirho {}

impl LedgerConservationCycleRowChirho {
    pub fn canonical_json_chirho(
        &self,
    ) -> std::result::Result<Vec<u8>, LedgerConservationCycleWireRefusalChirho> {
        self.validate_chirho()?;
        serde_json::to_vec(self)
            .map_err(|_error_chirho| LedgerConservationCycleWireRefusalChirho::InvalidJsonChirho)
    }

    fn validate_chirho(&self) -> std::result::Result<(), LedgerConservationCycleWireRefusalChirho> {
        if self.schema_chirho != LEDGER_CONSERVATION_CYCLE_SCHEMA_V1_CHIRHO {
            return Err(LedgerConservationCycleWireRefusalChirho::WrongSchemaChirho);
        }
        if !(MIN_LEDGER_MONITOR_CADENCE_MS_CHIRHO..=MAX_LEDGER_MONITOR_CADENCE_MS_CHIRHO)
            .contains(&self.configured_cadence_ms_chirho)
        {
            return Err(LedgerConservationCycleWireRefusalChirho::InvalidCadenceChirho);
        }
        if self.cycle_finished_at_ms_chirho < self.cycle_started_at_ms_chirho {
            return Err(LedgerConservationCycleWireRefusalChirho::InvalidTimingChirho);
        }
        validate_outcome_evidence_chirho(&self.outcome_chirho)?;
        Ok(())
    }
}

fn validate_outcome_evidence_chirho(
    outcome_chirho: &LedgerConservationCycleOutcomeChirho,
) -> std::result::Result<(), LedgerConservationCycleWireRefusalChirho> {
    match outcome_chirho {
        LedgerConservationCycleOutcomeChirho::GreenChirho { head_chirho, .. }
        | LedgerConservationCycleOutcomeChirho::RedChirho { head_chirho, .. } => {
            validate_head_evidence_chirho(head_chirho)?;
        }
        LedgerConservationCycleOutcomeChirho::RefusedChirho { .. } => {}
    }
    if let LedgerConservationCycleOutcomeChirho::RedChirho {
        incident_chirho, ..
    } = outcome_chirho
    {
        validate_incident_evidence_chirho(incident_chirho)?;
    }
    Ok(())
}

fn validate_head_evidence_chirho(
    head_chirho: &LedgerConservationHeadEvidenceChirho,
) -> std::result::Result<(), LedgerConservationCycleWireRefusalChirho> {
    if head_chirho.checkpoint_digest_chirho.len() != 64
        || !head_chirho
            .checkpoint_digest_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
    {
        return Err(LedgerConservationCycleWireRefusalChirho::InvalidEvidenceChirho);
    }
    Ok(())
}

fn validate_incident_evidence_chirho(
    incident_chirho: &LedgerConservationIncidentEvidenceChirho,
) -> std::result::Result<(), LedgerConservationCycleWireRefusalChirho> {
    let tokens_chirho: &[&str] = match incident_chirho {
        LedgerConservationIncidentEvidenceChirho::DuplicateDomainKindRollupChirho {
            money_group_id_chirho,
            cluster_id_chirho,
            kind_id_chirho,
        }
        | LedgerConservationIncidentEvidenceChirho::DomainDriftChirho {
            money_group_id_chirho,
            cluster_id_chirho,
            kind_id_chirho,
            ..
        } => &[money_group_id_chirho, cluster_id_chirho, kind_id_chirho],
        LedgerConservationIncidentEvidenceChirho::DuplicateGlobalKindSupplyChirho {
            money_group_id_chirho,
            kind_id_chirho,
        }
        | LedgerConservationIncidentEvidenceChirho::MissingGlobalKindSupplyChirho {
            money_group_id_chirho,
            kind_id_chirho,
        }
        | LedgerConservationIncidentEvidenceChirho::GlobalSupplyWithoutDomainRollupChirho {
            money_group_id_chirho,
            kind_id_chirho,
        }
        | LedgerConservationIncidentEvidenceChirho::GlobalKindDriftChirho {
            money_group_id_chirho,
            kind_id_chirho,
            ..
        } => &[money_group_id_chirho, kind_id_chirho],
        LedgerConservationIncidentEvidenceChirho::ArithmeticOverflowChirho => &[],
    };
    if tokens_chirho.iter().any(|token_chirho| {
        token_chirho.is_empty()
            || token_chirho.len() > MAX_LEDGER_CONSERVATION_TOKEN_BYTES_CHIRHO
            || token_chirho.contains('@')
            || token_chirho
                .chars()
                .any(|char_chirho| char_chirho.is_control() || char_chirho.is_whitespace())
    }) {
        return Err(LedgerConservationCycleWireRefusalChirho::InvalidEvidenceChirho);
    }
    Ok(())
}

pub fn parse_ledger_conservation_cycle_row_chirho(
    bytes_chirho: &[u8],
) -> std::result::Result<LedgerConservationCycleRowChirho, LedgerConservationCycleWireRefusalChirho>
{
    let row_chirho: LedgerConservationCycleRowChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_error_chirho| LedgerConservationCycleWireRefusalChirho::InvalidJsonChirho)?;
    row_chirho.validate_chirho()?;
    if row_chirho.canonical_json_chirho()? != bytes_chirho {
        return Err(LedgerConservationCycleWireRefusalChirho::NoncanonicalChirho);
    }
    Ok(row_chirho)
}

/// Fixed-input-only paging. No path, identifier, incident detail, or error text can cross it.
pub(crate) trait LedgerConservationAlarmPortChirho: Send + Sync {
    fn page_red_chirho(&self);
    fn page_refused_chirho(&self);
    fn page_evidence_write_chirho(&self);
}

pub(crate) struct FixedLedgerConservationAlarmChirho;

impl LedgerConservationAlarmPortChirho for FixedLedgerConservationAlarmChirho {
    fn page_red_chirho(&self) {
        let _ = writeln!(
            std::io::stderr().lock(),
            "CAIRN_LEDGER_CONSERVATION_RED_CHIRHO"
        );
    }

    fn page_refused_chirho(&self) {
        let _ = writeln!(
            std::io::stderr().lock(),
            "CAIRN_LEDGER_CONSERVATION_REFUSED_CHIRHO"
        );
    }

    fn page_evidence_write_chirho(&self) {
        let _ = writeln!(
            std::io::stderr().lock(),
            "CAIRN_LEDGER_CONSERVATION_EVIDENCE_WRITE_REFUSED_CHIRHO"
        );
    }
}

pub(crate) trait LedgerMonitorCadenceWaitPortChirho: Send + Sync {
    fn wait_chirho(
        &self,
        cadence_chirho: Duration,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

pub(crate) struct TokioLedgerMonitorCadenceWaitChirho;

impl LedgerMonitorCadenceWaitPortChirho for TokioLedgerMonitorCadenceWaitChirho {
    fn wait_chirho(
        &self,
        cadence_chirho: Duration,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(cadence_chirho))
    }
}

impl LedgerHostProjectionReadPortChirho {
    pub fn run_conservation_cycle_once_chirho(&self) -> Result<LedgerConservationCycleRowChirho> {
        self.run_conservation_cycle_with_alarm_chirho(&FixedLedgerConservationAlarmChirho)
    }

    pub(crate) fn run_conservation_cycle_with_alarm_chirho(
        &self,
        alarm_chirho: &dyn LedgerConservationAlarmPortChirho,
    ) -> Result<LedgerConservationCycleRowChirho> {
        // The cadenced monitor and the test-kind operator share this exact host. Serialize the
        // complete read-and-evidence cycle so their JSONL rows cannot depend on concurrent append
        // behavior and each returned row names one complete observed ledger cut.
        let _cycle_guard_chirho =
            self.conservation_cycle_lock_chirho
                .lock()
                .map_err(|_error_chirho| {
                    super::LedgerHostRuntimeRefusalChirho::ConservationCycleUnavailableChirho
                })?;
        let cycle_started_at_ms_chirho = self.clock_chirho.physical_now_ms_chirho();
        let outcome_chirho = self.load_conservation_outcome_chirho();
        let cycle_finished_at_ms_chirho = self.clock_chirho.physical_now_ms_chirho();
        record_cycle_outcome_chirho(
            &self.monitor_evidence_sink_chirho,
            &self.monitor_evidence_path_chirho,
            self.monitor_cadence_ms_chirho,
            cycle_started_at_ms_chirho,
            cycle_finished_at_ms_chirho,
            outcome_chirho,
            alarm_chirho,
        )
    }

    pub(crate) async fn run_conservation_monitor_loop_chirho(
        self: Arc<Self>,
        wait_chirho: Arc<dyn LedgerMonitorCadenceWaitPortChirho>,
        alarm_chirho: Arc<dyn LedgerConservationAlarmPortChirho>,
    ) {
        let cadence_chirho = Duration::from_millis(self.monitor_cadence_ms_chirho);
        loop {
            // Waiting first preserves boot-no-write and uses the configured cadence from cycle one.
            wait_chirho.wait_chirho(cadence_chirho).await;
            let cycle_chirho = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.run_conservation_cycle_with_alarm_chirho(alarm_chirho.as_ref())
            }));
            if cycle_chirho.is_err() {
                alarm_chirho.page_refused_chirho();
            }
            // Typed failures have already produced either a durable row or the evidence-write page.
            // The observer never returns an error into the serve future and retries next cadence.
        }
    }

    fn load_conservation_outcome_chirho(&self) -> LedgerConservationCycleOutcomeChirho {
        let kind_registry_chirho = match self.load_kind_registry_chirho() {
            Ok(kind_registry_chirho) => kind_registry_chirho,
            Err(_error_chirho) => {
                return LedgerConservationCycleOutcomeChirho::RefusedChirho {
                    reason_chirho:
                        LedgerConservationRefusalCodeChirho::KindRegistryUnavailableChirho,
                }
            }
        };
        let authority_chirho = PlatformPolicyMintAuthorityChirho::new_chirho(&kind_registry_chirho);
        let journal_ports_chirho = JournalPortsChirho {
            storage_chirho: &self.storage_chirho,
            signer_chirho: self.signers_chirho.journal_signer_chirho(),
            clock_chirho: &self.clock_chirho,
            membership_chirho: &self.membership_chirho,
            kind_registry_chirho: &kind_registry_chirho,
            authority_chirho: &authority_chirho,
        };
        let source_chirho = JournalConservationSourceChirho {
            journal_ports_chirho,
            journal_path_chirho: self.journal_path_chirho.clone(),
            cluster_chirho: self.cluster_chirho.clone(),
            money_group_chirho: self.money_group_chirho.clone(),
        };
        match run_conservation_monitor_once_chirho(&source_chirho) {
            Ok(evidence_chirho) => green_outcome_chirho(evidence_chirho),
            Err(ConservationMonitorFailureChirho::IncidentChirho(incident_chirho)) => {
                red_outcome_chirho(incident_chirho)
            }
            Err(ConservationMonitorFailureChirho::VerifiedSnapshotUnavailableChirho(
                error_chirho,
            )) => LedgerConservationCycleOutcomeChirho::RefusedChirho {
                reason_chirho: refusal_code_chirho(&error_chirho),
            },
        }
    }
}

fn record_cycle_outcome_chirho(
    sink_chirho: &FsMonitorEvidenceSinkChirho,
    evidence_path_chirho: &str,
    configured_cadence_ms_chirho: u64,
    cycle_started_at_ms_chirho: u64,
    cycle_finished_at_ms_chirho: u64,
    outcome_chirho: LedgerConservationCycleOutcomeChirho,
    alarm_chirho: &dyn LedgerConservationAlarmPortChirho,
) -> Result<LedgerConservationCycleRowChirho> {
    let row_chirho = LedgerConservationCycleRowChirho {
        schema_chirho: LEDGER_CONSERVATION_CYCLE_SCHEMA_V1_CHIRHO.to_string(),
        configured_cadence_ms_chirho,
        cycle_started_at_ms_chirho,
        cycle_finished_at_ms_chirho,
        outcome_chirho,
    };
    let canonical_chirho = match row_chirho.canonical_json_chirho() {
        Ok(canonical_chirho) => canonical_chirho,
        Err(error_chirho) => {
            alarm_chirho.page_evidence_write_chirho();
            return Err(error_chirho.into());
        }
    };
    let append_result_chirho =
        sink_chirho.append_operational_row_chirho(evidence_path_chirho, &canonical_chirho);
    match &row_chirho.outcome_chirho {
        LedgerConservationCycleOutcomeChirho::GreenChirho { .. } => {}
        LedgerConservationCycleOutcomeChirho::RedChirho { .. } => {
            alarm_chirho.page_red_chirho();
        }
        LedgerConservationCycleOutcomeChirho::RefusedChirho { .. } => {
            alarm_chirho.page_refused_chirho();
        }
    }
    if let Err(error_chirho) = append_result_chirho {
        // A missing row is represented by this fixed page, so a sequence gap is not silent.
        alarm_chirho.page_evidence_write_chirho();
        return Err(error_chirho);
    }
    Ok(row_chirho)
}

fn green_outcome_chirho(
    evidence_chirho: ConservationGreenEvidenceChirho,
) -> LedgerConservationCycleOutcomeChirho {
    let Ok(money_group_kind_scopes_checked_chirho) =
        u64::try_from(evidence_chirho.money_group_kind_scopes_checked_chirho)
    else {
        return LedgerConservationCycleOutcomeChirho::RefusedChirho {
            reason_chirho: LedgerConservationRefusalCodeChirho::SnapshotDerivationRefusedChirho,
        };
    };
    let Ok(domain_kind_rollups_checked_chirho) =
        u64::try_from(evidence_chirho.domain_kind_rollups_checked_chirho)
    else {
        return LedgerConservationCycleOutcomeChirho::RefusedChirho {
            reason_chirho: LedgerConservationRefusalCodeChirho::SnapshotDerivationRefusedChirho,
        };
    };
    let Ok(global_supplies_checked_chirho) =
        u64::try_from(evidence_chirho.global_supplies_checked_chirho)
    else {
        return LedgerConservationCycleOutcomeChirho::RefusedChirho {
            reason_chirho: LedgerConservationRefusalCodeChirho::SnapshotDerivationRefusedChirho,
        };
    };
    let Ok(work_items_checked_chirho) = u64::try_from(evidence_chirho.work_items_checked_chirho)
    else {
        return LedgerConservationCycleOutcomeChirho::RefusedChirho {
            reason_chirho: LedgerConservationRefusalCodeChirho::SnapshotDerivationRefusedChirho,
        };
    };
    LedgerConservationCycleOutcomeChirho::GreenChirho {
        head_chirho: head_evidence_chirho(evidence_chirho.head_chirho),
        money_group_kind_scopes_checked_chirho,
        domain_kind_rollups_checked_chirho,
        global_supplies_checked_chirho,
        work_items_checked_chirho,
    }
}

fn red_outcome_chirho(
    incident_chirho: ConservationIncidentChirho,
) -> LedgerConservationCycleOutcomeChirho {
    LedgerConservationCycleOutcomeChirho::RedChirho {
        head_chirho: head_evidence_chirho(incident_chirho.head_chirho),
        incident_chirho: incident_evidence_chirho(*incident_chirho.kind_chirho),
    }
}

fn head_evidence_chirho(
    head_chirho: ConservationHeadCoordinateChirho,
) -> LedgerConservationHeadEvidenceChirho {
    LedgerConservationHeadEvidenceChirho {
        epoch_chirho: head_chirho.epoch_chirho,
        checkpoint_digest_chirho: head_chirho.checkpoint_digest_chirho.0,
        covered_record_count_chirho: head_chirho.covered_record_count_chirho,
    }
}

fn incident_evidence_chirho(
    incident_chirho: ConservationIncidentKindChirho,
) -> LedgerConservationIncidentEvidenceChirho {
    match incident_chirho {
        ConservationIncidentKindChirho::DuplicateDomainKindRollupChirho {
            domain_chirho,
            kind_id_chirho,
        } => LedgerConservationIncidentEvidenceChirho::DuplicateDomainKindRollupChirho {
            money_group_id_chirho: domain_chirho.money_group_chirho.0,
            cluster_id_chirho: domain_chirho.cluster_chirho.0,
            kind_id_chirho: kind_id_chirho.0,
        },
        ConservationIncidentKindChirho::DuplicateGlobalKindSupplyChirho {
            money_group_chirho,
            kind_id_chirho,
        } => LedgerConservationIncidentEvidenceChirho::DuplicateGlobalKindSupplyChirho {
            money_group_id_chirho: money_group_chirho.0,
            kind_id_chirho: kind_id_chirho.0,
        },
        ConservationIncidentKindChirho::MissingGlobalKindSupplyChirho {
            money_group_chirho,
            kind_id_chirho,
        } => LedgerConservationIncidentEvidenceChirho::MissingGlobalKindSupplyChirho {
            money_group_id_chirho: money_group_chirho.0,
            kind_id_chirho: kind_id_chirho.0,
        },
        ConservationIncidentKindChirho::GlobalSupplyWithoutDomainRollupChirho {
            money_group_chirho,
            kind_id_chirho,
        } => LedgerConservationIncidentEvidenceChirho::GlobalSupplyWithoutDomainRollupChirho {
            money_group_id_chirho: money_group_chirho.0,
            kind_id_chirho: kind_id_chirho.0,
        },
        ConservationIncidentKindChirho::ArithmeticOverflowChirho => {
            LedgerConservationIncidentEvidenceChirho::ArithmeticOverflowChirho
        }
        ConservationIncidentKindChirho::DomainDriftChirho {
            domain_chirho,
            kind_id_chirho,
            account_net_chirho,
            local_supply_chirho,
        } => LedgerConservationIncidentEvidenceChirho::DomainDriftChirho {
            money_group_id_chirho: domain_chirho.money_group_chirho.0,
            cluster_id_chirho: domain_chirho.cluster_chirho.0,
            kind_id_chirho: kind_id_chirho.0,
            account_net_chirho,
            local_supply_chirho,
        },
        ConservationIncidentKindChirho::GlobalKindDriftChirho {
            money_group_chirho,
            kind_id_chirho,
            account_net_chirho,
            supply_chirho,
        } => LedgerConservationIncidentEvidenceChirho::GlobalKindDriftChirho {
            money_group_id_chirho: money_group_chirho.0,
            kind_id_chirho: kind_id_chirho.0,
            account_net_chirho,
            supply_chirho,
        },
    }
}

fn refusal_code_chirho(
    error_chirho: &JournalConservationSourceErrorChirho,
) -> LedgerConservationRefusalCodeChirho {
    match error_chirho {
        JournalConservationSourceErrorChirho::JournalOpenChirho(
            cairn_ledger_log_chirho::journal_chirho::JournalErrorChirho::ReadOnlyRecoveryRequiredChirho {
                ..
            },
        ) => LedgerConservationRefusalCodeChirho::JournalRecoveryRequiredChirho,
        JournalConservationSourceErrorChirho::JournalOpenChirho(_) => {
            LedgerConservationRefusalCodeChirho::JournalOpenUnavailableChirho
        }
        JournalConservationSourceErrorChirho::JournalLineReadChirho(_) => {
            LedgerConservationRefusalCodeChirho::JournalLineUnavailableChirho
        }
        JournalConservationSourceErrorChirho::JournalLineParseChirho(_) => {
            LedgerConservationRefusalCodeChirho::JournalLineNoncanonicalChirho
        }
        JournalConservationSourceErrorChirho::MixedCutChirho { .. } => {
            LedgerConservationRefusalCodeChirho::JournalMixedCutChirho
        }
        JournalConservationSourceErrorChirho::SnapshotDerivationChirho(_) => {
            LedgerConservationRefusalCodeChirho::SnapshotDerivationRefusedChirho
        }
    }
}

#[cfg(test)]
#[path = "monitor_chirho/monitor_tests_chirho.rs"]
mod monitor_tests_chirho;
