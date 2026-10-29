// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Grouped clap argument payloads for `privacy_args_chirho`.

use std::path::PathBuf;

#[derive(clap::Args)]
pub struct PrivacyExportArgsChirho {
    #[arg(long = "subject")]
    pub subject_chirho: String,
    #[arg(long = "requested-by", default_value = "operator/privacy-export")]
    pub requested_by_chirho: String,
    #[arg(long = "include-private")]
    pub include_private_chirho: bool,
}

#[derive(clap::Args)]
pub struct PrivacyEraseArgsChirho {
    #[arg(long = "subject")]
    pub subject_chirho: String,
    #[arg(long = "requested-by")]
    pub requested_by_chirho: String,
    #[arg(long = "reason", default_value = "erasure-request")]
    pub reason_chirho: String,
}

#[derive(clap::Args)]
pub struct PrivacyErasureHistoryArgsChirho {
    #[arg(long = "subject")]
    pub subject_chirho: Option<String>,
}

#[derive(clap::Args)]
pub struct PrivacyRetentionSweepArgsChirho {
    #[arg(long = "retention-days")]
    pub retention_days_chirho: u32,
    #[arg(long = "operator", default_value = "operator/privacy-retention")]
    pub operator_chirho: String,
    #[arg(long = "dry-run")]
    pub dry_run_chirho: bool,
}

#[derive(clap::Args)]
pub struct LegalHoldPlaceArgsChirho {
    #[arg(long = "hold")]
    pub hold_id_chirho: String,
    #[arg(long = "subject")]
    pub subject_chirho: String,
    #[arg(long = "case")]
    pub case_ref_chirho: String,
    #[arg(long = "reason", default_value = "legal-hold")]
    pub reason_chirho: String,
    #[arg(long = "operator", default_value = "operator/legal")]
    pub operator_chirho: String,
}

#[derive(clap::Args)]
pub struct LegalHoldReleaseArgsChirho {
    #[arg(long = "hold")]
    pub hold_id_chirho: String,
    #[arg(long = "reason", default_value = "legal-hold-release")]
    pub reason_chirho: String,
    #[arg(long = "operator", default_value = "operator/legal")]
    pub operator_chirho: String,
}

#[derive(clap::Args)]
pub struct LegalHoldsArgsChirho {
    #[arg(long = "subject")]
    pub subject_chirho: Option<String>,
}

#[derive(clap::Args)]
pub struct PrivacyReplicaRegisterArgsChirho {
    #[arg(long = "replica")]
    pub replica_chirho: String,
    #[arg(long = "root")]
    pub replica_root_chirho: PathBuf,
    #[arg(long = "registered-by", default_value = "operator/privacy-replica")]
    pub registered_by_chirho: String,
}

#[derive(clap::Args)]
pub struct PrivacyBackupPolicySetArgsChirho {
    #[arg(long = "scope", default_value = "durable-backups-ciphertext-only")]
    pub scope_chirho: String,
    #[arg(long = "declared-by", default_value = "operator/privacy-backup")]
    pub declared_by_chirho: String,
}

#[derive(clap::Args)]
pub struct PrivacyErasurePropagateArgsChirho {
    #[arg(long = "erasure")]
    pub erasure_chirho: u64,
    #[arg(long = "replica")]
    pub replica_chirho: String,
    #[arg(long = "requested-by", default_value = "operator/privacy-replica")]
    pub requested_by_chirho: String,
}

#[derive(clap::Args)]
pub struct PrivacyErasurePropagationsArgsChirho {
    #[arg(long = "subject")]
    pub subject_chirho: Option<String>,
    #[arg(long = "replica")]
    pub replica_chirho: Option<String>,
}

#[derive(clap::Args)]
pub struct PrivacyVerifyArgsChirho {
    #[arg(long = "json")]
    pub json_chirho: bool,
    #[arg(long = "fail-on-empty-evidence")]
    pub fail_on_empty_evidence_chirho: bool,
}

#[derive(clap::Args)]
pub struct PrivacyScanArgsChirho {
    #[arg(long = "json")]
    pub json_chirho: bool,
    #[arg(long = "fail-on-findings")]
    pub fail_on_findings_chirho: bool,
}
