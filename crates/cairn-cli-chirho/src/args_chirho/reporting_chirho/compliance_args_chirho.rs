// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Grouped clap argument payloads for `compliance_args_chirho`.

#[derive(clap::Args)]
pub struct ComplianceEvidenceGenerateArgsChirho {
    #[arg(long = "framework")]
    pub frameworks_chirho: Vec<String>,
    #[arg(long = "period-start-ms", default_value_t = 0)]
    pub period_start_ms_chirho: u64,
    #[arg(long = "period-end-ms")]
    pub period_end_ms_chirho: Option<u64>,
    #[arg(long = "generated-by", default_value = "operator/compliance-evidence")]
    pub generated_by_chirho: String,
    #[arg(long = "fail-on-failed-sources")]
    pub fail_on_failed_sources_chirho: bool,
    #[arg(long = "fail-on-coverage-gaps")]
    pub fail_on_coverage_gaps_chirho: bool,
    #[arg(long = "fail-on-manual-controls")]
    pub fail_on_manual_controls_chirho: bool,
}

#[derive(clap::Args)]
pub struct ComplianceEvidenceVerifyArgsChirho {
    pub pack_chirho: Option<String>,
    #[arg(long = "fail-on-failed-sources")]
    pub fail_on_failed_sources_chirho: bool,
    #[arg(long = "fail-on-coverage-gaps")]
    pub fail_on_coverage_gaps_chirho: bool,
    #[arg(long = "fail-on-manual-controls")]
    pub fail_on_manual_controls_chirho: bool,
}

#[derive(clap::Args)]
pub struct DataResidencySetArgsChirho {
    #[arg(long = "data-region", required = true)]
    pub data_regions_chirho: Vec<String>,
    #[arg(long = "processing-region", required = true)]
    pub processing_regions_chirho: Vec<String>,
    #[arg(long = "operator", default_value = "operator/data-residency")]
    pub operator_chirho: String,
    #[arg(long = "allow-unattested-processing")]
    pub allow_unattested_processing_chirho: bool,
}

#[derive(clap::Args)]
pub struct DataResidencyAttestArgsChirho {
    #[arg(long = "host-region")]
    pub host_region_chirho: String,
    #[arg(long = "processing-region")]
    pub processing_region_chirho: String,
    #[arg(long = "data-region")]
    pub data_region_chirho: String,
    #[arg(long = "region-source", default_value = "operator-declared")]
    pub region_source_chirho: String,
    #[arg(long = "operator", default_value = "operator/data-residency")]
    pub operator_chirho: String,
}

#[derive(clap::Args)]
pub struct DataResidencyCheckPlacementArgsChirho {
    #[arg(long = "candidate")]
    pub candidate_chirho: String,
}

#[derive(clap::Args)]
pub struct DataResidencyVerifyArgsChirho {
    #[arg(long = "fail-on-violations")]
    pub fail_on_violations_chirho: bool,
}

#[derive(clap::Args)]
pub struct VolatileEffectsArgsChirho {
    #[arg(long = "json")]
    pub json_chirho: bool,
}

#[derive(clap::Args)]
pub struct VolatileEffectsVerifyArgsChirho {
    #[arg(long = "json")]
    pub json_chirho: bool,
}
