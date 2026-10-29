// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Grouped clap argument payloads for `agent_args_chirho`.

#[derive(clap::Args)]
pub struct AgentReportCreateArgsChirho {
    #[arg(long = "producer")]
    pub producer_chirho: String,
    #[arg(long = "category", default_value = "informational")]
    pub category_chirho: String,
    #[arg(long = "priority", default_value = "normal")]
    pub priority_chirho: String,
    #[arg(long = "happened")]
    pub happened_chirho: String,
    #[arg(long = "affected")]
    pub affected_chirho: String,
    #[arg(long = "why-matters")]
    pub why_matters_chirho: String,
    #[arg(long = "evidence", required = true)]
    pub evidence_chirho: Vec<String>,
    #[arg(long = "related-run")]
    pub related_runs_chirho: Vec<String>,
    #[arg(long = "related-effect")]
    pub related_effects_chirho: Vec<String>,
    #[arg(long = "requested-action")]
    pub requested_action_chirho: Option<String>,
}

#[derive(clap::Args)]
pub struct AgentReportsArgsChirho {
    #[arg(long = "producer")]
    pub producer_chirho: Option<String>,
    #[arg(long = "category")]
    pub category_chirho: Option<String>,
}

#[derive(clap::Args)]
pub struct AgentReportBudgetGrantArgsChirho {
    #[arg(long = "agent")]
    pub agent_chirho: String,
    #[arg(long = "granted-by")]
    pub granted_by_chirho: String,
    #[arg(long = "amount-token")]
    pub amount_token_chirho: i64,
    #[arg(long = "reason")]
    pub reason_chirho: String,
}

#[derive(clap::Args)]
pub struct AgentReportBudgetArgsChirho {
    #[arg(long = "agent")]
    pub agent_chirho: String,
}

#[derive(clap::Args)]
pub struct AgentReportChargesArgsChirho {
    #[arg(long = "agent")]
    pub agent_chirho: Option<String>,
}

#[derive(clap::Args)]
pub struct AgentAuthorityRespondArgsChirho {
    #[arg(long = "admin")]
    pub admin_chirho: String,
    #[arg(long = "agent")]
    pub agent_chirho: String,
    #[arg(long = "report-seq")]
    pub report_seq_chirho: u64,
    #[arg(long = "report")]
    pub report_chirho: String,
    #[arg(long = "kind")]
    pub kind_chirho: String,
    #[arg(long = "rule")]
    pub rule_chirho: String,
    #[arg(long = "scope")]
    pub scope_chirho: Option<String>,
    #[arg(long = "budget-token")]
    pub budget_token_chirho: Option<u64>,
    #[arg(long = "param")]
    pub param_chirho: Vec<String>,
    #[arg(long = "reason")]
    pub reason_chirho: String,
}

#[derive(clap::Args)]
pub struct AgentAuthorityShowArgsChirho {
    #[arg(long = "agent")]
    pub agent_chirho: String,
}

#[derive(clap::Args)]
pub struct AgentAuthorityCheckArgsChirho {
    #[arg(long = "agent")]
    pub agent_chirho: String,
    #[arg(long = "scope")]
    pub scope_chirho: String,
    #[arg(long = "cost-token", default_value_t = 0)]
    pub cost_token_chirho: u64,
}

#[derive(clap::Args)]
pub struct AgentAuthorityResponsesArgsChirho {
    #[arg(long = "agent")]
    pub agent_chirho: Option<String>,
}
