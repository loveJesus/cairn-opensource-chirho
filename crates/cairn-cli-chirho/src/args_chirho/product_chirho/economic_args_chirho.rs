// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Grouped clap argument payloads for `economic_args_chirho`.

use std::path::PathBuf;

#[derive(clap::Args)]
pub struct MeterRunArgsChirho {
    pub node_chirho: String,
    #[arg(long = "account")]
    pub account_chirho: String,
    #[arg(long = "input")]
    pub input_chirho: Option<String>,
}

#[derive(clap::Args)]
pub struct PriceBookSetArgsChirho {
    pub app_chirho: String,
    #[arg(long = "owner")]
    pub owner_chirho: String,
    #[arg(long = "request-price")]
    pub request_price_chirho: Option<i64>,
    #[arg(long = "effect-price")]
    pub effect_prices_chirho: Vec<String>,
    /// Reserved owner markup over external provider cost, in basis points.
    #[arg(long = "external-markup-bps", default_value_t = 0)]
    pub external_markup_bps_chirho: i64,
}

#[derive(clap::Args)]
pub struct BillingPolicySetArgsChirho {
    pub app_chirho: String,
    #[arg(long = "owner")]
    pub owner_chirho: String,
    #[arg(long = "mode")]
    pub mode_chirho: String,
    #[arg(long = "per-user-budget")]
    pub per_user_budget_chirho: Option<i64>,
    #[arg(long = "overage")]
    pub overage_chirho: Option<String>,
    #[arg(long = "effect-policy")]
    pub effect_policies_chirho: Vec<String>,
    #[arg(long = "per-user-spend-cap")]
    pub per_user_spend_cap_chirho: Option<i64>,
    #[arg(long = "app-spend-cap")]
    pub app_spend_cap_chirho: Option<i64>,
}

#[derive(clap::Args)]
pub struct BillingRollupArgsChirho {
    #[arg(long = "axis")]
    pub axis_chirho: String,
}

#[derive(clap::Args)]
pub struct BillingRefundArgsChirho {
    pub usage_seq_chirho: u64,
    #[arg(long = "reason")]
    pub reason_chirho: String,
}

#[derive(clap::Args)]
pub struct ResourcePolicySetArgsChirho {
    pub app_chirho: String,
    #[arg(long = "owner")]
    pub owner_chirho: String,
    #[arg(long = "file")]
    pub file_chirho: PathBuf,
}

#[derive(clap::Args)]
pub struct ResourcePolicyUnsetArgsChirho {
    pub app_chirho: String,
    #[arg(long = "owner")]
    pub owner_chirho: String,
}

#[derive(clap::Args)]
pub struct ResourceUseArgsChirho {
    pub app_chirho: String,
    #[arg(long = "user")]
    pub user_chirho: String,
    #[arg(long = "actor")]
    pub actor_chirho: Option<String>,
    #[arg(long = "section")]
    pub section_chirho: String,
    #[arg(long = "action")]
    pub action_chirho: String,
    #[arg(long = "effect")]
    pub effect_chirho: Option<String>,
    #[arg(long = "run")]
    pub run_chirho: Option<String>,
    #[arg(long = "bridge")]
    pub bridges_chirho: Vec<String>,
}

#[derive(clap::Args)]
pub struct ResourceUsageArgsChirho {
    #[arg(long = "app")]
    pub app_chirho: Option<String>,
}

#[derive(clap::Args)]
pub struct ResourceRollupArgsChirho {
    #[arg(long = "axis")]
    pub axis_chirho: String,
    #[arg(long = "app")]
    pub app_chirho: Option<String>,
}

#[derive(clap::Args)]
pub struct ResourceStatusArgsChirho {
    #[arg(long = "app")]
    pub app_chirho: Option<String>,
    #[arg(long = "user")]
    pub user_chirho: Option<String>,
}
