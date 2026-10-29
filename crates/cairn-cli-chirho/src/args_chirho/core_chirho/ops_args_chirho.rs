// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Grouped clap argument payloads for `ops_args_chirho`.

use std::path::PathBuf;

#[derive(clap::Args)]
pub struct SecretSetArgsChirho {
    #[arg(long = "name")]
    pub name_chirho: String,
    #[arg(long = "file")]
    pub file_chirho: PathBuf,
}

#[derive(clap::Args)]
pub struct SecretRefArgsChirho {
    #[arg(long = "name")]
    pub name_chirho: String,
}

#[derive(clap::Args)]
pub struct PublishArgsChirho {
    pub name_chirho: String,
    pub dag_chirho: String,
    #[arg(long = "owner")]
    pub owner_chirho: String,
    #[arg(long = "server")]
    pub server_chirho: String,
    #[arg(long = "token")]
    pub token_chirho: Option<String>,
}

#[derive(clap::Args)]
pub struct ServeArgsChirho {
    #[arg(long = "port", default_value_t = 8787)]
    pub port_chirho: u16,
    #[arg(long = "registration-token", default_value = "")]
    pub registration_token_chirho: String,
    #[arg(long = "allow-platform-root-chirho")]
    pub allow_platform_root_chirho: bool,
    /// Successful sign-ins per principal per hour (default 10; brick 4a). `up` reads it from its reviewed TOML.
    #[arg(long = "sign-in-principal-successes-per-hour-chirho")]
    pub sign_in_principal_successes_per_hour_chirho: Option<u64>,
    /// Successful sign-ins per client network per hour (default 60; brick 4a). `up` reads it from its reviewed TOML.
    #[arg(long = "sign-in-source-successes-per-hour-chirho")]
    pub sign_in_source_successes_per_hour_chirho: Option<u64>,
    /// Failed attempts per client network per 15-minute window, across login, token and recover (default 100; R12).
    /// `up` reads it from its reviewed TOML.
    #[arg(long = "sign-in-source-failures-per-window-chirho")]
    pub sign_in_source_failures_per_window_chirho: Option<u64>,
}

#[derive(clap::Args)]
pub struct UpArgsChirho {
    #[arg(long = "config")]
    pub config_path_chirho: Option<PathBuf>,
    /// Reviewed BLAKE3 of the exact config bytes, supplied outside the config's filesystem.
    #[arg(long = "expected-config-digest-chirho")]
    pub expected_config_digest_chirho: String,
    #[arg(long = "allow-platform-root-chirho")]
    pub allow_platform_root_chirho: bool,
}

#[derive(clap::Args)]
pub struct LedgerRegenesisArgsChirho {
    #[arg(long = "config-chirho")]
    pub config_path_chirho: PathBuf,
    #[arg(long = "plan-chirho")]
    pub plan_path_chirho: PathBuf,
    #[arg(long = "expected-plan-digest-chirho")]
    pub expected_plan_digest_chirho: String,
    #[arg(long = "issuer-secret-name-chirho")]
    pub issuer_secret_name_chirho: String,
    #[arg(long = "activation-authorization-chirho")]
    pub activation_authorization_path_chirho: PathBuf,
    #[arg(long = "expected-activation-authorization-digest-chirho")]
    pub expected_activation_authorization_digest_chirho: String,
}

/// Dev-only served-LLM ledger bootstrap: fund a payer via the single-node regenesis mint. The root
/// comes from the global `--root`; storage layout is fixed by the bootstrap and refuses a production
/// posture.
#[derive(clap::Args)]
pub struct ServedLlmDevBootstrapArgsChirho {
    #[arg(long = "payer-principal")]
    pub payer_principal_chirho: String,
    #[arg(long = "owner-principal")]
    pub owner_principal_chirho: String,
    #[arg(long = "amount")]
    pub amount_chirho: u64,
    #[arg(long = "billing-kind")]
    pub billing_kind_chirho: String,
}

#[derive(clap::Args)]
pub struct LedgerShadowCanaryReportArgsChirho {
    /// The reviewed runtime config whose effective root must equal the selected `--root`.
    #[arg(long = "config-chirho")]
    pub config_path_chirho: PathBuf,
}

#[derive(clap::Args)]
pub struct LedgerShadowCanaryVerdictArgsChirho {
    /// One captured report whose exact bytes the emitted verdict binds.
    #[arg(long = "report-chirho")]
    pub report_path_chirho: PathBuf,
    #[arg(long = "minimum-observation-count-chirho")]
    pub minimum_observation_count_chirho: u64,
    #[arg(long = "minimum-interval-millis-chirho")]
    pub minimum_interval_millis_chirho: u64,
}

#[derive(clap::Args)]
pub struct LedgerMirrorLiveHeadReportArgsChirho {
    /// The reviewed runtime config whose effective root must equal the selected `--root`.
    #[arg(long = "config-chirho")]
    pub config_path_chirho: PathBuf,
    /// Reviewed BLAKE3 of the exact config bytes, supplied outside the config's filesystem.
    #[arg(long = "expected-config-digest-chirho")]
    pub expected_config_digest_chirho: String,
}

#[derive(clap::Args)]
pub struct LedgerMirrorLiveHeadVerdictArgsChirho {
    /// One captured live-head report whose exact bytes the emitted verdict binds.
    #[arg(long = "report-chirho")]
    pub report_path_chirho: PathBuf,
}

/// Which posture a ledger-host authoring invocation declares.
///
/// **There is no `#[arg(default_value)]` on the flag that carries this, and that is the point.** An
/// authoring mode that could be omitted would let a missing argument decide whether a money-authority
/// artifact is a production one. The typed mode is LEGIBILITY, never the control — the control is
/// custody, because the emitted pin is DERIVED from a pre-provisioned secret and a key that is not on
/// this root cannot be pinned by any flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum LedgerHostAuthoringModeArgChirho {
    #[value(name = "production")]
    ProductionChirho,
    #[value(name = "test-kind")]
    TestKindChirho,
}

/// The retained cluster-genesis bundle and signed destination-authority enrollment every host
/// authoring road verifies. These are all untrusted public inputs; only the verified typed value
/// produced from them may reach config derivation.
#[derive(clap::Args)]
pub struct DestinationAuthorityEnrollmentVerificationArgsChirho {
    #[arg(long = "destination-authority-enrollment-chirho")]
    pub enrollment_path_chirho: PathBuf,
    #[arg(long = "cluster-genesis-roster-chirho")]
    pub cluster_genesis_roster_path_chirho: PathBuf,
    #[arg(long = "cluster-genesis-roster-head-chirho")]
    pub cluster_genesis_roster_head_path_chirho: PathBuf,
    #[arg(long = "cluster-genesis-roster-operator-pubkey-hex-chirho")]
    pub cluster_genesis_roster_operator_pubkey_hex_chirho: String,
}

/// Author one stable cluster-genesis destination-authority enrollment from an existing external
/// keypair. The retained genesis bundle is verified before private destination custody is opened.
#[derive(clap::Args)]
pub struct DestinationAuthorityEnrollmentAuthorArgsChirho {
    #[arg(long = "destination-authority-signing-root-chirho")]
    pub destination_authority_signing_root_chirho: PathBuf,
    #[arg(long = "cluster-genesis-roster-chirho")]
    pub cluster_genesis_roster_path_chirho: PathBuf,
    #[arg(long = "cluster-genesis-roster-head-chirho")]
    pub cluster_genesis_roster_head_path_chirho: PathBuf,
    #[arg(long = "cluster-genesis-roster-operator-pubkey-hex-chirho")]
    pub cluster_genesis_roster_operator_pubkey_hex_chirho: String,
    /// Create-new private retained artifact. Re-authoring never replaces a reviewed enrollment.
    #[arg(long = "output-chirho")]
    pub output_path_chirho: PathBuf,
}

/// The coordinates every ledger-host authoring invocation needs, whether or not it writes anything.
///
/// **Every field here is an UNTRUSTED input: a path, a secret NAME, or a choice between two branches.**
/// No field carries a verifying key, a derived artifact, a loaded signer set, or a pre-built test-kind
/// marker — each of which would let a caller hand this program an authority it never proved. The two
/// secret arguments name which pre-provisioned secret this operator can reach; the values stay in the
/// root's secret store and this binary never creates one.
#[derive(clap::Args)]
pub struct LedgerHostAuthoringCoordinatesArgsChirho {
    /// The reviewed authoring-inputs document. Every money amount, path, and principal lives there,
    /// never in a flag — the same law the regenesis porcelain applies to its plan.
    #[arg(long = "inputs-chirho")]
    pub inputs_path_chirho: PathBuf,
    #[arg(long = "issuer-secret-name-chirho")]
    pub issuer_secret_name_chirho: String,
    /// Absent authors a config with no activation authority. Never defaulted to the issuer.
    #[arg(long = "activation-secret-name-chirho")]
    pub activation_secret_name_chirho: Option<String>,
    #[arg(long = "mode-chirho", value_enum)]
    pub mode_chirho: LedgerHostAuthoringModeArgChirho,
    #[command(flatten)]
    pub destination_authority_enrollment_chirho:
        DestinationAuthorityEnrollmentVerificationArgsChirho,
}

/// Derive one reviewed document and report on it. Writes nothing, so it needs no review binding —
/// it PRINTS the digest the authoring command then requires.
#[derive(clap::Args)]
pub struct LedgerHostAuthorReviewArgsChirho {
    #[command(flatten)]
    pub coordinates_chirho: LedgerHostAuthoringCoordinatesArgsChirho,
}

/// Author and emit the config/plan pair one reviewed document authorizes.
#[derive(clap::Args)]
pub struct LedgerHostAuthorArgsChirho {
    #[command(flatten)]
    pub coordinates_chirho: LedgerHostAuthoringCoordinatesArgsChirho,
    /// Pasted from the review command's report. Without it an operator can review one document and
    /// author from another with nothing noticing.
    #[arg(long = "expected-inputs-digest-chirho")]
    pub expected_inputs_digest_chirho: String,
    /// Pasted from the review report. Compared with the exact enrollment bytes before that record
    /// is parsed, a destination pin is derived, or node-root signer custody is opened.
    #[arg(long = "expected-destination-authority-enrollment-digest-chirho")]
    pub expected_destination_authority_enrollment_digest_chirho: String,
    #[arg(long = "config-output-chirho")]
    pub config_output_chirho: PathBuf,
    #[arg(long = "plan-output-chirho")]
    pub plan_output_chirho: PathBuf,
    /// The HTTP port the emitted runtime config names. Required with no default: it is written into
    /// a reviewed artifact, and a defaulted coordinate in a reviewed artifact is one nobody reviewed.
    #[arg(long = "serve-port-chirho")]
    pub serve_port_chirho: u16,
}

/// Author the pre-signed H3 ledger activation authorization from an EXISTING reviewed config/plan.
///
/// **Every field is an UNTRUSTED input: a path, a secret NAME, or a digest to CHECK.** No field
/// carries a verifying key, a loaded signer set, or a derived artifact. The two secret arguments
/// name which pre-provisioned secret the offline authoring road may reach; the values stay in the
/// selected root's secret store and this binary never creates one. This is the third authoring
/// artifact the config/plan emission road deliberately does not write, because it is a signing act
/// whose validity window is fixed at 15 minutes and so belongs beside the start it authorizes.
#[derive(clap::Args)]
pub struct LedgerHostActivationAuthorArgsChirho {
    /// The already-authored ledger host config the activation authority pin lives in.
    #[arg(long = "config-chirho")]
    pub config_path_chirho: PathBuf,
    /// The already-authored regenesis plan the activation statement is derived from.
    #[arg(long = "plan-chirho")]
    pub plan_path_chirho: PathBuf,
    /// Pasted from the `ledger-host-author-chirho` report; re-derived and compared before the plan
    /// is trusted, exactly as a later `ledger-regenesis-chirho` run requires it.
    #[arg(long = "expected-plan-digest-chirho")]
    pub expected_plan_digest_chirho: String,
    #[arg(long = "issuer-secret-name-chirho")]
    pub issuer_secret_name_chirho: String,
    /// Required with no default: an activation authorization signed by the issuer secret instead of
    /// a distinct activation secret would collapse two authorities into one.
    #[arg(long = "activation-secret-name-chirho")]
    pub activation_secret_name_chirho: String,
    /// Create-new, private (`0600`) output for the signed authorization. Never overwrites, so a
    /// stale authorization cannot be silently reused past its window.
    #[arg(long = "activation-authorization-output-chirho")]
    pub activation_authorization_output_chirho: PathBuf,
}

#[derive(clap::Args)]
pub struct LedgerCompensationArgsChirho {
    #[arg(long = "config-chirho")]
    pub config_path_chirho: PathBuf,
    /// Reviewed BLAKE3 of the exact config bytes, supplied outside the config's filesystem.
    #[arg(long = "expected-config-digest-chirho")]
    pub expected_config_digest_chirho: String,
    #[arg(long = "app-chirho")]
    pub app_chirho: String,
    #[arg(long = "owner-chirho")]
    pub owner_chirho: String,
}

#[derive(clap::Args)]
pub struct LedgerRuntimePreflightArgsChirho {
    #[arg(long = "config-chirho")]
    pub config_path_chirho: PathBuf,
    /// Reviewed BLAKE3 of the exact config bytes, supplied outside the config's filesystem.
    #[arg(long = "expected-config-digest-chirho")]
    pub expected_config_digest_chirho: String,
}

#[derive(clap::Args)]
pub struct ProjectArgsChirho {
    #[arg(long = "at")]
    pub at_chirho: Option<u64>,
}
